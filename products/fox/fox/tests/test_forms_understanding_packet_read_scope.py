"""Operation-local pure source derivation only; no customer or external calls."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from copy import deepcopy
import hashlib
import json
import os
import time

import pytest

from fox import forms_facts, forms_focus, forms_understanding_packet as packets
from fox import prototype_read_scope as scope
from fox.opaf import OpafError
from test_forms_understanding_packet import document


@pytest.fixture
def case(tmp_path):
    root = tmp_path / 'proof'
    root.mkdir()
    documents = [('a.xml', document(blocks=2)), ('b.xml', document('BEGIN NULL; END;', blocks=3))]
    (root / 'source.xml').write_bytes(documents[0][1])
    return root, documents


@pytest.fixture
def builds(monkeypatch):
    original, calls = packets._build_uncached, []
    def counted(documents):
        calls.append(tuple(name for name, _ in documents) if isinstance(documents, list) else None)
        return original(documents)
    monkeypatch.setattr(packets, '_build_uncached', counted)
    return calls


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def test_exact_reference_bytes_aliases_once_per_scope_and_new_scope_recomputes(case, builds):
    root, documents = case
    reference = packets._build_uncached(documents)
    builds.clear()
    with scope.readonly_proof_scope(root):
        first, second = packets._build(documents), packets._build(deepcopy(documents))
        assert type(first) is tuple and encoded(first) == encoded(second) == encoded(reference)
        assert first is not second and first[0] is not second[0]
        facts = second[0]['sources'][0]['facts']
        assert facts['modules'][0] is facts['objects'][0]
        assert len(builds) == 1
    with scope.readonly_proof_scope(root):
        assert encoded(packets._build(documents)) == encoded(reference)
    assert len(builds) == 2 and scope._state.get() is None


def test_outside_scope_uses_unchanged_reference_every_time(case, builds):
    _, documents = case
    assert encoded(packets._build(documents)) == encoded(packets._build(documents))
    assert len(builds) == 2


def test_local_approved_and_mutated_returns_cannot_poison_later_call(case, builds):
    root, documents = case
    reference = packets._build_uncached(documents)
    builds.clear()
    with scope.readonly_proof_scope(root):
        local = packets.local_packet(documents)
        selected = {row['id']: row['sha256'] for row in local['chunks']}
        approved = packets.approved_packet(documents, expected_source_binding=local['source_binding'], approved_chunk_hashes=selected)
        assert approved['selection_status'] == 'SCOPED_CONTENT_SELECTED'
        assert packets.local_packet(documents)['selection_status'] == 'NOT_SELECTED'
        first = packets._build(documents)
        first[0]['sources'].clear()
        first[1][0]['text'] = 'mutated caller text'
        local['chunks'].clear()
        approved['sources'].clear()
        assert encoded(packets._build(documents)) == encoded(reference)
        assert len(builds) == 1


@pytest.mark.parametrize('change', ['bytes', 'name', 'order'])
def test_exact_source_descriptors_miss_on_every_change(case, builds, change):
    root, documents = case
    with scope.readonly_proof_scope(root):
        original = packets._build(documents)
        changed = list(documents)
        if change == 'bytes': changed[0] = (changed[0][0], changed[0][1] + b' ')
        elif change == 'name': changed[0] = ('renamed.xml', changed[0][1])
        else: changed.reverse()
        result = packets._build(changed)
        assert len(builds) == 2
        # Logical packet ordering is still canonical, while the cache key is
        # deliberately the EXACT ordered document sequence, not a shortcut.
        assert (encoded(result) == encoded(original)) is (change == 'order')


def test_selected_chunks_source_binding_and_focus_limits_remain_fresh(case, builds):
    root, documents = case
    with scope.readonly_proof_scope(root):
        local = packets.local_packet(documents)
        chunk = local['chunks'][0]
        chosen = packets.approved_packet(documents, expected_source_binding=local['source_binding'],
            approved_chunk_hashes={chunk['id']: chunk['sha256']})
        empty = packets.approved_packet(documents, expected_source_binding=local['source_binding'], approved_chunk_hashes={})
        assert len(chosen['chunks']) == 1 and empty['chunks'] == []
        with pytest.raises(ValueError, match='complete'):
            packets.approved_packet(documents, expected_source_binding=local['source_binding'],
                approved_chunk_hashes={chunk['id']: '0' * 64})
        with pytest.raises(ValueError, match='stale'):
            packets.approved_packet(documents, expected_source_binding='0' * 64, approved_chunk_hashes={})
        narrow = forms_focus.build_focus_plan(documents, expected_source_binding=local['source_binding'], approved_chunk_hashes={}, max_owned_objects=1)
        wider = forms_focus.build_focus_plan(documents, expected_source_binding=local['source_binding'], approved_chunk_hashes={}, max_owned_objects=2)
        assert narrow['max_owned_objects'] == 1 and wider['max_owned_objects'] == 2
        assert len(narrow['requests']) > len(wider['requests']) and len(builds) == 1


@pytest.mark.parametrize('documents', [None, [], [('a.xml', b'<bad')], [('a.xml', b'<FormModule Name="A"><!')],
    [('a.xml', b'<!DOCTYPE FormModule [<!ENTITY x "x">]><FormModule Name="A"/>')],
    [('a.xml', b'<FormModule Name="A" password="ordinary-secret"/>')],
    [('a.xml', document()), ('A.XML', document('BEGIN NULL; END;'))],
    [('a.xml', document()), ('b.xml', document())], [('bad/path.xml', document())],
    [('a.xml', bytearray(b'<FormModule Name="A"/>'))], [('a.xml',)], ['wrong'],
], ids=['none', 'empty', 'malformed', 'truncated', 'dtd', 'secret', 'duplicate-name', 'duplicate-bytes',
    'unsafe-name', 'mutable-bytes', 'short-tuple', 'wrong-row'])
def test_invalid_inputs_match_uncached_failure_and_never_cache(case, documents, builds):
    root, _ = case
    with pytest.raises(Exception) as expected:
        packets._build_uncached(documents)
    with scope.readonly_proof_scope(root):
        for _ in range(2):
            with pytest.raises(type(expected.value)) as actual:
                packets._build(documents)
            assert str(actual.value) == str(expected.value)
        assert not scope._state.get()['document_builds']


def test_original_file_and_element_limits_still_reject_on_warm_scope(case, monkeypatch):
    root, documents = case
    with scope.readonly_proof_scope(root):
        packets._build(documents)
        # Use DIFFERENT source bytes; no changed validation policy is a cache key.
        too_large = [('oversized.xml', b'x' * (forms_facts.MAX_FILE_BYTES + 1))]
        with pytest.raises(ValueError, match='5 MB'):
            packets._build(too_large)
        too_many = [('items.xml', b'<FormModule Name="A">' + b'<Item Name="I"/>' * forms_facts.MAX_ELEMENTS + b'</FormModule>')]
        with pytest.raises(ValueError, match='bounded'):
            packets._build(too_many)


def test_list_tuple_string_and_bytes_subclasses_retain_uncached_path(case, builds):
    root, documents = case
    class List(list): pass
    class Tuple(tuple): pass
    class Text(str): pass
    class Bytes(bytes): pass
    variants = [List(documents), [Tuple(row) for row in documents],
        [(Text(name), raw) for name, raw in documents], [(name, Bytes(raw)) for name, raw in documents]]
    with scope.readonly_proof_scope(root):
        for variant in variants:
            packets._build(variant)
            packets._build(variant)
        assert len(builds) == 8 and not scope._state.get()['document_builds']


@pytest.mark.parametrize('limit', ['MAX_DOCUMENT_BUILDS', 'MAX_DOCUMENT_BUILD_VALUE_BYTES', 'MAX_DOCUMENT_BUILD_BYTES'])
def test_optional_capacity_falls_back_without_error_or_storage(case, builds, monkeypatch, limit):
    root, documents = case
    monkeypatch.setattr(scope, limit, 0)
    reference = packets._build_uncached(documents)
    builds.clear()
    with scope.readonly_proof_scope(root):
        assert encoded(packets._build(documents)) == encoded(reference)
        assert encoded(packets._build(documents)) == encoded(reference)
        assert not scope._state.get()['document_builds'] and scope._state.get()['document_build_bytes'] == 0
    assert len(builds) == 2


def test_full_optional_cache_cannot_spend_mandatory_budget_or_change_strict_semantics(case, monkeypatch):
    root, documents = case
    monkeypatch.setattr(scope, 'MAX_CACHED_VALUES', 1)
    monkeypatch.setattr(scope, 'MAX_CACHED_VALUE_BYTES', 20)
    monkeypatch.setattr(scope, 'MAX_CACHE_BYTES', 20)
    with scope.readonly_proof_scope(root):
        packets._build(documents)
        assert scope._state.get()['document_build_bytes'] > 20
        assert scope._state.get()['bytes'] == 0 and not scope._state.get()['cache']
        assert scope.cached_read(root, 'technical_record', {'id': 1}, lambda: {'v': 'x'}) == {'v': 'x'}
        with pytest.raises(OpafError):
            scope.cached_read(root, 'technical_record', {'id': 2}, lambda: {})
        assert packets._build(documents)[0]['source_binding']
    with scope.readonly_proof_scope(root):
        scope.cached_read(root, 'technical_record', {'id': 1}, lambda: {'v': 'x'})
        assert packets._build(documents)[0]['source_binding']
        with pytest.raises(OpafError):
            scope.cached_read(root, 'document_build', {}, lambda: {})


def test_optional_aggregate_and_entry_fallback_preserve_existing_hits(case, builds, monkeypatch):
    root, documents = case
    reference = packets._build_uncached(documents)
    size = len(encoded(reference))
    monkeypatch.setattr(scope, 'MAX_DOCUMENT_BUILD_BYTES', size)
    renamed = [('other.xml', documents[0][1]), documents[1]]
    builds.clear()
    with scope.readonly_proof_scope(root):
        packets._build(documents)
        packets._build(renamed)
        packets._build(renamed)
        assert len(builds) == 3 and len(scope._state.get()['document_builds']) == 1
        assert encoded(packets._build(documents)) == encoded(reference) and len(builds) == 3
    monkeypatch.setattr(scope, 'MAX_DOCUMENT_BUILD_BYTES', 8 * 1024 * 1024)
    monkeypatch.setattr(scope, 'MAX_DOCUMENT_BUILDS', 1)
    with scope.readonly_proof_scope(root):
        packets._build(documents)
        packets._build(renamed)
        packets._build(renamed)
        assert len(scope._state.get()['document_builds']) == 1


@pytest.mark.parametrize('mutation', ['bytes', 'replace', 'extra', 'mode', 'link'])
def test_file_identity_mode_link_and_complete_tree_fences_still_fail_after_hit(case, mutation):
    root, documents = case
    path = root / 'source.xml'
    with pytest.raises(OpafError):
        with scope.readonly_proof_scope(root):
            packets._build(documents)
            packets._build(documents)
            if mutation == 'bytes': path.write_bytes(path.read_bytes() + b' ')
            elif mutation == 'replace':
                replacement = root / 'replacement'
                replacement.write_bytes(path.read_bytes())
                os.replace(replacement, path)
            elif mutation == 'extra': (root / 'extra').write_bytes(b'x')
            elif mutation == 'mode': path.chmod(0o444)
            else: os.link(path, root / 'hardlink')
    assert scope._state.get() is None


def test_wrong_root_and_inherited_thread_task_scopes_cannot_fallback_or_compute(case, builds):
    root, documents = case
    identity = (('a.xml', 1, '0' * 64),)
    with scope.readonly_proof_scope(root):
        packets._build(documents)
        before = len(builds)
        with pytest.raises(OpafError):
            scope.optional_document_build(root.parent, identity, lambda: pytest.fail('Wrong root computed'))
        context = copy_context()
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(context.run, packets._build, documents)
            with pytest.raises(OpafError): future.result()
        assert len(builds) == before
    async def check():
        with scope.readonly_proof_scope(root):
            packets._build(documents)
            async def child():
                with pytest.raises(OpafError): packets._build(documents)
            await asyncio.create_task(child())
    asyncio.run(check())


def test_optional_cache_never_masks_compute_error_or_allows_execution(case, monkeypatch):
    root, documents = case
    monkeypatch.setattr(scope, 'MAX_DOCUMENT_BUILDS', 0)
    with scope.readonly_proof_scope(root):
        with pytest.raises(OpafError): scope.forbid_execution()
        def fails(): raise RuntimeError('ORIGINAL_COMPUTE_FAILURE')
        with pytest.raises(RuntimeError, match='ORIGINAL_COMPUTE'):
            scope.optional_document_build(root, (('x', 1, '0' * 64),), fails)


def test_synthetic_repeated_pure_build_counts_cpu_wall_and_exact_equivalence(case, monkeypatch, record_property):
    root, _ = case
    documents = [('synthetic.xml', document(blocks=80))]
    original, calls = packets._build_uncached, []
    def counted(source):
        calls.append(1)
        return original(source)
    monkeypatch.setattr(packets, '_build_uncached', counted)
    results = {}
    for name, function in [('uncached', packets._build_uncached), ('scoped', packets._build)]:
        calls.clear()
        cpu, wall = time.process_time(), time.perf_counter()
        with scope.readonly_proof_scope(root):
            for _ in range(8): value = function(documents)
        results[name] = {'uncached_builds': len(calls), 'cpu_seconds': time.process_time() - cpu,
            'wall_seconds': time.perf_counter() - wall, 'sha256': hashlib.sha256(encoded(value)).hexdigest()}
    assert results['uncached']['uncached_builds'] == 8 and results['scoped']['uncached_builds'] == 1
    assert results['uncached']['sha256'] == results['scoped']['sha256']
    record_property('synthetic_source_bytes', len(documents[0][1]))
    record_property('repetitions', 8)
    record_property('pure_build_measurement', json.dumps(results, sort_keys=True))
