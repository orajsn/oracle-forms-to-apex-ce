"""Synthetic initial-direct packet reuse; no model, compiler or Oracle calls."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from copy import deepcopy
import json
import os

import pytest

from fox import forms_facts, forms_understanding_packet as packets
from fox import prototype_direct_container as container
from fox import prototype_initial_direct_read_scope as scope
from fox import prototype_read_scope as epochs
from fox.opaf import OpafError, canonical_hash
from test_forms_understanding_packet import document
from test_oci_genai import target
from test_saved_direct_read_scope import job


@pytest.fixture
def documents():
    return [('a.xml', document(blocks=2)), ('b.xml', document('BEGIN NULL; END;', blocks=3))]


@pytest.fixture
def builds(monkeypatch):
    original, calls = packets._build_uncached, []
    def counted(documents):
        calls.append(True)
        return original(documents)
    monkeypatch.setattr(packets, '_build_uncached', counted)
    return calls


def encoded(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def identity(documents):
    return tuple((name, len(raw), packets._hash(raw)) for name, raw in documents)


def test_exact_bytes_tuple_aliases_and_new_scope_recomputes(job, documents, builds):
    reference = packets._build_uncached(documents)
    builds.clear()
    for _ in range(2):
        with scope.initial_direct_read_scope(job, target()):
            first = packets._build(documents)
            second = packets._build(deepcopy(documents))
            assert type(first) is tuple and encoded(first) == encoded(second) == encoded(reference)
            assert first is not second and first[0] is not second[0]
            facts = second[0]['sources'][0]['facts']
            assert facts['modules'][0] is facts['objects'][0]
    assert len(builds) == 2 and scope._state.get() is None
    packets._build(documents)
    packets._build(documents)
    assert len(builds) == 4


@pytest.mark.parametrize('change', ['bytes', 'name', 'order'])
def test_names_order_and_exact_bytes_cannot_alias(job, documents, builds, change):
    with scope.initial_direct_read_scope(job, target()):
        original = packets._build(documents)
        changed = list(documents)
        if change == 'bytes':
            changed[0] = (changed[0][0], changed[0][1] + b' ')
        elif change == 'name':
            changed[0] = ('renamed.xml', changed[0][1])
        else:
            changed.reverse()
        result = packets._build(changed)
        assert len(builds) == 2
        assert (encoded(result) == encoded(original)) is (change == 'order')
        assert set(scope._state.get()['document_builds']) == {identity(documents), identity(changed)}


def test_mutation_cannot_poison_cache_or_skip_fresh_selection_checks(job, documents, builds):
    reference = packets._build_uncached(documents)
    builds.clear()
    with scope.initial_direct_read_scope(job, target()):
        local = packets.local_packet(documents)
        chunk = deepcopy(local['chunks'][0])
        selected = {chunk['id']: chunk['sha256']}
        approved = packets.approved_packet(documents, expected_source_binding=local['source_binding'],
                                           approved_chunk_hashes=selected)
        empty = packets.approved_packet(documents, expected_source_binding=local['source_binding'],
                                        approved_chunk_hashes={})
        assert len(approved['chunks']) == 1 and empty['chunks'] == []
        assert approved['transfer_authorized'] is False
        assert approved['caller_must_check_processing_approval'] is True
        assert packets.local_packet(documents)['selection_status'] == 'NOT_SELECTED'
        with pytest.raises(ValueError, match='complete'):
            packets.approved_packet(documents, expected_source_binding=local['source_binding'],
                                    approved_chunk_hashes={chunk['id']: '0' * 64})
        with pytest.raises(ValueError, match='stale'):
            packets.approved_packet(documents, expected_source_binding='0' * 64, approved_chunk_hashes={})
        with pytest.raises(ValueError, match='unknown'):
            packets.approved_packet(documents, expected_source_binding=local['source_binding'],
                                    approved_chunk_hashes={'unknown': '0' * 64})
        first = packets._build(documents)
        first[0]['sources'].clear()
        first[1][0]['text'] = 'caller mutation'
        local['chunks'].clear()
        approved['sources'].clear()
        assert encoded(packets._build(documents)) == encoded(reference)
        assert len(builds) == 1


@pytest.mark.parametrize('bad', [None, [], [('a.xml', b'<bad')],
    [('a.xml', b'<!DOCTYPE FormModule [<!ENTITY x "x">]><FormModule Name="A"/>')],
    [('a.xml', b'<FormModule Name="A" password="ordinary-secret"/>')],
    [('a.xml', document()), ('A.XML', document('BEGIN NULL; END;'))],
    [('a.xml', document()), ('b.xml', document())], [('bad/path.xml', document())],
    [('a.xml', bytearray(document()))], [('a.xml',)], ['wrong'],
    [('x' * 181, document())], [('a.xml', b'')], [('a.xml', 'not bytes')],
    [(f'{i}.xml', document()) for i in range(5)],
], ids=['none', 'empty', 'malformed', 'dtd', 'secret', 'duplicate-name', 'duplicate-bytes',
        'unsafe-name', 'mutable-bytes', 'short-row', 'wrong-row', 'long-name', 'empty-bytes',
        'text', 'too-many'])
def test_invalid_inputs_preserve_exception_and_do_not_cache(job, bad):
    with pytest.raises(Exception) as expected:
        packets._build_uncached(bad)
    with scope.initial_direct_read_scope(job, target()):
        for _ in range(2):
            with pytest.raises(type(expected.value)) as actual:
                packets._build(bad)
            assert str(actual.value) == str(expected.value)
        assert not scope._state.get()['document_builds']


def test_subclasses_keep_original_uncached_behavior(job, documents, builds):
    class List(list): pass
    class Tuple(tuple): pass
    class Text(str): pass
    class Bytes(bytes): pass
    variants = [List(documents), [Tuple(row) for row in documents],
                [(Text(name), raw) for name, raw in documents],
                [(name, Bytes(raw)) for name, raw in documents]]
    with scope.initial_direct_read_scope(job, target()):
        for variant in variants:
            expected = packets._build_uncached(variant)
            assert encoded(packets._build(variant)) == encoded(expected)
            assert encoded(packets._build(variant)) == encoded(expected)
        assert len(builds) == 12 and not scope._state.get()['document_builds']


def test_source_size_and_total_limits_keep_uncached_failures(job, documents, monkeypatch):
    with scope.initial_direct_read_scope(job, target()):
        packets._build(documents)
        with pytest.raises(ValueError, match='5 MB'):
            packets._build([('oversized.xml', b'x' * (forms_facts.MAX_FILE_BYTES + 1))])
        too_many = b'<FormModule Name="A">' + b'<Item Name="I"/>' * forms_facts.MAX_ELEMENTS + b'</FormModule>'
        with pytest.raises(ValueError, match='bounded'):
            packets._build([('items.xml', too_many)])
    monkeypatch.setattr(packets, 'MAX_TOTAL_SOURCE_BYTES', 1)
    with scope.initial_direct_read_scope(job, target()):
        with pytest.raises(ValueError, match='total source-byte'):
            packets._build(documents)
        assert not scope._state.get()['document_builds']


@pytest.mark.parametrize('limit', ['MAX_DOCUMENT_BUILDS', 'MAX_DOCUMENT_BUILD_VALUE_BYTES',
                                   'MAX_DOCUMENT_BUILD_BYTES'])
def test_capacity_only_declines_storage(job, documents, builds, monkeypatch, limit):
    monkeypatch.setattr(scope, limit, 0)
    reference = packets._build_uncached(documents)
    builds.clear()
    with scope.initial_direct_read_scope(job, target()):
        assert encoded(packets._build(documents)) == encoded(reference)
        assert encoded(packets._build(documents)) == encoded(reference)
        assert scope._state.get()['document_build_bytes'] == 0
        assert not scope._state.get()['document_builds']
    assert len(builds) == 2


@pytest.mark.parametrize('limit', ['count', 'total'])
def test_full_cache_preserves_hits_and_independent_proof_budget(job, documents, builds, monkeypatch, limit):
    reference = packets._build_uncached(documents)
    if limit == 'count':
        monkeypatch.setattr(scope, 'MAX_DOCUMENT_BUILDS', 1)
    else:
        monkeypatch.setattr(scope, 'MAX_DOCUMENT_BUILD_BYTES', len(encoded(reference)))
    builds.clear()
    with scope.initial_direct_read_scope(job, target()):
        packets._build(documents)
        changed = [('renamed.xml', documents[0][1]), documents[1]]
        packets._build(changed)
        packets._build(changed)
        assert len(builds) == 3 and len(scope._state.get()['document_builds']) == 1
        assert encoded(packets._build(documents)) == encoded(reference) and len(builds) == 3
        assert scope._state.get()['bytes'] == 0 and not scope._state.get()['proofs']
        root = job / 'prototype-pipeline'
        assert scope.optional_proof(root, canonical_hash('proof'), lambda: {'proof': True}) == {'proof': True}
        assert scope._state.get()['bytes'] > 0
        assert len(scope._state.get()['document_builds']) == 1
    monkeypatch.setattr(scope, 'MAX_PROOFS', 0)
    monkeypatch.setattr(scope, 'MAX_CACHE_BYTES', 0)
    with scope.initial_direct_read_scope(job, target()):
        assert packets._build(documents) == packets._build(documents)
        assert len(scope._state.get()['document_builds']) == 1


def test_wrong_job_thread_task_and_revoked_context_fail_before_compute(job, documents, builds):
    with scope.initial_direct_read_scope(job, target()):
        packets._build(documents)
        before = len(builds)
        with pytest.raises(OpafError):
            scope.optional_document_build(job.parent, identity(documents), lambda: pytest.fail('Wrong job computed'))
        captured = copy_context()
        with ThreadPoolExecutor(max_workers=1) as pool:
            result = pool.submit(captured.run, packets._build, documents)
            with pytest.raises(OpafError):
                result.result()
        assert len(builds) == before
        state = scope._state.get()
    assert state['active'] is False and not state['document_builds'] and state['document_build_bytes'] == 0
    with pytest.raises(OpafError):
        captured.run(packets._build, documents)
    with scope.initial_direct_read_scope(job, target()):
        with pytest.raises(OpafError):
            captured.run(packets._build, documents)
    async def check():
        with scope.initial_direct_read_scope(job, target()):
            packets._build(documents)
            async def child():
                with pytest.raises(OpafError):
                    packets._build(documents)
            await asyncio.create_task(child())
    asyncio.run(check())


def test_independent_threads_and_tasks_build_separately(job, documents, monkeypatch):
    def operation():
        with scope.initial_direct_read_scope(job, target()):
            assert packets._build(documents) == packets._build(documents)
            return scope._state.get()
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [future.result() for future in [pool.submit(operation), pool.submit(operation)]]
    assert results[0] is not results[1]
    async def check():
        async def child():
            with scope.initial_direct_read_scope(job, target()):
                packets._build(documents)
                await asyncio.sleep(0)
                assert packets._build(documents)
                return scope._state.get()
        first, second = await asyncio.gather(child(), child())
        assert first is not second
    asyncio.run(check())


@pytest.mark.parametrize('mutation', ['bytes', 'restored-mtime', 'replace', 'extra', 'outside', 'mode', 'link'])
def test_complete_job_invalidation_after_packet_hit(job, documents, mutation):
    path = job / 'prototype-pipeline/original.json'
    with pytest.raises(OpafError):
        with scope.initial_direct_read_scope(job, target()):
            assert packets._build(documents) == packets._build(documents)
            captured = copy_context()
            if mutation in ('bytes', 'restored-mtime'):
                metadata = path.stat()
                path.write_bytes(b'{"proof":null}')
                if mutation == 'restored-mtime':
                    os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
            elif mutation == 'replace':
                replacement = job / 'replacement'
                replacement.write_bytes(path.read_bytes())
                os.replace(replacement, path)
            elif mutation == 'extra':
                (job / 'extra').write_bytes(b'x')
            elif mutation == 'outside':
                (job / 'source-snapshot.json').write_bytes(b'{"original":false}')
            elif mutation == 'mode':
                path.chmod(0o444)
            else:
                os.link(path, job / 'hardlink')
    if path.exists():
        path.chmod(0o666)
    assert scope._state.get() is None
    with pytest.raises(OpafError):
        captured.run(packets._build, documents)


def test_compute_failures_reset_and_execution_stays_forbidden(job, documents, monkeypatch):
    with pytest.raises(RuntimeError, match='ORIGINAL_COMPUTE_FAILURE'):
        with scope.initial_direct_read_scope(job, target()):
            with pytest.raises(OpafError):
                scope.forbid_execution()
            monkeypatch.setattr(scope, 'MAX_DOCUMENT_BUILDS', 0)
            def fails():
                raise RuntimeError('ORIGINAL_COMPUTE_FAILURE')
            scope.optional_document_build(job / 'prototype-pipeline', identity(documents), fails)
    assert scope._state.get() is None
    scope.forbid_execution()


@pytest.mark.parametrize('gate', ['not-direct', 'no-container', 'epoch'])
def test_ineligible_initial_direct_scope_preserves_uncached_path(job, documents, builds, gate):
    current = target()
    if gate == 'not-direct':
        current = {}
    elif gate == 'no-container':
        (job / 'prototype-pipeline' / container.TECHNICAL).unlink()
    else:
        (job / 'prototype-pipeline/epochs').mkdir()
    with scope.initial_direct_read_scope(job, current):
        assert scope.current_read_root() is None
        assert packets._build(documents) == packets._build(documents)
    assert len(builds) == 2


def test_epoch_cache_keeps_its_existing_store_and_budgets(tmp_path, documents, builds):
    root = tmp_path / 'epoch-proof'
    root.mkdir()
    (root / 'source.xml').write_bytes(documents[0][1])
    with epochs.readonly_proof_scope(root):
        assert packets._build(documents) == packets._build(documents)
        assert len(epochs._state.get()['document_builds']) == 1
        assert scope._state.get() is None
    assert len(builds) == 1
