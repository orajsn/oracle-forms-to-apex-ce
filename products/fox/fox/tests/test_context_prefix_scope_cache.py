"""Actual pure prefix differentials on authored inputs; never live grants."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from copy import deepcopy
import json
import os
from pathlib import Path
import time

import pytest

from fox import prototype_design_context as context, prototype_read_scope as scope
from fox import forms_blueprint as blueprint
from fox.opaf import canonical_hash, OpafError
from test_prototype_design_context import example, structural, references, TARGET


@pytest.fixture
def case(tmp_path):
    root = tmp_path / 'prototype-pipeline'; root.mkdir()
    (root / 'marker.json').write_bytes(b'{"authored":"prefix-fence-only"}')
    packet, plan, originals, proposed, receipt = example()
    candidates, refs = structural(packet, plan, originals, proposed)
    return root, [packet, plan, candidates, refs, TARGET, None, None], receipt


@pytest.fixture
def calls(monkeypatch):
    seen = []
    original = context._prefix_uncached
    def measured(*args, **kwargs):
        seen.append(kwargs.get('materialize_rows', True))
        return original(*args, **kwargs)
    monkeypatch.setattr(context, '_prefix_uncached', measured)
    return seen


def result(function, args, mode=True):
    try:
        return ('value', canonical_hash(function(*args, materialize_rows=mode)))
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError,
            UnicodeError, StopIteration, IndexError) as error:
        return ('error', type(error), str(error))


@pytest.mark.parametrize('variant', ['reviewed', 'unreviewed-last', 'root-proposal', 'proposal-and-unreviewed'])
@pytest.mark.parametrize('mode', [True, False])
def test_full_summary_proposal_unreviewed_parity_copies_and_flags(case, calls, variant, mode):
    root, args, receipt = case
    if 'proposal' in variant:
        focus = args[2][0]['focus_id']; args[3].pop(focus); args[5] = {focus: receipt}
    if 'unreviewed' in variant:
        args[6] = args[2][-1]['focus_id']; args[3].pop(args[6])
    before = deepcopy(args)
    expected = context._prefix_uncached(*args, materialize_rows=mode); calls.clear()
    with scope.readonly_proof_scope(root):
        first = context._prefix(*args, materialize_rows=mode)
        assert first == expected and type(first) is tuple
        assert bool(first[1]) is mode
        for key in context._FALSE: assert first[0][key] is False
        first[0]['reference_bindings'].clear()
        if first[1]: first[1][0]['mapping']['reason'] = 'Mutation must remain detached'
        with scope.readonly_proof_scope(root):
            assert context._prefix(*deepcopy(args), materialize_rows=mode) == expected
        assert canonical_hash(context._prefix(*args, materialize_rows=mode)) == canonical_hash(expected)
        assert calls == ([False] if mode is False else [True, True, True])
        assert len(scope._state.get()['context_prefixes']) == (1 if mode is False else 0)
    assert args == before


def test_materialized_and_summary_modes_are_distinct_full_keys(case, calls):
    root, args, _ = case
    with scope.readonly_proof_scope(root):
        full = context._prefix(*args)
        summary = context._prefix(*args, materialize_rows=False)
        assert full[0] == summary[0] and full[1] and summary[1] == []
        assert context._prefix(*args) == full and context._prefix(*args, materialize_rows=False) == summary
        assert len(scope._state.get()['context_prefixes']) == 1
    assert calls == [True, False, True]


@pytest.mark.parametrize('index', range(8))
def test_every_actual_argument_is_bound_not_only_supplied_hashes(case, calls, index):
    root, args, _ = case
    with scope.readonly_proof_scope(root):
        context._prefix(*args, materialize_rows=False)
        changed = deepcopy(args); mode = False
        if index == 0: changed[0]['sources'][0]['facts']['objects'][0]['name'] = 'Different actual source'
        elif index == 1: changed[1]['requests'][-1]['owned_objects'][0]['name'] = 'Different actual plan'
        elif index == 2: changed[2][0]['blueprint']['objects'][0]['reason'] = 'Different actual mapping'
        elif index == 3: next(iter(changed[3].values()))['proof_sha256'] = 'e' * 64
        elif index == 4: changed[4] = 'e' * 64
        elif index == 5: changed[5] = {}  # Same result, but a distinct actual argument.
        elif index == 6: changed[6] = changed[2][-1]['focus_id']
        else: mode = True
        expected = result(context._prefix_uncached, changed, mode); before = len(calls)
        assert result(context._prefix, changed, mode) == expected
        assert len(calls) == before + 1


@pytest.mark.parametrize('change', ['claim', 'missing-action', 'screen', 'owner', 'source-body', 'proposal', 'reason'])
def test_resealed_mapping_behavior_and_proposal_changes_still_revalidate(case, calls, change):
    root, args, receipt = case
    with scope.readonly_proof_scope(root):
        context._prefix(*args, materialize_rows=False)
        changed = deepcopy(args)
        if change == 'claim': changed[2][-1]['blueprint']['claims'][0]['value'] = 'Different unreviewed intent'
        elif change == 'missing-action': changed[2][-1]['blueprint']['actions'].pop()
        elif change == 'screen': changed[2][1]['blueprint']['screens'][0]['title'] = 'Different declaration'
        elif change == 'owner': changed[2][1]['blueprint']['objects'][0]['native_component'] = 'page-items'
        elif change == 'source-body': changed[1]['requests'][-1]['chunks'][0]['text'] = 'BEGIN'
        elif change == 'reason': changed[2][0]['blueprint']['objects'][0]['reason'] = 'Another unreviewed rationale'
        else:
            focus = changed[2][0]['focus_id']; changed[3].pop(focus)
            changed[5] = {focus: deepcopy(receipt)}; changed[5][focus]['after']['reason'] = 'Forged proposal'
        if change != 'proposal': changed[3] = references(changed[1], changed[2])
        expected = result(context._prefix_uncached, changed, False); before = len(calls)
        assert result(context._prefix, changed, False) == expected
        assert len(calls) == before + 1


@pytest.mark.parametrize('change', ['tuple', 'dict-subclass', 'scalar-subclass', 'nonstring-key',
    'nan', 'cycle', 'huge-int', 'oversize', 'empty', 'none-candidates', 'bad-proposals', 'bool-version'])
def test_unsupported_and_malformed_inputs_keep_exact_original_error_behavior(case, calls, monkeypatch, change):
    class CustomDict(dict): pass
    class CustomStr(str): pass
    root, args, _ = case
    with scope.readonly_proof_scope(root):
        context._prefix(*args, materialize_rows=False)
        changed = deepcopy(args)
        if change == 'tuple': changed[2] = tuple(changed[2])
        elif change == 'dict-subclass': changed[0] = CustomDict(changed[0])
        elif change == 'scalar-subclass': changed[4] = CustomStr(changed[4])
        elif change == 'nonstring-key': changed[0][1] = 'Not plain JSON'
        elif change == 'nan': changed[0]['schema_version'] = float('nan')
        elif change == 'cycle': changed[0]['cycle'] = changed[0]
        elif change == 'huge-int': changed[1]['large'] = 1 << 20_000
        elif change == 'oversize': changed[2][0]['blueprint']['objects'][0]['reason'] = 'x' * (blueprint.MAX_FILE_BYTES + 1)
        elif change == 'empty': changed[2] = []
        elif change == 'none-candidates': changed[2] = None
        elif change == 'bad-proposals': changed[5] = []
        else: changed[1]['schema_version'] = True
        expected = result(context._prefix_uncached, changed, False); before = len(calls)
        assert result(context._prefix, changed, False) == expected
        assert len(calls) == before + 1
        assert len(scope._state.get()['context_prefixes']) == 1


@pytest.mark.parametrize('mode', [None, 0, 1, '', [], {}])
def test_nonboolean_materialization_preserves_original_truthiness_without_caching(case, calls, mode):
    root, args, _ = case
    with scope.readonly_proof_scope(root):
        expected = result(context._prefix_uncached, args, mode); before = len(calls)
        assert result(context._prefix, args, mode) == expected
        assert len(calls) == before + 1 and not scope._state.get()['context_prefixes']


@pytest.mark.parametrize('budget', ['_INDEX_CACHE_MAX_NODES', '_INDEX_CACHE_MAX_DEPTH', '_INDEX_CACHE_MAX_TEXT'])
def test_eligibility_limits_fall_back_and_keep_original_false_mode_materialization(case, calls, monkeypatch, budget):
    root, args, _ = case
    monkeypatch.setattr(blueprint, budget, 0)
    with scope.readonly_proof_scope(root):
        expected = context._prefix_uncached(*args, materialize_rows=False)
        assert expected[1]  # Original unsupported-input path materializes rows.
        before = len(calls)
        assert context._prefix(*args, materialize_rows=False) == expected
        assert len(calls) == before + 1 and not scope._state.get()['context_prefixes']


def test_no_scope_new_scope_threads_tasks_and_root_errors(case, calls, tmp_path):
    root, args, _ = case
    for _ in range(2): context._prefix(*args)
    assert len(calls) == 2
    other = tmp_path / 'other'; other.mkdir()
    with scope.readonly_proof_scope(root):
        context._prefix(*args)
        with ThreadPoolExecutor(max_workers=1) as pool:
            with pytest.raises(OpafError): pool.submit(copy_context().run, context._prefix, *args).result()
        with pytest.raises(OpafError):
            with scope.readonly_proof_scope(other): context._prefix(*args)
        with pytest.raises(OpafError): scope.optional_context_prefix(other, 'a' * 64, lambda: None)
        with pytest.raises(OpafError): scope.forbid_execution()
    with scope.readonly_proof_scope(other): context._prefix(*args)
    async def owner():
        with scope.readonly_proof_scope(root):
            context._prefix(*args)
            async def child(): return context._prefix(*args)
            with pytest.raises(OpafError): await asyncio.create_task(child())
    asyncio.run(owner())
    assert len(calls) == 5 and scope.current_read_root() is None


@pytest.mark.parametrize('change', ['content', 'replacement', 'extra', 'missing', 'mode', 'hardlink'])
def test_warm_result_never_suppresses_existing_file_fences(case, change):
    root, args, _ = case; path = root / 'marker.json'
    with pytest.raises(OpafError):
        with scope.readonly_proof_scope(root):
            assert context._prefix(*args, materialize_rows=False) == context._prefix(*args, materialize_rows=False)
            if change == 'content': path.write_bytes(b'{"changed":true}')
            elif change == 'replacement':
                temporary = root / 'replacement'; temporary.write_bytes(path.read_bytes()); os.replace(temporary, path)
            elif change == 'extra': (root / 'extra.json').write_bytes(b'{}')
            elif change == 'missing': path.unlink()
            elif change == 'mode': path.chmod(0o444)
            else: os.link(path, root / 'hardlink.json')
    assert scope.current_read_root() is None


def test_actual_prefix_miss_and_hit_are_filesystem_free(case, monkeypatch):
    root, args, _ = case
    with scope.readonly_proof_scope(root):
        with monkeypatch.context() as pure:
            def forbidden(*a, **kw): pytest.fail('Pure prefix accessed filesystem state.')
            for name in ('open', 'read_bytes', 'read_text', 'write_bytes', 'mkdir', 'stat', 'lstat'):
                pure.setattr(Path, name, forbidden)
            assert context._prefix(*args, materialize_rows=False) == context._prefix(*args, materialize_rows=False)


@pytest.mark.parametrize('limit', ['entries', 'value-bytes', 'aggregate-bytes'])
def test_optional_capacity_fallback_and_all_other_budgets_are_independent(case, calls, monkeypatch, limit):
    root, args, _ = case
    if limit == 'entries': monkeypatch.setattr(scope, 'MAX_CONTEXT_PREFIXES', 1)
    elif limit == 'value-bytes': monkeypatch.setattr(scope, 'MAX_CONTEXT_PREFIX_VALUE_BYTES', 0)
    else: monkeypatch.setattr(scope, 'MAX_CONTEXT_PREFIX_BYTES', 0)
    with scope.readonly_proof_scope(root):
        assert context._prefix(*args, materialize_rows=False) == context._prefix(*args, materialize_rows=False)
        if limit == 'entries':
            next(iter(args[3].values()))['proof_sha256'] = 'e' * 64
            assert context._prefix(*args, materialize_rows=False) == context._prefix(*args, materialize_rows=False)
            assert len(calls) == 3
        else: assert len(calls) == 2
        state = scope._state.get(); mandatory = (len(state['cache']), state['bytes'])
        scope.optional_context_prefix(root, 'a' * 64, lambda: {'authored': True})
        assert (len(state['cache']), state['bytes']) == mandatory
        assert not state['document_builds'] and not state['container_proofs'] and not state['screen_projections']
        assert scope.cached_read(root, 'technical_record', {'new': True}, lambda: {'valid': True}) == {'valid': True}
        scope.optional_document_build(root, (('authored.xml', 1, 'a' * 64),), lambda: {'valid': True})
        scope.optional_container_proof(root, 'b' * 64, lambda: {'valid': True})
        scope.optional_screen_projection(root, 'c' * 64, lambda: {'valid': True})
        assert len(state['document_builds']) == len(state['container_proofs']) == len(state['screen_projections']) == 1


def test_128_entry_budget_and_129th_fallback_without_large_fixture_loop(case):
    root, _, _ = case; calls = []
    def compute(): calls.append(True); return {'authored': 'capacity-only'}
    with scope.readonly_proof_scope(root):
        for number in range(scope.MAX_CONTEXT_PREFIXES):
            for _ in range(2): scope.optional_context_prefix(root, f'{number:064x}', compute)
        assert len(calls) == scope.MAX_CONTEXT_PREFIXES == 128
        for _ in range(2): scope.optional_context_prefix(root, 'f' * 64, compute)
        assert len(calls) == 130 and len(scope._state.get()['context_prefixes']) == 128


@pytest.mark.parametrize('limit', ['value', 'aggregate'])
def test_exact_serialized_byte_boundary_declines_only_storage(case, monkeypatch, limit):
    root, _, _ = case; value = {'authored': 'x' * 30}; seen = []
    size = len(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode())
    if limit == 'value': monkeypatch.setattr(scope, 'MAX_CONTEXT_PREFIX_VALUE_BYTES', size)
    else: monkeypatch.setattr(scope, 'MAX_CONTEXT_PREFIX_BYTES', size * 2 - 1)
    def compute(): seen.append(True); return deepcopy(value)
    with scope.readonly_proof_scope(root):
        scope.optional_context_prefix(root, 'a' * 64, compute)
        assert scope.optional_context_prefix(root, 'a' * 64, compute) == value
        if limit == 'value': value['authored'] += 'x'
        for _ in range(2): assert scope.optional_context_prefix(root, 'b' * 64, compute) == value
        assert len(seen) == 3 and len(scope._state.get()['context_prefixes']) == 1


def test_full_mandatory_and_other_optional_budgets_do_not_block_prefix_store(case, calls, monkeypatch):
    root, args, _ = case
    with scope.readonly_proof_scope(root):
        context._prefix(*args, materialize_rows=False)
        state = scope._state.get(); mandatory = (len(state['cache']), state['bytes'])
        for name in ('MAX_CACHED_VALUES', 'MAX_CACHE_BYTES', 'MAX_DOCUMENT_BUILDS', 'MAX_CONTAINER_PROOFS', 'MAX_SCREEN_PROJECTIONS'):
            monkeypatch.setattr(scope, name, 0)
        next(iter(args[3].values()))['proof_sha256'] = 'e' * 64
        assert context._prefix(*args, materialize_rows=False) == context._prefix(*args, materialize_rows=False)
        assert len(calls) == 2 and len(state['context_prefixes']) == 2
        assert (len(state['cache']), state['bytes']) == mandatory


@pytest.mark.parametrize('error', [RuntimeError, OpafError, ValueError, TypeError, KeyError, AttributeError,
    RecursionError, OverflowError, UnicodeError, StopIteration, IndexError])
def test_errors_are_not_cached_or_masked_and_public_normalization_is_unchanged(case, monkeypatch, error):
    root, args, _ = case; calls = []
    def refused(*a, **kw): calls.append(True); raise error('Authored prefix failure')
    monkeypatch.setattr(context, '_prefix_uncached', refused)
    with scope.readonly_proof_scope(root):
        for _ in range(2):
            with pytest.raises(error, match='Authored prefix failure'): context._prefix(*args)
        normalized = (ValueError, TypeError, KeyError, AttributeError, RecursionError,
                      OverflowError, UnicodeError, StopIteration)
        with pytest.raises(ValueError if error in normalized else error):
            context.validate_prefix_context(*args[:4], expected_target_sha256=args[4])
        assert not scope._state.get()['context_prefixes']
    assert len(calls) == 3


@pytest.mark.parametrize('mode', [True, False])
def test_actual_uncached_prefix_counts_and_bounded_synthetic_timing(case, calls, record_property, mode):
    root, args, _ = case; results = {}
    for name, function in [('uncached', context._prefix_uncached), ('cached', context._prefix)]:
        calls.clear(); start = time.perf_counter()
        with scope.readonly_proof_scope(root):
            hashes = []
            for _ in range(8):
                value = function(*args, materialize_rows=mode)
                hashes.append(canonical_hash(value))
            state = scope._state.get()
            retained = {'stored_entries': len(state['context_prefixes']),
                'stored_serialized_bytes': state['context_prefix_bytes'], 'returned_rows': len(value[1]),
                'value_serialized_bytes': len(json.dumps(value, sort_keys=True, separators=(',', ':'),
                    ensure_ascii=False, allow_nan=False).encode())}
        results[name] = {'wall_seconds': time.perf_counter() - start, 'full_prefix_calls': len(calls),
            'result_sha256': hashes[0], **retained}
        assert len(set(hashes)) == 1
    assert results['uncached']['result_sha256'] == results['cached']['result_sha256']
    assert results['uncached']['full_prefix_calls'] == 8
    assert results['cached']['full_prefix_calls'] == (1 if mode is False else 8)
    assert results['cached']['stored_entries'] == (1 if mode is False else 0)
    record_property('authored_prefix_not_live_timing_materialize_' + str(mode), json.dumps(results, sort_keys=True))


@pytest.fixture
def review_case(case):
    root, args, _ = case
    data = deepcopy(args[:4]); focus = data[2][-1]['focus_id']; data[3].pop(focus)
    return root, data, {'expected_target_sha256': args[4], 'focus_id': focus}


@pytest.fixture
def review_calls(monkeypatch):
    seen = []; original = context._build_review_context_uncached
    def measured(*a, **kw): seen.append(True); return original(*a, **kw)
    monkeypatch.setattr(context, '_build_review_context_uncached', measured)
    return seen


def review_result(function, data, bindings):
    try:
        return ('value', canonical_hash(function(*data, **bindings)))
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError,
            UnicodeError, StopIteration, IndexError) as error:
        return ('error', type(error), str(error))


def test_final_context_full_parity_flags_copies_and_distinct_summary_purpose(review_case, review_calls):
    root, data, bindings = review_case
    expected = context._build_review_context_uncached(*data, **bindings); review_calls.clear()
    before = deepcopy((data, bindings))
    prefix_args = [*data, bindings['expected_target_sha256'], None, bindings['focus_id']]
    with scope.readonly_proof_scope(root):
        summary = context._prefix(*prefix_args, materialize_rows=False)
        full = context._prefix(*prefix_args)
        assert full[0] == summary[0] and full[1] and summary[1] == []
        first = context.build_review_context(*data, **bindings)
        assert first == expected and first['prefix_check'] == summary[0]
        assert len(first['owned_rows']) < len(full[1])
        for key in context._FALSE: assert first[key] is False
        assert first['review_required'] is True
        first['owned_rows'][0]['mapping']['reason'] = 'Detached focused context'
        first['prefix_check']['reference_bindings'].clear()
        assert context.build_review_context(*deepcopy(data), **dict(bindings)) == expected
        assert len(review_calls) == 1 and len(scope._state.get()['context_prefixes']) == 2
        assert (data, bindings) == before


@pytest.mark.parametrize('index', range(6))
def test_final_context_all_six_actual_arguments_are_bound(review_case, review_calls, index):
    root, data, bindings = review_case
    with scope.readonly_proof_scope(root):
        context.build_review_context(*data, **bindings)
        changed = deepcopy(data); changed_bindings = dict(bindings)
        if index == 0: changed[0]['sources'][0]['facts']['objects'][0]['name'] = 'Changed actual source'
        elif index == 1: changed[1]['requests'][-1]['owned_objects'][0]['name'] = 'Changed actual plan'
        elif index == 2: changed[2][-1]['blueprint']['objects'][0]['reason'] = 'Changed current unreviewed rationale'
        elif index == 3: next(iter(changed[3].values()))['proof_sha256'] = 'e' * 64
        elif index == 4: changed_bindings['expected_target_sha256'] = 'e' * 64
        else: changed_bindings['focus_id'] = changed[2][0]['focus_id']
        expected = review_result(context._build_review_context_uncached, changed, changed_bindings)
        before = len(review_calls)
        assert review_result(context.build_review_context, changed, changed_bindings) == expected
        assert len(review_calls) == before + 1


@pytest.mark.parametrize('change', ['tuple', 'subclass', 'cycle', 'huge-int', 'oversize', 'missing-source',
    'empty-candidates', 'list-refs', 'surrogate-target', 'missing-action'])
def test_final_context_malformed_fallback_and_errors_match_uncached(review_case, review_calls, change):
    class CustomDict(dict): pass
    root, data, bindings = review_case
    with scope.readonly_proof_scope(root):
        context.build_review_context(*data, **bindings)
        changed = list(deepcopy(data)); changed_bindings = dict(bindings)
        if change == 'tuple': changed[2] = tuple(changed[2])
        elif change == 'subclass': changed[0] = CustomDict(changed[0])
        elif change == 'cycle': changed[0]['cycle'] = changed[0]
        elif change == 'huge-int': changed[1]['large'] = 1 << 20_000
        elif change == 'oversize': changed[2][-1]['blueprint']['objects'][0]['reason'] = 'x' * (blueprint.MAX_FILE_BYTES + 1)
        elif change == 'missing-source': changed[0].pop('source_binding')
        elif change == 'empty-candidates': changed[2] = []
        elif change == 'list-refs': changed[3] = list(changed[3].values())
        elif change == 'surrogate-target': changed_bindings['expected_target_sha256'] = '\ud800'
        else: changed[2][-1]['blueprint']['actions'].pop()
        expected = review_result(context._build_review_context_uncached, changed, changed_bindings)
        before = len(review_calls)
        assert review_result(context.build_review_context, changed, changed_bindings) == expected
        assert len(review_calls) == before + 1 and len(scope._state.get()['context_prefixes']) == 1


def test_summary_plain_unencodable_key_falls_back_to_original(case, calls):
    root, args, _ = case
    args[4] = '\ud800'
    with scope.readonly_proof_scope(root):
        expected = result(context._prefix_uncached, args, False); before = len(calls)
        assert result(context._prefix, args, False) == expected
        assert len(calls) == before + 1 and not scope._state.get()['context_prefixes']


def test_final_context_no_io_scope_thread_task_expiry_and_fence_rules(review_case, review_calls, monkeypatch, tmp_path):
    root, data, bindings = review_case
    for _ in range(2): context.build_review_context(*data, **bindings)
    assert len(review_calls) == 2
    with scope.readonly_proof_scope(root):
        with monkeypatch.context() as pure:
            def forbidden(*a, **kw): pytest.fail('Pure final context accessed filesystem state.')
            for name in ('open', 'read_bytes', 'read_text', 'write_bytes', 'mkdir', 'stat', 'lstat'):
                pure.setattr(Path, name, forbidden)
            assert context.build_review_context(*data, **bindings) == context.build_review_context(*data, **bindings)
        with ThreadPoolExecutor(max_workers=1) as pool:
            with pytest.raises(OpafError): pool.submit(copy_context().run, context.build_review_context, *data, **bindings).result()
    async def owner():
        with scope.readonly_proof_scope(root):
            context.build_review_context(*data, **bindings)
            async def child(): return context.build_review_context(*data, **bindings)
            with pytest.raises(OpafError): await asyncio.create_task(child())
    asyncio.run(owner())
    with pytest.raises(OpafError):
        with scope.readonly_proof_scope(root):
            assert context.build_review_context(*data, **bindings) == context.build_review_context(*data, **bindings)
            (root / 'marker.json').write_bytes(b'{"changed":true}')
    assert len(review_calls) == 5 and scope.current_read_root() is None


@pytest.mark.parametrize('limit', ['entries', 'aggregate-bytes', 'value-bytes', 'summary-filled-entry'])
def test_final_context_capacity_falls_back_in_shared_summary_budget(review_case, review_calls, monkeypatch, limit):
    root, data, bindings = review_case
    if limit in ('entries', 'summary-filled-entry'): monkeypatch.setattr(scope, 'MAX_CONTEXT_PREFIXES', 1)
    elif limit == 'value-bytes': monkeypatch.setattr(scope, 'MAX_CONTEXT_PREFIX_VALUE_BYTES', 0)
    with scope.readonly_proof_scope(root):
        if limit == 'summary-filled-entry':
            context._prefix(*data, bindings['expected_target_sha256'], None, bindings['focus_id'], materialize_rows=False)
        first = context.build_review_context(*data, **bindings)
        if limit == 'aggregate-bytes':
            monkeypatch.setattr(scope, 'MAX_CONTEXT_PREFIX_BYTES', scope._state.get()['context_prefix_bytes'] + 1)
        if limit in ('entries', 'aggregate-bytes'): next(iter(data[3].values()))['proof_sha256'] = 'e' * 64
        for _ in range(2): context.build_review_context(*data, **bindings)
        assert len(review_calls) == 3
        state = scope._state.get()
        assert not state['container_proofs'] and not state['screen_projections'] and not state['document_builds']
        assert len(state['context_prefixes']) == (0 if limit == 'value-bytes' else 1)


def test_eight_public_review_context_calls_build_once_and_record_retained_size(review_case, review_calls, record_property):
    root, data, bindings = review_case; samples = {}
    for label, function in [('uncached', context._build_review_context_uncached), ('cached', context.build_review_context)]:
        review_calls.clear(); start = time.perf_counter()
        with scope.readonly_proof_scope(root):
            hashes = []
            for _ in range(8):
                value = function(*data, **bindings); hashes.append(canonical_hash(value))
            state = scope._state.get()
            retained = {'stored_entries': len(state['context_prefixes']), 'stored_serialized_bytes': state['context_prefix_bytes'],
                'focused_rows': len(value['owned_rows']), 'value_serialized_bytes': len(json.dumps(value,
                    sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode())}
        samples[label] = {'wall_seconds': time.perf_counter() - start, 'full_review_builds': len(review_calls),
            'result_sha256': hashes[0], **retained}
        assert len(set(hashes)) == 1
    assert samples['cached']['result_sha256'] == samples['uncached']['result_sha256']
    assert samples['cached']['full_review_builds'] == 1 and samples['uncached']['full_review_builds'] == 8
    record_property('authored_focused_review_context_not_live', json.dumps(samples, sort_keys=True))
