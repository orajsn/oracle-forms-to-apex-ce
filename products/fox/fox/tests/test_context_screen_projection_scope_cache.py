"""Actual pure projection on authored inputs; no historical or live grants."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from copy import deepcopy
import json
import os
from pathlib import Path
import time

import pytest

from fox import forms_blueprint as blueprint
from fox import prototype_context_screen_projection as projection, prototype_read_scope as scope
from fox.opaf import canonical_hash, OpafError
from test_prototype_context_screen_projection import scenario, pins, rebind_refs

BINDINGS = ('expected_source_binding', 'expected_plan_sha256', 'expected_focus_id',
    'expected_request_sha256', 'expected_raw_candidate_sha256', 'expected_target_sha256')


@pytest.fixture
def case(tmp_path):
    root = tmp_path / 'prototype-pipeline'; root.mkdir()
    (root / 'marker.json').write_bytes(b'{"authored":"scope-fence-only"}')
    data = scenario()
    return root, data, pins(data)


@pytest.fixture
def calls(monkeypatch):
    counts = {'project': 0, 'plan': 0, 'prefix': 0}
    for module, name, label in ((projection, '_project_uncached', 'project'),
            (projection.context, '_plan', 'plan'), (projection.context, '_prefix', 'prefix')):
        original = getattr(module, name)
        def measured(*args, _original=original, _label=label, **kwargs):
            counts[_label] += 1
            return _original(*args, **kwargs)
        monkeypatch.setattr(module, name, measured)
    return counts


def uncached(data, bindings):
    # Preserve the unchanged public facade's exact exception normalization.
    try:
        return projection._project_uncached(*data, *(bindings[key] for key in BINDINGS))
    except projection._ERRORS:
        projection._fail()


def project(data, bindings):
    return projection.project_context_screens(*data, **bindings)


def outcome(function, data, bindings):
    try:
        return ('value', canonical_hash(function(data, bindings)))
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError, UnicodeError) as error:
        return ('error', type(error), str(error))


def test_full_value_parity_deepcopy_flags_and_equal_clone_reuse(case, calls):
    root, data, bindings = case
    before = deepcopy((data, bindings))
    expected = uncached(data, bindings); counts = dict(calls)
    calls.update(dict.fromkeys(calls, 0))
    with scope.readonly_proof_scope(root):
        first = project(data, bindings)
        assert type(first) is tuple and first == expected
        first[0]['blueprint']['objects'].clear()
        first[1]['removed_screens'][0]['declaration']['title'] = 'Mutated copy'
        with scope.readonly_proof_scope(root):
            assert project(*deepcopy((data, bindings))) == expected
        assert calls == counts
        receipt = project(data, bindings)[1]
        for flag in projection.context._FALSE:
            assert receipt[flag] is False
        assert receipt['status'] == 'PROJECTED_UNREVIEWED'
        assert receipt['independent_review_required'] is True
        assert receipt['ai_approval_granted'] is False
        assert receipt['semantic_equivalence_asserted'] is False
        assert canonical_hash(project(data, bindings)) == canonical_hash(expected)
    assert (data, bindings) == before


@pytest.mark.parametrize('kind', ['already-projected', 'owned-new-screen', 'two-blocks'])
def test_no_change_and_multiple_block_paths_match_original(case, calls, kind):
    root, data, bindings = case
    if kind == 'already-projected': data[2][-1] = uncached(data, bindings)[0]
    elif kind == 'two-blocks': data = scenario(two_blocks=True)
    else:
        packet, plan, candidates, refs = data
        index = next(i for i, request in enumerate(plan['requests'])
            if any(row['kind'] == 'Block' for row in request['owned_objects']))
        prefix = candidates[:index + 1]
        data = packet, plan, prefix, {k: v for k, v in refs.items() if k in {c['focus_id'] for c in prefix[:-1]}}
    bindings = pins(data); expected = uncached(data, bindings)
    calls.update(dict.fromkeys(calls, 0))
    with scope.readonly_proof_scope(root):
        for _ in range(3): assert project(data, bindings) == expected
    assert calls['project'] == 1
    if kind != 'two-blocks': assert expected[1]['status'] == 'NO_CHANGE'


@pytest.mark.parametrize('field', BINDINGS)
def test_each_independent_pin_revalidates_not_a_cached_approval(case, calls, field):
    root, data, bindings = case
    with scope.readonly_proof_scope(root):
        project(data, bindings)
        changed = {**bindings, field: 'f' * 64}
        expected = outcome(uncached, data, changed); before = calls['project']
        assert outcome(project, data, changed) == expected
        assert expected[0] == 'error' and calls['project'] == before + 1


@pytest.mark.parametrize('change', ['packet', 'plan', 'candidate-reason', 'reference-proof',
    'screen-title', 'screen-id', 'screen-owner', 'duplicate-screen', 'mapping-screen',
    'claim-value', 'missing-claim', 'action', 'question', 'assumption', 'wrong-reference-target'])
def test_every_actual_input_screen_mapping_and_claim_change_revalidates(case, calls, change):
    root, data, bindings = case
    with scope.readonly_proof_scope(root):
        project(data, bindings)
        changed = deepcopy(data)
        packet, plan, candidates, refs = changed
        raw = candidates[-1]['blueprint']
        if change == 'packet': packet['sources'][0]['facts']['objects'][0]['name'] = 'Changed actual source'
        elif change == 'plan': plan['requests'][-1]['owned_objects'][0]['name'] = 'Changed actual request'
        elif change == 'candidate-reason': raw['objects'][0]['reason'] = 'Different unreviewed rationale'
        elif change == 'reference-proof': next(iter(refs.values()))['proof_sha256'] = 'e' * 64
        elif change == 'screen-title': raw['screens'][0]['title'] = 'Changed duplicate declaration'
        elif change == 'screen-id': raw['screens'][0]['id'] = 'screen-foreign'
        elif change == 'screen-owner':
            prior_mapping = next(row for c in candidates[:-1] for row in c['blueprint']['objects'] if 'native_component' in row)
            prior_mapping['disposition'] = 'unresolved'; prior_mapping.pop('native_component'); prior_mapping.pop('screen_id')
            rebind_refs(changed)
        elif change == 'duplicate-screen': raw['screens'] *= 2
        elif change == 'mapping-screen': raw['objects'][0]['screen_id'] = 'screen-foreign'
        elif change == 'claim-value': raw['claims'][0]['value'] = 'Different unreviewed business intent'
        elif change == 'missing-claim': raw['claims'].pop()
        elif change == 'action': raw['actions'].pop()
        elif change == 'question': raw['questions'][0]['text'] = 'Different question'
        elif change == 'assumption': raw['assumptions'][0]['text'] = 'Different scope assumption'
        else: next(iter(refs.values()))['target_profile_sha256'] = 'e' * 64
        # The independent pins are deliberately unchanged. Hash claims cannot
        # conceal different packet/plan/candidate/reference inputs from the key.
        expected = outcome(uncached, changed, bindings); before = calls['project']
        assert outcome(project, changed, bindings) == expected
        assert calls['project'] == before + 1


@pytest.mark.parametrize('change', ['reason', 'claim', 'action', 'receipt-approval', 'receipt-owner', 'receipt-version'])
def test_caller_candidate_receipt_checks_still_execute_when_projection_is_warm(case, calls, change):
    root, data, bindings = case
    with scope.readonly_proof_scope(root):
        candidate, receipt = project(data, bindings)
        assert projection.validate_context_screen_projection(candidate, receipt, *data, **bindings) == receipt
        if change == 'reason': candidate['blueprint']['objects'][0]['reason'] = 'Changed result'
        elif change == 'claim': candidate['blueprint']['claims'][0]['value'] = 'Changed behavior'
        elif change == 'action': candidate['blueprint']['actions'].pop()
        elif change == 'receipt-approval': receipt['ai_approval_granted'] = True
        elif change == 'receipt-owner': receipt['removed_screens'][0]['owner_mapping']['reason'] = 'Forged owner'
        else: receipt['schema_version'] = 2
        with pytest.raises(ValueError, match='Invalid source-bound context screen projection'):
            projection.validate_context_screen_projection(candidate, receipt, *data, **bindings)
    assert calls['project'] == 1


@pytest.mark.parametrize('change', ['candidate-tuple', 'dict-subclass', 'scalar-subclass', 'nonstring-key',
    'nan', 'cycle', 'huge-int', 'oversized-text'])
def test_nonplain_cycles_and_oversize_retain_original_path_and_errors(case, calls, monkeypatch, change):
    class CustomDict(dict): pass
    class CustomStr(str): pass
    root, data, bindings = case
    with scope.readonly_proof_scope(root):
        project(data, bindings)
        changed = list(deepcopy(data)); changed_bindings = dict(bindings)
        if change == 'candidate-tuple': changed[2] = tuple(changed[2])
        elif change == 'dict-subclass': changed[0] = CustomDict(changed[0])
        elif change == 'scalar-subclass': changed_bindings['expected_source_binding'] = CustomStr(bindings['expected_source_binding'])
        elif change == 'nonstring-key': changed[0][1] = 'Not JSON'
        elif change == 'nan': changed[0]['schema_version'] = float('nan')
        elif change == 'cycle': changed[0]['cycle'] = changed[0]
        elif change == 'huge-int': changed[1]['large'] = 1 << 20_000
        else: changed[2][-1]['blueprint']['objects'][0]['reason'] = 'x' * (blueprint.MAX_FILE_BYTES + 1)
        expected = outcome(uncached, changed, changed_bindings); before = calls['project']
        def forbidden(*a, **kw): pytest.fail('Unsupported input reached the optional store.')
        monkeypatch.setattr(scope, 'optional_screen_projection', forbidden)
        assert outcome(project, changed, changed_bindings) == expected
        assert calls['project'] == before + 1


@pytest.mark.parametrize('budget', ['_INDEX_CACHE_MAX_NODES', '_INDEX_CACHE_MAX_DEPTH', '_INDEX_CACHE_MAX_TEXT'])
def test_eligibility_budget_declines_cache_not_valid_projection(case, calls, monkeypatch, budget):
    root, data, bindings = case
    expected = uncached(data, bindings); calls.update(dict.fromkeys(calls, 0))
    monkeypatch.setattr(blueprint, budget, 0)
    with scope.readonly_proof_scope(root):
        for _ in range(2): assert project(data, bindings) == expected
        assert not scope._state.get()['screen_projections']
    assert calls['project'] == 2


def test_outside_scope_is_exact_original_without_eligibility_guard(case, calls, monkeypatch):
    _, data, bindings = case
    expected = uncached(data, bindings); calls.update(dict.fromkeys(calls, 0))
    def forbidden(*a): pytest.fail('Outside-scope behavior must remain unchanged.')
    monkeypatch.setattr(projection, '_index_cache_eligible', forbidden)
    for _ in range(2): assert project(data, bindings) == expected
    assert calls['project'] == 2


def test_scope_expiration_threads_tasks_and_root_checks(case, calls, tmp_path):
    root, data, bindings = case
    other = tmp_path / 'other'; other.mkdir()
    with scope.readonly_proof_scope(root):
        project(data, bindings)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(copy_context().run, project, data, bindings)
            with pytest.raises(OpafError): future.result()
        with pytest.raises(OpafError):
            with scope.readonly_proof_scope(other): project(data, bindings)
        with pytest.raises(OpafError): scope.optional_screen_projection(other, 'a' * 64, lambda: None)
        with pytest.raises(OpafError): scope.forbid_execution()
    with scope.readonly_proof_scope(other): project(data, bindings)
    async def owner():
        with scope.readonly_proof_scope(root):
            project(data, bindings)
            async def child(): return project(data, bindings)
            with pytest.raises(OpafError): await asyncio.create_task(child())
    asyncio.run(owner())
    assert calls['project'] == 3 and scope.current_read_root() is None


@pytest.mark.parametrize('change', ['content', 'replacement', 'extra', 'missing', 'mode', 'hardlink'])
def test_warm_projection_cannot_suppress_scope_file_fences(case, change):
    root, data, bindings = case
    marker = root / 'marker.json'
    with pytest.raises(OpafError):
        with scope.readonly_proof_scope(root):
            expected = project(data, bindings)
            assert project(data, bindings) == expected
            if change == 'content': marker.write_bytes(b'{"changed":true}')
            elif change == 'replacement':
                temporary = root / 'replacement'; temporary.write_bytes(marker.read_bytes()); os.replace(temporary, marker)
            elif change == 'extra': (root / 'extra.json').write_bytes(b'{}')
            elif change == 'missing': marker.unlink()
            elif change == 'mode': marker.chmod(0o444)
            else: os.link(marker, root / 'linked.json')
    assert scope.current_read_root() is None


def test_projection_is_actually_pure_no_filesystem_access_on_miss_or_hit(case, monkeypatch):
    root, data, bindings = case
    with scope.readonly_proof_scope(root):
        with monkeypatch.context() as pure:
            def forbidden(*a, **kw): pytest.fail('Pure projection accessed the filesystem.')
            for name in ('open', 'read_bytes', 'read_text', 'write_bytes', 'write_text', 'mkdir', 'stat', 'lstat'):
                pure.setattr(Path, name, forbidden)
            assert project(data, bindings) == project(data, bindings)


@pytest.mark.parametrize('capacity', ['entries', 'value-bytes', 'aggregate-bytes'])
def test_optional_capacity_falls_back_without_exhausting_other_stores(case, calls, monkeypatch, capacity):
    root, data, bindings = case
    if capacity == 'entries': monkeypatch.setattr(scope, 'MAX_SCREEN_PROJECTIONS', 1)
    elif capacity == 'value-bytes': monkeypatch.setattr(scope, 'MAX_SCREEN_PROJECTION_VALUE_BYTES', 0)
    else: monkeypatch.setattr(scope, 'MAX_SCREEN_PROJECTION_BYTES', 0)
    with scope.readonly_proof_scope(root):
        expected = project(data, bindings)
        assert project(data, bindings) == expected
        if capacity == 'entries':
            next(iter(data[3].values()))['proof_sha256'] = 'e' * 64
            for _ in range(2): project(data, bindings)
            assert calls['project'] == 3
        else: assert calls['project'] == 2
        state = scope._state.get()
        assert not state['document_builds'] and not state['container_proofs']
        mandatory = (len(state['cache']), state['bytes'])
        scope.optional_screen_projection(root, 'f' * 64, lambda: {'optional': True})
        assert (len(state['cache']), state['bytes']) == mandatory
        assert scope.cached_read(root, 'technical_record', {'new': 'mandatory'}, lambda: {'valid': True}) == {'valid': True}
        assert scope.optional_document_build(root, (('authored.xml', 1, 'a' * 64),), lambda: {'valid': True}) == {'valid': True}
        assert scope.optional_container_proof(root, 'b' * 64, lambda: {'valid': True}) == {'valid': True}
        assert len(state['document_builds']) == len(state['container_proofs']) == 1


def test_exhausted_other_store_budgets_do_not_spend_screen_projection_capacity(case, monkeypatch):
    root, data, bindings = case
    with scope.readonly_proof_scope(root):
        expected = project(data, bindings)
        state = scope._state.get()
        before = (len(state['cache']), state['bytes'], len(state['screen_projections']), state['screen_projection_bytes'])
        monkeypatch.setattr(scope, 'MAX_DOCUMENT_BUILDS', 0)
        monkeypatch.setattr(scope, 'MAX_CONTAINER_PROOFS', 0)
        assert project(data, bindings) == expected
        assert (len(state['cache']), state['bytes'], len(state['screen_projections']), state['screen_projection_bytes']) == before


def test_default_entry_capacity_and_next_identity_fallback(case, calls):
    root, data, bindings = case
    with scope.readonly_proof_scope(root):
        reference = next(iter(data[3].values()))
        for number in range(scope.MAX_SCREEN_PROJECTIONS):
            reference['proof_sha256'] = f'{number:064x}'
            assert project(data, bindings) == project(data, bindings)
        assert calls['project'] == scope.MAX_SCREEN_PROJECTIONS == 128
        assert scope.MAX_SCREEN_PROJECTION_VALUE_BYTES == 4 * 1024 * 1024
        assert scope.MAX_SCREEN_PROJECTION_BYTES == 8 * 1024 * 1024
        reference['proof_sha256'] = 'f' * 64
        assert project(data, bindings) == project(data, bindings)
        assert calls['project'] == scope.MAX_SCREEN_PROJECTIONS + 2
        assert len(scope._state.get()['screen_projections']) == scope.MAX_SCREEN_PROJECTIONS


def test_full_mandatory_budget_does_not_block_new_projection_entry(case, calls, monkeypatch):
    root, data, bindings = case
    with scope.readonly_proof_scope(root):
        project(data, bindings)
        state = scope._state.get(); mandatory = (len(state['cache']), state['bytes'])
        monkeypatch.setattr(scope, 'MAX_CACHED_VALUES', 0)
        monkeypatch.setattr(scope, 'MAX_CACHE_BYTES', 0)
        next(iter(data[3].values()))['proof_sha256'] = 'f' * 64
        assert project(data, bindings) == project(data, bindings)
        assert len(state['screen_projections']) == 2 and calls['project'] == 2
        assert (len(state['cache']), state['bytes']) == mandatory


@pytest.mark.parametrize('change', ['missing-source', 'empty-candidates', 'none-candidates',
    'list-refs', 'missing-blueprint', 'boolean-plan-version'])
def test_actual_malformed_inputs_preserve_original_errors_after_warm_success(case, calls, change):
    root, data, bindings = case
    with scope.readonly_proof_scope(root):
        project(data, bindings)
        changed = list(deepcopy(data))
        if change == 'missing-source': changed[0].pop('source_binding')
        elif change == 'empty-candidates': changed[2] = []
        elif change == 'none-candidates': changed[2] = None
        elif change == 'list-refs': changed[3] = list(changed[3].values())
        elif change == 'missing-blueprint': changed[2][-1].pop('blueprint')
        else: changed[1]['schema_version'] = True
        expected = outcome(uncached, changed, bindings); before = calls['project']
        assert outcome(project, changed, bindings) == expected
        assert expected[0] == 'error' and calls['project'] == before + 1
        assert len(scope._state.get()['screen_projections']) == 1


@pytest.mark.parametrize('error', [RuntimeError, OpafError, ValueError, TypeError, KeyError, AttributeError,
    RecursionError, OverflowError, UnicodeError, StopIteration, IndexError])
def test_compute_errors_not_stored_or_retried_and_public_error_contract_preserved(case, monkeypatch, error):
    root, data, bindings = case
    calls = []
    def refused(*args): calls.append(True); raise error('Authored deterministic failure')
    monkeypatch.setattr(projection, '_project_uncached', refused)
    with scope.readonly_proof_scope(root):
        for _ in range(2):
            if error in projection._ERRORS:
                with pytest.raises(ValueError, match='Invalid source-bound context screen projection'): project(data, bindings)
            else:
                with pytest.raises(error, match='Authored deterministic failure'): project(data, bindings)
        assert not scope._state.get()['screen_projections']
    assert len(calls) == 2


def test_synthetic_actual_full_projection_counts_and_bounded_timing(case, calls, record_property):
    root, data, bindings = case
    results = {}
    for name, function in [('uncached', uncached), ('cached', project)]:
        calls.update(dict.fromkeys(calls, 0)); start = time.perf_counter()
        with scope.readonly_proof_scope(root):
            hashes = [canonical_hash(function(data, bindings)) for _ in range(8)]
        results[name] = {'wall_seconds': time.perf_counter() - start, 'counts': dict(calls), 'result_sha256': hashes[0]}
        assert len(set(hashes)) == 1
    assert results['uncached']['result_sha256'] == results['cached']['result_sha256']
    assert results['uncached']['counts']['project'] == 8 and results['cached']['counts']['project'] == 1
    assert results['uncached']['counts']['plan'] == results['cached']['counts']['plan'] * 8
    assert results['uncached']['counts']['prefix'] == results['cached']['counts']['prefix'] * 8
    record_property('authored_pure_projection_not_live_timing', json.dumps(results, sort_keys=True))
