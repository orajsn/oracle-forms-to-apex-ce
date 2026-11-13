"""Summary/full differentials on synthetic context only; no authority or models."""
from copy import deepcopy
import hashlib
import json
import time

import pytest

from fox import prototype_design_context as context
from fox.forms_focus import build_focus_plan
from fox.forms_understanding_packet import local_packet
from fox.opaf import canonical_hash
from fox import prototype_read_scope as scope
from test_prototype_design_context import example, structural, references, reseal, mapping_candidate, TARGET


def case(mode='reviewed'):
    packet, plan, originals, proposed, receipt = example()
    candidates, refs = structural(packet, plan, originals, proposed)
    proposals, unreviewed = None, None
    if mode == 'partial':
        candidates = candidates[:1]
        refs = references(plan, candidates)
    if mode in ('unreviewed', 'proposal'):
        unreviewed = candidates[-1]['focus_id']
        refs.pop(unreviewed)
    if mode == 'proposal':
        root = candidates[0]['focus_id']
        refs.pop(root)
        proposals = {root: receipt}
    return packet, plan, candidates, refs, TARGET, proposals, unreviewed


def outcome(args, *, detailed):
    try:
        value = context._prefix(*args, materialize_rows=detailed)
        return 'ok', value[0]
    except Exception as error:
        return 'error', type(error), str(error)


def assert_differential(args):
    before = deepcopy(args)
    full = outcome(args, detailed=True)
    summary = outcome(args, detailed=False)
    assert full == summary
    assert args == before
    if full[0] == 'ok':
        packet, plan, candidates, refs, target, proposals, unreviewed = args
        assert context.validate_prefix_context(packet, plan, candidates, refs, expected_target_sha256=target,
            container_proposals=proposals, unreviewed_focus_id=unreviewed) == full[1]
        assert context._prefix(*args, materialize_rows=False)[1] == []
        assert all(full[1][key] is False for key in context._FALSE)
    return full


@pytest.mark.parametrize('mode', ['reviewed', 'partial', 'unreviewed', 'proposal'])
def test_summary_matches_original_full_path_and_never_mutates_inputs(mode):
    assert assert_differential(case(mode))[0] == 'ok'


@pytest.mark.parametrize('change', ['empty', 'missing-ref', 'extra-ref', 'approved-ref', 'proof-sha',
    'target', 'source', 'plan', 'request', 'duplicate-focus', 'order', 'missing-screen', 'foreign-screen',
    'duplicate-screen', 'missing-screen-id', 'omitted-root', 'unresolved-owner', 'native-item',
    'component', 'extra-object', 'missing-chunk', 'partial-body', 'unit-sha', 'missing-unit',
    'missing-claim', 'behavior-kind', 'claim-evidence', 'scalar-behavior', 'missing-action',
    'wrong-action', 'duplicate-action', 'parent-cycle'])
def test_changed_or_malformed_context_has_identical_failure(change):
    args = list(case())
    packet, plan, candidates, refs = args[:4]
    last, bp = plan['requests'][-1], candidates[-1]['blueprint']
    if change == 'empty': candidates.clear()
    elif change == 'missing-ref': refs.pop(next(iter(refs)))
    elif change == 'extra-ref': refs['unknown'] = deepcopy(next(iter(refs.values())))
    elif change == 'approved-ref': next(iter(refs.values()))['approved'] = True
    elif change == 'proof-sha': next(iter(refs.values()))['proof_sha256'] = True
    elif change == 'target': args[4] = '0' * 64
    elif change == 'source': packet['source_binding'] = '0' * 64
    elif change == 'plan': plan['plan_binding'] = '0' * 64
    elif change == 'request': last['focus_binding'] = '0' * 64
    elif change == 'duplicate-focus': candidates.append(deepcopy(candidates[-1]))
    elif change == 'order': candidates[1], candidates[2] = candidates[2], candidates[1]
    elif change == 'missing-screen': candidates[1]['blueprint']['screens'].clear()
    elif change == 'foreign-screen': bp['objects'][0]['screen_id'] = 'screen-foreign'
    elif change == 'duplicate-screen': bp['screens'] = deepcopy(candidates[1]['blueprint']['screens'])
    elif change == 'missing-screen-id': bp['objects'][0].pop('screen_id')
    elif change == 'omitted-root': candidates[0]['blueprint']['objects'][0]['disposition'] = 'omitted'
    elif change == 'unresolved-owner':
        owner = candidates[1]['blueprint']['objects'][0]
        owner.update(disposition='unresolved')
        owner.pop('screen_id'); owner.pop('native_component')
        candidates[1]['blueprint']['screens'].clear()
    elif change == 'native-item': bp['objects'][0]['native_component'] = 'form'
    elif change == 'component': candidates[1]['blueprint']['objects'][0]['native_component'] = 'page-items'
    elif change == 'extra-object': bp['objects'].append(deepcopy(candidates[1]['blueprint']['objects'][0]))
    elif change == 'missing-chunk':
        removed = last['chunks'].pop()
        del plan['selected_chunk_hashes'][removed['id']]
        last['unselected_code_unit_ids'] = [removed['code_unit_id']]
    elif change == 'partial-body': last['chunks'][0]['text'] = 'BEGIN'
    elif change == 'unit-sha': last['code_units'][0]['sha256'] = '0' * 64
    elif change == 'missing-unit': last['code_units'].pop()
    elif change == 'missing-claim': bp['claims'].pop()
    elif change == 'behavior-kind': bp['claims'][0]['kind'] = 'unrelated.intent'
    elif change == 'claim-evidence': bp['claims'][0]['evidence_refs'] = [bp['claims'][0]['source_object_id']]
    elif change == 'scalar-behavior': bp['claims'][0]['value'] = True
    elif change == 'missing-action': bp['actions'].pop()
    elif change == 'wrong-action': bp['actions'][0]['claim_ids'] = [bp['claims'][1]['id']]
    elif change == 'duplicate-action': bp['actions'].append(deepcopy(bp['actions'][0]))
    else:
        row = packet['sources'][0]['facts']['objects'][-1]
        row['parent_id'] = row['id']
    if change not in ('empty', 'order', 'duplicate-focus', 'plan', 'request'):
        reseal(plan, candidates)
        if change not in ('missing-ref', 'extra-ref', 'approved-ref', 'proof-sha'):
            refs = references(plan, candidates)
            args[3] = refs
    assert assert_differential(tuple(args))[0] == 'error'


@pytest.mark.parametrize('change', ['proposal-before', 'proposal-after', 'proposal-focus', 'wrong-unreviewed', 'proposal-plus-ref'])
def test_proposal_and_unreviewed_boundaries_are_not_relaxed(change):
    args = list(case('proposal'))
    packet, plan, candidates, refs, target, proposals, unreviewed = args
    receipt = next(iter(proposals.values()))
    if change == 'proposal-before': receipt['before']['reason'] = 'forged'
    elif change == 'proposal-after': receipt['after']['reason'] = 'forged'
    elif change == 'proposal-focus': receipt['focus_id'] = 'unknown'
    elif change == 'wrong-unreviewed': args[-1] = candidates[0]['focus_id']
    else: refs.update(references(plan, candidates[:1]))
    assert assert_differential(tuple(args))[0] == 'error'


def deep_ancestor_case(depth=24):
    groups = ''.join(f'<ObjectGroup Name="G{i}">' for i in range(depth))
    docs = [('deep.xml', ('<FormModule Name="DEEP"><Block Name="B" DatabaseBlock="true">' + groups
        + '<Item Name="I" ItemType="Text Item" DatabaseItem="true"/><Trigger Name="T" TriggerText="BEGIN NULL; END;"/>'
        + '</ObjectGroup>' * depth + '</Block></FormModule>').encode())]
    packet = local_packet(docs)
    plan = build_focus_plan(docs, expected_source_binding=packet['source_binding'],
        approved_chunk_hashes={row['id']: row['sha256'] for row in packet['chunks']}, max_owned_objects=8)
    block = next(row for row in packet['sources'][0]['facts']['objects'] if row['kind'] == 'Block')
    candidates = [mapping_candidate(request, 'screen-' + block['id']) for request in plan['requests']]
    return packet, plan, candidates, references(plan, candidates), TARGET, None, None


def test_deep_ancestors_are_fully_validated_but_not_materialized():
    args = deep_ancestor_case()
    assert assert_differential(args)[0] == 'ok'
    _, rows = context._prefix(*args)
    assert max(len(row['ancestors']) for row in rows) >= 24


def test_full_prefix_and_build_review_context_remain_exact_and_skip_no_copy(monkeypatch):
    args = case('unreviewed')
    packet, plan, candidates, refs, target, _, current = args
    summary, rows = context._prefix(*args)
    expected = {'schema_version': 1, 'scope': context.REVIEW_SCOPE, 'focus_id': current,
        'source_binding': packet['source_binding'], 'target_profile_sha256': target,
        'focus_request_sha256': canonical_hash(plan['requests'][len(candidates) - 1]),
        'candidate_sha256': canonical_hash(candidates[-1]), 'prefix_check': summary,
        'owned_rows': [row for row in rows if row['focus_id'] == current], 'review_required': True, **context._FALSE}
    def forbidden(_): pytest.fail('Default full path checked summary eligibility')
    monkeypatch.setattr(context, '_index_cache_eligible', forbidden)
    actual = context.build_review_context(packet, plan, candidates, refs, expected_target_sha256=target, focus_id=current)
    assert actual == expected


def test_nonplain_inputs_fall_back_to_full_and_keep_original_error(monkeypatch):
    class NonPlain(list): pass
    args = list(case())
    args[2] = NonPlain(args[2])
    assert context._index_cache_eligible(list(args)) is False
    assert outcome(tuple(args), detailed=True) == outcome(tuple(args), detailed=False)
    for position, value in ((0, None), (1, 'not-plan'), (2, []), (3, True), (4, None)):
        malformed = list(case())
        malformed[position] = value
        assert outcome(tuple(malformed), detailed=True) == outcome(tuple(malformed), detailed=False)


def test_summary_eligibility_limits_fall_back_without_changing_full_result(monkeypatch):
    args = case()
    original, counts = context.deepcopy, []
    def counted(value): counts.append(1); return original(value)
    monkeypatch.setattr(context, 'deepcopy', counted)
    full = context._prefix(*args)[0]
    full_count = len(counts)
    counts.clear()
    monkeypatch.setattr(context, '_index_cache_eligible', lambda value: False)
    assert context._prefix(*args, materialize_rows=False)[0] == full
    assert len(counts) == full_count


def test_summary_copy_count_cpu_wall_measurement_is_synthetic_and_equivalent(tmp_path, monkeypatch, record_property):
    args = deep_ancestor_case(24)
    assert context._index_cache_eligible(list(args)) is True
    root = tmp_path / 'proof'
    root.mkdir()
    original, copies = context.deepcopy, []
    def counted(value): copies.append(1); return original(value)
    monkeypatch.setattr(context, 'deepcopy', counted)
    measurements = {}
    for name, detailed in [('full', True), ('summary', False)]:
        copies.clear()
        cpu, wall = time.process_time(), time.perf_counter()
        with scope.readonly_proof_scope(root):
            for _ in range(8): value = context._prefix(*args, materialize_rows=detailed)[0]
        measurements[name] = {'deepcopy_calls': len(copies), 'cpu_seconds': time.process_time() - cpu,
            'wall_seconds': time.perf_counter() - wall,
            'summary_sha256': hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
    assert measurements['full']['summary_sha256'] == measurements['summary']['summary_sha256']
    assert measurements['summary']['deepcopy_calls'] < measurements['full']['deepcopy_calls']
    record_property('synthetic_prefix_repetitions', 8)
    record_property('ancestor_depth', 24)
    record_property('summary_materialization_measurement', json.dumps(measurements, sort_keys=True))
