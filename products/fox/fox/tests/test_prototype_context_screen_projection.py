"""Authored synthetic fixtures only; no live-flow or prior approval proof."""
from copy import deepcopy

import pytest

from fox.forms_focus import build_focus_plan
from fox.forms_understanding_packet import local_packet
from fox.opaf import canonical_hash
from fox.prototype_design_context import REFERENCE_SCOPE
from fox.prototype_partition_review import build_partition_review_task
from fox import prototype_context_screen_projection as contract

TARGET = canonical_hash({'authored_target': 'not a deployed environment'})


def mapped_candidate(request):
    objects, screens, claims, actions = [], [], [], []
    for source in request['owned_objects']:
        row = {'source_object_id': source['id'], 'disposition': 'unresolved',
               'reason': 'Authored nonvisual metadata retained; not accepted behavior.'}
        if source['kind'] in ('Block', 'Item', 'Trigger'):
            block_id = source['id'] if source['kind'] == 'Block' else source['block_id']
            row.update(disposition='proposed', screen_id='screen-' + block_id)
        if source['kind'] == 'Block':
            row['native_component'] = 'form'
            screens.append({'id': row['screen_id'], 'title': 'Authored ' + source['name']})
        objects.append(row)
        for unit in request['code_units']:
            if unit['owner_id'] != source['id']:
                continue
            claim_id = request['focus_id'] + '-claim-' + str(len(claims))
            claims.append({'id': claim_id, 'source_object_id': source['id'],
                'kind': 'behavior.intent', 'status': 'proposal',
                'value': 'Authored interpretation awaiting independent review.',
                'evidence_refs': [unit['id']], 'reason': 'Complete authored body retained.'})
            actions.append({'id': claim_id + '-action', 'claim_ids': [claim_id]})
    return {'focus_id': request['focus_id'], 'focus_binding': request['focus_binding'],
        'blueprint': {'schema_version': 1, 'scope': 'fox-forms-blueprint-v1',
            'source_binding': request['source_binding'], 'objects': objects, 'screens': screens,
            'claims': claims, 'actions': actions, 'relationships': [],
            'questions': [{'id': request['focus_id'] + '-question',
                'source_object_id': request['owned_objects'][0]['id'], 'text': 'Authored unresolved question.'}],
            'assumptions': [{'id': request['focus_id'] + '-assumption',
                'scope': 'prototype-only', 'text': 'Authored assumption, not verified.'}]}}


def scenario(two_blocks=False):
    items = ''.join(f'<Item Name="V{i}" ItemType="Text Item" DatabaseItem="true"/>' for i in range(60))
    triggers = ''.join(f'<Trigger Name="T{i}" TriggerText="BEGIN NULL; END;"/>' for i in range(3))
    other = '<Block Name="OTHER" DatabaseBlock="true"/>' if two_blocks else ''
    body = ('<FormModule Name="AUTHORED"><Window Name="W"/><Canvas Name="C"/>' + other +
        '<Block Name="MAIN" DatabaseBlock="true">' + items + triggers + '</Block></FormModule>')
    docs = [('authored.xml', body.encode())]
    packet = local_packet(docs)
    plan = build_focus_plan(docs, expected_source_binding=packet['source_binding'],
        approved_chunk_hashes={row['id']: row['sha256'] for row in packet['chunks']}, max_owned_objects=32)
    candidates = [mapped_candidate(request) for request in plan['requests']]
    refs = {c['focus_id']: {'scope': REFERENCE_SCOPE, 'focus_id': c['focus_id'],
        'source_binding': packet['source_binding'], 'focus_request_sha256': canonical_hash(request),
        'candidate_sha256': canonical_hash(c), 'target_profile_sha256': TARGET,
        'proof_sha256': canonical_hash(['authored reference, not an approval', c['focus_id']])}
        for request, c in zip(plan['requests'][:-1], candidates[:-1], strict=True)}
    screen_id = candidates[-1]['blueprint']['objects'][0]['screen_id']
    declaration = next(s for c in candidates[:-1] for s in c['blueprint']['screens'] if s['id'] == screen_id)
    candidates[-1]['blueprint']['screens'].append(deepcopy(declaration))
    candidates[-1]['blueprint']['relationships'].append({
        'id': candidates[-1]['focus_id'] + '-relationship',
        'claim_ids': [candidates[-1]['blueprint']['claims'][0]['id']]})
    return packet, plan, candidates, refs


@pytest.fixture
def inputs():
    return scenario()


def pins(inputs):
    packet, plan, candidates, _ = inputs
    return {'expected_source_binding': packet['source_binding'],
        'expected_plan_sha256': canonical_hash(plan), 'expected_focus_id': candidates[-1]['focus_id'],
        'expected_request_sha256': canonical_hash(plan['requests'][len(candidates) - 1]),
        'expected_raw_candidate_sha256': canonical_hash(candidates[-1]), 'expected_target_sha256': TARGET}


def project(inputs, **extra):
    return contract.project_context_screens(*inputs, **{**pins(inputs), **extra})


def rebind_refs(inputs):
    _, plan, candidates, refs = inputs
    for request, candidate in zip(plan['requests'], candidates):
        if candidate['focus_id'] in refs:
            refs[candidate['focus_id']]['candidate_sha256'] = canonical_hash(candidate)
            refs[candidate['focus_id']]['focus_request_sha256'] = canonical_hash(request)


def test_exact_duplicate_changes_only_screens_and_passes_frozen_reviewer(inputs):
    before = deepcopy(inputs)
    candidate, receipt = project(inputs)
    expected = deepcopy(inputs[2][-1])
    expected['blueprint']['screens'] = []
    assert candidate == expected
    assert inputs == before
    assert receipt['schema_version'] == 1 and receipt['scope'] == contract.PROJECTION_SCOPE
    assert receipt['status'] == 'PROJECTED_UNREVIEWED'
    assert receipt['raw_candidate_sha256'] != receipt['candidate_sha256']
    removed = receipt['removed_screens'][0]
    assert removed['declaration'] == inputs[2][-1]['blueprint']['screens'][0]
    assert len(removed['current_reference_source_ids']) == 32
    assert [r['kind'] for r in inputs[1]['requests'][-1]['owned_objects']].count('Trigger') == 3
    assert removed['prior_reference'] == inputs[3][removed['prior_focus_id']]
    assert receipt['independent_review_required'] is True
    for key in ('ai_approval_granted', 'authority_granted', 'business_behavior_accepted',
                'historical_review_provenance_verified', 'native_apex_generated', 'import_verified'):
        assert receipt[key] is False
    assert contract.validate_context_screen_projection(candidate, receipt, *inputs, **pins(inputs)) == receipt
    task, _ = build_partition_review_task(inputs[0], inputs[1], [*inputs[2][:-1], candidate], inputs[3],
        expected_target_sha256=TARGET, expected_candidate_sha256=canonical_hash(candidate), review_context=receipt)
    assert task['independent_semantic_review_required'] is True


def test_no_duplicate_is_explicit_noop_and_projection_is_idempotent(inputs):
    candidate, _ = project(inputs)
    inputs[2][-1] = candidate
    before = deepcopy(inputs)
    again, receipt = project(inputs)
    assert again == candidate
    assert receipt['status'] == 'NO_CHANGE' and receipt['removed_screens'] == []
    assert receipt['raw_candidate_sha256'] == receipt['candidate_sha256']
    assert project(inputs) == (again, receipt)
    assert inputs == before
    again['blueprint']['objects'][0]['reason'] = 'Detached result'
    assert inputs == before


def test_owned_new_screen_is_retained_as_noop(inputs):
    packet, plan, candidates, refs = inputs
    index = next(i for i, r in enumerate(plan['requests']) if any(s['kind'] == 'Block' for s in r['owned_objects']))
    data = packet, plan, candidates[:index + 1], {k: v for k, v in refs.items()
        if k in {c['focus_id'] for c in candidates[:index]}}
    candidate, receipt = project(data)
    assert candidate == data[2][-1] and candidate['blueprint']['screens']
    assert receipt['status'] == 'NO_CHANGE'


@pytest.mark.parametrize('field', ['expected_source_binding', 'expected_plan_sha256',
    'expected_request_sha256', 'expected_raw_candidate_sha256', 'expected_target_sha256', 'expected_focus_id'])
def test_all_independent_pins_required_and_checked(inputs, field):
    with pytest.raises(ValueError, match='Invalid source-bound context screen projection'):
        project(inputs, **{field: 'f' * 64})


@pytest.mark.parametrize('mutation', ['title', 'id', 'duplicate-id', 'owned-block', 'unowned-ref',
    'missing-prior-binding', 'foreign-ref', 'future-owner', 'omitted-ancestor', 'missing-ancestor',
    'tampered-source', 'tampered-whole-unit', 'missing-behavior', 'missing-action', 'oversize',
    'owner-kind', 'owner-unresolved', 'prior-candidate-pin', 'prior-target', 'unused-duplicate'])
def test_ambiguous_or_unbound_input_rejected(inputs, mutation):
    packet, plan, candidates, refs = inputs
    raw, request = candidates[-1], plan['requests'][-1]
    if mutation == 'title': raw['blueprint']['screens'][0]['title'] = 'Conflicting title'
    elif mutation == 'id': raw['blueprint']['screens'][0]['id'] = 'screen-foreign'
    elif mutation == 'duplicate-id': raw['blueprint']['screens'] *= 2
    elif mutation == 'owned-block':
        # An owned Item cannot be reclassified or treated as the screen Block.
        request['owned_objects'][0]['kind'] = 'Block'
    elif mutation == 'unowned-ref':
        raw['blueprint']['objects'].append(deepcopy(candidates[0]['blueprint']['objects'][0]))
    elif mutation == 'missing-prior-binding': refs.pop(next(iter(refs)))
    elif mutation == 'foreign-ref': refs['future'] = deepcopy(next(iter(refs.values())))
    elif mutation == 'future-owner':
        candidates[:] = candidates[-1:]
        refs.clear()
    elif mutation == 'omitted-ancestor':
        candidates[0]['blueprint']['objects'][0]['disposition'] = 'omitted'
        rebind_refs(inputs)
    elif mutation == 'missing-ancestor': request['context_objects'].pop()
    elif mutation == 'tampered-source': packet['sources'][0]['facts']['objects'][0]['name'] = 'Tampered'
    elif mutation == 'tampered-whole-unit': request['chunks'][0]['text'] = 'BEGIN'
    elif mutation == 'missing-behavior': raw['blueprint']['claims'].pop()
    elif mutation == 'missing-action': raw['blueprint']['actions'].pop()
    elif mutation == 'oversize': raw['blueprint']['objects'][0]['reason'] = 'x' * 500_001
    elif mutation in ('owner-kind', 'owner-unresolved'):
        owner = next(r for c in candidates[:-1] for r in c['blueprint']['objects'] if 'native_component' in r)
        if mutation == 'owner-kind': owner['native_component'] = 'page-items'
        else:
            owner['disposition'] = 'unresolved'
            owner.pop('screen_id')
            owner.pop('native_component')
        rebind_refs(inputs)
    elif mutation == 'prior-candidate-pin': next(iter(refs.values()))['candidate_sha256'] = 'f' * 64
    elif mutation == 'prior-target': next(iter(refs.values()))['target_profile_sha256'] = 'f' * 64
    else:
        for row in raw['blueprint']['objects']:
            row.update(disposition='unresolved')
            row.pop('screen_id', None)
    with pytest.raises(ValueError, match='Invalid source-bound context screen projection'):
        project(inputs)


@pytest.mark.parametrize('kind', ['Item', 'Trigger'])
def test_other_source_block_screen_rejected_even_if_prior_owner_exists(kind):
    data = scenario(two_blocks=True)
    _, plan, candidates, _ = data
    source = next(r for r in plan['requests'][-1]['owned_objects'] if r['kind'] == kind)
    mapping = next(r for r in candidates[-1]['blueprint']['objects'] if r['source_object_id'] == source['id'])
    other = next(s for c in candidates[:-1] for s in c['blueprint']['screens'] if s['id'] != mapping['screen_id'])
    mapping['screen_id'] = other['id']
    candidates[-1]['blueprint']['screens'].append(deepcopy(other))
    with pytest.raises(ValueError): project(data)


def test_actual_owned_block_cannot_claim_prior_block_screen():
    packet, plan, candidates, refs = scenario(two_blocks=True)
    block_indices = [i for i, request in enumerate(plan['requests'])
        if any(row['kind'] == 'Block' for row in request['owned_objects'])]
    index = block_indices[-1]
    assert index > block_indices[0]
    prefix = candidates[:index + 1]
    prior = next(screen for c in candidates[:index] for screen in c['blueprint']['screens'])
    current = prefix[-1]['blueprint']
    block_mapping = next(row for row in current['objects'] if 'native_component' in row)
    block_mapping['screen_id'] = prior['id']
    current['screens'].append(deepcopy(prior))
    data = packet, plan, prefix, {key: value for key, value in refs.items()
        if key in {c['focus_id'] for c in prefix[:-1]}}
    with pytest.raises(ValueError): project(data)


def test_owner_moved_to_future_in_otherwise_rebound_plan_is_rejected(inputs):
    packet, plan, candidates, refs = inputs
    owner_index = next(i for i, c in enumerate(candidates[:-1]) if c['blueprint']['screens'])
    owner_request = plan['requests'].pop(owner_index)
    owner_candidate = candidates.pop(owner_index)
    plan['requests'].append(owner_request)
    refs.pop(owner_candidate['focus_id'])
    plan['plan_binding'] = canonical_hash({k: v for k, v in plan.items() if k != 'plan_binding'})
    with pytest.raises(ValueError): project(inputs)


@pytest.mark.parametrize('mutation', ['reason', 'claim', 'action', 'question', 'assumption', 'screen',
    'receipt-hash', 'receipt-owner', 'receipt-approval', 'receipt-version'])
def test_derived_candidate_or_receipt_tampering_rejected(inputs, mutation):
    candidate, receipt = project(inputs)
    bp = candidate['blueprint']
    if mutation == 'reason': bp['objects'][0]['reason'] = 'Changed business rationale'
    elif mutation == 'claim': bp['claims'][0]['value'] = 'Changed behavior'
    elif mutation == 'action': bp['actions'].pop()
    elif mutation == 'question': bp['questions'][0]['text'] = 'Changed question'
    elif mutation == 'assumption': bp['assumptions'][0]['text'] = 'Changed scope'
    elif mutation == 'screen': bp['screens'] = deepcopy(inputs[2][-1]['blueprint']['screens'])
    elif mutation == 'receipt-hash': receipt['candidate_sha256'] = 'f' * 64
    elif mutation == 'receipt-owner': receipt['removed_screens'][0]['owner_mapping']['reason'] = 'Forged'
    elif mutation == 'receipt-approval': receipt['ai_approval_granted'] = True
    else: receipt['schema_version'] = 2
    # Even self-rehashing the receipt cannot authorize a non-screen delta.
    if mutation in ('reason', 'claim', 'action', 'question', 'assumption', 'screen'):
        receipt['candidate_sha256'] = canonical_hash(candidate)
    with pytest.raises(ValueError):
        contract.validate_context_screen_projection(candidate, receipt, *inputs, **pins(inputs))


def test_receipt_and_result_do_not_alias_inputs(inputs):
    before = deepcopy(inputs)
    candidate, receipt = project(inputs)
    receipt['removed_screens'][0]['declaration']['title'] = 'Detached evidence'
    receipt['removed_screens'][0]['prior_reference']['proof_sha256'] = 'f' * 64
    candidate['blueprint']['questions'][0]['text'] = 'Detached candidate'
    assert inputs == before
