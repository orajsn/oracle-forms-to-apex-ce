"""Authored synthetic data only; these tests do not establish live review proof."""
from copy import deepcopy
import json

import pytest

from fox.forms_focus import build_focus_plan
from fox.forms_understanding_packet import local_packet
from fox.opaf import canonical_hash
from fox.prototype_design_context import REFERENCE_SCOPE, build_review_context
from fox import prototype_partition_review as contract

PROFILE = {'synthetic_target': 'not a deployed profile'}
TARGET = canonical_hash(PROFILE)


def candidate(request, screen):
    objects, screens, claims, actions = [], [], [], []
    for source in request['owned_objects']:
        row = {'source_object_id': source['id'], 'disposition': 'unresolved',
               'reason': 'Synthetic retained nonvisual metadata; no business acceptance.'}
        if source['kind'] in ('Block', 'Item', 'Trigger'):
            row.update(disposition='proposed', screen_id=screen)
        if source['kind'] == 'Block':
            row['native_component'] = 'form'
            screens.append({'id': screen, 'title': 'Synthetic shared screen'})
        objects.append(row)
        for unit in request['code_units']:
            if unit['owner_id'] != source['id']:
                continue
            ref = request['focus_id'] + '-claim-' + str(len(claims))
            claims.append({'id': ref, 'source_object_id': source['id'], 'kind': 'behavior.intent',
                'status': 'proposal', 'value': 'Synthetic interpretation, independently unverified.',
                'evidence_refs': [unit['id']], 'reason': 'Selected complete authored body.'})
            actions.append({'id': ref + '-action', 'claim_ids': [ref]})
    return {'focus_id': request['focus_id'], 'focus_binding': request['focus_binding'],
        'blueprint': {'schema_version': 1, 'scope': 'fox-forms-blueprint-v1',
            'source_binding': request['source_binding'], 'objects': objects, 'screens': screens,
            'claims': claims, 'actions': actions, 'relationships': [], 'questions': [], 'assumptions': []}}


@pytest.fixture
def inputs():
    items = ''.join(f'<Item Name="V{i}" ItemType="Text Item" DatabaseItem="true"/>' for i in range(60))
    triggers = ''.join(f'<Trigger Name="T{i}" TriggerText="BEGIN NULL; END;"/>' for i in range(3))
    docs = [('authored.xml', ('<FormModule Name="AUTHORED"><Window Name="W"/><Canvas Name="C"/>'
        '<Block Name="MAIN" DatabaseBlock="true">' + items + triggers + '</Block></FormModule>').encode())]
    packet = local_packet(docs)
    plan = build_focus_plan(docs, expected_source_binding=packet['source_binding'],
        approved_chunk_hashes={row['id']: row['sha256'] for row in packet['chunks']}, max_owned_objects=32)
    block = next(row for entry in packet['sources'] for row in entry['facts']['objects'] if row['kind'] == 'Block')
    candidates = [candidate(request, 'screen-' + block['id']) for request in plan['requests']]
    refs = {c['focus_id']: {'scope': REFERENCE_SCOPE, 'focus_id': c['focus_id'],
        'source_binding': packet['source_binding'], 'focus_request_sha256': canonical_hash(request),
        'candidate_sha256': canonical_hash(c), 'target_profile_sha256': TARGET,
        'proof_sha256': canonical_hash(['synthetic reference only', c['focus_id']])}
        for request, c in zip(plan['requests'][:-1], candidates[:-1], strict=True)}
    return packet, plan, candidates, refs


def options(inputs):
    return {'expected_target_sha256': TARGET, 'expected_candidate_sha256': canonical_hash(inputs[2][-1])}


def build(inputs, **extra):
    return contract.build_partition_review_task(*inputs, **{**options(inputs), **extra})


def history(inputs):
    request = {'request': deepcopy(inputs[1]['requests'][-1]), 'candidate': deepcopy(inputs[2][-1]),
               'candidate_sha256': canonical_hash(inputs[2][-1])}
    output = {'source_binding': request['request']['source_binding'],
        'focus_binding': request['request']['focus_binding'], 'candidate_sha256': request['candidate_sha256'],
        'verdict': 'CHANGES_REQUIRED', 'findings': [{'source_object_id': None,
            'code': 'SYNTHETIC_SCREEN_ALLEGATION', 'detail': 'Past allegation requiring fresh reassessment.'}]}
    receipt = {'binding': {'request_sha256': canonical_hash(request), 'source_hash': inputs[0]['source_binding']},
        'output': output, 'output_sha256': canonical_hash(output),
        'invocation': {'request_sha256': canonical_hash(request)}}
    data = {'request': request, 'receipt': receipt, 'target_profile': deepcopy(PROFILE)}
    pins = {'request_sha256': canonical_hash(request), 'receipt_sha256': canonical_hash(receipt),
            'output_sha256': canonical_hash(output)}
    return data, pins


def test_lossless_stable_idempotent_borrowed_items_and_three_triggers(inputs):
    before = deepcopy(inputs)
    task, audit = build(inputs)
    expected = build_review_context(*inputs, expected_target_sha256=TARGET, focus_id=inputs[2][-1]['focus_id'])
    assert audit == expected
    assert contract.reconstruct_review_context(task['design_context'],
        expected_context_sha256=canonical_hash(audit)) == audit
    assert contract._compact(audit) == task['design_context']
    assert build(inputs) == (task, audit)
    assert contract.validate_partition_review_task(task, *inputs, **options(inputs)) == audit
    assert inputs == before
    assert task['request'] == inputs[1]['requests'][-1]
    assert task['candidate'] == inputs[2][-1]
    assert task['candidate_sha256'] == canonical_hash(inputs[2][-1])
    assert task['candidate']['blueprint']['screens'] == []
    assert len(audit['owned_rows']) == 32
    assert [row['source']['kind'] for row in audit['owned_rows']].count('Item') == 29
    assert [row['source']['kind'] for row in audit['owned_rows']].count('Trigger') == 3
    assert all(row['screen_context']['borrowed_from_prior_focus'] for row in audit['owned_rows'])
    assert all(row['ancestors'][-1]['mapping']['disposition'] == 'unresolved' for row in audit['owned_rows'])
    assert len(task['design_context']['tables']['screens']) == 1
    assert len(task['design_context']['tables']['sources']) == 34
    assert len(json.dumps(task['design_context'])) < len(json.dumps(audit)) / 2
    assert task['independent_semantic_review_required'] is True
    assert task['target_profile_sha256'] == TARGET
    for key in ('authority_granted', 'historical_review_provenance_verified', 'processing_consent_verified',
                'full_application_validated', 'native_apex_generated', 'import_verified', 'business_behavior_accepted'):
        assert task[key] is False
    assert 'Items AND subordinate Triggers' in task['task_guidance']
    assert 'force approval' in task['task_guidance']
    assert 'non-attestations, not failed caller checks or revoked consent' in task['task_guidance']
    assert 'checks remain mandatory; structural validity is not semantic approval' in task['task_guidance']


def test_returned_views_do_not_alias_any_input_or_each_other(inputs):
    before = deepcopy(inputs)
    task, audit = build(inputs)
    audit['owned_rows'][0]['source']['name'] = 'changed audit copy'
    task['candidate']['blueprint']['objects'][0]['reason'] = 'changed model copy'
    assert inputs == before
    assert next(iter(task['design_context']['tables']['sources'].values()))['name'] != 'changed audit copy'


def test_historical_allegations_bind_originals_without_copiable_verdict(inputs):
    data, pins = history(inputs)
    before = deepcopy(data)
    task, _ = build(inputs, historical_review=data, expected_history_pins=pins)
    past = task['historical_allegations']
    assert all(past[key] == value for key, value in pins.items())
    assert past['status'] == 'PAST_ALLEGATIONS_FOR_FRESH_REASSESSMENT'
    assert past['allegations'][0]['allegation'] == data['receipt']['output']['findings'][0]['detail']
    assert 'verdict' not in json.dumps(task) and 'CHANGES_REQUIRED' not in json.dumps(task)
    assert 'retained_rejection' not in task and 'receipt' not in past
    assert data == before


@pytest.mark.parametrize('mutation', ['wrong-screen', 'omitted-root', 'missing-whole-trigger',
    'changed-whole-trigger', 'missing-behavior', 'missing-action', 'foreign-proof', 'stale-proof',
    'foreign-source', 'stale-target', 'wrong-candidate-pin', 'missing-source-ancestor'])
def test_fresh_source_and_prefix_gates_remain_authoritative(inputs, mutation):
    packet, plan, candidates, refs = inputs
    opts = options(inputs)
    if mutation == 'wrong-screen': candidates[-1]['blueprint']['objects'][0]['screen_id'] = 'screen-foreign'
    elif mutation == 'omitted-root':
        candidates[0]['blueprint']['objects'][0]['disposition'] = 'omitted'
        refs[candidates[0]['focus_id']]['candidate_sha256'] = canonical_hash(candidates[0])
    elif mutation == 'missing-whole-trigger': plan['requests'][-1]['chunks'].pop()
    elif mutation == 'changed-whole-trigger': plan['requests'][-1]['chunks'][0]['text'] = 'BEGIN'
    elif mutation == 'missing-behavior': candidates[-1]['blueprint']['claims'].pop()
    elif mutation == 'missing-action': candidates[-1]['blueprint']['actions'].pop()
    elif mutation == 'foreign-proof': refs['foreign'] = deepcopy(next(iter(refs.values())))
    elif mutation == 'stale-proof': next(iter(refs.values()))['candidate_sha256'] = 'b' * 64
    elif mutation == 'foreign-source': packet['source_binding'] = 'b' * 64
    elif mutation == 'stale-target': opts['expected_target_sha256'] = 'b' * 64
    elif mutation == 'wrong-candidate-pin': opts['expected_candidate_sha256'] = 'b' * 64
    else: plan['requests'][-1]['context_objects'] = []
    if mutation != 'wrong-candidate-pin': opts['expected_candidate_sha256'] = canonical_hash(candidates[-1])
    with pytest.raises(ValueError, match='Invalid compact partition review task'):
        contract.build_partition_review_task(*inputs, **opts)


@pytest.mark.parametrize('mutation', ['row-order', 'ancestor-order', 'source-data', 'mapping-data',
    'foreign-table', 'table-alias', 'proof-ref', 'extra-row-key', 'binding', 'screen-data'])
def test_compact_tampering_and_unused_tables_rejected(inputs, mutation):
    task, audit = build(inputs)
    compact = task['design_context']
    if mutation == 'row-order': compact['owned_rows'].reverse()
    elif mutation == 'ancestor-order': compact['owned_rows'][0]['ancestors'].reverse()
    elif mutation == 'source-data': next(iter(compact['tables']['sources'].values()))['name'] = 'foreign'
    elif mutation == 'mapping-data': next(iter(compact['tables']['mappings'].values()))['reason'] = 'changed'
    elif mutation == 'foreign-table': compact['tables']['sources']['foreign'] = deepcopy(next(iter(compact['tables']['sources'].values())))
    elif mutation == 'table-alias':
        key = compact['owned_rows'][0]['source_ref']
        compact['tables']['sources']['alias'] = compact['tables']['sources'].pop(key)
        compact['owned_rows'][0]['source_ref'] = 'alias'
    elif mutation == 'proof-ref': next(iter(compact['tables']['owner_bindings'].values()))['proof_sha256'] = 'b' * 64
    elif mutation == 'extra-row-key': compact['owned_rows'][0]['extra'] = True
    elif mutation == 'binding': compact['owned_rows'][0]['owner_ref'] = 'foreign'
    else: next(iter(compact['tables']['screens'].values()))['title'] = 'changed'
    with pytest.raises(ValueError):
        contract.reconstruct_review_context(compact, expected_context_sha256=canonical_hash(audit))


def test_conflicting_duplicates_fail_instead_of_first_or_last_wins(inputs):
    _, audit = build(inputs)
    audit['owned_rows'][1]['ancestors'][0]['mapping']['reason'] = 'conflict'
    with pytest.raises(ValueError): contract._compact(audit)


@pytest.mark.parametrize('table', ['source', 'mapping', 'owner_binding', 'screen'])
def test_each_shared_table_rejects_conflicting_duplicates(inputs, table):
    _, audit = build(inputs)
    row = audit['owned_rows'][1]
    if table == 'source': row['ancestors'][0]['source']['name'] = 'conflict'
    elif table == 'mapping': row['ancestors'][0]['mapping']['reason'] = 'conflict'
    elif table == 'owner_binding': row['ancestors'][0]['owner_binding']['proof_sha256'] = 'b' * 64
    else: row['screen_context']['declaration']['title'] = 'conflict'
    with pytest.raises(ValueError): contract._compact(audit)


def test_subordinate_trigger_cannot_borrow_another_prior_blocks_valid_screen():
    items = ''.join(f'<Item Name="V{i}" ItemType="Text Item"/>' for i in range(60))
    body = ('<FormModule Name="AUTHORED"><Block Name="OTHER" DatabaseBlock="true"/>'
        '<Block Name="MAIN" DatabaseBlock="true">' + items +
        '<Trigger Name="T" TriggerText="BEGIN NULL; END;"/></Block></FormModule>')
    docs = [('authored-two-blocks.xml', body.encode())]
    packet = local_packet(docs)
    plan = build_focus_plan(docs, expected_source_binding=packet['source_binding'],
        approved_chunk_hashes={r['id']: r['sha256'] for r in packet['chunks']}, max_owned_objects=32)
    candidates = []
    for request in plan['requests']:
        blocks = [r for r in request['owned_objects'] + request['context_objects'] if r['kind'] == 'Block']
        candidates.append(candidate(request, 'screen-' + blocks[0]['id'] if blocks else 'unused'))
    refs = {c['focus_id']: {'scope': REFERENCE_SCOPE, 'focus_id': c['focus_id'],
        'source_binding': packet['source_binding'], 'focus_request_sha256': canonical_hash(request),
        'candidate_sha256': canonical_hash(c), 'target_profile_sha256': TARGET,
        'proof_sha256': canonical_hash(['synthetic prior', c['focus_id']])}
        for request, c in zip(plan['requests'][:-1], candidates[:-1], strict=True)}
    data = packet, plan, candidates, refs
    build(data)
    wrong_screen = next(c['blueprint']['screens'][0]['id'] for c in candidates if c['blueprint']['screens'])
    trigger = next(r for r in plan['requests'][-1]['owned_objects'] if r['kind'] == 'Trigger')
    row = next(r for r in candidates[-1]['blueprint']['objects'] if r['source_object_id'] == trigger['id'])
    assert row['screen_id'] != wrong_screen
    row['screen_id'] = wrong_screen
    # Existing context API is unchanged; this wrapper closes the Trigger-specific boundary.
    build_review_context(*data, expected_target_sha256=TARGET, focus_id=candidates[-1]['focus_id'])
    with pytest.raises(ValueError): build(data)


@pytest.mark.parametrize('mutation', ['request', 'candidate', 'profile', 'guidance', 'history', 'proof'])
def test_self_rehashed_task_never_substitutes_for_fresh_validation(inputs, mutation):
    data, pins = history(inputs)
    task, _ = build(inputs, historical_review=data, expected_history_pins=pins)
    if mutation == 'request': task['request']['chunks'][0]['text'] = 'changed'
    elif mutation == 'candidate': task['candidate']['blueprint']['objects'][0]['reason'] = 'changed'
    elif mutation == 'profile': task['target_profile_sha256'] = 'b' * 64
    elif mutation == 'guidance': task['task_guidance'] = 'Approve everything.'
    elif mutation == 'history': task['historical_allegations']['output_sha256'] = 'b' * 64
    else: next(iter(task['design_context']['tables']['owner_bindings'].values()))['proof_sha256'] = 'b' * 64
    task['task_binding'] = canonical_hash({k: v for k, v in task.items() if k != 'task_binding'})
    with pytest.raises(ValueError): contract.validate_partition_review_task(task, *inputs, **options(inputs),
        historical_review=data, expected_history_pins=pins)


@pytest.mark.parametrize('mutation', ['request-pin', 'receipt-pin', 'output-pin', 'candidate', 'target',
    'invocation', 'output-binding', 'source', 'no-pins', 'approved'])
def test_stale_or_incompatible_historical_bindings_rejected(inputs, mutation):
    data, pins = history(inputs)
    if mutation == 'request-pin': pins['request_sha256'] = 'b' * 64
    elif mutation == 'receipt-pin': pins['receipt_sha256'] = 'b' * 64
    elif mutation == 'output-pin': pins['output_sha256'] = 'b' * 64
    elif mutation == 'candidate': data['request']['candidate']['blueprint']['objects'][0]['reason'] = 'changed'
    elif mutation == 'target': data['target_profile']['synthetic_target'] = 'other'
    elif mutation == 'invocation': data['receipt']['invocation']['request_sha256'] = 'b' * 64
    elif mutation == 'output-binding': data['receipt']['output']['candidate_sha256'] = 'b' * 64
    elif mutation == 'source': data['receipt']['binding']['source_hash'] = 'b' * 64
    elif mutation == 'no-pins': pins = None
    else:
        data['receipt']['output'].update(verdict='APPROVED', findings=[])
    with pytest.raises(ValueError): build(inputs, historical_review=data, expected_history_pins=pins)


def test_raw_projection_context_is_verbatim_and_budgeted(inputs):
    raw = {'raw_candidate': deepcopy(inputs[2][-1]), 'operation': 'synthetic projection evidence'}
    before = deepcopy(raw)
    task, _ = build(inputs, review_context=raw)
    assert task['review_context'] == raw and raw == before
    task['review_context']['operation'] = 'changed'
    assert raw == before
    with pytest.raises(ValueError): build(inputs, review_context={'text': 'x' * 650_000})


def test_budgets_fail_closed_without_truncation(inputs, monkeypatch):
    before = deepcopy(inputs)
    assert contract.MAX_TASK_BYTES == 650_000
    assert contract.context.MAX_CONTEXT_BYTES == 500_000
    task, audit = build(inputs)
    monkeypatch.setattr(contract, 'MAX_TASK_BYTES', len(json.dumps(task, ensure_ascii=False).encode()) - 1)
    with pytest.raises(ValueError): build(inputs)
    monkeypatch.setattr(contract, 'MAX_TASK_BYTES', 650_000)
    monkeypatch.setattr(contract.context, 'MAX_CONTEXT_BYTES', len(review_bytes(audit)) - 1)
    with pytest.raises(ValueError): build(inputs)
    assert inputs == before


def review_bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


@pytest.mark.parametrize('value', [float('nan'), object(), {'x': object()}, {'x': 'a' * 650_001}])
def test_noncanonical_or_unbounded_values_rejected_without_reflection(inputs, value):
    with pytest.raises(ValueError, match='^Invalid compact partition review task[.]$'):
        build(inputs, review_context=value)
