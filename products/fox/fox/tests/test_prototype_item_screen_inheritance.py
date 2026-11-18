"""Pure exact Item-screen completion; synthetic source, no model or file I/O."""
from copy import deepcopy

import pytest

from fox.forms_design_review import BLUEPRINT_SCOPE
from fox.forms_focus import build_focus_plan
from fox.forms_focus_merge import merge_focus_blueprints
from fox.forms_understanding_packet import local_packet
from fox.opaf import canonical_hash
from fox.prototype_focus_projection import source_fact_gate
from fox.prototype_item_screen_inheritance import POLICY, SCOPE, project, validate


def example(*, max_owned_objects=32, multi=False):
    raw = (b'<FormModule Name="SYNTHETIC"><Block Name="CTRL" DatabaseBlock="false">'
        b'<Item Name="ONE" ItemType="Text Item"/><Item Name="TWO" ItemType="Text Item"/>'
        b'<Trigger Name="CHECK" TriggerText="BEGIN APP.CHECK_VALUE(123); END;"/></Block>'
        b'<Block Name="OTHER" DatabaseBlock="false"><Item Name="THREE" ItemType="Text Item"/>'
        b'</Block></FormModule>')
    docs = [('first.xml', raw)]
    if multi:
        docs.append(('second.xml', raw.replace(b'SYNTHETIC', b'SECOND')))
    packet = local_packet(docs)
    plan = build_focus_plan(docs, expected_source_binding=packet['source_binding'],
        approved_chunk_hashes={row['id']: row['sha256'] for row in packet['chunks']},
        max_owned_objects=max_owned_objects)
    sources = {row['id']: row for entry in packet['sources'] for row in entry['facts']['objects']}
    responses = []
    for request in plan['requests']:
        rows, screens = [], []
        for source in request['owned_objects']:
            row = {'source_object_id': source['id'], 'disposition': 'unresolved',
                   'reason': 'Original synthetic design, not accepted business behavior.'}
            if source['kind'] == 'Block' and source['name'] == 'CTRL':
                screen = 'screen-' + source['id']
                row.update(disposition='proposed', screen_id=screen, native_component='page-items')
                screens.append({'id': screen, 'title': 'Original control screen'})
            if source['kind'] == 'Item' and sources[source['block_id']]['name'] == 'CTRL':
                row['disposition'] = 'proposed'  # Exact missing KEY, not null.
            rows.append(row)
        responses.append({'focus_id': request['focus_id'], 'focus_binding': request['focus_binding'],
            'blueprint': {'schema_version': 1, 'scope': BLUEPRINT_SCOPE,
                'source_binding': packet['source_binding'], 'objects': rows, 'screens': screens,
                'claims': [], 'actions': [], 'relationships': [], 'questions': [], 'assumptions': []}})
    return docs, packet, plan, responses


def control(plan, responses):
    request = next(row for row in plan['requests'] if any(
        source['kind'] == 'Block' and source['name'] == 'CTRL' for source in row['owned_objects']))
    response = next(row for row in responses if row['focus_id'] == request['focus_id'])
    source = next(row for row in request['owned_objects'] if row['kind'] == 'Block')
    block = next(row for row in response['blueprint']['objects'] if row['source_object_id'] == source['id'])
    item_ids = {row['id'] for row in request['owned_objects'] if row['kind'] == 'Item'}
    items = [row for row in response['blueprint']['objects'] if row['source_object_id'] in item_ids]
    return request, response, source, block, items


def test_two_absent_item_links_are_the_only_changes_and_old_merge_stays_strict():
    docs, packet, plan, responses = example()
    request, response, source, block, items = control(plan, responses)
    claim = {'id': 'original-claim', 'source_object_id': source['id'], 'kind': 'object.name',
        'value': source['name'], 'status': 'source_fact', 'evidence_refs': [source['id']],
        'reason': 'Exact original source observation.'}
    response['blueprint']['claims'] = [claim]
    response['blueprint']['actions'] = [{'id': 'original-action', 'claim_ids': [claim['id']]}]
    before = deepcopy((docs, plan, responses))
    for row in responses:
        source_fact_gate(packet, next(r for r in plan['requests'] if r['focus_id'] == row['focus_id']), row)
    with pytest.raises(ValueError, match='existing blueprint screen'):
        merge_focus_blueprints(docs, plan, responses)
    completed, receipt = project(docs, plan, responses)
    assert (docs, plan, responses) == before
    expected = deepcopy(responses)
    _, _, _, _, expected_items = control(plan, expected)
    for row in expected_items:
        row['screen_id'] = block['screen_id']
    assert completed == expected and len(receipt['changes']) == 2
    merged = merge_focus_blueprints(docs, plan, completed)
    assert merged['validation']['structured_blueprint_valid'] is True
    assert len(merged['validation']['supplied_code_unit_ids']) == 1
    assert merged['validation']['code_units_not_supplied'] == []
    assert receipt['schema_version'] == 1 and receipt['scope'] == SCOPE and receipt['policy'] == POLICY
    assert receipt['original_responses_sha256'] == canonical_hash(responses)
    assert receipt['completed_responses_sha256'] == canonical_hash(completed)
    assert receipt['plan_sha256'] == canonical_hash(plan)
    assert receipt['packet_sha256'] == canonical_hash(packet)
    assert receipt['merged_result_sha256'] == canonical_hash(merged)
    assert receipt['merged_blueprint_sha256'] == canonical_hash(merged['blueprint'])
    assert receipt['merge_validation'] == merged['validation']
    for change in receipt['changes']:
        assert 'screen_id' not in change['before']
        assert change['after'] == {**change['before'], 'screen_id': block['screen_id']}
        assert change['source_item']['parent_id'] == change['source_item']['block_id'] == source['id']
        assert change['source_block'] == source and change['block_mapping'] == block
        assert change['local_screen'] == response['blueprint']['screens'][0]
        assert change['before_row_sha256'] == canonical_hash(change['before'])
        assert change['after_row_sha256'] == canonical_hash(change['after'])
    for key in ('review_authority_granted', 'historical_reviews_relabelled', 'review_requirement_decided',
                'semantic_equivalence_attested', 'processing_consent_verified',
                'execution_authorized', 'business_behavior_accepted'):
        assert receipt[key] is False
    assert validate(docs, plan, responses, completed, receipt)
    with pytest.raises(ValueError): merge_focus_blueprints(docs, plan, responses)


def test_complete_valid_design_is_identity_without_completion_receipt():
    docs, _, plan, responses = example()
    completed, _ = project(docs, plan, responses)
    same, receipt = project(docs, plan, completed)
    assert same is completed and receipt is None
    assert validate(docs, plan, completed, completed, None)


def test_multiple_forms_preserve_exact_independent_source_parent_and_screen_links():
    docs, _, plan, responses = example(multi=True)
    completed, receipt = project(docs, plan, responses)
    assert len(receipt['changes']) == 4
    assert len({row['source_block_id'] for row in receipt['changes']}) == 2
    for row in receipt['changes']:
        assert row['source_item']['module_id'] == row['source_block']['module_id']
        assert row['after']['screen_id'] == row['block_mapping']['screen_id'] == row['local_screen']['id']
    assert merge_focus_blueprints(docs, plan, completed)['validation']['accounted_objects'] == plan['total_source_objects']


def test_response_order_is_preserved_without_changing_full_merge_result():
    docs, _, plan, responses = example()
    first, _ = project(docs, plan, responses)
    reversed_raw = list(reversed(responses))
    reversed_completed, receipt = project(docs, plan, reversed_raw)
    assert [row['focus_id'] for row in reversed_completed] == [row['focus_id'] for row in reversed_raw]
    assert merge_focus_blueprints(docs, plan, reversed_completed) == merge_focus_blueprints(docs, plan, first)
    assert receipt['original_responses_sha256'] == canonical_hash(reversed_raw)


@pytest.mark.parametrize('value', [None, 'unknown-screen', '', False])
def test_present_null_unknown_or_invalid_item_screen_key_is_never_overwritten(value):
    docs, _, plan, responses = example()
    items = control(plan, responses)[4]
    items[0]['screen_id'] = value
    with pytest.raises(ValueError): project(docs, plan, responses)


def test_present_declared_but_mismatched_item_link_is_never_replaced():
    docs, _, plan, responses = example()
    _, response, _, _, items = control(plan, responses)
    response['blueprint']['screens'].append({'id': 'different-screen', 'title': 'Existing different proposal'})
    items[0]['screen_id'] = 'different-screen'
    with pytest.raises(ValueError): project(docs, plan, responses)


@pytest.mark.parametrize('change', ['parent-unresolved', 'parent-omitted', 'parent-screen-missing',
    'parent-screen-null', 'parent-screen-unknown', 'component-missing', 'component-wrong',
    'item-component', 'local-screen-missing', 'local-screen-duplicate', 'global-screen-only',
    'source-collision-screen', 'missing-other-proposed-screen', 'omitted-ancestor',
    'invalid-source-fact', 'unknown-action-claim', 'global-duplicate-screen'])
def test_only_the_exact_redundant_links_may_complete_and_other_latent_defects_fail(change):
    docs, _, plan, responses = example()
    request, response, source, block, items = control(plan, responses)
    if change == 'parent-unresolved': block['disposition'] = 'unresolved'
    elif change == 'parent-omitted': block['disposition'] = 'omitted'
    elif change == 'parent-screen-missing': block.pop('screen_id')
    elif change == 'parent-screen-null': block['screen_id'] = None
    elif change == 'parent-screen-unknown': block['screen_id'] = 'unknown-screen'
    elif change == 'component-missing': block.pop('native_component')
    elif change == 'component-wrong': block['native_component'] = 'form'
    elif change == 'item-component': items[0]['native_component'] = 'page-items'
    elif change == 'local-screen-missing': response['blueprint']['screens'].clear()
    elif change == 'local-screen-duplicate': response['blueprint']['screens'] *= 2
    elif change == 'global-screen-only':
        other = next(row for row in responses if row is not response)
        other['blueprint']['screens'] = response['blueprint']['screens']
        response['blueprint']['screens'] = []
    elif change == 'source-collision-screen':
        block['screen_id'] = source['id']
        response['blueprint']['screens'][0]['id'] = source['id']
    elif change == 'missing-other-proposed-screen':
        trigger = next(row for row in request['owned_objects'] if row['kind'] == 'Trigger')
        next(row for row in response['blueprint']['objects'] if row['source_object_id'] == trigger['id'])['disposition'] = 'proposed'
    elif change == 'omitted-ancestor':
        module = next(row for row in plan['requests'] for row in row['owned_objects'] if row['kind'] == 'FormModule')
        next(row for response in responses for row in response['blueprint']['objects']
             if row['source_object_id'] == module['id'])['disposition'] = 'omitted'
    elif change == 'invalid-source-fact':
        response['blueprint']['claims'] = [{'id': 'bad-fact', 'source_object_id': source['id'],
            'kind': 'object.name', 'status': 'source_fact', 'value': 'Invented',
            'evidence_refs': [source['id']], 'reason': 'Invalid synthetic fact.'}]
    elif change == 'unknown-action-claim':
        response['blueprint']['actions'] = [{'id': 'bad-action', 'claim_ids': ['unknown-claim']}]
    else:
        other = next(row for row in responses if row is not response)
        other['blueprint']['screens'] = deepcopy(response['blueprint']['screens'])
    with pytest.raises(ValueError): project(docs, plan, responses)


def test_source_parent_must_be_owned_in_same_focus_even_when_global_screen_exists():
    docs, _, plan, responses = example(max_owned_objects=1)
    with pytest.raises(ValueError): project(docs, plan, responses)


def test_unresolved_items_remain_unchanged_when_original_full_merge_is_valid():
    docs, _, plan, responses = example()
    for row in control(plan, responses)[4]:
        row['disposition'] = 'unresolved'
    completed, receipt = project(docs, plan, responses)
    assert completed is responses and receipt is None


@pytest.mark.parametrize('change', ['stale-source', 'forged-parent', 'forged-block', 'stale-plan',
    'missing-focus', 'duplicate-focus', 'unknown-focus', 'duplicate-object', 'unknown-extra'])
def test_source_plan_and_complete_original_response_set_are_rebuilt(change):
    docs, _, plan, responses = example()
    request, response, _, _, _ = control(plan, responses)
    if change == 'stale-source': docs[0] = (docs[0][0], docs[0][1].replace(b'123', b'124'))
    elif change in ('forged-parent', 'forged-block'):
        item = next(row for row in request['owned_objects'] if row['kind'] == 'Item')
        item['parent_id' if change == 'forged-parent' else 'block_id'] = 'unknown-parent'
    elif change == 'stale-plan': plan['plan_binding'] = '0' * 64
    elif change == 'missing-focus': responses.pop()
    elif change == 'duplicate-focus': responses.append(deepcopy(responses[0]))
    elif change == 'unknown-focus': responses[0]['focus_id'] = 'unknown-focus'
    elif change == 'duplicate-object': response['blueprint']['objects'].append(deepcopy(response['blueprint']['objects'][0]))
    else: response['ready'] = True
    with pytest.raises(ValueError): project(docs, plan, responses)


@pytest.mark.parametrize('change', ['completed-screen', 'completed-reason', 'original-hash', 'completed-hash',
    'plan-hash', 'before-row', 'after-row', 'source-parent', 'block-mapping', 'local-screen',
    'merged-hash', 'validation', 'review-authority', 'policy', 'version', 'missing', 'extra'])
def test_all_completed_rows_and_receipt_evidence_are_rederived(change):
    docs, _, plan, responses = example()
    completed, receipt = project(docs, plan, responses)
    if change == 'completed-screen': control(plan, completed)[4][0]['screen_id'] = 'different'
    elif change == 'completed-reason': control(plan, completed)[4][0]['reason'] = 'Changed rationale'
    elif change == 'original-hash': receipt['original_responses_sha256'] = '0' * 64
    elif change == 'completed-hash': receipt['completed_responses_sha256'] = '0' * 64
    elif change == 'plan-hash': receipt['plan_sha256'] = '0' * 64
    elif change == 'before-row': receipt['changes'][0]['before']['screen_id'] = 'injected'
    elif change == 'after-row': receipt['changes'][0]['after']['screen_id'] = 'different'
    elif change == 'source-parent': receipt['changes'][0]['source_item']['parent_id'] = 'different'
    elif change == 'block-mapping': receipt['changes'][0]['block_mapping']['native_component'] = 'form'
    elif change == 'local-screen': receipt['changes'][0]['local_screen']['title'] = 'Different screen'
    elif change == 'merged-hash': receipt['merged_result_sha256'] = '0' * 64
    elif change == 'validation': receipt['merge_validation']['business_behavior_accepted'] = True
    elif change == 'review-authority': receipt['review_authority_granted'] = True
    elif change == 'policy': receipt['policy'] = 'unknown'
    elif change == 'version': receipt['schema_version'] = True
    elif change == 'missing': receipt = None
    else: receipt['approved'] = True
    with pytest.raises(ValueError): validate(docs, plan, responses, completed, receipt)


def test_completed_responses_and_receipt_do_not_alias_original_sources_or_candidates():
    docs, _, plan, responses = example()
    before = deepcopy((docs, plan, responses))
    completed, receipt = project(docs, plan, responses)
    control(plan, completed)[4][0]['reason'] = 'Local change'
    receipt['changes'][0]['block_mapping']['reason'] = 'Local change'
    receipt['changes'][0]['before']['reason'] = 'Local change'
    assert (docs, plan, responses) == before


@pytest.mark.parametrize('change', ['object', 'deep', 'oversized'])
def test_plain_json_is_bounded_before_any_completion(change):
    docs, _, plan, responses = example()
    if change == 'object': responses[0]['blueprint']['objects'][0]['reason'] = object()
    elif change == 'oversized': responses[0]['blueprint']['objects'][0]['reason'] = 'x' * 500_001
    else:
        nested = responses[0]
        for _ in range(150):
            nested['extra'] = {}
            nested = nested['extra']
    with pytest.raises(ValueError): project(docs, plan, responses)
