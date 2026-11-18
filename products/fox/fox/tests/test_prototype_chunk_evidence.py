"""Small synthetic evidence projections; no files, model or Oracle operations."""
from copy import deepcopy

import pytest

from fox.forms_design_review import BLUEPRINT_SCOPE
from fox.forms_focus import build_focus_plan
from fox.forms_understanding_packet import local_packet
from fox.opaf import canonical_hash
from fox.prototype_candidate_format import normalize_candidate
from fox.prototype_chunk_evidence import (POLICY, SCOPE, project_chunk_evidence,
                                          validate_chunk_evidence)
from fox.prototype_focus_projection import source_fact_gate


def example():
    docs = [('synthetic.xml', b'<FormModule Name="SYNTHETIC"><Block Name="MAIN" '
        b'WhereClause="FLAG = 123" OrderByClause="ITEM_ID DESC">'
        b'<Item Name="FIELD_A" ItemType="Text Item"/>'
        b'<Trigger Name="SAVE" TriggerText="BEGIN APP.SAVE(123); END;"/>'
        b'</Block><Block Name="OTHER"><Trigger Name="OTHER_SAVE" '
        b'TriggerText="BEGIN APP.OTHER_SAVE(456); END;"/></Block></FormModule>')]
    packet = local_packet(docs)
    selected = {row['id']: row['sha256'] for row in packet['chunks']}
    plan = build_focus_plan(docs, expected_source_binding=packet['source_binding'],
                            approved_chunk_hashes=selected, max_owned_objects=32)
    request = next(row for row in plan['requests'] if any(o['name'] == 'MAIN' for o in row['owned_objects']))
    trigger = next(row for row in request['owned_objects'] if row['kind'] == 'Trigger')
    item = next(row for row in request['owned_objects'] if row['kind'] == 'Item')
    block = next(row for row in request['owned_objects'] if row['kind'] == 'Block')
    chunks = {row['code_unit_id']: row for row in request['chunks']}
    trigger_unit = next(row for row in request['code_units'] if row['owner_id'] == trigger['id'])
    block_units = [row for row in request['code_units'] if row['owner_id'] == block['id']]
    claims = [{'id': 'save-intent', 'source_object_id': trigger['id'], 'kind': 'behavior.intent',
        'status': 'proposal', 'value': 'Retain the proposed save intent with value 123.',
        'reason': 'Synthetic source interpretation needs independent review.',
        'evidence_refs': [trigger['id'], trigger_unit['id']]},
        {'id': 'block-intent', 'source_object_id': block['id'], 'kind': 'behavior.intent',
        'status': 'unresolved', 'value': 'Filtering and ordering remain uncertain.',
        'reason': 'Original business decision is unresolved.',
        'evidence_refs': [block['id'], *[row['id'] for row in block_units]]},
        {'id': 'item-type', 'source_object_id': item['id'], 'kind': 'item.item_type',
        'status': 'source_fact', 'value': item['item_type'], 'reason': 'Exact original metadata.',
        'evidence_refs': [item['id']]}]
    expected = {'focus_id': request['focus_id'], 'focus_binding': request['focus_binding'],
        'blueprint': {'schema_version': 1, 'scope': BLUEPRINT_SCOPE,
            'source_binding': request['source_binding'], 'objects': [
                {'source_object_id': row['id'], 'disposition': 'unresolved', 'reason': 'Needs review.'}
                for row in request['owned_objects']], 'screens': [], 'claims': claims,
            'actions': [{'id': 'save-action', 'claim_ids': ['save-intent']}],
            'relationships': [], 'questions': [], 'assumptions': []}}
    raw = deepcopy(expected)
    for claim in raw['blueprint']['claims'][:2]:
        claim['evidence_refs'] = [chunks[ref]['id'] if ref in chunks else ref for ref in claim['evidence_refs']]
    return docs, packet, request, expected, raw


def rebind(request, *candidates):
    request['focus_binding'] = canonical_hash({key: value for key, value in request.items() if key != 'focus_binding'})
    for candidate in candidates:
        candidate['focus_binding'] = request['focus_binding']


def test_exact_projection_preserves_raw_source_and_every_unrelated_field():
    docs, packet, request, expected, raw = example()
    original = deepcopy((docs, request, raw))
    with pytest.raises(ValueError): source_fact_gate(packet, request, raw)
    candidate, receipt = project_chunk_evidence(docs, request, raw)
    assert candidate == expected and (docs, request, raw) == original
    assert source_fact_gate(packet, request, candidate)['source_facts_checked'] is True
    assert receipt['policy'] == POLICY and receipt['scope'] == SCOPE and receipt['schema_version'] == 1
    assert len(receipt['changes']) == 2
    assert sum(len(row['mappings']) for row in receipt['changes']) == 3
    assert receipt['raw_candidate_sha256'] == canonical_hash(raw)
    assert receipt['candidate_sha256'] == canonical_hash(candidate)
    assert receipt['packet_sha256'] == canonical_hash(packet)
    assert receipt['request_sha256'] == canonical_hash(request)
    assert receipt['independent_review_required'] is True
    for key in ('processing_consent_verified', 'semantic_equivalence_attested',
                'execution_authorized', 'business_behavior_accepted'):
        assert receipt[key] is False
    for change in receipt['changes']:
        index = change['path'][2]
        assert change['before'] == raw['blueprint']['claims'][index]['evidence_refs']
        assert change['after'] == candidate['blueprint']['claims'][index]['evidence_refs']
        assert change['before_claim_sha256'] == canonical_hash(raw['blueprint']['claims'][index])
        assert change['after_claim_sha256'] == canonical_hash(candidate['blueprint']['claims'][index])
        for mapping in change['mappings']:
            chunk = next(row for row in request['chunks'] if row['id'] == mapping['before'])
            assert mapping['after'] == chunk['code_unit_id']
            assert mapping['code_unit_sha256'] == chunk['sha256']
    assert validate_chunk_evidence(docs, request, raw, candidate, receipt) is True


def test_canonical_identity_and_existing_format_policy_remain_unchanged():
    docs, _, request, expected, raw = example()
    candidate, receipt = project_chunk_evidence(docs, request, expected)
    assert candidate is expected and receipt is None
    assert validate_chunk_evidence(docs, request, expected, expected, None)
    with pytest.raises(ValueError): normalize_candidate(docs, request, raw)


@pytest.mark.parametrize('change', ['unknown', 'context-chunk', 'other-owner', 'context-owner',
    'missing-owner', 'duplicate-ref', 'post-duplicate', 'wrong-kind', 'source-fact-status',
    'extra-envelope', 'extra-claim-field', 'duplicate-claim', 'colliding-claim', 'cross-category-id',
    'changed-source-fact', 'changed-source-fact-type', 'source-fact-chunk', 'stale-source',
    'source-binding', 'focus-binding', 'blueprint-binding'])
def test_unknown_unselected_wrong_owner_duplicate_and_nonmechanical_inputs_fail(change):
    docs, packet, request, _, raw = example()
    claim = raw['blueprint']['claims'][0]
    if change == 'unknown': claim['evidence_refs'][1] = 'fup1-' + '0' * 64
    elif change == 'context-chunk':
        claim['evidence_refs'][1] = next(row['id'] for row in packet['chunks']
            if row['id'] not in {chunk['id'] for chunk in request['chunks']})
    elif change == 'other-owner': claim['evidence_refs'][1] = raw['blueprint']['claims'][1]['evidence_refs'][1]
    elif change == 'context-owner': claim['source_object_id'] = request['context_objects'][0]['id']
    elif change == 'missing-owner': claim['evidence_refs'].pop(0)
    elif change == 'duplicate-ref': claim['evidence_refs'].append(claim['evidence_refs'][1])
    elif change == 'post-duplicate':
        chunk = next(row for row in request['chunks'] if row['id'] == claim['evidence_refs'][1])
        claim['evidence_refs'].append(chunk['code_unit_id'])
    elif change == 'wrong-kind': claim['kind'] = 'object.name'
    elif change == 'source-fact-status': claim['status'] = 'source_fact'
    elif change == 'extra-envelope': raw['source_binding'] = request['source_binding']
    elif change == 'extra-claim-field': claim['ready'] = True
    elif change == 'duplicate-claim': raw['blueprint']['claims'].append(deepcopy(claim))
    elif change == 'colliding-claim': claim['id'] = claim['source_object_id']
    elif change == 'cross-category-id': raw['blueprint']['actions'][0]['id'] = claim['id']
    elif change == 'changed-source-fact': raw['blueprint']['claims'][2]['value'] = 'Invented widget'
    elif change == 'changed-source-fact-type': raw['blueprint']['claims'][2]['value'] = True
    elif change == 'source-fact-chunk': raw['blueprint']['claims'][2]['evidence_refs'].append(claim['evidence_refs'][1])
    elif change == 'stale-source': docs[0] = (docs[0][0], docs[0][1].replace(b'123', b'124'))
    elif change == 'source-binding': request['source_binding'] = '0' * 64
    elif change == 'focus-binding': request['focus_binding'] = '0' * 64
    else: raw['blueprint']['source_binding'] = '0' * 64
    with pytest.raises(ValueError): project_chunk_evidence(docs, request, raw)


@pytest.mark.parametrize('change', ['text', 'hash', 'unit', 'owner', 'chunk-id', 'duplicate-chunk',
    'unit-hash', 'unit-owner', 'metadata', 'selection', 'selected-context'])
def test_resealed_request_must_rebuild_from_original_source_and_exact_selection(change):
    docs, packet, request, _, raw = example()
    chunk = request['chunks'][0]
    if change == 'text': chunk['text'] += ' '
    elif change == 'hash': chunk['sha256'] = '0' * 64
    elif change == 'unit': chunk['code_unit_id'] = request['chunks'][-1]['code_unit_id']
    elif change == 'owner': request['owned_objects'][-1]['parent_id'] = None
    elif change == 'chunk-id': chunk['id'] = 'fup1-' + '0' * 64
    elif change == 'duplicate-chunk': request['chunks'].append(deepcopy(chunk))
    elif change == 'unit-hash': request['code_units'][0]['sha256'] = '0' * 64
    elif change == 'unit-owner': request['code_units'][0]['owner_id'] = request['owned_objects'][-1]['id']
    elif change == 'metadata': request['owned_objects'][-1]['name'] = 'Invented'
    elif change == 'selected-context':
        foreign = next(row for row in packet['chunks'] if row['id'] not in {r['id'] for r in request['chunks']})
        request['chunks'].append({**foreign, 'text': 'Invented'})
    else:
        # Removing a valid selected chunk creates a valid narrower request. The
        # raw candidate still cannot cite that now-unselected chunk.
        removed = request['chunks'].pop(0)
        request['unselected_code_unit_ids'] = [removed['code_unit_id']]
    rebind(request, raw)
    with pytest.raises(ValueError): project_chunk_evidence(docs, request, raw)


@pytest.mark.parametrize('change', ['candidate-text', 'candidate-other-field', 'candidate-ref',
    'receipt-hash', 'receipt-map', 'receipt-before', 'receipt-policy', 'receipt-version',
    'receipt-flag', 'receipt-extra', 'receipt-missing'])
def test_receipt_and_candidate_are_rederived_without_accepting_mutation(change):
    docs, _, request, _, raw = example()
    candidate, receipt = project_chunk_evidence(docs, request, raw)
    if change == 'candidate-text': candidate['blueprint']['claims'][0]['value'] = 'Changed meaning'
    elif change == 'candidate-other-field': candidate['blueprint']['objects'][0]['reason'] = 'Different'
    elif change == 'candidate-ref': candidate['blueprint']['claims'][0]['evidence_refs'].pop()
    elif change == 'receipt-hash': receipt['raw_candidate_sha256'] = '0' * 64
    elif change == 'receipt-map': receipt['changes'][0]['mappings'][0]['after'] = 'unknown'
    elif change == 'receipt-before': receipt['changes'][0]['before'].reverse()
    elif change == 'receipt-policy': receipt['policy'] = 'unknown'
    elif change == 'receipt-version': receipt['schema_version'] = True
    elif change == 'receipt-flag': receipt['independent_review_required'] = False
    elif change == 'receipt-extra': receipt['approved'] = True
    else: receipt = None
    with pytest.raises(ValueError): validate_chunk_evidence(docs, request, raw, candidate, receipt)


def test_outputs_and_receipt_do_not_alias_inputs():
    docs, _, request, _, raw = example()
    before = deepcopy((docs, request, raw))
    candidate, receipt = project_chunk_evidence(docs, request, raw)
    candidate['blueprint']['claims'][0]['value'] = 'Local change'
    receipt['changes'][0]['before'].append('Local change')
    assert (docs, request, raw) == before


def test_reordered_refs_keep_exact_order_except_projected_ids():
    docs, _, request, expected, raw = example()
    raw['blueprint']['claims'][0]['evidence_refs'].reverse()
    expected['blueprint']['claims'][0]['evidence_refs'].reverse()
    candidate, _ = project_chunk_evidence(docs, request, raw)
    assert candidate == expected


@pytest.mark.parametrize('field', ['request', 'candidate', 'documents'])
def test_malformed_unbounded_inputs_fail_without_running_object_hooks(field):
    docs, _, request, _, raw = example()
    if field == 'request': request['extra'] = object()
    elif field == 'candidate': raw['blueprint']['claims'][0]['value'] = object()
    else: docs = [('synthetic.xml', 'not bytes')]
    with pytest.raises(ValueError): project_chunk_evidence(docs, request, raw)
