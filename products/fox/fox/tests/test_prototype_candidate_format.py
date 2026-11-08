"""Synthetic exact-source format normalization; no provider or acceptance."""
from copy import deepcopy

import pytest

from fox.forms_focus import build_focus_plan
from fox.forms_understanding_packet import local_packet
from fox.opaf import canonical_hash
from fox.prototype_candidate_format import normalize_candidate, validate_normalization, POLICY
from fox.prototype_focus_projection import source_fact_gate


def example():
    docs = [('synthetic.xml', b'<FormModule Name="SYNTHETIC"><Block Name="MAIN">'
             b'<Item Name="FIELD_A" ItemType="Text Item" DatabaseItem="true"/>'
             b'<Item Name="FIELD_B" ItemType="Display Item" DatabaseItem="false"/>'
             b'</Block></FormModule>')]
    packet = local_packet(docs)
    plan = build_focus_plan(docs, expected_source_binding=packet['source_binding'],
                           approved_chunk_hashes={}, max_owned_objects=2)
    request = next(r for r in plan['requests'] if any(o['kind'] == 'Item' for o in r['owned_objects']))
    item = next(o for o in request['owned_objects'] if o['kind'] == 'Item')
    claims = [{'id': 'item-type', 'source_object_id': item['id'], 'kind': 'item.item_type',
               'value': item['item_type'], 'status': 'source_fact', 'evidence_refs': [item['id']],
               'reason': 'Exact synthetic source metadata.'},
              {'id': 'database-item', 'source_object_id': item['id'], 'kind': 'item.database_item',
               'value': item['database_item'], 'status': 'source_fact', 'evidence_refs': [item['id']],
               'reason': 'Exact synthetic source metadata.'}]
    candidate = {'focus_id': request['focus_id'], 'focus_binding': request['focus_binding'],
        'blueprint': {'schema_version': 1, 'scope': 'forms-to-apex-blueprint-v1',
            'source_binding': request['source_binding'], 'objects': [
                {'source_object_id': o['id'], 'disposition': 'unresolved', 'reason': 'Unimplemented synthetic mapping.'}
                for o in request['owned_objects']], 'screens': [], 'claims': claims,
            'actions': [{'id': 'action', 'claim_ids': ['item-type']}],
            'relationships': [{'id': 'relationship', 'claim_ids': ['database-item']}],
            'questions': [], 'assumptions': []}}
    # Use the existing canonical scope, not a new blueprint schema.
    from fox.forms_design_review import BLUEPRINT_SCOPE
    candidate['blueprint']['scope'] = BLUEPRINT_SCOPE
    raw = deepcopy(candidate);raw['source_binding'] = request['source_binding']
    raw['blueprint']['claims'][0]['kind'] = 'object.item_type'
    raw['blueprint']['claims'][1]['kind'] = 'object.database_item'
    return docs, packet, request, candidate, raw


def test_exact_echo_and_aliases_preserve_every_other_field_and_raw():
    docs, packet, request, expected, raw = example()
    before = deepcopy((docs, request, raw))
    candidate, receipt = normalize_candidate(docs, request, raw)
    assert candidate == expected and (docs, request, raw) == before
    assert len(receipt['changes']) == 3 and receipt['policy'] == POLICY
    assert receipt['raw_candidate_sha256'] == canonical_hash(raw)
    assert receipt['candidate_sha256'] == canonical_hash(candidate)
    assert receipt['request_sha256'] == canonical_hash(request)
    assert receipt['packet_sha256'] == canonical_hash(packet)
    assert receipt['independent_review_required'] is True and receipt['execution_authorized'] is False
    assert source_fact_gate(packet, request, candidate)['source_facts_checked'] is True
    assert validate_normalization(docs, request, raw, candidate, receipt) is True


def test_legacy_is_identity_without_new_receipt():
    docs, _, request, candidate, _ = example()
    normalized, receipt = normalize_candidate(docs, request, candidate)
    assert normalized is candidate and receipt is None
    assert validate_normalization(docs, request, candidate, candidate, None)


@pytest.mark.parametrize('only', ['echo', 'item-type', 'database-item'])
def test_each_format_change_is_independently_supported(only):
    docs, _, request, expected, raw = example()
    selected = deepcopy(expected)
    if only == 'echo': selected['source_binding'] = raw['source_binding']
    else: selected['blueprint']['claims'][0 if only == 'item-type' else 1]['kind'] = 'object.item_type' if only == 'item-type' else 'object.database_item'
    candidate, receipt = normalize_candidate(docs, request, selected)
    assert candidate == expected and len(receipt['changes']) == 1


@pytest.mark.parametrize('change', ['echo', 'blueprint-binding', 'focus-binding', 'unknown-extra',
    'unknown-alias', 'value', 'bool-int', 'bool-string', 'refs', 'duplicate-refs', 'missing-ref',
    'context-owner', 'wrong-kind', 'status', 'stale-source', 'request-metadata', 'request-hash'])
def test_mismatches_and_nonmechanical_changes_refused(change):
    docs, _, request, _, raw = example();claim = raw['blueprint']['claims'][1]
    if change == 'echo': raw['source_binding'] = '0' * 64
    elif change == 'blueprint-binding': raw['blueprint']['source_binding'] = '0' * 64
    elif change == 'focus-binding': raw['focus_binding'] = '0' * 64
    elif change == 'unknown-extra': raw['ready'] = True
    elif change == 'unknown-alias': claim['kind'] = 'object.databaseItem'
    elif change == 'value': raw['blueprint']['claims'][0]['value'] = 'Invented widget'
    elif change == 'bool-int': claim['value'] = int(claim['value'])
    elif change == 'bool-string': claim['value'] = str(claim['value'])
    elif change == 'refs': claim['evidence_refs'] = ['unknown']
    elif change == 'duplicate-refs': claim['evidence_refs'] *= 2
    elif change == 'missing-ref': claim['evidence_refs'] = []
    elif change == 'context-owner': claim['source_object_id'] = request['context_objects'][0]['id']
    elif change == 'wrong-kind':
        block = next(o for o in request['owned_objects'] if o['kind'] != 'Item')
        claim.update(source_object_id=block['id'], evidence_refs=[block['id']])
    elif change == 'status': claim['status'] = 'proposal'
    elif change == 'stale-source': docs[0] = (docs[0][0], docs[0][1].replace(b'Text Item', b'Check Box'))
    elif change == 'request-metadata': request['owned_objects'][-1]['name'] = 'Different'
    else: request['focus_binding'] = '0' * 64
    with pytest.raises(ValueError): normalize_candidate(docs, request, raw)


@pytest.mark.parametrize('change', ['candidate', 'receipt-hash', 'receipt-change', 'receipt-policy', 'receipt-bool', 'missing-receipt'])
def test_receipts_are_rederived_not_trusted(change):
    docs, _, request, _, raw = example();candidate, receipt = normalize_candidate(docs, request, raw)
    if change == 'candidate': candidate['blueprint']['objects'][0]['reason'] = 'Changed semantic choice'
    elif change == 'receipt-hash': receipt['raw_candidate_sha256'] = '0' * 64
    elif change == 'receipt-change': receipt['changes'].pop()
    elif change == 'receipt-policy': receipt['policy'] = 'unknown'
    elif change == 'receipt-bool': receipt['schema_version'] = True
    else: receipt = None
    with pytest.raises(ValueError): validate_normalization(docs, request, raw, candidate, receipt)


def test_normalized_outputs_and_receipts_do_not_alias_inputs():
    docs, _, request, _, raw = example();before = deepcopy(raw)
    candidate, receipt = normalize_candidate(docs, request, raw)
    candidate['blueprint']['claims'][0]['reason'] = 'Local mutation'
    receipt['changes'][0]['before'] = 'Local mutation'
    assert raw == before
