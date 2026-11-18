"""Pure V2 source-echo composition; synthetic inputs, no provider or file I/O."""
from copy import deepcopy

import pytest

from fox.forms_focus import build_focus_plan
from fox.opaf import canonical_hash
from fox.prototype_development_reference_view import project as project_v1
from fox.prototype_focus_projection import source_fact_gate
from fox.prototype_reference_echo import POLICY, SCOPE, project, validate
from test_prototype_chunk_evidence import example

TARGET = {'scope': 'synthetic-only'}


def echoed():
    docs, packet, request, expected, raw = example()
    raw['source_binding'] = request['source_binding']
    return docs, packet, request, expected, raw


def test_matching_echo_and_chunk_refs_compose_exact_unchanged_v1_proof():
    docs, packet, request, expected, raw = echoed()
    before = deepcopy((docs, packet, request, raw, TARGET))
    prepared = {key: value for key, value in raw.items() if key != 'source_binding'}
    inner_candidate, inner_receipt = project_v1(docs, packet, request, prepared, TARGET)
    with pytest.raises(ValueError): project_v1(docs, packet, request, raw, TARGET)
    candidate, receipt = project(docs, packet, request, raw, TARGET)
    assert candidate == expected == inner_candidate
    assert (docs, packet, request, raw, TARGET) == before
    assert receipt['schema_version'] == 2 and receipt['scope'] == SCOPE and receipt['policy'] == POLICY
    assert receipt['echo_removal'] == {'operation': 'remove_matching_source_binding_echo',
        'path': ['source_binding'], 'before': request['source_binding']}
    assert receipt['raw_candidate_sha256'] == canonical_hash(raw)
    assert receipt['prepared_candidate_sha256'] == canonical_hash(prepared)
    assert receipt['candidate_sha256'] == canonical_hash(candidate)
    assert receipt['packet_sha256'] == canonical_hash(packet)
    assert receipt['request_sha256'] == canonical_hash(request)
    assert receipt['target_profile_sha256'] == canonical_hash(TARGET)
    assert receipt['v1_projection'] == inner_receipt
    assert receipt['source_fact_check'] == source_fact_gate(packet, request, candidate)
    assert receipt['independent_review_required'] is True
    for flag in ('processing_consent_verified', 'semantic_equivalence_attested',
                 'execution_authorized', 'business_behavior_accepted'):
        assert receipt[flag] is False
    assert validate(docs, packet, request, raw, TARGET, candidate, receipt)


def test_echo_only_and_chunk_only_remain_explicit_unreviewed_v2_derivations():
    docs, packet, request, expected, chunks = example()
    echo_only = deepcopy(expected)
    echo_only['source_binding'] = request['source_binding']
    candidate, receipt = project(docs, packet, request, echo_only, TARGET)
    assert candidate == expected and receipt['echo_removal'] is not None
    assert receipt['v1_projection'] is None
    candidate, receipt = project(docs, packet, request, chunks, TARGET)
    assert candidate == expected and receipt['echo_removal'] is None
    assert receipt['v1_projection'] is not None


def test_no_echo_and_no_v1_change_is_identity_without_new_receipt():
    docs, packet, request, expected, _ = example()
    candidate, receipt = project(docs, packet, request, expected, TARGET)
    assert candidate is expected and receipt is None
    assert validate(docs, packet, request, expected, TARGET, expected, None)


def test_v1_container_projection_receipt_remains_unchanged_inside_v2():
    docs, packet, _, expected, _ = example()
    selected = {row['id']: row['sha256'] for row in packet['chunks']}
    plan = build_focus_plan(docs, expected_source_binding=packet['source_binding'], approved_chunk_hashes=selected)
    request = next(row for row in plan['requests'] if any(o['kind'] == 'FormModule' for o in row['owned_objects']))
    original = {'focus_id': request['focus_id'], 'focus_binding': request['focus_binding'],
        'blueprint': {**deepcopy(expected['blueprint']), 'objects': [
            {'source_object_id': row['id'], 'disposition': 'omitted', 'reason': 'Original unreviewed choice.'}
            for row in request['owned_objects']], 'claims': [], 'actions': []}}
    target = {'design_provider': {}}  # Pure branch selection, not a usable provider configuration.
    inner_candidate, inner_receipt = project_v1(docs, packet, request, original, target)
    assert inner_receipt['container_retention'] is not None
    raw = {**deepcopy(original), 'source_binding': request['source_binding']}
    candidate, receipt = project(docs, packet, request, raw, target)
    assert candidate == inner_candidate
    assert receipt['v1_projection'] == inner_receipt
    assert receipt['independent_review_required'] is True


@pytest.mark.parametrize('value', [None, False, True, 1, '', '0' * 64, [], {}])
def test_echo_requires_exact_matching_string(value):
    docs, packet, request, _, raw = echoed()
    raw['source_binding'] = value
    with pytest.raises(ValueError): project(docs, packet, request, raw, TARGET)


@pytest.mark.parametrize('change', ['request-binding', 'packet-binding', 'blueprint-binding',
    'unknown-extra', 'item-alias-plus-chunk', 'source-fact', 'unknown-ref', 'wrong-owner',
    'duplicate-ref', 'chunk-text', 'chunk-hash', 'forged-packet', 'stale-documents'])
def test_echo_cannot_hide_other_extras_or_unproven_source_and_evidence(change):
    docs, packet, request, _, raw = echoed()
    if change == 'request-binding': request['source_binding'] = '0' * 64
    elif change == 'packet-binding': packet['source_binding'] = '0' * 64
    elif change == 'blueprint-binding': raw['blueprint']['source_binding'] = '0' * 64
    elif change == 'unknown-extra': raw['other_echo'] = request['source_binding']
    elif change == 'item-alias-plus-chunk': raw['blueprint']['claims'][2]['kind'] = 'object.item_type'
    elif change == 'source-fact': raw['blueprint']['claims'][2]['value'] = 'Invented widget'
    elif change == 'unknown-ref': raw['blueprint']['claims'][0]['evidence_refs'][1] = 'unknown'
    elif change == 'wrong-owner':
        raw['blueprint']['claims'][0]['evidence_refs'][1] = raw['blueprint']['claims'][1]['evidence_refs'][1]
    elif change == 'duplicate-ref': raw['blueprint']['claims'][0]['evidence_refs'] *= 2
    elif change == 'chunk-text': request['chunks'][0]['text'] += ' '
    elif change == 'chunk-hash': request['chunks'][0]['sha256'] = '0' * 64
    elif change == 'forged-packet': packet['sources'][0]['facts']['objects'][0]['name'] = 'Invented'
    else: docs[0] = (docs[0][0], docs[0][1].replace(b'123', b'124'))
    with pytest.raises(ValueError): project(docs, packet, request, raw, TARGET)


@pytest.mark.parametrize('change', ['candidate', 'target', 'raw-hash', 'prepared-hash',
    'echo-removal', 'inner-receipt', 'scope', 'policy', 'version', 'review-flag', 'extra', 'missing'])
def test_receipt_and_candidate_are_fully_rederived(change):
    docs, packet, request, _, raw = echoed()
    candidate, receipt = project(docs, packet, request, raw, TARGET)
    target = TARGET
    if change == 'candidate': candidate['blueprint']['claims'][0]['value'] = 'Changed meaning'
    elif change == 'target': target = {**TARGET, 'changed': True}
    elif change == 'raw-hash': receipt['raw_candidate_sha256'] = '0' * 64
    elif change == 'prepared-hash': receipt['prepared_candidate_sha256'] = '0' * 64
    elif change == 'echo-removal': receipt['echo_removal']['before'] = '0' * 64
    elif change == 'inner-receipt': receipt['v1_projection']['candidate_sha256'] = '0' * 64
    elif change == 'scope': receipt['scope'] = 'unknown'
    elif change == 'policy': receipt['policy'] = 'unknown'
    elif change == 'version': receipt['schema_version'] = True
    elif change == 'review-flag': receipt['independent_review_required'] = False
    elif change == 'extra': receipt['approved'] = True
    else: receipt = None
    with pytest.raises(ValueError): validate(docs, packet, request, raw, target, candidate, receipt)


def test_outputs_do_not_alias_raw_packet_or_request():
    docs, packet, request, _, raw = echoed()
    before = deepcopy((docs, packet, request, raw))
    candidate, receipt = project(docs, packet, request, raw, TARGET)
    candidate['blueprint']['claims'][0]['reason'] = 'Local mutation'
    receipt['echo_removal']['path'].append('Local mutation')
    receipt['v1_projection']['chunk_evidence']['changes'][0]['before'].clear()
    assert (docs, packet, request, raw) == before


@pytest.mark.parametrize('change', ['object', 'deep', 'oversized'])
def test_raw_json_is_bounded_before_projection(change):
    docs, packet, request, _, raw = echoed()
    if change == 'object': raw['source_binding'] = object()
    elif change == 'oversized': raw['source_binding'] = 'x' * 500_001
    else:
        nested = raw
        for _ in range(22):
            nested['extra'] = {}
            nested = nested['extra']
    with pytest.raises(ValueError): project(docs, packet, request, raw, TARGET)
