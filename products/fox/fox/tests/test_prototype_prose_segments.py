"""Lossless bounded prose, synthetic pure inputs; no provider or file I/O."""
from copy import deepcopy
import hashlib

import pytest

from fox.opaf import canonical_hash
from fox.prototype_focus_projection import source_fact_gate
from fox.prototype_prose_segments import POLICY, SCOPE, project, validate
from fox.prototype_reference_echo import project as project_v2
from test_prototype_reference_echo import TARGET, echoed
from test_prototype_chunk_evidence import example


def prose(text='a' * 604):
    docs, packet, request, expected, raw = echoed()
    raw['blueprint']['claims'][0]['value'] = text
    return docs, packet, request, expected, raw


def descriptor(text):
    body = text.encode('utf-8')
    return {'characters': len(text), 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}


def test_604_char_proposal_is_lossless_and_delegates_to_unchanged_v2():
    docs, packet, request, expected, raw = prose()
    before = deepcopy((docs, packet, request, raw, TARGET))
    with pytest.raises(ValueError): project_v2(docs, packet, request, raw, TARGET)
    candidate, receipt = project(docs, packet, request, raw, TARGET)
    parts = ['a' * 512, 'a' * 92]
    expected['blueprint']['claims'][0]['value'] = parts
    assert candidate == expected and (docs, packet, request, raw, TARGET) == before
    assert receipt['schema_version'] == 3 and receipt['scope'] == SCOPE and receipt['policy'] == POLICY
    assert len(receipt['changes']) == 1
    change = receipt['changes'][0]
    assert change['path'] == ['blueprint', 'claims', 0, 'value']
    assert change['before'] == 'a' * 604
    assert change['before_text'] == change['recomposed_text'] == descriptor(''.join(parts))
    assert change['segments'] == [descriptor(part) for part in parts]
    prepared = deepcopy(raw)
    prepared['blueprint']['claims'][0]['value'] = parts
    inner_candidate, inner = project_v2(docs, packet, request, prepared, TARGET)
    assert candidate == inner_candidate and receipt['v2_projection'] == inner
    assert receipt['raw_candidate_sha256'] == canonical_hash(raw)
    assert receipt['prepared_candidate_sha256'] == canonical_hash(prepared)
    assert receipt['candidate_sha256'] == canonical_hash(candidate)
    assert change['before_claim_sha256'] == canonical_hash(raw['blueprint']['claims'][0])
    assert change['prepared_claim_sha256'] == canonical_hash(prepared['blueprint']['claims'][0])
    assert receipt['source_fact_check'] == source_fact_gate(packet, request, candidate)
    assert receipt['independent_review_required'] is True
    for key in ('processing_consent_verified', 'semantic_equivalence_attested',
                'execution_authorized', 'business_behavior_accepted'):
        assert receipt[key] is False
    assert validate(docs, packet, request, raw, TARGET, candidate, receipt)


@pytest.mark.parametrize('text', ['x' * 513, 'x' * 1024, 'x' * 1537, 'x' * 2048,
    'word ' * 409 + 'abc', 'alpha\tbeta\r\n' * 60, 'alpha\u00a0beta ' * 65,
    'é界😀' * 250, 'A' * 512 + ' ' * 92])
def test_every_character_whitespace_and_utf8_byte_recomposes_exactly(text):
    docs, packet, request, _, raw = prose(text)
    candidate, receipt = project(docs, packet, request, raw, TARGET)
    parts = candidate['blueprint']['claims'][0]['value']
    assert 2 <= len(parts) <= 4 and all(0 < len(part) <= 512 and part.strip() for part in parts)
    assert ''.join(parts) == text and ''.join(parts).encode('utf-8') == text.encode('utf-8')
    assert receipt['changes'][0]['before_text'] == receipt['changes'][0]['recomposed_text'] == descriptor(text)
    assert receipt['changes'][0]['segments'] == [descriptor(part) for part in parts]
    assert project(docs, packet, request, raw, TARGET) == (candidate, receipt)


def test_whitespace_is_preferred_only_when_four_segment_capacity_is_preserved():
    docs, packet, request, _, raw = prose('word ' * 120 + 'tail')
    candidate, _ = project(docs, packet, request, raw, TARGET)
    assert candidate['blueprint']['claims'][0]['value'][0].endswith(' ')
    docs, packet, request, _, raw = prose('word ' * 409 + 'abc')
    candidate, _ = project(docs, packet, request, raw, TARGET)
    # 2048 characters require all four segments to use the full existing limit;
    # an earlier whitespace cut would require a fifth segment and is forbidden.
    assert [len(part) for part in candidate['blueprint']['claims'][0]['value']] == [512] * 4


def test_unresolved_behavior_has_same_exact_representation_without_status_change():
    docs, packet, request, _, raw = prose()
    raw['blueprint']['claims'][0]['status'] = 'unresolved'
    candidate, _ = project(docs, packet, request, raw, TARGET)
    assert candidate['blueprint']['claims'][0]['status'] == 'unresolved'
    assert ''.join(candidate['blueprint']['claims'][0]['value']) == raw['blueprint']['claims'][0]['value']


@pytest.mark.parametrize('value', ['short', 'x' * 512, ['a' * 512, 'b' * 92], ['valid'] * 32])
def test_already_valid_scalar_or_array_is_unchanged_and_has_no_new_receipt(value):
    docs, packet, request, expected, _ = example()
    expected['blueprint']['claims'][0]['value'] = value
    candidate, receipt = project(docs, packet, request, expected, TARGET)
    assert candidate is expected and candidate['blueprint']['claims'][0]['value'] == value
    assert receipt is None
    assert validate(docs, packet, request, expected, TARGET, expected, None)


def test_v2_only_projection_retains_verbatim_inner_proof_with_no_segmentation():
    docs, packet, request, _, raw = echoed()
    inner_candidate, inner = project_v2(docs, packet, request, raw, TARGET)
    candidate, receipt = project(docs, packet, request, raw, TARGET)
    assert candidate == inner_candidate and receipt['changes'] == []
    assert receipt['v2_projection'] == inner


def test_segmentation_only_needs_no_echo_or_other_reference_projection():
    docs, packet, request, raw, _ = example()
    raw['blueprint']['claims'][0]['value'] = 'a' * 604
    original = deepcopy(raw)
    candidate, receipt = project(docs, packet, request, raw, TARGET)
    assert raw == original
    assert candidate['blueprint']['claims'][0]['value'] == ['a' * 512, 'a' * 92]
    assert len(receipt['changes']) == 1 and receipt['v2_projection'] is None
    assert validate(docs, packet, request, raw, TARGET, candidate, receipt)


@pytest.mark.parametrize('change', ['too-long', 'other-kind', 'source-fact', 'unknown-status',
    'array-long-element', 'nested-array', 'array-too-many', 'control', 'surrogate',
    'blank-only', 'leading-unrepresentable-whitespace', 'unknown-ref', 'wrong-owner',
    'duplicate-ref', 'source-fact-change', 'alias-plus-chunk', 'echo', 'extra', 'stale-source'])
def test_out_of_scope_and_existing_gate_failures_are_never_repaired(change):
    docs, packet, request, _, raw = prose()
    claim = raw['blueprint']['claims'][0]
    if change == 'too-long': claim['value'] = 'x' * 2049
    elif change == 'other-kind': claim['kind'] = 'dependency.intent'
    elif change == 'source-fact': claim['status'] = 'source_fact'
    elif change == 'unknown-status': claim['status'] = 'accepted'
    elif change == 'array-long-element': claim['value'] = ['x' * 604]
    elif change == 'nested-array': claim['value'] = [['x' * 604]]
    elif change == 'array-too-many': claim['value'] = ['valid'] * 33
    elif change == 'control': claim['value'] = 'x' * 603 + '\x01'
    elif change == 'surrogate': claim['value'] = 'x' * 603 + '\ud800'
    elif change == 'blank-only': claim['value'] = ' ' * 604
    elif change == 'leading-unrepresentable-whitespace': claim['value'] = ' ' * 512 + 'x' * 92
    elif change == 'unknown-ref': claim['evidence_refs'][1] = 'unknown'
    elif change == 'wrong-owner': claim['source_object_id'] = raw['blueprint']['claims'][1]['source_object_id']
    elif change == 'duplicate-ref': claim['evidence_refs'] *= 2
    elif change == 'source-fact-change': raw['blueprint']['claims'][2]['value'] = 'Invented widget'
    elif change == 'alias-plus-chunk': raw['blueprint']['claims'][2]['kind'] = 'object.item_type'
    elif change == 'echo': raw['source_binding'] = '0' * 64
    elif change == 'extra': raw['unexpected'] = True
    else: docs[0] = (docs[0][0], docs[0][1].replace(b'123', b'124'))
    with pytest.raises(ValueError): project(docs, packet, request, raw, TARGET)


@pytest.mark.parametrize('change', ['candidate-text', 'candidate-order', 'raw-hash', 'prepared-hash',
    'before', 'segment-hash', 'segment-size', 'recomposition-hash', 'inner-proof', 'target',
    'policy', 'version', 'scope', 'review-flag', 'extra', 'missing'])
def test_receipt_and_all_text_bindings_are_rederived(change):
    docs, packet, request, _, raw = prose()
    candidate, receipt = project(docs, packet, request, raw, TARGET)
    target = TARGET
    if change == 'candidate-text': candidate['blueprint']['claims'][0]['value'][0] = 'Changed meaning'
    elif change == 'candidate-order': candidate['blueprint']['claims'][0]['value'].reverse()
    elif change == 'raw-hash': receipt['raw_candidate_sha256'] = '0' * 64
    elif change == 'prepared-hash': receipt['prepared_candidate_sha256'] = '0' * 64
    elif change == 'before': receipt['changes'][0]['before'] += ' '
    elif change == 'segment-hash': receipt['changes'][0]['segments'][0]['sha256'] = '0' * 64
    elif change == 'segment-size': receipt['changes'][0]['segments'][0]['characters'] = 1
    elif change == 'recomposition-hash': receipt['changes'][0]['recomposed_text']['sha256'] = '0' * 64
    elif change == 'inner-proof': receipt['v2_projection']['candidate_sha256'] = '0' * 64
    elif change == 'target': target = {**TARGET, 'changed': True}
    elif change == 'policy': receipt['policy'] = 'unknown'
    elif change == 'version': receipt['schema_version'] = True
    elif change == 'scope': receipt['scope'] = 'unknown'
    elif change == 'review-flag': receipt['independent_review_required'] = False
    elif change == 'extra': receipt['approved'] = True
    else: receipt = None
    with pytest.raises(ValueError): validate(docs, packet, request, raw, target, candidate, receipt)


def test_every_changed_claim_has_its_own_original_text_and_recomposition_proof():
    docs, packet, request, _, raw = prose()
    raw['blueprint']['claims'][1]['value'] = 'β' * 1025
    candidate, receipt = project(docs, packet, request, raw, TARGET)
    assert len(receipt['changes']) == 2
    for change in receipt['changes']:
        index = change['path'][2]
        assert change['before'] == raw['blueprint']['claims'][index]['value']
        assert ''.join(candidate['blueprint']['claims'][index]['value']) == change['before']
        assert change['before_text'] == change['recomposed_text']


def test_outputs_and_receipts_do_not_alias_original_data():
    docs, packet, request, _, raw = prose()
    before = deepcopy((docs, packet, request, raw))
    candidate, receipt = project(docs, packet, request, raw, TARGET)
    candidate['blueprint']['claims'][0]['value'][0] = 'Local mutation'
    receipt['changes'][0]['segments'][0]['sha256'] = '0' * 64
    receipt['v2_projection']['echo_removal']['path'].append('Local mutation')
    assert (docs, packet, request, raw) == before


@pytest.mark.parametrize('change', ['object', 'deep', 'oversized'])
def test_global_plain_json_limits_are_unchanged(change):
    docs, packet, request, _, raw = prose()
    if change == 'object': raw['blueprint']['claims'][0]['value'] = object()
    elif change == 'oversized': raw['blueprint']['claims'][0]['value'] = 'x' * 500_001
    else:
        nested = raw
        for _ in range(22):
            nested['extra'] = {}
            nested = nested['extra']
    with pytest.raises(ValueError): project(docs, packet, request, raw, TARGET)
