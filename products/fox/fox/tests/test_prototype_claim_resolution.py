"""Synthetic source-bound resolution, preserving every raw model byte."""
from copy import deepcopy
import json

import pytest

from fox.prototype_claim_resolution import resolve_claim_owners, resolved_mapper
from fox.forms_focus import build_focus_plan
from fox.forms_understanding_packet import local_packet
from fox.opaf import OpafError, canonical_hash
from test_prototype_pipeline import SyntheticOpaf, PROFILE, documents


def example():
    docs = documents()
    request = next(row for row in build_focus_plan(docs,
        expected_source_binding=local_packet(docs)['source_binding'], approved_chunk_hashes={})['requests'] if row['code_units'])
    candidate, _ = SyntheticOpaf().invoke(PROFILE['mapper'], request)
    unit = request['code_units'][0]
    candidate['blueprint']['claims'] = [{'id': 'behavior', 'source_object_id': unit['id'],
        'kind': 'behavior', 'value': 'Manual review remains required', 'status': 'proposal',
        'evidence_refs': [unit['id']], 'reason': 'Authored source-bound synthetic claim.'}]
    return request, candidate


def test_resolves_only_owner_field_and_preserves_raw_candidate(tmp_path):
    request, raw = example()
    before = deepcopy(raw)
    candidate, receipt = resolve_claim_owners(request, raw)
    expected = deepcopy(raw)
    expected['blueprint']['claims'][0]['source_object_id'] = request['code_units'][0]['owner_id']
    assert candidate == expected and raw == before
    assert receipt['raw_candidate_sha256'] == canonical_hash(raw)
    assert receipt['candidate_sha256'] == canonical_hash(candidate)
    assert receipt['request_sha256'] == canonical_hash(request)
    assert resolved_mapper(tmp_path, request, raw, write=True) == (candidate, receipt)
    original = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    assert resolved_mapper(tmp_path, request, raw) == (candidate, receipt)
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == original
    path = tmp_path / 'mapper-resolved.json'
    altered = deepcopy(candidate)
    altered['blueprint']['claims'][0]['reason'] = 'Semantic edit forbidden'
    path.write_text(json.dumps(altered))
    with pytest.raises(OpafError):
        resolved_mapper(tmp_path, request, raw)


@pytest.mark.parametrize('change', ['unknown', 'missing-ref', 'duplicate-unit', 'collision', 'context-owner',
                                   'inconsistent-ref', 'duplicate-ref', 'different-shape'])
def test_no_guessing_ambiguous_or_semantic_repairs(change):
    request, raw = example()
    claim, unit = raw['blueprint']['claims'][0], request['code_units'][0]
    if change == 'unknown': claim['source_object_id'] = 'unknown'
    elif change == 'missing-ref': claim['evidence_refs'] = []
    elif change == 'duplicate-unit': request['code_units'].append(deepcopy(unit))
    elif change == 'collision': request['context_objects'].append({'id': unit['id']})
    elif change == 'context-owner': unit['owner_id'] = request['context_objects'][0]['id']
    elif change == 'inconsistent-ref': claim['evidence_refs'].append('unknown')
    elif change == 'duplicate-ref': claim['evidence_refs'].append(unit['id'])
    else: raw['blueprint']['objects'].pop()
    with pytest.raises((ValueError, KeyError)):
        resolve_claim_owners(request, raw)


def test_unchanged_valid_candidate_has_no_new_files_or_provenance(tmp_path):
    request, raw = example()
    raw['blueprint']['claims'] = []
    assert resolve_claim_owners(request, raw) == (raw, None)
    assert resolved_mapper(tmp_path, request, raw, write=True) == (raw, None)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('artifact', ['candidate', 'receipt'])
@pytest.mark.parametrize('write', [False, True])
def test_bool_int_equality_never_hides_resolution_tampering(tmp_path, artifact, write):
    request, raw = example()
    resolved_mapper(tmp_path, request, raw, write=True)
    path = tmp_path / ('mapper-resolved.json' if artifact == 'candidate' else 'mapper-resolution.json')
    value = json.loads(path.read_bytes())
    if artifact == 'candidate': value['blueprint']['schema_version'] = True
    else: value['resolutions'][0]['claim_index'] = False
    path.write_text(json.dumps(value))
    with pytest.raises(OpafError):
        resolved_mapper(tmp_path, request, raw, write=write)
