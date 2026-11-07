"""Versioned focus contracts, with complete synthetic source coverage only."""
from copy import deepcopy
import hashlib
import json

import pytest

from fox.forms_focus import build_focus_plan
from fox.forms_understanding_packet import local_packet
from fox.opaf import OpafError, canonical_hash
from fox.prototype_admission import bound_focus_limit, prepare_prototype_admission
from fox.prototype_job import validate_prototype_snapshot, run_prototype_job
from fox.prototype_pipeline import authorize_prototype_request, run_prototype_pipeline
from test_prototype_admission import arguments, documents
from test_prototype_job import queued
from test_prototype_pipeline import setup, SyntheticConverter


def large_documents():
    # Full whole code units, distributed across many ownership partitions.
    items = ''.join(f'<Item Name="V{i}" ItemType="Text Item"/>' for i in range(180))
    code = ''.join(f'<Trigger Name="T{i}" TriggerText="BEGIN NULL; END;"/>' for i in range(71))
    return [('synthetic.xml', ('<FormModule Name="SYNTHETIC"><Block Name="MAIN">' +
                             items + code + '</Block></FormModule>').encode())]


def test_legacy_admission_is_identical_and_new_strategy_preserves_complete_coverage():
    args = arguments()
    legacy = prepare_prototype_admission(documents(), **args)
    explicit = prepare_prototype_admission(documents(), **args, schema_version=1)
    assert json.dumps(legacy) == json.dumps(explicit)
    assert set(legacy['prototype']) == {'schema_version', 'source_binding', 'focus_plan_sha256',
        'approved_chunk_hashes', 'approved_policy_id', 'target_profile_sha256'}
    old_plan = build_focus_plan(documents(), expected_source_binding=args['expected_source_binding'],
                                approved_chunk_hashes=args['approved_chunk_hashes'])
    assert canonical_hash(old_plan) == legacy['prototype']['focus_plan_sha256']
    assert bound_focus_limit(legacy['prototype']) == 250

    docs = large_documents()
    packet = local_packet(docs)
    selected = {row['id']: row['sha256'] for row in packet['chunks']}
    args.update(expected_source_binding=packet['source_binding'], approved_chunk_hashes=selected)
    admission = prepare_prototype_admission(docs, **args, schema_version=2)
    plan = build_focus_plan(docs, expected_source_binding=packet['source_binding'],
                           approved_chunk_hashes=selected, max_owned_objects=32)
    assert admission['prototype']['max_owned_objects'] == bound_focus_limit(admission['prototype']) == 32
    assert canonical_hash(plan) == admission['prototype']['focus_plan_sha256']
    owned = [row['id'] for request in plan['requests'] for row in request['owned_objects']]
    expected = [row['id'] for source in packet['sources'] for row in source['facts']['objects']]
    assert len(owned) == len(set(owned)) == len(expected) == plan['total_source_objects']
    assert set(owned) == set(expected)
    chunks = [row for request in plan['requests'] for row in request['chunks']]
    assert len(chunks) == len(selected) == 71
    assert {row['id']: row['sha256'] for row in chunks} == selected
    for row in chunks:
        assert row['text'] == 'BEGIN NULL; END;'
        assert len(row['text'].encode()) == row['bytes']
        assert hashlib.sha256(row['text'].encode()).hexdigest() == row['sha256']
    assert max(len(request['owned_objects']) for request in plan['requests']) <= 32


@pytest.mark.parametrize('binding', [{}, {'schema_version': True}, {'schema_version': 3},
    {'schema_version': 1, 'max_owned_objects': 250}, {'schema_version': 2},
    {'schema_version': 2, 'max_owned_objects': 250}, {'schema_version': 2, 'max_owned_objects': True}])
def test_unversioned_or_unapproved_limit_rejected(binding):
    with pytest.raises(ValueError):
        bound_focus_limit(binding)


def test_old_and_new_snapshots_reconstruct_without_changing_original_bytes(queued):
    _, job, _, snapshot, _, _, _ = queued
    old_raw = (job / 'source-snapshot.json').read_bytes()
    docs = validate_prototype_snapshot(snapshot)
    assert (job / 'source-snapshot.json').read_bytes() == old_raw
    updated = deepcopy(snapshot)
    old = snapshot['prototype']
    updated['prototype'] = prepare_prototype_admission(docs,
        expected_source_binding=old['source_binding'], approved_chunk_hashes=old['approved_chunk_hashes'],
        target_profile_sha256=old['target_profile_sha256'], approved_redacted_source=True,
        approved_external_ai=True, approved_prototype_scope=True, schema_version=2)['prototype']
    assert validate_prototype_snapshot(updated) == docs
    assert (job / 'source-snapshot.json').read_bytes() == old_raw
    updated['prototype']['max_owned_objects'] = 250
    with pytest.raises(OpafError):
        validate_prototype_snapshot(updated)


@pytest.mark.parametrize('version', [1, 2])
def test_pipeline_and_readonly_converter_authority_reconstruct_exact_strategy(setup, version):
    job, docs, client, _, kwargs = setup
    converter = SyntheticConverter(supported=('validate',))
    run_prototype_pipeline(job, docs, converter_adapter=converter, focus_schema_version=version, **kwargs)
    original = {p.relative_to(job): p.read_bytes() for p in job.rglob('*') if p.is_file()}
    binding = json.loads((job / 'prototype-pipeline' / 'binding.json').read_bytes())
    assert binding['schema_version'] == version
    assert bound_focus_limit(binding) == (250 if version == 1 else 32)
    calls = deepcopy(client.calls)
    assert authorize_prototype_request(job, converter.requests[0]) is converter.requests[0]
    assert client.calls == calls
    assert original == {p.relative_to(job): p.read_bytes() for p in job.rglob('*') if p.is_file()}
    binding['schema_version'] = 2 if version == 1 else 1
    (job / 'prototype-pipeline' / 'binding.json').write_text(json.dumps(binding))
    with pytest.raises((OpafError, ValueError)):
        authorize_prototype_request(job, converter.requests[0])


def test_retry_snapshot_cannot_execute_under_a_different_job_identity(queued):
    _, job, _, snapshot, model, _, configurations = queued
    selected = snapshot['prototype']
    snapshot['prototype'] = prepare_prototype_admission(validate_prototype_snapshot(snapshot),
        expected_source_binding=selected['source_binding'], approved_chunk_hashes=selected['approved_chunk_hashes'],
        target_profile_sha256=selected['target_profile_sha256'], approved_redacted_source=True,
        approved_external_ai=True, approved_prototype_scope=True, schema_version=2)['prototype']
    snapshot.update(retry_of='fox-' + '7' * 20, mapping_recovery={
        'schema_version': 1, 'strategy': 'repartition-32-v1', 'parent_snapshot_sha256': 'a' * 64})
    (job / 'source-snapshot.json').write_text(json.dumps(snapshot))
    with pytest.raises(OpafError, match='parent identity'):
        run_prototype_job(job, approval_check=lambda _: True)
    assert configurations == [] and model.calls == []
