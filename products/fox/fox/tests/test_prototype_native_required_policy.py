"""Local admission/reconstruction tests; model/stage replies are authored only."""
from copy import deepcopy
import json
import shutil

import pytest

from fox.forms_native_required_plan import INPUT_POLICY_ID, PROFILE_ID
from fox.intake import checked_source
from fox.opaf import OpafError, canonical_hash
from fox.prototype_admission import prepare_prototype_admission
from fox.prototype_job import run_prototype_job, validate_prototype_snapshot
from fox.prototype_pipeline import authorize_prototype_request, run_prototype_pipeline
from fox import source_history
from test_prototype_admission import arguments, documents
from test_prototype_pipeline import setup as pipeline_setup, SyntheticConverter, TARGET
from test_prototype_job import queued
from test_prototype_project_routes import configured, prepare
from test_source_history_api import client, settings, no_external_actions


def admit_pipeline(job, docs, kwargs, policy=INPUT_POLICY_ID):
    selected = prepare_prototype_admission(docs,
        expected_source_binding=kwargs['expected_source_binding'],
        approved_chunk_hashes=kwargs['approved_chunk_hashes'], target_profile_sha256=canonical_hash(TARGET),
        approved_redacted_source=True, approved_external_ai=True, approved_prototype_scope=True,
        native_input_policy=policy)['prototype']
    files = [checked_source(name, raw) for name, raw in docs]
    snapshot = {'project': kwargs['project_id'], 'project_id': kwargs['project_id'],
        'project_name': kwargs['project_name'], 'source_hash': source_history._hash(files),
        'conversion_profile': 'native-blueprint-prototype-v1',
        'selected_source_set_id': 'ss-' + '1' * 32, 'files': files, 'prototype': selected,
        'approvals': {'owner': 'synthetic-owner', 'approved_at': 1.0,
            'redacted_source': True, 'external_ai': True, 'synthetic_prototype': True}}
    job.mkdir(exist_ok=True)
    (job / 'source-snapshot.json').write_text(json.dumps(snapshot), encoding='utf-8')
    return snapshot


def test_admission_only_adds_explicit_known_policy_and_still_requires_scope():
    legacy = prepare_prototype_admission(documents(), **arguments())
    assert 'native_input_policy' not in legacy['prototype']
    assert prepare_prototype_admission(documents(), native_input_policy=None, **arguments()) == legacy
    current = prepare_prototype_admission(documents(), native_input_policy=INPUT_POLICY_ID, **arguments())
    assert current['prototype'].pop('native_input_policy') == INPUT_POLICY_ID
    assert current == legacy
    args = arguments(); args['approved_prototype_scope'] = False
    with pytest.raises(ValueError, match='Confirm'):
        prepare_prototype_admission(documents(), native_input_policy=INPUT_POLICY_ID, **args)


@pytest.mark.parametrize('value', ['', True, 1, [], {}, 'forms-required-inputs-v2'])
def test_unknown_admission_policy_rejected(value):
    with pytest.raises(ValueError, match='native input policy'):
        prepare_prototype_admission(documents(), native_input_policy=value, **arguments())


def test_local_pipeline_saved_policy_real_renderer_and_readonly_reconstruction(pipeline_setup):
    job, docs, model, approvals, kwargs = pipeline_setup
    docs = [(name, raw.replace(b'DatabaseItem="true"', b'DatabaseItem="true" Required="true"'))
            for name, raw in docs]
    from fox.forms_understanding_packet import local_packet
    kwargs['expected_source_binding'] = local_packet(docs)['source_binding']
    snapshot = admit_pipeline(job, docs, kwargs)
    original_snapshot = (job / 'source-snapshot.json').read_bytes()
    converter = SyntheticConverter()
    result = run_prototype_pipeline(job, docs, converter_adapter=converter, **kwargs)
    assert result['status'] == 'APEX_GENERATED'  # Authored adapter stages, not live proof.
    spec = converter.requests[0]['rendering_spec']
    assert spec['schema_version'] == 2 and spec['profile_id'] == PROFILE_ID
    assert all(field['value_required'] is True and field['nullable'] is True
               for block in spec['blocks'] for field in block['fields'])
    binding = json.loads((job / 'prototype-pipeline/binding.json').read_bytes())
    assert binding['native_input_policy'] == snapshot['prototype']['native_input_policy'] == INPUT_POLICY_ID
    assert all(context['native_input_policy'] == INPUT_POLICY_ID for context in approvals)
    before = {path.relative_to(job): path.read_bytes() for path in job.rglob('*') if path.is_file()}
    assert authorize_prototype_request(job, converter.requests[0]) == converter.requests[0]
    assert {path.relative_to(job): path.read_bytes() for path in job.rglob('*') if path.is_file()} == before
    calls = deepcopy(model.calls)
    assert run_prototype_pipeline(job, docs, converter_adapter=converter, **kwargs) == result
    assert model.calls == calls
    assert (job / 'source-snapshot.json').read_bytes() == original_snapshot
    assert result['facts']['business_behavior_accepted'] is False
    assert result['facts']['technically_verified'] is False


def test_staged_technical_projection_is_explicit_not_missing_snapshot_fallback(pipeline_setup, tmp_path):
    job, docs, model, _, kwargs = pipeline_setup
    admit_pipeline(job, docs, kwargs)
    converter = SyntheticConverter()
    run_prototype_pipeline(job, docs, converter_adapter=converter, **kwargs)
    request = converter.requests[0]
    staged_job = tmp_path / 'receiver' / job.name
    shutil.copytree(job / 'prototype-pipeline', staged_job / 'prototype-pipeline')
    before = {path.relative_to(staged_job): path.read_bytes()
              for path in staged_job.rglob('*') if path.is_file()}
    calls = deepcopy((model.calls, converter.calls))
    with pytest.raises(OpafError, match='Native input policy'):
        authorize_prototype_request(staged_job, request)
    public_request = {**request, 'staged_projection': True}
    with pytest.raises(OpafError, match='Native input policy'):
        authorize_prototype_request(staged_job, public_request)
    assert authorize_prototype_request(staged_job, request, staged_projection=True) == request
    assert {path.relative_to(staged_job): path.read_bytes()
            for path in staged_job.rglob('*') if path.is_file()} == before
    assert (model.calls, converter.calls) == calls
    altered = deepcopy(request)
    altered['rendering_spec']['blocks'][0]['fields'][0]['value_required'] = True
    with pytest.raises(OpafError):
        authorize_prototype_request(staged_job, altered, staged_projection=True)
    with pytest.raises(OpafError):
        authorize_prototype_request(staged_job, request, staged_projection=1)


@pytest.mark.parametrize('change', ['unknown', 'null', 'remove', 'source', 'project', 'binding', 'spec', 'value-required'])
def test_reconstruction_rejects_policy_source_request_tampering_without_execution(pipeline_setup, change):
    job, docs, model, _, kwargs = pipeline_setup
    snapshot = admit_pipeline(job, docs, kwargs)
    converter = SyntheticConverter()
    run_prototype_pipeline(job, docs, converter_adapter=converter, **kwargs)
    request = deepcopy(converter.requests[0])
    if change in ('unknown', 'null', 'remove', 'source', 'project'):
        if change == 'unknown': snapshot['prototype']['native_input_policy'] = 'unknown'
        elif change == 'null': snapshot['prototype']['native_input_policy'] = None
        elif change == 'remove': snapshot['prototype'].pop('native_input_policy')
        elif change == 'source': snapshot['files'][0]['text'] += ' '
        else: snapshot['project_name'] = 'Different project'
        (job / 'source-snapshot.json').write_text(json.dumps(snapshot), encoding='utf-8')
    elif change == 'binding':
        path = job / 'prototype-pipeline/binding.json'
        value = json.loads(path.read_bytes()); value.pop('native_input_policy')
        path.write_text(json.dumps(value), encoding='utf-8')
    elif change == 'spec': request['rendering_spec']['input_validation_policy'] = 'unknown'
    else: request['rendering_spec']['blocks'][0]['fields'][0]['value_required'] = True
    calls = deepcopy((model.calls, converter.calls, converter.recoveries))
    before = {path.relative_to(job): path.read_bytes() for path in job.rglob('*') if path.is_file()}
    with pytest.raises(OpafError):
        authorize_prototype_request(job, request)
    assert (model.calls, converter.calls, converter.recoveries) == calls
    assert {path.relative_to(job): path.read_bytes() for path in job.rglob('*') if path.is_file()} == before


@pytest.mark.parametrize('change', ['unknown', 'null', 'source', 'consent'])
def test_snapshot_tampering_stops_job_before_configuration(queued, change):
    _, job, _, snapshot, model, converter, configurations = queued
    snapshot['prototype']['native_input_policy'] = INPUT_POLICY_ID
    if change == 'unknown': snapshot['prototype']['native_input_policy'] = 'unknown'
    elif change == 'null': snapshot['prototype']['native_input_policy'] = None
    elif change == 'source': snapshot['files'][0]['text'] += ' '
    else: snapshot['approvals']['synthetic_prototype'] = False
    (job / 'source-snapshot.json').write_text(json.dumps(snapshot), encoding='utf-8')
    with pytest.raises(OpafError):
        run_prototype_job(job, approval_check=lambda _: True)
    assert configurations == [] and model.calls == [] and converter.calls == []


@pytest.mark.parametrize('change', ['unknown', 'missing-snapshot', 'legacy-upgrade', 'source', 'project', 'selection', 'strategy'])
def test_pipeline_rejects_changed_policy_or_source_before_any_model(pipeline_setup, change):
    job, docs, model, _, kwargs = pipeline_setup
    if change != 'missing-snapshot':
        admit_pipeline(job, docs, kwargs, policy=None if change == 'legacy-upgrade' else INPUT_POLICY_ID)
    kwargs['native_input_policy'] = 'unknown' if change == 'unknown' else INPUT_POLICY_ID
    if change == 'source': docs[0] = docs[0][0], docs[0][1] + b' '
    if change == 'project': kwargs['project_name'] = 'Different project'
    if change == 'selection':
        from fox.forms_understanding_packet import local_packet
        chunk = local_packet(docs)['chunks'][0]
        kwargs['approved_chunk_hashes'] = {chunk['id']: chunk['sha256']}
    if change == 'strategy': kwargs['focus_schema_version'] = 2
    with pytest.raises(OpafError, match='Native input policy'):
        run_prototype_pipeline(job, docs, **kwargs)
    assert model.calls == [] and not (job / 'prototype-pipeline').exists()


def test_old_checkpoint_cannot_be_upgraded_even_with_changed_snapshot(pipeline_setup):
    job, docs, model, _, kwargs = pipeline_setup
    admit_pipeline(job, docs, kwargs, policy=None)
    run_prototype_pipeline(job, docs, **kwargs)
    before = {path.relative_to(job): path.read_bytes() for path in (job / 'prototype-pipeline').rglob('*') if path.is_file()}
    calls = deepcopy(model.calls)
    admit_pipeline(job, docs, kwargs)
    with pytest.raises(OpafError):
        run_prototype_pipeline(job, docs, **kwargs)
    assert model.calls == calls
    assert {path.relative_to(job): path.read_bytes() for path in (job / 'prototype-pipeline').rglob('*') if path.is_file()} == before


def test_new_run_api_persists_choice_with_normal_explicit_scope(client, configured):
    c, root, pid, _, body = prepare(client)
    body['native_input_policy'] = INPUT_POLICY_ID
    response = c.post(f'/api/projects/{pid}/prototype-runs', json=body)
    assert response.status_code == 202, response.text
    snapshot = json.loads((root / 'jobs' / response.json()['id'] / 'source-snapshot.json').read_bytes())
    assert snapshot['prototype']['native_input_policy'] == INPUT_POLICY_ID
    assert snapshot['approvals']['synthetic_prototype'] is True
    validate_prototype_snapshot(snapshot)


@pytest.mark.parametrize('policy', ['unknown', True, 1, {}, []])
def test_new_run_api_rejects_unknown_policy_without_job(client, configured, policy):
    c, root, pid, _, body = prepare(client)
    body['native_input_policy'] = policy
    response = c.post(f'/api/projects/{pid}/prototype-runs', json=body)
    assert response.status_code == 422, response.text
    assert not list((root / 'jobs').glob('fox-*'))
