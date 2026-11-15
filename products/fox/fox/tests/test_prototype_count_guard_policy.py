"""Actual local API/SQLite/snapshots; authored model cache, never live proof."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3

import pytest

from fox import source_history
from fox.forms_count_guard_selection import POLICY_ID, describe_count_checks
from fox.forms_native_required_plan import build_native_plan
from fox.forms_understanding_packet import local_packet
from fox.intake import checked_source
from fox.opaf import OpafError, canonical_hash
from fox.prototype_admission import prepare_prototype_admission
from fox.prototype_job import validate_prototype_snapshot, run_prototype_job
from fox.prototype_pipeline import run_prototype_pipeline, authorize_prototype_request
from fox.prototype_project_routes import PrototypeRunInput, PrototypeContinuationInput
from test_forms_native_count_guard_plan import source
from test_forms_native_plan import design
from test_prototype_pipeline import PROFILE, TARGET, SyntheticOpaf
from test_prototype_project_routes import configured
from test_source_history_api import client, settings, no_external_actions, upload


def documents():
    return [('synthetic.xml', source())]


def choice_fields(docs=None):
    docs = documents() if docs is None else docs
    found = describe_count_checks(docs)
    assert len(found['checks']) == 1
    return {'count_guard_policy': POLICY_ID, 'count_guard_selection': found['checks'][0]['selection'],
            'approved_count_guard_partial_scope': True}


def prepare_api(case):
    c, root, pid = case
    upload(c, pid, documents())
    response = c.get(f'/api/projects/{pid}/prototype-count-checks')
    assert response.status_code == 200, response.text
    discovery = response.json()
    assessment = c.get(f'/api/projects/{pid}/prototype-assessment').json()
    body = {key: discovery[key] for key in ('source_hash', 'source_binding', 'target_profile_sha256')}
    body.update(expected_current_source_set_id=discovery['selected_source_set_id'], approved_chunk_hashes={},
        approved_redacted_source=True, approved_external_ai=True, approved_prototype_scope=True,
        **choice_fields())
    assert discovery['source_binding'] == assessment['source_binding']
    return c, root, pid, discovery, body


def tree_bytes(path):
    return {str(p.relative_to(path)): p.read_bytes() for p in path.rglob('*') if p.is_file()}


def test_actual_readonly_discovery_and_creation_snapshot_bind_source_ids(client, configured):
    c, root, pid, found, body = prepare_api(client)
    before = tree_bytes(root / 'jobs')
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        counts = [db.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0] for table in ('runs', 'events', 'acceptances')]
    response = c.get(f'/api/projects/{pid}/prototype-count-checks')
    assert response.json() == found and response.headers['cache-control'] == 'no-store'
    assert tree_bytes(root / 'jobs') == before
    assert found['processing_approved'] is found['partial_scope_approved'] is found['business_behavior_accepted'] is False
    assert 'TriggerText' not in response.text and 'SELECT COUNT' not in response.text
    assert found['checks'][0]['selection']['source_sha256'] == hashlib.sha256(documents()[0][1]).hexdigest()
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert counts == [db.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0] for table in ('runs', 'events', 'acceptances')]
    queued = c.post(f'/api/projects/{pid}/prototype-runs', json=body)
    assert queued.status_code == 202, queued.text
    job = root / 'jobs' / queued.json()['id']
    snapshot = json.loads((job / 'source-snapshot.json').read_bytes())
    assert validate_prototype_snapshot(snapshot) == documents()
    assert snapshot['prototype']['count_guard'] == {'policy_id': POLICY_ID,
        'selection': body['count_guard_selection'], 'partial_scope_consent': True}
    assert snapshot['approvals']['isolated_count_check'] is True
    assert 'native_input_policy' not in snapshot['prototype']
    plan = build_native_plan(documents(), design(documents()), project_id=pid,
        project_name=snapshot['project_name'], approved_policy_id=snapshot['prototype']['approved_policy_id'],
        count_guard=snapshot['prototype']['count_guard'])
    assert plan['rendering_spec']['schema_version'] == 3
    assert plan['count_guard_plan']['business_behavior_accepted'] is False
    assert c.post(f'/api/projects/{pid}/prototype-runs', json=body).status_code == 409


@pytest.mark.parametrize('mutation', ['no_policy', 'no_selection', 'no_consent', 'false_consent',
    'integer_consent', 'stale_sha', 'unknown_button', 'unknown_policy', 'extra_selector', 'target', 'source_binding'])
def test_actual_api_rejects_missing_unsupported_stale_scope_without_queue(client, configured, mutation):
    c, root, pid, _, body = prepare_api(client)
    if mutation == 'no_policy': body.pop('count_guard_policy')
    elif mutation == 'no_selection': body.pop('count_guard_selection')
    elif mutation == 'no_consent': body.pop('approved_count_guard_partial_scope')
    elif mutation == 'false_consent': body['approved_count_guard_partial_scope'] = False
    elif mutation == 'integer_consent': body['approved_count_guard_partial_scope'] = 1
    elif mutation == 'stale_sha': body['count_guard_selection']['source_sha256'] = 'b' * 64
    elif mutation == 'unknown_button': body['count_guard_selection']['item'] = 'MISSING_BUTTON'
    elif mutation == 'unknown_policy': body['count_guard_policy'] = 'unknown'
    elif mutation == 'extra_selector': body['count_guard_selection']['sql'] = 'select 1 from dual'
    elif mutation == 'target': body['target_profile_sha256'] = 'b' * 64
    else: body['source_binding'] = 'b' * 64
    assert c.post(f'/api/projects/{pid}/prototype-runs', json=body).status_code in {409, 422}
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 0
    assert not list((root / 'jobs').glob('*/source-snapshot.json'))


def test_discovery_owner_boundary_missing_target_and_unsupported_source(client, configured, monkeypatch):
    c, root, pid, _, body = prepare_api(client)
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)', ('other', 'other-owner', 'Test', 'Private', '', 1))
    assert c.get('/api/projects/other/prototype-count-checks').status_code == 404
    monkeypatch.delenv('FOX_PROTOTYPE_PROFILE_FILE')
    found = c.get(f'/api/projects/{pid}/prototype-count-checks').json()
    assert found['conversion_configured'] is False and found['target_profile_sha256'] is None
    assert c.post(f'/api/projects/{pid}/prototype-runs', json=body).status_code == 503
    altered = [('synthetic.xml', source().replace(b'NVL(QUANTITY,0)=0', b'NVL(QUANTITY,0)&lt;0'))]
    result = describe_count_checks(altered)
    assert result['checks'] == [] and len(result['unsupported']) == 1
    assert result['processing_approved'] is False


@pytest.mark.parametrize('model', [PrototypeRunInput, PrototypeContinuationInput])
def test_new_choice_fields_cannot_be_submitted_as_continuation_or_retry(client, configured, model):
    _, _, _, _, body = prepare_api(client)
    if model is PrototypeContinuationInput:
        body['checkpoint_sha256'] = 'c' * 64
    with pytest.raises(ValueError, match='creation-only'):
        model.model_validate(body)


def admitted_pipeline(tmp_path, *, native_input_policy=None):
    docs = documents()
    packet = local_packet(docs)
    chosen = prepare_prototype_admission(docs, expected_source_binding=packet['source_binding'],
        approved_chunk_hashes={}, target_profile_sha256=canonical_hash(TARGET),
        approved_redacted_source=True, approved_external_ai=True, approved_prototype_scope=True,
        native_input_policy=native_input_policy, **choice_fields(docs))['prototype']
    files = [checked_source(name, raw) for name, raw in docs]
    snapshot = {'project': 'synthetic-project', 'project_id': 'synthetic-project',
        'project_name': 'Synthetic native check', 'source_hash': source_history._hash(files),
        'conversion_profile': 'native-blueprint-prototype-v1', 'selected_source_set_id': 'ss-' + '1' * 32,
        'files': files, 'prototype': chosen, 'approvals': {'owner': 'synthetic-owner', 'approved_at': 1.0,
            'redacted_source': True, 'external_ai': True, 'synthetic_prototype': True, 'isolated_count_check': True}}
    job = tmp_path / ('fox-' + '1' * 20)
    job.mkdir()
    (job / 'source-snapshot.json').write_text(json.dumps(snapshot), encoding='utf-8')
    client, approvals = SyntheticOpaf(), []
    kwargs = dict(project_id=snapshot['project_id'], project_name=snapshot['project_name'],
        expected_source_binding=packet['source_binding'], approved_chunk_hashes={},
        approved_policy_id=chosen['approved_policy_id'], opaf_client=client, profile=deepcopy(PROFILE),
        target_profile_loader=lambda: deepcopy(TARGET),
        processing_approval_check=lambda context: approvals.append(context) or True,
        count_guard=chosen['count_guard'])
    return job, docs, snapshot, client, approvals, kwargs


@pytest.mark.parametrize('native_policy', [None, 'forms-required-inputs-v1'])
def test_local_pipeline_real_v3_render_and_readonly_source_authority(tmp_path, native_policy):
    job, docs, snapshot, model, approvals, kwargs = admitted_pipeline(tmp_path, native_input_policy=native_policy)
    result = run_prototype_pipeline(job, docs, **kwargs)
    assert result['status'] == 'BLOCKED_ADAPTER' and result['stage'] == 'validate'
    assert result['facts']['native_source_rendered'] is True
    assert result['facts']['native_apex_generated'] is result['facts']['business_behavior_accepted'] is False
    assert all(context['count_guard'] == snapshot['prototype']['count_guard'] for context in approvals)
    plan = json.loads((job / 'prototype-pipeline/native-plan.json').read_bytes())
    rendered = json.loads((job / 'prototype-pipeline/rendered.json').read_bytes())
    binding = json.loads((job / 'prototype-pipeline/binding.json').read_bytes())
    manifest = json.loads((job / 'prototype-pipeline/sources-manifest.json').read_bytes())
    reviews = json.loads((job / 'prototype-pipeline/review-index.json').read_bytes())
    request = {'schema_version': 1, 'scope': 'fox-prototype-converter-request-v1', 'job_id': job.name,
        'project_id': snapshot['project_id'], 'source_binding': binding['source_binding'],
        'plan_sha256': plan['plan_sha256'], 'rendering_spec': plan['rendering_spec'],
        'rendered_zip_sha256': rendered['zip_sha256'], 'prior_receipts': {},
        'source_authority': {'schema_version': 1, 'scope': 'fox-prototype-source-authority-v1',
            'binding_sha256': canonical_hash(binding), 'sources_manifest_sha256': canonical_hash(manifest),
            'review_index_sha256': canonical_hash(reviews)}}
    before = tree_bytes(job)
    calls = deepcopy(model.calls)
    assert authorize_prototype_request(job, request) == request
    from fox.prototype_mapping_epochs import reconstruct
    assert reconstruct(job, snapshot, (job / 'source-snapshot.json').read_bytes(), TARGET)[0] == local_packet(docs)
    assert tree_bytes(job) == before and model.calls == calls
    staged = tmp_path / 'receiver' / job.name
    shutil.copytree(job / 'prototype-pipeline', staged / 'prototype-pipeline')
    with pytest.raises(OpafError, match='Count-check|Native input'):
        authorize_prototype_request(staged, request)
    with pytest.raises(OpafError, match='Count-check|Native input'):
        authorize_prototype_request(staged, {**request, 'staged_projection': True})
    assert authorize_prototype_request(staged, request, staged_projection=True) == request
    snapshot['approvals']['isolated_count_check'] = False
    (job / 'source-snapshot.json').write_text(json.dumps(snapshot), encoding='utf-8')
    with pytest.raises(OpafError):
        authorize_prototype_request(job, request)
    assert model.calls == calls


@pytest.mark.parametrize('mutation', ['missing_approval', 'revoked_approval', 'changed_selection', 'changed_source', 'null_group'])
def test_snapshot_rejects_count_check_tampering_before_configuration(tmp_path, mutation):
    job, _, snapshot, model, _, _ = admitted_pipeline(tmp_path)
    if mutation == 'missing_approval': snapshot['approvals'].pop('isolated_count_check')
    elif mutation == 'revoked_approval': snapshot['approvals']['isolated_count_check'] = False
    elif mutation == 'changed_selection': snapshot['prototype']['count_guard']['selection']['item'] = 'OTHER'
    elif mutation == 'changed_source': snapshot['files'][0]['text'] += ' '
    else: snapshot['prototype']['count_guard'] = None
    (job / 'source-snapshot.json').write_text(json.dumps(snapshot), encoding='utf-8')
    configurations = []
    with pytest.raises(OpafError):
        run_prototype_job(job, approval_check=lambda _: True,
            configuration_loader=lambda *args, **kwargs: configurations.append(True))
    assert configurations == [] and model.calls == []


def test_no_snapshot_cannot_gain_count_check_rights(tmp_path):
    job, docs, _, model, _, kwargs = admitted_pipeline(tmp_path)
    (job / 'source-snapshot.json').unlink()
    with pytest.raises(OpafError, match='Count-check'):
        run_prototype_pipeline(job, docs, **kwargs)
    assert model.calls == []


def test_legacy_snapshot_cannot_be_upgraded_by_a_new_requested_choice(tmp_path):
    job, docs, snapshot, model, _, kwargs = admitted_pipeline(tmp_path)
    snapshot['prototype'].pop('count_guard')
    snapshot['approvals'].pop('isolated_count_check')
    original = json.dumps(snapshot).encode()
    (job / 'source-snapshot.json').write_bytes(original)
    assert validate_prototype_snapshot(snapshot) == docs
    with pytest.raises(OpafError, match='Count-check'):
        run_prototype_pipeline(job, docs, **kwargs)
    assert model.calls == []
    assert (job / 'source-snapshot.json').read_bytes() == original


def test_revoked_current_owner_approval_stops_before_configuration(tmp_path):
    job, _, _, model, _, _ = admitted_pipeline(tmp_path)
    configurations = []
    with pytest.raises(OpafError, match='approval is no longer current'):
        run_prototype_job(job, approval_check=lambda _: False,
            configuration_loader=lambda *args, **kwargs: configurations.append(True))
    assert configurations == [] and model.calls == []


@pytest.mark.parametrize('native_policy', [None, 'forms-required-inputs-v1'])
def test_actual_recovery_api_inherits_exact_selection_without_new_approval_fields(client, configured, monkeypatch, native_policy):
    from test_prototype_mapping_recovery import EmptyMapper
    c, root, pid, _, body = prepare_api(client)
    envelope = {'target_profile': deepcopy(TARGET), 'target_profile_sha256': canonical_hash(TARGET)}
    monkeypatch.setattr('fox.prototype_job.load_prototype_profile', lambda _: deepcopy(envelope))
    body['target_profile_sha256'] = envelope['target_profile_sha256']
    if native_policy is not None:
        body['native_input_policy'] = native_policy
    queued = c.post(f'/api/projects/{pid}/prototype-runs', json=body)
    assert queued.status_code == 202, queued.text
    rid = queued.json()['id']
    job = root / 'jobs' / rid
    original = (job / 'source-snapshot.json').read_bytes()
    snapshot = json.loads(original)
    model = EmptyMapper()
    with pytest.raises(ValueError):
        run_prototype_pipeline(job, documents(), project_id=pid, project_name=snapshot['project_name'],
            expected_source_binding=body['source_binding'], approved_chunk_hashes={},
            approved_policy_id=snapshot['prototype']['approved_policy_id'], opaf_client=model,
            profile=deepcopy(PROFILE), target_profile_loader=lambda: deepcopy(TARGET),
            processing_approval_check=lambda _: True, focus_schema_version=2,
            count_guard=snapshot['prototype']['count_guard'])
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute("UPDATE runs SET state='ATTENTION' WHERE id=?", (rid,))
    before = tree_bytes(job)
    url = f'/api/projects/{pid}/prototype-runs/{rid}'
    checked = c.get(url + '/mapping-recovery')
    assert checked.status_code == 200, checked.text
    assert checked.json()['eligible'] is True
    assert tree_bytes(job) == before
    retry_body = {key: value for key, value in body.items()
                  if key not in {'count_guard_policy', 'count_guard_selection', 'approved_count_guard_partial_scope'}}
    retried = c.post(url + '/retry-mapping', json=retry_body)
    assert retried.status_code == 202, retried.text
    child = json.loads((root / 'jobs' / retried.json()['id'] / 'source-snapshot.json').read_bytes())
    assert child['prototype']['count_guard'] == snapshot['prototype']['count_guard']
    assert child['prototype'].get('native_input_policy') == native_policy
    assert child['approvals']['isolated_count_check'] is True
    assert validate_prototype_snapshot(child) == documents()
    assert (job / 'source-snapshot.json').read_bytes() == original
    assert model.calls and len(model.calls) == 1


def test_schema_fixture_receipt_is_preserved_whole_not_filtered():
    from fox.prototype_pipeline import _check_converter_receipt
    request = {'source_binding': 'a' * 64, 'plan_sha256': 'b' * 64}
    receipt = {'stage': 'prepare_schema', 'request_sha256': canonical_hash(request),
        'source_binding': request['source_binding'], 'plan_sha256': request['plan_sha256'],
        'ready_for_import': True, 'count_guard_fixture': {'scope': 'authored-metadata-preservation-test-only',
            'rows': [{'label': 'synthetic-null-case'}, {'label': 'synthetic-nonzero-case'}]}}
    original = deepcopy(receipt)
    assert _check_converter_receipt('prepare_schema', request, receipt) is receipt
    assert receipt == original
