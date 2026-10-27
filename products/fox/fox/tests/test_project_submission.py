"""Actual authenticated project submission; providers, workers and DB are offline."""
import json
import sqlite3

import pytest

from fox.app import PROJECT_PROFILE
from fox.project_conversion import assess_project_conversion
from test_native_ui import client, assert_not_queued
from test_project_conversion import pair, source, xml, module
from test_source_history_api import no_external_actions


def prepare(client, monkeypatch, files=None):
    c, root, pid, _, _ = client
    monkeypatch.setenv('FOX_CONVERSION_PROFILE', PROJECT_PROFILE)
    files = pair() + pair('BETA', 'FOX_NATIVE_BETA') if files is None else files
    uploaded = c.post(f'/api/projects/{pid}/sources', files=[
        ('files', (item['name'], item['text'].encode())) for item in files])
    assert uploaded.status_code == 200, uploaded.text
    plan = c.get(f'/api/projects/{pid}/conversion-plan').json()
    return c, root, pid, plan


def consent(plan):
    return {'source_hash': plan['source_hash'], 'plan_sha256': plan['plan_sha256'],
        'expected_current_source_set_id': plan['selected_source_set_id'],
        'approved_redacted_source': True, 'approved_external_ai': True,
        'approved_prototype_scope': True}


def test_project_configuration_never_reads_secrets_or_claims_connectivity(client, monkeypatch):
    c, _, _, _ = prepare(client, monkeypatch)
    session = c.get('/api/session').json()
    assert session['conversion_profile'] == PROJECT_PROFILE
    assert session['conversion_configured'] is True
    assert all(row['ready'] for row in session['configuration_checks'])
    assert 'Configuration only' in session['configuration_scope']


def mapped_profile(client):
    from fox.native_project_pipeline import PROJECT_MAPPING_CAPABILITY
    path = client[3]
    profile = json.loads(path.read_text())
    profile.update(schema_version=2, profile_id=PROJECT_PROFILE, **PROJECT_MAPPING_CAPABILITY)
    path.write_text(json.dumps(profile), encoding='utf-8')


def test_ordinary_source_plan_is_ready_but_old_workflow_cannot_queue_it(client, monkeypatch):
    c, root, pid, plan = prepare(client, monkeypatch, pair('ORDERS', 'ORDERS'))
    assert plan['can_generate'] and plan['forms'][0]['table_name'] == 'ORDERS'
    mapping = plan['forms'][0]['storage_mapping']
    assert mapping['source_table_name'] == 'ORDERS'
    assert mapping['target_table_name'].startswith('FOX_NATIVE_')
    assert c.get('/api/session').json()['configured_project_schema_versions'] == [1]
    detail = c.get(f'/api/projects/{pid}').json()
    assert detail['project_capabilities']['process']['enabled'] is False
    response = c.post(f'/api/projects/{pid}/runs', json=consent(plan))
    assert response.status_code == 503 and 'no conversion was queued' in response.json()['detail']
    assert_not_queued(root)


def test_mapped_configuration_freezes_original_sources_and_explicit_stub_contract(client, monkeypatch):
    sources = pair('ORDERS', 'ORDERS') + pair('DETAILS', 'ORDER_LINES')
    c, root, pid, plan = prepare(client, monkeypatch, sources)
    mapped_profile(client)
    session = c.get('/api/session').json()
    assert session['conversion_configured'] and session['configured_project_schema_versions'] == [1, 2]
    assert c.get(f'/api/projects/{pid}').json()['project_capabilities']['process']['enabled'] is True
    response = c.post(f'/api/projects/{pid}/runs', json=consent(plan))
    assert response.status_code == 202, response.text
    snapshot = json.loads((root / 'jobs' / response.json()['id'] / 'source-snapshot.json').read_text())
    expected = {item['name']: (item['text'], item['sha256']) for item in sources}
    assert {item['name']: (item['text'], item['sha256']) for item in snapshot['files']} == expected
    spec = snapshot['native_project']
    assert spec['schema_version'] == 2 and spec['project_id'] == pid
    assert {item['storage_mapping']['source_table_name'] for item in spec['forms']} == {'ORDERS', 'ORDER_LINES'}
    for form in spec['forms']:
        assert form['native_form']['table_name'] == form['storage_mapping']['target_table_name']
        assert form['storage_mapping']['project_id'] == pid and form['ddl_sources']
    assert snapshot['source_hash'] == plan['source_hash'] and snapshot['plan_sha256'] == plan['plan_sha256']


def test_same_ordinary_schema_in_independent_projects_has_independent_stubs(client, monkeypatch):
    c, root, first, plan = prepare(client, monkeypatch, pair('ORDERS', 'ORDERS'))
    second = c.post('/api/projects', json={'customer': 'Synthetic', 'name': 'Independent application'}).json()['id']
    files = pair('ORDERS', 'ORDERS')
    c.post(f'/api/projects/{second}/sources', files=[('files', (item['name'], item['text'].encode())) for item in files])
    other = c.get(f'/api/projects/{second}/conversion-plan').json()
    assert plan['source_hash'] == other['source_hash']
    assert plan['forms'][0]['storage_mapping']['target_table_name'] != other['forms'][0]['storage_mapping']['target_table_name']
    assert_not_queued(root)


def test_one_source_bound_snapshot_contains_both_forms_and_one_run(client, monkeypatch):
    c, root, pid, plan = prepare(client, monkeypatch)
    result = c.post(f'/api/projects/{pid}/runs', json=consent(plan))
    assert result.status_code == 202, result.text
    rid = result.json()['id']
    snapshot = json.loads((root / 'jobs' / rid / 'source-snapshot.json').read_text())
    assert snapshot['project'] == snapshot['project_id'] == pid
    assert snapshot['conversion_profile'] == PROJECT_PROFILE
    assert snapshot['selected_source_set_id'] == plan['selected_source_set_id']
    expected = assess_project_conversion(snapshot['files'], project_id=pid,
        project_name=snapshot['project_name'], source_hash=snapshot['source_hash'])
    assert snapshot['plan_sha256'] == expected['plan_sha256'] == plan['plan_sha256']
    assert snapshot['native_project'] == expected['rendering_spec']
    assert len(snapshot['native_project']['forms']) == 2
    assert 'native_form' not in snapshot
    assert c.post(f'/api/projects/{pid}/runs', json=consent(plan)).json()['id'] == rid
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 1
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0] == 0
    assert c.get(f'/api/projects/{pid}/runs/{rid}/download').status_code == 409


@pytest.mark.parametrize('field', ['source_hash', 'plan_sha256', 'expected_current_source_set_id'])
def test_stale_source_or_plan_cannot_submit(client, monkeypatch, field):
    c, root, pid, plan = prepare(client, monkeypatch)
    body = consent(plan)
    body[field] = 'ss-' + '0' * 32 if field == 'expected_current_source_set_id' else '0' * 64
    assert c.post(f'/api/projects/{pid}/runs', json=body).status_code == 409
    assert_not_queued(root)


@pytest.mark.parametrize('field', ['plan_sha256', 'expected_current_source_set_id'])
def test_project_identity_fields_cannot_be_omitted(client, monkeypatch, field):
    c, root, pid, plan = prepare(client, monkeypatch)
    body = consent(plan); body.pop(field)
    assert c.post(f'/api/projects/{pid}/runs', json=body).status_code == 409
    assert_not_queued(root)


@pytest.mark.parametrize('field', ['approved_redacted_source', 'approved_external_ai', 'approved_prototype_scope'])
def test_project_requires_all_processing_consents(client, monkeypatch, field):
    c, root, pid, plan = prepare(client, monkeypatch)
    assert c.post(f'/api/projects/{pid}/runs', json={**consent(plan), field: False}).status_code == 422
    assert_not_queued(root)


def test_one_missing_form_definition_blocks_the_entire_project(client, monkeypatch):
    c, root, pid, plan = prepare(client, monkeypatch,
        pair() + [source('beta.xml', xml(module('BETA', 'FOX_NATIVE_BETA')))])
    assert plan['summary']['form_count'] == 2 and not plan['can_generate']
    result = c.post(f'/api/projects/{pid}/runs', json=consent(plan))
    assert result.status_code == 409 and 'No partial' in result.json()['detail']
    assert_not_queued(root)


def test_unknown_converter_configuration_keeps_sources_but_never_queues(client, monkeypatch):
    c, root, pid, plan = prepare(client, monkeypatch)
    monkeypatch.setenv('FOX_CONVERTER_URL', 'http://public.invalid:8091')
    assert c.get('/api/session').json()['conversion_configured'] is False
    assert c.post(f'/api/projects/{pid}/runs', json=consent(plan)).status_code == 503
    assert c.get(f'/api/projects/{pid}/conversion-plan').json() == plan
    assert_not_queued(root)


def test_client_cannot_submit_a_partial_or_invented_rendering_spec(client, monkeypatch):
    c, root, pid, plan = prepare(client, monkeypatch)
    result = c.post(f'/api/projects/{pid}/runs', json={**consent(plan), 'native_project': {'forms': []}})
    assert result.status_code == 422
    assert_not_queued(root)


def test_plan_is_rechecked_after_write_lock_before_snapshot(client, monkeypatch):
    import fox.app as app_module
    c, root, pid, plan = prepare(client, monkeypatch)
    configured = app_module.conversion_configuration
    def change_project_during_preflight():
        result = configured()
        with sqlite3.connect(root / 'fox.sqlite3') as db:
            db.execute('UPDATE projects SET name=? WHERE id=?', ('Changed during preflight', pid))
        return result
    monkeypatch.setattr(app_module, 'conversion_configuration', change_project_during_preflight)
    response = c.post(f'/api/projects/{pid}/runs', json=consent(plan))
    assert response.status_code == 409 and 'plan changed' in response.json()['detail']
    assert_not_queued(root)


@pytest.mark.parametrize('name', ['N' * 81, '&APP_NAME.', 'Name\nwith a new line'])
def test_new_project_name_matches_renderer_bounds(client, name):
    c, _, _, _, _ = client
    result = c.post('/api/projects', json={'customer': 'Synthetic', 'name': name})
    assert result.status_code == 422


def test_run_cannot_be_accepted_by_forging_only_database_state(client, monkeypatch):
    c, root, pid, plan = prepare(client, monkeypatch)
    result = c.post(f'/api/projects/{pid}/runs', json=consent(plan))
    rid = result.json()['id']
    job = root / 'jobs' / rid
    (job / 'apex-package.zip').write_bytes(b'not a verified native project')
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute('UPDATE runs SET state=?,artifact=? WHERE id=?',
            ('REVIEW_REQUIRED', f'jobs/{rid}/apex-package.zip', rid))
    body = {'source_hash': plan['source_hash'], 'business_flow_tested': True,
        'remediation_reviewed': True, 'notes': 'Isolated negative guard; no genuine acceptance.'}
    assert c.post(f'/api/projects/{pid}/runs/{rid}/accept', json=body).status_code == 409
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0] == 0


def test_project_run_projection_does_not_echo_provider_diagnostics(client, monkeypatch):
    c, root, pid, plan = prepare(client, monkeypatch)
    rid = c.post(f'/api/projects/{pid}/runs', json=consent(plan)).json()['id']
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute('UPDATE runs SET message=? WHERE id=?', ('PRIVATE PROVIDER RESPONSE', rid))
    response = c.get(f'/api/projects/{pid}')
    assert response.status_code == 200
    run = response.json()['runs'][0]
    assert run['project_id'] == pid and run['artifact_generated'] is False
    assert run['technical_verified'] is False and run['human_accepted'] is False
    assert run['downloadable'] is False
    assert run['recovery']['safety'] == 'read_only'
    assert 'PRIVATE PROVIDER RESPONSE' not in response.text
    assert 'artifact' not in run and 'project' not in run


@pytest.mark.parametrize('raw', [b'{', b'[]', b'{"x":1,"x":2}'])
def test_malformed_saved_evidence_has_safe_actionable_response(client, monkeypatch, raw):
    c, root, pid, plan = prepare(client, monkeypatch)
    rid = c.post(f'/api/projects/{pid}/runs', json=consent(plan)).json()['id']
    path = root / 'jobs' / rid / 'release-evidence.json'
    path.write_bytes(raw)
    result = c.get(f'/api/projects/{pid}/runs/{rid}/evidence')
    assert result.status_code == 409
    assert 'no new conversion was started' in result.json()['detail']
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 1
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0] == 0


@pytest.mark.parametrize('state', ['QA_REQUIRED', 'VERIFIED', 'ACCEPTED'])
def test_database_state_alone_cannot_produce_success_copy(client, monkeypatch, state):
    c, root, pid, plan = prepare(client, monkeypatch)
    rid = c.post(f'/api/projects/{pid}/runs', json=consent(plan)).json()['id']
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute('UPDATE runs SET state=? WHERE id=?', (state, rid))
    run = c.get(f'/api/projects/{pid}').json()['runs'][0]
    assert not run['artifact_generated'] and not run['technical_verified'] and not run['human_accepted']
    assert not run['downloadable']
    assert run['message'] not in {
        'The generated package is waiting for technical verification.',
        'Technical checks are recorded. Review the evidence and validate the business behavior.',
        'Human review is recorded. Download availability is checked against the exact accepted package.'}


def test_evidence_file_open_race_has_safe_response(client, monkeypatch):
    from fox import native_verification
    c, root, pid, plan = prepare(client, monkeypatch)
    rid = c.post(f'/api/projects/{pid}/runs', json=consent(plan)).json()['id']
    def vanished(*args, **kwargs):
        raise FileNotFoundError('private synthetic filesystem diagnostic')
    monkeypatch.setattr(native_verification, '_read', vanished)
    result = c.get(f'/api/projects/{pid}/runs/{rid}/evidence')
    assert result.status_code == 409
    assert 'private synthetic filesystem diagnostic' not in result.text
