"""Isolated authenticated API/worker tests. Compiler doubles are explicitly synthetic.

No network, paid model, SQLcl or Oracle execution occurs in this suite.
"""
import json
import logging
import sqlite3
import uuid

import pytest
from fastapi.testclient import TestClient

from fox import xml_mapping_job as jobs
from fox.app import create_app
from fox.worker import process_one
from fox.prototype_export_only import _members
from test_source_history_api import settings, no_external_actions, upload, ORIGIN, login, new_project
from test_xml_mapping import source, fake_validator


@pytest.fixture
def client(tmp_path_factory, settings):
    # Deep job/compiler-log paths need short fixture directories on Windows.
    root = tmp_path_factory.mktemp('x') / 'd'
    with TestClient(create_app(root, enable_worker=False), base_url=ORIGIN) as c:
        login(c)
        yield c, root, new_project(c)


@pytest.fixture(autouse=True)
def installed_compiler(monkeypatch, tmp_path):
    compiler = tmp_path / 'synthetic-sqlcl-not-executed'
    compiler.write_text('SYNTHETIC TEST ONLY')
    monkeypatch.setenv('FOX_EXPORT_SQLCL_PATH', str(compiler))
    monkeypatch.setattr('fox.xml_mapping.validate_offline', fake_validator)
    # Provider/adapter configuration is deliberately absent.
    monkeypatch.delenv('FOX_RUN_ADAPTER', raising=False)
    monkeypatch.delenv('FOX_PROTOTYPE_PROFILE_FILE', raising=False)
    original = jobs.run_job
    def diagnostic_job(*args, **kwargs):
        try:
            return original(*args, **kwargs)
        except Exception:
            logging.exception('Synthetic mapping job stopped')
            raise
    monkeypatch.setattr(jobs, 'run_job', diagnostic_job)


def prepare(client):
    c, root, pid = client
    upload(c, pid, [('order.xml', source())])
    response = c.get(f'/api/projects/{pid}/xml-mapping')
    assert response.status_code == 200, response.text
    assessment = response.json()
    assert assessment['available'] is True, assessment
    body = {key: assessment[key] for key in ('source_hash', 'selected_source_set_id', 'source_binding', 'catalog_sha256')}
    body.update(request_id=str(uuid.uuid4()), approved_synthetic_scope=True, approved_local_source_processing=True)
    return c, root, pid, assessment, body


def connection(root):
    def db():
        c = sqlite3.connect(root / 'fox.sqlite3')
        c.row_factory = sqlite3.Row
        return c
    return db


def queue(client):
    c, root, pid, assessment, body = prepare(client)
    response = c.post(f'/api/projects/{pid}/xml-mapping/runs', json=body)
    assert response.status_code == 202, response.text
    return c, root, pid, body, response.json()


def finish(client):
    c, root, pid, body, run = queue(client)
    process_one(connection(root), root)
    completed = c.get(f"/api/projects/{pid}/xml-mapping/runs/{run['id']}").json()
    assert completed['state'] == 'GENERATED', completed
    return c, root, pid, body, completed


def test_auth_origin_and_cross_owner(client):
    c, root, pid, assessment, body = prepare(client)
    c.headers['Origin'] = 'https://other.invalid'
    assert c.post(f'/api/projects/{pid}/xml-mapping/runs', json=body).status_code == 403
    c.headers['Origin'] = ORIGIN
    with connection(root)() as db:
        db.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)', ('other', 'other-owner', 'T', 'Private', '', 1))
    assert c.get('/api/projects/other/xml-mapping').status_code == 404
    assert c.post('/api/projects/other/xml-mapping/runs', json=body).status_code == 404
    c.cookies.clear()
    assert c.get(f'/api/projects/{pid}/xml-mapping').status_code == 401


def test_queue_exact_source_consent_without_ai_approvals(client):
    c, root, pid, body, run = queue(client)
    assert run['conversion_profile'] == 'xml-mapping-v1'
    assert run['request_id'] == body['request_id']
    assert run['generated_units'] is None and run['total_units'] is None
    snapshot = json.loads((root / 'jobs' / run['id'] / 'source-snapshot.json').read_bytes())
    assert snapshot['files'][0]['text'].encode() == source()
    assert snapshot['request'] == body
    assert 'approvals' not in snapshot
    with connection(root)() as db:
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0] == 0
        assert db.execute('SELECT action FROM events WHERE object_id=?', (run['id'],)).fetchone()[0].startswith(jobs.APPROVAL)


@pytest.mark.parametrize('field,value', [('source_hash', 'f'*64), ('source_binding', 'f'*64),
    ('selected_source_set_id', 'ss-'+'f'*32), ('catalog_sha256', 'f'*64),
    ('approved_synthetic_scope', False), ('approved_local_source_processing', False),
    ('approved_local_source_processing', 'true'), ('request_id', 'not-a-uuid')])
def test_stale_or_unapproved_rejected(client, field, value):
    c, root, pid, _, body = prepare(client)
    body[field] = value
    assert c.post(f'/api/projects/{pid}/xml-mapping/runs', json=body).status_code in (409, 422)
    with connection(root)() as db:
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 0


def test_idempotent_exact_request_and_conflict(client):
    c, root, pid, body, first = queue(client)
    second = c.post(f'/api/projects/{pid}/xml-mapping/runs', json=body)
    assert second.status_code == 202 and second.json()['id'] == first['id']
    body['source_hash'] = 'e'*64
    assert c.post(f'/api/projects/{pid}/xml-mapping/runs', json=body).status_code == 409
    with connection(root)() as db:
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 1


def test_real_render_worker_and_checked_download_compiler_double(client):
    c, root, pid, body, run = finish(client)
    assert run['format_validated'] is True
    assert (run['generated_units'], run['unsupported_units'], run['total_units']) == (1, 0, 1)
    assert run['runtime_verified'] is False and run['business_behavior_accepted'] is False
    response = c.get(run['download_url'])
    assert response.status_code == 200
    assert jobs.sha(response.content) == run['package_sha256']
    assert response.headers['content-disposition'].endswith('-APEXlang.zip"')
    history = c.get(f'/api/projects/{pid}/xml-mapping').json()['runs']
    assert history == [run]
    project_run = c.get(f'/api/projects/{pid}').json()['runs'][0]
    assert project_run == run  # No AI recovery, acceptance or verifier projection.
    with connection(root)() as db:
        assert db.execute('SELECT artifact FROM runs WHERE id=?', (run['id'],)).fetchone()[0] is None
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0] == 0


@pytest.mark.parametrize('target', ['candidate.zip', 'apexlang.zip', 'result.json', 'validation-log', 'snapshot'])
def test_tamper_blocks_download_without_repair(client, target):
    c, root, pid, body, run = finish(client)
    job = root / 'jobs' / run['id']
    path = (job / 'source-snapshot.json' if target == 'snapshot' else
            next((job / 'xml-mapping' / 'validation').glob('*.log')) if target == 'validation-log' else
            job / 'xml-mapping' / target)
    path.write_bytes(path.read_bytes() + b'\nTAMPER')
    before = {str(p): p.read_bytes() for p in job.rglob('*') if p.is_file()}
    response = c.get(run['download_url'])
    assert response.status_code == 409
    assert c.get(f"/api/projects/{pid}/xml-mapping/runs/{run['id']}").json()['state'] == 'ATTENTION'
    assert before == {str(p): p.read_bytes() for p in job.rglob('*') if p.is_file()}
    assert c.get(f'/api/projects/{pid}/xml-mapping').json()['available'] is False
    assert c.post(f'/api/projects/{pid}/xml-mapping/runs', json={**body, 'request_id': str(uuid.uuid4())}).status_code == 409


def test_worker_source_change_stops_before_compiler(client, monkeypatch):
    c, root, pid, body, run = queue(client)
    upload(c, pid, [('order.xml', source(module='CHANGED'))])
    def forbidden(*args, **kwargs):
        pytest.fail('Compiler must not run for stale source')
    monkeypatch.setattr('fox.xml_mapping.validate_xml_package', forbidden)
    process_one(connection(root), root)
    result = c.get(f"/api/projects/{pid}/xml-mapping/runs/{run['id']}").json()
    assert result['state'] == 'ATTENTION' and result['current_source'] is False
    assert not (root / 'jobs' / run['id'] / 'xml-mapping').exists()


def test_restart_interrupted_attention_never_replays(client):
    c, root, pid, body, run = queue(client)
    with connection(root)() as db:
        db.execute("UPDATE runs SET state='PROCESSING'")
    with TestClient(create_app(root, enable_worker=False), base_url=ORIGIN) as restarted:
        login(restarted)
        value = restarted.get(f"/api/projects/{pid}/xml-mapping/runs/{run['id']}").json()
        assert value['state'] == 'ATTENTION'
        assert restarted.post(f'/api/projects/{pid}/xml-mapping/runs', json=body).json()['id'] == run['id']
        body['request_id'] = str(uuid.uuid4())
        assert restarted.post(f'/api/projects/{pid}/xml-mapping/runs', json=body).status_code == 409
    process_one(connection(root), root)
    assert not (root / 'jobs' / run['id'] / 'xml-mapping').exists()


def test_queued_restart_can_complete_once(client):
    c, root, pid, body, run = queue(client)
    with TestClient(create_app(root, enable_worker=False), base_url=ORIGIN):
        process_one(connection(root), root)
        process_one(connection(root), root)
    with connection(root)() as db:
        assert db.execute('SELECT state FROM runs').fetchone()[0] == 'GENERATED'
        assert db.execute('SELECT COUNT(*) FROM events WHERE action LIKE ?', (jobs.RESULT+'%',)).fetchone()[0] == 1


def test_failure_retains_attempt_and_never_replays(client, monkeypatch):
    c, root, pid, body, run = queue(client)
    def fail(*args, **kwargs):
        raise RuntimeError('Synthetic offline compiler failure; no compiler executed.')
    monkeypatch.setattr('fox.xml_mapping.validate_xml_package', fail)
    process_one(connection(root), root)
    result = c.get(f"/api/projects/{pid}/xml-mapping/runs/{run['id']}").json()
    assert result['state'] == 'ATTENTION' and result['format_validated'] is False
    assert (root/'jobs'/run['id']/'xml-mapping'/'candidate.zip').exists()
    body['request_id'] = str(uuid.uuid4())
    assert c.post(f'/api/projects/{pid}/xml-mapping/runs', json=body).status_code == 409


def test_complete_set_rejects_non_xml_and_missing_compiler(client, monkeypatch):
    c, root, pid, _, body = prepare(client)
    upload(c, pid, [('order.xml', source()), ('schema.sql', b'CREATE TABLE FOX_TEST (ID NUMBER);')])
    assert c.get(f'/api/projects/{pid}/xml-mapping').json()['available'] is False
    assert c.post(f'/api/projects/{pid}/xml-mapping/runs', json=body).status_code == 409
    monkeypatch.setenv('FOX_EXPORT_SQLCL_PATH', 'nonexistent-synthetic-sqlcl')
    assert c.get(f'/api/projects/{pid}/xml-mapping').json()['available'] is False


def test_historical_attention_preserved_but_active_work_blocks(client):
    c, root, pid, _, body = prepare(client)
    with connection(root)() as db:
        db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)', ('fox-'+'a'*20, pid, body['source_hash'], 'ATTENTION', 'old unknown AI result', 1, 1, None))
    response = c.post(f'/api/projects/{pid}/xml-mapping/runs', json=body)
    assert response.status_code == 202, response.text
    body['request_id'] = str(uuid.uuid4())
    assert c.post(f'/api/projects/{pid}/xml-mapping/runs', json=body).status_code == 409
    with connection(root)() as db:
        assert db.execute('SELECT message FROM runs WHERE id=?', ('fox-'+'a'*20,)).fetchone()[0] == 'old unknown AI result'


def test_download_owner_and_cross_project_boundaries(client):
    c, root, pid, body, run = finish(client)
    other = new_project(c)
    for suffix in ('', '/download'):
        assert c.get(f"/api/projects/{other}/xml-mapping/runs/{run['id']}{suffix}").status_code == 404
    with connection(root)() as db:
        db.execute('UPDATE projects SET owner=? WHERE id=?', ('another-owner', pid))
    assert c.get(run['download_url']).status_code == 404


def test_download_is_readonly_and_does_not_invoke_compiler(client, monkeypatch):
    c, root, pid, body, run = finish(client)
    def forbidden(*args, **kwargs):
        pytest.fail('Read-only proof must not compile or create files')
    monkeypatch.setattr(jobs.xml_mapping, 'validate_xml_package', forbidden)
    monkeypatch.setattr(jobs.xml_mapping, 'validate_offline', forbidden)
    job = root / 'jobs' / run['id']
    before = {str(p): p.read_bytes() for p in job.rglob('*') if p.is_file()}
    with connection(root)() as db:
        rows_before = list(db.execute('SELECT * FROM events'))
    assert c.get(run['download_url']).status_code == 200
    assert c.get(f"/api/projects/{pid}/xml-mapping/runs/{run['id']}").json()['format_validated'] is True
    assert before == {str(p): p.read_bytes() for p in job.rglob('*') if p.is_file()}
    with connection(root)() as db:
        assert [tuple(row) for row in db.execute('SELECT * FROM events')] == [tuple(row) for row in rows_before]


def test_multiple_forms_one_application_and_visible_unsupported(client):
    c, root, pid = client
    docs = [('one.xml', source(extra='<Trigger Name="WHEN-BUTTON-PRESSED" TriggerText="COMMIT;"/>')),
            ('two.xml', source(module='SECOND', block='OTHER'))]
    upload(c, pid, docs)
    assessment = c.get(f'/api/projects/{pid}/xml-mapping').json()
    body = {key: assessment[key] for key in ('source_hash', 'selected_source_set_id', 'source_binding', 'catalog_sha256')}
    body.update(request_id=str(uuid.uuid4()), approved_synthetic_scope=True, approved_local_source_processing=True)
    queued = c.post(f'/api/projects/{pid}/xml-mapping/runs', json=body).json()
    process_one(connection(root), root)
    run = c.get(f"/api/projects/{pid}/xml-mapping/runs/{queued['id']}").json()
    assert (run['generated_units'], run['unsupported_units'], run['total_units']) == (2, 1, 3)
    files = _members(c.get(run['download_url']).content)
    assert json.loads(files['fox-package/metadata.json'])['application_count'] == 1
    for name, raw in docs:
        assert files['fox-package/sources/' + name] == raw


def test_catalog_change_preserves_completed_download_but_rejects_stale_admission(client, monkeypatch):
    c, root, pid, body, run = finish(client)
    original = jobs.xml_mapping.mapping_catalog
    def changed_catalog():
        return {**original(), 'catalog_sha256': 'f'*64}
    monkeypatch.setattr(jobs.xml_mapping, 'mapping_catalog', changed_catalog)
    download = c.get(run['download_url'])
    assert download.status_code == 200 and jobs.sha(download.content) == run['package_sha256']
    assert c.post(f'/api/projects/{pid}/xml-mapping/runs', json={**body, 'request_id': str(uuid.uuid4())}).status_code == 409


def test_interrupted_attempt_marker_prevents_manual_queue_replay(client):
    c, root, pid, body, run = finish(client)
    before = (root/'jobs'/run['id']/'xml-mapping'/'apexlang.zip').read_bytes()
    with connection(root)() as db:
        db.execute("UPDATE runs SET state='QUEUED' WHERE id=?", (run['id'],))
    process_one(connection(root), root)
    with connection(root)() as db:
        assert db.execute('SELECT state FROM runs').fetchone()[0] == 'ATTENTION'
    assert (root/'jobs'/run['id']/'xml-mapping'/'apexlang.zip').read_bytes() == before


def test_hardlinked_package_is_rejected(client):
    c, root, pid, body, run = finish(client)
    package = root/'jobs'/run['id']/'xml-mapping'/'apexlang.zip'
    (root/'extra-link.zip').hardlink_to(package)
    assert c.get(run['download_url']).status_code == 409


def test_fresh_install_route_binding_stays_disabled(client):
    # Isolated route registration tests the explicit disabled binding without
    # constructing or weakening the real fresh-startup admission fence.
    from fastapi import FastAPI
    from fox.xml_mapping_routes import attach_xml_mapping_routes
    c, root, pid, assessment, body = prepare(client)
    app = FastAPI()
    attach_xml_mapping_routes(app, root=root, db=connection(root),
        project=lambda request, project_id: {'id': pid, 'name': 'Test', 'owner': 'Test'}, fresh=True)
    with TestClient(app) as fresh:
        preview = fresh.get(f'/api/projects/{pid}/xml-mapping').json()
        assert preview['available'] is False and 'fresh installations' in preview['reason']
        assert fresh.post(f'/api/projects/{pid}/xml-mapping/runs', json=body).status_code == 503
    with connection(root)() as db:
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 0


def test_definite_non_admission_has_explicit_browser_reconciliation_signal(client):
    c, root, pid, scope, body = prepare(client)
    body['catalog_sha256'] = 'f' * 64
    response = c.post(f'/api/projects/{pid}/xml-mapping/runs', json=body)
    assert response.status_code == 409
    assert response.headers['X-FOX-Admission'] == 'not-admitted'
    with connection(root)() as db:
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 0


def test_retained_folder_is_uncertain_not_definite_rejection(client):
    c, root, pid, scope, body = prepare(client)
    rid = 'fox-' + jobs.sha(jobs.encoded([pid, body['request_id']]))[:20]
    jobs.job_path(root, rid).mkdir(parents=True)
    response = c.post(f'/api/projects/{pid}/xml-mapping/runs', json=body)
    assert response.status_code == 409
    assert response.headers['X-FOX-Admission'] == 'uncertain'
    assert not (jobs.job_path(root, rid) / 'source-snapshot.json').exists()
    with connection(root)() as db:
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 0


def test_observed_mapping_completion_counts_generated_without_replay(client, monkeypatch):
    from fox.worker_observability import WorkerMonitor, observed_poll
    c, root, pid, body, run = queue(client)
    calls, events = [], []
    def validator(candidate, directory):
        calls.append(jobs.sha(candidate))
        return fake_validator(candidate, directory)
    monkeypatch.setattr(jobs.xml_mapping, 'validate_offline', validator)
    monitor = WorkerMonitor(emit=events.append)
    monitor.started()
    observed_poll(process_one, connection(root), root, monitor)
    status = monitor.snapshot(thread_alive=True)
    assert status['healthy'] is True and status['jobs_completed'] == 1
    assert status['last_outcome'] == 'GENERATED' and status['errors_observed'] == 0
    assert events[-1]['event'] == 'job_outcome' and events[-1]['outcome'] == 'GENERATED'
    observed_poll(process_one, connection(root), root, monitor)
    assert len(calls) == 1 and monitor.snapshot()['jobs_completed'] == 1
    result = c.get(f"/api/projects/{pid}/xml-mapping/runs/{run['id']}").json()
    assert result['state'] == 'GENERATED' and result['format_validated'] is True
    assert result['runtime_verified'] is False and result['business_behavior_accepted'] is False


def test_record_context_summary_keeps_review_assignments_out_of_converted_count(client):
    from pathlib import Path
    c,root,pid=client
    example=Path(__file__).resolve().parents[2]/'examples/xml-mapping/record_context.xml'
    upload(c,pid,[('record_context.xml',example.read_bytes())])
    scope=c.get(f'/api/projects/{pid}/xml-mapping').json()
    body={key:scope[key] for key in ('source_hash','selected_source_set_id','source_binding','catalog_sha256')}
    body.update(request_id=str(uuid.uuid4()),approved_synthetic_scope=True,approved_local_source_processing=True)
    response=c.post(f'/api/projects/{pid}/xml-mapping/runs',json=body)
    assert response.status_code==202
    run=response.json();assert run['context_summary'] is None
    process_one(connection(root),root)
    result=c.get(f"/api/projects/{pid}/xml-mapping/runs/{run['id']}").json()
    assert result['state']=='GENERATED' and result['format_validated'] is True
    assert (result['generated_units'],result['unsupported_units'],result['total_units'])==(1,2,3)
    assert result['context_summary']=={'relations_generated':2,'relations_not_converted':0,'assignments_generated_unwired':2}
    assert all('not wired' in gap['message'] for gap in result['gaps'])
    package=c.get(result['download_url']);assert package.status_code==200
    files=_members(package.content)
    assert b'GENERATED_UNWIRED' in files['fox-package/assignment-review.sql']
    assert b'CREATE OR REPLACE PACKAGE' in files['fox-package/assignment-review.sql']
    assert not any(b'FOX_ASG_' in raw for name,raw in files.items() if name.endswith('.apx'))
