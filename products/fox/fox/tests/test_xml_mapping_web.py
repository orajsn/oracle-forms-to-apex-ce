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


def test_policy_rules_appear_in_download_and_separate_unwired_api_count(client):
    from pathlib import Path
    c,root,pid=client
    example=Path(__file__).resolve().parents[2]/'examples/xml-mapping/policy_rules.xml'
    upload(c,pid,[('policy_rules.xml',example.read_bytes())])
    scope=c.get(f'/api/projects/{pid}/xml-mapping').json()
    body={key:scope[key] for key in ('source_hash','selected_source_set_id','source_binding','catalog_sha256')}
    body.update(request_id=str(uuid.uuid4()),approved_synthetic_scope=True,approved_local_source_processing=True)
    response=c.post(f'/api/projects/{pid}/xml-mapping/runs',json=body)
    assert response.status_code==202
    run=response.json();assert run['policy_summary'] is None
    process_one(connection(root),root)
    result=c.get(f"/api/projects/{pid}/xml-mapping/runs/{run['id']}").json()
    assert result['state']=='GENERATED' and result['format_validated'] is True
    assert (result['generated_units'],result['unsupported_units'],result['total_units'])==(1,5,6)
    assert result['policy_summary']=={'rules_generated_unwired':5}
    assert all('not wired' in gap['message'] for gap in result['gaps'])
    package=c.get(result['download_url']);assert package.status_code==200
    files=_members(package.content)
    assert b'GENERATED_UNWIRED' in files['fox-package/policy-review.sql']
    assert b'CREATE OR REPLACE PACKAGE' in files['fox-package/policy-review.sql']
    assert not any(b'FOX_POL_' in raw for name,raw in files.items() if name.endswith('.apx'))
    assert not result['runtime_verified']


def test_connected_record_check_appears_in_native_package_and_api(client):
    from pathlib import Path
    c,root,pid=client
    example=Path(__file__).resolve().parents[2]/'examples/xml-mapping/record_buffer.xml'
    upload(c,pid,[('record_buffer.xml',example.read_bytes())])
    scope=c.get(f'/api/projects/{pid}/xml-mapping').json()
    body={key:scope[key] for key in ('source_hash','selected_source_set_id','source_binding','catalog_sha256')}
    body.update(request_id=str(uuid.uuid4()),approved_synthetic_scope=True,approved_local_source_processing=True)
    response=c.post(f'/api/projects/{pid}/xml-mapping/runs',json=body)
    assert response.status_code==202
    run=response.json();assert run['buffer_summary'] is None
    process_one(connection(root),root)
    result=c.get(f"/api/projects/{pid}/xml-mapping/runs/{run['id']}").json()
    assert result['state']=='GENERATED' and result['format_validated'] is True
    assert (result['generated_units'],result['unsupported_units'],result['total_units'])==(3,0,3)
    assert result['buffer_summary']=={'record_validation_flows':1}
    assert result['policy_summary']=={'rules_generated_unwired':0}
    package=c.get(result['download_url']);assert package.status_code==200
    files=_members(package.content)
    receipt=json.loads(files['fox-package/buffer-receipt.json'])
    assert len(receipt['generated_operations'])==1
    op=receipt['generated_operations'][0]
    assert b'apex_collection.update_member_attribute' in files[op['page_file']]
    assert b'Keep draft' in files[op['page_file']]
    assert op['native_event_wired'] and not op['event_activated']
    assert not result['runtime_verified']


def test_current_row_save_events_are_available_in_the_saved_download(client):
    from pathlib import Path
    c, root, pid = client
    fixture = Path(__file__).resolve().parents[2] / 'examples/xml-mapping/synthetic_record_save.xml'
    upload(c, pid, [(fixture.name, fixture.read_bytes())])
    url = f'/api/projects/{pid}/xml-mapping'
    scope = c.get(url).json()
    body = {key: scope[key] for key in ('source_hash', 'selected_source_set_id', 'source_binding', 'catalog_sha256')}
    body.update(request_id=str(uuid.uuid4()), approved_synthetic_scope=True, approved_local_source_processing=True)
    response = c.post(url + '/runs', json=body)
    assert response.status_code == 202
    assert response.json()['synthetic_save_summary'] is None
    process_one(connection(root), root)
    run = c.get(url + '/runs/' + response.json()['id']).json()
    assert run['state'] == 'GENERATED' and run['format_validated'] is True
    assert run['synthetic_save_summary'] == {'screens': 1, 'before_write_events': 2}
    assert run['context_summary']['assignments_generated_unwired'] == 0
    assert (run['generated_units'], run['unsupported_units'], run['total_units']) == (5, 2, 7)
    assert not run['runtime_verified'] and not run['business_behavior_accepted']
    download = c.get(run['download_url'])
    assert download.status_code == 200
    files = _members(download.content)
    events = json.loads(files['fox-package/synthetic-save-receipt.json'])['generated_operations']
    assert {op['source_event'] for op in events} == {'PRE-INSERT', 'PRE-UPDATE'}
    assert len({op['page_file'] for op in events}) == 1
    assert b'FOX_SYNTHETIC_SAVE' in files[events[0]['page_file']]
    assert files['fox-package/sources/' + fixture.name] == fixture.read_bytes()


def test_partial_source_discrepancies_visible_after_generation(client):
    from pathlib import Path
    c,root,pid=client
    example=Path(__file__).resolve().parents[2]/'examples/xml-mapping/policy_rules.xml'
    raw=example.read_bytes().replace(b'</FormModule>',b'<Trigger Name="KEY-PRINT" TriggerText="BEGIN REMOTE_REPORT.RUN; END;"/></FormModule>')
    upload(c,pid,[('policy_with_gaps.xml',raw)])
    scope=c.get(f'/api/projects/{pid}/xml-mapping').json()
    body={key:scope[key] for key in ('source_hash','selected_source_set_id','source_binding','catalog_sha256')}
    body.update(request_id=str(uuid.uuid4()),approved_synthetic_scope=True,approved_local_source_processing=True)
    response=c.post(f'/api/projects/{pid}/xml-mapping/runs',json=body)
    assert response.status_code==202
    run=response.json();assert run['discrepancies'] is None
    process_one(connection(root),root)
    result=c.get(f"/api/projects/{pid}/xml-mapping/runs/{run['id']}").json()
    assert result['state']=='GENERATED'
    d=result['discrepancies'];assert d['source_binding']==scope['source_binding']
    assert d['summary']['total_units']==result['total_units']==7
    assert d['summary']['generated_units']==result['generated_units']==1
    assert d['summary']['encoded_unwired_units']==5
    assert d['summary']['unimplemented_units']==1
    assert result['unsupported_units']==6
    assert c.get(result['download_url']).status_code==200


def test_partial_coordination_effects_are_bound_to_downloadable_pages_and_unit_notes(client):
    from test_forms_detail_clear import source as clear_source
    c, root, pid = client
    upload(c, pid, clear_source(renamed=True))
    scope = c.get(f'/api/projects/{pid}/xml-mapping').json()
    body = {key: scope[key] for key in ('source_hash', 'selected_source_set_id', 'source_binding', 'catalog_sha256')}
    body.update(request_id=str(uuid.uuid4()), approved_synthetic_scope=True, approved_local_source_processing=True)
    queued = c.post(f'/api/projects/{pid}/xml-mapping/runs', json=body)
    assert queued.status_code == 202
    process_one(connection(root), root)
    run = c.get(f"/api/projects/{pid}/xml-mapping/runs/{queued.json()['id']}").json()
    assert run['state'] == 'GENERATED'
    files = _members(c.get(run['download_url']).content)
    ledger = json.loads(files['fox-package/mapping-ledger.json'])
    partial = {u['source_unit_id']: u for u in ledger['coordination_partial_units']}
    gaps = {g['source_unit_id']: g for g in run['gaps']}
    notes = {u['source_unit_id']: u for u in run['discrepancies']['units']}
    assert len(partial) == 6
    for uid,record in partial.items():
        assert notes[uid]['status'] != 'generated'
        assert gaps[uid]['reason'] == record['reason']
        assert record['effects'] and all(effect['page_file'] in files for effect in record['effects'])
    assert sum(g['reason']=='master_population_partly_connected' for g in gaps.values()) == 2
    assert sum(g['reason']=='master_clear_partly_connected' for g in gaps.values()) == 2
    assert not run['runtime_verified'] and not run['business_behavior_accepted']


def test_interface_csv_download_uses_exact_saved_register(client):
    c, _, pid, _, completed = finish(client)
    url = f"/api/projects/{pid}/xml-mapping/runs/{completed['id']}/interfaces.csv"
    summary = completed['interface_summary']
    assert summary['csv_available'] and summary['json_available'] and not summary['size_limited']
    files = _members(c.get(completed['download_url']).content)
    response = c.get(url)
    assert response.status_code == 200 and response.headers['content-type'].startswith('text/csv')
    assert response.content == files['fox-package/interface-register.csv']
    register = json.loads(files['fox-package/interface-register.json'])
    assert len(register['records']) == summary['records']
    assert response.content.decode('utf-8-sig').startswith('record_id,name,role')
    c.cookies.clear()
    assert c.get(url).status_code == 401


def test_approval_readiness_is_partial_and_links_both_external_call_sites(client):
    from test_forms_approval_plan import source as approval_source
    c,root,pid=client
    upload(c,pid,approval_source(renamed=True))
    url=f'/api/projects/{pid}/xml-mapping'
    scope=c.get(url).json()
    body={k:scope[k] for k in ('source_hash','selected_source_set_id','source_binding','catalog_sha256')}
    body.update(request_id=str(uuid.uuid4()),approved_synthetic_scope=True,approved_local_source_processing=True)
    queued=c.post(url+'/runs',json=body)
    assert queued.status_code==202
    process_one(connection(root),root)
    result=c.get(url+'/runs/'+queued.json()['id']).json()
    assert result['state']=='GENERATED'
    files=_members(c.get(result['download_url']).content)
    ledger=json.loads(files['fox-package/mapping-ledger.json'])
    action,=ledger['approval_readiness']
    links=ledger['approval_interface_links']
    assert action['approval_flag_written'] is False and action['page_file'] in files
    assert [(link['stage_id'],link['supplied_argument_count']) for link in links]==[('external_1',2),('external_2',5)]
    assert all(link['interface_record_id'] and not link['external_outcome_verified'] for link in links)
    unit=next(u for u in result['discrepancies']['units'] if u['source_unit_id']==action['source_unit_id'])
    assert unit['status']=='encoded_unwired'
    assert 'additional commit stages' in unit['message']


def test_staging_refresh_retains_delete_insert_and_read_for_the_same_action(client):
    from test_forms_manifest_filter import source
    action = ('IF :TRACKING IS NOT NULL THEN DELETE APP.QUERY_ROWS WHERE TRACKING=:TRACKING; '
              'INSERT INTO APP.QUERY_ROWS(TRACKING,KIND,DEPOT,SERIAL) '
              'SELECT TRACKING,KIND,DEPOT,SERIAL FROM APP.ARCHIVE_ROWS WHERE TRACKING=:TRACKING; '
              'EXECUTE_QUERY; ELSE NULL; END IF;')
    item = ('<Item Name="TRACKING" ColumnName="TRACKING" DataType="Char" MaximumLength="20" '
            'DatabaseItem="true" ItemType="Text Item"><Trigger Name="KEY-EXEQRY" TriggerText="' +
            action + '"/></Item>')
    c, root, pid = client
    raw = source(table='APP.QUERY_ROWS', extra=item, kind_extra='MaximumLength="20"',
                 depot_extra='MaximumLength="20"')
    upload(c, pid, [('dispatch.xml', raw)])
    url = f'/api/projects/{pid}/xml-mapping'
    scope = c.get(url).json()
    body = {k: scope[k] for k in ('source_hash', 'selected_source_set_id', 'source_binding', 'catalog_sha256')}
    body.update(request_id=str(uuid.uuid4()), approved_synthetic_scope=True, approved_local_source_processing=True)
    queued = c.post(url + '/runs', json=body)
    assert queued.status_code == 202
    process_one(connection(root), root)
    result = c.get(url + '/runs/' + queued.json()['id']).json()
    assert result['state'] == 'GENERATED'
    files = _members(c.get(result['download_url']).content)
    ledger = json.loads(files['fox-package/mapping-ledger.json'])
    target, = ledger['staged_queries']
    links = ledger['staged_query_interfaces']
    assert target['native_page'] in files and target['whole_source_unit_converted'] is False
    assert [(r['role'], r['source_table']) for r in links] == [
        ('delete', 'APP.QUERY_ROWS'), ('insert', 'APP.QUERY_ROWS'), ('read', 'APP.ARCHIVE_ROWS')]
    assert len({r['interface_record_id'] for r in links}) == 3
    assert all(r['interface_record_id'] and r['position'] and not r['target_interface_verified'] for r in links)
    unit = next(r for r in result['discrepancies']['units'] if r['source_unit_id'] == target['source_unit_id'])
    assert unit['status'] == 'encoded_unwired' and 'APEX session' in unit['message']


def test_retained_interface_csv_requires_its_declared_digest():
    metadata = {'source_binding':'source', 'interface_register':{
        'scope':'fox-source-interface-register-v1','source_binding':'source','record_count':1,
        'size_limited':True,'detail_limited':False,'artifacts':{'csv':{'path':'fox-package/interface-register.csv','sha256':'0'*64}}}}
    with pytest.raises(ValueError,match='interface register evidence changed'):
        jobs._interface_fields(metadata,{'fox-package/interface-register.csv':b'different'})
    assert jobs._interface_fields({}, {}) is None


@pytest.mark.parametrize('incomplete',[False,True])
def test_source_item_validation_reaches_saved_run_with_honest_coverage(client,incomplete):
    from test_forms_item_validation import source as item_source
    c, root, pid = client
    upload(c, pid, item_source(renamed=True, missing_provider=incomplete))
    url = f'/api/projects/{pid}/xml-mapping'
    scope = c.get(url).json()
    body = {key:scope[key] for key in ('source_hash','selected_source_set_id','source_binding','catalog_sha256')}
    body.update(request_id=str(uuid.uuid4()),approved_synthetic_scope=True,approved_local_source_processing=True)
    queued = c.post(url+'/runs',json=body)
    assert queued.status_code == 202
    process_one(connection(root),root)
    run = c.get(url+'/runs/'+queued.json()['id']).json()
    assert run['state'] == 'GENERATED'
    assert run['item_validation_summary'] == {'wired':int(not incomplete),'partial':int(incomplete),'encoded_only':0}
    wvi, = [u for u in run['discrepancies']['units'] if u['source_name']=='WHEN-VALIDATE-ITEM']
    assert wvi['status'] == ('encoded_unwired' if incomplete else 'generated')
    if incomplete:
        gap, = [g for g in run['gaps'] if g['source_unit_id'] == wvi['source_unit_id']]
        assert gap['reason']=='item_lookup_partly_connected'
    assert not run['runtime_verified']


def test_source_lookup_handlers_are_generated_but_original_reads_stay_disabled(client):
    from pathlib import Path
    c,root,pid=client
    example=Path(__file__).resolve().parents[2]/'examples/xml-mapping/source_lookups.xml'
    upload(c,pid,[('source_lookups.xml',example.read_bytes())])
    scope=c.get(f'/api/projects/{pid}/xml-mapping').json()
    body={key:scope[key] for key in ('source_hash','selected_source_set_id','source_binding','catalog_sha256')}
    body.update(request_id=str(uuid.uuid4()),approved_synthetic_scope=True,approved_local_source_processing=True)
    response=c.post(f'/api/projects/{pid}/xml-mapping/runs',json=body)
    assert response.status_code==202
    run=response.json();assert run['lookup_summary'] is None
    process_one(connection(root),root)
    result=c.get(f"/api/projects/{pid}/xml-mapping/runs/{run['id']}").json()
    assert result['state']=='GENERATED' and result['format_validated'] is True
    assert (result['generated_units'],result['unsupported_units'],result['total_units'])==(3,0,3)
    assert result['lookup_summary']=={'generated_lookup_handlers':3,'original_reads_enabled':False}
    assert result['discrepancies']['summary']['generated_units']==3
    package=c.get(result['download_url']);assert package.status_code==200
    files=_members(package.content)
    assert files['shared-components/app-items.apx'].count(b'sessionStateProtection: restricted')==3
    assert not result['runtime_verified']
