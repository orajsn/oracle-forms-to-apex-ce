"""Native product preflight and queue gates; no models, containers or databases."""
import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import fox.app as app_module
from fox.app import create_app, password_hash, native_progress, NATIVE_STAGE_MESSAGES


ORIGIN = 'http://127.0.0.1:8100'
PROFILE = 'native-table-form-v1'
FIXTURES = Path(__file__).parent/'fixtures'


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv('FOX_PASSWORD_HASH', password_hash('test-only-password'))
    monkeypatch.setenv('FOX_PUBLIC_ORIGIN', ORIGIN)
    monkeypatch.setenv('FOX_CONVERSION_PROFILE', PROFILE)
    monkeypatch.delenv('FOX_OPAF_RUN_URL', raising=False)
    role = {'workflow_id':'A'*32,'model':'xai.grok-4.3','graph_sha256':'a'*64}
    profile = tmp_path/'native-profile.json'
    profile.write_text(json.dumps({'schema_version':1,'profile_id':PROFILE,
        'opaf_base_url':'https://localhost:8080/agentFactory','certificate_sha256':'b'*64,
        'mapper':role,'reviewer':{**role,'workflow_id':'B'*32}}), encoding='utf-8')
    credentials = tmp_path/'protected-credentials.json'
    # Deliberately not valid JSON: session/queue configuration must not read secrets.
    credentials.write_text('do not read this credential file', encoding='utf-8')
    monkeypatch.setenv('FOX_NATIVE_PROFILE_FILE', str(profile))
    monkeypatch.setenv('FOX_OPAF_CREDENTIAL_FILE', str(credentials))
    monkeypatch.setenv('FOX_CONVERTER_URL', 'http://127.0.0.1:8091')
    monkeypatch.setenv('FOX_RUN_ADAPTER', 'embedded-opaf')
    root = tmp_path/'data'
    with TestClient(create_app(root, enable_worker=False), base_url=ORIGIN) as c:
        c.headers['Origin'] = ORIGIN
        assert c.post('/api/login',json={'username':'jason','password':'test-only-password'}).status_code == 200
        pid = c.post('/api/projects',json={'customer':'Synthetic fixture','name':'Native beta'}).json()['id']
        yield c, root, pid, profile, credentials


def upload_ready(c, pid, *, xml=None, ddl=None):
    files = [('files',('native.xml',xml if xml is not None else (FIXTURES/'native-beta.xml').read_bytes())),
             ('files',('native.sql',ddl if ddl is not None else (FIXTURES/'native-beta.sql').read_bytes()))]
    response = c.post(f'/api/projects/{pid}/sources',files=files)
    assert response.status_code == 200, response.text
    return response.json()


def consent(report):
    return {'source_hash':report['source_hash'],'approved_redacted_source':True,
            'approved_external_ai':True,'approved_prototype_scope':True}


def assert_not_queued(root):
    with sqlite3.connect(root/'fox.sqlite3') as c:
        assert c.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 0
    assert not (root/'jobs').exists()


def test_native_session_and_assessments_advertise_scope_without_secrets(client):
    c, root, pid, profile, credentials = client
    session = c.get('/api/session').json()
    assert session['conversion_profile'] == PROFILE
    assert session['conversion_configured'] is True
    assert all(item['ready'] for item in session['configuration_checks'])
    assert 'Configuration only' in session['configuration_scope']
    assert str(profile) not in json.dumps(session) and str(credentials) not in json.dumps(session)
    empty = c.get(f'/api/projects/{pid}').json()['inventory']
    assert empty['native_assessment']['state'] == 'BLOCKED'
    uploaded = upload_ready(c, pid)
    assert uploaded['native_assessment']['state'] == 'READY'
    assert uploaded['conversion_profile'] == PROFILE
    detail = c.get(f'/api/projects/{pid}').json()['inventory']
    assessment = c.get(f'/api/projects/{pid}/assessment').json()
    assert uploaded == detail == assessment
    assert 'not proof of live schema' in assessment['native_assessment']['scope_note']


def test_queue_freezes_native_contract_approval_and_source_hash(client, monkeypatch):
    c, root, pid, _, credentials = client
    report = upload_ready(c, pid)
    read_text = Path.read_text
    def protected_read(path, *args, **kwargs):
        assert path != credentials, 'UI must not retrieve credentials'
        return read_text(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'read_text', protected_read)
    response = c.post(f'/api/projects/{pid}/runs',json=consent(report))
    assert response.status_code == 202
    rid = response.json()['id']
    snapshot = json.loads((root/'jobs'/rid/'source-snapshot.json').read_text())
    assert snapshot['conversion_profile'] == PROFILE
    assert snapshot['native_form'] == report['native_assessment']['native_form']
    assert snapshot['source_hash'] == report['source_hash']
    assert snapshot['approvals']['owner'] == 'jason'
    assert all(snapshot['approvals'][key] is True for key in ('redacted_source','external_ai','synthetic_prototype'))
    assert c.post(f'/api/projects/{pid}/runs',json=consent(report)).json()['id'] == rid
    assert c.get(f'/api/projects/{pid}/runs/{rid}/download').status_code == 409


@pytest.mark.parametrize('field',['approved_redacted_source','approved_external_ai','approved_prototype_scope'])
def test_every_approval_is_mandatory(client,field):
    c, root, pid, _, _ = client
    report = upload_ready(c, pid)
    response = c.post(f'/api/projects/{pid}/runs',json={**consent(report),field:False})
    assert response.status_code == 422
    assert_not_queued(root)


@pytest.mark.parametrize('variable,check',[
    ('FOX_NATIVE_PROFILE_FILE','NATIVE_WORKFLOW_PROFILE'),
    ('FOX_OPAF_CREDENTIAL_FILE','PROTECTED_CREDENTIAL_FILE'),
    ('FOX_CONVERTER_URL','INTERNAL_CONVERTER'),
    ('FOX_RUN_ADAPTER','EMBEDDED_ADAPTER'),
])
def test_missing_native_configuration_blocks_before_queue(client,monkeypatch,variable,check):
    c, root, pid, _, _ = client
    report = upload_ready(c,pid)
    monkeypatch.delenv(variable)
    # An old workflow URL never enables native conversion.
    monkeypatch.setenv('FOX_OPAF_RUN_URL','https://old-config.invalid')
    session = c.get('/api/session').json()
    assert session['conversion_configured'] is False
    assert next(item for item in session['configuration_checks'] if item['code']==check)['ready'] is False
    assert c.post(f'/api/projects/{pid}/runs',json=consent(report)).status_code == 503
    assert_not_queued(root)


@pytest.mark.parametrize('value',['not json','{}','[]','null','{"schema_version":1}'])
def test_malformed_profile_is_configuration_pending(client,value):
    c, _, _, profile, _ = client
    profile.write_text(value,encoding='utf-8')
    response = c.get('/api/session')
    assert response.status_code == 200
    assert response.json()['conversion_configured'] is False


def test_blocked_native_candidate_cannot_use_generic_eligibility(client):
    c, root, pid, _, _ = client
    xml = (FIXTURES/'native-beta.xml').read_bytes().replace(b'</FormModule>', b'<Trigger Name="WHEN-NEW-FORM-INSTANCE" TriggerText="BEGIN NULL; END;"/></FormModule>')
    report = upload_ready(c,pid,xml=xml)
    assert report['conversion_eligible'] is True
    assert report['native_assessment']['native_form'] is not None
    assert report['native_assessment']['state'] == 'BLOCKED'
    response = c.post(f'/api/projects/{pid}/runs',json=consent(report))
    assert response.status_code == 409
    assert 'unconverted behavior' in response.json()['detail']
    assert_not_queued(root)


def test_missing_ddl_is_actionable_and_cannot_queue(client):
    c, root, pid, _, _ = client
    uploaded = c.post(f'/api/projects/{pid}/sources',files={'files':('native.xml',(FIXTURES/'native-beta.xml').read_bytes())}).json()
    assert 'DDL_REQUIRED' in {item['code'] for item in uploaded['native_assessment']['blockers']}
    assert c.post(f'/api/projects/{pid}/runs',json=consent(uploaded)).status_code == 409
    assert_not_queued(root)


def test_changed_source_invalidates_approval(client):
    c, root, pid, _, _ = client
    report = upload_ready(c,pid)
    xml = (FIXTURES/'native-beta.xml').read_bytes().replace(b'Work title',b'Revised title')
    changed = upload_ready(c,pid,xml=xml)
    assert changed['source_hash'] != report['source_hash']
    assert c.post(f'/api/projects/{pid}/runs',json=consent(report)).status_code == 409
    assert_not_queued(root)


def test_post_lock_hash_recheck_prevents_upload_race(client,monkeypatch):
    c, root, pid, _, _ = client
    report = upload_ready(c,pid)
    original = app_module.inventory
    calls = []
    def changed_after_assessment(files):
        value = original(files)
        calls.append(True)
        if len(calls) == 2:
            value['source_hash'] = 'f'*64
        return value
    monkeypatch.setattr(app_module,'inventory',changed_after_assessment)
    assert c.post(f'/api/projects/{pid}/runs',json=consent(report)).status_code == 409
    assert len(calls) == 2
    assert_not_queued(root)


def test_unknown_profile_never_falls_back_to_legacy(client,monkeypatch):
    c, root, pid, _, _ = client
    report = upload_ready(c,pid)
    monkeypatch.setenv('FOX_CONVERSION_PROFILE','typo-native-profile')
    monkeypatch.setenv('FOX_OPAF_RUN_URL','https://old-config.invalid')
    assert c.get('/api/session').json()['conversion_configured'] is False
    assert c.post(f'/api/projects/{pid}/runs',json=consent(report)).status_code == 503
    assert_not_queued(root)


def test_switching_profile_preserves_existing_run_without_reusing_it(client,monkeypatch):
    c, root, pid, _, _ = client
    report = upload_ready(c,pid)
    native = c.post(f'/api/projects/{pid}/runs',json=consent(report))
    assert native.status_code == 202
    monkeypatch.delenv('FOX_CONVERSION_PROFILE')
    monkeypatch.setenv('FOX_OPAF_RUN_URL','https://old-config.invalid')
    response = c.post(f'/api/projects/{pid}/runs',json=consent(report))
    assert response.status_code == 409
    assert 'another conversion profile' in response.json()['detail']
    with sqlite3.connect(root/'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 1


def test_lab_verification_pending_cannot_be_accepted_by_user(client):
    c, root, pid, _, _ = client
    report = upload_ready(c,pid)
    rid = c.post(f'/api/projects/{pid}/runs',json=consent(report)).json()['id']
    with sqlite3.connect(root/'fox.sqlite3') as db:
        db.execute("UPDATE runs SET state='QA_REQUIRED',artifact='unverified.zip' WHERE id=?",(rid,))
    response = c.post(f'/api/projects/{pid}/runs/{rid}/accept',json={
        'source_hash':report['source_hash'],'business_flow_tested':True,
        'remediation_reviewed':True,'notes':'A human cannot bypass lab verification.'})
    assert response.status_code == 409
    assert c.get(f'/api/projects/{pid}/runs/{rid}/download').status_code == 409


@pytest.mark.parametrize('snapshot',['[]','not JSON'])
def test_unreadable_existing_snapshot_requires_reconciliation(client,snapshot):
    c, root, pid, _, _ = client
    report = upload_ready(c,pid)
    rid = c.post(f'/api/projects/{pid}/runs',json=consent(report)).json()['id']
    (root/'jobs'/rid/'source-snapshot.json').write_text(snapshot,encoding='utf-8')
    response = c.post(f'/api/projects/{pid}/runs',json=consent(report))
    assert response.status_code == 409
    assert 'reconciliation' in response.json()['detail']
    with sqlite3.connect(root/'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 1


def test_intake_secret_and_binary_rejections_remain_atomic(client):
    c, root, pid, _, _ = client
    for name, raw in [('raw.fmb',b'raw'),('bad.sql',b'password=unsafe'),('unsafe.xml',b'<bad>')]:
        assert c.post(f'/api/projects/{pid}/sources',files={'files':(name,raw)}).status_code == 422
    assert c.get(f'/api/projects/{pid}').json()['inventory']['files'] == []
    assert_not_queued(root)


@pytest.fixture
def progress_file(tmp_path):
    root = tmp_path.resolve()
    run = {'id':'fox-'+'a'*20,'state':'PROCESSING'}
    job = root/'jobs'/run['id']
    job.mkdir(parents=True)
    path = job/'native-progress.json'
    path.write_text(json.dumps({'stage':'mapping','updated_at_utc':'2026-10-16T12:30:45.123456+00:00'}),encoding='utf-8')
    return root, run, path


@pytest.mark.parametrize('state',['PROCESSING','ATTENTION'])
@pytest.mark.parametrize('stage',list(NATIVE_STAGE_MESSAGES))
def test_progress_is_fixed_whitelisted_message(progress_file,state,stage):
    root, run, path = progress_file
    path.write_text(json.dumps({'stage':stage,'updated_at_utc':'2026-10-16T12:30:45Z'}),encoding='utf-8')
    value = native_progress(root,{**run,'state':state})
    assert value == {'stage':stage,'stage_message':NATIVE_STAGE_MESSAGES[stage],
                     'stage_updated_at_utc':'2026-10-16T12:30:45+00:00'}


@pytest.mark.parametrize('state',['QUEUED','QA_REQUIRED','REVIEW_REQUIRED','VERIFIED','ACCEPTED'])
def test_progress_does_not_change_final_or_queued_states(progress_file,state):
    root, run, _ = progress_file
    assert native_progress(root,{**run,'state':state}) == {}


@pytest.mark.parametrize('payload',[
    b'not JSON',b'[]',b'null',b'{}',b'\xff',
    b'{"stage":"provider secret text","updated_at_utc":"2026-10-16T12:30:45Z"}',
    b'{"stage":"mapping","updated_at_utc":"provider secret text"}',
    b'{"stage":"mapping","updated_at_utc":"2026-10-16T12:30:45+07:00"}',
    b'{"stage":"mapping","updated_at_utc":"2026-99-16T12:30:45Z"}',
    b'{"stage":[],"updated_at_utc":"2026-10-16T12:30:45Z"}',
    b'{"stage":"mapping","updated_at_utc":123}',
    b'{"stage":"mapping","updated_at_utc":"2026-10-16T12:30:45Z","message":"provider secret text"}',
    b' '*2049,
])
def test_malformed_or_oversized_progress_is_omitted(progress_file,payload):
    root, run, path = progress_file
    path.write_bytes(payload)
    assert native_progress(root,run) == {}


@pytest.mark.parametrize('component',['jobs','job','file'])
def test_progress_symlink_components_are_never_read(progress_file,monkeypatch,component):
    root, run, path = progress_file
    selected = {'jobs':path.parent.parent,'job':path.parent,'file':path}[component]
    original_symlink = Path.is_symlink
    original_open = Path.open
    monkeypatch.setattr(Path,'is_symlink',lambda item: item==selected or original_symlink(item))
    def no_progress_read(item,*args,**kwargs):
        assert item != path, 'A symlink progress path must not be opened'
        return original_open(item,*args,**kwargs)
    monkeypatch.setattr(Path,'open',no_progress_read)
    assert native_progress(root,run) == {}


def test_missing_and_unreadable_progress_is_omitted(progress_file,monkeypatch):
    root, run, path = progress_file
    original_open = Path.open
    def unavailable(item,*args,**kwargs):
        if item == path:
            raise PermissionError('private filesystem detail')
        return original_open(item,*args,**kwargs)
    monkeypatch.setattr(Path,'open',unavailable)
    assert native_progress(root,run) == {}
    assert native_progress(root,{**run,'id':'fox-'+'b'*20}) == {}


def test_resolved_progress_path_must_stay_in_original_job(progress_file,monkeypatch):
    root, run, path = progress_file
    original_resolve = Path.resolve
    def redirected(item,*args,**kwargs):
        return root/'elsewhere.json' if item == path else original_resolve(item,*args,**kwargs)
    monkeypatch.setattr(Path,'resolve',redirected)
    assert native_progress(root,run) == {}


def test_project_progress_is_advisory_and_never_exposes_file_text(client):
    c, root, pid, _, _ = client
    report = upload_ready(c,pid)
    rid = c.post(f'/api/projects/{pid}/runs',json=consent(report)).json()['id']
    path = root/'jobs'/rid/'native-progress.json'
    original_message = 'Saved conversion status remains authoritative.'
    with sqlite3.connect(root/'fox.sqlite3') as db:
        db.execute("UPDATE runs SET state='PROCESSING',message=? WHERE id=?",(original_message,rid))
    path.write_text(json.dumps({'stage':'reviewing','updated_at_utc':'2026-10-16T12:30:45Z'}),encoding='utf-8')
    current = c.get(f'/api/projects/{pid}').json()['runs'][0]
    assert current['message'] == original_message
    assert current['stage_message'] == NATIVE_STAGE_MESSAGES['reviewing']
    path.write_text('{"provider":"private source text"}',encoding='utf-8')
    response = c.get(f'/api/projects/{pid}')
    assert response.status_code == 200
    assert 'stage' not in response.json()['runs'][0]
    assert 'private source text' not in response.text
