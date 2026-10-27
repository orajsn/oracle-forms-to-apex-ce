"""Real local ASGI/storage profile checks; no listener or external service.

Historical markers are created only in new isolated synthetic directories.
Existing private sessions, Oracle tools and conversion targets are never used.
"""
from contextlib import closing, contextmanager
import gc
import hashlib
import importlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient

from fox import local_assessment as launch
from fox.local_security import LocalSessionError
from test_project_conversion import pair


ORIGIN = 'http://127.0.0.1:8100'
REQUEST = {'port': 8100, 'password': 'Synthetic-profile-only-password', 'username': 'Local.Owner'}


@pytest.fixture
def isolated_session_base():
    root = Path(__file__).resolve().parents[1] / 'work'
    root.mkdir(exist_ok=True)
    with patch.dict(os.environ, dict(os.environ), clear=True):
        yield Path(tempfile.mkdtemp(prefix='lp-', dir=root))
    gc.collect()


@contextmanager
def guarded_client(app):
    from fox import worker
    from fox.opaf import OpafClient, ConverterClient
    with patch.object(worker, 'process_one', side_effect=AssertionError('No conversion worker')), \
         patch.object(OpafClient, '_request', side_effect=AssertionError('No model request')), \
         patch.object(ConverterClient, 'request', side_effect=AssertionError('No converter/DB transport')), \
         patch.object(httpx.HTTPTransport, 'handle_request', side_effect=AssertionError('No HTTP transport')), \
         patch.object(httpx.AsyncHTTPTransport, 'handle_async_request', side_effect=AssertionError('No async HTTP transport')), \
         patch('socket.create_connection', side_effect=AssertionError('No external connection')), \
         patch('subprocess.Popen', side_effect=AssertionError('No native tool or database process')), \
         TestClient(app, base_url=ORIGIN, client=('127.0.0.1', 50000)) as client:
        client.headers['Origin'] = ORIGIN
        assert client.post('/api/login', json={'username': REQUEST['username'],
                                             'password': REQUEST['password']}).status_code == 200
        yield client
    gc.collect()


def test_fresh_project_profile_has_two_form_plan_but_no_execution(isolated_session_base):
    inherited = {'FOX_CONVERSION_PROFILE': 'native-table-form-v1',
                 'FOX_RUN_ADAPTER': 'embedded-opaf', 'FOX_NATIVE_PROFILE_FILE': 'do-not-read-profile',
                 'FOX_CONVERTER_URL': 'https://do-not-contact.invalid',
                 'FOX_OPAF_CREDENTIAL_FILE': 'do-not-read-credential', 'FOX_VERIFICATION_ENABLED': '1',
                 'F2A_TARGET_PROFILE_PATH': 'do-not-read-target', 'F2A_MCP_BEARER_TOKEN': 'synthetic-do-not-use'}
    os.environ.update(inherited)
    app, root = launch.build_assessment_app(dict(REQUEST), base=isolated_session_base)
    assert os.environ['FOX_CONVERSION_PROFILE'] == 'native-project-v1'
    assert {key for key in os.environ if key.startswith(('FOX_', 'F2A_'))} == {
        'FOX_DATA_DIR', 'FOX_PUBLIC_ORIGIN', 'FOX_ADMIN_USERNAME', 'FOX_CONVERSION_PROFILE', 'FOX_PASSWORD_HASH'}
    with guarded_client(app) as client:
        session = client.get('/api/session').json()
        assert session['conversion_profile'] == 'native-project-v1'
        assert session['conversion_configured'] is False
        assert client.get('/api/health').json()['worker']['enabled'] is False
        assert client.get('/api/local-preparation/capabilities').status_code == 200
        created = client.post('/api/projects', json={'customer': 'Synthetic QA', 'name': 'Two local forms'})
        assert created.status_code == 201
        project_id = created.json()['id']
        sources = pair() + pair('BETA', 'FOX_NATIVE_BETA')
        uploaded = client.post(f'/api/projects/{project_id}/sources', files=[
            ('files', (source['name'], source['text'].encode('utf-8'))) for source in sources])
        assert uploaded.status_code == 200, uploaded.text
        detail = client.get(f'/api/projects/{project_id}').json()
        plan = client.get(f'/api/projects/{project_id}/conversion-plan').json()
        assert detail['inventory']['conversion_profile'] == 'native-project-v1'
        assert plan['state'] == 'READY' and plan['summary']['form_count'] == 2
        assert detail['project_plan'] == plan
        assert detail['project_capabilities']['local_preparation']['enabled'] is True
        assert detail['project_capabilities']['process']['enabled'] is False
        assert detail['runs'] == []
        response = client.post(f'/api/projects/{project_id}/runs', json={
            'source_hash': plan['source_hash'], 'expected_current_source_set_id': plan['selected_source_set_id'],
            'plan_sha256': plan['plan_sha256'], 'approved_redacted_source': True,
            'approved_external_ai': True, 'approved_prototype_scope': True})
        assert response.status_code == 503, response.text
    with closing(sqlite3.connect(root / 'fox.sqlite3')) as db:
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 0
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0] == 0
    marker = json.loads((root / launch.SESSION_MARKER).read_bytes())
    assert marker['conversion_profile'] == 'native-project-v1' and marker['worker_enabled'] is False


@pytest.mark.parametrize('saved_profile', ['native-table-form-v1', 'native-project-v1'])
def test_real_saved_profile_identity_and_hash_resume_without_marker_rewrite(isolated_session_base, saved_profile):
    # Reproduce the historical v1 marker at creation time, not by rewriting a
    # user's marker. The current profile uses the same on-disk schema.
    with patch.object(launch, 'DEFAULT_PROFILE', saved_profile):
        app, root = launch.build_assessment_app(dict(REQUEST), base=isolated_session_base)
    with guarded_client(app) as client:
        project_id = client.post('/api/projects', json={'customer': 'Synthetic QA', 'name': 'Saved profile'}).json()['id']
        uploaded = client.post(f'/api/projects/{project_id}/sources', files=[('files', ('notes.txt', b'Synthetic retained source'))])
        assert uploaded.status_code == 200
        source_hash = uploaded.json()['source_hash']
    marker_path = root / launch.SESSION_MARKER
    before = marker_path.read_bytes()
    before_hash = hashlib.sha256(before).hexdigest()
    marker = json.loads(before)
    assert marker['conversion_profile'] == saved_profile and marker['schema_version'] == 1
    resume_request = {key: value for key, value in REQUEST.items() if key != 'username'}
    resume_request['resume_session'] = root.name
    db_before = (root / 'fox.sqlite3').read_bytes()
    opened, lock, saved, resumed = launch.open_session(resume_request, base=isolated_session_base)
    try:
        assert resumed and opened == root
        assert saved['conversion_profile'] == saved_profile
        assert saved['username'] == REQUEST['username']
        assert saved['password_verifier'] == marker['password_verifier']
    finally:
        lock.close()
    assert (root / 'fox.sqlite3').read_bytes() == db_before
    os.environ['FOX_CONVERSION_PROFILE'] = 'untrusted-environment-profile'
    reopened, reopened_root = launch.build_assessment_app(resume_request, base=isolated_session_base)
    assert reopened_root == root
    assert os.environ['FOX_CONVERSION_PROFILE'] == saved_profile
    assert os.environ['FOX_PASSWORD_HASH'] == marker['password_verifier']
    with guarded_client(reopened) as client:
        session = client.get('/api/session').json()
        assert session['username'] == REQUEST['username']
        assert session['conversion_profile'] == saved_profile and session['conversion_configured'] is False
        detail = client.get(f'/api/projects/{project_id}').json()
        assert detail['inventory']['source_hash'] == source_hash
        assert detail['inventory']['conversion_profile'] == saved_profile
        assert client.get('/api/health').json()['worker']['enabled'] is False
    assert marker_path.read_bytes() == before
    assert hashlib.sha256(marker_path.read_bytes()).hexdigest() == before_hash


@pytest.mark.parametrize('profile', [None, True, 1, {}, [], '', 'legacy-html-prototype-v1',
                                    'NATIVE-PROJECT-V1', 'native-project-v1 ', 'untrusted-profile'])
def test_invalid_saved_profile_refuses_before_app_import_without_rewrite(isolated_session_base, profile):
    app, root = launch.build_assessment_app(dict(REQUEST), base=isolated_session_base)
    with guarded_client(app):
        pass
    marker_path = root / launch.SESSION_MARKER
    marker = json.loads(marker_path.read_bytes())
    marker['conversion_profile'] = profile
    # Tamper only with this newly created synthetic fixture.
    marker_path.write_bytes(json.dumps(marker).encode())
    before = marker_path.read_bytes()
    database_before = (root / 'fox.sqlite3').read_bytes()
    with patch.object(importlib, 'import_module') as importer:
        with pytest.raises(LocalSessionError, match='assessment profile is invalid'):
            launch.build_assessment_app({**REQUEST, 'resume_session': root.name}, base=isolated_session_base)
        importer.assert_not_called()
    assert marker_path.read_bytes() == before
    assert (root / 'fox.sqlite3').read_bytes() == database_before


@pytest.mark.parametrize('key', ['conversion_profile', 'profile', 'saved_profile'])
def test_request_cannot_select_profile_before_any_state_change(key):
    with patch.dict(os.environ, {'FOX_DATA_DIR': 'unchanged'}, clear=True), \
         patch.object(launch, 'new_data_directory') as storage, \
         patch.object(importlib, 'import_module') as importer:
        with pytest.raises(ValueError):
            launch.build_assessment_app({**REQUEST, key: 'native-table-form-v1'})
        assert os.environ == {'FOX_DATA_DIR': 'unchanged'}
        storage.assert_not_called()
        importer.assert_not_called()
