"""Configurable identity, with real isolated ASGI login and retained sessions.

No server socket, Oracle tool, model, cloud or operator credential is used.
The unchanged local owner/ACL and lifetime-lock checks remain in the path.
"""
from contextlib import closing, redirect_stderr, redirect_stdout
import gc
import importlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from fox import local_assessment as launch
from fox.local_security import LocalSessionError


FOX_ROOT = Path(__file__).resolve().parents[1]
ORIGIN = 'http://127.0.0.1:8100'
PASSWORD = 'Synthetic-identity-only-秘密'


@pytest.fixture
def isolated_environment():
    # build_assessment_app intentionally clears its own process environment.
    # Restore the pytest process after every case without changing the caller.
    with patch.dict(os.environ, dict(os.environ), clear=True):
        yield


@pytest.fixture
def session_base():
    # Short, create-only retained fixture paths avoid Windows path-budget noise.
    root = FOX_ROOT / 'work'
    root.mkdir(exist_ok=True)
    return Path(tempfile.mkdtemp(prefix='id-', dir=root))


def client_for(app):
    from fastapi.testclient import TestClient
    return TestClient(app, base_url=ORIGIN, client=('127.0.0.1', 50000))


def close_unserved(app):
    app.state.local_preparation_service.close()
    app.state.local_session_lock.close()
    gc.collect()


def create_retained(base, username):
    """The v1 on-disk marker shape matches the pre-configurable launcher."""
    request = {'port': 8100, 'password': PASSWORD, 'username': username}
    app, root = launch.build_assessment_app(request, base=base)
    with client_for(app) as client:
        headers = {'Origin': ORIGIN}
        assert client.post('/api/login', headers=headers,
                           json={'username': username, 'password': PASSWORD}).status_code == 200
        project = client.post('/api/projects', headers=headers,
                              json={'customer': 'Synthetic QA', 'name': 'Retained identity'}).json()
        uploaded = client.post('/api/projects/' + project['id'] + '/sources', headers=headers,
                               files=[('files', ('notes.txt', b'Synthetic identity fixture only.'))])
        assert uploaded.status_code == 200
        source_hash = uploaded.json()['source_hash']
    gc.collect()
    return root, project['id'], source_hash


def test_neutral_default_and_custom_case_are_not_normalized():
    assert launch.DEFAULT_USERNAME == 'fox-local'
    assert launch._startup_binding({'port': 8100})['username'] == 'fox-local'
    assert launch._startup_binding({'port': 8100, 'username': 'Team.One+qa@example.test'})['username'] == 'Team.One+qa@example.test'


@pytest.mark.parametrize('value', ['a', '0', 'Team.One', 'user_name-1', 'user+qa@example.test', 'a' * 100])
def test_explicit_identity_is_validated_without_mutating_request(value):
    request = {'port': 8100, 'password': PASSWORD, 'username': value}
    before = dict(request)
    assert launch.validate_request(request) == before
    assert launch.read_request(io.BytesIO(json.dumps(request).encode())) == before
    assert request == before


@pytest.mark.parametrize('value', ['', ' a', 'a ', 'a\n', 'a\r', 'a\x00', 'a/b', 'a\\b',
                                  'a:b', '.a', '-a', '_a', 'a' * 101, 'é', None, True, 3, ['name']])
def test_bad_identity_is_rejected_before_environment_storage_or_import(value):
    with patch.dict(os.environ, {'FOX_DATA_DIR': 'must-stay-unchanged'}, clear=True), \
         patch.object(launch, 'new_data_directory') as storage, \
         patch.object(importlib, 'import_module') as importer:
        with pytest.raises(ValueError) as error:
            launch.build_assessment_app({'port': 8100, 'password': PASSWORD, 'username': value})
        assert PASSWORD not in str(error.value)
        assert os.environ['FOX_DATA_DIR'] == 'must-stay-unchanged'
        storage.assert_not_called()
        importer.assert_not_called()


def test_duplicate_stdin_identity_is_rejected_not_last_value_wins():
    raw = b'{"port":8100,"password":"synthetic","username":"one","username":"two"}'
    with pytest.raises(ValueError, match='no supplied values'):
        launch.read_request(io.BytesIO(raw))


@pytest.mark.parametrize('args, expected', [([], None), (['--username', 'Team.One'], 'Team.One'),
                                           (['--username=Team.One'], 'Team.One')])
def test_cli_supports_only_explicit_nonsecret_identity(args, expected):
    assert launch.username_option(args) == expected


@pytest.mark.parametrize('args', [['--username'], ['--username='], ['--password', 'never-output'],
                                ['--host', '0.0.0.0'], ['--username', 'one', '--username', 'two'],
                                ['--username=one', '--username=two'], ['--username', 'one\n']])
def test_cli_rejects_unknown_duplicate_or_invalid_values(args):
    with pytest.raises(ValueError) as error:
        launch.username_option(args)
    assert 'never-output' not in str(error.value)


def test_stdin_and_cli_disagreement_never_overrides_identity():
    original = {'port': 8100, 'password': PASSWORD, 'username': 'Case.One'}
    assert launch.apply_username_option(original, 'Case.One') == original
    with pytest.raises(ValueError, match='do not match'):
        launch.apply_username_option(original, 'case.one')
    assert original['username'] == 'Case.One'


@pytest.mark.parametrize('username', [None, 'Team.One+qa@example.test'])
def test_actual_api_login_uses_new_default_or_explicit_identity(isolated_environment, session_base, username):
    os.environ.update(FOX_ADMIN_USERNAME='inherited-identity-must-not-win',
                      FOX_OPAF_CREDENTIAL_FILE='never-open-this-file', FOX_RUN_ADAPTER='embedded-opaf')
    request = {'port': 8100, 'password': PASSWORD}
    if username is not None:
        request['username'] = username
    expected = username or launch.DEFAULT_USERNAME
    app, root = launch.build_assessment_app(request, base=session_base)
    assert app.state.local_session_username == expected
    assert 'FOX_OPAF_CREDENTIAL_FILE' not in os.environ
    assert 'FOX_RUN_ADAPTER' not in os.environ
    with patch('socket.create_connection', side_effect=AssertionError('No external connection')), \
         patch('subprocess.Popen', side_effect=AssertionError('No extraction/conversion child')), \
         client_for(app) as client:
        headers = {'Origin': ORIGIN}
        assert client.get('/api/health').json()['worker']['enabled'] is False
        assert client.post('/api/login', headers=headers,
                           json={'username': 'different-user', 'password': PASSWORD}).status_code == 401
        assert client.post('/api/login', headers=headers,
                           json={'username': expected, 'password': PASSWORD}).status_code == 200
        assert client.get('/api/session').json()['username'] == expected
        assert client.get('/api/session').json()['conversion_configured'] is False
        project = client.post('/api/projects', headers=headers,
                              json={'customer': 'Synthetic QA', 'name': 'Identity project'})
        assert project.status_code == 201
    with closing(sqlite3.connect(root / 'fox.sqlite3')) as db:
        assert db.execute('SELECT owner FROM projects').fetchall() == [(expected,)]
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 0
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0] == 0
    marker = (root / launch.SESSION_MARKER).read_bytes()
    assert json.loads(marker)['username'] == expected
    assert PASSWORD.encode() not in marker
    gc.collect()


@pytest.mark.parametrize('username', ['jason', 'Earlier.Account'])
@pytest.mark.parametrize('explicit', [False, True])
def test_saved_v1_identity_survives_resume_without_rebinding(isolated_environment, session_base, username, explicit):
    root, project_id, source_hash = create_retained(session_base, username)
    marker_path = root / launch.SESSION_MARKER
    marker_before = marker_path.read_bytes()
    marker = json.loads(marker_before)
    assert marker['document_type'] == 'fox-local-assessment-session-v1'
    assert marker['schema_version'] == 1
    request = {'port': 8100, 'password': PASSWORD, 'resume_session': root.name}
    if explicit:
        request['username'] = username
    # open_session itself reads but does not initialize/migrate an old database.
    database_before = (root / 'fox.sqlite3').read_bytes()
    opened, lock, saved, resumed = launch.open_session(request, base=session_base)
    try:
        assert resumed and opened == root and saved['username'] == username
        assert saved['password_verifier'] == marker['password_verifier']
    finally:
        lock.close()
    assert (root / 'fox.sqlite3').read_bytes() == database_before
    assert marker_path.read_bytes() == marker_before
    app, resumed_root = launch.build_assessment_app(request, base=session_base)
    assert resumed_root == root and app.state.local_session_username == username
    with client_for(app) as client:
        assert client.post('/api/login', headers={'Origin': ORIGIN},
                           json={'username': username, 'password': PASSWORD}).status_code == 200
        assert [p['id'] for p in client.get('/api/projects').json()] == [project_id]
        assert client.get('/api/projects/' + project_id).json()['inventory']['source_hash'] == source_hash
    assert marker_path.read_bytes() == marker_before
    gc.collect()


@pytest.mark.parametrize('different', ['fox-local', 'Jason', 'other-user'])
def test_explicit_mismatched_resume_refuses_before_app_import(isolated_environment, session_base, different):
    root, _, _ = create_retained(session_base, 'jason')
    marker_path = root / launch.SESSION_MARKER
    marker_before = marker_path.read_bytes()
    database_before = (root / 'fox.sqlite3').read_bytes()
    before_children = sorted(p.name for p in session_base.iterdir())
    with patch.object(importlib, 'import_module') as importer:
        with pytest.raises(LocalSessionError, match='username does not match'):
            launch.build_assessment_app({'port': 8100, 'password': PASSWORD,
                                         'resume_session': root.name, 'username': different}, base=session_base)
        importer.assert_not_called()
    assert marker_path.read_bytes() == marker_before
    assert (root / 'fox.sqlite3').read_bytes() == database_before
    assert sorted(p.name for p in session_base.iterdir()) == before_children


def test_saved_identity_is_read_only_after_lifetime_lock(isolated_environment, session_base):
    app, root = launch.build_assessment_app({'port': 8100, 'password': PASSWORD,
                                           'username': 'Owner.One'}, base=session_base)
    try:
        with patch.object(launch, '_read_marker', side_effect=AssertionError('Must hold lifetime lock first')):
            with pytest.raises(LocalSessionError):
                launch.open_session({'port': 8100, 'password': PASSWORD, 'resume_session': root.name}, base=session_base)
    finally:
        close_unserved(app)


def test_main_reports_effective_saved_identity_and_withholds_password():
    output, error = io.StringIO(), io.StringIO()
    close = Mock()
    app = SimpleNamespace(state=SimpleNamespace(local_session_resumed=True,
        local_session_username='Saved.Account', local_session_lock=SimpleNamespace(close=close)))
    captured = {}
    runner = SimpleNamespace(run=lambda served, **kwargs: captured.update(kwargs))
    stdin = SimpleNamespace(buffer=io.BytesIO(json.dumps({'port': 8100, 'password': PASSWORD,
                                                       'resume_session': 'session-' + 'a' * 32}).encode()))
    with patch.object(sys, 'argv', ['local_assessment']), patch.object(sys, 'stdin', stdin), \
         patch.object(launch, 'build_assessment_app', return_value=(app, Path('synthetic-only'))), \
         patch.dict(sys.modules, {'uvicorn': runner}), redirect_stdout(output), redirect_stderr(error):
        assert launch.main() == 0
    assert 'username: Saved.Account' in output.getvalue()
    assert PASSWORD not in output.getvalue() + error.getvalue()
    assert captured['host'] == '127.0.0.1' and captured['port'] == 8100
    assert captured['access_log'] is False and captured['proxy_headers'] is False
    close.assert_called_once()


@pytest.mark.parametrize('args, body', [(['--password', 'must-not-echo'], {'port': 8100, 'password': PASSWORD}),
    (['--username', 'Other.Account'], {'port': 8100, 'password': PASSWORD, 'username': 'Saved.Account'})])
def test_main_rejects_bad_identity_arguments_without_start_or_value_echo(args, body):
    output, error = io.StringIO(), io.StringIO()
    stdin = SimpleNamespace(buffer=io.BytesIO(json.dumps(body).encode()))
    with patch.object(sys, 'argv', ['local_assessment', *args]), patch.object(sys, 'stdin', stdin), \
         patch.object(launch, 'build_assessment_app') as build, redirect_stdout(output), redirect_stderr(error):
        assert launch.main() == 1
    build.assert_not_called()
    assert PASSWORD not in output.getvalue() + error.getvalue()
    assert 'must-not-echo' not in output.getvalue() + error.getvalue()


@pytest.mark.skipif(os.name != 'nt', reason='Windows PowerShell parameter validation')
def test_powershell_username_validation_matches_python_without_starting_launcher():
    shell = Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    source = FOX_ROOT / 'scripts/start-local.ps1'
    program = r'''
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile('__SCRIPT__',[ref]$tokens,[ref]$errors)
if($errors.Count) { throw 'PARSE_FAILED' }
$parameters=@($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Username' })
if($parameters.Count -ne 1) { throw 'USERNAME_PARAMETER_MISSING' }
$validation=@($ast.EndBlock.Statements | Where-Object { $_.Extent.Text.StartsWith('if ($foxHasUsername -and') })
if($validation.Count -ne 1) { throw 'VALIDATION_BLOCK_MISSING' }
$test=[ScriptBlock]::Create('param([string]$Username,[bool]$foxHasUsername)' + $validation[0].Extent.Text)
foreach($name in @('fox-local','Team.One+qa@example.test',('a'*100))) { & $test $name $true }
foreach($name in @('', ' a', 'a ', "a`n", 'a/b', '-a', ('a'*101))) {
 $blocked=$false
 try { & $test $name $true } catch { $blocked=$true }
 if(!$blocked) { throw 'INVALID_USERNAME_ACCEPTED' }
}
& $test '' $false
[Console]::WriteLine('USERNAME_VALIDATION_OK_NO_LAUNCH')
'''.replace('__SCRIPT__', str(source).replace("'", "''"))
    result = subprocess.run([str(shell), '-NoProfile', '-NonInteractive', '-Command', program],
                            capture_output=True, text=True, timeout=20, check=False)
    assert result.returncode == 0
    assert result.stdout.strip() == 'USERNAME_VALIDATION_OK_NO_LAUNCH'
    text = source.read_text(encoding='utf-8')
    assert '$foxRequest.username = $Username' in text
    assert "$foxStart.Arguments = '-B -m fox.local_assessment'" in text
    assert '$foxRequest.password' in text and 'RedirectStandardInput = $true' in text
