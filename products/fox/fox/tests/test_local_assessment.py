"""Finite localhost-launch proof. Synthetic stores; no server socket or provider."""
from contextlib import asynccontextmanager, closing, redirect_stderr, redirect_stdout
import gc
import importlib
import io
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


FOX_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FOX_ROOT))
from fox import local_assessment as launch


class LocalAssessmentTests(unittest.TestCase):
    def test_child_environment_excludes_all_integration_and_secret_values(self):
        parent = {'PATH': 'ordinary-runtime-path', 'SystemRoot': 'ordinary-windows-root',
                  'FOX_DATA_DIR': '/never-read-live-data', 'FOX_RUN_ADAPTER': 'embedded-opaf',
                  'FOX_OPAF_CREDENTIAL_FILE': '/never-read-secret', 'FOX_PASSWORD_HASH': 'old-secret',
                  'FOX_NATIVE_PROFILE_FILE': '/never-read-profile', 'FOX_OPAF_RUN_URL': 'https://never.invalid',
                  'F2A_TARGET_PROFILE_PATH': '/never-read-target', 'F2A_MCP_BEARER_TOKEN': 'old-token',
                  'OPAF_PASSWORD': 'old-secret', 'OCI_CONFIG_FILE': '/never-read-oci',
                  'TNS_ADMIN': '/never-read-wallet', 'PYTHONPATH': '/never-import', 'AWS_SECRET_ACCESS_KEY': 'old-secret',
                  'ORACLE_HOME': '/never-inherit-tools', 'JAVA_HOME': '/never-inherit-java',
                  'USERPROFILE': '/unneeded-profile', 'APPDATA': '/unneeded-appdata', 'LOCALAPPDATA': '/unneeded-localdata'}
        result = launch.child_environment(parent)
        self.assertEqual(set(result), {'PATH', 'SystemRoot', 'PYTHONNOUSERSITE', 'PYTHONDONTWRITEBYTECODE', 'PYTHONUNBUFFERED'})
        self.assertEqual(parent['FOX_DATA_DIR'], '/never-read-live-data')
        self.assertNotIn('old-secret', json.dumps(result))

    def test_request_is_bounded_strict_and_does_not_echo_values(self):
        good = {'port': 8100, 'password': 'synthetic-test-password'}
        self.assertEqual(launch.read_request(io.BytesIO(json.dumps(good).encode())), good)
        for value in ({**good, 'port': True}, {**good, 'port': 80}, {**good, 'port': 65536},
                      {**good, 'host': '0.0.0.0'}, {**good, 'password': ''}, {**good, 'password': None}, [], None):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ValueError) as error:
                launch.read_request(io.BytesIO(json.dumps(value).encode()))
            self.assertNotIn('synthetic-test-password', str(error.exception))
        for raw in (b'x' * 8193, b'not-json-secret-value', b'\xff'):
            with self.assertRaises(ValueError) as error:
                launch.read_request(io.BytesIO(raw))
            self.assertNotIn('secret-value', str(error.exception))

    def test_data_is_new_per_session_and_existing_files_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / 'assessment'
            first = launch.new_data_directory(base)
            marker = first / 'retained.txt'
            marker.write_text('keep', encoding='utf-8')
            second = launch.new_data_directory(base)
            self.assertNotEqual(first, second)
            self.assertEqual(first.parent, base)
            self.assertEqual(marker.read_text(encoding='utf-8'), 'keep')
            self.assertFalse((base / 'fox.sqlite3').exists())

    def test_unicode_password_survives_explicit_utf8_stdin(self):
        request = {'port': 8100, 'password': 'Synthetic-秘密-café-🔒'}
        raw = json.dumps(request, ensure_ascii=False).encode('utf-8')
        self.assertEqual(launch.read_request(io.BytesIO(raw)), request)

    def test_optional_tools_are_explicit_paired_local_absolute_paths(self):
        request = {'port': 8100, 'password': 'synthetic-only'}
        with tempfile.TemporaryDirectory() as directory:
            configured = {**request, 'oracle_home': str(Path(directory) / 'Forms-秘密'),
                          'java_exe': str(Path(directory) / 'Java-café' / 'java.exe')}
            self.assertEqual(launch.read_request(io.BytesIO(json.dumps(configured, ensure_ascii=False).encode('utf-8'))), configured)
            for invalid in ({**request, 'oracle_home': configured['oracle_home']},
                            {**request, 'java_exe': configured['java_exe']},
                            {**configured, 'oracle_home': None}, {**configured, 'java_exe': ''},
                            {**configured, 'oracle_home': 'relative/Forms'},
                            {**configured, 'java_exe': 'https://never.invalid/java.exe'},
                            {**configured, 'oracle_home': '\\\\server\\Forms'},
                            {**configured, 'backend': 'browser-selected'},
                            {**configured, 'java_exe': configured['java_exe'] + '\x00'}):
                with self.subTest(keys=list(invalid)), self.assertRaises(ValueError):
                    launch.read_request(io.BytesIO(json.dumps(invalid).encode()))

    def test_bad_tool_request_fails_before_environment_storage_or_app_import(self):
        with patch.dict(os.environ, {'FOX_DATA_DIR': 'retained-env'}, clear=True), \
             patch.object(launch, 'new_data_directory') as storage, \
             patch.object(importlib, 'import_module') as importer:
            with self.assertRaises(ValueError):
                launch.build_assessment_app({'port': 8100, 'password': 'synthetic', 'oracle_home': 'incomplete'})
            storage.assert_not_called()
            importer.assert_not_called()
            self.assertEqual(os.environ['FOX_DATA_DIR'], 'retained-env')

    def test_linked_storage_is_rejected_before_mkdir(self):
        with patch.object(Path, 'is_symlink', return_value=True), patch.object(Path, 'mkdir') as mkdir:
            with self.assertRaises(ValueError):
                launch.new_data_directory(Path('linked-preview'))
            mkdir.assert_not_called()

    def test_sanitizes_before_app_import_and_explicitly_disables_served_worker(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
                'FOX_DATA_DIR': '/never-touch-live', 'FOX_RUN_ADAPTER': 'embedded-opaf',
                'FOX_OPAF_CREDENTIAL_FILE': '/never-touch-secret', 'OCI_CONFIG_FILE': '/never-touch-oci'}, clear=True):
            calls = []
            from fastapi import FastAPI
            fake_app = FastAPI()
            def import_app(name):
                self.assertEqual(name, 'fox.app')
                self.assertNotIn('FOX_RUN_ADAPTER', os.environ)
                self.assertNotIn('FOX_OPAF_CREDENTIAL_FILE', os.environ)
                self.assertNotIn('OCI_CONFIG_FILE', os.environ)
                self.assertNotEqual(os.environ['FOX_DATA_DIR'], '/never-touch-live')
                self.assertRegex(os.environ['FOX_PASSWORD_HASH'], r'^[0-9a-f]{32}:[0-9a-f]{128}$')
                return SimpleNamespace(password_hash=lambda password: 'test-hash-only',
                    create_app=lambda **kwargs: (calls.append(kwargs), fake_app)[1])
            with patch.object(importlib, 'import_module', side_effect=import_app), \
                 patch.object(launch, '_check_assessment_database'):
                app, path = launch.build_assessment_app({'port': 8101, 'password': 'never-log-this'}, base=Path(directory))
            self.assertIs(app, fake_app)
            self.assertEqual(calls, [{'data_dir': path, 'enable_worker': False,
                                     'enable_local_preparation': True, 'local_preparation_backend': None}])
            self.assertEqual(os.environ['FOX_PUBLIC_ORIGIN'], 'http://127.0.0.1:8101')
            self.assertEqual(os.environ['FOX_CONVERSION_PROFILE'], 'native-project-v1')
            self.assertRegex(os.environ['FOX_PASSWORD_HASH'], r'^[0-9a-f]{32}:[0-9a-f]{128}$')
            app.state.local_session_lock.close()

    def test_main_uses_only_loopback_and_never_prints_password_or_hash(self):
        secret = 'synthetic-secret-never-output'
        output, error = io.StringIO(), io.StringIO()
        captured = {}
        runner = SimpleNamespace(run=lambda app, **kwargs: captured.update(kwargs))
        fake_app = SimpleNamespace(state=SimpleNamespace(local_session_resumed=False,
                                   local_session_username=launch.DEFAULT_USERNAME,
                                   local_session_lock=SimpleNamespace(close=lambda: None)))
        stream = SimpleNamespace(buffer=io.BytesIO(json.dumps({'port': 8123, 'password': secret}).encode()))
        with patch.object(sys, 'argv', ['local_assessment']), patch.object(sys, 'stdin', stream), \
             patch.object(launch, 'build_assessment_app', return_value=(fake_app, Path('synthetic-assessment'))), \
             patch.dict(sys.modules, {'uvicorn': runner}), redirect_stdout(output), redirect_stderr(error):
            self.assertEqual(launch.main(), 0)
        self.assertEqual(captured['host'], '127.0.0.1')
        self.assertEqual(captured['port'], 8123)
        self.assertFalse(captured['access_log'])
        self.assertFalse(captured['proxy_headers'])
        self.assertNotIn(secret, output.getvalue() + error.getvalue())
        self.assertIn('conversion and worker disabled', output.getvalue())

    def test_failure_diagnostics_withhold_exception_and_secret(self):
        output, error = io.StringIO(), io.StringIO()
        stream = SimpleNamespace(buffer=io.BytesIO(b'{"port":8100,"password":"secret-value"}'))
        with patch.object(sys, 'argv', ['local_assessment']), patch.object(sys, 'stdin', stream), \
             patch.object(launch, 'build_assessment_app', side_effect=RuntimeError('secret-value /private/path')), \
             redirect_stdout(output), redirect_stderr(error):
            self.assertEqual(launch.main(), 1)
        self.assertNotIn('secret-value', output.getvalue() + error.getvalue())
        self.assertNotIn('/private/path', error.getvalue())

    def test_powershell_contract_keeps_secret_stdin_and_caller_environment(self):
        source = (FOX_ROOT / 'scripts/start-local.ps1').read_text(encoding='utf-8')
        self.assertIn('Read-Host', source)
        self.assertIn('-AsSecureString', source)
        self.assertIn('RedirectStandardInput = $true', source)
        self.assertNotIn('StandardInputEncoding', source)
        self.assertIn('[System.Text.Encoding]::UTF8.GetBytes', source)
        self.assertIn('StandardInput.BaseStream.Write($foxInputBytes, 0, $foxInputBytes.Length)', source)
        self.assertIn('[Array]::Clear($foxInputBytes', source)
        self.assertIn('EnvironmentVariables.Clear()', source)
        self.assertIn("'-B -m fox.local_assessment'", source)
        self.assertNotIn('from fox.app', source)
        self.assertNotIn('fox.app:app', source)
        self.assertNotRegex(source, r'\$env:')
        self.assertNotIn('Set-Location', source)
        allowed = re.search(r'\$foxAllowedEnvironment = @\(([^\n]+)\)', source).group(1)
        self.assertEqual(tuple(re.findall(r"'([^']+)'", allowed)), launch.ENVIRONMENT_ALLOWLIST)
        self.assertIn('ZeroFreeBSTR', source)
        self.assertIn('Stop-FoxOwnedProcessTree -Process $foxProcess -ExpectedId $foxOwnedId -ExpectedStartTicks $foxOwnedStartTicks', source)
        self.assertIn('$Process.Refresh()', source)
        self.assertIn('$Process.StartTime.ToUniversalTime().Ticks', source)
        self.assertIn("'System32\\taskkill.exe'", source)
        self.assertNotIn('/IM ', source)
        self.assertIn("$PSBoundParameters.ContainsKey('OracleHome')", source)
        self.assertIn("$PSBoundParameters.ContainsKey('JavaExe')", source)
        self.assertIn('$foxRequest.oracle_home = $foxOracleHome', source)
        self.assertIn('$foxRequest.java_exe = $foxJavaExe', source)
        self.assertIn('$foxRequest.resume_session = $ResumeSession', source)
        self.assertIn('GetUnresolvedProviderPathFromPSPath', source)

    @unittest.skipUnless(os.name == 'nt', 'Windows PowerShell mocked shutdown contract')
    def test_powershell_stop_targets_only_matching_owned_identity_and_captures_output(self):
        shell = Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
        script = str(FOX_ROOT / 'scripts/start-local.ps1').replace("'", "''")
        probe = r'''
$ErrorActionPreference = 'Stop'
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile('__SCRIPT__',[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'PARSE_FAILED' }
$names=@('Get-FoxOwnedProcessIdentity','Invoke-FoxOwnedTreeTermination','Stop-FoxOwnedProcessTree')
$nodes=$ast.FindAll({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $names -contains $node.Name},$true)
if ($nodes.Count -ne 3) { throw 'FUNCTIONS_MISSING' }
foreach($node in $nodes) { . ([ScriptBlock]::Create($node.Extent.Text)) }
# Never start taskkill, Python, Java or any application: these replace the two
# operating-system seams before the shutdown coordinator is exercised.
$script:mode='match'; $script:invocations=0
function Get-FoxOwnedProcessIdentity {
 param($Process)
 if($script:mode -eq 'exited') { return $null }
 if($script:mode -eq 'unavailable') { throw 'Local preview shutdown identity could not be verified; no process was targeted.' }
 if($script:mode -eq 'pid-changed') { return @{Id=4322;StartTicks=123456} }
 if($script:mode -eq 'start-changed') { return @{Id=4321;StartTicks=123457} }
 return @{Id=4321;StartTicks=123456}
}
function Invoke-FoxOwnedTreeTermination {
 param($StartInfo)
 $expected=Join-Path ([Environment]::GetFolderPath('Windows')) 'System32\taskkill.exe'
 if($StartInfo.FileName -ne $expected -or $StartInfo.Arguments -ne '/PID 4321 /T /F') { throw 'WRONG_TARGET' }
 if($StartInfo.UseShellExecute -or !$StartInfo.CreateNoWindow -or !$StartInfo.RedirectStandardOutput -or !$StartInfo.RedirectStandardError) { throw 'UNSAFE_HELPER' }
 $script:invocations++
 return 0
}
$fake=[PSCustomObject]@{}
$fake | Add-Member -MemberType ScriptMethod -Name WaitForExit -Value { param($timeout) return $true }
Stop-FoxOwnedProcessTree -Process $fake -ExpectedId 4321 -ExpectedStartTicks 123456
if($script:invocations -ne 1) { throw 'MATCH_NOT_STOPPED' }
foreach($case in @('pid-changed','start-changed','unavailable')) {
 $script:mode=$case; $rejected=$false
 try { Stop-FoxOwnedProcessTree -Process $fake -ExpectedId 4321 -ExpectedStartTicks 123456 }
 catch { $rejected=$_.Exception.Message -eq 'Local preview shutdown identity could not be verified; no process was targeted.' }
 if(!$rejected -or $script:invocations -ne 1) { throw 'IDENTITY_GUARD_FAILED' }
}
$script:mode='exited'
Stop-FoxOwnedProcessTree -Process $fake -ExpectedId 4321 -ExpectedStartTicks 123456
if($script:invocations -ne 1) { throw 'EXITED_TARGET_WAS_STOPPED' }
Write-Output 'MOCK_OWNED_TREE_STOP_OK'
'''.replace('__SCRIPT__', script)
        result = subprocess.run([str(shell), '-NoProfile', '-NonInteractive', '-Command', probe],
                                capture_output=True, text=True, timeout=20, check=False)
        self.assertEqual(result.returncode, 0, 'Mocked owned-process-tree contract failed.')
        self.assertIn('MOCK_OWNED_TREE_STOP_OK', result.stdout)

    def test_real_app_lifecycle_assesses_without_worker_network_or_existing_store(self):
        from fastapi.testclient import TestClient
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
                'FOX_DATA_DIR': str(Path(directory) / 'live-do-not-touch'),
                'FOX_RUN_ADAPTER': 'embedded-opaf', 'FOX_OPAF_RUN_URL': 'https://never.invalid',
                'FOX_OPAF_CREDENTIAL_FILE': str(Path(directory) / 'secret-do-not-open')}, clear=True):
            app, data = launch.build_assessment_app({'port': 8100, 'password': 'test-only-password'}, base=Path(directory) / 'preview')
            from fox import worker
            with patch.object(worker, 'process_one', side_effect=AssertionError('worker must not run')), \
                 patch('socket.create_connection', side_effect=AssertionError('no external connection')), \
                 patch('subprocess.Popen', side_effect=AssertionError('no conversion process')), \
                 TestClient(app, base_url='http://127.0.0.1:8100', client=('127.0.0.1', 50000)) as client:
                self.assertEqual(client.get('/api/health').json()['worker']['state'], 'disabled')
                self.assertEqual(client.get('/api/local-preparation/capabilities').status_code, 401)
                headers = {'Origin': 'http://127.0.0.1:8100'}
                self.assertEqual(client.post('/api/login', headers=headers, json={'username': launch.DEFAULT_USERNAME, 'password': 'test-only-password'}).status_code, 200)
                self.assertFalse(client.get('/api/session').json()['conversion_configured'])
                capabilities = client.get('/api/local-preparation/capabilities')
                self.assertEqual(capabilities.status_code, 200)
                self.assertEqual(capabilities.json()['native_formats'], [])
                project = client.post('/api/projects', headers=headers, json={'customer': 'Synthetic', 'name': 'Assessment test'}).json()
                response = client.post(f"/api/projects/{project['id']}/sources", headers=headers,
                    files=[('files', ('notes.txt', b'Synthetic readable evidence only.', 'text/plain'))])
                self.assertEqual(response.status_code, 200)
                body = {'source_hash': response.json()['source_hash'], 'approved_redacted_source': True,
                        'approved_external_ai': True, 'approved_prototype_scope': True}
                self.assertIn(client.post(f"/api/projects/{project['id']}/runs", headers=headers, json=body).status_code, (409, 503))
            self.assertFalse((Path(directory) / 'live-do-not-touch').exists())
            self.assertFalse((Path(directory) / 'secret-do-not-open').exists())
            with closing(sqlite3.connect(data / 'fox.sqlite3')) as db:
                self.assertEqual(db.execute('select count(*) from runs').fetchone()[0], 0)
            gc.collect()  # Release temporary SQLite connection cycles on Windows.

    def test_real_hosted_factory_has_no_local_routes_and_rejects_worker_enabled_feature(self):
        from fastapi.testclient import TestClient
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            local_app, _ = launch.build_assessment_app({'port': 8100, 'password': 'test-only'}, base=Path(directory) / 'local')
            from fox.app import create_app
            os.environ['FOX_ENABLE_LOCAL_PREPARATION'] = 'true'  # Not an activation mechanism.
            hosted = create_app(Path(directory) / 'hosted', enable_worker=False)
            with TestClient(hosted, base_url='http://127.0.0.1:8100', client=('127.0.0.1', 50000)) as client:
                self.assertEqual(client.get('/api/local-preparation/capabilities').status_code, 404)
            with self.assertRaises(ValueError):
                create_app(Path(directory) / 'not-created', enable_worker=True, enable_local_preparation=True)
            self.assertFalse((Path(directory) / 'not-created').exists())
            local_app.state.local_preparation_service.close()
            local_app.state.local_session_lock.close()
            gc.collect()

    def test_real_local_auth_origin_and_explicit_prepared_handoff_never_convert(self):
        from fastapi.testclient import TestClient
        origin = 'http://127.0.0.1:8100'
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {}, clear=True):
            app, root = launch.build_assessment_app({'port': 8100, 'password': 'test-only'}, base=Path(directory))
            from fox import worker
            from fox.opaf import OpafClient
            with patch.object(worker, 'process_one', side_effect=AssertionError('no worker')), \
                 patch.object(OpafClient, '_request', side_effect=AssertionError('no model request')), \
                 patch('socket.create_connection', side_effect=AssertionError('no network')), \
                 patch('subprocess.Popen', side_effect=AssertionError('no native/conversion execution')), \
                 TestClient(app, base_url=origin, client=('127.0.0.1', 50000)) as client:
                prefix = '/api/local-preparation'
                self.assertEqual(client.get(prefix + '/capabilities').status_code, 401)
                self.assertEqual(client.post('/api/login', headers={'Origin': origin},
                    json={'username': launch.DEFAULT_USERNAME, 'password': 'test-only'}).status_code, 200)
                self.assertEqual(client.get(prefix + '/capabilities', headers={'Host': 'other.invalid'}).status_code, 403)
                self.assertEqual(client.get(prefix + '/capabilities', headers={'Origin': 'https://other.invalid'}).status_code, 403)
                self.assertEqual(client.post(prefix + '/jobs', files={'files': ('a.txt', b'local')}).status_code, 403)
                fixtures = FOX_ROOT / 'tests/fixtures'
                selected = [('files', ('native.xml', (fixtures / 'native-beta.xml').read_bytes())),
                            ('files', ('native.sql', (fixtures / 'native-beta.sql').read_bytes()))]
                prepared = client.post(prefix + '/jobs', headers={'Origin': origin}, files=selected)
                self.assertEqual(prepared.status_code, 202, prepared.text)
                app.state.local_preparation_service._future.result(timeout=5)
                status = client.get(prefix + '/jobs/' + prepared.json()['job_id']).json()
                self.assertEqual(status['state'], 'PREPARED_REVIEW_REQUIRED')
                self.assertFalse(status['approved_for_upload'])
                with closing(sqlite3.connect(root / 'fox.sqlite3')) as db:
                    self.assertEqual(db.execute('select count(*) from sources').fetchone()[0], 0)
                    self.assertEqual(db.execute('select count(*) from runs').fetchone()[0], 0)
                handoff = []
                for item in status['files']:
                    response = client.get(prefix + '/jobs/' + status['job_id'] + '/files/' + item['file_id'])
                    self.assertEqual(response.status_code, 200)
                    field = 'prepared_manifest' if item['name'] == 'fox-readable-upload.json' else 'files'
                    handoff.append((field, (item['name'], response.content)))
                project = client.post('/api/projects', headers={'Origin': origin},
                    json={'customer': 'Synthetic', 'name': 'Explicit reviewed local handoff'}).json()['id']
                target = f'/api/projects/{project}/sources'
                self.assertEqual(client.post(target, headers={'Origin': 'https://other.invalid'}, files=handoff).status_code, 403)
                uploaded = client.post(target, headers={'Origin': origin}, files=handoff)
                self.assertEqual(uploaded.status_code, 200, uploaded.text)
                assessment = uploaded.json()
                self.assertEqual(assessment['source_preparation']['mode'], 'PREPARED_SET_MATCH')
                self.assertEqual(assessment['project_assessment']['native_state'], 'READY')
                plan = client.get(f'/api/projects/{project}/conversion-plan').json()
                body = {'source_hash': assessment['source_hash'], 'approved_redacted_source': True,
                        'approved_external_ai': True, 'approved_prototype_scope': True,
                        'expected_current_source_set_id': plan['selected_source_set_id'],
                        'plan_sha256': plan['plan_sha256']}
                self.assertEqual(client.post(f'/api/projects/{project}/runs', headers={'Origin': origin}, json=body).status_code, 503)
                self.assertEqual(client.get('/api/health').json()['worker']['state'], 'disabled')
            with closing(sqlite3.connect(root / 'fox.sqlite3')) as db:
                self.assertEqual(db.execute('select count(*) from runs').fetchone()[0], 0)
                self.assertEqual(db.execute('select count(*) from acceptances').fetchone()[0], 0)
            gc.collect()

    def test_only_explicit_startup_paths_construct_native_backend_without_executing_tools(self):
        from fastapi.testclient import TestClient
        from fox import extractor

        class FakeNative:
            name = 'FAKE-NATIVE-UNIT-TEST-ONLY'
            calls = 0
            def check(self):
                return {'formats': ['.fmb', '.mmb', '.olb', '.pll']}
            def extract(self, source, destination):
                self.calls += 1
                output = destination / 'synthetic_pll.xml'
                output.write_bytes(b'<Module><FormModule Name="SYNTHETIC"/></Module>')
                return output

        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {
                'ORACLE_HOME': 'ignored-home', 'JAVA_HOME': 'ignored-java',
                'FOX_OPAF_CREDENTIAL_FILE': 'ignored-secret'}, clear=True):
            home, java = Path(directory) / 'explicit-forms', Path(directory) / 'explicit-java.exe'
            backend = FakeNative()
            with patch.object(extractor, 'OracleFormsBackend', return_value=backend) as constructor:
                app, _ = launch.build_assessment_app({'port': 8100, 'password': 'test-only',
                    'oracle_home': str(home), 'java_exe': str(java)}, base=Path(directory) / 'data')
                constructor.assert_called_once_with(home, java)
                self.assertEqual(backend.calls, 0)
                self.assertNotIn('ORACLE_HOME', os.environ)
                self.assertNotIn('JAVA_HOME', os.environ)
                with patch('subprocess.Popen', side_effect=AssertionError('no real Oracle tool')), \
                     TestClient(app, base_url='http://127.0.0.1:8100', client=('127.0.0.1', 50000)) as client:
                    headers = {'Origin': 'http://127.0.0.1:8100'}
                    self.assertEqual(client.post('/api/login', headers=headers,
                        json={'username': launch.DEFAULT_USERNAME, 'password': 'test-only'}).status_code, 200)
                    capability = client.get('/api/local-preparation/capabilities').json()
                    self.assertEqual(capability['native_formats'], ['.fmb', '.mmb', '.olb', '.pll'])
                    self.assertTrue(capability['tool_presence_only'])
                    self.assertFalse(capability['native_extraction_verified'])
                    rejected = client.post('/api/local-preparation/jobs', headers=headers,
                        files=[('files', ('module.pll', b'FAKE ONLY')), ('oracle_home', (None, 'browser-override'))])
                    self.assertEqual(rejected.status_code, 422)
                    response = client.post('/api/local-preparation/jobs', headers=headers,
                        files=[('files', ('module.pll', b'FAKE ONLY'))])
                    self.assertEqual(response.status_code, 202)
                    app.state.local_preparation_service._future.result(timeout=5)
                    self.assertEqual(backend.calls, 1)
                    self.assertEqual(client.get('/api/local-preparation/jobs/' + response.json()['job_id']).json()['state'], 'PREPARED_REVIEW_REQUIRED')
            gc.collect()


if __name__ == '__main__':
    unittest.main()
