"""Actual private filesystem/OS locks plus synthetic in-process resume tests.

No listener, real Oracle tools, customer data or remote connections are used.
"""
from contextlib import closing
import gc
import hashlib
import importlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fox import local_assessment as launch
from fox import local_security as security


REQUEST = {'port': 8100, 'password': 'Synthetic-resume-only-秘密'}
ORIGIN = 'http://127.0.0.1:8100'


def client_for(app):
    from fastapi.testclient import TestClient
    return TestClient(app, base_url=ORIGIN, client=('127.0.0.1', 50000))


def finish_unserved(app):
    app.state.local_preparation_service.close()
    app.state.local_session_lock.close()
    gc.collect()


def create_closed(base):
    app, root = launch.build_assessment_app(dict(REQUEST), base=base)
    with client_for(app):
        pass
    gc.collect()
    return root


class LocalSessionResumeTests(unittest.TestCase):
    def test_actual_private_owner_and_cross_process_lifetime_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / 'owned-new'
            root.mkdir()
            owner = security.protect_new_directory(root)
            self.assertEqual(security.verify_private(root), owner)
            lock_path = root / launch.SESSION_LOCK
            lock = security.SessionLock(lock_path, create=True)
            self.assertEqual(security.verify_private(lock_path), owner)
            code = "import sys;from fox.local_security import SessionLock,LocalSessionError;\ntry:\n l=SessionLock(sys.argv[1]);l.close();print('ACQUIRED')\nexcept LocalSessionError:\n print('LOCKED')"
            command = [sys.executable, '-B', '-c', code, str(lock_path)]
            try:
                first = subprocess.run(command, cwd=Path(__file__).resolve().parents[1],
                                       capture_output=True, text=True, timeout=10, check=False)
                self.assertEqual((first.returncode, first.stdout.strip()), (0, 'LOCKED'))
            finally:
                lock.close()
            second = subprocess.run(command, cwd=Path(__file__).resolve().parents[1],
                                    capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual((second.returncode, second.stdout.strip()), (0, 'ACQUIRED'))

    def test_actual_prepare_explicit_upload_and_project_resume_without_preparation_replay(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, dict(os.environ), clear=True):
            base = Path(temporary) / 'sessions'
            app, root = launch.build_assessment_app(dict(REQUEST), base=base)
            marker_before = (root / launch.SESSION_MARKER).read_bytes()
            self.assertNotIn(REQUEST['password'].encode('utf-8'), marker_before)
            marker = json.loads(marker_before)
            self.assertEqual(marker['owner_id'], security.verify_private(root))
            from fox.app import check_password
            self.assertTrue(check_password(REQUEST['password'], marker['password_verifier']))
            with client_for(app) as client:
                headers = {'Origin': ORIGIN}
                self.assertEqual(client.post('/api/login', headers=headers,
                    json={'username': launch.DEFAULT_USERNAME, 'password': REQUEST['password']}).status_code, 200)
                submitted = client.post('/api/local-preparation/jobs', headers=headers,
                    files=[('files', ('reviewed.txt', b'Synthetic local source\r\n'))])
                self.assertEqual(submitted.status_code, 202, submitted.text)
                app.state.local_preparation_service._future.result(timeout=5)
                preparation_id = submitted.json()['job_id']
                prepared = client.get('/api/local-preparation/jobs/' + preparation_id).json()
                self.assertEqual(prepared['state'], 'PREPARED_REVIEW_REQUIRED')
                files = []
                for entry in prepared['files']:
                    output = client.get('/api/local-preparation/jobs/' + preparation_id + '/files/' + entry['file_id'])
                    self.assertEqual(output.status_code, 200)
                    field = 'prepared_manifest' if entry['name'] == 'fox-readable-upload.json' else 'files'
                    files.append((field, (entry['name'], output.content)))
                project_id = client.post('/api/projects', headers=headers,
                    json={'customer': 'Synthetic', 'name': 'Retained local project'}).json()['id']
                uploaded = client.post('/api/projects/' + project_id + '/sources', headers=headers, files=files)
                self.assertEqual(uploaded.status_code, 200)
                source_hash = uploaded.json()['source_hash']
            gc.collect()
            # Retained incomplete extraction material is not deleted or replayed.
            incomplete = root / 'local-preparation' / ('prep-' + 'f' * 32)
            incomplete.mkdir(parents=True)
            (incomplete / 'local-status.json').write_text('{"state":"RUNNING"}', encoding='utf-8')
            before = {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
                      for folder in ('local-preparation', 'i', 'p')
                      for path in (root / folder).rglob('*') if path.is_file()}
            resumed, resumed_root = launch.build_assessment_app({**REQUEST, 'resume_session': root.name}, base=base)
            self.assertEqual(resumed_root, root)
            self.assertTrue(resumed.state.local_session_resumed)
            self.assertEqual(resumed.state.local_preparation_service._jobs, {})
            with client_for(resumed) as client:
                headers = {'Origin': ORIGIN}
                self.assertEqual(client.post('/api/login', headers=headers,
                    json={'username': launch.DEFAULT_USERNAME, 'password': REQUEST['password']}).status_code, 200)
                projects = client.get('/api/projects').json()
                self.assertEqual([item['id'] for item in projects], [project_id])
                self.assertEqual(client.get('/api/projects/' + project_id).json()['inventory']['source_hash'], source_hash)
                self.assertEqual(client.get('/api/local-preparation/jobs/' + preparation_id).status_code, 404)
                self.assertFalse(client.get('/api/session').json()['conversion_configured'])
                self.assertEqual(client.get('/api/health').json()['worker']['state'], 'disabled')
            gc.collect()
            after = {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
                     for folder in ('local-preparation', 'i', 'p')
                     for path in (root / folder).rglob('*') if path.is_file()}
            self.assertEqual(after, before)
            self.assertEqual((root / launch.SESSION_MARKER).read_bytes(), marker_before)

    def test_wrong_password_origin_tool_binding_and_owner_fail_before_app_import(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, dict(os.environ), clear=True):
            base = Path(temporary)
            root = create_closed(base)
            marker_path = root / launch.SESSION_MARKER
            marker_raw = marker_path.read_bytes()
            database_hash = hashlib.sha256((root / 'fox.sqlite3').read_bytes()).hexdigest()
            attempts = [
                {**REQUEST, 'resume_session': root.name, 'password': 'wrong-synthetic-password'},
                {**REQUEST, 'resume_session': root.name, 'port': 8101},
                {**REQUEST, 'resume_session': root.name, 'oracle_home': str(base / 'explicit-home'), 'java_exe': str(base / 'explicit-java.exe')},
            ]
            for request in attempts:
                with patch.object(importlib, 'import_module', side_effect=AssertionError('must not import app')):
                    with self.assertRaises(security.LocalSessionError) as error:
                        launch.build_assessment_app(request, base=base)
                self.assertNotIn(request['password'], str(error.exception))
                self.assertEqual(marker_path.read_bytes(), marker_raw)
                self.assertEqual(hashlib.sha256((root / 'fox.sqlite3').read_bytes()).hexdigest(), database_hash)
            changed = json.loads(marker_raw)
            changed['owner_id'] = 'not-the-current-owner'
            marker_path.write_text(json.dumps(changed), encoding='utf-8')
            with patch.object(importlib, 'import_module', side_effect=AssertionError('must not import app')):
                with self.assertRaises(security.LocalSessionError):
                    launch.build_assessment_app({**REQUEST, 'resume_session': root.name}, base=base)

    def test_busy_session_rejects_second_open_before_reading_marker(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, dict(os.environ), clear=True):
            app, root = launch.build_assessment_app(dict(REQUEST), base=Path(temporary))
            try:
                with patch.object(launch, '_read_marker', side_effect=AssertionError('lock must precede marker read')):
                    with self.assertRaises(security.LocalSessionError):
                        launch.build_assessment_app({**REQUEST, 'resume_session': root.name}, base=Path(temporary))
            finally:
                finish_unserved(app)

    def test_exact_session_id_only_and_no_implicit_adoption(self):
        for identifier in ('../data', 'session-' + 'a' * 31, 'session-' + 'A' * 32,
                           'C:/hosted/data', 'latest', '', None, True):
            with self.subTest(identifier_type=type(identifier).__name__), self.assertRaises(ValueError):
                launch.validate_request({**REQUEST, 'resume_session': identifier})
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, dict(os.environ), clear=True):
            base = Path(temporary)
            unmarked = launch.new_data_directory(base)
            (unmarked / 'sentinel.txt').write_bytes(b'kept-unadopted')
            with self.assertRaises(security.LocalSessionError):
                launch.build_assessment_app({**REQUEST, 'resume_session': unmarked.name}, base=base)
            self.assertFalse((unmarked / launch.SESSION_MARKER).exists())
            self.assertEqual((unmarked / 'sentinel.txt').read_bytes(), b'kept-unadopted')
            first = create_closed(base)
            second = create_closed(base)
            self.assertNotEqual(first, second)

    def test_marker_tamper_and_non_assessment_database_are_not_migrated(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, dict(os.environ), clear=True):
            base = Path(temporary)
            root = create_closed(base)
            marker_path = root / launch.SESSION_MARKER
            original = marker_path.read_bytes()
            for change in ({'worker_enabled': True}, {'schema_version': True}, {'unsupported': 'never-echo'},
                           {'password_verifier': 'invalid'}, {'session_id': 'session-' + '0' * 32}):
                marker = json.loads(original)
                marker.update(change)
                marker_path.write_text(json.dumps(marker), encoding='utf-8')
                with self.assertRaises(security.LocalSessionError):
                    launch.build_assessment_app({**REQUEST, 'resume_session': root.name}, base=base)
            marker_path.write_bytes(original)
            with closing(sqlite3.connect(root / 'fox.sqlite3')) as connection:
                connection.execute("INSERT INTO projects VALUES('synthetic-other','other-owner','Synthetic','Other','',0)")
                connection.commit()
            gc.collect()
            before = (root / 'fox.sqlite3').read_bytes()
            with self.assertRaises(security.LocalSessionError):
                launch.build_assessment_app({**REQUEST, 'resume_session': root.name}, base=base)
            self.assertEqual((root / 'fox.sqlite3').read_bytes(), before)

    @unittest.skipUnless(os.name == 'nt', 'Actual Windows DACL regression')
    def test_actual_permission_drift_is_rejected_and_not_repaired(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, dict(os.environ), clear=True):
            base = Path(temporary)
            root = create_closed(base)
            # Deliberately widen ONLY this freshly owned synthetic test directory.
            script = r'''
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$path=[Console]::In.ReadToEnd()
$acl=[System.Security.AccessControl.DirectorySecurity]::new()
$sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true,$false)
foreach($principal in @($sid,[System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'))) {
 $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($principal,'FullControl','ContainerInherit, ObjectInherit','None','Allow'))
}
$everyone=[System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($everyone,'ReadAndExecute','Allow'))
[System.IO.Directory]::SetAccessControl($path,$acl)
[Console]::WriteLine('SYNTHETIC_ACL_WIDENED')
'''
            import base64
            shell = Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
            environment = {key: value for key, value in os.environ.items() if key.upper() in {'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'PATH'}}
            environment.update(SystemRoot=str(shell.parents[3]), WINDIR=str(shell.parents[3]),
                               PSModulePath=str(shell.parent / 'Modules'))
            result = subprocess.run([str(shell), '-NoProfile', '-NonInteractive', '-EncodedCommand',
                                     base64.b64encode(script.encode('utf-16-le')).decode()],
                                    input=str(root).encode(), capture_output=True, env=environment, timeout=15)
            self.assertEqual(result.returncode, 0, 'Synthetic ACL setup failed: ' + result.stderr.decode(errors='replace')[:2000])
            for _ in range(2):
                with self.assertRaises(security.LocalSessionError):
                    launch.build_assessment_app({**REQUEST, 'resume_session': root.name}, base=base)
                with self.assertRaises(security.LocalSessionError):
                    security.verify_private(root)


if __name__ == '__main__':
    unittest.main()
