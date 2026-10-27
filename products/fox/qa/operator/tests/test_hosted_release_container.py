"""Execute the v3 generated loader against unchanged source and local SQLite.

Only container path prefixes, UID/GID, environment and stdio are mapped.
Production source hashes, imports, manifest validation and queue reads/writes
remain real. All files are synthetic temporary fixtures; external IO is blocked.
"""
from __future__ import annotations

import builtins
from contextlib import ExitStack, closing
from copy import deepcopy
import io
import json
import os
import pathlib
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
for directory in (ROOT, ROOT / 'converter', ROOT / 'fox'):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from qa.operator import product_queue_transport as bridge, product_verifier as verifier
from qa.operator.tests.test_hosted_release_binding import (
    PROFILE_PATH, canonical_bytes, digest, offline_configuration, operator_configuration)
from fox import verification_queue as queue_module


GENERATED = '<hosted-v3-container-fixture>'
JOB = 'fox-' + '1' * 20


class GeneratedHostedContainerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='v3c-', dir=ROOT / 'work')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source_root = self.root / 'modules'
        self.source_root.mkdir()
        self.data = self.root / 'data'
        self.data.mkdir()
        self.profile = self.root / 'profile.json'
        self.configuration = offline_configuration()
        self.manifest = verifier.build_manifest(operator_configuration(self.configuration),
            hosted_configuration=canonical_bytes(self.configuration))
        self.assertEqual(self.manifest['schema_version'], 3)
        self.release = bridge.release_sha256(self.manifest)
        self.expected_sources = dict(self.manifest['modules'])
        self.expected_sources.update(self.manifest['project']['modules'])
        self.expected_sources.update(self.manifest['project']['queue_modules'])
        for name, expected in self.expected_sources.items():
            raw = (ROOT / 'fox/fox' / name).read_bytes()
            self.assertEqual(digest(raw), expected, 'Test must use actual unchanged source bytes')
            (self.source_root / name).write_bytes(raw)
        raw = (ROOT / PROFILE_PATH).read_bytes()
        self.assertEqual(digest(raw), self.manifest['native_profile_sha256'])
        self.profile.write_bytes(raw)
        self.database = self.data / 'fox.sqlite3'
        self.binding = queue_module.VerificationBinding(JOB, '2' * 64, '3' * 64, self.release)
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute('CREATE TABLE runs(id TEXT PRIMARY KEY,source_hash TEXT,state TEXT,artifact TEXT)')
            db.execute('INSERT INTO runs VALUES(?,?,?,?)', (JOB, self.binding.source_manifest_sha256,
                'QA_REQUIRED', str(Path('jobs') / JOB / 'apex-package.zip')))
            db.execute('CREATE TABLE verification_operator_contact('
                'singleton INTEGER PRIMARY KEY CHECK(singleton=1),release_sha256 TEXT NOT NULL,last_seen REAL NOT NULL)')
        self.queue = queue_module.VerificationQueue(self.database, enabled=True,
            verifier_release_sha256=self.release)
        self.queue.initialize()
        self.expected_row = self.queue.enqueue(self.binding)

    def execute(self, *, operation='status', mutate_request=None, enabled='1', effective_uid=1000):
        request = {'operation': operation, 'apply': operation != 'status',
            'manifest': deepcopy(self.manifest), 'release_sha256': self.release,
            'binding': self.binding.payload() if operation == 'status' else None,
            'claim': None, 'code': None, 'proof_sha256': None}
        if mutate_request is not None:
            mutate_request(request)
        program = bridge.container_source()
        mapped = []

        def mapped_path(*parts):
            path = Path(*parts)
            text = str(parts[0]).replace('\\', '/') if len(parts) == 1 else path.as_posix()
            prefixes = {'/app/fox': self.source_root, '/data': self.data,
                '/run/fox-native/profile.json': self.profile}
            for prefix, destination in prefixes.items():
                if text == prefix or text.startswith(prefix + '/'):
                    path = destination if text == prefix else destination / text[len(prefix):].lstrip('/')
                    mapped.append((text, path))
                    break
            return path

        real_import = builtins.__import__

        def import_mapped(name, globals=None, locals=None, fromlist=(), level=0):
            filename = str((globals or {}).get('__file__', ''))
            if name == 'pathlib' and (filename == GENERATED or filename.startswith('/app/fox/')):
                return SimpleNamespace(**{**vars(pathlib), 'Path': mapped_path})
            return real_import(name, globals, locals, fromlist, level)

        modules_before = dict(sys.modules)
        path_before, meta_before = list(sys.path), list(sys.meta_path)
        no_bytecode_before, trace_before = sys.dont_write_bytecode, sys.gettrace()
        output, exceptions, imported, database_calls, statements = io.StringIO(), [], set(), [], []
        real_connect = sqlite3.connect

        def traced_connect(*args, **kwargs):
            database_calls.append((args, kwargs))
            connection = real_connect(*args, **kwargs)
            connection.set_trace_callback(statements.append)
            return connection

        def trace(frame, event, arg):
            filename = frame.f_code.co_filename
            if event == 'call' and filename.startswith('/app/fox/'):
                imported.add(filename.rsplit('/', 1)[-1])
            if event == 'exception' and (filename == GENERATED or filename.startswith('/app/fox/')):
                exceptions.append((filename, frame.f_lineno, type(arg[1]).__name__, str(arg[1])))
            return trace

        try:
            with ExitStack() as stack:
                stack.enter_context(patch.object(builtins, '__import__', import_mapped))
                stack.enter_context(patch.object(os, 'geteuid', return_value=effective_uid, create=True))
                stack.enter_context(patch.object(os, 'getegid', return_value=1000, create=True))
                stack.enter_context(patch.dict(os.environ, {'FOX_VERIFICATION_ENABLED': enabled,
                    'FOX_VERIFIER_RELEASE_SHA256': self.release}))
                stack.enter_context(patch.object(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(canonical_bytes(request)))))
                stack.enter_context(patch.object(sys, 'stdout', output))
                stack.enter_context(patch.object(sqlite3, 'connect', side_effect=traced_connect))
                boundaries = [stack.enter_context(patch.object(module, name,
                    side_effect=AssertionError('External IO forbidden in generated-container fixture')))
                    for module, name in ((socket, 'create_connection'), (socket.socket, 'connect'),
                                         (subprocess, 'run'), (subprocess, 'Popen'))]
                sys.settrace(trace)
                exec(compile(program, GENERATED, 'exec', optimize=2),
                    {'__name__': '_hosted_v3_container_fixture', '__file__': GENERATED})
                for boundary in boundaries:
                    boundary.assert_not_called()
        finally:
            sys.settrace(trace_before)
            sys.path[:] = path_before
            sys.meta_path[:] = meta_before
            sys.dont_write_bytecode = no_bytecode_before
            for name in list(sys.modules):
                if name not in modules_before:
                    sys.modules.pop(name, None)
            sys.modules.update(modules_before)
        self.assertEqual(set(sys.modules), set(modules_before))
        self.assertTrue(all(sys.modules[name] is value for name, value in modules_before.items()))
        self.assertEqual(sys.path, path_before)
        self.assertEqual(sys.meta_path, meta_before)
        return SimpleNamespace(result=json.loads(output.getvalue()), imported=imported,
            exceptions=exceptions, mapped=mapped, database_calls=database_calls, statements=statements)

    def assert_stopped_before_import_or_database(self, observed):
        self.assertEqual(observed.result, {'status': 'STOPPED',
            'code': 'QUEUE_CONTAINER_OUTCOME_UNCONFIRMED_NO_REPLAY', 'automatic_replay_permitted': False})
        self.assertFalse(observed.imported, observed.exceptions[-8:])
        self.assertFalse(observed.database_calls)

    def test_actual_v3_loader_reads_real_queue_with_unchanged_installed_modules(self):
        before = self.database.read_bytes()
        observed = self.execute()
        self.assertEqual(observed.result, {'status': 'STATUS', 'verifier_release_sha256': self.release,
            'automatic_replay_permitted': False, 'queue': self.expected_row}, observed.exceptions[-8:])
        self.assertTrue({'verification_queue.py', 'verification_runtime.py', 'technical_release.py',
            'verification_recovery.py', 'native_verification.py'} <= observed.imported)
        self.assertTrue(any(text == '/run/fox-native/profile.json' for text, _ in observed.mapped))
        self.assertTrue(any(text == '/data' for text, _ in observed.mapped))
        self.assertTrue(observed.database_calls)
        self.assertTrue(all(args[0].endswith('?mode=ro') and kwargs['uri'] is True
                            for args, kwargs in observed.database_calls))
        self.assertTrue(all(sql.lstrip().upper().startswith(('SELECT ', 'PRAGMA '))
                            for sql in observed.statements))
        self.assertEqual(self.database.read_bytes(), before)
        for name, expected in self.expected_sources.items():
            self.assertEqual(digest((self.source_root / name).read_bytes()), expected)

    def test_actual_v3_runtime_heartbeat_writes_only_synthetic_contact(self):
        observed = self.execute(operation='heartbeat')
        self.assertEqual(observed.result, {'status': 'CONTACT_RECORDED',
            'verifier_release_sha256': self.release, 'automatic_replay_permitted': False}, observed.exceptions[-8:])
        self.assertIn('verification_runtime.py', observed.imported)
        self.assertEqual(self.queue.get(JOB), self.expected_row)
        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute('SELECT singleton,release_sha256 FROM verification_operator_contact').fetchall(),
                             [(1, self.release)])
            self.assertEqual(db.execute('SELECT COUNT(*) FROM runs').fetchone(), (1,))

    def test_every_changed_installed_dependency_fails_before_import_or_database(self):
        before = self.database.read_bytes()
        for name in self.expected_sources:
            with self.subTest(module=name):
                member = self.source_root / name
                original = member.read_bytes()
                member.write_bytes(original + b'\n# synthetic source mismatch\n')
                try:
                    self.assert_stopped_before_import_or_database(self.execute())
                finally:
                    member.write_bytes(original)
        self.assertEqual(self.database.read_bytes(), before)

    def test_stale_mounted_profile_fails_before_import_or_database(self):
        self.profile.write_bytes(b'{"synthetic":"stale mounted profile inode"}\n')
        self.assert_stopped_before_import_or_database(self.execute())

    def test_unknown_manifest_fields_fail_before_import_or_database(self):
        for mutate in (lambda request: request['manifest'].update(unreviewed=True),
                       lambda request: request['manifest']['opaf_profile'].update(unreviewed=True)):
            with self.subTest(mutation=mutate):
                self.assert_stopped_before_import_or_database(self.execute(mutate_request=mutate))

    def test_container_identity_and_configuration_fail_before_import_or_database(self):
        for options in ({'effective_uid': 0}, {'enabled': '0'},
                        {'mutate_request': lambda request: request.update(release_sha256='9' * 64)}):
            with self.subTest(options=options):
                self.assert_stopped_before_import_or_database(self.execute(**options))


if __name__ == '__main__':
    unittest.main(verbosity=2)
