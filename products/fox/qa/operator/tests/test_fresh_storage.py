"""Local fresh-storage checks, not installation or migration authority.

POSIX cases use real private directories, SQLite and flock. Windows runs the
pure/import contract cases. No OCI, SSH, Oracle, model or live container is used.
"""
from __future__ import annotations

from contextlib import closing
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import select
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
for directory in (ROOT, ROOT / 'fox'):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))
from qa.operator import fresh_storage as s


def declaration(base='/synthetic/local/fresh', owner_uid=1000):
    return s.declaration(**{name: str(PurePosixPath(base) / name) for name in s.ROLES}, owner_uid=owner_uid)


def snapshot(root):
    """Application-visible state; atime is intentionally not an integrity field."""
    result = {}
    for path in (root, *sorted(root.rglob('*'))):
        info = path.lstat()
        metadata = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        data = (os.readlink(path) if path.is_symlink() else
                hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None)
        result[path.relative_to(root).as_posix()] = (metadata, data)
    return result


def assert_no_authority(test, value):
    for name in ('connected_admission', 'services_started', 'oracle_accessed', 'automatic_replay_permitted'):
        test.assertIs(value[name], False)
    test.assertNotIn(value['status'], {'READY', 'INSTALLED', 'ADMITTED'})


class FreshStorageContractTests(unittest.TestCase):
    def test_declaration_is_bound_to_actual_source_and_canonical_bytes(self):
        plan = declaration()
        self.assertEqual(set(plan), {'schema_version', 'scope', 'owner_uid', 'roots', 'source_sha256', 'initial_schema_sha256'})
        self.assertEqual(plan['scope'], 'fox-fresh-local-storage-plan-v1')
        self.assertEqual(set(plan['roots']), set(s.ROLES))
        self.assertEqual(set(plan['source_sha256']), set(s.SOURCE_NAMES))
        for name, digest in plan['source_sha256'].items():
            self.assertEqual(digest, hashlib.sha256((ROOT / name).read_bytes()).hexdigest())
        self.assertEqual(s.plan_sha256(plan), hashlib.sha256(s.canonical(plan)).hexdigest())
        self.assertRegex(plan['initial_schema_sha256'], '^[a-f0-9]{64}$')
        self.assertEqual(json.loads(s.canonical(plan)), plan)

    def test_declaration_has_no_filesystem_storage_effect(self):
        with tempfile.TemporaryDirectory(prefix='fox-fresh-declare-') as temp:
            root = Path(temp)
            before = snapshot(root)
            # POSIX declarations are data; they do not touch these paths even on Windows.
            declaration()
            self.assertEqual(snapshot(root), before)

    def test_owner_must_be_explicit_nonroot_integer(self):
        for value in (0, -1, True, False, '1000', None, 1.5):
            with self.subTest(owner=value), self.assertRaises(s.FreshStorageError):
                declaration(owner_uid=value)

    def test_root_path_formats_are_not_silently_normalized(self):
        for value in ('relative/data', '/tmp/a/../data', '/tmp/a//data', '/tmp/a/data/',
                      '/tmp/a/data\\x', '/tmp/a/data\n', '/tmp/a/data\x00', 'C:/private/data', '/'):
            with self.subTest(path=value), self.assertRaises(s.FreshStorageError):
                s.declaration(fox_data=value, converter_jobs='/tmp/other/jobs',
                              operator_state='/tmp/other/operator', records='/tmp/other/records', owner_uid=1000)

    def test_overlapping_roots_are_rejected(self):
        for data, jobs in (('/tmp/private/data', '/tmp/private/data'),
                           ('/tmp/private/data', '/tmp/private/data/jobs'),
                           ('/tmp/private/data/jobs', '/tmp/private/data')):
            with self.subTest(roots=(data, jobs)), self.assertRaisesRegex(s.FreshStorageError, 'STORAGE_ROOTS_OVERLAP'):
                s.declaration(fox_data=data, converter_jobs=jobs, operator_state='/tmp/private/operator',
                              records='/tmp/private/records', owner_uid=1000)

    def test_known_migration_roots_cannot_select_fresh_mode(self):
        for existing in s.LEGACY_ROOTS:
            with self.subTest(root=existing), self.assertRaisesRegex(s.FreshStorageError, 'EXISTING_MIGRATION_SCOPE_FORBIDDEN'):
                s.declaration(fox_data=existing + '/not-an-upgrade', converter_jobs='/tmp/private/jobs',
                              operator_state='/tmp/private/operator', records='/tmp/private/records', owner_uid=1000)

    def test_plan_tamper_is_rejected_before_platform_or_storage_access(self):
        plan = declaration()
        for alter in (lambda v: v.update(schema_version=True), lambda v: v.update(scope='fresh-fallback'),
                      lambda v: v.update(retirement=None), lambda v: v['roots'].update(unreviewed='/tmp/private/a')):
            changed = deepcopy(plan); alter(changed)
            with self.subTest(plan=changed), self.assertRaises(s.FreshStorageError):
                s.initialize_storage(changed, expected_plan_sha256=s.plan_sha256(changed), apply=True)
        with self.assertRaisesRegex(s.FreshStorageError, 'EXACT_STORAGE_PLAN_REQUIRED'):
            s.initialize_storage(plan, expected_plan_sha256='0' * 64, apply=True)

    def test_apply_is_not_implied_or_truthy(self):
        plan = declaration()
        for flag in (False, None, 0, 1, 'yes', 'true'):
            with self.subTest(flag=flag), self.assertRaisesRegex(s.FreshStorageError, 'EXPLICIT_STORAGE_APPLY_REQUIRED'):
                s.initialize_storage(plan, expected_plan_sha256=s.plan_sha256(plan), apply=flag)

    def test_import_creates_no_storage_process_or_connection(self):
        program = r'''
import importlib, pathlib, socket, sqlite3, subprocess, sys, threading
from unittest.mock import patch
root=pathlib.Path(sys.argv[1]);sys.path[:0]=[str(root),str(root/'fox')]
def denied(*args,**kwargs):raise AssertionError('Import attempted a side effect')
with patch.object(pathlib.Path,'mkdir',side_effect=denied), patch.object(sqlite3,'connect',side_effect=denied), \
     patch.object(socket.socket,'connect',side_effect=denied), patch.object(subprocess,'run',side_effect=denied), \
     patch.object(subprocess,'Popen',side_effect=denied), patch.object(threading.Thread,'start',side_effect=denied):
 importlib.import_module('qa.operator.fresh_storage')
assert 'fox.app' not in sys.modules
print('IMPORT_INERT')
'''
        with tempfile.TemporaryDirectory(prefix='fox-fresh-import-') as temp:
            root = Path(temp); before = snapshot(root)
            result = subprocess.run([sys.executable, '-I', '-B', '-c', program, str(ROOT)],
                cwd=root, stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            self.assertEqual(result.stdout.strip(), b'IMPORT_INERT')
            self.assertEqual(snapshot(root), before)

    @unittest.skipIf(os.name == 'posix', 'Windows refusal is platform-specific')
    def test_non_posix_cannot_initialize_a_store(self):
        plan = declaration()
        with self.assertRaisesRegex(s.FreshStorageError, 'POSIX_OWNER_RUNTIME_REQUIRED'):
            s.initialize_storage(plan, expected_plan_sha256=s.plan_sha256(plan), apply=True)


POSIX = os.name == 'posix' and hasattr(os, 'geteuid') and os.geteuid() > 0


@unittest.skipUnless(POSIX, 'Actual nonroot POSIX filesystem required; use local WSL.')
class FreshStorageFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='fox-fresh-storage-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.plan = declaration(str(self.root), os.geteuid())
        self.digest = s.plan_sha256(self.plan)
        self.paths = {key: Path(value) for key, value in self.plan['roots'].items()}
        self.database = self.paths['fox_data'] / 'fox.sqlite3'

    def initialize(self):
        return s.initialize_storage(self.plan, expected_plan_sha256=self.digest, apply=True)

    def inspect(self):
        before = snapshot(self.root)
        result = s.inspect_storage(self.plan, expected_plan_sha256=self.digest)
        self.assertEqual(snapshot(self.root), before, 'Read-only inspection changed filesystem evidence')
        assert_no_authority(self, result)
        self.assertIs(result['read_only'], True)
        return result

    def readonly_db(self):
        return closing(sqlite3.connect(self.database.as_uri() + '?mode=ro&immutable=1', uri=True))

    def test_unstarted_inspection_writes_nothing(self):
        self.assertEqual(self.inspect()['status'], 'NOT_STARTED')
        self.assertEqual(list(self.root.iterdir()), [])

    def test_actual_shared_schema_and_generated_identity(self):
        result = self.initialize()
        self.assertEqual(result['status'], 'LOCAL_STORAGE_INITIALIZED_NOT_ADMITTED')
        assert_no_authority(self, result)
        self.assertRegex(result['installation_id'], '^fst-[a-f0-9]{32}$')
        for path in self.paths.values():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            self.assertEqual(path.stat().st_uid, os.geteuid())
        self.assertEqual(stat.S_IMODE(self.database.stat().st_mode), 0o600)
        self.assertFalse(any(Path(str(self.database) + suffix).exists() for suffix in ('-wal', '-shm', '-journal')))
        with self.readonly_db() as db:
            self.assertEqual(db.execute('SELECT singleton,installation_id,plan_sha256 FROM fox_storage_identity').fetchall(),
                             [(1, result['installation_id'], self.digest)])
            self.assertEqual(db.execute('SELECT owner,action,object_id FROM events').fetchall(),
                             [('system-source-history', 'source_history_initialized', 'schema-v1')])
            for name in ('projects','sources','sessions','attempts','runs','acceptances','prepared_uploads',
                         'source_sets','source_set_members','project_source_selection'):
                self.assertEqual(db.execute('SELECT COUNT(*) FROM ' + name).fetchone()[0], 0)
            self.assertFalse(db.execute("SELECT 1 FROM sqlite_master WHERE name='verification_queue'").fetchone())
        observed = self.inspect()
        self.assertEqual(observed['status'], 'LOCAL_STORAGE_BASELINE_OBSERVED_NOT_ADMITTED')
        self.assertEqual(observed['installation_id'], result['installation_id'])
        self.assertIs(observed['mutable_database_bytes_hashed'], False)
        self.assertEqual(list(self.paths['converter_jobs'].iterdir()), [])
        self.assertEqual(list(self.paths['operator_state'].iterdir()), [])

    def test_new_initializations_receive_different_real_identities(self):
        first = self.initialize()['installation_id']
        parent = self.root / 'second-install'; parent.mkdir(mode=0o700)
        plan = declaration(str(parent), os.geteuid())
        second = s.initialize_storage(plan, expected_plan_sha256=s.plan_sha256(plan), apply=True)['installation_id']
        self.assertNotEqual(first, second)

    def test_existing_empty_root_is_never_adopted_for_every_role(self):
        for role in s.ROLES:
            with self.subTest(role=role), tempfile.TemporaryDirectory(prefix='fox-fresh-existing-') as temp:
                parent = Path(temp); parent.chmod(0o700)
                plan = declaration(str(parent), os.geteuid())
                Path(plan['roots'][role]).mkdir(mode=0o700)
                before = snapshot(parent)
                with self.assertRaisesRegex(s.FreshStorageError, 'EXISTING_STORAGE_NOT_ADOPTED'):
                    s.initialize_storage(plan, expected_plan_sha256=s.plan_sha256(plan), apply=True)
                self.assertEqual(snapshot(parent), before)

    def test_copied_legacy_project_files_are_not_a_fresh_store(self):
        data = self.paths['fox_data']; data.mkdir(mode=0o700)
        (data / 'fox.sqlite3').write_bytes(b'RETAINED G DATABASE FIXTURE')
        jobs = data / 'jobs'; jobs.mkdir(mode=0o700)
        (jobs / 'old-proof.json').write_bytes(b'{"state":"VERIFIED","synthetic_fixture":true}')
        before = snapshot(self.root)
        with self.assertRaisesRegex(s.FreshStorageError, 'EXISTING_STORAGE_NOT_ADOPTED'):
            self.initialize()
        self.assertEqual(snapshot(self.root), before)
        self.assertEqual(self.inspect()['code'], 'PREEXISTING_STORAGE_WITHOUT_ATTEMPT')

    def test_parent_with_existing_store_marker_is_forbidden(self):
        (self.root / 'fox.sqlite3').write_bytes(b'EXISTING OWNER DATA')
        before = snapshot(self.root)
        with self.assertRaisesRegex(s.FreshStorageError, 'EXISTING_STORE_ANCESTOR_FORBIDDEN'):
            self.initialize()
        self.assertEqual(snapshot(self.root), before)

    def test_missing_parent_is_not_created(self):
        plan = declaration(str(self.root / 'missing'), os.geteuid())
        before = snapshot(self.root)
        with self.assertRaises((s.FreshStorageError, FileNotFoundError)):
            s.initialize_storage(plan, expected_plan_sha256=s.plan_sha256(plan), apply=True)
        self.assertEqual(snapshot(self.root), before)

    def test_nonprivate_parent_is_not_repaired(self):
        self.root.chmod(0o755)
        before = snapshot(self.root)
        with self.assertRaisesRegex(s.FreshStorageError, 'OWNER_PRIVATE_DIRECTORY_REQUIRED'):
            self.initialize()
        self.assertEqual(snapshot(self.root), before)

    def test_wrong_owner_declaration_fails_before_writes(self):
        plan = deepcopy(self.plan); plan['owner_uid'] = os.geteuid() + 1
        before = snapshot(self.root)
        with self.assertRaisesRegex(s.FreshStorageError, 'POSIX_OWNER_RUNTIME_REQUIRED'):
            s.initialize_storage(plan, expected_plan_sha256=s.plan_sha256(plan), apply=True)
        self.assertEqual(snapshot(self.root), before)

    def test_rehashed_changed_source_binding_cannot_initialize(self):
        plan = deepcopy(self.plan)
        plan['source_sha256']['fox/fox/storage.py'] = '0' * 64
        before = snapshot(self.root)
        with self.assertRaisesRegex(s.FreshStorageError, 'INITIALIZER_SOURCE_CHANGED'):
            s.initialize_storage(plan, expected_plan_sha256=s.plan_sha256(plan), apply=True)
        self.assertEqual(snapshot(self.root), before)

    def test_rehashed_changed_initial_schema_binding_cannot_initialize(self):
        plan = deepcopy(self.plan); plan['initial_schema_sha256'] = '0' * 64
        before = snapshot(self.root)
        with self.assertRaisesRegex(s.FreshStorageError, 'INITIAL_SCHEMA_BINDING_CHANGED'):
            s.initialize_storage(plan, expected_plan_sha256=s.plan_sha256(plan), apply=True)
        self.assertEqual(snapshot(self.root), before)

    def test_symlink_root_is_rejected_without_following(self):
        elsewhere = self.root / 'elsewhere'; elsewhere.mkdir(mode=0o700)
        self.paths['fox_data'].symlink_to(elsewhere, target_is_directory=True)
        before = snapshot(self.root)
        with self.assertRaises(s.FreshStorageError):
            self.initialize()
        self.assertEqual(snapshot(self.root), before)

    def test_symlink_parent_is_rejected_without_following(self):
        real = self.root / 'real'; real.mkdir(mode=0o700)
        link = self.root / 'linked'; link.symlink_to(real, target_is_directory=True)
        plan = declaration(str(link), os.geteuid())
        before = snapshot(self.root)
        with self.assertRaises(s.FreshStorageError):
            s.initialize_storage(plan, expected_plan_sha256=s.plan_sha256(plan), apply=True)
        self.assertEqual(snapshot(self.root), before)

    def test_second_initialize_never_resets_or_replays(self):
        self.initialize(); before = snapshot(self.root)
        with patch.object(sqlite3, 'connect', side_effect=AssertionError('No repeat SQL')):
            with self.assertRaisesRegex(s.FreshStorageError, 'EXISTING_STORAGE_NOT_ADOPTED'):
                self.initialize()
        self.assertEqual(snapshot(self.root), before)

    def test_later_project_and_normal_verification_tables_keep_identity(self):
        result = self.initialize()
        old_hash = hashlib.sha256(self.database.read_bytes()).hexdigest()
        from fox import source_history
        from fox.storage import initialize_schema
        from fox.verification_runtime import initialize, VerificationConfig
        with closing(sqlite3.connect(str(self.database))) as db, db:
            db.execute('PRAGMA foreign_keys=ON')
            db.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)',
                       ('synthetic-project', 'synthetic-owner', 'Synthetic', 'Local project', 'No customer data', 1.0))
            source_history.create_project_selection(db, 'synthetic-project', 1.0)
            db.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
                       ('synthetic-owner', 'project-created', 'synthetic-project', 1.0))
        with closing(sqlite3.connect(str(self.database))) as db, db:
            initialize_schema(db)  # The normal application's existing-store initialization.
        initialize(self.paths['fox_data'], VerificationConfig(True, 'a' * 64))
        jobs = self.paths['fox_data'] / 'jobs'; jobs.mkdir(mode=0o700)
        (jobs / 'synthetic-history.json').write_bytes(b'{"synthetic":true}')
        self.assertNotEqual(hashlib.sha256(self.database.read_bytes()).hexdigest(), old_hash)
        observed = self.inspect()
        self.assertEqual(observed['status'], 'LOCAL_STORAGE_BASELINE_OBSERVED_NOT_ADMITTED')
        self.assertEqual(observed['installation_id'], result['installation_id'])
        with self.readonly_db() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM projects').fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events WHERE action='source_history_initialized'").fetchone()[0], 1)

    def test_receipt_failure_after_real_initialization_preserves_everything(self):
        original = s._write
        def failing_write(path, raw):
            if path.name == 'complete.json':
                raise OSError('SYNTHETIC_RECEIPT_FAILURE')
            return original(path, raw)
        with patch.object(s, '_write', side_effect=failing_write), self.assertRaises(s.FreshStorageError):
            self.initialize()
        self.assertTrue(self.database.is_file())
        self.assertTrue((self.paths['records'] / 'database-initialized.json').is_file())
        self.assertFalse((self.paths['records'] / 'complete.json').exists())
        with self.readonly_db() as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM fox_storage_identity').fetchone()[0], 1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM events').fetchone()[0], 1)
        result = self.inspect()
        self.assertEqual(result['status'], 'ATTENTION')
        self.assertEqual(result['code'], 'INITIALIZATION_OBSERVED_WITHOUT_COMPLETION')
        before = snapshot(self.root)
        with self.assertRaisesRegex(s.FreshStorageError, 'EXISTING_STORAGE_NOT_ADOPTED'):
            self.initialize()
        self.assertEqual(snapshot(self.root), before)

    def test_memory_prerequisite_failure_closes_connection_and_creates_nothing(self):
        from fox import storage
        real_connect, real_initialize = sqlite3.connect, storage.initialize_schema
        connections = []
        def tracked_connect(*args, **kwargs):
            connection = real_connect(*args, **kwargs)
            connections.append((args[0], connection))
            return connection
        def failed_initializer(connection):
            real_initialize(connection)
            raise RuntimeError('SYNTHETIC_PRIVATE_PREREQUISITE_DIAGNOSTIC')
        before = snapshot(self.root)
        with patch.object(sqlite3, 'connect', side_effect=tracked_connect), \
             patch.object(storage, 'initialize_schema', side_effect=failed_initializer):
            with self.assertRaises(s.FreshStorageError) as error:
                self.initialize()
        self.assertNotIn('PRIVATE_PREREQUISITE', str(error.exception))
        self.assertEqual(len(connections), 1)
        self.assertEqual(connections[0][0], ':memory:')
        with self.assertRaises(sqlite3.ProgrammingError):
            connections[0][1].execute('SELECT 1')
        self.assertEqual(snapshot(self.root), before)

    def test_partial_root_allocation_remains_an_attention_state(self):
        original = s._mkdir
        def failed_mkdir(path):
            if path == self.paths['operator_state']:
                raise OSError('SYNTHETIC_ALLOCATION_FAILURE')
            return original(path)
        with patch.object(s, '_mkdir', side_effect=failed_mkdir), self.assertRaises(s.FreshStorageError):
            self.initialize()
        self.assertTrue(self.paths['fox_data'].is_dir())
        self.assertTrue(self.paths['converter_jobs'].is_dir())
        self.assertFalse(self.paths['operator_state'].exists())
        self.assertFalse(self.database.exists())
        observed = self.inspect()
        self.assertEqual(observed['status'], 'ATTENTION')
        self.assertEqual(observed['code'], 'PARTIAL_ROOT_ALLOCATION')
        before = snapshot(self.root)
        with self.assertRaises(s.FreshStorageError):self.initialize()
        self.assertEqual(snapshot(self.root), before)

    def test_partial_attempt_without_lock_is_not_restarted(self):
        self.paths['records'].mkdir(mode=0o700)
        result = self.inspect()
        self.assertEqual(result['status'], 'ATTENTION')
        self.assertEqual(result['code'], 'PARTIAL_ATTEMPT_WITHOUT_LOCK')
        before = snapshot(self.root)
        with self.assertRaises(s.FreshStorageError):self.initialize()
        self.assertEqual(snapshot(self.root), before)

    def test_unknown_record_is_not_ignored(self):
        self.initialize()
        extra = self.paths['records'] / 'pretend-ready.json'; extra.write_bytes(b'{"ready":true}'); extra.chmod(0o600)
        self.assertEqual(self.inspect()['code'], 'RECORD_INVENTORY_CHANGED')

    def test_changed_database_identity_is_not_adopted(self):
        self.initialize()
        with closing(sqlite3.connect(str(self.database))) as db, db:
            db.execute('UPDATE fox_storage_identity SET installation_id=?', ('fst-' + '0' * 32,))
        self.assertEqual(self.inspect()['code'], 'STORAGE_IDENTITY_CHANGED')

    def test_removed_core_schema_is_reported_not_recreated(self):
        self.initialize()
        with closing(sqlite3.connect(str(self.database))) as db, db:
            db.execute('DROP TABLE acceptances')
        self.assertEqual(self.inspect()['code'], 'INITIALIZED_SCHEMA_CHANGED')

    def test_altered_completion_is_detected_without_rewrite(self):
        self.initialize()
        path = self.paths['records'] / 'complete.json'
        value = json.loads(path.read_bytes()); value['intent_sha256'] = '0' * 64
        path.write_bytes(s.canonical(value))
        self.assertEqual(self.inspect()['code'], 'COMPLETION_BINDING_CHANGED')

    def _rewrite_schema_observation_and_rehash_completion(self, mutate):
        observed_path = self.paths['records'] / 'database-initialized.json'
        observed = json.loads(observed_path.read_bytes())
        mutate(observed)
        changed = s.canonical(observed); observed_path.write_bytes(changed)
        completion_path = self.paths['records'] / 'complete.json'
        completion = json.loads(completion_path.read_bytes())
        completion['schema_observation_sha256'] = hashlib.sha256(changed).hexdigest()
        completion_path.write_bytes(s.canonical(completion))

    def test_rehashed_pruned_schema_observation_is_still_invalid(self):
        self.initialize()
        self._rewrite_schema_observation_and_rehash_completion(
            lambda value: value.update(schema={'fox_storage_identity': value['schema']['fox_storage_identity']}))
        self.assertEqual(self.inspect()['status'], 'ATTENTION')

    def test_rehashed_nonempty_initial_business_count_is_still_invalid(self):
        self.initialize()
        self._rewrite_schema_observation_and_rehash_completion(
            lambda value: value['initial_counts'].update(projects=1))
        self.assertEqual(self.inspect()['status'], 'ATTENTION')

    def test_duplicate_record_json_is_not_accepted(self):
        self.initialize()
        path = self.paths['records'] / 'complete.json'
        raw = path.read_bytes(); path.write_bytes(raw.replace(b'{', b'{"scope":"duplicate",', 1))
        self.assertEqual(self.inspect()['code'], 'DUPLICATE_RECORD_KEY')

    def test_nonprivate_record_is_not_read_or_repaired(self):
        self.initialize(); path = self.paths['records'] / 'complete.json'; path.chmod(0o644)
        self.assertEqual(self.inspect()['code'], 'PRIVATE_RECORD_REQUIRED')

    def test_record_hardlink_is_rejected(self):
        self.initialize()
        os.link(self.paths['records'] / 'complete.json', self.root / 'linked-completion')
        self.assertEqual(self.inspect()['code'], 'PRIVATE_RECORD_REQUIRED')

    def test_database_symlink_is_not_followed(self):
        self.initialize()
        retained = self.root / 'retained.sqlite3'; self.database.rename(retained)
        self.database.symlink_to(retained)
        self.assertEqual(self.inspect()['code'], 'PRIVATE_SQLITE_FILE_REQUIRED')

    def test_copied_directory_at_same_path_has_wrong_identity(self):
        self.initialize()
        original = self.paths['converter_jobs']; retained = self.root / 'retained-jobs'
        original.rename(retained)
        shutil.copytree(retained, original)
        self.assertEqual(self.inspect()['code'], 'STORAGE_ROOT_IDENTITY_CHANGED')

    def test_root_changed_after_real_database_read_cannot_return_baseline(self):
        self.initialize()
        original = s._database_observation
        def concurrent_root_change(*args, **kwargs):
            result = original(*args, **kwargs)
            old = self.paths['converter_jobs']
            old.rename(self.root / 'retained-concurrent-jobs')
            old.mkdir(mode=0o700)
            return result
        with patch.object(s, '_database_observation', side_effect=concurrent_root_change):
            observed = s.inspect_storage(self.plan, expected_plan_sha256=self.digest)
        self.assertEqual(observed['status'], 'ATTENTION')
        assert_no_authority(self, observed)

    def test_record_changed_after_real_database_read_cannot_return_baseline(self):
        self.initialize()
        original = s._database_observation
        def concurrent_record_change(*args, **kwargs):
            result = original(*args, **kwargs)
            path = self.paths['records'] / 'intent.json'
            value = json.loads(path.read_bytes())
            value['created_at_utc'] = 'CHANGED_DURING_READ_SYNTHETIC'
            path.write_bytes(s.canonical(value))
            return result
        with patch.object(s, '_database_observation', side_effect=concurrent_record_change):
            observed = s.inspect_storage(self.plan, expected_plan_sha256=self.digest)
        self.assertEqual(observed['status'], 'ATTENTION')
        assert_no_authority(self, observed)

    def test_active_wal_is_attention_without_creating_or_changing_sidecars(self):
        self.initialize()
        with closing(sqlite3.connect(str(self.database))) as db:
            db.execute('PRAGMA journal_mode=WAL'); db.execute('PRAGMA wal_autocheckpoint=0')
            with db:db.execute('INSERT INTO attempts VALUES(?,?)', ('synthetic-loopback', 2.0))
            self.assertTrue(Path(str(self.database) + '-wal').exists())
            self.assertEqual(self.inspect()['code'], 'SQLITE_ACTIVE_OR_UNRECONCILED_SIDECARS')
        self.assertEqual(self.inspect()['status'], 'LOCAL_STORAGE_BASELINE_OBSERVED_NOT_ADMITTED')

    def test_empty_leftover_sidecar_is_not_deleted_or_reconciled_by_status(self):
        self.initialize()
        sidecar = Path(str(self.database) + '-wal'); sidecar.write_bytes(b''); sidecar.chmod(0o600)
        self.assertEqual(self.inspect()['code'], 'SQLITE_ACTIVE_OR_UNRECONCILED_SIDECARS')
        self.assertTrue(sidecar.exists())

    def test_real_exclusive_flock_yields_read_only_attention(self):
        self.initialize()
        lock = self.paths['records'] / 'operation.lock'
        program = "import fcntl,sys; f=open(sys.argv[1],'rb'); fcntl.flock(f,fcntl.LOCK_EX); print('LOCKED',flush=True); sys.stdin.readline()"
        child = subprocess.Popen([sys.executable, '-I', '-B', '-c', program, str(lock)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            ready, _, _ = select.select([child.stdout], [], [], 10)
            self.assertTrue(ready, 'Owned lock child did not report readiness')
            self.assertEqual(child.stdout.readline().strip(), 'LOCKED')
            self.assertEqual(self.inspect()['code'], 'STORAGE_OPERATION_LOCKED')
            stdout, stderr = child.communicate('\n', timeout=10)
            self.assertEqual(child.returncode, 0, stderr)
        finally:
            if child.poll() is None:
                child.kill(); child.communicate(timeout=10)
            if child.stdin:child.stdin.close()
            if child.stdout:child.stdout.close()
            if child.stderr:child.stderr.close()

    def test_exclusive_storage_keeps_real_lock_and_has_no_admission(self):
        initial = self.initialize()
        before = snapshot(self.root)
        with s.exclusive_storage(self.plan, expected_plan_sha256=self.digest) as observed:
            self.assertEqual(observed['installation_id'], initial['installation_id'])
            self.assertEqual(observed['completion_sha256'], initial['completion_sha256'])
            assert_no_authority(self, observed)
            self.assertEqual(s.inspect_storage(self.plan, expected_plan_sha256=self.digest)['code'],
                             'STORAGE_OPERATION_LOCKED')
            with self.assertRaisesRegex(s.FreshStorageError, 'STORAGE_OPERATION_LOCKED'):
                with s.exclusive_storage(self.plan, expected_plan_sha256=self.digest):
                    self.fail('A second descriptor must not enter the same exclusive lease')
        self.assertEqual(snapshot(self.root), before)
        self.assertEqual(self.inspect()['status'], 'LOCAL_STORAGE_BASELINE_OBSERVED_NOT_ADMITTED')

    def test_exclusive_storage_releases_lock_after_caller_failure(self):
        self.initialize()
        before = snapshot(self.root)
        with self.assertRaisesRegex(RuntimeError, 'SYNTHETIC_CALLER_FAILURE'):
            with s.exclusive_storage(self.plan, expected_plan_sha256=self.digest):
                raise RuntimeError('SYNTHETIC_CALLER_FAILURE')
        self.assertEqual(snapshot(self.root), before)
        self.assertEqual(self.inspect()['status'], 'LOCAL_STORAGE_BASELINE_OBSERVED_NOT_ADMITTED')

    def test_exclusive_storage_permits_separate_backend_journal_not_s0_rewrite(self):
        self.initialize()
        records = snapshot(self.paths['records'])
        with s.exclusive_storage(self.plan, expected_plan_sha256=self.digest):
            attempt = self.paths['operator_state'] / 'synthetic-backend-attempt'
            attempt.mkdir(mode=0o700)
            s._write(attempt / 'intent.json', b'{"synthetic_test_only":true}\n')
            with closing(sqlite3.connect(self.database)) as db, db:
                db.execute('CREATE TABLE synthetic_backend_extension(id INTEGER PRIMARY KEY)')
            # A real F producer separately validates complete schema/counts,
            # finalizes DELETE mode and emits its own receipt. This is not F.
        self.assertEqual(snapshot(self.paths['records']), records)
        self.assertEqual(self.inspect()['status'], 'LOCAL_STORAGE_BASELINE_OBSERVED_NOT_ADMITTED')

    def test_exclusive_storage_detects_s0_record_mutation_and_preserves_it(self):
        self.initialize()
        changed = b'{"synthetic_corruption":true}\n'
        path = self.paths['records'] / 'complete.json'
        with self.assertRaisesRegex(s.FreshStorageError, 'STORAGE_BASELINE_RECORDS_CHANGED'):
            with s.exclusive_storage(self.plan, expected_plan_sha256=self.digest):
                path.write_bytes(changed)
        self.assertEqual(path.read_bytes(), changed)

    def test_exclusive_storage_detects_root_replacement_and_preserves_both(self):
        self.initialize()
        root = self.paths['converter_jobs']
        retained = self.root / 'synthetic-retained-jobs'
        with self.assertRaisesRegex(s.FreshStorageError, 'STORAGE_ROOT_IDENTITY_CHANGED'):
            with s.exclusive_storage(self.plan, expected_plan_sha256=self.digest):
                root.rename(retained)
                root.mkdir(mode=0o700)
        self.assertTrue(root.is_dir() and retained.is_dir())

    def test_exclusive_storage_rejects_stale_initializer_before_yield(self):
        self.initialize()
        before = snapshot(self.root)
        with patch.object(s, '_source_pins', return_value={}):
            with self.assertRaisesRegex(s.FreshStorageError, 'INITIALIZER_SOURCE_CHANGED'):
                with s.exclusive_storage(self.plan, expected_plan_sha256=self.digest):
                    self.fail('A different initializer must not use this S0')
        self.assertEqual(snapshot(self.root), before)

    def test_exclusive_storage_detects_replaced_lock_even_with_identical_bytes(self):
        self.initialize()
        lock = self.paths['records'] / 'operation.lock'
        retained = self.root / 'synthetic-retained-lock'
        with self.assertRaisesRegex(s.FreshStorageError, 'STORAGE_LOCK_CHANGED'):
            with s.exclusive_storage(self.plan, expected_plan_sha256=self.digest):
                lock.rename(retained)
                s._write(lock, b'0')
        self.assertEqual(lock.read_bytes(), retained.read_bytes())


if __name__ == '__main__':
    unittest.main()
