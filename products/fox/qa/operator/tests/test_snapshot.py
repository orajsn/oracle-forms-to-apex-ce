"""Actual POSIX stopped-copy round trips; no OCI, Oracle, service or secret I/O.

Every source is an authored synthetic fixture. Windows runs the pure contract
checks; execute this module with the existing local POSIX Python for filesystem,
SQLite WAL, ownership and no-follow checks. No privacy implementation is mocked.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from qa.operator import snapshot as s

SECRET = b'SYNTHETIC_ONLY_SECRET_NOT_FOR_PUBLIC_RESULTS_6e69a6\n'


def put(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(data)
    path.chmod(0o600)
    return path


def file_hashes(root):
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob('*') if p.is_file()}


class SnapshotContractTests(unittest.TestCase):
    def test_exact_four_role_directory_contract(self):
        self.assertEqual(s.ROLES, frozenset(('fox-data', 'converter-jobs',
                                            'protected-config', 'operator-state')))

    def test_public_error_is_bounded(self):
        with self.assertRaisesRegex(s.SnapshotError, '^ARCHIVE_MEMBER_NAME_INVALID$'):
            s._member_path('operator-state/../../' + SECRET.decode().strip())

    def test_unsafe_archive_names_rejected(self):
        for name in ('/fox-data/a', '../fox-data/a', 'unknown/a', 'operator-state/a/../b',
                     'operator-state//a', 'operator-state/a\\b', 'operator-state/C:a',
                     'operator-state/a\nb'):
            with self.subTest(name=name), self.assertRaises(s.SnapshotError):
                s._member_path(name)

    def test_full_hash_type_and_hidden_members_are_not_filtered(self):
        self.assertEqual(str(s._member_path('converter-jobs/.native-schema/identity.json')),
                         'converter-jobs/.native-schema/identity.json')
        self.assertEqual(str(s._member_path('operator-state/handoffs/.retained')),
                         'operator-state/handoffs/.retained')


@unittest.skipUnless(os.name == 'posix', 'Actual POSIX permissions required; use local WSL unittest runner.')
class SnapshotFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='fox-snapshot-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.roles = {name: self.root / name for name in s.ROLES}
        for path in self.roles.values():
            path.mkdir(mode=0o700)
        self.output = self.root / 'private-output'
        self.output.mkdir(mode=0o700)
        database = self.roles['fox-data'] / 'fox.sqlite3'
        with closing(sqlite3.connect(str(database))) as connection, connection:
            connection.executescript('''
                CREATE TABLE projects(id TEXT PRIMARY KEY,name TEXT NOT NULL);
                CREATE TABLE source_sets(id TEXT PRIMARY KEY,project TEXT NOT NULL REFERENCES projects(id),source_hash TEXT);
                CREATE TABLE project_source_selection(project TEXT PRIMARY KEY REFERENCES projects(id),selected TEXT REFERENCES source_sets(id));
                CREATE TABLE runs(id TEXT PRIMARY KEY,project TEXT REFERENCES projects(id),state TEXT);
                CREATE TABLE technical_verifications(run TEXT PRIMARY KEY REFERENCES runs(id),proof BLOB);
                CREATE TABLE acceptances(run TEXT PRIMARY KEY REFERENCES runs(id),owner TEXT);
                INSERT INTO projects VALUES('synthetic-project','Synthetic project');
                INSERT INTO source_sets VALUES('older','synthetic-project','aaa');
                INSERT INTO source_sets VALUES('selected','synthetic-project','bbb');
                INSERT INTO project_source_selection VALUES('synthetic-project','selected');
                INSERT INTO runs VALUES('synthetic-project-job','synthetic-project','VERIFIED');
                INSERT INTO technical_verifications VALUES('synthetic-project-job',x'00017fff');
            ''')
        database.chmod(0o600)
        self.expected = {
            'fox-data/jobs/synthetic-project-job/source-snapshot.json': b'{"synthetic":true,"source":"original"}\n',
            'fox-data/jobs/synthetic-project-job/project-technical-verification/verification.json': b'project-proof\n',
            'fox-data/.opaf-project-v2-registration/mapper-result.json': b'graph-receipt\n',
            'converter-jobs/.native-schema/identity.json': b'registry-identity\n',
            'converter-jobs/.native-schema/physical-table.ownership.json': b'full-source-mapping-identity\n',
            'converter-jobs/.native-schema/physical-table.intent.json': b'original-create-intent\n',
            'converter-jobs/.native-schema/physical-table.created.json': b'created-object-identity\n',
            'converter-jobs/.native-schema-index.json': b'registry-identity\n',
            'converter-jobs/creator-job/schema-preparation-started.json': b'started-create\n',
            'converter-jobs/creator-job/physical-table.schema-dispatch.json': b'independent-dispatch-anchor\n',
            'converter-jobs/creator-job/schema-preparation.json': b'completed-preparation\n',
            'converter-jobs/creator-job/sqlcl-import-intent.json': b'import-reservation\n',
            'operator-state/clean-install/old-native/plan.json': b'original-native-plan\n',
            'operator-state/project-clean-install/current-project/plan.json': b'project-plan\n',
            'operator-state/product-verifier/release/session-a/claim-intent.json': b'no-replay-intent\n',
            'operator-state/product-verifier/release/session-a/terminal.json': b'complete\n',
            'operator-state/handoffs/retirement/archive/closed-idle.json': b'interrupted-idle-not-clean-exit\n',
            'operator-state/handoffs/retirement/attestation.json': b'retirement-attestation\n',
            'protected-config/references/admin-secret': SECRET,
            'protected-config/references/wallet/cwallet.sso': b'SYNTHETIC-WALLET-BYTES\x00\x01',
            'protected-config/references/sqlcl/.dbtools/connection.json': b'synthetic-saved-connection\n',
            'protected-config/config/runtime.json': b'bound-C\n',
            'protected-config/config/release.json': b'bound-R\n',
            'protected-config/config/admission.json': b'bound-D\n',
        }
        for name, raw in self.expected.items():
            put(self.root / name, raw)

    def backup(self, roles=None):
        destination = self.output / 'backup'
        result = s.backup(self.roles if roles is None else roles, destination)
        return destination, result

    def test_complete_project_and_operator_state_round_trip(self):
        before = {name: file_hashes(path) for name, path in self.roles.items()}
        destination, result = self.backup()
        self.assertEqual(result['status'], 'BACKUP_VERIFIED')
        restored = self.output / 'restore'
        receipt = s.restore_test(destination, restored)
        self.assertEqual(receipt['status'], 'RESTORE_TEST_PASSED')
        self.assertFalse(receipt['live_data_restored'])
        self.assertFalse(receipt['services_started'])
        self.assertFalse(receipt['authentication_or_runtime_tested'])
        self.assertEqual(before, {name: file_hashes(path) for name, path in self.roles.items()})
        for name, raw in self.expected.items():
            self.assertEqual((restored / 'restored' / name).read_bytes(), raw, name)
        with closing(sqlite3.connect(str(restored / 'sqlite-restored.sqlite3'))) as connection:
            self.assertEqual(connection.execute('SELECT selected FROM project_source_selection').fetchall(), [('selected',)])
            self.assertEqual(connection.execute('SELECT count(*) FROM source_sets').fetchone(), (2,))
            self.assertEqual(connection.execute('SELECT state FROM runs').fetchall(), [('VERIFIED',)])
            self.assertEqual(connection.execute('SELECT count(*) FROM acceptances').fetchone(), (0,))

    def test_output_and_restored_secret_are_owner_private(self):
        destination, result = self.backup()
        restored = self.output / 'restore'
        receipt = s.restore_test(destination, restored)
        for root in (destination, restored):
            for path in (root, *root.rglob('*')):
                info = path.lstat()
                self.assertEqual(info.st_uid, os.getuid())
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o700 if path.is_dir() else 0o600)
        self.assertNotIn(SECRET.decode().strip(), json.dumps(result))
        self.assertNotIn(SECRET.decode().strip(), json.dumps(receipt))
        self.assertEqual((restored / 'restored/protected-config/references/admin-secret').read_bytes(), SECRET)

    def test_legacy_three_roles_remain_readable_but_not_hosted_completeness(self):
        legacy = {key: value for key, value in self.roles.items() if key != 'operator-state'}
        destination, result = self.backup(legacy)
        self.assertNotIn('operator-state', result['roles'])
        receipt = s.restore_test(destination, self.output / 'restore')
        self.assertEqual(receipt['roles'], sorted(legacy))

    def test_stopped_wal_capture_preserves_committed_rows_and_raw_inputs(self):
        # Make a quiescent WAL snapshot in a separate fixture DB, then close that
        # writer before the engine runs. The engine never opens original files.
        staging = self.root / 'wal-author'
        staging.mkdir(mode=0o700)
        path = staging / 'fox.sqlite3'
        connection = sqlite3.connect(str(path))
        try:
            self.assertEqual(connection.execute('PRAGMA journal_mode=WAL').fetchone(), ('wal',))
            connection.execute('PRAGMA wal_autocheckpoint=0')
            connection.execute('CREATE TABLE wal_rows(id INTEGER PRIMARY KEY,value TEXT)')
            connection.execute('INSERT INTO wal_rows VALUES(1,?)', ('synthetic committed WAL row',))
            connection.commit()
            for source in staging.iterdir():
                shutil.copyfile(source, self.roles['fox-data'] / source.name)
                (self.roles['fox-data'] / source.name).chmod(0o600)
        finally:
            connection.close()
        before = file_hashes(self.roles['fox-data'])
        self.assertIn('fox.sqlite3-wal', before)
        destination, _ = self.backup()
        receipt = s.restore_test(destination, self.output / 'restore')
        self.assertEqual(receipt['status'], 'RESTORE_TEST_PASSED')
        self.assertEqual(file_hashes(self.roles['fox-data']), before)
        with closing(sqlite3.connect(str(self.output / 'restore/sqlite-restored.sqlite3'))) as restored:
            self.assertEqual(restored.execute('SELECT value FROM wal_rows').fetchall(), [('synthetic committed WAL row',)])

    def test_source_symlink_rejected_without_backup_completion(self):
        (self.roles['operator-state'] / 'linked').symlink_to(self.roles['protected-config'], target_is_directory=True)
        with self.assertRaises(s.SnapshotError):
            self.backup()
        self.assertFalse((self.output / 'backup/completion.json').exists())

    def test_source_hardlink_rejected(self):
        os.link(self.root / 'protected-config/references/admin-secret', self.roles['operator-state'] / 'hardlink')
        with self.assertRaises(s.SnapshotError):
            self.backup()
        self.assertFalse((self.output / 'backup/completion.json').exists())

    def test_file_role_is_rejected(self):
        roles = {**self.roles, 'operator-state': self.root / 'protected-config/references/admin-secret'}
        with self.assertRaisesRegex(s.SnapshotError, '^ROLE_DIRECTORY_REQUIRED$'):
            self.backup(roles)

    def test_unknown_role_rejected_before_write(self):
        with self.assertRaisesRegex(s.SnapshotError, '^ROLES_INVALID$'):
            self.backup({**self.roles, 'whole-home': self.root})
        self.assertFalse((self.output / 'backup').exists())

    def test_overlapping_roles_and_destination_are_rejected(self):
        with self.assertRaisesRegex(s.SnapshotError, '^PATHS_OVERLAP$'):
            self.backup({**self.roles, 'operator-state': self.roles['fox-data'] / 'jobs'})
        with self.assertRaisesRegex(s.SnapshotError, '^PATHS_OVERLAP$'):
            s.backup(self.roles, self.roles['operator-state'] / 'backup')

    def test_missing_sqlite_rejected_before_destination(self):
        (self.roles['fox-data'] / 'fox.sqlite3').unlink()
        with self.assertRaisesRegex(s.SnapshotError, '^FOX_SQLITE_REQUIRED$'):
            self.backup()
        self.assertFalse((self.output / 'backup').exists())

    def test_existing_backup_and_restore_never_overwritten(self):
        destination, _ = self.backup()
        before = file_hashes(destination)
        with self.assertRaises(s.SnapshotError):
            self.backup()
        self.assertEqual(before, file_hashes(destination))
        restored = self.output / 'restore'
        s.restore_test(destination, restored)
        before_restored = file_hashes(restored)
        with self.assertRaises(s.SnapshotError):
            s.restore_test(destination, restored)
        self.assertEqual(before_restored, file_hashes(restored))

    def test_incomplete_backup_cannot_restore(self):
        destination, _ = self.backup()
        (destination / 'completion.json').unlink()
        with self.assertRaises(s.SnapshotError):
            s.restore_test(destination, self.output / 'restore')
        self.assertFalse((self.output / 'restore').exists())

    def test_changed_archive_cannot_restore(self):
        destination, _ = self.backup()
        archive = destination / 'roles.tar'
        raw = archive.read_bytes()
        archive.write_bytes(raw[:-1] + bytes((raw[-1] ^ 1,)))
        with self.assertRaisesRegex(s.SnapshotError, '^BACKUP_ARTIFACTS_CHANGED$'):
            s.restore_test(destination, self.output / 'restore')

    def test_changed_consistent_database_cannot_restore(self):
        destination, _ = self.backup()
        with closing(sqlite3.connect(str(destination / 'sqlite-consistent.sqlite3'))) as connection, connection:
            connection.execute("UPDATE runs SET state='ACCEPTED'")
        with self.assertRaises(s.SnapshotError):
            s.restore_test(destination, self.output / 'restore')

    def test_changed_completion_pin_cannot_restore(self):
        destination, _ = self.backup()
        put(destination / 'completion.json', s._raw({'schema_version': 1,
            'scope': 'fox-stopped-snapshot-complete-v1', 'manifest_sha256': '0' * 64}))
        with self.assertRaisesRegex(s.SnapshotError, '^BACKUP_MANIFEST_CHANGED$'):
            s.restore_test(destination, self.output / 'restore')

    def test_public_output_directory_is_rejected(self):
        self.output.chmod(0o755)
        with self.assertRaisesRegex(s.SnapshotError, '^PRIVATE_OWNER_STORAGE_REQUIRED$'):
            self.backup()
        self.assertFalse((self.output / 'backup').exists())

    def test_long_pax_directory_and_empty_file_round_trip(self):
        name = 'operator-state/handoffs/' + 'a' * 110 + '/zero'
        put(self.root / name, b'')
        destination, _ = self.backup()
        restored = self.output / 'restore'
        s.restore_test(destination, restored)
        self.assertEqual((restored / 'restored' / name).read_bytes(), b'')

    def test_engine_never_opens_original_sqlite(self):
        real_connect = sqlite3.connect
        opened = []
        def capture(path, *args, **kwargs):
            opened.append(str(path))
            return real_connect(path, *args, **kwargs)
        # Only record real SQLite calls; no database/privacy behavior is faked.
        with patch.object(s.sqlite3, 'connect', side_effect=capture):
            destination, _ = self.backup()
            s.restore_test(destination, self.output / 'restore')
        self.assertTrue(opened)
        original = str(self.roles['fox-data'])
        self.assertTrue(all(original not in path for path in opened))
        self.assertTrue(all(str(self.output) in path for path in opened))

    def test_invalid_sqlite_error_does_not_expose_secret(self):
        put(self.roles['fox-data'] / 'fox.sqlite3', SECRET)
        with self.assertRaisesRegex(s.SnapshotError, '^BACKUP_FAILED_PARTIALS_PRESERVED$') as error:
            self.backup()
        self.assertNotIn(SECRET.decode().strip(), str(error.exception))
        self.assertFalse((self.output / 'backup/completion.json').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
