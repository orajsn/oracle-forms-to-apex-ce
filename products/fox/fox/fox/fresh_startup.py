"""Local FOX startup fence, not an installer or a live-admission producer.

The read-only public mount and independently pinned P/F/C3/R4 digests are the
host trust boundary. This module cannot attest containers, S0 allocation or an
exclusion lease. The protected installer must establish those before publishing
A. No operator source/configuration, credentials or private records are loaded.
"""
from __future__ import annotations

from contextlib import closing
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat

from .installation import parse_projection


PUBLIC_FILENAMES = frozenset(('projection.json', 'backend-initialization.json', 'live-admission.json'))
ENVIRONMENT = {
    'mode': 'FOX_INSTALLATION_MODE',
    'public_directory': 'FOX_FRESH_PUBLIC_CONFIG_DIR',
    'projection_sha256': 'FOX_FRESH_PROJECTION_SHA256',
    'provider_sha256': 'FOX_FRESH_PROVIDER_SHA256',
    'release_sha256': 'FOX_VERIFIER_RELEASE_SHA256',
    'backend_sha256': 'FOX_FRESH_BACKEND_SHA256',
}
INITIAL_COUNTS = {name: (1 if name in ('events', 'fox_storage_identity') else 0) for name in (
    'projects', 'sources', 'sessions', 'attempts', 'runs', 'events', 'acceptances',
    'prepared_uploads', 'source_sets', 'source_set_members', 'project_source_selection',
    'fox_storage_identity', 'verification_queue', 'verification_operator_contact',
    'verification_failed_dispositions', 'verification_retry_attempts',
    'verification_retry_events', 'verification_producer_observations')}
BACKEND_FIELDS = frozenset(('schema_version', 'scope', 'installation_id', 'storage_plan_sha256',
    'storage_completion_sha256', 'app_projection_sha256', 'provider_configuration_sha256',
    'release_sha256', 'intent_sha256', 'backend_schema_sha256', 'initial_counts', 'completed_at_utc'))
ADMISSION_FIELDS = frozenset(('schema_version', 'scope', 'installation_id', 'storage_completion_sha256',
    'app_projection_sha256', 'provider_configuration_sha256', 'release_sha256',
    'backend_initialization_sha256', 'admission_sha256', 'installation_sha256',
    'live_observation_sha256', 'observed_at_utc', 'transition', 'automatic_replay_permitted'))
_SHA = re.compile(r'[a-f0-9]{64}\Z')


class FreshStartupError(RuntimeError):
    """Closed diagnostic codes only, never supplied paths/SQL/credentials."""


def _need(condition, code):
    if not condition:
        raise FreshStartupError(code)


def _hash(value):
    return type(value) is str and _SHA.fullmatch(value) is not None


def _canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                       allow_nan=False) + '\n').encode('utf-8')


def _utc(value):
    _need(type(value) is str and re.fullmatch(
        r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|\+00:00)', value),
        'FRESH_TIMESTAMP_INVALID')
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise FreshStartupError('FRESH_TIMESTAMP_INVALID') from None


def _parse(raw, fields):
    def pairs(items):
        value = {}
        for key, item in items:
            _need(key not in value, 'FRESH_DOCUMENT_DUPLICATE_KEY')
            value[key] = item
        return value
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        _need(type(value) is dict and set(value) == fields, 'FRESH_DOCUMENT_FIELDS_INVALID')
        _need(_canonical(value) == raw, 'FRESH_DOCUMENT_NOT_CANONICAL')
        return value
    except FreshStartupError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise FreshStartupError('FRESH_DOCUMENT_INVALID') from None


def _path(path, *, directory=False):
    """Reject links/junctions (including ancestors), absent paths and devices."""
    path = Path(path).absolute()
    try:
        _need(path.resolve(strict=True) == path, 'FRESH_PATH_UNSAFE')
        for item in (path, *path.parents):
            info = item.lstat()
            _need(not stat.S_ISLNK(info.st_mode)
                  and not (getattr(info, 'st_file_attributes', 0) & 0x400), 'FRESH_PATH_UNSAFE')
        info = path.stat()
        _need(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), 'FRESH_PATH_UNSAFE')
        if not directory:
            _need(info.st_nlink == 1, 'FRESH_PATH_UNSAFE')
        return path, (info.st_dev, info.st_ino)
    except (OSError, RuntimeError):
        raise FreshStartupError('FRESH_PATH_UNAVAILABLE') from None


def _read(path):
    path, identity = _path(path)
    try:
        with path.open('rb') as stream:
            opened = os.fstat(stream.fileno())
            _need((opened.st_dev, opened.st_ino) == identity and 0 < opened.st_size <= 16384,
                  'FRESH_DOCUMENT_UNAVAILABLE')
            raw = stream.read(16385)
        _need(0 < len(raw) <= 16384 and _path(path)[1] == identity, 'FRESH_DOCUMENT_CHANGED')
        return raw
    except OSError:
        raise FreshStartupError('FRESH_DOCUMENT_UNAVAILABLE') from None


def reject_fresh_legacy(database):
    """Do not mistake read failures for the absence of a fresh identity marker."""
    if not os.path.lexists(database):
        return
    path, _ = _path(database)
    try:
        with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=2)) as db:
            db.execute('PRAGMA query_only=ON')
            _need(db.execute("SELECT 1 FROM sqlite_master WHERE name='fox_storage_identity'").fetchone()
                  is None, 'FRESH_STORE_REQUIRES_EXPLICIT_MODE')
    except sqlite3.Error:
        raise FreshStartupError('LEGACY_DATABASE_IDENTITY_UNREADABLE') from None


def configured_fence(data_dir, environ=None):
    """Missing mode is legacy; unknown/blank/whitespace modes never downgrade."""
    values = os.environ if environ is None else environ
    mode = values.get(ENVIRONMENT['mode'])
    _need(mode in (None, 'legacy', 'fresh'), 'FOX_INSTALLATION_MODE_INVALID')
    if mode != 'fresh':
        _need(not any(name.startswith('FOX_FRESH_') for name in values), 'FRESH_MODE_REQUIRED')
        reject_fresh_legacy(Path(data_dir).resolve() / 'fox.sqlite3')
        return None
    return FreshStartupFence(data_dir, values)


class FreshStartupFence:
    def __init__(self, data_dir, values):
        self.root, self._root_identity = _path(data_dir, directory=True)
        self.database, self._database_identity = _path(self.root / 'fox.sqlite3')
        public = values.get(ENVIRONMENT['public_directory'])
        _need(type(public) is str and public and Path(public).is_absolute(), 'FRESH_PUBLIC_DIRECTORY_REQUIRED')
        self.public, self._public_identity = _path(public, directory=True)
        _need(self.root != self.public and self.root not in self.public.parents
              and self.public not in self.root.parents, 'FRESH_PUBLIC_DIRECTORY_OVERLAP')
        self.hashes = {key: values.get(ENVIRONMENT[key]) for key in
                       ('projection_sha256', 'provider_sha256', 'release_sha256', 'backend_sha256')}
        _need(all(_hash(value) for value in self.hashes.values()), 'FRESH_PIN_REQUIRED')
        self._admission_digest = None
        self.projection = None
        self.refresh()

    def _documents(self):
        _need(_path(self.root, directory=True)[1] == self._root_identity
              and _path(self.database)[1] == self._database_identity
              and _path(self.public, directory=True)[1] == self._public_identity, 'FRESH_STORAGE_IDENTITY_CHANGED')
        try:
            # The projection mount contains public records only; never browse
            # or mount private operator configuration as a convenience.
            names = set()
            with os.scandir(self.public) as entries:
                for entry in entries:
                    names.add(entry.name)
                    _need(len(names) <= 3, 'FRESH_PUBLIC_DIRECTORY_CONTENTS_INVALID')
        except OSError:
            raise FreshStartupError('FRESH_PUBLIC_DIRECTORY_UNAVAILABLE') from None
        _need(names <= PUBLIC_FILENAMES and {'projection.json', 'backend-initialization.json'} <= names,
              'FRESH_PUBLIC_DIRECTORY_CONTENTS_INVALID')
        try:
            projection = parse_projection(_read(self.public / 'projection.json'),
                                           expected_sha256=self.hashes['projection_sha256'])
        except ValueError:
            raise FreshStartupError('FRESH_PROJECTION_INVALID') from None
        raw = _read(self.public / 'backend-initialization.json')
        _need(hashlib.sha256(raw).hexdigest() == self.hashes['backend_sha256'], 'FRESH_BACKEND_HASH_CHANGED')
        backend = _parse(raw, BACKEND_FIELDS)
        expected = {'installation_id': projection['installation_id'],
            'storage_plan_sha256': projection['storage_plan_sha256'],
            'storage_completion_sha256': projection['storage_completion_sha256'],
            'app_projection_sha256': self.hashes['projection_sha256'],
            'provider_configuration_sha256': self.hashes['provider_sha256'], 'release_sha256': self.hashes['release_sha256']}
        _need(type(backend['schema_version']) is int and backend['schema_version'] == 1
              and backend['scope'] == 'fox-fresh-backend-initialization-v1'
              and all(backend[key] == item for key, item in expected.items())
              and _hash(backend['intent_sha256']) and _hash(backend['backend_schema_sha256'])
              and _canonical(backend['initial_counts']) == _canonical(INITIAL_COUNTS), 'FRESH_BACKEND_BINDING_CHANGED')
        completed = _utc(backend['completed_at_utc'])
        admitted = 'live-admission.json' in names
        if admitted:
            raw = _read(self.public / 'live-admission.json')
            admission = _parse(raw, ADMISSION_FIELDS)
            expected.pop('storage_plan_sha256')
            expected['backend_initialization_sha256'] = self.hashes['backend_sha256']
            _need(type(admission['schema_version']) is int and admission['schema_version'] == 1
                  and admission['scope'] == 'fox-fresh-live-admission-v1'
                  and all(admission[key] == item for key, item in expected.items())
                  and all(_hash(admission[key]) for key in ('admission_sha256', 'installation_sha256', 'live_observation_sha256'))
                  and admission['transition'] == 'INITIAL_TO_NORMAL'
                  and admission['automatic_replay_permitted'] is False
                  and _utc(admission['observed_at_utc']) >= completed, 'FRESH_ADMISSION_BINDING_CHANGED')
            digest = hashlib.sha256(raw).hexdigest()
            _need(self._admission_digest in (None, digest), 'FRESH_ADMISSION_CHANGED')
        else:
            _need(self._admission_digest is None, 'FRESH_ADMISSION_REMOVED')
            digest = None
        return projection, backend, admitted, digest

    def refresh(self):
        """Coherent query-only WAL observation; no immutable=1/checkpoint/DDL."""
        from .backend_storage import validate_backend_storage, BackendStorageError
        projection, backend, admitted, digest = self._documents()
        self._sqlite_files(admitted=admitted)
        try:
            with closing(sqlite3.connect(self.database.as_uri() + '?mode=ro', uri=True, timeout=2)) as db:
                db.row_factory = sqlite3.Row
                db.execute('PRAGMA query_only=ON')
                # Bound SQL work as well as file sizes. A busy or huge store
                # requires attention rather than an unbounded health request.
                remaining = [2000]
                def progress():
                    remaining[0] -= 1
                    return remaining[0] < 0
                db.set_progress_handler(progress, 1000)
                db.execute('BEGIN')
                observation = validate_backend_storage(db, installation_id=projection['installation_id'],
                    plan_sha256=projection['storage_plan_sha256'], require_empty=not admitted)
                _need(observation['backend_schema_sha256'] == backend['backend_schema_sha256'], 'FRESH_BACKEND_SCHEMA_CHANGED')
                if admitted:
                    self._normal_records(db)
                db.rollback()
        except (sqlite3.Error, BackendStorageError):
            raise FreshStartupError('FRESH_BACKEND_STATE_UNAVAILABLE') from None
        _need(_path(self.database)[1] == self._database_identity, 'FRESH_STORAGE_IDENTITY_CHANGED')
        # Normal WAL writers may legitimately close/checkpoint and rotate
        # sidecars. SQLite's read transaction owns snapshot consistency; check
        # path safety again, not perpetual WAL inode identity.
        self._sqlite_files(admitted=admitted)
        self.projection, self._admission_digest = projection, digest
        return admitted

    def _sqlite_files(self, *, admitted):
        try:
            with self.database.open('rb') as stream:
                opened = os.fstat(stream.fileno())
                _need((opened.st_dev, opened.st_ino) == self._database_identity, 'FRESH_STORAGE_IDENTITY_CHANGED')
                header = stream.read(100)
            _need(len(header) == 100 and header[:16] == b'SQLite format 3\x00', 'FRESH_SQLITE_HEADER_INVALID')
            sidecars = {}
            for suffix in ('-wal', '-shm', '-journal'):
                path = Path(str(self.database) + suffix)
                if os.path.lexists(path):
                    sidecars[suffix] = _path(path)[1]
            if not admitted:
                # SQLite mode=ro/query_only still writes WAL coordination
                # files. F must leave DELETE mode under its real exclusion
                # lease, with no sidecars, before the fenced app starts. Never
                # use immutable=1 to hide live committed WAL transactions.
                _need(header[18:20] == b'\x01\x01' and not sidecars,
                      'FRESH_PRE_ADMISSION_ROLLBACK_JOURNAL_REQUIRED')
            return sidecars
        except OSError:
            raise FreshStartupError('FRESH_SQLITE_FILES_UNAVAILABLE') from None

    def _normal_records(self, db):
        from .verification_queue import VerificationQueue, QueueError
        from .verification_recovery import VerificationRecovery, RecoveryError
        try:
            _need(db.execute('PRAGMA foreign_key_check').fetchone() is None, 'FRESH_NORMAL_RELATION_CHANGED')
            remaining_bytes = 16_000_000
            def bounded_rows(table):
                nonlocal remaining_bytes
                # Table names below are fixed module-owned constants; schema
                # validation has already checked every column definition.
                columns = [row[1] for row in db.execute('PRAGMA table_info(' + table + ')')]
                size = '+'.join('coalesce(length("' + name + '"),0)' for name in columns)
                count, total = db.execute('SELECT count(*),coalesce(sum(' + size + '),0) FROM ' + table).fetchone()
                _need(count <= 4096 and 0 <= total <= remaining_bytes, 'FRESH_NORMAL_STATE_BOUND')
                remaining_bytes -= total
                return db.execute('SELECT * FROM ' + table + ' LIMIT 4097').fetchall()
            # Bound the entire ledger before _attempt() performs its own
            # retained-event fetch; checking events afterwards would be late.
            records = {table: bounded_rows(table) for table in
                       ('verification_queue', *VerificationRecovery._TABLES)}
            for row in records['verification_queue']:
                VerificationQueue._record(row)
            # Preserve all append-only records and check journal transitions.
            # Protected recovery/claim paths still validate retained technical
            # proofs and current live producer authority before execution.
            recovery = VerificationRecovery(self.database, enabled=True)
            for table in VerificationRecovery._TABLES:
                for row in records[table]:
                    VerificationRecovery._checked_record(table, row)
                    if table == 'verification_retry_attempts':
                        recovery._attempt(db, row['attempt_id'])
        except (QueueError, RecoveryError):
            raise FreshStartupError('FRESH_NORMAL_STATE_INVALID') from None

    def identity(self):
        return {'installation_mode': 'fresh', 'installation_id': self.projection['installation_id'],
                'state': 'NORMAL' if self._admission_digest else 'FENCED',
                'automatic_replay_permitted': False}
