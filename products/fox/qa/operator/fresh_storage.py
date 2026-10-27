"""Once-only local storage initialization, never connected admission.

Import is inert. This POSIX-only helper creates new private directories and a
SQLite base schema; it does not start an application, initialize an Oracle
schema, create converter ownership records, or replace migration history.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
from datetime import datetime, timezone
import hashlib
import importlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import uuid

from fox.storage import IDENTITY_SQL

SCOPE = 'fox-fresh-local-storage-plan-v1'
ROLES = ('fox_data', 'converter_jobs', 'operator_state', 'records')
SOURCE_NAMES = ('qa/operator/fresh_storage.py', 'fox/fox/__init__.py',
                'fox/fox/storage.py', 'fox/fox/source_history.py', 'fox/fox/intake.py')
LEGACY_ROOTS = ('/home/opc/fox', '/home/opc/forms2apex/outputs/jobs',
                '/home/opc/.local/state/fox-product-verifier',
                '/home/opc/.local/share/fox-project-activation',
                '/home/opc/.local/share/fox-project-builds',
                '/home/opc/.config/fox-project-runtime')
SHA = re.compile(r'[a-f0-9]{64}\Z')
RECORDS = {'operation.lock', 'intent.json', 'roots.json', 'schema-started.json',
           'database-initialized.json', 'complete.json', 'failure.json'}


class FreshStorageError(RuntimeError):
    """Bounded diagnostics, without paths, source text or SQL output."""


def need(value, code):
    if not value:
        raise FreshStorageError(code)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                       allow_nan=False) + '\n').encode('utf-8')


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def plan_sha256(plan):
    return _sha(canonical(plan))


def _path(value):
    need(type(value) is str and 1 < len(value) <= 1024 and '\\' not in value
         and not any(ord(c) < 32 or ord(c) == 127 for c in value), 'CANONICAL_POSIX_PATH_REQUIRED')
    p = PurePosixPath(value)
    need(p.is_absolute() and str(p) == value and '..' not in p.parts
         and len(p.parts) >= 4, 'CANONICAL_POSIX_PATH_REQUIRED')
    return p


def _overlap(a, b):
    return a == b or a in b.parents or b in a.parents


def _source_pins():
    root = Path(__file__).resolve().parents[2]
    result = {}
    for name in SOURCE_NAMES:
        p = root / name
        need(p.is_file() and not p.is_symlink() and p.resolve() == p
             and p.stat().st_nlink == 1 and p.stat().st_size <= 2_000_000, 'INITIALIZER_SOURCE_UNSAFE')
        result[name] = _sha(p.read_bytes())
    return result


def declaration(*, fox_data, converter_jobs, operator_state, records, owner_uid):
    """Read sources and check the schema in memory; create no storage."""
    result = {'schema_version': 1, 'scope': SCOPE, 'owner_uid': owner_uid,
        'roots': dict(zip(ROLES, map(str, (fox_data, converter_jobs, operator_state, records)))),
        'source_sha256': _source_pins(), 'initial_schema_sha256': '0' * 64}
    _plan(result, plan_sha256(result))
    result['initial_schema_sha256'] = _sha(canonical(_prerequisite_schema(result)))
    return result


def _plan(plan, expected):
    need(type(plan) is dict and set(plan) == {'schema_version', 'scope', 'owner_uid', 'roots', 'source_sha256', 'initial_schema_sha256'}
         and type(plan['schema_version']) is int and plan['schema_version'] == 1
         and plan['scope'] == SCOPE and type(plan['owner_uid']) is int and plan['owner_uid'] > 0
         and type(expected) is str and SHA.fullmatch(expected) and plan_sha256(plan) == expected,
         'EXACT_STORAGE_PLAN_REQUIRED')
    need(type(plan['roots']) is dict and set(plan['roots']) == set(ROLES), 'EXACT_STORAGE_ROOTS_REQUIRED')
    roots = [_path(plan['roots'][key]) for key in ROLES]
    need(all(not _overlap(a, b) for i, a in enumerate(roots) for b in roots[i + 1:]), 'STORAGE_ROOTS_OVERLAP')
    need(all(not _overlap(p, PurePosixPath(old)) for p in roots for old in LEGACY_ROOTS),
         'EXISTING_MIGRATION_SCOPE_FORBIDDEN')
    pins = plan['source_sha256']
    need(type(pins) is dict and set(pins) == set(SOURCE_NAMES)
         and all(type(v) is str and SHA.fullmatch(v) for v in pins.values()), 'INITIALIZER_SOURCE_BINDING_REQUIRED')
    need(type(plan['initial_schema_sha256']) is str and SHA.fullmatch(plan['initial_schema_sha256']),
         'INITIAL_SCHEMA_BINDING_REQUIRED')
    return json.loads(canonical(plan))


def _runtime(plan):
    need(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW') and hasattr(os, 'O_DIRECTORY')
         and os.geteuid() == plan['owner_uid'] > 0, 'POSIX_OWNER_RUNTIME_REQUIRED')


def _private_dir(path):
    need(path.is_absolute() and path.resolve() == path, 'STORAGE_LINK_FORBIDDEN')
    for part in (path, *path.parents):
        info = part.lstat()
        sticky = part != path and stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        need(not stat.S_ISLNK(info.st_mode) and info.st_uid in (0, os.geteuid())
             and (not stat.S_IMODE(info.st_mode) & 0o022 or sticky), 'STORAGE_ANCESTOR_UNSAFE')
    info = path.stat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
         and stat.S_IMODE(info.st_mode) == 0o700, 'OWNER_PRIVATE_DIRECTORY_REQUIRED')


def _new_root(path):
    _private_dir(path.parent)
    need(not os.path.lexists(path), 'EXISTING_STORAGE_NOT_ADOPTED')
    source_root = Path(__file__).resolve().parents[2]
    need(not _overlap(path, source_root), 'STORAGE_OVERLAPS_BOOTSTRAP_SOURCE')
    for ancestor in path.parents:
        need(not any(os.path.lexists(ancestor / name) for name in
            ('fox.sqlite3', '.native-schema-index.json', '.native-schema')), 'EXISTING_STORE_ANCESTOR_FORBIDDEN')


def _sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _mkdir(path):
    _new_root(path)
    path.mkdir(mode=0o700)
    _sync(path.parent)
    _private_dir(path)


def _write(path, raw):
    _private_dir(path.parent)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    _sync(path.parent)


def _read(path, maximum=2_000_000):
    _private_dir(path.parent)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid()
         and stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= maximum, 'PRIVATE_RECORD_REQUIRED')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        opened = os.fstat(stream.fileno()); raw = stream.read(maximum + 1); after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    final = path.lstat()
    need(all(getattr(before, k) == getattr(opened, k) == getattr(after, k) == getattr(final, k) for k in fields)
         and len(raw) == before.st_size, 'RECORD_CHANGED_DURING_READ')
    return raw


def _json(path):
    raw = _read(path)
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'DUPLICATE_RECORD_KEY'); result[key] = value
        return result
    result = json.loads(raw, object_pairs_hook=pairs)
    need(type(result) is dict and canonical(result) == raw, 'CANONICAL_RECORD_REQUIRED')
    return result


@contextmanager
def _lock(records, exclusive):
    import fcntl
    path = records / 'operation.lock'
    need(_read(path, 1) == b'0', 'STORAGE_LOCK_CHANGED')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        before = path.stat(); actual = os.fstat(stream.fileno())
        need((before.st_dev, before.st_ino) == (actual.st_dev, actual.st_ino), 'STORAGE_LOCK_CHANGED')
        try:
            fcntl.flock(stream.fileno(), (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError:
            raise FreshStorageError('STORAGE_OPERATION_LOCKED') from None
        try:
            yield
        finally:
            try:
                final = path.lstat()
                need(stat.S_ISREG(final.st_mode) and final.st_nlink == 1
                     and (final.st_dev, final.st_ino) == (actual.st_dev, actual.st_ino),
                     'STORAGE_LOCK_CHANGED')
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _root_identity(path):
    _private_dir(path)
    s = path.stat()
    return {'device': s.st_dev, 'inode': s.st_ino, 'uid': s.st_uid, 'gid': s.st_gid, 'mode': stat.S_IMODE(s.st_mode)}


def _schema(connection):
    rows = connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name LIMIT 257").fetchall()
    need(len(rows) <= 256 and all(type(kind) is str and type(name) is str and type(table) is str
         and (sql is None or type(sql) is str) and len(name) <= 128 and len(table) <= 128
         and (sql is None or len(sql) <= 65536) for kind, name, table, sql in rows), 'SCHEMA_OBSERVATION_BOUND')
    result = {name: [kind, table, sql] for kind, name, table, sql in rows}
    need(len(result) == len(rows) and len(canonical(result)) <= 2_000_000, 'SCHEMA_OBSERVATION_BOUND')
    return result


def _initializer(plan):
    need(_source_pins() == plan['source_sha256'], 'INITIALIZER_SOURCE_CHANGED')
    module = importlib.import_module('fox.storage')
    expected = Path(__file__).resolve().parents[2] / 'fox/fox/storage.py'
    need(Path(module.__file__).resolve() == expected and callable(module.initialize_schema), 'EXPECTED_INITIALIZER_REQUIRED')
    return module.initialize_schema


def _expected_schema(initializer):
    import sqlite3
    with closing(sqlite3.connect(':memory:')) as connection, connection:
        connection.execute('PRAGMA foreign_keys=ON')
        initializer(connection)
        connection.execute(IDENTITY_SQL)
        schema = _schema(connection)
    return schema


def _prerequisite_schema(plan):
    try:
        return _expected_schema(_initializer(plan))
    except FreshStorageError:
        raise
    except Exception:
        raise FreshStorageError('INITIALIZER_PREREQUISITE_FAILED') from None


def _empty(connection):
    tables = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    counts = {}
    for name in tables:
        need(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', name), 'UNEXPECTED_SCHEMA_IDENTIFIER')
        counts[name] = connection.execute('SELECT COUNT(*) FROM "' + name + '"').fetchone()[0]
    need(all(count == (1 if name in ('events', 'fox_storage_identity') else 0) for name, count in counts.items()),
         'FRESH_BUSINESS_STATE_NOT_EMPTY')
    event = connection.execute('SELECT owner,action,object_id,created FROM events').fetchall()
    need(len(event) == 1 and tuple(event[0][:3]) == ('system-source-history', 'source_history_initialized', 'schema-v1')
         and type(event[0][3]) in (float, int) and event[0][3] >= 0, 'INITIALIZATION_EVENT_CHANGED')
    return counts


def _result(status, **values):
    return {'status': status, 'connected_admission': False, 'services_started': False,
            'oracle_accessed': False, 'automatic_replay_permitted': False, **values}


def initialize_storage(plan, *, expected_plan_sha256, apply=False):
    """Create a new local store once. Failure preserves all partial evidence."""
    need(apply is True, 'EXPLICIT_STORAGE_APPLY_REQUIRED')
    plan = _plan(plan, expected_plan_sha256); _runtime(plan)
    roots = {key: Path(value) for key, value in plan['roots'].items()}
    for path in roots.values():
        _new_root(path)
    expected_schema = _prerequisite_schema(plan)  # Memory-only prerequisite before filesystem writes.
    need(_sha(canonical(expected_schema)) == plan['initial_schema_sha256'], 'INITIAL_SCHEMA_BINDING_CHANGED')
    initializer = _initializer(plan)
    records = roots['records']; _mkdir(records); _write(records / 'operation.lock', b'0')
    phase = 'ALLOCATE_ROOTS'
    installation_id = 'fst-' + uuid.uuid4().hex
    try:
        with _lock(records, True):
            intent = {'scope': 'fox-fresh-storage-intent-v1', 'installation_id': installation_id,
                'plan': plan, 'plan_sha256': expected_plan_sha256,
                'created_at_utc': datetime.now(timezone.utc).isoformat()}
            _write(records / 'intent.json', canonical(intent))
            for role in ROLES[:-1]:
                _mkdir(roots[role])
            identities = {role: _root_identity(path) for role, path in roots.items()}
            root_record = {'scope': 'fox-fresh-storage-roots-v1', 'installation_id': installation_id,
                           'plan_sha256': expected_plan_sha256, 'identities': identities}
            _write(records / 'roots.json', canonical(root_record))
            phase = 'INITIALIZE_SQLITE'
            _write(records / 'schema-started.json', canonical({'scope': 'fox-fresh-storage-schema-intent-v1',
                'installation_id': installation_id, 'plan_sha256': expected_plan_sha256}))
            database = roots['fox_data'] / 'fox.sqlite3'
            _write(database, b'')  # Exclusive file creation; SQLite receives only this owned new file.
            import sqlite3
            connection = sqlite3.connect(str(database), timeout=5)
            try:
                with connection:
                    connection.execute('PRAGMA foreign_keys=ON')
                    initializer(connection)
                    connection.execute(IDENTITY_SQL)
                    connection.execute('INSERT INTO fox_storage_identity VALUES(1,?,?)',
                                       (installation_id, expected_plan_sha256))
                    need(_schema(connection) == expected_schema, 'FRESH_SCHEMA_DIFFERS')
                    counts = _empty(connection)
                need(connection.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()[0] == 0,
                     'SQLITE_CHECKPOINT_UNCONFIRMED')
            finally:
                connection.close()
            need(not any(os.path.lexists(str(database) + suffix) for suffix in ('-wal', '-shm', '-journal')),
                 'SQLITE_SIDECARS_REMAIN')
            need({role: _root_identity(path) for role, path in roots.items()} == identities, 'STORAGE_ROOT_IDENTITY_CHANGED')
            need(_source_pins() == plan['source_sha256'], 'INITIALIZER_SOURCE_CHANGED')
            initialized = {'scope': 'fox-fresh-storage-schema-observation-v1', 'installation_id': installation_id,
                'plan_sha256': expected_plan_sha256, 'schema': expected_schema, 'initial_counts': counts,
                'sqlite_version': sqlite3.sqlite_version}
            _write(records / 'database-initialized.json', canonical(initialized))
            phase = 'PUBLISH_COMPLETION'
            completed = {'scope': 'fox-fresh-storage-completion-v1', 'installation_id': installation_id,
                'plan_sha256': expected_plan_sha256, 'intent_sha256': _sha(canonical(intent)),
                'roots_sha256': _sha(canonical(root_record)), 'schema_observation_sha256': _sha(canonical(initialized)),
                'completed_at_utc': datetime.now(timezone.utc).isoformat()}
            _write(records / 'complete.json', canonical(completed))
            return _result('LOCAL_STORAGE_INITIALIZED_NOT_ADMITTED', installation_id=installation_id,
                plan_sha256=expected_plan_sha256, completion_sha256=_sha(canonical(completed)))
    except Exception as error:
        code = str(error) if type(error) is FreshStorageError else 'INITIALIZATION_OUTCOME_UNCONFIRMED'
        try:
            _write(records / 'failure.json', canonical({'scope': 'fox-fresh-storage-failure-v1',
                'phase': phase, 'code': code, 'installation_id': installation_id,
                'plan_sha256': expected_plan_sha256, 'automatic_replay_permitted': False}))
        except Exception:
            pass
        raise FreshStorageError(code) from None


def _database_observation(database, expected_id, plan_hash, schema):
    """Read a stable checkpointed file only; never let SQLite create sidecars."""
    import sqlite3
    need(not any(os.path.lexists(str(database) + suffix) for suffix in ('-wal', '-shm', '-journal')),
         'SQLITE_ACTIVE_OR_UNRECONCILED_SIDECARS')
    _private_dir(database.parent)
    before = database.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid()
         and stat.S_IMODE(before.st_mode) == 0o600 and before.st_size > 0, 'PRIVATE_SQLITE_FILE_REQUIRED')
    connection = sqlite3.connect(database.as_uri() + '?mode=ro&immutable=1', uri=True, timeout=1)
    try:
        connection.execute('PRAGMA query_only=ON'); connection.execute('PRAGMA trusted_schema=OFF')
        connection.set_progress_handler(lambda: 1, 100000)
        current = _schema(connection)
        need(all(current.get(name) == value for name, value in schema.items()), 'INITIALIZED_SCHEMA_CHANGED')
        row = connection.execute('SELECT singleton,installation_id,plan_sha256 FROM fox_storage_identity').fetchall()
        need(row == [(1, expected_id, plan_hash)], 'STORAGE_IDENTITY_CHANGED')
    finally:
        connection.close()
    after = database.lstat()
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')
    need(all(getattr(before, key) == getattr(after, key) for key in fields)
         and not any(os.path.lexists(str(database) + suffix) for suffix in ('-wal', '-shm', '-journal')),
         'SQLITE_CHANGED_DURING_INSPECTION')


def _retained_records(records):
    _private_dir(records)
    paths = []
    for path in records.iterdir():
        need(len(paths) < len(RECORDS) and path.name in RECORDS, 'RECORD_INVENTORY_CHANGED')
        paths.append(path)
    return {path.name: _read(path, 1 if path.name == 'operation.lock' else 2_000_000)
            for path in paths}


def _inspect_locked(plan, expected_plan_sha256, roots):
    """Existing S0 observation, called only while the real operation lock is held."""
    records = roots['records']
    retained = _retained_records(records)
    intent = _json(records / 'intent.json')
    need(set(intent) == {'scope','installation_id','plan','plan_sha256','created_at_utc'}
         and intent.get('scope') == 'fox-fresh-storage-intent-v1' and intent.get('plan') == plan
         and intent.get('plan_sha256') == expected_plan_sha256
         and type(intent.get('installation_id')) is str
         and re.fullmatch('fst-[a-f0-9]{32}', intent['installation_id']), 'ATTEMPT_BINDING_CHANGED')
    identity = intent['installation_id']
    need(all(os.path.lexists(path) for path in roots.values()), 'PARTIAL_ROOT_ALLOCATION')
    root_record = _json(records / 'roots.json')
    need(root_record == {'scope': 'fox-fresh-storage-roots-v1', 'installation_id': identity,
        'plan_sha256': expected_plan_sha256, 'identities': {role: _root_identity(path) for role, path in roots.items()}},
        'STORAGE_ROOT_IDENTITY_CHANGED')
    schema_intent = _json(records / 'schema-started.json')
    need(schema_intent == {'scope': 'fox-fresh-storage-schema-intent-v1', 'installation_id': identity,
         'plan_sha256': expected_plan_sha256}, 'SCHEMA_INTENT_CHANGED')
    need((records / 'database-initialized.json').is_file(), 'PARTIAL_SCHEMA_INITIALIZATION')
    initialized = _json(records / 'database-initialized.json')
    need(set(initialized) == {'scope','installation_id','plan_sha256','schema','initial_counts','sqlite_version'}
         and initialized.get('scope') == 'fox-fresh-storage-schema-observation-v1'
         and initialized.get('installation_id') == identity and initialized.get('plan_sha256') == expected_plan_sha256
         and type(initialized.get('schema')) is dict and 'fox_storage_identity' in initialized['schema']
         and _sha(canonical(initialized['schema'])) == plan['initial_schema_sha256'],
         'SCHEMA_OBSERVATION_CHANGED')
    tables = {name for name, item in initialized['schema'].items() if item[0] == 'table'}
    counts = initialized['initial_counts']
    need(type(counts) is dict and set(counts) == tables and {'events','fox_storage_identity'} <= tables
         and all(type(count) is int and count == (1 if name in ('events','fox_storage_identity') else 0)
                 for name, count in counts.items()), 'INITIAL_EMPTY_COUNTS_CHANGED')
    _database_observation(roots['fox_data'] / 'fox.sqlite3', identity, expected_plan_sha256, initialized['schema'])
    need((records / 'complete.json').is_file(), 'INITIALIZATION_OBSERVED_WITHOUT_COMPLETION')
    complete = _json(records / 'complete.json')
    need(set(complete) == {'scope','installation_id','plan_sha256','intent_sha256','roots_sha256',
         'schema_observation_sha256','completed_at_utc'}
         and complete['scope'] == 'fox-fresh-storage-completion-v1' and complete['installation_id'] == identity
         and complete['plan_sha256'] == expected_plan_sha256 and complete['intent_sha256'] == _sha(canonical(intent))
         and complete['roots_sha256'] == _sha(canonical(root_record))
         and complete['schema_observation_sha256'] == _sha(canonical(initialized)), 'COMPLETION_BINDING_CHANGED')
    need('failure.json' not in retained, 'FAILED_ATTEMPT_REQUIRES_REVIEW')
    need({role: _root_identity(path) for role, path in roots.items()} == root_record['identities'],
         'STORAGE_ROOT_IDENTITY_CHANGED_DURING_INSPECTION')
    need(_retained_records(records) == retained, 'RECORDS_CHANGED_DURING_INSPECTION')
    return _result('LOCAL_STORAGE_BASELINE_OBSERVED_NOT_ADMITTED', read_only=True,
        installation_id=identity, completion_sha256=_sha(canonical(complete)), mutable_database_bytes_hashed=False)


@contextmanager
def exclusive_storage(plan, *, expected_plan_sha256):
    """Hold the genuine S0 lock for a separate once-only backend initializer.

    This does not prove empty business state or grant connected admission. The
    caller must validate the actual base schema/counts before its own writes,
    journal those writes separately and finalize its own backend observation.
    Original S0 records and root identities must remain unchanged throughout.
    """
    plan = _plan(plan, expected_plan_sha256); _runtime(plan)
    need(_source_pins() == plan['source_sha256'], 'INITIALIZER_SOURCE_CHANGED')
    roots = {key: Path(value) for key, value in plan['roots'].items()}
    records = roots['records']
    _private_dir(records)
    with _lock(records, True):
        observation = _inspect_locked(plan, expected_plan_sha256, roots)
        retained = _retained_records(records)
        identities = {role: _root_identity(path) for role, path in roots.items()}
        try:
            yield observation
        finally:
            need(_retained_records(records) == retained, 'STORAGE_BASELINE_RECORDS_CHANGED')
            need({role: _root_identity(path) for role, path in roots.items()} == identities,
                 'STORAGE_ROOT_IDENTITY_CHANGED')
            need(_source_pins() == plan['source_sha256'], 'INITIALIZER_SOURCE_CHANGED')


def inspect_storage(plan, *, expected_plan_sha256):
    """Read-only classification, not initialization, replay or admission."""
    plan = _plan(plan, expected_plan_sha256); _runtime(plan)
    roots = {key: Path(value) for key, value in plan['roots'].items()}
    present = {key: os.path.lexists(path) for key, path in roots.items()}
    if not any(present.values()):
        return _result('NOT_STARTED', read_only=True)
    if not present['records']:
        return _result('ATTENTION', code='PREEXISTING_STORAGE_WITHOUT_ATTEMPT', read_only=True)
    try:
        records = roots['records']; _private_dir(records)
        need((records / 'operation.lock').is_file(), 'PARTIAL_ATTEMPT_WITHOUT_LOCK')
        with _lock(records, False):
            return _inspect_locked(plan, expected_plan_sha256, roots)
    except Exception as error:
        return _result('ATTENTION', read_only=True,
            code=str(error) if type(error) is FreshStorageError else 'STORAGE_EVIDENCE_UNCONFIRMED')
