"""One-shot local F production on genuine, still-empty S0 storage.

Import is inert. This module does not select a hosted provider, read credentials,
inspect/start containers, contact Oracle, admit work or replay an interrupted
attempt. Call only from an isolated, bytecode-disabled protected source bundle.
All original S0 records remain unchanged; a separate private attempt preserves
intent, observation and failures. Even an apparently completed attempt cannot
be rerun. A returned F is local initialization evidence, never runtime authority.
"""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path, PurePosixPath
import sqlite3
import stat
import sys

from fox import backend_storage, verification_queue, verification_recovery, verification_runtime
from . import fresh_contracts as contracts
from . import fresh_storage as storage


ATTEMPT_NAME = 'fresh-backend'
MAX_SOURCE_BYTES = 64_000_000
MAX_SOURCE_TOTAL = 512_000_000
_SIDECARS = ('-wal', '-shm', '-journal')
_META = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
         'st_size', 'st_mtime_ns', 'st_ctime_ns')
_FILE_ID = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink')
_LOCAL_PREFIXES = ('fox', 'forms2apex', 'fox_source_contract', 'qa', 'defusedxml')


class FreshBackendError(RuntimeError):
    """Closed diagnostics only; never paths, credential text or SQL errors."""


def _need(value, code):
    if not value:
        raise FreshBackendError(code)


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _identity(info, fields=_META):
    return tuple(getattr(info, name) for name in fields)


def _ancestors(path):
    _need(path.is_absolute() and path.resolve(strict=True) == path, 'BACKEND_PATH_LINK_FORBIDDEN')
    for part in (path, *path.parents):
        info = part.lstat()
        sticky = (part != path and stat.S_ISDIR(info.st_mode) and info.st_uid == 0
                  and bool(info.st_mode & stat.S_ISVTX))
        _need(not stat.S_ISLNK(info.st_mode) and info.st_uid in (0, os.geteuid())
              and (not stat.S_IMODE(info.st_mode) & 0o022 or sticky), 'BACKEND_PATH_OWNER_OR_MODE_INVALID')


def _source_raw(path, maximum=MAX_SOURCE_BYTES):
    """Stable no-follow source read; empty package markers are legitimate."""
    _ancestors(path)
    before = path.lstat()
    _need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
          and 0 <= before.st_size <= maximum, 'BACKEND_SOURCE_FILE_INVALID')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    _need(_identity(before) == _identity(opened) == _identity(after) == _identity(path.lstat())
          and len(raw) == before.st_size, 'BACKEND_SOURCE_CHANGED_DURING_READ')
    return raw


def _verify_sources(root, inventory):
    """Check exact actual inventory and the origins of executing local modules."""
    _need(Path(__file__).resolve(strict=True).parents[2] == root,
          'BACKEND_EXECUTING_ROOT_CHANGED')
    _need(sys.flags.isolated == 1 and sys.dont_write_bytecode and sys.pycache_prefix is None,
          'BACKEND_ISOLATED_BYTECODE_DISABLED_RUNTIME_REQUIRED')
    _need('fox.app' not in sys.modules and 'fox.worker' not in sys.modules,
          'BACKEND_APPLICATION_MUST_NOT_BE_IMPORTED')
    _ancestors(root)
    expected_dirs = {str(parent) for name in inventory for parent in PurePosixPath(name).parents
                     if str(parent) != '.'}
    seen, directories, todo, total = set(), set(), [root], 0
    while todo:
        directory = todo.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                name = path.relative_to(root).as_posix()
                _need(not entry.is_symlink(), 'BACKEND_SOURCE_LINK_FORBIDDEN')
                if entry.is_dir(follow_symlinks=False):
                    _need(name in expected_dirs, 'BACKEND_SOURCE_DIRECTORY_CHANGED')
                    _ancestors(path); directories.add(name); todo.append(path)
                else:
                    _need(name in inventory, 'BACKEND_SOURCE_INVENTORY_CHANGED')
                    raw = _source_raw(path); total += len(raw)
                    _need(total <= MAX_SOURCE_TOTAL and _digest(raw) == inventory[name],
                          'BACKEND_SOURCE_BYTES_CHANGED')
                    seen.add(name)
    _need(seen == set(inventory) and directories == expected_dirs,
          'BACKEND_SOURCE_INVENTORY_CHANGED')
    executed = {}
    for name, module in tuple(sys.modules.items()):
        if not any(name == prefix or name.startswith(prefix + '.') for prefix in _LOCAL_PREFIXES):
            continue
        filename = getattr(module, '__file__', None)
        if filename is None:
            paths = tuple(getattr(module, '__path__', ()))
            _need(paths and all(Path(p).resolve(strict=True) == Path(p)
                  and root in Path(p).parents for p in paths), 'BACKEND_MODULE_ORIGIN_CHANGED')
            continue
        path = Path(filename)
        _need(path.is_absolute() and path.suffix == '.py' and path.resolve(strict=True) == path
              and root in path.parents, 'BACKEND_MODULE_ORIGIN_CHANGED')
        relative = path.relative_to(root).as_posix()
        _need(relative in inventory and _digest(_source_raw(path)) == inventory[relative],
              'BACKEND_EXECUTING_SOURCE_UNBOUND')
        executed[name] = {'path': relative, 'sha256': inventory[relative]}
    _need(executed.get(__name__, {}).get('path') == 'qa/operator/fresh_backend.py',
          'BACKEND_INITIALIZER_SOURCE_UNBOUND')
    return executed


def _read_reference(reference, artifacts):
    reference = contracts._ref(reference)
    raw = storage._read(Path(reference['path']))
    _need(_digest(raw) == reference['sha256'], 'BACKEND_REFERENCE_BYTES_CHANGED')
    _need(reference['path'] not in artifacts or artifacts[reference['path']] == raw,
          'BACKEND_REFERENCE_REBOUND')
    artifacts[reference['path']] = raw
    return contracts._parse(raw)


def _verify_release_sources(root, release):
    """Measure existing inert source bundles, never select or run a provider."""
    from . import clean_install, native_qa_dispatch, project_clean_install, project_qa_dispatch

    # Explicit images avoid the legacy bundle helpers' runtime-provider lookup.
    # These are declaration inputs, not proof that any image exists or is clean.
    images = release['images']
    measured = {
        'clean_operator_code_sha256': clean_install.code_bundle()[1],
        'qa_source_sha256': native_qa_dispatch.bundle(images=images)[3],
        'promotion_transport_sha256': _digest(_source_raw(root / 'qa/operator/promote_native.py')),
    }
    project = {
        'clean_operator_code_sha256': project_clean_install.code_bundle()[1],
        'qa_source_sha256': project_qa_dispatch.bundle(images=images)[3],
        'promotion_transport_sha256': _digest(_source_raw(root / 'qa/operator/promote_project.py')),
        'operator_code_sha256': _digest(_source_raw(root / 'qa/operator/project_operator.py')),
    }
    _need(all(release[key] == value for key, value in measured.items())
          and all(release['project'][key] == value for key, value in project.items()),
          'BACKEND_RELEASE_SOURCE_AGGREGATE_CHANGED')


def _inputs(provider_reference, release_reference, layout):
    """Resolve only bounded public/profile/configuration references, no secrets."""
    artifacts = {}
    config = _read_reference(provider_reference, artifacts)
    contracts._keys(layout, ('release_root', 'inventory'), 'LAYOUT_FIELDS_INVALID')
    # Reject declared secret aliases before resolving any descendant reference.
    # These are only paths in C3; their files and directories are never opened.
    secret_paths = [str(contracts._path(config['admin_secret_file']))]
    secret_destinations = {'/run/fox-opaf', '/opt/forms2apex/wallet', '/home/converter/.dbtools'}
    for role in config['runtime']['roles'].values():
        for mount in role['mounts']:
            if mount['destination'] in secret_destinations:
                secret_paths.append(str(contracts._path(mount['source'])))
    following = (release_reference, layout['inventory'], config['storage']['plan'],
        config['storage']['completion'], config['app_projection'],
        config['runtime']['opaf_profile'], config['runtime']['target_profile'])
    _need(all(contracts._outside(contracts._ref(ref)['path'], secret_paths) for ref in following),
          'BACKEND_REFERENCE_OVERLAPS_SECRET')
    _read_reference(release_reference, artifacts)
    inventory = _read_reference(layout['inventory'], artifacts)
    plan = _read_reference(config['storage']['plan'], artifacts)
    _read_reference(config['storage']['completion'], artifacts)
    _read_reference(config['app_projection'], artifacts)
    for key in ('opaf_profile', 'target_profile'):
        ref = contracts._ref(config['runtime'][key])
        raw = storage._read(Path(ref['path']))
        _need(_digest(raw) == ref['sha256'], 'BACKEND_REFERENCE_BYTES_CHANGED')
        artifacts[ref['path']] = raw
    config = contracts.validate_provider(provider_reference, artifacts)
    release = contracts.validate_release(release_reference, artifacts,
        provider_reference=provider_reference, layout=layout)
    _need(config['owner_uid'] == os.geteuid() == plan['owner_uid'], 'BACKEND_OWNER_CHANGED')
    return config, plan, release, inventory['files'], artifacts


def _same_inputs(artifacts):
    for path, raw in artifacts.items():
        _need(storage._read(Path(path)) == raw, 'BACKEND_REFERENCE_BYTES_CHANGED')


def _no_sidecars(database):
    _need(not any(os.path.lexists(str(database) + suffix) for suffix in _SIDECARS),
          'BACKEND_ACTIVE_OR_UNRECONCILED_SIDECARS')


def _database_file(database):
    storage._private_dir(database.parent)
    info = database.lstat()
    _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
          and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 64_000_000,
          'BACKEND_PRIVATE_DATABASE_REQUIRED')
    return _identity(info, _FILE_ID)


def _event(connection):
    return [tuple(row) for row in connection.execute('SELECT * FROM events ORDER BY id LIMIT 2')]


def _initial_state(database, plan, installation_id):
    """Read exact S0 state before any attempt or SQLite writer is opened."""
    _no_sidecars(database)
    identity = _database_file(database)
    before = _identity(database.lstat())
    expected = storage._prerequisite_schema(plan)
    _need(_digest(storage.canonical(expected)) == plan['initial_schema_sha256'],
          'BACKEND_BASE_SCHEMA_BINDING_CHANGED')
    with closing(sqlite3.connect(database.as_uri() + '?mode=ro&immutable=1', uri=True, timeout=1)) as db:
        db.execute('PRAGMA query_only=ON'); db.execute('PRAGMA trusted_schema=OFF')
        db.set_progress_handler(lambda: 1, 100000)
        _need(storage._schema(db) == expected, 'BACKEND_REQUIRES_EXACT_INITIAL_SCHEMA')
        counts = storage._empty(db)
        _need(db.execute('SELECT singleton,installation_id,plan_sha256 FROM fox_storage_identity').fetchall()
              == [(1, installation_id, storage.plan_sha256(plan))], 'BACKEND_STORAGE_IDENTITY_CHANGED')
        _need(db.execute('PRAGMA quick_check').fetchall() == [('ok',)]
              and not db.execute('PRAGMA foreign_key_check').fetchone(), 'BACKEND_BASE_INTEGRITY_CHANGED')
        event = _event(db)
    _no_sidecars(database)
    _need(_identity(database.lstat()) == before, 'BACKEND_DATABASE_CHANGED_DURING_READ')
    return identity, expected, counts, event


def _public_inventory(public, names):
    storage._private_dir(public)
    _need({entry.name for entry in public.iterdir()} == set(names), 'BACKEND_PUBLIC_INVENTORY_CHANGED')


def _baseline_snapshot(roots):
    records = roots['records']
    return ({role: storage._root_identity(path) for role, path in roots.items()},
            {entry.name: storage._read(entry, 1 if entry.name == 'operation.lock' else 2_000_000)
             for entry in records.iterdir()}, _identity((records / 'operation.lock').lstat()))


def _check_baseline(roots, baseline):
    _need(_baseline_snapshot(roots) == baseline, 'BACKEND_STORAGE_EXCLUSION_OR_BASELINE_CHANGED')


def _initialize_database(database, identity, expected, initial_counts, initial_event, installation_id, plan_hash):
    """Write only shared backend schemas, then finalize the rollback-mode file."""
    _need(_database_file(database) == identity, 'BACKEND_DATABASE_IDENTITY_CHANGED')
    with closing(sqlite3.connect(database.as_uri() + '?mode=rw', uri=True, timeout=1,
                                 isolation_level=None)) as db:
        db.execute('PRAGMA foreign_keys=ON'); db.execute('PRAGMA synchronous=FULL')
        db.execute('PRAGMA trusted_schema=OFF'); db.execute('BEGIN EXCLUSIVE')
        try:
            _need(storage._schema(db) == expected and storage._empty(db) == initial_counts
                  and _event(db) == initial_event, 'BACKEND_INITIAL_STATE_CHANGED')
            _need(db.execute('SELECT singleton,installation_id,plan_sha256 FROM fox_storage_identity').fetchall()
                  == [(1, installation_id, plan_hash)], 'BACKEND_STORAGE_IDENTITY_CHANGED')
            verification_queue.initialize_schema(db)
            verification_runtime.initialize_contact_schema(db)
            verification_recovery.initialize_schema(db)
            backend_storage.validate_backend_storage(db, installation_id=installation_id,
                                                     plan_sha256=plan_hash, require_empty=True)
            _need(_event(db) == initial_event, 'BACKEND_INITIALIZATION_EVENT_CHANGED')
            db.commit()
        finally:
            if db.in_transaction:
                db.rollback()
        checkpoint = db.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone()
        _need(checkpoint is not None and checkpoint[0] == 0, 'BACKEND_CHECKPOINT_UNCONFIRMED')
        _need(db.execute('PRAGMA journal_mode=DELETE').fetchone() == ('delete',),
              'BACKEND_ROLLBACK_JOURNAL_UNCONFIRMED')
    # SQLite itself handles its own journal lifecycle. Never delete a sidecar.
    _no_sidecars(database)
    _need(_database_file(database) == identity, 'BACKEND_DATABASE_IDENTITY_CHANGED')
    fd = os.open(database, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        _need(_identity(os.fstat(fd), _FILE_ID) == identity, 'BACKEND_DATABASE_IDENTITY_CHANGED')
        os.fsync(fd)
    finally:
        os.close(fd)
    storage._sync(database.parent)


def _final_observation(database, identity, initial_event, installation_id, plan_hash):
    _no_sidecars(database)
    _need(_database_file(database) == identity, 'BACKEND_DATABASE_IDENTITY_CHANGED')
    before = _identity(database.lstat())
    with os.fdopen(os.open(database, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        header = stream.read(100)
    _need(len(header) == 100 and header[:16] == b'SQLite format 3\x00' and header[18:20] == b'\x01\x01',
          'BACKEND_ROLLBACK_HEADER_REQUIRED')
    with closing(sqlite3.connect(database.as_uri() + '?mode=ro&immutable=1', uri=True, timeout=1)) as db:
        db.execute('PRAGMA query_only=ON'); db.execute('PRAGMA trusted_schema=OFF')
        db.set_progress_handler(lambda: 1, 100000)
        value = backend_storage.validate_backend_storage(db, installation_id=installation_id,
                                                         plan_sha256=plan_hash, require_empty=True)
        _need(_event(db) == initial_event and db.execute('PRAGMA quick_check').fetchall() == [('ok',)]
              and not db.execute('PRAGMA foreign_key_check').fetchone(), 'BACKEND_FINAL_INTEGRITY_CHANGED')
    _no_sidecars(database)
    _need(_identity(database.lstat()) == before, 'BACKEND_DATABASE_CHANGED_DURING_READ')
    return value


def initialize_backend(provider_reference, release_reference, *, layout, apply=False):
    """Produce F once from exact reviewed references and actual protected bytes.

    Requires genuine nonroot POSIX execution with ``-I -B``. The protected
    layout inventory must include every file in the executing source bundle,
    including the actual imported defusedxml dependency. C3's Python path/hash
    and version must describe this interpreter. No credential file is opened.
    Any existing attempt/F, failed read or uncertain write requires review.
    """
    _need(apply is True, 'EXPLICIT_BACKEND_APPLY_REQUIRED')
    _need(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW') and hasattr(os, 'O_DIRECTORY')
          and os.geteuid() > 0, 'BACKEND_POSIX_OWNER_RUNTIME_REQUIRED')
    attempt, attempt_identity, phase = None, None, 'VALIDATE_PREREQUISITES'
    try:
        config, plan, release, inventory, artifacts = _inputs(provider_reference, release_reference, layout)
        root = Path(layout['release_root'])
        _verify_sources(root, inventory)
        _verify_release_sources(root, release)
        executed = _verify_sources(root, inventory)
        python = config['python']
        _need(Path(sys.executable).resolve(strict=True) == Path(python['path'])
              and list(sys.version_info[:3]) == python['version']
              and _digest(_source_raw(Path(python['path']), 128_000_000)) == python['sha256'],
              'BACKEND_INTERPRETER_BINDING_CHANGED')
        roots = {role: Path(path) for role, path in plan['roots'].items()}
        public = Path(config['runtime']['public_configuration']['directory'])
        output = public / contracts.PUBLIC_FILENAMES['backend_filename']
        installation_id = config['storage']['installation_id']
        plan_hash = config['storage']['plan']['sha256']
        prospective_attempt = roots['operator_state'] / ATTEMPT_NAME
        _need(not os.path.lexists(prospective_attempt) and not os.path.lexists(output),
              'BACKEND_ATTEMPT_EXISTS_NO_REPLAY')
        with storage.exclusive_storage(plan, expected_plan_sha256=plan_hash) as baseline_observation:
            _need(baseline_observation['installation_id'] == installation_id
                  and baseline_observation['completion_sha256'] == config['storage']['completion']['sha256'],
                  'BACKEND_S0_BINDING_CHANGED')
            baseline = _baseline_snapshot(roots)
            _same_inputs(artifacts); _verify_sources(root, inventory)
            _public_inventory(public, [contracts.PUBLIC_FILENAMES['projection_filename']])
            public_identity = storage._root_identity(public)
            _need(not any(roots['operator_state'].iterdir()) and not any(roots['converter_jobs'].iterdir())
                  and {p.name for p in roots['fox_data'].iterdir()} == {'fox.sqlite3'},
                  'BACKEND_INITIAL_STORAGE_INVENTORY_CHANGED')
            database = roots['fox_data'] / 'fox.sqlite3'
            identity, expected, counts, event = _initial_state(database, plan, installation_id)
            _check_baseline(roots, baseline)
            prospective_attempt.mkdir(mode=0o700)
            attempt = prospective_attempt; attempt_identity = storage._root_identity(attempt)
            storage._sync(attempt.parent)
            bindings = {'installation_id': installation_id, 'storage_plan_sha256': plan_hash,
                'storage_completion_sha256': config['storage']['completion']['sha256'],
                'app_projection_sha256': config['app_projection']['sha256'],
                'provider_configuration_sha256': provider_reference['sha256'],
                'release_sha256': release_reference['sha256']}
            intent = {'schema_version': 1, 'scope': 'fox-fresh-backend-intent-v1', **bindings,
                'source_inventory': layout['inventory'], 'executing_sources': executed,
                'automatic_replay_permitted': False, 'created_at_utc': datetime.now(timezone.utc).isoformat()}
            intent_raw = storage.canonical(intent)
            storage._write(attempt / 'intent.json', intent_raw)
            phase = 'INITIALIZE_BACKEND'
            _same_inputs(artifacts); _verify_sources(root, inventory); _check_baseline(roots, baseline)
            _initialize_database(database, identity, expected, counts, event, installation_id, plan_hash)
            phase = 'OBSERVE_FINAL_BACKEND'
            observed = _final_observation(database, identity, event, installation_id, plan_hash)
            observed_raw = storage.canonical({
                'scope': 'fox-fresh-backend-observation-v1', **bindings,
                'intent_sha256': _digest(intent_raw), **observed, 'sqlite_version': sqlite3.sqlite_version,
                'journal_mode': 'delete', 'sqlite_header_read_version': 1, 'sqlite_header_write_version': 1})
            storage._write(attempt / 'observed.json', observed_raw)
            value = {'schema_version': 1, 'scope': contracts.SCOPES['backend'], **bindings,
                'intent_sha256': _digest(intent_raw), 'backend_schema_sha256': observed['backend_schema_sha256'],
                'initial_counts': observed['initial_counts'], 'completed_at_utc': datetime.now(timezone.utc).isoformat()}
            raw = contracts.canonical(value)
            reference = {'path': str(output), 'sha256': _digest(raw)}
            contracts.validate_backend_initialization(reference, {**artifacts, str(output): raw},
                provider_reference=provider_reference, release_reference=release_reference, layout=layout)
            phase = 'PUBLISH_F'
            _same_inputs(artifacts); _verify_sources(root, inventory); _check_baseline(roots, baseline)
            _need(storage._root_identity(attempt) == attempt_identity
                  and {path.name for path in attempt.iterdir()} == {'intent.json', 'observed.json'}
                  and storage._read(attempt / 'intent.json') == intent_raw
                  and storage._read(attempt / 'observed.json') == observed_raw, 'BACKEND_ATTEMPT_CHANGED')
            _need(storage._root_identity(public) == public_identity, 'BACKEND_PUBLIC_DIRECTORY_CHANGED')
            _public_inventory(public, [contracts.PUBLIC_FILENAMES['projection_filename']])
            _need(_final_observation(database, identity, event, installation_id, plan_hash) == observed,
                  'BACKEND_FINAL_OBSERVATION_CHANGED')
            storage._write(output, raw)  # Create-only; no replace, retry or cleanup path.
            _need(storage._read(output) == raw, 'BACKEND_PUBLICATION_UNCONFIRMED')
            _public_inventory(public, [contracts.PUBLIC_FILENAMES['projection_filename'], output.name])
            _need(storage._root_identity(public) == public_identity, 'BACKEND_PUBLIC_DIRECTORY_CHANGED')
            _check_baseline(roots, baseline)
        return {'status': 'FRESH_BACKEND_INITIALIZED_NOT_ADMITTED', 'installation_id': installation_id,
                'backend_initialization': reference, 'connected_admission': False, 'services_started': False,
                'oracle_accessed': False, 'automatic_replay_permitted': False}
    except Exception as error:
        known = (FreshBackendError, storage.FreshStorageError, contracts.FreshContractError,
                 backend_storage.BackendStorageError, verification_queue.QueueError,
                 verification_recovery.RecoveryError, verification_runtime.VerificationRuntimeError)
        code = str(error) if type(error) in known else 'BACKEND_INITIALIZATION_OUTCOME_UNCONFIRMED'
        if attempt is not None:
            try:
                _need(storage._root_identity(attempt) == attempt_identity, 'BACKEND_ATTEMPT_CHANGED')
                storage._write(attempt / 'failure.json', storage.canonical({
                    'scope': 'fox-fresh-backend-failure-v1', 'phase': phase, 'code': code,
                    'automatic_replay_permitted': False}))
            except Exception:
                pass  # Preserve partial evidence; failure recording cannot justify replay.
        raise FreshBackendError(code) from None
