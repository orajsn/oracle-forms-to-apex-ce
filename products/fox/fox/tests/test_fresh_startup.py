"""Synthetic local configuration, actual temporary SQLite and HTTP only.

Every A below is a test record, NEVER an actual admission or live observation.
No OCI, SSH, model, Oracle tool or container command is permitted.
"""
from contextlib import closing
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest

from fox import storage, backend_storage, fresh_startup as M
from fox import verification_queue, verification_recovery, verification_runtime
from fox.app import create_app, password_hash
from fox.installation import projection_bytes
from test_source_history_api import no_external_actions


ORIGIN = 'http://127.0.0.1:8100'
IDENTITY = 'fst-' + 'a' * 32


def raw(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def contents(root):
    with closing(sqlite3.connect(root / 'fox.sqlite3')) as db:
        return list(db.iterdump())


@pytest.fixture
def synthetic(tmp_path, monkeypatch):
    root, public = tmp_path / 'synthetic-data', tmp_path / 'synthetic-public'
    root.mkdir(); public.mkdir()
    with closing(sqlite3.connect(root / 'fox.sqlite3')) as db, db:
        db.row_factory = sqlite3.Row
        storage.initialize_schema(db)
        db.execute(storage.IDENTITY_SQL)
        db.execute('INSERT INTO fox_storage_identity VALUES(1,?,?)', (IDENTITY, '1' * 64))
        verification_queue.initialize_schema(db)
        verification_runtime.initialize_contact_schema(db)
        verification_recovery.initialize_schema(db)
        db.commit()
        assert db.execute('PRAGMA journal_mode=DELETE').fetchone()[0] == 'delete'
    projection = {'schema_version': 1, 'scope': 'fox-fresh-app-projection-v1',
        'installation_mode': 'fresh', 'installation_id': IDENTITY, 'storage_plan_sha256': '1' * 64,
        'storage_completion_sha256': '2' * 64, 'converter_endpoint': 'http://127.0.0.1:18091'}
    p = projection_bytes(projection)
    backend = {'schema_version': 1, 'scope': 'fox-fresh-backend-initialization-v1',
        'installation_id': IDENTITY, 'storage_plan_sha256': '1' * 64, 'storage_completion_sha256': '2' * 64,
        'app_projection_sha256': sha(p), 'provider_configuration_sha256': '3' * 64,
        'release_sha256': '4' * 64, 'intent_sha256': '5' * 64,
        'backend_schema_sha256': sha(raw(backend_storage.expected_backend_schema())),
        'initial_counts': M.INITIAL_COUNTS, 'completed_at_utc': '2026-01-01T00:00:01Z'}
    f = raw(backend)
    admission = {'schema_version': 1, 'scope': 'fox-fresh-live-admission-v1',
        'installation_id': IDENTITY, 'storage_completion_sha256': '2' * 64,
        'app_projection_sha256': sha(p), 'provider_configuration_sha256': '3' * 64,
        'release_sha256': '4' * 64, 'backend_initialization_sha256': sha(f),
        'admission_sha256': '6' * 64, 'installation_sha256': '7' * 64,
        'live_observation_sha256': '8' * 64, 'observed_at_utc': '2026-01-01T00:00:02Z',
        'transition': 'INITIAL_TO_NORMAL', 'automatic_replay_permitted': False}
    (public / 'projection.json').write_bytes(p)
    (public / 'backend-initialization.json').write_bytes(f)
    env = {'FOX_INSTALLATION_MODE': 'fresh', 'FOX_FRESH_PUBLIC_CONFIG_DIR': str(public),
        'FOX_FRESH_PROJECTION_SHA256': sha(p), 'FOX_FRESH_PROVIDER_SHA256': '3' * 64,
        'FOX_VERIFIER_RELEASE_SHA256': '4' * 64, 'FOX_FRESH_BACKEND_SHA256': sha(f)}
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv('FOX_PASSWORD_HASH', password_hash('synthetic-password'))
    monkeypatch.setenv('FOX_ADMIN_USERNAME', 'synthetic-user')
    monkeypatch.setenv('FOX_PUBLIC_ORIGIN', ORIGIN)
    monkeypatch.setenv('FOX_VERIFICATION_ENABLED', '1')
    return SimpleNamespace(root=root, public=public, env=env, projection=projection,
                           backend=backend, admission=admission)


def publish_test_a(fixture):
    (fixture.public / 'live-admission.json').write_bytes(raw(fixture.admission))


def test_environment_mapping_is_frozen():
    assert M.ENVIRONMENT == {'mode': 'FOX_INSTALLATION_MODE',
        'public_directory': 'FOX_FRESH_PUBLIC_CONFIG_DIR',
        'projection_sha256': 'FOX_FRESH_PROJECTION_SHA256',
        'provider_sha256': 'FOX_FRESH_PROVIDER_SHA256',
        'release_sha256': 'FOX_VERIFIER_RELEASE_SHA256', 'backend_sha256': 'FOX_FRESH_BACKEND_SHA256'}


@pytest.mark.parametrize('mode', ['', 'Fresh', 'fresh ', ' fresh', 'unknown', '0'])
def test_unknown_modes_cannot_create_or_fall_back(tmp_path, monkeypatch, mode):
    monkeypatch.setenv('FOX_INSTALLATION_MODE', mode)
    target = tmp_path / 'missing-data'
    with pytest.raises(M.FreshStartupError, match='MODE_INVALID'):
        create_app(target, enable_worker=False)
    assert not target.exists()


def test_missing_fresh_data_mount_is_not_created(synthetic):
    target = synthetic.root.parent / 'missing-mount'
    with pytest.raises(M.FreshStartupError):
        create_app(target, enable_worker=False)
    assert not target.exists()


def test_missing_fresh_database_is_not_created(synthetic):
    (synthetic.root / 'fox.sqlite3').unlink()
    with pytest.raises(M.FreshStartupError):
        create_app(synthetic.root, enable_worker=False)
    assert not (synthetic.root / 'fox.sqlite3').exists()


def test_legacy_rejects_fresh_marker_and_read_failure(synthetic, monkeypatch, tmp_path):
    for key in synthetic.env:
        monkeypatch.delenv(key)
    before = contents(synthetic.root)
    with pytest.raises(M.FreshStartupError, match='EXPLICIT_MODE'):
        create_app(synthetic.root, enable_worker=False)
    assert contents(synthetic.root) == before
    corrupt = tmp_path / 'corrupt'; corrupt.mkdir()
    (corrupt / 'fox.sqlite3').write_bytes(b'Synthetic corrupt database, not a legacy marker.')
    with pytest.raises(M.FreshStartupError, match='UNREADABLE'):
        create_app(corrupt, enable_worker=False)


def test_pre_a_only_health_identity_and_no_initialization_or_worker(synthetic, monkeypatch):
    before = contents(synthetic.root)
    files_before = {path.name: path.read_bytes() for path in synthetic.root.iterdir()}
    def forbidden(*args, **kwargs):
        raise AssertionError('No pre-admission initializer or conversion worker may run.')
    monkeypatch.setattr(verification_runtime, 'initialize', forbidden)
    import fox.worker
    monkeypatch.setattr(fox.worker, 'process_one', forbidden)
    app = create_app(synthetic.root, enable_worker=True)
    with TestClient(app) as client:
        for route in ('/api/health', '/api/installation'):
            response = client.get(route)
            assert response.status_code == 200
            assert 'FENCED' in response.text
        for method, route, payload in (
            ('post', '/api/login', {'username': 'synthetic-user', 'password': 'synthetic-password'}),
            ('get', '/api/projects', None), ('post', '/api/projects', {'customer': 'test', 'name': 'test'}),
            ('post', '/api/projects/absent/runs', {}), ('get', '/', None), ('get', '/assets/no.js', None),
            ('get', '/api/health/extra', None)):
            response = client.request(method, route, json=payload, headers={'origin': ORIGIN})
            assert response.status_code == 503
        assert app.state.worker_monitor.snapshot(thread_alive=False)['polls_completed'] == 0
    assert contents(synthetic.root) == before
    assert {path.name: path.read_bytes() for path in synthetic.root.iterdir()} == files_before


def test_test_a_opens_once_second_project_and_restart_do_not_require_empty(synthetic, monkeypatch):
    calls = []
    original = verification_runtime.initialize
    def record(*args, **kwargs):
        calls.append('initialized')
        return original(*args, **kwargs)
    monkeypatch.setattr(verification_runtime, 'initialize', record)
    app = create_app(synthetic.root, enable_worker=False)
    with TestClient(app) as client:
        assert client.get('/api/health').json()['status'] == 'fenced'
        publish_test_a(synthetic)
        assert client.get('/api/installation').json()['state'] == 'NORMAL'
        with closing(sqlite3.connect(synthetic.root / 'fox.sqlite3')) as db:
            assert db.execute('PRAGMA journal_mode').fetchone()[0] == 'wal'
        assert client.post('/api/login', json={'username': 'wrong-user', 'password': 'synthetic-password'},
                           headers={'origin': ORIGIN}).status_code == 401
        assert client.post('/api/login', json={'username': 'synthetic-user', 'password': 'synthetic-password'},
                           headers={'origin': ORIGIN}).status_code == 200
        for name in ('First synthetic project', 'Second synthetic project'):
            assert client.post('/api/projects', json={'customer': 'Synthetic only', 'name': name},
                               headers={'origin': ORIGIN}).status_code in (200, 201)
        for _ in range(3):
            assert client.get('/api/installation').json()['state'] == 'NORMAL'
    assert calls == ['initialized']
    before = contents(synthetic.root)
    with TestClient(create_app(synthetic.root, enable_worker=False)) as client:
        assert client.get('/api/installation').json()['state'] == 'NORMAL'
    assert contents(synthetic.root) == before
    assert calls == ['initialized', 'initialized']


@pytest.mark.parametrize('document', ['projection', 'backend', 'admission'])
def test_changed_records_fail_closed_without_database_mutation(synthetic, document):
    publish_test_a(synthetic)
    before = contents(synthetic.root)
    name = {'projection':'projection.json', 'backend':'backend-initialization.json', 'admission':'live-admission.json'}[document]
    value = deepcopy(getattr(synthetic, document)); value['installation_id'] = 'fst-' + 'b' * 32
    (synthetic.public / name).write_bytes(raw(value))
    with pytest.raises(M.FreshStartupError):
        create_app(synthetic.root, enable_worker=False)
    assert contents(synthetic.root) == before


@pytest.mark.parametrize('mutation', [lambda a: a.update(automatic_replay_permitted=True),
    lambda a: a.update(schema_version=True), lambda a: a.update(ready=True),
    lambda a: a.update(release_sha256='9' * 64), lambda a: a.update(observed_at_utc='2025-01-01T00:00:00Z'),
    lambda a: a.update(admission_sha256='not-a-hash')])
def test_invalid_test_a_never_admits(synthetic, mutation):
    mutation(synthetic.admission); publish_test_a(synthetic)
    before = contents(synthetic.root)
    with pytest.raises(M.FreshStartupError):
        create_app(synthetic.root, enable_worker=False)
    assert contents(synthetic.root) == before


def test_missing_a_after_activity_cannot_restart_bootstrap(synthetic):
    with closing(sqlite3.connect(synthetic.root / 'fox.sqlite3')) as db, db:
        db.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)', ('p', 'o', 'Synthetic', 'P', '', 1))
    before = contents(synthetic.root)
    with pytest.raises(M.FreshStartupError):
        create_app(synthetic.root, enable_worker=False)
    assert contents(synthetic.root) == before


def test_removing_a_fences_running_http_instance_permanently(synthetic):
    publish_test_a(synthetic)
    with TestClient(create_app(synthetic.root, enable_worker=False)) as client:
        assert client.get('/api/installation').json()['state'] == 'NORMAL'
        (synthetic.public / 'live-admission.json').unlink()
        assert client.get('/api/health').status_code == 503
        publish_test_a(synthetic)
        assert client.get('/api/health').status_code == 503


def test_public_mount_rejects_private_configuration(synthetic):
    (synthetic.public / 'operator-private.json').write_bytes(b'{}')
    with pytest.raises(M.FreshStartupError, match='CONTENTS_INVALID'):
        create_app(synthetic.root, enable_worker=False)


def test_identity_change_in_live_wal_is_seen_without_checkpoint(synthetic):
    publish_test_a(synthetic)
    with closing(sqlite3.connect(synthetic.root / 'fox.sqlite3')) as writer:
        writer.execute('PRAGMA journal_mode=WAL')
        fence = M.configured_fence(synthetic.root)
        writer.execute('PRAGMA wal_autocheckpoint=0')
        writer.execute('UPDATE fox_storage_identity SET installation_id=?', ('fst-' + 'b' * 32,)); writer.commit()
        wal = Path(str(synthetic.root / 'fox.sqlite3') + '-wal')
        before = wal.read_bytes()
        with pytest.raises(M.FreshStartupError):
            fence.refresh()
        assert wal.read_bytes() == before


def test_pre_a_cold_wal_is_rejected_before_sqlite_creates_sidecars(synthetic):
    with closing(sqlite3.connect(synthetic.root / 'fox.sqlite3')) as db:
        db.execute('PRAGMA journal_mode=WAL')
    before = {path.name: path.read_bytes() for path in synthetic.root.iterdir()}
    assert set(before) == {'fox.sqlite3'}
    with pytest.raises(M.FreshStartupError, match='ROLLBACK_JOURNAL_REQUIRED'):
        create_app(synthetic.root, enable_worker=False)
    assert {path.name: path.read_bytes() for path in synthetic.root.iterdir()} == before


@pytest.mark.parametrize('suffix', ['-wal', '-shm', '-journal'])
def test_pre_a_sidecars_are_preserved_and_rejected(synthetic, suffix):
    sidecar = Path(str(synthetic.root / 'fox.sqlite3') + suffix)
    sidecar.write_bytes(b'Synthetic uncertain sidecar, never recovery authority.')
    before = {path.name: path.read_bytes() for path in synthetic.root.iterdir()}
    with pytest.raises(M.FreshStartupError, match='ROLLBACK_JOURNAL_REQUIRED'):
        create_app(synthetic.root, enable_worker=False)
    assert {path.name: path.read_bytes() for path in synthetic.root.iterdir()} == before


def test_worker_start_failure_permanently_fences_after_test_a(synthetic, monkeypatch):
    import threading
    app = create_app(synthetic.root, enable_worker=True)
    original = threading.Thread.start
    with TestClient(app) as client:
        def fail_worker(thread):
            if thread.name == 'fox-worker':
                raise RuntimeError('Synthetic worker start failure')
            return original(thread)
        monkeypatch.setattr(threading.Thread, 'start', fail_worker)
        publish_test_a(synthetic)
        assert client.get('/api/health').status_code == 503
        monkeypatch.setattr(threading.Thread, 'start', original)
        assert client.post('/api/login', json={'username':'synthetic-user', 'password':'synthetic-password'},
                           headers={'origin':ORIGIN}).status_code == 503


def test_post_a_initialization_failure_permanently_fences(synthetic, monkeypatch):
    original = verification_runtime.initialize
    def fail(*args, **kwargs):
        raise sqlite3.OperationalError('Synthetic startup outcome is uncertain')
    monkeypatch.setattr(verification_runtime, 'initialize', fail)
    app = create_app(synthetic.root, enable_worker=False)
    with TestClient(app) as client:
        publish_test_a(synthetic)
        assert client.get('/api/health').status_code == 503
        monkeypatch.setattr(verification_runtime, 'initialize', original)
        assert client.get('/api/health').status_code == 503


def test_post_a_recovery_update_failure_permanently_fences(synthetic, monkeypatch):
    original = sqlite3.connect
    class UncertainUpdate(sqlite3.Connection):
        def execute(self, sql, *args, **kwargs):
            if sql.startswith("UPDATE runs SET state='ATTENTION'"):
                raise sqlite3.OperationalError('Synthetic update failure')
            return super().execute(sql, *args, **kwargs)
    app = create_app(synthetic.root, enable_worker=False)
    with TestClient(app) as client:
        def connect(*args, **kwargs):
            return original(*args, **kwargs, factory=UncertainUpdate)
        monkeypatch.setattr(sqlite3, 'connect', connect)
        publish_test_a(synthetic)
        assert client.get('/api/health').status_code == 503
        monkeypatch.setattr(sqlite3, 'connect', original)
        assert client.get('/api/health').status_code == 503


def test_worker_is_started_once_after_test_a(synthetic, monkeypatch):
    import threading
    original = threading.Thread.start
    workers = []
    def start(thread):
        if thread.name == 'fox-worker':
            workers.append(thread)
        return original(thread)
    monkeypatch.setattr(threading.Thread, 'start', start)
    app = create_app(synthetic.root, enable_worker=True)
    with TestClient(app) as client:
        assert workers == []
        publish_test_a(synthetic)
        for _ in range(4):
            assert client.get('/api/installation').json()['state'] == 'NORMAL'
        assert len(workers) == 1
    workers[0].join(timeout=5)
    assert not workers[0].is_alive()


@pytest.mark.parametrize('suffix', ['-wal', '-shm', '-journal'])
def test_post_a_hardlinked_sidecar_is_rejected_before_sqlite(synthetic, suffix):
    publish_test_a(synthetic)
    target = synthetic.root.parent / 'synthetic-sidecar-source'
    target.write_bytes(b'Synthetic linked sidecar must not be opened by SQLite.')
    os.link(target, Path(str(synthetic.root / 'fox.sqlite3') + suffix))
    with pytest.raises(M.FreshStartupError):
        create_app(synthetic.root, enable_worker=False)
    assert target.read_bytes() == b'Synthetic linked sidecar must not be opened by SQLite.'


def test_schema_drift_is_not_initialized_away(synthetic):
    with closing(sqlite3.connect(synthetic.root / 'fox.sqlite3')) as db, db:
        db.execute('DROP TRIGGER verification_retry_events_no_update')
    before = contents(synthetic.root)
    with pytest.raises(M.FreshStartupError):
        create_app(synthetic.root, enable_worker=False)
    assert contents(synthetic.root) == before


def test_normal_restart_rejects_hash_valid_orphan_recovery_journal(synthetic):
    publish_test_a(synthetic)
    with closing(sqlite3.connect(synthetic.root / 'fox.sqlite3')) as db, db:
        verification_recovery.VerificationRecovery._insert(db, 'verification_retry_events', {
            'attempt_id': 'synthetic-orphan', 'sequence': 0, 'state': 'reserved',
            'payload_raw': raw({'request_sha256': 'a' * 64}), 'previous_sha256': '0' * 64,
            'recorded_at_utc': '2026-01-01T00:00:03Z'})
    before = contents(synthetic.root)
    with pytest.raises(M.FreshStartupError, match='RELATION_CHANGED'):
        create_app(synthetic.root, enable_worker=False)
    assert contents(synthetic.root) == before


def test_normal_restart_rejects_changed_queue_record(synthetic):
    publish_test_a(synthetic)
    job = 'fox-' + 'c' * 20
    binding = verification_queue.VerificationBinding(job, 'a' * 64, 'b' * 64, '4' * 64)
    with closing(sqlite3.connect(synthetic.root / 'fox.sqlite3')) as db, db:
        db.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)', ('p', 'o', 'Synthetic', 'P', '', 1))
        db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
                   (job, 'p', 'a' * 64, 'QA_REQUIRED', 'Synthetic', 1, 1, 'jobs/' + job + '/apex-package.zip'))
        verification_queue.VerificationQueue._save(db, {**binding.payload(),
            'binding_sha256': verification_queue._digest(binding.payload()), 'state': 'queued',
            'claim_token': None, 'proof_sha256': None, 'attention_code': None,
            'created_at_utc': '2026-01-01T00:00:03Z', 'updated_at_utc': '2026-01-01T00:00:03Z',
            'record_sha256': ''}, insert=True)
        db.execute('UPDATE verification_queue SET record_sha256=?', ('f' * 64,))
    before = contents(synthetic.root)
    with pytest.raises(M.FreshStartupError, match='NORMAL_STATE_INVALID'):
        create_app(synthetic.root, enable_worker=False)
    assert contents(synthetic.root) == before


@pytest.mark.parametrize('defect', ['sequence', 'oversized'])
def test_normal_restart_checks_journal_sequence_and_bounds(synthetic, monkeypatch, defect):
    publish_test_a(synthetic)
    job = 'fox-' + 'c' * 20
    binding = verification_queue.VerificationBinding(job, 'a' * 64, 'b' * 64, '4' * 64)
    request = {'schema_version': 1, 'scope': verification_recovery.RETRY_SCOPE,
        'request_id': 'request-' + 'a' * 32, 'attempt_id': 'attempt-' + 'a' * 32,
        'disposition_sha256': 'd' * 64, 'binding': binding.payload(),
        'explicit_operator_authorization': True, 'automatic_retry_permitted': False}
    encoded = raw(request)
    with closing(sqlite3.connect(synthetic.root / 'fox.sqlite3')) as db, db:
        db.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)', ('p', 'o', 'Synthetic', 'P', '', 1))
        db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
                   (job, 'p', 'a' * 64, 'QA_REQUIRED', 'Synthetic', 1, 1, 'jobs/' + job + '/apex-package.zip'))
        verification_queue.VerificationQueue._save(db, {**binding.payload(),
            'binding_sha256': verification_queue._digest(binding.payload()), 'state': 'queued',
            'claim_token': None, 'proof_sha256': None, 'attention_code': None,
            'created_at_utc': '2026-01-01T00:00:03Z', 'updated_at_utc': '2026-01-01T00:00:03Z',
            'record_sha256': ''}, insert=True)
        insert = verification_recovery.VerificationRecovery._insert
        insert(db, 'verification_failed_dispositions', {'disposition_sha256': 'd' * 64,
            'job_id': job, 'legacy_record_sha256': 'e' * 64, 'claim_sha256': 'f' * 64,
            'disposition_raw': raw({'synthetic': 'not a live failure disposition'}),
            'recorded_at_utc': '2026-01-01T00:00:03Z'})
        insert(db, 'verification_retry_attempts', {'attempt_id': request['attempt_id'],
            'request_id': request['request_id'], 'disposition_sha256': 'd' * 64, 'job_id': job,
            'request_raw': encoded, 'request_sha256': sha(encoded), 'created_at_utc': '2026-01-01T00:00:03Z'})
        insert(db, 'verification_retry_events', {'attempt_id': request['attempt_id'],
            'sequence': 1, 'state': 'reserved', 'payload_raw': (b'x' * 16_000_001
                if defect == 'oversized' else raw({'request_sha256': sha(encoded)})),
            'previous_sha256': '0' * 64, 'recorded_at_utc': '2026-01-01T00:00:03Z'})
        assert db.execute('PRAGMA foreign_key_check').fetchall() == []
    if defect == 'oversized':
        def forbidden(*args, **kwargs):
            raise AssertionError('Journal must be bounded before _attempt fetches payloads.')
        monkeypatch.setattr(verification_recovery.VerificationRecovery, '_attempt', forbidden)
    before = contents(synthetic.root)
    with pytest.raises(M.FreshStartupError, match='NORMAL_STATE_BOUND' if defect == 'oversized' else 'NORMAL_STATE_INVALID'):
        create_app(synthetic.root, enable_worker=False)
    assert contents(synthetic.root) == before


def test_contract_fields_match_complete_synthetic_operator_chain(synthetic, monkeypatch):
    # Test-only imports. The FOX image source never imports qa.operator.
    repository = Path(__file__).resolve().parents[2]
    for path in (repository, repository / 'converter'):
        monkeypatch.syspath_prepend(str(path))
    from qa.operator.tests.test_fresh_contracts import chain, checked
    expected_schema_hash = sha(raw(backend_storage.expected_backend_schema()))
    example = chain({'backend': lambda v: v.update(backend_schema_sha256=expected_schema_hash)})
    assert checked(example)['connected_admission'] is False
    assert set(example.values['backend']) == M.BACKEND_FIELDS
    assert set(example.values['transition']) == M.ADMISSION_FIELDS
    assert example.values['backend']['initial_counts'] == M.INITIAL_COUNTS
    for key, filename in (('projection', 'projection.json'), ('backend', 'backend-initialization.json'),
                          ('transition', 'live-admission.json')):
        (synthetic.public / filename).write_bytes(example.artifacts[example.refs[key]['path']])
    for key, env in (('projection', 'FOX_FRESH_PROJECTION_SHA256'), ('backend', 'FOX_FRESH_BACKEND_SHA256'),
                     ('provider', 'FOX_FRESH_PROVIDER_SHA256'), ('release', 'FOX_VERIFIER_RELEASE_SHA256')):
        monkeypatch.setenv(env, example.refs[key]['sha256'])
    with closing(sqlite3.connect(synthetic.root / 'fox.sqlite3')) as db, db:
        db.execute('UPDATE fox_storage_identity SET plan_sha256=?', (example.refs['storage_plan']['sha256'],))
    assert M.configured_fence(synthetic.root).identity()['state'] == 'NORMAL'
