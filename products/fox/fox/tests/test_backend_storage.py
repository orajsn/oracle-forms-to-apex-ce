"""Synthetic, local-only schema extraction and read-only validation tests.

No receipt here asserts installation, admission, producer state or Oracle proof.
"""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

from fox import backend_storage, storage
from fox import verification_queue as queue
from fox import verification_recovery as recovery
from fox import verification_runtime as runtime


REPOSITORY = Path(__file__).resolve().parents[1]
INSTALLATION = 'fst-' + '1' * 32
PLAN = '2' * 64
RELEASE = '3' * 64
JOB = 'fox-' + '4' * 20
TABLES = {
    'projects', 'sources', 'sessions', 'attempts', 'runs', 'events', 'acceptances',
    'prepared_uploads', 'source_sets', 'source_set_members', 'project_source_selection',
    'fox_storage_identity', 'verification_queue', 'verification_operator_contact',
    'verification_failed_dispositions', 'verification_retry_attempts',
    'verification_retry_events', 'verification_producer_observations',
}
COUNTS = {name: int(name in {'events', 'fox_storage_identity'}) for name in TABLES}


def connect(path=':memory:', row_factory=None):
    connection = sqlite3.connect(path, timeout=1)
    connection.row_factory = row_factory
    connection.execute('PRAGMA foreign_keys=ON')
    return connection


def base(connection):
    with connection:
        storage.initialize_schema(connection)
        connection.execute(storage.IDENTITY_SQL)
        connection.execute('INSERT INTO fox_storage_identity VALUES(1,?,?)', (INSTALLATION, PLAN))


def complete(connection):
    base(connection)
    with connection:
        connection.execute('BEGIN IMMEDIATE')
        queue.initialize_schema(connection)
        runtime.initialize_contact_schema(connection)
        recovery.initialize_schema(connection)


def snapshot(connection):
    schema = [tuple(row) for row in connection.execute(
        'SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name')]
    names = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
    return schema, {name: [tuple(row) for row in connection.execute('SELECT * FROM "' + name + '" ORDER BY rowid')]
                    for name in names}


def validate(connection, *, require_empty=False):
    return backend_storage.validate_backend_storage(connection, installation_id=INSTALLATION,
        plan_sha256=PLAN, require_empty=require_empty)


def test_import_is_inert_in_fresh_process(tmp_path):
    program = r'''
import json,os,pathlib,socket,sqlite3,subprocess,sys,threading
sys.path.insert(0,sys.argv[1])
before=sorted(pathlib.Path.cwd().iterdir())
def forbidden(*args,**kwargs):
 raise AssertionError('IMPORT_MUST_NOT_CREATE_CONNECT_OR_START')
def audit(event,args):
 if event=='open':
  mode=args[1]
  flags=args[2]
  if (isinstance(mode,str) and any(c in mode for c in 'wax+')) or (isinstance(flags,int) and flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND)):
   forbidden()
 if event in {'os.mkdir','os.remove','os.rename','os.rmdir','os.system','subprocess.Popen','sqlite3.connect','socket.connect'}:
  forbidden()
sys.addaudithook(audit)
sqlite3.connect=forbidden
threading.Thread.start=forbidden
subprocess.Popen=forbidden
socket.create_connection=forbidden
socket.socket.connect=forbidden
import fox.backend_storage,fox.verification_queue,fox.verification_runtime,fox.verification_recovery
assert 'fox.app' not in sys.modules
assert 'fox.worker' not in sys.modules
assert not any(name=='qa' or name.startswith('qa.') for name in sys.modules)
assert sorted(pathlib.Path.cwd().iterdir())==before
assert not pathlib.Path(os.environ['FOX_DATA_DIR']).exists()
print(json.dumps({'app_imported':False,'state_created':False,'operator_imported':False}))
'''
    environment = {**os.environ, 'FOX_DATA_DIR': str(tmp_path / 'absent'),
                   'FOX_VERIFICATION_ENABLED': '1', 'PYTHONDONTWRITEBYTECODE': '1'}
    result = subprocess.run([sys.executable, '-I', '-B', '-c', program, str(REPOSITORY)],
        cwd=tmp_path, env=environment, capture_output=True, timeout=30, check=True)
    assert not result.stderr
    assert json.loads(result.stdout) == {'app_imported': False, 'state_created': False, 'operator_imported': False}
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('row_factory', [None, sqlite3.Row], ids=['tuples', 'sqlite-rows'])
def test_expected_memory_schema_matches_public_initializers(tmp_path, row_factory):
    database = tmp_path / 'fox.sqlite3'
    with closing(connect(database, row_factory)) as connection:
        base(connection)
    runtime.initialize(tmp_path, runtime.VerificationConfig(True, RELEASE))
    recovery.VerificationRecovery(database, enabled=True).initialize()
    with closing(connect(database, row_factory)) as connection:
        observed = backend_storage.schema(connection)
        expected = backend_storage.expected_backend_schema()
        assert observed == expected
        assert {name for name, item in observed.items() if item[0] == 'table'} == TABLES
        assert backend_storage.initial_counts(connection) == COUNTS
        assert backend_storage.expected_backend_counts() == backend_storage.initial_counts(connection)
        result = validate(connection, require_empty=True)
        assert result['schema'] == observed
        assert result['initial_counts'] == COUNTS
        canonical = (json.dumps(expected, sort_keys=True, separators=(',', ':'), ensure_ascii=False) + '\n').encode('utf-8')
        assert result['backend_schema_sha256'] == hashlib.sha256(canonical).hexdigest()
        assert connection.row_factory is row_factory


@pytest.mark.parametrize('initializer,table', [
    (queue.initialize_schema, 'verification_queue'),
    (runtime.initialize_contact_schema, 'verification_operator_contact'),
    (recovery.initialize_schema, 'verification_failed_dispositions'),
])
@pytest.mark.parametrize('row_factory', [None, sqlite3.Row], ids=['tuples', 'sqlite-rows'])
def test_helpers_leave_transaction_and_connection_to_caller(initializer, table, row_factory):
    with closing(connect(row_factory=row_factory)) as connection:
        base(connection)
        if initializer is recovery.initialize_schema:
            with connection:
                connection.execute('BEGIN IMMEDIATE')
                queue.initialize_schema(connection)
        before = snapshot(connection)
        traced = []
        connection.set_trace_callback(traced.append)
        connection.execute('BEGIN IMMEDIATE')
        connection.execute('INSERT INTO attempts VALUES(?,?)', ('synthetic rollback witness', 1))
        assert initializer(connection) is None
        assert connection.in_transaction
        assert connection.row_factory is row_factory
        assert connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
        assert not any(statement.strip().upper() in {'COMMIT', 'ROLLBACK'} for statement in traced)
        connection.rollback()
        assert snapshot(connection) == before
        assert connection.execute('SELECT 1').fetchone()[0] == 1


def test_idempotent_helpers_preserve_existing_data_and_schema():
    with closing(connect()) as connection:
        complete(connection)
        with connection:
            connection.execute('INSERT INTO attempts VALUES(?,?)', ('synthetic retained attempt', 1))
            connection.execute('INSERT INTO sessions VALUES(?,?,?)', ('synthetic session', 'synthetic owner', 2))
            connection.execute('INSERT INTO verification_operator_contact VALUES(1,?,?)', (RELEASE, 3))
        before = snapshot(connection)
        with connection:
            connection.execute('BEGIN IMMEDIATE')
            queue.initialize_schema(connection)
            runtime.initialize_contact_schema(connection)
            recovery.initialize_schema(connection)
        assert snapshot(connection) == before


def seed_recovery_rows(connection):
    """Structural synthetic rows to exercise fences, never proof data."""
    connection.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)', ('p', 'synthetic', 'Synthetic only', 'Retained', '', 1))
    connection.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
        (JOB, 'p', 'a' * 64, 'QA_REQUIRED', 'Synthetic only', 1, 1, 'jobs/' + JOB + '/apex-package.zip'))
    connection.execute('INSERT INTO verification_queue VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
        (JOB, 'a' * 64, 'b' * 64, RELEASE, 'c' * 64, 'queued', None, None, None, 'synthetic', 'synthetic', 'd' * 64))
    connection.execute('INSERT INTO verification_failed_dispositions VALUES(?,?,?,?,?,?,?)',
        ('disposition', JOB, 'synthetic legacy', 'synthetic claim', b'synthetic only', 'synthetic', 'synthetic hash'))
    connection.execute('INSERT INTO verification_retry_attempts VALUES(?,?,?,?,?,?,?,?)',
        ('attempt', 'request', 'disposition', JOB, b'synthetic only', 'synthetic hash', 'synthetic', 'synthetic hash'))
    connection.execute('INSERT INTO verification_retry_events VALUES(?,?,?,?,?,?,?)',
        ('attempt', 1, 'synthetic', b'synthetic only', 'synthetic previous', 'synthetic', 'synthetic hash'))
    connection.execute('INSERT INTO verification_producer_observations VALUES(?,?,?,?,?,?,?,?)',
        ('observation', 'disposition', 'synthetic', RELEASE, 'attempt', b'synthetic only', 'synthetic', 'synthetic hash'))


@pytest.mark.parametrize('table', sorted(recovery.VerificationRecovery._TABLES))
@pytest.mark.parametrize('action', ['UPDATE', 'DELETE'])
def test_recovery_append_only_fences_survive_helper_reinitialization(table, action):
    with closing(connect()) as connection:
        complete(connection)
        with connection:
            seed_recovery_rows(connection)
        before = snapshot(connection)
        with connection:
            connection.execute('BEGIN IMMEDIATE')
            recovery.initialize_schema(connection)
        with pytest.raises(sqlite3.IntegrityError, match='RECOVERY_APPEND_ONLY'):
            connection.execute(action + ' ' + ('FROM ' + table if action == 'DELETE' else table + " SET record_sha256='changed'"))
        connection.rollback()
        assert snapshot(connection) == before


@pytest.mark.parametrize('statement', [
    'DELETE FROM verification_queue',
    "UPDATE verification_queue SET record_sha256='changed'",
])
def test_closed_legacy_fences_survive_helper_reinitialization(statement):
    with closing(connect()) as connection:
        complete(connection)
        with connection:
            seed_recovery_rows(connection)
        before = snapshot(connection)
        with connection:
            connection.execute('BEGIN IMMEDIATE')
            recovery.initialize_schema(connection)
        with pytest.raises(sqlite3.IntegrityError, match='RECOVERY_LEGACY_HISTORY_IMMUTABLE'):
            connection.execute(statement)
        connection.rollback()
        assert snapshot(connection) == before


@pytest.mark.parametrize('variant,code', [
    ('one_table', 'RECOVERY_PARTIAL_SCHEMA'),
    ('legacy', 'RECOVERY_EXPLICIT_OBSERVATION_MIGRATION_REQUIRED'),
    ('broken_fence', 'RECOVERY_SCHEMA_OR_FENCE_DEFINITION_CHANGED'),
])
def test_recovery_helper_and_public_initializer_reject_existing_schema_without_repair(tmp_path, variant, code):
    database = tmp_path / 'fox.sqlite3'
    with closing(connect(database)) as connection:
        base(connection)
        with connection:
            connection.execute('BEGIN IMMEDIATE')
            queue.initialize_schema(connection)
            definitions = recovery.VerificationRecovery.schema_definitions(include_observations=variant != 'legacy')
            if variant == 'one_table':
                definitions = {next(iter(definitions)): next(iter(definitions.values()))}
            for sql in definitions.values():
                connection.execute(sql)
            if variant == 'broken_fence':
                connection.execute('DROP TRIGGER verification_retry_events_no_delete')
        before = snapshot(connection)
        connection.execute('BEGIN IMMEDIATE')
        with pytest.raises(recovery.RecoveryError, match='^' + code + '$'):
            recovery.initialize_schema(connection)
        assert connection.in_transaction
        connection.rollback()
        assert snapshot(connection) == before
    with pytest.raises(recovery.RecoveryError, match='^' + code + '$'):
        recovery.VerificationRecovery(database, enabled=True).initialize()
    with closing(connect(database)) as connection:
        assert snapshot(connection) == before


@pytest.mark.parametrize('require_empty', [False, True])
def test_validation_is_read_only_on_supplied_connection(require_empty):
    with closing(connect()) as connection:
        complete(connection)
        before = snapshot(connection)
        connection.execute('PRAGMA query_only=ON')
        allowed = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_RECURSIVE}
        attempted = []
        def authorizer(action, first, second, database, source):
            # Read-only table_info is needed by the existing recovery schema checker.
            if action in allowed or action == sqlite3.SQLITE_PRAGMA and first == 'table_info':
                return sqlite3.SQLITE_OK
            attempted.append((action, first, second))
            return sqlite3.SQLITE_DENY
        connection.set_authorizer(authorizer)
        try:
            result = validate(connection, require_empty=require_empty)
        finally:
            connection.set_authorizer(None)
        assert attempted == []
        assert result['initial_counts'] == (COUNTS if require_empty else None)
        assert not connection.in_transaction
        assert snapshot(connection) == before


@pytest.mark.parametrize('mutation', [
    'identity_value', 'identity_missing', 'identity_table_missing', 'queue_missing',
    'contact_changed', 'fence_missing', 'additional_owned_trigger',
])
def test_validator_rejects_changed_identity_or_schema_without_repair(mutation):
    with closing(connect()) as connection:
        complete(connection)
        with connection:
            if mutation == 'identity_value':
                connection.execute("UPDATE fox_storage_identity SET installation_id='fst-' || ?", ('9' * 32,))
            elif mutation == 'identity_missing':
                connection.execute('DELETE FROM fox_storage_identity')
            elif mutation == 'identity_table_missing':
                connection.execute('DROP TABLE fox_storage_identity')
            elif mutation == 'queue_missing':
                connection.execute('DROP TABLE verification_queue')
            elif mutation == 'contact_changed':
                connection.execute('ALTER TABLE verification_operator_contact ADD COLUMN unexpected TEXT')
            elif mutation == 'fence_missing':
                connection.execute('DROP TRIGGER verification_retry_events_no_update')
            else:
                connection.execute("CREATE TRIGGER unexpected BEFORE INSERT ON projects BEGIN SELECT RAISE(ABORT,'unexpected'); END")
        before = snapshot(connection)
        with pytest.raises(backend_storage.BackendStorageError):
            validate(connection)
        assert snapshot(connection) == before


@pytest.mark.parametrize('mutation', ['business_row', 'contact_row', 'event_value', 'event_missing', 'extra_table'])
def test_initial_validation_rejects_noninitial_state(mutation):
    with closing(connect()) as connection:
        complete(connection)
        with connection:
            if mutation == 'business_row':
                connection.execute('INSERT INTO attempts VALUES(?,?)', ('synthetic', 1))
            elif mutation == 'contact_row':
                connection.execute('INSERT INTO verification_operator_contact VALUES(1,?,?)', (RELEASE, 1))
            elif mutation == 'event_value':
                connection.execute("UPDATE events SET object_id='not-the-initial-event'")
            elif mutation == 'event_missing':
                connection.execute('DELETE FROM events')
            else:
                connection.execute('CREATE TABLE technical_verifications(run TEXT PRIMARY KEY)')
        before = snapshot(connection)
        with pytest.raises(backend_storage.BackendStorageError):
            validate(connection, require_empty=True)
        assert snapshot(connection) == before


def test_normal_validation_allows_business_activity_and_later_table():
    with closing(connect()) as connection:
        complete(connection)
        with connection:
            connection.execute('INSERT INTO attempts VALUES(?,?)', ('synthetic retained activity', 1))
            connection.execute('CREATE TABLE technical_verifications(run TEXT PRIMARY KEY)')
            connection.execute('INSERT INTO technical_verifications VALUES(?)', ('synthetic retained proof reference',))
        before = snapshot(connection)
        result = validate(connection)
        assert 'technical_verifications' in result['schema']
        assert result['initial_counts'] is None
        assert snapshot(connection) == before


def test_expected_schema_is_a_fresh_detached_observation():
    expected = backend_storage.expected_backend_schema()
    expected['verification_queue'][2] = 'not schema'
    expected['fake'] = ['table', 'fake', 'not schema']
    actual = backend_storage.expected_backend_schema()
    assert 'fake' not in actual
    assert actual['verification_queue'][2].startswith('CREATE TABLE verification_queue(')


def test_expected_counts_are_detached_actual_reference_counts():
    counts = backend_storage.expected_backend_counts()
    assert counts == COUNTS
    counts['events'] = 9
    counts['fake'] = 1
    assert backend_storage.expected_backend_counts() == COUNTS
