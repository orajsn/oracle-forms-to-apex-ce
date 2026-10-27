"""Storage extraction tests with synthetic local SQLite data only.

These tests establish initializer behavior, not fresh-install admission, Oracle
execution, technical verification or genuine business acceptance.
"""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

from fox import source_history, storage
from fox.intake import checked_source


REPOSITORY = Path(__file__).resolve().parents[1]
BASE_TABLES = {'projects', 'sources', 'sessions', 'attempts', 'runs', 'events',
               'acceptances', 'prepared_uploads'}
HISTORY_TABLES = {'source_sets', 'source_set_members', 'project_source_selection'}
LEGACY_SCHEMA = '''
CREATE TABLE projects(id TEXT PRIMARY KEY,owner TEXT NOT NULL,customer TEXT NOT NULL,name TEXT NOT NULL,description TEXT NOT NULL,created REAL NOT NULL);
CREATE TABLE sources(id TEXT PRIMARY KEY,project TEXT NOT NULL REFERENCES projects(id),name TEXT NOT NULL,sha256 TEXT NOT NULL,bytes INTEGER NOT NULL,text TEXT NOT NULL,created REAL NOT NULL,UNIQUE(project,name,sha256));
CREATE TABLE runs(id TEXT PRIMARY KEY,project TEXT NOT NULL REFERENCES projects(id),source_hash TEXT NOT NULL,state TEXT NOT NULL,message TEXT NOT NULL,created REAL NOT NULL,updated REAL NOT NULL,artifact TEXT,UNIQUE(project,source_hash));
CREATE TABLE events(id INTEGER PRIMARY KEY,owner TEXT NOT NULL,action TEXT NOT NULL,object_id TEXT NOT NULL,created REAL NOT NULL);
'''


def connect(path):
    connection = sqlite3.connect(path, timeout=1)
    connection.row_factory = sqlite3.Row
    connection.execute('PRAGMA foreign_keys=ON')
    return connection


def rows(connection, table):
    # Names are hardcoded test-schema names, never uploaded identifiers.
    return [tuple(row) for row in connection.execute(f'SELECT * FROM {table} ORDER BY rowid')]


def tables(connection):
    return {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def snapshot(connection):
    return {
        'schema': [tuple(row) for row in connection.execute(
            'SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name')],
        'rows': {name: rows(connection, name) for name in sorted(tables(connection))},
    }


def seed_legacy(connection, *, invalid=False):
    connection.executescript(LEGACY_SCHEMA)
    with connection:
        connection.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)',
                           ('synthetic-project', 'synthetic-owner', 'Synthetic only', 'Legacy example', '', 1))
        connection.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)',
                           ('empty-project', 'synthetic-owner', 'Synthetic only', 'Empty example', '', 1))
        for sid, name, raw, created in (
            ('old-alpha', 'alpha.xml', b'<FormModule Name="OLD"/>', 100),
            ('only-notes', 'notes.txt', b'Synthetic source notes\r\n', 1),
            ('new-alpha', 'alpha.xml', b'\xef\xbb\xbf<FormModule Name="NEW"/>\r\n', 2),
        ):
            value = checked_source(name, raw)
            connection.execute('INSERT INTO sources VALUES(?,?,?,?,?,?,?)',
                (sid, 'synthetic-project', name, '0' * 64 if invalid and sid == 'new-alpha' else value['sha256'],
                 value['bytes'], value['text'], created))
        connection.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
            ('fox-' + '1' * 20, 'synthetic-project', '1' * 64, 'ATTENTION',
             'Synthetic retained run, not conversion proof', 3, 4, None))


def test_import_is_inert_in_a_fresh_process(tmp_path):
    absent = tmp_path / 'must-not-be-created'
    program = r'''
import json,os,pathlib,socket,sqlite3,subprocess,sys,threading
sys.path.insert(0,sys.argv[1])
root=pathlib.Path(os.environ['FOX_DATA_DIR'])
before=sorted(pathlib.Path.cwd().iterdir())
def forbidden(*args,**kwargs):
 raise AssertionError('IMPORT_MUST_NOT_CREATE_CONNECT_OR_START')
sqlite3.connect=forbidden
pathlib.Path.mkdir=forbidden
pathlib.Path.write_bytes=forbidden
pathlib.Path.write_text=forbidden
threading.Thread.start=forbidden
subprocess.Popen=forbidden
socket.create_connection=forbidden
socket.socket.connect=forbidden
import fox.storage
assert 'fox.app' not in sys.modules
assert not root.exists()
assert sorted(pathlib.Path.cwd().iterdir())==before
print(json.dumps({'app_imported':False,'state_created':False,'initializer_callable':callable(fox.storage.initialize_schema)}))
'''
    environment = {**os.environ, 'FOX_DATA_DIR': str(absent), 'FOX_VERIFICATION_ENABLED': '1',
                   'PYTHONDONTWRITEBYTECODE': '1'}
    result = subprocess.run([sys.executable, '-I', '-B', '-c', program, str(REPOSITORY)],
        cwd=tmp_path, env=environment, capture_output=True, timeout=30, check=True)
    assert not result.stderr
    assert json.loads(result.stdout) == {'app_imported': False, 'state_created': False, 'initializer_callable': True}
    assert not absent.exists()


def test_explicit_call_initializes_schema_without_app_or_worker(tmp_path):
    with closing(connect(tmp_path / 'fox.sqlite3')) as connection:
        assert tables(connection) == set()
        with connection:
            assert storage.initialize_schema(connection) is None
            assert connection.in_transaction
        assert not connection.in_transaction
        assert tables(connection) == BASE_TABLES | HISTORY_TABLES
        assert connection.execute('PRAGMA journal_mode').fetchone()[0] == 'wal'
        assert connection.execute('PRAGMA foreign_keys').fetchone()[0] == 1
        assert connection.execute('PRAGMA foreign_key_check').fetchall() == []
        assert [(row['owner'], row['action'], row['object_id']) for row in connection.execute('SELECT * FROM events')] == [
            ('system-source-history', 'source_history_initialized', 'schema-v1')]
        assert all(rows(connection, name) == [] for name in tables(connection) - {'events'})
        assert 'verification_queue' not in tables(connection)
        # The caller still owns the usable connection after initialization.
        assert connection.execute('SELECT 1').fetchone()[0] == 1


def test_core_constraints_remain_enforced(tmp_path):
    with closing(connect(tmp_path / 'fox.sqlite3')) as connection:
        with connection:
            storage.initialize_schema(connection)
        with pytest.raises(sqlite3.IntegrityError):
            with connection:
                connection.execute('INSERT INTO sources VALUES(?,?,?,?,?,?,?)',
                    ('s', 'missing-project', 'a.txt', 'a' * 64, 1, 'a', 1))
        with connection:
            connection.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)', ('p', 'o', 'Synthetic', 'P', '', 1))
            source_history.create_project_selection(connection, 'p', 1)
            connection.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
                               ('r1', 'p', 'a' * 64, 'ATTENTION', 'Synthetic', 1, 1, None))
        with pytest.raises(sqlite3.IntegrityError):
            with connection:
                connection.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
                                   ('r2', 'p', 'a' * 64, 'ATTENTION', 'Synthetic', 1, 1, None))


def test_caller_controls_history_transaction_commit_or_rollback(tmp_path):
    with closing(connect(tmp_path / 'fox.sqlite3')) as connection:
        storage.initialize_schema(connection)
        assert connection.in_transaction
        connection.rollback()
        # Existing app behavior: base executescript precedes the transactional
        # source-history migration. Rolling history back does not drop base DDL.
        assert tables(connection) == BASE_TABLES
        assert rows(connection, 'events') == []
        with connection:
            storage.initialize_schema(connection)
        assert tables(connection) == BASE_TABLES | HISTORY_TABLES
        assert len(rows(connection, 'events')) == 1


def test_legacy_migration_preserves_sources_runs_and_artifacts(tmp_path):
    artifact = tmp_path / 'retained-output.txt'
    artifact.write_bytes(b'Synthetic retained bytes; no real APEX output.\r\n')
    with closing(connect(tmp_path / 'fox.sqlite3')) as connection:
        seed_legacy(connection)
        before = {name: rows(connection, name) for name in ('projects', 'sources', 'runs')}
        with connection:
            storage.initialize_schema(connection)
        assert {name: rows(connection, name) for name in before} == before
        assert [item['id'] for item in source_history.selected_sources(connection, 'synthetic-project')] == [
            'new-alpha', 'only-notes']
        assert source_history.selected_source_set_id(connection, 'empty-project') is None
        sets = source_history.list_source_sets(connection, 'synthetic-project')['source_sets']
        assert len(sets) == 1 and sets[0]['origin'] == 'legacy-current'
        first = snapshot(connection)
        with connection:
            storage.initialize_schema(connection)
        assert snapshot(connection) == first
        assert artifact.read_bytes() == b'Synthetic retained bytes; no real APEX output.\r\n'


def test_existing_rows_selections_and_extra_state_are_not_reset(tmp_path):
    with closing(connect(tmp_path / 'fox.sqlite3')) as connection:
        with connection:
            storage.initialize_schema(connection)
            connection.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)', ('p', 'o', 'Synthetic', 'P', '', 1))
            source_history.create_project_selection(connection, 'p', 1)
            source_history.publish_upload(connection, 'p', [checked_source('notes.txt', b'First')], 2, 'o')
            source_history.publish_upload(connection, 'p', [checked_source('notes.txt', b'Second')], 3, 'o')
            connection.execute('INSERT INTO sessions VALUES(?,?,?)', ('synthetic-token', 'o', 100))
            connection.execute('INSERT INTO attempts VALUES(?,?)', ('127.0.0.1', 4))
            connection.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
                               ('r', 'p', 'a' * 64, 'ACCEPTED', 'Synthetic storage fixture only', 4, 5, 'jobs/r/apex-package.zip'))
            connection.execute('INSERT INTO acceptances VALUES(?,?,?,?,?,?)',
                               ('r', 'o', 'a' * 64, 'b' * 64, 'Synthetic row preservation, not business acceptance', 5))
            connection.execute('INSERT INTO prepared_uploads VALUES(?,?,?,?,?,?,?)',
                               ('upload', 'p', 'synthetic-extraction', 'c' * 64, 'd' * 64, '{}', 3))
            connection.execute('CREATE TABLE retained_extra_note(value TEXT)')
            connection.execute('INSERT INTO retained_extra_note VALUES(?)', ('Preserve, do not certify fresh.',))
        before = snapshot(connection)
        with connection:
            storage.initialize_schema(connection)
        assert snapshot(connection) == before


def test_invalid_legacy_source_rolls_back_history_without_repairing_data(tmp_path):
    with closing(connect(tmp_path / 'fox.sqlite3')) as connection:
        seed_legacy(connection, invalid=True)
        before = {name: rows(connection, name) for name in ('projects', 'sources', 'runs', 'events')}
        with pytest.raises(source_history.SourceHistoryError):
            with connection:
                storage.initialize_schema(connection)
        assert {name: rows(connection, name) for name in before} == before
        assert not (tables(connection) & HISTORY_TABLES)


def test_missing_history_with_retained_event_is_not_recreated(tmp_path):
    with closing(connect(tmp_path / 'fox.sqlite3')) as connection:
        seed_legacy(connection)
        with connection:
            connection.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
                               ('system-source-history', 'source_history_initialized', 'schema-v1', 2))
        before = {name: rows(connection, name) for name in ('projects', 'sources', 'runs', 'events')}
        with pytest.raises(source_history.SourceHistoryError):
            with connection:
                storage.initialize_schema(connection)
        assert {name: rows(connection, name) for name in before} == before
        assert not (tables(connection) & HISTORY_TABLES)


@pytest.mark.parametrize('verification_enabled', [False, True])
def test_application_calls_shared_initializer_and_keeps_verification_separate(tmp_path, monkeypatch, verification_enabled):
    # conftest.py isolates the application's existing default-object import.
    from fox import app as application
    monkeypatch.setenv('FOX_VERIFICATION_ENABLED', '1' if verification_enabled else '0')
    if verification_enabled:
        monkeypatch.setenv('FOX_VERIFIER_RELEASE_SHA256', 'e' * 64)
    else:
        monkeypatch.delenv('FOX_VERIFIER_RELEASE_SHA256', raising=False)
    calls = []
    def observed(connection):
        calls.append((connection.row_factory, connection.execute('PRAGMA foreign_keys').fetchone()[0]))
        return storage.initialize_schema(connection)
    monkeypatch.setattr(application, 'initialize_storage_schema', observed)
    root = tmp_path / 'app'
    application.create_app(root, enable_worker=False)
    assert calls == [(sqlite3.Row, 1)]
    with closing(connect(root / 'fox.sqlite3')) as connection:
        assert ('verification_queue' in tables(connection)) is verification_enabled
        assert ('verification_operator_contact' in tables(connection)) is verification_enabled
        assert len(rows(connection, 'events')) == 1
