"""Explicit FOX base-schema and source-history initialization.

Importing this module creates no directory, database, connection or worker. The
caller supplies its chosen SQLite connection and owns its transaction context.
This preserves the application's existing initialize/migrate behavior; it is
not an emptiness check, a fresh-install attestation or permission to adopt data.
"""
from __future__ import annotations

import sqlite3
import re

from . import source_history


IDENTITY_SQL = '''CREATE TABLE fox_storage_identity(
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    installation_id TEXT NOT NULL, plan_sha256 TEXT NOT NULL)'''


BASE_SCHEMA_SQL = '''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS projects(id TEXT PRIMARY KEY,owner TEXT NOT NULL,customer TEXT NOT NULL,name TEXT NOT NULL,description TEXT NOT NULL,created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS sources(id TEXT PRIMARY KEY,project TEXT NOT NULL REFERENCES projects(id),name TEXT NOT NULL,sha256 TEXT NOT NULL,bytes INTEGER NOT NULL,text TEXT NOT NULL,created REAL NOT NULL,UNIQUE(project,name,sha256));
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,owner TEXT NOT NULL,expires REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS attempts(ip TEXT NOT NULL,created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY,project TEXT NOT NULL REFERENCES projects(id),source_hash TEXT NOT NULL,state TEXT NOT NULL,message TEXT NOT NULL,created REAL NOT NULL,updated REAL NOT NULL,artifact TEXT);
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,owner TEXT NOT NULL,action TEXT NOT NULL,object_id TEXT NOT NULL,created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS acceptances(run TEXT PRIMARY KEY REFERENCES runs(id),owner TEXT NOT NULL,source_hash TEXT NOT NULL,artifact_sha256 TEXT NOT NULL,notes TEXT NOT NULL,created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS prepared_uploads(id TEXT PRIMARY KEY,project TEXT NOT NULL REFERENCES projects(id),extraction_job_id TEXT NOT NULL,readable_source_hash TEXT NOT NULL,canonical_manifest_sha256 TEXT NOT NULL,manifest_json TEXT NOT NULL,created REAL NOT NULL,UNIQUE(project,canonical_manifest_sha256));
        CREATE TABLE IF NOT EXISTS source_redaction_receipts(project TEXT NOT NULL REFERENCES projects(id),name TEXT NOT NULL,sha256 TEXT NOT NULL,receipt_json TEXT NOT NULL,receipt_sha256 TEXT NOT NULL,owner TEXT NOT NULL,created REAL NOT NULL,PRIMARY KEY(project,name,sha256));
        CREATE TRIGGER IF NOT EXISTS source_redaction_receipts_no_update BEFORE UPDATE ON source_redaction_receipts BEGIN SELECT RAISE(ABORT,'Source redaction receipts are immutable'); END;
        CREATE TRIGGER IF NOT EXISTS source_redaction_receipts_no_delete BEFORE DELETE ON source_redaction_receipts BEGIN SELECT RAISE(ABORT,'Source redaction receipts are immutable'); END;
        '''


_RUN_BODY = ('id TEXT PRIMARY KEY,project TEXT NOT NULL REFERENCES projects(id),'
             'source_hash TEXT NOT NULL,state TEXT NOT NULL,message TEXT NOT NULL,'
             'created REAL NOT NULL,updated REAL NOT NULL,artifact TEXT')
_RUN_INDEX = 'runs_project_source_hash_idx'


def _runs_schema(connection):
    """Only the two known base schemas may enter this bounded migration."""
    def normalized(sql):
        return re.sub(r'\s+', '', sql or '').lower().replace('"', '')
    row = connection.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='runs'").fetchone()
    actual = normalized(row[0]) if row else ''
    current = normalized('CREATE TABLE runs(' + _RUN_BODY + ')')
    legacy = normalized('CREATE TABLE runs(' + _RUN_BODY + ',UNIQUE(project,source_hash))')
    if actual not in (current, legacy):
        raise ValueError('Unrecognized runs schema; no mapping-recovery migration was applied.')
    if connection.execute("SELECT 1 FROM sqlite_master WHERE type='trigger' AND tbl_name='runs'").fetchone():
        raise ValueError('Custom runs triggers require operator review before migration.')
    for index in connection.execute('PRAGMA index_list(runs)').fetchall():
        name, unique, origin = index[1], index[2], index[3]
        columns = tuple(row[2] for row in connection.execute('PRAGMA index_info("' + name.replace('"', '""') + '")'))
        if ((origin == 'pk' and unique == 1 and columns == ('id',))
                or (actual == legacy and origin == 'u' and unique == 1 and columns == ('project', 'source_hash'))
                or (name == _RUN_INDEX and unique == 0 and origin == 'c'
                    and columns == ('project', 'source_hash') and index[4] == 0)):
            continue
        raise ValueError('Custom runs indexes require operator review before migration.')
    return actual == legacy


def migrate_mapping_recovery_runs(connection):
    """Remove only the legacy source uniqueness constraint, retaining every row.

    Admission still serializes ordinary duplicate checks. A retry receives its
    own deterministic primary key, without changing source or project identity.
    No Oracle state is involved. Unexpected schema and failed checks roll back.
    """
    if connection.in_transaction:
        raise ValueError('Runs migration requires an explicit transaction boundary.')
    original_fk = connection.execute('PRAGMA foreign_keys').fetchone()[0]
    try:
        connection.execute('PRAGMA foreign_keys=OFF')
        connection.execute('BEGIN IMMEDIATE')
        legacy = _runs_schema(connection)
        if legacy:
            if connection.execute("SELECT 1 FROM sqlite_master WHERE name='runs_mapping_recovery_v1'").fetchone():
                raise ValueError('Retained runs migration storage requires operator reconciliation.')
            before = [tuple(row) for row in connection.execute('SELECT * FROM runs ORDER BY id')]
            connection.execute('CREATE TABLE runs_mapping_recovery_v1(' + _RUN_BODY + ')')
            connection.execute('INSERT INTO runs_mapping_recovery_v1 SELECT * FROM runs')
            copied = [tuple(row) for row in connection.execute('SELECT * FROM runs_mapping_recovery_v1 ORDER BY id')]
            if copied != before:
                raise ValueError('Runs migration row comparison failed.')
            connection.execute('DROP TABLE runs')
            connection.execute('ALTER TABLE runs_mapping_recovery_v1 RENAME TO runs')
            after = [tuple(row) for row in connection.execute('SELECT * FROM runs ORDER BY id')]
            if before != after:
                raise ValueError('Runs migration changed retained data.')
        connection.execute('CREATE INDEX IF NOT EXISTS ' + _RUN_INDEX + ' ON runs(project,source_hash)')
        if connection.execute('PRAGMA foreign_key_check').fetchone():
            raise ValueError('Runs migration foreign-key validation failed.')
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.execute('PRAGMA foreign_keys=' + ('ON' if original_fk else 'OFF'))


def initialize_schema(connection: sqlite3.Connection) -> None:
    """Initialize base tables and migrate/validate source history explicitly.

    Call before unrelated transaction work: ``executescript`` has SQLite's
    normal implicit-commit behavior. The source-history step opens a new
    ``BEGIN IMMEDIATE`` transaction; the caller must commit or roll it back,
    normally with ``with connection:`` as the application already does.

    Verification/recovery schemas remain separate explicit initialization.
    A fresh-bootstrap caller must establish its genuine new-root/empty-state
    authority before opening the connection and calling this function.
    """
    connection.executescript(BASE_SCHEMA_SQL)
    migrate_mapping_recovery_runs(connection)
    connection.execute('BEGIN IMMEDIATE')
    source_history.initialize(connection)
