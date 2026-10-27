"""Explicit FOX base-schema and source-history initialization.

Importing this module creates no directory, database, connection or worker. The
caller supplies its chosen SQLite connection and owns its transaction context.
This preserves the application's existing initialize/migrate behavior; it is
not an emptiness check, a fresh-install attestation or permission to adopt data.
"""
from __future__ import annotations

import sqlite3

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
        CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY,project TEXT NOT NULL REFERENCES projects(id),source_hash TEXT NOT NULL,state TEXT NOT NULL,message TEXT NOT NULL,created REAL NOT NULL,updated REAL NOT NULL,artifact TEXT,UNIQUE(project,source_hash));
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,owner TEXT NOT NULL,action TEXT NOT NULL,object_id TEXT NOT NULL,created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS acceptances(run TEXT PRIMARY KEY REFERENCES runs(id),owner TEXT NOT NULL,source_hash TEXT NOT NULL,artifact_sha256 TEXT NOT NULL,notes TEXT NOT NULL,created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS prepared_uploads(id TEXT PRIMARY KEY,project TEXT NOT NULL REFERENCES projects(id),extraction_job_id TEXT NOT NULL,readable_source_hash TEXT NOT NULL,canonical_manifest_sha256 TEXT NOT NULL,manifest_json TEXT NOT NULL,created REAL NOT NULL,UNIQUE(project,canonical_manifest_sha256));
        '''


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
    connection.execute('BEGIN IMMEDIATE')
    source_history.initialize(connection)
