"""Inert backend schema references and read-only local storage validation.

Import creates no connection, directory, database or worker. The reference is
built only when explicitly requested, using the real shared initializers on an
in-memory SQLite connection. A reference is not an installation receipt.

Validation never initializes, repairs, adopts or migrates the supplied store.
The caller owns its read-only connection, coherent transaction, work bounds and
filesystem/identity checks. These helpers grant no admission, retry, deployment,
Oracle access or business-acceptance authority.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import math
import re
import sqlite3

from . import storage, verification_queue, verification_recovery, verification_runtime


_ID = re.compile(r'fst-[a-f0-9]{32}\Z')
_SHA = re.compile(r'[a-f0-9]{64}\Z')
_IDENTIFIER = re.compile(r'[A-Za-z_][A-Za-z0-9_]*\Z')


class BackendStorageError(RuntimeError):
    """Closed diagnostics only; never private rows, paths or SQLite errors."""


def _need(condition, code):
    if not condition:
        raise BackendStorageError(code)


def _canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                       allow_nan=False) + '\n').encode('utf-8')


def schema(connection: sqlite3.Connection) -> dict:
    """Read bounded SQLite metadata as name -> [type, table, SQL]."""
    try:
        rows = connection.execute(
            'SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY name LIMIT 257').fetchall()
        _need(len(rows) <= 256 and all(type(kind) is str and type(name) is str and type(table) is str
              and (sql is None or type(sql) is str) and len(name) <= 128 and len(table) <= 128
              and (sql is None or len(sql) <= 65536) for kind, name, table, sql in rows),
              'BACKEND_SCHEMA_OBSERVATION_BOUND')
        result = {name: [kind, table, sql] for kind, name, table, sql in rows}
        _need(len(result) == len(rows) and len(_canonical(result)) <= 2_000_000,
              'BACKEND_SCHEMA_OBSERVATION_BOUND')
        return result
    except (sqlite3.Error, UnicodeError):
        raise BackendStorageError('BACKEND_STORAGE_UNAVAILABLE') from None


def _table_counts(connection, observed):
    counts = {}
    for name, item in observed.items():
        if item[0] != 'table':
            continue
        _need(_IDENTIFIER.fullmatch(name) is not None, 'BACKEND_SCHEMA_IDENTIFIER_INVALID')
        count = connection.execute('SELECT COUNT(*) FROM "' + name + '"').fetchone()[0]
        _need(type(count) is int and count >= 0, 'BACKEND_TABLE_COUNT_INVALID')
        counts[name] = count
    return counts


def _reference_backend():
    """A disposable SQLite reference, never a persisted storage identity."""
    with closing(sqlite3.connect(':memory:')) as connection, connection:
        connection.execute('PRAGMA foreign_keys=ON')
        storage.initialize_schema(connection)
        connection.execute(storage.IDENTITY_SQL)
        # Only an in-memory reference row, to measure the real baseline counts.
        # This value is neither returned as an identity nor saved as a receipt.
        connection.execute('INSERT INTO fox_storage_identity VALUES(1,?,?)',
                           ('fst-' + '0' * 32, '0' * 64))
        verification_queue.initialize_schema(connection)
        verification_runtime.initialize_contact_schema(connection)
        verification_recovery.initialize_schema(connection)
        observed = schema(connection)
        return observed, _table_counts(connection, observed)


def expected_backend_schema() -> dict:
    """Return a new real in-memory base/identity/queue/contact/recovery schema."""
    return _reference_backend()[0]


def expected_backend_counts() -> dict:
    """Measure the initial reference counts, including its initialization row."""
    return _reference_backend()[1]


def _initial_counts(connection, observed, expected, expected_counts):
    _need(observed == expected, 'BACKEND_INITIAL_SCHEMA_CHANGED')
    counts = _table_counts(connection, observed)
    _need(counts == expected_counts, 'BACKEND_INITIAL_STATE_NOT_EMPTY')
    events = connection.execute('SELECT owner,action,object_id,created FROM events LIMIT 2').fetchall()
    _need(len(events) == 1 and tuple(events[0][:3]) ==
          ('system-source-history', 'source_history_initialized', 'schema-v1')
          and type(events[0][3]) in (int, float) and math.isfinite(events[0][3])
          and events[0][3] >= 0, 'BACKEND_INITIALIZATION_EVENT_CHANGED')
    return counts


def initial_counts(connection: sqlite3.Connection) -> dict:
    """Read and require genuine initial state; never clear existing rows."""
    try:
        expected, counts = _reference_backend()
        return _initial_counts(connection, schema(connection), expected, counts)
    except sqlite3.Error:
        raise BackendStorageError('BACKEND_STORAGE_UNAVAILABLE') from None


def validate_backend_storage(connection: sqlite3.Connection, *, installation_id: str,
                             plan_sha256: str, require_empty: bool = False) -> dict:
    """Read required schema and identity, optionally requiring initial state.

    Normal restarts permit later tables/indexes, such as technical verification
    records, without pretending that their contents have been verified here.
    Extra triggers on baseline-owned tables are forbidden. Required definitions
    and append-only fences must remain exact. Normal queue/recovery record and
    retained-proof validation remain the responsibility of their existing gates.

    ``backend_schema_sha256`` hashes the validated required schema, not optional
    later tables or mutable database bytes. ``initial_counts`` is None unless
    the caller explicitly requires the initial empty business state.
    """
    _need(type(installation_id) is str and _ID.fullmatch(installation_id) is not None
          and type(plan_sha256) is str and _SHA.fullmatch(plan_sha256) is not None,
          'BACKEND_IDENTITY_BINDING_INVALID')
    _need(type(require_empty) is bool, 'BACKEND_EMPTY_FLAG_INVALID')
    try:
        expected, expected_counts = _reference_backend()
        observed = schema(connection)
        _need(all(observed.get(name) == definition for name, definition in expected.items()),
              'BACKEND_SCHEMA_CHANGED')
        tables = {name for name, item in expected.items() if item[0] == 'table'}
        _need(not any(name not in expected and item[0] == 'trigger' and item[1] in tables
                      for name, item in observed.items()), 'BACKEND_UNREVIEWED_TRIGGER')
        # The independent recovery reader also enforces its closed trigger set.
        verification_recovery.VerificationRecovery.validate_schema(connection)
        identities = connection.execute(
            'SELECT singleton,installation_id,plan_sha256 FROM fox_storage_identity LIMIT 2').fetchall()
        _need([tuple(row) for row in identities] == [(1, installation_id, plan_sha256)],
              'BACKEND_STORAGE_IDENTITY_CHANGED')
        counts = (_initial_counts(connection, observed, expected, expected_counts)
                  if require_empty else None)
        return {'schema': observed,
                'backend_schema_sha256': hashlib.sha256(_canonical(expected)).hexdigest(),
                'initial_counts': counts}
    except verification_recovery.RecoveryError:
        raise BackendStorageError('BACKEND_RECOVERY_SCHEMA_CHANGED') from None
    except sqlite3.Error:
        raise BackendStorageError('BACKEND_STORAGE_UNAVAILABLE') from None
