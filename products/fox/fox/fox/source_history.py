"""Immutable complete readable-source sets; no inference, network or commits.

Every mutation requires a caller-owned transaction (BEGIN IMMEDIATE for the
SQLite application). Authorization belongs to the caller; mutation methods also
match the supplied owner to the project. Reads always filter by project.

History is an integrity mechanism, not proof of redaction or Oracle extraction.
"""
from __future__ import annotations

import hashlib
import io
import json
import math
import re
import sqlite3
import time
import uuid
import zipfile

from .intake import ALLOWED, MAX_FILE_BYTES, checked_source

MAX_RETAINED_BYTES = 100 * 1024 * 1024
MAX_EXPORT_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_EXPORT_ARCHIVE_BYTES = 113_246_208  # 108 MiB, including ZIP metadata.
EXPORT_MANIFEST_NAME = 'fox-source-set.json'
_TABLES = {'source_sets', 'source_set_members', 'project_source_selection'}
_OWNER_UNSET = object()
_BAD = 'Source history is unavailable or inconsistent.'
_RESERVED = {'CON', 'PRN', 'AUX', 'NUL',
             *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10))}


class SourceHistoryError(ValueError):
    """Bounded diagnostic safe for an operator or API response."""


class SourceHistoryConflict(SourceHistoryError):
    """An optimistic source selection did not match the current pointer."""


class SourceHistoryNotFound(SourceHistoryError):
    """A requested project-scoped source set does not exist."""


class SourceHistoryInputError(SourceHistoryError):
    """The requested operation is invalid or exceeds retained-source limits."""


class SourceHistoryExportTooLarge(SourceHistoryError):
    """A complete export cannot fit the supported manifest or archive bound."""


def _export_too_large() -> None:
    raise SourceHistoryExportTooLarge('Source history export exceeds the supported size limit.')


def _fail() -> None:
    raise SourceHistoryError(_BAD)


def _rows(c: sqlite3.Connection, sql: str, params=()) -> list[dict]:
    cursor = c.execute(sql, params)
    keys = [item[0] for item in cursor.description]
    return [dict(zip(keys, row)) for row in cursor.fetchall()]


def _one(c: sqlite3.Connection, sql: str, params=()) -> dict | None:
    rows = _rows(c, sql, params)
    if len(rows) > 1:
        _fail()
    return rows[0] if rows else None


def _transaction(c: sqlite3.Connection) -> None:
    if not c.in_transaction:
        raise SourceHistoryError('Source history writes require a caller-owned transaction.')


def _now(now: float) -> float:
    if type(now) not in (int, float) or not math.isfinite(now) or now < 0:
        _fail()
    return float(now)


def _project(c: sqlite3.Connection, pid: str, owner: object = _OWNER_UNSET) -> dict:
    if type(pid) is not str or not pid:
        _fail()
    project = _one(c, 'SELECT id,owner FROM projects WHERE id=?', (pid,))
    if project is None or (owner is not _OWNER_UNSET and (type(owner) is not str or owner != project['owner'])):
        raise SourceHistoryNotFound('Source history was not found.')
    return project


def _set_id(sid: str) -> str:
    if type(sid) is not str or not re.fullmatch(r'ss-[a-f0-9]{32}', sid):
        raise SourceHistoryNotFound('Source set was not found.')
    return sid


def _hash(files: list[dict]) -> str:
    joined = '\n'.join(item['name'] + ':' + item['sha256'] for item in sorted(files, key=lambda item: item['name']))
    return hashlib.sha256(joined.encode('utf-8')).hexdigest()


def readable_source_bytes(entry: dict) -> bytes:
    """Recover only exact UTF-8 or BOM+UTF-8 bytes; never normalize newlines."""
    if (type(entry) is not dict or type(entry.get('text')) is not str
            or len(entry['text']) > MAX_FILE_BYTES
            or type(entry.get('sha256')) is not str
            or not re.fullmatch(r'[a-f0-9]{64}', entry['sha256'])
            or type(entry.get('bytes')) is not int or not 1 <= entry['bytes'] <= MAX_FILE_BYTES):
        _fail()
    try:
        raw = entry['text'].encode('utf-8', errors='strict')
    except UnicodeError:
        raise SourceHistoryError(_BAD) from None
    for candidate in (raw, b'\xef\xbb\xbf' + raw):
        if len(candidate) == entry['bytes'] and hashlib.sha256(candidate).hexdigest() == entry['sha256']:
            return candidate
    _fail()


def _checked(entry: dict) -> dict:
    raw = readable_source_bytes(entry)
    try:
        verified = checked_source(entry.get('name'), raw)
    except (ValueError, TypeError, AttributeError):
        raise SourceHistoryError(_BAD) from None
    if any(verified[key] != entry.get(key) for key in ('name', 'sha256', 'bytes', 'text')):
        _fail()
    return verified


def _selection(c: sqlite3.Connection, pid: str) -> dict:
    _project(c, pid)
    value = _one(c, 'SELECT project,current_source_set_id,updated FROM project_source_selection WHERE project=?', (pid,))
    if value is None:
        _fail()
    _now(value['updated'])
    return value


def _load_set(c: sqlite3.Connection, pid: str, sid: str) -> tuple[dict, list[dict]]:
    _set_id(sid)
    head = _one(c, 'SELECT id,project,source_hash,file_count,source_bytes,created,origin FROM source_sets WHERE id=? AND project=?', (sid, pid))
    if head is None:
        raise SourceHistoryNotFound('Source set was not found.')
    _now(head['created'])
    if (head['origin'] not in ('upload', 'legacy-current', 'exclude')
            or type(head['file_count']) is not int or head['file_count'] < 1
            or type(head['source_bytes']) is not int or not 1 <= head['source_bytes'] <= MAX_RETAINED_BYTES):
        _fail()
    members = _rows(c, '''SELECT m.source_id AS member_source_id,m.name AS member_name,
        m.sha256 AS member_sha256,m.bytes AS member_bytes,
        s.id,s.project,s.name,s.sha256,s.bytes,s.text,s.created
        FROM source_set_members m LEFT JOIN sources s ON s.id=m.source_id
        WHERE m.source_set_id=? ORDER BY m.name''', (sid,))
    files, names = [], set()
    for member in members:
        if (type(member['id']) is not str or not 1 <= len(member['id']) <= 128
                or any(ord(char) < 32 or ord(char) == 127 for char in member['id'])
                or member['project'] != pid
                or any(member[key] != member['member_' + key] for key in ('name', 'sha256', 'bytes'))
                or member['id'] != member['member_source_id'] or member['name'] in names):
            _fail()
        names.add(member['name'])
        source = {key: member[key] for key in ('id', 'project', 'name', 'sha256', 'bytes', 'text', 'created')}
        _checked(source)
        _now(source['created'])
        files.append(source)
    if (len(files) != head['file_count'] or sum(item['bytes'] for item in files) != head['source_bytes']
            or _hash(files) != head['source_hash']):
        _fail()
    return head, files


def selected_sources(c: sqlite3.Connection, pid: str) -> list[dict]:
    """Return one verified complete set; never fall back to latest source rows."""
    selection = _selection(c, pid)
    sid = selection['current_source_set_id']
    if sid is None:
        # A null pointer is legitimate only before the project's first upload.
        if (c.execute('SELECT 1 FROM sources WHERE project=? LIMIT 1', (pid,)).fetchone()
                or c.execute('SELECT 1 FROM source_sets WHERE project=? LIMIT 1', (pid,)).fetchone()):
            _fail()
        return []
    try:
        return _load_set(c, pid, sid)[1]
    except SourceHistoryNotFound:
        raise SourceHistoryError(_BAD) from None


def selected_source_set_id(c: sqlite3.Connection, pid: str) -> str | None:
    selected_sources(c, pid)
    return _selection(c, pid)['current_source_set_id']


def source_set_sources(c: sqlite3.Connection, pid: str, sid: str) -> list[dict]:
    selected_sources(c, pid)
    return _load_set(c, pid, sid)[1]


def _new_set(c: sqlite3.Connection, pid: str, files: list[dict], now: float, origin: str) -> tuple[str, bool]:
    for item in files:
        if (type(item.get('id')) is not str or not 1 <= len(item['id']) <= 128
                or any(ord(char) < 32 or ord(char) == 127 for char in item['id'])
                or item.get('project') != pid):
            _fail()
        _now(item['created'])
    digest = _hash(files)
    old = _one(c, 'SELECT id FROM source_sets WHERE project=? AND source_hash=?', (pid, digest))
    if old:
        _, existing = _load_set(c, pid, old['id'])
        expected = [{key: item[key] for key in ('id', 'name', 'sha256', 'bytes')} for item in files]
        actual = [{key: item[key] for key in ('id', 'name', 'sha256', 'bytes')} for item in existing]
        if sorted(expected, key=lambda item: item['name']) != actual:
            _fail()
        return old['id'], True
    sid = 'ss-' + uuid.uuid4().hex
    c.execute('INSERT INTO source_sets(id,project,source_hash,file_count,source_bytes,created,origin) VALUES(?,?,?,?,?,?,?)',
              (sid, pid, digest, len(files), sum(item['bytes'] for item in files), now, origin))
    for item in sorted(files, key=lambda item: item['name']):
        c.execute('INSERT INTO source_set_members(source_set_id,source_id,name,sha256,bytes) VALUES(?,?,?,?,?)',
                  (sid, item['id'], item['name'], item['sha256'], item['bytes']))
    return sid, False


_SCHEMA = (
    '''CREATE TABLE source_sets(id TEXT PRIMARY KEY,project TEXT NOT NULL REFERENCES projects(id),
       source_hash TEXT NOT NULL,file_count INTEGER NOT NULL CHECK(file_count>0),
       source_bytes INTEGER NOT NULL CHECK(source_bytes>0 AND source_bytes<=104857600),
       created REAL NOT NULL,origin TEXT NOT NULL CHECK(origin IN ('upload','legacy-current','exclude')),
       UNIQUE(project,source_hash))''',
    '''CREATE TABLE source_set_members(source_set_id TEXT NOT NULL REFERENCES source_sets(id),
       source_id TEXT NOT NULL REFERENCES sources(id),name TEXT NOT NULL,sha256 TEXT NOT NULL,
       bytes INTEGER NOT NULL CHECK(bytes>0),PRIMARY KEY(source_set_id,name),
       UNIQUE(source_set_id,source_id))''',
    '''CREATE TABLE project_source_selection(project TEXT PRIMARY KEY REFERENCES projects(id),
       current_source_set_id TEXT REFERENCES source_sets(id),updated REAL NOT NULL)''',
    '''CREATE TRIGGER source_sets_no_update BEFORE UPDATE ON source_sets
       BEGIN SELECT RAISE(ABORT,'Source sets are immutable.'); END''',
    '''CREATE TRIGGER source_sets_no_delete BEFORE DELETE ON source_sets
       BEGIN SELECT RAISE(ABORT,'Source sets are immutable.'); END''',
    '''CREATE TRIGGER source_set_members_no_update BEFORE UPDATE ON source_set_members
       BEGIN SELECT RAISE(ABORT,'Source set membership is immutable.'); END''',
    '''CREATE TRIGGER source_set_members_no_delete BEFORE DELETE ON source_set_members
       BEGIN SELECT RAISE(ABORT,'Source set membership is immutable.'); END''',
    '''CREATE TRIGGER source_set_members_insert_guard BEFORE INSERT ON source_set_members
       BEGIN
       SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM source_sets h JOIN sources s ON s.project=h.project
           WHERE h.id=NEW.source_set_id AND s.id=NEW.source_id AND s.name=NEW.name
             AND s.sha256=NEW.sha256 AND s.bytes=NEW.bytes)
         THEN RAISE(ABORT,'Invalid source set membership.') END;
       SELECT CASE WHEN (SELECT COUNT(*) FROM source_set_members WHERE source_set_id=NEW.source_set_id)
           >=(SELECT file_count FROM source_sets WHERE id=NEW.source_set_id)
         THEN RAISE(ABORT,'Source set membership is complete.') END;
       END''',
    '''CREATE TRIGGER source_selection_insert_guard BEFORE INSERT ON project_source_selection
       WHEN NEW.current_source_set_id IS NOT NULL AND NOT EXISTS(
           SELECT 1 FROM source_sets WHERE id=NEW.current_source_set_id AND project=NEW.project)
       BEGIN SELECT RAISE(ABORT,'Invalid project source selection.'); END''',
    '''CREATE TRIGGER source_selection_update_guard BEFORE UPDATE ON project_source_selection
       WHEN NEW.current_source_set_id IS NOT NULL AND NOT EXISTS(
           SELECT 1 FROM source_sets WHERE id=NEW.current_source_set_id AND project=NEW.project)
       BEGIN SELECT RAISE(ABORT,'Invalid project source selection.'); END''',
)


def initialize(c: sqlite3.Connection) -> None:
    """Migrate once inside caller BEGIN IMMEDIATE, with one truthful baseline.

    Existing tables mean initialization has already occurred. Missing/broken
    selections then fail closed instead of manufacturing a new legacy baseline.
    """
    _transaction(c)
    existing = {row['name'] for row in _rows(c, "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('source_sets','source_set_members','project_source_selection')")}
    if existing and existing != _TABLES:
        _fail()
    if existing:
        if not c.execute("SELECT 1 FROM events WHERE action='source_history_initialized' AND owner='system-source-history' AND object_id='schema-v1' LIMIT 1").fetchone():
            _fail()
        required = {re.search(r'CREATE TRIGGER (\w+)', sql)[1]
                    for sql in _SCHEMA if sql.startswith('CREATE TRIGGER')}
        installed = {row['name'] for row in _rows(c, "SELECT name FROM sqlite_master WHERE type='trigger'")}
        if not required.issubset(installed):
            _fail()
        for project in _rows(c, 'SELECT id FROM projects'):
            selected_sources(c, project['id'])
        return
    # History events survive accidental table loss. Do not reinterpret that
    # damage as a first migration and silently rebuild from global MAX(rowid).
    if c.execute("SELECT 1 FROM events WHERE action IN ('source_history_initialized','source_set_uploaded','source_set_selected','source_set_excluded') LIMIT 1").fetchone():
        _fail()
    for statement in _SCHEMA:
        c.execute(statement)
    now = time.time()
    for project in _rows(c, 'SELECT id FROM projects ORDER BY id'):
        pid = project['id']
        retained = _rows(c, 'SELECT bytes FROM sources WHERE project=?', (pid,))
        if any(type(item['bytes']) is not int or item['bytes'] < 1 for item in retained) or sum(item['bytes'] for item in retained) > MAX_RETAINED_BYTES:
            _fail()
        files = _rows(c, '''SELECT s.id,s.project,s.name,s.sha256,s.bytes,s.text,s.created
            FROM sources s WHERE s.project=? AND s.rowid=(SELECT MAX(newer.rowid)
            FROM sources newer WHERE newer.project=s.project AND newer.name=s.name) ORDER BY s.name''', (pid,))
        for item in files:
            _checked(item)
            _now(item['created'])
        sid = _new_set(c, pid, files, now, 'legacy-current')[0] if files else None
        c.execute('INSERT INTO project_source_selection(project,current_source_set_id,updated) VALUES(?,?,?)', (pid, sid, now))
    c.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
              ('system-source-history', 'source_history_initialized', 'schema-v1', now))


def create_project_selection(c: sqlite3.Connection, pid: str, now: float) -> None:
    """Register a newly created empty project in its creation transaction."""
    _transaction(c)
    _project(c, pid)
    now = _now(now)
    if c.execute('SELECT 1 FROM project_source_selection WHERE project=?', (pid,)).fetchone():
        selected_sources(c, pid)
        return
    if (c.execute('SELECT 1 FROM sources WHERE project=? LIMIT 1', (pid,)).fetchone()
            or c.execute('SELECT 1 FROM source_sets WHERE project=? LIMIT 1', (pid,)).fetchone()):
        _fail()
    c.execute('INSERT INTO project_source_selection(project,current_source_set_id,updated) VALUES(?,?,?)', (pid, None, now))


def _metadata(c: sqlite3.Connection, head: dict, selected: str | None) -> dict:
    result = {key: head[key] for key in ('id', 'source_hash', 'file_count', 'source_bytes', 'created', 'origin')}
    result['is_selected'] = head['id'] == selected
    # The runs table is unique by project/hash. Fetch two to detect corruption,
    # not truncate it into a seemingly valid public response.
    run_ids = [row['id'] for row in _rows(c, 'SELECT id FROM runs WHERE project=? AND source_hash=? ORDER BY created,id LIMIT 2', (head['project'], head['source_hash']))]
    if (len(run_ids) > 1 or any(type(value) is not str or not 1 <= len(value) <= 128
                              or any(ord(char) < 32 or ord(char) == 127 for char in value)
                              for value in run_ids)):
        _fail()
    result['run_ids'] = run_ids
    return result


def list_source_sets(c: sqlite3.Connection, pid: str, before: str | None = None, limit: int = 50) -> dict:
    selected_sources(c, pid)
    if type(limit) is not int or not 1 <= limit <= 100:
        raise SourceHistoryInputError('Source history page size must be between 1 and 100.')
    selected = _selection(c, pid)['current_source_set_id']
    cursor_clause, params = '', [pid]
    if before is not None:
        cursor, _ = _load_set(c, pid, before)
        cursor_clause = ' AND (created<? OR (created=? AND id<?))'
        params.extend((cursor['created'], cursor['created'], cursor['id']))
    params.append(limit + 1)
    page = _rows(c, 'SELECT id FROM source_sets WHERE project=?' + cursor_clause + ' ORDER BY created DESC,id DESC LIMIT ?', params)
    result = []
    for item in page[:limit]:
        head, _ = _load_set(c, pid, item['id'])
        result.append(_metadata(c, head, selected))
    return {'selected_source_set_id': selected, 'source_sets': result,
            'next_cursor': page[limit - 1]['id'] if len(page) > limit else None}


def source_set_detail(c: sqlite3.Connection, pid: str, sid: str) -> dict:
    selected_sources(c, pid)
    head, files = _load_set(c, pid, sid)
    selected = _selection(c, pid)['current_source_set_id']
    return {**_metadata(c, head, selected), 'selected_source_set_id': selected,
            'files': [{key: item[key] for key in ('id', 'name', 'sha256', 'bytes')} for item in files]}


def source_set_metadata(c: sqlite3.Connection, pid: str, sid: str) -> dict:
    """Verified complete-set identity and counts, without a file list."""
    selected_sources(c, pid)
    head, _ = _load_set(c, pid, sid)
    selected = _selection(c, pid)['current_source_set_id']
    return {**_metadata(c, head, selected), 'selected_source_set_id': selected}


def source_set_page(c: sqlite3.Connection, pid: str, sid: str,
                    after: str | None = None, limit: int = 50) -> dict:
    """Return at most 50 members after an exact ID from this complete set.

    Full-set integrity is checked on the server before any page is returned.
    A page is not the complete source manifest or a client-side hash proof.
    """
    selected_sources(c, pid)
    head, complete = _load_set(c, pid, sid)
    if type(limit) is not int or not 1 <= limit <= 50:
        raise SourceHistoryInputError('Source file page size must be between 1 and 50.')
    complete = sorted(complete, key=lambda item: item['name'])
    offset = 0
    if after is not None:
        if (type(after) is not str or not 1 <= len(after) <= 128
                or any(ord(char) < 32 or ord(char) == 127 for char in after)):
            raise SourceHistoryNotFound('Source file cursor was not found.')
        positions = [index for index, item in enumerate(complete) if item['id'] == after]
        if len(positions) != 1:
            raise SourceHistoryNotFound('Source file cursor was not found.')
        offset = positions[0] + 1
    page = complete[offset:offset + limit]
    selected = _selection(c, pid)['current_source_set_id']
    return {
        'selected_source_set_id': selected,
        'source_set': _metadata(c, head, selected),
        'files': [{key: item[key] for key in ('id', 'name', 'sha256', 'bytes')} for item in page],
        'files_page': {'offset': offset, 'limit': limit, 'total': head['file_count'],
                       'next_cursor': page[-1]['id'] if offset + len(page) < len(complete) else None},
    }


def _audit(c: sqlite3.Connection, owner: str, action: str, sid: str, now: float) -> None:
    c.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)', (owner, action, sid, now))


def publish_upload(c: sqlite3.Connection, pid: str, checked: list[dict], now: float, owner: str) -> dict:
    """Merge exact-name replacements into the selected set, retaining all rows."""
    _transaction(c)
    _project(c, pid, owner)
    now = _now(now)
    current = selected_sources(c, pid)
    previous = _selection(c, pid)['current_source_set_id']
    if type(checked) is not list or not checked:
        _fail()
    uploaded, names = [], set()
    for item in checked:
        value = _checked(item)
        if value['name'] in names:
            _fail()
        names.add(value['name'])
        uploaded.append(value)
    retained = _rows(c, 'SELECT bytes FROM sources WHERE project=?', (pid,))
    if any(type(item['bytes']) is not int or item['bytes'] < 1 for item in retained):
        _fail()
    retained_total = sum(item['bytes'] for item in retained)
    chosen, insertions = {}, []
    for item in uploaded:
        row = _one(c, 'SELECT id,project,name,sha256,bytes,text,created FROM sources WHERE project=? AND name=? AND sha256=?', (pid, item['name'], item['sha256']))
        if row:
            _checked(row)
            if any(row[key] != item[key] for key in ('name', 'sha256', 'bytes', 'text')):
                _fail()
        else:
            row = {**item, 'id': uuid.uuid4().hex, 'project': pid, 'created': now}
            insertions.append(row)
            retained_total += row['bytes']
        chosen[row['name']] = row
    if retained_total > MAX_RETAINED_BYTES:
        raise SourceHistoryInputError('Project source history limit is 100 MB.')
    for row in insertions:
        c.execute('INSERT INTO sources(id,project,name,sha256,bytes,text,created) VALUES(?,?,?,?,?,?,?)',
                  tuple(row[key] for key in ('id', 'project', 'name', 'sha256', 'bytes', 'text', 'created')))
    merged = {item['name']: item for item in current}
    merged.update(chosen)
    sid, reused = _new_set(c, pid, list(merged.values()), now, 'upload')
    changed = previous != sid
    if changed:
        c.execute('UPDATE project_source_selection SET current_source_set_id=?,updated=? WHERE project=?', (sid, now, pid))
    _audit(c, owner, 'source_set_uploaded', sid, now)
    return {'source_set': source_set_detail(c, pid, sid), 'changed': changed, 'reused': reused}


def select_source_set(c: sqlite3.Connection, pid: str, sid: str, expected_current_id: str | None,
                      now: float, owner: str) -> bool:
    """Explicit optimistic selection; runs, approvals and source rows are untouched."""
    _transaction(c)
    _project(c, pid, owner)
    now = _now(now)
    _set_id(sid)
    if expected_current_id is not None:
        _set_id(expected_current_id)
    selected_sources(c, pid)
    _load_set(c, pid, sid)
    current = _selection(c, pid)['current_source_set_id']
    if current != expected_current_id:
        raise SourceHistoryConflict('Source selection changed. Refresh and retry.')
    if current == sid:
        return False
    c.execute('UPDATE project_source_selection SET current_source_set_id=?,updated=? WHERE project=?', (sid, now, pid))
    _audit(c, owner, 'source_set_selected', sid, now)
    return True


def exclude_sources(c: sqlite3.Connection, pid: str, sid: str, excluded_file_ids: list[str],
                    expected_current_id: str | None, now: float, owner: str) -> dict:
    """Select a new complete set without the named members; delete nothing."""
    _transaction(c)
    _project(c, pid, owner)
    now = _now(now)
    _set_id(sid)
    if expected_current_id is not None:
        _set_id(expected_current_id)
    current = selected_sources(c, pid)
    _load_set(c, pid, sid)
    previous = _selection(c, pid)['current_source_set_id']
    if previous != expected_current_id or sid != previous:
        raise SourceHistoryConflict('Source selection changed. Refresh and retry.')
    if (type(excluded_file_ids) is not list or not 1 <= len(excluded_file_ids) <= 50
            or any(type(value) is not str or not 1 <= len(value) <= 128
                   or any(ord(char) < 32 or ord(char) == 127 for char in value)
                   for value in excluded_file_ids)
            or len(set(excluded_file_ids)) != len(excluded_file_ids)):
        raise SourceHistoryInputError('Select between 1 and 50 distinct source files to exclude.')
    excluded = set(excluded_file_ids)
    if not excluded.issubset({item['id'] for item in current}):
        raise SourceHistoryInputError('An excluded file does not belong to the selected source set.')
    kept = [item for item in current if item['id'] not in excluded]
    if not kept:
        raise SourceHistoryInputError('Keep at least one source file, or upload a replacement first.')
    new_sid, reused = _new_set(c, pid, kept, now, 'exclude')
    c.execute('UPDATE project_source_selection SET current_source_set_id=?,updated=? WHERE project=?', (new_sid, now, pid))
    _audit(c, owner, 'source_set_excluded', new_sid, now)
    return {'source_set': source_set_detail(c, pid, new_sid), 'changed': previous != new_sid, 'reused': reused}


def _export_name(name: str) -> None:
    # Export names are basename-only on Windows and POSIX. Retain valid legacy
    # names in history even if they cannot safely be emitted in a portable ZIP.
    if (type(name) is not str or not name or len(name) > 180
            or name.endswith((' ', '.')) or name in ('.', '..') or '..' in name
            or any(char in name for char in '/\\:<>"|?*')
            or any(ord(char) < 32 or ord(char) == 127 for char in name)
            or name.split('.')[0].rstrip(' .').upper() in _RESERVED
            or name.casefold() == EXPORT_MANIFEST_NAME.casefold()
            or '.' not in name or '.' + name.rsplit('.', 1)[1].lower() not in ALLOWED):
        raise SourceHistoryError('This source set contains filenames that cannot be exported safely.')


class _BoundedArchive(io.BytesIO):
    """Refuse output growth beyond a byte bound, including ZIP finalization."""

    def __init__(self, limit: int):
        super().__init__()
        self.limit = limit

    def write(self, data):
        if self.tell() + len(data) > self.limit:
            _export_too_large()
        return super().write(data)


def _encode_export_manifest(manifest: dict) -> bytes:
    """Emit canonical UTF-8 incrementally; never build an unbounded JSON blob.

    Complete-set integrity and its metadata list still reside in memory. This
    bounds the encoded output, not the entire source-history calculation.
    """
    output = _BoundedArchive(MAX_EXPORT_MANIFEST_BYTES)
    encoder = json.JSONEncoder(sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
    for chunk in encoder.iterencode(manifest):
        output.write(chunk.encode('utf-8'))
    return output.getvalue()


def export_source_set(c: sqlite3.Connection, pid: str, sid: str) -> bytes:
    """Build a deterministic readable-only ZIP without mutating history."""
    selected_sources(c, pid)
    head, files = _load_set(c, pid, sid)
    seen = set()
    for item in files:
        _export_name(item['name'])
        if item['name'].casefold() in seen:
            raise SourceHistoryError('This source set contains filenames that cannot be exported safely.')
        seen.add(item['name'].casefold())
    manifest = {'format': 'FOX-SOURCE-SET', 'schema_version': 1,
                'source_set_id': sid, 'source_hash': head['source_hash'],
                'files': [{key: item[key] for key in ('name', 'sha256', 'bytes')} for item in files]}
    manifest_raw = _encode_export_manifest(manifest)
    result = _BoundedArchive(MAX_EXPORT_ARCHIVE_BYTES)
    with zipfile.ZipFile(result, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        def write_member(name, raw):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o100600 << 16
            archive.writestr(info, raw)
        for item in files:
            write_member(item['name'], readable_source_bytes(item))
        write_member(EXPORT_MANIFEST_NAME, manifest_raw)
    if result.getbuffer().nbytes > MAX_EXPORT_ARCHIVE_BYTES:
        _export_too_large()
    return result.getvalue()
