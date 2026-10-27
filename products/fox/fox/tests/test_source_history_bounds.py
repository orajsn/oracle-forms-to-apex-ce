"""Synthetic bounded-output tests for the canonical source-history store."""
from contextlib import contextmanager
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import zipfile

import pytest

from fox import source_history as history, intake

CANONICAL_PACKAGE = Path(__file__).resolve().parents[1] / 'fox'
assert Path(history.__file__).resolve() == CANONICAL_PACKAGE / 'source_history.py'
assert Path(intake.__file__).resolve() == CANONICAL_PACKAGE / 'intake.py'

SCHEMA = '''
CREATE TABLE projects(id TEXT PRIMARY KEY,owner TEXT NOT NULL,customer TEXT NOT NULL,name TEXT NOT NULL,description TEXT NOT NULL,created REAL NOT NULL);
CREATE TABLE sources(id TEXT PRIMARY KEY,project TEXT NOT NULL REFERENCES projects(id),name TEXT NOT NULL,sha256 TEXT NOT NULL,bytes INTEGER NOT NULL,text TEXT NOT NULL,created REAL NOT NULL,UNIQUE(project,name,sha256));
CREATE TABLE runs(id TEXT PRIMARY KEY,project TEXT NOT NULL REFERENCES projects(id),source_hash TEXT NOT NULL,state TEXT NOT NULL,message TEXT NOT NULL,created REAL NOT NULL,updated REAL NOT NULL,artifact TEXT,UNIQUE(project,source_hash));
CREATE TABLE events(id INTEGER PRIMARY KEY,owner TEXT NOT NULL,action TEXT NOT NULL,object_id TEXT NOT NULL,created REAL NOT NULL);
'''


@contextmanager
def transaction(c):
    c.execute('BEGIN IMMEDIATE')
    try:
        yield c
    except BaseException:
        c.rollback()
        raise
    else:
        c.commit()


def connection():
    c = sqlite3.connect(':memory:')
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    c.executescript(SCHEMA)
    return c


def source(name='a.txt', raw=b'synthetic\r\n'):
    return intake.checked_source(name, raw)


def add_project(c, pid='p', owner='alice'):
    c.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)', (pid, owner, 'Synthetic', 'Bounds', '', 1))


@pytest.fixture
def db():
    c = connection()
    with transaction(c):
        add_project(c)
        history.initialize(c)
    yield c
    c.close()


def upload(c, files, pid='p', owner='alice', now=10):
    with transaction(c):
        return history.publish_upload(c, pid, files, now, owner)['source_set']


@pytest.fixture
def large_set(db):
    # Five genuine helper transactions, each within the application's existing
    # 50-file upload limit. The resulting full set genuinely has 201 members.
    for start in range(0, 201, 50):
        head = upload(db, [source(f'file-{i:04}.txt', b'x') for i in range(start, min(start + 50, 201))], now=10 + start)
    return head


def state(c):
    return {table: [tuple(row) for row in c.execute(f'SELECT * FROM {table} ORDER BY rowid')]
            for table in ('sources', 'source_sets', 'source_set_members', 'project_source_selection', 'events')}


def add_run(c, sid, run_id='run-1', pid='p'):
    head = history.source_set_metadata(c, pid, sid)
    c.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)', (run_id, pid, head['source_hash'], 'DRAFTED', 'synthetic', 1, 1, None))


def test_constants_are_exact_production_byte_caps():
    assert history.MAX_RETAINED_BYTES == 104_857_600
    assert history.MAX_EXPORT_MANIFEST_BYTES == 2_097_152
    assert history.MAX_EXPORT_ARCHIVE_BYTES == 113_246_208 == 108 * 1024 * 1024


def test_large_metadata_is_complete_counts_without_file_list(db, large_set):
    before = state(db)
    metadata = history.source_set_metadata(db, 'p', large_set['id'])
    assert set(metadata) == {'id', 'source_hash', 'file_count', 'source_bytes', 'created', 'origin', 'is_selected', 'run_ids', 'selected_source_set_id'}
    assert metadata['file_count'] == metadata['source_bytes'] == 201
    assert 'files' not in metadata and 'text' not in metadata
    assert len(json.dumps(metadata).encode()) < 1024
    assert state(db) == before and not db.in_transaction


def test_actual_201_member_set_pages_without_omissions_duplicates_or_mutations(db, large_set):
    before_state = state(db)
    cursor, seen, offsets = None, [], []
    while True:
        page = history.source_set_page(db, 'p', large_set['id'], after=cursor)
        assert set(page) == {'selected_source_set_id', 'source_set', 'files', 'files_page'}
        assert set(page['source_set']) == {'id', 'source_hash', 'file_count', 'source_bytes', 'created', 'origin', 'is_selected', 'run_ids'}
        assert set(page['files_page']) == {'offset', 'limit', 'total', 'next_cursor'}
        assert page['selected_source_set_id'] == large_set['id']
        assert page['source_set']['source_hash'] == large_set['source_hash']
        assert page['source_set']['file_count'] == page['files_page']['total'] == 201
        assert page['files_page']['limit'] == 50 and 1 <= len(page['files']) <= 50
        assert all(set(item) == {'id', 'name', 'sha256', 'bytes'} for item in page['files'])
        offsets.append(page['files_page']['offset'])
        seen.extend(page['files'])
        cursor = page['files_page']['next_cursor']
        if cursor is None:
            break
        assert cursor == page['files'][-1]['id']
    assert offsets == [0, 50, 100, 150, 200]
    assert [item['name'] for item in seen] == [f'file-{i:04}.txt' for i in range(201)]
    assert len({item['id'] for item in seen}) == 201
    assert state(db) == before_state and not db.in_transaction


def test_last_exact_member_cursor_returns_empty_terminal_page(db, large_set):
    last = history.source_set_detail(db, 'p', large_set['id'])['files'][-1]['id']
    page = history.source_set_page(db, 'p', large_set['id'], after=last)
    assert page['files'] == []
    assert page['files_page'] == {'offset': 201, 'limit': 50, 'total': 201, 'next_cursor': None}


@pytest.mark.parametrize('limit', [1, 7, 49, 50])
def test_valid_requested_page_size(db, large_set, limit):
    page = history.source_set_page(db, 'p', large_set['id'], limit=limit)
    assert len(page['files']) == limit
    assert page['files_page']['limit'] == limit


@pytest.mark.parametrize('limit', [0, -1, 51, 100, True, False, 1.0, '50', None])
def test_invalid_page_sizes_rejected(db, limit):
    head = upload(db, [source()])
    with pytest.raises(history.SourceHistoryInputError):
        history.source_set_page(db, 'p', head['id'], limit=limit)


def test_unicode_scalar_filename_order_matches_complete_hash_order(db):
    names = ['z.txt', 'A.txt', 'é.txt', 'e\u0301.txt', '\ue000.txt', '\U00010000.txt', 'Ω.txt', 'a.txt']
    head = upload(db, [source(name) for name in reversed(names)])
    cursor, actual = None, []
    while True:
        page = history.source_set_page(db, 'p', head['id'], after=cursor, limit=3)
        actual.extend(item['name'] for item in page['files'])
        cursor = page['files_page']['next_cursor']
        if cursor is None:
            break
    assert actual == sorted(names)
    joined = '\n'.join(item['name'] + ':' + item['sha256'] for item in sorted(head['files'], key=lambda item: item['name']))
    assert hashlib.sha256(joined.encode()).hexdigest() == head['source_hash']


@pytest.mark.parametrize('cursor', ['', 'missing', 'x' * 129, 'x\n', 'x\x7f', True, 1, [], {}])
def test_missing_or_malformed_file_cursor_is_not_found(db, cursor):
    head = upload(db, [source()])
    with pytest.raises(history.SourceHistoryNotFound):
        history.source_set_page(db, 'p', head['id'], after=cursor)


def test_cursor_must_belong_to_exact_requested_version(db):
    a = upload(db, [source('a.txt', b'old')])
    b = upload(db, [source('a.txt', b'new'), source('b.txt')], now=20)
    for head, cursor in ((a, b['files'][0]['id']), (a, b['files'][1]['id']), (b, a['files'][0]['id'])):
        with pytest.raises(history.SourceHistoryNotFound):
            history.source_set_page(db, 'p', head['id'], after=cursor)


def test_shared_unchanged_member_is_valid_cursor_in_each_set_that_contains_it(db):
    a = upload(db, [source('a.txt')])
    b = upload(db, [source('b.txt')], now=20)
    cursor = a['files'][0]['id']
    assert history.source_set_page(db, 'p', a['id'], after=cursor)['files'] == []
    assert [item['name'] for item in history.source_set_page(db, 'p', b['id'], after=cursor)['files']] == ['b.txt']


def test_foreign_project_set_and_member_cursor_are_not_found(db):
    own = upload(db, [source()])
    with transaction(db):
        add_project(db, 'other', 'bob')
        history.create_project_selection(db, 'other', 1)
    foreign = upload(db, [source()], pid='other', owner='bob')
    for call in (
        lambda: history.source_set_page(db, 'p', foreign['id']),
        lambda: history.source_set_metadata(db, 'p', foreign['id']),
        lambda: history.source_set_page(db, 'p', own['id'], after=foreign['files'][0]['id']),
    ):
        with pytest.raises(history.SourceHistoryNotFound):
            call()


@pytest.mark.parametrize('operation', ['metadata', 'page'])
def test_off_page_member_corruption_rejected_before_small_response(db, large_set, operation):
    last = large_set['files'][-1]['id']
    with transaction(db):
        db.execute('UPDATE sources SET text=? WHERE id=?', ('changed', last))
    call = history.source_set_metadata if operation == 'metadata' else history.source_set_page
    with pytest.raises(history.SourceHistoryError):
        call(db, 'p', large_set['id'])


@pytest.mark.parametrize('run_id', ['x', 'opaque run/id:with punctuation', 'r' * 128, 'é'])
def test_valid_opaque_run_id_preserved_without_truncation(db, run_id):
    head = upload(db, [source()])
    with transaction(db):
        add_run(db, head['id'], run_id)
    assert history.source_set_metadata(db, 'p', head['id'])['run_ids'] == [run_id]
    assert history.source_set_page(db, 'p', head['id'])['source_set']['run_ids'] == [run_id]


@pytest.mark.parametrize('run_id', ['', 'r' * 129, 'run\n', 'run\r', 'run\t', 'run\x00', 'run\x7f', b'blob-run-id', None])
def test_invalid_stored_run_id_fails_all_metadata_outputs(db, run_id):
    head = upload(db, [source()])
    with transaction(db):
        add_run(db, head['id'], run_id)
    for call in (
        lambda: history.source_set_metadata(db, 'p', head['id']),
        lambda: history.source_set_page(db, 'p', head['id']),
        lambda: history.source_set_detail(db, 'p', head['id']),
        lambda: history.list_source_sets(db, 'p'),
    ):
        with pytest.raises(history.SourceHistoryError, match='unavailable or inconsistent'):
            call()


def test_multiple_run_ids_are_integrity_error_not_truncated(db):
    head = upload(db, [source()])
    with transaction(db):
        db.execute('ALTER TABLE runs RENAME TO corrupt_runs_old')
        db.execute('CREATE TABLE runs(id TEXT,project TEXT,source_hash TEXT,created REAL)')
        for run_id in ('run-a', 'run-b', 'run-c'):
            db.execute('INSERT INTO runs VALUES(?,?,?,?)', (run_id, 'p', head['source_hash'], 1))
    with pytest.raises(history.SourceHistoryError):
        history.source_set_metadata(db, 'p', head['id'])


def test_export_exact_utf8_bom_crlf_and_manifest_bytes(db):
    raws = {'é.txt': b'\xef\xbb\xbfline\r\n', 'b.txt': b'line\n'}
    head = upload(db, [source(name, raw) for name, raw in raws.items()])
    before = state(db)
    raw_zip = history.export_source_set(db, 'p', head['id'])
    with zipfile.ZipFile(io.BytesIO(raw_zip)) as archive:
        assert set(archive.namelist()) == set(raws) | {'fox-source-set.json'}
        for name, raw in raws.items():
            assert archive.read(name) == raw
        manifest = archive.read('fox-source-set.json')
        assert len(manifest) > len(manifest.decode('utf-8'))
        value = json.loads(manifest)
        assert value['source_hash'] == head['source_hash']
        assert set(value) == {'format', 'schema_version', 'source_set_id', 'source_hash', 'files'}
    assert raw_zip == history.export_source_set(db, 'p', head['id'])
    assert before == state(db)


@pytest.mark.parametrize('delta,allowed', [(0, True), (-1, False)])
def test_manifest_bound_uses_exact_encoded_bytes_and_never_truncates(db, monkeypatch, delta, allowed):
    head = upload(db, [source('é.txt', b'\xef\xbb\xbftext\r\n')])
    raw_zip = history.export_source_set(db, 'p', head['id'])
    with zipfile.ZipFile(io.BytesIO(raw_zip)) as archive:
        size = len(archive.read('fox-source-set.json'))
    before = state(db)
    monkeypatch.setattr(history, 'MAX_EXPORT_MANIFEST_BYTES', size + delta)
    if allowed:
        assert history.export_source_set(db, 'p', head['id']) == raw_zip
    else:
        with pytest.raises(history.SourceHistoryExportTooLarge) as error:
            history.export_source_set(db, 'p', head['id'])
        assert str(error.value) == 'Source history export exceeds the supported size limit.'
    assert state(db) == before
    assert history.source_set_page(db, 'p', head['id'])['files_page']['total'] == 1


@pytest.mark.parametrize('delta,allowed', [(0, True), (-1, False), (-30, False)])
def test_archive_complete_byte_bound_includes_central_directory(db, monkeypatch, delta, allowed):
    head = upload(db, [source('a.txt'), source('b.txt')])
    raw_zip = history.export_source_set(db, 'p', head['id'])
    before = state(db)
    monkeypatch.setattr(history, 'MAX_EXPORT_ARCHIVE_BYTES', len(raw_zip) + delta)
    if allowed:
        assert history.export_source_set(db, 'p', head['id']) == raw_zip
    else:
        with pytest.raises(history.SourceHistoryExportTooLarge) as error:
            history.export_source_set(db, 'p', head['id'])
        assert str(error.value) == 'Source history export exceeds the supported size limit.'
    assert state(db) == before
    assert history.source_set_metadata(db, 'p', head['id'])['file_count'] == 2


def test_archive_buffer_rejects_growth_at_write_time():
    buffer = history._BoundedArchive(3)
    assert buffer.write(b'abc') == 3
    with pytest.raises(history.SourceHistoryExportTooLarge):
        buffer.write(b'd')
    assert buffer.getvalue() == b'abc'
    buffer.seek(0)
    assert buffer.write(b'xy') == 2
    assert buffer.getvalue() == b'xyc'


def test_incremental_manifest_encoding_is_canonical_and_has_bounded_growth(monkeypatch):
    value = {'files': [{'name': 'é.txt', 'sha256': 'a' * 64, 'bytes': 1}], 'schema_version': 1}
    expected = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()
    assert history._encode_export_manifest(value) == expected
    observed = []
    original = history._BoundedArchive
    class TrackingBuffer(original):
        def write(self, data):
            try:
                return super().write(data)
            finally:
                observed.append(self.getbuffer().nbytes)
    monkeypatch.setattr(history, '_BoundedArchive', TrackingBuffer)
    monkeypatch.setattr(history, 'MAX_EXPORT_MANIFEST_BYTES', 50)
    with pytest.raises(history.SourceHistoryExportTooLarge):
        history._encode_export_manifest(value)
    assert observed and max(observed) <= 50


def test_export_does_not_materialize_json_with_dumps(db, monkeypatch):
    head = upload(db, [source()])
    def forbidden_dumps(*args, **kwargs):
        raise AssertionError('Monolithic JSON encoding must not be used.')
    monkeypatch.setattr(history.json, 'dumps', forbidden_dumps)
    raw = history.export_source_set(db, 'p', head['id'])
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        assert json.loads(archive.read('fox-source-set.json'))['source_set_id'] == head['id']


def test_real_large_metadata_exceeds_production_manifest_limit_without_losing_page_access():
    c = connection()
    digest = hashlib.sha256(b'x').hexdigest()
    with transaction(c):
        add_project(c)
        # Actual retained fixture: metadata dominates the 9 KB of source text.
        # No limit monkeypatch, fake counts, or omitted source rows are used.
        rows = [(f'legacy-{i:05}', 'p', f'f{i:05}-' + 'a' * 150 + '.txt', digest, 1, 'x', 1)
                for i in range(9000)]
        c.executemany('INSERT INTO sources VALUES(?,?,?,?,?,?,?)', rows)
        history.initialize(c)
    sid = history.selected_source_set_id(c, 'p')
    assert history.source_set_metadata(c, 'p', sid)['file_count'] == 9000
    files = history.source_set_detail(c, 'p', sid)['files']
    actual_manifest = {'format': 'FOX-SOURCE-SET', 'schema_version': 1, 'source_set_id': sid,
                       'source_hash': history.source_set_metadata(c, 'p', sid)['source_hash'],
                       'files': [{key: item[key] for key in ('name', 'sha256', 'bytes')} for item in files]}
    assert len(json.dumps(actual_manifest, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()) > history.MAX_EXPORT_MANIFEST_BYTES
    before = state(c)
    with pytest.raises(history.SourceHistoryExportTooLarge):
        history.export_source_set(c, 'p', sid)
    assert state(c) == before
    first = history.source_set_page(c, 'p', sid)
    second = history.source_set_page(c, 'p', sid, after=first['files_page']['next_cursor'])
    assert len(first['files']) == len(second['files']) == 50
    assert second['files_page']['offset'] == 50 and second['files_page']['total'] == 9000
    assert first['files'][-1]['name'] < second['files'][0]['name']
    c.close()


def test_previous_mutation_and_detail_contracts_remain_available(db):
    first = upload(db, [source('a.txt')])
    second = upload(db, [source('b.txt')], now=20)
    assert set(second) == {'id', 'source_hash', 'file_count', 'source_bytes', 'created', 'origin', 'is_selected', 'run_ids', 'selected_source_set_id', 'files'}
    with transaction(db):
        excluded = history.exclude_sources(db, 'p', second['id'], [second['files'][1]['id']], second['id'], 30, 'alice')
    assert excluded['source_set']['id'] == first['id'] and excluded['reused']
    with transaction(db):
        assert history.select_source_set(db, 'p', second['id'], first['id'], 40, 'alice')
    third = upload(db, [source('c.txt')], now=50)
    assert third['file_count'] == 3
    assert history.source_set_detail(db, 'p', second['id'])['file_count'] == 2
