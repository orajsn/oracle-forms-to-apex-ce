"""Synthetic SQLite behavior tests for the canonical source-history store."""
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
CREATE TABLE acceptances(run TEXT PRIMARY KEY REFERENCES runs(id),owner TEXT NOT NULL,source_hash TEXT NOT NULL,artifact_sha256 TEXT NOT NULL,notes TEXT NOT NULL,created REAL NOT NULL);
'''


def connection(path=':memory:'):
    c = sqlite3.connect(path, timeout=0.05)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    c.executescript(SCHEMA)
    return c


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


def project(c, pid='p', owner='alice'):
    c.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)', (pid, owner, 'Synthetic', 'Test', '', 1.0))


def source(name='a.txt', raw=b'first\r\n'):
    return intake.checked_source(name, raw)


def retained(c, sid, value, pid='p', created=2):
    c.execute('INSERT INTO sources VALUES(?,?,?,?,?,?,?)',
              (sid, pid, value['name'], value['sha256'], value['bytes'], value['text'], created))


@pytest.fixture
def db():
    c = connection()
    with transaction(c):
        project(c)
        history.initialize(c)
    yield c
    c.close()


def upload(c, files=None, pid='p', owner='alice', now=10):
    with transaction(c):
        return history.publish_upload(c, pid, files or [source()], now, owner)


def ids(c, table):
    return [tuple(row) for row in c.execute(f'SELECT * FROM {table} ORDER BY rowid')]


def test_empty_project_has_null_selection_and_no_fabricated_empty_set(db):
    assert history.selected_sources(db, 'p') == []
    assert history.selected_source_set_id(db, 'p') is None
    assert history.list_source_sets(db, 'p') == {'selected_source_set_id': None, 'source_sets': [], 'next_cursor': None}
    assert db.execute('SELECT COUNT(*) FROM source_sets').fetchone()[0] == 0
    assert not db.in_transaction


def test_new_project_registration_and_idempotent_initialize(db):
    with transaction(db):
        project(db, 'second', 'bob')
        history.create_project_selection(db, 'second', 20)
    before = ids(db, 'project_source_selection')
    with transaction(db):
        history.initialize(db)
        history.create_project_selection(db, 'second', 30)
    assert ids(db, 'project_source_selection') == before
    assert history.selected_sources(db, 'second') == []


def test_first_migration_backfills_only_actual_latest_per_name_not_subsets():
    c = connection()
    with transaction(c):
        project(c)
        retained(c, 'old-a', source('a.txt', b'old-a'), created=100)
        retained(c, 'only-b', source('b.txt', b'only-b'), created=1)
        retained(c, 'new-a', source('a.txt', b'new-a'), created=2)
        history.initialize(c)
    result = history.list_source_sets(c, 'p')
    assert len(result['source_sets']) == 1
    baseline = result['source_sets'][0]
    assert baseline['origin'] == 'legacy-current'
    assert baseline['file_count'] == 2
    assert [item['id'] for item in history.selected_sources(c, 'p')] == ['new-a', 'only-b']
    assert c.execute('SELECT COUNT(*) FROM sources').fetchone()[0] == 3
    with transaction(c):
        history.initialize(c)
    assert history.list_source_sets(c, 'p') == result
    c.close()


@pytest.mark.parametrize('sid', [b'opaque-blob-id', '', 'x' * 129, 'control\n'])
def test_legacy_migration_rejects_invalid_member_ids_before_baseline(sid):
    c = connection()
    with transaction(c):
        project(c)
        retained(c, sid, source())
    with pytest.raises(history.SourceHistoryError):
        with transaction(c):
            history.initialize(c)
    assert c.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='source_sets'").fetchone()[0] == 0
    assert c.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 0


def test_initialize_and_upload_do_not_commit_the_callers_transaction():
    c = connection()
    c.execute('BEGIN IMMEDIATE')
    project(c)
    history.initialize(c)
    assert c.in_transaction
    result = history.publish_upload(c, 'p', [source()], 2, 'alice')
    assert result['changed'] and c.in_transaction
    c.rollback()
    assert c.execute('SELECT COUNT(*) FROM projects').fetchone()[0] == 0
    assert c.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='source_sets'").fetchone()[0] == 0
    c.close()


@pytest.mark.parametrize('operation', ['initialize', 'create', 'upload', 'select', 'exclude'])
def test_mutations_require_caller_transaction(db, operation):
    sid = 'ss-' + 'a' * 32
    call = {
        'initialize': lambda: history.initialize(db),
        'create': lambda: history.create_project_selection(db, 'p', 1),
        'upload': lambda: history.publish_upload(db, 'p', [source()], 1, 'alice'),
        'select': lambda: history.select_source_set(db, 'p', sid, None, 1, 'alice'),
        'exclude': lambda: history.exclude_sources(db, 'p', sid, ['x'], None, 1, 'alice'),
    }[operation]
    with pytest.raises(history.SourceHistoryError, match='caller-owned'):
        call()


def test_complete_sets_append_replace_select_then_branch_from_selected(db):
    a = upload(db, [source('a.txt', b'a1'), source('b.txt', b'b1')])['source_set']
    b = upload(db, [source('a.txt', b'a2'), source('new.txt', b'new')], now=20)['source_set']
    assert [item['name'] for item in b['files']] == ['a.txt', 'b.txt', 'new.txt']
    with transaction(db):
        assert history.select_source_set(db, 'p', a['id'], b['id'], 30, 'alice') is True
    c = upload(db, [source('c.txt', b'c1')], now=40)['source_set']
    rows = history.source_set_sources(db, 'p', c['id'])
    assert [(item['name'], item['text']) for item in rows] == [('a.txt', 'a1'), ('b.txt', 'b1'), ('c.txt', 'c1')]
    assert len(history.source_set_sources(db, 'p', b['id'])) == 3
    assert c['id'] not in {a['id'], b['id']}
    assert c['origin'] == 'upload'
    assert db.execute('SELECT COUNT(*) FROM sources').fetchone()[0] == 5


def test_deduped_old_raw_can_restore_complete_existing_set(db):
    old = upload(db, [source('a.txt', b'old')], now=10)['source_set']
    new = upload(db, [source('a.txt', b'new')], now=20)['source_set']
    restored = upload(db, [source('a.txt', b'old')], now=30)
    assert restored['reused'] is True and restored['changed'] is True
    assert restored['source_set']['id'] == old['id']
    assert restored['source_set']['created'] == old['created']
    assert restored['source_set']['origin'] == old['origin']
    assert history.selected_sources(db, 'p')[0]['text'] == 'old'
    assert db.execute('SELECT COUNT(*) FROM sources').fetchone()[0] == 2
    assert db.execute('SELECT COUNT(*) FROM source_sets').fetchone()[0] == 2
    with transaction(db):
        assert history.select_source_set(db, 'p', new['id'], old['id'], 40, 'alice')
    assert history.selected_sources(db, 'p')[0]['text'] == 'new'


def test_identical_upload_reuses_immutable_set_and_pointer_time(db):
    first = upload(db, now=10)
    pointer = ids(db, 'project_source_selection')
    sets, members, sources = ids(db, 'source_sets'), ids(db, 'source_set_members'), ids(db, 'sources')
    second = upload(db, now=20)
    assert second['source_set']['id'] == first['source_set']['id']
    assert second['changed'] is False and second['reused'] is True
    assert ids(db, 'project_source_selection') == pointer
    assert ids(db, 'source_sets') == sets and ids(db, 'source_set_members') == members and ids(db, 'sources') == sources
    assert [row['action'] for row in db.execute('SELECT action FROM events')] == ['source_history_initialized', 'source_set_uploaded', 'source_set_uploaded']


def test_select_unchanged_has_no_event_or_timestamp_mutation(db):
    sid = upload(db)['source_set']['id']
    events, pointer = ids(db, 'events'), ids(db, 'project_source_selection')
    with transaction(db):
        assert history.select_source_set(db, 'p', sid, sid, 99, 'alice') is False
    assert ids(db, 'events') == events and ids(db, 'project_source_selection') == pointer


def test_selection_optimistic_conflict_leaves_history_unchanged(db):
    a = upload(db)['source_set']['id']
    b = upload(db, [source('a.txt', b'changed')], now=20)['source_set']['id']
    before = ids(db, 'events')
    with pytest.raises(history.SourceHistoryConflict):
        with transaction(db):
            history.select_source_set(db, 'p', a, a, 30, 'alice')
    assert history.selected_source_set_id(db, 'p') == b
    assert ids(db, 'events') == before


def test_membership_and_header_are_sqlite_immutable(db):
    sid = upload(db)['source_set']['id']
    statements = [
        ('UPDATE source_sets SET origin=? WHERE id=?', ('legacy-current', sid)),
        ('DELETE FROM source_sets WHERE id=?', (sid,)),
        ('UPDATE source_set_members SET name=? WHERE source_set_id=?', ('other.txt', sid)),
        ('DELETE FROM source_set_members WHERE source_set_id=?', (sid,)),
    ]
    for sql, params in statements:
        with pytest.raises(sqlite3.IntegrityError):
            with transaction(db):
                db.execute(sql, params)
    with transaction(db):
        retained(db, 'extra', source('extra.txt'))
    with pytest.raises(sqlite3.IntegrityError):
        with transaction(db):
            file = source('extra.txt')
            db.execute('INSERT INTO source_set_members VALUES(?,?,?,?,?)', (sid, 'extra', file['name'], file['sha256'], file['bytes']))


@pytest.mark.parametrize('change', ['text', 'name', 'sha256', 'bytes', 'project', 'missing_pointer', 'null_pointer', 'bad_pointer', 'member', 'count', 'hash'])
def test_tampering_fails_closed_without_global_latest_fallback(db, change):
    first = upload(db)['source_set']
    file_id = first['files'][0]['id']
    with transaction(db):
        if change in {'text', 'name', 'sha256', 'bytes', 'project'}:
            values = {'text': 'changed', 'name': 'renamed.txt', 'sha256': '0' * 64, 'bytes': 1, 'project': 'other'}
            if change == 'project':
                project(db, 'other')
            db.execute(f'UPDATE sources SET {change}=? WHERE id=?', (values[change], file_id))
        elif change == 'missing_pointer':
            db.execute('DELETE FROM project_source_selection WHERE project=?', ('p',))
        elif change == 'null_pointer':
            db.execute('UPDATE project_source_selection SET current_source_set_id=NULL WHERE project=?', ('p',))
        elif change == 'bad_pointer':
            db.execute('DROP TRIGGER source_selection_update_guard')
            db.execute('PRAGMA defer_foreign_keys=ON')
            # Keep FK valid but select a set from another project.
            project(db, 'other')
            history.create_project_selection(db, 'other', 1)
            other = history.publish_upload(db, 'other', [source()], 2, 'alice')['source_set']['id']
            db.execute('UPDATE project_source_selection SET current_source_set_id=? WHERE project=?', (other, 'p'))
        elif change == 'member':
            db.execute('DROP TRIGGER source_set_members_no_delete')
            db.execute('DELETE FROM source_set_members WHERE source_set_id=?', (first['id'],))
        else:
            db.execute('DROP TRIGGER source_sets_no_update')
            field, value = ('file_count', 2) if change == 'count' else ('source_hash', '0' * 64)
            db.execute(f'UPDATE source_sets SET {field}=? WHERE id=?', (value, first['id']))
    with pytest.raises(history.SourceHistoryError):
        history.selected_sources(db, 'p')
    with pytest.raises(history.SourceHistoryError):
        history.list_source_sets(db, 'p')
    with pytest.raises(history.SourceHistoryError):
        with transaction(db):
            history.initialize(db)


def test_partial_schema_is_not_repaired_as_legacy():
    c = connection()
    with transaction(c):
        project(c)
        c.execute('CREATE TABLE source_sets(id TEXT)')
    with pytest.raises(history.SourceHistoryError):
        with transaction(c):
            history.initialize(c)
    assert c.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='project_source_selection'").fetchone()[0] == 0


def test_missing_immutability_trigger_fails_reinitialization(db):
    with transaction(db):
        db.execute('DROP TRIGGER source_sets_no_update')
    with pytest.raises(history.SourceHistoryError):
        with transaction(db):
            history.initialize(db)


@pytest.mark.parametrize('with_upload', [False, True])
def test_all_history_tables_lost_does_not_rebaseline_existing_sources(db, with_upload):
    if with_upload:
        upload(db)
        upload(db, [source('a.txt', b'new')])
    with transaction(db):
        db.execute('DROP TABLE project_source_selection')
        db.execute('DROP TABLE source_set_members')
        db.execute('DROP TABLE source_sets')
    before = (ids(db, 'sources'), ids(db, 'events'))
    with pytest.raises(history.SourceHistoryError):
        with transaction(db):
            history.initialize(db)
    assert before == (ids(db, 'sources'), ids(db, 'events'))
    assert db.execute("SELECT COUNT(*) FROM sqlite_master WHERE name IN ('source_sets','source_set_members','project_source_selection')").fetchone()[0] == 0


@pytest.mark.parametrize('action', ['source_history_initialized', 'source_set_uploaded', 'source_set_selected', 'source_set_excluded'])
def test_prior_history_event_prevents_false_first_migration(action):
    c = connection()
    with transaction(c):
        project(c)
        retained(c, 'legacy', source())
        c.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)', ('alice', action, 'old', 1))
    with pytest.raises(history.SourceHistoryError):
        with transaction(c):
            history.initialize(c)
    assert c.execute("SELECT COUNT(*) FROM sqlite_master WHERE name='source_sets'").fetchone()[0] == 0


def test_missing_initialization_marker_fails_existing_schema(db):
    with transaction(db):
        db.execute("DELETE FROM events WHERE action='source_history_initialized'")
    with pytest.raises(history.SourceHistoryError):
        with transaction(db):
            history.initialize(db)


def test_current_set_missing_registration_does_not_get_backfilled(db):
    with transaction(db):
        project(db, 'forgotten')
        retained(db, 'forgotten-source', source(), 'forgotten')
    with pytest.raises(history.SourceHistoryError):
        with transaction(db):
            history.initialize(db)
    with pytest.raises(history.SourceHistoryError):
        with transaction(db):
            history.create_project_selection(db, 'forgotten', 10)


@pytest.mark.parametrize('operation', ['detail', 'sources', 'select', 'export', 'cursor'])
def test_project_scoped_reads_and_ids_cannot_cross_projects(db, operation):
    with transaction(db):
        project(db, 'other', 'bob')
        history.create_project_selection(db, 'other', 1)
    own = upload(db)['source_set']['id']
    foreign = upload(db, pid='other', owner='bob')['source_set']['id']
    call = {
        'detail': lambda: history.source_set_detail(db, 'p', foreign),
        'sources': lambda: history.source_set_sources(db, 'p', foreign),
        'select': lambda: history.select_source_set(db, 'p', foreign, own, 30, 'alice'),
        'export': lambda: history.export_source_set(db, 'p', foreign),
        'cursor': lambda: history.list_source_sets(db, 'p', before=foreign),
    }[operation]
    with pytest.raises(history.SourceHistoryNotFound):
        with transaction(db):
            call()
    assert history.selected_source_set_id(db, 'p') == own


@pytest.mark.parametrize('owner', ['bob', '', None, True])
def test_mutation_owner_mismatch_rejected_before_any_write(db, owner):
    with pytest.raises(history.SourceHistoryNotFound):
        with transaction(db):
            history.publish_upload(db, 'p', [source()], 10, owner)
    assert history.selected_sources(db, 'p') == []
    assert db.execute('SELECT COUNT(*) FROM sources').fetchone()[0] == 0


def test_run_and_approval_rows_never_changed_or_inherited(db):
    a = upload(db)['source_set']
    with transaction(db):
        db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)', ('run-a', 'p', a['source_hash'], 'ACCEPTED', 'synthetic', 1, 1, 'package.zip'))
        db.execute('INSERT INTO acceptances VALUES(?,?,?,?,?,?)', ('run-a', 'alice', a['source_hash'], 'a' * 64, 'synthetic', 1))
    before = (ids(db, 'runs'), ids(db, 'acceptances'))
    b = upload(db, [source('b.txt', b'b')], now=20)['source_set']
    assert history.source_set_detail(db, 'p', a['id'])['run_ids'] == ['run-a']
    assert b['run_ids'] == []
    with transaction(db):
        history.select_source_set(db, 'p', a['id'], b['id'], 30, 'alice')
    assert (ids(db, 'runs'), ids(db, 'acceptances')) == before


def test_metadata_does_not_expose_source_text_or_private_source_fields(db):
    sid = upload(db)['source_set']['id']
    listing = history.list_source_sets(db, 'p')['source_sets'][0]
    assert set(listing) == {'id', 'source_hash', 'file_count', 'source_bytes', 'created', 'origin', 'is_selected', 'run_ids'}
    detail = history.source_set_detail(db, 'p', sid)
    assert set(detail) == set(listing) | {'files', 'selected_source_set_id'}
    assert set(detail['files'][0]) == {'id', 'name', 'sha256', 'bytes'}
    assert 'text' not in json.dumps(detail) and 'alice' not in json.dumps(detail)


def test_zip_preserves_exact_original_utf8_bom_crlf_and_is_deterministic(db):
    raws = {'a.txt': b'plain\n', 'b.txt': b'\xef\xbb\xbfbom\r\n',
            'c.txt': 'unicode é\r\n'.encode(), 'd.xml': b'\xef\xbb\xbf<Module/>\r\n'}
    head = upload(db, [source(name, raw) for name, raw in raws.items()])['source_set']
    before = (ids(db, 'sources'), ids(db, 'source_sets'), ids(db, 'events'))
    raw_zip = history.export_source_set(db, 'p', head['id'])
    assert raw_zip == history.export_source_set(db, 'p', head['id'])
    with zipfile.ZipFile(io.BytesIO(raw_zip)) as archive:
        assert set(archive.namelist()) == set(raws) | {'fox-source-set.json'}
        for name, raw in raws.items():
            assert archive.read(name) == raw
        manifest = json.loads(archive.read('fox-source-set.json'))
        assert set(manifest) == {'format', 'schema_version', 'source_set_id', 'source_hash', 'files'}
        assert manifest['format'] == 'FOX-SOURCE-SET' and manifest['schema_version'] == 1
        assert manifest['source_set_id'] == head['id'] and manifest['source_hash'] == head['source_hash']
        assert all(set(item) == {'name', 'sha256', 'bytes'} for item in manifest['files'])
        assert all(item['sha256'] == hashlib.sha256(raws[item['name']]).hexdigest() for item in manifest['files'])
    assert before == (ids(db, 'sources'), ids(db, 'source_sets'), ids(db, 'events'))


def test_historical_zip_does_not_change_after_later_upload(db):
    a = upload(db)['source_set']['id']
    original = history.export_source_set(db, 'p', a)
    upload(db, [source('a.txt', b'replacement'), source('extra.txt', b'new')])
    assert history.export_source_set(db, 'p', a) == original


@pytest.mark.parametrize('name', ['CON.txt', 'nul.SQL', 'a?.txt', 'a*.txt', 'a|b.txt', 'a<b.txt', 'a\"b.txt'])
def test_legacy_intake_names_retained_but_unsafe_export_fails(db, name):
    sid = upload(db, [source(name)])['source_set']['id']
    assert history.selected_sources(db, 'p')[0]['name'] == name
    with pytest.raises(history.SourceHistoryError, match='filenames'):
        history.export_source_set(db, 'p', sid)


def test_case_sensitive_history_retained_but_ambiguous_zip_fails(db):
    sid = upload(db, [source('A.txt'), source('a.txt')])['source_set']['id']
    assert len(history.selected_sources(db, 'p')) == 2
    with pytest.raises(history.SourceHistoryError, match='filenames'):
        history.export_source_set(db, 'p', sid)


def test_dedupe_bytes_charged_only_for_new_retained_rows(db, monkeypatch):
    monkeypatch.setattr(history, 'MAX_RETAINED_BYTES', 8)
    a = upload(db, [source('a.txt', b'aaaa')])['source_set']
    b = upload(db, [source('a.txt', b'bbbb')])['source_set']
    assert upload(db, [source('a.txt', b'aaaa')])['source_set']['id'] == a['id']
    before = (ids(db, 'sources'), ids(db, 'source_sets'), ids(db, 'events'))
    with pytest.raises(history.SourceHistoryInputError, match='100 MB'):
        upload(db, [source('a.txt', b'cccc')])
    assert before == (ids(db, 'sources'), ids(db, 'source_sets'), ids(db, 'events'))
    assert history.source_set_detail(db, 'p', b['id'])['source_bytes'] == 4


def test_same_content_different_names_are_retained_separately(db):
    sid = upload(db, [source('a.txt', b'same'), source('b.txt', b'same')])['source_set']
    assert sid['file_count'] == 2 and sid['source_bytes'] == 8
    assert len({item['id'] for item in sid['files']}) == 2


def test_no_new_fifty_file_full_set_limit(db):
    a = upload(db, [source(f'f{i:03}.txt', b'x') for i in range(50)])['source_set']
    b = upload(db, [source('more.txt', b'x')])['source_set']
    assert a['file_count'] == 50 and b['file_count'] == 51


def test_exclude_is_reversible_and_reuses_prior_complete_set(db):
    a = upload(db, [source('a.txt', b'a')])['source_set']
    b = upload(db, [source('b.txt', b'b')])['source_set']
    before_sources = ids(db, 'sources')
    file_id = next(item['id'] for item in b['files'] if item['name'] == 'b.txt')
    with transaction(db):
        result = history.exclude_sources(db, 'p', b['id'], [file_id], b['id'], 30, 'alice')
    assert result['reused'] and result['changed']
    assert result['source_set']['id'] == a['id'] and result['source_set']['origin'] == 'upload'
    assert ids(db, 'sources') == before_sources
    assert db.execute('SELECT action FROM events ORDER BY id DESC LIMIT 1').fetchone()[0] == 'source_set_excluded'
    with transaction(db):
        history.select_source_set(db, 'p', b['id'], a['id'], 40, 'alice')
    assert len(history.selected_sources(db, 'p')) == 2


def test_new_exclusion_revision_origin_and_immutable_members(db):
    original = upload(db, [source('a.txt'), source('b.txt'), source('c.txt')])['source_set']
    with transaction(db):
        result = history.exclude_sources(db, 'p', original['id'], [original['files'][1]['id']], original['id'], 20, 'alice')
    assert result['source_set']['origin'] == 'exclude' and result['reused'] is False
    assert [item['name'] for item in result['source_set']['files']] == ['a.txt', 'c.txt']
    assert len(history.source_set_sources(db, 'p', original['id'])) == 3


@pytest.mark.parametrize('bad', [[], ['unknown'], ['same', 'same'], [None], [''], ['x' * 129], ['x\n'], 'not-list', ['x'] * 51])
def test_invalid_exclusion_requests_have_input_error(db, bad):
    head = upload(db, [source('a.txt'), source('b.txt')])['source_set']
    before = (ids(db, 'source_sets'), ids(db, 'events'))
    with pytest.raises(history.SourceHistoryInputError):
        with transaction(db):
            history.exclude_sources(db, 'p', head['id'], bad, head['id'], 20, 'alice')
    assert before == (ids(db, 'source_sets'), ids(db, 'events'))


def test_excluding_all_members_requires_replacement_first(db):
    head = upload(db)['source_set']
    with pytest.raises(history.SourceHistoryInputError, match='replacement first'):
        with transaction(db):
            history.exclude_sources(db, 'p', head['id'], [head['files'][0]['id']], head['id'], 20, 'alice')


def test_exclude_requires_exact_current_and_expected_set(db):
    a = upload(db, [source('a.txt'), source('b.txt')])['source_set']
    b = upload(db, [source('a.txt', b'changed')])['source_set']
    for sid, expected in ((a['id'], a['id']), (a['id'], b['id']), (b['id'], a['id'])):
        with pytest.raises(history.SourceHistoryConflict):
            with transaction(db):
                history.exclude_sources(db, 'p', sid, [a['files'][1]['id']], expected, 30, 'alice')


@pytest.mark.parametrize('operation', ['select', 'exclude'])
@pytest.mark.parametrize('kind', ['missing', 'foreign'])
def test_requested_target_missing_or_foreign_is_not_found_before_stale_check(db, operation, kind):
    old = upload(db, [source('a.txt'), source('b.txt')])['source_set']
    upload(db, [source('a.txt', b'new')])
    sid = 'ss-' + 'a' * 32
    if kind == 'foreign':
        with transaction(db):
            project(db, 'other', 'bob')
            history.create_project_selection(db, 'other', 1)
        sid = upload(db, pid='other', owner='bob')['source_set']['id']
    with pytest.raises(history.SourceHistoryNotFound):
        with transaction(db):
            if operation == 'select':
                history.select_source_set(db, 'p', sid, old['id'], 30, 'alice')
            else:
                history.exclude_sources(db, 'p', sid, [old['files'][0]['id']], old['id'], 30, 'alice')


def test_exclusion_accepts_opaque_legacy_file_ids():
    c = connection()
    with transaction(c):
        project(c)
        retained(c, 'legacy:opaque/source id', source('a.txt'))
        retained(c, 'another id', source('b.txt'))
        history.initialize(c)
    sid = history.selected_source_set_id(c, 'p')
    with transaction(c):
        result = history.exclude_sources(c, 'p', sid, ['legacy:opaque/source id'], sid, 10, 'alice')
    assert result['source_set']['file_count'] == 1


def test_paginated_history_stable_equal_timestamp_order_and_all_pages(db):
    created = [upload(db, [source('a.txt', f'v{i}'.encode())], now=10)['source_set']['id'] for i in range(7)]
    seen, before = [], None
    while True:
        page = history.list_source_sets(db, 'p', before=before, limit=2)
        assert page['selected_source_set_id'] == created[-1]
        seen.extend(item['id'] for item in page['source_sets'])
        before = page['next_cursor']
        if before is None:
            break
    assert seen == sorted(created, reverse=True)
    assert len(set(seen)) == len(created)


@pytest.mark.parametrize('limit', [0, -1, 101, True, 1.0, '50', None])
def test_pagination_limit_validation(db, limit):
    with pytest.raises(history.SourceHistoryInputError):
        history.list_source_sets(db, 'p', limit=limit)


def test_missing_history_cursor_rejected(db):
    with pytest.raises(history.SourceHistoryNotFound):
        history.list_source_sets(db, 'p', before='ss-' + 'a' * 32)


def test_corrupt_nonselected_cursor_timestamp_fails_closed(db):
    old = upload(db, now=10)['source_set']['id']
    upload(db, [source('a.txt', b'new')], now=20)
    with transaction(db):
        db.execute('DROP TRIGGER source_sets_no_update')
        db.execute('UPDATE source_sets SET created=? WHERE id=?', (b'bad', old))
    with pytest.raises(history.SourceHistoryError):
        history.list_source_sets(db, 'p', before=old)


def test_concurrent_immediate_transactions_serialize_merge_and_stale_selection(tmp_path):
    path = tmp_path / 'store.sqlite3'
    c1 = connection(path)
    with transaction(c1):
        project(c1)
        history.initialize(c1)
    a = upload(c1)['source_set']['id']
    c2 = sqlite3.connect(path, timeout=0.05)
    c2.row_factory = sqlite3.Row
    c2.execute('PRAGMA foreign_keys=ON')
    c1.execute('BEGIN IMMEDIATE')
    b = history.publish_upload(c1, 'p', [source('b.txt', b'b')], 20, 'alice')['source_set']['id']
    with pytest.raises(sqlite3.OperationalError, match='locked'):
        c2.execute('BEGIN IMMEDIATE')
    c1.commit()
    with transaction(c2):
        result = history.publish_upload(c2, 'p', [source('c.txt', b'c')], 30, 'alice')
    assert [item['name'] for item in result['source_set']['files']] == ['a.txt', 'b.txt', 'c.txt']
    with pytest.raises(history.SourceHistoryConflict):
        with transaction(c1):
            history.select_source_set(c1, 'p', a, b, 40, 'alice')
    assert history.selected_source_set_id(c1, 'p') == result['source_set']['id']
    c1.close()
    c2.close()


def test_plain_sqlite_tuple_rows_supported():
    c = connection()
    c.row_factory = None
    with transaction(c):
        project(c)
        history.initialize(c)
    assert upload(c)['source_set']['file_count'] == 1


@pytest.mark.parametrize('field,value', [('sha256', '0' * 64), ('bytes', 999), ('text', 'different'), ('bytes', True)])
def test_uploaded_checked_metadata_mismatch_fails_without_rows(db, field, value):
    item = source()
    item[field] = value
    with pytest.raises(history.SourceHistoryError):
        upload(db, [item])
    assert not db.execute('SELECT 1 FROM sources').fetchall()
