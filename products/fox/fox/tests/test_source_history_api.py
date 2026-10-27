"""Isolated synthetic API contract tests for complete source-set history.

No worker, external transport, model, Oracle tooling, or live database is used.
The companion proof tests reuse these helpers against the canonical package.
"""
import hashlib
import io
import json
import re
import socket
import sqlite3
import subprocess
import sys
import time
from types import SimpleNamespace
import uuid
import zipfile
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from fox.app import create_app, password_hash
from fox.intake import checked_source, inventory
from fox.prepared_source import encode_upload_manifest, make_upload_manifest


ORIGIN = 'http://127.0.0.1:8100'
USERNAME = 'fox-synthetic-history'
PASSWORD = 'synthetic-history-test-only'
SID = re.compile(r'ss-[a-f0-9]{32}')
REPOSITORY = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def no_external_actions(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('External actions are forbidden in synthetic history tests.')
    original_connect = socket.socket.connect
    socketpair_code = getattr(getattr(socket, '_fallback_socketpair', None), '__code__', None)
    def guarded_connect(sock, address):
        # Windows asyncio builds its wake-up pipe through this exact stdlib
        # helper. Permit only that helper's own freshly bound loopback listener,
        # never arbitrary localhost traffic from application/provider code.
        caller = sys._getframe(1)
        listener = caller.f_locals.get('lsock')
        if (socketpair_code is not None and caller.f_code is socketpair_code
                and listener is not None and address == listener.getsockname()
                and address[0] in {'127.0.0.1', '::1'}):
            return original_connect(sock, address)
        forbidden()
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    monkeypatch.setattr(socket.socket, 'connect', guarded_connect)
    monkeypatch.setattr(socket.socket, 'connect_ex', forbidden)
    monkeypatch.setattr(httpx.HTTPTransport, 'handle_request', forbidden)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, 'handle_async_request', forbidden)
    monkeypatch.setattr(subprocess, 'Popen', forbidden)


@pytest.fixture
def settings(monkeypatch):
    monkeypatch.setenv('FOX_PASSWORD_HASH', password_hash(PASSWORD))
    monkeypatch.setenv('FOX_PUBLIC_ORIGIN', ORIGIN)
    monkeypatch.setenv('FOX_ADMIN_USERNAME', USERNAME)
    monkeypatch.setenv('FOX_CONVERSION_PROFILE', 'legacy-html-prototype-v1')
    monkeypatch.setenv('FOX_OPAF_RUN_URL', 'https://synthetic-never-contact.invalid/run')
    monkeypatch.delenv('FOX_VERIFICATION_ENABLED', raising=False)
    monkeypatch.delenv('FOX_VERIFIER_RELEASE_MANIFEST', raising=False)
    monkeypatch.delenv('FOX_VERIFIER_RELEASE_SHA256', raising=False)


def login(c):
    c.headers['Origin'] = ORIGIN
    response = c.post('/api/login', json={'username': USERNAME, 'password': PASSWORD})
    assert response.status_code == 200, response.text


@pytest.fixture
def client(tmp_path, settings):
    root = tmp_path / 'data'
    with TestClient(create_app(root, enable_worker=False), base_url=ORIGIN) as c:
        login(c)
        yield c, root, new_project(c)


def new_project(c):
    response = c.post('/api/projects', json={
        'customer': 'Synthetic source-history fixture', 'name': 'Revisitable application',
    })
    assert response.status_code == 201, response.text
    return response.json()['id']


def sources(label='A', *, bom=False, crlf=False):
    files = [
        ('main.xml', f'<FormModule Name="SYNTHETIC_{label}"/>\n'.encode()),
        ('shared.sql', f'-- Synthetic version {label}; structure only.\nCREATE TABLE FOX_{label} (ID NUMBER);\n'.encode()),
    ]
    if crlf:
        files = [(name, raw.replace(b'\n', b'\r\n')) for name, raw in files]
    if bom:
        files = [(name, b'\xef\xbb\xbf' + raw) for name, raw in files]
    return files


def upload(c, pid, files):
    response = c.post(f'/api/projects/{pid}/sources',
                      files=[('files', (name, raw)) for name, raw in files])
    assert response.status_code == 200, response.text
    return response.json()


def history(c, pid):
    response = c.get(f'/api/projects/{pid}/source-sets')
    assert response.status_code == 200, response.text
    return response.json()


def selected(c, pid):
    value = history(c, pid)
    sid = value['selected_source_set_id']
    if sid is None:
        return None
    visible = next((item for item in value['source_sets'] if item['id'] == sid), None)
    # An explicitly selected old version (or a timestamp tie) can be outside
    # page one. The immutable detail route remains the authoritative lookup.
    return visible if visible is not None else detail(c, pid, sid)['source_set']


def detail(c, pid, sid):
    response = c.get(f'/api/projects/{pid}/source-sets/{sid}')
    assert response.status_code == 200, response.text
    return response.json()


def select(c, pid, sid, expected):
    return c.post(f'/api/projects/{pid}/source-sets/{sid}/select',
                  json={'expected_current_source_set_id': expected})


def exclude(c, pid, sid, expected, ids):
    return c.post(f'/api/projects/{pid}/source-sets/{sid}/exclude', json={
        'expected_current_source_set_id': expected, 'excluded_file_ids': ids,
    })


def digest(files):
    return inventory([checked_source(name, raw) for name, raw in files])['source_hash']


def approvals(source_hash):
    return {'source_hash': source_hash, 'approved_redacted_source': True,
            'approved_external_ai': True, 'approved_prototype_scope': True}


def database_rows(root, table):
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        return db.execute(f'SELECT * FROM {table} ORDER BY rowid').fetchall()


def durable_rows(root):
    return {table: database_rows(root, table)
            for table in ('sources', 'runs', 'acceptances', 'prepared_uploads')}


def job_files(root):
    path = root / 'jobs'
    return {} if not path.exists() else {
        str(item.relative_to(path)): item.read_bytes()
        for item in path.rglob('*') if item.is_file()
    }


def archive(c, pid, sid):
    response = c.get(f'/api/projects/{pid}/source-sets/{sid}/download')
    assert response.status_code == 200, response.text
    assert response.headers['content-type'].startswith('application/zip')
    with zipfile.ZipFile(io.BytesIO(response.content)) as package:
        return {name: package.read(name) for name in package.namelist()}


def test_empty_project_has_no_invented_source_revision(client):
    c, root, pid = client
    assert history(c, pid) == {'selected_source_set_id': None, 'source_sets': [], 'next_cursor': None}
    assert selected(c, pid) is None
    assert durable_rows(root) == {'sources': [], 'runs': [], 'acceptances': [], 'prepared_uploads': []}
    assert job_files(root) == {}
    listed = next(item for item in c.get('/api/projects').json() if item['id'] == pid)
    assert listed['file_count'] == listed['run_count'] == 0


def test_upload_revisions_exist_before_any_processing_and_preserve_A(client):
    c, root, pid = client
    first_report = upload(c, pid, sources('A'))
    first = selected(c, pid)
    second_report = upload(c, pid, sources('B'))
    second = selected(c, pid)
    assert SID.fullmatch(first['id']) and SID.fullmatch(second['id'])
    assert first['id'] != second['id']
    assert first['source_hash'] == first_report['source_hash'] == digest(sources('A'))
    assert second['source_hash'] == second_report['source_hash'] == digest(sources('B'))
    listing = history(c, pid)
    assert listing['selected_source_set_id'] == second['id']
    assert len(listing['source_sets']) == 2
    by_id = {item['id']: item for item in listing['source_sets']}
    assert by_id[first['id']]['is_selected'] is False
    assert by_id[second['id']]['is_selected'] is True
    for item in by_id.values():
        assert item['origin'] == 'upload'
        assert item['file_count'] == 2
        assert item['created'] > 0
        assert item['run_ids'] == []
    older = detail(c, pid, first['id'])
    assert older['selected_source_set_id'] == second['id']
    assert older['assessment_summary']['source_hash'] == first_report['source_hash']
    assert {f['name']: (f['sha256'], f['bytes']) for f in older['files']} == {
        name: (hashlib.sha256(raw).hexdigest(), len(raw)) for name, raw in sources('A')}
    assert len(database_rows(root, 'sources')) == 4
    assert database_rows(root, 'runs') == database_rows(root, 'acceptances') == []
    assert job_files(root) == {}


@pytest.mark.parametrize('bom,crlf', [(False, False), (False, True), (True, False), (True, True)])
def test_historical_zip_preserves_exact_readable_bytes_and_safe_metadata(client, bom, crlf):
    c, _, pid = client
    original = sources('A', bom=bom, crlf=crlf)
    original.append(('unicode.txt', 'Synthetic café and 日本語\r\n'.encode()))
    upload(c, pid, original)
    first = selected(c, pid)
    upload(c, pid, sources('B'))
    contents = archive(c, pid, first['id'])
    assert set(contents) == {name for name, _ in original} | {'fox-source-set.json'}
    for name, raw in original:
        assert contents[name] == raw
    metadata = json.loads(contents['fox-source-set.json'])
    # Public source evidence is distinct from a prepared upload or APEX package.
    assert set(metadata) == {'format', 'schema_version', 'source_set_id', 'source_hash', 'files'}
    assert metadata['schema_version'] == 1
    assert metadata['source_set_id'] == first['id']
    assert metadata['source_hash'] == digest(original)
    assert {f['name'] for f in metadata['files']} == {name for name, _ in original}
    assert all(set(f) == {'name', 'sha256', 'bytes'} for f in metadata['files'])
    serialized = json.dumps(metadata)
    for forbidden in ('approved', 'password', 'private', 'local_path', 'backend', 'inputs'):
        assert forbidden not in serialized.lower()
    assert 'apex' not in metadata['format'].lower()


def test_select_A_then_upload_C_merges_selected_A_not_global_newest_B(client):
    c, root, pid = client
    upload(c, pid, sources('A'))
    first = selected(c, pid)
    upload(c, pid, sources('B') + [('only-B.txt', b'Only in version B.')])
    second = selected(c, pid)
    response = select(c, pid, first['id'], second['id'])
    assert response.status_code == 200, response.text
    assert response.json()['selection_changed'] is True
    assert response.json()['assessment_summary']['source_hash'] == digest(sources('A'))
    changed = [('main.xml', b'<FormModule Name="SYNTHETIC_C"/>\n')]
    report = upload(c, pid, changed)
    expected = [changed[0], sources('A')[1]]
    assert report['source_hash'] == digest(expected)
    current = selected(c, pid)
    assert current['id'] not in {first['id'], second['id']}
    assert {f['name'] for f in detail(c, pid, current['id'])['files']} == {'main.xml', 'shared.sql'}
    assert {f['name'] for f in detail(c, pid, second['id'])['files']} == {'main.xml', 'shared.sql', 'only-B.txt'}
    assert archive(c, pid, first['id'])['main.xml'] == sources('A')[0][1]
    assert len(database_rows(root, 'sources')) == 6


def test_known_old_upload_selects_that_content_without_duplicating_source_rows(client):
    c, root, pid = client
    first_report = upload(c, pid, sources('A'))
    first = selected(c, pid)
    upload(c, pid, sources('B'))
    before_sources = database_rows(root, 'sources')
    restored = upload(c, pid, sources('A'))
    assert restored['source_hash'] == first_report['source_hash']
    assert selected(c, pid)['id'] == first['id']
    assert database_rows(root, 'sources') == before_sources
    assert len(history(c, pid)['source_sets']) == 2


def test_select_is_only_pointer_and_audit_change_without_jobs_or_approvals(client):
    c, root, pid = client
    report = upload(c, pid, sources('A'))
    first = selected(c, pid)
    queued = c.post(f'/api/projects/{pid}/runs', json=approvals(report['source_hash']))
    assert queued.status_code == 202, queued.text
    upload(c, pid, sources('B'))
    second = selected(c, pid)
    rows, jobs = durable_rows(root), job_files(root)
    before_events = len(database_rows(root, 'events'))
    response = select(c, pid, first['id'], second['id'])
    assert response.status_code == 200
    assert response.json()['selection_changed'] is True
    assert durable_rows(root) == rows and job_files(root) == jobs
    assert len(database_rows(root, 'events')) == before_events + 1
    assert database_rows(root, 'acceptances') == []
    returned = response.json()
    assert not {'approvals', 'accepted', 'approved_external_ai'} & set(returned)
    assert selected(c, pid)['run_ids'] == [queued.json()['id']]
    again = select(c, pid, first['id'], first['id'])
    assert again.status_code == 200
    assert again.json()['selection_changed'] is False
    assert durable_rows(root) == rows and job_files(root) == jobs


def test_restored_set_allows_explicit_idempotent_run_but_does_not_restore_consent(client):
    c, root, pid = client
    report = upload(c, pid, sources('A'))
    first = selected(c, pid)
    run = c.post(f'/api/projects/{pid}/runs', json=approvals(report['source_hash'])).json()
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute("UPDATE runs SET state='ATTENTION',message='Synthetic retained failure' WHERE id=?", (run['id'],))
    upload(c, pid, sources('B'))
    second = selected(c, pid)
    rows, jobs = durable_rows(root), job_files(root)
    assert select(c, pid, first['id'], second['id']).status_code == 200
    assert durable_rows(root) == rows and job_files(root) == jobs
    body = approvals(report['source_hash'])
    for key in ('approved_redacted_source', 'approved_external_ai', 'approved_prototype_scope'):
        assert c.post(f'/api/projects/{pid}/runs', json={**body, key: False}).status_code == 422
    explicit = c.post(f'/api/projects/{pid}/runs', json=body)
    assert explicit.status_code == 202
    assert explicit.json()['id'] == run['id']
    assert explicit.json()['state'] == 'ATTENTION'
    assert durable_rows(root) == rows and job_files(root) == jobs


def test_stale_selection_CAS_returns_bounded_conflict_and_keeps_all_state(client):
    c, root, pid = client
    upload(c, pid, sources('A'))
    first = selected(c, pid)
    upload(c, pid, sources('B'))
    second = selected(c, pid)
    rows, sets, events = durable_rows(root), history(c, pid), database_rows(root, 'events')
    response = select(c, pid, first['id'], first['id'])
    assert response.status_code == 409
    assert response.json()['code'] == 'SOURCE_SELECTION_CHANGED'
    assert isinstance(response.json()['detail'], str)
    assert durable_rows(root) == rows
    assert history(c, pid) == sets
    assert database_rows(root, 'events') == events
    assert selected(c, pid)['id'] == second['id']


@pytest.mark.parametrize('body', [
    {}, {'expected_current_source_set_id': True},
    {'expected_current_source_set_id': 7}, {'expected_current_source_set_id': []},
    {'expected_current_source_set_id': {}}, {'expected_current_source_set_id': 'bad'},
    {'expected_current_source_set_id': 'ss-' + 'a' * 32, 'approved_external_ai': True},
])
def test_malformed_select_requests_cannot_mutate_state(client, body):
    c, root, pid = client
    upload(c, pid, sources())
    revision = selected(c, pid)
    before, events = durable_rows(root), database_rows(root, 'events')
    response = c.post(f'/api/projects/{pid}/source-sets/{revision["id"]}/select', json=body)
    assert response.status_code == 422, response.text
    assert durable_rows(root) == before and database_rows(root, 'events') == events


@pytest.mark.parametrize('sid', ['bad', 'ss-' + 'A' * 32, 'ss-' + 'a' * 31, 'ss-' + 'f' * 32])
def test_unknown_or_malformed_source_set_ids_are_not_enumerable(client, sid):
    c, root, pid = client
    upload(c, pid, sources())
    current = selected(c, pid)['id']
    before = durable_rows(root)
    assert c.get(f'/api/projects/{pid}/source-sets/{sid}').status_code == 404
    assert c.get(f'/api/projects/{pid}/source-sets/{sid}/download').status_code == 404
    assert select(c, pid, sid, current).status_code == 404
    assert exclude(c, pid, sid, current, ['f' * 32]).status_code == 404
    assert durable_rows(root) == before


def test_source_sets_cannot_cross_project_or_owner_boundary(client):
    c, root, pid = client
    upload(c, pid, sources('A'))
    first = selected(c, pid)
    other = new_project(c)
    upload(c, other, sources('B'))
    second = selected(c, other)
    before = durable_rows(root)
    assert c.get(f'/api/projects/{other}/source-sets/{first["id"]}').status_code == 404
    assert c.get(f'/api/projects/{other}/source-sets/{first["id"]}/download').status_code == 404
    assert select(c, other, first['id'], second['id']).status_code == 404
    assert exclude(c, other, first['id'], second['id'], ['f' * 32]).status_code == 404
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute('UPDATE projects SET owner=? WHERE id=?', ('another-owner', pid))
    assert c.get(f'/api/projects/{pid}/source-sets').status_code == 404
    assert c.get(f'/api/projects/{pid}/source-sets/{first["id"]}').status_code == 404
    assert select(c, pid, first['id'], first['id']).status_code == 404
    assert durable_rows(root) == before


def test_source_history_requires_authentication_and_mutations_require_origin(client):
    c, root, pid = client
    upload(c, pid, sources())
    revision = selected(c, pid)
    f_id = detail(c, pid, revision['id'])['files'][0]['id']
    before = durable_rows(root)
    bad_origin = {'Origin': 'https://unapproved.invalid'}
    assert c.post(f'/api/projects/{pid}/source-sets/{revision["id"]}/select',
                  json={'expected_current_source_set_id': revision['id']}, headers=bad_origin).status_code == 403
    assert c.post(f'/api/projects/{pid}/source-sets/{revision["id"]}/exclude', json={
        'expected_current_source_set_id': revision['id'], 'excluded_file_ids': [f_id]},
        headers=bad_origin).status_code == 403
    c.post('/api/logout', json={})
    assert c.get(f'/api/projects/{pid}/source-sets').status_code == 401
    assert c.get(f'/api/projects/{pid}/source-sets/{revision["id"]}').status_code == 401
    assert c.get(f'/api/projects/{pid}/source-sets/{revision["id"]}/download').status_code == 401
    assert select(c, pid, revision['id'], revision['id']).status_code == 401
    assert exclude(c, pid, revision['id'], revision['id'], [f_id]).status_code == 401
    assert durable_rows(root) == before


def test_historical_detail_is_read_only_and_does_not_select_or_run(client):
    c, root, pid = client
    upload(c, pid, sources('A'))
    first = selected(c, pid)
    upload(c, pid, sources('B'))
    second = selected(c, pid)
    before, events = durable_rows(root), database_rows(root, 'events')
    for _ in range(2):
        assert detail(c, pid, first['id'])['assessment_summary']['source_hash'] == first['source_hash']
        archive(c, pid, first['id'])
        history(c, pid)
    assert selected(c, pid)['id'] == second['id']
    assert durable_rows(root) == before and database_rows(root, 'events') == events
    assert job_files(root) == {}


def test_exclusion_creates_complete_selected_revision_without_deleting_history(client):
    c, root, pid = client
    upload(c, pid, sources('A') + [('unused.txt', b'Retain this in source history.')])
    first = selected(c, pid)
    files = detail(c, pid, first['id'])['files']
    removed = next(f['id'] for f in files if f['name'] == 'unused.txt')
    rows, jobs = durable_rows(root), job_files(root)
    response = exclude(c, pid, first['id'], first['id'], [removed])
    assert response.status_code == 200, response.text
    result = response.json()
    assert result['selection_changed'] is True
    second = selected(c, pid)
    assert second['origin'] == 'exclude'
    assert second['id'] != first['id']
    assert second['file_count'] == 2
    assert result['assessment_summary']['source_hash'] == digest(sources('A'))
    assert len(detail(c, pid, first['id'])['files']) == 3
    assert archive(c, pid, first['id'])['unused.txt'] == b'Retain this in source history.'
    assert durable_rows(root) == rows and job_files(root) == jobs


def test_excluding_to_an_existing_complete_revision_reuses_its_id(client):
    c, root, pid = client
    upload(c, pid, sources('A'))
    first = selected(c, pid)
    upload(c, pid, [('extra.txt', b'Exclude this without erasing it.')])
    second = selected(c, pid)
    extra = next(f['id'] for f in detail(c, pid, second['id'])['files'] if f['name'] == 'extra.txt')
    rows = durable_rows(root)
    response = exclude(c, pid, second['id'], second['id'], [extra])
    assert response.status_code == 200
    assert response.json()['selected_source_set_id'] == first['id']
    assert selected(c, pid)['origin'] == 'upload'
    assert len(history(c, pid)['source_sets']) == 2
    assert durable_rows(root) == rows


@pytest.mark.parametrize('variation', ['empty', 'duplicate', 'all', 'unknown', 'too-many', 'nonstring'])
def test_invalid_exclusion_never_partially_updates_selection(client, variation):
    c, root, pid = client
    upload(c, pid, sources('A'))
    revision = selected(c, pid)
    file_ids = [f['id'] for f in detail(c, pid, revision['id'])['files']]
    ids = {
        'empty': [], 'duplicate': [file_ids[0], file_ids[0]], 'all': file_ids,
        'unknown': ['f' * 32], 'too-many': [uuid.uuid4().hex for _ in range(51)],
        'nonstring': [True],
    }[variation]
    before, sets, events = durable_rows(root), history(c, pid), database_rows(root, 'events')
    response = exclude(c, pid, revision['id'], revision['id'], ids)
    assert response.status_code == 422, response.text
    assert durable_rows(root) == before
    assert history(c, pid) == sets and database_rows(root, 'events') == events


def test_exclusion_stale_compare_and_swap_keeps_current_revision(client):
    c, root, pid = client
    upload(c, pid, sources('A'))
    first = selected(c, pid)
    f_id = detail(c, pid, first['id'])['files'][0]['id']
    upload(c, pid, sources('B'))
    second = selected(c, pid)
    before, events = durable_rows(root), database_rows(root, 'events')
    response = exclude(c, pid, first['id'], first['id'], [f_id])
    assert response.status_code == 409
    assert response.json()['code'] == 'SOURCE_SELECTION_CHANGED'
    assert isinstance(response.json()['detail'], str)
    assert selected(c, pid)['id'] == second['id']
    assert durable_rows(root) == before and database_rows(root, 'events') == events


def test_selection_does_not_turn_prepared_subset_into_complete_current_receipt(client):
    c, _, pid = client
    first_files = sources('A')
    manifest = make_upload_manifest('extract-synthetic-history',
                                    [checked_source(name, raw) for name, raw in first_files])
    response = c.post(f'/api/projects/{pid}/sources', files=[
        *[('files', (name, raw)) for name, raw in first_files],
        ('prepared_manifest', ('fox-readable-upload.json', encode_upload_manifest(manifest))),
    ])
    assert response.status_code == 200
    first = selected(c, pid)
    upload(c, pid, [('extra.txt', b'Outside of the prepared source set.')])
    second = selected(c, pid)
    assert 'source_preparation' not in detail(c, pid, second['id'])['assessment_summary']
    assert c.get(f'/api/projects/{pid}').json()['inventory']['source_preparation']['matches_current_source'] is False
    response = select(c, pid, first['id'], second['id'])
    assert response.status_code == 200
    assert 'source_preparation' not in response.json()['assessment_summary']
    current = c.get(f'/api/projects/{pid}').json()['inventory']
    assert current['source_preparation']['matches_current_source'] is True
    assert 'processing permission' in current['source_preparation']['scope']
    assert 'approvals' not in response.json()


def seed_legacy(root):
    """Only an old-schema synthetic file history, never a real DB migration."""
    root.mkdir()
    pid, empty = uuid.uuid4().hex, uuid.uuid4().hex
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.executescript('''
        CREATE TABLE projects(id TEXT PRIMARY KEY,owner TEXT NOT NULL,customer TEXT NOT NULL,name TEXT NOT NULL,description TEXT NOT NULL,created REAL NOT NULL);
        CREATE TABLE sources(id TEXT PRIMARY KEY,project TEXT NOT NULL REFERENCES projects(id),name TEXT NOT NULL,sha256 TEXT NOT NULL,bytes INTEGER NOT NULL,text TEXT NOT NULL,created REAL NOT NULL,UNIQUE(project,name,sha256));
        CREATE TABLE runs(id TEXT PRIMARY KEY,project TEXT NOT NULL REFERENCES projects(id),source_hash TEXT NOT NULL,state TEXT NOT NULL,message TEXT NOT NULL,created REAL NOT NULL,updated REAL NOT NULL,artifact TEXT,UNIQUE(project,source_hash));
        ''')
        for project_id in (pid, empty):
            db.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)',
                       (project_id, USERNAME, 'Synthetic migration', 'Legacy project', '', 1))
        for filename, raw in sources('A') + sources('B'):
            item = checked_source(filename, raw)
            db.execute('INSERT INTO sources VALUES(?,?,?,?,?,?,?)',
                       (uuid.uuid4().hex, pid, item['name'], item['sha256'], item['bytes'], item['text'], 1))
        # A historical run is not evidence that every intermediate uploaded set
        # can be reconstructed, and must not manufacture a selectable revision.
        run_id = 'fox-' + 'a' * 20
        db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
                   (run_id, pid, digest(sources('A')), 'ATTENTION', 'Synthetic legacy run', 1, 1, None))
    job = root / 'jobs' / run_id
    job.mkdir(parents=True)
    (job / 'source-snapshot.json').write_text(json.dumps({
        'source_hash': digest(sources('A')),
        'files': [checked_source(name, raw) for name, raw in sources('A')],
        'conversion_profile': 'legacy-html-prototype-v1',
    }), encoding='utf-8')
    return pid, empty


def test_legacy_backfill_captures_only_actual_current_once_and_keeps_old_runs(tmp_path, settings):
    root = tmp_path / 'legacy'
    pid, empty = seed_legacy(root)
    old_rows, old_jobs = database_rows(root, 'sources'), job_files(root)
    with TestClient(create_app(root, enable_worker=False), base_url=ORIGIN) as c:
        login(c)
        listing = history(c, pid)
        assert len(listing['source_sets']) == 1
        revision = selected(c, pid)
        assert revision['origin'] == 'legacy-current'
        assert revision['source_hash'] == digest(sources('B'))
        assert revision['run_ids'] == []
        assert history(c, empty) == {'selected_source_set_id': None, 'source_sets': [], 'next_cursor': None}
        assert len(c.get(f'/api/projects/{pid}').json()['runs']) == 1
        assert database_rows(root, 'sources') == old_rows
        assert job_files(root) == old_jobs
    # Restart must not fabricate another baseline or replace the chosen pointer.
    with TestClient(create_app(root, enable_worker=False), base_url=ORIGIN) as c:
        login(c)
        assert history(c, pid) == listing
        assert database_rows(root, 'sources') == old_rows
        assert job_files(root) == old_jobs


def test_identical_reupload_reuses_revision_without_fabricated_history(client):
    c, root, pid = client
    upload(c, pid, sources('A'))
    first = selected(c, pid)
    rows = database_rows(root, 'sources')
    upload(c, pid, list(reversed(sources('A'))))
    assert selected(c, pid)['id'] == first['id']
    assert len(history(c, pid)['source_sets']) == 1
    assert database_rows(root, 'sources') == rows


def test_transport_guard_denies_application_loopback_external_http_and_processes():
    # The only socket exemption is the stdlib's own Windows asyncio wake pipe.
    with socket.socket() as sock, pytest.raises(AssertionError, match='External actions'):
        sock.connect(('127.0.0.1', 1))
    with pytest.raises(AssertionError, match='External actions'):
        socket.create_connection(('example.invalid', 443))
    with pytest.raises(AssertionError, match='External actions'):
        httpx.get('https://example.invalid/')
    with pytest.raises(AssertionError, match='External actions'):
        subprocess.Popen(['synthetic-must-never-execute'])


def test_upload_CAS_null_first_version_then_bound_replacement(client):
    c, root, pid = client
    parts = [('files', (name, raw)) for name, raw in sources('A')]
    first = c.post(f'/api/projects/{pid}/sources', files=parts,
                   data={'expected_current_source_set_id': 'null'})
    assert first.status_code == 200, first.text
    first_id = selected(c, pid)['id']
    second = c.post(f'/api/projects/{pid}/sources',
                    files=[('files', (name, raw)) for name, raw in sources('B')],
                    data={'expected_current_source_set_id': first_id})
    assert second.status_code == 200
    assert second.json()['source_hash'] == digest(sources('B'))
    assert selected(c, pid)['id'] != first_id
    assert len(database_rows(root, 'sources')) == 4


@pytest.mark.parametrize('prepared', [False, True])
@pytest.mark.parametrize('expected', ['old', 'null'])
def test_stale_upload_CAS_rejects_before_rows_receipts_or_history_change(client, prepared, expected):
    c, root, pid = client
    upload(c, pid, sources('A'))
    first_id = selected(c, pid)['id']
    upload(c, pid, sources('B'))
    before, sets, events = durable_rows(root), history(c, pid), database_rows(root, 'events')
    files = sources('C')
    parts = [('files', (name, raw)) for name, raw in files]
    if prepared:
        manifest = make_upload_manifest('extract-cas-synthetic',
                                        [checked_source(name, raw) for name, raw in files])
        parts.append(('prepared_manifest', ('fox-readable-upload.json', encode_upload_manifest(manifest))))
    response = c.post(f'/api/projects/{pid}/sources', files=parts,
                      data={'expected_current_source_set_id': first_id if expected == 'old' else 'null'})
    assert response.status_code == 409
    assert response.json()['code'] == 'SOURCE_SELECTION_CHANGED'
    assert isinstance(response.json()['detail'], str)
    assert durable_rows(root) == before
    assert history(c, pid) == sets and database_rows(root, 'events') == events


@pytest.mark.parametrize('expected', ['bad', 'NULL', 'true', '7', 'ss-' + 'A' * 32])
def test_invalid_upload_CAS_is_bounded_input_error(client, expected):
    c, root, pid = client
    before, events = durable_rows(root), database_rows(root, 'events')
    response = c.post(f'/api/projects/{pid}/sources',
                      files=[('files', (name, raw)) for name, raw in sources()],
                      data={'expected_current_source_set_id': expected})
    assert response.status_code == 422
    assert durable_rows(root) == before and database_rows(root, 'events') == events
    assert selected(c, pid) is None


def test_legacy_upload_without_optional_CAS_remains_compatible_after_upgrade(tmp_path, settings):
    root = tmp_path / 'legacy'
    pid, _ = seed_legacy(root)
    with TestClient(create_app(root, enable_worker=False), base_url=ORIGIN) as c:
        login(c)
        baseline = selected(c, pid)
        assert baseline['origin'] == 'legacy-current'
        report = upload(c, pid, sources('A'))
        assert report['source_hash'] == digest(sources('A'))
        assert selected(c, pid)['id'] != baseline['id']
        assert selected(c, pid)['origin'] == 'upload'


@pytest.mark.parametrize('constant_clock', [False, True])
def test_pagination_is_project_scoped_and_does_not_duplicate_or_omit_revisions(client, monkeypatch, constant_clock):
    c, root, pid = client
    if constant_clock:
        import fox.app as app_module
        stamp = time.time()
        monkeypatch.setattr(app_module, 'time', SimpleNamespace(time=lambda: stamp))
    versions = []
    for index in range(53):
        upload(c, pid, [('main.xml', f'<FormModule Name="SYNTHETIC_{index}"/>'.encode())])
        versions.append(selected(c, pid))
    first = history(c, pid)
    assert len(first['source_sets']) == 50
    assert first['next_cursor'] == first['source_sets'][-1]['id']
    second_response = c.get(f'/api/projects/{pid}/source-sets', params={'before': first['next_cursor']})
    assert second_response.status_code == 200
    second = second_response.json()
    assert len(second['source_sets']) == 3 and second['next_cursor'] is None
    # The documented stable order is timestamp then ID, not arrival order.
    # Windows clocks can legitimately give different uploads equal timestamps.
    expected = sorted(versions, key=lambda item: (item['created'], item['id']), reverse=True)
    returned = first['source_sets'] + second['source_sets']
    assert [item['id'] for item in returned] == [item['id'] for item in expected]
    assert len({item['id'] for item in returned}) == 53
    assert first['selected_source_set_id'] == second['selected_source_set_id'] == versions[-1]['id']
    assert sum(item['is_selected'] for item in first['source_sets'] + second['source_sets']) == 1
    old_id = expected[-1]['id']
    assert select(c, pid, old_id, versions[-1]['id']).status_code == 200
    refreshed = history(c, pid)
    assert refreshed['selected_source_set_id'] == old_id
    assert old_id not in {item['id'] for item in refreshed['source_sets']}
    assert selected(c, pid)['id'] == old_id
    other = new_project(c)
    upload(c, other, sources('A'))
    foreign_id = selected(c, other)['id']
    before = durable_rows(root)
    for invalid in ('bad', 'ss-' + 'f' * 32, foreign_id):
        assert c.get(f'/api/projects/{pid}/source-sets', params={'before': invalid}).status_code == 404
    assert durable_rows(root) == before


def test_historical_set_must_be_selected_before_exclusion(client):
    c, root, pid = client
    upload(c, pid, sources('A'))
    first = selected(c, pid)
    file_id = detail(c, pid, first['id'])['files'][0]['id']
    upload(c, pid, sources('B'))
    second = selected(c, pid)
    before, sets, events = durable_rows(root), history(c, pid), database_rows(root, 'events')
    response = exclude(c, pid, first['id'], second['id'], [file_id])
    assert response.status_code == 409
    assert response.json()['code'] == 'SOURCE_SELECTION_CHANGED'
    assert durable_rows(root) == before
    assert history(c, pid) == sets and database_rows(root, 'events') == events


@pytest.mark.parametrize('mutation', ['missing-expected', 'missing-files', 'unexpected-field',
                                       'wrong-expected-type', 'wrong-files-type'])
def test_exclusion_requires_strict_explicit_payload(client, mutation):
    c, root, pid = client
    upload(c, pid, sources('A'))
    revision = selected(c, pid)
    file_id = detail(c, pid, revision['id'])['files'][0]['id']
    body = {'expected_current_source_set_id': revision['id'], 'excluded_file_ids': [file_id]}
    if mutation == 'missing-expected':
        del body['expected_current_source_set_id']
    elif mutation == 'missing-files':
        del body['excluded_file_ids']
    elif mutation == 'unexpected-field':
        body['approved_external_ai'] = True
    elif mutation == 'wrong-expected-type':
        body['expected_current_source_set_id'] = True
    else:
        body['excluded_file_ids'] = file_id
    before, events = durable_rows(root), database_rows(root, 'events')
    response = c.post(f'/api/projects/{pid}/source-sets/{revision["id"]}/exclude', json=body)
    assert response.status_code == 422
    assert durable_rows(root) == before and database_rows(root, 'events') == events


def test_project_list_file_count_tracks_selection_and_exclusion_not_all_history(client):
    c, _, pid = client
    def listed_count():
        return next(item for item in c.get('/api/projects').json() if item['id'] == pid)['file_count']
    assert listed_count() == 0
    upload(c, pid, sources('A'))
    first = selected(c, pid)
    assert listed_count() == 2
    upload(c, pid, [('extra.txt', b'Kept in historical version only.')])
    second = selected(c, pid)
    assert listed_count() == 3
    assert select(c, pid, first['id'], second['id']).status_code == 200
    assert listed_count() == 2
    files = detail(c, pid, first['id'])['files']
    removed = next(item['id'] for item in files if item['name'] == 'shared.sql')
    assert exclude(c, pid, first['id'], first['id'], [removed]).status_code == 200
    assert listed_count() == 1
    assert len(detail(c, pid, second['id'])['files']) == 3


def test_historical_assessment_does_not_attach_current_prepared_receipt(client):
    c, _, pid = client
    upload(c, pid, sources('A'))
    first = selected(c, pid)
    files = sources('B')
    manifest = make_upload_manifest('extract-current-only',
                                    [checked_source(name, raw) for name, raw in files])
    response = c.post(f'/api/projects/{pid}/sources', files=[
        *[('files', (name, raw)) for name, raw in files],
        ('prepared_manifest', ('fox-readable-upload.json', encode_upload_manifest(manifest))),
    ])
    assert response.status_code == 200
    current_id = selected(c, pid)['id']
    assert response.json()['source_preparation']['matches_current_source'] is True
    old = detail(c, pid, first['id'])
    assert old['selected_source_set_id'] == current_id
    assert old['assessment_summary']['source_hash'] == first['source_hash']
    assert 'source_preparation' not in old['assessment_summary']
