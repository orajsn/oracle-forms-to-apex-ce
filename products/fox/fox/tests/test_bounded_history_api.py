"""Canonical bounded history responses with lossless retained source evidence.

Only synthetic local SQLite/ASGI fixtures run. Storage seeds use checked_source
and the normal source-history helper under legitimate write transactions; no
worker, external transport, model, Oracle tool, or live database is involved.
"""
import hashlib
import io
import json
import math
import re
import sqlite3
import time
import zipfile
from pathlib import Path

import pytest

import fox.app as app_module
from fox import intake, source_history as store
from fox.intake import checked_source, inventory
from fox.native_source import assess_native_source
from test_source_history_api import (
    USERNAME, client, no_external_actions, settings, select, exclude,
)


REPOSITORY = Path(__file__).resolve().parents[1]
JSON_LIMIT = 256 * 1024
SUMMARY_KEYS = {
    'source_hash', 'conversion_profile', 'source_checks_passed', 'file_count',
    'source_bytes', 'conversion_source_bytes', 'max_conversion_bytes',
    'max_conversion_files', 'missing_dependency_count', 'assessment_finding_count',
    'conversion_blocker_count', 'blocker_codes', 'native_state',
}
METADATA_KEYS = {
    'id', 'source_hash', 'file_count', 'source_bytes', 'created', 'origin',
    'is_selected', 'run_ids',
}


@pytest.fixture(autouse=True)
def canonical_package_only():
    expected = REPOSITORY / 'fox'
    for module in (app_module, intake, store):
        assert Path(module.__file__).resolve().parent == expected
    assert app_module.MAX_HISTORY_JSON_BYTES == JSON_LIMIT
    assert store.MAX_RETAINED_BYTES == 100 * 1024 * 1024
    assert store.MAX_EXPORT_MANIFEST_BYTES == 2 * 1024 * 1024
    assert store.MAX_EXPORT_ARCHIVE_BYTES == 108 * 1024 * 1024


def checked(files):
    return [checked_source(name, raw) for name, raw in files]


def seed_upload(root, pid, files, *, now=None):
    """Use the real merge/immutability helper without HTTP response expansion."""
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('BEGIN IMMEDIATE')
        store.publish_upload(db, pid, checked(files), time.time() if now is None else now, USERNAME)
        return store.selected_source_set_id(db, pid)


def seed_many(root, pid, count=151):
    files = [('main.xml', b'<FormModule Name="SYNTHETIC_BOUNDARY"/>\r\n')]
    files += [(f'source-{index:04d}.txt', f'Synthetic source member {index}.\r\n'.encode())
              for index in range(count - 1)]
    sid = None
    for offset in range(0, len(files), 50):
        sid = seed_upload(root, pid, files[offset:offset + 50])
    return sid, files


def state(root):
    """Every durable table, including selection, members and audit rows."""
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        names = [row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
        assert all(re.fullmatch(r'[a-z_]+', name) for name in names)
        return {name: db.execute(f'SELECT * FROM {name} ORDER BY rowid').fetchall() for name in names}


def response_json(response, status=200):
    assert response.status_code == status, response.text[:1000]
    assert response.headers['content-type'].startswith('application/json')
    assert len(response.content) <= JSON_LIMIT
    return response.json()


def details(c, pid, sid, cursor=None):
    params = {} if cursor is None else {'files_after': cursor}
    return c.get(f'/api/projects/{pid}/source-sets/{sid}', params=params)


def history(c, pid, cursor=None):
    return c.get(f'/api/projects/{pid}/source-sets',
                 params={} if cursor is None else {'before': cursor})


def assert_metadata(value):
    assert set(value) == METADATA_KEYS
    assert re.fullmatch(r'ss-[a-f0-9]{32}', value['id'])
    assert re.fullmatch(r'[a-f0-9]{64}', value['source_hash'])
    assert type(value['file_count']) is int and value['file_count'] > 0
    assert type(value['source_bytes']) is int and value['source_bytes'] > 0
    assert type(value['created']) in (int, float) and math.isfinite(value['created'])
    assert value['origin'] in {'upload', 'legacy-current', 'exclude'}
    assert type(value['is_selected']) is bool
    assert type(value['run_ids']) is list and len(value['run_ids']) <= 1
    for rid in value['run_ids']:
        assert type(rid) is str and 1 <= len(rid) <= 128
        assert not any(ord(char) < 32 or ord(char) == 127 for char in rid)


def assert_summary(value, files, *, profile='legacy-html-prototype-v1'):
    assert set(value) == SUMMARY_KEYS
    expected = inventory(checked(files))
    native = assess_native_source(checked(files)) if profile == 'native-table-form-v1' else None
    blockers = expected['conversion_blockers'] + (native['blockers'] if native else [])
    assert value['source_hash'] == expected['source_hash']
    assert value['conversion_profile'] == profile
    assert type(value['source_checks_passed']) is bool
    assert value['source_checks_passed'] is bool(
        profile != 'unconfigured' and expected['conversion_eligible']
        and (native is None or native['state'] == 'READY'))
    for key in ('file_count', 'source_bytes', 'conversion_source_bytes',
                'max_conversion_bytes', 'max_conversion_files',
                'missing_dependency_count', 'assessment_finding_count',
                'conversion_blocker_count'):
        assert type(value[key]) is int and value[key] >= 0
    assert value['file_count'] == len(files)
    assert value['source_bytes'] == sum(len(raw) for _, raw in files)
    assert value['conversion_source_bytes'] == expected['conversion_source_bytes']
    assert value['max_conversion_bytes'] == expected['max_conversion_bytes']
    assert value['max_conversion_files'] == 50
    assert value['missing_dependency_count'] == expected['missing_count']
    assert value['assessment_finding_count'] == len(expected['issues'])
    assert value['conversion_blocker_count'] == len(blockers)
    codes = value['blocker_codes']
    assert type(codes) is list and len(codes) <= 64
    assert codes == sorted(set(codes))
    assert codes == sorted({item['code'] for item in blockers})
    assert all(type(code) is str and re.fullmatch(r'[A-Z0-9_]{1,64}', code) for code in codes)
    assert value['native_state'] == (native['state'] if native else None)
    # No arbitrary source identifiers or explanatory/source-owned text slots.
    assert not {'files', 'dependencies', 'issues', 'native_form', 'message', 'scope_note'} & set(value)


def assert_detail(value, sid, files, *, offset=0, selected=None):
    assert set(value) == {'selected_source_set_id', 'source_set', 'files', 'files_page', 'assessment_summary'}
    if selected is not None:
        assert value['selected_source_set_id'] == selected
    assert value['source_set']['id'] == sid
    assert_metadata(value['source_set'])
    assert_summary(value['assessment_summary'], files)
    assert value['source_set']['source_hash'] == value['assessment_summary']['source_hash']
    page = value['files_page']
    assert set(page) == {'offset', 'limit', 'total', 'next_cursor'}
    assert page['offset'] == offset and page['limit'] == 50 and page['total'] == len(files)
    assert 0 < len(value['files']) <= 50
    assert len(value['files']) == min(50, len(files) - offset)
    for entry in value['files']:
        assert set(entry) == {'id', 'name', 'sha256', 'bytes'}
        assert type(entry['id']) is str and 1 <= len(entry['id']) <= 128
        assert not any(ord(char) < 32 or ord(char) == 127 for char in entry['id'])
    if offset + len(value['files']) < len(files):
        assert page['next_cursor'] == value['files'][-1]['id']
    else:
        assert page['next_cursor'] is None


def assert_ack(value, sid, files, *, changed=True):
    assert set(value) == {'selected_source_set_id', 'source_set', 'assessment_summary', 'selection_changed'}
    assert value['selected_source_set_id'] == value['source_set']['id'] == sid
    assert value['selection_changed'] is changed
    assert_metadata(value['source_set'])
    assert_summary(value['assessment_summary'], files)
    assert 'inventory' not in value and 'assessment' not in value


def long_identifier_files():
    # This is genuine well-formed XML accepted by normal intake, not a mocked
    # JSON body. No claim is made that Oracle Forms accepts this identifier.
    marker = b'LONG_SYNTHETIC_BLOCK_IDENTIFIER_'
    name = marker + b'B' * (2 * 1024 * 1024)
    raw = (b'\xef\xbb\xbf<FormModule Name="SYNTHETIC">\r\n<Block Name="' + name
           + b'"/>\r\n</FormModule>\r\n')
    return [('large.xml', raw), ('keep.txt', b'Synthetic retained companion.\r\n')], marker


def test_real_large_XML_inventory_is_replaced_by_small_lossless_history_summary(client):
    c, root, pid = client
    files, marker = long_identifier_files()
    old_full_inventory = inventory(checked(files))
    assert len(json.dumps(old_full_inventory).encode()) > 2 * 1024 * 1024
    sid = seed_upload(root, pid, files)
    before = state(root)
    response = details(c, pid, sid)
    value = response_json(response)
    assert len(response.content) < 4096
    assert marker not in response.content
    assert_detail(value, sid, files, selected=sid)
    assert value['assessment_summary']['source_checks_passed'] is False
    assert 'CONVERSION_SIZE_LIMIT' in value['assessment_summary']['blocker_codes']
    listing = response_json(history(c, pid))
    assert len(listing['source_sets']) == 1
    assert_metadata(listing['source_sets'][0])
    exported = c.get(f'/api/projects/{pid}/source-sets/{sid}/download')
    assert exported.status_code == 200
    with zipfile.ZipFile(io.BytesIO(exported.content)) as package:
        assert set(package.namelist()) == {'large.xml', 'keep.txt', 'fox-source-set.json'}
        for name, raw in files:
            assert package.read(name) == raw
        manifest = json.loads(package.read('fox-source-set.json'))
        assert manifest['source_hash'] == value['source_set']['source_hash']
        assert len(package.read('fox-source-set.json')) <= 2 * 1024 * 1024
    assert state(root) == before


def test_real_large_identifier_select_and_exclude_return_small_summary_only(client):
    c, root, pid = client
    first_files, marker = long_identifier_files()
    first = seed_upload(root, pid, first_files)
    second_files = [('large.xml', b'<FormModule Name="SMALL_REPLACEMENT"/>\n'), first_files[1]]
    second = seed_upload(root, pid, second_files)
    selected_response = select(c, pid, first, second)
    ack = response_json(selected_response)
    assert len(selected_response.content) < 4096 and marker not in selected_response.content
    assert_ack(ack, first, first_files)
    current = response_json(details(c, pid, first))
    remove = next(item['id'] for item in current['files'] if item['name'] == 'keep.txt')
    exclusion_response = exclude(c, pid, first, first, [remove])
    excluded = response_json(exclusion_response)
    assert len(exclusion_response.content) < 4096 and marker not in exclusion_response.content
    assert_ack(excluded, excluded['selected_source_set_id'], first_files[:1])
    # Full original membership remains readable from the historical first set.
    historical = response_json(details(c, pid, first))
    assert historical['source_set']['file_count'] == 2


def test_151_real_members_paginate_exactly_without_omission_or_duplicate(client):
    c, root, pid = client
    sid, files = seed_many(root, pid)
    original_state = state(root)
    cursor, offset, seen, pages = None, 0, [], []
    while True:
        response = details(c, pid, sid, cursor)
        value = response_json(response)
        assert_detail(value, sid, files, offset=offset, selected=sid)
        assert value['assessment_summary']['source_checks_passed'] is False
        assert 'CONVERSION_FILE_COUNT_LIMIT' in value['assessment_summary']['blocker_codes']
        assert len(response.content) < 32 * 1024
        pages.append(value)
        seen.extend(value['files'])
        offset += len(value['files'])
        cursor = value['files_page']['next_cursor']
        if cursor is None:
            break
        assert len(pages) <= 4
    assert [len(page['files']) for page in pages] == [50, 50, 50, 1]
    assert [item['name'] for item in seen] == sorted(name for name, _ in files)
    assert len({item['id'] for item in seen}) == 151
    assert {item['name']: (item['bytes'], item['sha256']) for item in seen} == {
        name: (len(raw), hashlib.sha256(raw).hexdigest()) for name, raw in files}
    assert state(root) == original_state


def test_member_pages_keep_requested_immutable_hash_when_selection_changes(client):
    c, root, pid = client
    first, files = seed_many(root, pid)
    page1 = response_json(details(c, pid, first))
    cursor = page1['files_page']['next_cursor']
    changed = [('source-0000.txt', b'Synthetic replacement for revision B.\n')]
    second = seed_upload(root, pid, changed)
    assert second != first
    page2 = response_json(details(c, pid, first, cursor))
    assert_detail(page2, first, files, offset=50, selected=second)
    assert page2['source_set']['is_selected'] is False
    assert page2['source_set']['source_hash'] == page1['source_set']['source_hash']
    assert page2['assessment_summary'] == page1['assessment_summary']


def test_member_cursor_scope_rejects_nonmembers_but_accepts_shared_member_ID(client):
    c, root, pid = client
    first, files = seed_many(root, pid)
    page = response_json(details(c, pid, first))
    replaced = next(item for item in page['files'] if item['name'] == 'source-0000.txt')
    shared = next(item for item in page['files'] if item['name'] == 'source-0001.txt')
    second = seed_upload(root, pid, [('source-0000.txt', b'Different valid source bytes.')])
    before = state(root)
    assert details(c, pid, second, replaced['id']).status_code == 404
    for bad in ('not-a-member', 'f' * 32, 'x' * 129, 'bad\nvalue'):
        assert details(c, pid, second, bad).status_code == 404
    # File IDs identify membership, not the version from which a caller learned
    # the ID. An unchanged member valid in both sets is a legal cursor in both.
    shared_page = response_json(details(c, pid, second, shared['id']))
    assert shared_page['source_set']['id'] == second
    assert shared_page['files_page']['offset'] == 3
    assert all(item['name'] > shared['name'] for item in shared_page['files'])
    assert state(root) == before


def test_last_member_cursor_returns_an_explicit_empty_terminal_page(client):
    c, root, pid = client
    files = [('a.txt', b'First synthetic member.'), ('z.txt', b'Last synthetic member.')]
    sid = seed_upload(root, pid, files)
    page = response_json(details(c, pid, sid))
    final = response_json(details(c, pid, sid, page['files'][-1]['id']))
    assert final['source_set']['id'] == sid
    assert final['files'] == []
    assert final['files_page'] == {'offset': 2, 'limit': 50, 'total': 2, 'next_cursor': None}
    assert_summary(final['assessment_summary'], files)


def test_history_list_caps_revisions_and_run_ids_with_bounded_metadata(client):
    c, root, pid = client
    identifiers = []
    for index in range(53):
        sid = seed_upload(root, pid, [('main.xml', f'<FormModule Name="V{index}"/>'.encode())], now=1000 + index)
        identifiers.append(sid)
    # Legacy schema permits opaque IDs; the read contract accepts a bounded ID
    # without leaking other run fields, source names, or provider messages.
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        source_hash = db.execute('SELECT source_hash FROM source_sets WHERE id=?', (identifiers[-1],)).fetchone()[0]
        db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
                   ('R' * 128, pid, source_hash, 'ATTENTION', 'Never expose this source-owned message.', 1, 1, None))
    first = response_json(history(c, pid))
    assert set(first) == {'selected_source_set_id', 'source_sets', 'next_cursor'}
    assert len(first['source_sets']) == 50
    assert first['next_cursor'] == first['source_sets'][-1]['id']
    second = response_json(history(c, pid, first['next_cursor']))
    assert len(second['source_sets']) == 3 and second['next_cursor'] is None
    all_metadata = first['source_sets'] + second['source_sets']
    assert [item['id'] for item in all_metadata] == list(reversed(identifiers))
    for item in all_metadata:
        assert_metadata(item)
    assert all_metadata[0]['run_ids'] == ['R' * 128]
    assert 'Never expose' not in json.dumps(first)


@pytest.mark.parametrize('bad_id', ['R' * 129, 'bad\nrun', 'bad\x7frun'])
def test_invalid_legacy_run_identifier_is_not_reflected_in_history(client, bad_id):
    c, root, pid = client
    sid = seed_upload(root, pid, [('main.xml', b'<FormModule Name="SYNTHETIC"/>')])
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        source_hash = db.execute('SELECT source_hash FROM source_sets WHERE id=?', (sid,)).fetchone()[0]
        db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
                   (bad_id, pid, source_hash, 'ATTENTION', 'private-run-message', 1, 1, None))
    before = state(root)
    for response in (history(c, pid), details(c, pid, sid)):
        value = response_json(response, 409)
        assert isinstance(value['detail'], str)
        assert bad_id not in response.text and 'private-run-message' not in response.text
    assert state(root) == before


@pytest.mark.parametrize('operation', ['select', 'exclude'])
def test_oversize_mutation_ack_rolls_back_selection_members_and_audit(client, monkeypatch, operation):
    c, root, pid = client
    first_files, _ = long_identifier_files()
    first = seed_upload(root, pid, first_files)
    if operation == 'select':
        current = seed_upload(root, pid, [('large.xml', b'<FormModule Name="SYNTHETIC_B"/>')])
        invoke = lambda: select(c, pid, first, current)
    else:
        page = response_json(details(c, pid, first))
        remove = next(item['id'] for item in page['files'] if item['name'] == 'keep.txt')
        current = first
        invoke = lambda: exclude(c, pid, first, first, [remove])
    before = state(root)
    monkeypatch.setattr(app_module, 'MAX_HISTORY_JSON_BYTES', 512)
    refused = response_json(invoke(), 409)
    assert refused['code'] == 'SOURCE_HISTORY_RESPONSE_TOO_LARGE'
    assert isinstance(refused['detail'], str)
    assert state(root) == before
    monkeypatch.setattr(app_module, 'MAX_HISTORY_JSON_BYTES', JSON_LIMIT)
    assert response_json(history(c, pid))['selected_source_set_id'] == current
    # Rollback preserved enough history to perform the same explicit action.
    successful = response_json(invoke())
    assert successful['selection_changed'] is True


@pytest.mark.parametrize('route', ['list', 'detail'])
def test_oversize_read_response_is_explicit_and_preserves_pages(client, monkeypatch, route):
    c, root, pid = client
    sid, files = seed_many(root, pid)
    before = state(root)
    monkeypatch.setattr(app_module, 'MAX_HISTORY_JSON_BYTES', 512)
    response = history(c, pid) if route == 'list' else details(c, pid, sid)
    value = response_json(response, 409)
    assert value['code'] == 'SOURCE_HISTORY_RESPONSE_TOO_LARGE'
    assert state(root) == before
    monkeypatch.setattr(app_module, 'MAX_HISTORY_JSON_BYTES', JSON_LIMIT)
    assert_detail(response_json(details(c, pid, sid)), sid, files, selected=sid)


@pytest.mark.parametrize('limit_name', ['MAX_EXPORT_MANIFEST_BYTES', 'MAX_EXPORT_ARCHIVE_BYTES'])
def test_oversize_export_is_explicit_not_truncated_and_preserves_history(client, monkeypatch, limit_name):
    c, root, pid = client
    sid, files = seed_many(root, pid)
    path = f'/api/projects/{pid}/source-sets/{sid}/download'
    normal = c.get(path)
    assert normal.status_code == 200
    with zipfile.ZipFile(io.BytesIO(normal.content)) as package:
        manifest_size = len(package.read('fox-source-set.json'))
        assert set(package.namelist()) == {name for name, _ in files} | {'fox-source-set.json'}
        for name, raw in files:
            assert package.read(name) == raw
    cutoff = manifest_size - 1 if limit_name == 'MAX_EXPORT_MANIFEST_BYTES' else len(normal.content) - 1
    assert cutoff > 0
    before = state(root)
    with monkeypatch.context() as limits:
        limits.setattr(store, limit_name, cutoff + 1)
        equal_boundary = c.get(path)
        assert equal_boundary.status_code == 200
        assert equal_boundary.content == normal.content
        limits.setattr(store, limit_name, cutoff)
        refusal = c.get(path)
        value = response_json(refusal, 409)
        assert value['code'] == 'SOURCE_HISTORY_EXPORT_TOO_LARGE'
        assert isinstance(value['detail'], str)
        assert not refusal.content.startswith(b'PK')
        assert 'attachment' not in refusal.headers.get('content-disposition', '')
    assert state(root) == before
    retained = response_json(details(c, pid, sid))
    assert_detail(retained, sid, files, selected=sid)
    assert c.get(path).content == normal.content


def test_detail_response_limit_counts_serialized_UTF8_bytes(client, monkeypatch):
    c, root, pid = client
    filename = 'é' * 170 + '.txt'
    sid = seed_upload(root, pid, [(filename, b'Synthetic UTF-8 filename fixture.')])
    normal = details(c, pid, sid)
    response_json(normal)
    boundary = len(normal.content)
    before = state(root)
    with monkeypatch.context() as limit:
        limit.setattr(app_module, 'MAX_HISTORY_JSON_BYTES', boundary)
        assert details(c, pid, sid).content == normal.content
        limit.setattr(app_module, 'MAX_HISTORY_JSON_BYTES', boundary - 1)
        failure = response_json(details(c, pid, sid), 409)
        assert failure['code'] == 'SOURCE_HISTORY_RESPONSE_TOO_LARGE'
    assert state(root) == before


@pytest.mark.parametrize('profile,expected', [
    ('legacy-html-prototype-v1', 'legacy-html-prototype-v1'),
    ('native-table-form-v1', 'native-table-form-v1'),
    ('untrusted-arbitrary-provider-string', 'unconfigured'),
])
def test_summary_normalizes_profile_without_freeform_leak(client, monkeypatch, profile, expected):
    c, root, pid = client
    files = [('main.xml', b'<FormModule Name="SYNTHETIC"/>')]
    sid = seed_upload(root, pid, files)
    monkeypatch.setenv('FOX_CONVERSION_PROFILE', profile)
    response = details(c, pid, sid)
    value = response_json(response)
    assert_summary(value['assessment_summary'], files, profile=expected)
    if expected == 'unconfigured':
        assert profile not in response.text
        assert value['assessment_summary']['source_checks_passed'] is False
    if expected == 'native-table-form-v1':
        assert value['assessment_summary']['native_state'] == 'BLOCKED'
    else:
        assert value['assessment_summary']['native_state'] is None


def test_summary_preserves_nonzero_missing_dependency_and_remediation_counts(client):
    c, root, pid = client
    raw = (b'<FormModule Name="SYNTHETIC_GAPS">'
           b'<AttachedLibrary Name="SYNTHETIC_MISSING_LIBRARY"/>'
           b'<Trigger Name="WHEN-BUTTON-PRESSED" TriggerText="HOST(\'synthetic\');"/>'
           b'</FormModule>')
    files = [('gaps.xml', raw)]
    sid = seed_upload(root, pid, files)
    response = details(c, pid, sid)
    value = response_json(response)['assessment_summary']
    assert_summary(value, files)
    assert value['missing_dependency_count'] == 1
    assert value['assessment_finding_count'] == 1
    assert value['conversion_blocker_count'] == 1
    assert value['blocker_codes'] == ['MISSING_DEPENDENCIES']
    assert value['source_checks_passed'] is False
    assert 'SYNTHETIC_MISSING_LIBRARY' not in response.text
    assert 'WHEN-BUTTON-PRESSED' not in response.text


def test_summary_reports_positive_native_ready_without_embedding_native_spec(client, monkeypatch):
    c, root, pid = client
    fixtures = Path(__file__).resolve().parent / 'fixtures'
    files = [(name, (fixtures / name).read_bytes())
             for name in ('native-beta.xml', 'native-beta.sql')]
    sid = seed_upload(root, pid, files)
    monkeypatch.setenv('FOX_CONVERSION_PROFILE', 'native-table-form-v1')
    response = details(c, pid, sid)
    value = response_json(response)['assessment_summary']
    assert_summary(value, files, profile='native-table-form-v1')
    assert value['native_state'] == 'READY'
    assert value['source_checks_passed'] is True
    assert value['missing_dependency_count'] == value['assessment_finding_count'] == 0
    assert value['conversion_blocker_count'] == 0 and value['blocker_codes'] == []
    assert 'FOX_NATIVE_BETA' not in response.text
    assert 'native_form' not in response.text

