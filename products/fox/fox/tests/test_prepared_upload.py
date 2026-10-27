"""Prepared source uploads prove byte integrity, not approval or completeness.

These tests use local TestClient/SQLite and synthetic source only. They never
run the worker, invoke a model, or contact a database or OCI service.
"""
import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from fox.app import create_app, password_hash
from fox.extractor import prepare, verify
from fox.intake import checked_source
from fox.prepared_source import (
    MAX_MANIFEST_BYTES,
    UPLOAD_MANIFEST_NAME,
    encode_upload_manifest,
    make_upload_manifest,
)


ORIGIN = 'http://127.0.0.1:8100'
PROFILE = 'native-table-form-v1'
FIXTURES = Path(__file__).parent / 'fixtures'


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv('FOX_PASSWORD_HASH', password_hash('test-only-password'))
    monkeypatch.setenv('FOX_PUBLIC_ORIGIN', ORIGIN)
    monkeypatch.setenv('FOX_ADMIN_USERNAME', 'jason')
    monkeypatch.setenv('FOX_CONVERSION_PROFILE', PROFILE)
    monkeypatch.delenv('FOX_OPAF_RUN_URL', raising=False)
    role = {'workflow_id': 'A' * 32, 'model': 'xai.grok-4.3', 'graph_sha256': 'a' * 64}
    profile = tmp_path / 'native-profile.json'
    profile.write_text(json.dumps({
        'schema_version': 1, 'profile_id': PROFILE,
        'opaf_base_url': 'https://localhost:8080/agentFactory',
        'certificate_sha256': 'b' * 64, 'mapper': role,
        'reviewer': {**role, 'workflow_id': 'B' * 32},
    }), encoding='utf-8')
    credentials = tmp_path / 'protected-credentials.json'
    # Configuration checks must not read secrets; no usable secret is needed.
    credentials.write_text('not a usable credential file', encoding='utf-8')
    monkeypatch.setenv('FOX_NATIVE_PROFILE_FILE', str(profile))
    monkeypatch.setenv('FOX_OPAF_CREDENTIAL_FILE', str(credentials))
    monkeypatch.setenv('FOX_CONVERTER_URL', 'http://127.0.0.1:8091')
    monkeypatch.setenv('FOX_RUN_ADAPTER', 'embedded-opaf')
    root = tmp_path / 'data'
    with TestClient(create_app(root, enable_worker=False), base_url=ORIGIN) as c:
        c.headers['Origin'] = ORIGIN
        assert c.post('/api/login', json={
            'username': 'jason', 'password': 'test-only-password',
        }).status_code == 200
        pid = new_project(c)
        yield c, root, pid


def new_project(c):
    response = c.post('/api/projects', json={
        'customer': 'Synthetic fixture', 'name': 'Prepared source boundary',
    })
    assert response.status_code == 201
    return response.json()['id']


def ready_files():
    return [
        ('native.xml', (FIXTURES / 'native-beta.xml').read_bytes()),
        ('native.sql', (FIXTURES / 'native-beta.sql').read_bytes()),
    ]


def public_manifest(files, job='extract-synthetic-api'):
    return make_upload_manifest(job, [checked_source(name, raw) for name, raw in files])


def prepared(c, pid, files=None, *, manifest=None, raw_manifest=None,
             filename=UPLOAD_MANIFEST_NAME):
    files = ready_files() if files is None else files
    if raw_manifest is None:
        raw_manifest = encode_upload_manifest(
            public_manifest(files) if manifest is None else manifest)
    parts = [('files', (name, raw)) for name, raw in files]
    parts.append(('prepared_manifest', (filename, raw_manifest, 'application/json')))
    return c.post(f'/api/projects/{pid}/sources', files=parts)


def direct(c, pid, files):
    return c.post(f'/api/projects/{pid}/sources',
                  files=[('files', (name, raw)) for name, raw in files])


def assessment(c, pid):
    response = c.get(f'/api/projects/{pid}/assessment')
    assert response.status_code == 200
    return response.json()


def stored_state(root):
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        return {
            table: db.execute(f'SELECT * FROM {table} ORDER BY rowid').fetchall()
            for table in ('sources', 'prepared_uploads', 'events', 'runs')
        }


def approvals(report):
    return {'source_hash': report['source_hash'],
            'approved_redacted_source': True, 'approved_external_ai': True,
            'approved_prototype_scope': True}


def assert_not_queued(root):
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 0
    assert not (root / 'jobs').exists()


def test_exact_prepared_set_has_integrity_receipt_without_trust_claims(client):
    c, root, pid = client
    manifest = public_manifest(ready_files())
    response = prepared(c, pid, manifest=manifest)
    assert response.status_code == 200, response.text
    report = response.json()
    preparation = report['source_preparation']
    assert preparation['mode'] == 'PREPARED_SET_MATCH'
    assert preparation['matches_current_source'] is True
    assert preparation['readable_source_hash'] == report['source_hash']
    assert preparation['extraction_job_id'] == manifest['extraction_job_id']
    assert preparation['files'] == manifest['files']
    assert preparation['canonical_manifest_sha256'] == hashlib.sha256(
        encode_upload_manifest(manifest)).hexdigest()
    assert set(preparation) == {
        'mode', 'receipt_id', 'extraction_job_id', 'canonical_manifest_sha256',
        'readable_source_hash', 'files', 'matches_current_source', 'scope',
    }
    assert 'integrity only' in preparation['scope']
    assert 'not proof of Oracle tooling' in preparation['scope']
    assert report == assessment(c, pid)
    assert report == c.get(f'/api/projects/{pid}').json()['inventory']
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        stored = db.execute('SELECT manifest_json FROM prepared_uploads').fetchone()[0]
        assert stored.encode() == encode_upload_manifest(manifest)
        assert {r[0] for r in db.execute('SELECT name FROM sources')} == {'native.xml', 'native.sql'}
    assert_not_queued(root)


def test_manifest_optional_direct_upload_contract_is_preserved(client):
    c, root, pid = client
    response = direct(c, pid, ready_files())
    assert response.status_code == 200
    assert response.json()['native_assessment']['state'] == 'READY'
    assert response.json()['source_preparation']['mode'] == 'DIRECT_READABLE'
    assert response.json()['source_preparation']['matches_current_source'] is False
    assert stored_state(root)['prepared_uploads'] == []


@pytest.mark.parametrize('unsupported', [False, True], ids=['native-ready', 'unsupported-trigger'])
def test_local_ready_folder_handoff_preserves_integrity_and_native_preflight(client, tmp_path, unsupported):
    c, root, pid = client
    original = tmp_path / 'reviewed-readable-source'
    original.mkdir()
    for name, raw in ready_files():
        if unsupported and name.endswith('.xml'):
            raw = raw.replace(b'</FormModule>', b'<Trigger Name="WHEN-NEW-FORM-INSTANCE" '
                              b'TriggerText="BEGIN NULL; END;"/></FormModule>')
        (original / name).write_bytes(raw)
    job = prepare(original, tmp_path / 'extractions', job_id='prepared-api-handoff')
    assert verify(job)['status'] == 'VERIFIED_REVIEW_REQUIRED'
    ready = job / 'ready'
    frozen = {path.name: path.read_bytes() for path in ready.iterdir()}
    sidecar = frozen[UPLOAD_MANIFEST_NAME]
    files = [(name, raw) for name, raw in frozen.items() if name != UPLOAD_MANIFEST_NAME]
    response = prepared(c, pid, files, raw_manifest=sidecar)
    assert response.status_code == 200, response.text
    report = response.json()
    assert report['source_preparation']['matches_current_source'] is True
    assert report['source_preparation']['extraction_job_id'] == job.name
    assert report['native_assessment']['state'] == ('BLOCKED' if unsupported else 'READY')
    assert_not_queued(root)
    assert {path.name: path.read_bytes() for path in ready.iterdir()} == frozen
    assert verify(job)['approved_for_upload'] is False


@pytest.mark.parametrize('variation', ['absent', 'missing', 'extra', 'mutated', 'renamed', 'case-changed'])
def test_inexact_selected_files_rejected_without_partial_writes(client, variation):
    c, root, pid = client
    assert direct(c, pid, [('keep.txt', b'Keep the existing source history.')]).status_code == 200
    files = ready_files()
    declaration = encode_upload_manifest(public_manifest(files))
    if variation == 'absent':
        files = []
    elif variation == 'missing':
        files = files[:1]
    elif variation == 'extra':
        files += [('extra.txt', b'An undeclared readable source.')]
    elif variation == 'mutated':
        files[0] = (files[0][0], files[0][1].replace(b'Work title', b'Work label'))
    elif variation == 'renamed':
        files[0] = ('renamed.xml', files[0][1])
    else:
        files[0] = ('NATIVE.xml', files[0][1])
    before = stored_state(root)
    response = prepared(c, pid, files, raw_manifest=declaration)
    assert response.status_code == 422, response.text
    assert stored_state(root) == before
    assert_not_queued(root)


@pytest.mark.parametrize('variation', [
    'unknown-field', 'private-inputs', 'approval-field', 'file-path',
    'source-field', 'backend-field', 'case-duplicate', 'duplicate-name',
    'wrong-bytes', 'wrong-digest', 'wrong-combined-hash', 'duplicate-json-key',
    'empty', 'oversize', 'malformed',
])
def test_invalid_public_manifest_is_atomic_and_does_not_echo_private_values(client, variation):
    c, root, pid = client
    files = ready_files()
    manifest = public_manifest(files)
    private = 'private-source-path-marker'
    if variation == 'unknown-field':
        manifest['operator_notes'] = private
    elif variation == 'private-inputs':
        manifest['inputs'] = [{'path': private}]
    elif variation == 'approval-field':
        manifest['approved_external_ai'] = True
    elif variation == 'file-path':
        manifest['files'][0]['name'] = f'../{private}.sql'
    elif variation == 'source-field':
        manifest['files'][0]['source'] = private
    elif variation == 'backend-field':
        manifest['files'][0]['backend'] = private
    elif variation == 'case-duplicate':
        manifest['files'].append({**manifest['files'][0],
                                  'name': manifest['files'][0]['name'].upper()})
    elif variation == 'duplicate-name':
        manifest['files'].append(dict(manifest['files'][0]))
    elif variation == 'wrong-bytes':
        manifest['files'][0]['bytes'] += 1
    elif variation == 'wrong-digest':
        manifest['files'][0]['sha256'] = 'f' * 64
    elif variation == 'wrong-combined-hash':
        manifest['readable_source_hash'] = 'f' * 64
    raw = json.dumps(manifest).encode()
    if variation == 'duplicate-json-key':
        raw = raw.replace(b'"schema_version": 1', b'"schema_version": 1, "schema_version": 1')
    elif variation == 'empty':
        raw = b''
    elif variation == 'oversize':
        raw += b' ' * MAX_MANIFEST_BYTES
    elif variation == 'malformed':
        raw = b'{"files":['
    before = stored_state(root)
    response = prepared(c, pid, files, raw_manifest=raw)
    assert response.status_code == 422, response.text
    assert private not in response.text
    assert stored_state(root) == before


@pytest.mark.parametrize('filename', ['manifest.json', 'status.json', 'inventory.json',
                                      'FOX-READABLE-UPLOAD.JSON', '../fox-readable-upload.json'])
def test_private_or_wrong_manifest_filename_is_not_accepted(client, filename):
    c, root, pid = client
    before = stored_state(root)
    response = prepared(c, pid, filename=filename)
    assert response.status_code == 422
    assert stored_state(root) == before


@pytest.mark.parametrize('name,raw', [
    ('source.fmb', b'raw binary'), ('source.mmb', b'raw binary'),
    ('source.olb', b'raw binary'), ('source.pll', b'raw binary'),
    ('source.zip', b'PK\x03\x04'), ('bad.xml', b'<unclosed>'),
    ('secret.txt', b'password=not-an-uploadable-value'),
    ('records.sql', b'INSERT INTO customers VALUES (1);'),
    ('identifier.txt', b'person@example.com'),
    ('binary.txt', b'\x00binary'),
])
def test_preparation_does_not_bypass_normal_intake(client, name, raw):
    c, root, pid = client
    declaration = encode_upload_manifest(public_manifest(ready_files()))
    before = stored_state(root)
    response = prepared(c, pid, ready_files() + [(name, raw)], raw_manifest=declaration)
    assert response.status_code == 422
    assert stored_state(root) == before


def test_sidecar_must_not_be_sent_as_source_content(client):
    c, root, pid = client
    raw = encode_upload_manifest(public_manifest(ready_files()))
    before = stored_state(root)
    response = direct(c, pid, ready_files() + [(UPLOAD_MANIFEST_NAME, raw)])
    assert response.status_code == 422
    assert stored_state(root) == before


def test_case_duplicate_actual_upload_is_rejected(client):
    c, root, pid = client
    declaration = encode_upload_manifest(public_manifest(ready_files()))
    files = ready_files() + [('NATIVE.XML', ready_files()[0][1])]
    before = stored_state(root)
    assert prepared(c, pid, files, raw_manifest=declaration).status_code == 422
    assert stored_state(root) == before


def test_original_bom_and_crlf_bytes_are_hashed_without_normalization(client):
    c, root, pid = client
    files = [(name, b'\xef\xbb\xbf' + raw.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'))
             for name, raw in ready_files()]
    response = prepared(c, pid, files)
    assert response.status_code == 200, response.text
    entries = {f['name']: f for f in response.json()['source_preparation']['files']}
    for name, raw in files:
        assert entries[name]['bytes'] == len(raw)
        assert entries[name]['sha256'] == hashlib.sha256(raw).hexdigest()
        assert entries[name]['sha256'] != hashlib.sha256(raw[3:]).hexdigest()
    assert response.json()['source_preparation']['matches_current_source'] is True
    # A manifest based on normalized text cannot certify the original uploads.
    normalized = [(name, raw[3:].replace(b'\r\n', b'\n')) for name, raw in files]
    wrong = encode_upload_manifest(public_manifest(normalized))
    before = stored_state(root)
    assert prepared(c, pid, files, raw_manifest=wrong).status_code == 422
    assert stored_state(root) == before


def test_canonical_dedup_ignores_json_style_key_and_file_order_but_appends_event(client):
    c, root, pid = client
    manifest = public_manifest(ready_files())
    first_raw = json.dumps({k: manifest[k] for k in reversed(manifest)}, indent=2).encode()
    first = prepared(c, pid, raw_manifest=first_raw).json()['source_preparation']
    reordered = {**manifest, 'files': [dict(reversed(list(f.items())))
                                      for f in reversed(manifest['files'])]}
    second_raw = json.dumps(reordered, separators=(', ', ': ')).encode()
    second_response = prepared(c, pid, list(reversed(ready_files())), raw_manifest=second_raw)
    assert second_response.status_code == 200
    second = second_response.json()['source_preparation']
    assert first_raw != second_raw
    assert first['receipt_id'] == second['receipt_id']
    assert first['canonical_manifest_sha256'] == second['canonical_manifest_sha256']
    assert second['canonical_manifest_sha256'] not in {
        hashlib.sha256(first_raw).hexdigest(), hashlib.sha256(second_raw).hexdigest(),
    }
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM prepared_uploads').fetchone()[0] == 1
        assert db.execute('SELECT COUNT(*) FROM sources').fetchone()[0] == 2
        events = db.execute("SELECT object_id FROM events WHERE action='prepared_sources_verified' ORDER BY id").fetchall()
        assert events == [(first['receipt_id'],), (first['receipt_id'],)]


def test_latest_upload_event_can_select_an_older_deduplicated_receipt(client):
    c, root, pid = client
    first_manifest = public_manifest(ready_files(), 'extract-first')
    first = prepared(c, pid, manifest=first_manifest).json()['source_preparation']
    second = prepared(c, pid, manifest=public_manifest(ready_files(), 'extract-second')).json()['source_preparation']
    assert first['receipt_id'] != second['receipt_id']
    latest = prepared(c, pid, manifest=first_manifest).json()['source_preparation']
    assert latest['receipt_id'] == first['receipt_id']
    assert latest['extraction_job_id'] == 'extract-first'
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM prepared_uploads').fetchone()[0] == 2
        assert db.execute("SELECT COUNT(*) FROM events WHERE action='prepared_sources_verified'").fetchone()[0] == 3


@pytest.mark.parametrize('later_change', ['extra', 'changed'])
def test_later_direct_upload_dynamically_invalidates_full_current_match(client, later_change):
    c, _, pid = client
    initial = prepared(c, pid).json()['source_preparation']
    files = [('notes.txt', b'Extra scope must be assessed separately.')]
    if later_change == 'changed':
        name, raw = ready_files()[0]
        files = [(name, raw.replace(b'Work title', b'New label'))]
    response = direct(c, pid, files)
    assert response.status_code == 200
    current = response.json()['source_preparation']
    assert current['mode'] == 'PREPARED_SET_PARTIAL_OR_CHANGED'
    assert current['matches_current_source'] is False
    assert current['receipt_id'] == initial['receipt_id']
    assert current['readable_source_hash'] == initial['readable_source_hash']
    assert response.json() == assessment(c, pid)


def test_prepared_subset_does_not_claim_whole_existing_project(client):
    c, _, pid = client
    assert direct(c, pid, [('notes.txt', b'Already present outside prepared set.')]).status_code == 200
    response = prepared(c, pid)
    assert response.status_code == 200
    report = response.json()
    assert report['source_preparation']['mode'] == 'PREPARED_SET_PARTIAL_OR_CHANGED'
    assert report['source_preparation']['matches_current_source'] is False
    assert len(report['files']) == 3
    assert len(report['source_preparation']['files']) == 2


def test_known_older_source_reupload_selects_stored_version_and_preserves_newer_set(client):
    c, root, pid = client
    files = ready_files()
    first = prepared(c, pid, files).json()
    changed_files = [(name, raw.replace(b'Work title', b'New label')) for name, raw in files]
    changed = prepared(c, pid, changed_files,
                       manifest=public_manifest(changed_files, 'extract-new')).json()
    assert changed['source_hash'] != first['source_hash']
    response = prepared(c, pid, files)
    assert response.status_code == 200
    current = response.json()
    assert current['source_hash'] == first['source_hash']
    assert current['selected_source_set_id'] == first['selected_source_set_id']
    assert current['selected_source_set_id'] != changed['selected_source_set_id']
    assert current['source_preparation']['receipt_id'] == first['source_preparation']['receipt_id']
    assert current['source_preparation']['mode'] == 'PREPARED_SET_MATCH'
    assert current['source_preparation']['matches_current_source'] is True
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM sources').fetchone()[0] == 3
        assert db.execute('SELECT COUNT(*) FROM prepared_uploads').fetchone()[0] == 2
        assert db.execute('SELECT COUNT(*) FROM source_sets').fetchone()[0] == 2
        assert db.execute('SELECT current_source_set_id FROM project_source_selection WHERE project=?',
                          (pid,)).fetchone()[0] == first['selected_source_set_id']
        assert db.execute('SELECT source_hash FROM source_sets WHERE id=?',
                          (changed['selected_source_set_id'],)).fetchone()[0] == changed['source_hash']


def test_receipts_are_project_scoped_and_project_ownership_is_enforced(client):
    c, root, pid = client
    first = prepared(c, pid).json()['source_preparation']
    second_pid = new_project(c)
    second = prepared(c, second_pid).json()['source_preparation']
    assert first['receipt_id'] != second['receipt_id']
    assert first['canonical_manifest_sha256'] == second['canonical_manifest_sha256']
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute('UPDATE projects SET owner=? WHERE id=?', ('another-owner', pid))
    before = stored_state(root)
    assert prepared(c, pid).status_code == 404
    assert c.get(f'/api/projects/{pid}').status_code == 404
    assert c.get(f'/api/projects/{pid}/assessment').status_code == 404
    assert stored_state(root) == before
    assert assessment(c, second_pid)['source_preparation'] == second


def test_unauthenticated_upload_cannot_write_sources_or_receipts(client):
    c, root, pid = client
    c.post('/api/logout', json={})
    before = stored_state(root)
    assert prepared(c, pid).status_code == 401
    assert stored_state(root) == before


@pytest.mark.parametrize('field', [
    'approved_redacted_source', 'approved_external_ai', 'approved_prototype_scope',
])
@pytest.mark.parametrize('missing', [False, True], ids=['false', 'absent'])
def test_integrity_receipt_never_grants_processing_consent(client, field, missing):
    c, root, pid = client
    report = prepared(c, pid).json()
    assert report['native_assessment']['state'] == 'READY'
    body = approvals(report)
    if missing:
        del body[field]
    else:
        body[field] = False
    response = c.post(f'/api/projects/{pid}/runs', json=body)
    assert response.status_code == 422
    assert_not_queued(root)


@pytest.mark.parametrize('variation', ['missing-ddl', 'unsupported-trigger', 'unrelated-xml'])
def test_integrity_receipt_never_grants_native_eligibility(client, variation):
    c, root, pid = client
    files = ready_files()
    if variation == 'missing-ddl':
        files = files[:1]
    elif variation == 'unsupported-trigger':
        files[0] = (files[0][0], files[0][1].replace(
            b'</FormModule>',
            b'<Trigger Name="WHEN-NEW-FORM-INSTANCE" TriggerText="BEGIN NULL; END;"/></FormModule>'))
    else:
        files = [('other.xml', b'<catalog><item name="not-a-form"/></catalog>')]
    response = prepared(c, pid, files)
    assert response.status_code == 200, response.text
    report = response.json()
    assert report['source_preparation']['matches_current_source'] is True
    assert report['native_assessment']['state'] == 'BLOCKED'
    assert c.post(f'/api/projects/{pid}/runs', json=approvals(report)).status_code == 409
    assert_not_queued(root)


def test_queued_snapshot_keeps_receipt_descriptive_and_json_out_of_source_files(client):
    c, root, pid = client
    report = prepared(c, pid).json()
    response = c.post(f'/api/projects/{pid}/runs', json=approvals(report))
    assert response.status_code == 202, response.text
    run = response.json()['id']
    snapshot = json.loads((root / 'jobs' / run / 'source-snapshot.json').read_text())
    assert {f['name'] for f in snapshot['files']} == {'native.xml', 'native.sql'}
    assert {f['file'] for f in snapshot['inventory']['files']} == {'native.xml', 'native.sql'}
    assert snapshot['inventory']['source_preparation'] == report['source_preparation']
    assert snapshot['source_hash'] == report['source_hash']
    for source in snapshot['files']:
        assert UPLOAD_MANIFEST_NAME not in source['name']
        assert 'FOX-READABLE-UPLOAD' not in source['text']
        assert 'extract-synthetic-api' not in source['text']
    assert snapshot['approvals']['owner'] == 'jason'
    assert all(snapshot['approvals'][key] is True for key in (
        'redacted_source', 'external_ai', 'synthetic_prototype'))
    assert c.get(f'/api/projects/{pid}/runs/{run}/download').status_code == 409


@pytest.mark.parametrize('corruption', ['manifest', 'canonical-hash', 'source-hash', 'job-id'])
def test_corrupt_stored_receipt_fails_closed_without_hiding_source_assessment(client, corruption):
    c, root, pid = client
    initial = prepared(c, pid).json()
    column, value = {
        'manifest': ('manifest_json', '{not json'),
        'canonical-hash': ('canonical_manifest_sha256', 'f' * 64),
        'source-hash': ('readable_source_hash', 'f' * 64),
        'job-id': ('extraction_job_id', 'extract-corrupt'),
    }[corruption]
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute(f'UPDATE prepared_uploads SET {column}=? WHERE project=?', (value, pid))
    current = assessment(c, pid)
    assert current['source_hash'] == initial['source_hash']
    assert current['files'] == initial['files']
    assert current['native_assessment']['state'] == 'READY'
    assert current['source_preparation']['mode'] == 'PREPARED_RECEIPT_UNAVAILABLE'
    assert current['source_preparation']['matches_current_source'] is False

