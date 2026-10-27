"""Isolated product acceptance/download integration, not real owner acceptance.

These reuse the native package/proof fixtures, real FastAPI handlers, and real
temporary SQLite transactions. Oracle/OPAF results remain synthetic fixture
evidence. No browser, external API, live data, or original retained package is
used or changed; the worker and external transports are disabled.
"""
from copy import deepcopy
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import tempfile

import pytest
from fastapi.testclient import TestClient

# app.py exposes a default app at import time. Keep even that unused default
# instance out of the repository's data folder and any caller's FOX_DATA_DIR.
_IMPORT_DATA = tempfile.TemporaryDirectory(prefix='fox-product-import-')
_PREVIOUS_DATA = os.environ.get('FOX_DATA_DIR')
os.environ['FOX_DATA_DIR'] = _IMPORT_DATA.name
try:
    from fox.app import create_app, password_hash
    from fox import native_verification as gate
    from test_native_pipeline import harness, valid_package
    from test_native_verification import proof_case, raw, sha, arguments, NOW, POLICY
    from test_native_verification_policy import bind_v2
finally:
    if _PREVIOUS_DATA is None:
        os.environ.pop('FOX_DATA_DIR', None)
    else:
        os.environ['FOX_DATA_DIR'] = _PREVIOUS_DATA

ORIGIN = 'http://synthetic-product.test'
OWNER = 'synthetic-product-reviewer'
NOTES = 'Synthetic isolated product regression only; not Jason approval, customer review, or live acceptance.'
FIXTURES = Path(__file__).parent / 'fixtures'


def durable_state(root, run_id):
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        state = db.execute('SELECT state FROM runs WHERE id=?', (run_id,)).fetchone()[0]
        accepted = db.execute('SELECT owner,source_hash,artifact_sha256,notes FROM acceptances WHERE run=?', (run_id,)).fetchall()
        events = db.execute("SELECT COUNT(*) FROM events WHERE object_id=? AND action='human_accepted'", (run_id,)).fetchone()[0]
    return state, accepted, events


@pytest.fixture(params=[1, 2], ids=['historical-v1', 'reusable-v2'])
def product_case(request, proof_case, harness, tmp_path, monkeypatch):
    original_case = deepcopy(proof_case)
    fixture_hashes = {name: sha((FIXTURES / name).read_bytes()) for name in
                      ('native-beta.xml', 'native-beta.sql', 'native-verification-profile-v2.json')}
    original_artifacts = {path: path.read_bytes() for path in harness.job.rglob('*') if path.is_file()}
    case = bind_v2(proof_case) if request.param == 2 else deepcopy(proof_case)
    root = tmp_path / 'isolated-product-data'
    operator = tmp_path / 'isolated-operator-inputs'
    assert root.parent == operator.parent == tmp_path

    def forbidden(*args, **kwargs):
        pytest.fail('External network/process activity is forbidden in the isolated product regression')
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    monkeypatch.setattr(subprocess, 'run', forbidden)
    monkeypatch.setenv('FOX_ADMIN_USERNAME', OWNER)
    monkeypatch.setenv('FOX_PASSWORD_HASH', password_hash('synthetic-product-test-only'))
    monkeypatch.setenv('FOX_PUBLIC_ORIGIN', ORIGIN)
    monkeypatch.setenv('FOX_CONVERSION_PROFILE', gate.PROFILE_ID)
    monkeypatch.setenv('FOX_DATA_DIR', str(root))
    # The existing gate fixture convention tests transaction/content behavior
    # on Windows; it does not pretend that POSIX ownership was checked here.
    monkeypatch.setattr(gate, '_private', lambda path, directory=False: gate._safe_path(path))
    monkeypatch.setattr(gate, '_sync_dir', lambda path: None)

    with TestClient(create_app(root, enable_worker=False), base_url=ORIGIN) as client:
        # Windows asyncio initializes an internal loopback socketpair before
        # the ASGI portal starts. Block socket connects for all product actions
        # after that local event-loop setup; TestClient itself needs no network.
        monkeypatch.setattr(socket.socket, 'connect', forbidden)
        client.headers['Origin'] = ORIGIN
        assert client.post('/api/login', json={'username': OWNER, 'password': 'synthetic-product-test-only'}).status_code == 200
        created = client.post('/api/projects', json={'customer': 'Synthetic local product regression',
                                                    'name': 'Isolated native acceptance lifecycle'})
        assert created.status_code == 201
        project = created.json()['id']
        for source in case['snapshot']['files']:
            response = client.post(f'/api/projects/{project}/sources',
                                   files={'files': (source['name'], source['text'].encode())})
            assert response.status_code == 200
        case['snapshot']['project'] = project
        run_id = case['release']['job_id']
        job = root / 'jobs' / run_id
        (job / 'native-pipeline').mkdir(parents=True)
        (job / 'source-snapshot.json').write_bytes(raw(case['snapshot']))
        (job / 'release-evidence.json').write_bytes(raw(case['release']))
        (job / 'apex-package.zip').write_bytes(case['package'])
        (job / 'native-pipeline/download.json').write_bytes(raw({
            'package_sha256': sha(case['package']), 'source_hash': case['snapshot']['source_hash']}))
        operator.mkdir()
        for name, key in zip(gate.RECEIPT_NAMES, ('clean', 'qa', 'target', 'profile')):
            (operator / name).write_bytes(raw(case[key]))
        policy = case.get('verification_policy', POLICY)
        if request.param == 2:
            (operator / 'verification-profile.json').write_bytes(policy.raw)
            (operator / 'allocation-receipt.json').write_bytes(case['allocation_raw'])
        with sqlite3.connect(root / 'fox.sqlite3') as db:
            db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)', (
                run_id, project, case['snapshot']['source_hash'], 'QA_REQUIRED',
                'Synthetic local proof fixture only', arguments(case)['run_created'], 1,
                str((job / 'apex-package.zip').relative_to(root))))
        url = f'/api/projects/{project}/runs/{run_id}'
        body = {'source_hash': case['snapshot']['source_hash'], 'business_flow_tested': True,
                'remediation_reviewed': True, 'notes': NOTES}
        assert client.get(url + '/download').status_code == 409
        assert client.post(url + '/accept', json=body).status_code == 409
        assert gate.promote_native_run(root=root, run_id=run_id, operator_receipt_dir=operator,
                                      policy=policy, now=NOW)['state'] == 'VERIFIED'
        yield client, root, project, run_id, job, case, url, body

    assert proof_case == original_case
    assert {name: sha((FIXTURES / name).read_bytes()) for name in fixture_hashes} == fixture_hashes
    assert {path: path.read_bytes() for path in original_artifacts} == original_artifacts


def test_verified_requires_explicit_acceptance_then_downloads_exact_native_bytes(product_case):
    client, root, project, run_id, job, case, url, body = product_case
    original_package = case['package']
    original_proof = (job / 'technical-verification/verification.json').read_bytes()
    assert durable_state(root, run_id) == ('VERIFIED', [], 0)
    assert client.get(url + '/download').status_code == 409
    assert client.get(url + '/evidence').json()['technical_verification']['human_acceptance_recorded'] is False

    response = client.post(url + '/accept', json=body)
    expected_hash = sha(original_package)
    assert response.status_code == 200
    assert response.json() == {'id': run_id, 'state': 'ACCEPTED', 'artifact_sha256': expected_hash}
    downloaded = client.get(url + '/download')
    assert downloaded.status_code == 200
    assert downloaded.headers['content-type'] == 'application/zip'
    assert downloaded.headers['content-disposition'] == f'attachment; filename="{run_id}-apex.zip"'
    assert downloaded.content == original_package
    assert sha(downloaded.content) == expected_hash == sha((job / 'apex-package.zip').read_bytes())
    assert durable_state(root, run_id) == ('ACCEPTED', [(OWNER, body['source_hash'], expected_hash, NOTES)], 1)
    assert client.post(url + '/accept', json=body).status_code == 409
    assert durable_state(root, run_id)[2] == 1
    # Technical proof is immutable; synthetic product acceptance is a separate
    # record, not a rewritten claim that the QA operator supplied human review.
    assert (job / 'technical-verification/verification.json').read_bytes() == original_proof
    assert client.get(url + '/evidence').json()['technical_verification']['human_acceptance_recorded'] is False


@pytest.mark.parametrize('change', ['untested', 'unreviewed', 'blank_notes', 'empty_notes',
                                  'missing_business_flag', 'missing_remediation_flag', 'missing_notes',
                                  'missing_source_hash', 'wrong_source_hash'])
def test_incomplete_or_wrongly_bound_acceptance_never_unlocks_download(product_case, change):
    client, root, _, run_id, _, _, url, original = product_case
    body = dict(original)
    if change == 'untested': body['business_flow_tested'] = False
    elif change == 'unreviewed': body['remediation_reviewed'] = False
    elif change == 'blank_notes': body['notes'] = ' \t\n '
    elif change == 'empty_notes': body['notes'] = ''
    elif change == 'missing_business_flag': del body['business_flow_tested']
    elif change == 'missing_remediation_flag': del body['remediation_reviewed']
    elif change == 'missing_notes': del body['notes']
    elif change == 'missing_source_hash': del body['source_hash']
    elif change == 'wrong_source_hash': body['source_hash'] = '0' * 64
    assert client.post(url + '/accept', json=body).status_code == (409 if change == 'wrong_source_hash' else 422)
    assert client.get(url + '/download').status_code == 409
    assert durable_state(root, run_id) == ('VERIFIED', [], 0)


def test_current_source_change_requires_review_of_the_new_version(product_case):
    client, root, project, run_id, _, _, url, body = product_case
    assert client.post(f'/api/projects/{project}/sources',
                       files={'files': ('later-source.txt', b'Synthetic later source version')}).status_code == 200
    assert client.post(url + '/accept', json=body).status_code == 409
    assert client.get(url + '/download').status_code == 409
    assert durable_state(root, run_id) == ('VERIFIED', [], 0)


@pytest.mark.parametrize('when', ['before_acceptance', 'after_acceptance'])
@pytest.mark.parametrize('artifact', ['source-snapshot.json', 'apex-package.zip',
                                     'technical-verification/qa-result.json'])
def test_tampered_bound_source_package_or_receipt_blocks_product_release(product_case, when, artifact):
    client, root, _, run_id, job, _, url, body = product_case
    if when == 'after_acceptance':
        assert client.post(url + '/accept', json=body).status_code == 200
    path = job / artifact
    if artifact == 'source-snapshot.json':
        snapshot = json.loads(path.read_bytes())
        snapshot['files'][0]['text'] += '\nSynthetic tamper after the technical decision'
        path.write_bytes(raw(snapshot))
    else:
        # Even semantically equivalent JSON whitespace changes the retained
        # receipt-byte hash; ZIP changes likewise cannot borrow its old proof.
        path.write_bytes(path.read_bytes() + b'\n')
    assert client.post(url + '/accept', json=body).status_code == 409
    assert client.get(url + '/download').status_code == 409
    assert client.get(url + '/evidence').status_code == 409
    state, accepted, events = durable_state(root, run_id)
    assert state == ('ACCEPTED' if when == 'after_acceptance' else 'VERIFIED')
    assert len(accepted) == events == (1 if when == 'after_acceptance' else 0)
