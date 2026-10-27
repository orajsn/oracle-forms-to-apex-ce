"""Exercise real project release proof through the public authenticated API.

The reused fixture builds the real converter package and detached proof from
authored synthetic observations. Only external transports and the confined
test OS ownership boundary are isolated; no release verifier is replaced.
Acceptance here is a synthetic user's explicit HTTP action, not live approval.
"""
import sqlite3

import pytest
from fastapi.testclient import TestClient

from fox.app import create_app, password_hash
from test_project_verification_runtime import (
    actual_release, case, change_sources, counts, promote, row, sha,
)


ORIGIN = 'http://127.0.0.1:8100'
OWNER = 'synthetic-owner'
PASSWORD = 'synthetic-project-api-password'


@pytest.fixture
def api(case, monkeypatch):
    monkeypatch.setenv('FOX_PASSWORD_HASH', password_hash(PASSWORD))
    monkeypatch.setenv('FOX_ADMIN_USERNAME', OWNER)
    monkeypatch.setenv('FOX_PUBLIC_ORIGIN', ORIGIN)
    monkeypatch.setenv('FOX_CONVERSION_PROFILE', 'native-project-v1')
    monkeypatch.setenv('FOX_VERIFICATION_ENABLED', '0')
    with TestClient(create_app(case.root, enable_worker=False), base_url=ORIGIN) as client:
        client.headers['Origin'] = ORIGIN
        response = client.post('/api/login', json={'username': OWNER, 'password': PASSWORD})
        assert response.status_code == 200
        yield client, case, f"/api/projects/{case.snapshot['project_id']}/runs/{case.run_id}"


def acceptance(case, **changes):
    return {'source_hash': case.snapshot['source_hash'], 'business_flow_tested': True,
            'remediation_reviewed': True,
            'notes': 'Synthetic API test: authored review of both fixture forms.', **changes}


def accepted(api):
    client, case, url = api
    promote(case)
    result = client.post(url + '/accept', json=acceptance(case))
    assert result.status_code == 200, result.text
    assert result.json() == {'id': case.run_id, 'state': 'ACCEPTED',
                             'artifact_sha256': sha(case.built.package)}
    return client, case, url


def test_real_verified_project_requires_explicit_human_action_and_returns_exact_package(api):
    client, case, url = api
    original = case.job.joinpath('apex-package.zip').read_bytes()
    promote(case)
    result = client.get(url + '/evidence')
    assert result.status_code == 200, result.text
    evidence = result.json()
    technical = evidence.pop('technical_verification')
    assert evidence == case.built.evidence
    assert technical['scope'] == 'fox-project-technical-verification-v1'
    assert technical['package_sha256'] == sha(original)
    assert len(technical['form_results']) == 2
    assert technical['human_acceptance_recorded'] is False
    assert counts(case)['acceptances'] == 0
    assert client.get(url + '/download').status_code == 409
    assert client.post(url + '/accept', json=acceptance(case, business_flow_tested=False)).status_code == 422
    assert client.post(url + '/accept', json=acceptance(case, remediation_reviewed=False)).status_code == 422
    assert counts(case)['acceptances'] == 0

    response = client.post(url + '/accept', json=acceptance(case))
    assert response.status_code == 200, response.text
    assert response.json()['artifact_sha256'] == sha(original)
    assert row(case)['state'] == 'ACCEPTED'
    with sqlite3.connect(case.root / 'fox.sqlite3') as db:
        receipt = db.execute('SELECT owner,source_hash,artifact_sha256,notes FROM acceptances WHERE run=?',
                             (case.run_id,)).fetchone()
        events = db.execute("SELECT COUNT(*) FROM events WHERE action='human_accepted' AND object_id=?",
                            (case.run_id,)).fetchone()[0]
    assert receipt == (OWNER, case.snapshot['source_hash'], sha(original), acceptance(case)['notes'])
    assert events == 1
    download = client.get(url + '/download')
    assert download.status_code == 200, download.text
    assert download.content == original == case.built.package
    assert download.headers['content-type'] == 'application/zip'
    assert case.job.joinpath('apex-package.zip').read_bytes() == original
    # Human acceptance stays a separate database record, not a rewritten proof.
    evidence_after = client.get(url + '/evidence')
    assert evidence_after.status_code == 200
    assert evidence_after.json()['technical_verification'] == technical


@pytest.mark.parametrize('state', ['QA_REQUIRED', 'REVIEW_REQUIRED', 'VERIFIED'])
def test_unproved_project_cannot_be_accepted_through_a_legacy_state(api, state):
    client, case, url = api
    with sqlite3.connect(case.root / 'fox.sqlite3') as db:
        db.execute('UPDATE runs SET state=? WHERE id=?', (state, case.run_id))
    before = row(case)
    result = client.post(url + '/accept', json=acceptance(case))
    assert result.status_code == 409, result.text
    assert client.get(url + '/download').status_code == 409
    if state == 'VERIFIED':
        assert client.get(url + '/evidence').status_code == 409
    assert row(case) == before
    assert counts(case) == {'proofs': 0, 'technical_events': 0, 'acceptances': 0}


def test_acceptance_requires_current_selected_complete_sources(api):
    client, case, url = api
    promote(case)
    change_sources(case)
    result = client.post(url + '/accept', json=acceptance(case))
    assert result.status_code == 409, result.text
    assert result.json()['detail'] == 'Sources changed. Test and accept the current source version.'
    assert row(case)['state'] == 'VERIFIED'
    assert counts(case)['acceptances'] == 0
    assert client.get(url + '/download').status_code == 409


def test_accepted_historical_source_keeps_its_exact_download_and_proof(api):
    client, case, url = accepted(api)
    before_row, before_counts = row(case), counts(case)
    proof_before = client.get(url + '/evidence').json()['technical_verification']
    change_sources(case)
    result = client.get(url + '/download')
    assert result.status_code == 200, result.text
    assert result.content == case.built.package
    evidence = client.get(url + '/evidence')
    assert evidence.status_code == 200, evidence.text
    assert evidence.json()['technical_verification'] == proof_before
    assert row(case) == before_row
    assert counts(case) == before_counts


TAMPER_PATHS = ['source-snapshot.json', 'release-evidence.json', 'apex-package.zip',
                'project-technical-verification/verification.json',
                'project-technical-verification/qa-result.json']


@pytest.mark.parametrize('relative', TAMPER_PATHS)
def test_changed_exact_evidence_blocks_human_acceptance_without_mutation(api, relative):
    client, case, url = api
    promote(case)
    before_row, before_counts = row(case), counts(case)
    path = case.job / relative
    # Whitespace keeps JSON parseable and appending preserves ZIP readability;
    # the exact retained-byte proof must still reject every changed input.
    path.write_bytes(path.read_bytes() + b'\n')
    result = client.post(url + '/accept', json=acceptance(case))
    assert result.status_code == 409, result.text
    assert row(case) == before_row
    assert counts(case) == before_counts


@pytest.mark.parametrize('relative', TAMPER_PATHS)
def test_changed_accepted_evidence_blocks_evidence_and_download(api, relative):
    client, case, url = accepted(api)
    before_row, before_counts = row(case), counts(case)
    path = case.job / relative
    path.write_bytes(path.read_bytes() + b'\n')
    assert client.get(url + '/evidence').status_code == 409
    assert client.get(url + '/download').status_code == 409
    assert row(case) == before_row
    assert counts(case) == before_counts


@pytest.mark.parametrize(('column', 'replacement'), [
    ('owner', 'another-synthetic-owner'), ('source_hash', '0' * 64), ('artifact_sha256', '0' * 64),
])
def test_acceptance_record_must_match_owner_source_and_exact_package(api, column, replacement):
    client, case, url = accepted(api)
    # Column identifiers are fixed test parameters, never request input.
    with sqlite3.connect(case.root / 'fox.sqlite3') as db:
        db.execute(f'UPDATE acceptances SET {column}=? WHERE run=?', (replacement, case.run_id))
    before_row, before_counts = row(case), counts(case)
    result = client.get(url + '/download')
    assert result.status_code == 409, (result.status_code, result.headers.get('content-type'), len(result.content))
    assert row(case) == before_row
    assert counts(case) == before_counts
