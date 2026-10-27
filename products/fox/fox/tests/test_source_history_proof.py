"""Local synthetic source-history compatibility with the real native proof gate.

The retained receipts describe fabricated test data, not a real APEX deployment.
Only the existing POSIX ownership/fsync test hooks are adapted for Windows;
detached verification, promotion, acceptance and download stay unmocked.
"""
from copy import deepcopy
from pathlib import Path
import sqlite3
import sys

import pytest

ROOT_TESTS = Path(__file__).resolve().parent
if str(ROOT_TESTS) not in sys.path:
    sys.path.append(str(ROOT_TESTS))

from fox import native_verification as gate
from fox.intake import inventory
from test_native_pipeline import harness, valid_package
from test_native_verification import NOW, POLICY, arguments, proof_case, raw, sha
from test_native_verification_policy import bind_v2
from test_source_history_api import (client, history, no_external_actions, selected,
                                     select, settings, upload)


@pytest.fixture(params=[1, 2], ids=['historical-v1', 'reusable-v2'])
def native_case(request, client, proof_case, harness, monkeypatch, tmp_path):
    c, root, pid = client
    assert Path(gate.__file__).resolve().parent == Path(__file__).resolve().parents[1] / 'fox'
    monkeypatch.setenv('FOX_CONVERSION_PROFILE', gate.PROFILE_ID)
    original_case = deepcopy(proof_case)
    case = bind_v2(proof_case) if request.param == 2 else deepcopy(proof_case)
    sources = [(item['name'], item['text'].encode('utf-8')) for item in case['snapshot']['files']]
    upload(c, pid, sources)
    source_a = selected(c, pid)
    assert source_a['source_hash'] == case['snapshot']['source_hash']
    case['snapshot']['project'] = pid
    rid = case['release']['job_id']
    job = root / 'jobs' / rid
    (job / 'native-pipeline').mkdir(parents=True)
    (job / 'source-snapshot.json').write_bytes(raw(case['snapshot']))
    (job / 'release-evidence.json').write_bytes(raw(case['release']))
    (job / 'apex-package.zip').write_bytes(case['package'])
    (job / 'native-pipeline' / 'download.json').write_bytes(raw({
        'package_sha256': sha(case['package']), 'source_hash': case['snapshot']['source_hash']}))
    operator = tmp_path.parent / (tmp_path.name + '-history-operator')
    operator.mkdir()
    for name, key in zip(gate.RECEIPT_NAMES, ('clean', 'qa', 'target', 'profile')):
        (operator / name).write_bytes(raw(case[key]))
    policy = case.get('verification_policy', POLICY)
    if request.param == 2:
        (operator / 'verification-profile.json').write_bytes(policy.raw)
        (operator / 'allocation-receipt.json').write_bytes(case['allocation_raw'])
    # Portable transaction/content tests do not claim Windows ACL verification.
    monkeypatch.setattr(gate, '_private', lambda path, directory=False: gate._safe_path(path))
    monkeypatch.setattr(gate, '_sync_dir', lambda path: None)
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)', (
            rid, pid, case['snapshot']['source_hash'], 'QA_REQUIRED',
            'Synthetic pending technical verification.', arguments(case)['run_created'], 1,
            str((job / 'apex-package.zip').relative_to(root))))
    model_calls = deepcopy(harness.model_calls)
    gateway_calls = deepcopy(harness.calls)
    result = dict(c=c, root=root, pid=pid, rid=rid, job=job, operator=operator,
                  proof=case, policy=policy, proof_version=request.param,
                  a=source_a, base=f'/api/projects/{pid}/runs/{rid}')
    yield result
    # Building the fabricated package above uses local fake harness responses;
    # source selection, proof checks and HTTP routes must invoke none of them.
    assert harness.model_calls == model_calls
    assert harness.calls == gateway_calls
    assert harness.client_constructions == harness.gateway_constructions == 0
    assert proof_case == original_case


def promote(case):
    return gate.promote_native_run(root=case['root'], run_id=case['rid'],
        operator_receipt_dir=case['operator'], policy=case['policy'], now=NOW)


def accept_body(case):
    return dict(source_hash=case['a']['source_hash'], business_flow_tested=True,
                remediation_reviewed=True, notes='Synthetic source-history proof test only.')


def revision_b(case):
    source = next(item for item in case['proof']['snapshot']['files'] if item['name'].endswith('.xml'))
    changed = source['text'].encode('utf-8') + b'\n<!-- Synthetic revision B marker. -->\n'
    upload(case['c'], case['pid'], [(source['name'], changed)])
    source_b = selected(case['c'], case['pid'])
    assert source_b['id'] != case['a']['id']
    assert source_b['source_hash'] != case['a']['source_hash']
    return source_b


def counts(case):
    with sqlite3.connect(case['root'] / 'fox.sqlite3') as db:
        return {
            'runs': db.execute('SELECT COUNT(*) FROM runs').fetchone()[0],
            'acceptances': db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0],
            'verified': db.execute("SELECT COUNT(*) FROM events WHERE action='native_technical_verified'").fetchone()[0],
            'accepted': db.execute("SELECT COUNT(*) FROM events WHERE action='human_accepted'").fetchone()[0],
        }


def frozen_run(case):
    with sqlite3.connect(case['root'] / 'fox.sqlite3') as db:
        state = {'runs': db.execute('SELECT * FROM runs ORDER BY id').fetchall(),
                 'acceptances': db.execute('SELECT * FROM acceptances ORDER BY run').fetchall(),
                 'approval_events': db.execute("SELECT * FROM events WHERE action IN "
                    "('approved_conversion','human_accepted','native_technical_verified') ORDER BY id").fetchall()}
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='technical_verifications'").fetchone():
            state['proofs'] = db.execute('SELECT * FROM technical_verifications ORDER BY run').fetchall()
    state['files'] = {str(item.relative_to(case['job'])): item.read_bytes()
                      for item in case['job'].rglob('*') if item.is_file()}
    return state


def test_accepted_historical_native_package_remains_downloadable(native_case):
    case = native_case
    assert promote(case)['state'] == 'VERIFIED'
    assert case['c'].post(case['base'] + '/accept', json=accept_body(case)).status_code == 200
    retained = frozen_run(case)
    source_b = revision_b(case)
    assert selected(case['c'], case['pid'])['id'] == source_b['id']
    response = case['c'].get(case['base'] + '/download')
    assert response.status_code == 200
    assert response.content == case['proof']['package']
    evidence = case['c'].get(case['base'] + '/evidence')
    assert evidence.status_code == 200
    assert evidence.json()['technical_verification']['schema_version'] == case['proof_version']
    assert evidence.json()['technical_verification']['source_manifest_sha256'] == case['a']['source_hash']
    assert evidence.json()['technical_verification']['human_acceptance_recorded'] is False
    assert frozen_run(case) == retained
    versions = {item['id']: item for item in history(case['c'], case['pid'])['source_sets']}
    assert versions[case['a']['id']]['run_ids'] == [case['rid']]
    assert versions[source_b['id']]['run_ids'] == []
    assert counts(case) == {'runs': 1, 'acceptances': 1, 'verified': 1, 'accepted': 1}


def test_verified_old_run_requires_explicit_source_selection_before_acceptance(native_case):
    case = native_case
    assert promote(case)['state'] == 'VERIFIED'
    source_b = revision_b(case)
    before = frozen_run(case)
    assert case['c'].post(case['base'] + '/accept', json=accept_body(case)).status_code == 409
    assert case['c'].get(case['base'] + '/download').status_code == 409
    assert frozen_run(case) == before
    response = select(case['c'], case['pid'], case['a']['id'], source_b['id'])
    assert response.status_code == 200
    assert response.json()['selection_changed'] is True
    assert response.json()['assessment_summary']['source_hash'] == case['a']['source_hash']
    assert frozen_run(case) == before
    assert counts(case) == {'runs': 1, 'acceptances': 0, 'verified': 1, 'accepted': 0}
    assert case['c'].get(case['base'] + '/download').status_code == 409
    assert case['c'].post(case['base'] + '/accept', json=accept_body(case)).status_code == 200
    assert case['c'].get(case['base'] + '/download').content == case['proof']['package']


def test_first_promotion_uses_selected_set_not_global_latest_file_rows(native_case):
    case = native_case
    source_b = revision_b(case)
    with pytest.raises(gate.VerificationError, match='sources changed'):
        promote(case)
    assert counts(case) == {'runs': 1, 'acceptances': 0, 'verified': 0, 'accepted': 0}
    response = select(case['c'], case['pid'], case['a']['id'], source_b['id'])
    assert response.status_code == 200
    with sqlite3.connect(case['root'] / 'fox.sqlite3') as db:
        db.row_factory = sqlite3.Row
        global_latest = [dict(row) for row in db.execute('''SELECT s.* FROM sources s
            WHERE s.project=? AND s.rowid=(SELECT MAX(n.rowid) FROM sources n
            WHERE n.project=s.project AND n.name=s.name) ORDER BY s.name''', (case['pid'],))]
        assert inventory(global_latest)['source_hash'] == source_b['source_hash']
    assert promote(case)['state'] == 'VERIFIED'
    assert counts(case) == {'runs': 1, 'acceptances': 0, 'verified': 1, 'accepted': 0}
    assert case['c'].get(case['base'] + '/download').status_code == 409


@pytest.mark.parametrize('missing', [
    'approved_redacted_source', 'approved_external_ai', 'approved_prototype_scope'])
def test_selection_does_not_restore_prior_processing_consents(native_case, missing):
    case = native_case
    assert promote(case)['state'] == 'VERIFIED'
    source_b = revision_b(case)
    before = frozen_run(case)
    response = select(case['c'], case['pid'], case['a']['id'], source_b['id'])
    assert response.status_code == 200
    assert 'approvals' not in response.json()['source_set']
    assert 'approvals' not in response.json()['assessment_summary']
    response = select(case['c'], case['pid'], source_b['id'], case['a']['id'])
    assert response.status_code == 200
    assert 'approvals' not in response.json()['source_set']
    assert 'approvals' not in response.json()['assessment_summary']
    body = dict(source_hash=source_b['source_hash'], approved_redacted_source=True,
                approved_external_ai=True, approved_prototype_scope=True)
    body[missing] = False
    refused = case['c'].post(f"/api/projects/{case['pid']}/runs", json=body)
    assert refused.status_code == 422
    assert 'Confirm redaction' in refused.json()['detail']
    assert frozen_run(case) == before
    assert case['c'].get(case['base'] + '/download').status_code == 409


def test_selection_never_duplicates_accepted_run_or_technical_decision(native_case):
    case = native_case
    promote(case)
    assert case['c'].post(case['base'] + '/accept', json=accept_body(case)).status_code == 200
    source_b = revision_b(case)
    before = frozen_run(case)
    for target, expected in [(case['a']['id'], source_b['id']),
                             (case['a']['id'], case['a']['id']),
                             (source_b['id'], case['a']['id'])]:
        assert select(case['c'], case['pid'], target, expected).status_code == 200
        assert frozen_run(case) == before
    assert promote(case)['idempotent'] is True
    assert frozen_run(case) == before
    assert counts(case) == {'runs': 1, 'acceptances': 1, 'verified': 1, 'accepted': 1}
    assert case['c'].get(case['base'] + '/download').content == case['proof']['package']


def test_stale_selection_does_not_bypass_old_run_acceptance_guard(native_case):
    case = native_case
    promote(case)
    source_b = revision_b(case)
    before = frozen_run(case)
    response = select(case['c'], case['pid'], case['a']['id'], case['a']['id'])
    assert response.status_code == 409
    assert selected(case['c'], case['pid'])['id'] == source_b['id']
    assert case['c'].post(case['base'] + '/accept', json=accept_body(case)).status_code == 409
    assert frozen_run(case) == before
    assert counts(case) == {'runs': 1, 'acceptances': 0, 'verified': 1, 'accepted': 0}


@pytest.mark.parametrize('path', ['apex-package.zip', 'technical-verification/qa-result.json'])
def test_historical_download_still_rechecks_exact_retained_proof(native_case, path):
    case = native_case
    promote(case)
    assert case['c'].post(case['base'] + '/accept', json=accept_body(case)).status_code == 200
    revision_b(case)
    (case['job'] / path).write_bytes(b'changed synthetic retained artifact')
    assert case['c'].get(case['base'] + '/download').status_code == 409
    assert case['c'].get(case['base'] + '/evidence').status_code == 409
    assert counts(case) == {'runs': 1, 'acceptances': 1, 'verified': 1, 'accepted': 1}
