"""Read-only historical v1/v2 presentation using real retained release readers.

The reused native fixture has exact package/receipt hashes and is promoted by
the real gate. Provider results are synthetic test observations, not live QA or
human acceptance. Only the confined temporary Windows/POSIX I/O boundary is
isolated; no positive package, proof or release validator is replaced.
"""
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from fox import project_run_status as status
from fox import source_history as history
from test_product_download_lifecycle import product_case, proof_case as native_proof_case, harness, valid_package, durable_state
from test_native_verification import arguments, raw, sha, NOW, POLICY
from test_native_verification_policy import bind_v2
from test_source_history_store import SCHEMA
from test_technical_release import legacy


FIELDS = {'project_id', 'artifact_generated', 'technical_verified', 'human_accepted', 'downloadable',
          'preview_available', 'review_available', 'application_url', 'steps', 'forms', 'recovery', 'error'}
FLAGS = ('artifact_generated', 'technical_verified', 'human_accepted', 'downloadable', 'preview_available', 'review_available')
PRODUCT_URL = status.safe_io.ORDS + '/r/forms2apex_poc/f2a_native_unit_test/'


@pytest.fixture
def proof_case(valid_package, harness, request):
    """Author original product metadata before package hashing and promotion.

    Default preserves the existing unknown-target native fixture. A supplied
    URL is synthetic test input, never a rewrite of a retained QA decision.
    """
    members, release, native = deepcopy(valid_package)
    if hasattr(request, 'param'):
        if request.param is None:
            release.pop('application_url', None)
        else:
            release['application_url'] = request.param
    return native_proof_case.__wrapped__((members, release, native), harness)


@pytest.fixture(autouse=True)
def confined_paths(tmp_path, monkeypatch):
    """Do not require sandbox access to Windows ancestors above this test."""
    base = tmp_path.resolve()
    def confined(path):
        path = Path(path).absolute()
        resolved = path.resolve(strict=True)
        if path != resolved or not resolved.is_relative_to(base):
            raise status.safe_io.VerificationError('Synthetic fixture escaped its temporary root')
        for parent in (path, *path.parents):
            if parent == base:
                break
            if parent.is_symlink():
                raise status.safe_io.VerificationError('Synthetic fixture is linked')
        return resolved
    monkeypatch.setattr(status.safe_io, '_safe_path', confined)


def present(product_case, current_source_hash=None):
    _, root, _, run_id, _, case, _, _ = product_case
    with sqlite3.connect((root / 'fox.sqlite3').as_uri() + '?mode=ro', uri=True) as db:
        db.row_factory = sqlite3.Row
        run = dict(db.execute('SELECT * FROM runs WHERE id=?', (run_id,)).fetchone())
        return status.historical_native_run_status(db, root, run, current_source_hash or case['snapshot']['source_hash'])


def files(root):
    # SQLite changes reader lock/slot bookkeeping in SHM even for mode=ro.
    # Keep all durable database/WAL and retained artifact bytes in the check.
    return {str(path.relative_to(root)): path.read_bytes() for path in root.rglob('*')
            if path.is_file() and path.name != 'fox.sqlite3-shm'}


def accept(product_case):
    client, _, _, _, _, _, url, body = product_case
    result = client.post(url + '/accept', json=body)
    assert result.status_code == 200, result.text


def change_current_source(product_case):
    client, _, project, _, _, case, _, _ = product_case
    response = client.post(f'/api/projects/{project}/sources',
                          files={'files': ('later-source.txt', b'Synthetic later selected source version')})
    assert response.status_code == 200, response.text
    current = client.get(f'/api/projects/{project}').json()['inventory']['source_hash']
    assert current != case['snapshot']['source_hash']
    return current


def test_native_checked_proof_does_not_turn_unknown_product_target_into_qa_preview(product_case):
    _, root, project, run_id, job, case, _, _ = product_case
    proof = json.loads((job / 'technical-verification/verification.json').read_bytes())
    assert proof['schema_version'] in (1, 2)
    before = files(root)
    result = present(product_case)
    assert result is not None and set(result) <= FIELDS
    assert result['project_id'] == project
    assert result['artifact_generated'] is result['technical_verified'] is result['review_available'] is True
    assert result['preview_available'] is False and 'application_url' not in result
    assert result['human_accepted'] is result['downloadable'] is False
    assert proof['clean_application_url'] == case['clean']['application_url']
    assert result['forms'] == []  # Historical single-form proof is not a new project plan.
    assert result['recovery']['kind'] == 'check_status' and result['recovery']['safety'] == 'read_only'
    assert 'error' not in result
    assert files(root) == before
    assert durable_state(root, run_id) == ('VERIFIED', [], 0)


def test_current_source_change_disables_review_but_preserves_exact_historical_proof(product_case):
    current = change_current_source(product_case)
    before = files(product_case[1])
    result = present(product_case, current)
    assert result['artifact_generated'] is result['technical_verified'] is True
    assert result['preview_available'] is False and 'application_url' not in result
    assert result['review_available'] is result['human_accepted'] is result['downloadable'] is False
    assert files(product_case[1]) == before


@pytest.mark.parametrize('proof_case', [PRODUCT_URL,
    PRODUCT_URL.replace(status.safe_io.ORDS.split('/')[2], status.safe_io.ORDS.split('/')[2].upper())],
    indirect=True, ids=['original-product-url', 'hostname-case'])
def test_genuine_api_acceptance_keeps_original_preview_and_historical_download_after_source_change(product_case):
    client, root, _, run_id, job, case, url, _ = product_case
    proof_before = (job / 'technical-verification/verification.json').read_bytes()
    accept(product_case)
    current = change_current_source(product_case)
    before = files(root)
    result = present(product_case, current)
    assert all(result[name] is True for name in ('artifact_generated', 'technical_verified', 'human_accepted', 'downloadable', 'preview_available'))
    assert result['review_available'] is False
    assert result['application_url'] == PRODUCT_URL != case['clean']['application_url']
    assert client.get(url + '/download').content == case['package']
    assert files(root) == before
    assert (job / 'technical-verification/verification.json').read_bytes() == proof_before
    assert durable_state(root, run_id)[2] == 1


@pytest.mark.parametrize('proof_case', [PRODUCT_URL], indirect=True)
def test_project_deployment_api_preserves_genuine_historical_native_release(product_case, monkeypatch):
    client, root, project, run_id, job, case, url, body = product_case
    # Model an upgraded deployment, without changing the older run/proof.
    monkeypatch.setenv('FOX_CONVERSION_PROFILE', 'native-project-v1')
    assert client.get('/api/session').json()['conversion_profile'] == 'native-project-v1'
    proof_before = (job / 'technical-verification/verification.json').read_bytes()
    package_before = (job / 'apex-package.zip').read_bytes()
    def public_run():
        response = client.get(f'/api/projects/{project}')
        assert response.status_code == 200, response.text
        return next(item for item in response.json()['runs'] if item['id'] == run_id)
    result = public_run()
    assert result['project_id'] == project and result['source_hash'] == body['source_hash']
    assert result['state'] == 'VERIFIED'
    assert result['artifact_generated'] is result['technical_verified'] is result['preview_available'] is result['review_available'] is True
    assert result['human_accepted'] is result['downloadable'] is False
    assert result['application_url'] == PRODUCT_URL != case['clean']['application_url']
    assert result['forms'] == []
    accept(product_case)
    accepted = public_run()
    assert accepted['state'] == 'ACCEPTED' and accepted['human_accepted'] is accepted['downloadable'] is True
    assert accepted['review_available'] is False
    assert accepted['application_url'] == PRODUCT_URL
    current = change_current_source(product_case)
    historical = public_run()
    assert historical['source_hash'] != current
    assert historical['artifact_generated'] is historical['technical_verified'] is historical['human_accepted'] is historical['downloadable'] is True
    assert historical['review_available'] is False
    assert historical['application_url'] == PRODUCT_URL
    downloaded = client.get(url + '/download')
    assert downloaded.status_code == 200, (downloaded.status_code, len(downloaded.content))
    assert downloaded.content == package_before == case['package']
    assert (job / 'apex-package.zip').read_bytes() == package_before
    assert (job / 'technical-verification/verification.json').read_bytes() == proof_before


@pytest.mark.parametrize('proof_case', [None, '', 'https://attacker.invalid/', 'javascript:alert(1)',
    PRODUCT_URL.replace('/forms2apex_poc/', '/other_workspace/'),
    PRODUCT_URL.replace('f2a_native_unit_test/', 'wrong_alias/'),
    PRODUCT_URL + '?secret=private', PRODUCT_URL + '#fragment',
    PRODUCT_URL.replace('https://', 'https://private@'), PRODUCT_URL.replace('/ords/', ':443/ords/'),
    PRODUCT_URL.replace('/ords/', '/%6frds/'),
    status.safe_io.ORDS + '/r/fox_qa_261017a/f2a_qa_unit/'], indirect=True)
def test_bound_but_unapproved_original_urls_never_fall_back_to_clean_qa(product_case):
    client, root, _, run_id, job, case, url, _ = product_case
    proof_before = (job / 'technical-verification/verification.json').read_bytes()
    before = files(root)
    result = present(product_case)
    assert result['artifact_generated'] is result['technical_verified'] is result['review_available'] is True
    assert result['preview_available'] is False and 'application_url' not in result
    assert case['clean']['application_url'] not in json.dumps(result)
    assert files(root) == before
    accept(product_case)
    current = change_current_source(product_case)
    accepted = present(product_case, current)
    assert accepted['human_accepted'] is accepted['downloadable'] is True
    assert accepted['preview_available'] is accepted['review_available'] is False
    assert 'application_url' not in accepted
    assert client.get(url + '/download').content == case['package']
    assert (job / 'technical-verification/verification.json').read_bytes() == proof_before
    assert durable_state(root, run_id)[2] == 1


def test_project_deployment_api_does_not_relabel_unproved_history_as_verified(product_case, monkeypatch):
    client, root, project, run_id, _, _, _, _ = product_case
    monkeypatch.setenv('FOX_CONVERSION_PROFILE', 'native-project-v1')
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute('DELETE FROM technical_verifications WHERE run=?', (run_id,))
        db.execute("UPDATE runs SET message='PRIVATE PROVIDER ERROR' WHERE id=?", (run_id,))
    response = client.get(f'/api/projects/{project}')
    assert response.status_code == 200, response.text
    result = next(item for item in response.json()['runs'] if item['id'] == run_id)
    assert all(result[name] is False for name in FLAGS)
    assert result['error']['owner'] == 'OPERATOR'
    assert 'PRIVATE PROVIDER ERROR' not in json.dumps(result)
    assert 'application_url' not in result


@pytest.mark.parametrize('column,value', [('owner', 'other-synthetic-owner'), ('source_hash', '0' * 64), ('artifact_sha256', '0' * 64)])
def test_historical_acceptance_requires_owner_source_and_exact_package(product_case, column, value):
    _, root, _, run_id, _, _, _, _ = product_case
    accept(product_case)
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        # Fixed test-only column choices, never caller-controlled SQL.
        db.execute(f'UPDATE acceptances SET {column}=? WHERE run=?', (value, run_id))
    before = files(root)
    result = present(product_case)
    assert result['artifact_generated'] is result['technical_verified'] is True
    assert result['human_accepted'] is result['downloadable'] is result['review_available'] is False
    assert result['error']['owner'] == 'OPERATOR'
    assert files(root) == before


@pytest.mark.parametrize('relative', ['source-snapshot.json', 'release-evidence.json', 'apex-package.zip',
                                     'technical-verification/verification.json', 'technical-verification/qa-result.json'])
def test_changed_historical_material_never_keeps_permissive_flags(product_case, relative):
    _, root, _, _, job, _, _, _ = product_case
    accept(product_case)
    path = job / relative
    if relative in {'source-snapshot.json', 'release-evidence.json'}:
        value = json.loads(path.read_bytes())
        if relative == 'source-snapshot.json':
            value['files'][0]['text'] += '\nSynthetic altered source bytes'
        else:
            value['application_url'] = PRODUCT_URL
        path.write_text(json.dumps(value), encoding='utf-8')
    else:
        path.write_bytes(path.read_bytes() + b'\n')
    before = files(root)
    result = present(product_case)
    assert result is not None and all(result[name] is False for name in FLAGS)
    assert 'application_url' not in result
    assert result['error']['owner'] == 'OPERATOR'
    assert files(root) == before


def test_old_verified_state_without_retained_decision_is_not_enough(product_case):
    _, root, _, run_id, _, _, _, _ = product_case
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute('DELETE FROM technical_verifications WHERE run=?', (run_id,))
        db.execute("UPDATE runs SET message='PRIVATE PROVIDER ERROR' WHERE id=?", (run_id,))
    before = files(root)
    result = present(product_case)
    assert result is not None and all(result[name] is False for name in FLAGS)
    assert 'PRIVATE PROVIDER ERROR' not in json.dumps(result)
    assert result['error']['owner'] == 'OPERATOR'
    assert files(root) == before


def test_validated_legacy_html_returns_none_without_native_flags(tmp_path):
    root = tmp_path / 'legacy-data'
    run_id = 'fox-' + 'a' * 20
    job = root / 'jobs' / run_id
    job.mkdir(parents=True)
    run = {'id': run_id, 'project': 'legacy-project', 'source_hash': 'a' * 64,
           'state': 'ACCEPTED', 'artifact': None}
    # Reuse only the coherent legacy ZIP builder, not its context/spied readers.
    legacy(SimpleNamespace(root=root, job=job, run=run, checked={}))
    before = files(root)
    with sqlite3.connect(':memory:') as db:
        db.row_factory = sqlite3.Row
        result = status.historical_native_run_status(db, root, run, run['source_hash'])
    assert result is None
    assert files(root) == before


def test_unknown_history_never_returns_legacy_fallback(tmp_path):
    root = tmp_path / 'unknown-data'
    run_id = 'fox-' + 'b' * 20
    job = root / 'jobs' / run_id
    job.mkdir(parents=True)
    (job / 'source-snapshot.json').write_bytes(b'{}')
    run = {'id': run_id, 'project': 'unknown-project', 'source_hash': 'b' * 64,
           'state': 'ACCEPTED', 'artifact': None}
    before = files(root)
    with sqlite3.connect(':memory:') as db:
        db.row_factory = sqlite3.Row
        result = status.historical_native_run_status(db, root, run, run['source_hash'])
    assert result is not None and all(result[name] is False for name in FLAGS)
    assert result['error']['owner'] == 'OPERATOR'
    assert files(root) == before


@pytest.mark.parametrize('version', [1, 2], ids=['historical-v1', 'reusable-v2'])
def test_previously_supported_target_url_case_remains_usable(proof_case, tmp_path, monkeypatch, version):
    # Author a differently cased URL BEFORE any technical decision. Never
    # rewrite a retained proof or its hashes to invent an accepted history.
    case = bind_v2(proof_case) if version == 2 else deepcopy(proof_case)
    case['target']['url'] = case['target']['url'].upper()
    case['qa']['target'] = case['target']
    case['qa']['target_receipt_sha256'] = sha(raw(case['target']))
    root, operator = tmp_path / 'case-varied-data', tmp_path / 'case-varied-operator'
    project, run_id = 'case-varied-project', case['release']['job_id']
    job = root / 'jobs' / run_id
    (job / 'native-pipeline').mkdir(parents=True)
    operator.mkdir()
    case['snapshot']['project'] = project
    (job / 'source-snapshot.json').write_bytes(raw(case['snapshot']))
    (job / 'release-evidence.json').write_bytes(raw(case['release']))
    (job / 'apex-package.zip').write_bytes(case['package'])
    (job / 'native-pipeline/download.json').write_bytes(raw({
        'package_sha256': sha(case['package']), 'source_hash': case['snapshot']['source_hash']}))
    for name, key in zip(status.safe_io.RECEIPT_NAMES, ('clean', 'qa', 'target', 'profile')):
        (operator / name).write_bytes(raw(case[key]))
    policy = case.get('verification_policy', POLICY)
    if version == 2:
        (operator / 'verification-profile.json').write_bytes(policy.raw)
        (operator / 'allocation-receipt.json').write_bytes(case['allocation_raw'])
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.executescript(SCHEMA)
        db.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)',
                   (project, 'synthetic-owner', 'Synthetic', 'Historical URL case', '', 1))
        history.initialize(db)
        history.publish_upload(db, project, case['snapshot']['files'], 1, 'synthetic-owner')
        db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)', (run_id, project, case['snapshot']['source_hash'],
            'QA_REQUIRED', 'Synthetic observed proof pending', arguments(case)['run_created'], 1,
            str((job / 'apex-package.zip').relative_to(root))))
    monkeypatch.setattr(status.safe_io, '_private', lambda path, directory=False: status.safe_io._safe_path(path))
    monkeypatch.setattr(status.safe_io, '_sync_dir', lambda path: None)
    promoted = status.safe_io.promote_native_run(root=root, run_id=run_id, operator_receipt_dir=operator, policy=policy, now=NOW)
    assert promoted['state'] == 'VERIFIED'
    before = files(root)
    with sqlite3.connect((root / 'fox.sqlite3').as_uri() + '?mode=ro', uri=True) as db:
        db.row_factory = sqlite3.Row
        run = dict(db.execute('SELECT * FROM runs WHERE id=?', (run_id,)).fetchone())
        result = status.historical_native_run_status(db, root, run, run['source_hash'])
    assert result['artifact_generated'] is result['technical_verified'] is result['review_available'] is True
    assert result['preview_available'] is False and 'application_url' not in result
    assert 'error' not in result
    assert files(root) == before
