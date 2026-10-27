"""Authored synthetic Oracle observations; real producer/retained/API checks.

These are not live Oracle/model operations, deployed FOX or business review.
No positive source/package/review/proof validator is replaced.
"""
from copy import deepcopy
import importlib.util
import inspect
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import contract as delivery
from fox.app import create_app, password_hash
from fox.native_project_pipeline import verify_project_package
from test_project_verification_runtime import case, promote, row, counts

ROOT = Path(__file__).resolve().parents[4]


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('EXTERNAL_NETWORK_FORBIDDEN_IN_DELIVERY_TEST')
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    original = socket.socket.connect
    def guarded_connect(self, address):
        # Windows asyncio implements its internal self-pipe through the
        # standard-library socketpair helper, not an external test endpoint.
        caller = inspect.currentframe().f_back
        helper = getattr(socket, '_fallback_socketpair', None)
        if helper is not None and caller.f_code is helper.__code__ and address[0] == '127.0.0.1':
            return original(self, address)
        return forbidden()
    monkeypatch.setattr(socket.socket, 'connect', guarded_connect)


@pytest.fixture(scope='module')
def actual_release(tmp_path_factory):
    from test_project_source import mapped_snapshot
    path = ROOT / 'converter/tests/test_project_release.py'
    spec = importlib.util.spec_from_file_location('_delivery_actual_package', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    with pytest.MonkeyPatch.context() as boundary:
        built = module.build_actual_project_release(tmp_path_factory, boundary,
            source_snapshot=mapped_snapshot(project_id='d' * 32))
        assert verify_project_package(built.package, built.evidence, built.project, built.profile) == delivery.sha(built.package)
    return SimpleNamespace(package=built.package, evidence=deepcopy(built.evidence),
        project=deepcopy(built.project), snapshot=deepcopy(built.snapshot), profile=deepcopy(built.profile))


@pytest.fixture
def exported(case):
    promoted = promote(case)
    expected = {'job_id': case.run_id, 'project_id': case.snapshot['project_id'],
        'source_hash': case.snapshot['source_hash'], 'package_sha256': delivery.sha(case.built.package),
        'proof_sha256': promoted['proof_sha256'], 'fox_image': 'sha256:' + 'a' * 64,
        'release_sha256': 'b' * 64}
    raw = delivery.export_readonly(case.root, expected)
    return case, expected, raw


def change(raw, function):
    value = json.loads(raw); function(value)
    return delivery.canonical(value)


def test_export_is_readonly_and_preserves_exact_original_files(exported):
    case, expected, raw = exported
    value, files, snapshot = delivery.validate_export(raw, expected_sha256=delivery.sha(raw), expected_binding=expected)
    assert value['read_only'] is True and value['live_acceptance_count'] == 0
    assert len(files) == 13 and files['apex-package.zip'] == case.built.package
    assert snapshot == case.snapshot
    assert counts(case) == {'proofs': 1, 'technical_events': 1, 'acceptances': 0}
    assert all((case.job / name).read_bytes() == blob for name, blob in files.items())


def test_independent_final_read_detects_concurrent_owner_acceptance(exported, monkeypatch):
    case, expected, _ = exported
    database = case.root / 'fox.sqlite3'
    with sqlite3.connect(database) as db:
        assert db.execute('PRAGMA journal_mode=WAL').fetchone()[0] == 'wal'
    original = delivery.read
    triggered = False
    def concurrent(path, maximum=delivery.MAX_JSON):
        nonlocal triggered
        raw = original(path, maximum)
        if not triggered and Path(path).name == 'source-snapshot.json':
            triggered = True
            with sqlite3.connect(database) as db:
                db.execute('INSERT INTO acceptances VALUES(?,?,?,?,?,?)', (case.run_id, 'synthetic-owner',
                    expected['source_hash'], expected['package_sha256'], 'Simulated independent owner event', 1))
                db.execute("UPDATE runs SET state='ACCEPTED' WHERE id=?", (case.run_id,))
        return raw
    monkeypatch.setattr(delivery, 'read', concurrent)
    with pytest.raises(delivery.DeliveryError, match='LIVE_ACCEPTANCE_MUST_REMAIN_ABSENT'):
        delivery.export_readonly(case.root, expected)
    assert triggered and counts(case)['acceptances'] == 1


@pytest.mark.parametrize('mutation', [
    lambda v: v.update(live_acceptance_count=1),
    lambda v: v.update(live_acceptance_count=False),
    lambda v: v['run'].update(state='ACCEPTED'),
    lambda v: v['run'].update(artifact='../unrelated.zip'),
    lambda v: v['project'].update(name='Different project name'),
    lambda v: v['project'].update(id='e' * 32),
    lambda v: v['technical_verification'].update(proof_json='{}'),
    lambda v: v['files'].pop('native-project-pipeline/target-profile.json'),
    lambda v: v['files'].update({'../../outside': {'bytes': 1, 'base64': 'YQ==', 'sha256': delivery.sha(b'a')}}),
    lambda v: v['files']['apex-package.zip'].update(bytes=True),
    lambda v: v['files']['source-snapshot.json'].update(base64='not-base64'),
    lambda v: v.update(read_only=False),
])
def test_rehashed_mutations_do_not_bypass_copy_contract(exported, mutation):
    _, expected, raw = exported
    altered = change(raw, mutation)
    with pytest.raises(delivery.DeliveryError):
        delivery.validate_export(altered, expected_sha256=delivery.sha(altered), expected_binding=expected)


def test_real_proof_not_merely_a_verified_state_is_required(case):
    with sqlite3.connect(case.root / 'fox.sqlite3') as connection:
        connection.execute("UPDATE runs SET state='VERIFIED'")
    expected = {'job_id': case.run_id, 'project_id': case.snapshot['project_id'],
        'source_hash': case.snapshot['source_hash'], 'package_sha256': delivery.sha(case.built.package),
        'proof_sha256': 'e' * 64, 'fox_image': 'sha256:' + 'a' * 64, 'release_sha256': 'b' * 64}
    with pytest.raises((delivery.DeliveryError, sqlite3.OperationalError)):
        delivery.export_readonly(case.root, expected)
    assert counts(case)['acceptances'] == 0


def test_normal_synthetic_login_accepts_exact_genuine_copy_only(exported, monkeypatch):
    case, expected, raw = exported
    copied = case.root.parent / 'copy'; copied.mkdir()
    origin = 'http://127.0.0.1:8123'
    monkeypatch.setenv('FOX_PUBLIC_ORIGIN', origin)
    monkeypatch.setenv('FOX_ADMIN_USERNAME', delivery.OWNER)
    monkeypatch.setenv('FOX_PASSWORD_HASH', password_hash('isolated-only-test-password'))
    monkeypatch.setenv('FOX_VERIFICATION_ENABLED', '0')
    monkeypatch.setenv('FOX_CONVERSION_PROFILE', 'native-project-v1')
    app = create_app(copied, enable_worker=False)
    fixture = delivery.seed_isolated(copied, raw, expected_sha256=delivery.sha(raw), expected_binding=expected)
    before = delivery.audit_isolated(copied, raw, expected_sha256=delivery.sha(raw), expected_binding=expected, accepted=False)
    assert before['status'] == 'GENUINE_COPY_VERIFIED'
    route = f"/api/projects/{fixture['project_id']}/runs/{fixture['run_id']}"
    with TestClient(app, base_url=origin) as client:
        client.headers['Origin'] = origin
        assert client.get('/api/projects').status_code == 401
        assert client.post('/api/login', json={'username': delivery.OWNER, 'password': 'isolated-only-test-password'}).status_code == 200
        project = client.get('/api/projects/' + fixture['project_id']).json()
        assert project['runs'][0]['technical_verified'] is True
        assert project['runs'][0]['human_accepted'] is False
        assert len(project['runs'][0]['forms']) == 2
        assert client.get(route + '/download').status_code == 409
        body = {'source_hash': fixture['source_hash'], 'business_flow_tested': True,
                'remediation_reviewed': True, 'notes': delivery.NOTES}
        assert client.post(route + '/accept', json={**body, 'business_flow_tested': False}).status_code == 422
        assert client.post(route + '/accept', json=body).status_code == 200
        assert client.post(route + '/accept', json=body).status_code == 409
        result = client.get(route + '/download')
        assert result.status_code == 200 and result.content == case.built.package
    checked = delivery.audit_isolated(copied, raw, expected_sha256=delivery.sha(raw), expected_binding=expected, accepted=True)
    assert checked['producer_bytes_unchanged'] is True and checked['technical_proof_unchanged'] is True
    assert counts(case)['acceptances'] == 0 and row(case)['state'] == 'VERIFIED'


def test_existing_database_or_job_cannot_be_replaced(exported):
    case, expected, raw = exported
    with pytest.raises(delivery.DeliveryError, match='FRESH_ISOLATED'):
        delivery.seed_isolated(case.root, raw, expected_sha256=delivery.sha(raw), expected_binding=expected)


def test_extra_application_event_prevents_adoption(exported, monkeypatch):
    case, expected, raw = exported
    copied = case.root.parent / 'copy'; copied.mkdir()
    monkeypatch.setenv('FOX_PASSWORD_HASH', password_hash('isolated-only-test-password'))
    create_app(copied, enable_worker=False)
    with sqlite3.connect(copied / 'fox.sqlite3') as db:
        db.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
                   ('someone', 'prior_use', 'prior', 1))
    with pytest.raises(delivery.DeliveryError, match='EXACT_FRESH_SCHEMA_EVENT'):
        delivery.seed_isolated(copied, raw, expected_sha256=delivery.sha(raw), expected_binding=expected)
    assert not (copied / 'jobs').exists()


def test_read_only_image_bootstrap_works_in_fresh_script_namespace(tmp_path):
    image = ROOT / 'work/b27a/bundle/fox'
    assert (image / 'fox/technical_release.py').is_file()
    code = ('import sys,pathlib;sys.path.insert(0,sys.argv[1]);import runtime;'
            'runtime.image_imports(pathlib.Path(sys.argv[2]));import fox.technical_release;'
            'assert "fox.app" not in sys.modules;'
            'assert pathlib.Path(fox.technical_release.__file__).resolve()==pathlib.Path(sys.argv[2])/"fox/technical_release.py";'
            'print("EXACT_IMAGE_READER_IMPORTED_WITHOUT_APP_STORAGE")')
    env = {key: value for key, value in os.environ.items() if key.upper() in
           {'SYSTEMROOT', 'WINDIR', 'PATH', 'PATHEXT', 'TEMP', 'TMP', 'COMSPEC'}}
    result = subprocess.run([sys.executable, '-I', '-B', '-c', code,
        str(Path(__file__).resolve().parents[1]), str(image)], cwd=tmp_path,
        env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    assert result.stdout.strip() == b'EXACT_IMAGE_READER_IMPORTED_WITHOUT_APP_STORAGE'
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize('name', ['source-snapshot.json', 'project-technical-verification/verification.json', 'apex-package.zip'])
def test_producer_tampering_after_clone_is_blocked(exported, monkeypatch, name):
    case, expected, raw = exported
    copied = case.root.parent / 'copy'; copied.mkdir()
    monkeypatch.setenv('FOX_PASSWORD_HASH', password_hash('isolated-only-test-password'))
    create_app(copied, enable_worker=False)
    fixture = delivery.seed_isolated(copied, raw, expected_sha256=delivery.sha(raw), expected_binding=expected)
    path = copied / 'jobs' / fixture['run_id'] / name
    path.write_bytes(path.read_bytes() + b'\n')
    with pytest.raises(delivery.DeliveryError, match='PRODUCER_BYTES_CHANGED'):
        delivery.audit_isolated(copied, raw, expected_sha256=delivery.sha(raw), expected_binding=expected, accepted=False)
