"""Real local callback/SQLite/proof reconstruction, synthetic pipeline setup only."""
from copy import deepcopy
from contextlib import contextmanager
import json
import socket

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from fox import prototype_authority as authority, prototype_job, worker
from fox.opaf import canonical_hash
from forms2apex.target_profile import select_target_profile
from test_prototype_job import queued
from test_prototype_pipeline import TARGET


@pytest.fixture
def prepared(queued, monkeypatch):
    root, job, db, snapshot, client, converter, _ = queued
    # Authored synthetic model evidence on a complete registered target tuple;
    # no external model/database/browser is invoked by this fixture.
    complete = select_target_profile('jsn-native-project-2616-v1')
    for key in ('active', 'scope', 'oci', 'database', 'apex', 'sqlcl'):
        monkeypatch.setitem(TARGET, key, deepcopy(complete[key]))
    for key in ('apex', 'sqlcl', 'apexlang_mmd'):
        monkeypatch.setitem(TARGET['tested_versions'], key, complete['tested_versions'][key])
    snapshot['prototype']['target_profile_sha256'] = canonical_hash(TARGET)
    (job / 'source-snapshot.json').write_text(json.dumps(snapshot))
    original_stage = converter.run_stage
    def authored_stage(stage, request):
        receipt = original_stage(stage, request)
        receipt.update(status='COMPLETE', business_behavior_accepted=False)
        return receipt
    monkeypatch.setattr(converter, 'run_stage', authored_stage)
    worker.process_one(db, root)
    with db() as c:
        message = dict(c.execute('SELECT * FROM runs WHERE id=?', (job.name,)).fetchone())
    assert converter.requests, message['message']
    profile = root / 'profile.json'
    profile.write_text(json.dumps({'target_profile': TARGET, 'target_profile_sha256': canonical_hash(TARGET)}))
    profile.chmod(0o600)
    token = root / 'credentials.json'
    token.write_text(json.dumps({'converter_token': 'synthetic-test-token-not-a-live-secret'}))
    token.chmod(0o600)
    return root, job, db, snapshot, converter.requests[-1], profile, token, client


def invoke(prepared):
    root, _, db, _, request, profile, _, _ = prepared
    return authority.authorize_current(root, db, profile, request)


def test_actual_readonly_reconstruction_and_fresh_generated_owner(prepared, monkeypatch):
    root, job, db, _, request, _, _, model = prepared
    before = {p.relative_to(job): p.read_bytes() for p in job.rglob('*') if p.is_file()}
    calls = deepcopy((model.calls, model.observations))
    def forbidden(*args, **kwargs):
        pytest.fail('Authorization must not invoke network/model/Oracle/subprocess')
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    monkeypatch.setattr(model, 'invoke', forbidden)
    @contextmanager
    def readonly_db():
        with db() as c:
            yield c
            assert c.total_changes == 0
            assert c.execute('PRAGMA query_only').fetchone()[0] == 1
    result = authority.authorize_current(root, readonly_db, prepared[5], request)
    assert result['request_sha256'] == canonical_hash(request)
    assert result['execution_target_sha256'] == canonical_hash(authority.execution_target(TARGET))
    assert set(result) == {'schema_version', 'scope', 'request_sha256', 'job_id', 'project_id',
                           'source_binding', 'target_profile_sha256', 'execution_target_sha256'}
    assert {p.relative_to(job): p.read_bytes() for p in job.rglob('*') if p.is_file()} == before
    assert (model.calls, model.observations) == calls
    with db() as c:
        c.execute("UPDATE runs SET state='PROCESSING'")
    assert invoke(prepared) == result
    with db() as c:
        c.execute("UPDATE projects SET owner='different-owner'")
    with pytest.raises(ValueError, match='Owner'):
        invoke(prepared)


@pytest.mark.parametrize('change', ['owner', 'source_hash', 'source_bytes', 'selection', 'state',
                                   'consent', 'policy', 'target', 'request', 'review', 'zip', 'role', 'prior'])
def test_current_authority_rejects_stale_or_tampered_state(prepared, change):
    root, job, db, snapshot, request, profile, _, _ = prepared
    if change in ('owner', 'source_hash', 'source_bytes', 'selection', 'state'):
        with db() as c:
            if change == 'owner': c.execute("UPDATE projects SET owner='wrong-owner'")
            elif change == 'source_hash': c.execute("UPDATE runs SET source_hash=?", ('0' * 64,))
            elif change == 'source_bytes': c.execute("UPDATE sources SET text=text||' '")
            elif change == 'selection': c.execute('UPDATE project_source_selection SET current_source_set_id=NULL')
            else: c.execute("UPDATE runs SET state='ATTENTION'")
    elif change in ('consent', 'policy'):
        if change == 'consent': snapshot['approvals']['synthetic_prototype'] = False
        else: snapshot['prototype']['approved_policy_id'] = 'not-approved'
        (job / 'source-snapshot.json').write_text(json.dumps(snapshot))
    elif change == 'target':
        value = json.loads(profile.read_text())
        value['target_profile']['apex']['workspace'] = 'OTHER'
        value['target_profile_sha256'] = canonical_hash(value['target_profile'])
        profile.write_text(json.dumps(value))
    elif change == 'request': request['rendering_spec']['project_name'] = 'tampered'
    elif change == 'review':
        path = next((job / 'prototype-pipeline').glob('focus-*/reviewer.json'))
        value = json.loads(path.read_text()); value['output']['verdict'] = 'CHANGES_REQUIRED'
        path.write_text(json.dumps(value))
    elif change == 'zip': (job / 'prototype-pipeline' / 'candidate-apexlang.zip').write_bytes(b'tampered')
    elif change == 'role':
        path = job / 'prototype-pipeline' / 'binding.json'
        value = json.loads(path.read_text()); value['profile_sha256'] = '0' * 64
        path.write_text(json.dumps(value))
    else: request['prior_receipts']['validate']['passed'] = False
    with pytest.raises((ValueError, RuntimeError, KeyError)):
        invoke(prepared)


def test_disabled_route_never_reads_profile_or_credentials(tmp_path, monkeypatch):
    def forbidden(*args): pytest.fail('Disabled authority read protected configuration')
    monkeypatch.setattr(authority, '_protected_token', forbidden)
    monkeypatch.setattr(authority, 'load_prototype_profile', forbidden)
    app = FastAPI()
    assert authority.attach_prototype_authority(app, root=tmp_path, db=None) is False
    assert TestClient(app).post(authority.AUTHORITY_PATH).status_code == 404


def test_local_http_requires_bearer_exact_origin_and_duplicate_free_bounded_json(prepared):
    root, _, db, _, request, profile, token, _ = prepared
    app = FastAPI()
    assert authority.attach_prototype_authority(app, root=root, db=db, enabled=True,
        profile_path=profile, credential_path=token, allowed_origin='https://fox.example.test')
    client = TestClient(app)
    headers = {'Authorization': 'Bearer synthetic-test-token-not-a-live-secret',
               'Origin': 'https://fox.example.test'}
    assert client.post(authority.AUTHORITY_PATH, json=request, headers=headers).status_code == 200
    for bad in ({'Origin': headers['Origin']}, {'Authorization': headers['Authorization']},
                {**headers, 'Authorization': 'Bearer wrong'}, {**headers, 'Origin': 'https://other.test'}):
        assert client.post(authority.AUTHORITY_PATH, json=request, headers=bad,
                           cookies={'fox_session': 'synthetic-cookie'}).status_code in (401, 403)
    for raw in (b'{"job_id":"x","job_id":"y"}', b'{"value":NaN}', b'[]', b'{'):
        assert client.post(authority.AUTHORITY_PATH, content=raw, headers=headers).status_code == 409
    assert client.post(authority.AUTHORITY_PATH, content=b'x' * (authority.MAX_REQUEST_BYTES + 1),
                       headers=headers).status_code == 413


def test_validated_fox_id_is_only_job_selector(prepared):
    for value in ('../fox-job', '/tmp/job', 'fox-' + 'g' * 20, 'fox-' + '1' * 21):
        prepared[4]['job_id'] = value
        with pytest.raises(ValueError): invoke(prepared)


def test_lazy_credential_read_respects_middleware_origin_and_rotation(prepared, monkeypatch):
    root, _, db, _, request, profile, token, _ = prepared
    app = FastAPI()
    reads = []
    original = authority._protected_token
    def observed(path):
        reads.append(path)
        return original(path)
    monkeypatch.setattr(authority, '_protected_token', observed)
    authority.attach_prototype_authority(app, root=root, db=db, enabled=True,
        profile_path=profile, credential_path=token, allowed_origin='https://fox.example.test')
    assert reads == []
    fenced = True
    @app.middleware('http')
    async def admission(request, call_next):
        if fenced:
            return authority.JSONResponse({'detail': 'Synthetic local fresh-admission fence'}, 503)
        return await call_next(request)
    client = TestClient(app)
    headers = {'Authorization': 'Bearer synthetic-test-token-not-a-live-secret',
               'Origin': 'https://fox.example.test'}
    assert client.post(authority.AUTHORITY_PATH, json=request, headers=headers).status_code == 503
    assert reads == []
    fenced = False
    assert client.post(authority.AUTHORITY_PATH, json=request,
                       headers={**headers, 'Origin': 'https://other.test'}).status_code == 403
    assert client.post(authority.AUTHORITY_PATH, json=request,
        headers=[('Origin', headers['Origin']), ('Authorization', headers['Authorization']),
                 ('Authorization', headers['Authorization'])]).status_code == 401
    assert reads == []
    assert client.post(authority.AUTHORITY_PATH, json=request, headers=headers).status_code == 200
    token.write_text(json.dumps({'converter_token': 'synthetic-rotated-converter-test-token'}))
    assert client.post(authority.AUTHORITY_PATH, json=request, headers=headers).status_code == 401
    assert client.post(authority.AUTHORITY_PATH, json=request, headers={**headers,
        'Authorization': 'Bearer synthetic-rotated-converter-test-token'}).status_code == 200
    token.write_text('{')
    assert client.post(authority.AUTHORITY_PATH, json=request, headers=headers).status_code == 503
    assert len(reads) == 4


def test_generated_run_cannot_authorize_earlier_stage_or_tampered_export(prepared):
    request = prepared[4]
    request['prior_receipts'] = {}
    with pytest.raises(ValueError): invoke(prepared)
