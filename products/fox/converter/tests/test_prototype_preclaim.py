"""Actual local HTTP receiver; SQLcl replies authored, no external operations."""
from copy import deepcopy
import base64
import hashlib
from types import SimpleNamespace

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from forms2apex import prototype_gateway as gateway
from forms2apex.prototype_routes import attach_prototype_routes
from forms2apex.target_profile import select_target_profile
from test_prototype_gateway import case, authority_bundle, rebind_bundle
from test_prototype_routes import MCP


@pytest.fixture
def staged(case):
    bundle = authority_bundle(case)
    members = {row['path']: base64.b64decode(row['content_base64']) for row in bundle['files']}
    binding = gateway._authority_json(members['binding.json'])
    binding['project_id'] = case.request['project_id']
    members['binding.json'] = gateway.canonical(binding)
    members['native-plan.json'] = gateway.canonical({k: case.request[k] for k in ('plan_sha256', 'rendering_spec')})
    members['rendered.json'] = gateway.canonical({'zip_sha256': case.request['rendered_zip_sha256']})
    members['candidate-apexlang.zip'] = gateway.native_blueprint.deterministic_prototype_zip(case.request['rendering_spec'])
    bundle['source_authority']['binding_sha256'] = gateway.digest(binding)
    case.request['source_authority'] = deepcopy(bundle['source_authority'])
    for row in bundle['files']:
        raw = members[row['path']]
        row.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                   content_base64=base64.b64encode(raw).decode())
    rebind_bundle(bundle)
    case.adapter.target_profile_loader = lambda _: select_target_profile('jsn-native-project-2616-v1')
    case.adapter.authorize.authorize_preclaim = lambda request, record: deepcopy(request)
    case.adapter.stage_source_authority(case.request['job_id'], bundle)
    return case


def files(case):
    return {p.relative_to(case.settings.jobs_root).as_posix(): p.read_bytes()
            for p in case.settings.jobs_root.rglob('*') if p.is_file()}


def test_positive_http_witness_then_one_first_validation_claim(staged):
    case = staged
    mcp = MCP()
    attach_prototype_routes(mcp, case.adapter, SimpleNamespace(bearer_token='synthetic-preclaim-token'))
    headers = {'Authorization': 'Bearer synthetic-preclaim-token'}
    path = '/fox/prototype/jobs/' + case.request['job_id']
    before = files(case)
    with TestClient(Starlette(routes=mcp.routes)) as client:
        assert client.get(path + '/stages/validate', headers=headers).status_code == 404
        response = client.post(path + '/validate-preclaim-witness', json=case.request, headers=headers)
        assert response.status_code == 200, response.text
        witness = response.json()
        assert witness['source_review_authorized'] is False
        assert files(case) == before and case.calls == []
        response = client.post(path + '/continue-validation',
            json={'request': case.request, 'witness': witness, 'record_sha256':'a'*64}, headers=headers)
        assert response.status_code == 200, response.text
        assert response.json()['passed'] is True and case.calls == ['validate']
        assert client.post(path + '/continue-validation',
            json={'request': case.request, 'witness': witness, 'record_sha256':'a'*64}, headers=headers).status_code == 409
        assert case.calls == ['validate']
        assert client.get(path + '/stages/validate', headers=headers).json() == response.json()


@pytest.mark.parametrize('entry', ['snapshot.json', 'candidate-apexlang.zip', 'validate-request.json',
    'validate-intent.json', 'validation.log', 'validate.json', 'prepare_schema-intent.json',
    'import.json', 'runtime', 'unknown'])
def test_every_attempt_or_unknown_entry_refuses(staged, entry):
    root = staged.settings.jobs_root / staged.request['job_id'] / 'prototype-converter'
    (root / entry).write_bytes(b'preserved synthetic evidence')
    before = files(staged)
    with pytest.raises(RuntimeError, match='PRECLAIM_ATTEMPT_OR_UNKNOWN'):
        staged.adapter.validate_preclaim_witness(staged.request)
    assert files(staged) == before and not staged.calls


def test_callback_race_rechecked_before_snapshot_or_claim(staged):
    witness = staged.adapter.validate_preclaim_witness(staged.request)
    root = staged.settings.jobs_root / staged.request['job_id'] / 'prototype-converter'
    def competing(request):
        (root / 'validate-intent.json').write_bytes(b'unknown competing claim')
        return request
    competing.authorize_preclaim=lambda request,record:deepcopy(request)
    staged.adapter.authorize = competing
    with pytest.raises(RuntimeError, match='PRECLAIM_ATTEMPT_OR_UNKNOWN'):
        staged.adapter.continue_validation(staged.request, witness, 'a'*64)
    assert not (root / 'snapshot.json').exists() and not staged.calls


@pytest.mark.parametrize('field',['witness_sha256','manifest_sha256','execution_target_sha256','receiver_sha256','request_sha256'])
def test_changed_witness_cannot_authorize_a_claim(staged,field):
    witness=staged.adapter.validate_preclaim_witness(staged.request)
    witness[field]='0'*64
    before=files(staged)
    with pytest.raises(RuntimeError,match='WITNESS_CHANGED'):
        staged.adapter.continue_validation(staged.request,witness,'a'*64)
    assert files(staged)==before and not staged.calls


def test_missing_typed_owner_callback_cannot_use_normal_callback_as_consent(staged):
    witness=staged.adapter.validate_preclaim_witness(staged.request)
    staged.adapter.authorize=lambda request:deepcopy(request)
    before=files(staged)
    with pytest.raises(RuntimeError,match='PRECLAIM_OWNER_AUTHORIZATION_UNAVAILABLE'):
        staged.adapter.continue_validation(staged.request,witness,'a'*64)
    assert files(staged)==before and not staged.calls


def test_response_failure_after_exclusive_claim_has_no_new_witness_or_replay(staged):
    witness=staged.adapter.validate_preclaim_witness(staged.request)
    def uncertain(*args):
        staged.calls.append('validate')
        raise TimeoutError('Authored SQLcl result uncertainty')
    staged.adapter.validator=uncertain
    with pytest.raises(TimeoutError): staged.adapter.continue_validation(staged.request,witness,'a'*64)
    root=staged.settings.jobs_root/staged.request['job_id']/'prototype-converter'
    assert (root/'validate-intent.json').is_file() and not (root/'validate.json').exists()
    for _ in range(2):
        with pytest.raises(RuntimeError,match='ATTEMPT_OR_UNKNOWN'):
            staged.adapter.continue_validation(staged.request,witness,'a'*64)
    assert staged.calls==['validate']


def test_active_receiver_serializes_witness_behind_actual_claim(staged):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    started,release=Event(),Event()
    original=staged.adapter.validator
    def held(*args):
        started.set();assert release.wait(5)
        return original(*args)
    staged.adapter.validator=held
    with ThreadPoolExecutor(max_workers=2) as pool:
        run=pool.submit(staged.adapter.run_stage,'validate',staged.request)
        assert started.wait(5)
        inspect=pool.submit(staged.adapter.validate_preclaim_witness,staged.request)
        assert not inspect.done()
        release.set();assert run.result()['passed']
        with pytest.raises(RuntimeError,match='ATTEMPT_OR_UNKNOWN'): inspect.result()
    assert staged.calls==['validate']
