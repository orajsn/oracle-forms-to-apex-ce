"""Synthetic factory/account protocol checks; no secrets, SQLcl, browser or cloud."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from qa.operator import direct_preview_runtime as module
from qa.operator.prototype_runtime_worker import RuntimeWorkerConfig


@pytest.fixture
def case(tmp_path, monkeypatch):
    jobs, stage, qa = (tmp_path / name for name in ('jobs', 'staging', 'qa'))
    for path in (jobs, stage, qa):
        path.mkdir()
    credential = tmp_path / 'synthetic.json'
    raw = json.dumps({'username': 'synthetic-preview', 'password': 'synthetic-only'}).encode()
    credential.write_bytes(raw)
    config = {'schema_version': 1, 'jobs_root': str(jobs), 'staging_jobs_root': str(stage),
              'qa_root': str(qa), 'image_id': 'sha256:' + 'a'*64,
              'credentials_file': str(credential), 'credentials_sha256': hashlib.sha256(raw).hexdigest(),
              'username': 'synthetic-preview', 'target_profile_file': str(tmp_path/'target.json'),
              'sqlcl_path': str(tmp_path/'sql'), 'bearer_token_file': str(tmp_path/'token'),
              'authority_origin': 'http://127.0.0.1:8180', 'synthetic_identity_approved': True}
    profile = {'design_provider': {'provider': 'oci_genai'},
               'apex': {'workspace': 'FORMS2APEX_POC', 'ords_origin': module.ORIGIN},
               'database': {'db_name': module.DB_NAME}, 'sqlcl': {'saved_connection': 'F2A_APEX'}}
    monkeypatch.setattr(module, 'private', lambda path, **kwargs: Path(path))
    monkeypatch.setattr(module.os, 'getuid', lambda: 1000, raising=False)
    monkeypatch.setattr(module.os, 'getgid', lambda: 1000, raising=False)
    monkeypatch.setattr(module.runtime_preflight, 'bound_target_profile', lambda _: deepcopy(profile))
    calls = []
    def sql(path, args, commands, cwd, timeout):
        calls.append((path, args, commands, cwd, timeout))
        return SimpleNamespace(returncode=0, stderr='', stdout='FOX_RUNTIME_ACCOUNT=1\n')
    monkeypatch.setattr(module.sqlcl, '_run_script', sql)
    settings = SimpleNamespace(sqlcl_path=tmp_path/'sql')
    return SimpleNamespace(config=config, profile=profile, settings=settings,
                           credential=credential, raw=raw, calls=calls)


def create(case, authority=lambda value: value):
    return module.build(case.config, settings=case.settings, authority=authority)


def test_factory_is_inert_and_uses_existing_runtime(case):
    runtime = create(case)
    assert isinstance(runtime, RuntimeWorkerConfig)
    assert runtime.staging_jobs_root == Path(case.config['staging_jobs_root'])
    assert case.calls == []
    assert runtime.authorize({'job_id': 'synthetic'}) == {'job_id': 'synthetic'}


def test_current_account_target_and_credential_hash_required(case):
    runtime = create(case)
    result = runtime.browser.credential_authorizer({'job_id': 'synthetic'}, credential_file=case.credential)
    assert result['credentials_sha256'] == case.config['credentials_sha256']
    assert result['username_sha256'] == hashlib.sha256(b'synthetic-preview').hexdigest()
    assert result['workspace'] == 'FORMS2APEX_POC'
    assert len(case.calls) == 1
    _, args, commands, cwd, timeout = case.calls[0]
    assert args == ['-S', '-L', '-name', 'F2A_APEX']
    assert cwd == runtime.staging_jobs_root and timeout == 60
    assert "upper(user_name)='SYNTHETIC-PREVIEW'" in commands[-1]
    assert all('synthetic-only' not in command for command in commands)
    assert not any(word in ' '.join(commands).lower() for word in ('insert ', 'update ', 'delete ', 'create '))


@pytest.mark.parametrize('change', [
    lambda c: c.update(synthetic_identity_approved=False),
    lambda c: c.update(username='Jason'),
    lambda c: c.update(username="qa' OR 1=1--"),
    lambda c: c.update(image_id='latest'),
    lambda c: c.update(credentials_sha256='x'*64),
    lambda c: c.update(staging_jobs_root=c['jobs_root']),
    lambda c: c.update(staging_jobs_root=str(Path(c['jobs_root'])/'nested')),
    lambda c: c.update(unexpected=True),
])
def test_invalid_configuration_fails_before_sql(case, change):
    change(case.config)
    with pytest.raises(RuntimeError):
        create(case)
    assert case.calls == []


@pytest.mark.parametrize('stdout,stderr,code', [
    ('FOX_RUNTIME_ACCOUNT=0', '', 0), ('FOX_RUNTIME_ACCOUNT=2', '', 0),
    ('FOX_RUNTIME_ACCOUNT=1\nORA-00000', '', 0), ('FOX_RUNTIME_ACCOUNT=1', 'warning', 0),
    ('FOX_RUNTIME_ACCOUNT=1', '', 1),
])
def test_failed_missing_or_ambiguous_account_not_authorized(case, monkeypatch, stdout, stderr, code):
    runtime = create(case)
    monkeypatch.setattr(module.sqlcl, '_run_script', lambda *a, **k:
                        SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr))
    with pytest.raises(RuntimeError):
        runtime.browser.credential_authorizer({}, credential_file=case.credential)


def test_changed_credential_never_reaches_sql(case):
    runtime = create(case)
    case.credential.write_text('{}')
    with pytest.raises(RuntimeError):
        runtime.browser.credential_authorizer({}, credential_file=case.credential)
    assert case.calls == []


def test_stale_target_and_authority_rejected(case):
    runtime = create(case)
    case.profile['database']['db_name'] = 'OTHER'
    with pytest.raises(RuntimeError):
        runtime.authorize({})
    assert case.calls == []


def test_authorizer_cannot_mutate_request(case):
    def mutate(value):
        value['changed'] = True
        return value
    runtime = create(case, mutate)
    with pytest.raises(RuntimeError):
        runtime.authorize({})
    assert case.calls == []


def test_duplicate_configuration_keys_rejected():
    with pytest.raises(RuntimeError):
        module.load_json(b'{"a":1,"a":2}')


def test_factory_freezes_operator_configuration(case):
    runtime = create(case)
    case.config['username'] = 'changed-after-construction'
    result = runtime.browser.credential_authorizer({}, credential_file=case.credential)
    assert result['username_sha256'] == hashlib.sha256(b'synthetic-preview').hexdigest()


@pytest.mark.parametrize('origin', ['http://localhost:8180', 'http://127.0.0.1',
                                  'http://127.0.0.1:65536', 'http://127.0.0.1:8180/path'])
def test_factory_rejects_nonexact_loopback_origin(case, origin):
    case.config['authority_origin'] = origin
    with pytest.raises(RuntimeError):
        create(case)
