"""Synthetic factory tests; no credentials, cloud, database or browser calls."""
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from qa.operator import prototype_host as host
USERNAME = 'FOX_SYNTHETIC_TEST'


def test_account_probe_is_select_only_and_bound_to_saved_connection():
    calls = []
    def run(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(stderr=b'', stdout=(
            f'IDENTITY={host.DB}|{host.WORKSPACE}\n'
            f'WORKSPACE={host.WORKSPACE}|{host.WORKSPACE}|9009446931169094\n'
            f'ACCOUNT={USERNAME}|No\n').encode())
    value = host.observe_account({'converter_id': 'a'*64, 'username':USERNAME}, run=run)
    assert value['compartment_id'] == host.COMPARTMENT
    args, kwargs = calls[0]
    assert args[-5:] == ['-nohistory', '-S', '-L', '-name', 'F2A_APEX']
    sql = kwargs['data'].decode().lower()
    assert 'set transaction read only;' in sql and 'rollback;' in sql
    assert all(word not in sql for word in ('insert ', 'update ', 'delete ', 'create ', 'alter ', 'password'))


@pytest.mark.parametrize('output', [b'', b'ACCOUNT=unexpected|No',
    (f'IDENTITY={host.DB}|{host.WORKSPACE}\n'
     f'WORKSPACE={host.WORKSPACE}|{host.WORKSPACE}|9009446931169094\n'
     f'ACCOUNT={USERNAME}|Yes\n').encode()])
def test_account_probe_rejects_missing_wrong_or_locked_account(output):
    with pytest.raises(RuntimeError):
        host.observe_account({'converter_id': 'a'*64,'username':USERNAME},
            run=lambda *args, **kwargs: SimpleNamespace(stdout=output, stderr=b''))


@pytest.mark.parametrize('state', ['PUBLISHED', 'UNKNOWN_NO_REPLAY'])
def test_poll_reports_actual_worker_state_without_retry(monkeypatch, state):
    now = datetime.now(timezone.utc)
    raw=json.dumps({'issued_at_utc':now.isoformat(),'deadline_at_utc':(now+timedelta(seconds=100)).isoformat()}).encode()
    config = SimpleNamespace(io=SimpleNamespace(pending=lambda **kw: ['fox-'+'a'*20],read=lambda *a:raw))
    monkeypatch.setattr(host, 'configure', lambda: config)
    calls = []
    monkeypatch.setattr(host, 'run_once', lambda *a: calls.append(a) or {'state': state})
    assert host.poll_once() == {'status': state, 'job_id': 'fox-'+'a'*20}
    assert len(calls) == 1


def test_poll_idle_invokes_no_browser(monkeypatch):
    monkeypatch.setattr(host, 'configure', lambda: SimpleNamespace(io=SimpleNamespace(pending=lambda **kw: [])))
    monkeypatch.setattr(host, 'run_once', lambda *a: pytest.fail('No job may execute'))
    assert host.poll_once() == {'status': 'IDLE'}


def test_expired_first_request_does_not_starve_valid_second(monkeypatch):
    now=datetime.now(timezone.utc)
    expired=json.dumps({'issued_at_utc':(now-timedelta(seconds=100)).isoformat(),
                        'deadline_at_utc':(now-timedelta(seconds=10)).isoformat()}).encode()
    valid=json.dumps({'issued_at_utc':now.isoformat(),
                      'deadline_at_utc':(now+timedelta(seconds=100)).isoformat()}).encode()
    first,second='fox-'+'a'*20,'fox-'+'b'*20
    io=SimpleNamespace(pending=lambda **kw:[first,second],read=lambda job,*a:expired if job==first else valid)
    monkeypatch.setattr(host,'configure',lambda:SimpleNamespace(io=io))
    calls=[]
    monkeypatch.setattr(host,'run_once',lambda cfg,job:calls.append(job) or {'state':'PUBLISHED'})
    assert host.poll_once()=={'status':'PUBLISHED','job_id':second}
    assert calls==[second]


def test_factory_composes_current_authority_and_original_account(monkeypatch, tmp_path):
    profile = json.loads((Path(__file__).parents[3]/'deployment/target-profile.jsn-project-2616.json').read_bytes())
    target = tmp_path/'target.json'; target.write_text(json.dumps(profile))
    credential = tmp_path/'opaf.json'; credential.write_text(json.dumps({'converter_token':'synthetic-test-only-token-long-enough'}))
    staging=tmp_path/'jobs'; staging.mkdir()
    qa=tmp_path/'qa'; qa.mkdir()
    config = {'schema_version':1,'scope':'fox-prototype-host-v1','converter_id':'a'*64,
        'converter_image':'sha256:'+'b'*64,'image_id':'sha256:'+'c'*64,
        'jobs_root':'/home/opc/forms2apex/outputs/jobs','staging_jobs_root':str(staging),
        'qa_root':str(qa),'credentials_file':'/home/opc/.config/fox-prototype-runtime/fox-demo-qa.json',
        'opaf_credentials_file':str(credential),'target_profile_file':str(target),
        'target_profile_sha256':hashlib.sha256(target.read_bytes()).hexdigest(),
        'authority_origin':'https://fox.example.test','username':USERNAME}
    path=tmp_path/'config.json'; path.write_text(json.dumps(config))
    monkeypatch.setenv('FOX_PROTOTYPE_HOST_CONFIG', str(path))
    monkeypatch.setattr(host, 'private', lambda p, **kw: Path(p))
    monkeypatch.setattr(host.os, 'getuid', lambda:1000, raising=False)
    monkeypatch.setattr(host.os, 'getgid', lambda:1000, raising=False)
    monkeypatch.setattr(host, 'PodmanNamespaceJobIO', lambda root: SimpleNamespace(jobs_root=root))
    observed=[]
    monkeypatch.setattr(host, 'observe_host', lambda cfg: observed.append(cfg['converter_id']))
    calls=[]
    monkeypatch.setattr(host, 'PrototypeAuthorityClient', lambda *a, **kw: lambda request: calls.append(request) or request)
    worker=host.configure()
    assert worker.authorize({'synthetic':True}) == {'synthetic':True}
    assert len(observed)==2 and len(calls)==1
    assert worker.browser.config.credentials_file == Path(config['credentials_file'])
    path.write_text('{}')
    with pytest.raises(RuntimeError): worker.authorize({'synthetic':True})
    assert len(calls)==1


@pytest.mark.parametrize('username', ["NAME' OR '1'='1", 'x\n', '', 'a'*101, 'USER SPACE'])
def test_untrusted_account_identifier_never_reaches_sql(username):
    with pytest.raises(RuntimeError):
        host.observe_account({'converter_id':'a'*64,'username':username},
            run=lambda *args,**kwargs:pytest.fail('Untrusted identifier must never reach SQLcl'))
