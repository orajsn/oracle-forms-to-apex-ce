"""Local integration checks. No provider/model/DB calls are performed."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from forms2apex.fox_gateway import attach_routes
from forms2apex.target_profile import TargetProfileError, load_target_profile, target_profile_sha256
from forms2apex.security import alias_for_job
from test_native_workflow import make_job
from test_release_recovery import job


@pytest.fixture
def native(tmp_path_factory,monkeypatch):
    workflow,root,spec=make_job(tmp_path_factory.mktemp('pf'))
    workflow.generate(root.name,json.dumps(spec))
    calls=[]
    def collect(settings,job_root,**kwargs):
        calls.append(('preflight',kwargs['action']))
        assert kwargs['source_manifest_sha256']=='a'*64
        assert kwargs['job_id']==root.name and job_root==root
        assert 'opaf_attestation' not in kwargs
        return {'profile_sha256':'b'*64,'receipt_sha256':'c'*64,'passed':True,
                'scope':'jsn-native-deterministic-action-preflight-v1','job_id':root.name,'action':kwargs['action']}
    def compile(*args):
        calls.append(('sqlcl','validate'))
        return {'passed':True}
    monkeypatch.setattr('forms2apex.runtime_preflight.collect_deterministic_preflight',collect)
    monkeypatch.setattr('forms2apex.workflow.validate_apexlang',compile)
    monkeypatch.setattr('forms2apex.native_target.verify_native_schema',lambda *args:{'passed':True,'table_name':spec['native_form']['table_name']})
    monkeypatch.setattr('forms2apex.workflow.runtime_login_check',lambda url:{'passed':True,'scope':'login_page_reachability','url':url})
    return SimpleNamespace(workflow=workflow,root=root,spec=spec,calls=calls,collect=collect)


def test_native_validation_probes_target_before_sqlcl_and_binds_evidence(native):
    result=native.workflow.validate(native.root.name)
    assert native.calls==[('preflight','validate'),('sqlcl','validate')]
    reference=result['target_preflight']
    raw=(native.root/reference['file']).read_bytes()
    assert hashlib.sha256(raw).hexdigest()==reference['sha256']
    record=json.loads(raw)
    assert record['artifact_binding']==native.workflow.assert_artifact_binding(native.root.name)
    assert record['preflight']['action']=='validate'


@pytest.mark.parametrize('reason',['Wrong OCI compartment','APEX version drift','SQLcl version drift','MMD version drift'])
def test_failed_target_gate_blocks_compilation_and_preserves_review(native,monkeypatch,reason):
    original=(native.root/'native-review.json').read_bytes()
    def reject(*args,**kwargs):raise TargetProfileError(reason)
    monkeypatch.setattr('forms2apex.runtime_preflight.collect_deterministic_preflight',reject)
    with pytest.raises(TargetProfileError):native.workflow.validate(native.root.name)
    assert native.calls==[]
    assert native.workflow.status(native.root.name)['state']=='DRAFTED'
    assert (native.root/'native-review.json').read_bytes()==original
    assert not list(native.root.glob('target-check-*.json'))


def test_absent_profile_blocks_native_deterministic_action_before_sqlcl(tmp_path_factory,monkeypatch):
    workflow,root,spec=make_job(tmp_path_factory.mktemp('ap'))
    workflow.generate(root.name,json.dumps(spec))
    monkeypatch.setattr('forms2apex.workflow.validate_apexlang',lambda *args:pytest.fail('Must not compile'))
    with pytest.raises(TargetProfileError,match='active target profile'):
        workflow.validate(root.name)
    assert workflow.status(root.name)['state']=='DRAFTED'


def test_import_rechecks_current_scope_after_prior_valid_result(native,monkeypatch):
    native.workflow.validate(native.root.name)
    native.calls.clear()
    def reject(settings,root,**kwargs):
        assert kwargs['action']=='import'
        raise TargetProfileError('Current database compartment no longer matches')
    monkeypatch.setattr('forms2apex.runtime_preflight.collect_deterministic_preflight',reject)
    monkeypatch.setattr('forms2apex.workflow.import_apexlang_durable',lambda *args,**kwargs:pytest.fail('Must not import'))
    with pytest.raises(TargetProfileError):native.workflow.import_draft(native.root.name)
    assert not (native.root/'import-intent.json').exists()
    assert native.workflow.status(native.root.name)['state']=='VALID'


def test_sealed_historical_review_allows_deterministic_action_without_opaf(native,monkeypatch):
    original=(native.root/'native-review.json').read_bytes()
    monkeypatch.setattr('http.client.HTTPSConnection',lambda *args,**kwargs:pytest.fail('No live OPAF/model call in this workflow boundary'))
    monkeypatch.setattr('urllib.request.urlopen',lambda *args,**kwargs:pytest.fail('No model replay'))
    assert native.workflow.validate(native.root.name)['passed'] is True
    assert (native.root/'native-review.json').read_bytes()==original
    assert native.calls==[('preflight','validate'),('sqlcl','validate')]


def test_artifact_drift_during_probe_prevents_compilation(native,monkeypatch):
    def changed(*args,**kwargs):
        value=native.collect(*args,**kwargs)
        path=native.root/'apexlang/pages/p00002-record.apx'
        path.write_bytes(path.read_bytes()+b'changed')
        return value
    monkeypatch.setattr('forms2apex.runtime_preflight.collect_deterministic_preflight',changed)
    with pytest.raises(RuntimeError):native.workflow.validate(native.root.name)
    assert ('sqlcl','validate') not in native.calls
    assert not list(native.root.glob('target-check-*.json'))


def test_target_profile_handshake_is_bearer_authenticated_and_secret_free(tmp_path):
    routes=[]
    class MCP:
        def custom_route(self,path,methods,**kwargs):
            def decorate(func):routes.append(Route(path,func,methods=methods));return func
            return decorate
    profile=load_target_profile(Path(__file__).resolve().parents[2]/'deployment/target-profile.jsn.json')
    workflow=SimpleNamespace(target_profile=lambda:profile,store=SimpleNamespace())
    attach_routes(MCP(),workflow,SimpleNamespace(jobs_root=tmp_path,bearer_token='x'*48))
    with TestClient(Starlette(routes=routes)) as client:
        assert client.get('/fox/target-profile').status_code==401
        response=client.get('/fox/target-profile',headers={'Authorization':'Bearer '+'x'*48})
    assert response.status_code==200
    assert response.json()=={'target_profile':profile,'target_profile_sha256':target_profile_sha256(profile)}
    assert 'password' not in response.text and 'bearer_token' not in response.text


def test_missing_target_profile_handshake_is_safe_configuration_error(tmp_path):
    routes=[]
    class MCP:
        def custom_route(self,path,methods,**kwargs):
            def decorate(func):routes.append(Route(path,func,methods=methods));return func
            return decorate
    def blocked():raise TargetProfileError('private configuration detail')
    attach_routes(MCP(),SimpleNamespace(target_profile=blocked,store=SimpleNamespace()),SimpleNamespace(jobs_root=tmp_path,bearer_token='x'*48))
    with TestClient(Starlette(routes=routes)) as client:
        response=client.get('/fox/target-profile',headers={'Authorization':'Bearer '+'x'*48})
    assert response.status_code==409 and 'private configuration detail' not in response.text


def test_native_release_target_mismatch_blocks_before_export(job):
    from forms2apex.release import finalize_release
    from test_release_recovery import JOB
    (job.root/'migration-spec.json').write_text(json.dumps({'native_form':{}}),encoding='utf-8')
    def blocked(*args):raise TargetProfileError('Changed target compartment')
    job.workflow.native_target_preflight=blocked
    with pytest.raises(TargetProfileError):finalize_release(job.workflow,JOB)
    assert job.calls==[]
    assert not (job.root/'package-reimport-intent.json').exists()


def test_native_release_rechecks_before_sql_reimport_even_after_export_pass(job):
    from forms2apex.release import finalize_release
    from test_release_recovery import JOB
    (job.root/'migration-spec.json').write_text(json.dumps({'native_form':{}}),encoding='utf-8')
    probes=[]
    def probe(job_id,action):
        probes.append(action)
        if len(probes)==2:raise TargetProfileError('APEX changed after export')
        return {'scope':'first isolated mock passed'}
    job.workflow.native_target_preflight=probe
    with pytest.raises(TargetProfileError):finalize_release(job.workflow,JOB)
    assert probes==['release','release']
    assert job.calls==['export','validate_export']
    assert not (job.root/'package-reimport-intent.json').exists()


def test_release_freshness_is_rechecked_after_read_only_allocation_query(job):
    from forms2apex.release import finalize_release
    from test_release_recovery import JOB
    (job.root/'migration-spec.json').write_text(json.dumps({'native_form':{}}),encoding='utf-8')
    job.workflow.native_target_preflight=lambda *args:{'scope':'isolated mock target proof'}
    def expired(*args):
        assert job.calls==['export','validate_export','reimport_precheck']
        raise TargetProfileError('Target preflight expired during allocation')
    job.workflow.assert_native_preflight_fresh=expired
    with pytest.raises(TargetProfileError,match='expired'):finalize_release(job.workflow,JOB)
    assert job.calls==['export','validate_export','reimport_precheck']
    assert not (job.root/'package-reimport-intent.json').exists()
