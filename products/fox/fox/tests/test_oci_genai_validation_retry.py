"""Real local retry transport/authority/runtime reads; injected SQL/OCI only."""
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace as NS

from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
import pytest

from fox import prototype_job, prototype_authority, prototype_validation_retry as retry, worker, source_history
from fox.design_provider import roles
from fox.opaf import OpafError, canonical_hash, ConverterClient
from fox.oci_genai import OciGenAiClient
from fox.prototype_project_routes import PrototypeContinuationInput
from forms2apex.prototype_gateway import PrototypeGateway
from forms2apex.project_reviews import publish, read_object
from forms2apex.prototype_validation_retry import PREFIX, INTENT, RECEIPT
from test_prototype_job import queued, saved_row
from test_oci_genai import target, InjectedService, fake_sdk
from test_oci_genai_container import correction_body


@pytest.fixture
def failed_validation(queued,monkeypatch):
    root,job,db,snapshot,legacy,unused,configurations=queued
    current=target()
    snapshot['prototype']['target_profile_sha256']=canonical_hash(current)
    (job/'source-snapshot.json').write_text(json.dumps(snapshot))
    with db() as c:
        c.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
            (snapshot['approvals']['owner'],'approved_prototype_conversion',job.name,snapshot['approvals']['approved_at']))
    profile=root/'profile.json'
    profile.write_text(json.dumps({'target_profile':current,'target_profile_sha256':canonical_hash(current)}))
    profile.chmod(0o600)
    service=InjectedService()
    model=OciGenAiClient(current,client=service,sdk=fake_sdk())
    jobs=root/'r';jobs.mkdir()
    validation_calls=[]
    failure=NS(raise_on_retry=False)
    def validate(sql,app,log):
        validation_calls.append(str(app))
        if failure.raise_on_retry and len(validation_calls)>1: raise TimeoutError('INJECTED_UNCERTAIN')
        passed=len(validation_calls)>1
        log.write_text('Validation successful' if passed else 'Injected wrapper failed before SQLcl start')
        return {'passed':passed,'return_code':0 if passed else 126,'log':str(log)}
    class Authorizer:
        def __call__(self,request):
            prototype_authority.authorize_current(root,db,profile,request)
            return request
        def authorize_validation_retry(self,request,key):
            prototype_authority.authorize_validation_retry_current(root,db,profile,request,key)
            return request
    settings=NS(jobs_root=jobs,sqlcl_path=root/'not-executed',sqlcl_connection_name='F2A_APEX',
        apex_workspace='FORMS2APEX_POC',apex_parsing_schema='FORMS2APEX_POC')
    modeled=[]
    def imported(*args,**kw):
        from forms2apex import blueprint_profiles
        from forms2apex.security import alias_for_job
        from forms2apex.provenance import tree_digest
        first=read_object(jobs/job.name/'prototype-converter/validate-request.json')
        files=blueprint_profiles.select(first['rendering_spec']).render_native_blueprint(first['rendering_spec'])
        import hashlib
        compiled=canonical_hash({n:hashlib.sha256(v.encode()).hexdigest() for n,v in files.items()})
        kw['pre_write_check']();modeled.append('import')
        return {'application_id':12345,'application_alias':alias_for_job(job.name),'workspace':'FORMS2APEX_POC',
            'import_intent_sha256':'1'*64,'compiled_metadata_sha256':compiled}
    gateway=PrototypeGateway(settings,authorize=Authorizer(),validator=validate,importer=imported,
        preflight=lambda *a:lambda:None,target_profile_loader=lambda settings:current)
    def prepare(root,request,spec,check):
        check()
        assert gateway.recover_stage('validate',{**request,'prior_receipts':{}})==request['prior_receipts']['validate']
        modeled.append('prepare_schema')
        return {'ready_for_import':True}
    monkeypatch.setattr(gateway,'_prepare_schema',prepare)
    monkeypatch.setattr(gateway,'_observe',lambda *a:None)
    class Client(ConverterClient):
        def __init__(self): super().__init__('http://127.0.0.1:8091','injected-offline-token')
        def request(self,method,path,payload=None):
            if path.endswith('/capabilities'): return {'schema_version':1,'scope':'fox-prototype-capabilities-v1','stages':[s for s in ('validate','prepare_schema','import','verify_runtime','export') if gateway.supports(s)]}
            if path.endswith('/authority'):
                value=gateway.stage_source_authority(job.name,payload) if method=='POST' else gateway.recover_source_authority(job.name)
            elif path.endswith('/validation-retry'):
                value=gateway.validation_retry_witness(job.name) if method=='GET' else gateway.retry_validation(payload['request'],payload['witness'],payload['record_sha256'])
            else:
                stage=path.rsplit('/',1)[1]
                value=gateway.run_stage(stage,payload) if method=='POST' else gateway.recover_stage_for_job(job.name,stage)
            if value is None: raise OpafError('Injected missing resource',404)
            return value
    client=Client()
    def config(approved,**kwargs):
        assert approved==canonical_hash(current)
        return {'profile':roles(current),'opaf_client':model,'target_profile_loader':lambda:deepcopy(current),'gateway':client}
    monkeypatch.setattr(prototype_job,'_configuration',config)
    monkeypatch.setenv('FOX_RUN_ADAPTER','oci-genai')
    worker.process_one(db,root)
    assert saved_row(db,job)['state']=='ATTENTION'
    assert len(validation_calls)==1 and not modeled, saved_row(db,job)
    remote=jobs/job.name/'prototype-converter'
    original={p.relative_to(remote).as_posix():p.read_bytes() for p in remote.rglob('*') if p.is_file()}
    app=FastAPI()
    def owner(request,pid):
        value=request.headers.get('x-test-owner')
        with db() as c: row=c.execute('SELECT * FROM projects WHERE id=? AND owner=?',(pid,value)).fetchone()
        if row is None: raise HTTPException(404)
        return dict(row)
    retry.attach_routes(app,root=root,db=db,project_owner=owner,
        current_sources=lambda pid,c:source_history.selected_sources(c,pid),admission_allowed=lambda c:True,
        target_reader=lambda:{'target_profile':current,'target_profile_sha256':canonical_hash(current)},
        input_model=PrototypeContinuationInput)
    http=TestClient(app,headers={'x-test-owner':snapshot['approvals']['owner']})
    path=f"/api/projects/{snapshot['project_id']}/prototype-runs/{job.name}/retry-validation"
    return NS(root=root,job=job,db=db,gateway=gateway,http=http,path=path,service=service,remote=remote,
        original=original,validation_calls=validation_calls,modeled=modeled,jobs=jobs,failure=failure)


def test_explicit_retry_preserves_failure_and_reaches_effective_prior_runtime_reads(failed_validation):
    r=failed_validation
    count=len(r.service.calls)
    response=r.http.get(r.path)
    assert response.status_code==200,response.text
    preview=response.json()
    assert preview['validation_attempt']==2 and preview['new_model_calls']==0
    assert preview['validation_database_calls']==0 and preview['continues_original_pipeline'] is True
    body=correction_body(preview)
    assert r.http.post(r.path,json=body).status_code==202
    assert r.http.post(r.path,json=body).status_code==200
    worker.process_one(r.db,r.root)
    assert len(r.service.calls)==count and len(r.validation_calls)==2
    assert r.modeled==['prepare_schema','import']
    assert all((r.remote/name).read_bytes()==raw for name,raw in r.original.items())
    assert read_object(r.remote/'validate.json')['status']=='FAILED'
    effective=read_object(r.remote/RECEIPT)
    assert effective['status']=='COMPLETE' and effective['validation_attempt']['attempt']==2
    assert read_object(r.job/'prototype-pipeline/validate.json')==effective
    # Actual runtime bridge and LocalJobIO must select attempt2, retaining the
    # failed attempt1 bytes. Only modeled DB stage receipts are used here.
    from forms2apex.prototype_runtime_bridge import LocalJobIO,check_retained
    imported=read_object(r.remote/'import-request.json')
    imported['prior_receipts']['import']=read_object(r.remote/'import.json')
    publish(r.remote/'verify_runtime-request.json',imported)
    publish(r.remote/'verify_runtime-intent.json',{'request_sha256':canonical_hash(imported)})
    check_retained(LocalJobIO(r.jobs),{'request':imported,'artifact_binding':read_object(r.remote/'snapshot.json')})
    assert r.http.post(r.path,json=body).status_code==200
    assert len(r.validation_calls)==2


@pytest.mark.parametrize('field',['approved_external_ai','checkpoint_sha256','source_hash','target_profile_sha256'])
def test_retry_requires_exact_current_owner_scope_and_consent(failed_validation,field):
    r=failed_validation
    preview=r.http.get(r.path).json()
    body=correction_body(preview)
    body[field]=False if field=='approved_external_ai' else '0'*64
    assert r.http.post(r.path,json=body).status_code==409
    assert len(r.validation_calls)==1 and not (r.job/retry.RECORD).exists()
    assert r.http.get(r.path,headers={'x-test-owner':'someone-else'}).status_code==404


def test_uncertain_attempt2_never_falls_back_or_replays(failed_validation):
    r=failed_validation
    body=correction_body(r.http.get(r.path).json())
    assert r.http.post(r.path,json=body).status_code==202
    r.failure.raise_on_retry=True
    count=len(r.service.calls)
    worker.process_one(r.db,r.root)
    assert len(r.validation_calls)==2 and len(r.service.calls)==count and not r.modeled
    assert (r.remote/INTENT).is_file() and not (r.remote/RECEIPT).exists()
    from forms2apex.prototype_validation_retry import local_effective
    with pytest.raises(RuntimeError):
        local_effective(r.remote,'validate',read_object(r.remote/'validate-request.json'))
    assert r.http.post(r.path,json=body).status_code==409
    worker.process_one(r.db,r.root)
    assert len(r.validation_calls)==2


def test_retry_missing_durable_owner_event_stops_before_validation(failed_validation):
    r=failed_validation
    body=correction_body(r.http.get(r.path).json())
    assert r.http.post(r.path,json=body).status_code==202
    with r.db() as c: c.execute('DELETE FROM events WHERE action=?',(retry.EVENT,))
    worker.process_one(r.db,r.root)
    assert len(r.validation_calls)==1 and not (r.remote/PREFIX).exists()


def test_downstream_or_changed_original_failure_blocks_admission(failed_validation):
    r=failed_validation
    (r.remote/'import-reservation.json').write_text('{}')
    assert r.http.get(r.path).status_code==409
    assert len(r.validation_calls)==1


@pytest.mark.parametrize('partial',['empty','log','intent'])
def test_partial_second_attempt_cannot_fall_back_to_original_failure(failed_validation,partial):
    r=failed_validation
    from forms2apex.prototype_validation_retry import local_effective,LOG
    (r.remote/PREFIX).mkdir()
    if partial=='log': (r.remote/LOG).write_text('partial unsealed output')
    if partial=='intent': (r.remote/INTENT).write_text('{}')
    with pytest.raises(RuntimeError):
        local_effective(r.remote,'validate',read_object(r.remote/'validate-request.json'))
    assert r.http.get(r.path).status_code==409
    assert len(r.validation_calls)==1


def test_retry_completes_modeled_export_and_actual_package_reader(failed_validation,monkeypatch):
    r=failed_validation
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2]/'converter/tests'))
    from test_prototype_release import browser_receipt
    from forms2apex import blueprint_profiles
    from forms2apex.security import alias_for_job
    r.gateway.runtime_verifier=browser_receipt  # Explicit authored browser fixture, no live claim.
    first=read_object(r.remote/'validate-request.json')
    files=blueprint_profiles.select(first['rendering_spec']).render_native_blueprint(first['rendering_spec'])
    def export_runner(sql,args,commands,directory,**kwargs):
        assert any('apex export' in line for line in commands)
        imported=read_object(r.remote/'import.json')
        (directory/f"f{imported['application_id']}.sql").write_bytes(b'-- authored offline SQLcl export fixture\n'*100)
        app=directory/alias_for_job(r.job.name).lower()
        for name,text in files.items():
            path=app/name
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text(text,encoding='utf-8',newline='\n')
        return NS(returncode=0,stdout='FOX_PROTO_EXPORT_BEFORE=1\nFOX_PROTO_EXPORT_AFTER=1\n',stderr='')
    r.gateway.runner=export_runner
    body=correction_body(r.http.get(r.path).json())
    assert r.http.post(r.path,json=body).status_code==202
    count=len(r.service.calls)
    worker.process_one(r.db,r.root)
    assert saved_row(r.db,r.job)['state']=='GENERATED',saved_row(r.db,r.job)['message']
    assert len(r.service.calls)==count
    # Original failed validate + explicit attempt2 + normal export validation.
    assert len(r.validation_calls)==3
    package=r.gateway.read_package(r.job.name)
    assert package==(r.remote/'prototype-package.zip').read_bytes()
    assert read_object(r.remote/'validate.json')['status']=='FAILED'
    assert read_object(r.remote/RECEIPT)['status']=='COMPLETE'
    for name,raw in r.original.items(): assert (r.remote/name).read_bytes()==raw
    from forms2apex.prototype_runtime_bridge import LocalJobIO,check_retained
    runtime_request=read_object(r.remote/'verify_runtime-request.json')
    check_retained(LocalJobIO(r.jobs),{'request':runtime_request,'artifact_binding':read_object(r.remote/'snapshot.json')})
    before=len(r.validation_calls)
    assert r.gateway.read_package(r.job.name)==package
    assert len(r.validation_calls)==before


@pytest.mark.parametrize('name',['validate.json','validation.log'])
def test_mutated_original_after_preview_cannot_be_approved(failed_validation,name):
    r=failed_validation
    body=correction_body(r.http.get(r.path).json())
    path=r.remote/name
    if name.endswith('.json'):
        value=read_object(path);value['validation']['return_code']=127
        path.write_text(json.dumps(value))
    else: path.write_text('changed original failure log')
    assert r.http.post(r.path,json=body).status_code==409
    assert len(r.validation_calls)==1 and not (r.job/retry.RECORD).exists()


def test_validation_retry_transport_uses_full_validation_timeout(monkeypatch):
    import fox.opaf as opaf
    observed=[]
    class Connection:
        def __init__(self,host,port,timeout): observed.append(timeout)
        def request(self,*args,**kwargs): pass
        def getresponse(self): return NS(status=200,read=lambda n:b'{}')
        def close(self): pass
    monkeypatch.setattr(opaf.http.client,'HTTPConnection',Connection)
    client=opaf.ConverterClient('http://127.0.0.1:8091','injected-offline-token')
    client.request('POST','/fox/prototype/jobs/fox-'+'a'*20+'/validation-retry',{})
    assert observed==[1080]
