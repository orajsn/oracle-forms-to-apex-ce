"""Fresh local FOX/receiver HTTP; provider/SQLcl/browser replies authored only."""
from copy import deepcopy
from contextlib import contextmanager
import base64
import hashlib
import importlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from starlette.applications import Starlette

from fox import prototype_authority as authority,prototype_job,worker
from fox import prototype_preclaim_continuation as preclaim
from fox.opaf import ConverterClient,OpafError,canonical_hash
from fox.prototype_transport import PrototypeHttpConverterAdapter
from test_prototype_job import queued,saved_row
from test_prototype_pipeline import TARGET,PROFILE
from test_prototype_mapping_epochs import tmp_path
from test_source_history_api import client,settings,no_external_actions,create_app,ORIGIN,PASSWORD
from test_prototype_mapping_recovery import recoverable


@pytest.fixture
def stopped(queued,tmp_path_factory,monkeypatch):
    from forms2apex import native_blueprint
    from forms2apex.project_reviews import digest
    from forms2apex.security import alias_for_job
    from forms2apex.target_profile import select_target_profile
    from forms2apex.prototype_routes import attach_prototype_routes
    root,job,db,snapshot,model,_,_=queued
    complete=select_target_profile('jsn-native-project-2616-v1')
    for key in ('active','scope','oci','database','apex','sqlcl'):
        monkeypatch.setitem(TARGET,key,deepcopy(complete[key]))
    for key in ('apex','sqlcl','apexlang_mmd'):
        monkeypatch.setitem(TARGET['tested_versions'],key,complete['tested_versions'][key])
    snapshot['prototype']['target_profile_sha256']=canonical_hash(TARGET)
    (job/'source-snapshot.json').write_text(json.dumps(snapshot))
    profile=root/'profile.json'
    profile.write_text(json.dumps({'target_profile':TARGET,'target_profile_sha256':canonical_hash(TARGET)}))
    profile.chmod(0o600)
    with db() as c:
        c.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
            ('synthetic-owner','approved_prototype_conversion',job.name,snapshot['approvals']['approved_at']))
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2]/'converter/tests'))
    fixture=importlib.import_module('test_prototype_gateway')
    release=importlib.import_module('test_prototype_release')
    routes=importlib.import_module('test_prototype_routes')
    state=SimpleNamespace(item=None,http=None,failed_authority=True,posts=[],requests=[])
    def initialize(bundle):
        members={row['path']:base64.b64decode(row['content_base64']) for row in bundle['files']}
        spec=json.loads(members['native-plan.json'])['rendering_spec']
        monkeypatch.setattr(fixture,'spec',lambda _:deepcopy(spec))
        item=fixture.case.__wrapped__(tmp_path_factory)
        original_import=item.adapter.importer
        files=native_blueprint.render_native_blueprint(spec)
        compiled=digest({name:hashlib.sha256(text.encode()).hexdigest() for name,text in files.items()})
        def imported(*a,**kw):
            return {**original_import(*a,**kw),'application_alias':alias_for_job(job.name),
                'workspace':'FORMS2APEX_POC','compiled_metadata_sha256':compiled}
        item.adapter.importer=imported
        item.adapter.runtime_verifier=release.browser_receipt
        item.adapter.target_profile_loader=lambda _:deepcopy(complete)
        original_runner=item.adapter.runner
        def exported(sql,args,commands,directory,**kw):
            if not any('apex export' in command for command in commands):
                return original_runner(sql,args,commands,directory,**kw)
            item.calls.append('export')
            app_id=item.request['prior_receipts']['import']['application_id']
            (directory/f'f{app_id}.sql').write_bytes(b'-- Authored synthetic SQLcl export\n'*100)
            app=directory/alias_for_job(job.name).lower()
            for name,text in files.items():
                path=app/name;path.parent.mkdir(parents=True,exist_ok=True)
                path.write_text(text,encoding='utf-8',newline='\n')
            return SimpleNamespace(returncode=0,stdout='FOX_PROTO_EXPORT_BEFORE=1\nFOX_PROTO_EXPORT_AFTER=1\n',stderr='')
        item.adapter.runner=exported
        class CurrentAuthority:
            def __call__(self,request):
                if state.failed_authority: raise TimeoutError('Authored preclaim callback timeout')
                authority.authorize_current(root,db,profile,request)
                return request
            def authorize_preclaim(self,request,record_sha256):
                authority.authorize_preclaim_current(root,db,profile,request,record_sha256)
                return request
        item.adapter.authorize=CurrentAuthority()
        mcp=routes.MCP()
        attach_prototype_routes(mcp,item.adapter,SimpleNamespace(bearer_token='synthetic-preclaim-token'))
        state.item=item;state.http=TestClient(Starlette(routes=mcp.routes))
        state.http.__enter__()
    client=ConverterClient('http://127.0.0.1:8091','synthetic-preclaim-token')
    def request(method,path,payload=None,*,binary=False):
        if method=='POST': state.posts.append(path)
        if state.item is None:
            if method=='GET': raise OpafError('Not found',status_code=404)
            assert path.endswith('/authority');initialize(payload)
        if '/stages/' in path and method=='POST' or path.endswith('/continue-validation'):
            stage_request=payload['request'] if path.endswith('/continue-validation') else payload
            state.item.request.clear();state.item.request.update(deepcopy(stage_request))
            state.requests.append(deepcopy(stage_request))
        response=state.http.request(method,path,json=payload,headers={'Authorization':'Bearer synthetic-preclaim-token'})
        if response.status_code>=400: raise OpafError('Authored local HTTP status',status_code=response.status_code)
        return response.content if binary else response.json()
    monkeypatch.setattr(client,'request',request)
    transport=PrototypeHttpConverterAdapter(job,client)
    def configuration(approved_sha,**kw):
        assert approved_sha==canonical_hash(TARGET)
        return {'profile':deepcopy(PROFILE),'opaf_client':model,'target_profile_loader':lambda:deepcopy(TARGET),
            'converter_adapter':transport,'gateway':client}
    monkeypatch.setattr(prototype_job,'_configuration',configuration)
    worker.process_one(db,root)
    assert saved_row(db,job)['state']=='ATTENTION'
    assert (job/'prototype-pipeline/validate-intent.json').is_file()
    assert state.item.calls==[]
    assert not (state.item.settings.jobs_root/job.name/'prototype-converter/validate-intent.json').exists()
    state.failed_authority=False
    monkeypatch.setenv('FOX_PROTOTYPE_PROFILE_FILE',str(profile))
    monkeypatch.setenv('FOX_ADMIN_USERNAME','synthetic-owner')
    yield SimpleNamespace(root=root,job=job,db=db,snapshot=snapshot,model=model,client=client,state=state,profile=profile)
    state.http.__exit__(None,None,None)


@contextmanager
def login(item):
    with TestClient(create_app(item.root,enable_worker=False),base_url=ORIGIN) as client:
        client.headers['Origin']=ORIGIN
        assert client.post('/api/login',json={'username':'synthetic-owner','password':PASSWORD}).status_code==200
        yield client


def body(plan):
    return {'source_hash':plan['source_hash'],'source_binding':plan['source_binding'],
        'expected_current_source_set_id':plan['selected_source_set_id'],'target_profile_sha256':plan['target_profile_sha256'],
        'approved_chunk_hashes':plan['approved_chunk_hashes'],'approved_redacted_source':True,
        'approved_external_ai':True,'approved_prototype_scope':True,'checkpoint_sha256':plan['checkpoint_sha256'],
        'expected_validate_request_sha256':plan['validate_request_sha256'],
        'expected_receiver_witness_sha256':plan['receiver_witness_sha256']}


def test_positive_same_run_reuses_all_models_and_downloads_exact_zip(stopped,settings,monkeypatch):
    # settings are applied before login; restore this fixture's explicit owner.
    item=stopped
    monkeypatch.setenv('FOX_ADMIN_USERNAME','synthetic-owner')
    before={p.relative_to(item.job):p.read_bytes() for p in item.job.rglob('*') if p.is_file()}
    calls=deepcopy((item.model.calls,item.model.observations))
    with item.db() as c:
        preclaim.inspect(item.job,item.snapshot,(item.job/'source-snapshot.json').read_bytes(),TARGET,c)
    path=f"/api/projects/{item.snapshot['project_id']}/prototype-runs/{item.job.name}/validate-preclaim-continuation"
    with login(item) as client:
        response=client.get(path)
        assert response.status_code==200,response.text
        plan=response.json();assert plan['eligible'] and plan['repeated_model_calls']==0
        dto=body(plan)
        response=client.post(path,json=dto)
        assert response.status_code==202,response.text
        assert response.json()['id']==item.job.name and saved_row(item.db,item.job)['state']=='QUEUED'
        files={p.relative_to(item.job):p.read_bytes() for p in item.job.rglob('*') if p.is_file()}
        with item.db() as c: count=c.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        duplicate=client.post(path,json=dto)
        assert duplicate.status_code==200,duplicate.text
        assert {p.relative_to(item.job):p.read_bytes() for p in item.job.rglob('*') if p.is_file()}==files
        with item.db() as c: assert c.execute('SELECT COUNT(*) FROM events').fetchone()[0]==count
        worker.process_one(item.db,item.root)
        assert saved_row(item.db,item.job)['state']=='GENERATED',saved_row(item.db,item.job)['message']
        assert (item.model.calls,item.model.observations)==calls
        assert sum(p.endswith('/continue-validation') for p in item.state.posts)==1
        for name,raw in before.items():
            if name.as_posix()!='prototype-result.json': assert (item.job/name).read_bytes()==raw
        response=client.get(path.rsplit('/',1)[0]+'/download')
        assert response.status_code==200,response.text
        import io,zipfile
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            assert 'apexlang/application.apx' in archive.namelist()
            assert any(name.startswith('sql/f') for name in archive.namelist())
        assert response.headers['X-Content-SHA256']==hashlib.sha256(response.content).hexdigest()
        assert saved_row(item.db,item.job)['artifact'] is None


@pytest.mark.parametrize('change,status',[('missing',422),('false',409),('bool-string',422),
    ('exclusion',422),('checkpoint',409),('request',409),('witness',409),('source',409),('selection',409),('target',409)])
def test_consent_and_exact_body_refusal_without_queue_or_mutation(stopped,settings,monkeypatch,change,status):
    item=stopped;monkeypatch.setenv('FOX_ADMIN_USERNAME','synthetic-owner')
    path=f"/api/projects/{item.snapshot['project_id']}/prototype-runs/{item.job.name}/validate-preclaim-continuation"
    with login(item) as client:
        response=client.get(path);assert response.status_code==200,response.text
        dto=body(response.json())
        if change=='missing': dto.pop('approved_prototype_scope')
        elif change=='false': dto['approved_prototype_scope']=False
        elif change=='bool-string': dto['approved_prototype_scope']='true'
        elif change=='exclusion': dto['excluded_stopped_job_id']=item.job.name
        else:
            key={'checkpoint':'checkpoint_sha256','request':'expected_validate_request_sha256',
                'witness':'expected_receiver_witness_sha256','source':'source_hash',
                'selection':'expected_current_source_set_id','target':'target_profile_sha256'}[change]
            dto[key]='f'*64
        before={p.relative_to(item.job):p.read_bytes() for p in item.job.rglob('*') if p.is_file()}
        assert client.post(path,json=dto).status_code==status
        assert saved_row(item.db,item.job)['state']=='ATTENTION'
        assert {p.relative_to(item.job):p.read_bytes() for p in item.job.rglob('*') if p.is_file()}==before
        assert not item.state.item.calls


@pytest.mark.parametrize('change',['owner','selection','active','proof','zip','index','intent','receiver','manifest'])
def test_drift_or_active_producer_refuses_inspection(stopped,settings,monkeypatch,change):
    item=stopped;monkeypatch.setenv('FOX_ADMIN_USERNAME','synthetic-owner')
    root=item.job/'prototype-pipeline'
    if change in ('owner','selection','active'):
        with item.db() as c:
            if change=='owner': c.execute("UPDATE projects SET owner='different' WHERE id=?",(item.snapshot['project_id'],))
            elif change=='active': c.execute("UPDATE runs SET state='PROCESSING' WHERE id=?",(item.job.name,))
            else:
                from fox import source_history
                from fox.intake import checked_source
                c.execute('BEGIN IMMEDIATE')
                source_history.publish_upload(c,item.snapshot['project_id'],
                    [checked_source('new-synthetic.xml',item.snapshot['files'][0]['text'].encode())],99.0,'synthetic-owner')
    else:
        path={'proof':next(root.glob('focus-*/mapper.json')),'zip':root/'candidate-apexlang.zip',
            'index':root/'review-index.json','intent':root/'validate-intent.json',
            'receiver':item.state.item.settings.jobs_root/item.job.name/'prototype-converter/snapshot.json',
            'manifest':item.state.item.settings.jobs_root/item.job.name/'prototype-converter/authority-manifest.json'}[change]
        path.write_bytes(b'{}')
    calls=deepcopy(item.model.calls)
    path=f"/api/projects/{item.snapshot['project_id']}/prototype-runs/{item.job.name}/validate-preclaim-continuation"
    with login(item) as client:
        if change=='active':
            # App startup legitimately reconciles a stale PROCESSING row.
            # Model an actual active producer AFTER that startup pass.
            with item.db() as c: c.execute("UPDATE runs SET state='PROCESSING' WHERE id=?",(item.job.name,))
        assert client.get(path).status_code in (403,404,409)
    assert item.model.calls==calls and not item.state.item.calls
    assert not (root/preclaim.RECORD).exists()


def test_concurrent_confirmations_create_one_event_and_queue_once(stopped,settings,monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    item=stopped;monkeypatch.setenv('FOX_ADMIN_USERNAME','synthetic-owner')
    path=f"/api/projects/{item.snapshot['project_id']}/prototype-runs/{item.job.name}/validate-preclaim-continuation"
    with login(item) as client:
        response=client.get(path);assert response.status_code==200,response.text
        dto=body(response.json())
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(lambda _:client.post(path,json=dto),range(2)))
        assert sorted(r.status_code for r in results)==[200,202],[r.text for r in results]
    with item.db() as c:
        assert c.execute('SELECT COUNT(*) FROM events WHERE action=?',(preclaim.EVENT,)).fetchone()[0]==1
    assert saved_row(item.db,item.job)['state']=='QUEUED' and not item.state.item.calls


def test_changed_proof_after_consent_never_falls_through_to_provider(stopped,settings,monkeypatch):
    item=stopped;monkeypatch.setenv('FOX_ADMIN_USERNAME','synthetic-owner')
    path=f"/api/projects/{item.snapshot['project_id']}/prototype-runs/{item.job.name}/validate-preclaim-continuation"
    with login(item) as client:
        plan=client.get(path).json();assert client.post(path,json=body(plan)).status_code==202
    calls=deepcopy((item.model.calls,item.model.observations))
    next((item.job/'prototype-pipeline').glob('focus-*/reviewer.json')).write_bytes(b'{}')
    worker.process_one(item.db,item.root)
    assert saved_row(item.db,item.job)['state']=='ATTENTION'
    assert (item.model.calls,item.model.observations)==calls and not item.state.item.calls


def test_lost_response_after_claim_never_posts_again(stopped,settings,monkeypatch):
    item=stopped;monkeypatch.setenv('FOX_ADMIN_USERNAME','synthetic-owner')
    path=f"/api/projects/{item.snapshot['project_id']}/prototype-runs/{item.job.name}/validate-preclaim-continuation"
    with login(item) as client:
        plan=client.get(path).json();assert client.post(path,json=body(plan)).status_code==202
    original=item.client.request
    recovered=[]
    def lost(method,path,payload=None,**kw):
        result=original(method,path,payload,**kw)
        if path.endswith('/continue-validation'):
            # The original worker is STILL PROCESSING. Current authority allows
            # read-only retrieval now; no queue/state reset or POST is needed.
            posts=deepcopy(item.state.posts)
            receipt=PrototypeHttpConverterAdapter(item.job,item.client).recover_stage('validate',payload['request'])
            assert receipt==result and item.state.posts==posts
            recovered.append(receipt)
            raise OpafError('Authored response loss after receiver outcome')
        return result
    monkeypatch.setattr(item.client,'request',lost)
    worker.process_one(item.db,item.root)
    assert saved_row(item.db,item.job)['state']=='ATTENTION'
    assert len(recovered)==1 and recovered[0]['status']=='COMPLETE'
    assert item.state.item.calls==['validate']
    request=preclaim.request_for(item.job,item.snapshot)
    posts=deepcopy(item.state.posts)
    with pytest.raises(OpafError,match='already attempted'):
        PrototypeHttpConverterAdapter(item.job,item.client).continue_validation(request)
    assert item.state.posts==posts
    # Terminal ATTENTION recovery is not silently authorized by this slice.
    # Existing normal current authority refuses; user-visible P4 remains open.
    with pytest.raises(OpafError) as denied:
        PrototypeHttpConverterAdapter(item.job,item.client).recover_stage('validate',request)
    assert denied.value.status_code==409 and item.state.posts==posts
    with login(item) as client:
        duplicate=client.post(path,json=body(plan))
        assert duplicate.status_code==200,duplicate.text
    assert saved_row(item.db,item.job)['state']=='ATTENTION'


def test_private_authority_http_requires_exact_current_record_event_and_processing(stopped,settings,monkeypatch):
    from fastapi import FastAPI
    item=stopped;monkeypatch.setenv('FOX_ADMIN_USERNAME','synthetic-owner')
    path=f"/api/projects/{item.snapshot['project_id']}/prototype-runs/{item.job.name}/validate-preclaim-continuation"
    with login(item) as client:
        plan=client.get(path).json();assert client.post(path,json=body(plan)).status_code==202
    record=json.loads((item.job/'prototype-pipeline'/preclaim.RECORD).read_bytes())
    token=item.root/'authored-test-token.json'
    token.write_text(json.dumps({'converter_token':'synthetic-preclaim-test-token'}));token.chmod(0o600)
    app=FastAPI()
    authority.attach_prototype_authority(app,root=item.root,db=item.db,enabled=True,
        profile_path=item.profile,credential_path=token,allowed_origin='https://fox.example.test')
    envelope={'schema_version':1,'scope':'fox-prototype-preclaim-authorize-request-v1',
        'request':record['request'],'record_sha256':canonical_hash(record)}
    headers={'Authorization':'Bearer synthetic-preclaim-test-token','Origin':'https://fox.example.test'}
    with TestClient(app) as client:
        assert client.post(authority.PRECLAIM_AUTHORITY_PATH,json=envelope).status_code==401
        assert client.post(authority.PRECLAIM_AUTHORITY_PATH,json=envelope,headers=headers).status_code==409
        with item.db() as c: c.execute("UPDATE runs SET state='PROCESSING' WHERE id=?",(item.job.name,))
        value=client.post(authority.PRECLAIM_AUTHORITY_PATH,json=envelope,headers=headers)
        assert value.status_code==200,value.text
        assert value.json()['record_sha256']==canonical_hash(record)
        for bad in ({**envelope,'record_sha256':'0'*64},{**envelope,'schema_version':True},
                    {k:v for k,v in envelope.items() if k!='record_sha256'}, {**envelope,'safe_to_retry':True}):
            assert client.post(authority.PRECLAIM_AUTHORITY_PATH,json=bad,headers=headers).status_code==409
        with item.db() as c: c.execute('DELETE FROM events WHERE action=?',(preclaim.EVENT,))
        assert client.post(authority.PRECLAIM_AUTHORITY_PATH,json=envelope,headers=headers).status_code==409


def test_known_earlier_checkpoint_has_only_explicit_ineligible_fallback(recoverable):
    c,_,pid,rid,job,_,_,_,model=recoverable
    before={p.relative_to(job):p.read_bytes() for p in job.rglob('*') if p.is_file()}
    calls=deepcopy(model.calls)
    response=c.get(f'/api/projects/{pid}/prototype-runs/{rid}/validate-preclaim-continuation')
    assert response.status_code==200,response.text
    value=response.json()
    assert value['eligible'] is value['continuation_recorded'] is False
    assert value['next_action']=='check_existing_repairs' and 'checkpoint_sha256' not in value
    assert {p.relative_to(job):p.read_bytes() for p in job.rglob('*') if p.is_file()}==before and model.calls==calls
    next((job/'prototype-pipeline').glob('focus-*/mapper.json')).write_bytes(b'{}')
    assert c.get(f'/api/projects/{pid}/prototype-runs/{rid}/validate-preclaim-continuation').status_code==409
