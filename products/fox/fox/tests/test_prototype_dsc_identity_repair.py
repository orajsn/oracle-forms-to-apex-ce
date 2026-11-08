"""Actual local identity-repair API/worker; external replies are AUTHORED only."""
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3

import pytest

from fox import prototype_dsc_identity_repair as dsc, prototype_mapping_epochs as epochs
from fox import prototype_context_screen_epoch as screen, prototype_project_routes as routes
from fox.opaf import canonical_hash, OpafError
from test_forms_dsc_identity import example
from test_prototype_pipeline import PROFILE
from test_prototype_mapping_recovery import recoverable
from test_prototype_review_correction import (correction_case, next_body as correction_body,
    screen_case, partition_case, container_case, container_source_model, clause_case, epochs_case,
    tmp_path, client, settings, no_external_actions, api, files, process)


@pytest.fixture(autouse=True)
def historical_dsc_source(monkeypatch,container_source_model,request):
    if 'dsc_case' not in request.fixturenames: return
    # Author an explicit historical legacy task policy, not new-admission default.
    original_admission=routes.prepare_prototype_admission
    def legacy(*args,**kwargs):
        kwargs['metadata_task_policy']=None
        return original_admission(*args,**kwargs)
    monkeypatch.setattr(routes,'prepare_prototype_admission',legacy)
    import test_prototype_mapping_epochs as fixtures
    original_upload=fixtures.upload
    def augmented(documents):
        name,raw=documents[0]
        suffix=b'</Block>'
        suffix+=b''.join(f'<Block Name="TAIL{i}" DatabaseBlock="true"><DataSourceColumn DSCName="COL_END_{i}"/></Block>'.encode() for i in range(5))
        assert raw.count(b'</Block><Block Name="LAST"')==1
        raw=raw.replace(b'</Block><Block Name="LAST"',suffix+b'<Block Name="LAST"')
        return [(name,raw)]
    def upload(c,pid,documents):return original_upload(c,pid,augmented(documents))
    monkeypatch.setattr(fixtures,'upload',upload)
    original_pipeline=fixtures.run_prototype_pipeline
    def initial_pipeline(job,documents,**kwargs):return original_pipeline(job,augmented(documents),**kwargs)
    monkeypatch.setattr(fixtures,'run_prototype_pipeline',initial_pipeline)
    original=fixtures.EpochModel.invoke
    def invoke(self,role,payload):
        output,invocation=original(self,role,payload)
        if role==PROFILE['mapper']:
            owned={row['id'] for row in payload['owned_objects'] if row['kind']=='DataSourceColumn'}
            for row in output['blueprint']['objects']:
                if row['source_object_id'] in owned:
                    ref=row['source_object_id'];row.clear()
                    row.update(source_object_id=ref,disposition='unresolved',reason='OBJECT_NAME_UNAVAILABLE')
        elif payload.get('scope')!=dsc.SCOPE and any(row['kind']=='Block' and row['name']=='TAIL4' for row in payload['request']['owned_objects']):
            output.update(verdict='CHANGES_REQUIRED',findings=[{'source_object_id':None,
                'code':'MISSING_COLUMN_IDENTITY','detail':'Authored genuine missing-name reason defect; no approval.'}])
        invocation['response_sha256']=canonical_hash(output)
        return output,invocation
    monkeypatch.setattr(fixtures.EpochModel,'invoke',invoke)


@pytest.fixture
def dsc_case(correction_case,monkeypatch):
    case=correction_case
    _,body=correction_body(case)
    response=case[0].post(api(case,'review-correction'),json=body)
    assert response.status_code==202,response.text
    row,errors=process(case,monkeypatch)
    assert row['state']=='ATTENTION',errors
    result=epochs.read(case[4]/'prototype-result.json')
    assert result['status']=='CHANGES_REQUIRED'
    assert (case[4]/screen.RESULT_BASE/'publication.json').is_file()
    return case


def next_body(case):
    response=case[0].get(api(case,'dsc-identity-repair'))
    assert response.status_code==200,response.text
    plan=response.json()
    return plan,{**case[6],'checkpoint_sha256':plan['checkpoint_sha256'],
        'expected_epoch_record_sha256':plan['epoch_record_sha256'],
        'expected_terminal_closure_sha256':plan['terminal_closure_sha256'],
        'expected_supplement_sha256':plan['supplement_sha256']}


def test_review_wrapper_has_actual_historical_context_and_only_relevant_identity_metadata():
    docs,_,_,request,candidate=example()
    supplement=dsc.identity.build_identity_supplement(docs)
    projected,receipt=dsc.identity.project_candidate_reasons(docs,request,candidate,supplement)
    historical={'request':request,'candidate':candidate,'design_context':{'synthetic':'actual original compact context'},'task_guidance':'Old guidance'}
    task=dsc._review_task(request,projected,receipt,supplement,historical)
    assert task['historical_review_context']==historical
    assert task['candidate']==projected and task['candidate']!=historical['candidate']
    assert task['source_identity_metadata']['full_supplement_sha256']==canonical_hash(supplement)
    assert task['source_identity_metadata']['identity_count']==2
    task['historical_review_context']['design_context']['synthetic']='Mutated returned copy'
    assert historical['design_context']['synthetic']=='actual original compact context'
    assert 'not a processing-consent' in task['task_guidance']


def test_new_admission_policy_explicit_and_old_snapshot_contract_remains_legacy():
    from fox.prototype_admission import prepare_prototype_admission
    docs,packet,_,_,_=example()
    kwargs={'expected_source_binding':packet['source_binding'],
        'approved_chunk_hashes':{row['id']:row['sha256'] for row in packet['chunks']},
        'target_profile_sha256':'a'*64,'approved_redacted_source':True,
        'approved_external_ai':True,'approved_prototype_scope':True,'schema_version':2}
    legacy=prepare_prototype_admission(docs,**kwargs)
    modern=prepare_prototype_admission(docs,**kwargs,metadata_task_policy=dsc.TASK_POLICY)
    assert 'metadata_task_policy' not in legacy['prototype']
    assert modern['prototype']=={**legacy['prototype'],'metadata_task_policy':dsc.TASK_POLICY}
    fields=routes.PrototypeDscIdentityRepairInput.model_fields
    assert set(fields)==set(routes.PrototypeRunInput.model_fields)|{'checkpoint_sha256',
        'expected_epoch_record_sha256','expected_terminal_closure_sha256','expected_supplement_sha256'}


def test_new_default_api_policy_sealed_first_mapper_and_normal_recovery(client,monkeypatch):
    from fox import prototype_job
    from fox.prototype_pipeline import run_prototype_pipeline
    from test_prototype_project_routes import prepare
    from test_prototype_mapping_recovery import EmptyMapper
    from test_prototype_pipeline import TARGET
    envelope={'target_profile':deepcopy(TARGET),'target_profile_sha256':canonical_hash(TARGET)}
    monkeypatch.setenv('FOX_PROTOTYPE_PROFILE_FILE','authored-no-secret-profile')
    monkeypatch.setattr(prototype_job,'load_prototype_profile',lambda _:deepcopy(envelope))
    c,root,pid,_,body=prepare(client)
    response=c.post(f'/api/projects/{pid}/prototype-runs',json=body)
    assert response.status_code==202,response.text
    rid=response.json()['id'];job=root/'jobs'/rid
    snapshot=json.loads((job/'source-snapshot.json').read_bytes())
    assert snapshot['prototype']['metadata_task_policy']==dsc.TASK_POLICY
    model=EmptyMapper();docs=routes.source_documents(snapshot['files'])
    with pytest.raises(ValueError):
        run_prototype_pipeline(job,docs,project_id=pid,project_name=snapshot['project_name'],
            expected_source_binding=body['source_binding'],approved_chunk_hashes=body['approved_chunk_hashes'],
            approved_policy_id=snapshot['prototype']['approved_policy_id'],opaf_client=model,profile=PROFILE,
            target_profile_loader=lambda:deepcopy(TARGET),processing_approval_check=lambda _:True,focus_schema_version=2)
    assert [name for name,_ in model.calls]==['mapper']
    task=model.calls[0][1]
    assert task['metadata_task_policy']==dsc.TASK_POLICY and task['source_identity_metadata']['full_identity_count']==0
    assert epochs.read(job/'prototype-pipeline/binding.json')['metadata_task_policy']==dsc.TASK_POLICY
    with sqlite3.connect(root/'fox.sqlite3') as db:db.execute("UPDATE runs SET state='ATTENTION' WHERE id=?",(rid,))
    url=f'/api/projects/{pid}/prototype-runs/{rid}'
    fallback=c.get(url+'/dsc-identity-repair')
    assert fallback.status_code==200,fallback.text
    assert fallback.json()['next_action']=='check_existing_repairs' and fallback.json()['eligible'] is False
    assert c.get(url+'/mapping-recovery').status_code==200
    binding_path=job/'prototype-pipeline/binding.json';binding_raw=binding_path.read_bytes()
    model_task_path=next((job/'prototype-pipeline').glob('focus-*/mapper-metadata-task.json'))
    task_raw=model_task_path.read_bytes()
    try:
        changed=epochs.read(binding_path);changed['metadata_task_policy']='unknown-policy'
        binding_path.write_text(json.dumps(changed))
        assert c.get(url+'/mapping-recovery').status_code==409
    finally:binding_path.write_bytes(binding_raw)
    try:
        changed=epochs.read(model_task_path);changed['metadata_guidance']='Stale task'
        model_task_path.write_text(json.dumps(changed))
        assert c.get(url+'/mapping-recovery').status_code==409
    finally:model_task_path.write_bytes(task_raw)
    changed=deepcopy(snapshot);changed['prototype']['metadata_task_policy']='unknown-policy'
    with pytest.raises(OpafError):prototype_job.validate_prototype_snapshot(changed)
    retried=c.post(url+'/retry-mapping',json=body)
    assert retried.status_code==202,retried.text
    child=epochs.read(root/'jobs'/retried.json()['id']/'source-snapshot.json')
    assert child['prototype']['metadata_task_policy']==dsc.TASK_POLICY


def test_fresh_default_policy_survives_normal_owner_continuation(epochs_case):
    case=epochs_case
    assert case[5]['prototype']['metadata_task_policy']==dsc.TASK_POLICY
    binding=epochs.read(case[4]/'prototype-pipeline/binding.json')
    assert binding['metadata_task_policy']==dsc.TASK_POLICY
    record=epochs.read(case[4]/'mapping-continuation.json')
    assert any(name.endswith('mapper-metadata-task.json') for name in record['files'])
    assert any(name.endswith('reviewer-metadata-task.json') for name in record['files'])


def test_proven_legacy_role_graph_change_has_only_explicit_mapping_recovery_fallback(recoverable):
    c,_,pid,rid,_,_,_,envelope,_=recoverable
    role=envelope['target_profile']['opaf']['roles']['mapper']
    role.update(workflow_id='9'*32,graph_sha256='9'*64)
    envelope['target_profile_sha256']=canonical_hash(envelope['target_profile'])
    response=c.get(f'/api/projects/{pid}/prototype-runs/{rid}/dsc-identity-repair')
    assert response.status_code==200,response.text
    value=response.json()
    assert value['scope']==dsc.SCOPE and value['next_action']=='check_mapping_recovery'
    assert value['eligible'] is value['identity_repair_recorded'] is False


def test_fixed_dsc_path_does_not_admit_mapper_or_second_attempt():
    assert dsc.authority_member(dsc.PREFIX+'/authorization.json')
    assert dsc.authority_member(dsc.PREFIX+'/focus-'+'a'*24+'/reviewer.json')
    for tail in ('mapper.json','reviewer.py','extra.json','../reviewer.json','attempt-000002/reviewer.json'):
        assert not dsc.authority_member(dsc.PREFIX+'/focus-'+'a'*24+'/'+tail)


def test_sealed_read_adapter_remains_inert_and_cannot_be_used_for_writes():
    class Sealed: pass
    payload={'historical':'exact immutable role input'}
    assert dsc.model_task(Sealed(),'mapper',payload,write=False) is payload
    with pytest.raises(OpafError):dsc.model_task(Sealed(),'mapper',payload,write=True)


def metadata_root(tmp_path,policy=None):
    """Task/index unit inputs, not an authorization or executed-role attestation."""
    docs,packet,_,request,candidate=example()
    root=tmp_path/'job/prototype-pipeline';child=root/request['focus_id']
    def write(path,value):
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(json.dumps(value))
    binding={'source_binding':packet['source_binding']}
    if policy is not None:binding['metadata_task_policy']=policy
    write(root/'binding.json',binding)
    write(root/'sources-manifest.json',{'files':[{'name':name,'sha256':dsc.hashlib.sha256(raw).hexdigest(),
        'bytes':len(raw)} for name,raw in docs]})
    for i,(_,raw) in enumerate(docs):
        path=root/f'sources/source-{i:03}.xml';path.parent.mkdir(exist_ok=True);path.write_bytes(raw)
    for name,value in {'request.json':request,'mapper.json':{'output':candidate},'mapper-target.json':{},
                       'reviewer.json':{},'reviewer-target.json':{},'review-receipt.json':{}}.items():
        write(child/name,value)
    return root,child,request,candidate,packet,write


@pytest.mark.parametrize('kind',['paired-files','dangling-link'])
def test_legacy_orphan_metadata_cannot_enter_index_or_model_task(tmp_path,monkeypatch,kind):
    from fox.prototype_pipeline import _review_index
    root,child,request,_,packet,write=metadata_root(tmp_path)
    plan={'requests':[request],'source_binding':packet['source_binding']}
    baseline=_review_index(root,plan)
    assert not any('metadata-task' in key for key in baseline['focuses'][0])
    if kind=='paired-files':
        for role in ('mapper','reviewer'):
            write(child/(role+'-metadata-task.json'),{'metadata_task_policy':dsc.TASK_POLICY,'untrusted_orphan':True})
    else:
        # Exercise the dangling-link refusal without requiring Windows symlink
        # privileges; actual path/link fences are independently tested below.
        path=child/'mapper-metadata-task.json';original=Path.is_symlink
        monkeypatch.setattr(Path,'is_symlink',lambda self:self==path or original(self))
    with pytest.raises(OpafError):dsc.model_task(child,'mapper',request,write=False)
    with pytest.raises(OpafError):_review_index(root,plan)


def test_modern_metadata_is_reconstructed_not_reinterpreted_after_repair(tmp_path):
    root,child,request,_,_,write=metadata_root(tmp_path,dsc.TASK_POLICY)
    original=dsc.model_task(child,'mapper',request,write=True)
    sidecar=child/'mapper-metadata-task.json';raw=sidecar.read_bytes()
    before={p.relative_to(root.parent).as_posix():dsc.hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (child/'mapper.json',sidecar)}
    # Isolate task-selection mechanics only. No caller may use this minimal
    # stub as repair authority; connected tests validate the complete record.
    write(root/dsc.RECORD,{'before_files':before})
    assert dsc.model_task(child,'mapper',request,write=False)==original
    assert original!=request and sidecar.read_bytes()==raw
    before.pop(sidecar.relative_to(root.parent).as_posix())
    write(root/dsc.RECORD,{'before_files':before})
    with pytest.raises(OpafError):dsc.model_task(child,'mapper',request,write=False)


@pytest.mark.parametrize('drift',['source-bytes','binding','request'])
def test_modern_metadata_source_binding_is_exact_before_task_creation(tmp_path,drift):
    root,child,request,_,_,write=metadata_root(tmp_path,dsc.TASK_POLICY)
    if drift=='source-bytes':
        path=root/'sources/source-000.xml';path.write_bytes(path.read_bytes().replace(b'COL_A',b'OTHER'))
    elif drift=='binding':write(root/'binding.json',{'metadata_task_policy':dsc.TASK_POLICY,'source_binding':'0'*64})
    else:request={**request,'source_binding':'0'*64}
    with pytest.raises(OpafError):dsc.model_task(child,'mapper',request,write=True)
    assert not (child/'mapper-metadata-task.json').exists()


@pytest.mark.parametrize('number,historical_four',[(4,True),(4,False),(5,False)])
def test_historical_publication_selector_never_inherits_physical_epoch_six_child(tmp_path,monkeypatch,number,historical_four):
    """Selector unit only; connected tests retain the real historical proofs."""
    from fox import prototype_result_publication as publication, prototype_container_epoch as container
    job=tmp_path/('fox-'+'a'*20)
    root=job/'prototype-pipeline';directory=root/'focus-one';directory.mkdir(parents=True)
    for path in (job/'source-snapshot.json',directory/'mapper-target.json',root/'assessment.json'):
        path.write_text('{}')
    request={'focus_id':'focus-one'};packet={'source_binding':'b'*64};plan={'requests':[request]}
    view={'checked':{'approved_structured_design':False},'proof':{'historical':'unchanged'}}
    monkeypatch.setattr(epochs,'reconstruct',lambda *a:(packet,plan))
    monkeypatch.setattr(container,'_historical_active_focus',lambda *a,**k:deepcopy(view))
    monkeypatch.setattr(epochs,'active_focus',lambda *a,**k:deepcopy(view))
    proof_key='container_proof_sha256' if number==4 else 'partition_proof_sha256'
    record={'epoch_number':number,'plan':{'repair_focus_id':'focus-one','previous_result':{'retained':'unchanged'}},
        'project_id':'project','source_hash':'c'*64,'source_binding':packet['source_binding'],proof_key:'d'*64}
    facts={name:False for name in ('native_source_rendered','sqlcl_validated','schema_prepared','import_verified',
        'runtime_verified','native_apex_generated','package_reimport_passed','clean_schema_install_passed',
        'technically_verified','business_behavior_accepted','download_ready')}
    result={'schema_version':1,'scope':'fox-prototype-pipeline-v1','job_id':job.name,
        'source_binding':packet['source_binding'],'status':'CHANGES_REQUIRED','stage':'reviewing','facts':facts,
        'assessment':{},'artifacts':{'checkpoint_directory':str(root)},'mapping_epoch_sha256':canonical_hash(record),
        'blocked_focus_id':'focus-one'}
    raw=json.dumps(result).encode();history=job/'old-result.json';history.write_bytes(raw)
    before=publication._reconstruct_binding(job,record,result,historical_four=historical_four)
    child=root/dsc.RECORD;child.parent.mkdir(parents=True);child.write_text('{}')
    after=publication._reconstruct_binding(job,record,result,historical_four=historical_four)
    assert before==after and 'dsc_identity_repair_sha256' not in after
    assert after['active_proofs_sha256']==canonical_hash([view['proof']]) and history.read_bytes()==raw


def test_connected_negative_stops_without_old_mapper_replay_and_preserves_terminal_history(dsc_case,monkeypatch):
    case=dsc_case;c,_,_,rid,job,snapshot,_,model,_,db,_=case
    before=files(job);calls=len(model.calls)
    plan,body=next_body(case)
    assert plan['projected_focuses']==plan['new_reviewer_calls']==5
    assert plan['changed_reason_count']==5 and plan['unstarted_focus_count']==1
    assert plan['repeated_mapper_calls']==0
    for key,value in [('approved_external_ai',False),('expected_supplement_sha256','0'*64),
                      ('expected_terminal_closure_sha256','0'*64),('source_hash','0'*64),('target_profile_sha256','0'*64)]:
        assert c.post(api(case,'dsc-identity-repair'),json={**body,key:value}).status_code==409
    assert files(job)==before and len(model.calls)==calls
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses=list(pool.map(lambda _:c.post(api(case,'dsc-identity-repair'),json=body),range(2)))
    assert sorted(response.status_code for response in responses)==[200,202],[r.text for r in responses]
    duplicate=c.post(api(case,'dsc-identity-repair'),json=body)
    assert duplicate.status_code==200 and duplicate.json()['dsc_identity_repair_recorded'] is True
    original=model.invoke
    def negative(role,payload):
        output,invocation=original(role,payload)
        if payload.get('scope')==dsc.SCOPE:
            output.update(verdict='CHANGES_REQUIRED',findings=[{'source_object_id':None,
                'code':'REAL_DEFECT','detail':'Authored genuine independent rejection.'}])
            invocation['response_sha256']=canonical_hash(output)
        return output,invocation
    monkeypatch.setattr(model,'invoke',negative)
    row,errors=process(case,monkeypatch)
    assert row['state']=='ATTENTION',errors
    assert [name for name,_ in model.calls[calls:]]==['reviewer']
    assert all((job/name).read_bytes()==raw for name,raw in before.items() if name!='prototype-result.json')
    assert (job/screen.RESULT_BASE/'publication.json').read_bytes()==before[screen.RESULT_BASE+'/publication.json']
    assert (job/dsc.RESULT_BASE/'publication.json').is_file()
    assert epochs.read(job/'prototype-result.json')['status']=='CHANGES_REQUIRED'
    count=len(model.calls)
    assert c.post(api(case,'dsc-identity-repair'),json=body).status_code==200
    assert len(model.calls)==count
    with db() as connection:
        assert connection.execute('SELECT COUNT(*) FROM events WHERE action=?',(dsc.EVENT,)).fetchone()[0]==1
