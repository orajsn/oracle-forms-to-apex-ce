"""Actual local files/API/worker, authored provider replies; NOT live OPAF/Oracle."""
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
import json

import pytest

from fox import prototype_candidate_continuation as continuation, prototype_mapping_epochs as epochs
from fox import prototype_project_routes as routes
from fox.opaf import canonical_hash, OpafError
from fox.prototype_pipeline import run_prototype_pipeline, authorize_prototype_request
from fox.prototype_transport import build_authority_bundle
from test_prototype_pipeline import setup, PROFILE, SyntheticOpaf
from test_prototype_dsc_identity_repair import (dsc_case, historical_dsc_source, next_body as dsc_body,
    correction_case,screen_case,partition_case,container_case,container_source_model,clause_case,epochs_case,
    tmp_path,client,settings,no_external_actions,api,files,process,dsc)


def test_new_policy_pipeline_reconstructs_identical_candidate_and_provenance(setup, monkeypatch):
    job,docs,model,approvals,kwargs=setup
    original=model.invoke
    def aliases(role,payload):
        base=payload if role==PROFILE['mapper'] else {k:payload[k] for k in ('request','candidate','candidate_sha256')}
        result,proof=original(role,base)
        if role==PROFILE['mapper']:
            result['source_binding']=payload['source_binding']
            for obj in payload['owned_objects']:
                if obj['kind']=='Item':
                    result['blueprint']['claims'].append({'id':obj['id']+'-alias','source_object_id':obj['id'],
                        'kind':'object.database_item','value':obj['database_item'],'status':'source_fact',
                        'evidence_refs':[obj['id']],'reason':'Exact authored source fact.'})
        proof['request_sha256']=canonical_hash(payload);proof['response_sha256']=canonical_hash(result)
        return result,proof
    monkeypatch.setattr(model,'invoke',aliases)
    kwargs['candidate_format_policy']=continuation.POLICY
    result=run_prototype_pipeline(job,docs,**kwargs)
    assert result['status']=='BLOCKED_ADAPTER'
    assert [r for r,_ in model.calls]==['mapper','reviewer']*result['assessment']['focus_count']
    root=job/'prototype-pipeline';index=epochs.read(root/'review-index.json')
    assert index['schema_version']==3 and index['candidate_format_policy']==continuation.POLICY
    from test_prototype_pipeline import CONVERTER_STAGES
    native=epochs.read(root/'native-plan.json');rendered=epochs.read(root/'rendered.json')
    request={'schema_version':1,'scope':'fox-prototype-converter-request-v1','job_id':job.name,
        'project_id':kwargs['project_id'],'source_binding':kwargs['expected_source_binding'],
        'plan_sha256':native['plan_sha256'],'rendering_spec':native['rendering_spec'],
        'rendered_zip_sha256':rendered['zip_sha256'],'prior_receipts':{},'source_authority':{
            'schema_version':1,'scope':'fox-prototype-source-authority-v1',
            'binding_sha256':canonical_hash(epochs.read(root/'binding.json')),
            'sources_manifest_sha256':canonical_hash(epochs.read(root/'sources-manifest.json')),
            'review_index_sha256':canonical_hash(index)}}
    count=len(model.calls);before=files(job)
    authorize_prototype_request(job,request)
    bundle=build_authority_bundle(job,request)
    assert len(model.calls)==count and files(job)==before
    assert any(r['path'].endswith('/projection-receipt.json') for r in bundle['files'])
    from forms2apex.prototype_gateway import _authority_descriptor,_check_authority_members
    import base64
    descriptor=_authority_descriptor(bundle,encoded=True)
    _check_authority_members(descriptor,{r['path']:base64.b64decode(r['content_base64']) for r in bundle['files']})
    # Reindexing is itself a technical boundary, not a way to bless changed
    # request.json or unbound/non-independent stored roles with a new hash.
    from fox.forms_focus import build_focus_plan
    from fox.forms_understanding_packet import local_packet
    from fox.prototype_pipeline import _review_index
    plan=build_focus_plan(docs,expected_source_binding=local_packet(docs)['source_binding'],approved_chunk_hashes={})
    request_path=root/plan['requests'][0]['focus_id']/'request.json'
    binding_path=root/'binding.json';target_path=root/plan['requests'][0]['focus_id']/'mapper-target.json'
    originals={p:p.read_bytes() for p in (request_path,binding_path,target_path)}
    for change in ('request','role-hash','same-workflow'):
        try:
            if change=='request':
                value=epochs.read(request_path);value['focus_binding']='0'*64
                request_path.write_text(json.dumps(value))
            elif change=='role-hash':
                value=epochs.read(binding_path);value['profile_sha256']='0'*64
                binding_path.write_text(json.dumps(value))
            else:
                target=epochs.read(target_path);roles=target['opaf']['roles']
                roles['reviewer']['workflow_id']=roles['mapper']['workflow_id']
                target_path.write_text(json.dumps(target))
                binding=epochs.read(binding_path);binding['profile_sha256']=canonical_hash(roles)
                binding_path.write_text(json.dumps(binding))
            mutated={p:p.read_bytes() for p in originals}
            with pytest.raises(OpafError):_review_index(root,plan)
            assert {p:p.read_bytes() for p in originals}==mutated
        finally:
            for path,raw in originals.items():path.write_bytes(raw)
    assert _review_index(root,plan)==index


@pytest.fixture
def format_case(dsc_case,monkeypatch):
    return _stopped_format_case(dsc_case,monkeypatch)


def _stopped_format_case(case,monkeypatch):
    from fox.prototype_read_scope import epoch_read_scope
    with case[9]() as connection,epoch_read_scope(case[4]/'prototype-pipeline'):
        dsc.inspect(case[4],case[5],(case[4]/'source-snapshot.json').read_bytes(),case[10]['target_profile'],connection)
    _,body=dsc_body(case)
    response=case[0].post(api(case,'dsc-identity-repair'),json=body)
    assert response.status_code==202,response.text
    original=case[7].invoke
    def format_defect(role,payload):
        output,proof=original(role,payload)
        if role==PROFILE['mapper']:
            output['source_binding']=payload['source_binding']
            for obj in payload['owned_objects']:
                if obj['kind']=='Item':
                    output['blueprint']['claims'].append({'id':obj['id']+'-database-alias',
                        'source_object_id':obj['id'],'kind':'object.database_item',
                        'status':'source_fact','value':obj['database_item'],
                        'evidence_refs':[obj['id']],'reason':'Authored exact source Item metadata.'})
        proof['response_sha256']=canonical_hash(output)
        return output,proof
    monkeypatch.setattr(case[7],'invoke',format_defect)
    row,errors=process(case,monkeypatch)
    assert row['state']=='ATTENTION',errors
    assert not (case[4]/dsc.RESULT_BASE/'publication.json').exists()
    return case


@pytest.fixture(autouse=True)
def historical_format_policy(monkeypatch,request):
    if 'format_case' not in request.fixturenames: return
    original=routes.prepare_prototype_admission
    def legacy(*args,**kwargs):
        kwargs['candidate_format_policy']=None
        return original(*args,**kwargs)
    monkeypatch.setattr(routes,'prepare_prototype_admission',legacy)


def next_body(case):
    response=case[0].get(api(case,'candidate-format-continuation'))
    assert response.status_code==200,response.text
    plan=response.json()
    return plan,{**case[6],'checkpoint_sha256':plan['checkpoint_sha256'],
        **{'expected_'+key:plan[key] for key in ('terminal_closure_sha256','raw_candidate_sha256',
            'candidate_sha256','normalization_receipt_sha256')}}


def test_same_run_one_post_duplicate_no_mapper_replay(format_case,monkeypatch):
    case=format_case;c,_,_,rid,job,snapshot,_,model,_,db,envelope=case
    before=files(job);count=len(model.calls)
    plan,body=next_body(case)
    assert files(job)==before and len(model.calls)==count
    assert plan['eligible'] and plan['first_next_operation']=='reviewer' and plan['repeated_mapper_calls']==0
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses=list(pool.map(lambda _:c.post(api(case,'candidate-format-continuation'),json=body),range(2)))
    assert sorted(r.status_code for r in responses)==[200,202],[r.text for r in responses]
    assert len(model.calls)==count
    row,errors=process(case,monkeypatch)
    assert row['state']=='GENERATED',errors
    assert [r for r,_ in model.calls[count:]]==['reviewer']
    assert all((job/name).read_bytes()==raw for name,raw in before.items() if name!='prototype-result.json')
    assert c.post(api(case,'candidate-format-continuation'),json=body).status_code==200
    with db() as connection:
        assert connection.execute('SELECT COUNT(*) FROM runs').fetchone()[0]==1
        assert connection.execute('SELECT COUNT(*) FROM events WHERE action=?',(continuation.EVENT,)).fetchone()[0]==1
        epochs.validate_epoch_chain(job,snapshot,(job/'source-snapshot.json').read_bytes(),connection)
    from fox.prototype_download import retained_export_request
    retained_export_request(job,snapshot,envelope)


@pytest.mark.parametrize('options',[{'runtime':{},'allow_format':True,'preview':True},
    {'allow_format':True,'preview':True}, {'allow_format':True,'preview':False},
    {'runtime':{},'artifact_plan':object(),'preview':True}, {'artifact_plan':object()}])
def test_planning_flags_never_authorize_execution(options):
    with pytest.raises(OpafError,match='pure pre-review'):
        epochs._active_focus(None,None,None,None,None,None,None,None,**options)


def test_artifact_plan_is_pure_create_only_and_rejects_changed_existing_files(tmp_path):
    path=tmp_path/'focus'/'projection-receipt.json'
    plan=continuation.ArtifactPlan(tmp_path);value={'source_proven':True}
    plan.save(path,value);value['source_proven']=False
    assert not path.exists() and plan.files=={'focus/projection-receipt.json':{'source_proven':True}}
    with pytest.raises(OpafError): epochs.save(path,{'source_proven':True},False)
    plan.materialize();before=path.read_bytes();plan.materialize()
    assert path.read_bytes()==before
    path.write_text('{"source_proven":false}')
    with pytest.raises(OpafError): plan.materialize()


def test_format_receipt_chains_already_resolved_owner_without_changing_raw(tmp_path):
    from test_prototype_claim_resolution import example
    from test_prototype_pipeline import documents
    from fox.prototype_claim_resolution import resolve_claim_owners
    request,raw=example()
    # Add one independent exact Item metadata alias. The proposal continues to
    # require its existing code-unit owner repair, not a format-policy guess.
    item=next(row for row in request['owned_objects'] if row['kind']=='Item')
    raw['blueprint']['claims'].append({'id':'format-alias','source_object_id':item['id'],
        'kind':'object.item_type','value':item['item_type'],'status':'source_fact',
        'evidence_refs':[item['id']],'reason':'Authored exact source metadata.'})
    before=deepcopy(raw);owner,receipt=resolve_claim_owners(request,raw)
    root=tmp_path/'prototype-pipeline';(root/'sources').mkdir(parents=True)
    docs=documents()
    epochs.save(root/'sources-manifest.json',{'files':[{'name':name} for name,_ in docs]},True)
    for index,(_,body) in enumerate(docs): (root/'sources'/f'source-{index:03}.xml').write_bytes(body)
    candidate,evidence=continuation.normalize_remaining(root,request,raw,owner,receipt,authorized=True)
    assert raw==before and candidate['blueprint']['claims'][0]==owner['blueprint']['claims'][0]
    assert evidence['raw_candidate_sha256']==canonical_hash(raw)
    assert evidence['owner_candidate_sha256']==canonical_hash(owner)
    assert evidence['owner_resolution_v1']==receipt
    assert evidence['candidate_format_normalization']['raw_candidate_sha256']==canonical_hash(owner)


def test_new_default_policy_survives_existing_retry_api(client,monkeypatch):
    from test_prototype_dsc_identity_repair import test_new_default_api_policy_sealed_first_mapper_and_normal_recovery
    test_new_default_api_policy_sealed_first_mapper_and_normal_recovery(client,monkeypatch)
    snapshots=[epochs.read(p) for p in (client[1]/'jobs').glob('fox-*/source-snapshot.json')]
    assert len(snapshots)==2 and sum('retry_of' in row for row in snapshots)==1
    assert all(row['prototype']['candidate_format_policy']==continuation.POLICY for row in snapshots)


def test_server_only_exclusion_still_checks_other_unresolved_work(client):
    """Unit-test internal guard only; this is NOT frontier authorization proof."""
    import inspect,sqlite3
    c,root,pid=client
    endpoint=next(r.endpoint for r in c.app.routes if getattr(r,'path','').endswith('/candidate-format-continuation')
        and 'POST' in getattr(r,'methods',()))
    callback=inspect.getclosurevars(endpoint).nonlocals['admission_allowed']
    rid='fox-'+'d'*20;other='fox-'+'e'*20
    with sqlite3.connect(root/'fox.sqlite3') as db:
        db.row_factory=sqlite3.Row;db.execute('BEGIN IMMEDIATE')
        db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',(rid,pid,'d'*64,'ATTENTION','Authored guard unit',1.,1.,None))
        assert callback(db,excluded_stopped_job_id=rid)
        for state in ('QUEUED','PROCESSING','ATTENTION'):
            db.execute('INSERT OR REPLACE INTO runs VALUES(?,?,?,?,?,?,?,?)',
                (other,pid,'e'*64,state,'Authored unresolved guard unit',1.,1.,None))
            assert not callback(db,excluded_stopped_job_id=rid)
        db.rollback()
    from pydantic import ValidationError
    with pytest.raises(ValidationError):routes.PrototypeCandidateFormatInput.model_validate({'excluded_stopped_job_id':rid})
