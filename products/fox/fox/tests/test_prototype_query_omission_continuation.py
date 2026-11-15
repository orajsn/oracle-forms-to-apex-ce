"""Actual local API/worker/authority tests; authored model/Oracle receipts only."""
from contextlib import contextmanager
from copy import deepcopy
import json
from pathlib import Path
import sqlite3

import pytest

from fox import prototype_pipeline as pipeline, prototype_job, worker
from fox import prototype_query_omission_continuation as omission
from fox.opaf import canonical_hash, OpafError
from fox.prototype_transport import build_authority_bundle
from test_source_history_api import client, settings as baseline_settings, no_external_actions, upload
from test_prototype_pipeline import SyntheticOpaf, SyntheticConverter, PROFILE, TARGET


class QueryMapper(SyntheticOpaf):
    def invoke(self, role, request):
        base = request if role == PROFILE['mapper'] else {k: request[k] for k in ('request','candidate','candidate_sha256')}
        output, invocation = super().invoke(role, base)
        self.calls[-1] = (self.calls[-1][0], deepcopy(request))
        if role == PROFILE['mapper'] and len([n for n, _ in self.calls if n == 'mapper']) == 3:
            output['source_binding'] = request['source_binding']
            units = {u['source_attribute']: u for u in request['code_units']}
            output['blueprint']['claims'] = [
                {'id':'query-' + attribute,'source_object_id':units[attribute]['owner_id'],
                 'kind':kind,'status':'source_fact','value':value,'evidence_refs':[units[attribute]['id']],
                 'reason':'Authored unsupported model assertion, never proven source semantics.'}
                for attribute,kind,value in [('WhereClause','block.where','STATUS=REDACTED'),
                                             ('OrderByClause','block.order','VALUE desc')]]
        invocation.update(request_sha256=canonical_hash(request),response_sha256=canonical_hash(output))
        return output, invocation


@pytest.fixture
def settings(monkeypatch):
    baseline_settings.__wrapped__(monkeypatch)
    monkeypatch.setenv('FOX_VERIFICATION_ENABLED','1')
    monkeypatch.setenv('FOX_VERIFIER_RELEASE_SHA256','d'*64)


@pytest.fixture
def case(client, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / 'converter'))
    monkeypatch.setenv('FOX_RUN_ADAPTER','embedded-opaf')
    monkeypatch.delenv('FOX_INSTALLATION_MODE',raising=False)
    monkeypatch.setitem(TARGET,'active',True)
    monkeypatch.setitem(TARGET,'scope',{'data_mode':'synthetic_test_only','existing_resources_only':True,
                                     'customer_deployment_authorized':False,'supported_operations':['query','insert','update']})
    for name,fields in {'oci':('compartment_id','database_id','instance_id','region'),
            'database':('db_name','session_user','parsing_schema'),
            'apex':('workspace','workspace_id','ords_origin','ords_base_path'),
            'sqlcl':('saved_connection',)}.items():
        monkeypatch.setitem(TARGET,name,{key:'SYNTHETIC-'+key for key in fields})
    monkeypatch.setitem(TARGET,'tested_versions',{'opaf':'synthetic-26.4','apex':'26.1.6',
                                                'sqlcl':'26.1.2.0','apexlang_mmd':'26.1.0+3102'})
    envelope = {'target_profile':TARGET,'target_profile_sha256':canonical_hash(TARGET)}
    monkeypatch.setenv('FOX_PROTOTYPE_PROFILE_FILE','synthetic-public-metadata')
    monkeypatch.setattr(prototype_job,'load_prototype_profile',lambda _:deepcopy(envelope))
    c, root, pid = client
    raw = ('<FormModule Name="SYNTHETIC">' + ''.join(
        f'<Block Name="B{i}" DatabaseBlock="true" WhereClause="STATUS=FOX_REDACTED_LITERAL_1" '
        'OrderByClause="VALUE desc"><Item Name="VALUE" ItemType="Text Item" DataType="Char" '
        'MaximumLength="80" DatabaseItem="true" Required="true"/></Block>' for i in range(4)) + '</FormModule>').encode()
    upload(c,pid,[('synthetic.xml',raw)])
    assessment = c.get(f'/api/projects/{pid}/prototype-assessment').json()
    body = {k:assessment[k] for k in ('source_hash','source_binding','target_profile_sha256')}
    body.update(expected_current_source_set_id=assessment['selected_source_set_id'],
        approved_chunk_hashes={r['id']:r['sha256'] for r in assessment['chunks']},
        approved_redacted_source=True,approved_external_ai=True,approved_prototype_scope=True)
    queued = c.post(f'/api/projects/{pid}/prototype-runs',json={**body,'native_input_policy':'forms-required-inputs-v1'})
    assert queued.status_code == 202, queued.text
    rid = queued.json()['id']; job = root/'jobs'/rid; root.chmod(0o700)
    snapshot = json.loads((job/'source-snapshot.json').read_bytes())
    model, converter = QueryMapper(), SyntheticConverter()
    with pytest.raises(ValueError):
        pipeline.run_prototype_pipeline(job,[('synthetic.xml',raw)],project_id=pid,
            project_name=snapshot['project_name'],expected_source_binding=body['source_binding'],
            approved_chunk_hashes=body['approved_chunk_hashes'],approved_policy_id=snapshot['prototype']['approved_policy_id'],
            opaf_client=model,profile=PROFILE,target_profile_loader=lambda:deepcopy(TARGET),
            processing_approval_check=lambda _:True,focus_schema_version=2,
            native_input_policy='forms-required-inputs-v1')
    with sqlite3.connect(root/'fox.sqlite3') as connection:
        connection.execute("UPDATE runs SET state='ATTENTION' WHERE id=?",(rid,))
    @contextmanager
    def db():
        connection = sqlite3.connect(root/'fox.sqlite3'); connection.row_factory = sqlite3.Row
        try:
            with connection: yield connection
        finally: connection.close()
    monkeypatch.setattr(prototype_job,'_configuration',lambda *a,**kw:{'profile':PROFILE,
        'opaf_client':model,'target_profile_loader':lambda:deepcopy(TARGET),'converter_adapter':converter})
    return c,root,pid,rid,job,body,model,converter,db,envelope


def url(case):
    return f'/api/projects/{case[2]}/prototype-runs/{case[3]}/redacted-query-omission'


def body_for(case):
    response = case[0].get(url(case))
    assert response.status_code == 200, response.text
    plan = response.json()
    return plan,{**case[5],'checkpoint_sha256':plan['checkpoint_sha256'],'approved_query_omission':True,
        **{'expected_'+k:plan[k] for k in ('terminal_closure_sha256','raw_candidate_sha256','candidate_sha256','omission_receipt_sha256')}}


def files(job):
    return {p.relative_to(job):p.read_bytes() for p in job.rglob('*') if p.is_file()}


def test_same_run_reviewer_first_exact_prefix_and_authority(case):
    c,root,_,rid,job,_,model,converter,db,envelope = case
    original = files(job); old_calls = deepcopy(model.calls)
    plan, body = body_for(case)
    assert plan['completed_focus_count'] == 2 and plan['remaining_focus_count'] == 2
    assert plan['repeated_mapper_calls'] == 0 and plan['fresh_reviewer_calls'] == 1
    assert files(job) == original and model.calls == old_calls and not converter.calls
    assert c.post(url(case),json=body).status_code == 202
    assert c.post(url(case),json=body).status_code == 200
    stage = converter.run_stage
    def complete(name,request):
        receipt = stage(name,request); receipt.update(status='COMPLETE',business_behavior_accepted=False)
        return receipt
    converter.run_stage = complete
    worker.process_one(db,root)
    with db() as connection:
        row = connection.execute('SELECT state,message FROM runs WHERE id=?',(rid,)).fetchone()
        assert row['state'] == 'GENERATED', row['message']
        assert connection.execute('SELECT COUNT(*) FROM runs').fetchone()[0] == 1
        assert connection.execute('SELECT COUNT(*) FROM events WHERE action=?',(omission.EVENT,)).fetchone()[0] == 1
    assert model.calls[:len(old_calls)] == old_calls
    assert model.calls[len(old_calls)][0] == 'reviewer'
    assert len([n for n,_ in model.calls if n == 'mapper']) == 5
    assert all((job/p).read_bytes() == raw for p,raw in original.items())
    assert c.post(url(case),json=body).status_code == 200
    request = converter.requests[0]
    before = files(job); operations = deepcopy((model.calls,converter.calls))
    pipeline.authorize_prototype_request(job,request)
    bundle = build_authority_bundle(job,request)
    assert omission.RECORD in {r['path'] for r in bundle['files']}
    from types import SimpleNamespace
    from forms2apex.prototype_gateway import PrototypeGateway
    remote = root/'receiver-jobs'; remote.mkdir()
    receiver = PrototypeGateway(SimpleNamespace(jobs_root=remote),
        authorize=lambda value:pipeline.authorize_prototype_request(remote/rid,value,staged_projection=True))
    assert receiver.stage_source_authority(rid,bundle)['staged'] is True
    receiver._authorize(request)
    assert files(job) == before and (model.calls,converter.calls) == operations
    from fox.prototype_download import retained_export_request
    retained_export_request(job,json.loads((job/'source-snapshot.json').read_bytes()),envelope)
    output = f'/api/projects/{case[2]}/prototype-runs/{rid}/output'
    assert c.get(output).status_code == 200
    with db() as connection: connection.execute('DELETE FROM events WHERE action=?',(omission.EVENT,))
    assert c.get(output).status_code == 409


@pytest.mark.parametrize('field', ['approved_query_omission','approved_external_ai','approved_redacted_source','approved_prototype_scope'])
def test_each_explicit_consent_required(case,field):
    _, body = body_for(case); body[field] = False
    before = files(case[4]); calls = deepcopy(case[6].calls)
    assert case[0].post(url(case),json=body).status_code == 409
    assert files(case[4]) == before and case[6].calls == calls


@pytest.mark.parametrize('artifact', ['reviewer-intent.json','reviewer-request.json','reviewer-metadata-task.json','reviewer.json'])
def test_any_prior_review_prevents_omission(case,artifact):
    plan,_ = body_for(case)
    (case[4]/'prototype-pipeline'/plan['focus_id']/artifact).write_text('{}')
    before = files(case[4]); calls = deepcopy(case[6].calls)
    assert case[0].get(url(case)).status_code == 409
    assert files(case[4]) == before and case[6].calls == calls


@pytest.mark.parametrize('artifact', ['validate-intent.json','prepare_schema-intent.json','import.json','native-plan.json'])
def test_no_downstream_work_may_be_reclassified(case,artifact):
    (case[4]/'prototype-pipeline'/artifact).write_text('{}')
    assert case[0].get(url(case)).status_code == 409


def test_missing_event_blocks_configuration_and_models(case):
    _,body = body_for(case)
    assert case[0].post(url(case),json=body).status_code == 202
    calls = deepcopy(case[6].calls)
    with case[8]() as db: db.execute('DELETE FROM events WHERE action=?',(omission.EVENT,))
    worker.process_one(case[8],case[1])
    with case[8]() as db:
        assert db.execute('SELECT state FROM runs WHERE id=?',(case[3],)).fetchone()[0] == 'ATTENTION'
    assert case[6].calls == calls and not case[7].calls


@pytest.mark.parametrize('where', ['later-mapper-intent','converter-intent','foreign-file','later-directory'])
def test_new_uncertain_or_foreign_work_after_consent_blocks_every_call(case,where):
    plan,body = body_for(case)
    assert case[0].post(url(case),json=body).status_code == 202
    root = case[4]/'prototype-pipeline'
    if where.startswith('later-'):
        from fox.prototype_job import read_prototype_snapshot
        from fox.prototype_mapping_epochs import reconstruct
        snapshot,raw = read_prototype_snapshot(case[4])
        _,focuses = reconstruct(case[4],snapshot,raw,case[-1]['target_profile'])
        directory = root/focuses['requests'][plan['completed_focus_count']+1]['focus_id']
        directory.mkdir()
        if where == 'later-mapper-intent': (directory/'mapper-intent.json').write_text('{}')
    else:
        (root/('import-intent.json' if where == 'converter-intent' else 'unexpected.json')).write_text('{}')
    calls = deepcopy(case[6].calls)
    assert case[0].get(url(case)).status_code == 409
    worker.process_one(case[8],case[1])
    assert case[6].calls == calls and not case[7].calls
    with case[8]() as db:
        assert db.execute('SELECT state FROM runs WHERE id=?',(case[3],)).fetchone()[0] == 'ATTENTION'


@pytest.mark.parametrize('field', ['checkpoint_sha256','expected_raw_candidate_sha256',
    'expected_candidate_sha256','expected_omission_receipt_sha256','expected_terminal_closure_sha256',
    'source_hash','source_binding','target_profile_sha256'])
def test_changed_consent_binding_is_rejected_without_writes(case,field):
    _,body = body_for(case); body[field] = '0'*64
    before = files(case[4]); calls = deepcopy(case[6].calls)
    assert case[0].post(url(case),json=body).status_code == 409
    assert files(case[4]) == before and case[6].calls == calls and not case[7].calls


def test_unknown_reviewer_never_replays_or_reaches_converter(case):
    _,body = body_for(case)
    assert case[0].post(url(case),json=body).status_code == 202
    case[6].fail_role = 'reviewer'
    worker.process_one(case[8],case[1])
    calls = deepcopy(case[6].calls)
    assert calls[-1][0] == 'reviewer' and not case[7].calls
    assert case[0].get(url(case)).status_code == 409
    assert case[0].post(url(case),json=body).status_code == 409
    assert case[6].calls == calls and not case[7].calls


def test_reviewer_rejection_never_reaches_converter(case):
    _,body = body_for(case)
    assert case[0].post(url(case),json=body).status_code == 202
    case[6].changes_role = 'reviewer'
    worker.process_one(case[8],case[1])
    assert case[6].calls[-1][0] == 'reviewer' and not case[7].calls
    with case[8]() as db:
        assert db.execute('SELECT state FROM runs WHERE id=?',(case[3],)).fetchone()[0] == 'ATTENTION'


def seed_other_history(case,monkeypatch):
    """Valid synthetic stopped source; receiver observations are authored only."""
    from fox import source_history
    from fox.intake import checked_source
    from fox.opaf import ConverterClient
    from types import SimpleNamespace
    old_id='fox-'+'9'*20;pid='9'*32
    snapshot=json.loads((case[4]/'source-snapshot.json').read_bytes())
    owner=snapshot['approvals']['owner']
    files_to_upload=[checked_source(row['name'],source_history.readable_source_bytes(row)) for row in snapshot['files']]
    with case[8]() as db:
        db.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)',(pid,owner,'Other','Other stopped prototype','',1.0))
        source_history.create_project_selection(db,pid,1.0)
        source_history.publish_upload(db,pid,files_to_upload,2.0,owner)
        snapshot.update(project=pid,project_id=pid,project_name='Other stopped prototype',
            files=source_history.selected_sources(db,pid),selected_source_set_id=source_history.selected_source_set_id(db,pid))
        db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
            (old_id,pid,snapshot['source_hash'],'ATTENTION','Authored stopped source',3.0,3.0,None))
    old_job=case[1]/'jobs'/old_id;old_job.mkdir()
    (old_job/'source-snapshot.json').write_text(json.dumps(snapshot))
    state=SimpleNamespace(id=old_id,job=old_job,calls=[],mutate=None,intercept=None)
    transport=ConverterClient('http://127.0.0.1:8091','SYNTHETIC-ISOLATION-ONLY')
    def observe(method,path):
        assert method=='GET' and '/isolation-witness?challenge=' in path and old_id in path
        nonce=path.rsplit('=',1)[1];state.calls.append((method,path))
        if state.intercept: state.intercept()
        value={'schema_version':1,'scope':'fox-prototype-isolation-witness-v1','job_id':old_id,'challenge':nonce,
            'boundary':'receiver_absent','project_id':None,'source_binding':None,'request_sha256':None,
            'execution_target_sha256':None,'retained_sha256':'d'*64,'process_scope':'single_converter_process',
            'execution_authorized':False,'retry_authorized':False,'closure_claimed':False,'business_behavior_accepted':False}
        return state.mutate(value) if state.mutate else value
    monkeypatch.setattr(transport,'request',observe)
    prior=prototype_job._configuration
    monkeypatch.setattr(prototype_job,'_configuration',lambda *a,**kw:{**prior(*a,**kw),'gateway':transport})
    return state


def test_omission_isolates_other_history_without_replaying_or_changing_it(case,monkeypatch):
    other=seed_other_history(case,monkeypatch);before=files(other.job)
    with case[8]() as db: old=dict(db.execute('SELECT * FROM runs WHERE id=?',(other.id,)).fetchone())
    _,body=body_for(case)
    assert not other.calls
    response=case[0].post(url(case),json=body)
    assert response.status_code==202,response.text
    assert len(other.calls)==1 and files(other.job)==before
    with case[8]() as db:
        assert dict(db.execute('SELECT * FROM runs WHERE id=?',(other.id,)).fetchone())==old
        assert db.execute('SELECT state FROM runs WHERE id=?',(case[3],)).fetchone()[0]=='QUEUED'
    assert case[6].calls[-1][0]=='mapper' and not case[7].calls


@pytest.mark.parametrize('field,value',[('challenge','0'*64),('job_id','fox-'+'0'*20),
    ('boundary','unknown'),('boundary','pending'),('execution_authorized',True),
    ('retry_authorized',True),('closure_claimed',True),('business_behavior_accepted',True)])
def test_omission_unknown_or_promoting_other_witness_cannot_queue(case,monkeypatch,field,value):
    other=seed_other_history(case,monkeypatch);other.mutate=lambda row:{**row,field:value}
    _,body=body_for(case);before=files(case[4])
    assert case[0].post(url(case),json=body).status_code==409
    assert len(other.calls)==1
    assert files(case[4])==before and not case[7].calls


@pytest.mark.parametrize('change',['other-active','own-ledger','same-project-run','other-owner','other-tree','target'])
def test_omission_isolation_refuses_active_or_changed_history(case,monkeypatch,change):
    other=seed_other_history(case,monkeypatch)
    _,body=body_for(case)
    if change in ('other-active','own-ledger','same-project-run'):
        with case[8]() as db:
            if change=='other-active': db.execute("UPDATE runs SET state='PROCESSING' WHERE id=?",(other.id,))
            elif change=='own-ledger':
                db.execute('CREATE TABLE verification_test_ledger(job_id TEXT)')
                db.execute('INSERT INTO verification_test_ledger VALUES(?)',(case[3],))
            else: db.execute('UPDATE runs SET project=? WHERE id=?',(case[2],other.id))
    elif change=='other-owner':
        with case[8]() as db: db.execute('UPDATE projects SET owner=? WHERE id=?',('changed','9'*32))
    elif change=='other-tree': other.intercept=lambda:(other.job/'new.json').write_text('{}')
    else: other.intercept=lambda:TARGET['tested_versions'].update(apex='changed')
    response=case[0].post(url(case),json=body)
    assert response.status_code in (409,429),response.text
    assert len(other.calls)==(1 if change in ('other-tree','target') else 0)
    with case[8]() as db: assert db.execute('SELECT state FROM runs WHERE id=?',(case[3],)).fetchone()[0]=='ATTENTION'
    assert not case[7].calls


def test_isolation_holds_database_write_lock_during_witness(case,monkeypatch):
    other=seed_other_history(case,monkeypatch);observed=[]
    def compete():
        with sqlite3.connect(case[1]/'fox.sqlite3',timeout=0.01) as db:
            with pytest.raises(sqlite3.OperationalError,match='locked'):
                db.execute("UPDATE runs SET state='PROCESSING' WHERE id=?",(other.id,))
        observed.append(True)
    other.intercept=compete
    _,body=body_for(case)
    assert case[0].post(url(case),json=body).status_code==202
    assert observed==[True]


def test_own_unexpected_addition_before_queue_is_rejected(case,monkeypatch):
    from fox.prototype_fresh_admission import QueryOmissionAdmissionRead
    original=QueryOmissionAdmissionRead.__call__
    def changed(check,*,expected_own_additions=None):
        if expected_own_additions is not None:
            (check.own['job']/'unexpected.json').write_text('{}')
        return original(check,expected_own_additions=expected_own_additions)
    monkeypatch.setattr(QueryOmissionAdmissionRead,'__call__',changed)
    _,body=body_for(case)
    assert case[0].post(url(case),json=body).status_code==409
    with case[8]() as db:
        assert db.execute('SELECT state FROM runs WHERE id=?',(case[3],)).fetchone()[0]=='ATTENTION'
        assert db.execute('SELECT COUNT(*) FROM events WHERE action=?',(omission.EVENT,)).fetchone()[0]==0
    # The partial record remains evidence, never repaired into fresh consent.
    assert case[0].post(url(case),json=body).status_code==409
    assert not case[7].calls
