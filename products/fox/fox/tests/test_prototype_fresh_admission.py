"""Canonical authenticated API + SQLite/files; converter observations are authored.

No model, Oracle, browser runtime or real converter is called. These tests prove
fresh-submission isolation boundaries, not completed conversion/import evidence.
"""
from copy import deepcopy
from pathlib import Path
import hashlib
import json
import re
import sqlite3
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest

from fox.app import create_app
from fox.opaf import ConverterClient, OpafError, canonical_hash
from fox.prototype_authority import execution_target
from fox.verification_recovery import VerificationRecovery, preclaim_tree
from test_source_history_api import (settings, no_external_actions, login, new_project, upload, ORIGIN)
from test_prototype_admission import documents


@pytest.fixture
def case(tmp_path_factory,settings,monkeypatch):
    from forms2apex.target_profile import select_target_profile
    folder=tmp_path_factory.mktemp('fa');root=folder/'data'
    target=select_target_profile('jsn-native-project-2616-v1')
    envelope={'target_profile':target,'target_profile_sha256':canonical_hash(target)}
    profile=folder/'profile.json';profile.write_text(json.dumps(envelope),encoding='utf-8')
    monkeypatch.setenv('FOX_PROTOTYPE_PROFILE_FILE',str(profile))
    monkeypatch.setenv('FOX_VERIFICATION_ENABLED','1')
    monkeypatch.setenv('FOX_VERIFIER_RELEASE_SHA256','a'*64)
    transport=ConverterClient('http://127.0.0.1:8091','synthetic-isolation-token')
    state=SimpleNamespace(root=root,target=target,profile=profile,envelope=envelope,requests=[],
                          replies={},intercept=None,mutation=None,configuration_calls=[])
    def request(method,path,payload=None,binary=False):
        match=re.fullmatch('/fox/prototype/jobs/(fox-[a-f0-9]{20})/isolation-witness\\?challenge=([a-f0-9]{64})',path)
        assert method=='GET' and match and payload is None and binary is False
        job_id,challenge=match.groups();state.requests.append((job_id,challenge))
        if state.intercept is not None:
            state.intercept()
        value=deepcopy(state.replies[job_id]);value['challenge']=challenge
        if state.mutation is not None:value=state.mutation(value)
        return value
    transport.request=request
    def configuration(approved_target_sha256,*,installation_projection=None):
        assert approved_target_sha256==envelope['target_profile_sha256']
        state.configuration_calls.append(approved_target_sha256)
        return {'gateway':transport,'target_profile_loader':lambda:deepcopy(state.target)}
    monkeypatch.setattr('fox.prototype_job._configuration',configuration)
    with TestClient(create_app(root,enable_worker=False),base_url=ORIGIN) as client:
        login(client);state.client=client
        yield state


def approved_body(case,project):
    upload(case.client,project,documents())
    response=case.client.get(f'/api/projects/{project}/prototype-assessment')
    assert response.status_code==200,response.text
    value=response.json()
    return {**{key:value[key] for key in ('source_hash','source_binding','target_profile_sha256')},
        'expected_current_source_set_id':value['selected_source_set_id'],
        'approved_chunk_hashes':{row['id']:row['sha256'] for row in value['chunks']},
        'approved_redacted_source':True,'approved_external_ai':True,'approved_prototype_scope':True}


def rows(case):
    with sqlite3.connect(case.root/'fox.sqlite3') as connection:
        connection.row_factory=sqlite3.Row
        return {row['id']:dict(row) for row in connection.execute('SELECT * FROM runs')}


def seed_stopped(case,boundary='runtime_not_dispatched'):
    old_project=new_project(case.client);body=approved_body(case,old_project)
    response=case.client.post(f'/api/projects/{old_project}/prototype-runs',json=body)
    assert response.status_code==202,response.text
    job_id=response.json()['id'];job=case.root/'jobs'/job_id
    snapshot=json.loads((job/'source-snapshot.json').read_bytes())
    state='GENERATED' if boundary=='export_complete' else 'ATTENTION'
    with sqlite3.connect(case.root/'fox.sqlite3') as connection:
        connection.execute('UPDATE runs SET state=?,message=?,updated=updated+1 WHERE id=?',
                           (state,'Authored stopped-protocol fixture',job_id))
    pipeline=job/'prototype-pipeline';pipeline.mkdir()
    request_sha='d'*64
    if boundary!='receiver_absent':
        # Source-linked request metadata only; the bytes below are deliberately
        # not an executable APEX archive and are never sent to a real converter.
        candidate=b'Authored request-binding fixture, not an APEX package.'
        binding={'project_id':old_project,'source_binding':snapshot['prototype']['source_binding']}
        manifest={'evidence_scope':'authored API metadata only'}
        review_index={'evidence_scope':'authored API metadata only'}
        native={'plan_sha256':'a'*64,'rendering_spec':{'profile_id':'synthetic-metadata-only'}}
        rendered={'zip_sha256':hashlib.sha256(candidate).hexdigest()}
        for name,value in (('binding',binding),('sources-manifest',manifest),('review-index',review_index),
                           ('native-plan',native),('rendered',rendered)):
            (pipeline/(name+'.json')).write_text(json.dumps(value),encoding='utf-8')
        (pipeline/'candidate-apexlang.zip').write_bytes(candidate)
        base={'schema_version':1,'scope':'fox-prototype-converter-request-v1',
              'job_id':job_id,'project_id':old_project,'source_binding':binding['source_binding'],
              'plan_sha256':native['plan_sha256'],'rendering_spec':native['rendering_spec'],
              'rendered_zip_sha256':rendered['zip_sha256'],'prior_receipts':{},
              'source_authority':{'schema_version':1,'scope':'fox-prototype-source-authority-v1',
                  'binding_sha256':canonical_hash(binding),'sources_manifest_sha256':canonical_hash(manifest),
                  'review_index_sha256':canonical_hash(review_index)}}
        stages=('validate','prepare_schema','import')
        if boundary=='export_complete':stages+=('verify_runtime','export')
        receipts={}
        for stage in stages:
            current={**base,'prior_receipts':dict(receipts)}
            request_sha=canonical_hash(current)
            (pipeline/(stage+'-intent.json')).write_text(json.dumps({'request_sha256':request_sha}),encoding='utf-8')
            # Actual production envelope builder; stage outcomes remain authored.
            # In particular, real receipts do NOT repeat job_id/project_id.
            from forms2apex.prototype_gateway import PrototypeGateway
            outcome={'validate':{'passed':True},'prepare_schema':{'ready_for_import':True},
                     'import':{'imported':True,'application_id':123},
                     'verify_runtime':{'passed':True,'authenticated':True,'business_pages_tested':True},
                     'export':{'exported':True,'package_sha256':'b'*64}}[stage]
            value=PrototypeGateway._receipt(stage,current,'COMPLETE',**outcome)
            assert 'job_id' not in value and 'project_id' not in value
            (pipeline/(stage+'.json')).write_text(json.dumps(value),encoding='utf-8')
            receipts[stage]=value
        stage='export' if boundary=='export_complete' else 'verify_runtime'
        if boundary!='export_complete':request_sha=canonical_hash({**base,'prior_receipts':receipts})
        (pipeline/(stage+'-intent.json')).write_text(json.dumps({'request_sha256':request_sha}),encoding='utf-8')
    absent=boundary=='receiver_absent'
    case.replies[job_id]={'schema_version':1,'scope':'fox-prototype-isolation-witness-v1','job_id':job_id,
        'challenge':None,'boundary':boundary,'project_id':None if absent else old_project,
        'source_binding':None if absent else snapshot['prototype']['source_binding'],
        'request_sha256':None if absent else request_sha,
        'execution_target_sha256':None if absent else canonical_hash(execution_target(case.target)),
        'retained_sha256':'e'*64,'process_scope':'single_converter_process',
        'execution_authorized':False,'retry_authorized':False,'closure_claimed':False,'business_behavior_accepted':False}
    case.old_project,case.old_id,case.old_body=old_project,job_id,body
    case.old_row=rows(case)[job_id];case.old_tree=preclaim_tree(job)
    return job_id


def submit_new(case):
    project=new_project(case.client);body=approved_body(case,project)
    assert body['source_hash']==case.old_body['source_hash']  # Same file in a different project is allowed.
    return project,case.client.post(f'/api/projects/{project}/prototype-runs',json=body)


def unchanged(case):
    assert rows(case)[case.old_id]==case.old_row
    assert preclaim_tree(case.root/'jobs'/case.old_id)==case.old_tree
    with sqlite3.connect(case.root/'fox.sqlite3') as connection:
        assert connection.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0]==0


@pytest.mark.parametrize('boundary',['receiver_absent','runtime_not_dispatched','export_complete'])
def test_fresh_project_queues_without_adopting_or_replaying_stopped_history(case,boundary):
    seed_stopped(case,boundary)
    database=case.root/'fox.sqlite3'
    with sqlite3.connect(database) as connection:
        connection.row_factory=sqlite3.Row;connection.execute('BEGIN IMMEDIATE')
        assert not VerificationRecovery(database,enabled=True).admission_allowed(connection)
    project,response=submit_new(case)
    assert response.status_code==202,response.text
    assert rows(case)[response.json()['id']]['project']==project
    assert len(case.requests)==1 and len(case.requests[0][1])==64
    assert len(rows(case))==2
    unchanged(case)
    with sqlite3.connect(database) as connection:
        connection.row_factory=sqlite3.Row;connection.execute('BEGIN IMMEDIATE')
        legacy=VerificationRecovery(database,enabled=True)._eligibility(connection,case.old_id)
        assert legacy['blocks_admission'] is True and legacy['retry_eligible'] is False


def test_db_write_lock_spans_actual_witness_callback(case):
    seed_stopped(case)
    attempted=[]
    def concurrent_write():
        with sqlite3.connect(case.root/'fox.sqlite3',timeout=0.01) as other:
            with pytest.raises(sqlite3.OperationalError,match='locked'):
                other.execute('UPDATE runs SET state="PROCESSING" WHERE id=?',(case.old_id,))
        attempted.append(True)
    case.intercept=concurrent_write
    _,response=submit_new(case)
    assert response.status_code==202,response.text
    assert attempted==[True];unchanged(case)


@pytest.mark.parametrize('field,value',[
    ('challenge','0'*64),('job_id','fox-'+'0'*20),('project_id','0'*32),('source_binding','0'*64),
    ('request_sha256','0'*64),('execution_target_sha256','0'*64),('retained_sha256','invalid'),
    ('execution_authorized',True),('retry_authorized',True),('closure_claimed',True),
    ('business_behavior_accepted',True),('process_scope','unknown'),('boundary','unknown'),
    ('schema_version',True),('extra','not-allowed')])
def test_wrong_or_promoting_observation_never_queues(case,field,value):
    seed_stopped(case)
    case.mutation=lambda result:{**result,field:value}
    _,response=submit_new(case)
    assert response.status_code==409,response.text
    assert len(rows(case))==1;unchanged(case)


@pytest.mark.parametrize('state',['QUEUED','PROCESSING'])
def test_active_conversion_refuses_without_observation(case,state):
    seed_stopped(case)
    with sqlite3.connect(case.root/'fox.sqlite3') as connection:
        connection.execute('UPDATE runs SET state=? WHERE id=?',(state,case.old_id))
    _,response=submit_new(case)
    assert response.status_code==429 and not case.requests
    assert len(rows(case))==1


def test_same_project_does_not_gain_a_retry(case):
    seed_stopped(case)
    response=case.client.post(f'/api/projects/{case.old_project}/prototype-runs',json=case.old_body)
    assert response.status_code==409 and not case.requests
    assert len(rows(case))==1;unchanged(case)


@pytest.mark.parametrize('failure',[OpafError('busy',429),OpafError('busy',503),OpafError('unknown',409)])
def test_unavailable_or_uncertain_converter_refuses_without_new_run(case,failure):
    seed_stopped(case)
    def fail():raise failure
    case.intercept=fail
    _,response=submit_new(case)
    assert response.status_code==(503 if failure.status_code in (429,503) else 409)
    assert len(rows(case))==1;unchanged(case)


@pytest.mark.parametrize('boundary',['receiver_absent','runtime_not_dispatched'])
def test_unknown_recovery_ledger_cannot_be_skipped(case,boundary):
    seed_stopped(case,boundary)
    with sqlite3.connect(case.root/'fox.sqlite3') as connection:
        connection.execute('CREATE TABLE verification_unknown_fixture(job_id TEXT,payload BLOB)')
        connection.execute('INSERT INTO verification_unknown_fixture VALUES(?,?)',(case.old_id,b'opaque fixture'))
    _,response=submit_new(case)
    assert response.status_code==409 and not case.requests
    assert len(rows(case))==1;unchanged(case)


def test_retained_file_change_during_observation_is_not_accepted(case):
    seed_stopped(case)
    marker=case.root/'jobs'/case.old_id/'prototype-pipeline/import.json'
    case.intercept=lambda:marker.write_text('{}',encoding='utf-8')
    _,response=submit_new(case)
    assert response.status_code==409 and len(rows(case))==1
    assert rows(case)[case.old_id]==case.old_row


def test_target_change_during_observation_refuses(case):
    seed_stopped(case)
    case.intercept=lambda:case.target['tested_versions'].update(apex='synthetic-changed')
    _,response=submit_new(case)
    assert response.status_code==409 and len(rows(case))==1
    unchanged(case)


@pytest.mark.parametrize('change',['delete','unsafe-directory','empty-file'])
def test_final_file_recheck_errors_are_actionable_and_roll_back_new_row(case,monkeypatch,change):
    from fox.prototype_fresh_admission import FreshAdmissionRead
    seed_stopped(case)
    original=FreshAdmissionRead._recheck
    marker=case.root/'jobs'/case.old_id/'prototype-pipeline/import.json'
    def after_insert(self,*,new_run_id=None):
        if new_run_id is not None:
            marker.unlink()
            if change=='unsafe-directory':marker.mkdir()
            if change=='empty-file':marker.write_bytes(b'')
        return original(self,new_run_id=new_run_id)
    monkeypatch.setattr(FreshAdmissionRead,'_recheck',after_insert)
    _,response=submit_new(case)
    assert response.status_code==409 and 'operator check' in response.json()['detail']
    assert len(rows(case))==1 and rows(case)[case.old_id]==case.old_row


def test_complete_headers_do_not_hide_changed_web_receipt_contents(case):
    seed_stopped(case)
    marker=case.root/'jobs'/case.old_id/'prototype-pipeline/import.json'
    value=json.loads(marker.read_bytes());value['application_id']=987
    marker.write_text(json.dumps(value),encoding='utf-8')
    _,response=submit_new(case)
    assert response.status_code==409 and len(rows(case))==1
