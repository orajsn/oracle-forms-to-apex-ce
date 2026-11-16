"""Synthetic regression for source-only container retention; no external effects."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace as NS

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from fox import prototype_direct_container as container
from fox import prototype_job, source_history, worker
from fox.design_provider import roles
from fox.forms_understanding_packet import local_packet
from fox.opaf import OpafError, canonical_hash
from fox.prototype_pipeline import run_prototype_pipeline, authorize_prototype_request
from fox.prototype_project_routes import PrototypeContinuationInput
from fox.prototype_transport import build_authority_bundle
from test_oci_genai import direct_setup, target, InjectedService, fake_sdk
from test_prototype_job import queued, saved_row


def omit_container(service, docs):
    packet = local_packet(docs)
    modules = {r['id'] for e in packet['sources'] for r in e['facts']['objects'] if r['kind'] == 'FormModule'}
    def alter(body):
        part = body['chat_response']['choices'][0]['message']['content'][0]
        output = json.loads(part['text'])
        if 'blueprint' in output:
            for row in output['blueprint']['objects']:
                if row['source_object_id'] in modules:
                    row['disposition'] = 'omitted'
                    row['reason'] = 'Source container metadata; no owned Blocks in this partition.'
            part['text'] = json.dumps(output)
    service.alter = alter


def test_fresh_direct_projects_source_container_before_initial_review(direct_setup):
    job, docs, client, service, current, approvals, kwargs = direct_setup
    omit_container(service, docs)
    result = run_prototype_pipeline(job, docs, **kwargs)
    assert result['facts']['native_source_rendered'] is True
    projections = list((job/'prototype-pipeline').glob('focus-*/projection-receipt.json'))
    assert projections
    for path in projections:
        receipt = json.loads(path.read_text())
        assert receipt['scope'] == container.POLICY
        original = json.loads((path.parent/'mapper.json').read_text())['output']
        derived = json.loads((path.parent/'projection-candidate.json').read_text())
        assert any(r['disposition'] == 'omitted' for r in original['blueprint']['objects'])
        assert all(r['disposition'] == 'unresolved' for r in derived['blueprint']['objects'])
        reviewer = json.loads((path.parent/'reviewer-request.json').read_text())
        assert reviewer['candidate_sha256'] == canonical_hash(derived)
    count = len(service.calls)
    run_prototype_pipeline(job, docs, **kwargs)
    assert len(service.calls) == count


@pytest.fixture
def retained(queued, monkeypatch):
    root, job, db, snapshot, old_client, converter, old_config = queued
    from fox.oci_genai import OciGenAiClient
    # One module gives one precisely bounded structural correction.
    current, service = target(), InjectedService()
    docs = prototype_job.validate_prototype_snapshot(snapshot)
    # The queued fixture contains two modules. Select a synthetic single-module
    # fixture by leaving only the first module's source version before admission.
    docs = docs[:1]
    from fox.intake import checked_source
    from fox.prototype_admission import prepare_prototype_admission
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        source_history.publish_source_branch(c, snapshot['project_id'], [checked_source(n,b) for n,b in docs], 5.0, snapshot['approvals']['owner'])
        snapshot['files'] = source_history.selected_sources(c, snapshot['project_id'])
        snapshot['source_hash'] = source_history._hash(snapshot['files'])
        snapshot['selected_source_set_id'] = source_history.selected_source_set_id(c, snapshot['project_id'])
        c.execute('UPDATE runs SET source_hash=? WHERE id=?',(snapshot['source_hash'],job.name))
        c.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
            (snapshot['approvals']['owner'],'approved_prototype_conversion',job.name,snapshot['approvals']['approved_at']))
    snapshot['prototype'] = prepare_prototype_admission(docs,
        expected_source_binding=local_packet(docs)['source_binding'],approved_chunk_hashes={},
        target_profile_sha256=canonical_hash(current),approved_redacted_source=True,
        approved_external_ai=True,approved_prototype_scope=True)['prototype']
    (job/'source-snapshot.json').write_text(json.dumps(snapshot))
    omit_container(service,docs)
    client = OciGenAiClient(current,client=service,sdk=fake_sdk())
    def config(approved,**kwargs):
        assert approved == canonical_hash(current)
        return {'profile':roles(current),'opaf_client':client,'target_profile_loader':lambda:deepcopy(current),
                'converter_adapter':converter}
    monkeypatch.setattr(prototype_job,'_configuration',config)
    monkeypatch.setenv('FOX_RUN_ADAPTER','oci-genai')
    with monkeypatch.context() as legacy:
        legacy.setattr(container,'initial',lambda packet,request,candidate,directory,**kw:(candidate,None))
        worker.process_one(db,root)
    assert saved_row(db,job)['state'] == 'ATTENTION'
    assert not converter.calls
    before = {p.relative_to(job).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
              for p in job.rglob('*') if p.is_file()}
    app = FastAPI()
    def owner(request,pid):
        value = request.headers.get('x-test-owner')
        if value is None: raise HTTPException(401)
        with db() as c: row = c.execute('SELECT * FROM projects WHERE id=? AND owner=?',(pid,value)).fetchone()
        if row is None: raise HTTPException(404)
        return dict(row)
    container.attach_routes(app,root=root,db=db,project_owner=owner,
        current_sources=lambda pid,c:source_history.selected_sources(c,pid),admission_allowed=lambda c:True,
        target_reader=lambda:{'target_profile':current,'target_profile_sha256':canonical_hash(current)},
        input_model=PrototypeContinuationInput)
    http = TestClient(app,headers={'x-test-owner':snapshot['approvals']['owner']})
    path = f"/api/projects/{snapshot['project_id']}/prototype-runs/{job.name}/container-correction"
    return NS(root=root,job=job,db=db,snapshot=snapshot,service=service,converter=converter,before=before,
        http=http,path=path,current=current,client=client)


def correction_body(projection):
    return {key:projection[key] for key in ('checkpoint_sha256','source_hash','source_binding',
        'target_profile_sha256','approved_chunk_hashes')} | {
        'expected_current_source_set_id':projection['selected_source_set_id'],
        'approved_redacted_source':True,'approved_external_ai':True,'approved_prototype_scope':True}


def test_retained_owner_route_preserves_originals_and_runs_one_new_review(retained):
    r = retained
    old_count = len(r.service.calls)
    preview = r.http.get(r.path)
    assert preview.status_code == 200,preview.text
    value = preview.json()
    assert value['eligible'] and value['retained_model_calls'] == old_count
    assert value['container_corrections'] == value['new_reviewer_calls'] == 1
    assert len(r.service.calls) == old_count
    body = correction_body(value)
    assert r.http.post(r.path,json=body).status_code == 202
    repeated = r.http.post(r.path,json=body)
    assert repeated.status_code == 200
    worker.process_one(r.db,r.root)
    assert saved_row(r.db,r.job)['state'] == 'GENERATED'
    assert len(r.service.calls) == old_count+1
    assert r.converter.calls
    for name,digest in r.before.items():
        assert hashlib.sha256((r.job/name).read_bytes()).hexdigest() == digest
    assert r.http.post(r.path,json=body).status_code == 200
    assert len(r.service.calls) == old_count+1
    request = r.converter.requests[0]
    assert authorize_prototype_request(r.job,request) == request
    bundle = build_authority_bundle(r.job,request)
    assert any(row['path'] == container.TECHNICAL for row in bundle['files'])
    from forms2apex.prototype_gateway import _authority_descriptor
    assert _authority_descriptor(bundle,encoded=True)['job_id'] == r.job.name
    from forms2apex.prototype_gateway import PrototypeGateway
    jobs = r.root / 'received'
    jobs.mkdir()
    receiver = PrototypeGateway(NS(jobs_root=jobs))
    assert receiver.recover_source_authority(r.job.name) is None
    receipt = receiver.stage_source_authority(r.job.name,bundle)
    assert receipt['source_review_authorized'] is False
    staged = jobs / r.job.name
    assert authorize_prototype_request(staged,request,staged_projection=True) is request
    staged_before = {p.relative_to(staged).as_posix():p.read_bytes() for p in staged.rglob('*') if p.is_file()}
    assert receiver.recover_source_authority(r.job.name) == receipt
    assert receiver.stage_source_authority(r.job.name,bundle) == receipt
    assert staged_before == {p.relative_to(staged).as_posix():p.read_bytes() for p in staged.rglob('*') if p.is_file()}


@pytest.mark.parametrize('field', ['approved_external_ai','checkpoint_sha256','source_hash','target_profile_sha256'])
def test_correction_rejects_stale_binding_or_withheld_consent(retained,field):
    r=retained
    value=r.http.get(r.path).json()
    body=correction_body(value)
    body[field]=False if field=='approved_external_ai' else '0'*64
    count=len(r.service.calls)
    assert r.http.post(r.path,json=body).status_code==409
    assert len(r.service.calls)==count
    assert saved_row(r.db,r.job)['state']=='ATTENTION'
    assert not (r.job/container.OWNER_RECORD).exists()


def test_uncertain_new_review_cannot_replay_or_requeue(retained):
    r=retained
    body=correction_body(r.http.get(r.path).json())
    assert r.http.post(r.path,json=body).status_code==202
    count=len(r.service.calls)
    r.service.failure=TimeoutError('PRIVATE')
    worker.process_one(r.db,r.root)
    assert saved_row(r.db,r.job)['state']=='ATTENTION'
    assert len(r.service.calls)==count+1
    assert not r.converter.calls
    r.service.failure=None
    response=r.http.post(r.path,json=body)
    assert response.status_code==200 and response.json()['state']=='ATTENTION'
    worker.process_one(r.db,r.root)
    assert len(r.service.calls)==count+1


def test_correction_owner_and_durable_event_are_mandatory(retained):
    r=retained
    assert r.http.get(r.path,headers={'x-test-owner':'another-owner'}).status_code==404
    body=correction_body(r.http.get(r.path).json())
    assert r.http.post(r.path,json=body).status_code==202
    with r.db() as c: c.execute('DELETE FROM events WHERE action=?',(container.EVENT,))
    count=len(r.service.calls)
    worker.process_one(r.db,r.root)
    assert saved_row(r.db,r.job)['state']=='ATTENTION'
    assert len(r.service.calls)==count
