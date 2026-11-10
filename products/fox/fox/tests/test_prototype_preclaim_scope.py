"""Real local epoch-six proof reuse; model replies are authored, not live proof."""
from collections import Counter
from contextlib import contextmanager
from copy import deepcopy
import json
import sqlite3
from time import perf_counter

import pytest

from fox import prototype_mapping_epochs as epochs, prototype_read_scope as scope
from fox import prototype_dsc_identity_repair as dsc, prototype_container_epoch as container
from fox import prototype_authority as authority
from fox.opaf import OpafError, canonical_hash
from test_prototype_candidate_continuation import (
    format_case, historical_format_policy, dsc_case, historical_dsc_source,
    correction_case, screen_case, partition_case, container_case, container_source_model,
    clause_case, epochs_case, tmp_path, client, settings, no_external_actions,
    next_body, api, files, process,
)


@pytest.fixture
def reviewed_epoch(format_case,monkeypatch):
    case=format_case
    _,body=next_body(case)
    response=case[0].post(api(case,'candidate-format-continuation'),json=body)
    assert response.status_code==202,response.text
    # Finish the actual retained review/render path, stopping BEFORE any
    # converter GET/POST. All saved epoch/DSC/candidate proofs remain real.
    monkeypatch.setattr(case[8],'supported',())
    from fox import prototype_result_publication as publication
    observed=[]
    summary=(case[4]/'prototype-result.json').read_bytes()
    # This is a prepared-phase test, not terminal-result publication. The
    # publisher accepts rejection or full export, not a blocked adapter.
    monkeypatch.setattr(publication,'controlled_save_result',lambda job,result,record:observed.append(deepcopy(result)))
    row,errors=process(case,monkeypatch)
    assert row['state']=='ATTENTION',errors
    job=case[4];root=job/'prototype-pipeline'
    assert len(observed)==1 and observed[0]['status']=='BLOCKED_ADAPTER',errors
    assert (job/'prototype-result.json').read_bytes()==summary
    assert (job/'mapping-epochs/epoch-000006.json').is_file()
    assert (root/'candidate-format-continuation.json').is_file()
    native=epochs.read(root/'native-plan.json');rendered=epochs.read(root/'rendered.json')
    request={'schema_version':1,'scope':'fox-prototype-converter-request-v1','job_id':job.name,
        'project_id':case[5]['project_id'],'source_binding':case[5]['prototype']['source_binding'],
        'plan_sha256':native['plan_sha256'],'rendering_spec':native['rendering_spec'],
        'rendered_zip_sha256':rendered['zip_sha256'],'prior_receipts':{},'source_authority':{
            'schema_version':1,'scope':'fox-prototype-source-authority-v1',
            'binding_sha256':canonical_hash(epochs.read(root/'binding.json')),
            'sources_manifest_sha256':canonical_hash(epochs.read(root/'sources-manifest.json')),
            'review_index_sha256':canonical_hash(epochs.read(root/'review-index.json'))}}
    assert not case[8].calls and not (root/'validate-intent.json').exists()
    return case,request,(job/'source-snapshot.json').read_bytes()


def _compare_real_recursive_work(reviewed_epoch,monkeypatch,record_property):
    case,request,original=reviewed_epoch;job=case[4];snapshot=case[5]
    counts=Counter()
    for module,name in ((dsc,'_derive'),(container,'_proof'),(epochs,'_dispatch_active_focus')):
        real=getattr(module,name)
        def counted(*args,_real=real,_name=name,**kwargs):
            counts[_name]+=1
            return _real(*args,**kwargs)
        monkeypatch.setattr(module,name,counted)
    before=files(job);model_calls=deepcopy(case[7].calls)
    print('START_UNSCOPED_CONVERTER_PHASE',flush=True)
    start=perf_counter();unscoped=epochs._converter_phase(job,snapshot,original,'validate',request)
    unscoped_seconds=perf_counter()-start;unscoped_counts=dict(counts);counts.clear()
    print('START_SCOPED_CONVERTER_PHASE',flush=True)
    start=perf_counter();scoped=epochs.converter_phase(job,snapshot,original,'validate',request)
    scoped_seconds=perf_counter()-start;scoped_counts=dict(counts)
    print({'unscoped_calls':unscoped_counts,'scoped_calls':scoped_counts,
        'unscoped_seconds':unscoped_seconds,'scoped_seconds':scoped_seconds},flush=True)
    assert scoped==unscoped and scoped.stage=='validate'
    assert scoped.request_sha256==canonical_hash(request)
    assert unscoped_counts['_derive']>scoped_counts['_derive']==1
    assert all(scoped_counts.get(name,0)<=count for name,count in unscoped_counts.items())
    assert files(job)==before and case[7].calls==model_calls and not case[8].calls
    assert scope.current_read_root() is None
    record_property('real_recursive_calls_unscoped',json.dumps(unscoped_counts,sort_keys=True))
    record_property('real_recursive_calls_scoped',json.dumps(scoped_counts,sort_keys=True))
    record_property('unscoped_seconds',unscoped_seconds);record_property('scoped_seconds',scoped_seconds)


def _check_source_tamper(reviewed_epoch,monkeypatch):
    case,request,original=reviewed_epoch;job=case[4]
    source=job/'prototype-pipeline/sources/source-000.xml';raw=source.read_bytes()
    real=epochs._model_fence
    def changed_after_reconstruction(*args,**kwargs):
        result=real(*args,**kwargs);source.write_bytes(raw+b'\n');return result
    monkeypatch.setattr(epochs,'_model_fence',changed_after_reconstruction)
    try:
        with pytest.raises(OpafError):epochs.converter_phase(job,case[5],original,'validate',request)
    finally:source.write_bytes(raw)
    assert scope.current_read_root() is None and not case[8].calls


def _check_current_authority(reviewed_epoch,profile_root):
    case,request,original=reviewed_epoch;_,root,_,_,job,snapshot,_,model,converter,db,envelope=case
    profile=profile_root/'scope-target.json';profile.write_text(json.dumps(envelope));profile.chmod(0o600)
    with db() as connection:connection.execute("UPDATE runs SET state='PROCESSING' WHERE id=?",(job.name,))
    phase=epochs.converter_phase(job,snapshot,original,'validate',request)
    assert phase is not None and scope.current_read_root() is None
    assert authority.authorize_current(root,db,profile,request)['request_sha256']==canonical_hash(request)
    with db() as connection:connection.execute("UPDATE projects SET owner='revoked-owner' WHERE id=?",(snapshot['project_id'],))
    with pytest.raises((ValueError,OpafError)):authority.authorize_current(root,db,profile,request)
    with db() as connection:connection.execute('UPDATE projects SET owner=? WHERE id=?',(snapshot['approvals']['owner'],snapshot['project_id']))
    record=epochs.read(job/'mapping-epochs/epoch-000006.json');object_id=epochs.event_id(job.name,record)
    with db() as connection:connection.execute('DELETE FROM events WHERE action=? AND object_id=?',(epochs.EVENT,object_id))
    with pytest.raises(OpafError):epochs.converter_phase(job,snapshot,original,'validate',request)
    with db() as connection:connection.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
        (record['owner'],epochs.EVENT,object_id,record['approved_at']))
    changed=deepcopy(envelope);changed['target_profile']['apex']['workspace']='CHANGED'
    changed['target_profile_sha256']=canonical_hash(changed['target_profile']);profile.write_text(json.dumps(changed))
    with pytest.raises((ValueError,OpafError)):authority.authorize_current(root,db,profile,request)
    assert not converter.calls and scope.current_read_root() is None


def _authority_db_copy(reviewed_epoch,destination,monkeypatch):
    case,request,_=reviewed_epoch
    # Historical publications bind absolute artifact paths: do not rewrite
    # them to make a moved tree pass. Keep validated proof bytes at that root
    # and clone only the synthetic SQLite authority for revocation checks.
    source=case[1]/'fox.sqlite3';target=destination/'fox.sqlite3'
    assert not target.exists();connect=sqlite3.connect
    original=connect(source.absolute().as_uri()+'?mode=ro',uri=True);copied=connect(target)
    try:original.backup(copied)
    finally:original.close();copied.close()
    original_uri=source.absolute().as_uri()+'?mode=ro'
    def current_db(database,*args,**kwargs):
        if str(database)==original_uri:database=target.absolute().as_uri()+'?mode=ro'
        return connect(database,*args,**kwargs)
    monkeypatch.setattr(sqlite3,'connect',current_db)
    clone=list(case);clone[5]=deepcopy(case[5]);clone[10]=deepcopy(case[10])
    @contextmanager
    def db():
        connection=connect(target);connection.row_factory=sqlite3.Row
        try:
            with connection:yield connection
        finally:connection.close()
    clone[9]=db
    return tuple(clone),deepcopy(request),(clone[4]/'source-snapshot.json').read_bytes()


def test_real_epoch_six_scope_reuse_and_fresh_refusals(reviewed_epoch,monkeypatch,record_property,tmp_path_factory):
    before=files(reviewed_epoch[0][4])
    _compare_real_recursive_work(reviewed_epoch,monkeypatch,record_property)
    with monkeypatch.context() as local:_check_source_tamper(reviewed_epoch,local)
    target=tmp_path_factory.mktemp('n')
    with monkeypatch.context() as local:
        authority_case=_authority_db_copy(reviewed_epoch,target,local)
        _check_current_authority(authority_case,target)
    assert files(reviewed_epoch[0][4])==before
