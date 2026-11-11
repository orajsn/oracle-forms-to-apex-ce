"""Production-shaped synthetic claimed history; no live/model/Oracle proof."""
from copy import deepcopy
import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest

from fox import verification_recovery as r
from fox import prototype_preclaim_continuation as continuation
from fox.opaf import canonical_hash as h
from forms2apex import native_blueprint
from test_preclaim_maintenance_pair import (pair_case, original_format_case, historical_format_policy,
    dsc_case, historical_dsc_source, correction_case, screen_case, partition_case, container_case,
    container_source_model, clause_case, epochs_case, client, settings, no_external_actions,
    save, tmp_path)


@pytest.fixture
def format_case(dsc_case, monkeypatch):
    return original_format_case.__wrapped__(dsc_case, monkeypatch)


@pytest.fixture
def claimed_case(pair_case):
    case, receiver, packet, expected, _ = pair_case
    job = case[4]; request = r.preclaim_request(job)
    from forms2apex.prototype_gateway import PrototypeGateway
    from types import SimpleNamespace
    gateway = PrototypeGateway(SimpleNamespace(jobs_root=receiver.parent),
        target_profile_loader=lambda _: deepcopy(case[10]['target_profile']))
    witness = gateway.validate_preclaim_witness(request)
    before = {name:pin['sha256'] for name,pin in r.preclaim_tree(job)['files'].items()}
    record = {'schema_version':1,'scope':continuation.SCOPE,'job_id':job.name,
        'project_id':case[2],'snapshot_sha256':before['source-snapshot.json'],
        'source_hash':case[5]['source_hash'],'source_binding':request['source_binding'],
        'target_profile_sha256':case[5]['prototype']['target_profile_sha256'],
        'owner':case[5]['approvals']['owner'],'approved_at':datetime.now(timezone.utc).timestamp(),
        'approvals':{'redacted_source':True,'external_ai':True,'synthetic_prototype':True},
        'before_files':before,'request':request,'witness':witness,
        'checkpoint_sha256':continuation.checkpoint(before,request,witness)}
    save(job/'prototype-pipeline'/continuation.RECORD,record)
    save(job/'prototype-pipeline'/continuation.ATTEMPT,{'record_sha256':h(record),
        'request_sha256':h(request),'witness_sha256':witness['witness_sha256']})
    with case[9]() as db:
        db.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
            (record['owner'],continuation.EVENT,continuation.event_id(job.name,record),record['approved_at']))
        db.commit()
    # The actual private snapshot writer and deterministic renderer, not a stub.
    gateway._snapshot(receiver/'prototype-converter',request,request['rendering_spec'],
        native_blueprint.deterministic_prototype_zip(request['rendering_spec']),create=True)
    save(receiver/'prototype-converter/validate-request.json',request)
    save(receiver/'prototype-converter/validate-intent.json',{'request_sha256':h(request)})
    packet=deepcopy(packet)
    packet['scope']=r.CLAIMED_VALIDATION_MAINTENANCE_SCOPE
    packet['fox_tree']=r.preclaim_tree(job);packet['receiver_tree']=r.preclaim_tree(receiver)
    packet['receiver_claims']={name:base64.b64encode((receiver/'prototype-converter'/name).read_bytes()).decode()
        for name in ('snapshot.json','validate-request.json','validate-intent.json')}
    # Fresh real technical reconstruction over the synthetic claimed web tree.
    # DB-only event is in the private fixture memory copy, so use its exact backup.
    with case[9]() as db:
        claimed_database=case[1]/'claimed.sqlite3';assert not claimed_database.exists()
        with claimed_database.open('xb') as target:target.write(db.serialize())
    packet['technical']=r.preclaim_technical_read(claimed_database,job.name,case[10]['target_profile'],'e'*64)
    packet['technical']['receiver_manifest_raw_sha256']=r.digest((receiver/'prototype-converter/authority-manifest.json').read_bytes())
    packet['serialization_barrier']['binding'].update(fox_tree_sha256=h(packet['fox_tree']),receiver_tree_sha256=h(packet['receiver_tree']))
    packet['serialization_barrier']['result']={'method':'READ_ONLY_PAIRED_TREE','stage':'claimed_validate',
        'job_id':job.name,'maintenance_only':True,'source_review_authorized':False}
    packet['gateway_witness']=r.claimed_validation_observation(packet,packet['technical'])
    now=datetime.now(timezone.utc)
    packet.update(observed_at_utc=now.isoformat(),expires_at_utc=(now+timedelta(seconds=30)).isoformat())
    packet['serialization_barrier']['observed_at_utc']=now.isoformat()
    return case,receiver,packet,expected,now


def test_claimed_history_preservation_and_closed_rejection_matrix(claimed_case):
    case,receiver,packet,expected,now=claimed_case
    before=r.preclaim_tree(case[4]),r.preclaim_tree(receiver)
    with case[9]() as db:
        db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
        store=r.VerificationRecovery(case[1]/'fox.sqlite3',enabled=True)
        run=dict(db.execute('SELECT * FROM runs WHERE id=?',(case[3],)).fetchone())
        value=store._protected_read_status(db,case[3],purpose='maintenance_preclaim_preservation',
            paired_readback=packet,expected_pair=expected,now=now)
        assert value['preservation_allowed'] is True
        assert value['admission']['blocks_admission'] is True and value['admission']['retry_eligible'] is False
        for mode in ('transition','startup'):
            p=deepcopy(packet);e=deepcopy(expected);p['binding']=e;e['mode']=mode
            assert r.validate_preclaim_pair(case[1]/'fox.sqlite3',db,run,p,e,now=now)
        for fault in ('missing','extra','zip','request','intent','snapshot','raw','expiry','lease','producer',
                      'target','old-scope','get-barrier','execution-witness','boolean-producer','later-log','later-receipt'):
            p=deepcopy(packet);e=deepcopy(expected);p['binding']=e
            files=p['receiver_tree']['files']
            if fault=='missing':files.pop('prototype-converter/snapshot.json')
            elif fault in ('extra','later-log','later-receipt'):
                name={'extra':'unknown.json','later-log':'validation.log','later-receipt':'validate.json'}[fault]
                files['prototype-converter/'+name]={'sha256':'1'*64,'bytes':1}
            elif fault=='zip':files['prototype-converter/candidate-apexlang.zip']['sha256']='0'*64
            elif fault in ('request','intent','snapshot'):
                name={'request':'validate-request.json','intent':'validate-intent.json','snapshot':'snapshot.json'}[fault]
                raw=b'{"changed":true}';p['receiver_claims'][name]=base64.b64encode(raw).decode()
                files['prototype-converter/'+name]={'sha256':r.digest(raw),'bytes':len(raw)}
            elif fault=='raw':p['receiver_claims']['snapshot.json']='!!!!'
            elif fault=='expiry':p['expires_at_utc']=(now-timedelta(seconds=1)).isoformat()
            elif fault=='lease':e['lease_sha256']=None
            elif fault=='producer':p['producer']['receiver_operations']=1
            elif fault=='boolean-producer':p['producer']['receiver_servers']=True
            elif fault=='target':e['target_profile_sha256']='0'*64
            elif fault=='old-scope':p['scope']=r.PRECLAIM_MAINTENANCE_SCOPE
            elif fault=='get-barrier':p['serialization_barrier']['result']={'method':'GET','stage':'validate','job_id':case[3],'status':404}
            else:p['gateway_witness']['source_review_authorized']=True
            with pytest.raises((r.RecoveryError,ValueError)):
                r.validate_preclaim_pair(case[1]/'fox.sqlite3',db,run,p,e,now=now)
    with case[9]() as db:
        db.execute('PRAGMA query_only=OFF')
        for statement,parameters in (
            ('UPDATE projects SET owner=? WHERE id=?',('changed-owner',case[2])),
            ('UPDATE sources SET text=text||?',('changed',)),
            ('DELETE FROM events WHERE action=?',(continuation.EVENT,))):
            db.execute('SAVEPOINT rejected_change')
            try:
                db.execute(statement,parameters)
                with pytest.raises((r.RecoveryError,ValueError)):
                    r.validate_preclaim_pair(case[1]/'fox.sqlite3',db,run,packet,expected,now=now)
            finally:
                db.execute('ROLLBACK TO rejected_change');db.execute('RELEASE rejected_change')
        # Exercise reader rejection of a VALID different selection, not rejection
        # by the source-selection trigger of a nonexistent source-set identity.
        from fox import intake, source_history
        db.execute('SAVEPOINT rejected_selection')
        try:
            alternate={'id':'claimed-negative-alternate','project':case[2],'created':now.timestamp(),
                **intake.checked_source('alternate.xml',b'<Module Name="ALTERNATE"/>')}
            columns=('id','project','name','sha256','bytes','text','created')
            db.execute('INSERT INTO sources(id,project,name,sha256,bytes,text,created) VALUES(?,?,?,?,?,?,?)',
                tuple(alternate[key] for key in columns))
            alternate_set,reused=source_history._new_set(db,case[2],[alternate],now.timestamp(),'upload')
            assert not reused and alternate_set!=case[5]['selected_source_set_id']
            db.execute('UPDATE project_source_selection SET current_source_set_id=? WHERE project=?',
                (alternate_set,case[2]))
            assert source_history.selected_source_set_id(db,case[2])==alternate_set
            with pytest.raises(r.RecoveryError,match='PRECLAIM_OWNER_SOURCE_OR_CONSENT_CHANGED'):
                r.validate_preclaim_pair(case[1]/'fox.sqlite3',db,run,packet,expected,now=now)
        finally:
            db.execute('ROLLBACK TO rejected_selection');db.execute('RELEASE rejected_selection')
    for name in (continuation.RECORD,continuation.ATTEMPT):
        path=case[4]/'prototype-pipeline'/name;original=path.read_bytes()
        try:
            changed=json.loads(original);changed[next(iter(changed))]='changed'
            path.write_text(json.dumps(changed))
            with case[9]() as db:
                with pytest.raises((r.RecoveryError,ValueError)):
                    r.validate_preclaim_pair(case[1]/'fox.sqlite3',db,run,packet,expected,now=now)
        finally:path.write_bytes(original)
    assert before==(r.preclaim_tree(case[4]),r.preclaim_tree(receiver))
