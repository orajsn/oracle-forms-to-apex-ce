"""LOCAL synthetic preservation evidence, never SQLcl/Oracle or live-flow proof."""
from copy import deepcopy
import base64
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import sys
import zipfile

import pytest

from fox import verification_recovery as r
from fox.opaf import canonical_hash as h
from forms2apex.prototype_gateway import PrototypeGateway
from forms2apex.provenance import tree_digest
from test_claimed_validation_maintenance import (claimed_case, format_case, pair_case,
    original_format_case, historical_format_policy, dsc_case, historical_dsc_source,
    correction_case, screen_case, partition_case, container_case, container_source_model,
    clause_case, epochs_case, client, settings, no_external_actions, save, tmp_path)


@pytest.fixture
def schema_case(claimed_case, tmp_path):
    case, receiver, packet, expected, _ = claimed_case
    job = case[4]; root = receiver/'prototype-converter'
    original = r.preclaim_request(job)
    operation = '8'*64
    log_name = 'validation-recovery-' + operation[:20] + '.log'
    log = 'Synthetic retained validator output\nValidation successful\n'
    (root/log_name).write_bytes(log.encode('utf-8'))
    extracted = tmp_path/'draft'; extracted.mkdir()
    with zipfile.ZipFile(io.BytesIO((root/'candidate-apexlang.zip').read_bytes())) as archive:
        archive.extractall(extracted)
    receipt = PrototypeGateway._receipt('validate',original,'COMPLETE',passed=True,
        validation={'passed':True,'return_code':0,'summary':log,
            'log':'/opt/forms2apex/outputs/jobs/'+job.name+'/prototype-converter/'+log_name},
        draft_sha256=tree_digest(extracted), artifact_binding=r.claimed_validation_snapshot(original))
    save(root/'validate.json',receipt)
    save(job/'prototype-pipeline/validate.json',receipt)
    request = {**original,'prior_receipts':{'validate':receipt}}
    save(job/'prototype-pipeline/prepare_schema-intent.json',{'request_sha256':h(request)})
    save(root/'prepare_schema-request.json',request)
    save(root/'prepare_schema-intent.json',{'request_sha256':h(request)})
    now = datetime.now(timezone.utc)
    owner=case[5]['approvals']['owner']
    save(root/('validate-recovery-attempt-'+operation[:20]+'.json'),{
        'scope':'one-retained-validation-maintenance-attempt-v1','plan_sha256':operation,
        'request_sha256':h(original),'operator':owner,'started_at':now.timestamp()+1})
    with case[9]() as db:
        db.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
            (owner,'operator-retained-validation-claim-v1',job.name+':'+operation,now.timestamp()))
        db.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
            (owner,'operator-retained-validation-handoff-v1',job.name+':'+operation+':'+h(receipt),now.timestamp()+2))
        db.execute('UPDATE runs SET updated=? WHERE id=?',(now.timestamp()+3,job.name))
        db.commit()
        database=case[1]/'schema.sqlite3'
        with database.open('xb') as target: target.write(db.serialize())
    packet=deepcopy(packet);expected=deepcopy(expected)
    expected['request_sha256']=h(request);packet['binding']=expected
    packet['scope']=r.SCHEMA_PREWRITE_MAINTENANCE_SCOPE
    packet['fox_tree']=r.preclaim_tree(job);packet['receiver_tree']=r.preclaim_tree(receiver)
    packet['receiver_schema_prewrite']={path.name:base64.b64encode(path.read_bytes()).decode()
        for path in root.iterdir() if path.name in {'validate.json','prepare_schema-request.json','prepare_schema-intent.json',log_name}
        or path.name.startswith('validate-recovery-attempt-')}
    packet['technical']=r.preclaim_technical_read(database,job.name,case[10]['target_profile'],'e'*64,stage='prepare_schema')
    packet['technical']['receiver_manifest_raw_sha256']=r.digest((root/'authority-manifest.json').read_bytes())
    packet['serialization_barrier']['binding'].update(fox_tree_sha256=h(packet['fox_tree']),receiver_tree_sha256=h(packet['receiver_tree']))
    packet['serialization_barrier']['result']={'method':'READ_ONLY_PAIRED_TREE','stage':'schema_prewrite',
        'job_id':job.name,'maintenance_only':True,'source_review_authorized':False}
    packet['gateway_witness']=r.schema_prewrite_observation(packet,packet['technical'])
    packet.update(observed_at_utc=now.isoformat(),expires_at_utc=(now+timedelta(seconds=30)).isoformat())
    packet['serialization_barrier']['observed_at_utc']=now.isoformat()
    return case,receiver,packet,expected,now,database


def check(case,packet,expected,now,db):
    run=dict(db.execute('SELECT * FROM runs WHERE id=?',(case[3],)).fetchone())
    return r.validate_preclaim_pair(case[1]/'fox.sqlite3',db,run,packet,expected,now=now,stage='prepare_schema')


def test_terminal_schema_prewrite_preserves_only_and_rejects_changes(schema_case):
    case,receiver,packet,expected,now,database=schema_case
    before=(r.preclaim_tree(case[4]),r.preclaim_tree(receiver),database.read_bytes())
    with case[9]() as db:
        db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
        changes=db.total_changes
        store=r.VerificationRecovery(case[1]/'fox.sqlite3',enabled=True)
        value=store._protected_read_status(db,case[3],purpose='maintenance_schema_prewrite_preservation',
            paired_readback=packet,expected_pair=expected,now=now)
        assert value['preservation_allowed'] is True and value['preservation_state']=='schema_prewrite_history'
        assert value['admission']['blocks_admission'] is True and value['admission']['retry_eligible'] is False
        assert db.execute('SELECT state,artifact FROM runs WHERE id=?',(case[3],)).fetchone()[:]==('ATTENTION',None)
        with pytest.raises(r.RecoveryError):
            store._protected_read_status(db,case[3],purpose='maintenance_preclaim_preservation',
                paired_readback=packet,expected_pair=expected,now=now)
        for mode in ('transition','startup'):
            p=deepcopy(packet);e=deepcopy(expected);p['binding']=e;e['mode']=mode
            assert check(case,p,e,now,db)
        for fault in ('receipt','request','intent','log','attempt','missing','raw','expiry','producer','unknown-producer',
                      'boolean-producer','barrier','witness','target','old-scope','later','namespace','stopped-no-guard'):
            p=deepcopy(packet);e=deepcopy(expected);p['binding']=e
            rawdocs=p['receiver_schema_prewrite'];files=p['receiver_tree']['files']
            if fault in ('receipt','request','intent','log','attempt'):
                name=next(name for name in rawdocs if name.startswith({'receipt':'validate.json','request':'prepare_schema-request',
                    'intent':'prepare_schema-intent','log':'validation-recovery','attempt':'validate-recovery-attempt'}[fault]))
                raw=b'changed' if fault=='log' else b'{"changed":true}'
                rawdocs[name]=base64.b64encode(raw).decode();files['prototype-converter/'+name]={'sha256':r.digest(raw),'bytes':len(raw)}
            elif fault=='missing':rawdocs.pop('validate.json')
            elif fault=='raw':rawdocs['validate.json']='!!!!'
            elif fault=='expiry':p['expires_at_utc']=(now-timedelta(seconds=1)).isoformat()
            elif fault=='producer':p['producer']['receiver_operations']=1
            elif fault=='unknown-producer':p['producer']['unknown_producers']=1
            elif fault=='boolean-producer':p['producer']['receiver_servers']=True
            elif fault=='barrier':p['serialization_barrier']['result']['stage']='claimed_validate'
            elif fault=='witness':p['gateway_witness']['source_review_authorized']=True
            elif fault=='target':e['target_profile_sha256']='0'*64
            elif fault=='old-scope':p['scope']=r.CLAIMED_VALIDATION_MAINTENANCE_SCOPE
            elif fault=='namespace':p['fox_tree']['namespace']['inode']+=1
            elif fault=='stopped-no-guard':
                e['runtime_state']='stopped';p['producer'].update(fox_worker='stopped',receiver_servers=0)
                p['serialization_barrier']['kind']='historical_before_stop'
            else:files['prototype-converter/import-intent.json']={'sha256':'1'*64,'bytes':1}
            with pytest.raises((r.RecoveryError,ValueError)):
                check(case,p,e,now,db)
        # The recovery-attempt record is optional, but may never be hidden when present.
        p=deepcopy(packet);name=next(n for n in p['receiver_schema_prewrite'] if n.startswith('validate-recovery-attempt-'))
        p['receiver_schema_prewrite'].pop(name);p['receiver_tree']['files'].pop('prototype-converter/'+name)
        p['serialization_barrier']['binding']['receiver_tree_sha256']=h(p['receiver_tree'])
        p['gateway_witness']=r.schema_prewrite_observation(p,p['technical'])
        assert check(case,p,expected,now,db)
        assert db.total_changes==changes
    with case[9]() as db:
        db.execute('PRAGMA query_only=OFF')
        for action in ('operator-retained-validation-claim-v1','operator-retained-validation-handoff-v1'):
            db.execute('SAVEPOINT changed_event')
            try:
                db.execute('UPDATE events SET object_id=object_id||? WHERE action=?',('changed',action))
                with pytest.raises(r.RecoveryError):check(case,packet,expected,now,db)
            finally:db.execute('ROLLBACK TO changed_event');db.execute('RELEASE changed_event')
    for relative in ('prototype-pipeline/synthetic-schema.sql','prototype-pipeline/schema-write-intent.json',
                     'prototype-pipeline/prepare_schema.json','prototype-pipeline/import-intent.json'):
        path=case[4]/relative
        try:
            path.write_bytes(b'{}')
            with case[9]() as db:
                with pytest.raises(r.RecoveryError):check(case,packet,expected,now,db)
        finally:path.unlink()
    assert before==(r.preclaim_tree(case[4]),r.preclaim_tree(receiver),database.read_bytes())


def test_schema_collector_and_real_pure_reader_never_construct_runtime(schema_case,monkeypatch):
    case,receiver,packet,expected,now,database=schema_case
    def forbidden(*args,**kwargs):raise AssertionError('Runtime construction is forbidden in preservation read')
    from fox import prototype_job
    monkeypatch.setattr(prototype_job,'_configuration',forbidden)
    monkeypatch.setattr(PrototypeGateway,'__init__',forbidden)
    before=(r.preclaim_tree(case[4]),r.preclaim_tree(receiver),database.read_bytes())
    technical=r.preclaim_technical_read(database,case[3],case[10]['target_profile'],'e'*64,stage='prepare_schema')
    assert technical=={k:v for k,v in packet['technical'].items() if k!='receiver_manifest_raw_sha256'}
    params={'fox_data':str(case[1]),'receiver_jobs':str(receiver.parent),'job_id':case[3],'stage':'prepare_schema'}
    output=io.StringIO()
    # Execute the exact emitted stdlib program; keep the inherited prohibition
    # on subprocess/HTTP/Oracle/model boundaries intact.
    with monkeypatch.context() as patch:
        patch.setattr(sys,'stdin',io.StringIO(json.dumps(params)))
        patch.setattr(sys,'stdout',output)
        exec(compile(r.preclaim_collector_source(stage='prepare_schema'),'<schema-prewrite-collector>','exec'),{})
    collected=json.loads(output.getvalue())
    for key in ('fox_tree','receiver_tree','receiver_claims','receiver_schema_prewrite'):
        assert collected[key]==packet[key]
    assert r.schema_prewrite_request(case[4])['prior_receipts']['validate']['validation']['return_code']==0
    assert r.preclaim_request(case[4])['prior_receipts']=={}
    for stage in ('import','prepare-schema',None):
        with pytest.raises(r.RecoveryError):r.preclaim_collector_source(stage=stage)
    assert before==(r.preclaim_tree(case[4]),r.preclaim_tree(receiver),database.read_bytes())


def test_default_unclaimed_validate_contract_with_static_historical_fixtures(pair_case):
    # The older module dynamically obtains dsc_case, hiding it from autouse
    # fixture dependency discovery. Reuse its UNCHANGED acceptance body with
    # the same static historical fixture graph already used by claimed_case.
    from test_preclaim_maintenance_pair import test_positive_actual_pure_cf_readback_is_preservation_only
    test_positive_actual_pure_cf_readback_is_preservation_only(pair_case)
