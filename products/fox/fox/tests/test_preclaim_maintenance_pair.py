"""Actual local closed synthetic CF lineage; no live/model/Oracle authority."""
from copy import deepcopy
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import base64
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import sqlite3
import shutil
import sys

import pytest

from fox import verification_recovery as recovery
from fox import prototype_candidate_continuation as candidate
from fox.opaf import canonical_hash
from fox.prototype_transport import build_authority_bundle, authority_manifest
from forms2apex.prototype_gateway import PrototypeGateway
from test_prototype_candidate_continuation import (format_case as original_format_case, historical_format_policy,
    dsc_case,historical_dsc_source,correction_case,screen_case,partition_case,container_case,
    container_source_model,clause_case,epochs_case,client,settings,no_external_actions,
    next_body,api,process)
from test_prototype_container_terminal import combine,generated_reader
from qa.operator.tests.test_retirement_remote_backend import historical_case

_TECHNICAL_CACHE = {}


@pytest.fixture
def tmp_path(tmp_path_factory,request):
    if request.node.name=='test_structural_old_namespace_consumers_independently_recheck_pair':
        root=tmp_path_factory.getbasetemp()/'s';root.mkdir()
        return root
    return tmp_path_factory.mktemp('e')


def save(path, value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value),encoding='utf-8')


@pytest.fixture
def format_case(request,monkeypatch):
    retained=os.environ.get('PRECLAIM_MAINTENANCE_REUSE_ROOT')
    if not retained:
        return original_format_case.__wrapped__(request.getfixturevalue('dsc_case'),monkeypatch)
    root=Path(retained).resolve()
    assert root.is_relative_to((Path(__file__).resolve().parents[6]/'work').resolve())
    jobs=list((root/'jobs').iterdir());assert len(jobs)==1
    job=jobs[0];snapshot=json.loads((job/'source-snapshot.json').read_bytes())
    target=json.loads(next((job/'prototype-pipeline').glob('focus-*/mapper-target.json')).read_bytes())
    return (None,root,snapshot['project_id'],job.name,job,snapshot,None,None,None,None,{'target_profile':target})


@pytest.fixture
def pair_case(format_case, monkeypatch, tmp_path):
    case = format_case
    if case[0] is not None:
        _, body = next_body(case)
        response = case[0].post(api(case,'candidate-format-continuation'),json=body)
        assert response.status_code == 202, response.text
        def preclaim_failure(stage, request):
            assert stage == 'validate'
            raise RuntimeError('Authored terminal preclaim failure; no converter operation.')
        monkeypatch.setattr(case[8],'run_stage',preclaim_failure)
        row, errors = process(case,monkeypatch)
        assert row['state'] == 'ATTENTION', errors
    request = recovery.preclaim_request(case[4])
    if case[0] is not None:
        bundle = build_authority_bundle(case[4],request)
        receiver_root = tmp_path / 'receiver'; receiver_root.mkdir()
        gateway = PrototypeGateway(SimpleNamespace(jobs_root=receiver_root))
        receipt = gateway.stage_source_authority(case[3],bundle)
        transport = {key:receipt[key] for key in ('job_id','source_binding','source_authority','manifest_sha256')}
        save(case[4]/'prototype-transport/authority-intent.json',transport)
        save(case[4]/'prototype-transport/authority.json',receipt)
    else:
        receiver_root=case[1].parent/'receiver'
    # Supported empty verification ledgers in a private in-memory copy only.
    # The completed original synthetic source, DB and model artifacts stay readonly.
    memory=sqlite3.connect(':memory:');memory.row_factory=sqlite3.Row
    with sqlite3.connect('file:'+str(case[1]/'fox.sqlite3')+'?mode=ro',uri=True) as original:
        original.backup(memory)
    from fox.verification_queue import initialize_schema
    initialize_schema(memory);recovery.initialize_schema(memory);memory.commit()
    @contextmanager
    def db():
        try:
            yield memory
        finally:
            if memory.in_transaction:memory.rollback()
    case=(*case[:9],db,case[10])
    expected = {'job_id':case[3],'request_sha256':canonical_hash(request),
        'source_binding':request['source_binding'],'target_profile_sha256':case[5]['prototype']['target_profile_sha256'],
        'pair_sha256':'a'*64,'scope_sha256':'b'*64,'lease_sha256':'c'*64,'original_terminal_sha256':'d'*64,
        'technical_source_sha256':'e'*64,'mode':'transition','runtime_state':'running','stopped_writer_sha256':None}
    fox_tree = recovery.preclaim_tree(case[4]); receiver = receiver_root / case[3]
    # This is the actual pure production reconstruction, not a stubbed pass.
    key=(canonical_hash(fox_tree),canonical_hash(case[10]['target_profile']),
         hashlib.sha256(Path(recovery.__file__).read_bytes()).hexdigest())
    if key not in _TECHNICAL_CACHE:
        _TECHNICAL_CACHE[key]=recovery.preclaim_technical_read(case[1]/'fox.sqlite3',case[3],case[10]['target_profile'],'e'*64)
    technical=deepcopy(_TECHNICAL_CACHE[key])
    technical['receiver_manifest_raw_sha256'] = hashlib.sha256(
        (receiver/'prototype-converter/authority-manifest.json').read_bytes()).hexdigest()
    now = datetime.now(timezone.utc)
    readback = {'schema_version':1,'scope':recovery.PRECLAIM_MAINTENANCE_SCOPE,
        'observed_at_utc':now.isoformat(),'expires_at_utc':(now+timedelta(seconds=30)).isoformat(),
        'binding':expected,'fox_tree':fox_tree,'receiver_tree':recovery.preclaim_tree(receiver),
        'receiver_manifest':json.loads((receiver/'prototype-converter/authority-manifest.json').read_bytes()),
        'technical':technical,'producer':{'fox_worker':'terminal_idle','receiver_servers':1,'receiver_operations':0,
            'unknown_producers':0,'original_terminal_sha256':'d'*64},
        'serialization_barrier':{'kind':'current_serialized_read','observed_at_utc':now.isoformat(),
            'binding':{'pair_sha256':expected['pair_sha256'],'fox_tree_sha256':canonical_hash(fox_tree),
                'receiver_tree_sha256':canonical_hash(recovery.preclaim_tree(receiver))},
            'result':{'method':'GET','stage':'validate','job_id':case[3],'status':404}},
        'gateway_witness':None,'stopped_writer':None}
    return case, receiver, readback, expected, now


def test_positive_actual_pure_cf_readback_is_preservation_only(pair_case):
    case, receiver, readback, expected, now = pair_case
    before = recovery.preclaim_tree(case[4]),recovery.preclaim_tree(receiver)
    with case[9]() as db:
        db.execute('PRAGMA query_only=ON'); db.execute('BEGIN')
        store = recovery.VerificationRecovery(case[1]/'fox.sqlite3',enabled=True)
        value = store._protected_read_status(db,case[3],purpose='maintenance_preclaim_preservation',
            paired_readback=readback,expected_pair=expected,now=now)
        assert value['preservation_allowed'] is True and value['preservation_state'] == 'preclaim_validate_history'
        assert value['admission']['blocks_admission'] is True and value['admission']['retry_eligible'] is False
        assert db.total_changes == 0
    assert before == (recovery.preclaim_tree(case[4]),recovery.preclaim_tree(receiver))


@pytest.mark.parametrize('fault',['scope','binding','expiry','future','manifest','member','orphan-snapshot',
    'orphan-intent','orphan-log','later-phase','unknown-directory','active','unknown-producer','boolean-server',
    'owner','source','state','target','technical','barrier','forged-gateway','stopped-without-guard',
    'fox-namespace','receiver-namespace'])
def test_forged_unclosed_changed_or_live_readbacks_reject(pair_case,fault):
    case,receiver,original,expectation,now=pair_case
    readback,expected=deepcopy(original),deepcopy(expectation)
    readback['binding']=expected
    with case[9]() as db:
        db.execute('BEGIN')
        if fault=='scope':readback['scope']='user-ready'
        elif fault=='binding':readback['binding']={**expected,'lease_sha256':'0'*64}
        elif fault=='expiry':readback['expires_at_utc']=(now-timedelta(seconds=1)).isoformat()
        elif fault=='future':readback['observed_at_utc']=(now+timedelta(seconds=10)).isoformat()
        elif fault=='manifest':
            readback['receiver_manifest']['files'][0]['sha256']='0'*64
            readback['receiver_manifest']['manifest_sha256']=canonical_hash({k:v for k,v in readback['receiver_manifest'].items() if k!='manifest_sha256'})
        elif fault=='member':next(iter(readback['receiver_tree']['files'].values()))['bytes']+=1
        elif fault.startswith('orphan-') or fault=='later-phase':
            name={'orphan-snapshot':'snapshot.json','orphan-intent':'validate-intent.json',
                  'orphan-log':'validation.log','later-phase':'import-intent.json'}[fault]
            readback['receiver_tree']['files']['prototype-converter/'+name]={'sha256':'1'*64,'bytes':1}
        elif fault=='unknown-directory':readback['receiver_tree']['directories'].append('unrecognized')
        elif fault=='active':readback['producer']['receiver_operations']=1
        elif fault=='unknown-producer':readback['producer']['unknown_producers']=1
        elif fault=='boolean-server':readback['producer']['receiver_servers']=True
        elif fault=='owner':db.execute("UPDATE projects SET owner='foreign' WHERE id=?",(case[2],))
        elif fault=='source':db.execute("UPDATE sources SET text=text||' '")
        elif fault=='state':db.execute("UPDATE runs SET state='PROCESSING' WHERE id=?",(case[3],))
        elif fault=='target':expected['target_profile_sha256']='0'*64
        elif fault=='technical':readback['technical']['fox_tree_sha256']='0'*64
        elif fault=='barrier':readback['serialization_barrier']['result']['status']=200
        elif fault=='forged-gateway':
            expected['mode']='startup';readback['gateway_witness']={'scope':'fox-prototype-validate-preclaim-witness-v1','ready':True}
        elif fault=='fox-namespace':readback['fox_tree']['namespace']['inode']+=1
        elif fault=='receiver-namespace':readback['receiver_tree']['namespace']['inode']+=1
        else:
            expected['runtime_state']='stopped';readback['producer'].update(fox_worker='stopped',receiver_servers=0)
            readback['serialization_barrier']['kind']='historical_before_stop'
        run=dict(db.execute('SELECT * FROM runs WHERE id=?',(case[3],)).fetchone())
        with pytest.raises(recovery.RecoveryError):
            recovery.validate_preclaim_pair(case[1]/'fox.sqlite3',db,run,readback,expected,now=now)


def test_actual_receiver_orphans_collected_not_hidden_by_missing_request(pair_case,tmp_path):
    case,receiver,readback,expected,now=pair_case
    clone=tmp_path/'r'/case[3]
    shutil.copytree(receiver,clone)
    before=recovery.preclaim_tree(receiver)
    for name in ('snapshot.json','candidate-apexlang.zip','validate-intent.json','validation.log','export.json'):
        marker=clone/'prototype-converter'/name
        marker.write_bytes(b'{}')
        changed=deepcopy(readback);changed['receiver_tree']=recovery.preclaim_tree(clone)
        with case[9]() as db:
            run=dict(db.execute('SELECT * FROM runs WHERE id=?',(case[3],)).fetchone())
            with pytest.raises(recovery.RecoveryError,match='RECEIVER_ATTEMPT_OR_UNKNOWN'):
                recovery.validate_preclaim_pair(case[1]/'fox.sqlite3',db,run,changed,expected,now=now)
        marker.unlink()
    assert recovery.preclaim_tree(receiver)==before


def test_exact_new_gateway_witness_is_separate_from_execution(pair_case):
    case,receiver,readback,expected,now=pair_case
    gateway=PrototypeGateway(SimpleNamespace(jobs_root=receiver.parent),
        target_profile_loader=lambda _:deepcopy(case[10]['target_profile']))
    witness=gateway.validate_preclaim_witness(recovery.preclaim_request(case[4]))
    readback,expected=deepcopy(readback),deepcopy(expected);readback['binding']=expected
    expected['mode']='startup';readback['gateway_witness']=witness
    with case[9]() as db:
        run=dict(db.execute('SELECT * FROM runs WHERE id=?',(case[3],)).fetchone())
        result=recovery.validate_preclaim_pair(case[1]/'fox.sqlite3',db,run,readback,expected,now=now)
        assert result['request_sha256']==witness['request_sha256']
        assert recovery.VerificationRecovery(case[1]/'fox.sqlite3',enabled=True)._eligibility(db,case[3])['blocks_admission'] is True
    assert witness['source_review_authorized'] is False


def test_stopped_pair_requires_actual_guard_and_retained_before_stop_barrier(pair_case):
    case,receiver,readback,expected,now=pair_case
    readback,expected=deepcopy(readback),deepcopy(expected);readback['binding']=expected
    expected['runtime_state']='stopped'
    readback['producer'].update(fox_worker='stopped',receiver_servers=0)
    readback['serialization_barrier']['kind']='historical_before_stop'
    # Authored stopped-guard payload tests the typed boundary; actual controller
    # always obtains this from the existing measured snapshot _host_guard.
    readback['stopped_writer']={'scope':'fox-stopped-writer-observation-v1','runtime':{'fixed':'synthetic'}}
    expected['stopped_writer_sha256']=canonical_hash(readback['stopped_writer'])
    with case[9]() as db:
        run=dict(db.execute('SELECT * FROM runs WHERE id=?',(case[3],)).fetchone())
        assert recovery.validate_preclaim_pair(case[1]/'fox.sqlite3',db,run,readback,expected,now=now)
    readback['producer']['receiver_servers']=1
    with case[9]() as db:
        with pytest.raises(recovery.RecoveryError,match='PRODUCER_NOT_TERMINAL'):
            recovery.validate_preclaim_pair(case[1]/'fox.sqlite3',db,run,readback,expected,now=now)


def test_v2_pinned_carrier_and_honest_overlay_file_identity():
    from deployment import current_pair_transition as transition
    value={'schema_version':2,'scope':transition.SCOPE_V2,'controller_sha256':'a'*64}
    for number,name in enumerate((*transition.REFS,'snapshot_adapter','preclaim_preservation')):
        value[name]={'path':'/home/opc/private/'+name+'.json','sha256':format(number+1,'x')*64}
    value['old_unit']['path']=transition.UNIT.as_posix()
    raw=transition.cb(value)
    assert transition.plan_document(raw,transition.sha(raw))==value
    assert transition.preclaim_module_origin('fox.prototype_design_context','a'*64,'a'*64)=='/app/fox/prototype_design_context.py'
    origin=transition.preclaim_module_origin('fox.prototype_design_context','a'*64,'b'*64)
    assert origin.startswith('<measured-new:') and origin!='/app/fox/prototype_design_context.py'
    assert transition.preclaim_module_origin('fox','a'*64,'a'*64)=='/app/fox/__init__.py'


def test_structural_old_namespace_consumers_independently_recheck_pair(pair_case,historical_case,monkeypatch):
    from qa.operator import retirement_remote as remote
    from fox import verification_queue as queue_module
    from deployment import current_pair_transition as transition
    case,receiver,readback,expected,_=pair_case
    combine(case,historical_case)
    copied=recovery.preclaim_tree(historical_case.root/'jobs'/case[3])
    assert copied['files']==readback['fox_tree']['files'] and copied['directories']==readback['fox_tree']['directories']
    assert recovery.preclaim_tree(receiver)==readback['receiver_tree']
    # STRUCTURAL ADAPTER MODEL ONLY. The original technical check is performed
    # separately on its original absolute root. No technical replay of relocated
    # epoch/CF publications is asserted here. Model the trusted child/host packet
    # for this byte-identical adapter root; production cannot rebind a receipt:
    # the actual child and host collector independently hash its device/inode.
    readback=deepcopy(readback);readback['fox_tree']=copied
    readback['technical']['fox_tree_sha256']=canonical_hash(copied)
    readback['serialization_barrier']['binding']['fox_tree_sha256']=canonical_hash(copied)
    now=datetime.now(timezone.utc)
    readback['observed_at_utc']=now.isoformat();readback['expires_at_utc']=(now+timedelta(seconds=30)).isoformat()
    readback['serialization_barrier']['observed_at_utc']=now.isoformat()
    paired={case[3]:{'readback':readback,'expected':expected}}
    original=remote.container_source
    def emitted(*args):
        source=original(*args)
        marker=' request=_retirement_validate_request(json.loads(raw))'
        assert source.count(marker)==1
        # Model only the trusted host's internally collected packet. The actual
        # measured CheckedFinder, full lineage and independent recheck run intact.
        return source.replace(marker,marker+"\n request['paired_preclaim']="+repr(paired),1)
    with monkeypatch.context() as patch:
        patch.setattr(remote,'container_source',emitted)
        result,imports,errors=generated_reader(historical_case,patch)
    assert result.get('status')=='RETIRED_HISTORY_OBSERVED',errors[-6:]
    assert not imports & {'prototype_pipeline.py','prototype_preclaim_continuation.py','prototype_gateway.py'}
    # Run the real transition backend over actual combined local SQL/files.
    raw=Path(recovery.__file__).read_bytes()
    packet={'source':base64.b64encode(raw).decode(),'sha256':hashlib.sha256(raw).hexdigest(),
            'paths':sys.path[:],'data':str(historical_case.root),'paired_preclaim':paired}
    output=io.StringIO()
    with monkeypatch.context() as patch:
        patch.setattr(sys,'stdin',io.StringIO(json.dumps(packet)));patch.setattr(sys,'stdout',output)
        exec(compile(transition.BACKEND,'<actual-paired-transition-backend>','exec'),{})
    result=json.loads(output.getvalue())
    assert result['eligibility'][case[3]]['blocks_admission'] is True
    assert result['preservation'][case[3]]['state']=='preclaim_validate_history'
    actual=recovery.VerificationRecovery._protected_read_status
    preserved=result['preservation'][case[3]]['preserved']
    def forged(self,db,rid,**kwargs):
        if rid==case[3]:
            return {'admission':{'blocks_admission':True,'recovery_state':'unresolved','retry_eligible':False},
                'preservation_allowed':True,'preservation_state':'preclaim_validate_history','preserved':preserved}
        return actual(self,db,rid,**kwargs)
    monkeypatch.setattr(recovery.VerificationRecovery,'_protected_read_status',forged)
    monkeypatch.setattr(recovery,'validate_preclaim_pair',lambda *a,**kw:False)
    with pytest.raises(remote.RetirementRemoteError,match='PRECLAIM_UNCONFIRMED'):
        remote._backend_read(historical_case.history,'d'*64,True,queue_module,recovery,historical_case.root,paired)
