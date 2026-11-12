"""Synthetic actual lineage/SQLite and modelled host startup, never live proof."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT/'fox/tests') not in sys.path:
    sys.path.insert(0,str(ROOT/'fox/tests'))

from fox import verification_recovery as recovery, verification_queue as queue
from fox.opaf import canonical_hash as hashed
from qa.operator import retirement_remote as remote
from qa.operator.tests.test_claimed_validation_preservation import model as provenance_model
from qa.operator.tests.test_retirement_remote_backend import historical_case
from test_schema_prewrite_maintenance import (schema_case, claimed_case, format_case, pair_case,
    original_format_case, historical_format_policy, dsc_case, historical_dsc_source,
    correction_case, screen_case, partition_case, container_case, container_source_model,
    clause_case, epochs_case, client, settings, no_external_actions, save, tmp_path)
from test_prototype_container_terminal import combine


def _actual_schema_startup_child_uses_saved_stage_and_no_gateway(schema_case,monkeypatch):
    case,receiver,packet,expected,now,database=schema_case
    from fox import prototype_job, prototype_download
    before=(recovery.preclaim_tree(case[4]),recovery.preclaim_tree(receiver),database.read_bytes())
    monkeypatch.setenv('FOX_PROTOTYPE_PROFILE_FILE','/modelled/nonsecret/profile.json')
    target=case[10]['target_profile']
    monkeypatch.setattr(prototype_job,'load_prototype_profile',lambda path:{
        'target_profile':target,'target_profile_sha256':hashed(target)})
    def forbidden(*args,**kwargs):raise AssertionError('Schema preservation may not construct runtime clients')
    monkeypatch.setattr(prototype_download,'configured_download_client',forbidden)
    # Relocate only fixed container paths into this synthetic local fixture.
    # The emitted production lineage/technical/collector programs run intact.
    code=remote.STARTUP_PRECLAIM.replace("'/data/fox.sqlite3'",repr(str(database)))
    code=code.replace("'file:/data/fox.sqlite3?mode=ro'",repr(database.as_uri()+'?mode=ro'))
    code=code.replace("pathlib.Path('/data/jobs')",'pathlib.Path('+repr(str(case[1]/'jobs'))+')')
    output=io.StringIO()
    with monkeypatch.context() as patch:
        patch.setattr(sys,'stdin',io.StringIO(json.dumps({'reader_sha256':hashlib.sha256(Path(recovery.__file__).read_bytes()).hexdigest(),
            'image_sha256':'e'*64})))
        patch.setattr(sys,'stdout',output)
        exec(compile(code,'<actual-local-schema-startup>','exec'),{})
    result=json.loads(output.getvalue());entry=result['jobs'][case[3]]
    assert entry['stage']=='prepare_schema' and entry['claimed_validation'] is True
    assert entry['witness'] is None and entry['request']['prior_receipts']['validate']['passed'] is True
    assert entry['collector']==recovery.preclaim_collector_source(stage='prepare_schema')
    assert result['collector']==recovery.preclaim_collector_source()
    assert before==(recovery.preclaim_tree(case[4]),recovery.preclaim_tree(receiver),database.read_bytes())


def schema_provenance(monkeypatch,fault=None):
    v,infrastructure,baseline,calls,plan_path=provenance_model(monkeypatch,fault)
    path_type=remote.Path;original_read=path_type.read_bytes;original_stat=path_type.stat
    value=json.loads(original_read(path_type(baseline['path'])))
    value['scope']='fox-reviewed-schema-prewrite-terminal-baseline-v1'
    value['original_handler']['stage']='prepare_schema'
    raw=json.dumps(value,sort_keys=True).encode()
    plan=json.loads(original_read(path_type(plan_path)))
    plan['preclaim_preservation']['sha256']=hashlib.sha256(raw).hexdigest()
    replacements={baseline['path']:raw,plan_path:json.dumps(plan).encode()}
    def read(path):return replacements[str(path)] if str(path) in replacements else original_read(path)
    def stat(path):
        info=original_stat(path)
        if str(path) in replacements:info.st_size=len(replacements[str(path)])
        return info
    monkeypatch.setattr(path_type,'read_bytes',read)
    monkeypatch.setattr(path_type,'stat',stat)
    return v,infrastructure,replacements,path_type,baseline


def test_schema_provenance_requires_typed_baseline_and_original_terminal(monkeypatch):
    v,infrastructure,docs,path_type,baseline=schema_provenance(monkeypatch)
    first=remote._host_claimed_provenance(v,infrastructure,stage='prepare_schema')
    assert first['baseline']['scope']==recovery.SCHEMA_PREWRITE_BASELINE_SCOPE
    assert first['baseline']['original_handler']['stage']=='prepare_schema'
    assert remote._host_claimed_provenance(v,infrastructure,stage='prepare_schema')==first
    with pytest.raises(ValueError):remote._host_claimed_provenance(v,infrastructure)


@pytest.mark.parametrize('fault',['terminal','running','old-id','old-image','old-name','early-finish',
    'symlink','permissions','current-mount','current-profile-env','profile-bytes'])
def test_schema_provenance_keeps_existing_guards(monkeypatch,fault):
    v,infrastructure,_,_,_=schema_provenance(monkeypatch,fault)
    with pytest.raises(ValueError):remote._host_claimed_provenance(v,infrastructure,stage='prepare_schema')


def model_schema_host(monkeypatch,case,packet,expected):
    infrastructure={'fox':{'id':'1'*64,'image':'sha256:'+'e'*64},
        'forms2apex-mcp':{'id':'2'*64,'image':'sha256:'+'f'*64}}
    items={name:{'Id':pin['id'],'Image':pin['image'],'Name':name,
        'State':{'Running':True,'Pid':1},'HostConfig':{'ReadonlyRootfs':name=='fox'},
        'Config':{'Env':[]},'Mounts':[]} for name,pin in infrastructure.items()}
    items['forms2apex-mcp']['Mounts']=[{'Destination':'/opt/forms2apex/outputs/jobs',
        'Source':'/home/opc/forms2apex/outputs/jobs','Type':'bind','RW':True}]
    technical={k:v for k,v in packet['technical'].items() if k!='receiver_manifest_raw_sha256'}
    entry={'technical':technical,'request':recovery.schema_prewrite_request(case[4]),'witness':None,
        'target_profile_sha256':expected['target_profile_sha256'],'claimed_validation':True,
        'stage':'prepare_schema','collector':recovery.preclaim_collector_source(stage='prepare_schema')}
    startup={'jobs':{case[3]:entry},'collector':recovery.preclaim_collector_source()}
    collected={k:deepcopy(packet[k]) for k in ('fox_tree','receiver_tree','receiver_manifest',
        'receiver_claims','receiver_schema_prewrite')}
    collected['receiver_manifest_raw_sha256']=packet['technical']['receiver_manifest_raw_sha256']
    baseline={'job_id':case[3],'request_sha256':expected['request_sha256'],
        'source_binding':expected['source_binding'],'target_profile_sha256':expected['target_profile_sha256'],
        'fox_tree_sha256':hashed(collected['fox_tree']),'receiver_tree_sha256':hashed(collected['receiver_tree']),
        'manifest_sha256':collected['receiver_manifest']['manifest_sha256']}
    provenance={'baseline':baseline,'original_terminal_sha256':expected['original_terminal_sha256'],
        'execution_target_sha256':technical['execution_target_sha256']}
    calls=[];collections=[];stages=[]
    def run(argv,**kw):
        calls.append(argv)
        if argv[:2]==['podman','inspect']:
            result=[next(item for item in items.values() if item['Id']==argv[2])]
            return SimpleNamespace(returncode=0,stderr=b'',stdout=json.dumps(result).encode())
        if argv[:2]==['podman','top']:return SimpleNamespace(returncode=0,stderr=b'',stdout=b'PID\n1\n')
        assert argv[:2]==['podman','exec'] and argv[-1]==remote.STARTUP_PRECLAIM
        return SimpleNamespace(returncode=0,stderr=b'',stdout=json.dumps(startup).encode())
    def collect(code,params):
        assert code==entry['collector'] and params['stage']=='prepare_schema'
        collections.append(deepcopy(params));return deepcopy(collected)
    def source_provenance(v,pins,*,stage='validate'):
        stages.append(stage);assert stage=='prepare_schema';return deepcopy(provenance)
    class HostPath(PurePosixPath):
        def resolve(self,strict=False):return self
    monkeypatch.setattr(remote,'Path',HostPath)
    monkeypatch.setattr(remote,'subprocess',SimpleNamespace(run=run,PIPE=-1),raising=False)
    monkeypatch.setattr(remote,'guard',lambda ok:None if ok else (_ for _ in ()).throw(ValueError('closed')),raising=False)
    monkeypatch.setattr(remote,'p',{'cli_scope':{'scope':'synthetic-fixed-jsn'}},raising=False)
    monkeypatch.setattr(remote,'timedelta',timedelta,raising=False)  # Emitted host imports this itself.
    monkeypatch.setattr(remote,'_host_preclaim_health',lambda:None)
    monkeypatch.setattr(remote,'_host_preclaim_collect',collect)
    monkeypatch.setattr(remote,'_host_claimed_provenance',source_provenance)
    v={'release_sha256':'a'*64,'configuration_sha256':'b'*64,
        'manifest':{'images':{'fox':infrastructure['fox']['image']},'project':{'queue_modules':{'verification_recovery.py':'c'*64}}}}
    return v,items,infrastructure,collected,entry,calls,collections,stages


def _schema_host_builds_typed_pair_and_rechecks_stage(schema_case,monkeypatch):
    case,receiver,packet,expected,now,database=schema_case
    v,items,infrastructure,collected,entry,calls,collections,stages=model_schema_host(monkeypatch,case,packet,expected)
    paired,captures,pair=remote._host_preclaim(v,items['fox'],infrastructure,remote.STARTUP_PRECLAIM)
    result=paired[case[3]]['readback']
    assert result['scope']==recovery.SCHEMA_PREWRITE_MAINTENANCE_SCOPE
    assert result['serialization_barrier']['result']['stage']=='schema_prewrite'
    assert result['gateway_witness']==recovery.schema_prewrite_observation(result,result['technical'])
    assert result['receiver_schema_prewrite']==packet['receiver_schema_prewrite']
    assert paired[case[3]]['expected']['mode']=='startup'
    remote._host_preclaim_recheck(captures,infrastructure,pair)
    assert len(collections)==2 and stages==['prepare_schema','prepare_schema']
    collected['receiver_tree']['namespace']['inode']+=1
    with pytest.raises(ValueError):remote._host_preclaim_recheck(captures,infrastructure,pair)


def _real_schema_backend_preservation_is_readonly_and_not_admission(schema_case,historical_case,monkeypatch):
    case,receiver,packet,expected,now,database=schema_case
    combine(case,historical_case)
    # This structural adapter model relocates byte-identical synthetic history;
    # the real pure technical read above remains bound to its original root.
    p=deepcopy(packet);e=deepcopy(expected);e['mode']='startup';p['binding']=e
    p['fox_tree']=recovery.preclaim_tree(historical_case.root/'jobs'/case[3])
    p['technical']['fox_tree_sha256']=hashed(p['fox_tree'])
    p['serialization_barrier']['binding']['fox_tree_sha256']=hashed(p['fox_tree'])
    now=datetime.now(timezone.utc)
    p.update(observed_at_utc=now.isoformat(),expires_at_utc=(now+timedelta(seconds=30)).isoformat())
    p['serialization_barrier']['observed_at_utc']=now.isoformat()
    p['gateway_witness']=recovery.schema_prewrite_observation(p,p['technical'])
    paired={case[3]:{'readback':p,'expected':e}}
    before=(recovery.preclaim_tree(historical_case.root/'jobs'/case[3]),recovery.preclaim_tree(receiver))
    result=remote._backend_read(historical_case.history,'d'*64,True,queue,recovery,historical_case.root,paired)
    assert result['snapshot']['preservation'][case[3]]['state']=='schema_prewrite_history'
    admission=result['snapshot']['eligibility'][case[3]]
    assert admission['blocks_admission'] is True and admission['retry_eligible'] is False
    for fault in ('scope','expiry','receiver-claim','schema-document','barrier','witness','producer','later'):
        changed=deepcopy(p)
        if fault=='scope':changed['scope']=recovery.CLAIMED_VALIDATION_MAINTENANCE_SCOPE
        elif fault=='expiry':changed['expires_at_utc']=(now-timedelta(seconds=1)).isoformat()
        elif fault=='receiver-claim':changed['receiver_claims'].pop('snapshot.json')
        elif fault=='schema-document':changed['receiver_schema_prewrite'].pop('validate.json')
        elif fault=='barrier':changed['serialization_barrier']['result']['stage']='claimed_validate'
        elif fault=='witness':changed['gateway_witness']['source_review_authorized']=True
        elif fault=='producer':changed['producer']['receiver_operations']=1
        else:changed['receiver_tree']['files']['prototype-converter/schema-write-intent.json']={'sha256':'1'*64,'bytes':1}
        with pytest.raises((recovery.RecoveryError,remote.RetirementRemoteError)):
            remote._backend_read(historical_case.history,'d'*64,True,queue,recovery,historical_case.root,
                {case[3]:{'readback':changed,'expected':e}})
    with pytest.raises(remote.RetirementRemoteError,match='SCHEMA_STARTUP_ONLY'):
        remote._backend_read(historical_case.history,'d'*64,False,queue,recovery,historical_case.root,paired)
    assert before==(recovery.preclaim_tree(historical_case.root/'jobs'/case[3]),recovery.preclaim_tree(receiver))


def test_actual_schema_startup_pair_and_backend_one_fixture(schema_case,historical_case,monkeypatch):
    # Share the expensive existing real synthetic lineage once; external-boundary
    # models are isolated and never promoted into real technical-read evidence.
    with monkeypatch.context() as patch:
        _actual_schema_startup_child_uses_saved_stage_and_no_gateway(schema_case,patch)
    with monkeypatch.context() as patch:
        _schema_host_builds_typed_pair_and_rechecks_stage(schema_case,patch)
    with monkeypatch.context() as patch:
        _real_schema_backend_preservation_is_readonly_and_not_admission(schema_case,historical_case,patch)
