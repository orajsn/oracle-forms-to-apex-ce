"""Actual emitted local programs; host transport remains explicitly modelled."""
from copy import deepcopy
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/'fox/tests'),str(ROOT/'fox'),str(ROOT)]
from test_paused_stage_preservation import inert_case, mixed_inert_case, validate
from fox import paused_stage_preservation as inert
from qa.operator import retirement_remote as remote, paused_stage_host as host
from qa.operator.tests.test_retirement_remote_backend import historical_case, CURRENT


def execute(source,payload,monkeypatch):
    output=io.StringIO()
    with monkeypatch.context() as patch:
        patch.setattr(sys,'stdin',io.StringIO(json.dumps(payload)));patch.setattr(sys,'stdout',output)
        exec(compile(source,'<actual-local-inert-program>','exec'),{})
    return json.loads(output.getvalue())


def test_emitted_startup_and_receiver_are_actual_local_readonly(inert_case,monkeypatch):
    c=inert_case
    from fox import prototype_job
    monkeypatch.setenv('FOX_VERIFICATION_ENABLED','1');monkeypatch.setenv('FOX_VERIFIER_RELEASE_SHA256','f'*64)
    monkeypatch.setenv('FOX_PROTOTYPE_PROFILE_FILE','/synthetic/nonsecret')
    monkeypatch.setattr(prototype_job,'load_prototype_profile',lambda p:{'target_profile':{},'target_profile_sha256':'c'*64})
    source=remote.STARTUP_INERT.replace("'file:/data/fox.sqlite3?mode=ro'",repr(c.database.as_uri()+'?mode=ro'))
    source=source.replace("'/data/fox.sqlite3'",repr(str(c.database)))
    before=c.database.read_bytes()
    result=execute(source,{'source_sha256':__import__('hashlib').sha256(Path(inert.__file__).read_bytes()).hexdigest(),
                           'release_sha256':'f'*64},monkeypatch)
    assert result['observation']=={key:c.baseline[key] for key in ('database','jobs','fox')}
    receiver=execute(result['collector'],{'receiver_jobs':str(c.receiver),'jobs':[c.job_id]},monkeypatch)
    assert receiver['receiver']==c.baseline['receiver'] and receiver['requests'][c.job_id]==inert.hashed(c.request)
    assert c.database.read_bytes()==before
    monkeypatch.setenv('FOX_VERIFICATION_ENABLED','0')
    with pytest.raises(AssertionError):execute(source,{'source_sha256':__import__('hashlib').sha256(Path(inert.__file__).read_bytes()).hexdigest(),
                                                   'release_sha256':'f'*64},monkeypatch)


@pytest.mark.parametrize('name',['runtime-request.json','runtime-claim.json','runtime-result.json','runtime-receipt.json',
                                'verify_runtime.json','export-intent.json','export.json','prototype-package.zip'])
def test_receiver_rejects_every_dispatch_or_export_marker(inert_case,monkeypatch,name):
    c=inert_case;(c.stage/name).write_text('{}')
    with pytest.raises(AssertionError):execute(inert.receiver_collector_source(),{'receiver_jobs':str(c.receiver),'jobs':[c.job_id]},monkeypatch)


@pytest.mark.parametrize('present',[False,True])
def test_emitted_mixed_startup_preserves_all_jobs_and_receiver_runtime_subset(mixed_inert_case,monkeypatch,present):
    c=mixed_inert_case
    if present:
        stage=c.receiver/c.opaque_id/'prototype-converter';stage.mkdir(parents=True)
        (stage/'validate-intent.json').write_text('{"unknown":"earlier outcome preserved"}')
        c.refresh()
    from fox import prototype_job
    monkeypatch.setenv('FOX_VERIFICATION_ENABLED','1');monkeypatch.setenv('FOX_VERIFIER_RELEASE_SHA256','f'*64)
    monkeypatch.setenv('FOX_PROTOTYPE_PROFILE_FILE','/synthetic/nonsecret')
    monkeypatch.setattr(prototype_job,'load_prototype_profile',lambda p:{'target_profile':{},'target_profile_sha256':'c'*64})
    source=remote.STARTUP_INERT.replace("'file:/data/fox.sqlite3?mode=ro'",repr(c.database.as_uri()+'?mode=ro'))
    source=source.replace("'/data/fox.sqlite3'",repr(str(c.database)))
    before=c.database.read_bytes()
    result=execute(source,{'source_sha256':__import__('hashlib').sha256(Path(inert.__file__).read_bytes()).hexdigest(),
                           'release_sha256':'f'*64},monkeypatch)
    received=execute(result['collector'],{'receiver_jobs':str(c.receiver),'jobs':sorted(c.baseline['jobs'])},monkeypatch)
    assert result['observation']=={key:c.baseline[key]for key in ('database','jobs','fox')}
    assert received['receiver']==c.baseline['receiver']
    assert set(received['identities'])==set(received['requests'])=={c.job_id}
    assert set(received['receiver'])=={c.job_id,c.opaque_id}
    assert received['receiver'][c.opaque_id].get('absent')is (True if not present else None)
    assert c.database.read_bytes()==before
    assert (c.receiver/c.opaque_id).exists()is present


@pytest.mark.parametrize('name',['verify_runtime-intent.json','verify_runtime-request.json','verify_runtime.json',
    'export-request.json','export-intent.json','export-attempt.json','export.json','prototype-package.zip',
    'runtime-request.json','runtime-claim.json','runtime-result.json','runtime-receipt.json','runtime-evidence'])
@pytest.mark.parametrize('directory',[False,True])
def test_opaque_receiver_cannot_hide_partial_runtime_or_later_artifacts(mixed_inert_case,monkeypatch,name,directory):
    c=mixed_inert_case;stage=c.receiver/c.opaque_id/'prototype-converter';stage.mkdir(parents=True)
    path=stage/name
    if directory:path.mkdir()
    else:path.write_text('{}')
    with pytest.raises((AssertionError,RuntimeError,OSError)):
        execute(inert.receiver_collector_source(),{'receiver_jobs':str(c.receiver),'jobs':sorted(c.baseline['jobs'])},monkeypatch)


def test_receiver_absence_namespace_changes_and_new_children_are_not_adopted(mixed_inert_case):
    c=mixed_inert_case;before=inert.receiver_job_tree(c.receiver,c.opaque_id)
    (c.receiver/c.opaque_id).mkdir()
    assert inert.receiver_job_tree(c.receiver,c.opaque_id)!=before
    assert before['absent']is True and before['parent_namespace']['inode']==c.receiver.stat().st_ino


def test_mixed_host_uses_runtime_subset_but_all_jobs_still_block_producers(mixed_inert_case,monkeypatch):
    c=mixed_inert_case;runtime,pins,items=host_model(c,monkeypatch)
    received=execute(inert.receiver_collector_source(),{'receiver_jobs':str(c.receiver),'jobs':sorted(c.baseline['jobs'])},monkeypatch)
    c.baseline['runtime']=runtime
    identity=deepcopy(c.expected['identity']);identity['profile_sha256']=host.hashed({'profile':'nonsecret'})
    paired=host.paired(c.baseline,{key:c.baseline[key]for key in ('database','jobs','fox')},received,identity,pins,storage=c.storage)
    assert set(paired)=={c.job_id,c.opaque_id}
    for job,item in paired.items():
        with __import__('sqlite3').connect(c.database.as_uri()+'?mode=ro',uri=True)as db:
            db.row_factory=__import__('sqlite3').Row;db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
            result=inert.validate_pair(c.database,db,job,item['readback'],item['expected'])
        assert result['admission']['blocks_admission']is True and result['admission']['retry_eligible']is False
    bad=deepcopy(received);bad['requests'][c.opaque_id]='a'*64
    with pytest.raises(RuntimeError):host.paired(c.baseline,{key:c.baseline[key]for key in ('database','jobs','fox')},bad,identity,pins,storage=c.storage)
    staging=Path(runtime['staging_root'])/c.opaque_id;staging.mkdir(parents=True)
    with pytest.raises(RuntimeError,match='HOST_ATTEMPT'):
        host.collect(runtime,received['receiver'],received['identities'],c.baseline['jobs'],pins,storage=c.storage)


def test_mixed_opaque_job_still_constrains_global_oldest_and_unknown_producers(mixed_inert_case,monkeypatch):
    c=mixed_inert_case;runtime,pins,items=host_model(c,monkeypatch)
    identities={c.job_id:inert.runtime_identity(c.request,c.request['prior_receipts']['import'],{'opaque':'preserved'})}
    items.append({'Id':'9'*64,'Image':runtime['qa_image'],'State':{'Running':False,'Pid':0,'Status':'exited',
        'FinishedAt':'1970-01-01T00:00:00.500000Z'},'Mounts':[]})
    with pytest.raises(RuntimeError,match='UNATTRIBUTED_QA'):
        host.collect(runtime,c.baseline['receiver'],identities,c.baseline['jobs'],pins,storage=c.storage)
    items.pop();monkeypatch.setattr(host,'process_inventory',lambda *a,**kw:[{'pid':999,'start_ticks':1}])
    with pytest.raises(RuntimeError,match='UNKNOWN_HOST_PRODUCER'):
        host.collect(runtime,c.baseline['receiver'],identities,c.baseline['jobs'],pins,storage=c.storage)


def host_model(c,monkeypatch):
    runtime={'config':{'path':str(c.root/'config'),'sha256':'1'*64},'unit':{'path':str(c.root/'unit'),'sha256':'2'*64},
      'python':{'path':str(c.root/'python'),'sha256':'3'*64},'profile':{'path':str(c.root/'profile'),'sha256':'4'*64},
      'source_root':str(c.root),'sources':{n:'5'*64 for n in ('qa/operator/prototype_host.py',
      'qa/operator/prototype_runtime_worker.py','qa/operator/prototype_browser.py','qa/run-prototype.mjs','qa/lib/contracts.mjs')},
      'receiver_jobs':str(c.receiver),'staging_root':str(c.root/'staging'),'qa_root':str(c.root/'qa'),
      'qa_image':'sha256:'+'6'*64,'service':'synthetic.service','other_containers':[]}
    config={'scope':'fox-prototype-host-v1','schema_version':1,'converter_id':'2'*64,'converter_image':'sha256:'+'8'*64,
      'jobs_root':runtime['receiver_jobs'],'staging_jobs_root':runtime['staging_root'],'qa_root':runtime['qa_root'],
      'image_id':runtime['qa_image'],'target_profile_file':runtime['profile']['path'],'target_profile_sha256':'4'*64}
    pins={'fox':{'id':'1'*64,'image':'sha256:'+'7'*64},'forms2apex-mcp':{'id':'2'*64,'image':'sha256:'+'8'*64}}
    items=[{'Id':p['id'],'Image':p['image'],'State':{'Running':True,'Pid':100+i,'ConmonPid':200+i,'Status':'running'},
            'Config':{},'Mounts':[]} for i,p in enumerate(pins.values())]
    c.storage={'fox_data':str(c.root/'persistent-fox'),'receiver_jobs':runtime['receiver_jobs']}
    items[0]['Mounts']=[{'Source':c.storage['fox_data'],'Destination':'/data','Type':'bind','RW':True}]
    items[1]['Mounts']=[{'Source':runtime['receiver_jobs'],'Destination':'/opt/forms2apex/outputs/jobs','Type':'bind','RW':True}]
    # Structural host transport model uses native temporary paths on Windows;
    # adapt only their spelling before the actual POSIX overlap predicate.
    original_overlap=host.overlaps
    monkeypatch.setattr(host,'overlaps',lambda a,b:original_overlap('/'+Path(a).as_posix().lstrip('/'),
                                                                 '/'+Path(b).as_posix().lstrip('/')))
    monkeypatch.setattr(host,'os',SimpleNamespace(name='posix',getuid=lambda:1000))
    monkeypatch.setattr(host,'read_ref',lambda ref:json.dumps(config if ref==runtime['config'] else {'profile':'nonsecret'}).encode())
    monkeypatch.setattr(host,'metadata',lambda *a,**k:{'device':1,'inode':2,'mode':448})
    monkeypatch.setattr(host,'effective_unit',lambda *a:{'MainPID':'0','ActiveState':'inactive'})
    monkeypatch.setattr(host,'process_inventory',lambda roots,**kw:[])
    monkeypatch.setattr(host,'lock_holders',lambda root:[])
    def command(args):
        if 'top' in args:return b'PID\n1\n'
        if 'ps' in args:return '\n'.join(item['Id'] for item in items).encode()
        assert '--format' in args and 'Config' not in args[-1] and 'Env' not in args[-1]
        return '\n'.join(json.dumps({k:item[k] for k in ('Id','Image','State','Mounts')}) for item in items).encode()
    monkeypatch.setattr(host,'command',command)
    return runtime,pins,items


def test_modelled_host_positive_and_unknown_producer_refusal(inert_case,monkeypatch):
    c=inert_case;runtime,pins,items=host_model(c,monkeypatch)
    identities={c.job_id:inert.runtime_identity(c.request,c.request['prior_receipts']['import'],{'opaque':'preserved'})}
    packet,_=host.collect(runtime,c.baseline['receiver'],identities,c.baseline['jobs'],pins,storage=c.storage)
    assert packet['blockers']==[] and packet['runtime_sha256']==inert.hashed(runtime)
    monkeypatch.setattr(host,'process_inventory',lambda roots,**kw:[{'pid':999,'start_ticks':1}])
    with pytest.raises(RuntimeError,match='UNKNOWN_HOST_PRODUCER'):
        host.collect(runtime,c.baseline['receiver'],identities,c.baseline['jobs'],pins,storage=c.storage)


@pytest.mark.parametrize('fault',['stage','qa','active-container','bound-container','wrong-image','active-lock','active-service'])
def test_modelled_host_rejects_real_measurement_changes(inert_case,monkeypatch,fault):
    c=inert_case;runtime,pins,items=host_model(c,monkeypatch)
    identities={c.job_id:inert.runtime_identity(c.request,c.request['prior_receipts']['import'],{'opaque':'preserved'})}
    if fault in ('stage','qa'):
        path=(Path(runtime['staging_root'])/c.job_id if fault=='stage' else Path(runtime['qa_root'])/('prototype-'+inert.hashed(identities[c.job_id])))
        path.mkdir(parents=True)
    elif fault=='active-container':items.append({'Id':'9'*64,'Image':'sha256:'+'a'*64,'State':{'Running':True,'Pid':333,'Status':'running'},'Config':{},'Mounts':[]})
    elif fault=='bound-container':items[0]['Mounts']=[{'Source':str(Path(runtime['staging_root'])/c.job_id)}]
    elif fault=='wrong-image':items[0]['Image']='sha256:'+'0'*64
    elif fault=='active-lock':monkeypatch.setattr(host,'lock_holders',lambda root:['actual observed lock'])
    else:monkeypatch.setattr(host,'effective_unit',lambda *a:(_ for _ in ()).throw(RuntimeError('active service')))
    with pytest.raises(RuntimeError):host.collect(runtime,c.baseline['receiver'],identities,c.baseline['jobs'],pins,storage=c.storage)


def test_actual_retirement_backend_preserves_unresolved_job_with_real_legacy_ledgers(inert_case,historical_case):
    import shutil
    import sqlite3
    c=inert_case;h=historical_case
    target=h.root/'jobs'/c.job_id
    assert not target.exists()
    shutil.copytree(c.job,target);c.job=target;c.root=h.root;c.database=h.database
    with sqlite3.connect(c.database) as db:
        db.execute('INSERT INTO projects(id,owner) VALUES(?,?)',('project-a','owner-a'))
        db.execute('INSERT INTO source_sets VALUES(?,?,?,?,?,?,?)',('source-set-a','project-a','b'*64,1,1,1.,'upload'))
        db.execute('INSERT INTO project_source_selection VALUES(?,?,?)',('project-a','source-set-a',1.))
        db.execute('INSERT INTO runs(id,project,source_hash,state,artifact,created,updated,message) VALUES(?,?,?,?,?,?,?,?)',
                   (c.job_id,'project-a','b'*64,'ATTENTION',None,1.,2.,'original failure'))
    fox=c.observe(c.database);c.baseline.update(fox)
    c.expected['baseline_sha256']=inert.hashed(c.baseline)
    c.expected['identity']['release_sha256']=CURRENT;c.expected['identity']['admission']['release_sha256']=CURRENT
    c.packet.update(fox=fox,binding=c.expected['baseline_sha256'])
    paired={c.job_id:{'readback':c.packet,'expected':c.expected}}
    before=c.database.read_bytes()
    from fox import verification_queue, verification_recovery
    result=remote._backend_read(h.history,CURRENT,True,verification_queue,verification_recovery,h.root,paired)
    assert result['snapshot']['preservation'][c.job_id]['state']==inert.STATE
    assert result['snapshot']['eligibility'][c.job_id]['blocks_admission'] is True
    assert c.database.read_bytes()==before
    with pytest.raises(remote.RetirementRemoteError,match='INERT_STARTUP_ONLY'):
        remote._backend_read(h.history,CURRENT,False,verification_queue,verification_recovery,h.root,paired)


def test_modelled_exact_old_nonbound_qa_container_is_retained(inert_case,monkeypatch):
    c=inert_case;runtime,pins,items=host_model(c,monkeypatch)
    old={'Id':'9'*64,'Image':runtime['qa_image'],'State':{'Running':False,'Pid':0,'Status':'exited',
         'FinishedAt':'1970-01-01T00:00:00.500000Z'},'Config':{},'Mounts':[]}
    items.append(old)
    identities={c.job_id:inert.runtime_identity(c.request,c.request['prior_receipts']['import'],{'opaque':'preserved'})}
    value,_=host.collect(runtime,c.baseline['receiver'],identities,c.baseline['jobs'],pins,storage=c.storage)
    assert value['blockers']==[] and items[-1]==old
    old['State']['FinishedAt']='1970-01-01T00:00:02Z'
    with pytest.raises(RuntimeError,match='UNATTRIBUTED_QA'):
        host.collect(runtime,c.baseline['receiver'],identities,c.baseline['jobs'],pins,storage=c.storage)


def test_modelled_stopped_original_runtime_binding_is_not_current_dispatch_authority(inert_case,monkeypatch):
    c=inert_case;runtime,pins,items=host_model(c,monkeypatch)
    old=items[1];old['State'].update(Running=False,Pid=0,Status='exited')
    current=deepcopy(old);current['Id']='9'*64;current['State'].update(Running=True,Pid=111,ConmonPid=211,Status='running')
    items.append(current);pins['forms2apex-mcp']['id']=current['Id']
    identities={c.job_id:inert.runtime_identity(c.request,c.request['prior_receipts']['import'],{'opaque':'preserved'})}
    value,_=host.collect(runtime,c.baseline['receiver'],identities,c.baseline['jobs'],pins,storage=c.storage)
    assert value['blockers']==[] and 'dispatch_authorized' not in value
    old['State'].update(Running=True,Pid=101,Status='running')
    with pytest.raises(RuntimeError,match='OLD_RUNTIME_RECEIVER_STILL_LIVE'):
        host.collect(runtime,c.baseline['receiver'],identities,c.baseline['jobs'],pins,storage=c.storage)


def test_actual_unit_metadata_parser_requires_bound_idle_service(monkeypatch):
    runtime={'service':'synthetic.service','unit':{'path':'/synthetic/runtime.service'},
             'source_root':'/synthetic/source','config':{'path':'/synthetic/runtime.json'},
             'python':{'path':'/synthetic/python'},'receiver_jobs':'/synthetic/receiver',
             'staging_root':'/synthetic/stage','qa_root':'/synthetic/qa','qa_image':'sha256:'+'a'*64,
             'profile':{'path':'/synthetic/profile.json','sha256':'b'*64}}
    config={'scope':'fox-prototype-host-v1','schema_version':1,'jobs_root':runtime['receiver_jobs'],
            'staging_jobs_root':runtime['staging_root'],'qa_root':runtime['qa_root'],'image_id':runtime['qa_image'],
            'target_profile_file':runtime['profile']['path'],'target_profile_sha256':'b'*64}
    unit={'FragmentPath':runtime['unit']['path'],'DropInPaths':'','MainPID':'0','ActiveState':'inactive','SubState':'dead',
          'WorkingDirectory':runtime['source_root'],'Environment':'FOX_PROTOTYPE_HOST_CONFIG='+runtime['config']['path'],
          'ExecStart':'{ path=/synthetic/python ; argv[]=/synthetic/python -s -B -m qa.operator.prototype_host ; }'}
    monkeypatch.setattr(host,'command',lambda args:'\n'.join(k+'='+v for k,v in unit.items()).encode())
    assert host.effective_unit(runtime,config)==unit
    for key,value in (('MainPID','123'),('DropInPaths','/unknown.conf'),('Environment','unbound'),('WorkingDirectory','/other')):
        original=unit[key];unit[key]=value
        with pytest.raises(RuntimeError):host.effective_unit(runtime,config)
        unit[key]=original


@pytest.mark.parametrize('left,right,expected',[
    ('/home/opc','/home/opc/fox/data',True),('/home/opc/fox/data','/home/opc',True),
    ('/data','/data',True),('/data/jobs/one','/data',True),('/data-old','/data',False),
    ('/opaf/cache','/fox/data',False)])
def test_actual_mount_overlap_is_both_direction_and_component_aware(left,right,expected):
    assert host.overlaps(left,right) is expected


@pytest.mark.parametrize('where',['ancestor','fox-data','fox-db','fox-jobs','receiver','receiver-child','stage-root','qa-root'])
def test_registered_nonpair_live_container_cannot_mount_protected_storage(inert_case,monkeypatch,where):
    c=inert_case;runtime,pins,items=host_model(c,monkeypatch)
    roots={'ancestor':str(c.root.parent),'fox-data':c.storage['fox_data'],
           'fox-db':str(Path(c.storage['fox_data'])/'fox.sqlite3'),'fox-jobs':str(Path(c.storage['fox_data'])/'jobs'),
           'receiver':runtime['receiver_jobs'],'receiver-child':str(Path(runtime['receiver_jobs'])/c.job_id),
           'stage-root':runtime['staging_root'],'qa-root':runtime['qa_root']}
    runtime['other_containers']=[{'id':'3'*64,'image':'sha256:'+'a'*64}]
    items.append({'Id':'3'*64,'Image':'sha256:'+'a'*64,'State':{'Running':True,'Pid':103,'ConmonPid':203,'Status':'running'},
                  'Mounts':[{'Source':roots[where],'Destination':'/persistent','Type':'bind','RW':True}]})
    identities={c.job_id:inert.runtime_identity(c.request,c.request['prior_receipts']['import'],{'opaque':'preserved'})}
    with pytest.raises(RuntimeError,match='PERSISTENT_MOUNT'):
        host.collect(runtime,c.baseline['receiver'],identities,c.baseline['jobs'],pins,storage=c.storage)


def test_registered_opaf_unrelated_mount_and_exact_pair_mounts_are_allowed(inert_case,monkeypatch):
    c=inert_case;runtime,pins,items=host_model(c,monkeypatch)
    runtime['other_containers']=[{'id':'3'*64,'image':'sha256:'+'a'*64}]
    items.append({'Id':'3'*64,'Image':'sha256:'+'a'*64,'State':{'Running':True,'Pid':103,'ConmonPid':203,'Status':'running'},
                  'Mounts':[{'Source':str(c.root/'unrelated-opaf'),'Destination':'/opaf','Type':'bind','RW':True}]})
    identities={c.job_id:inert.runtime_identity(c.request,c.request['prior_receipts']['import'],{'opaque':'preserved'})}
    result,_=host.collect(runtime,c.baseline['receiver'],identities,c.baseline['jobs'],pins,storage=c.storage)
    assert result['blockers']==[]
    items[0]['Mounts'].append({'Source':str(c.root.parent),'Destination':'/extra','Type':'bind','RW':True})
    with pytest.raises(RuntimeError,match='PERSISTENT_MOUNT'):
        host.collect(runtime,c.baseline['receiver'],identities,c.baseline['jobs'],pins,storage=c.storage)


def test_peer_verifier_is_rechecked_around_inventory(inert_case,monkeypatch):
    c=inert_case;runtime,pins,items=host_model(c,monkeypatch)
    identities={c.job_id:inert.runtime_identity(c.request,c.request['prior_receipts']['import'],{'opaque':'preserved'})}
    proof={'identity':{'pid':456,'start_ticks':123},'witness':{'session':'session-'+'a'*24}}
    calls=[]
    def observe(binding):
        calls.append(deepcopy(binding));value=deepcopy(proof)
        if len(calls)>1:value['identity']['start_ticks']+=1
        return value
    monkeypatch.setattr(host,'verifier_observation',observe)
    with pytest.raises(RuntimeError,match='VERIFIER_OBSERVATION_CHANGED'):
        host.collect(runtime,c.baseline['receiver'],identities,c.baseline['jobs'],pins,storage=c.storage,
                     verifier={'independently-bound':'modelled'})
    assert len(calls)==2 and calls[1]['session']==proof['witness']['session']


def test_actual_ancestor_rule_does_not_create_peer_idle_bypass(monkeypatch):
    binding={key:{'path':'/synthetic/'+key,'sha256':'1'*64} for key in ('helper','support','installation','unit')}
    monkeypatch.setattr(host,'command',lambda args:b'MainPID=456\n')
    monkeypatch.setattr(host,'ancestor_pids',lambda:{456})
    monkeypatch.setattr(host,'read_ref',lambda *a:pytest.fail('Own startup retains only the existing actual-ancestor rule'))
    assert host.verifier_observation(binding) is None
    monkeypatch.setattr(host,'ancestor_pids',lambda:set())
    with pytest.raises(pytest.fail.Exception):host.verifier_observation(binding)
