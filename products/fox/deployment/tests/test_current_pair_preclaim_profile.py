"""Protected profile adapter tests; authored observations, no host/secret access."""
from copy import deepcopy
import builtins
from datetime import datetime, timezone
import json
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest

from test_current_pair_transition import M
from test_activate_project_release import M as A, profile, prototype_configuration, upgrade_plan


@pytest.fixture
def case():
    native=json.loads((Path(__file__).resolve().parents[2]/'deployment/target-profile.jsn-project-v2.json').read_bytes())
    focused=deepcopy(native);focused['profile_id']='focused-not-native'
    focused['opaf']['roles']['mapper']['workflow_id']='A'*32
    focused['opaf']['roles']['reviewer']['workflow_id']='B'*32
    envelope={'target_profile':focused,'target_profile_sha256':M.sha(M.cb(focused)[:-1])}
    option=prototype_configuration();option['profile']['sha256']=M.sha(M.cb(envelope))
    candidate=upgrade_plan();candidate['prototype_authority']=option
    raw=M.cb(candidate);path=PurePosixPath('/home/opc/private/activation-plan.json')
    pin={'id':'1'*64,'image':'sha256:'+'2'*64}
    fox={'Id':pin['id'],'Image':pin['image'],'Name':'fox','Config':{'User':'1000:1000',
        'Env':['FOX_PROTOTYPE_PROFILE_FILE=/run/fox-opaf/prototype-focus-test.json',
               'FOX_PROTOTYPE_AUTHORITY_ENABLED=1','FOX_PUBLIC_ORIGIN='+option['origin']]},
        'Mounts':[{'Type':'bind','Destination':'/run/fox-opaf','Source':A.PROTOTYPE_PROFILE_ROOT,'RW':False}],
        'State':{'Running':True,'Pid':123,'Status':'running'}}
    reads,commands=[],[]
    def read(source,**kwargs):
        assert source.as_posix()==path.as_posix(),'No host native/focused/credential file may be read'
        assert kwargs=={'private':True};reads.append(source);return raw
    observed={'status':'PROTECTED_PROTOTYPE_PROFILE_READABLE','profile_sha256':option['profile']['sha256'],
              'envelope':deepcopy(envelope)}
    def command(argv,**kwargs):
        commands.append((argv,kwargs))
        assert argv==['/usr/bin/podman','exec',pin['id'],'/usr/local/bin/python','-I','-B','-c',
                      A.PROTOTYPE_PROFILE_PROBE,'prototype-focus-test.json',option['profile']['sha256']]
        assert kwargs=={'maximum':131072}
        return M.cb(observed)
    helper=SimpleNamespace(read=read,plan_document=A.plan_document,prototype_configuration=A.prototype_configuration,
        environment=A.environment,mount_map=A.mount_map,PROTOTYPE_PROFILE_ROOT=A.PROTOTYPE_PROFILE_ROOT,
        PROTOTYPE_PROFILE_PROBE=A.PROTOTYPE_PROFILE_PROBE,prototype_execution_target=A.prototype_execution_target,
        parse=A.parse,command=command)
    context=object.__new__(M.Transition);context.A=helper;context.cfg={'target_profile':native}
    context.candidate_path=path;context.candidate_plan=candidate
    context.p={'schema_version':2,'candidate_plan':{'path':path.as_posix(),'sha256':M.sha(raw)}}
    # Reproduce the real layout: native project profile is NOT a focused envelope.
    context.old=SimpleNamespace(manifest={'opaf_profile':{'host_path':'/native/project-opaf-profile-v2.json'}})
    assert 'target_profile' not in profile()
    return SimpleNamespace(context=context,fox=fox,pin=pin,baseline={'target_profile_sha256':envelope['target_profile_sha256']},
        envelope=envelope,observed=observed,reads=reads,commands=commands,raw=raw)


def test_positive_reads_focused_envelope_not_native_host_profile(case):
    result=case.context.preclaim_profile(case.fox,case.pin,case.baseline)
    assert result['observation']=='mounted_live' and result['envelope']==case.envelope
    assert len(case.commands)==len(case.reads)==1
    assert result['binding']['profile']['sha256']==case.observed['profile_sha256']
    assert result['envelope']['target_profile']!=case.context.cfg['target_profile']


@pytest.mark.parametrize('fault',['environment-path','environment-enabled','origin','profile-path','plan-sha',
    'plan-bytes','mount-source','mount-writable','mount-missing','profile-response-sha','profile-status',
    'envelope-sha','snapshot-target','execution-target','container-id','image','user','not-running'])
def test_wrong_profile_bindings_refuse(case,fault):
    context=case.context
    if fault.startswith('environment-') or fault=='origin':
        key={'environment-path':'FOX_PROTOTYPE_PROFILE_FILE','environment-enabled':'FOX_PROTOTYPE_AUTHORITY_ENABLED',
             'origin':'FOX_PUBLIC_ORIGIN'}[fault]
        env=A.environment(case.fox);env[key]='wrong';case.fox['Config']['Env']=[k+'='+v for k,v in env.items()]
    elif fault=='profile-path':context.candidate_plan['prototype_authority']['profile']['path']='/unbound/prototype-focus-test.json'
    elif fault=='plan-sha':context.p['candidate_plan']['sha256']='0'*64
    elif fault=='plan-bytes':context.A.read=lambda *a,**k:case.raw+b' '
    elif fault=='mount-source':case.fox['Mounts'][0]['Source']='/unbound/opaf-client'
    elif fault=='mount-writable':case.fox['Mounts'][0]['RW']=True
    elif fault=='mount-missing':case.fox['Mounts']=[]
    elif fault=='profile-response-sha':case.observed['profile_sha256']='0'*64
    elif fault=='profile-status':case.observed['status']='ready'
    elif fault=='envelope-sha':case.observed['envelope']['target_profile_sha256']='0'*64
    elif fault=='snapshot-target':case.baseline['target_profile_sha256']='0'*64
    elif fault=='execution-target':context.cfg['target_profile']['database']['parsing_schema']='DIFFERENT'
    elif fault=='container-id':case.fox['Id']='3'*64
    elif fault=='image':case.fox['Image']='sha256:'+'3'*64
    elif fault=='user':case.fox['Config']['User']='0:0'
    else:case.fox['State'].update(Running=False,Pid=0,Status='exited')
    with pytest.raises((M.TransitionError,A.ActivationError)):
        context.preclaim_profile(case.fox,case.pin,case.baseline)


def test_stopped_profile_reuses_actual_bound_observation_without_exec(case):
    retained=case.context.preclaim_profile(case.fox,case.pin,case.baseline)
    case.commands.clear();case.fox['State'].update(Running=False,Pid=0,Status='exited')
    case.context.A.command=lambda *a,**k:pytest.fail('Stopped container must not execute a profile probe')
    result=case.context.preclaim_profile(case.fox,case.pin,case.baseline,stopped=True,retained=retained)
    assert result['observation']=='retained_before_stop' and result['envelope']==retained['envelope']
    assert case.commands==[]
    with pytest.raises(M.TransitionError,match='RETAINED_FOCUSED_PROFILE_REQUIRED'):
        case.context.preclaim_profile(case.fox,case.pin,case.baseline,stopped=True)
    case.fox['Config']['Env'][0]='FOX_PROTOTYPE_PROFILE_FILE=/run/fox-opaf/prototype-other.json'
    with pytest.raises(M.TransitionError,match='ENVIRONMENT_CHANGED'):
        case.context.preclaim_profile(case.fox,case.pin,case.baseline,stopped=True,retained=retained)


def test_new_running_pair_reads_its_own_current_mount(case):
    case.context.preclaim_profile(case.fox,case.pin,case.baseline)
    case.commands.clear();new=deepcopy(case.fox);new_pin={'id':'9'*64,'image':'sha256:'+'8'*64}
    new.update(Id=new_pin['id'],Image=new_pin['image'])
    def read_new(argv,**kwargs):
        case.commands.append(argv);assert argv[2]==new_pin['id'] and argv[7]==A.PROTOTYPE_PROFILE_PROBE
        return M.cb(case.observed)
    case.context.A.command=read_new
    result=case.context.preclaim_profile(new,new_pin,case.baseline)
    assert len(case.commands)==1 and result['binding']['container_id']==new_pin['id']


def test_old_namespace_never_imports_new_prototype_client(case,monkeypatch):
    original=builtins.__import__
    def old_namespace(name,*args,**kwargs):
        if name.startswith(('forms2apex.prototype_authority_client','fox.prototype_authority_client')):
            raise ModuleNotFoundError('Unavailable in old namespace')
        return original(name,*args,**kwargs)
    monkeypatch.setattr(builtins,'__import__',old_namespace)
    assert case.context.preclaim_profile(case.fox,case.pin,case.baseline)['envelope']==case.envelope


def test_full_stopped_preclaim_path_never_executes_server_or_rebuilds_target(case,monkeypatch):
    context=case.context
    profile_observation=context.preclaim_profile(case.fox,case.pin,case.baseline)
    case.fox['State'].update(Running=False,Pid=0,Status='exited')
    tree={'files':{},'directories':[],'namespace':{'device':1,'inode':2}}
    request={'job_id':'fox-'+'4'*20};h=lambda value:M.sha(M.cb(value)[:-1])
    barrier={'kind':'current_serialized_read','observed_at_utc':datetime.now(timezone.utc).isoformat(),
        'binding':{'pair_sha256':'a'*64,'fox_tree_sha256':h(tree),'receiver_tree_sha256':h(tree)},
        'result':{'method':'GET','stage':'validate','job_id':request['job_id'],'status':404}}
    converter=deepcopy(case.fox);converter.update(Id='5'*64,Image='sha256:'+'6'*64,Name='forms2apex-mcp')
    core=deepcopy(case.fox);core.update(Id='7'*64,Name='oracle-applied-ai-label');core['State'].update(Running=True,Pid=20)
    for item in (case.fox,converter,core):
        item.update(Created='2026-11-01T00:00:00Z');item['State'].update(ExitCode=0,StartedAt='2026-11-01T00:00:00Z',FinishedAt='2026-11-02T00:00:00Z')
    items={v['Id']:v for v in (case.fox,converter,core)}
    context.old_pins={'fox':case.pin,'forms2apex-mcp':{'id':converter['Id'],'image':converter['Image']},
                      'oracle-applied-ai-label':{'id':core['Id'],'image':core['Image']}}
    baseline={'schema_version':1,'scope':'fox-reviewed-preclaim-terminal-baseline-v1','job_id':request['job_id'],
        'request_sha256':h(request),'source_binding':'b'*64,'target_profile_sha256':case.baseline['target_profile_sha256'],
        'fox_tree_sha256':h(tree),'receiver_tree_sha256':h(tree),'manifest_sha256':'c'*64,
        'original_handler':{'method':'POST','stage':'validate','status':409,'container_id':converter['Id'],
                            'completed_at_utc':'2026-11-02T00:00:00Z'}}
    baseline_path=Path('/home/opc/private/baseline.json');old_read=context.A.read
    context.A.read=lambda path,**kw:M.cb(baseline) if path==baseline_path else old_read(path,**kw)
    context.p.update(preclaim_preservation={'path':baseline_path.as_posix(),'sha256':M.sha(M.cb(baseline))},recovery={})
    context.old.release='d'*64;context.digest='e'*64
    context.service=SimpleNamespace(product=SimpleNamespace(PrivateJournal=lambda _:SimpleNamespace(root=Path('/journal'))))
    context.cfg['python']={'path':'/usr/bin/python3'}
    context.new_i={'layout':{'inventory':{'sha256':'f'*64}}}
    context.snapshot={'role_paths':{'fox-data':'/fox-data','converter-jobs':'/receiver'}}
    context.scope=lambda:{'fixed':'scope'}
    context.M=SimpleNamespace(configuration_signature=lambda *_:{'fixed':'configuration'})
    guards=[];context.S=SimpleNamespace(_host_guard=lambda _:guards.append(True) or {'scope':'fox-stopped-writer-observation-v1'})
    context._preclaim_live_proof={'profile':profile_observation,'proof':{'request':request,'technical':{}},'barrier':barrier}
    context._preclaim_sources=lambda:pytest.fail('Stopped path must retain actual prior target/proof, not rebuild a packet')
    context.A.inspect_container=lambda identity:items[identity]
    def command(argv,**kw):
        assert argv==['/usr/bin/podman','ps','-aq','--no-trunc'];return ('\n'.join(items)+'\n').encode()
    context.A.command=command
    reader=SimpleNamespace(PRECLAIM_MAINTENANCE_SCOPE='scope',preclaim_collector_source=lambda:'collector',
        classification_contract=lambda:SimpleNamespace(timestamp=lambda _:0,
            classify_row=lambda row,_:'LIVE' if row['running'] else 'STOPPED_NON_LIVE'))
    monkeypatch.setattr(M,'load',lambda *a:reader)
    def collect(argv,**kwargs):
        assert argv[:2]==['/usr/bin/podman','unshare'],'Stopped path attempted exec'
        return SimpleNamespace(returncode=0,stderr=b'',stdout=M.cb({'fox_tree':tree,'receiver_tree':tree,
            'receiver_manifest':{'manifest_sha256':'c'*64},'receiver_manifest_raw_sha256':'0'*64}))
    monkeypatch.setattr(M.subprocess,'run',collect)
    result=context.preclaim_read(stopped=True,new=False,lease=SimpleNamespace(require_active=lambda *a:None))
    assert result[request['job_id']]['readback']['producer']['receiver_servers']==0 and guards==[True]
    assert result[request['job_id']]['readback']['serialization_barrier']['kind']=='historical_before_stop'
