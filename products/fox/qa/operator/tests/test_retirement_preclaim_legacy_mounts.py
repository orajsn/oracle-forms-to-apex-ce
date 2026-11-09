"""Whole emitted host program with modeled OS/transport observations only.

Uses the retained actual legacy mount/rootfs shape. No OCI, process, service,
credential, model, database or mounted host path is accessed. Subprocess child
proofs are authored subsystem responses, not live admission acceptance.
"""
import base64
import builtins
from copy import deepcopy
from datetime import datetime,timedelta,timezone
import hashlib
import io
import json
from pathlib import Path,PurePosixPath
import subprocess
import sys
from types import SimpleNamespace
import urllib.request

import pytest

ROOT=Path(__file__).resolve().parents[3]
for folder in (ROOT,ROOT/'fox',ROOT/'converter'):
    if str(folder) not in sys.path:sys.path.insert(0,str(folder))

from qa.operator import retirement_remote as remote
from qa.operator.tests.test_retirement_remote import configuration,history,snapshot
from qa.operator.tests.test_hosted_release_binding import offline_configuration

OBSERVED=json.loads((ROOT/'deployment/tests/fixtures/activation-runtime-shape.json').read_bytes())
RECEIVER_ROOT='/home/opc/forms2apex/outputs/jobs'
JOB='fox-'+'f'*20


def model_host(monkeypatch,change=None,late_change=None):
    config=configuration();manifest,release,infrastructure,config_sha=config
    retained=history();now=datetime.now(timezone.utc)
    children={};calls=[];collections=[];frames=[]
    for name in ('fox','forms2apex-mcp','oracle-applied-ai-label'):
        observed=OBSERVED['containers'].get(name)
        item={'Id':infrastructure[name]['id'],'Name':name,'Image':infrastructure[name]['image'],
            'Created':(now-timedelta(hours=1)).isoformat(),
            'State':{'Running':True,'Pid':100+len(children),'Status':'running','ExitCode':0,
                'StartedAt':(now-timedelta(minutes=50)).isoformat(),'FinishedAt':'0001-01-01T00:00:00Z'},
            'Config':{'User':observed['user'] if observed else '1000','Env':[]},
            'HostConfig':deepcopy(observed['host']) if observed else {'ReadonlyRootfs':False},
            'Mounts':deepcopy(observed['mounts']) if observed else []}
        if name=='fox':
            for mount in item['Mounts']:
                if mount['Destination']=='/run/fox-native/profile.json':mount['Source']=manifest['opaf_profile']['host_path']
        children[name]=item
    assert children['fox']['HostConfig']['ReadonlyRootfs'] is True
    assert children['forms2apex-mcp']['HostConfig']['ReadonlyRootfs'] is False
    mount=next(row for row in children['forms2apex-mcp']['Mounts'] if row['Destination']=='/opt/forms2apex/outputs/jobs')
    assert mount=={'Destination':'/opt/forms2apex/outputs/jobs','RW':True,'Source':RECEIVER_ROOT,'Type':'bind'}
    tree={'files':{'inert.json':{'sha256':'a'*64,'bytes':2}},'directories':[],
          'namespace':{'device':1,'inode':10}}
    receiver_tree={**deepcopy(tree),'namespace':{'device':1,'inode':20}}
    h=lambda v:hashlib.sha256(json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
    startup={'jobs':{JOB:{'technical':{'status':'PURE_TECHNICAL_READ_ONLY_MATCH','fox_tree_sha256':h(tree),
        'request_sha256':'b'*64},'request':{'source_binding':'c'*64},
        'witness':{'witness_sha256':'d'*64},'target_profile_sha256':'e'*64}},'collector':'AUTHORED_READONLY_COLLECTOR'}
    collected={'fox_tree':tree,'receiver_tree':receiver_tree,'receiver_manifest':{'manifest_sha256':'9'*64},
               'receiver_manifest_raw_sha256':'8'*64}
    value=snapshot(config,retained,observed=now)
    # Host-owned facts are added by the real emitted source, not the child stub.
    for key in ('inventory','observed_at_utc','host_scope_verified','fox_image'):value.pop(key)
    request={'operation':'retired_history_read','apply':False,'manifest':manifest,'release_sha256':release,
        'configuration_sha256':config_sha,'provider_configuration_sha256':manifest['hosted_runtime_configuration_sha256'],
        'history':retained,'for_startup':True}
    if change:change(children,request)
    profile_path=manifest['opaf_profile']['host_path']
    profile_raw=(ROOT/manifest['opaf_profile']['path']).read_bytes()

    class ModeledPath(PurePosixPath):
        def resolve(self,strict=False):
            if str(self)==RECEIVER_ROOT and change and getattr(change,'alias',False):return ModeledPath('/unbound/alias')
            return self
        def is_symlink(self):return False
        def is_file(self):return str(self)==profile_path
        def stat(self):
            assert str(self)==profile_path
            return SimpleNamespace(st_size=len(profile_raw))
        def open(self,mode='r',**kwargs):
            assert str(self)==profile_path and mode=='rb','No credential or unrelated file read permitted'
            return io.BytesIO(profile_raw)
    scope=offline_configuration()['target_profile']['oci']
    payload={'request':request,'cli_scope':scope}
    def urlopen(url,**kwargs):
        address=url.full_url if isinstance(url,urllib.request.Request) else url
        if address=='http://169.254.169.254/opc/v2/instance/':
            body={'id':scope['instance_id'],'compartmentId':scope['compartment_id'],'canonicalRegionName':scope['region']}
        else:
            assert address=='http://127.0.0.1:8100/api/health'
            body={'status':'ok','product':'FOX','worker':{'healthy':True,'state':'idle'}}
        return io.BytesIO(json.dumps(body).encode())
    def run(argv,**kwargs):
        calls.append(argv)
        def result(data):return SimpleNamespace(returncode=0,stderr=b'',stdout=json.dumps(data).encode())
        if argv[:4]==['podman','ps','-aq','--no-trunc']:
            return SimpleNamespace(returncode=0,stderr=b'',stdout=('\n'.join(sorted(row['Id'] for row in children.values()))+'\n').encode())
        if argv[:2]==['podman','inspect']:
            selected=[]
            for identifier in argv[2:]:
                item=children.get(identifier) or next(row for row in children.values() if row['Id']==identifier)
                selected.append(deepcopy(item))
            return result(selected)
        if argv[:2]==['podman','top']:
            assert argv[2:]==[infrastructure['forms2apex-mcp']['id'],'pid']
            return SimpleNamespace(returncode=0,stderr=b'',stdout=b'PID\n1\n')
        if argv[:2]==['podman','unshare']:
            assert argv[-1]==startup['collector']
            packet=json.loads(kwargs['input']);collections.append(packet)
            assert packet=={'fox_data':'/home/opc/fox/data','receiver_jobs':RECEIVER_ROOT,'job_id':JOB}
            return result(collected)
        assert argv[:4]==['podman','exec','-i',infrastructure['fox']['id']]
        if argv[-1]==remote.STARTUP_PRECLAIM:return result(startup)
        # Actual main container reader source/framing is preserved. Its full
        # historical proof response is modeled; existing backend tests cover it.
        code,body,_=kwargs['input'].split(b'\n',2)
        assert base64.b64decode(code).decode()==remote.container_source(release,config_sha)
        frame=json.loads(body);frames.append(frame)
        assert frame['paired_preclaim'][JOB]['readback']['receiver_tree']==receiver_tree
        if late_change:late_change(children,collected)
        return result(value)
    original_import=builtins.__import__
    def modeled_import(name,globals=None,locals=None,fromlist=(),level=0):
        if name=='pathlib' and (globals or {}).get('__file__')=='<whole-legacy-preclaim-host>':
            import pathlib
            return SimpleNamespace(**{**vars(pathlib),'Path':ModeledPath})
        return original_import(name,globals,locals,fromlist,level)
    def forbidden(*args,**kwargs):pytest.fail('Real process/network operation attempted')
    with monkeypatch.context() as patch:
        patch.setattr(subprocess,'run',run);patch.setattr(subprocess,'Popen',forbidden)
        patch.setattr(urllib.request,'urlopen',urlopen);patch.setattr(builtins,'__import__',modeled_import)
        patch.setattr(sys,'stdin',SimpleNamespace(buffer=io.BytesIO(json.dumps(payload).encode())))
        output=io.StringIO();patch.setattr(sys,'stdout',output)
        exec(compile(remote.host_source(release,config_sha,infrastructure),'<whole-legacy-preclaim-host>','exec'),
             {'__file__':'<whole-legacy-preclaim-host>'})
    return json.loads(output.getvalue()),config,retained,calls,collections,frames


def test_positive_whole_host_uses_approved_legacy_converter_and_exact_mount(monkeypatch):
    value,config,retained,calls,collections,frames=model_host(monkeypatch)
    assert value['status']=='RETIRED_HISTORY_OBSERVED',value
    assert len(collections)==2 and len(frames)==1
    assert value['read_only'] is True and value['automatic_replay_permitted'] is False
    assert 'startup_admitted' not in value
    manifest,release,infrastructure,config_sha=config
    assert remote.validate_snapshot(value,history=retained,current_release=release,configuration_sha256=config_sha,
        provider_configuration_sha256=manifest['hosted_runtime_configuration_sha256'],images=manifest['images'],
        infrastructure=infrastructure,for_startup=True)==value
    assert all(argv[0]=='podman' and argv[1] in ('inspect','ps','top','exec','unshare') for argv in calls)


@pytest.mark.parametrize('fault',['wrong-root','relative-root','fox-prefix-root','wrong-destination',
    'missing-mount','mount-type','mount-readonly','mount-rw-one',
    'converter-id','converter-image','converter-name','converter-rootfs-true','converter-rootfs-missing',
    'converter-rootfs-zero','fox-id','fox-image','fox-name','fox-rootfs-false','fox-rootfs-one',
    'fox-rootfs-missing','not-running','pid-zero','caller-false-override'])
def test_legacy_guard_refuses_every_unbound_shape(monkeypatch,fault):
    def changed(items,request):
        converter=items['forms2apex-mcp'];fox=items['fox']
        mount=next(v for v in converter['Mounts'] if v['Destination']=='/opt/forms2apex/outputs/jobs')
        if fault=='wrong-root':mount['Source']='/home/opc/forms2apex/outputs/jobs-old'
        elif fault=='relative-root':mount['Source']='home/opc/forms2apex/outputs/jobs'
        elif fault=='fox-prefix-root':mount['Source']='/home/opc/fox/unbound-receiver'
        elif fault=='wrong-destination':mount['Destination']='/opt/forms2apex/outputs/jobs-old'
        elif fault=='missing-mount':converter['Mounts'].remove(mount)
        elif fault=='mount-type':mount['Type']='volume'
        elif fault=='mount-readonly':mount['RW']=False
        elif fault=='mount-rw-one':mount['RW']=1
        elif fault=='converter-id':converter['Id']='9'*64
        elif fault=='converter-image':converter['Image']='sha256:'+'9'*64
        elif fault=='converter-name':converter['Name']='future-generic-service'
        elif fault=='converter-rootfs-true':converter['HostConfig']['ReadonlyRootfs']=True
        elif fault=='converter-rootfs-missing':converter['HostConfig'].pop('ReadonlyRootfs')
        elif fault=='converter-rootfs-zero':converter['HostConfig']['ReadonlyRootfs']=0
        elif fault=='fox-id':fox['Id']='9'*64
        elif fault=='fox-image':fox['Image']='sha256:'+'9'*64
        elif fault=='fox-name':fox['Name']='future-generic-fox'
        elif fault=='fox-rootfs-false':fox['HostConfig']['ReadonlyRootfs']=False
        elif fault=='fox-rootfs-one':fox['HostConfig']['ReadonlyRootfs']=1
        elif fault=='fox-rootfs-missing':fox['HostConfig'].pop('ReadonlyRootfs')
        elif fault=='not-running':converter['State']['Running']=False
        elif fault=='pid-zero':converter['State']['Pid']=0
        else:
            fox['HostConfig']['ReadonlyRootfs']=False
            request['caller_role_contract']={'fox':False,'future-role':False}
    value,_,_,_,_,frames=model_host(monkeypatch,changed)
    assert value=={'status':'STOPPED','code':'QUEUE_HOST_OUTCOME_UNCONFIRMED_NO_REPLAY','automatic_replay_permitted':False}
    assert frames==[]


def test_canonical_receiver_root_is_still_required(monkeypatch):
    def alias(*args):pass
    alias.alias=True
    value,_,_,_,_,frames=model_host(monkeypatch,alias)
    assert value['status']=='STOPPED' and frames==[]


@pytest.mark.parametrize('fault',['configuration','config-env','mount-source','mount-destination','mount-type',
    'mount-rw','container-id','container-image','namespace','fox-tree','receiver-manifest','container-state',
    'container-name','container-pid'])
def test_before_after_fingerprints_and_paired_rechecks_still_refuse_drift(monkeypatch,fault):
    def drift(items,collected):
        converter=items['forms2apex-mcp']
        mount=next(v for v in converter['Mounts'] if v['Destination']=='/opt/forms2apex/outputs/jobs')
        if fault=='configuration':converter['HostConfig']['ReadonlyRootfs']=True
        elif fault=='config-env':converter['Config']['Env'].append('UNBOUND=true')
        elif fault=='mount-source':mount['Source']='/home/opc/forms2apex/outputs/jobs-old'
        elif fault=='mount-destination':mount['Destination']='/opt/forms2apex/outputs/jobs-old'
        elif fault=='mount-type':mount['Type']='volume'
        elif fault=='mount-rw':mount['RW']=False
        elif fault=='container-id':converter['Id']='9'*64
        elif fault=='container-image':converter['Image']='sha256:'+'9'*64
        elif fault=='namespace':collected['receiver_tree']['namespace']['inode']+=1
        elif fault=='fox-tree':collected['fox_tree']['files']['inert.json']['sha256']='0'*64
        elif fault=='receiver-manifest':collected['receiver_manifest']['manifest_sha256']='0'*64
        elif fault=='container-name':converter['Name']='future-generic-service'
        elif fault=='container-pid':converter['State']['Pid']+=1
        else:converter['State']['Running']=False
    value,_,_,_,collections,frames=model_host(monkeypatch,late_change=drift)
    assert len(frames)==1 and collections  # Guard ran after the modeled child read.
    assert value=={'status':'STOPPED','code':'QUEUE_HOST_OUTCOME_UNCONFIRMED_NO_REPLAY','automatic_replay_permitted':False}
