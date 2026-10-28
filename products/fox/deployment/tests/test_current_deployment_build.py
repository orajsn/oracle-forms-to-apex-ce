"""Current-deployment build guards; HTTP/Podman observations are synthetic."""
from copy import deepcopy
import importlib.util
import io
import os
from pathlib import Path, PurePosixPath
import subprocess
from types import SimpleNamespace

import pytest

spec=importlib.util.spec_from_file_location('current_build_test',Path(__file__).resolve().parents[1]/'build_project_release.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)


def declared():
    return {'schema_version':1,'scope':'fox-hosted-admission-v1','provider_configuration_sha256':'a'*64,
        'current_release_sha256':'b'*64,'infrastructure':{name:{'id':str(n)*64,'image':'sha256:'+str(n+3)*64}
            for n,name in enumerate(M.BASE,1)}}


def reference(value=None):
    raw=M.canonical(declared() if value is None else value)
    return raw,M.digest(raw)


@pytest.mark.parametrize('change',['schema_bool','scope','extra','missing_role','duplicate_id','bad_image','extra_pin','release_hash','wrong_digest','uncanonical'])
def test_declaration_needs_exact_independently_pinned_bytes(change):
    value=declared()
    if change=='schema_bool':value['schema_version']=True
    elif change=='scope':value['scope']='caller-approved'
    elif change=='extra':value['approved']=True
    elif change=='missing_role':del value['infrastructure']['fox']
    elif change=='duplicate_id':value['infrastructure']['fox']['id']=value['infrastructure']['forms2apex-mcp']['id']
    elif change=='bad_image':value['infrastructure']['fox']['image']='latest'
    elif change=='extra_pin':value['infrastructure']['fox']['ready']=True
    elif change=='release_hash':value['current_release_sha256']='invalid'
    raw,digest=reference(value)
    if change=='wrong_digest':digest='0'*64
    elif change=='uncanonical':raw+=b' ';digest=M.digest(raw)
    with pytest.raises(M.StageError):M.deployment_document((raw,digest))


def guard_case(monkeypatch):
    value=declared();ref=reference(value)
    containers=[{'Id':pin['id'],'Image':pin['image'],'Name':name,
        'State':{'Running':True,'StartedAt':'2026-10-27T00:00:00Z','Pid':100+n},
        'Config':{'Env':['FOX_VERIFIER_RELEASE_SHA256='+value['current_release_sha256'],'FOX_CONVERSION_PROFILE=native-project-v1'] if name=='fox' else []},
        'HostConfig':{'AutoRemove':False},'Mounts':[{'Source':'/home/opc/live/'+name}]} for n,(name,pin) in enumerate(value['infrastructure'].items())]
    metadata={'id':M.SCOPE['instance_id'],'compartmentId':M.SCOPE['compartment_id'],'canonicalRegionName':M.SCOPE['region']}
    calls=[]
    monkeypatch.setattr(M.os,'name','posix');monkeypatch.setattr(M.os,'geteuid',lambda:1000,raising=False)
    monkeypatch.setattr(M,'Path',PurePosixPath)
    monkeypatch.setattr(M.urllib.request,'urlopen',lambda *a,**kw:io.BytesIO(M.canonical(metadata)))
    def command(argv,**kw):
        calls.append(argv);assert argv[:2]==['podman','inspect'] and len(argv)==5 and set(argv[2:])==set(M.BASE)
        return M.canonical(containers)
    monkeypatch.setattr(M,'command',command)
    return ref,containers,metadata,calls


def test_current_deployment_is_explicit_and_does_not_redefine_legacy_baseline(monkeypatch):
    ref,containers,metadata,calls=guard_case(monkeypatch)
    target=PurePosixPath('/home/opc/private-builds/new-source')
    before=deepcopy(M.BASE)
    actual=M.guarded_host(target,deployment=ref)
    assert actual['deployment_sha256']==ref[1] and actual['release_sha256']=='b'*64
    assert actual['containers']['fox']['pid']==100 and len(actual['containers']['fox']['configuration_sha256'])==64
    assert M.BASE==before
    with pytest.raises(M.StageError,match='BASELINE_CONTAINER_CHANGED'):M.guarded_host(target)
    assert len(calls)==2


@pytest.mark.parametrize('change',['compartment','instance','region','id','image','stopped','pid','release','profile','duplicate_env','mount_overlap'])
def test_other_scope_or_runtime_identity_rejected_without_a_write(monkeypatch,change):
    ref,containers,metadata,calls=guard_case(monkeypatch)
    if change=='compartment':metadata['compartmentId']='other'
    elif change=='instance':metadata['id']='other'
    elif change=='region':metadata['canonicalRegionName']='other'
    elif change=='id':containers[0]['Id']='f'*64
    elif change=='image':containers[0]['Image']='sha256:'+'f'*64
    elif change=='stopped':containers[0]['State']['Running']=False
    elif change=='pid':containers[0]['State']['Pid']=True
    elif change=='release':containers[0]['Config']['Env'][0]='FOX_VERIFIER_RELEASE_SHA256='+'f'*64
    elif change=='profile':containers[0]['Config']['Env'][1]='FOX_CONVERSION_PROFILE=legacy'
    elif change=='duplicate_env':containers[0]['Config']['Env']+=containers[0]['Config']['Env'][:1]
    else:containers[0]['Mounts']=[{'Source':'/home/opc/private-builds'}]
    with pytest.raises(M.StageError):M.guarded_host(PurePosixPath('/home/opc/private-builds/new-source'),deployment=ref)
    if change in ('compartment','instance','region'):assert not calls


def test_before_after_comparison_detects_static_configuration_and_pid_changes(monkeypatch):
    ref,containers,metadata,calls=guard_case(monkeypatch)
    target=PurePosixPath('/home/opc/private-builds/new-source');before=M.guarded_host(target,deployment=ref)
    containers[0]['Config']['Env'].append('SYNTHETIC_SETTING=changed')
    assert M.guarded_host(target,deployment=ref)!=before
    containers[0]['Config']['Env'].pop();containers[0]['State']['Pid']+=1
    assert M.guarded_host(target,deployment=ref)!=before


def test_capacity_is_checked_from_actual_graphroot_not_workspace_guess(tmp_path,monkeypatch):
    monkeypatch.setattr(M,'command',lambda argv:str(tmp_path).encode())
    monkeypatch.setattr(M.os,'statvfs',lambda path:SimpleNamespace(f_bavail=3*1024**3,f_frsize=1),raising=False)
    assert M.build_capacity()['minimum_bytes']==2*1024**3
    monkeypatch.setattr(M.os,'statvfs',lambda path:SimpleNamespace(f_bavail=1024,f_frsize=1),raising=False)
    with pytest.raises(M.StageError,match='CAPACITY_LOW'):M.build_capacity()


@pytest.mark.skipif(os.name!='posix',reason='Actual Linux proc identity')
def test_actual_owned_build_process_identity_and_terminal_absence():
    process=subprocess.Popen(['/bin/sleep','10'])
    try:
        first=M.build_process_identity(process.pid)
        assert first['pid']==process.pid and first['start_ticks']>0 and len(first['boot_id'])==36
        assert M.build_process_identity(process.pid)==first
    finally:
        process.terminate();process.wait(timeout=5)
    assert M.build_process_identity(process.pid) is None
