"""Modeled retained transition provenance and emitted readonly startup boundary."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest

from qa.operator import retirement_remote as remote


def model(monkeypatch, fault=None):
    release='a'*64;config='b'*64;provider='c'*64;reader='d'*64
    infrastructure={'forms2apex-mcp':{'id':'1'*64,'image':'sha256:'+'2'*64}}
    oldpin={'id':'3'*64,'image':'sha256:'+'4'*64}
    manifest={'project':{'queue_modules':{'verification_recovery.py':reader}}}
    docs={}
    def add(name,value,pin=None):
        raw=json.dumps(value,sort_keys=True).encode();path='/private/'+name
        docs[path]=raw
        # Release/config/provider pins are modeled trusted current identities.
        return {'path':path,'sha256':pin or hashlib.sha256(raw).hexdigest()}
    newrelease=add('release',manifest)
    release=newrelease['sha256']
    newadmission=add('new-admission',{'infrastructure':infrastructure});config=newadmission['sha256']
    oldadmission=add('old-admission',{'infrastructure':{'forms2apex-mcp':oldpin}})
    profile=json.loads((Path(__file__).resolve().parents[3]/'deployment/target-profile.jsn-project-v2.json').read_bytes())
    profile_raw=json.dumps(profile,sort_keys=True).encode()
    docs['/new/deployment/target-profile.jsn-project-v2.json']=profile_raw
    provider_ref=add('provider',{'target_profile':profile});provider=provider_ref['sha256']
    inventory=add('inventory',{'files':{'fox/fox/verification_recovery.py':reader,
        'deployment/target-profile.jsn-project-v2.json':hashlib.sha256(profile_raw).hexdigest()}})
    new=add('new',{'release':newrelease,'admission':newadmission,
        'provider':provider_ref,
        'layout':{'inventory':inventory,'release_root':'/new'}})
    old=add('old',{'admission':oldadmission})
    now=datetime.now(timezone.utc)
    baseline={'schema_version':1,'scope':'fox-reviewed-claimed-validation-terminal-baseline-v1',
        'job_id':'fox-'+'5'*20,'request_sha256':'6'*64,'source_binding':'7'*64,
        'target_profile_sha256':'8'*64,'fox_tree_sha256':'9'*64,'receiver_tree_sha256':'a'*64,
        'manifest_sha256':'b'*64,'original_handler':{'method':'POST','stage':'validate','status':409,
            'container_id':oldpin['id'],'completed_at_utc':(now-timedelta(hours=1)).isoformat()}}
    if fault=='terminal':baseline['original_handler']['status']=200
    if fault=='scope':baseline['scope']='fox-reviewed-preclaim-terminal-baseline-v1'
    baseline_ref=add('baseline',baseline)
    plan={'schema_version':2,'scope':'fox-current-pair-transition-v2',
        'new_installation':new,'old_installation':old,'preclaim_preservation':baseline_ref,
        'recovery':{'path':'/new/fox/fox/verification_recovery.py','sha256':reader}}
    plan_path='/home/opc/.local/share/fox-project-transitions/'+release+'/plan.json'
    docs[plan_path]=json.dumps(plan).encode()
    if fault=='hash':docs['/private/baseline']+=b' '
    state={'Running':False,'Pid':0,'Status':'exited','FinishedAt':now.isoformat()}
    item={'Id':oldpin['id'],'Name':'forms2apex-pre-upgrade-'+release[:16],
        'Image':oldpin['image'],'State':state}
    current={'Id':infrastructure['forms2apex-mcp']['id'],
        'Mounts':[{'Destination':'/run/fox-target/profile.json','Source':'/new/deployment/target-profile.jsn-project-v2.json',
            'Type':'bind','RW':False}], 'Config':{'Env':['F2A_TARGET_PROFILE_PATH=/run/fox-target/profile.json']}}
    if fault=='running':state.update(Running=True,Pid=42,Status='running')
    if fault=='old-id':item['Id']='0'*64
    if fault=='old-image':item['Image']='sha256:'+'0'*64
    if fault=='old-name':item['Name']='forms2apex-mcp'
    if fault=='early-finish':state['FinishedAt']=(now-timedelta(hours=2)).isoformat()
    if fault=='current-mount':current['Mounts'][0]['RW']=True
    if fault=='current-profile-env':current['Config']['Env']=[]
    if fault=='profile-bytes':docs['/new/deployment/target-profile.jsn-project-v2.json']+=b' '
    calls=[]
    class ModelPath(PurePosixPath):
        def resolve(self,strict=False):return self
        def is_symlink(self):return fault=='symlink' and str(self)==plan_path
        def stat(self):
            raw=docs[str(self)]
            return SimpleNamespace(st_mode=0o100600 if fault!='permissions' else 0o100644,
                st_nlink=1,st_uid=0,st_size=len(raw),st_dev=1,st_ino=2,st_mtime_ns=3)
        def read_bytes(self):calls.append(str(self));return docs[str(self)]
    def run(argv,**kw):
        assert argv[:2]==['podman','inspect']
        selected={oldpin['id']:item,infrastructure['forms2apex-mcp']['id']:current}[argv[2]]
        return SimpleNamespace(returncode=0,stderr=b'',stdout=json.dumps([selected]).encode())
    monkeypatch.setattr(remote,'Path',ModelPath)
    monkeypatch.setattr(remote,'subprocess',SimpleNamespace(run=run,PIPE=-1),raising=False)
    monkeypatch.setattr(remote,'guard',lambda value: None if value else (_ for _ in ()).throw(ValueError('closed')),raising=False)
    monkeypatch.setattr(os,'getuid',lambda:0,raising=False)
    v={'release_sha256':release,'configuration_sha256':config,
        'provider_configuration_sha256':provider,'manifest':manifest}
    return v,infrastructure,baseline_ref,calls,plan_path


def test_exact_current_transition_provenance_is_readonly(monkeypatch):
    v,infrastructure,baseline,calls,path=model(monkeypatch)
    first=remote._host_claimed_provenance(v,infrastructure)
    assert remote._host_claimed_provenance(v,infrastructure)==first
    assert first['original_terminal_sha256']==baseline['sha256']
    assert calls[0]==path and set(calls)==set(first['captures'])


@pytest.mark.parametrize('fault',['terminal','scope','hash','running','old-id','old-image',
    'old-name','early-finish','symlink','permissions','current-mount','current-profile-env','profile-bytes'])
def test_changed_or_untrusted_retained_provenance_fails_closed(monkeypatch,fault):
    v,infrastructure,_,_,_=model(monkeypatch,fault)
    with pytest.raises(ValueError):remote._host_claimed_provenance(v,infrastructure)


def test_claimed_startup_has_no_gateway_authority_and_emits_registered_provenance():
    source=remote.STARTUP_PRECLAIM
    branch=source.split(' if claimed:',1)[1].split(' else:',1)[0]
    assert 'preclaim_technical_read' in branch and 'witness=None' in branch
    assert 'configured_download_client' not in branch and 'adapter.' not in branch
    assert 'READ_ONLY_PAIRED_TREE' in remote.host_source.__globals__['_host_preclaim'].__code__.co_consts
