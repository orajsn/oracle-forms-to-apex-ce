"""Explicit current-installation candidate preparation, not cutover authority.

Saved shapes and cloud/container observations are synthetic. POSIX probes use
actual source, private files and production I/C/R/D/inventory validators.
"""
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path,PurePosixPath
import subprocess
import sys
import pytest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('current_candidates',ROOT/'deployment/activate_project_release.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
from test_activate_project_release import plan,baseline_item,profile,BINDING_PROBE


def upgrade_plan():
    value=plan();value.update(schema_version=2,scope=M.UPGRADE_SCOPE,
        current_installation={'path':'/home/opc/.config/current/I.json','sha256':'9'*64})
    return value


def test_explicit_current_reference_is_independent_and_legacy_shape_stays_intact():
    old=plan();new=upgrade_plan()
    assert M.plan_document(M.canonical(old),M.sha(M.canonical(old)))==old
    assert M.plan_document(M.canonical(new),M.sha(M.canonical(new)))==new
    assert 'current_installation' not in old and old['schema_version']==1
    assert old['scope']!=new['scope'] and old['helper_sha256']==new['helper_sha256']


@pytest.mark.parametrize('fault',['scope','missing','extra','bool','hash','relative','traversal','inside','colliding','extra_ref'])
def test_bad_upgrade_reference_stops_before_any_file_or_effect(fault,monkeypatch):
    value=upgrade_plan()
    if fault=='scope':value['scope']=M.SCOPE
    elif fault=='missing':value.pop('current_installation')
    elif fault=='extra':value['caller_approved']=True
    elif fault=='bool':value['schema_version']=True
    elif fault=='hash':value['current_installation']['sha256']='invalid'
    elif fault=='relative':value['current_installation']['path']='I.json'
    elif fault=='traversal':value['current_installation']['path']='/home/opc/../I.json'
    elif fault=='inside':value['current_installation']['path']=value['bundle_root']+'/I.json'
    elif fault=='colliding':value['current_installation']['path']=value['provider']['path']
    else:value['current_installation']['ready']=True
    monkeypatch.setattr(M,'read',lambda *_a,**_k:pytest.fail('Pure plan validation must not read files'))
    with pytest.raises(M.ActivationError):M.plan_document(M.canonical(value),M.sha(M.canonical(value)))


@pytest.mark.parametrize('role',['fox','converter'])
def test_current_profile_mounts_need_explicit_measured_source_paths(role):
    old=baseline_item(role);value=upgrade_plan();release={'images':{'fox':'sha256:'+'a'*64,'converter':'sha256:'+'b'*64}}
    profiles={'fox':'/private/current-bundle/deployment/project-opaf-profile-v2.json',
        'converter':'/private/current-bundle/deployment/target-profile.jsn-project-v2.json'}
    destination='/run/fox-native/profile.json' if role=='fox' else '/run/fox-target/profile.json'
    next(m for m in old['Mounts'] if m['Destination']==destination)['Source']=profiles[role]
    original=deepcopy(old)
    with pytest.raises(M.ActivationError):M.candidate_argv(role,old,value,release,PurePosixPath('/private/new-stage'))
    argv,mounts=M.candidate_argv(role,old,value,release,PurePosixPath('/private/new-stage'),baseline_profiles=profiles)
    assert old==original
    assert mounts[destination][0].startswith(value['bundle_root']+'/deployment/')
    assert argv[:2]==['/usr/bin/podman','create']
    assert not {'start','stop','restart','rm','--replace','--rm'}&set(argv)
    assert M.BASE_PROFILES['fox']!=profiles['fox']


# Reuse the existing actual-source builder up to the final binding probe, then
# build a separately pinned existing installation. No live host/Podman call.
CURRENT_PROBE=BINDING_PROBE.split(" for name in tuple(sys.modules):",1)[0]+r'''
 from qa.operator import hosted_service as service,retirement_remote as remote
 pins={'fox':{'id':'1'*64,'image':images['fox']},
  'forms2apex-mcp':{'id':'2'*64,'image':images['converter']},
  'oracle-applied-ai-label':{'id':tool.BASE['oracle-applied-ai-label'][0],
   'image':'sha256:'+tool.BASE['oracle-applied-ai-label'][1]}}
 admission=remote.admission_configuration(rsha,csha,pins)
 d=tool.canonical(admission);(stage/'D.json').write_bytes(d)
 installation={'schema_version':1,'scope':service.SCOPE,
  'provider':{'path':str(stage/'C.json'),'sha256':csha},
  'release':{'path':str(stage/'R.json'),'sha256':rsha},
  'admission':{'path':str(stage/'D.json'),'sha256':tool.sha(d)},
  'retirement':{'path':str(stage/'private-state/handoffs/old-archive'),'attestation_sha256':'1'*64},
  'layout':{'release_root':str(root),'inventory':{'path':str(stage/'source-inventory.json'),'sha256':b}},
  'bounds':{'max_jobs':1,'max_polls':1,'max_seconds':60,'poll_seconds':1},'batch_pause_seconds':1}
 i=tool.canonical(installation);(stage/'I.json').write_bytes(i)
 current_plan={'schema_version':2,'current_installation':{'path':str(stage/'I.json'),'sha256':tool.sha(i)}}
 if mutation=='wrong-I-sha':current_plan['current_installation']['sha256']='0'*64
 if mutation=='changed-C':(stage/'C.json').write_bytes(c+b' ')
 if mutation=='changed-D':(stage/'D.json').write_bytes(d+b' ')
 if mutation=='changed-inventory':(stage/'source-inventory.json').write_bytes(inventory+b' ')
 if mutation=='source-link':
  source=root/'qa/operator/contracts.py';raw=source.read_bytes();source.unlink()
  other=stage/'not-source.py';other.write_bytes(raw);source.symlink_to(other)
 try:
  current=tool.CurrentBaseline(current_plan)
  if mutation=='recheck-I':
   (stage/'I.json').write_bytes(i+b' ');current.recheck();raise AssertionError('MUTATION_ACCEPTED')
  if mutation=='source-pin':current.manifest['code']['contracts.py']='0'*64
  if mutation=='infrastructure':current.infrastructure['fox']['id']='9'*64
  if mutation=='configuration':current.configuration['target_profile']['tested_versions']['apex']='26.1.6'
  if mutation=='provider':current.provider=object()
  if mutation in ('source-pin','infrastructure','configuration','provider'):
   current.recheck();raise AssertionError('MUTATION_ACCEPTED')
  assert mutation=='none','MUTATION_ACCEPTED'
  assert current.release_sha256==rsha and current.infrastructure==pins
  assert current.profile_paths['fox']==str(root/'deployment/project-opaf-profile-v2.json')
  assert runtime._selected is runtime._UNSELECTED
  result={'status':'ACTUAL_CURRENT_DECLARATION_VERIFIED','runtime_selected':False,'host_contacted':False}
 except Exception as error:
  if mutation=='none':raise
  assert str(error)!='MUTATION_ACCEPTED'
  result={'status':'REJECTED','host_contacted':False}
 print(json.dumps(result,sort_keys=True))
'''


@pytest.mark.skipif(os.name!='posix',reason='Actual private POSIX source/installation checks')
@pytest.mark.parametrize('mutation',['none','wrong-I-sha','changed-C','changed-D','changed-inventory','source-link','recheck-I',
    'source-pin','infrastructure','configuration','provider'])
def test_actual_current_installation_and_source_are_checked_without_selection_or_contact(mutation):
    outcome=subprocess.run([sys.executable,'-B','-c',CURRENT_PROBE,str(ROOT),mutation],
        capture_output=True,text=True,timeout=90,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
    assert outcome.returncode==0,outcome.stderr
    value=json.loads(outcome.stdout)
    assert value['host_contacted'] is False
    assert value['status']==('ACTUAL_CURRENT_DECLARATION_VERIFIED' if mutation=='none' else 'REJECTED')
