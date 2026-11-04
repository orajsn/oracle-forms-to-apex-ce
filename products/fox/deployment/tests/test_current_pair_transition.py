"""Transition contracts only; no cloud, services, journals or live data used."""
from copy import deepcopy
import importlib.util
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import pytest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('current_transition_contracts',ROOT/'deployment/current_pair_transition.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
support_spec=importlib.util.spec_from_file_location('transition_support_contracts',ROOT/'deployment/cutover_project_release.py')
S=importlib.util.module_from_spec(support_spec);support_spec.loader.exec_module(S)


def plan():
    value={'schema_version':1,'scope':M.SCOPE,'controller_sha256':'a'*64}
    for number,name in enumerate(M.REFS):
        value[name]={'path':'/home/opc/private/'+name+'.json','sha256':format(number+1,'x')*64}
    value['old_unit']['path']=str(M.UNIT)
    return value


def test_plan_is_exact_and_returns_no_implicit_authority():
    value=plan();raw=M.cb(value)
    assert M.plan_document(raw,M.sha(raw))==value
    assert 'apply' not in value and 'approved' not in value


@pytest.mark.parametrize('fault',['sha','extra','bool','scope','missing','path','traversal','drive','ref-extra','same-I','same-unit'])
def test_invalid_plan_cannot_reach_host_or_effects(fault,monkeypatch):
    value=plan()
    if fault=='extra':value['approved']=True
    elif fault=='bool':value['schema_version']=True
    elif fault=='scope':value['scope']='unknown'
    elif fault=='missing':del value['snapshot']
    elif fault=='path':value['snapshot']['path']='relative'
    elif fault=='traversal':value['snapshot']['path']='/home/opc/../snapshot'
    elif fault=='drive':value['snapshot']['path']='C:/private/file'
    elif fault=='ref-extra':value['helper']['ready']=True
    elif fault=='same-I':value['new_installation']=deepcopy(value['old_installation'])
    elif fault=='same-unit':value['new_unit']['path']=str(M.UNIT)
    raw=M.cb(value)
    monkeypatch.setattr(M,'load',lambda *_:pytest.fail('Invalid plan reached an import'))
    with pytest.raises(M.TransitionError):M.plan_document(raw,'0'*64 if fault=='sha' else M.sha(raw))


@pytest.mark.parametrize('program',['BACKEND','NEW_PROBE'])
def test_actual_serialized_read_only_programs_compile_without_running(program):
    compile(getattr(M,program),program,'exec')


def test_new_probe_does_not_pump_replay_accept_or_run_a_conversion_tool():
    for forbidden in ('.pump(','.reserve_retry(','.complete_retry(','.import_validated_draft(','.generate_apex_draft(','.accept('):
        assert forbidden not in M.NEW_PROBE
    assert "completed_jobs']==[]" in M.NEW_PROBE
    assert 'admission.check()' in M.NEW_PROBE


def container():
    return {'Id':'1'*64,'Name':'fox','Image':'a'*64,'Config':{'Env':['SAFE=synthetic']},
        'HostConfig':{},'Mounts':[],'ProcessLabel':'synthetic','MountLabel':'synthetic',
        'State':{'Running':True,'Pid':12,'StartedAt':'2026-11-04T00:00:00Z'}}


@pytest.mark.parametrize('fault',['none','id','name','image','state','pid','config'])
def test_exact_container_observation_cannot_hide_changes(fault):
    item=container();expected=S.configuration_signature(None,item)
    if fault=='id':item['Id']='2'*64
    elif fault=='name':item['Name']='different'
    elif fault=='image':item['Image']='b'*64
    elif fault=='state':item['State']['Running']=False
    elif fault=='pid':item['State']['Pid']=True
    elif fault=='config':item['Config']['Env']=['SAFE=changed']
    context=object.__new__(M.Transition)
    context.A=SimpleNamespace(inspect_container=lambda _id:item);context.M=S
    if fault=='none':assert context.check_container({'id':'1'*64,'image':'sha256:'+'a'*64},'fox',expected,running=True)==item
    else:
        with pytest.raises(M.TransitionError):context.check_container({'id':'1'*64,'image':'sha256:'+'a'*64},'fox',expected,running=True)


def test_effect_scope_is_rechecked_before_the_original_create_once_boundary():
    context=object.__new__(M.Transition);trace=[]
    context.scope=lambda:trace.append('real-scope-boundary')
    context.root=Path('/synthetic/operation');context.digest='a'*64
    context.A=SimpleNamespace(create_once=lambda *args:(trace.append('create-once-boundary') or b''))
    context.effect('synthetic',['synthetic-command'])
    assert trace==['real-scope-boundary','create-once-boundary']


@pytest.mark.skipif(os.name!='posix',reason='Actual no-follow ownership checks')
def test_initial_read_refuses_a_link_even_with_identical_bytes(tmp_path):
    target=tmp_path/'source.py';target.write_bytes(b'synthetic source\n')
    linked=tmp_path/'link.py';linked.symlink_to(target)
    with pytest.raises(M.TransitionError):M.initial_read(linked)
