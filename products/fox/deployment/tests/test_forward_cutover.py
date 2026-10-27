"""Measured OCI metadata, single-start waits and forward-only sequencing.

All services, authority and host IO below are synthetic test boundaries. No
running container, password, cloud resource or historical file is accessed.
"""
from contextlib import contextmanager
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

ROOT=Path(__file__).resolve().parents[2]
for directory in (ROOT,ROOT/'fox',ROOT/'converter'):
    if str(directory) not in sys.path:sys.path.insert(0,str(directory))
spec=importlib.util.spec_from_file_location('forward_cutover_test',ROOT/'deployment/cutover_project_release.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)


def item(identity='1'*64,name='forms2apex-mcp',*,running=False,image='a'*64):
    return {'Id':identity,'Name':name,'Image':image,'Created':'2026-10-26T00:00:00Z',
        'Config':{'Env':['SYNTHETIC=fixture-only'],'User':'10001','StopSignal':15,'Annotations':{'custom':'retained'}},
        'HostConfig':{'AutoRemove':False},'Mounts':[],'ProcessLabel':'synthetic-label','MountLabel':'synthetic-mount',
        'State':{'Running':running,'Pid':12 if running else 0,'Status':'running' if running else 'created','ExitCode':0,
            'StartedAt':'2026-10-27T01:00:00Z' if running else '0001-01-01T00:00:00Z','FinishedAt':'0001-01-01T00:00:00Z'},
        'NetworkSettings':{'Networks':{'forms2apex':{'IPAddress':'10.89.1.3'}}}}


def started(before):
    result=deepcopy(before);result['State'].update(Running=True,Pid=12,Status='running',StartedAt='2026-10-27T01:00:00Z')
    result['Config']['Annotations'].update({'io.container.manager':'libpod','org.opencontainers.image.stopSignal':'15'})
    return result


def test_only_proven_engine_annotations_are_projected_without_mutating_observation():
    before=item();after=started(before);saved=deepcopy(after)
    expected=M.configuration_signature(None,before)
    assert M.configuration_signature(None,after)!=expected
    assert M.configuration_matches(None,after,expected) is True and after==saved
    assert M.configuration_matches(None,before,expected) is True


@pytest.mark.parametrize('change',['manager','signal','boolean_signal','extra_annotation','env','image','mount','user','never_started'])
def test_metadata_projection_does_not_hide_any_other_change(change):
    before=item();after=started(before)
    if change=='manager':after['Config']['Annotations']['io.container.manager']='other-runtime'
    elif change=='signal':after['Config']['Annotations']['org.opencontainers.image.stopSignal']='9'
    elif change=='boolean_signal':after['Config']['StopSignal']=True
    elif change=='extra_annotation':after['Config']['Annotations']['unexpected']='not ignored'
    elif change=='env':after['Config']['Env']=['SYNTHETIC=changed']
    elif change=='image':after['Image']='b'*64
    elif change=='mount':after['Mounts']=[{'Destination':'/unexpected'}]
    elif change=='user':after['Config']['User']='0'
    else:after['State']['StartedAt']='0001-01-01T00:00:00Z'
    assert M.configuration_matches(None,after,M.configuration_signature(None,before)) is False


def test_wait_observes_a_single_async_start_without_issuing_another_effect(monkeypatch):
    before=item();after=started(before);observations=[before,after];calls=[]
    h=object.__new__(M.HostCutover)
    h.created={'candidates':{'converter':{'id':before['Id']}}};h.release={'images':{'converter':'sha256:'+before['Image']}}
    def inspect(identity):calls.append(identity);return observations.pop(0)
    h.A=SimpleNamespace(inspect_container=inspect)
    monkeypatch.setattr(M.time,'sleep',lambda seconds:None)
    assert h.await_started('converter','forms2apex-mcp',M.configuration_signature(None,before))==after
    assert calls==[before['Id'],before['Id']]


def test_failed_single_start_is_not_replayed():
    before=item();failed=started(before);failed['State'].update(Running=False,Pid=0,Status='exited')
    h=object.__new__(M.HostCutover);h.created={'candidates':{'converter':{'id':before['Id']}}}
    h.release={'images':{'converter':'sha256:'+before['Image']}};h.A=SimpleNamespace(inspect_container=lambda _:failed)
    with pytest.raises(M.CutoverError,match='NEW_RUNTIME_EXITED_NO_REPLAY'):
        h.await_started('converter','forms2apex-mcp',M.configuration_signature(None,before))


def harness(tmp_path,monkeypatch):
    h=object.__new__(M.HostCutover);h.stage=tmp_path;h.R='c'*64
    h.p={'plan_sha256':'d'*64,'installation':{'sha256':'e'*64},'backup_completion_sha256':'f'*64,'helper_sha256':'9'*64}
    oldfox=item('2'*64,'fox-pre-project-'+h.R[:16],image='b'*64)
    oldconverter=item('3'*64,'forms2apex-pre-project-'+h.R[:16],image='b'*64)
    for old in (oldfox,oldconverter):old['State'].update(Status='exited',StartedAt='2026-10-19T00:00:00Z')
    fox=item('4'*64,'fox',image='a'*64);converter_before=item('5'*64,'forms2apex-mcp',image='a'*64)
    converter=started(converter_before)
    objects={v['Id']:v for v in (oldfox,oldconverter,fox,converter)}
    h.old={'fox':deepcopy(oldfox),'forms2apex-mcp':deepcopy(oldconverter)}
    h.created={'admission_sha256':'8'*64,'candidates':{'fox':{'id':fox['Id']},'converter':{'id':converter['Id']}}}
    h.release={'images':{'fox':'sha256:'+fox['Image'],'converter':'sha256:'+converter['Image']}}
    boundaries={'new':{'fox':M.configuration_signature(None,fox),'converter':M.configuration_signature(None,converter_before)},
        'retained_names':{'fox':oldfox['Name'],'converter':oldconverter['Name']}}
    def save(path,value):
        with path.open('xb') as stream:stream.write(M.canonical(value))
    save(tmp_path/'cutover-boundaries.json',boundaries)
    save(tmp_path/'project-start-floor.json',{'release_sha256':h.R,'project_aware_code_required':True,
        'automatic_g_rollback_permitted':False,'backup_completion_sha256':'f'*64})
    save(tmp_path/'cutover-start-converter-create-exit.json',{'exit_code':0,'observed_original_process':True})
    save(tmp_path/'cutover-start-converter-create-intent.json',{'plan_sha256':'d'*64,
        'argv_sha256':M.sha(M.canonical(['/usr/bin/systemctl','--user','start','forms2apex-mcp.service']))})
    @contextmanager
    def held(stage):yield
    h.A=SimpleNamespace(held_stage=held,read=lambda path,**kwargs:path.read_bytes(),parse=json.loads,
        create_file=lambda path,raw:save(path,json.loads(raw)),
        inspect_container=lambda name:objects.get(name) or next(v for v in objects.values() if v['Name']==name),
        BASE={'fox':(oldfox['Id'],oldfox['Image']),'forms2apex-mcp':(oldconverter['Id'],oldconverter['Image'])})
    h.local_guards=lambda:None;h.require_tls=lambda running:None;h._backup=lambda:None;h.stopped_idle=lambda:None
    h.await_fox_health=lambda:None;h.admission=SimpleNamespace(check=lambda:{'status':'CHECKED_NOT_STARTED'})
    actions=[]
    def effect(name,argv):
        assert name=='forward-start-fox' and argv==['/usr/bin/systemctl','--user','start','fox.service']
        actions.append(name);objects[fox['Id']]=started(fox)
    h.effect=effect
    monkeypatch.setattr(M,'service_state',lambda A,name,**kwargs:{'ActiveState':'inactive' if name=='fox.service' else 'active'})
    monkeypatch.setattr(M,'read_idle',lambda A,cid:{'idle':True})
    return h,objects,fox,converter,actions


def test_forward_continuation_starts_only_never_started_fox_and_retains_parent_records(tmp_path,monkeypatch):
    h,objects,fox,converter,actions=harness(tmp_path,monkeypatch)
    original=(tmp_path/'cutover-start-converter-create-intent.json').read_bytes()
    result=h.resume_after_converter_start()
    assert result['status']=='PROJECT_RUNNING_TLS_HELD' and actions==['forward-start-fox']
    assert (tmp_path/'cutover-prepared.json').is_file() and (tmp_path/'forward-activation-complete.json').is_file()
    assert (tmp_path/'cutover-start-converter-create-intent.json').read_bytes()==original
    with pytest.raises(M.CutoverError,match='PRIOR_FORWARD_ACTIVATION_PRESERVED_NO_REPLAY'):
        h.resume_after_converter_start()
    assert actions==['forward-start-fox']


@pytest.mark.parametrize('change',['converter_stopped','converter_env','fox_started','fox_intent'])
def test_forward_continuation_rejects_unreconciled_or_different_state(tmp_path,monkeypatch,change):
    h,objects,fox,converter,actions=harness(tmp_path,monkeypatch)
    if change=='converter_stopped':converter['State']['Running']=False
    elif change=='converter_env':converter['Config']['Env']=['SYNTHETIC=not the original']
    elif change=='fox_started':fox['State']['StartedAt']='2026-10-27T02:00:00Z'
    else:(tmp_path/'cutover-start-fox-create-intent.json').write_bytes(b'{}')
    with pytest.raises(M.CutoverError):h.resume_after_converter_start()
    assert not actions and not (tmp_path/'forward-activation-intent.json').exists()


@pytest.mark.parametrize('context',[None,True,SimpleNamespace(require_active=lambda:True)])
def test_forward_api_rejects_declared_context_before_transport(context):
    raw=M.canonical({})
    with pytest.raises(M.CutoverError,match='REAL_FORWARD_WINDOWS_CONTEXT_REQUIRED'):
        M.execute_forward_under_lock(context,operation='finish-activation',plan_raw=raw,plan_sha256=M.sha(raw),
            installation_reference={},snapshot_configuration_raw=raw,snapshot_configuration_sha256=M.sha(raw),
            backup_operation='one',backup_completion_sha256='a'*64,restore_operation='two',restore_completion_sha256='b'*64,
            parent_result_sha256='c'*64,expected_source_sha256=M.sha(Path(M.__file__).read_bytes()),apply=True)
