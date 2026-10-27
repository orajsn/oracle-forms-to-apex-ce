"""Synthetic service boundaries; no cloud or actual verifier execution."""
from contextlib import contextmanager
import importlib.util
import json
from pathlib import Path, PurePosixPath
import sys
from types import SimpleNamespace

import pytest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('setting_repair_test',ROOT/'deployment/cutover_project_release.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)


@pytest.mark.parametrize('directory',['relative','/private/with space','/private/%n','/private/../other','/private/$HOME'])
def test_directory_projection_rejects_unreviewed_syntax(directory):
    admission=SimpleNamespace(source_root=PurePosixPath(directory))
    service=SimpleNamespace(service_unit=lambda *_:b'[Unit]\nDescription=FOX protected product verifier\n')
    with pytest.raises(M.CutoverError,match='UNIT_WORKING_DIRECTORY_UNSUPPORTED'):
        M.ordered_service_unit(service,admission,Path('/private/i.json'))


def setup(tmp_path,monkeypatch):
    h=object.__new__(M.HostCutover);h.stage=tmp_path/'stage';h.stage.mkdir();h.R='a'*64
    h.p={'installation':{'path':'/private/install.json','sha256':'b'*64},'plan_sha256':'c'*64}
    h.created={'candidates':{'fox':{'id':'d'*64}}}
    source=PurePosixPath('/private/synthetic-release')
    h.admission=SimpleNamespace(source_root=source,check=lambda:{'status':'CHECKED_NOT_STARTED'},
        provider=SimpleNamespace(path=lambda name:tmp_path/'journal'))
    raw=('[Unit]\nDescription=FOX protected product verifier\n\n[Service]\nWorkingDirectory="'+str(source)+'"\nExecStart="/bin/true"\n').encode()
    h.service=SimpleNamespace(service_unit=lambda *_:raw)
    unit=tmp_path/'fox-product-verifier.service'
    ordered=raw.replace(b'Description=FOX protected product verifier\n',b'Description=FOX protected product verifier\nAfter=fox.service forms2apex-mcp.service\nRequires=fox.service forms2apex-mcp.service\n')
    unit.write_bytes(ordered)
    def save(path,value):path.write_bytes(M.canonical(value))
    save(h.stage/'paired-readiness.json',{'actual':'parent'})
    save(h.stage/'public-release-intent.json',{'release_sha256':h.R,'installation_sha256':'b'*64,
        'unit_sha256':M.sha(ordered),'readiness_sha256':M.sha((h.stage/'paired-readiness.json').read_bytes()),'automatic_replay_permitted':False})
    for action,code in [('reload',0),('enable',0),('start',1)]:
        save(h.stage/('cutover-verifier-'+action+'-create-exit.json'),{'exit_code':code,'observed_original_process':True})
        argv=['/usr/bin/systemctl','--user']+(['daemon-reload'] if action=='reload' else [action,unit.name])
        save(h.stage/('cutover-verifier-'+action+'-create-intent.json'),{'plan_sha256':'c'*64,'argv_sha256':M.sha(M.canonical(argv))})
    @contextmanager
    def held(stage):yield
    events=[]
    def command(argv):events.append(('parse',argv));return b''
    h.A=SimpleNamespace(held_stage=held,read=lambda p,**kw:p.read_bytes(),parse=json.loads,
        create_file=lambda p,data:p.open('xb').write(data),command=command)
    h.local_guards=lambda:None;h.current_pair=lambda:None;h.require_tls=lambda value:None;h._backup=lambda:None
    h.record=lambda name,value:save(h.stage/name,value)
    h.effect=lambda name,argv:events.append((name,argv))
    # Stop after the real repair/start sequencing, before actual worker IO.
    h.first_idle=lambda:(_ for _ in ()).throw(RuntimeError('SYNTHETIC_STOP_AT_IDLE_BOUNDARY'))
    state={'LoadState':'bad-setting','ActiveState':'inactive','SubState':'dead','MainPID':'0'}
    def service_state(*args):
        return {**state,'LoadState':'loaded'} if any(e[0]=='verifier-setting-repair-reload' for e in events) else dict(state)
    monkeypatch.setattr(M,'service_state',service_state)
    monkeypatch.setattr(M,'verify_service_unit',lambda A,path:A.command(['synthetic-parser',str(path)]))
    monkeypatch.setattr(M,'read_idle',lambda *args:{'idle':True})
    original=M.Path
    monkeypatch.setattr(M,'Path',lambda value:unit if str(value)=='/home/opc/.config/systemd/user/fox-product-verifier.service' else original(value))
    return h,unit,state,events


def test_only_directory_setting_replaced_preserving_parent_and_no_enable_or_app_action(tmp_path,monkeypatch):
    h,unit,state,events=setup(tmp_path,monkeypatch)
    before=unit.read_bytes();parents={p.name:p.read_bytes() for p in h.stage.iterdir()}
    with pytest.raises(RuntimeError,match='SYNTHETIC_STOP_AT_IDLE_BOUNDARY'):h.resume_failed_verifier_setting()
    assert unit.read_bytes()==before.replace(('WorkingDirectory="'+str(h.admission.source_root)+'"').encode(),('WorkingDirectory='+str(h.admission.source_root)).encode())
    assert [e[0] for e in events]==['parse','verifier-setting-repair-reload','verifier-setting-repair-start']
    assert all((h.stage/name).read_bytes()==data for name,data in parents.items())
    assert (h.stage/'verifier-unit-before-setting-repair.json').exists()
    with pytest.raises(M.CutoverError,match='ALREADY_ATTEMPTED'):h.resume_failed_verifier_setting()


@pytest.mark.parametrize('change',['active','pid','loaded','journal','unit','prior','argv','exit'])
def test_other_states_never_start_or_replace(tmp_path,monkeypatch,change):
    h,unit,state,events=setup(tmp_path,monkeypatch)
    if change=='active':state['ActiveState']='active'
    elif change=='pid':state['MainPID']='123'
    elif change=='loaded':state['LoadState']='loaded'
    elif change=='journal':(tmp_path/'journal'/h.R[:16]).mkdir(parents=True)
    elif change=='unit':unit.write_bytes(unit.read_bytes()+b'# changed\n')
    elif change=='prior':(h.stage/'verifier-setting-repair-intent.json').write_text('{}')
    elif change=='argv':(h.stage/'cutover-verifier-start-create-intent.json').write_text('{}')
    else:(h.stage/'cutover-verifier-start-create-exit.json').write_text('{}')
    before=unit.read_bytes()
    with pytest.raises(M.CutoverError):h.resume_failed_verifier_setting()
    assert not events and unit.read_bytes()==before


def test_actual_parser_failure_prevents_unit_replacement_and_start(tmp_path,monkeypatch):
    h,unit,state,events=setup(tmp_path,monkeypatch);before=unit.read_bytes()
    h.A.command=lambda argv:(_ for _ in ()).throw(RuntimeError('SYNTHETIC_HOST_PARSE_FAILURE'))
    with pytest.raises(RuntimeError,match='HOST_PARSE_FAILURE'):h.resume_failed_verifier_setting()
    assert not events and unit.read_bytes()==before
    assert not (h.stage/'verifier-setting-repair-intent.json').exists()


def test_parser_uses_real_active_generated_unit_without_running_generators(monkeypatch):
    state={'LoadState':'loaded','ActiveState':'active','FragmentPath':'/run/user/1000/systemd/generator/forms2apex-network.service'}
    calls=[]
    monkeypatch.setattr(M,'service_state',lambda *a:dict(state))
    A=SimpleNamespace(read=lambda path:b'actual generated bytes',command=lambda argv:calls.append(argv))
    M.verify_service_unit(A,PurePosixPath('/private/candidate.service'))
    assert calls==[['/usr/bin/systemd-analyze','--user','--generators=no','verify','/private/candidate.service',state['FragmentPath']]]


@pytest.mark.parametrize('change',['inactive','wrong_fragment','not_found','changed_bytes'])
def test_generated_dependency_cannot_be_faked_or_changed(monkeypatch,change):
    state={'LoadState':'loaded','ActiveState':'active','FragmentPath':'/run/user/1000/systemd/generator/forms2apex-network.service'}
    if change=='inactive':state['ActiveState']='inactive'
    elif change=='wrong_fragment':state['FragmentPath']='/private/fake.service'
    elif change=='not_found':state['LoadState']='not-found'
    monkeypatch.setattr(M,'service_state',lambda *a:dict(state))
    reads=iter([b'first',b'changed'])
    A=SimpleNamespace(read=lambda p:next(reads),command=lambda argv:None)
    with pytest.raises(M.CutoverError):M.verify_service_unit(A,PurePosixPath('/private/candidate.service'))
