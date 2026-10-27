"""Real temporary directories; synthetic host/service/retirement boundaries."""
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import sys
from types import SimpleNamespace

import pytest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('storage_setup_test',ROOT/'deployment/cutover_project_release.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)


def roots_case(tmp_path):
    h=object.__new__(M.HostCutover)
    root=tmp_path/'private-state';root.mkdir(mode=0o700)
    names={'native':'clean-install','project':'project-clean-install','journal':'product-verifier'}
    h.provider={'state_root':str(root)}
    h.admission=SimpleNamespace(provider=SimpleNamespace(path=lambda kind:root/names[kind]))
    def private(path):
        assert path.is_dir() and not path.is_symlink() and path.resolve()==path
        if os.name=='posix':assert path.stat().st_mode & 0o777==0o700
    h.A=SimpleNamespace(private_dir=private,sync=lambda p:None)
    return h,root


def test_creates_only_two_absent_roots_and_preserves_existing_content(tmp_path):
    h,root=roots_case(tmp_path)
    result=h.prepare_working_roots()
    assert result=={'native':str(root/'clean-install'),'project':str(root/'project-clean-install')}
    assert sorted(p.name for p in root.iterdir())==['clean-install','project-clean-install']
    sentinel=root/'clean-install'/'retained-evidence';sentinel.write_bytes(b'unchanged')
    before=sentinel.stat()
    assert h.prepare_working_roots()==result
    assert sentinel.read_bytes()==b'unchanged' and sentinel.stat().st_ino==before.st_ino


@pytest.mark.parametrize('change',['wrong_path','file','linked','unsafe_mode'])
def test_all_paths_checked_before_creating_anything(tmp_path,change):
    h,root=roots_case(tmp_path)
    if change=='unsafe_mode' and os.name!='posix':pytest.skip('POSIX mode bits')
    if change=='wrong_path':h.admission.provider.path=lambda kind:root/('wrong' if kind=='project' else 'clean-install')
    elif change=='file':(root/'project-clean-install').write_bytes(b'retained')
    elif change=='linked':
        if os.name!='posix':pytest.skip('Actual POSIX symlink fixture')
        (root/'project-clean-install').symlink_to(tmp_path,target_is_directory=True)
    else:(root/'project-clean-install').mkdir(mode=0o755)
    with pytest.raises((M.CutoverError,AssertionError)):h.prepare_working_roots()
    assert not (root/'clean-install').exists()


def continuation(tmp_path,monkeypatch):
    h,root=roots_case(tmp_path);h.stage=tmp_path/'stage';h.stage.mkdir();h.R='a'*64
    h.p={'installation':{'path':'/private/install.json','sha256':'b'*64},'plan_sha256':'c'*64}
    h.created={'candidates':{'fox':{'id':'d'*64}}}
    h.admission.source_root=PurePosixPath('/private/synthetic-release')
    h.admission.check=lambda:{'status':'CHECKED_NOT_STARTED'}
    template=b'[Unit]\nDescription=FOX protected product verifier\n\n[Service]\nWorkingDirectory="/private/synthetic-release"\nExecStart="/bin/true"\n'
    h.service=SimpleNamespace(service_unit=lambda *_:template)
    raw=M.ordered_service_unit(h.service,h.admission,PurePosixPath('/private/install.json'))
    unit=tmp_path/'fox-product-verifier.service';unit.write_bytes(raw)
    def save(path,value):
        with path.open('xb') as stream:stream.write(M.canonical(value))
    save(h.stage/'verifier-setting-repair-intent.json',{'release_sha256':h.R,'new_unit_sha256':M.sha(raw)})
    for action in ('reload','start'):
        prefix='cutover-verifier-setting-repair-'+action+'-create-'
        save(h.stage/(prefix+'exit.json'),{'exit_code':0,'observed_original_process':True})
        argv=['/usr/bin/systemctl','--user']+(['daemon-reload'] if action=='reload' else ['start',unit.name])
        save(h.stage/(prefix+'intent.json'),{'plan_sha256':'c'*64,'argv_sha256':M.sha(M.canonical(argv))})
    @contextmanager
    def held(stage):yield
    h.A.held_stage=held;h.A.read=lambda p,**kw:p.read_bytes();h.A.parse=json.loads
    h.A.command=lambda argv:b'Result=exit-code\nExecMainCode=1\nExecMainStatus=2\n'
    h.local_guards=lambda:None;h.current_pair=lambda:None;h.require_tls=lambda running:None;h._backup=lambda:None
    h.record=lambda name,value:save(h.stage/name,value)
    events=[]
    h.effect=lambda name,argv:events.append((name,argv))
    h.observe_readiness=lambda:{'status':'READ_ONLY_CONNECTIVITY_CONFIRMED','release_sha256':h.R}
    h.first_idle=lambda:{'status':'MATCHED_FIRST_IDLE_CLAIM','identity':{'pid':123}}
    def finish(raw,witness):events.append(('finish_public',None));return {'status':'PAIRED_SERVICE_ACTIVATED'}
    h.finish_public=finish
    state={'LoadState':'loaded','ActiveState':'failed','SubState':'failed','MainPID':'0'}
    monkeypatch.setattr(M,'service_state',lambda *a:dict(state))
    monkeypatch.setattr(M,'read_idle',lambda *a:{'idle':True})
    monkeypatch.setattr(M,'verify_service_unit',lambda *a:None)
    original=M.Path
    monkeypatch.setattr(M,'Path',lambda value:unit if str(value)=='/home/opc/.config/systemd/user/fox-product-verifier.service' else original(value))
    return h,root,unit,state,events


def test_specific_start_after_prerequisites_no_unit_rewrite_or_other_effect(tmp_path,monkeypatch):
    h,root,unit,state,events=continuation(tmp_path,monkeypatch)
    original=unit.read_bytes();parents={p.name:p.read_bytes() for p in h.stage.iterdir()}
    assert h.resume_failed_verifier_storage()['status']=='PAIRED_SERVICE_ACTIVATED'
    assert [e[0] for e in events]==['verifier-working-roots-start','finish_public']
    assert unit.read_bytes()==original and all((h.stage/name).read_bytes()==raw for name,raw in parents.items())
    assert (h.stage/'verifier-working-roots-complete.json').is_file()
    with pytest.raises(M.CutoverError,match='ALREADY_ATTEMPTED'):h.resume_failed_verifier_storage()


@pytest.mark.parametrize('change',['active','pid','unit','journal','native_present','prior','exit','argv','guard_exit'])
def test_unknown_execution_or_changed_state_rejects_before_setup(tmp_path,monkeypatch,change):
    h,root,unit,state,events=continuation(tmp_path,monkeypatch)
    if change=='active':state['ActiveState']='active'
    elif change=='pid':state['MainPID']='123'
    elif change=='unit':unit.write_bytes(unit.read_bytes()+b'# unexpected\n')
    elif change=='journal':(root/'product-verifier').mkdir(mode=0o700)
    elif change=='native_present':(root/'clean-install').mkdir(mode=0o700)
    elif change=='prior':(h.stage/'verifier-working-roots-intent.json').write_text('{}')
    elif change=='exit':(h.stage/'cutover-verifier-setting-repair-start-create-exit.json').write_text('{}')
    elif change=='argv':(h.stage/'cutover-verifier-setting-repair-start-create-intent.json').write_text('{}')
    else:h.A.command=lambda argv:b'Result=exit-code\nExecMainCode=1\nExecMainStatus=1\n'
    before=unit.read_bytes()
    with pytest.raises(M.CutoverError):h.resume_failed_verifier_storage()
    assert not events and unit.read_bytes()==before and not (root/'project-clean-install').exists()


def test_readiness_failure_after_setup_does_not_start_service_or_release_public(tmp_path,monkeypatch):
    h,root,unit,state,events=continuation(tmp_path,monkeypatch)
    h.observe_readiness=lambda:(_ for _ in ()).throw(M.CutoverError('SYNTHETIC_READINESS_FAILURE'))
    with pytest.raises(M.CutoverError,match='READINESS_FAILURE'):h.resume_failed_verifier_storage()
    assert not events and (root/'clean-install').is_dir()
    assert (h.stage/'verifier-working-roots-intent.json').is_file()
    with pytest.raises(M.CutoverError,match='ALREADY_ATTEMPTED'):h.resume_failed_verifier_storage()
