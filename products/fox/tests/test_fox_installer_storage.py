"""Real nonroot POSIX storage phase, not simulated installed readiness."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'fox')]
from qa.operator import installer_storage as s


def snapshot(base):
    return {str(p.relative_to(base)):hashlib.sha256(p.read_bytes()).hexdigest()
            for p in base.rglob('*') if p.is_file()}


def test_one_folder_derives_existing_storage_contract():
    value=s.plan('/tmp/synthetic-installer/install',owner_uid=1000)
    assert value['storage_plan']['roots']=={
        'fox_data':'/tmp/synthetic-installer/install/data',
        'converter_jobs':'/tmp/synthetic-installer/install/jobs',
        'operator_state':'/tmp/synthetic-installer/install/operator',
        'records':'/tmp/synthetic-installer/install/storage-records'}


@pytest.mark.parametrize('root',['relative','/','/tmp','/tmp/a/../b','/tmp/a/','/tmp/a//b','C:/data'])
def test_root_not_normalized_or_guessed(root):
    with pytest.raises(s.InstallerStorageError):s.plan(root,owner_uid=1000)


@pytest.mark.parametrize('flag',[False,None,0,1,'yes'])
def test_apply_must_be_literal_true(flag):
    with pytest.raises(s.InstallerStorageError,match='EXPLICIT_INSTALLER_STORAGE_APPLY_REQUIRED'):
        s.initialize({},expected_plan_sha256='0'*64,apply=flag)


def test_tampered_plan_cannot_write():
    value=s.plan('/tmp/synthetic-installer/install',owner_uid=1000)
    with pytest.raises(s.InstallerStorageError,match='INSTALLER_STORAGE_PLAN_HASH_CHANGED'):
        s.initialize(value,expected_plan_sha256='0'*64,apply=True)


@pytest.fixture
def posix(tmp_path):
    if os.name!='posix' or os.geteuid()==0:pytest.skip('actual nonroot POSIX required')
    tmp_path.chmod(0o700)
    base=tmp_path/'install'
    value=s.plan(str(base),owner_uid=os.geteuid())
    return base,value


def test_real_create_and_read_only_repeat_preserve_identity(posix):
    base,value=posix
    first=s.initialize(value,expected_plan_sha256=s.digest(value),apply=True)
    before=snapshot(base)
    second=s.initialize(value,expected_plan_sha256=s.digest(value),apply=True)
    assert snapshot(base)==before
    assert first['status']=='STORAGE_INITIALIZED_NOT_INSTALLED'
    assert second['status']=='STORAGE_REUSED_NOT_INSTALLED' and second['read_only']
    assert first['installation_id']==second['installation_id']
    for key in ('conversion_ready','connected_admission','services_started','automatic_replay_permitted'):
        assert first[key] is second[key] is False


def test_retained_plan_can_continue_only_before_s0_starts(posix):
    base,value=posix
    with patch.object(s.storage,'initialize_storage',side_effect=RuntimeError('before S0')):
        with pytest.raises(RuntimeError,match='before S0'):
            s.initialize(value,expected_plan_sha256=s.digest(value),apply=True)
    assert set(p.name for p in base.iterdir())=={s.MARKER}
    assert s.initialize(value,expected_plan_sha256=s.digest(value),apply=True)['status']=='STORAGE_INITIALIZED_NOT_INSTALLED'


def test_partial_real_s0_never_replays(posix):
    base,value=posix
    original=s.storage._write
    def fail(path,raw):
        if path.name=='roots.json':raise RuntimeError('synthetic interruption')
        return original(path,raw)
    with patch.object(s.storage,'_write',fail):
        with pytest.raises(RuntimeError,match='INITIALIZATION_OUTCOME_UNCONFIRMED'):
            s.initialize(value,expected_plan_sha256=s.digest(value),apply=True)
    before=snapshot(base)
    with patch.object(s.storage,'initialize_storage',side_effect=AssertionError('no replay')):
        with pytest.raises(s.InstallerStorageError,match='STORAGE_ATTENTION_NO_REPLAY'):
            s.initialize(value,expected_plan_sha256=s.digest(value),apply=True)
    assert snapshot(base)==before


def test_existing_empty_directory_is_not_adopted(posix):
    base,value=posix;base.mkdir(mode=0o700)
    with pytest.raises(s.InstallerStorageError,match='EXISTING_INSTALLATION_NOT_ADOPTED'):
        s.initialize(value,expected_plan_sha256=s.digest(value),apply=True)
    assert not list(base.iterdir())


def test_added_unknown_file_blocks_repeat(posix):
    base,value=posix;s.initialize(value,expected_plan_sha256=s.digest(value),apply=True)
    (base/'unrelated').write_bytes(b'preserve')
    before=snapshot(base)
    with pytest.raises(s.InstallerStorageError,match='EXISTING_INSTALLATION_CONTENTS_REQUIRE_REVIEW'):
        s.initialize(value,expected_plan_sha256=s.digest(value),apply=True)
    assert snapshot(base)==before


def test_changed_receipt_cannot_adopt(posix):
    base,value=posix;s.initialize(value,expected_plan_sha256=s.digest(value),apply=True)
    (base/s.MARKER).write_bytes(b'{}')
    with pytest.raises(s.InstallerStorageError,match='RETAINED_INSTALLER_STORAGE_PLAN_CHANGED'):
        s.initialize(value,expected_plan_sha256=s.digest(value),apply=True)


def test_owned_ordinary_parent_needs_no_manual_permission_change(posix):
    base,value=posix;base.parent.chmod(0o755)
    assert s.initialize(value,expected_plan_sha256=s.digest(value),apply=True)['status']=='STORAGE_INITIALIZED_NOT_INSTALLED'
    assert base.parent.stat().st_mode & 0o777 == 0o755
    assert base.stat().st_mode & 0o777 == 0o700


def test_writable_parent_is_not_repaired_silently(posix):
    base,value=posix;base.parent.chmod(0o775)
    with pytest.raises(s.InstallerStorageError,match='INSTALLATION_PARENT_UNSAFE'):
        s.initialize(value,expected_plan_sha256=s.digest(value),apply=True)
    assert not base.exists()
    assert base.parent.stat().st_mode & 0o777 == 0o775


def test_actual_cli_plan_initialize_and_repeat(posix):
    base,_=posix
    def command(*args):
        result=subprocess.run([sys.executable,'-I','-B',str(ROOT/'scripts/fox-setup.py'),
            *args,'--installation-root',str(base)],capture_output=True,text=True,timeout=30)
        assert result.returncode==0,result.stdout+result.stderr
        return json.loads(result.stdout)
    planned=command('storage-plan')
    assert planned['status']=='STORAGE_PLAN_NOT_INSTALLED' and not base.exists()
    first=command('storage-initialize','--apply','--expected-plan-sha256',planned['plan_sha256'])
    before=snapshot(base)
    repeated=command('storage-initialize','--apply','--expected-plan-sha256',planned['plan_sha256'])
    assert repeated['status']=='STORAGE_REUSED_NOT_INSTALLED' and repeated['read_only']
    assert first['installation_id']==repeated['installation_id']
    assert snapshot(base)==before
    assert command('inspect')['status']=='EXISTING_STATE_UNVERIFIED'


def test_assessment_only_package_cannot_select_full_storage_phase(posix):
    base,_=posix
    package=base.parent/'assessment';(package/'scripts').mkdir(parents=True)
    (package/'scripts/fox-setup.py').write_bytes((ROOT/'scripts/fox-setup.py').read_bytes())
    result=subprocess.run([sys.executable,'-I','-B',str(package/'scripts/fox-setup.py'),
        'storage-plan','--installation-root',str(base)],capture_output=True,text=True,timeout=30)
    assert result.returncode==2
    assert json.loads(result.stdout)['code']=='STORAGE_STEP_COMPONENTS_MISSING'
    assert not base.exists()
