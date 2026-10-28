"""Archive/runtime bootstrap guards, not full product-installation claims."""
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
from unittest.mock import patch
import zipfile

import pytest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('fox_bootstrap',ROOT/'deployment/bootstrap_runtime.py')
B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)


@pytest.mark.parametrize('name',['../escape','/absolute','python/../bad','python//bad','python/bad\n','python\\bad'])
def test_member_paths_are_not_normalized_or_guessed(name):
    with pytest.raises(B.BootstrapError):B.member_name(name)


def archive(path,rows):
    with tarfile.open(path,'w:gz') as t:
        for name,target in rows:
            m=tarfile.TarInfo(name)
            if target is not None:m.type=tarfile.SYMTYPE;m.linkname=target;t.addfile(m)
            else:m.size=2;m.mode=0o644;t.addfile(m,io.BytesIO(b'ok'))


@pytest.mark.parametrize('rows',[
    [('python/link','../../escape')],
    [('python/link','target'),('python/link/child',None),('python/target',None)],
    [('python/a','b'),('python/b','a')],
    [('python/missing','absent')],
    [('outside/file',None)]])
def test_unsafe_archive_structure_is_rejected_before_extraction(tmp_path,rows):
    path=tmp_path/'input.tgz';archive(path,rows)
    with pytest.raises(B.BootstrapError):B.tar_entries(path)
    assert list(tmp_path.iterdir())==[path]


def test_original_safe_links_are_retained(tmp_path):
    path=tmp_path/'input.tgz';archive(path,[('python/bin/runtime',None),('python/bin/alias','runtime')])
    entries=B.tar_entries(path)
    assert entries['python/bin/alias']['target']=='runtime'
    assert entries['python/bin/runtime']['sha256']==B.sha(b'ok')


def test_wheel_cannot_write_scripts_or_traverse(tmp_path):
    for name in ('../../bad','defusedxml/../../bad','arbitrary.pth','defusedxml/evil.pth'):
        path=tmp_path/'input.whl'
        with zipfile.ZipFile(path,'w') as z:z.writestr(name,b'unsafe')
        with pytest.raises(B.BootstrapError):B.wheel_entries(path)


def test_child_environment_excludes_secrets_and_loader_injection():
    with patch.dict(os.environ,{'LD_PRELOAD':'private','PYTHONPATH':'private','OCI_PRIVATE_KEY':'private'}):
        assert B.environment()=={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1'}


@pytest.mark.skipif(os.name!='posix',reason='actual POSIX ownership/modes required')
def test_wrong_hash_never_executes_or_installs(tmp_path):
    if os.geteuid()==0:pytest.skip('nonroot required')
    tmp_path.chmod(0o700)
    p=tmp_path/'bad.tgz';p.write_bytes(b'not trusted');p.chmod(0o600)
    w=tmp_path/'bad.whl';w.write_bytes(b'not trusted');w.chmod(0o600)
    root=tmp_path/'runtime'
    with patch.object(B,'probe',side_effect=AssertionError('untrusted executable')):
        with pytest.raises(B.BootstrapError,match='RUNTIME_DOWNLOAD_INTEGRITY_FAILED'):
            B.prepare(root,p,w)
    assert (root/'intent.json').is_file() and not (root/'python').exists()
    with pytest.raises(B.BootstrapError,match='RUNTIME_DOWNLOAD_INTEGRITY_FAILED'):
        B.prepare(root,p,w)
    assert not (root/'python').exists()


@pytest.mark.skipif(os.name!='posix',reason='actual POSIX ownership/modes required')
def test_no_download_without_explicit_approval(tmp_path):
    if os.geteuid()==0:pytest.skip('nonroot required')
    tmp_path.chmod(0o700);root=tmp_path/'runtime'
    with patch.object(B.urllib.request,'urlopen',side_effect=AssertionError('no request')):
        with pytest.raises(B.BootstrapError,match='EXPLICIT_RUNTIME_DOWNLOAD_APPROVAL_REQUIRED'):
            B.prepare(root)
    assert not root.exists()


@pytest.mark.skipif(os.name!='posix',reason='actual POSIX ownership/modes required')
def test_partial_or_unknown_root_is_not_adopted(tmp_path):
    if os.geteuid()==0:pytest.skip('nonroot required')
    tmp_path.chmod(0o700);(tmp_path/'customer-file').write_bytes(b'preserve')
    with pytest.raises(B.BootstrapError,match='PARTIAL_OR_UNKNOWN_RUNTIME_REQUIRES_REVIEW'):
        B.prepare(tmp_path)
    assert (tmp_path/'customer-file').read_bytes()==b'preserve'
