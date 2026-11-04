"""Actual create-only local setup. No API, secret, network or service use."""
import importlib.util
from pathlib import Path
import socket
import subprocess
import sys
import pytest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('test_profile_setup',ROOT/'tools/prepare_test_profile.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


@pytest.fixture
def checkout(tmp_path,monkeypatch):
    def blocked(*_a,**_k):pytest.fail('Local test-profile setup must not contact or execute services')
    monkeypatch.setattr(socket.socket,'connect',blocked)
    monkeypatch.setattr(subprocess,'run',blocked);monkeypatch.setattr(subprocess,'Popen',blocked)
    (tmp_path/'deployment').mkdir()
    (tmp_path/'deployment/target-profile.jsn.json').write_bytes((ROOT/'deployment/target-profile.jsn.json').read_bytes())
    return tmp_path


def test_inspection_is_read_only_and_creates_nothing(checkout):
    before=list(checkout.rglob('*'))
    value=m.prepare(checkout)
    assert value['status']=='TEST_PROFILE_MISSING_NOT_CREATED'
    assert not value['connection_tested'] and not value['conversion_ready']
    assert list(checkout.rglob('*'))==before


def test_explicit_create_is_exact_idempotent_and_usable_by_real_profile_parser(checkout):
    value=m.prepare(checkout,apply=True);path=checkout/'deployment/native-beta-profile.json'
    assert value['status']=='TEST_PROFILE_CREATED'
    before=path.stat().st_mtime_ns,path.read_bytes()
    assert m.prepare(checkout,apply=True)['status']=='TEST_PROFILE_UNCHANGED'
    assert (path.stat().st_mtime_ns,path.read_bytes())==before
    sys.path.insert(0,str(ROOT/'fox'))
    from fox.opaf import load_native_profile
    assert load_native_profile(path)['profile_id']=='native-table-form-v1'
    assert b'password' not in path.read_bytes() and b'api_key' not in path.read_bytes()


@pytest.mark.parametrize('raw',[b'configured-do-not-replace',b'',b'PRIVATE_TEST_SENTINEL'])
def test_existing_configuration_is_never_overwritten_or_disclosed(checkout,raw):
    path=checkout/'deployment/native-beta-profile.json';path.write_bytes(raw)
    with pytest.raises(m.TestProfileError) as error:m.prepare(checkout,apply=True)
    assert 'PRIVATE_TEST_SENTINEL' not in str(error.value) and path.read_bytes()==raw


def test_unregistered_source_cannot_become_a_test_profile(checkout):
    source=checkout/'deployment/target-profile.jsn.json'
    source.write_text(source.read_text().replace('us-ashburn-1','ap-singapore-1'))
    with pytest.raises(Exception):m.prepare(checkout,apply=True)
    assert not (checkout/'deployment/native-beta-profile.json').exists()


def test_profile_path_must_not_be_a_directory(checkout):
    (checkout/'deployment/native-beta-profile.json').mkdir()
    with pytest.raises(m.TestProfileError):m.prepare(checkout,apply=True)
