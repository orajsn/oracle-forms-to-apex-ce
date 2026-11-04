"""Exact candidate tuple selection; no network, secrets or Oracle execution."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import importlib.util
import sys

import pytest

ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT),str(ROOT/'converter'),str(ROOT/'fox')]
from qa.operator import contracts as c,remote as r,project_contracts as pc,clean_install as cli
from forms2apex.target_profile import select_target_profile,target_profile_sha256,validate_target_profile,TargetProfileError

spec=importlib.util.spec_from_file_location('version_fixture',Path(__file__).with_name('test_contracts.py'))
fx=importlib.util.module_from_spec(spec);spec.loader.exec_module(fx)
NEW={**c.VERSIONS,'apex':'26.1.6'}


def native_plan(versions=None):
    source,package=fx.fixture()
    return c.make_plan(source,package,fx.NAMESPACE,fx.TIME,native_spec_sha256=fx.NATIVE,
        operator_code_sha256=fx.CODE,expected_versions=versions)


def test_legacy_constructor_bytes_and_default_are_preserved():
    plan=native_plan()
    assert plan==fx.plan() and plan['expected_versions']==c.VERSIONS
    assert c.VERSIONS['apex']=='26.1.5'
    assert c.digest(c.canonical_bytes(plan))=='cfee60dccadbb3b941ea2f6a0c34c1517e6798437a638663f21ad2294733cc8a'
    assert c.digest(c.canonical_bytes(c.make_verification_profile(plan,c.canonical_bytes(fx.allocation(plan)))))=='58a9c5efc9f5ac1d08a4cea78c27eae175aefdb86eeb28b0078a8e77857e459b'


def test_explicit_new_tuple_flows_into_plan_allocation_and_consumer_profile():
    plan=native_plan(NEW)
    assert plan['expected_versions']==NEW and c.VERSIONS['apex']=='26.1.5'
    allocation=fx.allocation(plan);allocation['observed_versions']=dict(NEW)
    c.validate_allocation(allocation,plan)
    profile=c.make_verification_profile(plan,c.canonical_bytes(allocation))
    assert profile['expected_versions']==NEW
    assert c.plan_sha256(plan)!=c.plan_sha256(native_plan())


def test_allocation_cannot_borrow_another_approved_tuple():
    plan=native_plan(NEW);allocation=fx.allocation(plan)
    with pytest.raises(c.ContractError,match='versions differ'):c.validate_allocation(allocation,plan)


@pytest.mark.parametrize('change',[{'apex':'26.1.7'},{'sqlcl':'26.2.0.0'},
    {'database':'23.26.5.0.0'},{'mmd':'26.2.0+1'},{'apex':True}])
def test_unknown_or_mixed_tuples_are_not_minimum_version_matches(change):
    with pytest.raises(c.ContractError):c.reviewed_versions({**NEW,**change})


def test_each_admin_and_schema_guard_asserts_the_selected_version_and_same_scope():
    sql=r._guard_sql('ADMIN',versions=NEW)
    assert b"v<>'26.1.6'" in sql and b"v<>'26.1.5'" not in sql
    for value in (c.COMPARTMENT,c.DATABASE,c.REGION,c.DB_NAME):assert value.encode() in sql
    assert b"v<>'26.1.6'" in r._guard_sql(fx.NAMESPACE,fx.NAMESPACE,'1234',versions=NEW)
    assert b"v<>'26.1.5'" in r._guard_sql('ADMIN')


def test_native_write_batches_do_not_revert_to_legacy_guards():
    plan=native_plan(NEW);allocation=fx.allocation(plan);allocation['observed_versions']=dict(NEW)
    _,package=fx.fixture()
    credentials={key:'Aa9!'+digit*26 for key,digit in zip(
        ('schema_password','password','second_password'),('a','b','c'))}
    for sql in (r.allocation_sql(plan,credentials),r.schema_sql(plan,allocation,package),r.import_sql(plan,allocation,package)):
        assert b"v<>'26.1.6'" in sql and b"v<>'26.1.5'" not in sql


def test_driver_selection_is_detached_and_a_mismatched_plan_stops_before_io(monkeypatch):
    driver=r.SqlclDriver(expected_versions=NEW)
    copy=driver.expected_versions;copy['apex']='26.1.5'
    assert driver.expected_versions==NEW
    monkeypatch.setattr(r.urllib.request,'urlopen',lambda *a,**k:pytest.fail('Wrong tuple reached network'))
    with pytest.raises(r.RemoteError,match='DRIVER_PLAN_VERSION_MISMATCH'):driver.scope(native_plan())


def test_selected_installation_target_not_environment_drives_prepare(monkeypatch):
    profile=select_target_profile('jsn-native-project-2616-v1')
    monkeypatch.setattr(cli.runtime_provider,'selected_hosted',lambda:SimpleNamespace(configuration={'target_profile':profile}))
    monkeypatch.setenv('F2A_APEX_VERSION','26.1.5')
    assert cli.selected_versions()==NEW
    profile['oci']['region']='another-region'
    with pytest.raises(cli.OperatorError,match='CONFIGURATION_INVALID'):cli.selected_versions()


def test_legacy_unconfigured_selection_does_not_guess_the_new_version(monkeypatch):
    monkeypatch.setattr(cli.runtime_provider,'selected_hosted',lambda:None)
    assert cli.selected_versions()==c.VERSIONS


def test_candidate_profile_has_new_identity_and_no_historical_mutation():
    old=select_target_profile('jsn-native-project-v2');original=deepcopy(old)
    current=select_target_profile('jsn-native-project-2616-v1')
    assert target_profile_sha256(old)=='7170d60927b7e5b7aed5d56174f97efbeff3052be247b244911deff768701ed3'
    assert target_profile_sha256(current)=='e1e4b7b9f1439ebd3c6d02e11c241053d16f346a7406272f49ae2a122b1ff7f9'
    assert current['oci']==old['oci'] and current['apex']==old['apex']
    old['tested_versions']['apex']='26.1.6'
    with pytest.raises(TargetProfileError):validate_target_profile(old)
    assert select_target_profile('jsn-native-project-v2')==original
