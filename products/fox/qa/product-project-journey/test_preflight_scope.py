"""Actual normalized provider schema; synthetic receipts, no live probes."""
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parent))
import preflight as P


def normalize(value,target):
    def need(ok,code):
        if not ok:raise RuntimeError(code)
    scope={'need':need}
    exec(compile(P.SCOPE_RECEIPT,'<actual-embedded-normalizer>','exec'),scope)
    return scope['scope_receipt'](value,target)


def fixture():
    target={'instance_id':'synthetic-vm','database_id':'synthetic-db','compartment_id':'synthetic-jsn','region':'synthetic-region'}
    return {**target,'database_db_name':'JSNF2APEX','instance_state':'RUNNING','database_state':'AVAILABLE','observed_at_utc':'2026-10-27T15:00:00Z'},target


def test_exact_normalized_provider_scope_not_underlying_raw_oci_payload():
    value,target=fixture();saved=deepcopy(value)
    actual=normalize(value,target)
    assert actual=={'instance':{'id':'synthetic-vm','compartment_id':'synthetic-jsn','region':'synthetic-region'},
        'database':{'id':'synthetic-db','compartment_id':'synthetic-jsn','lifecycle_state':'AVAILABLE','db_name':'JSNF2APEX'}}
    assert value==saved


@pytest.mark.parametrize('key',['instance_id','database_id','compartment_id','region','database_db_name','instance_state','database_state'])
def test_mismatched_scope_fails_closed(key):
    value,target=fixture();value[key]='changed'
    with pytest.raises(RuntimeError,match='OCI_SCOPE_IDENTITY_CHANGED'):normalize(value,target)


def test_raw_provider_payload_is_not_accepted_as_normalized_scope():
    value,target=fixture();value['instance_compartment_id']=value.pop('compartment_id')
    with pytest.raises(RuntimeError,match='RECEIPT_INVALID'):normalize(value,target)


@pytest.mark.parametrize('stderr',[b'',P.SSH_NOTICE,P.SSH_NOTICE.replace(b'\n',b'\r\n')])
def test_only_measured_client_notice_allowed(stderr):assert P.ssh_diagnostics_allowed(stderr)


@pytest.mark.parametrize('stderr',[b'warning',P.SSH_NOTICE+b'unknown diagnostic',b'Host key verification failed.\n',None])
def test_other_diagnostics_fail_closed(stderr):assert not P.ssh_diagnostics_allowed(stderr)
