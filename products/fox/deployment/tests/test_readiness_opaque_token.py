"""Opaque-token input safety only; no live token, HTTP or OCI access."""
import importlib.util
from pathlib import Path

import pytest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('opaque_token_readiness_test',ROOT/'deployment/project_release_readiness.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)


def namespace():
    scope={};exec(compile(M.MCP_PROGRAM,'<actual-readiness-mcp-program>','exec'),scope);return scope


def test_existing_opaque_visible_ascii_token_reaches_real_discovery_boundary():
    scope=namespace();seen=[]
    def request(*args,**kwargs):
        seen.append((args,kwargs));raise RuntimeError('SYNTHETIC_HTTP_BOUNDARY_REACHED')
    scope['request']=request
    token='SyntheticOnly-'+'X'*32+'!:#$%^&*'
    with pytest.raises(RuntimeError,match='SYNTHETIC_HTTP_BOUNDARY_REACHED'):
        scope['probe']({'bearer_token':token})
    assert len(seen)==1  # No token is sent until the unauthenticated check.


@pytest.mark.parametrize('token',['short','X'*4097,'X'*31,'X'*32+' ',' '+'X'*32,
    'X'*32+'\r\nInjected: value','X'*32+'\t','X'*32+'\0','X'*32+'\x7f','X'*32+'é'])
def test_unsafe_or_unbounded_token_never_reaches_http(token):
    scope=namespace();scope['request']=lambda *a,**k:pytest.fail('HTTP must not start')
    with pytest.raises(RuntimeError,match='MCP_TOKEN_SHAPE_INVALID'):
        scope['probe']({'bearer_token':token})
