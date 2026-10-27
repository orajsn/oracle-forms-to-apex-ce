"""Real curl framing/RPC parser with simulated subprocess/HTTP only."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('curl_readiness_tests',ROOT/'deployment/project_release_readiness.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
TOKEN='AuthoredSyntheticOnly-'+'X'*32+'!:"\\#$'


def fixture(monkeypatch,*,sse=False,change=None):
    release={'images':{'fox':'sha256:'+'a'*64,'converter':'sha256:'+'b'*64}}
    records={'fox':{'id':'1'*64,'image':release['images']['fox']},'converter':{'id':'2'*64,'image':release['images']['converter']}}
    base={'oracle-applied-ai-label':('3'*64,'c'*64)}
    objects={}
    for role,name in (('fox','fox'),('converter','forms2apex-mcp'),('opaf','oracle-applied-ai-label')):
        pin=records[role] if role!='opaf' else {'id':base[name][0],'image':'sha256:'+base[name][1]}
        objects[pin['id']]={'Id':pin['id'],'Name':name,'Image':pin['image'],
            'State':{'Running':True,'Pid':12,'StartedAt':'2026-10-27T01:00:00Z'},
            'NetworkSettings':{'Networks':{'forms2apex':{'IPAddress':'10.89.1.3'}}}}
    A=SimpleNamespace(BASE=base,host_identity=lambda:None,inspect_container=lambda cid:deepcopy(objects[cid]))
    calls=[]
    def transport(argv,**kwargs):
        assert argv[:6]==['/usr/bin/podman','exec','-i','3'*64,'/usr/bin/curl','-q']
        assert TOKEN not in repr(argv) and TOKEN not in repr(kwargs['env']) and kwargs['timeout']<=20
        options={};headers=[]
        for line in kwargs['input'].decode('ascii').splitlines():
            key,value=line.split(' = ',1);value=json.loads(value)
            if key=='header':headers.append(value)
            else:options[key]=value
        assert options['url']=='http://10.89.1.3:8090/mcp'
        calls.append((options,headers));authenticated='Authorization: Bearer '+TOKEN in headers
        status=200;body=b'';extra={};ctype='application/json'
        if not authenticated:status=200 if change=='unauth-accepted' else 401;body=b'{}'
        elif options['request']=='DELETE':status=405 if change=='delete-not-supported' else 204
        else:
            packet=json.loads(options['data']);method=packet['method']
            if method=='initialize':
                extra['Mcp-Session-Id']='synthetic-session'
                value={'protocolVersion':'2025-03-26','serverInfo':{'name':'JSN Forms-to-APEX Converter'},'capabilities':{'tools':{}}}
                if change=='wrong-server':value['serverInfo']['name']='other-server'
            elif method=='notifications/initialized':status=202;value=None
            else:
                names=list(M.EXPECTED_TOOLS)
                if change=='six-tools':names.append('unapproved')
                if change=='duplicate-tool':names[0]=names[-1]
                value={'tools':[{'name':name} for name in names]}
            if value is not None:
                body=json.dumps({'jsonrpc':'2.0','id':packet['id'],'result':value}).encode()
                if sse:body=b'event: message\r\ndata: '+body+b'\r\n\r\n';ctype='text/event-stream'
        head='HTTP/1.1 '+str(status)+' Synthetic\r\nContent-Type: '+ctype+'\r\n'
        head+=''.join(k+': '+v+'\r\n' for k,v in extra.items())+'\r\n'
        return SimpleNamespace(returncode=0,stderr=b'',stdout=head.encode()+body)
    monkeypatch.setattr(M.subprocess,'run',transport)
    return A,release,records,calls


@pytest.mark.parametrize('sse',[False,True])
def test_exact_five_tools_from_opaf_curl_with_stdin_only_opaque_token(monkeypatch,sse):
    A,release,records,calls=fixture(monkeypatch,sse=sse)
    result=M._validate_mcp(M._probe_mcp_curl(A,release,records,TOKEN))
    assert result['tool_names']==list(M.EXPECTED_TOOLS) and result['unauthenticated_http']==401
    assert result['session_termination_confirmed'] is True and len(calls)==5
    assert not any('Authorization:' in h for h in calls[0][1])
    assert 'Authorization: Bearer '+TOKEN in calls[1][1]
    assert calls[-1][0]['request']=='DELETE' and 'Mcp-Session-Id: synthetic-session' in calls[-1][1]


@pytest.mark.parametrize('change',['unauth-accepted','wrong-server','six-tools','duplicate-tool'])
def test_auth_server_or_tool_drift_never_produces_readiness(monkeypatch,change):
    A,release,records,calls=fixture(monkeypatch,change=change)
    with pytest.raises(M.ReadinessError):M._probe_mcp_curl(A,release,records,TOKEN)


def test_unsupported_session_delete_is_reported_not_claimed(monkeypatch):
    A,release,records,calls=fixture(monkeypatch,change='delete-not-supported')
    result=M._validate_mcp(M._probe_mcp_curl(A,release,records,TOKEN))
    assert result['session_termination_confirmed'] is False


@pytest.mark.parametrize('value',['bad\r\nheader','bad\0value','bad\nvalue'])
def test_curl_config_cannot_accept_header_or_config_line_injection(value):
    with pytest.raises(M.ReadinessError,match='MCP_CURL_CONFIG_VALUE_INVALID'):M._curl_scalar(value)


def test_rpc_duplicate_keys_and_ambiguous_ids_reject():
    with pytest.raises(M.ReadinessError):M._mcp_rpc_reply(b'{"jsonrpc":"2.0","id":1,"id":1,"result":{}}','application/json',1)
    with pytest.raises(M.ReadinessError):M._mcp_rpc_reply(b'{"jsonrpc":"2.0","id":true,"result":{}}','application/json',1)
