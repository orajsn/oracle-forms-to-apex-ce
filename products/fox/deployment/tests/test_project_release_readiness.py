"""Offline readiness contracts; external IPC/HTTP/filesystem observations are synthetic.

The serialized MCP parser/program and result validators are real. No test
contacts OCI, OPAF, SQLcl or a database, starts a container, or edits live state.
POSIX loader tests run an actual bounded child with no external IO.
"""
from copy import deepcopy
import base64
import hashlib
import importlib.util
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
for folder in (ROOT, ROOT/'fox', ROOT/'converter'):
    if str(folder) not in sys.path:sys.path.insert(0,str(folder))
SPEC = importlib.util.spec_from_file_location('readiness_under_test',ROOT/'deployment/project_release_readiness.py')
M = importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)
ASPEC = importlib.util.spec_from_file_location('activation_for_readiness_test',ROOT/'deployment/activate_project_release.py')
A = importlib.util.module_from_spec(ASPEC);ASPEC.loader.exec_module(A)
TARGET = json.loads((ROOT/'deployment/target-profile.jsn-project-v2.json').read_bytes())
SECRET = 'SYNTHETIC_TOKEN_DO_NOT_LOG_12345678901234567890'


def namespace():
    result = {'__name__':'synthetic_serialized_probe'}
    exec(compile(M.MCP_PROGRAM,'<actual-mcp-program>','exec'),result)
    return result


def rpc(identity,result):
    return json.dumps({'jsonrpc':'2.0','id':identity,'result':result}).encode()


@pytest.mark.parametrize('name',['FOX_PROGRAM','TARGET_PROGRAM','MCP_PROGRAM','LOADER'])
def test_actual_serialized_programs_compile(name):
    compile(getattr(M,name),name,'exec')


@pytest.mark.parametrize('content_type,raw',[
    ('application/json; charset=utf-8',rpc(1,{'value':'ok'})),
    ('text/event-stream',b': priming\r\n\r\ndata:\r\n\r\nevent: message\r\nid: arbitrary\r\ndata: '+rpc(1,{'value':'ok'})+b'\r\n\r\n'),
    ('text/event-stream',b'data: {"jsonrpc":"2.0",\ndata: "id":1,"result":{"value":"ok"}}\n\n'),
    ('text/event-stream',b'\xef\xbb\xbfdata: '+rpc(1,{'value':'ok'})+b'\r\r'),
])
def test_actual_json_and_sse_rpc_parser(content_type,raw):
    assert namespace()['rpc_reply'](raw,content_type,1)=={'value':'ok'}


@pytest.mark.parametrize('raw,kind',[
    (rpc(True,{}),'application/json'),
    (rpc(2,{}),'application/json'),
    (b'{"jsonrpc":"2.0","id":1,"error":{"message":"no"}}','application/json'),
    (b'{"jsonrpc":"2.0","id":1,"id":1,"result":{}}','application/json'),
    (b'{"jsonrpc":"2.0","id":1,"result":{"x":NaN}}','application/json'),
    (b'[]','application/json'),
    (rpc(1,[]),'application/json'),
    (b'data: '+rpc(1,{})+b'\n\ndata: '+rpc(1,{})+b'\n\n','text/event-stream'),
    (b'garbage: value\n\n','text/event-stream'),
    (rpc(1,{}),'text/html'),
    (b'','application/json'),
])
def test_rpc_errors_ids_ambiguity_and_nonfinite_fail_closed(raw,kind):
    with pytest.raises(Exception):namespace()['rpc_reply'](raw,kind,1)


def test_rpc_response_bound():
    with pytest.raises(Exception):namespace()['rpc_reply'](b'x'*1_000_001,'application/json',1)


def http_fixture(monkeypatch, *, mutation=None, cleanup=200):
    ns=namespace();calls=[]
    initialize={'protocolVersion':'2025-03-26','capabilities':{'tools':{}},
                'serverInfo':{'name':'JSN Forms-to-APEX Converter','version':SECRET}}
    tools={'tools':[{'name':name,'description':SECRET,'inputSchema':{}} for name in M.EXPECTED_TOOLS]}
    if mutation=='duplicates':tools['tools'][-1]['name']=tools['tools'][0]['name']
    if mutation=='extra':tools['tools'].append({'name':'extra'})
    if mutation=='missing':tools['tools'].pop()
    if mutation=='cursor':tools['nextCursor']='more'
    if mutation=='nullcursor':tools['nextCursor']=None
    if mutation=='metadata':tools['_meta']={'synthetic-secret':SECRET}
    if mutation=='protocol':initialize['protocolVersion']='unknown'
    if mutation=='server':initialize['serverInfo']['name']='other'
    if mutation=='tools-capability':initialize['capabilities']={}
    class Response:
        def __init__(self,status,headers,body):self.status,self.headers,self.body=status,headers,body
        def getheaders(self):return self.headers
        def read(self,count):return self.body[:count]
    class Connection:
        def __init__(self,host,port,timeout):
            assert (host,port,timeout)==('10.89.1.3',8090,15)
        def request(self,method,path,body,headers):
            value=json.loads(body) if body else None
            calls.append((method,path,value,dict(headers)))
            self.call=calls[-1]
        def getresponse(self):
            method,path,value,headers=self.call
            assert path=='/mcp'
            if method=='DELETE':return Response(cleanup,[],b'')
            if 'Authorization' not in headers:return Response(200 if mutation=='unauthenticated' else 401,[],b'')
            assert headers['Authorization']=='Bearer '+SECRET
            if value.get('method')=='initialize':
                items=[('Content-Type','text/event-stream')]
                if mutation!='session':items.append(('Mcp-Session-Id','synthetic-session-not-returned'))
                if mutation=='duplicate-header':items.append(('mcp-session-id','other-session'))
                return Response(200,items,b': start\n\ndata:\n\nevent: message\ndata: '+rpc(1,initialize)+b'\n\n')
            assert headers['Mcp-Session-Id']=='synthetic-session-not-returned'
            assert headers['MCP-Protocol-Version']=='2025-03-26'
            if value['method']=='notifications/initialized':return Response(202,[],b'')
            assert value['method']=='tools/list'
            return Response(200,[('Content-Type','application/json')],rpc(2,tools))
        def close(self):pass
    monkeypatch.setattr(ns['http'].client,'HTTPConnection',Connection)
    return ns,calls


def test_actual_mcp_program_uses_only_initialize_discovery_and_termination(monkeypatch):
    ns,calls=http_fixture(monkeypatch)
    result=ns['probe']({'bearer_token':SECRET})
    assert M._validate_mcp(result)==result
    assert [value.get('method') if value else 'DELETE' for _,_,value,_ in calls]==[
        'initialize','initialize','notifications/initialized','tools/list','DELETE']
    assert 'tools/call' not in json.dumps(calls)
    assert SECRET not in json.dumps(result)
    assert 'synthetic-session-not-returned' not in json.dumps(result)
    assert result['session_termination_confirmed'] is True


@pytest.mark.parametrize('mutation',['duplicates','extra','missing','cursor','nullcursor','protocol','server','tools-capability','session','unauthenticated','duplicate-header'])
def test_mcp_protocol_drift_is_not_readiness(monkeypatch,mutation):
    ns,calls=http_fixture(monkeypatch,mutation=mutation)
    with pytest.raises(Exception):ns['probe']({'bearer_token':SECRET})
    assert all(value is None or value.get('method')!='tools/call' for _,_,value,_ in calls)


def test_unsupported_session_delete_is_reported_truthfully(monkeypatch):
    ns,_=http_fixture(monkeypatch,cleanup=405)
    assert ns['probe']({'bearer_token':SECRET})['session_termination_confirmed'] is False


def test_standard_result_metadata_is_discarded_not_returned(monkeypatch):
    ns,_=http_fixture(monkeypatch,mutation='metadata')
    assert SECRET not in json.dumps(ns['probe']({'bearer_token':SECRET}))


@pytest.mark.parametrize('token',['short',SECRET+'\r\nInjected: value',SECRET+' '])
def test_bad_bearer_never_reaches_http(monkeypatch,token):
    ns,calls=http_fixture(monkeypatch)
    with pytest.raises(Exception):ns['probe']({'bearer_token':token})
    assert calls==[]


def good_fox():
    t=TARGET
    environments={role:{'schema_version':1,'scope':'opaf-model-environment-v1',
        'trust_boundary':'authenticated_fox_executor_not_vendor_attestation','job_id':'fox-'+'0'*20,'role':role,
        'source_manifest_sha256':'0'*64,'target_profile_sha256':M.TARGET_SHA256,'observed_at_utc':'2026-10-27T00:00:00+00:00',
        'opaf':{key:t['opaf'][key] for key in ('base_url','certificate_sha256','model_authentication','version_number','build_id')},
        'workflow':{**t['opaf']['roles'][role],'published':True},'opaf_version':t['tested_versions']['opaf']}
        for role in ('mapper','reviewer')}
    return {'scope':'fox-project-connections-readonly-v1','target_profile_sha256':M.TARGET_SHA256,
        'worker':{'enabled':True,'healthy':True,'state':'idle'},
        'capabilities':{'schema_version':1,'conversion_profiles':['read-only-html-prototype','native-table-form-v1','native-project-v1'],
            'project_protocol':'native-project-v1','schema_preparation':True,
            'project_mapping':{**t['scope']['project_mapping'],'paired_profile_ready':True}},
        'model_environment':environments,'model_invoked':False,'checkpoint_written':False}


def good_target():
    t=TARGET;o=t['oci']
    return {'scope':'fox-target-readonly-versions-v1','target_profile_sha256':M.TARGET_SHA256,
        'imds':{key:o[key] for key in ('instance_id','compartment_id','region')},
        'oci':{'database_id':o['database_id'],'database_compartment_id':o['compartment_id'],'instance_id':o['instance_id'],
               'instance_compartment_id':o['compartment_id'],'region':o['region'],'database_lifecycle_state':'AVAILABLE','instance_lifecycle_state':'RUNNING'},
        'tooling':{'sqlcl':t['tested_versions']['sqlcl'],'sqlcl_build':'26.1.2.132.1334','apexlang_mmd':t['tested_versions']['apexlang_mmd'],
            'compiler_jar_sha256':'a'*64,'sqlcl_source':'sqlcl_-V','mmd_source':'apexlang-compiler.jar!apexlang_meta_data.json#buildID'},
        'database':{'database':{'db_name':t['database']['db_name'],'session_user':t['database']['session_user'],
                    'current_schema':t['database']['parsing_schema']},
            'apex':{'workspace':t['apex']['workspace'],'workspace_id':t['apex']['workspace_id'],
                    'parsing_schema':t['database']['parsing_schema'],'workspace_schema_mapping_count':1},'apex_version':t['tested_versions']['apex']},
        'ords':{'ords_origin':t['apex']['ords_origin'],'ords_base_path':t['apex']['ords_base_path'],'https_reachable':True},
        'admin_used':False,'database_writes':False,'import_performed':False,'temporary_sql_files_used':True}


def good_mcp():
    return {'scope':'fox-internal-mcp-discovery-v1','source_container':'oracle-applied-ai-label',
        'endpoint':'http://10.89.1.3:8090/mcp','server_name':'JSN Forms-to-APEX Converter','protocol_version':'2025-03-26',
        'unauthenticated_http':401,'tool_names':list(M.EXPECTED_TOOLS),'tool_count':5,'conversion_tools_called':False,
        'protocol_session_created':True,'session_termination_confirmed':True}


@pytest.mark.parametrize('kind',['fox','target','mcp'])
def test_result_validators_reject_extra_secret_field(kind):
    value={'fox':good_fox,'target':good_target,'mcp':good_mcp}[kind]()
    value['password']=SECRET
    with pytest.raises(M.ReadinessError) as error:
        getattr(M,'_validate_'+kind)(value,*(() if kind=='mcp' else (TARGET,)))
    assert SECRET not in str(error.value)


@pytest.mark.parametrize('mutation',['published-int','workflow','model','date','role-secret','checkpoint','capability','worker'])
def test_model_environment_and_worker_claims_are_exact(mutation):
    value=good_fox()
    if mutation=='published-int':value['model_environment']['mapper']['workflow']['published']=1
    if mutation=='workflow':value['model_environment']['reviewer']['workflow']['workflow_id']='0'*32
    if mutation=='model':value['model_environment']['mapper']['workflow']['model']='other'
    if mutation=='date':value['model_environment']['mapper']['observed_at_utc']='bad'
    if mutation=='role-secret':value['model_environment']['reviewer']['opaf']['api_key']=SECRET
    if mutation=='checkpoint':value['checkpoint_written']=True
    if mutation=='capability':value['capabilities']['project_mapping']['paired_profile_ready']=False
    if mutation=='worker':value['worker']['healthy']=False
    with pytest.raises(M.ReadinessError):M._validate_fox(value,TARGET)


@pytest.mark.parametrize('mutation',['compartment','db-name','schema','version','ords','admin','mapping-bool','compiler'])
def test_target_claims_are_exact_and_read_only(mutation):
    value=good_target()
    if mutation=='compartment':value['oci']['database_compartment_id']='other'
    if mutation=='db-name':value['database']['database']['db_name']='other'
    if mutation=='schema':value['database']['database']['current_schema']='ADMIN'
    if mutation=='version':value['database']['apex_version']='26.1.1'
    if mutation=='ords':value['ords']['ords_origin']='https://other.invalid'
    if mutation=='admin':value['admin_used']=True
    if mutation=='mapping-bool':value['database']['apex']['workspace_schema_mapping_count']=True
    if mutation=='compiler':value['tooling']['compiler_jar_sha256']=SECRET
    with pytest.raises(M.ReadinessError):M._validate_target(value,TARGET)


def guard_fixture(monkeypatch):
    release={'images':{'fox':'sha256:'+'a'*64,'converter':'sha256:'+'b'*64}}
    records={'fox':{'id':'1'*64,'image':release['images']['fox']},'converter':{'id':'2'*64,'image':release['images']['converter']}}
    items={}
    for role,name in (('fox','fox'),('converter','forms2apex-mcp'),('opaf','oracle-applied-ai-label')):
        pin=records[role] if role!='opaf' else {'id':A.BASE[name][0],'image':'sha256:'+A.BASE[name][1]}
        items[pin['id']]={'Id':pin['id'],'Name':name,'Image':pin['image'],'State':{'Running':True,'Pid':123,'StartedAt':'2026-10-27T00:00:00Z'},
            'NetworkSettings':{'Networks':{'forms2apex':{'IPAddress':'10.89.1.3'}}},
            'Config':{'Env':['F2A_MCP_BEARER_TOKEN='+SECRET]}}
    monkeypatch.setattr(A,'host_identity',lambda:None)
    monkeypatch.setattr(A,'inspect_container',lambda identity:deepcopy(items[identity]))
    return release,records,items


def test_token_is_only_framed_stdin_never_argv_or_environment(monkeypatch):
    release,records,_=guard_fixture(monkeypatch);captured=[]
    def transport(argv,**kwargs):
        captured.append((argv,kwargs))
        header,raw=kwargs['input'].split(b'\n',1)
        header=json.loads(header);code=base64.b64decode(header['code'])
        assert code.decode()==M.MCP_PROGRAM and hashlib.sha256(code).hexdigest()==header['sha256']
        assert json.loads(raw)=={'bearer_token':SECRET}
        return SimpleNamespace(returncode=0,stderr=b'',stdout=json.dumps({'ok':True,'result':good_mcp()}).encode())
    monkeypatch.setattr(M.subprocess,'run',transport)
    assert M._exec(A,release,records,role='opaf',program=M.MCP_PROGRAM,payload={'bearer_token':SECRET},deadline=60)==good_mcp()
    argv,kwargs=captured[0]
    assert SECRET not in repr(argv) and SECRET not in repr(kwargs['env'])
    assert kwargs['timeout']==80 and argv[:4]==['/usr/bin/podman','exec','-i',A.BASE['oracle-applied-ai-label'][0]]


@pytest.mark.parametrize('failure',['stderr','exit','timeout','response','restart'])
def test_transport_uncertainty_and_restart_do_not_leak_provider_output(monkeypatch,failure):
    release,records,items=guard_fixture(monkeypatch)
    def transport(argv,**kwargs):
        if failure=='timeout':raise subprocess.TimeoutExpired(argv,80,output=SECRET.encode(),stderr=SECRET.encode())
        if failure=='restart':items[A.BASE['oracle-applied-ai-label'][0]]['State']['Pid']+=1
        return SimpleNamespace(returncode=1 if failure=='exit' else 0,stderr=SECRET.encode() if failure=='stderr' else b'',
            stdout=SECRET.encode() if failure=='response' else json.dumps({'ok':True,'result':good_mcp()}).encode())
    monkeypatch.setattr(M.subprocess,'run',transport)
    with pytest.raises(M.ReadinessError) as error:
        M._exec(A,release,records,role='opaf',program=M.MCP_PROGRAM,payload={'bearer_token':SECRET},deadline=60)
    assert SECRET not in str(error.value)


@pytest.mark.parametrize('name',['../x','x/../x','/absolute','a\\b','x//y'])
def test_serialized_source_reader_rejects_unsafe_members(tmp_path,name):
    ns={};exec(M.COMMON,ns)
    with pytest.raises(Exception):ns['sources'](tmp_path,{name:'a'*64})


def test_serialized_source_reader_hashes_actual_bytes_including_empty_files(tmp_path):
    ns={};exec(M.COMMON,ns)
    (tmp_path/'source.py').write_bytes(b'# synthetic source\n')
    (tmp_path/'REQUESTED').write_bytes(b'')
    pins={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in tmp_path.iterdir()}
    ns['sources'](tmp_path,pins)
    (tmp_path/'source.py').write_bytes(b'# changed\n')
    with pytest.raises(Exception):ns['sources'](tmp_path,pins)


@pytest.mark.skipif(os.name!='posix',reason='SIGALRM is the actual Linux container deadline')
@pytest.mark.parametrize('failure',[False,True,'alarm'])
def test_actual_loader_discards_incidental_output_and_bounds_failure(failure):
    code="def probe(p):\n import sys\n print(p['secret']);print(p['secret'],file=sys.stderr)\n"
    if failure=='alarm':code+=' import signal;signal.raise_signal(signal.SIGALRM)\n'
    elif failure:code+=" raise RuntimeError(p['secret'])\n"
    else:code+=" return {'checked':True}\n"
    header={'code':base64.b64encode(code.encode()).decode(),'sha256':hashlib.sha256(code.encode()).hexdigest(),'deadline_seconds':60}
    outcome=subprocess.run([sys.executable,'-I','-B','-c',M.LOADER],input=M.canonical(header)+b'\n'+M.canonical({'secret':SECRET}),
        capture_output=True,timeout=10)
    assert SECRET.encode() not in outcome.stdout+outcome.stderr
    assert not outcome.stderr
    value=json.loads(outcome.stdout)
    assert outcome.returncode==(2 if failure else 0)
    assert value==({'ok':False,'code':'READINESS_PROBE_UNCONFIRMED'} if failure else {'ok':True,'result':{'checked':True}})


@pytest.mark.skipif(os.name!='posix',reason='Actual Linux SIGALRM and child exit')
def test_deadline_during_mcp_tools_never_starts_blocking_delete():
    # The actual MCP program and loader run unchanged. Only the external HTTP
    # transport is synthetic. DELETE would block well beyond this test bound.
    fake_http=r'''
import signal,time
class Response:
 def __init__(self,status,body=b'',headers=()):self.status,self.body,self.headers=status,body,headers
 def read(self,count):return self.body[:count]
 def getheaders(self):return self.headers
class Connection:
 def __init__(self,*args,**kwargs):pass
 def request(self,method,path,body,headers):self.method,self.payload,self.headers=method,json.loads(body) if body else None,headers
 def getresponse(self):
  if self.method=='DELETE':time.sleep(5);return Response(200)
  if 'Authorization' not in self.headers:return Response(401)
  if self.payload['method']=='initialize':return Response(200,json.dumps({'jsonrpc':'2.0','id':1,'result':{'protocolVersion':'2025-03-26','capabilities':{'tools':{}},'serverInfo':{'name':'JSN Forms-to-APEX Converter'}}}).encode(),[('Content-Type','application/json'),('Mcp-Session-Id','synthetic')])
  if self.payload['method']=='notifications/initialized':return Response(202)
  signal.raise_signal(signal.SIGALRM)
 def close(self):pass
http.client.HTTPConnection=Connection
'''
    code=(M.MCP_PROGRAM+fake_http).encode()
    header={'code':base64.b64encode(code).decode(),'sha256':hashlib.sha256(code).hexdigest(),'deadline_seconds':60}
    started=time.monotonic()
    outcome=subprocess.run([sys.executable,'-I','-B','-c',M.LOADER],
        input=M.canonical(header)+b'\n'+M.canonical({'bearer_token':SECRET}),capture_output=True,timeout=3)
    assert time.monotonic()-started<3 and outcome.returncode==2
    assert json.loads(outcome.stdout)=={'ok':False,'code':'READINESS_PROBE_UNCONFIRMED'}
    assert not outcome.stderr and SECRET.encode() not in outcome.stdout


def orchestration_fixture(monkeypatch):
    """Actual release/result validators, synthetic filesystem/Podman/IPC edges."""
    bridge=importlib.import_module('qa.operator.product_queue_transport')
    release,records,items=guard_fixture(monkeypatch)
    inventory={'schema_version':1,'scope':'fox-hosted-source-inventory-v1','files':{
        'converter/forms2apex/'+name+'.py':'a'*64 for name in ('runtime_preflight','config','oci_identity','target_profile','server')}}
    inventory_raw=A.canonical(inventory);b=A.sha(inventory_raw)
    root=Path('/home/opc/.local/share/fox-project-builds/'+b+'/bundle')
    native_sha=A.sha((ROOT/'deployment/project-opaf-profile-v2.json').read_bytes())
    # This test exercises the ref/hash boundary, not full provider admission;
    # the caller's production C validator is covered by candidate/service tests.
    provider_raw=A.canonical({'scope':'synthetic-opaque-provider-ref','target':M.TARGET_SHA256})
    provider_sha=A.sha(provider_raw)
    release.update(schema_version=3,scope=bridge.HOSTED_SCOPE,enabled=True,
        modules={name:'a'*64 for name in bridge.MODULES},
        code={name:A.sha((ROOT/'qa/operator'/name).read_bytes()) for name in bridge.HOSTED_CODE},
        clean_operator_code_sha256='a'*64,qa_source_sha256='a'*64,promotion_transport_sha256='a'*64,
        native_profile_sha256=native_sha,target=bridge.TARGET,hosted_runtime_configuration_sha256=provider_sha,
        opaf_profile={'path':'deployment/project-opaf-profile-v2.json','sha256':native_sha,
            'target_profile_sha256':M.TARGET_SHA256,'host_path':root.as_posix()+'/deployment/project-opaf-profile-v2.json'},
        project={**{name:'a'*64 for name in bridge.PROJECT_HASHES},
                 'modules':{name:'a'*64 for name in bridge.PROJECT_MODULES},
                 'queue_modules':{name:'a'*64 for name in bridge.PROJECT_QUEUE_MODULES}})
    assert bridge.validate_release(release)==release
    plan={'schema_version':1,'scope':A.SCOPE,'source_bundle_sha256':b,'bundle_root':root.as_posix(),
          'provider':{'path':'/home/opc/private/provider.json','sha256':provider_sha},
          'release':{'path':'/home/opc/private/release.json','sha256':A.sha(A.canonical(release))},
          'helper_sha256':A.sha(Path(A.__file__).read_bytes())}
    filesystem={Path(plan['release']['path']):A.canonical(release),root.parent/'source-inventory.json':inventory_raw,
                Path(plan['provider']['path']):provider_raw,
                root/'deployment/target-profile.jsn-project-v2.json':A.canonical(TARGET),
                Path(bridge.__file__).absolute():Path(bridge.__file__).read_bytes()}
    monkeypatch.setattr(A,'read',lambda path,**kwargs:filesystem[Path(path)])
    calls=[];outputs={'fox':good_fox(),'converter':good_target(),'opaf':good_mcp()}
    def transport(argv,**kwargs):
        header,payload=kwargs['input'].split(b'\n',1);header=json.loads(header);payload=json.loads(payload)
        code=base64.b64decode(header['code']).decode()
        role={M.FOX_PROGRAM:'fox',M.TARGET_PROGRAM:'converter',M.MCP_PROGRAM:'opaf'}[code]
        calls.append((role,argv,kwargs,payload))
        if role in ('fox','converter'):assert payload['target_profile']==TARGET
        if role=='opaf':assert payload=={'bearer_token':SECRET}
        return SimpleNamespace(returncode=0,stderr=b'',stdout=json.dumps({'ok':True,'result':outputs[role]}).encode())
    monkeypatch.setattr(M.subprocess,'run',transport)
    return plan,release,records,filesystem,calls,outputs


def test_full_orchestration_uses_real_validators_and_only_readonly_programs(monkeypatch):
    plan,release,records,files,calls,outputs=orchestration_fixture(monkeypatch)
    result=M.run(A,plan,release,records)
    assert [row[0] for row in calls]==['fox','converter','opaf']
    assert result['status']=='READ_ONLY_CONNECTIVITY_CONFIRMED'
    assert result['model_invoked'] is result['database_writes'] is result['import_performed'] is result['human_acceptance_recorded'] is False
    assert SECRET not in json.dumps(result)
    for _,argv,kwargs,_ in calls:
        assert SECRET not in repr(argv) and SECRET not in repr(kwargs['env'])
    assert result['fox']==good_fox() and result['target']==good_target() and result['mcp']==good_mcp()


@pytest.mark.parametrize('mutation',['release-reference','provider-reference','source-inventory','target-file','mapper','target-output','mcp-output'])
def test_full_orchestration_stops_on_binding_or_observation_drift(monkeypatch,mutation):
    plan,release,records,files,calls,outputs=orchestration_fixture(monkeypatch)
    root=Path(plan['bundle_root'])
    if mutation=='release-reference':files[Path(plan['release']['path'])]=b'{}\n'
    if mutation=='provider-reference':files[Path(plan['provider']['path'])]=b'{}\n'
    if mutation=='source-inventory':files[root.parent/'source-inventory.json']=b'{}\n'
    if mutation=='target-file':files[root/'deployment/target-profile.jsn-project-v2.json']=b'{}\n'
    if mutation=='mapper':outputs['fox']['model_environment']['mapper']['workflow']['model']='other'
    if mutation=='target-output':outputs['converter']['credential']=SECRET
    if mutation=='mcp-output':outputs['opaf']['tool_count']=6
    with pytest.raises(M.ReadinessError) as error:M.run(A,plan,release,records)
    assert SECRET not in str(error.value)
    assert len(calls)=={'release-reference':0,'provider-reference':0,'source-inventory':0,'target-file':0,'mapper':1,'target-output':2,'mcp-output':3}[mutation]
