"""Read-only setup observations for an already-running, exact JSN paired release.

No service/container lifecycle action, import, model invocation or acceptance.
The saved parsing-schema probe creates and removes its own temporary SQL files;
MCP initialization creates an ephemeral protocol session. Neither is a claim
of zero filesystem/protocol effects. No credential enters argv, environment,
logs or returned evidence. This module has no CLI and performs no work at import.
Database-write flags concern the target database; server-side authentication
or audit effects are not inspected or claimed absent.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import importlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import time
import types

TARGET_SHA256 = '7170d60927b7e5b7aed5d56174f97efbeff3052be247b244911deff768701ed3'
EXPECTED_TOOLS = ('generate_apex_draft', 'get_job_status', 'import_validated_draft',
                  'inspect_forms_job', 'validate_apex_draft')
MAX_WIRE = 262_144
MAX_RESPONSE = 262_144
_SHA = re.compile(r'[a-f0-9]{64}\Z')


class ReadinessError(RuntimeError):
    """Closed error codes only; provider output and credentials are discarded."""


def need(value, code):
    if not value:
        raise ReadinessError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _same(value, expected, code):
    try:
        need(canonical(value) == canonical(expected), code)
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise ReadinessError(code) from None


def _validate_fox(value, target):
    need(type(value) is dict and set(value) == {'scope','target_profile_sha256','worker','capabilities',
         'model_environment','model_invoked','checkpoint_written'}, 'FOX_RESULT_FIELDS_INVALID')
    worker = value['worker']
    need(type(worker) is dict and worker.get('state') in ('idle','polling'), 'FOX_WORKER_RESULT_INVALID')
    expected_caps = {'schema_version':1,'conversion_profiles':['read-only-html-prototype','native-table-form-v1','native-project-v1'],
        'project_protocol':'native-project-v1','schema_preparation':True,
        'project_mapping':{**target['scope']['project_mapping'],'paired_profile_ready':True}}
    observations = value['model_environment']
    need(type(observations) is dict and set(observations) == {'mapper','reviewer'}, 'MODEL_OBSERVATIONS_INVALID')
    expected_observations = {}
    for role in ('mapper','reviewer'):
        observed = observations[role]
        stamp = observed.get('observed_at_utc') if type(observed) is dict else None
        need(type(stamp) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|\+00:00)',stamp),
             'MODEL_OBSERVATION_TIME_INVALID')
        try:
            datetime.fromisoformat(stamp.replace('Z','+00:00'))
        except ValueError:
            raise ReadinessError('MODEL_OBSERVATION_TIME_INVALID') from None
        expected_observations[role] = {'schema_version':1,'scope':'opaf-model-environment-v1',
            'trust_boundary':'authenticated_fox_executor_not_vendor_attestation','job_id':'fox-'+'0'*20,'role':role,
            'source_manifest_sha256':'0'*64,'target_profile_sha256':TARGET_SHA256,'observed_at_utc':stamp,
            'opaf':{key:target['opaf'][key] for key in ('base_url','certificate_sha256','model_authentication','version_number','build_id')},
            'workflow':{**target['opaf']['roles'][role],'published':True},'opaf_version':target['tested_versions']['opaf']}
    _same(value,{'scope':'fox-project-connections-readonly-v1','target_profile_sha256':TARGET_SHA256,
        'worker':{'enabled':True,'healthy':True,'state':worker['state']},'capabilities':expected_caps,
        'model_environment':expected_observations,'model_invoked':False,'checkpoint_written':False}, 'FOX_RESULT_CHANGED')
    return value


def _validate_target(value, target):
    need(type(value) is dict and set(value) == {'scope','target_profile_sha256','imds','oci','tooling','database','ords',
         'admin_used','database_writes','import_performed','temporary_sql_files_used'}, 'TARGET_RESULT_FIELDS_INVALID')
    tooling = value['tooling']
    need(type(tooling) is dict and type(tooling.get('sqlcl_build')) is str
         and re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,8}',tooling['sqlcl_build'])
         and type(tooling.get('compiler_jar_sha256')) is str and _SHA.fullmatch(tooling['compiler_jar_sha256']),
         'TOOLING_RESULT_INVALID')
    oci = target['oci']
    _same(value,{'scope':'fox-target-readonly-versions-v1','target_profile_sha256':TARGET_SHA256,
        'imds':{key:oci[key] for key in ('instance_id','compartment_id','region')},
        'oci':{'database_id':oci['database_id'],'database_compartment_id':oci['compartment_id'],
               'instance_id':oci['instance_id'],'instance_compartment_id':oci['compartment_id'],'region':oci['region'],
               'database_lifecycle_state':'AVAILABLE','instance_lifecycle_state':'RUNNING'},
        'tooling':{'sqlcl':target['tested_versions']['sqlcl'],'sqlcl_build':tooling['sqlcl_build'],
            'apexlang_mmd':target['tested_versions']['apexlang_mmd'],'compiler_jar_sha256':tooling['compiler_jar_sha256'],
            'sqlcl_source':'sqlcl_-V','mmd_source':'apexlang-compiler.jar!apexlang_meta_data.json#buildID'},
        'database':{'database':{'db_name':target['database']['db_name'],'session_user':target['database']['session_user'],
            'current_schema':target['database']['parsing_schema']},
            'apex':{'workspace':target['apex']['workspace'],'workspace_id':target['apex']['workspace_id'],
                    'parsing_schema':target['database']['parsing_schema'],'workspace_schema_mapping_count':1},
            'apex_version':target['tested_versions']['apex']},
        'ords':{'ords_origin':target['apex']['ords_origin'],'ords_base_path':target['apex']['ords_base_path'],'https_reachable':True},
        'admin_used':False,'database_writes':False,'import_performed':False,'temporary_sql_files_used':True}, 'TARGET_RESULT_CHANGED')
    return value


def _validate_mcp(value):
    need(type(value) is dict and type(value.get('session_termination_confirmed')) is bool, 'MCP_RESULT_INVALID')
    _same(value,{'scope':'fox-internal-mcp-discovery-v1','source_container':'oracle-applied-ai-label',
        'endpoint':'http://10.89.1.3:8090/mcp','server_name':'JSN Forms-to-APEX Converter','protocol_version':'2025-03-26',
        'unauthenticated_http':401,'tool_names':list(EXPECTED_TOOLS),'tool_count':5,'conversion_tools_called':False,
        'protocol_session_created':True,'session_termination_confirmed':value['session_termination_confirmed']}, 'MCP_RESULT_CHANGED')
    return value


COMMON = r'''
import hashlib,json,os,pathlib,re,sys
class ProbeError(RuntimeError):pass
def need(ok,code):
 if not ok:raise ProbeError(code)
def unique(rows):
 out={}
 for k,v in rows:
  need(k not in out,'DUPLICATE_JSON_KEY');out[k]=v
 return out
def parsed(raw):
 return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ProbeError('NONFINITE_JSON')))
def digest(value):
 return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()).hexdigest()
def sources(root,pins):
 need(type(pins) is dict and 0<len(pins)<=2000,'SOURCE_PINS_REQUIRED')
 total=0
 for name,expected in pins.items():
  rel=pathlib.PurePosixPath(name)
  need(type(name) is str and str(rel)==name and not rel.is_absolute() and '..' not in rel.parts and '\\' not in name
   and type(expected) is str and re.fullmatch('[a-f0-9]{64}',expected),'SOURCE_PIN_INVALID')
  path=root/name
  need(path.is_file() and not path.is_symlink() and path.resolve(strict=True)==path and path.stat().st_size<=8000000,'SOURCE_FILE_INVALID')
  raw=path.read_bytes();total+=len(raw)
  need(total<=80000000 and hashlib.sha256(raw).hexdigest()==expected,'SOURCE_BYTES_CHANGED')
'''

FOX_PROGRAM = COMMON + r'''
def probe(packet):
 import urllib.request
 need(set(packet)=={'modules','target_profile','native_profile_sha256','release_sha256'},'FOX_PACKET_INVALID')
 root=pathlib.Path('/app/fox');sources(root,packet['modules'])
 need(os.environ.get('FOX_CONVERSION_PROFILE')=='native-project-v1'
  and os.environ.get('FOX_VERIFIER_RELEASE_SHA256')==packet['release_sha256']
  and os.environ.get('FOX_NATIVE_PROFILE_FILE')=='/run/fox-native/profile.json'
  and os.environ.get('FOX_OPAF_CREDENTIAL_FILE')=='/run/fox-opaf/client.json'
  and os.environ.get('FOX_CONVERTER_URL')=='http://127.0.0.1:8091','FOX_CONFIGURATION_CHANGED')
 profile_file=pathlib.Path('/run/fox-native/profile.json')
 need(profile_file.is_file() and not profile_file.is_symlink() and profile_file.resolve(strict=True)==profile_file
  and profile_file.stat().st_size<=65536,'MOUNTED_PROFILE_INVALID')
 native_raw=profile_file.read_bytes()
 need(hashlib.sha256(native_raw).hexdigest()==packet['native_profile_sha256'],'MOUNTED_PROFILE_CHANGED')
 sys.path.insert(0,'/app')
 from fox.native_project_pipeline import _configuration,PROJECT_MAPPING_CAPABILITY
 profile,gateway,client=_configuration()
 target=packet['target_profile']
 need(digest(target)=='7170d60927b7e5b7aed5d56174f97efbeff3052be247b244911deff768701ed3','TARGET_CHANGED')
 envelope=gateway.request('GET','/fox/target-profile')
 need(envelope=={'target_profile':target,'target_profile_sha256':digest(target)},'CONVERTER_TARGET_CHANGED')
 capabilities=gateway.request('GET','/fox/capabilities')
 expected={'schema_version':1,'conversion_profiles':['read-only-html-prototype','native-table-form-v1','native-project-v1'],
  'project_protocol':'native-project-v1','schema_preparation':True,
  'project_mapping':{**PROJECT_MAPPING_CAPABILITY,'paired_profile_ready':True}}
 need(capabilities==expected,'CONVERTER_CAPABILITY_CHANGED')
 need(profile['schema_version']==2 and profile['profile_id']=='native-project-v1'
  and {k:profile[k] for k in ('mapper','reviewer')}==target['opaf']['roles'],'PAIRED_MODEL_PROFILE_CHANGED')
 request={'job_id':'fox-'+'0'*20,'source_hash':'0'*64}
 observations={}
 for role in ('mapper','reviewer'):
  observations[role]=client.observe_environment(profile[role],request,role_name=role,target_profile=target)
 class NoRedirect(urllib.request.HTTPRedirectHandler):
  def redirect_request(self,*args,**kwargs):return None
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
 with opener.open('http://127.0.0.1:8100/api/health',timeout=10) as response:
  need(response.status==200,'FOX_HEALTH_NOT_READY');raw=response.read(65537)
 need(len(raw)<=65536,'FOX_HEALTH_TOO_LARGE');health=parsed(raw)
 worker=health.get('worker',{})
 need(health.get('product')=='FOX' and health.get('status')=='ok'
  and worker.get('enabled') is True and worker.get('healthy') is True
  and worker.get('state') in ('idle','polling'),'FOX_WORKER_NOT_READY')
 sources(root,packet['modules'])
 need(profile_file.read_bytes()==native_raw,'MOUNTED_PROFILE_CHANGED_DURING_READ')
 return {'scope':'fox-project-connections-readonly-v1','target_profile_sha256':digest(target),
  'worker':{'enabled':True,'healthy':True,'state':worker['state']},'capabilities':capabilities,
  'model_environment':observations,'model_invoked':False,'checkpoint_written':False}
'''

TARGET_PROGRAM = COMMON + r'''
def probe(packet):
 import dataclasses,tempfile
 need(set(packet)=={'files','target_profile'},'TARGET_PACKET_INVALID')
 root=pathlib.Path('/opt/forms2apex/converter');sources(root,packet['files'])
 sys.path[:0]=['/opt/forms2apex/converter','/usr/local/lib64/python3.11/site-packages','/usr/local/lib/python3.11/site-packages']
 from forms2apex.config import Settings
 from forms2apex.runtime_preflight import bound_target_profile,collect_imds_identity,collect_tooling_versions,collect_database_identity,collect_ords_reachability
 from forms2apex.oci_identity import collect_oci_identity
 settings=Settings.from_env();profile=bound_target_profile(settings)
 need(profile==packet['target_profile'] and digest(profile)=='7170d60927b7e5b7aed5d56174f97efbeff3052be247b244911deff768701ed3','TARGET_CHANGED')
 # Verify actual approved OCI resources before opening the saved DB connection.
 imds=collect_imds_identity(profile);oci=collect_oci_identity(profile,imds)
 tooling=collect_tooling_versions(settings,profile)
 with tempfile.TemporaryDirectory(prefix='fox-release-readiness-') as directory:
  base=pathlib.Path(directory);job=base/'identity';job.mkdir(mode=0o700)
  database=collect_database_identity(dataclasses.replace(settings,jobs_root=base),profile,job)
 ords=collect_ords_reachability(profile)
 sources(root,packet['files'])
 return {'scope':'fox-target-readonly-versions-v1','target_profile_sha256':digest(profile),
  'imds':imds,'oci':oci,'tooling':tooling,'database':database,'ords':ords,
  'admin_used':False,'database_writes':False,'import_performed':False,'temporary_sql_files_used':True}
'''

MCP_PROGRAM = COMMON + r'''
import http.client
TOOLS=('generate_apex_draft','get_job_status','import_validated_draft','inspect_forms_job','validate_apex_draft')
PROTOCOL='2025-03-26'
def rpc_reply(raw,content_type,identity):
 need(type(raw) is bytes and 0<len(raw)<=1000000,'MCP_RESPONSE_BOUND')
 content_type=content_type.split(';',1)[0].strip().lower()
 if content_type=='application/json':values=[parsed(raw)]
 elif content_type=='text/event-stream':
  values=[];data=[]
  for line in raw.decode('utf-8-sig').replace('\r\n','\n').replace('\r','\n').split('\n')+['']:
   if line=='':
    if data:
     joined='\n'.join(data)
     if joined.strip():values.append(parsed(joined))
    data=[]
   elif line.startswith('data:'):data.append(line[5:].removeprefix(' '))
   elif line.startswith(':') or line.startswith(('event:','id:','retry:')):pass
   else:need(False,'MCP_SSE_FIELD_INVALID')
  need(len(values)<=128,'MCP_EVENT_BOUND')
 else:need(False,'MCP_RESPONSE_TYPE_INVALID')
 matches=[]
 for value in values:
  need(type(value) is dict and value.get('jsonrpc')=='2.0','MCP_RPC_INVALID')
  if 'id' in value:
   need(type(value['id']) is int and value['id']==identity,'MCP_RPC_ID_CHANGED');matches.append(value)
 need(len(matches)==1 and set(matches[0])=={'jsonrpc','id','result'} and type(matches[0]['result']) is dict,'MCP_RPC_RESULT_INVALID')
 return matches[0]['result']
def request(method,payload,token=None,session=None):
 headers={'Content-Type':'application/json','Accept':'application/json, text/event-stream'}
 if token is not None:headers['Authorization']='Bearer '+token
 if session is not None:
  headers['Mcp-Session-Id']=session;headers['MCP-Protocol-Version']=PROTOCOL
 connection=http.client.HTTPConnection('10.89.1.3',8090,timeout=15)
 try:
  connection.request(method,'/mcp',json.dumps(payload).encode() if payload is not None else None,headers)
  response=connection.getresponse();raw=response.read(1000001)
  need(len(raw)<=1000000,'MCP_RESPONSE_BOUND')
  pairs=[(key.lower(),value) for key,value in response.getheaders()]
  need(all(sum(key==name for key,_ in pairs)<=1 for name in ('content-type','mcp-session-id')),'MCP_HEADER_AMBIGUOUS')
  return response.status,dict(pairs),raw
 finally:connection.close()
def probe(packet):
 need(set(packet)=={'bearer_token'} and type(packet['bearer_token']) is str
  and re.fullmatch(r'[!-~]{32,4096}',packet['bearer_token']),'MCP_TOKEN_SHAPE_INVALID')
 token=packet['bearer_token'];session=None
 initialize={'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':PROTOCOL,
  'capabilities':{},'clientInfo':{'name':'fox-release-readiness','version':'1'}}}
 status,_,_=request('POST',initialize)
 need(status==401,'MCP_UNAUTHENTICATED_REQUEST_NOT_REJECTED')
 terminated=False
 try:
  status,headers,raw=request('POST',initialize,token)
  need(status==200,'MCP_INITIALIZE_FAILED')
  value=rpc_reply(raw,headers.get('content-type',''),1)
  need(value.get('protocolVersion')==PROTOCOL and value.get('serverInfo',{}).get('name')=='JSN Forms-to-APEX Converter'
   and type(value.get('capabilities',{}).get('tools')) is dict,'MCP_SERVER_CHANGED')
  session=headers.get('mcp-session-id')
  need(type(session) is str and re.fullmatch(r'[!-~]{1,4096}',session),'MCP_SESSION_HEADER_INVALID')
  status,_,_=request('POST',{'jsonrpc':'2.0','method':'notifications/initialized'},token,session)
  need(status in (200,202,204),'MCP_INITIALIZED_FAILED')
  status,headers,raw=request('POST',{'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}},token,session)
  need(status==200,'MCP_TOOLS_LIST_FAILED')
  result=rpc_reply(raw,headers.get('content-type',''),2)
  need(set(result) in ({'tools'},{'tools','_meta'}) and ('_meta' not in result or type(result['_meta']) is dict)
   and type(result['tools']) is list and len(result['tools'])==5,'MCP_TOOL_COUNT_OR_PAGINATION_CHANGED')
  names=[tool.get('name') if type(tool) is dict else None for tool in result['tools']]
  need(len(set(names))==5 and sorted(names)==list(TOOLS),'MCP_TOOL_NAMES_CHANGED')
 finally:
  # A deadline is not permission to begin another blocking cleanup request.
  # Closing the HTTP connection in request() is local; leave server-side
  # protocol-session expiry unclaimed when the owned deadline has fired.
  if session is not None and globals().get('_deadline_expired') is not True:
   status,_,_=request('DELETE',None,token,session)
   need(status in (200,202,204,404,405),'MCP_SESSION_TERMINATION_UNCONFIRMED')
   terminated=status in (200,202,204,404)
 return {'scope':'fox-internal-mcp-discovery-v1','source_container':'oracle-applied-ai-label',
  'endpoint':'http://10.89.1.3:8090/mcp','server_name':'JSN Forms-to-APEX Converter','protocol_version':PROTOCOL,
  'unauthenticated_http':401,'tool_names':list(TOOLS),'tool_count':5,'conversion_tools_called':False,
  'protocol_session_created':True,'session_termination_confirmed':terminated}
'''

LOADER = r'''
import base64,contextlib,hashlib,io,json,re,signal,sys
class Sink:
 def write(self,text):return len(text)
 def flush(self):pass
def expired(*_):
 namespace['_deadline_expired']=True
 raise TimeoutError('IN_CONTAINER_DEADLINE')
try:
 header_raw=sys.stdin.buffer.readline(262145)
 if len(header_raw)>262144 or not header_raw.endswith(b'\n'):raise ValueError()
 header=json.loads(header_raw);code=base64.b64decode(header['code'],validate=True)
 if set(header)!={'code','sha256','deadline_seconds'} or hashlib.sha256(code).hexdigest()!=header['sha256'] or type(header['deadline_seconds']) is not int or header['deadline_seconds'] not in (60,120,240):raise ValueError()
 raw=sys.stdin.buffer.read(262145)
 if len(raw)>262144:raise ValueError()
 packet=json.loads(raw)
 namespace={'__name__':'reviewed_readiness_probe','_deadline_expired':False}
 signal.signal(signal.SIGALRM,expired);signal.alarm(header['deadline_seconds'])
 with contextlib.redirect_stdout(Sink()),contextlib.redirect_stderr(Sink()):
  exec(compile(code,'<reviewed-readiness-probe>','exec'),namespace)
  result=namespace['probe'](packet)
 signal.alarm(0)
 print(json.dumps({'ok':True,'result':result},sort_keys=True))
except Exception:
 if hasattr(signal,'alarm'):signal.alarm(0)
 print('{"ok":false,"code":"READINESS_PROBE_UNCONFIRMED"}')
 raise SystemExit(2)
'''


def _guard(A, release, records):
    A.host_identity()
    need(type(records) is dict and set(records) == {'fox','converter'}, 'CANDIDATE_RECORDS_REQUIRED')
    projections, containers = {}, {}
    for role, name in (('fox','fox'),('converter','forms2apex-mcp'),('opaf','oracle-applied-ai-label')):
        pin = ({'id':A.BASE[name][0],'image':'sha256:'+A.BASE[name][1]} if role == 'opaf' else records[role])
        need(type(pin) is dict and _SHA.fullmatch(pin.get('id',''))
             and type(pin.get('image')) is str and re.fullmatch('sha256:[a-f0-9]{64}',pin['image']), 'CONTAINER_PIN_INVALID')
        if role != 'opaf':need(pin['image'] == release['images'][role], 'CONTAINER_IMAGE_BINDING_CHANGED')
        item = A.inspect_container(pin['id'])
        state = item['State']
        need(item['Id'] == pin['id'] and item['Name'].lstrip('/') == name
             and 'sha256:'+item['Image'].split(':')[-1] == pin['image']
             and state['Running'] is True and type(state['Pid']) is int and state['Pid'] > 0
             and type(state['StartedAt']) is str and 0 < len(state['StartedAt']) <= 100, 'EXACT_RUNNING_CONTAINER_REQUIRED')
        if role == 'converter':
            need(item['NetworkSettings']['Networks']['forms2apex']['IPAddress'] == '10.89.1.3', 'MCP_CONTAINER_ADDRESS_CHANGED')
        projections[role] = {**{key:pin[key] for key in ('id','image')},'pid':state['Pid'],'started_at':state['StartedAt']}
        containers[role] = item
    return projections, containers


def _exec(A, release, records, *, role, program, payload, deadline):
    before, containers = _guard(A,release,records)
    code = program.encode()
    header = {'code':base64.b64encode(code).decode(),'sha256':hashlib.sha256(code).hexdigest(),'deadline_seconds':deadline}
    packet = canonical(header)+b'\n'+canonical(payload)
    need(len(packet) <= MAX_WIRE and deadline in (60,120,240), 'READINESS_REQUEST_BOUND')
    executable = '/usr/local/bin/python' if role == 'fox' else 'python3.11' if role == 'converter' else 'python3'
    argv = ['/usr/bin/podman','exec','-i',containers[role]['Id'],executable,'-I','-B','-c',LOADER]
    try:
        result = subprocess.run(argv,input=packet,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=deadline+20,
            env={'PATH':'/usr/bin:/bin','HOME':'/home/opc','XDG_RUNTIME_DIR':'/run/user/1000','LANG':'C.UTF-8'},cwd='/')
        need(result.returncode == 0 and not result.stderr.strip() and 0 < len(result.stdout) <= MAX_RESPONSE,
             role.upper()+'_READINESS_UNCONFIRMED_NO_AUTOMATIC_RETRY')
        value = json.loads(result.stdout)
        need(type(value) is dict and set(value) == {'ok','result'} and value['ok'] is True and type(value['result']) is dict,
             'READINESS_RESPONSE_INVALID')
        after,_ = _guard(A,release,records)
        need(after == before,'CONTAINER_CHANGED_DURING_READINESS')
        return value['result']
    except ReadinessError:
        raise
    except Exception:
        raise ReadinessError(role.upper()+'_READINESS_UNCONFIRMED_NO_AUTOMATIC_RETRY') from None


def _curl_scalar(value):
    need(type(value)is str and not any(c in value for c in ('\r','\n','\0')),'MCP_CURL_CONFIG_VALUE_INVALID')
    return '"'+value.replace('\\','\\\\').replace('"','\\"')+'"'


def _curl_mcp_request(A,release,records,method,payload,*,token=None,session=None,deadline_at=None):
    """HTTP actually originates in OPAF; credentials occur only on stdin."""
    before,containers=_guard(A,release,records)
    headers=['Content-Type: application/json','Accept: application/json, text/event-stream']
    if token is not None:
        need(type(token)is str and re.fullmatch('[!-~]{32,4096}',token),'MCP_TOKEN_SHAPE_INVALID')
        headers.append('Authorization: Bearer '+token)
    if session is not None:
        need(type(session)is str and re.fullmatch('[!-~]{1,4096}',session),'MCP_SESSION_HEADER_INVALID')
        headers += ['Mcp-Session-Id: '+session,'MCP-Protocol-Version: 2025-03-26']
    lines=['url = '+_curl_scalar('http://10.89.1.3:8090/mcp'),'request = '+_curl_scalar(method)]
    lines += ['header = '+_curl_scalar(value) for value in headers]
    if payload is not None:
        lines.append('data = '+_curl_scalar(json.dumps(payload,separators=(',',':'),ensure_ascii=True,allow_nan=False)))
    config=('\n'.join(lines)+'\n').encode('ascii')
    need(len(config)<=32768,'MCP_CURL_CONFIG_BOUND')
    remaining=20 if deadline_at is None else deadline_at-time.monotonic()
    need(remaining>0,'MCP_DISCOVERY_DEADLINE_EXPIRED')
    argv=['/usr/bin/podman','exec','-i',containers['opaf']['Id'],'/usr/bin/curl','-q','--silent','--show-error',
        '--http1.1','--noproxy','*','--connect-timeout','5','--max-time',str(min(15,remaining)),'--max-filesize','1048576',
        '--include','--config','-']
    try:
        response=subprocess.run(argv,input=config,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=min(20,remaining),
            env={'PATH':'/usr/bin:/bin','HOME':'/home/opc','XDG_RUNTIME_DIR':'/run/user/1000','LANG':'C.UTF-8'},cwd='/')
    except Exception:
        raise ReadinessError('OPAF_CURL_UNCONFIRMED_NO_AUTOMATIC_RETRY') from None
    need(response.returncode==0 and not response.stderr.strip() and 0<len(response.stdout)<=1114112,
         'OPAF_CURL_UNCONFIRMED_NO_AUTOMATIC_RETRY')
    raw=response.stdout
    # No redirects/proxy/credentials are configured. Permit bounded interim
    # HTTP responses, then parse one exact header block and its unchanged body.
    for _ in range(4):
        boundary=raw.find(b'\r\n\r\n')
        need(0<boundary<=65536,'MCP_HTTP_HEADER_BOUND')
        head,body=raw[:boundary],raw[boundary+4:]
        rows=head.decode('iso-8859-1').split('\r\n')
        match=re.fullmatch(r'HTTP/1\.[01] ([0-9]{3})(?: [^\r\n]*)?',rows[0])
        need(match is not None,'MCP_HTTP_STATUS_INVALID');status=int(match.group(1))
        if 100<=status<200:
            raw=body;continue
        headers={}
        for row in rows[1:]:
            need(':' in row and not row.startswith((' ','\t')),'MCP_HTTP_HEADER_INVALID')
            name,value=row.split(':',1);name=name.lower();value=value.strip()
            if name in ('content-type','mcp-session-id'):
                need(name not in headers,'MCP_HEADER_AMBIGUOUS');headers[name]=value
        need(len(body)<=1000000,'MCP_RESPONSE_BOUND')
        after,_=_guard(A,release,records);need(after==before,'CONTAINER_CHANGED_DURING_READINESS')
        return status,headers,body
    raise ReadinessError('MCP_TOO_MANY_INTERIM_HEADERS')


def _mcp_rpc_reply(raw,content_type,identity):
    """The same bounded JSON/SSE and exact RPC result contract as the probe."""
    need(type(raw)is bytes and 0<len(raw)<=1000000,'MCP_RESPONSE_BOUND')
    def parsed(value):
        def unique(items):
            result={}
            for key,item in items:
                need(key not in result,'DUPLICATE_JSON_KEY');result[key]=item
            return result
        try:
            return json.loads(value,object_pairs_hook=unique,
                parse_constant=lambda _:(_ for _ in ()).throw(ReadinessError('NONFINITE_JSON')))
        except ReadinessError:raise
        except Exception:raise ReadinessError('MCP_RPC_JSON_INVALID') from None
    kind=content_type.split(';',1)[0].strip().lower()
    if kind=='application/json':values=[parsed(raw)]
    elif kind=='text/event-stream':
        values=[];data=[]
        try:lines=raw.decode('utf-8-sig').replace('\r\n','\n').replace('\r','\n').split('\n')+['']
        except UnicodeError:raise ReadinessError('MCP_RPC_JSON_INVALID') from None
        for line in lines:
            if line=='':
                if data:
                    joined='\n'.join(data)
                    if joined.strip():values.append(parsed(joined))
                data=[]
            elif line.startswith('data:'):data.append(line[5:].removeprefix(' '))
            elif line.startswith(':') or line.startswith(('event:','id:','retry:')):pass
            else:raise ReadinessError('MCP_SSE_FIELD_INVALID')
        need(len(values)<=128,'MCP_EVENT_BOUND')
    else:raise ReadinessError('MCP_RESPONSE_TYPE_INVALID')
    matches=[]
    for value in values:
        need(type(value)is dict and value.get('jsonrpc')=='2.0','MCP_RPC_INVALID')
        if 'id' in value:
            need(type(value['id'])is int and value['id']==identity,'MCP_RPC_ID_CHANGED');matches.append(value)
    need(len(matches)==1 and set(matches[0])=={'jsonrpc','id','result'}
         and type(matches[0]['result'])is dict,'MCP_RPC_RESULT_INVALID')
    return matches[0]['result']


def _probe_mcp_curl(A,release,records,token):
    need(type(token)is str and re.fullmatch('[!-~]{32,4096}',token),'MCP_TOKEN_SHAPE_INVALID')
    deadline=time.monotonic()+60
    def request(method,payload,**kwargs):
        return _curl_mcp_request(A,release,records,method,payload,deadline_at=deadline,**kwargs)
    protocol='2025-03-26'
    initialize={'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':protocol,
        'capabilities':{},'clientInfo':{'name':'fox-release-readiness','version':'1'}}}
    status,_,_=request('POST',initialize)
    need(status==401,'MCP_UNAUTHENTICATED_REQUEST_NOT_REJECTED')
    session=None;terminated=False
    try:
        status,headers,raw=request('POST',initialize,token=token)
        need(status==200,'MCP_INITIALIZE_FAILED')
        value=_mcp_rpc_reply(raw,headers.get('content-type',''),1)
        need(value.get('protocolVersion')==protocol and value.get('serverInfo',{}).get('name')=='JSN Forms-to-APEX Converter'
             and type(value.get('capabilities',{}).get('tools'))is dict,'MCP_SERVER_CHANGED')
        session=headers.get('mcp-session-id')
        need(type(session)is str and re.fullmatch('[!-~]{1,4096}',session),'MCP_SESSION_HEADER_INVALID')
        status,_,_=request('POST',{'jsonrpc':'2.0','method':'notifications/initialized'},token=token,session=session)
        need(status in (200,202,204),'MCP_INITIALIZED_FAILED')
        status,headers,raw=request('POST',{'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}},token=token,session=session)
        need(status==200,'MCP_TOOLS_LIST_FAILED')
        value=_mcp_rpc_reply(raw,headers.get('content-type',''),2)
        need(set(value) in ({'tools'},{'tools','_meta'}) and ('_meta' not in value or type(value['_meta'])is dict)
             and type(value['tools'])is list and len(value['tools'])==5,'MCP_TOOL_COUNT_OR_PAGINATION_CHANGED')
        names=[tool.get('name') if type(tool)is dict else None for tool in value['tools']]
        need(len(set(names))==5 and sorted(names)==list(EXPECTED_TOOLS),'MCP_TOOL_NAMES_CHANGED')
    finally:
        if session is not None and time.monotonic()<deadline:
            status,_,_=request('DELETE',None,token=token,session=session)
            need(status in (200,202,204,404,405),'MCP_SESSION_TERMINATION_UNCONFIRMED')
            terminated=status in (200,202,204,404)
    return {'scope':'fox-internal-mcp-discovery-v1','source_container':'oracle-applied-ai-label',
        'endpoint':'http://10.89.1.3:8090/mcp','server_name':'JSN Forms-to-APEX Converter','protocol_version':protocol,
        'unauthenticated_http':401,'tool_names':list(EXPECTED_TOOLS),'tool_count':5,'conversion_tools_called':False,
        'protocol_session_created':True,'session_termination_confirmed':terminated}


def run(A, plan, release, candidate_records):
    """Observe services after the caller's C/R admission; recheck both pinned refs.

    Component result validators are not injectable. This read-only helper is
    not a substitute for the installation's source/owner/lease admission.
    """
    need(type(A) is types.ModuleType and hashlib.sha256(Path(A.__file__).read_bytes()).hexdigest() == plan['helper_sha256'],
         'REVIEWED_CANDIDATE_HELPER_REQUIRED')
    A.plan_document(A.canonical(plan),A.sha(A.canonical(plan)))
    need(type(release) is dict and release.get('schema_version') == 3 and release.get('enabled') is True
         and hashlib.sha256(A.canonical(release)).hexdigest() == plan['release']['sha256']
         and release['opaf_profile']['target_profile_sha256'] == TARGET_SHA256,'EXACT_RELEASE_REQUIRED')
    need(A.read(Path(plan['release']['path']),private=True) == A.canonical(release),'RELEASE_REFERENCE_CHANGED')
    provider_raw = A.read(Path(plan['provider']['path']),private=True)
    need(hashlib.sha256(provider_raw).hexdigest() == plan['provider']['sha256']
         and release['hosted_runtime_configuration_sha256'] == plan['provider']['sha256'], 'PROVIDER_REFERENCE_CHANGED')
    bridge = importlib.import_module('qa.operator.product_queue_transport')
    need(hashlib.sha256(A.read(Path(bridge.__file__).absolute())).hexdigest() == release['code']['product_queue_transport.py'],
         'RELEASE_VALIDATOR_SOURCE_CHANGED')
    try:
        need(bridge.validate_release(release) == release,'RELEASE_CONTRACT_CHANGED')
    except Exception:
        raise ReadinessError('RELEASE_CONTRACT_CHANGED') from None
    root = Path(plan['bundle_root'])
    inventory_raw = A.read(root.parent/'source-inventory.json',private=True)
    need(hashlib.sha256(inventory_raw).hexdigest() == plan['source_bundle_sha256'],'SOURCE_INVENTORY_CHANGED')
    inventory = A.parse(inventory_raw)
    need(type(inventory) is dict and set(inventory) == {'schema_version','scope','files'}
         and inventory['schema_version'] == 1 and inventory['scope'] == 'fox-hosted-source-inventory-v1'
         and type(inventory['files']) is dict,'SOURCE_INVENTORY_INVALID')
    converter_files = {name[len('converter/'):]:value for name,value in inventory['files'].items() if name.startswith('converter/')}
    need({'forms2apex/runtime_preflight.py','forms2apex/config.py','forms2apex/oci_identity.py','forms2apex/target_profile.py',
          'forms2apex/server.py'} <= set(converter_files),'CONVERTER_SOURCE_BINDING_INCOMPLETE')
    target = A.parse(A.read(root/'deployment/target-profile.jsn-project-v2.json'))
    need(digest(target) == TARGET_SHA256,'EXACT_TARGET_REQUIRED')
    modules = {**release['modules'],**release['project']['modules'],**release['project']['queue_modules']}
    need({'opaf.py','native_project_pipeline.py','native_pipeline.py'} <= set(modules),'FOX_SOURCE_BINDING_INCOMPLETE')
    before,_ = _guard(A,release,candidate_records)
    fox = _validate_fox(_exec(A,release,candidate_records,role='fox',program=FOX_PROGRAM,deadline=120,
        payload={'modules':modules,'target_profile':target,'native_profile_sha256':release['native_profile_sha256'],
                 'release_sha256':plan['release']['sha256']}),target)
    target_result = _validate_target(_exec(A,release,candidate_records,role='converter',program=TARGET_PROGRAM,deadline=240,
                         payload={'files':converter_files,'target_profile':target}),target)
    _, containers = _guard(A,release,candidate_records)
    token = A.environment(containers['converter']).get('F2A_MCP_BEARER_TOKEN')
    # StaticTokenVerifier uses an opaque token, not necessarily base64/JWT.
    # Enforce bounded visible ASCII/no whitespace or controls; actual 401 and
    # authenticated discovery below establish correctness, never shape alone.
    need(type(token) is str and re.fullmatch(r'[!-~]{32,4096}',token),'MCP_CREDENTIAL_REFERENCE_INVALID')
    mcp = _validate_mcp(_probe_mcp_curl(A,release,candidate_records,token))
    del token
    need(fox.get('scope') == 'fox-project-connections-readonly-v1' and fox.get('target_profile_sha256') == TARGET_SHA256
         and fox.get('model_invoked') is False and fox.get('checkpoint_written') is False
         and target_result.get('scope') == 'fox-target-readonly-versions-v1' and target_result.get('target_profile_sha256') == TARGET_SHA256
         and all(target_result.get(key) is False for key in ('admin_used','database_writes','import_performed'))
         and mcp.get('scope') == 'fox-internal-mcp-discovery-v1' and mcp.get('tool_names') == list(EXPECTED_TOOLS)
         and mcp.get('tool_count') == 5 and mcp.get('conversion_tools_called') is False,'READINESS_RESULT_SCOPE_CHANGED')
    after,_ = _guard(A,release,candidate_records)
    need(after == before,'CONTAINER_CHANGED_DURING_READINESS')
    return {'schema_version':1,'scope':'fox-paired-release-readiness-v1','status':'READ_ONLY_CONNECTIVITY_CONFIRMED',
        'release_sha256':plan['release']['sha256'],'target_profile_sha256':TARGET_SHA256,
        'observed_at_utc':datetime.now(timezone.utc).isoformat(),'containers':after,
        'fox':fox,'target':target_result,'mcp':mcp,'model_invoked':False,'database_writes':False,
        'application_generated':False,'import_performed':False,'human_acceptance_recorded':False,'services_changed':False,
        'temporary_sql_files_used':True,'automatic_retry_permitted':False}
