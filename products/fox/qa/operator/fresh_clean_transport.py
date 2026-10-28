"""Selected fresh clean-install host programs, not admission or execution.

Compile installation-owned names/mounts/pins into the program, never accept
them as request overrides. General fresh execution and ADMIN retrieval remain
fenced until the concrete held-lease authority and all consumers are integrated.
No process, secret, SQL or filesystem mutation occurs during program creation.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from . import runtime_provider as runtime


class FreshCleanTransportError(RuntimeError):
    """Closed diagnostic codes only; private context/output is not a message."""


def need(value, code):
    if not value:raise FreshCleanTransportError(code)


def converter_environment(config, projection, app_projection_sha256):
    """Exact install-owned converter settings; no secret values or readiness."""
    target = config['target_profile']
    return {'F2A_INSTALLATION_MODE': 'fresh',
        'F2A_FRESH_PROVIDER_SHA256': projection['provider_configuration_sha256'],
        'F2A_FRESH_PROJECTION_SHA256': app_projection_sha256,
        'F2A_FRESH_BACKEND_SHA256': projection['backend_initialization_sha256'],
        'F2A_VERIFIER_RELEASE_SHA256': projection['release_sha256'],
        'F2A_JOBS_ROOT': '/opt/forms2apex/outputs/jobs', 'F2A_TARGET_PROFILE_PATH': '/run/fox-target/profile.json',
        'F2A_SQLCL_PATH': '/opt/sqlcl/bin/sql', 'F2A_SQLCL_CONNECTION_NAME': target['sqlcl']['saved_connection'],
        'F2A_APEX_WORKSPACE': target['apex']['workspace'], 'F2A_APEX_PARSING_SCHEMA': target['database']['parsing_schema'],
        'F2A_APEX_BASE_URL': target['apex']['ords_origin'] + target['apex']['ords_base_path'],
        'TNS_ADMIN': '/opt/forms2apex/wallet', 'PYTHONNOUSERSITE': '1'}


def program(kind):
    """Return a fresh-only host program, or None for unchanged legacy callers."""
    need(kind in ('source', 'native', 'project'), 'FRESH_CLEAN_PROGRAM_KIND_INVALID')
    provider = runtime.selected_hosted()
    need(provider is None or type(provider) in (runtime.HostedProvider, runtime.FreshHostedProvider),
         'CONCRETE_FRESH_CLEAN_PROVIDER_REQUIRED')
    if not isinstance(provider, runtime.FreshHostedProvider):
        need(runtime.execution_runtime() is None, 'CONCRETE_FRESH_CLEAN_PROVIDER_REQUIRED')
        return None
    need(type(provider) is runtime.FreshHostedProvider, 'CONCRETE_FRESH_CLEAN_PROVIDER_REQUIRED')
    config = provider.configuration; projection = provider.runtime_projection()
    references = dict(provider.references_raw)
    release = json.loads(references[json.loads(provider.release_reference_raw)['path']])
    plan = json.loads(references[config['storage']['plan']['path']])
    from . import clean_install as native, project_clean_install as project
    source_root = Path(config['converter_root']).parent
    # These exact app source files are already independently measured by C3/R4.
    # Load only their inert public-record readers in the isolated host program.
    sources = {}
    for name in ('installation.py', 'fresh_startup.py'):
        raw = runtime._read(source_root / 'fox/fox' / name, 2_000_000)
        need(hashlib.sha256(raw).hexdigest() == release['modules'][name], 'FRESH_CLEAN_PUBLIC_READER_CHANGED')
        sources[name] = base64.b64encode(raw).decode()
    code = native.SOURCE_CODE if kind == 'source' else native.EXECUTOR_CODE if kind == 'native' else project.EXECUTOR_CODE
    context = {'kind': kind, 'owner_uid': config['owner_uid'], 'projection': projection,
        'app_projection_sha256': config['app_projection']['sha256'],
        'private_paths': [config['admin_secret_file'], config['state_root'], plan['roots']['records']],
        'converter_environment': converter_environment(config, projection, config['app_projection']['sha256']),
        'operator_code_sha256': (None if kind == 'source' else release['clean_operator_code_sha256']
                                if kind == 'native' else release['project']['clean_operator_code_sha256']),
        'public_reader_sources': sources, 'code': code}
    need(provider.configuration == config, 'FRESH_CLEAN_CONFIGURATION_CHANGED')
    result = _compile(context, native.HOST_PREFIX, runtime.fresh_mount_program())
    need(len(result.encode('utf-8')) <= runtime.MAX_PROGRAM, 'FRESH_CLEAN_PROGRAM_BOUND')
    return result


def _compile(context, host_prefix, mount_program):
    """Internal compiler; this construction seam grants no caller authority."""
    constants = 'context=' + repr(context) + '\nmount_program=' + repr(mount_program) + '\n'
    return host_prefix + '\n' + constants + HOST_BODY


HOST_BODY = r'''
import io,os,types
from pathlib import Path
from contextlib import redirect_stdout,redirect_stderr
try:
 guard(os.geteuid()==context['owner_uid']>0)
 guard(not any(key.startswith('LD_') or key in ('CONTAINER_HOST','CONTAINER_CONNECTION',
  'PODMAN_CONNECTIONS_CONF','PYTHONHOME','PYTHONPATH') for key in os.environ))
 projection=context['projection'];roles=projection['runtime']['roles']
 guard(set(roles)=={'fox','converter','opaf'} and roles['fox']['name'].startswith('fox-fresh-')
  and roles['converter']['name'].startswith('forms2apex-fresh-'))
 wanted='fox' if context['kind']=='source' else 'converter'
 guard(p.get('fox_image' if wanted=='fox' else 'image')==roles[wanted]['image'])
 code=context['code'];encoded_key='reader_b64' if wanted=='fox' else 'executor_b64'
 guard(p.get(encoded_key)==base64.b64encode(code.encode()).decode())
 if wanted=='converter':
  guard(p.get('command') in ('check','status','apply') and type(p.get('apply')) is bool
   and p['apply'] is (p['command']=='apply')
   and (p.get('phase') in ('allocate','schema','import','verify') if p['apply'] else p.get('phase') is None))
  guard(p.get('operator_code_sha256')==context['operator_code_sha256'])
  guard(p['command']!='status' or 'admin_password' not in p)
 # The mounted public P/F/A bindings are checked without mounting or opening
 # FOX's SQLite into the converter. This is not the missing host lease check.
 saved={key:value for key,value in sys.modules.items() if key=='fox' or key.startswith('fox.')}
 for key in saved:del sys.modules[key]
 package=types.ModuleType('fox');package.__path__=[];sys.modules['fox']=package
 readers={}
 try:
  for filename in ('installation.py','fresh_startup.py'):
   name='fox.'+filename[:-3];module=types.ModuleType(name);module.__package__='fox'
   sys.modules[name]=module
   exec(compile(base64.b64decode(context['public_reader_sources'][filename],validate=True),filename,'exec'),module.__dict__)
   readers[filename]=module
 finally:
  for key in tuple(sys.modules):
   if key=='fox' or key.startswith('fox.'):del sys.modules[key]
  sys.modules.update(saved)
 public=Path(projection['runtime']['public_configuration']['directory'])
 reader=readers['fresh_startup.py'];install=readers['installation.py']
 guard(public.resolve(strict=True)==public and public.is_dir()
  and {x.name for x in public.iterdir()}==set(reader.PUBLIC_FILENAMES))
 def public_records():
  guard({x.name for x in public.iterdir()}==set(reader.PUBLIC_FILENAMES))
  raw={name:reader._read(public/name) for name in reader.PUBLIC_FILENAMES}
  app=install.parse_projection(raw['projection.json'],expected_sha256=context['app_projection_sha256'])
  guard(app['installation_id']==projection['installation_id'])
  guard(hashlib.sha256(raw['backend-initialization.json']).hexdigest()==projection['backend_initialization_sha256'])
  backend=reader._parse(raw['backend-initialization.json'],reader.BACKEND_FIELDS)
  base={'installation_id':app['installation_id'],'storage_completion_sha256':app['storage_completion_sha256'],
   'app_projection_sha256':context['app_projection_sha256'],
   'provider_configuration_sha256':projection['provider_configuration_sha256'],
   'release_sha256':projection['release_sha256']}
  guard(type(backend['schema_version']) is int and backend['schema_version']==1
   and backend['scope']=='fox-fresh-backend-initialization-v1'
   and all(backend[k]==v for k,v in base.items()) and backend['storage_plan_sha256']==app['storage_plan_sha256']
   and reader._hash(backend['intent_sha256']) and reader._hash(backend['backend_schema_sha256'])
   and reader._canonical(backend['initial_counts'])==reader._canonical(reader.INITIAL_COUNTS))
  admission=reader._parse(raw['live-admission.json'],reader.ADMISSION_FIELDS)
  guard(type(admission['schema_version']) is int and admission['schema_version']==1
   and admission['scope']=='fox-fresh-live-admission-v1' and all(admission[k]==v for k,v in base.items())
   and admission['backend_initialization_sha256']==projection['backend_initialization_sha256']
   and all(reader._hash(admission[k]) for k in ('admission_sha256','installation_sha256','live_observation_sha256'))
   and admission['transition']=='INITIAL_TO_NORMAL' and admission['automatic_replay_permitted'] is False
   and reader._utc(admission['observed_at_utc'])>=reader._utc(backend['completed_at_utc']))
  return raw
 before=public_records()
 def inspect_roles():
  packet={'projection':projection,'projection_sha256':hashlib.sha256((json.dumps(projection,
   sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode()).hexdigest(),
   'private_paths':context['private_paths']}
  capture=io.StringIO();old=sys.stdin
  try:
   sys.stdin=io.StringIO(json.dumps(packet))
   with redirect_stdout(capture),redirect_stderr(io.StringIO()):exec(compile(mount_program,'<fresh-mount-check>','exec'),{})
  finally:sys.stdin=old
  result=json.loads(capture.getvalue());guard(result['safe'] is True)
  return result['observed_roles']
 observed=inspect_roles();target=observed[wanted]['container_id']
 # Reinspect by the observed immutable ID before reading its environment.
 r=subprocess.run(['/usr/bin/podman','--remote=false','inspect','--',target],
  stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
 guard(r.returncode==0 and not r.stderr.strip() and 0<len(r.stdout)<=2000000)
 details=json.loads(r.stdout);guard(type(details) is list and len(details)==1 and details[0]['Id']==target)
 guard(details[0]['State']['Running'] is True and details[0]['Image'] in
  (roles[wanted]['image'],roles[wanted]['image'][7:]) and details[0]['Config']['User']==roles[wanted]['user']
  and details[0]['HostConfig']['ReadonlyRootfs'] is roles[wanted]['read_only_rootfs'])
 entries=details[0]['Config'].get('Env');guard(type(entries) is list and len(entries)<=256)
 guard(all(type(x) is str and '=' in x and len(x)<=8192 for x in entries))
 environment=dict(x.split('=',1) for x in entries);guard(len(environment)==len(entries))
 guard(not any(key.startswith('LD_') for key in environment))
 expected=({'FOX_INSTALLATION_MODE':'fresh','FOX_VERIFICATION_ENABLED':'1',
  'FOX_DATA_DIR':'/data','FOX_FRESH_PUBLIC_CONFIG_DIR':'/run/fox-installation',
  'FOX_NATIVE_PROFILE_FILE':'/run/fox-native/profile.json','FOX_CONVERSION_PROFILE':'native-project-v1',
  'FOX_RUN_ADAPTER':'embedded-opaf','FOX_CONVERTER_URL':projection['runtime']['converter_endpoint'],
  'FOX_VERIFIER_RELEASE_SHA256':projection['release_sha256'],
  'FOX_FRESH_PROVIDER_SHA256':projection['provider_configuration_sha256'],
  'FOX_FRESH_PROJECTION_SHA256':context['app_projection_sha256'],
  'FOX_FRESH_BACKEND_SHA256':projection['backend_initialization_sha256']}
  if wanted=='fox' else context['converter_environment'])
 guard(all(environment.get(k)==v for k,v in expected.items()))
 paths=['/app'] if wanted=='fox' else ['/opt/forms2apex/converter',
  '/usr/local/lib64/python3.11/site-packages','/usr/local/lib/python3.11/site-packages']
 loader='import base64,sys;sys.path[:0]='+repr(paths)+';exec(compile(base64.b64decode(sys.stdin.buffer.readline(),validate=True),"<fresh-clean-container>","exec"))'
 wire=base64.b64encode(code.encode())+b'\n'+json.dumps(p,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()+b'\n'
 binary='/usr/local/bin/python' if wanted=='fox' else '/usr/bin/python3.11'
 r=subprocess.run(['/usr/bin/podman','--remote=false','exec','-i','--user',roles[wanted]['user'],
  '--env','LD_PRELOAD=','--env','LD_AUDIT=','--env','LD_LIBRARY_PATH=',target,binary,'-I','-B','-c',loader],
  input=wire,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45 if wanted=='fox' else 1400)
 guard(r.returncode==0 and not r.stderr.strip() and 0<len(r.stdout)<=(16000000 if wanted=='fox' else 2000000))
 result=json.loads(r.stdout)
 guard(type(result) is dict and public_records()==before and inspect_roles()==observed)
 print(json.dumps(result,sort_keys=True))
except Exception:
 print(json.dumps({'status':'STOPPED','code':'FRESH_CLEAN_TRANSPORT_OUTCOME_UNCONFIRMED_NO_REPLAY',
  'automatic_replay_permitted':False},sort_keys=True))
'''
