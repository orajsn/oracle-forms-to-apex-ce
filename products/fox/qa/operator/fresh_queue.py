"""Fresh queue container adapter; not host execution or admission authority.

Reuses the existing queue dispatcher after genuine local startup-fence checks.
The provider and R4 supervisor remain fenced pending full transport/admission
integration. Building a packet/program never claims a job or grants permission.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import os
from pathlib import Path, PurePosixPath
import re

from . import product_queue_transport as queue
from . import fresh_contracts as contracts

SCOPE = 'fox-fresh-queue-request-v1'
RELEASE_SCOPE = contracts.SCOPES['release']
MODULES = contracts.MODULES
CODE = contracts.CODE
PROJECT_MODULES = contracts.PROJECT_MODULES
QUEUE_MODULES = contracts.QUEUE_MODULES
PROJECT_HASHES = contracts.PROJECT_HASHES
TARGET = dict(queue.TARGET)


class FreshQueueError(RuntimeError):
    """Closed diagnostics; private claims and captured output are not messages."""


def need(value, code):
    if not value:raise FreshQueueError(code)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                       allow_nan=False) + '\n').encode('utf-8')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def hashed(value):
    return type(value) is str and re.fullmatch(r'[a-f0-9]{64}', value) is not None


def hash_map(value, names):
    need(type(value) is dict and set(value) == set(names) and all(hashed(x) for x in value.values()),
         'FRESH_QUEUE_SOURCE_MAP_INVALID')


def validate_release(value):
    """Wire consistency only; independent mounted hashes/fence are required."""
    fields = {'schema_version', 'scope', 'installation_mode', 'enabled', 'images', 'modules', 'code',
        'clean_operator_code_sha256', 'qa_source_sha256', 'promotion_transport_sha256',
        'native_profile_sha256', 'target', 'project', 'hosted_runtime_configuration_sha256', 'opaf_profile'}
    need(type(value) is dict and set(value) == fields and type(value['schema_version']) is int
         and value['schema_version'] == 4 and value['scope'] == RELEASE_SCOPE
         and value['installation_mode'] == 'fresh' and value['enabled'] is True,
         'FRESH_QUEUE_RELEASE_REQUIRED')
    need(type(value['images']) is dict and set(value['images']) == {'fox', 'converter'}
         and all(type(x) is str and re.fullmatch(r'sha256:[a-f0-9]{64}', x) for x in value['images'].values())
         and value['images']['fox'] != H_FOX_IMAGE, 'FRESH_QUEUE_IMAGES_INVALID')
    hash_map(value['modules'], MODULES);hash_map(value['code'], CODE)
    for name in ('clean_operator_code_sha256', 'qa_source_sha256', 'promotion_transport_sha256',
                 'native_profile_sha256', 'hosted_runtime_configuration_sha256'):
        need(hashed(value[name]), 'FRESH_QUEUE_RELEASE_DIGEST_INVALID')
    need(type(value['target']) is dict and value['target'] == TARGET, 'FRESH_QUEUE_JSN_TARGET_REQUIRED')
    profile = value['opaf_profile']
    need(type(profile) is dict and set(profile) == {'path', 'sha256', 'target_profile_sha256'}
         and type(profile['path']) is str and re.fullmatch(r'/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+', profile['path'])
         and str(PurePosixPath(profile['path'])) == profile['path'] and '..' not in PurePosixPath(profile['path']).parts
         and profile['sha256'] == value['native_profile_sha256'] and hashed(profile['target_profile_sha256']),
         'FRESH_QUEUE_PROFILE_REFERENCE_INVALID')
    project = value['project']
    need(type(project) is dict and set(project) == {*PROJECT_HASHES, 'modules', 'queue_modules'}
         and all(hashed(project[x]) for x in PROJECT_HASHES), 'FRESH_QUEUE_PROJECT_RELEASE_INVALID')
    hash_map(project['modules'], PROJECT_MODULES);hash_map(project['queue_modules'], QUEUE_MODULES)
    need(all(project['modules'][x] == value['modules'][x] for x in set(MODULES) & set(PROJECT_MODULES)),
         'FRESH_QUEUE_SHARED_SOURCE_CHANGED')
    return json.loads(canonical(value))


H_FOX_IMAGE = queue.H_FOX_IMAGE


def validate_request(value):
    return _validate_request(value, release_validator=validate_release)


def validate_packet(value):
    fields = {'schema_version', 'scope', 'installation_id', 'provider_configuration_sha256',
              'app_projection_sha256', 'backend_initialization_sha256', 'fox_user', 'request'}
    need(type(value) is dict and set(value) == fields and type(value['schema_version']) is int
         and value['schema_version'] == 1 and value['scope'] == SCOPE
         and type(value['installation_id']) is str and re.fullmatch(r'fst-[a-f0-9]{32}', value['installation_id']),
         'FRESH_QUEUE_PACKET_INVALID')
    need(all(hashed(value[x]) for x in ('provider_configuration_sha256', 'app_projection_sha256',
                                      'backend_initialization_sha256')), 'FRESH_QUEUE_PACKET_PIN_INVALID')
    need(type(value['fox_user']) is str and re.fullmatch(r'[1-9][0-9]{0,9}(?::(?:0|[1-9][0-9]{0,9}))?', value['fox_user'])
         and all(int(x) < 2**31 for x in value['fox_user'].split(':')), 'FRESH_QUEUE_USER_INVALID')
    request = validate_request(value['request'])
    need(request['manifest']['hosted_runtime_configuration_sha256'] == value['provider_configuration_sha256'],
         'FRESH_QUEUE_PROVIDER_BINDING_CHANGED')
    return value


def packet(provider, request):
    """Create a source-bound command for the selected C3/R4/F; never execute."""
    from . import runtime_provider as runtime
    validate_request(request)
    need(type(provider) is runtime.FreshHostedProvider and runtime.selected_hosted() is provider,
         'SELECTED_FRESH_QUEUE_PROVIDER_REQUIRED')
    config = provider.configuration
    release_ref = json.loads(provider.release_reference_raw)
    backend_ref = json.loads(provider.backend_reference_raw)
    release_raw = dict(provider.references_raw)[release_ref['path']]
    need(canonical(request['manifest']) == release_raw and request['release_sha256'] == release_ref['sha256'],
         'FRESH_QUEUE_SELECTED_RELEASE_CHANGED')
    value = {'schema_version': 1, 'scope': SCOPE, 'installation_id': config['storage']['installation_id'],
             'provider_configuration_sha256': provider.sha256,
             'app_projection_sha256': config['app_projection']['sha256'],
             'backend_initialization_sha256': backend_ref['sha256'],
             'fox_user': config['runtime']['roles']['fox']['user'], 'request': request}
    validate_packet(value)
    need(provider.configuration == config, 'FRESH_QUEUE_CONFIGURATION_CHANGED')
    return json.loads(canonical(value))


def execute_container(value, queue_module, verification_module, runtime_module, startup_module,
                      *, root=None, environ=None):
    """Same queue implementation, gated by actual read-only fresh startup state.

    Module/root injection follows the existing bridge's local-test seam. The
    generated production program has fixed container paths and measured modules.
    No admission producer, schema initialization, retry or legacy fallback exists.
    """
    value = validate_packet(value)
    values = os.environ if environ is None else environ
    user = value['fox_user'].split(':')
    need(os.geteuid() == int(user[0]) and (len(user) == 1 or os.getegid() == int(user[1])),
         'FRESH_QUEUE_EFFECTIVE_USER_CHANGED')
    expected = {'FOX_INSTALLATION_MODE': 'fresh', 'FOX_VERIFICATION_ENABLED': '1',
        'FOX_VERIFIER_RELEASE_SHA256': value['request']['release_sha256'],
        'FOX_FRESH_PROVIDER_SHA256': value['provider_configuration_sha256'],
        'FOX_FRESH_PROJECTION_SHA256': value['app_projection_sha256'],
        'FOX_FRESH_BACKEND_SHA256': value['backend_initialization_sha256']}
    need(all(values.get(key) == item for key, item in expected.items()), 'FRESH_QUEUE_ENVIRONMENT_CHANGED')
    root = Path('/data') if root is None else Path(root)
    fence = startup_module.configured_fence(root, values)
    need(fence is not None and fence.refresh() is True
         and fence.identity()['installation_id'] == value['installation_id'], 'FRESH_QUEUE_LIVE_ADMISSION_REQUIRED')
    result = container_execute(value['request'], queue_module, verification_module, runtime_module,
                               root=root, request_validator=validate_request)
    need(fence.refresh() is True, 'FRESH_QUEUE_POSTCHECK_UNCONFIRMED_NO_REPLAY')
    return result


# Resolve shared functions without replacing the legacy module's global
# validators. Its normal dispatch still rejects R4 and requires R3 authority.
_validate_request = queue._validate_request
container_execute = queue.container_execute


def parse_packet(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 65536, 'FRESH_QUEUE_REQUEST_BOUND')
    def pairs(items):
        result = {}
        for name, value in items:
            need(name not in result, 'FRESH_QUEUE_DUPLICATE_FIELD');result[name] = value
        return result
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except FreshQueueError:raise
    except (ValueError, UnicodeError, RecursionError):
        raise FreshQueueError('FRESH_QUEUE_JSON_INVALID') from None
    return validate_packet(value)


def container_source():
    """Build fixed-path measured queue code; do not launch it or select a role."""
    constants = {'SCOPE': SCOPE, 'RELEASE_SCOPE': RELEASE_SCOPE, 'MODULES': MODULES, 'CODE': CODE,
        'PROJECT_MODULES': PROJECT_MODULES, 'QUEUE_MODULES': QUEUE_MODULES,
        'PROJECT_HASHES': PROJECT_HASHES, 'TARGET': TARGET, 'H_FOX_IMAGE': H_FOX_IMAGE}
    header = ('import hashlib,json,os,re\nfrom pathlib import Path,PurePosixPath\n'
        '_shared={}\nexec(compile(' + repr(queue._helper_source()) + ',"<shared-queue>","exec"),_shared)\n'
        '_validate_request=_shared["_validate_request"]\ncontainer_execute=_shared["container_execute"]\n'
        + '\n'.join(key + '=' + repr(value) for key, value in constants.items()) + '\n')
    functions = '\n'.join(inspect.getsource(function) for function in
        (FreshQueueError, need, canonical, digest, hashed, hash_map, validate_release,
         validate_request, validate_packet, execute_container, parse_packet))
    return header + functions + CONTAINER_BODY


CONTAINER_BODY = r'''
import io,sys,types,importlib.abc,importlib.util,importlib
from contextlib import redirect_stdout,redirect_stderr
try:
 packet=parse_packet(sys.stdin.buffer.read(65537))
 need(os.environ.get('FOX_DATA_DIR')=='/data'
  and os.environ.get('FOX_FRESH_PUBLIC_CONFIG_DIR')=='/run/fox-installation',
  'FRESH_QUEUE_FIXED_MOUNTS_REQUIRED')
 manifest=packet['request']['manifest']
 profile=Path('/run/fox-native/profile.json')
 need(profile.resolve(strict=True)==profile and profile.is_file() and not profile.is_symlink()
  and profile.stat().st_nlink==1 and 0<profile.stat().st_size<=65536,'FRESH_QUEUE_PROFILE_UNSAFE')
 with profile.open('rb') as stream:profile_raw=stream.read(65537)
 need(0<len(profile_raw)<=65536 and digest(profile_raw)==manifest['native_profile_sha256'],
  'FRESH_QUEUE_MOUNTED_PROFILE_CHANGED')
 expected={}
 for group in (manifest['modules'],manifest['project']['modules'],manifest['project']['queue_modules']):
  for name,wanted in group.items():
   need(name not in expected or expected[name]==wanted,'FRESH_QUEUE_SHARED_SOURCE_CHANGED')
   expected[name]=wanted
 sources={}
 for name,wanted in expected.items():
  path=Path('/app/fox')/name
  need(path.resolve(strict=True)==path and path.is_file() and not path.is_symlink()
   and path.stat().st_nlink==1 and 0<path.stat().st_size<=2000000,'FRESH_QUEUE_MODULE_UNSAFE')
  with path.open('rb') as stream:raw=stream.read(2000001)
  need(0<len(raw)<=2000000 and digest(raw)==wanted,'FRESH_QUEUE_MODULE_CHANGED')
  sources[name]=raw
 sys.dont_write_bytecode=True
 for name in tuple(sys.modules):
  if name=='fox' or name.startswith('fox.'):del sys.modules[name]
 package=types.ModuleType('fox');package.__path__=['/app/fox'];sys.modules['fox']=package
 class CheckedFinder(importlib.abc.MetaPathFinder,importlib.abc.Loader):
  def find_spec(self,fullname,path=None,target=None):
   if not fullname.startswith('fox.'):return None
   need(fullname.count('.')==1 and fullname[4:]+'.py' in sources,'FRESH_QUEUE_UNBOUND_DEPENDENCY')
   return importlib.util.spec_from_loader(fullname,self)
  def create_module(self,spec):return None
  def exec_module(self,module):
   filename=module.__name__[4:]+'.py';module.__file__='/app/fox/'+filename
   exec(compile(sources[filename],module.__file__,'exec'),module.__dict__)
 finder=CheckedFinder();sys.meta_path.insert(0,finder)
 try:
  with redirect_stdout(io.StringIO()),redirect_stderr(io.StringIO()):
   modules=[importlib.import_module('fox.'+name) for name in
    ('verification_queue','technical_release','verification_runtime','fresh_startup')]
   result=execute_container(packet,*modules)
 finally:sys.meta_path.remove(finder)
except FreshQueueError as error:
 result={'status':'STOPPED','code':str(error),'automatic_replay_permitted':False}
except Exception:
 result={'status':'STOPPED','code':'FRESH_QUEUE_CONTAINER_OUTCOME_UNCONFIRMED_NO_REPLAY',
  'automatic_replay_permitted':False}
print(json.dumps(result,sort_keys=True))
'''
