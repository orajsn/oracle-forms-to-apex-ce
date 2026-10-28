"""Developer-only project clean-install CLI for the existing JSN lab.

This is local operator code, not a deployment or an authorization to run it.
The pinned converter/FOX images must first be paired with the project package,
project QA and runtime dependency closure. The executor fails closed when those
dependencies are absent. No image is built, installed, started or replaced here.

prepare only reads the retained project and writes a protected local plan.
check/status are read-only; apply requires an exact plan hash and one explicit
phase. Existing native operator plans, journals and targets are never adopted.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
for location in (ROOT, ROOT / 'converter'):
    if str(location) not in sys.path:
        sys.path.insert(0, str(location))

from qa.operator import contracts as c
from qa.operator import clean_install as native_cli
from qa.operator import project_contracts as pc
from qa.operator import runtime_provider

PRIVATE = ROOT / 'work/private/project-clean-install'
IMAGE = native_cli.IMAGE
FOX_IMAGE = native_cli.FOX_IMAGE
SSH = tuple(native_cli.SSH)
HOST_PREFIX = native_cli.HOST_PREFIX
SOURCE_CODE = native_cli.SOURCE_CODE
MAX_WIRE = native_cli.MAX_WIRE
MAX_PACKAGE = 8_000_000
CODE_FILES = ('contracts.py', 'remote.py', 'clean_install.py', 'runtime_provider.py',
              'project_contracts.py', 'project_remote.py', 'project_clean_install.py')
OperatorError = native_cli.OperatorError
require = native_cli.require
run_process = native_cli.run_process


def oci_scope(*, require_database_available):
    return native_cli.oci_scope(require_database_available=require_database_available)


def admin_secret():
    return native_cli.admin_secret()


def image_pins():
    return native_cli._provider_call(runtime_provider.image_pins, {'fox': FOX_IMAGE, 'converter': IMAGE})


def private_root():
    return native_cli._provider_call(runtime_provider.private_root, 'project', PRIVATE)


def handoff_root(*, legacy_root=None):
    return native_cli._provider_call(runtime_provider.private_root, 'handoff', ROOT / 'work' if legacy_root is None else legacy_root)


def execute_host(program, encoded_packet, *, timeout=1500, legacy_loader=None):
    loader = legacy_loader or "python3 -B -c 'import base64,sys; exec(base64.b64decode(sys.stdin.buffer.readline()))'"
    try:
        return runtime_provider.execute_host(program, encoded_packet, timeout=timeout,
            legacy_argv=[*SSH, loader], legacy_runner=run_process, maximum=MAX_WIRE)
    except runtime_provider.ProviderError as error:
        raise OperatorError(str(error)) from None


def now():
    return datetime.now(timezone.utc)


def stamp():
    return now().isoformat()


def code_bundle():
    # Include the reused local transport helper, although it is not executed
    # remotely. Its behavior must not drift under an already approved plan.
    contents = {name: (HERE / name).read_bytes() for name in CODE_FILES}
    return contents, c.digest(c.canonical_bytes({name: c.digest(raw) for name, raw in contents.items()}))


EXECUTOR_CODE = r'''
import base64,hashlib,json,sys,types
def guard(value):
 if not value:raise RuntimeError('PROJECT_EXECUTOR_CODE_GUARD_FAILED')
p=json.load(sys.stdin);sources={name:base64.b64decode(raw,validate=True) for name,raw in p['code'].items()}
guard(set(sources)=={'contracts.py','remote.py','clean_install.py','runtime_provider.py','project_contracts.py','project_remote.py','project_clean_install.py'})
manifest={name:hashlib.sha256(raw).hexdigest() for name,raw in sources.items()}
canonical=(json.dumps(manifest,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()
guard(hashlib.sha256(canonical).hexdigest()==p['operator_code_sha256'])
sys.dont_write_bytecode=True
# Both sides must ship the paired project dependencies before any journal or
# SQL dispatch. This is a capability check, never a software installation.
from forms2apex.project_release import validate_project_package
from forms2apex.native_project import render_project_schema
from fox.project_qa_plan import derive_project_qa_plan,derive_project_qa_profile
for name in ('qa','qa.operator'):
 module=types.ModuleType(name);module.__path__=[];sys.modules[name]=module
for filename in ('contracts.py','remote.py','project_contracts.py','project_remote.py'):
 name='qa.operator.'+filename[:-3];module=types.ModuleType(name);module.__package__='qa.operator';sys.modules[name]=module
 exec(compile(sources[filename],filename,'exec'),module.__dict__)
try:
 r=sys.modules['qa.operator.project_remote'].execute(p['command'],base64.b64decode(p['plan_b64'],validate=True),
  base64.b64decode(p['package_b64'],validate=True),expected_plan_sha256=p['plan_sha256'],phase=p.get('phase'),
  apply=p['apply'],admin_password=p.get('admin_password'),operator_code_sha256=p['operator_code_sha256'])
except Exception as exc:
 r=sys.modules['qa.operator.remote'].failure_response(exc,p.get('phase'))
print(json.dumps(r,sort_keys=True))
'''


SOURCE_HOST = HOST_PREFIX + r'''
r=subprocess.run(['podman','inspect','fox'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
guard(r.returncode==0)
v=json.loads(r.stdout)[0];guard(v['State']['Running'] is True and v['Image'].split(':')[-1]==p['fox_image'].split(':')[-1])
code=base64.b64decode(p['reader_b64']).decode()
r=subprocess.run(['podman','exec','-i','fox','python','-B','-c',code],input=json.dumps(p).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45)
guard(r.returncode==0 and len(r.stdout)<=16000000)
sys.stdout.buffer.write(r.stdout)
'''

EXECUTOR_HOST = HOST_PREFIX + r'''
r=subprocess.run(['podman','inspect','forms2apex-mcp'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
guard(r.returncode==0)
v=json.loads(r.stdout)[0];guard(v['State']['Running'] is True and v['Image'].split(':')[-1]==p['image'].split(':')[-1])
e=dict(x.split('=',1) for x in v['Config']['Env'] if '=' in x)
guard(e.get('PYTHONNOUSERSITE')=='1' and e.get('PYTHONPATH')=='/opt/forms2apex/converter:/usr/local/lib64/python3.11/site-packages:/usr/local/lib/python3.11/site-packages')
guard(e.get('TNS_ADMIN')=='/opt/forms2apex/wallet')
code=base64.b64decode(p['executor_b64']).decode()
r=subprocess.run(['podman','exec','-i','forms2apex-mcp','python3.11','-B','-c',code],input=json.dumps(p).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=1400)
guard(r.returncode==0 and len(r.stdout)<=2000000)
sys.stdout.buffer.write(r.stdout)
'''


def ssh_json(program, packet):
    encoded = (json.dumps(packet, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                          allow_nan=False) + '\n').encode('utf-8')
    raw = execute_host(program, encoded)
    return json.loads(raw, object_pairs_hook=c._unique)


def fetch_source(job_id, package_sha256, scope):
    require(type(job_id) is str and c._JOB.fullmatch(job_id) is not None
            and type(package_sha256) is str and c._HASH.fullmatch(package_sha256) is not None,
            'SOURCE_JOB_AND_HASH_REQUIRED')
    host = native_cli.fresh_host_program('source') or SOURCE_HOST
    result = ssh_json(host, {'cli_scope': scope, 'job_id': job_id, 'package_sha256': package_sha256,
        'reader_b64': base64.b64encode(SOURCE_CODE.encode()).decode(), 'fox_image': image_pins()['fox']})
    require(type(result) is dict and set(result) == {'source_attestation', 'package_b64'},
            'PRIVATE_JOB_RESPONSE_INVALID')
    raw = base64.b64decode(result['package_b64'], validate=True)
    require(c.digest(raw) == package_sha256 and 0 < len(raw) <= MAX_PACKAGE, 'RETAINED_SOURCE_PACKAGE_CHANGED')
    source = c.validate_source_attestation(result['source_attestation'])
    age = (now() - c._timestamp(source['observed_at_utc'])).total_seconds()
    require(-c.MAX_CLOCK_SKEW_SECONDS <= age <= 300, 'SOURCE_OBSERVATION_NOT_FRESH')
    package = pc.load_package(raw, package_sha256)
    require(source['job_id'] == package['binding']['job_id'] == job_id
            and source['package_bytes'] == len(raw)
            and source['source_manifest_sha256'] == package['binding']['source_manifest_sha256'],
            'PRIVATE_JOB_PACKAGE_BINDING_MISMATCH')
    return raw, source, package


def private_directory(path):
    native_cli._provider_call(runtime_provider.private_destination, path, kinds=('project',))
    require(path.parent == private_root() and path.parent.resolve() == path.parent
            and c._HASH.fullmatch(path.name) is not None and not path.exists() and not path.is_symlink(),
            'LOCAL_PLAN_DESTINATION_MUST_BE_NEW')
    path.mkdir(mode=0o700)
    if os.name == 'nt':
        program = r'''$ErrorActionPreference='Stop'; $p=([Console]::In.ReadToEnd()|ConvertFrom-Json).path
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
$rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
$acl.SetAccessRule($rule); [IO.Directory]::SetAccessControl($p,$acl)
Write-Output 'PRIVATE_DIRECTORY_PROTECTED'
'''
        require(run_process(['powershell', '-NoProfile', '-Command', program],
                            data=json.dumps({'path': str(path)}).encode()).strip() == b'PRIVATE_DIRECTORY_PROTECTED',
                'WINDOWS_PLAN_PROTECTION_FAILED')


def save_new(path, raw):
    native_cli._provider_call(runtime_provider.private_destination, path, kinds=('project',))
    require(path.parent.parent == private_root() and c._HASH.fullmatch(path.parent.name) is not None
            and path.name in {'plan.json', 'apex-package.zip'} and path.parent.resolve() == path.parent
            and not path.exists() and not path.is_symlink() and type(raw) is bytes
            and 0 < len(raw) <= MAX_PACKAGE, 'PLAN_FILE_ALREADY_EXISTS_OR_LINKED')
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    with os.fdopen(os.open(path, flags, 0o600), 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _private_file(path, bound):
    path = Path(path).absolute()
    require(path.parent.parent == private_root() and c._HASH.fullmatch(path.parent.name) is not None
            and path.name in {'plan.json', 'apex-package.zip'} and path.resolve() == path
            and path.is_file() and not path.is_symlink(), 'OPERATOR_OWNED_PLAN_REQUIRED')
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= bound,
            'PRIVATE_FILE_PERMISSIONS')
    if os.name != 'nt':
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600
                and path.parent.stat().st_uid == os.getuid()
                and stat.S_IMODE(path.parent.stat().st_mode) == 0o700, 'PLAN_PERMISSIONS_INVALID')
    else:
        program = r'''$ErrorActionPreference='Stop'; $p=([Console]::In.ReadToEnd()|ConvertFrom-Json).path
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
foreach($item in @($p,[IO.Path]::GetDirectoryName($p))) {
 $acl=if([IO.Directory]::Exists($item)){[IO.Directory]::GetAccessControl($item)}else{[IO.File]::GetAccessControl($item)}
 if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid){throw 'Wrong owner'}
 foreach($r in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
  if($r.AccessControlType -eq 'Allow' -and $r.IdentityReference.Value -ne $sid){throw 'Unexpected reader'}
 }
}
Write-Output 'PRIVATE_PATH_VERIFIED'
'''
        require(run_process(['powershell', '-NoProfile', '-Command', program],
                            data=json.dumps({'path': str(path)}).encode()).strip() == b'PRIVATE_PATH_VERIFIED',
                'WINDOWS_PLAN_PERMISSIONS_INVALID')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    with os.fdopen(descriptor, 'rb') as stream:
        actual = os.fstat(stream.fileno())
        require((actual.st_dev, actual.st_ino) == (info.st_dev, info.st_ino)
                and stat.S_ISREG(actual.st_mode) and actual.st_nlink == 1 and actual.st_size <= bound,
                'PRIVATE_FILE_PERMISSIONS')
        raw = stream.read(bound + 1)
    require(0 < len(raw) <= bound, 'PRIVATE_FILE_PERMISSIONS')
    return raw


def read_plan(path):
    path = Path(path).absolute()
    require(path.name == 'plan.json', 'OPERATOR_OWNED_PLAN_REQUIRED')
    raw = _private_file(path, c.MAX_JSON_BYTES)
    require(path.parent.name == c.digest(raw), 'EXACT_PLAN_DIRECTORY_HASH_MISMATCH')
    return raw, pc.validate_plan(raw)


def prepare(job_id, package_sha256, namespace=None):
    require(type(job_id) is str and c._JOB.fullmatch(job_id) is not None
            and type(package_sha256) is str and c._HASH.fullmatch(package_sha256) is not None,
            'SOURCE_JOB_AND_HASH_REQUIRED')
    if namespace is not None:
        c._namespace(namespace)
    scope = oci_scope(require_database_available=False)
    raw, source, package = fetch_source(job_id, package_sha256, scope)
    created = stamp()
    if namespace is None:
        namespace = 'FOX_QA_' + now().strftime('%y%m%d') + '_' + secrets.token_hex(4).upper()
    _, code_hash = code_bundle()
    plan = pc.make_plan(source, package, namespace, created, operator_code_sha256=code_hash)
    plan_raw = c.canonical_bytes(plan)
    digest = c.digest(plan_raw)
    root = private_root()
    require(root.resolve() == root, 'LOCAL_PRIVATE_ROOT_LINKED')
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(root.resolve() == root, 'LOCAL_PRIVATE_ROOT_LINKED')
    destination = root / digest
    private_directory(destination)
    save_new(destination / 'apex-package.zip', raw)
    save_new(destination / 'plan.json', plan_raw)
    return {'state': 'PREPARED', 'plan_path': str(destination / 'plan.json'), 'plan_sha256': digest,
            'job_id': job_id, 'package_sha256': package_sha256, 'namespace': namespace,
            'remote_writes': False, 'clean_install_passed': False,
            'paired_project_release_required': True}


def dispatch(command, plan_path, *, expected_sha=None, phase=None, apply=False):
    require(command in ('check', 'status', 'apply') and type(apply) is bool, 'UNKNOWN_OPERATOR_COMMAND')
    require((command == 'apply') == apply, 'EXPLICIT_APPLY_FLAG_REQUIRED')
    require((phase in c.PHASES) if command == 'apply' else phase is None, 'EXPLICIT_SINGLE_PHASE_REQUIRED')
    plan_raw, plan = read_plan(plan_path)
    digest = c.digest(plan_raw)
    if command == 'apply':
        require(expected_sha == digest, 'EXACT_PLAN_SHA_REQUIRED_FOR_APPLY')
    elif expected_sha is not None:
        require(expected_sha == digest, 'PLAN_SHA_MISMATCH')
    code, code_hash = code_bundle()
    if command != 'status':
        require(code_hash == plan['operator_code_sha256'], 'OPERATOR_CODE_CHANGED_REPREPARE_OR_REVIEW')
    package_raw = _private_file(Path(plan_path).absolute().parent / 'apex-package.zip', MAX_PACKAGE)
    package = pc.load_package(package_raw, plan['binding']['package_sha256'])
    pc.validate_plan(plan_raw, package=package)
    scope = oci_scope(require_database_available=(command != 'status'))
    if command != 'status':
        current_raw, source, _ = fetch_source(plan['binding']['job_id'], plan['binding']['package_sha256'], scope)
        require(current_raw == package_raw, 'LIVE_PRIVATE_JOB_DIFFERS_FROM_PLAN_PACKAGE')
        pc.validate_plan(plan_raw, source_attestation=source)
    packet = {'cli_scope': scope, 'command': command, 'apply': apply, 'phase': phase,
        'plan_sha256': digest, 'plan_b64': base64.b64encode(plan_raw).decode(),
        'package_b64': base64.b64encode(package_raw).decode(), 'operator_code_sha256': code_hash,
        'code': {name: base64.b64encode(raw).decode() for name, raw in code.items()},
        'executor_b64': base64.b64encode(EXECUTOR_CODE.encode()).decode(), 'image': image_pins()['converter']}
    host = native_cli.fresh_host_program('project') or EXECUTOR_HOST
    try:
        if command != 'status':
            packet['admin_password'] = admin_secret()
        result = ssh_json(host, packet)
        if type(result) is dict and result.get('status') == 'STOPPED':
            return c.failure_response(result.get('code'), phase, result.get('diagnostics'))
        return result
    finally:
        packet.pop('admin_password', None)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('prepare', 'check', 'apply', 'status'))
    parser.add_argument('--job'); parser.add_argument('--package-sha256'); parser.add_argument('--namespace')
    parser.add_argument('--plan'); parser.add_argument('--plan-sha256')
    parser.add_argument('--phase', choices=('allocate', 'schema', 'import', 'verify'))
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    if args.command == 'prepare':
        require(args.job and args.package_sha256 and args.plan is None and args.plan_sha256 is None
                and args.phase is None and not args.apply, 'PREPARE_DOES_NOT_ACCEPT_EXECUTION_FLAGS')
        result = prepare(args.job, args.package_sha256, args.namespace)
    else:
        require(args.plan and args.job is None and args.package_sha256 is None and args.namespace is None,
                'EXECUTION_REQUIRES_EXISTING_PLAN_NOT_TARGET_OVERRIDES')
        result = dispatch(args.command, args.plan, expected_sha=args.plan_sha256, phase=args.phase, apply=args.apply)
    print(json.dumps(result, sort_keys=True))
    if result.get('status') == 'STOPPED':
        raise SystemExit(2)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        result = c.failure_response(exc.args[0] if type(exc) is OperatorError and exc.args else 'LOCAL_OPERATOR_GUARD_FAILED')
        result['message'] = 'Project operator stopped; preserve the project plan and private journals. No automatic replay.'
        print(json.dumps(result))
        raise SystemExit(2)
