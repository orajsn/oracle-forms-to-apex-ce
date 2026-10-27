"""Developer-only clean-install CLI for the existing JSN lab.

prepare reads a retained FOX job and creates only local, protected plan files.
check/status are read-only. apply requires an explicit flag, exact immutable
plan hash and one named phase. No public API, customer UI, service or scheduler
is added. Secrets travel only through protected subprocess stdin.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / 'converter') not in sys.path:
    sys.path.insert(0, str(ROOT / 'converter'))
from qa.operator import contracts as C
from qa.operator import runtime_provider
from forms2apex.clean_package import validate_native_package

PRIVATE = ROOT / 'work/private/clean-install'
IMAGE = 'sha256:c7fdb53bc04450e297cbbbc89fb834be714e106d5a164b1c80dc77d544db5a1b'
FOX_IMAGE = 'sha256:8ac18481bfcb0e991582f93b351ed66203372d8d9b9a11cc28ede7fd8d618f8d'
SSH = ['ssh', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-i',
       str(Path.home() / '.ssh/jsn-opaf-shared-ed25519'), 'opc@129.213.189.48']
EXPECTED_PYTHONPATH = '/opt/forms2apex/converter:/usr/local/lib64/python3.11/site-packages:/usr/local/lib/python3.11/site-packages'
ADMIN_SECRET = str(Path.home() / '.oci/jsn-secrets/jsn-apex-admin.dpapi')
MAX_WIRE = 20_000_000


class OperatorError(RuntimeError):
    pass


def require(ok, code):
    if not ok:
        raise OperatorError(code)


def _provider_call(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except runtime_provider.ProviderError as error:
        raise OperatorError(str(error)) from None


def image_pins():
    return _provider_call(runtime_provider.image_pins, {'fox': FOX_IMAGE, 'converter': IMAGE})


def now():
    return datetime.now(timezone.utc)


def stamp():
    return now().isoformat()


def code_bundle():
    contents = {name: (HERE / name).read_bytes() for name in ('contracts.py', 'clean_install.py', 'remote.py', 'runtime_provider.py')}
    manifest = {name: C.digest(raw) for name, raw in contents.items()}
    return contents, C.digest(C.canonical_bytes(manifest))


def run_process(args, *, data=None, timeout=90, oci_json=False):
    options = {}
    if oci_json:
        # OCI's Windows Python stdout can otherwise use a legacy code page.
        # This changes only this child process, never the global environment.
        options['env'] = {**os.environ, 'PYTHONIOENCODING': 'utf-8:strict', 'PYTHONUTF8': '1'}
    try:
        result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, **options)
    except subprocess.TimeoutExpired:
        raise OperatorError('TRANSPORT_TIMEOUT_OUTCOME_UNCERTAIN_NO_REPLAY') from None
    require(result.returncode == 0, 'OCI_CLI_FAILED_OUTPUT_WITHHELD' if oci_json else 'PROTECTED_TRANSPORT_FAILED_OUTPUT_WITHHELD')
    if oci_json:
        require(not result.stderr.strip(), 'OCI_DIAGNOSTIC_OUTPUT_REVIEW_REQUIRED')
    require(len(result.stdout) <= MAX_WIRE, 'PROTECTED_RESPONSE_TOO_LARGE')
    return result.stdout


def oci_scope(*, require_database_available):
    provider = runtime_provider.hosted()
    if provider is not None:
        return _provider_call(provider.oci_scope, require_database_available=require_database_available)
    def read(arguments, *, database=False):
        query = 'data.{id:id,"compartment-id":"compartment-id","lifecycle-state":"lifecycle-state"'
        if database:
            query += ',"db-name":"db-name"'
        query += '}'
        raw = run_process(['oci', '--profile', 'JSN', '--region', C.REGION,
                           *arguments, '--query', query, '--output', 'json'], oci_json=True)
        try:
            value = C.load_json(raw)  # bounded JSON, strict UTF-8, no encoding fallback
        except C.ContractError:
            raise OperatorError('OCI_PROJECTED_JSON_INVALID') from None
        require(set(value) == {'id', 'compartment-id', 'lifecycle-state'} | ({'db-name'} if database else set()),
                'OCI_PROJECTED_FIELDS_INVALID')
        return value
    vm = read(['compute', 'instance', 'get', '--instance-id', C.INSTANCE])
    adb = read(['db', 'autonomous-database', 'get', '--autonomous-database-id', C.DATABASE], database=True)
    require(vm['id'] == C.INSTANCE and vm['compartment-id'] == C.COMPARTMENT
            and adb['id'] == C.DATABASE and adb['compartment-id'] == C.COMPARTMENT
            and adb['db-name'] == 'JSNF2APEX', 'EXACT_JSN_RESOURCE_IDENTITY_REQUIRED')
    require(vm['lifecycle-state'] == 'RUNNING', 'EXISTING_VM_MUST_BE_STARTED_BY_OPERATOR')
    if require_database_available:
        require(adb['lifecycle-state'] == 'AVAILABLE', 'EXISTING_DATABASE_MUST_BE_AVAILABLE')
    return {'instance_id': vm['id'], 'database_id': adb['id'], 'compartment_id': C.COMPARTMENT,
            'region': C.REGION, 'database_db_name': adb['db-name'],
            'instance_state': vm['lifecycle-state'], 'database_state': adb['lifecycle-state'],
            'observed_at_utc': stamp()}


HOST_PREFIX = r'''
import base64,hashlib,json,subprocess,sys,urllib.request
def guard(value):
 if not value:raise RuntimeError('PINNED_HOST_GUARD_FAILED')
p=json.loads(sys.stdin.buffer.read(20000000))
q=urllib.request.Request('http://169.254.169.254/opc/v2/instance/',headers={'Authorization':'Bearer Oracle'})
with urllib.request.urlopen(q,timeout=5) as r:m=json.loads(r.read(100000))
guard(m['id']=='ocid1.instance.oc1.iad.anuwcljtc7x6gxic5w37qsyp3rst64betkt4uk2pdcrtmy3okspcpbv77qea')
guard(m['compartmentId']=='ocid1.compartment.oc1..aaaaaaaa2q5aelkapmt5mhumvxadcynq5chez2faeucy5plefhy3ylmahtba' and m['canonicalRegionName']=='us-ashburn-1')
guard(p['cli_scope']['instance_id']==m['id'] and p['cli_scope']['compartment_id']==m['compartmentId'])
guard(p['cli_scope']['database_id']=='ocid1.autonomousdatabase.oc1.iad.anuwcljrc7x6gxiapkxouj7emfbelvnvompwjcpoxx5vg727cegjsqkbp4rq')
'''

SOURCE_CODE = r'''
import base64,datetime,hashlib,json,re,sqlite3,sys
from pathlib import Path
def guard(value):
 if not value:raise RuntimeError('RETAINED_SOURCE_GUARD_FAILED')
p=json.load(sys.stdin);job=p['job_id'];expected=p['package_sha256']
guard(re.fullmatch(r'fox-[a-f0-9]{20}',job) and re.fullmatch(r'[a-f0-9]{64}',expected))
root=Path('/data/jobs')/job;package=root/'apex-package.zip';release=root/'release-evidence.json'
guard(root.resolve()==root and package.is_file() and not package.is_symlink() and release.is_file() and not release.is_symlink())
raw=package.read_bytes();guard(0<len(raw)<=8000000 and hashlib.sha256(raw).hexdigest()==expected)
release_value=json.loads(release.read_bytes());guard(release_value['job_id']==job)
with sqlite3.connect('file:/data/fox.sqlite3?mode=ro',uri=True) as db:
 row=db.execute('select state,artifact,source_hash from runs where id=?',(job,)).fetchone()
guard(row and row[0] in ('QA_REQUIRED','VERIFIED','ACCEPTED') and row[1]=='jobs/'+job+'/apex-package.zip'
 and row[2]==release_value['source_manifest_sha256'])
attestation={'schema_version':1,'scope':'fox-private-job-package-read-v1','observed_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'instance_id':'ocid1.instance.oc1.iad.anuwcljtc7x6gxic5w37qsyp3rst64betkt4uk2pdcrtmy3okspcpbv77qea',
 'compartment_id':'ocid1.compartment.oc1..aaaaaaaa2q5aelkapmt5mhumvxadcynq5chez2faeucy5plefhy3ylmahtba','region':'us-ashburn-1',
 'job_id':job,'run_state':row[0],'package_sha256':expected,'package_bytes':len(raw),
 'source_manifest_sha256':release_value['source_manifest_sha256']}
print(json.dumps({'source_attestation':attestation,'package_b64':base64.b64encode(raw).decode()}))
'''

EXECUTOR_CODE = r'''
import base64,hashlib,json,re,sys,types
def guard(value):
 if not value:raise RuntimeError('EXECUTOR_CODE_GUARD_FAILED')
p=json.load(sys.stdin);sources={name:base64.b64decode(raw,validate=True) for name,raw in p['code'].items()}
guard(set(sources)=={'contracts.py','clean_install.py','remote.py','runtime_provider.py'})
manifest={name:hashlib.sha256(raw).hexdigest() for name,raw in sources.items()}
canonical=(json.dumps(manifest,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()
guard(hashlib.sha256(canonical).hexdigest()==p['operator_code_sha256'])
sys.dont_write_bytecode=True
for name in ('qa','qa.operator'):
 module=types.ModuleType(name);module.__path__=[];sys.modules[name]=module
for filename in ('contracts.py','remote.py'):
 name='qa.operator.'+filename[:-3];module=types.ModuleType(name);module.__package__='qa.operator';sys.modules[name]=module
 exec(compile(sources[filename],filename,'exec'),module.__dict__)
try:
 r=sys.modules['qa.operator.remote'].execute(p['command'],base64.b64decode(p['plan_b64'],validate=True),
  base64.b64decode(p['package_b64'],validate=True),expected_plan_sha256=p['plan_sha256'],phase=p.get('phase'),
  apply=p['apply'],admin_password=p.get('admin_password'),operator_code_sha256=p['operator_code_sha256'])
except Exception as exc:
 r=sys.modules['qa.operator.remote'].failure_response(exc,p.get('phase'))
print(json.dumps(r,sort_keys=True))
'''


def private_root():
    return _provider_call(runtime_provider.private_root, 'native', PRIVATE)


def handoff_root(*, legacy_root=None):
    return _provider_call(runtime_provider.private_root, 'handoff', ROOT / 'work' if legacy_root is None else legacy_root)


def execute_host(program, encoded_packet, *, timeout=1500, legacy_loader=None):
    loader = legacy_loader or "python3 -c 'import base64,sys; exec(base64.b64decode(sys.stdin.buffer.readline()))'"
    try:
        return runtime_provider.execute_host(program, encoded_packet, timeout=timeout,
            legacy_argv=SSH + [loader], legacy_runner=run_process, maximum=MAX_WIRE)
    except runtime_provider.ProviderError as error:
        raise OperatorError(str(error)) from None


def ssh_json(program, packet):
    # Contract JSON is intentionally limited to 64 KiB. A transport envelope
    # also carries the exact ZIP and three reviewed modules, so it needs its
    # own explicit bound rather than weakening the pure contract limit.
    encoded = (json.dumps(packet, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                          allow_nan=False) + '\n').encode('utf-8')
    raw = execute_host(program, encoded)
    return json.loads(raw)


def fetch_source(job_id, package_sha256, scope):
    require(re.fullmatch(r'fox-[a-f0-9]{20}', job_id or '') is not None
            and re.fullmatch(r'[a-f0-9]{64}', package_sha256 or '') is not None, 'SOURCE_JOB_AND_HASH_REQUIRED')
    host = HOST_PREFIX + r'''
r=subprocess.run(['podman','inspect','fox'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
guard(r.returncode==0)
v=json.loads(r.stdout)[0];guard(v['State']['Running'] is True and v['Image'].split(':')[-1]==p['fox_image'].split(':')[-1])
code=base64.b64decode(p['reader_b64']).decode()
r=subprocess.run(['podman','exec','-i','fox','python','-B','-c',code],input=json.dumps(p).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45)
guard(r.returncode==0 and len(r.stdout)<=16000000)
sys.stdout.buffer.write(r.stdout)
'''
    result = ssh_json(host, {'cli_scope': scope, 'job_id': job_id, 'package_sha256': package_sha256,
                             'reader_b64': base64.b64encode(SOURCE_CODE.encode()).decode(), 'fox_image': image_pins()['fox']})
    raw = base64.b64decode(result['package_b64'], validate=True)
    require(C.digest(raw) == package_sha256 and 0 < len(raw) <= 8_000_000, 'RETAINED_SOURCE_PACKAGE_CHANGED')
    observation = C.validate_source_attestation(result['source_attestation'])
    age = (now() - datetime.fromisoformat(observation['observed_at_utc'].replace('Z', '+00:00'))).total_seconds()
    require(-C.MAX_CLOCK_SKEW_SECONDS <= age <= 300, 'SOURCE_OBSERVATION_NOT_FRESH')
    validated = validate_native_package(raw, package_sha256)
    require(validated['job_id'] == job_id and observation['job_id'] == job_id
            and observation['package_bytes'] == len(raw)
            and validated['source_manifest_sha256'] == observation['source_manifest_sha256'], 'PRIVATE_JOB_PACKAGE_BINDING_MISMATCH')
    return raw, observation, validated


def native_digest(raw):
    # Called only after the existing complete pure validator succeeded. This
    # reads one already-validated member; it is not another archive validator.
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        return C.digest(archive.read('native-form-spec.json'))


def private_directory(path):
    provider = runtime_provider.hosted()
    if provider is not None:
        _provider_call(provider.private_destination, path, kinds=('native', 'journal'))
    require((provider is not None or path.is_relative_to(private_root())) and path.parent.resolve() == path.parent
            and not path.exists() and not path.is_symlink(), 'LOCAL_PLAN_DESTINATION_MUST_BE_NEW')
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
    _provider_call(runtime_provider.private_destination, path, kinds=('native', 'journal', 'handoff'))
    require(path.parent.resolve() == path.parent and not path.exists() and not path.is_symlink(), 'PLAN_FILE_ALREADY_EXISTS_OR_LINKED')
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def prepare(job_id, package_sha256, namespace=None):
    scope = oci_scope(require_database_available=False)
    raw, source, validated = fetch_source(job_id, package_sha256, scope)
    created = stamp()
    if namespace is None:
        namespace = 'FOX_QA_' + now().strftime('%y%m%d') + '_' + secrets.token_hex(4).upper()
    _, code_hash = code_bundle()
    plan = C.make_plan(source, validated, namespace, created, native_spec_sha256=native_digest(raw), operator_code_sha256=code_hash)
    plan_raw = C.canonical_bytes(plan); digest = C.digest(plan_raw)
    root = private_root()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(root.resolve() == root, 'LOCAL_PRIVATE_ROOT_LINKED')
    destination = root / digest
    private_directory(destination)
    save_new(destination / 'apex-package.zip', raw)
    save_new(destination / 'plan.json', plan_raw)
    return {'state': 'PREPARED', 'plan_path': str(destination / 'plan.json'), 'plan_sha256': digest,
            'job_id': job_id, 'package_sha256': package_sha256, 'namespace': namespace,
            'remote_writes': False, 'clean_install_passed': False}


def read_plan(path):
    path = Path(path).absolute()
    require(path.name == 'plan.json' and path.parent.parent == private_root()
            and path.resolve() == path and path.is_file() and not path.is_symlink(), 'OPERATOR_OWNED_PLAN_REQUIRED')
    if os.name != 'nt':
        require(path.stat().st_uid == os.getuid() and stat.S_IMODE(path.stat().st_mode) == 0o600
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
    raw = path.read_bytes()
    require(len(raw) <= 100_000 and path.parent.name == C.digest(raw), 'EXACT_PLAN_DIRECTORY_HASH_MISMATCH')
    return raw, C.validate_plan(raw)


def admin_secret():
    provider = runtime_provider.hosted()
    if provider is not None:
        return _provider_call(provider.admin_secret)
    raw = run_process(['powershell', '-NoProfile', '-File', str(ROOT / 'scripts/Get-JsnSecret.ps1'),
                       '-SecretFile', ADMIN_SECRET], timeout=30)
    value = raw.decode('utf-8').strip()
    require(re.fullmatch(r'[A-Za-z0-9_!#%+.,:=?@^*-]{12,128}', value) is not None, 'PROTECTED_ADMIN_BINDING_INVALID')
    return value


def dispatch(command, plan_path, *, expected_sha=None, phase=None, apply=False):
    require(command in ('check', 'status', 'apply'), 'UNKNOWN_OPERATOR_COMMAND')
    require((command == 'apply') == apply, 'EXPLICIT_APPLY_FLAG_REQUIRED')
    require((phase in C.PHASES) if command == 'apply' else phase is None, 'EXPLICIT_SINGLE_PHASE_REQUIRED')
    plan_raw, plan = read_plan(plan_path)
    digest = C.digest(plan_raw)
    if command == 'apply':
        require(expected_sha == digest, 'EXACT_PLAN_SHA_REQUIRED_FOR_APPLY')
    elif expected_sha is not None:
        require(expected_sha == digest, 'PLAN_SHA_MISMATCH')
    code, code_hash = code_bundle()
    if command != 'status':
        require(code_hash == plan['operator_code_sha256'], 'OPERATOR_CODE_CHANGED_REPREPARE_OR_REVIEW')
    scope = oci_scope(require_database_available=(command != 'status'))
    local_package = Path(plan_path).absolute().parent / 'apex-package.zip'
    require(local_package.is_file() and not local_package.is_symlink() and local_package.resolve() == local_package,
            'PROTECTED_PACKAGE_COPY_MISSING')
    package = local_package.read_bytes()
    validated = validate_native_package(package, plan['binding']['package_sha256'])
    C.validate_plan(plan_raw, validated_package=validated, native_spec_sha256=native_digest(package))
    if command != 'status':
        observed_package, observed_source, _ = fetch_source(plan['binding']['job_id'], plan['binding']['package_sha256'], scope)
        require(observed_package == package, 'LIVE_PRIVATE_JOB_DIFFERS_FROM_PLAN_PACKAGE')
        C.validate_plan(plan_raw, source_attestation=observed_source)
    packet = {'cli_scope': scope, 'command': command, 'apply': apply, 'phase': phase,
              'plan_sha256': digest, 'plan_b64': base64.b64encode(plan_raw).decode(),
              'package_b64': base64.b64encode(package).decode(), 'operator_code_sha256': code_hash,
              'code': {name: base64.b64encode(raw).decode() for name, raw in code.items()},
              'executor_b64': base64.b64encode(EXECUTOR_CODE.encode()).decode(), 'image': image_pins()['converter']}
    host = HOST_PREFIX + r'''
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
    try:
        if command != 'status':
            packet['admin_password'] = admin_secret()
        result = ssh_json(host, packet)
        if type(result) is dict and result.get('status') == 'STOPPED':
            return C.failure_response(result.get('code'), phase, result.get('diagnostics'))
        return result
    finally:
        packet.pop('admin_password', None)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('prepare', 'check', 'apply', 'status'))
    parser.add_argument('--job'); parser.add_argument('--package-sha256'); parser.add_argument('--namespace')
    parser.add_argument('--plan'); parser.add_argument('--plan-sha256')
    parser.add_argument('--phase', choices=('allocate', 'schema', 'import', 'verify')); parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    if args.command == 'prepare':
        require(args.plan is None and args.plan_sha256 is None and args.phase is None and not args.apply,
                'PREPARE_DOES_NOT_ACCEPT_EXECUTION_FLAGS')
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
        result = C.failure_response(exc.args[0] if type(exc) is OperatorError and exc.args else 'LOCAL_OPERATOR_GUARD_FAILED')
        result['message'] = 'Operator action stopped; preserve plan and private journals. Use read-only status/check.'
        print(json.dumps(result))
        raise SystemExit(2)
