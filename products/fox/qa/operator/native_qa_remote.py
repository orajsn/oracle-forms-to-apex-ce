"""Bounded parent-invoked QA stage/launch program. No work occurs on import."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

ROOT = Path('/home/opc/.config/fox-qa')
BASE_IMAGE = 'sha256:e3f7b9648271a741cf320b7ad928a17e0e1591ba66835e7420864905524eb571'
BASE_DIGEST = 'mcr.microsoft.com/playwright@sha256:06a9939e57531807f8d5fd76ce44b53165ffb7d7501d87ab10e285c20b1e971f'
FILES = {'package.json', 'package-lock.json', 'run-native.mjs', 'prepare-target.mjs',
         'run-jsn-qa.sh', 'lib/contracts.mjs', 'lib/package-evidence.mjs', 'lib/assert-jsn-vm.sh'}
HANDOFF = ('package.zip', 'native-form-spec.json', 'allocate.evidence.json',
           'verification-profile.json', 'verify.evidence.json', 'runtime-credentials.json')
LIMIT = 16_000_000


def require(ok, code):
    if not ok:
        raise RuntimeError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def bare_image(value):
    return value[7:] if value.startswith('sha256:') else value


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False) + '\n').encode()


def load(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'DUPLICATE_JSON_KEY')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: require(False, 'NONFINITE_JSON'))


def command(args, *, data=None, timeout=60, allowed=(0,)):
    try:
        result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError('QA_TIMEOUT_UNCERTAIN_NO_REPLAY') from None
    require(result.returncode in allowed and len(result.stdout) <= LIMIT, 'QA_COMMAND_FAILED_OUTPUT_WITHHELD')
    return result


def private_dir(path, *, create=False, exclusive=False):
    path = Path(path)
    require(path.is_absolute(), 'PRIVATE_ABSOLUTE_PATH_REQUIRED')
    # Every component is inspected; only the known root and its descendants
    # may be created. Existing parent paths must not be links.
    current = Path('/')
    for part in path.parts[1:]:
        current /= part
        if not current.exists():
            require(create and (current == ROOT or ROOT in current.parents), 'PRIVATE_PARENT_MISSING')
            current.mkdir(mode=0o700)
            parent_fd = os.open(current.parent, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(parent_fd)
            finally: os.close(parent_fd)
        elif current == path and exclusive:
            raise RuntimeError('QA_STAGE_ALREADY_EXISTS_NO_OVERWRITE')
        info = current.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode), 'PRIVATE_DIRECTORY_LINK')
        if current == ROOT or ROOT in current.parents:
            require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'PRIVATE_DIRECTORY_OWNER_MODE')
    return path


def read_private(path, *, limit=LIMIT):
    private_dir(Path(path).parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= limit, 'PRIVATE_FILE_OWNER_MODE')
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, 'PRIVATE_FILE_SIZE')
    return raw


def create(path, raw):
    private_dir(Path(path).parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)


def podman_args(image, *, network=False, volumes=()):
    args = ['podman', 'run', '--rm', '--init', '--pull=never', '--userns=keep-id', '--user', f'{os.getuid()}:{os.getgid()}',
            '--read-only', '--cap-drop=all', '--security-opt=no-new-privileges', '--ipc=private', '--shm-size=256m',
            '--cpus=1', '--memory=1536m', '--pids-limit=256', '--tmpfs', '/tmp:rw,nosuid,nodev,size=256m,mode=1777']
    if not network: args += ['--network=none']
    for source, target, mode in volumes:
        args += ['--volume', f'{Path(source).as_posix()}:{target}:{mode},Z']
    return args + ['--entrypoint', 'node', image]


def inspect_baselines(packet):
    import pwd
    require(os.getuid() != 0 and pwd.getpwuid(os.getuid()).pw_name == 'opc', 'OPC_ROOTLESS_REQUIRED')
    require(command(['podman', 'info', '--format', '{{.Host.Security.Rootless}}']).stdout.strip() == b'true', 'ROOTLESS_REQUIRED')
    for name, key in [('forms2apex-mcp', 'converter_image'), ('fox', 'fox_image')]:
        value = load(command(['podman', 'inspect', name]).stdout)[0]
        require(value['State']['Running'] is True and bare_image(value['Image']) == bare_image(packet['descriptor'][key]), 'SERVICE_BASELINE_CHANGED')
        if name == 'forms2apex-mcp':
            env = dict(item.split('=', 1) for item in value['Config']['Env'] if '=' in item)
            require(env.get('PYTHONNOUSERSITE') == '1' and env.get('TNS_ADMIN') == '/opt/forms2apex/wallet'
                    and env.get('PYTHONPATH') == '/opt/forms2apex/converter:/usr/local/lib64/python3.11/site-packages:/usr/local/lib/python3.11/site-packages', 'CONVERTER_ENVIRONMENT_CHANGED')
            require(any(m.get('Destination') == '/opt/forms2apex/outputs/jobs' and m.get('Source') == '/home/opc/forms2apex/outputs/jobs'
                        and m.get('RW') is True for m in value['Mounts']), 'CONVERTER_OUTPUT_BIND_CHANGED')
    image = command(['podman', 'image', 'inspect', BASE_IMAGE, '--format', '{{.Id}}']).stdout.decode().strip()
    require(bare_image(image) == bare_image(BASE_IMAGE), 'CACHED_QA_BASE_CHANGED')
    official = command(['podman', 'image', 'inspect', 'mcr.microsoft.com/playwright:v1.64.0-noble', '--format', '{{index .RepoDigests 0}}']).stdout.decode().strip()
    require(official == BASE_DIGEST, 'APPROVED_BROWSER_BASE_CHANGED')


HANDOFF_READER = r'''
import base64,hashlib,json,os,stat,sys,types
from pathlib import Path
def need(ok):
 if not ok:raise RuntimeError('PRIVATE_HANDOFF_INVALID')
p=json.load(sys.stdin);root=Path('/opt/forms2apex/outputs/jobs/.operator-clean')/p['plan_sha256']
for path in (root.parent,root):
 s=path.lstat();need(stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode) and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o700)
def read(name):
 fd=os.open(root/name,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno());need(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=8000000)
  return f.read(8000001)
plan_raw=read('plan.json');need(plan_raw==base64.b64decode(p['plan_b64'],validate=True))
need(json.loads(read('verify.complete.json'))['phase']=='verify')
names=('package.zip','native-form-spec.json','allocate.evidence.json','verification-profile.json','verify.evidence.json','runtime-credentials.json')
files={name:read(name) for name in names}
code=base64.b64decode(p['contracts_b64'],validate=True)
need(hashlib.sha256(code).hexdigest()==p['contracts_sha256'])
c=types.ModuleType('qa_handoff_contract');exec(compile(code,'contracts.py','exec'),c.__dict__)
plan=c.validate_plan(plan_raw,operator_code_sha256=p['operator_code_sha256'])
c.validate_allocation(files['allocate.evidence.json'],plan)
need(files['verification-profile.json']==c.canonical_bytes(c.make_verification_profile(plan,files['allocate.evidence.json'])))
print(json.dumps({name:base64.b64encode(raw).decode() for name,raw in files.items()}))
'''


def handoff(packet):
    wire = {'plan_sha256': packet['plan_sha256'], 'plan_b64': packet['plan_b64'], 'contracts_b64': packet['contracts_b64'],
            'contracts_sha256': packet['descriptor']['clean_operator_manifest']['contracts.py'],
            'operator_code_sha256': packet['descriptor']['clean_operator_code_sha256']}
    result = command(['podman', 'exec', '-i', 'forms2apex-mcp', 'python3.11', '-B', '-c', HANDOFF_READER], data=canonical(wire))
    values = load(result.stdout)
    require(set(values) == set(HANDOFF), 'HANDOFF_MEMBERS_DIFFER')
    return {name: base64.b64decode(raw, validate=True) for name, raw in values.items()}


def validate_handoff(packet, files):
    plan = load(base64.b64decode(packet['plan_b64'], validate=True))
    require(digest(base64.b64decode(packet['plan_b64'], validate=True)) == packet['plan_sha256'], 'PLAN_BYTES_DIFFER')
    # Canonical validation ran in HANDOFF_READER under the already-installed
    # converter Python 3.11, never in the VM's older host Python interpreter.
    allocation = load(files['allocate.evidence.json'])
    profile, imported = [load(files[name]) for name in ('verification-profile.json', 'verify.evidence.json')]
    allocation_hash = digest(files['allocate.evidence.json'])
    require(allocation.get('passed') is True and allocation.get('scope') == 'fox-clean-allocation-v2'
            and allocation.get('plan_sha256') == packet['plan_sha256'], 'ALLOCATION_UNPROVEN')
    require(profile.get('scope') == 'fox-native-verification-profile-v2' and profile.get('policy_id') == 'jsn-clean-native-v2'
            and profile.get('target') == {key: value for key, value in allocation['target'].items() if key != 'instance_id'}, 'PROFILE_ALLOCATION_DIFFERS')
    require(profile['binding']['allocation_receipt_sha256'] == allocation_hash
            and imported.get('allocation_receipt_sha256') == allocation_hash
            and imported.get('verification_profile_sha256') == digest(files['verification-profile.json'])
            and imported.get('scope') == 'fox-clean-package-install-v2' and imported.get('passed') is True, 'IMPORT_ALLOCATION_DIFFERS')
    for key in ('package_sha256', 'source_manifest_sha256', 'job_id'):
        require(profile['binding'][key] == plan['binding'][key] == imported[key], 'APPROVED_PACKAGE_BINDING_DIFFERS')
    require(digest(files['package.zip']) == plan['binding']['package_sha256']
            and digest(files['native-form-spec.json']) == plan['binding']['native_spec_sha256'] == imported['native_spec_sha256'], 'PACKAGE_NATIVE_BYTES_DIFFER')
    credentials = load(files['runtime-credentials.json'])
    require(set(credentials) == {'username', 'password', 'second_username', 'second_password'}
            and all(type(v) is str and 0 < len(v) <= 1024 for v in credentials.values())
            and credentials['username'].lower() != credentials['second_username'].lower(), 'TWO_RUNTIME_ACCOUNTS_REQUIRED')
    return allocation_hash


def source_packet(packet):
    require(packet.get('command') in ('stage', 'run', 'collect') and packet.get('apply') is (packet['command'] != 'collect'), 'EXPLICIT_PARENT_ACTION_REQUIRED')
    for key in ('plan_sha256', 'source_sha256'):
        require(type(packet.get(key)) is str and re.fullmatch('[a-f0-9]{64}', packet[key]), 'EXACT_DIGEST_REQUIRED')
    descriptor = packet['descriptor']
    require(descriptor['base_qa_image'] == BASE_IMAGE and descriptor['base_digest'] == BASE_DIGEST, 'BASE_OVERRIDE_FORBIDDEN')
    require(digest(canonical(descriptor)) == packet['source_sha256'] and set(packet['files']) == FILES
            and set(descriptor['files']) == FILES, 'SOURCE_MANIFEST_DIFFERS')
    require(digest(canonical(descriptor['clean_operator_manifest'])) == descriptor['clean_operator_code_sha256'], 'CLEAN_OPERATOR_MANIFEST_DIFFERS')
    files = {name: base64.b64decode(value, validate=True) for name, value in packet['files'].items()}
    require(all(0 < len(raw) <= 2_000_000 and digest(raw) == descriptor['files'][name] for name, raw in files.items()), 'SOURCE_BYTES_DIFFER')
    return files


def collect(stage, packet):
    receipt = load(read_private(stage / 'stage.complete.json'))
    require(receipt['plan_sha256'] == packet['plan_sha256'] and receipt['source_sha256'] == packet['source_sha256'], 'COLLECTION_IDENTITY_DIFFERS')
    mapping = {'package.zip': 'inputs/package.zip', 'native-form-spec.json': 'inputs/native-form-spec.json',
               'allocation-receipt.json': 'inputs/allocate.evidence.json', 'verification-profile.json': 'inputs/verification-profile.json',
               'clean-import-receipt.json': 'inputs/verify.evidence.json', 'qa-profile.json': 'prepared/profile.json',
               'target-receipt.json': 'prepared/target.json', 'stage-receipt.json': 'stage.complete.json'}
    files = {name: read_private(stage / relative) for name, relative in mapping.items()}
    for name, relative in mapping.items():
        if relative in receipt['bound_files']: require(digest(files[name]) == receipt['bound_files'][relative], 'COLLECTED_INPUT_CHANGED')
    reports = list((stage / 'results').glob('FQ-*/qa-result.json'))
    require(len(reports) == 1 and re.fullmatch(r'FQ-[0-9]{8}T[0-9]{6}-[a-f0-9]{8}', reports[0].parent.name), 'EXACT_SINGLE_QA_REPORT_REQUIRED')
    files['qa-result.json'] = read_private(reports[0])
    report = load(files['qa-result.json'])
    require(report.get('run_id') == reports[0].parent.name, 'QA_REPORT_IDENTITY_DIFFERS')
    files['launch-intent.json'] = read_private(ROOT / 'launch-v2' / (receipt['allocation_receipt_sha256'] + '.json'))
    dispatch_path = ROOT / 'dispatch-v2' / (receipt['allocation_receipt_sha256'] + '.json')
    needs_dispatch = bool(report.get('write_attempts')) or str(report.get('dispatch_state', '')).startswith('ATTEMPT_')
    require(not needs_dispatch or dispatch_path.exists(), 'ATTEMPTED_QA_DISPATCH_RECEIPT_MISSING')
    if dispatch_path.exists(): files['dispatch-receipt.json'] = read_private(dispatch_path)
    if (stage / 'launch.complete.json').exists(): files['launch-receipt.json'] = read_private(stage / 'launch.complete.json')
    secret_raw = read_private(stage / 'inputs' / 'runtime-credentials.json')
    require(digest(secret_raw) == receipt['bound_files']['inputs/runtime-credentials.json'], 'CREDENTIAL_COPY_CHANGED')
    secrets = load(secret_raw).values()
    require(not any(secret.encode() in raw for secret in secrets for raw in files.values()), 'SECRET_FOUND_IN_REQUESTED_EVIDENCE')
    require(sum(len(raw) for raw in files.values()) <= 12_000_000, 'EVIDENCE_TOO_LARGE')
    return {'status': 'COLLECTED', 'plan_sha256': packet['plan_sha256'], 'source_sha256': packet['source_sha256'],
            'report_path': str(reports[0]), 'sha256': {name: digest(raw) for name, raw in files.items()},
            'files': {name: base64.b64encode(raw).decode() for name, raw in files.items()},
            'credentials_and_logs_excluded': True, 'screenshots_retained_remotely': True}


def execute(packet):
    os.umask(0o077)
    sources = source_packet(packet)
    inspect_baselines(packet)
    stage = ROOT / 'v2-stages' / packet['plan_sha256'] / packet['source_sha256']
    if packet['command'] == 'collect':
        return collect(stage, packet)
    inputs = handoff(packet)
    allocation_hash = validate_handoff(packet, inputs)
    image_tag = 'localhost/fox-native-qa:v2-' + packet['plan_sha256'][:16] + '-' + packet['source_sha256'][:16]
    base_tag = image_tag + '-base'
    if packet['command'] == 'stage':
        # An offline inherited dependency layer must match these exact lock bytes.
        probe = "const fs=require('fs'),c=require('crypto');console.log(JSON.stringify({version:require('playwright/package.json').version,...Object.fromEntries(['package.json','package-lock.json'].map(n=>[n,c.createHash('sha256').update(fs.readFileSync('/opt/fox-qa/'+n)).digest('hex')]))}))"
        dependencies = load(command(podman_args(BASE_IMAGE) + ['-e', probe]).stdout)
        require(dependencies == {'version': '1.64.0', **{name: digest(sources[name]) for name in ('package.json', 'package-lock.json')}}, 'CACHED_DEPENDENCIES_DIFFER_NO_INSTALL')
        for tag in (image_tag, base_tag):
            require(command(['podman', 'image', 'exists', tag], allowed=(0, 1)).returncode == 1, 'UNIQUE_STAGE_IMAGE_ALREADY_EXISTS')
        private_dir(stage.parent, create=True)
        private_dir(stage, create=True, exclusive=True)
        for name in ('source', 'source/lib', 'inputs', 'prepared', 'results'):
            private_dir(stage / name, create=True)
        for name, raw in sources.items(): create(stage / 'source' / name, raw)
        for name, raw in inputs.items(): create(stage / 'inputs' / name, raw)
        create(stage / 'stage.intent.json', canonical({'plan_sha256': packet['plan_sha256'], 'source_sha256': packet['source_sha256'], 'allocation_receipt_sha256': allocation_hash}))
        # Unique alias enables FROM without changing the existing installed tag.
        command(['podman', 'tag', BASE_IMAGE, base_tag])
        containerfile = ('FROM ' + base_tag + '\nUSER root\nCOPY lib /opt/fox-qa/lib\nCOPY run-native.mjs prepare-target.mjs /opt/fox-qa/\nRUN chmod -R a+rX /opt/fox-qa\nUSER pwuser\n').encode()
        create(stage / 'source' / 'Containerfile', containerfile)
        command(['podman', 'build', '--pull=never', '--network=none', '--tag', image_tag, '--file', str(stage / 'source' / 'Containerfile'), str(stage / 'source')], timeout=300)
        image = command(['podman', 'image', 'inspect', image_tag, '--format', '{{.Id}}']).stdout.decode().strip()
        require(re.fullmatch('(sha256:)?[a-f0-9]{64}', image), 'IMMUTABLE_IMAGE_ID_REQUIRED')
        volumes = [(stage / 'inputs' / name, '/inputs/' + name, 'ro') for name in HANDOFF if name != 'runtime-credentials.json']
        volumes.append((stage / 'prepared', '/prepared', 'rw'))
        args = podman_args(image, volumes=volumes) + ['/opt/fox-qa/prepare-target.mjs', '--clean-install', '--verification-profile', '/inputs/verification-profile.json',
                '--package', '/inputs/package.zip', '--native-spec', '/inputs/native-form-spec.json', '--import-receipt', '/inputs/verify.evidence.json',
                '--profile-output', '/prepared/profile.json', '--output', '/prepared/target.json', '--approve-synthetic-writes']
        command(args)
        for name in ('target.json', 'profile.json'): read_private(stage / 'prepared' / name)
        old = b"image='localhost/fox-native-qa:pw1.64.0'"
        require(sources['run-jsn-qa.sh'].count(old) == 1, 'RUNNER_IMAGE_LINE_CHANGED')
        wrapper = sources['run-jsn-qa.sh'].replace(old, ("image='" + image + "'").encode())
        create(stage / 'source' / 'run-native-v2.sh', wrapper)
        bound = {path.relative_to(stage).as_posix(): digest(read_private(path)) for path in (
            *[stage / 'source' / name for name in sources], stage / 'source' / 'Containerfile', stage / 'source' / 'run-native-v2.sh',
            *[stage / 'inputs' / name for name in HANDOFF], stage / 'prepared' / 'profile.json', stage / 'prepared' / 'target.json')}
        receipt = {'status': 'STAGED', 'plan_sha256': packet['plan_sha256'], 'source_sha256': packet['source_sha256'],
                   'allocation_receipt_sha256': allocation_hash, 'image_id': image, 'image_tag': image_tag, 'stage': str(stage), 'bound_files': bound}
        create(stage / 'stage.complete.json', canonical(receipt))
        return {key: value for key, value in receipt.items() if key != 'bound_files'}
    private_dir(stage)
    receipt = load(read_private(stage / 'stage.complete.json'))
    require(receipt['source_sha256'] == packet['source_sha256'] and receipt['plan_sha256'] == packet['plan_sha256']
            and receipt['allocation_receipt_sha256'] == allocation_hash and receipt['stage'] == str(stage), 'STAGED_IDENTITY_DIFFERS')
    expected_bound = {'source/' + name for name in FILES} | {'source/Containerfile', 'source/run-native-v2.sh', 'prepared/profile.json', 'prepared/target.json'} | {'inputs/' + name for name in HANDOFF}
    require(set(receipt['bound_files']) == expected_bound, 'STAGED_BINDING_COVERAGE_DIFFERS')
    for name, expected in receipt['bound_files'].items():
        require(not Path(name).is_absolute() and '..' not in Path(name).parts and digest(read_private(stage / name)) == expected, 'STAGED_BYTES_CHANGED')
    for name in HANDOFF: require(read_private(stage / 'inputs' / name) == inputs[name], 'LIVE_HANDOFF_CHANGED')
    require(command(['podman', 'image', 'inspect', receipt['image_id'], '--format', '{{.Id}}']).stdout.decode().strip() == receipt['image_id'], 'STAGED_IMAGE_CHANGED')
    launch = private_dir(ROOT / 'launch-v2', create=True)
    require(not (ROOT / 'dispatch-v2' / (allocation_hash + '.json')).exists(), 'ALLOCATION_ALREADY_ATTEMPTED')
    create(launch / (allocation_hash + '.json'), canonical({'scope': 'fox-native-qa-launch-v2', 'allocation_receipt_sha256': allocation_hash,
           'plan_sha256': packet['plan_sha256'], 'source_sha256': packet['source_sha256'], 'image_id': receipt['image_id'], 'state': 'LAUNCH_INTENT_NO_AUTOMATIC_REPLAY'}))
    args = ['bash', str(stage / 'source' / 'run-native-v2.sh'), str(stage / 'prepared' / 'target.json'), str(stage / 'prepared' / 'profile.json'),
            str(stage / 'inputs' / 'runtime-credentials.json'), str(stage / 'results'), str(stage / 'inputs' / 'package.zip'),
            str(stage / 'inputs' / 'native-form-spec.json'), str(stage / 'inputs' / 'verify.evidence.json'), str(stage / 'inputs' / 'verification-profile.json')]
    completed = command(args, timeout=960, allowed=(0, 2, 124, 137))
    result = {'status': 'PASSED' if completed.returncode == 0 else 'QA_FAILED_OR_INCOMPLETE', 'exit_code': completed.returncode,
              'plan_sha256': packet['plan_sha256'], 'source_sha256': packet['source_sha256'], 'image_id': receipt['image_id'],
              'result_directory': str(stage / 'results'), 'automatic_replay_permitted': False}
    create(stage / 'launch.complete.json', canonical(result))
    return result
