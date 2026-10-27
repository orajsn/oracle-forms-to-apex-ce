"""JSN project QA stage/launch/harvest program; inert when imported.

The old host Python runs only orchestration. Exact package and prepared input
validation runs in the paired converter Python. New project paths never adopt
native v1/v2 stages or dispatch receipts. Every possible launch is create-only.
"""
import base64
import os
from pathlib import Path
import re
from . import native_qa_remote as n

ROOT, BASE_IMAGE, BASE_DIGEST = n.ROOT, n.BASE_IMAGE, n.BASE_DIGEST
LIMIT = n.LIMIT
require, digest, canonical, load = n.require, n.digest, n.canonical, n.load
command, private_dir, read_private, create = n.command, n.private_dir, n.read_private, n.create
podman_args, inspect_baselines = n.podman_args, n.inspect_baselines
FILES = {'package.json', 'package-lock.json', 'run-project.mjs', 'lib/contracts.mjs',
         'lib/package-evidence.mjs', 'lib/project-profile.mjs', 'lib/project-runner-inputs.mjs',
         'lib/project-runtime.mjs', 'lib/project-browser.mjs'}
HANDOFF = ('package.zip', 'native-project-spec.json', 'source-to-apex.json',
           'allocate.evidence.json', 'verification-profile.json', 'verify.evidence.json', 'runtime-credentials.json')
PREPARED = ('profile.json', 'target.json')

HANDOFF_READER = r'''
import base64,hashlib,json,os,stat,sys,types
from pathlib import Path
def need(ok):
 if not ok:raise RuntimeError('PROJECT_PRIVATE_HANDOFF_INVALID')
p=json.load(sys.stdin);root=Path('/opt/forms2apex/outputs/jobs/.operator-project-clean')/p['plan_sha256']
for path in (root.parent,root):
 s=path.lstat();need(stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode) and s.st_uid==os.getuid() and stat.S_IMODE(s.st_mode)==0o700)
def read(name):
 fd=os.open(root/name,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as f:
  s=os.fstat(f.fileno());need(stat.S_ISREG(s.st_mode) and s.st_uid==os.getuid() and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=8000000)
  raw=f.read(8000001);need(0<len(raw)<=8000000);return raw
plan_raw=read('plan.json');need(plan_raw==base64.b64decode(p['plan_b64'],validate=True))
need(hashlib.sha256(plan_raw).hexdigest()==p['plan_sha256'])
sources={name:base64.b64decode(raw,validate=True) for name,raw in p['clean_code'].items()}
need({name:hashlib.sha256(raw).hexdigest() for name,raw in sources.items()}==p['clean_operator_manifest'])
manifest=(json.dumps(p['clean_operator_manifest'],sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode()
need(hashlib.sha256(manifest).hexdigest()==p['operator_code_sha256'])
helper=base64.b64decode(p['prepare_b64'],validate=True);need(hashlib.sha256(helper).hexdigest()==p['prepare_sha256'])
for name in ('qa','qa.operator'):
 module=types.ModuleType(name);module.__path__=[];sys.modules[name]=module
for filename in ('contracts.py','project_contracts.py','project_qa_contracts.py'):
 name='qa.operator.'+filename[:-3];module=types.ModuleType(name);module.__package__='qa.operator';sys.modules[name]=module
 exec(compile(helper if filename=='project_qa_contracts.py' else sources[filename],filename,'exec'),module.__dict__)
c=sys.modules['qa.operator.contracts'];pc=sys.modules['qa.operator.project_contracts'];prepare=sys.modules['qa.operator.project_qa_contracts']
plan=pc.validate_plan(plan_raw,operator_code_sha256=p['operator_code_sha256'])
files={name:read(name) for name in prepare.HANDOFF}
intent,complete=map(c.load_json,(read('verify.intent.json'),read('verify.complete.json')))
need(pc.validate_phase_record(intent,plan,'verify')=='attention' and intent['state']=='intent')
need(pc.validate_phase_record(complete,plan,'verify')=='complete' and complete['started_at_utc']==intent['started_at_utc'])
need(complete['evidence_sha256']==c.digest(files['verify.evidence.json']) and not (root/'verify.attention.json').exists())
files.update(prepare.prepare_inputs(plan_raw,files,operator_code_sha256=p['operator_code_sha256']))
print(json.dumps({name:base64.b64encode(raw).decode() for name,raw in files.items()}))
'''


def source_packet(packet):
    require(packet.get('command') in ('stage', 'run', 'collect') and packet.get('apply') is (packet['command'] != 'collect'),
            'EXPLICIT_PROJECT_ACTION_REQUIRED')
    for key in ('plan_sha256', 'source_sha256'):
        require(type(packet.get(key)) is str and re.fullmatch('[a-f0-9]{64}', packet[key]), 'EXACT_PROJECT_DIGEST_REQUIRED')
    descriptor = packet['descriptor']
    require(descriptor.get('scope') == 'fox-project-qa-stage-source-v1' and descriptor.get('schema_version') == 1
        and descriptor['base_qa_image'] == BASE_IMAGE and descriptor['base_digest'] == BASE_DIGEST,
        'PROJECT_SOURCE_POLICY_DIFFERS')
    require(digest(canonical(descriptor)) == packet['source_sha256'] and set(packet['files']) == FILES
        and set(descriptor['files']) == FILES and set(packet['helpers']) == {'native_qa_remote.py', 'project_qa_contracts.py'}
        and set(descriptor['helpers']) == set(packet['helpers']), 'PROJECT_SOURCE_MANIFEST_DIFFERS')
    require(digest(canonical(descriptor['clean_operator_manifest'])) == descriptor['clean_operator_code_sha256'],
            'PROJECT_CLEAN_MANIFEST_DIFFERS')
    require(digest(base64.b64decode(packet['remote_b64'], validate=True)) == descriptor['remote_sha256'],
            'PROJECT_REMOTE_SOURCE_DIFFERS')
    for name, encoded in packet['helpers'].items():
        require(digest(base64.b64decode(encoded, validate=True)) == descriptor['helpers'][name], 'PROJECT_HELPER_SOURCE_DIFFERS')
    files = {name: base64.b64decode(raw, validate=True) for name, raw in packet['files'].items()}
    require(all(0 < len(raw) <= 2_000_000 and digest(raw) == descriptor['files'][name] for name, raw in files.items()),
            'PROJECT_RUNNER_SOURCE_DIFFERS')
    plan_raw = base64.b64decode(packet['plan_b64'], validate=True)
    require(digest(plan_raw) == packet['plan_sha256'], 'PROJECT_PLAN_BYTES_DIFFER')
    return files


def handoff(packet):
    descriptor = packet['descriptor']
    wire = {'plan_sha256': packet['plan_sha256'], 'plan_b64': packet['plan_b64'], 'clean_code': packet['clean_code'],
        'clean_operator_manifest': descriptor['clean_operator_manifest'],
        'operator_code_sha256': descriptor['clean_operator_code_sha256'],
        'prepare_b64': packet['helpers']['project_qa_contracts.py'],
        'prepare_sha256': descriptor['helpers']['project_qa_contracts.py']}
    result = command(['podman', 'exec', '-i', 'forms2apex-mcp', 'python3.11', '-B', '-c', HANDOFF_READER], data=canonical(wire))
    values = load(result.stdout)
    require(set(values) == set(HANDOFF) | set(PREPARED), 'PROJECT_HANDOFF_MEMBERS_DIFFER')
    return {name: base64.b64decode(raw, validate=True) for name, raw in values.items()}


def validate_handoff(packet, files):
    require(set(files) == set(HANDOFF) | set(PREPARED), 'PROJECT_HANDOFF_MEMBERS_DIFFER')
    plan = load(base64.b64decode(packet['plan_b64'], validate=True))
    require(plan.get('scope') == 'fox-project-clean-install-plan-v1', 'PROJECT_PLAN_SCOPE_DIFFERS')
    allocation, policy, imported, target = [load(files[name]) for name in (
        'allocate.evidence.json', 'verification-profile.json', 'verify.evidence.json', 'target.json')]
    binding = {key: plan['binding'][key] for key in ('job_id', 'source_manifest_sha256', 'package_sha256')}
    allocation_hash = digest(files['allocate.evidence.json'])
    require(allocation.get('scope') == 'fox-clean-allocation-v2' and allocation.get('passed') is True
        and allocation.get('plan_sha256') == packet['plan_sha256'] and allocation.get('binding') == binding,
        'PROJECT_ALLOCATION_UNPROVEN')
    require(policy.get('scope') == 'fox-native-verification-profile-v2' and policy.get('policy_id') == 'jsn-clean-native-v2'
        and policy.get('binding') == dict(binding, allocation_receipt_sha256=allocation_hash)
        and policy.get('target') == {key: value for key, value in allocation['target'].items() if key != 'instance_id'},
        'PROJECT_POLICY_ALLOCATION_DIFFERS')
    require(imported.get('scope') == 'fox-project-clean-package-install-v1' and target.get('scope') == 'fox-project-qa-target-v1'
        and target.get('target') == policy['target'] == imported.get('target')
        and all(target.get(key) == value == imported.get(key) for key, value in binding.items())
        and target.get('allocation_receipt_sha256') == allocation_hash == imported.get('allocation_receipt_sha256')
        and target.get('verification_profile_sha256') == digest(files['verification-profile.json']) == imported.get('verification_profile_sha256')
        and target.get('profile_sha256') == digest(files['profile.json'])
        and target.get('import_receipt_sha256') == digest(files['verify.evidence.json']), 'PROJECT_TARGET_BINDING_DIFFERS')
    for name, key in (('package.zip', 'package_sha256'), ('native-project-spec.json', 'project_spec_sha256'),
                      ('source-to-apex.json', 'source_to_apex_sha256')):
        require(digest(files[name]) == plan['binding'][key] == target.get(key), 'PROJECT_PACKAGE_BYTES_DIFFER')
    accounts = load(files['runtime-credentials.json'])
    require(set(accounts) == {'username', 'password', 'second_username', 'second_password'}
        and all(type(value) is str and 0 < len(value) <= 1024 for value in accounts.values())
        and accounts['username'] == 'FOX_QA_A' and accounts['second_username'] == 'FOX_QA_B'
        and accounts['password'] != accounts['second_password'], 'PROJECT_RUNTIME_IDENTITIES_DIFFER')
    return allocation_hash


def checked_stage(stage, packet):
    receipt = load(read_private(stage / 'stage.complete.json'))
    require(receipt.get('status') == 'STAGED' and receipt.get('plan_sha256') == packet['plan_sha256']
        and receipt.get('source_sha256') == packet['source_sha256'] and receipt.get('stage') == str(stage),
        'PROJECT_STAGE_IDENTITY_DIFFERS')
    expected = {'source/' + name for name in FILES} | {'source/Containerfile'}
    expected |= {'inputs/' + name for name in HANDOFF} | {'prepared/' + name for name in PREPARED}
    require(type(receipt.get('bound_files')) is dict and set(receipt['bound_files']) == expected,
            'PROJECT_STAGE_COVERAGE_DIFFERS')
    require(all(receipt['bound_files']['source/' + name] == expected_hash
                for name, expected_hash in packet['descriptor']['files'].items()),
            'PROJECT_STAGE_SOURCE_DIFFERS')
    for name, expected_hash in receipt['bound_files'].items():
        require(digest(read_private(stage / name)) == expected_hash, 'PROJECT_STAGE_BYTES_CHANGED')
    return receipt


def collect(stage, packet):
    # No handoff, SQL check, credential fetch or new target: read retained bytes.
    receipt = checked_stage(stage, packet)
    mapping = {'package.zip': 'inputs/package.zip', 'native-project-spec.json': 'inputs/native-project-spec.json',
        'source-to-apex.json': 'inputs/source-to-apex.json', 'allocation-receipt.json': 'inputs/allocate.evidence.json',
        'verification-profile.json': 'inputs/verification-profile.json', 'clean-import-receipt.json': 'inputs/verify.evidence.json',
        'qa-profile.json': 'prepared/profile.json', 'target-receipt.json': 'prepared/target.json', 'stage-receipt.json': 'stage.complete.json'}
    files = {name: read_private(stage / relative) for name, relative in mapping.items()}
    reports = list((stage / 'results').glob('FPQ-*/qa-result.json'))
    require(len(reports) == 1 and re.fullmatch(r'FPQ-[0-9]{8}T[0-9]{6}-[a-f0-9]{8}', reports[0].parent.name),
            'EXACT_SINGLE_PROJECT_REPORT_REQUIRED')
    files['qa-result.json'] = read_private(reports[0])
    report = load(files['qa-result.json'])
    require(report.get('run_id') == reports[0].parent.name, 'PROJECT_REPORT_IDENTITY_DIFFERS')
    allocation_hash = digest(files['allocation-receipt.json'])
    require(allocation_hash == receipt['allocation_receipt_sha256'], 'PROJECT_STAGE_ALLOCATION_DIFFERS')
    files['launch-intent.json'] = read_private(ROOT / 'launch-project-v1' / (allocation_hash + '.json'))
    launch = load(files['launch-intent.json'])
    require(launch == launch_intent(packet, receipt), 'PROJECT_LAUNCH_IDENTITY_DIFFERS')
    dispatch = ROOT / 'dispatch-project-v1' / (allocation_hash + '.json')
    attempted = bool(report.get('write_attempts')) or str(report.get('dispatch_state', '')).startswith('ATTEMPT_')
    require(not attempted or dispatch.exists(), 'PROJECT_DISPATCH_RECEIPT_MISSING')
    if dispatch.exists():files['dispatch-receipt.json'] = read_private(dispatch)
    if (stage / 'launch.complete.json').exists():files['launch-receipt.json'] = read_private(stage / 'launch.complete.json')
    accounts = load(read_private(stage / 'inputs' / 'runtime-credentials.json'))
    require(not any(secret.encode() in raw for secret in accounts.values() for raw in files.values()),
            'PROJECT_SECRET_FOUND_IN_EVIDENCE')
    require(sum(len(raw) for raw in files.values()) <= 12_000_000, 'PROJECT_EVIDENCE_TOO_LARGE')
    return {'status': 'COLLECTED', 'plan_sha256': packet['plan_sha256'], 'source_sha256': packet['source_sha256'],
        'report_path': str(reports[0]), 'sha256': {name: digest(raw) for name, raw in files.items()},
        'files': {name: base64.b64encode(raw).decode() for name, raw in files.items()},
        'credentials_and_logs_excluded': True, 'screenshots_retained_remotely': False}


def launch_intent(packet, receipt):
    return {'scope': 'fox-project-qa-launch-v1', 'allocation_receipt_sha256': receipt['allocation_receipt_sha256'],
        'plan_sha256': packet['plan_sha256'], 'source_sha256': packet['source_sha256'], 'image_id': receipt['image_id'],
        'state': 'LAUNCH_INTENT_NO_AUTOMATIC_REPLAY'}


def launch_args(stage, receipt):
    mounts = [(stage / 'inputs' / name, '/inputs/' + name, 'ro') for name in HANDOFF]
    mounts += [(stage / 'prepared', '/prepared', 'ro'), (stage / 'results', '/results', 'rw'),
               (ROOT / 'dispatch-project-v1', '/dispatch', 'rw')]
    args = podman_args(receipt['image_id'], network=True, volumes=mounts)
    environment = {'FOX_QA_PACKAGE': '/inputs/package.zip', 'FOX_QA_PROJECT_SPEC': '/inputs/native-project-spec.json',
        'FOX_QA_PROJECT_TRACE': '/inputs/source-to-apex.json', 'FOX_QA_PROFILE': '/prepared/profile.json',
        'FOX_QA_TARGET_RECEIPT': '/prepared/target.json', 'FOX_QA_IMPORT_RECEIPT': '/inputs/verify.evidence.json',
        'FOX_QA_VERIFICATION_PROFILE': '/inputs/verification-profile.json',
        'FOX_QA_ALLOCATION_RECEIPT': '/inputs/allocate.evidence.json', 'FOX_QA_CREDENTIAL_FILE': '/inputs/runtime-credentials.json',
        'FOX_QA_OUTPUT_DIR': '/results', 'FOX_QA_DISPATCH_DIR': '/dispatch', 'FOX_QA_IMAGE_ID': receipt['image_id']}
    # All container options precede the immutable image; no host env inheritance.
    index = args.index('--entrypoint')
    args[index:index] = [part for key, value in environment.items() for part in ('--env', key + '=' + value)]
    return args + ['/opt/fox-qa/run-project.mjs']


def execute(packet):
    os.umask(0o077)
    sources = source_packet(packet)
    inspect_baselines(packet)
    stage = ROOT / 'project-v1-stages' / packet['plan_sha256'] / packet['source_sha256']
    if packet['command'] == 'collect':return collect(stage, packet)
    inputs = handoff(packet)
    allocation_hash = validate_handoff(packet, inputs)
    image_tag = 'localhost/fox-project-qa:v1-' + packet['plan_sha256'][:16] + '-' + packet['source_sha256'][:16]
    base_tag = image_tag + '-base'
    if packet['command'] == 'stage':
        probe = "const fs=require('fs'),c=require('crypto');console.log(JSON.stringify({version:require('playwright/package.json').version,...Object.fromEntries(['package.json','package-lock.json'].map(n=>[n,c.createHash('sha256').update(fs.readFileSync('/opt/fox-qa/'+n)).digest('hex')]))}))"
        dependencies = load(command(podman_args(BASE_IMAGE) + ['-e', probe]).stdout)
        require(dependencies == {'version': '1.64.0', **{name: digest(sources[name]) for name in ('package.json', 'package-lock.json')}},
                'PROJECT_CACHED_DEPENDENCIES_DIFFER_NO_INSTALL')
        for tag in (image_tag, base_tag):
            require(command(['podman', 'image', 'exists', tag], allowed=(0, 1)).returncode == 1, 'PROJECT_STAGE_IMAGE_EXISTS')
        private_dir(stage.parent, create=True)
        private_dir(stage, create=True, exclusive=True)
        for name in ('source', 'source/lib', 'inputs', 'prepared', 'results'):private_dir(stage / name, create=True)
        for name, raw in sources.items():create(stage / 'source' / name, raw)
        for name in HANDOFF:create(stage / 'inputs' / name, inputs[name])
        for name in PREPARED:create(stage / 'prepared' / name, inputs[name])
        create(stage / 'stage.intent.json', canonical({'plan_sha256': packet['plan_sha256'], 'source_sha256': packet['source_sha256'],
                                                     'allocation_receipt_sha256': allocation_hash}))
        command(['podman', 'tag', BASE_IMAGE, base_tag])
        containerfile = ('FROM ' + base_tag + '\nUSER root\nCOPY lib /opt/fox-qa/lib\nCOPY run-project.mjs /opt/fox-qa/\nRUN chmod -R a+rX /opt/fox-qa\nUSER pwuser\n').encode()
        create(stage / 'source' / 'Containerfile', containerfile)
        command(['podman', 'build', '--pull=never', '--network=none', '--tag', image_tag, '--file', str(stage / 'source' / 'Containerfile'), str(stage / 'source')], timeout=300)
        image = command(['podman', 'image', 'inspect', image_tag, '--format', '{{.Id}}']).stdout.decode().strip()
        require(re.fullmatch('(sha256:)?[a-f0-9]{64}', image), 'PROJECT_IMMUTABLE_IMAGE_REQUIRED')
        names = {'source/' + name for name in sources} | {'source/Containerfile'}
        names |= {'inputs/' + name for name in HANDOFF} | {'prepared/' + name for name in PREPARED}
        bound = {name: digest(read_private(stage / name)) for name in sorted(names)}
        receipt = {'status': 'STAGED', 'plan_sha256': packet['plan_sha256'], 'source_sha256': packet['source_sha256'],
            'allocation_receipt_sha256': allocation_hash, 'image_id': image, 'image_tag': image_tag, 'stage': str(stage), 'bound_files': bound}
        create(stage / 'stage.complete.json', canonical(receipt))
        return {key: value for key, value in receipt.items() if key != 'bound_files'}
    receipt = checked_stage(stage, packet)
    require(receipt['allocation_receipt_sha256'] == allocation_hash, 'PROJECT_STAGED_ALLOCATION_DIFFERS')
    for name in HANDOFF:require(read_private(stage / 'inputs' / name) == inputs[name], 'PROJECT_LIVE_HANDOFF_CHANGED')
    for name in PREPARED:require(read_private(stage / 'prepared' / name) == inputs[name], 'PROJECT_PREPARED_INPUT_CHANGED')
    require(command(['podman', 'image', 'inspect', receipt['image_id'], '--format', '{{.Id}}']).stdout.decode().strip() == receipt['image_id'],
            'PROJECT_STAGED_IMAGE_CHANGED')
    launch = private_dir(ROOT / 'launch-project-v1', create=True)
    private_dir(ROOT / 'dispatch-project-v1', create=True)
    require(not (ROOT / 'dispatch-project-v1' / (allocation_hash + '.json')).exists(), 'PROJECT_ALLOCATION_ALREADY_ATTEMPTED')
    create(launch / (allocation_hash + '.json'), canonical(launch_intent(packet, receipt)))
    # Timeout or transport loss leaves the launch intent; never synthesize a
    # successful completion or replay browser writes after an uncertain result.
    completed = command(launch_args(stage, receipt), timeout=960, allowed=(0, 1, 2, 124, 137))
    exit_code = 2 if completed.returncode == 1 else completed.returncode
    result = {'status': 'PASSED' if exit_code == 0 else 'QA_FAILED_OR_INCOMPLETE', 'exit_code': exit_code,
        'plan_sha256': packet['plan_sha256'], 'source_sha256': packet['source_sha256'], 'image_id': receipt['image_id'],
        'result_directory': str(stage / 'results'), 'automatic_replay_permitted': False}
    create(stage / 'launch.complete.json', canonical(result))
    return result
