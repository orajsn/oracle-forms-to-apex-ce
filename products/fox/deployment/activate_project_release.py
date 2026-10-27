"""Prepare the exact JSN paired release without replacing a running container.

The public CLI creates STOPPED candidates only. No generic deploy, rollback,
container removal, secret lookup, database or OCI write operation is exposed.
The existing split stop/backup/activate/release route is separately leased.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import importlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import urllib.request

sys.dont_write_bytecode = True

SCOPE = 'fox-paired-project-activation-plan-v1'
PARENT = Path('/home/opc/.local/share/fox-project-activation')
G_RELEASE = 'acc3bf901d6f221cc5b887afe88a5cd53b9b4a8153e820b1f078b10d679004ba'
TARGET_HASH = '7170d60927b7e5b7aed5d56174f97efbeff3052be247b244911deff768701ed3'
BASE = {
    'fox': ('00d59808b89b0380b6a1cdd2f5d8c1656f81df83c8b9c1f25e15adf795ab556a',
            '9ce6e594cffedfbe85d3431af8ad929bb83222a2e1fd4b8521cad8edd9e52490'),
    'forms2apex-mcp': ('3d4294a16022444260ce242e18e7b749f967aba46e0023c7b9fc8b37ba20659a',
                      'c7fdb53bc04450e297cbbbc89fb834be714e106d5a164b1c80dc77d544db5a1b'),
    'oracle-applied-ai-label': ('ccaa17a43d933ffc6b6917e0c79aaa1a525c3f5f9cd8ae9133261ed359436ba9',
                              '7c7ebc1f3da055ab3887a520e25552142f0a37f6d05dd116c16a87cac59fee8f'),
}
UNITS = {
    'fox.service': ('/home/opc/.config/systemd/user/fox.service', '4cb1e78e4515e51bcc63f779cfd02dc84c2f72efdd7dbdb636bf3cb012eeb722'),
    'forms2apex-mcp.service': ('/home/opc/.config/systemd/user/forms2apex-mcp.service', '517f43d85893f3e3488ee59d730f3902820de4f2f00de5c17d3923f3c2219bba'),
    'fox-https.service': ('/etc/systemd/system/fox-https.service', '733385092671a4a867b81d6bd8c554760efa36b4376bdf6aa77862f4f13c86cd'),
}
BASE_PROFILES = {
    'fox': '/home/opc/fox/releases/native-beta-20261017h/deployment/native-beta-profile.json',
    'converter': '/home/opc/fox/releases/native-beta-20261017h/deployment/target-profile.jsn.json',
}
SHA = re.compile(r'[a-f0-9]{64}\Z')


class ActivationError(RuntimeError):
    """Only closed diagnostic categories; never credentials or subprocess text."""


def need(ok, code):
    if not ok:
        raise ActivationError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                       allow_nan=False) + '\n').encode()


def parse(raw):
    def unique(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'DUPLICATE_JSON_KEY')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ActivationError('INVALID_JSON_CONSTANT')))


def absolute(value):
    need(type(value) is str and 1 < len(value) <= 1024 and '\\' not in value
         and not any(ord(c) < 32 for c in value), 'CANONICAL_ABSOLUTE_PATH_REQUIRED')
    p = PurePosixPath(value)
    need(p.is_absolute() and str(p) == value and '..' not in p.parts, 'CANONICAL_ABSOLUTE_PATH_REQUIRED')
    return Path(value)


def read(path, *, private=False, maximum=16_000_000):
    path = Path(path)
    need(path.is_absolute() and path.resolve() == path, 'LINKED_PATH_FORBIDDEN')
    for member in (path, *path.parents):
        info = member.lstat()
        need(not stat.S_ISLNK(info.st_mode) and info.st_uid in (0, os.geteuid())
             and not stat.S_IMODE(info.st_mode) & 0o022, 'PATH_NOT_OWNER_CONTROLLED')
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 <= info.st_size <= maximum,
         'REGULAR_INPUT_REQUIRED')
    if private:
        need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600, 'PRIVATE_INPUT_REQUIRED')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        opened = os.fstat(stream.fileno()); raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    need(all(getattr(info, key) == getattr(opened, key) == getattr(after, key) == getattr(path.stat(), key)
             for key in fields) and len(raw) == info.st_size, 'INPUT_CHANGED_DURING_READ')
    return raw


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def create_file(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    sync(path.parent)


def private_dir(path):
    info = path.lstat()
    need(path.resolve() == path and stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
         and stat.S_IMODE(info.st_mode) == 0o700, 'PRIVATE_DIRECTORY_REQUIRED')


def command(argv, *, timeout=30, maximum=16_000_000):
    value = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout,
        env={'PATH': '/usr/bin:/bin', 'HOME': '/home/opc', 'XDG_RUNTIME_DIR': '/run/user/1000',
             'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'})
    need(value.returncode == 0 and len(value.stdout) <= maximum, 'HOST_COMMAND_UNCONFIRMED')
    return value.stdout


def host_identity():
    need(os.name == 'posix' and os.geteuid() == 1000, 'EXISTING_OPC_HOST_REQUIRED')
    request = urllib.request.Request('http://169.254.169.254/opc/v2/instance/', headers={'Authorization': 'Bearer Oracle'})
    with urllib.request.urlopen(request, timeout=10) as response:
        metadata = parse(response.read(100001))
    need(metadata.get('id') == 'ocid1.instance.oc1.iad.anuwcljtc7x6gxic5w37qsyp3rst64betkt4uk2pdcrtmy3okspcpbv77qea'
         and metadata.get('compartmentId') == 'ocid1.compartment.oc1..aaaaaaaa2q5aelkapmt5mhumvxadcynq5chez2faeucy5plefhy3ylmahtba'
         and metadata.get('canonicalRegionName') == 'us-ashburn-1', 'EXACT_JSN_HOST_REQUIRED')


def environment(item):
    result = {}
    for entry in item['Config']['Env']:
        need(type(entry) is str and '=' in entry and not any(c in entry for c in ('\n', '\r', '\x00')), 'UNSAFE_ENVIRONMENT')
        key, value = entry.split('=', 1)
        need(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', key) and key not in result, 'UNSAFE_ENVIRONMENT')
        result[key] = value
    return result


def inspect_container(name):
    values = parse(command(['/usr/bin/podman', 'inspect', name]))
    need(type(values) is list and len(values) == 1, 'EXACT_CONTAINER_REQUIRED')
    return values[0]


def baseline():
    host_identity()
    for path, expected in UNITS.values():
        need(sha(read(Path(path))) == expected, 'RETAINED_UNIT_CHANGED')
    result = {}
    for name, (identity, image) in BASE.items():
        value = inspect_container(name)
        need(value['Id'] == identity and value['Image'].split(':')[-1] == image
             and value['State']['Running'] is True and value['HostConfig']['AutoRemove'] is False,
             'G_BASELINE_CHANGED')
        result[name] = value
    need(environment(result['fox']).get('FOX_VERIFIER_RELEASE_SHA256') == G_RELEASE
         and environment(result['fox']).get('FOX_CONVERSION_PROFILE') == 'native-table-form-v1', 'G_PROFILE_CHANGED')
    return result


def baseline_signature(items):
    """Ignore transient exec sessions; preserve configuration and restart identity."""
    return sha(canonical({name: {**{key: item.get(key) for key in
        ('Id', 'Image', 'Config', 'HostConfig', 'Mounts', 'ProcessLabel', 'MountLabel')},
        'state': {key: item['State'].get(key) for key in ('Running', 'Pid', 'StartedAt')},
        'networks': item['NetworkSettings']['Networks']} for name, item in items.items()}))


def validate_bound_sources(items):
    """Compare current host paths to the actual G bind-mount inode identities."""
    for name in ('fox','forms2apex-mcp'):
        item = items[name]
        wanted = {}
        for mount in item['Mounts']:
            source = Path(mount['Source'])
            need(mount['Type'] == 'bind' and source.is_absolute() and source.resolve(strict=True) == source,
                 'BASELINE_BIND_SOURCE_LINKED_OR_MISSING')
            for part in (source,*source.parents):
                need(not part.is_symlink(),'BASELINE_BIND_SOURCE_LINKED_OR_MISSING')
            info = source.stat()
            need(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode),'BASELINE_BIND_SOURCE_UNSAFE')
            wanted[mount['Destination']] = [info.st_dev,info.st_ino,stat.S_IFMT(info.st_mode)]
        code = ('import json,os,stat,sys;paths=json.loads(sys.argv[1]);out={};'
                '\nfor p in paths:\n if os.path.islink(p):raise RuntimeError("LINKED_MOUNT")'
                '\n s=os.stat(p);out[p]=[s.st_dev,s.st_ino,stat.S_IFMT(s.st_mode)]'
                '\nprint(json.dumps(out,sort_keys=True))')
        python = '/usr/local/bin/python' if name == 'fox' else 'python3.11'
        observed = parse(command(['/usr/bin/podman','exec',item['Id'],python,'-I','-B','-c',code,json.dumps(sorted(wanted))]))
        need(observed == wanted,'BASELINE_MOUNT_INODE_DIFFERS_FROM_HOST_PATH')


def plan_document(raw, expected_sha256):
    need(type(raw) is bytes and SHA.fullmatch(expected_sha256 or '') and sha(raw) == expected_sha256, 'EXACT_PLAN_REQUIRED')
    value = parse(raw)
    need(type(value) is dict and set(value) == {'schema_version', 'scope', 'source_bundle_sha256',
         'bundle_root', 'provider', 'release', 'helper_sha256'} and type(value['schema_version']) is int and value['schema_version'] == 1
         and value['scope'] == SCOPE and canonical(value) == raw, 'PLAN_FIELDS_INVALID')
    need(SHA.fullmatch(value['source_bundle_sha256']) and SHA.fullmatch(value['helper_sha256']), 'PLAN_DIGEST_INVALID')
    root = absolute(value['bundle_root'])
    need(root.as_posix() == '/home/opc/.local/share/fox-project-builds/' + value['source_bundle_sha256'] + '/bundle',
         'EXACT_STAGED_SOURCE_ROOT_REQUIRED')
    for name in ('provider', 'release'):
        ref = value[name]
        need(type(ref) is dict and set(ref) == {'path', 'sha256'} and SHA.fullmatch(ref['sha256']), 'PLAN_REFERENCE_INVALID')
        path = absolute(ref['path'])
        need(path != root and root not in path.parents, 'CONFIGURATION_MUST_REMAIN_OUTSIDE_BUNDLE')
    need(value['provider']['path'] != value['release']['path'], 'CONFIGURATION_REFERENCES_COLLIDE')
    return value


def load_bindings(plan):
    """Measure B before importing its pure validators; select no runtime here."""
    root = absolute(plan['bundle_root'])
    inventory_raw = read(root.parent / 'source-inventory.json', private=True)
    need(sha(inventory_raw) == plan['source_bundle_sha256'], 'SOURCE_INVENTORY_CHANGED')
    inventory = parse(inventory_raw)
    need(inventory.get('scope') == 'fox-hosted-source-inventory-v1' and inventory.get('schema_version') == 1
         and type(inventory.get('files')) is dict and 0 < len(inventory['files']) <= 2000, 'SOURCE_INVENTORY_INVALID')
    actual = {}
    for path in root.rglob('*'):
        need(not path.is_symlink(), 'SOURCE_LINK_FORBIDDEN')
        if path.is_file():
            actual[path.relative_to(root).as_posix()] = sha(read(path))
    need(actual == inventory['files'], 'SOURCE_INVENTORY_CHANGED')
    for prefix in ('qa', 'fox', 'forms2apex'):
        need(not any(name == prefix or name.startswith(prefix + '.') for name in sys.modules), 'FRESH_VALIDATOR_NAMESPACE_REQUIRED')
    sys.path[:0] = [str(root), str(root / 'fox'), str(root / 'converter')]
    runtime = importlib.import_module('qa.operator.runtime_provider')
    bridge = importlib.import_module('qa.operator.product_queue_transport')
    verifier = importlib.import_module('qa.operator.product_verifier')
    provider_raw = read(absolute(plan['provider']['path']), private=True)
    release_raw = read(absolute(plan['release']['path']), private=True)
    provider = runtime.configuration_document(provider_raw, expected_sha256=plan['provider']['sha256'])
    release = bridge.validate_release(parse(release_raw))
    need(provider['schema_version'] == 2 and provider['owner_uid'] == 1000 and provider['converter_root'] == str(root / 'converter')
         and sha(release_raw) == plan['release']['sha256'] and canonical(release) == release_raw
         and release['schema_version'] == 3 and release['enabled'] is True
         and release['hosted_runtime_configuration_sha256'] == plan['provider']['sha256']
         and provider['images'] == release['images'] and release['opaf_profile']['target_profile_sha256'] == TARGET_HASH,
         'PAIRED_CONFIGURATION_CHANGED')
    reconstructed = verifier.build_manifest({'schema_version':3, 'scope':'fox-product-verifier-operator-config-v3',
        'enabled':True, 'images':release['images'], 'hosted_runtime_configuration_sha256':plan['provider']['sha256'],
        'opaf_profile':{key:value for key,value in release['opaf_profile'].items() if key != 'host_path'}},
        hosted_configuration=provider_raw)
    need(canonical(reconstructed) == release_raw, 'RELEASE_DOES_NOT_MATCH_ACTUAL_BUNDLE_SOURCE')
    need(release['opaf_profile']['host_path'] == str(root / 'deployment/project-opaf-profile-v2.json')
         and sha(read(Path(release['opaf_profile']['host_path']))) == release['native_profile_sha256'], 'OPAF_PROFILE_CHANGED')
    need(stat.S_IMODE(Path(release['opaf_profile']['host_path']).stat().st_mode) == 0o644, 'PUBLIC_PROFILE_NOT_READABLE_BY_FOX_UID')
    for role, old in (('fox', BASE['fox'][1]), ('converter', BASE['forms2apex-mcp'][1])):
        receipt = parse(read(root.parent / (role + '-build-complete.json'), private=True))
        need(receipt.get('status') == 'BUILT_NOT_ACTIVATED' and receipt.get('source_bundle_sha256') == plan['source_bundle_sha256']
             and receipt.get('image') == release['images'][role] and release['images'][role] != 'sha256:' + old,
             'ACTUAL_NEW_PAIRED_IMAGES_REQUIRED')
    return provider, release


def names(release):
    suffix = release[:16]
    return {'fox': 'fox-project-' + suffix, 'converter': 'forms2apex-project-' + suffix}


def new_environment(role, old, release, profile):
    result = environment(old)
    if role == 'fox':
        result.update(FOX_CONVERSION_PROFILE='native-project-v1', FOX_VERIFIER_RELEASE_SHA256=release)
        need(result.get('FOX_NATIVE_PROFILE_FILE') == '/run/fox-native/profile.json'
             and result.get('FOX_RUN_ADAPTER') == 'embedded-opaf' and result.get('FOX_VERIFICATION_ENABLED') == '1',
             'FOX_ENVIRONMENT_BOUNDARY_CHANGED')
    else:
        result.update(F2A_OPAF_MAPPER_WORKFLOW_ID=profile['mapper']['workflow_id'],
                      F2A_OPAF_REVIEWER_WORKFLOW_ID=profile['reviewer']['workflow_id'],
                      F2A_GENERATOR_MODEL=profile['mapper']['model'], F2A_REVIEWER_MODEL=profile['reviewer']['model'])
        need(result.get('F2A_TARGET_PROFILE_PATH') == '/run/fox-target/profile.json'
             and len(result.get('F2A_MCP_BEARER_TOKEN', '')) >= 32, 'CONVERTER_ENVIRONMENT_BOUNDARY_CHANGED')
    return result


def mount_map(item):
    result = {}
    for mount in item['Mounts']:
        need(mount['Type'] == 'bind' and mount['Destination'] not in result and type(mount['RW']) is bool,
             'EXACT_BIND_MOUNTS_REQUIRED')
        result[mount['Destination']] = (mount['Source'], mount['RW'])
    return result


def ulimits(item):
    result = {}
    for row in item['HostConfig'].get('Ulimits') or []:
        name = row['Name'].lower().removeprefix('rlimit_')
        need(name in {'as','core','cpu','data','fsize','locks','memlock','msgqueue','nice','nofile','nproc','rss',
                      'rtprio','rttime','sigpending','stack'} and name not in result
             and all(type(row[k]) is int and row[k] >= -1 for k in ('Soft', 'Hard')), 'ULIMITS_CHANGED')
        result[name] = (row['Soft'], row['Hard'])
    return result


def candidate_argv(role, old, plan, release, stage):
    root, label = PurePosixPath(plan['bundle_root']), plan['release']['sha256']
    stage = PurePosixPath(stage.as_posix())
    config = old['HostConfig']
    need(role in ('fox', 'converter') and config['Privileged'] is False and config['AutoRemove'] is False
         and all(config.get(k, 0) == 0 for k in ('Memory', 'NanoCpus', 'CpuPeriod', 'CpuQuota', 'PidsLimit')),
         'BASELINE_RESOURCE_OR_PRIVILEGE_BOUNDARY_CHANGED')
    levels = [x for x in config['SecurityOpt'] if x.startswith('label=level:')]
    need(len(levels) == 1 and re.fullmatch('label=level:s0:c[0-9]+,c[0-9]+', levels[0]), 'SELINUX_LEVEL_REQUIRED')
    args = ['/usr/bin/podman', 'create', '--name', names(label)[role], '--pull=never', '--http-proxy=false',
            '--image-volume=ignore', '--security-opt', levels[0], '--label', 'com.oracle.jsn.fox.release=' + label,
            '--label', 'com.oracle.jsn.fox.source-bundle=' + plan['source_bundle_sha256'],
            '--env-file', str(stage / (role + '.env'))]
    for name, (soft, hard) in sorted(ulimits(old).items()):
        args += ['--ulimit', f'{name}={soft}:{hard}']
    if role == 'fox':
        expected = {'/data': ('/home/opc/fox/data', True), '/run/fox-opaf': ('/home/opc/fox/secure/opaf-client', False),
                    '/run/fox-native/profile.json': (BASE_PROFILES['fox'], False)}
        need(mount_map(old) == expected and old['Config']['User'] == '1000:1000'
             and config['NetworkMode'] == 'host' and not config.get('UsernsMode') and config['ReadonlyRootfs'] is True
             and config['PortBindings'] == {}, 'FOX_BASELINE_CONFIGURATION_CHANGED')
        args += ['--network', 'host', '--read-only', '--cap-drop', 'all', '--security-opt', 'no-new-privileges',
                 '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m', '--user', '1000:1000']
        expected['/run/fox-native/profile.json'] = (str(root / 'deployment/project-opaf-profile-v2.json'), False)
    else:
        expected = {'/opt/forms2apex/outputs/jobs': ('/home/opc/forms2apex/outputs/jobs', True),
                    '/home/converter/.dbtools': ('/home/opc/forms2apex/sqlcl-user', True),
                    '/opt/forms2apex/wallet': ('/home/opc/opaf-secure/JSNF2APEX_wallet_single', False),
                    '/opt/sqlcl': ('/home/opc/sqlcl', False),
                    '/run/fox-target/profile.json': (BASE_PROFILES['converter'], False)}
        need(mount_map(old) == expected and old['Config']['User'] == '10001'
             and config['NetworkMode'] == 'bridge' and config['UsernsMode'] == 'private'
             and config['ReadonlyRootfs'] is False and config['PortBindings'] == {'8090/tcp': [{'HostIp':'127.0.0.1','HostPort':'8091'}]}
             and set(old['NetworkSettings']['Networks']) == {'forms2apex','applied-ai-agent_factory_oracle_network'}
             and old['NetworkSettings']['Networks']['forms2apex']['IPAddress'] == '10.89.1.3',
             'CONVERTER_BASELINE_CONFIGURATION_CHANGED')
        args += ['--publish', '127.0.0.1:8091:8090', '--network', 'forms2apex:ip=10.89.1.3',
                 '--network', 'applied-ai-agent_factory_oracle_network', '--userns', 'keep-id:uid=10001,gid=10001',
                 '--user', '10001']
        expected['/run/fox-target/profile.json'] = (str(root / 'deployment/target-profile.jsn-project-v2.json'), False)
    for target, (source, writable) in sorted(expected.items()):
        args += ['--volume', source + ':' + target + ('' if writable else ':ro')]
    return args + [release['images'][role]], expected


def check_candidate(item, role, plan, release, env, mounts, *, baseline_item):
    config = item['HostConfig']
    need(item['Name'].lstrip('/') == names(plan['release']['sha256'])[role]
         and item['Image'].split(':')[-1] == release['images'][role][7:]
         and item['State']['Running'] is False and item['State']['Pid'] == 0
         and item['State']['Status'] in ('created','configured') and config['AutoRemove'] is False
         and config['Privileged'] is False and environment(item) == env and mount_map(item) == mounts
         and item['Config'].get('Labels', {}).get('com.oracle.jsn.fox.release') == plan['release']['sha256'],
         'STOPPED_CANDIDATE_CONFIGURATION_CHANGED')
    need(config['ReadonlyRootfs'] is (role == 'fox')
         and item['Config']['User'] == ('1000:1000' if role == 'fox' else '10001'), 'CANDIDATE_USER_OR_FILESYSTEM_CHANGED')
    old = baseline_item['HostConfig']
    need(all(config.get(key) == old.get(key) for key in ('NetworkMode','UsernsMode','PortBindings','PublishAllPorts',
        'Memory','NanoCpus','CpuPeriod','CpuQuota','PidsLimit','ShmSize','RestartPolicy'))
        and set(config.get('SecurityOpt') or []) == set(old.get('SecurityOpt') or [])
        and set(config.get('CapAdd') or []) == set(old.get('CapAdd') or [])
        and set(config.get('CapDrop') or []) == set(old.get('CapDrop') or [])
        and ulimits(item) == ulimits(baseline_item)
        and set(item['NetworkSettings']['Networks']) == set(baseline_item['NetworkSettings']['Networks'])
        and item['Config']['Cmd'] == baseline_item['Config']['Cmd']
        and item['Config']['Entrypoint'] == baseline_item['Config']['Entrypoint']
        and item['Config']['WorkingDir'] == baseline_item['Config']['WorkingDir'],
        'CANDIDATE_RUNTIME_BOUNDARY_CHANGED')


def create_once(stage, role, argv, plan_sha256):
    """Retain original process/log/exit facts; never restart an uncertain create."""
    create_file(stage / (role + '-create-intent.json'), canonical({'argv_sha256':sha(canonical(argv)),
        'plan_sha256':plan_sha256,'started_at_utc':datetime.now(timezone.utc).isoformat(),
        'automatic_replay_permitted':False}))
    host_identity()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    with os.fdopen(os.open(stage / (role + '-create.stdout'), flags, 0o600), 'wb') as stdout, \
         os.fdopen(os.open(stage / (role + '-create.stderr'), flags, 0o600), 'wb') as stderr:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
            env={'PATH':'/usr/bin:/bin','HOME':'/home/opc','XDG_RUNTIME_DIR':'/run/user/1000','LANG':'C.UTF-8'})
        create_file(stage / (role + '-create-process.json'), canonical({'pid':process.pid,
            'parent_pid':os.getpid(),'started_at_utc':datetime.now(timezone.utc).isoformat(),
            'automatic_replay_permitted':False}))
        try:
            code = process.wait(timeout=90)
        except subprocess.TimeoutExpired:
            raise ActivationError('CREATE_OUTCOME_UNCONFIRMED_INSPECT_SAME_PROCESS_NO_REPLAY') from None
        stdout.flush(); os.fsync(stdout.fileno()); stderr.flush(); os.fsync(stderr.fileno())
    create_file(stage / (role + '-create-exit.json'), canonical({'exit_code':code,
        'observed_at_utc':datetime.now(timezone.utc).isoformat(),'observed_original_process':True}))
    need(code == 0, 'CREATE_FAILED_PRESERVED_NO_REPLAY')
    return read(stage / (role + '-create.stdout'), private=True, maximum=65536)


@contextmanager
def held_stage(stage, *, create=False):
    import fcntl
    if create:
        need(not stage.exists() and not stage.is_symlink(), 'PRIOR_CANDIDATE_STAGE_PRESERVED')
        if not stage.parent.exists():
            stage.parent.mkdir(mode=0o700); sync(stage.parent.parent)
        private_dir(stage.parent)
        stage.mkdir(mode=0o700); sync(stage.parent)
        create_file(stage / 'operation.lock', b'0')
    private_dir(stage)
    path = stage / 'operation.lock'
    need(read(path, private=True) == b'0', 'OPERATION_LOCK_CHANGED')
    with path.open('r+b') as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def create_candidates(plan, *, expected_plan_sha256, apply=False):
    need(apply is True and sha(canonical(plan)) == expected_plan_sha256
         and sha(read(Path(__file__).resolve())) == plan['helper_sha256'], 'EXPLICIT_REVIEWED_CREATE_REQUIRED')
    provider, release = load_bindings(plan)
    before = baseline()
    validate_bound_sources(before)
    signature = baseline_signature(before)
    stage = PARENT / plan['release']['sha256']
    need(not stage.exists(), 'PRIOR_CANDIDATE_STAGE_PRESERVED')
    existing_names = set(command(['/usr/bin/podman','ps','-a','--format','{{.Names}}']).decode().splitlines())
    need(not (set(names(plan['release']['sha256']).values()) & existing_names), 'CANDIDATE_NAME_ALREADY_EXISTS')
    profile = parse(read(Path(release['opaf_profile']['host_path'])))
    with held_stage(stage, create=True):
        create_file(stage / 'plan.json', canonical(plan))
        create_file(stage / 'before.private.json', canonical(before))
        result = {}
        for role, old_name in (('fox','fox'), ('converter','forms2apex-mcp')):
            old = before[old_name]
            env = new_environment(role, old, plan['release']['sha256'], profile)
            create_file(stage / (role + '.env'), ('\n'.join(k+'='+v for k,v in sorted(env.items()))+'\n').encode())
            args, mounts = candidate_argv(role, old, plan, release, stage)
            need(baseline_signature(baseline()) == signature, 'BASELINE_CHANGED_BEFORE_CREATE')
            cid = create_once(stage, role, args, expected_plan_sha256).decode().strip()
            need(SHA.fullmatch(cid), 'CANDIDATE_ID_UNCONFIRMED')
            item = inspect_container(cid)
            check_candidate(item, role, plan, release, env, mounts, baseline_item=old)
            result[role] = {'id':cid, 'image':release['images'][role], 'name':names(plan['release']['sha256'])[role]}
            create_file(stage / (role + '-created.json'), canonical(result[role]))
        need(baseline_signature(baseline()) == signature, 'BASELINE_CHANGED_DURING_CREATE')
        admission = {'schema_version':1,'scope':'fox-hosted-admission-v1',
            'provider_configuration_sha256':plan['provider']['sha256'],'current_release_sha256':plan['release']['sha256'],
            'infrastructure':{'fox':{k:result['fox'][k] for k in ('id','image')},
                'forms2apex-mcp':{k:result['converter'][k] for k in ('id','image')},
                'oracle-applied-ai-label':{'id':BASE['oracle-applied-ai-label'][0], 'image':'sha256:'+BASE['oracle-applied-ai-label'][1]}}}
        create_file(stage / 'admission.json', canonical(admission))
        report = {'status':'STOPPED_CANDIDATES_CREATED_NOT_ACTIVATED','plan_sha256':expected_plan_sha256,
            'release_sha256':plan['release']['sha256'],'candidates':result,'admission_sha256':sha(canonical(admission)),
            'admission_path':str(stage/'admission.json'),'baseline_unchanged':True,'containers_started':False,
            'services_changed':False,'automatic_replay_permitted':False}
        create_file(stage / 'created.json', canonical(report))
        return report


def stage_status(plan, expected_plan_sha256):
    """No retry, adoption, start, stop, completion rewrite or journal initialization."""
    host_identity()
    stage = PARENT / plan['release']['sha256']
    if not stage.exists() and not stage.is_symlink():
        return {'status':'NOT_STARTED','plan_sha256':expected_plan_sha256,'automatic_replay_permitted':False}
    private_dir(stage)
    need(read(stage/'plan.json',private=True) == canonical(plan),'STAGED_PLAN_CHANGED')
    states = {}
    for role in ('fox','converter'):
        values = {}
        for suffix in ('create-intent','create-process','create-exit','created'):
            path = stage / (role + '-' + suffix + '.json')
            if path.exists() or path.is_symlink():
                values[suffix] = parse(read(path,private=True))
        states[role] = values
    completed = stage/'created.json'
    present = completed.exists() or completed.is_symlink()
    return {'status':'RECORDED_CANDIDATES_REQUIRE_FRESH_INSPECTION' if present else 'ATTENTION_UNCONFIRMED_CREATE',
        'plan_sha256':expected_plan_sha256,'records':states,
        'completion_sha256':sha(read(completed,private=True)) if present else None,
        'automatic_replay_permitted':False}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('inspect','create','status'))
    parser.add_argument('--plan', required=True)
    parser.add_argument('--plan-sha256', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    plan = plan_document(read(Path(args.plan).absolute(), private=True), args.plan_sha256)
    if args.action == 'create':
        result = create_candidates(plan, expected_plan_sha256=args.plan_sha256, apply=args.apply)
    elif args.action == 'status':
        need(not args.apply, 'READ_ONLY_INSPECTION_REQUIRED')
        result = stage_status(plan, args.plan_sha256)
    else:
        need(not args.apply, 'READ_ONLY_INSPECTION_REQUIRED')
        load_bindings(plan); items = baseline(); validate_bound_sources(items)
        result = {'status':'PRECREATE_BASELINE_OBSERVED','plan_sha256':args.plan_sha256,
            'containers':{name:{'id':v['Id'],'image':'sha256:'+v['Image'].split(':')[-1]} for name,v in items.items()},
            'services_changed':False,'containers_started':False}
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status':'NOT_CONFIRMED','code':str(error) if type(error) is ActivationError else 'ACTIVATION_GUARD_FAILED',
                          'automatic_replay_permitted':False}), file=sys.stderr)
        sys.exit(1)
