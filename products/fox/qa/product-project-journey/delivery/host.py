"""JSN-only isolated delivery controller. No public port or live acceptance.

Run this on the approved VM after independently reviewing the plan SHA. Every
attempt is create-only; an interrupted attempt can be inspected, never rerun.
Real credentials are neither read nor mounted. One random synthetic password
travels only through the two owned child processes' stdin pipes.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import selectors
import stat
import subprocess
import sys
import time
import urllib.request

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
from contract import OWNER, MAX_EXPORT, DeliveryError, binding, canonical, parsed, sha, validate_export

SCOPE = 'fox-isolated-project-delivery-plan-v1'
PARENT = Path('/home/opc/.local/state/fox-project-delivery')
QA_IMAGE = 'sha256:e3f7b9648271a741cf320b7ad928a17e0e1591ba66835e7420864905524eb571'
QA_BASE = 'mcr.microsoft.com/playwright@sha256:06a9939e57531807f8d5fd76ce44b53165ffb7d7501d87ab10e285c20b1e971f'
VM = 'ocid1.instance.oc1.iad.anuwcljtc7x6gxic5w37qsyp3rst64betkt4uk2pdcrtmy3okspcpbv77qea'
COMPARTMENT = 'ocid1.compartment.oc1..aaaaaaaa2q5aelkapmt5mhumvxadcynq5chez2faeucy5plefhy3ylmahtba'
HASH = re.compile(r'[a-f0-9]{64}\Z')
IMAGE = re.compile(r'sha256:[a-f0-9]{64}\Z')
ATTEMPT = re.compile(r'delivery-[a-f0-9]{24}\Z')
HARNESS = ('contract.py', 'runtime.py', 'browser.mjs', 'host.py')
ORIGIN = 'http://127.0.0.1:8123'
LABEL = 'org.oracle.fox.delivery-attempt'
MAX_OUTPUT = 2_000_000
INPUT_LIMITS = {'backend': 4096, 'browser': 262144}
INPUT_TIMEOUT_SECONDS = 10.0


class HostError(RuntimeError):
    """Fixed diagnostic categories only."""


def need(ok, code):
    if not ok:
        raise HostError(code)


def public_code(error):
    value = str(error)
    return value if type(error) in (HostError, DeliveryError) and re.fullmatch(r'[A-Z0-9_]{1,128}', value) else 'ISOLATED_DELIVERY_OUTCOME_UNCONFIRMED'


def utc():
    return datetime.now(timezone.utc).isoformat()


def absolute(value):
    need(type(value) is str and 1 < len(value) <= 1024 and '\\' not in value
         and not any(ord(c) < 32 for c in value), 'CANONICAL_ABSOLUTE_PATH_REQUIRED')
    path = PurePosixPath(value)
    need(path.is_absolute() and path.as_posix() == value and '..' not in path.parts,
         'CANONICAL_ABSOLUTE_PATH_REQUIRED')
    return Path(value)


def reference(value):
    need(type(value) is dict and set(value) == {'path', 'sha256'} and type(value['sha256']) is str
         and HASH.fullmatch(value['sha256']), 'EXACT_REFERENCE_REQUIRED')
    absolute(value['path'])


def plan_document(raw, expected_sha256):
    need(type(raw) is bytes and 0 < len(raw) <= 65536 and type(expected_sha256) is str
         and HASH.fullmatch(expected_sha256) and sha(raw) == expected_sha256, 'REVIEWED_PLAN_BYTES_REQUIRED')
    value = parsed(raw)
    need(type(value) is dict and set(value) == {'schema_version', 'scope', 'attempt_id', 'input',
         'binding', 'deployment', 'harness'} and canonical(value) == raw
         and type(value['schema_version']) is int and value['schema_version'] == 1 and value['scope'] == SCOPE
         and type(value['attempt_id']) is str and ATTEMPT.fullmatch(value['attempt_id']), 'PLAN_SHAPE_INVALID')
    binding(value['binding'])
    reference(value['input']); reference(value['deployment'])
    harness = value['harness']
    need(type(harness) is dict and set(harness) == {'directory', 'files'}
         and type(harness['files']) is dict and set(harness['files']) == set(HARNESS)
         and all(type(item) is str and HASH.fullmatch(item) for item in harness['files'].values()),
         'EXACT_HARNESS_SOURCE_REQUIRED')
    absolute(harness['directory'])
    return value


def ancestors(path):
    need(path.is_absolute() and path.resolve() == path, 'LINKED_PRIVATE_PATH_FORBIDDEN')
    for part in (path, *path.parents):
        info = part.lstat()
        sticky = part != path and stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_mode & stat.S_ISVTX
        need(not stat.S_ISLNK(info.st_mode) and info.st_uid in (0, os.geteuid())
             and (not stat.S_IMODE(info.st_mode) & 0o022 or sticky), 'PRIVATE_PATH_NOT_OWNER_CONTROLLED')


def private_directory(path):
    ancestors(path)
    info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
         'PRIVATE_DIRECTORY_REQUIRED')


def read_private(path, maximum=MAX_OUTPUT):
    private_directory(path.parent)
    ancestors(path)
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
         and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= maximum, 'PRIVATE_REGULAR_FILE_REQUIRED')
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        before = os.fstat(stream.fileno())
        need((info.st_dev, info.st_ino) == (before.st_dev, before.st_ino), 'PRIVATE_INPUT_IDENTITY_CHANGED')
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    need((before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns)
         and len(raw) == before.st_size, 'PRIVATE_INPUT_CHANGED')
    return raw


def sync(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def mkdir_new(path):
    path.mkdir(mode=0o700); sync(path.parent)


def new(path, value):
    raw = value if type(value) is bytes else canonical(value)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    sync(path.parent)


def environment():
    return {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': '/home/opc', 'USER': 'opc',
            'LOGNAME': 'opc', 'XDG_RUNTIME_DIR': '/run/user/1000', 'LANG': 'C.UTF-8',
            'PYTHONDONTWRITEBYTECODE': '1'}


def command(argv, *, data=None, timeout=30, allow_missing=False):
    outcome = subprocess.run(argv, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             timeout=timeout, env=environment())
    if allow_missing and outcome.returncode == 1:
        return None
    need(outcome.returncode == 0 and len(outcome.stdout) <= MAX_OUTPUT, 'BOUNDED_HOST_COMMAND_FAILED')
    return outcome.stdout


def identity_guard():
    need(os.name == 'posix' and os.geteuid() == 1000, 'APPROVED_OPC_HOST_REQUIRED')
    request = urllib.request.Request('http://169.254.169.254/opc/v2/instance/', headers={'Authorization': 'Bearer Oracle'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=10) as response:
        need(response.status == 200, 'JSN_IDENTITY_UNCONFIRMED')
        value = parsed(response.read(100001))
    need(value.get('id') == VM and value.get('compartmentId') == COMPARTMENT
         and value.get('canonicalRegionName') == 'us-ashburn-1', 'EXACT_JSN_HOST_REQUIRED')
    need(command(['podman', 'info', '--format', '{{.Host.Security.Rootless}}']).strip() == b'true',
         'ROOTLESS_PODMAN_REQUIRED')


def deployment_document(raw, expected, expected_binding):
    need(sha(raw) == expected, 'DEPLOYMENT_BYTES_CHANGED')
    value = parsed(raw)
    need(type(value) is dict and set(value) == {'schema_version', 'scope', 'provider_configuration_sha256',
         'current_release_sha256', 'infrastructure'} and canonical(value) == raw
         and type(value['schema_version']) is int and value['schema_version'] == 1
         and value['scope'] == 'fox-hosted-admission-v1'
         and value['current_release_sha256'] == expected_binding['release_sha256']
         and type(value['provider_configuration_sha256']) is str and HASH.fullmatch(value['provider_configuration_sha256']),
         'EXACT_DEPLOYMENT_BINDING_REQUIRED')
    pins = value['infrastructure']
    need(type(pins) is dict and set(pins) == {'fox', 'forms2apex-mcp', 'oracle-applied-ai-label'}, 'DEPLOYMENT_INVENTORY_INVALID')
    for entry in pins.values():
        need(type(entry) is dict and set(entry) == {'id', 'image'} and type(entry['id']) is str
             and HASH.fullmatch(entry['id']) and type(entry['image']) is str and IMAGE.fullmatch(entry['image']),
             'EXACT_CONTAINER_PINS_REQUIRED')
    need(pins['fox']['image'] == expected_binding['fox_image'], 'DEPLOYMENT_IMAGE_DIFFERS')
    return value


def host_guard(plan, deployment):
    identity_guard()
    pins = deployment['infrastructure']
    values = parsed(command(['podman', 'inspect', *pins]))
    need(type(values) is list and len(values) == 3, 'LIVE_BASELINE_UNCONFIRMED')
    observed, mounts = {}, []
    for value in values:
        name = value['Name'].lstrip('/')
        need(name in pins and name not in observed and value['Id'] == pins[name]['id']
             and 'sha256:' + value['Image'].split(':')[-1] == pins[name]['image']
             and value['State']['Running'] is True, 'LIVE_DEPLOYMENT_CHANGED')
        observed[name] = {**pins[name], 'started_at': value['State']['StartedAt']}
        mounts.extend(Path(item['Source']) for item in value.get('Mounts', []) if item.get('Source'))
        if name == 'fox':
            pairs = [item.split('=', 1) for item in value['Config'].get('Env', [])]
            env = {pair[0]: pair[1] for pair in pairs if len(pair) == 2}
            need(env.get('FOX_VERIFIER_RELEASE_SHA256') == plan['binding']['release_sha256']
                 and env.get('FOX_CONVERSION_PROFILE') == 'native-project-v1', 'LIVE_RELEASE_SELECTION_DIFFERS')
    private_paths = [PARENT, absolute(plan['input']['path']), absolute(plan['harness']['directory'])]
    for path in private_paths:
        for mount in mounts:
            need(path != mount and mount not in path.parents and path not in mount.parents,
                 'PRIVATE_TEST_PATH_OVERLAPS_LIVE_MOUNT')
    return observed


def qa_image_guard():
    image = parsed(command(['podman', 'image', 'inspect', QA_IMAGE]))
    need(type(image) is list and len(image) == 1 and 'sha256:' + image[0]['Id'].split(':')[-1] == QA_IMAGE
         and image[0].get('Os') == 'linux' and image[0].get('Architecture') == 'amd64', 'CACHED_QA_IMAGE_CHANGED')
    official = command(['podman', 'image', 'inspect', 'mcr.microsoft.com/playwright:v1.64.0-noble',
                        '--format', '{{index .RepoDigests 0}}']).decode().strip()
    need(official == QA_BASE, 'APPROVED_BROWSER_BASE_CHANGED')


def _overlap(left, right):
    return left == right or left in right.parents or right in left.parents


def load_inputs(plan_raw, plan_sha256):
    plan = plan_document(plan_raw, plan_sha256)
    deployment = deployment_document(read_private(absolute(plan['deployment']['path'])),
                                     plan['deployment']['sha256'], plan['binding'])
    raw = read_private(absolute(plan['input']['path']), MAX_EXPORT)
    validate_export(raw, expected_sha256=plan['input']['sha256'], expected_binding=plan['binding'])
    folder = absolute(plan['harness']['directory'])
    private_directory(folder)
    source = {name: read_private(folder / name) for name in HARNESS}
    need({name: sha(value) for name, value in source.items()} == plan['harness']['files'], 'HARNESS_SOURCE_CHANGED')
    need(source['host.py'] == Path(__file__).read_bytes(), 'EXECUTED_HOST_SOURCE_DIFFERS')
    target = PARENT / plan['attempt_id']
    need(not any(_overlap(target, path) for path in (folder, absolute(plan['input']['path']),
                                                   absolute(plan['deployment']['path']))), 'TEST_OUTPUT_OVERLAPS_INPUT')
    return plan, deployment, raw, source


def container_name(attempt, role):
    need(ATTEMPT.fullmatch(attempt) and role in ('backend', 'browser'), 'ISOLATED_CONTAINER_NAME_INVALID')
    return 'fox-' + attempt + '-' + role


def runtime_args(plan, action):
    need(action in ('serve', 'audit'), 'RUNTIME_ACTION_INVALID')
    result = ['-B', '/harness/runtime.py', action, '--input', '/fixture/input.json',
              '--input-sha256', plan['input']['sha256'], '--image', plan['binding']['fox_image'],
              '--release', plan['binding']['release_sha256'], '--data', '/data']
    return result + (['--output', '/proof/runtime'] if action == 'serve' else [])


def container_args(plan, target, role, backend_id=None):
    name = container_name(plan['attempt_id'], role)
    common = ['podman', 'run', '--pull=never', '--name', name, '--label', LABEL + '=' + plan['attempt_id'],
        '--cidfile', str(target / (role + '.cid')),
        '--read-only', '--cap-drop=all', '--security-opt=no-new-privileges', '--security-opt=label=disable',
        '--user', '1000:1000', '--ipc=private', '--shm-size=256m', '--cpus=1', '--pids-limit=256',
        '--tmpfs', '/tmp:rw,nosuid,nodev,size=256m,mode=1777', '-i',
        '--volume', str(target / 'harness') + ':/harness:ro',
        '--volume', str(target / 'proof') + ':/proof:rw']
    if role == 'backend':
        return common + ['--network=none', '--userns=keep-id:uid=1000,gid=1000', '--memory=512m',
            '--volume', str(target / 'input') + ':/fixture:ro', '--volume', str(target / 'data') + ':/data:rw',
            '--entrypoint', 'python', plan['binding']['fox_image'], *runtime_args(plan, 'serve')]
    need(type(backend_id) is str and HASH.fullmatch(backend_id), 'EXACT_BACKEND_ID_REQUIRED')
    return common + ['--network=container:' + backend_id, '--userns=container:' + backend_id, '--memory=1536m',
        '--entrypoint', 'node', QA_IMAGE, '/harness/browser.mjs', '--apply']


def container_id(target, role, *, required=True):
    need(role in ('backend', 'browser'), 'CONTAINER_ROLE_INVALID')
    path = target / (role + '.cid')
    if not path.exists() and not path.is_symlink() and not required:
        return None
    value = read_private(path, 128).decode().strip()
    need(HASH.fullmatch(value), 'ORIGINAL_CONTAINER_ID_UNCONFIRMED')
    return value


def _inspect_owned(plan, target, role, expected_id=None, backend_id=None):
    values = parsed(command(['podman', 'inspect', expected_id or container_name(plan['attempt_id'], role)]))
    need(type(values) is list and len(values) == 1, 'OWNED_CONTAINER_UNCONFIRMED')
    item = values[0]
    image = plan['binding']['fox_image'] if role == 'backend' else QA_IMAGE
    need(item['Name'].lstrip('/') == container_name(plan['attempt_id'], role)
         and (expected_id is None or item['Id'] == expected_id) and HASH.fullmatch(item['Id'])
         and 'sha256:' + item['Image'].split(':')[-1] == image
         and item['Config'].get('Labels', {}).get(LABEL) == plan['attempt_id']
         and item['Config'].get('User') == '1000:1000', 'OWNED_CONTAINER_IDENTITY_CHANGED')
    expected_mounts = {'/harness': (str(target / 'harness'), False), '/proof': (str(target / 'proof'), True)}
    if role == 'backend':
        expected_mounts.update({'/fixture': (str(target / 'input'), False), '/data': (str(target / 'data'), True)})
    observed_mounts = item.get('Mounts', [])
    need(type(observed_mounts) is list and all(entry.get('Type') == 'bind' or
         entry.get('Type') == 'tmpfs' and entry.get('Destination') in ('/tmp', '/dev/shm') for entry in observed_mounts),
         'UNEXPECTED_ISOLATED_MOUNT_TYPE')
    mounts = {entry['Destination']: (entry['Source'], entry['RW']) for entry in observed_mounts
              if entry.get('Type') == 'bind'}
    need(mounts == expected_mounts and len(mounts) == len([entry for entry in observed_mounts if entry.get('Type') == 'bind']),
         'ISOLATED_MOUNTS_DIFFER')
    host = item['HostConfig']
    ports = item['NetworkSettings'].get('Ports') or {}
    need(type(ports) is dict and not any(ports.values())
         and host.get('ReadonlyRootfs') is True and host.get('Privileged') is False and not host.get('PortBindings'),
         'ISOLATED_ROOT_OR_PORTS_DIFFER')
    expected_network = 'none' if role == 'backend' else 'container:' + str(backend_id)
    need(host.get('NetworkMode') == expected_network, 'ISOLATED_NETWORK_DIFFERS')
    return {'id': item['Id'], 'image': image, 'name': item['Name'].lstrip('/'), 'running': item['State']['Running'],
            'status': item['State']['Status'], 'exit_code': item['State']['ExitCode'],
            'started_at': item['State']['StartedAt'], 'finished_at': item['State']['FinishedAt']}


HEALTH = "import json,urllib.request; o=urllib.request.build_opener(urllib.request.ProxyHandler({})); v=json.load(o.open('http://127.0.0.1:8123/api/health',timeout=2)); assert v['product']=='FOX' and v['worker']['enabled'] is False; print('ISOLATED_HEALTH_OK')"


def wait_health(process, plan, target, baseline, deployment, *, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        need(process.poll() is None, 'ISOLATED_SERVER_EXITED_BEFORE_HEALTH')
        try:
            cid = container_id(target, 'backend', required=False)
            if cid is None:
                time.sleep(0.2)
                continue
            owned = _inspect_owned(plan, target, 'backend', cid)
            if owned['running']:
                value = command(['podman', 'exec', owned['id'], 'python', '-I', '-B', '-c', HEALTH], timeout=5)
                if value.strip() == b'ISOLATED_HEALTH_OK':
                    need(host_guard(plan, deployment) == baseline, 'LIVE_BASELINE_CHANGED_DURING_START')
                    return owned
        except HostError as error:
            if str(error) not in ('BOUNDED_HOST_COMMAND_FAILED', 'OWNED_CONTAINER_UNCONFIRMED'):
                raise
            # Only a bounded not-yet-ready observation; never a new launch.
        time.sleep(0.2)
    raise HostError('ISOLATED_SERVER_HEALTH_UNCONFIRMED')


def process_identity(pid):
    """Observe an exact Linux process without reading its argv or environment."""
    need(type(pid) is int and pid > 1, 'NATIVE_PID_INVALID')
    root = Path('/proc') / str(pid)
    try:
        first = (root / 'stat').read_text()
        fields = first.rpartition(') ')[2].split()
        need(len(fields) >= 20 and fields[19].isdigit(), 'NATIVE_PROCESS_IDENTITY_UNCONFIRMED')
        executable = str((root / 'exe').resolve(strict=True))
        second = (root / 'stat').read_text().rpartition(') ')[2].split()
        need(len(second) >= 20 and second[19] == fields[19], 'NATIVE_PROCESS_CHANGED_DURING_READ')
        boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        need(re.fullmatch(r'[a-f0-9-]{36}', boot), 'HOST_BOOT_IDENTITY_INVALID')
        return {'pid': pid, 'start_ticks': fields[19], 'boot_id': boot, 'executable': executable}
    except FileNotFoundError:
        return None


def bounded_stdin(process, payload, *, maximum, timeout=INPUT_TIMEOUT_SECONDS, close_after=False):
    """Write one bounded packet to a fresh owned POSIX pipe, without buffering.

    Only this helper writes the Popen stdin. The original descriptor mode is
    restored on success or failure. Failed/partial writes leave stdin open so
    the caller stops the exact child before closing it; they never signal EOF
    to a browser that might otherwise process an incomplete packet.
    """
    need(os.name == 'posix' and type(payload) is bytes and type(maximum) is int
         and 0 < len(payload) <= maximum <= INPUT_LIMITS['browser']
         and type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 30
         and type(close_after) is bool, 'INPUT_PACKET_BOUND_INVALID')
    stream = process.stdin
    need(type(stream) is io.FileIO and not stream.closed, 'INPUT_DELIVERY_UNCONFIRMED')
    deadline = time.monotonic() + timeout
    fd = None
    original_blocking = None
    identity = None
    complete = False
    try:
        fd = stream.fileno()
        initial = os.fstat(fd)
        need(stat.S_ISFIFO(initial.st_mode), 'INPUT_DELIVERY_UNCONFIRMED')
        identity = (initial.st_dev, initial.st_ino)
        original_blocking = os.get_blocking(fd)
        os.set_blocking(fd, False)
        view = memoryview(payload)
        sent = 0
        with selectors.DefaultSelector() as selector:
            selector.register(fd, selectors.EVENT_WRITE)
            while sent < len(view):
                remaining = deadline - time.monotonic()
                need(remaining > 0 and process.poll() is None, 'INPUT_DELIVERY_UNCONFIRMED')
                if not selector.select(remaining):
                    continue
                need(time.monotonic() < deadline, 'INPUT_DELIVERY_UNCONFIRMED')
                try:
                    written = os.write(fd, view[sent:sent + 65536])
                except (BlockingIOError, InterruptedError):
                    continue
                need(written > 0, 'INPUT_DELIVERY_UNCONFIRMED')
                sent += written
            need(time.monotonic() < deadline, 'INPUT_DELIVERY_UNCONFIRMED')
        complete = True
    except (OSError, ValueError, TypeError):
        raise HostError('INPUT_DELIVERY_UNCONFIRMED') from None
    finally:
        if fd is not None and original_blocking is not None:
            try:
                current = os.fstat(fd)
                need(stat.S_ISFIFO(current.st_mode) and (current.st_dev, current.st_ino) == identity,
                     'INPUT_DELIVERY_UNCONFIRMED')
                os.set_blocking(fd, original_blocking)
            except (OSError, ValueError):
                raise HostError('INPUT_DELIVERY_UNCONFIRMED') from None
    if complete and close_after:
        # Popen uses bufsize=0, so FileIO.close has no pending buffer to flush.
        try:
            stream.close()
        except OSError:
            raise HostError('INPUT_DELIVERY_UNCONFIRMED') from None


def launch(plan, deployment, baseline, target, role, data, *, backend_id=None, processes=None):
    need(role in INPUT_LIMITS, 'ISOLATED_CONTAINER_ROLE_INVALID')
    payload = canonical(data)
    need(0 < len(payload) <= INPUT_LIMITS[role], 'INPUT_PACKET_BOUND_EXCEEDED')
    need(host_guard(plan, deployment) == baseline, 'LIVE_BASELINE_CHANGED_BEFORE_LAUNCH')
    name = container_name(plan['attempt_id'], role)
    need(command(['podman', 'container', 'exists', name], allow_missing=True) is None, 'PRIOR_CONTAINER_PRESERVED_NO_REPLAY')
    argv = container_args(plan, target, role, backend_id)
    new(target / (role + '-intent.json'), {'scope': 'fox-isolated-delivery-launch-v1', 'role': role,
        'attempt_id': plan['attempt_id'], 'argv': argv, 'started_at_utc': utc(), 'automatic_replay_permitted': False})
    stdout = os.fdopen(os.open(target / (role + '.stdout'), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb')
    stderr = os.fdopen(os.open(target / (role + '.stderr'), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb')
    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=stdout, stderr=stderr,
                                   env=environment(), umask=0o077, bufsize=0)
        # Retain the original handle even if later journaling or stdin fails.
        # The caller can stop only its exact newly-created labelled container.
        if processes is not None:
            processes[role] = process
        native = process_identity(process.pid)
        new(target / (role + '-process.json'), {'pid': process.pid, 'role': role, 'started_at_utc': utc(),
            'native_identity': native, 'observed_returncode': process.poll(), 'automatic_replay_permitted': False})
        try:
            bounded_stdin(process, payload, maximum=INPUT_LIMITS[role],
                          close_after=role == 'browser')
        except HostError:
            new(target / (role + '-stdin-unconfirmed.json'), {'status': 'INPUT_DELIVERY_UNCONFIRMED',
                                                           'automatic_replay_permitted': False})
            raise HostError('INPUT_DELIVERY_UNCONFIRMED') from None
        # Keep the backend's owned stdin open for the attached lifetime. Browser
        # reads its bounded packet until EOF and can then execute its tests.
        return process
    finally:
        stdout.close(); stderr.close()


def stop_owned(plan, target, role, identity, *, backend_id=None):
    identity_guard()
    observed = _inspect_owned(plan, target, role, identity['id'], backend_id)
    need(observed['started_at'] == identity['started_at'], 'OWNED_CONTAINER_RESTARTED')
    if observed['running']:
        new(target / (role + '-stop-intent.json'), {'id': observed['id'], 'started_at': observed['started_at'],
                                                'requested_at_utc': utc(), 'automatic_replay_permitted': False})
        command(['podman', 'stop', '--time', '10', observed['id']], timeout=25)
    after = _inspect_owned(plan, target, role, identity['id'], backend_id)
    need(after['running'] is False, 'OWNED_CONTAINER_STOP_UNCONFIRMED')
    new(target / (role + '-stopped.json'), after)
    return after


def check_browser_report(report, fixture, expected):
    fields = ('project_id', 'project_name', 'run_id', 'source_hash', 'package_sha256',
              'package_bytes', 'proof_sha256', 'form_count', 'notes', 'ui')
    normalized = {name: fixture[name] for name in fields}
    need(type(report) is dict and report.get('schema_version') == 1
         and report.get('scope') == 'fox-isolated-project-delivery-browser-v1'
         and report.get('origin') == ORIGIN and report.get('synthetic_owner') == OWNER
         and report.get('fixture_sha256') == sha(canonical(normalized)[:-1])
         and report.get('job_id') == expected['job_id']
         and report.get('package_sha256') == expected['package_sha256']
         and report.get('retained_proof_sha256') == expected['proof_sha256'], 'BROWSER_RESULT_BINDING_DIFFERS')
    need(report.get('passed') is True and report.get('browser_closed') is True
         and type(report.get('blocked_requests')) is int and report['blocked_requests'] == 0
         and all(report.get(name) is False for name in ('live_acceptance_recorded', 'conversion_invoked',
             'model_invoked', 'database_connection_opened', 'raw_retained_proof_verified_by_browser',
             'personal_profile_used', 'screenshots_or_traces_saved')), 'BROWSER_RESULT_NOT_PASSED')
    requests = report.get('requests')
    need(type(requests) is dict and set(requests) == {'login', 'acceptance_attempts', 'allowed_gets'}
         and type(requests['login']) is int and requests['login'] == 1
         and type(requests['acceptance_attempts']) is int and requests['acceptance_attempts'] == 3
         and type(requests['allowed_gets']) is int and 1 <= requests['allowed_gets'] <= 10000,
         'BROWSER_ACTION_INVENTORY_DIFFERS')
    before, after = (report.get('technical_evidence_' + part + '_sha256') for part in ('before', 'after'))
    need(type(before) is str and HASH.fullmatch(before) and before == after, 'BROWSER_TECHNICAL_EVIDENCE_CHANGED')
    ui = report.get('served_ui')
    need(type(ui) is dict and ui.get('index.html') == fixture['ui']['index.html']
         and any(name.endswith('.js') for name in ui) and any(name.endswith('.css') for name in ui)
         and all(fixture['ui'].get(name) == value for name, value in ui.items()), 'BROWSER_SERVED_UI_DIFFERS')
    names = {'exact_built_ui_and_normal_synthetic_login', 'incomplete_review_does_not_unlock_package',
             'normal_ui_records_only_synthetic_review', 'normal_ui_download_returns_exact_genuine_zip',
             'duplicate_review_blocked_and_technical_proof_unchanged'}
    tests = report.get('tests')
    need(type(tests) is list and len(tests) == len(names)
         and all(type(item) is dict and set(item) == {'name', 'status'} and item['status'] == 'PASSED' for item in tests)
         and {item['name'] for item in tests} == names, 'BROWSER_MILESTONES_INCOMPLETE')


def run(plan_raw, plan_sha256, *, apply=False):
    need(apply is True, 'EXPLICIT_ISOLATED_TEST_AUTHORITY_REQUIRED')
    plan, deployment, raw, source = load_inputs(plan_raw, plan_sha256)
    baseline = host_guard(plan, deployment); qa_image_guard()
    target = PARENT / plan['attempt_id']
    need(not target.exists() and not target.is_symlink(), 'EXISTING_ATTEMPT_MUST_BE_INSPECTED_NOT_REPLAYED')
    ancestors(PARENT.parent)
    if not PARENT.exists():
        mkdir_new(PARENT)
    private_directory(PARENT); mkdir_new(target)
    new(target / 'plan.json', plan_raw)
    new(target / 'attempt-intent.json', {'plan_sha256': plan_sha256, 'baseline': baseline,
        'started_at_utc': utc(), 'automatic_replay_permitted': False, 'live_acceptance_recorded': False})
    for name in ('harness', 'input', 'data', 'proof'):
        mkdir_new(target / name)
    for name in ('runtime', 'browser'):
        mkdir_new(target / 'proof' / name)
    for name, content in source.items():
        new(target / 'harness' / name, content)
    new(target / 'input/input.json', raw)
    need(host_guard(plan, deployment) == baseline, 'LIVE_BASELINE_CHANGED_DURING_PREPARATION')
    credentials = {'username': OWNER, 'password': secrets.token_urlsafe(48)}
    backend = browser = None
    processes = {}
    identities = {}
    status, code, cleanup = 'NOT_CONFIRMED', None, {}
    try:
        backend = launch(plan, deployment, baseline, target, 'backend', credentials, processes=processes)
        identities['backend'] = wait_health(backend, plan, target, baseline, deployment)
        new(target / 'backend-container.json', identities['backend'])
        fixture = parsed(read_private(target / 'proof/runtime/fixture.json'))
        need(fixture['owner'] == OWNER and fixture['input_sha256'] == plan['input']['sha256']
             and fixture['fox_image'] == plan['binding']['fox_image']
             and fixture['release_sha256'] == plan['binding']['release_sha256']
             and fixture['worker_enabled'] is False and fixture['integration_configured'] is False,
             'ISOLATED_RUNTIME_FIXTURE_DIFFERS')
        packet = {'origin': ORIGIN, **credentials, 'fixture': fixture, 'output_directory': '/proof/browser'}
        browser = launch(plan, deployment, baseline, target, 'browser', packet,
                         backend_id=identities['backend']['id'], processes=processes)
        # The original process handle is the only source of an exit receipt.
        exit_code = browser.wait(timeout=240)
        new(target / 'browser-exit.json', {'exit_code': exit_code, 'observed_at_utc': utc()})
        identities['browser'] = _inspect_owned(plan, target, 'browser', container_id(target, 'browser'),
                                               backend_id=identities['backend']['id'])
        new(target / 'browser-container.json', identities['browser'])
        need(exit_code == 0 and identities['browser']['running'] is False, 'BROWSER_DID_NOT_COMPLETE_SUCCESSFULLY')
        report_raw = read_private(target / 'proof/browser/browser-result.json')
        report = parsed(report_raw)
        check_browser_report(report, fixture, plan['binding'])
        package = read_private(target / 'proof/browser/accepted-apex.zip', 8_000_000)
        need(sha(package) == plan['binding']['package_sha256'] and report['download']['sha256'] == sha(package)
             and report['download']['bytes'] == len(package), 'EXACT_DOWNLOADED_PACKAGE_CHANGED')
        audit_raw = command(['podman', 'exec', identities['backend']['id'], 'python', *runtime_args(plan, 'audit')], timeout=60)
        audit = parsed(audit_raw)
        need(audit.get('status') == 'ISOLATED_ACCEPTANCE_VERIFIED' and audit.get('producer_bytes_unchanged') is True
             and audit.get('technical_proof_unchanged') is True and audit.get('live_acceptance_recorded') is False
             and audit.get('oracle_database_contacted') is False and audit.get('model_invoked') is False
             and audit.get('isolated_sqlite_used') is True
             and audit.get('synthetic_acceptance_count') == 1
             and audit.get('package_sha256') == plan['binding']['package_sha256']
             and audit.get('proof_sha256') == plan['binding']['proof_sha256'], 'RETAINED_RAW_PROOF_AUDIT_FAILED')
        new(target / 'final-audit.json', audit_raw)
        need(host_guard(plan, deployment) == baseline, 'LIVE_BASELINE_CHANGED_DURING_TEST')
        status = 'ISOLATED_DELIVERY_PASSED'
    except Exception as error:
        code = public_code(error)
    finally:
        credentials.clear()
        for role, process in (('browser', processes.get('browser')), ('backend', processes.get('backend'))):
            if process is None:
                continue
            try:
                if role not in identities:
                    identities[role] = _inspect_owned(plan, target, role, container_id(target, role),
                        backend_id=identities.get('backend', {}).get('id'))
                    new(target / (role + '-container.json'), identities[role])
                cleanup[role] = stop_owned(plan, target, role, identities[role],
                                          backend_id=identities.get('backend', {}).get('id'))
                if process.stdin and not process.stdin.closed:
                    process.stdin.close()
                process.wait(timeout=15)
            except Exception:
                cleanup[role] = {'status': 'UNCONFIRMED_INSPECT_SAME_ATTEMPT'}
                status = 'NOT_CONFIRMED'; code = 'OWNED_CLEANUP_UNCONFIRMED'
        try:
            need(host_guard(plan, deployment) == baseline, 'LIVE_BASELINE_CHANGED')
        except Exception:
            status = 'NOT_CONFIRMED'; code = 'LIVE_BASELINE_UNCONFIRMED'
    result = {'schema_version': 1, 'scope': 'fox-isolated-project-delivery-host-v1', 'status': status,
        'code': code, 'attempt_id': plan['attempt_id'], 'plan_sha256': plan_sha256,
        'input_sha256': plan['input']['sha256'], 'binding': plan['binding'], 'cleanup': cleanup,
        'live_acceptance_recorded': False, 'new_public_port': False, 'oracle_database_contacted': False,
        'model_invoked': False, 'isolated_sqlite_used': True,
        'automatic_replay_permitted': False, 'completed_at_utc': utc()}
    new(target / 'result.json', result)
    return result


def inspect(plan_raw, plan_sha256):
    plan = plan_document(plan_raw, plan_sha256)
    identity_guard()
    target = PARENT / plan['attempt_id']; private_directory(target)
    need(read_private(target / 'plan.json', 65536) == plan_raw, 'ATTEMPT_PLAN_CHANGED')
    containers, native = {}, {}
    for role in ('backend', 'browser'):
        reference = target / (role + '-container.json')
        backend = containers.get('backend', {}).get('id') if role == 'browser' else None
        if reference.exists():
            saved = parsed(read_private(reference))
            containers[role] = _inspect_owned(plan, target, role, saved['id'], backend)
        else:
            cid = container_id(target, role, required=False)
            if cid is not None and (role == 'backend' or backend is not None):
                # Read-only discovery is evidence, not adoption or replay authority.
                containers[role] = {**_inspect_owned(plan, target, role, cid, backend_id=backend),
                                    'identity_receipt_missing': True, 'read_only_discovery': True}
            else:
                containers[role] = {'status': 'NO_CONFIRMED_CONTAINER_ID', 'read_only': True}
        process_path = target / (role + '-process.json')
        if process_path.exists():
            saved_process = parsed(read_private(process_path))
            actual = process_identity(saved_process['pid'])
            prior = saved_process.get('native_identity')
            native[role] = {'status': 'ORIGINAL_PROCESS_ABSENT' if actual is None else
                'ORIGINAL_PROCESS_LIVE' if prior is not None and actual == prior else 'PID_IDENTITY_DIFFERS_OR_UNCONFIRMED',
                'saved': prior, 'observed': actual}
    terminal = parsed(read_private(target / 'result.json')) if (target / 'result.json').exists() else None
    return {'scope': 'fox-isolated-project-delivery-inspection-v1', 'read_only': True,
            'attempt_id': plan['attempt_id'], 'containers': containers, 'native_processes': native, 'terminal': terminal,
            'automatic_replay_permitted': False}


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('run', 'inspect'))
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--plan-sha256', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    raw = read_private(args.plan.absolute(), 65536)
    if args.action == 'inspect':
        need(not args.apply, 'INSPECT_IS_READ_ONLY')
        value = inspect(raw, args.plan_sha256)
    else:
        value = run(raw, args.plan_sha256, apply=args.apply)
    print(json.dumps(value, sort_keys=True))
    return 0 if value.get('read_only') or value.get('status') == 'ISOLATED_DELIVERY_PASSED' else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'status': 'NOT_CONFIRMED', 'code': public_code(error), 'automatic_replay_permitted': False}), file=sys.stderr)
        raise SystemExit(1)
