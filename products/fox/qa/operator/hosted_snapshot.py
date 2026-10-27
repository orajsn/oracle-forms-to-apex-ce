"""Create-only same-host FOX backup and isolated restore, never a deployment.

The existing pure snapshot engine owns archive/SQLite verification. This adapter
owns exact JSN/container/service guards, explicit protected-source assembly and
the actual caller-held operator lease. It exposes no stop/start, live restore,
secret lookup, SQL, OCI mutation or automatic replay operation.
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import subprocess
import sys
import time
import types
import urllib.request

SCOPE = 'fox-hosted-snapshot-plan-v1'
G_RELEASE = 'acc3bf901d6f221cc5b887afe88a5cd53b9b4a8153e820b1f078b10d679004ba'
TARGET = {'instance_id': 'ocid1.instance.oc1.iad.anuwcljtc7x6gxic5w37qsyp3rst64betkt4uk2pdcrtmy3okspcpbv77qea',
          'compartment_id': 'ocid1.compartment.oc1..aaaaaaaa2q5aelkapmt5mhumvxadcynq5chez2faeucy5plefhy3ylmahtba',
          'region': 'us-ashburn-1'}
SHA = re.compile(r'[a-f0-9]{64}\Z')
SERVICE_NAMES = {'fox': 'fox.service', 'converter': 'forms2apex-mcp.service',
                 'tls': 'fox-https.service', 'verifier': 'fox-product-verifier.service'}
CONTAINER_NAMES = {'fox': 'fox', 'converter': 'forms2apex-mcp', 'tls': 'fox-https'}
PROTECTED_REQUIRED = {'opaf-client', 'sqlcl-connections', 'wallet', 'converter-config',
                      'fox-unit', 'converter-unit', 'tls-unit', 'baseline-fox-profile',
                      'baseline-target-profile', 'release-metadata', 'opaf-definitions'}
PROTECTED_OPTIONAL = {'admin-secret', 'verifier-unit', 'operator-installation', 'operator-configuration', 'retirement-archive'}
HOSTED_REQUIRED = {'admin-secret', 'verifier-unit', 'operator-installation', 'operator-configuration'}
DIRECTORY_SOURCES = {'opaf-client', 'sqlcl-connections', 'wallet', 'converter-config',
                     'release-metadata', 'operator-configuration', 'retirement-archive'}
_KEY = object()


class SnapshotOperationError(RuntimeError):
    """Closed diagnostic categories only; never raw host or secret data."""


def need(ok, code):
    if not ok:
        raise SnapshotOperationError(code)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                       allow_nan=False) + '\n').encode()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def parse(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'SNAPSHOT_DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    need(type(raw) is bytes and 0 < len(raw) <= 2_000_000, 'SNAPSHOT_DOCUMENT_BOUND')
    value = json.loads(raw, object_pairs_hook=pairs)
    need(type(value) is dict and canonical(value) == raw, 'SNAPSHOT_CANONICAL_DOCUMENT_REQUIRED')
    return value


def path(value):
    need(type(value) is str and len(value) <= 1024 and '\\' not in value
         and not any(ord(c) < 32 for c in value), 'SNAPSHOT_PATH_INVALID')
    p = PurePosixPath(value)
    need(p.is_absolute() and str(p) == value and '..' not in p.parts and len(p.parts) >= 4,
         'SNAPSHOT_PATH_INVALID')
    return Path(value)


def overlap(a, b):
    a, b = PurePosixPath(a), PurePosixPath(b)
    return a == b or a in b.parents or b in a.parents


def configuration_document(raw, expected_sha256):
    need(type(raw) is bytes and type(expected_sha256) is str and SHA.fullmatch(expected_sha256)
         and sha(raw) == expected_sha256, 'SNAPSHOT_PLAN_HASH_CHANGED')
    value = parse(raw)
    need(set(value) == {'schema_version', 'scope', 'mode', 'target', 'operator_release_sha256',
         'provider_configuration_sha256', 'authority_source_sha256', 'python', 'runtime',
         'role_paths', 'protected_sources', 'output_root', 'source_sha256'}
         and type(value['schema_version']) is int and value['schema_version'] == 1
         and value['scope'] == SCOPE and value['target'] == TARGET
         and value['mode'] in ('pre-hosted-g', 'hosted'), 'SNAPSHOT_PLAN_FIELDS_INVALID')
    need(type(value['operator_release_sha256']) is str and SHA.fullmatch(value['operator_release_sha256']),
         'SNAPSHOT_RELEASE_INVALID')
    if value['mode'] == 'pre-hosted-g':
        need(value['operator_release_sha256'] == G_RELEASE and value['provider_configuration_sha256'] is None
             and type(value['authority_source_sha256']) is str and SHA.fullmatch(value['authority_source_sha256']),
             'SNAPSHOT_BASELINE_AUTHORITY_INVALID')
    else:
        need(type(value['provider_configuration_sha256']) is str and SHA.fullmatch(value['provider_configuration_sha256'])
             and value['authority_source_sha256'] is None, 'SNAPSHOT_HOSTED_AUTHORITY_INVALID')
    python = value['python']
    need(type(python) is dict and set(python) == {'path', 'sha256'}
         and type(python['sha256']) is str
         and SHA.fullmatch(python['sha256']), 'SNAPSHOT_PYTHON_INVALID')
    path(python['path'])
    need(type(value['runtime']) is dict and set(value['runtime']) == set(CONTAINER_NAMES), 'SNAPSHOT_RUNTIME_INVALID')
    for item in value['runtime'].values():
        need(type(item) is dict and set(item) == {'id', 'image'}
             and type(item['id']) is str and SHA.fullmatch(item['id'])
             and type(item['image']) is str and re.fullmatch('sha256:[a-f0-9]{64}', item['image']),
             'SNAPSHOT_RUNTIME_INVALID')
    need(len({item['id'] for item in value['runtime'].values()}) == 3, 'SNAPSHOT_RUNTIME_COLLISION')
    roles = value['role_paths']
    required = {'fox-data', 'converter-jobs'} | ({'operator-state'} if value['mode'] == 'hosted' else set())
    need(type(roles) is dict and set(roles) == required, 'SNAPSHOT_ROLE_COVERAGE_REQUIRED')
    roots = [path(item) for item in roles.values()]
    protected = value['protected_sources']
    need(type(protected) is dict and PROTECTED_REQUIRED <= set(protected)
         and set(protected) <= PROTECTED_REQUIRED | PROTECTED_OPTIONAL, 'SNAPSHOT_PROTECTED_COVERAGE_REQUIRED')
    if value['mode'] == 'hosted':
        need(HOSTED_REQUIRED <= set(protected), 'SNAPSHOT_HOSTED_PROTECTED_COVERAGE_REQUIRED')
    else:
        need('admin-secret' not in protected and 'verifier-unit' not in protected
             and 'operator-installation' not in protected, 'SNAPSHOT_UNINSTALLED_HOSTED_AUTHORITY_REQUIRED')
    for label, item in protected.items():
        need(type(item) is dict and set(item) == {'path', 'kind', 'sha256'}
             and item['kind'] in ('file', 'directory')
             and (item['sha256'] is None or item['kind'] == 'file'
                  and type(item['sha256']) is str and SHA.fullmatch(item['sha256'])),
             'SNAPSHOT_PROTECTED_REFERENCE_INVALID')
        need(item['kind'] == ('directory' if label in DIRECTORY_SOURCES else 'file'),
             'SNAPSHOT_PROTECTED_KIND_INVALID')
        path(item['path'])
    if value['mode'] == 'hosted':
        need(protected['operator-installation']['sha256'] is not None, 'SNAPSHOT_PINNED_INSTALLATION_REQUIRED')
    output = path(value['output_root'])
    need(all(not overlap(a, b) for index, a in enumerate(roots) for b in roots[index + 1:])
         and all(not overlap(output, item) for item in roots)
         and all(not overlap(output, item['path']) for item in protected.values()), 'SNAPSHOT_ROOTS_OVERLAP')
    need(type(value['source_sha256']) is dict and set(value['source_sha256']) == {'snapshot.py', 'hosted_snapshot.py'}
         and all(type(v) is str and SHA.fullmatch(v) for v in value['source_sha256'].values()),
         'SNAPSHOT_SOURCE_BINDING_REQUIRED')
    return value


class CaptureAuthority:
    __slots__ = ('_key', 'config', 'raw', 'digest', 'owner', 'release_raw', 'pid', 'issued')
    def __init__(self, key, raw, digest, owner, release_raw):
        need(key is _KEY, 'SNAPSHOT_TYPED_AUTHORITY_REQUIRED')
        self._key, self.raw, self.digest = key, raw, digest
        self.config = configuration_document(raw, digest)
        self.owner, self.release_raw = owner, release_raw
        self.pid, self.issued = os.getpid(), time.monotonic()

    def require_active(self):
        need(type(self) is CaptureAuthority and self._key is _KEY and self.pid == os.getpid()
             and 0 <= time.monotonic() - self.issued <= 1800
             and configuration_document(self.raw, self.digest) == self.config,
             'SNAPSHOT_AUTHORITY_EXPIRED_OR_CHANGED')
        if self.config['mode'] == 'pre-hosted-g':
            from qa.operator.preactivation_retirement import PreActivationRetirementContext
            need(type(self.owner) is PreActivationRetirementContext, 'SNAPSHOT_REAL_BASELINE_CONTEXT_REQUIRED')
            self.owner.require_active()
            need(self.owner.release == G_RELEASE and self.owner.current_raw == self.release_raw,
                 'SNAPSHOT_BASELINE_RELEASE_CHANGED')
        else:
            from qa.operator import runtime_provider
            from qa.operator.failed_verification import HeldOperatorLock
            provider = runtime_provider.selected_hosted()
            need(type(self.owner) is HeldOperatorLock and provider is not None
                 and provider.sha256 == self.config['provider_configuration_sha256'], 'SNAPSHOT_REAL_HOSTED_LEASE_REQUIRED')
            self.owner.require_active(self.config['operator_release_sha256'],
                provider.path('journal') / self.config['operator_release_sha256'][:16])
        return self.config


def baseline_authority(context, configuration_raw, *, expected_sha256):
    """Call while G still runs and C/F/G leases are held; then drain externally."""
    from qa.operator.preactivation_retirement import PreActivationRetirementContext
    config = configuration_document(configuration_raw, expected_sha256)
    need(config['mode'] == 'pre-hosted-g' and type(context) is PreActivationRetirementContext,
         'SNAPSHOT_REAL_BASELINE_CONTEXT_REQUIRED')
    context.require_active()
    for role, original in (('fox', 'fox'), ('converter', 'forms2apex-mcp')):
        need(config['runtime'][role] == context.configuration['infrastructure'][original],
             'SNAPSHOT_BASELINE_CONTAINER_CHANGED')
    sources = context.source_files()
    need(sha(sources['preactivation/preactivation_retirement.py']) == config['authority_source_sha256'],
         'SNAPSHOT_BASELINE_SOURCE_CHANGED')
    result = context.history_read_under_lock(for_startup=False)
    need(result['status'] == 'PREACTIVATION_HISTORY_READY' and result['release_sha256'] == G_RELEASE,
         'SNAPSHOT_BASELINE_RETIREMENT_NOT_READY')
    return CaptureAuthority(_KEY, configuration_raw, expected_sha256, context, context.current_raw)


def _covered(filename, config):
    filename = PurePosixPath(filename)
    return any(filename == PurePosixPath(item['path']) or item['kind'] == 'directory'
               and PurePosixPath(item['path']) in filename.parents
               for item in config['protected_sources'].values()) or any(
                   filename == PurePosixPath(root) or PurePosixPath(root) in filename.parents
                   for root in config['role_paths'].values())


def hosted_authority(lease, configuration_raw, *, expected_sha256, release_raw):
    """Requires a genuine current OS lease; does not initialize or recover one."""
    from qa.operator import runtime_provider, product_queue_transport, hosted_service, retirement_handoff
    from qa.operator.failed_verification import HeldOperatorLock
    config = configuration_document(configuration_raw, expected_sha256)
    provider = runtime_provider.selected_hosted()
    manifest = product_queue_transport.validate_release(parse(release_raw))
    need(config['mode'] == 'hosted' and provider is not None
         and provider.configuration['schema_version'] == 2 and provider.sha256 == config['provider_configuration_sha256']
         and sha(release_raw) == config['operator_release_sha256'] and manifest['schema_version'] == 3
         and manifest['hosted_runtime_configuration_sha256'] == provider.sha256
         and all(config['runtime'][role]['image'] == manifest['images'][role] for role in ('fox', 'converter'))
         and config['role_paths']['operator-state'] == provider.configuration['state_root']
         and config['protected_sources']['admin-secret']['path'] == provider.configuration['admin_secret_file'],
         'SNAPSHOT_HOSTED_BINDING_CHANGED')
    need(config['python'] == {key: provider.configuration['python'][key] for key in ('path', 'sha256')},
         'SNAPSHOT_HOSTED_PYTHON_CHANGED')
    need(type(lease) is HeldOperatorLock, 'SNAPSHOT_REAL_HOSTED_LEASE_REQUIRED')
    lease.require_active(config['operator_release_sha256'],
                         provider.path('journal') / config['operator_release_sha256'][:16])
    installed = config['protected_sources']['operator-installation']
    installation_raw = runtime_provider._read(path(installed['path']), 2_000_000, private=True)
    installation = hosted_service.installation_document(installation_raw, expected_sha256=installed['sha256'])
    need(installation['provider']['sha256'] == provider.sha256
         and installation['release']['sha256'] == config['operator_release_sha256']
         and installation['layout']['release_root'] == str(Path(provider.configuration['converter_root']).parent)
         and config['protected_sources']['release-metadata']['path'] == installation['layout']['release_root'],
         'SNAPSHOT_INSTALLED_RELEASE_CHANGED')
    references = [installation[name] for name in ('provider', 'release', 'admission')]
    references.append(installation['layout']['inventory'])
    for reference in references:
        need(_covered(reference['path'], config), 'SNAPSHOT_INSTALLATION_REFERENCE_NOT_COVERED')
        content = runtime_provider._read(path(reference['path']), 2_000_000, private=True)
        need(sha(content) == reference['sha256'], 'SNAPSHOT_INSTALLATION_REFERENCE_CHANGED')
    inventory_reference = installation['layout']['inventory']
    hosted_service.verify_inventory(path(installation['layout']['release_root']),
        runtime_provider._read(path(inventory_reference['path']), 2_000_000, private=True))
    archived = installation['retirement']
    state = PurePosixPath(config['role_paths']['operator-state'])
    need(state in PurePosixPath(archived['path']).parents, 'SNAPSHOT_RETIREMENT_OUTSIDE_STATE')
    if 'retirement-archive' in config['protected_sources']:
        need(config['protected_sources']['retirement-archive']['path'] == archived['path'],
             'SNAPSHOT_RETIREMENT_REFERENCE_CHANGED')
    retirement_handoff.RetirementArchive(path(archived['path']),
        attestation_sha256=archived['attestation_sha256'], release_sha256=config['operator_release_sha256'],
        configuration_sha256=installation['admission']['sha256']).read()
    product_queue_transport.require_ready(manifest, config['operator_release_sha256'])
    result = CaptureAuthority(_KEY, configuration_raw, expected_sha256, lease, release_raw)
    result.require_active()
    return result


def _command(args, *, data=None, timeout=40, maximum=2_000_000, allowed=(0,)):
    try:
        result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except Exception:
        raise SnapshotOperationError('SNAPSHOT_HOST_COMMAND_UNCONFIRMED') from None
    need(result.returncode in allowed and not result.stderr.strip() and len(result.stdout) <= maximum,
         'SNAPSHOT_HOST_COMMAND_UNCONFIRMED')
    return result.stdout


def _inspect(identity, rootful=False):
    prefix = ['sudo', '-n', '/usr/bin/podman'] if rootful else ['/usr/bin/podman']
    value = json.loads(_command(prefix + ['inspect', identity]))
    need(type(value) is list and len(value) == 1 and type(value[0]) is dict, 'SNAPSHOT_INSPECT_INVALID')
    return value[0]


def _service(role):
    prefix = ['/usr/bin/systemctl'] + ([] if role == 'tls' else ['--user'])
    raw = _command(prefix + ['show', SERVICE_NAMES[role], '--property=Id,LoadState,ActiveState,SubState,MainPID,FragmentPath'])
    rows = dict(line.split('=', 1) for line in raw.decode().splitlines())
    need(set(rows) == {'Id', 'LoadState', 'ActiveState', 'SubState', 'MainPID', 'FragmentPath'}
         and rows['Id'] == SERVICE_NAMES[role] and rows['MainPID'] == '0'
         and rows['ActiveState'] in ('inactive', 'failed') and rows['SubState'] in ('dead', 'failed'),
         'SNAPSHOT_DECLARED_WRITER_NOT_STOPPED')
    return rows


def _host_identity(config):
    """Read-only identity, including status calls after a lost response."""
    import pwd
    need(os.name == 'posix' and os.getuid() == os.getgid() == 1000
         and pwd.getpwuid(1000).pw_name == 'opc', 'SNAPSHOT_EXACT_OPC_REQUIRED')
    request = urllib.request.Request('http://169.254.169.254/opc/v2/instance/', headers={'Authorization': 'Bearer Oracle'})
    with urllib.request.urlopen(request, timeout=5) as response:
        value = json.loads(response.read(100001))
    observed = {'instance_id': value.get('id'), 'compartment_id': value.get('compartmentId'),
                'region': value.get('canonicalRegionName') or value.get('regionInfo', {}).get('regionIdentifier')}
    need(observed == TARGET, 'SNAPSHOT_EXACT_JSN_REQUIRED')
    need(sha(Path(config['python']['path']).read_bytes()) == config['python']['sha256'], 'SNAPSHOT_PYTHON_CHANGED')
    return observed


def _host_guard(config):
    """Actual read-only IMDS, systemd and rootless/rootful mount observations."""
    observed = _host_identity(config)
    containers, services = {}, {}
    for role, pin in config['runtime'].items():
        item = _inspect(pin['id'], role == 'tls')
        state = item.get('State', {})
        need(item.get('Id') == pin['id'] and item.get('Image', '').removeprefix('sha256:') == pin['image'][7:]
             and item.get('Name', '').lstrip('/') == CONTAINER_NAMES[role]
             and state.get('Running') is False and state.get('Pid') == 0
             and state.get('Status') in ('exited', 'stopped'), 'SNAPSHOT_EXACT_STOPPED_CONTAINERS_REQUIRED')
        containers[role] = item
        services[role] = _service(role)
        need(services[role]['LoadState'] == 'loaded'
             and services[role]['FragmentPath'] == config['protected_sources'][role + '-unit']['path'],
             'SNAPSHOT_UNIT_SOURCE_CHANGED')
    services['verifier'] = _service('verifier')
    if config['mode'] == 'pre-hosted-g':
        need(services['verifier']['LoadState'] == 'not-found' and not services['verifier']['FragmentPath'],
             'SNAPSHOT_HOSTED_WRITER_ALREADY_INSTALLED')
    else:
        need(services['verifier']['LoadState'] == 'loaded'
             and services['verifier']['FragmentPath'] == config['protected_sources']['verifier-unit']['path'],
             'SNAPSHOT_VERIFIER_UNIT_CHANGED')
    expected = {'fox': {'/data': config['role_paths']['fox-data'],
        '/run/fox-opaf': config['protected_sources']['opaf-client']['path'],
        '/run/fox-native/profile.json': config['protected_sources']['baseline-fox-profile']['path']},
        'converter': {'/opt/forms2apex/outputs/jobs': config['role_paths']['converter-jobs'],
        '/home/converter/.dbtools': config['protected_sources']['sqlcl-connections']['path'],
        '/opt/forms2apex/wallet': config['protected_sources']['wallet']['path'],
        '/run/fox-target/profile.json': config['protected_sources']['baseline-target-profile']['path']}}
    roots = list(config['role_paths'].values()) + [v['path'] for v in config['protected_sources'].values()] + [config['output_root']]
    for role in ('fox', 'converter'):
        mounts = containers[role].get('Mounts')
        need(type(mounts) is list and len(mounts) <= 64, 'SNAPSHOT_MOUNTS_INVALID')
        by_dest = {m.get('Destination'): m.get('Source') for m in mounts}
        need(len(by_dest) == len(mounts) and all(by_dest.get(k) == v for k, v in expected[role].items()),
             'SNAPSHOT_ROLE_MOUNT_CHANGED')
        if role == 'fox':
            private = [config['output_root']]
            if config['mode'] == 'hosted':
                private += [config['role_paths']['operator-state'], config['protected_sources']['admin-secret']['path']]
            need(all(not overlap(p, m['Source']) for p in private for m in mounts), 'SNAPSHOT_PRIVATE_PUBLIC_OVERLAP')
    for rootful in (False, True):
        prefix = ['sudo', '-n', '/usr/bin/podman'] if rootful else ['/usr/bin/podman']
        ids = _command(prefix + ['ps', '--no-trunc', '--format', '{{.ID}}']).decode().splitlines()
        need(len(ids) <= 256 and all(SHA.fullmatch(item) for item in ids), 'SNAPSHOT_WRITER_INVENTORY_INVALID')
        for identity in ids:
            item = _inspect(identity, rootful)
            need(item.get('Id') == identity and item.get('State', {}).get('Running') is True,
                 'SNAPSHOT_WRITER_IDENTITY_CHANGED')
            for mount in item.get('Mounts', []):
                need(not (mount.get('RW') is True and any(overlap(mount['Source'], root) for root in roots)),
                     'SNAPSHOT_OTHER_WRITER_MOUNT_PRESENT')
    return {'scope': 'fox-stopped-writer-observation-v1', 'target': observed,
            'runtime': config['runtime'], 'services': services, 'observed_at_utc': datetime.now(timezone.utc).isoformat()}


def _inventory_sources(s, sources):
    result, total = {}, 0
    for name, entry in sorted(sources.items()):
        root = s._path(Path(entry['path']))
        need(root.is_dir() if entry['kind'] == 'directory' else root.is_file(), 'SNAPSHOT_PROTECTED_KIND_CHANGED')
        todo = [(root, name)]
        while todo:
            source, key = todo.pop()
            s._member_path('protected-config/' + key)
            need(len(result) < s.MAX_ENTRIES, 'SNAPSHOT_PROTECTED_ENTRY_BOUND')
            observed = s._entry(source)
            result[key] = observed
            if observed['kind'] == 'directory':
                todo += [(child, key + '/' + child.name) for child in sorted(source.iterdir(), reverse=True)]
            else:
                total += observed['bytes']
                need(total <= s.MAX_TOTAL_BYTES, 'SNAPSHOT_PROTECTED_BYTES_BOUND')
        if entry['sha256'] is not None:
            need(result[name]['sha256'] == entry['sha256'], 'SNAPSHOT_PROTECTED_FILE_CHANGED')
    return result


def _process_identity(pid):
    need(type(pid) is int and pid > 0, 'SNAPSHOT_PROCESS_ID_INVALID')
    raw = Path('/proc/' + str(pid) + '/stat').read_text()
    fields = raw[raw.rfind(') ') + 2:].split()
    need(len(fields) >= 20 and fields[19].isdigit(), 'SNAPSHOT_PROCESS_IDENTITY_UNAVAILABLE')
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    need(re.fullmatch('[a-f0-9-]{36}', boot), 'SNAPSHOT_PROCESS_BOOT_ID_INVALID')
    return {'pid': pid, 'start_ticks': int(fields[19]), 'boot_id': boot}


def _worker_observation(s, stage, config_sha):
    marker = stage / 'namespace-worker.json'
    if not marker.exists():
        return {'state': 'NO_WORKER_IDENTITY_OBSERVED', 'exit_confirmed': False}
    value = parse(s._read(marker))
    need(set(value) == {'schema_version', 'scope', 'identity', 'operation', 'action', 'configuration_sha256'}
         and value['scope'] == 'fox-snapshot-namespace-worker-v1'
         and type(value['schema_version']) is int and value['schema_version'] == 1,
         'SNAPSHOT_WORKER_IDENTITY_CHANGED')
    need(value['operation'] == stage.name and value['action'] in ('capture', 'restore')
         and value['configuration_sha256'] == config_sha, 'SNAPSHOT_WORKER_REQUEST_CHANGED')
    identity = value['identity']
    need(type(identity) is dict and set(identity) == {'pid', 'start_ticks', 'boot_id'}
         and type(identity['pid']) is int and identity['pid'] > 0
         and type(identity['start_ticks']) is int and identity['start_ticks'] >= 0
         and type(identity['boot_id']) is str and re.fullmatch('[a-f0-9-]{36}', identity['boot_id']),
         'SNAPSHOT_WORKER_IDENTITY_CHANGED')
    try:
        current = _process_identity(identity['pid'])
    except FileNotFoundError:
        return {'state': 'RECORDED_PROCESS_ABSENT', 'pid': identity['pid'], 'exit_confirmed': False}
    return {'state': 'MATCHING_PROCESS_PRESENT' if current == identity else 'RECORDED_IDENTITY_NO_LONGER_PRESENT',
            'pid': identity['pid'], 'exit_confirmed': False}


def _record_work_result(s, stage, worker, result):
    s._new_file(stage / 'namespace-work-result.json', canonical({
        'schema_version': 1, 'scope': 'fox-snapshot-namespace-work-result-v1',
        'worker_sha256': sha(canonical(worker)), 'result_sha256': sha(canonical(result)),
        'work_returned': True, 'process_exit_confirmed': False}))
    return result


def _worker(packet, s):
    """Runs only under approved rootless user namespace; no network or SQL."""
    config = configuration_document(base64.b64decode(packet['configuration'], validate=True), packet['configuration_sha256'])
    need(os.name == 'posix' and os.getuid() == os.getgid() == 0, 'SNAPSHOT_ROOTLESS_NAMESPACE_REQUIRED')
    for name in ('uid', 'gid'):
        rows = [tuple(map(int, line.split())) for line in Path('/proc/self/' + name + '_map').read_text().splitlines()]
        need(rows and rows[0] == (0, 1000, 1), 'SNAPSHOT_ROOTLESS_MAPPING_CHANGED')
    if packet['action'] == 'measure':
        totals = {}
        sources = {**{key: {'path': value, 'kind': 'directory'} for key, value in config['role_paths'].items()},
                   **{'protected/' + key: value for key, value in config['protected_sources'].items()}}
        for label, entry in sources.items():
            source = s._path(Path(entry['path']))
            need(source.is_dir() if entry['kind'] == 'directory' else source.is_file(),
                 'SNAPSHOT_PROTECTED_KIND_CHANGED')
            entries, count, size, largest, todo = 0, 0, 0, 0, [source]
            while todo:
                item = s._path(todo.pop())
                info = item.lstat()
                entries += 1
                need(entries <= 1_000_000, 'SNAPSHOT_MEASUREMENT_ENTRY_BOUND')
                if stat.S_ISDIR(info.st_mode):
                    todo.extend(item.iterdir())
                else:
                    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'SNAPSHOT_MEASUREMENT_SPECIAL_FILE')
                    count += 1; size += info.st_size; largest = max(largest, info.st_size)
            totals[label] = {'entries': entries, 'files': count, 'bytes': size, 'largest_member_bytes': largest}
        # Plan + bounded authority manifest are embedded in protected-config.
        # Count their conservative upper bound; no source/secret content is read.
        size = sum(item['bytes'] for item in totals.values()) + len(base64.b64decode(packet['configuration'])) + 2_000_000
        entries = sum(item['entries'] for item in totals.values()) + 3
        largest = max([2_000_000, *(item['largest_member_bytes'] for item in totals.values())])
        bounds = {'entries': s.MAX_ENTRIES, 'member_bytes': s.MAX_MEMBER_BYTES, 'total_bytes': s.MAX_TOTAL_BYTES}
        exceeded = [key for key, actual in (('entries', entries), ('member_bytes', largest), ('total_bytes', size))
                    if actual > bounds[key]]
        return {'status': 'CAPACITY_ESTIMATE', 'scope': 'fox-snapshot-capacity-estimate-v1',
            'roles': totals, 'total_bytes_upper_bound': size, 'entries_upper_bound': entries,
            'largest_member_bytes': largest, 'limits': bounds, 'fits_current_limits': not exceeded,
            'exceeded_limits': exceeded, 'source_contents_read': False, 'files_written': False,
            'consistent_capture_proven': False,
            'next_action': 'REVIEW_BOUNDED_CAPACITY_CHANGE_NO_AUTOMATIC_EXPANSION' if exceeded else 'DRAIN_AND_CAPTURE_UNDER_REAL_LEASE'}
    stage = s._path(Path(packet['stage']))
    need(packet['action'] in ('capture', 'restore'), 'SNAPSHOT_WORKER_ACTION_INVALID')
    worker = {'schema_version': 1, 'scope': 'fox-snapshot-namespace-worker-v1',
        'identity': _process_identity(os.getpid()), 'operation': packet['operation'], 'action': packet['action'],
        'configuration_sha256': packet['configuration_sha256']}
    s._new_file(stage / 'namespace-worker.json', canonical(worker))
    if packet['action'] == 'restore':
        result = s.restore_test(Path(packet['backup']), stage / 'restored-copy')
        return _record_work_result(s, stage, worker, {'status': result['status'], 'result': result})
    before = _inventory_sources(s, config['protected_sources'])
    protected = stage / 'protected-capture'
    s._new_directory(protected)
    for key, entry in sorted(before.items()):
        parts = PurePosixPath(key).parts
        source = Path(config['protected_sources'][parts[0]]['path']).joinpath(*parts[1:])
        destination = protected.joinpath(*parts)
        if entry['kind'] == 'directory':
            s._new_directory(destination)
        else:
            raw = s._read(source)
            need(len(raw) == entry['bytes'] and sha(raw) == entry['sha256'], 'SNAPSHOT_PROTECTED_SOURCE_CHANGED')
            s._new_file(destination, raw)
    s._new_file(protected / 'snapshot-plan.json', base64.b64decode(packet['configuration'], validate=True))
    s._new_file(protected / 'operator-release.json', base64.b64decode(packet['release'], validate=True))
    s._new_file(stage / 'protected-source-inventory.json', canonical(before))
    roles = {key: Path(value) for key, value in config['role_paths'].items()}
    roles['protected-config'] = protected
    result = s.backup(roles, stage / 'snapshot')
    need(_inventory_sources(s, config['protected_sources']) == before, 'SNAPSHOT_PROTECTED_SOURCES_CHANGED')
    return _record_work_result(s, stage, worker, {'status': result['status'], 'result': result,
            'protected_source_inventory_sha256': sha(canonical(before))})


def _verified_completion(s, stage, config, config_sha, *, expected_sha=None, capture_only=False):
    """Read existing material and bind the outer receipt to exact inner bytes."""
    raw = s._read(stage / 'completion.json')
    if expected_sha is not None:
        need(type(expected_sha) is str and SHA.fullmatch(expected_sha) and sha(raw) == expected_sha,
             'SNAPSHOT_TRUSTED_BACKUP_REQUIRED')
    value = parse(raw)
    fields = {'schema_version', 'scope', 'action', 'configuration_sha256', 'operation', 'result',
              'completed_at_utc', 'live_data_restored', 'services_changed',
              'opaf_repository_recovery_proven', 'automatic_replay_permitted', 'writer_observations_sha256',
              'worker_evidence_sha256'}
    need(set(value) == fields and type(value['schema_version']) is int and value['schema_version'] == 1
         and value['scope'] == 'fox-hosted-snapshot-completion-v1'
         and value['configuration_sha256'] == config_sha and value['operation'] == stage.name
         and value['action'] in ('capture', 'restore')
         and (not capture_only or value['action'] == 'capture')
         and all(value[key] is False for key in ('live_data_restored', 'services_changed',
             'opaf_repository_recovery_proven', 'automatic_replay_permitted')), 'SNAPSHOT_COMPLETION_CHANGED')
    observed = value['writer_observations_sha256']
    need(type(observed) is dict and set(observed) == {'before.json', 'after.json'},
         'SNAPSHOT_WRITER_EVIDENCE_CHANGED')
    for name, digest in observed.items():
        content = s._read(stage / name)
        need(type(digest) is str and SHA.fullmatch(digest) and sha(content) == digest,
             'SNAPSHOT_WRITER_EVIDENCE_CHANGED')
        observation = parse(content)
        need(observation.get('scope') == 'fox-stopped-writer-observation-v1'
             and observation.get('target') == config['target'] and observation.get('runtime') == config['runtime'],
             'SNAPSHOT_WRITER_EVIDENCE_CHANGED')
    intent = parse(s._read(stage / 'intent.json'))
    need(set(intent) == {'action', 'operation', 'configuration_sha256', 'backup', 'backup_completion_sha256'}
         and all(intent[key] == value[key] for key in ('action', 'operation', 'configuration_sha256')),
         'SNAPSHOT_INTENT_CHANGED')
    result = value['result']
    need(type(result) is dict and type(result.get('result')) is dict, 'SNAPSHOT_RESULT_INVALID')
    records = value['worker_evidence_sha256']
    need(type(records) is dict and set(records) == {'namespace-worker.json', 'namespace-work-result.json',
         'namespace-worker-exit.json'}, 'SNAPSHOT_WORKER_EVIDENCE_CHANGED')
    documents = {}
    for name, expected in records.items():
        content = s._read(stage / name)
        need(sha(content) == expected, 'SNAPSHOT_WORKER_EVIDENCE_CHANGED')
        documents[name] = parse(content)
    worker, completed, exited = (documents[name] for name in
        ('namespace-worker.json', 'namespace-work-result.json', 'namespace-worker-exit.json'))
    need(worker.get('scope') == 'fox-snapshot-namespace-worker-v1'
         and all(worker.get(key) == value[key] for key in ('action', 'operation', 'configuration_sha256'))
         and completed == {'schema_version': 1, 'scope': 'fox-snapshot-namespace-work-result-v1',
            'worker_sha256': records['namespace-worker.json'], 'result_sha256': sha(canonical(result)),
            'work_returned': True, 'process_exit_confirmed': False}
         and exited == {'schema_version': 1, 'scope': 'fox-snapshot-namespace-exit-observation-v1',
            'worker_sha256': records['namespace-worker.json'], 'work_result_sha256': records['namespace-work-result.json'],
            'launcher_returncode': 0, 'observed_by': 'synchronous_host_subprocess'}, 'SNAPSHOT_WORKER_EVIDENCE_CHANGED')
    if value['action'] == 'capture':
        need(intent['backup'] is None and intent['backup_completion_sha256'] is None
             and set(result) == {'status', 'result', 'protected_source_inventory_sha256'}
             and result['status'] == 'BACKUP_VERIFIED', 'SNAPSHOT_CAPTURE_RESULT_INVALID')
        manifest, artifacts, completion_sha = s._verify_backup(stage / 'snapshot')
        report = result['result']
        need(report.get('status') == 'BACKUP_VERIFIED'
             and report.get('manifest_sha256') == artifacts['manifest.json']['sha256']
             and report.get('completion_sha256') == completion_sha
             and report.get('archive_sha256') == artifacts['roles.tar']['sha256']
             and report.get('sqlite_inventory_sha256') == s._sha(s._raw(manifest['sqlite_inventory']))
             and report.get('roles') == sorted(set(config['role_paths']) | {'protected-config'})
             and manifest['roles'] == report['roles']
             and report.get('source_unchanged') is True and report.get('live_data_restored') is False
             and result['protected_source_inventory_sha256'] == sha(s._read(stage / 'protected-source-inventory.json')),
             'SNAPSHOT_INNER_BACKUP_BINDING_CHANGED')
    else:
        need(set(result) == {'status', 'result'} and result['status'] == 'RESTORE_TEST_PASSED',
             'SNAPSHOT_RESTORE_RESULT_INVALID')
        backup = s._path(Path(intent['backup']))
        need(backup.name == 'snapshot' and backup.parent.parent == stage.parent
             and backup.parent != stage, 'SNAPSHOT_EXACT_BACKUP_PATH_REQUIRED')
        prior = _verified_completion(s, backup.parent, config, config_sha,
                                     expected_sha=intent['backup_completion_sha256'], capture_only=True)
        need(prior['action'] == 'capture', 'SNAPSHOT_CAPTURE_RECEIPT_REQUIRED')
        report_raw = s._read(stage / 'restored-copy/restore-result.json')
        report = json.loads(report_raw)
        need(report == result['result'] and report.get('status') == 'RESTORE_TEST_PASSED',
             'SNAPSHOT_RESTORE_REPORT_CHANGED')
        manifest, _, completion_sha = s._verify_backup(backup)
        need(report.get('backup_completion_sha256') == completion_sha
             and report.get('manifest_sha256') == prior['result']['result']['manifest_sha256'],
             'SNAPSHOT_RESTORE_BACKUP_BINDING_CHANGED')
        restored = stage / 'restored-copy/restored'
        actual = s._inventory({role: restored / role for role in manifest['roles']})
        need(set(actual) == set(manifest['inventory']), 'SNAPSHOT_RESTORED_MEMBERSHIP_CHANGED')
        for name, entry in actual.items():
            expected = manifest['inventory'][name]
            need(all(entry.get(k) == expected.get(k) for k in ('kind', 'bytes', 'sha256')),
                 'SNAPSHOT_RESTORED_CONTENT_CHANGED')
            s._privacy(restored.joinpath(*PurePosixPath(name).parts), entry['kind'] == 'directory')
        need(s._sqlite_readback(stage / 'restored-copy/sqlite-restored.sqlite3') == manifest['sqlite_inventory'],
             'SNAPSHOT_RESTORED_SQLITE_CHANGED')
    return value


def _host_entry(packet, s, own_raw, snapshot_raw):
    config = configuration_document(base64.b64decode(packet['configuration'], validate=True), packet['configuration_sha256'])
    need(sha(own_raw) == config['source_sha256']['hosted_snapshot.py']
         and sha(snapshot_raw) == config['source_sha256']['snapshot.py'], 'SNAPSHOT_HOST_SOURCE_CHANGED')
    action, operation = packet['action'], packet['operation']
    need(action in ('capture', 'restore', 'status', 'measure') and re.fullmatch('[a-z][a-z0-9-]{3,59}', operation),
         'SNAPSHOT_OPERATION_INVALID')
    if action == 'measure':
        _host_identity(config)
        payload = {**packet, 'own': base64.b64encode(own_raw).decode(), 'snapshot': base64.b64encode(snapshot_raw).decode()}
        loader = "import json,base64,types,sys;p=json.load(sys.stdin);s=types.ModuleType('snapshot');exec(compile(base64.b64decode(p.pop('snapshot'),validate=True),'<snapshot>','exec'),s.__dict__);m=types.ModuleType('hosted_snapshot');exec(compile(base64.b64decode(p.pop('own'),validate=True),'<hosted_snapshot>','exec'),m.__dict__);print(json.dumps(m._worker(p,s),sort_keys=True))"
        return json.loads(_command(['/usr/bin/podman', 'unshare', config['python']['path'], '-I', '-B', '-c', loader],
                                   data=canonical(payload), timeout=120))
    root = s._path(Path(config['output_root']))
    s._privacy(root, True)
    stage = root / operation
    if action == 'status':
        _host_identity(config)
        s._privacy(stage, True)
        if (stage / 'completion.json').exists():
            result = _verified_completion(s, stage, config, packet['configuration_sha256'])
            return {'status': 'COMPLETE', 'receipt': result, 'completion_sha256': sha(canonical(result)),
                    'automatic_replay_permitted': False}
        return {'status': 'ATTENTION', 'automatic_replay_permitted': False, 'partials_preserved': True,
                'worker': _worker_observation(s, stage, packet['configuration_sha256'])}
    before = _host_guard(config)
    if action == 'restore':
        backup = s._path(Path(packet['backup']))
        need(backup.name == 'snapshot' and backup.parent.parent == root and backup.parent != stage,
             'SNAPSHOT_EXACT_BACKUP_PATH_REQUIRED')
        need(not any(overlap(backup, p) or overlap(stage, p) for p in list(config['role_paths'].values())
                     + [v['path'] for v in config['protected_sources'].values()]), 'SNAPSHOT_RESTORE_OVERLAPS_LIVE_ROOT')
        previous = _verified_completion(s, backup.parent, config, packet['configuration_sha256'],
                                        expected_sha=packet['backup_completion_sha256'], capture_only=True)
        need(previous['configuration_sha256'] == packet['configuration_sha256'] and previous['action'] == 'capture',
             'SNAPSHOT_BACKUP_CONFIGURATION_CHANGED')
    s._new_directory(stage)
    s._new_file(stage / 'intent.json', canonical({key: packet[key] for key in
        ('action', 'operation', 'configuration_sha256', 'backup', 'backup_completion_sha256')}))
    s._new_file(stage / 'before.json', canonical(before))
    packet = dict(packet, stage=str(stage))
    payload = {**packet, 'own': base64.b64encode(own_raw).decode(), 'snapshot': base64.b64encode(snapshot_raw).decode()}
    loader = "import json,base64,types,sys;p=json.load(sys.stdin);s=types.ModuleType('snapshot');exec(compile(base64.b64decode(p.pop('snapshot'),validate=True),'<snapshot>','exec'),s.__dict__);m=types.ModuleType('hosted_snapshot');exec(compile(base64.b64decode(p.pop('own'),validate=True),'<hosted_snapshot>','exec'),m.__dict__);print(json.dumps(m._worker(p,s),sort_keys=True))"
    raw = _command(['/usr/bin/podman', 'unshare', config['python']['path'], '-I', '-B', '-c', loader],
                   data=canonical(payload), timeout=900)
    result = json.loads(raw)
    need(type(result) is dict and result.get('status') == ('BACKUP_VERIFIED' if action == 'capture' else 'RESTORE_TEST_PASSED'),
         'SNAPSHOT_CAPTURE_OR_RESTORE_UNCONFIRMED')
    worker_raw, work_raw = (s._read(stage / name) for name in ('namespace-worker.json', 'namespace-work-result.json'))
    need(parse(work_raw).get('worker_sha256') == sha(worker_raw)
         and parse(work_raw).get('result_sha256') == sha(canonical(result)), 'SNAPSHOT_WORKER_RESULT_CHANGED')
    exit_observation = {'schema_version': 1, 'scope': 'fox-snapshot-namespace-exit-observation-v1',
        'worker_sha256': sha(worker_raw), 'work_result_sha256': sha(work_raw),
        'launcher_returncode': 0, 'observed_by': 'synchronous_host_subprocess'}
    s._new_file(stage / 'namespace-worker-exit.json', canonical(exit_observation))
    after = _host_guard(config)
    need({k: v for k, v in before.items() if k != 'observed_at_utc'} ==
         {k: v for k, v in after.items() if k != 'observed_at_utc'}, 'SNAPSHOT_WRITERS_CHANGED_DURING_CAPTURE')
    receipt = {'schema_version': 1, 'scope': 'fox-hosted-snapshot-completion-v1', 'action': action,
        'configuration_sha256': packet['configuration_sha256'], 'operation': operation, 'result': result,
        'completed_at_utc': datetime.now(timezone.utc).isoformat(), 'live_data_restored': False,
        'services_changed': False, 'opaf_repository_recovery_proven': False, 'automatic_replay_permitted': False}
    receipt['writer_observations_sha256'] = {'before.json': sha(canonical(before)), 'after.json': sha(canonical(after))}
    receipt['worker_evidence_sha256'] = {'namespace-worker.json': sha(worker_raw),
        'namespace-work-result.json': sha(work_raw), 'namespace-worker-exit.json': sha(canonical(exit_observation))}
    s._new_file(stage / 'after.json', canonical(after))
    s._new_file(stage / 'completion.json', canonical(receipt))
    _verified_completion(s, stage, config, packet['configuration_sha256'])
    return {'status': 'COMPLETE', 'receipt': receipt, 'completion_sha256': sha(canonical(receipt)),
            'automatic_replay_permitted': False}


def _wire(config, configuration_raw, config_sha, release_raw, *, action, operation, backup, backup_completion_sha256):
    """Explicit action, exact source pins, same live lease; uncertain replies never replay."""
    own = Path(__file__).read_bytes()
    source = Path(__file__).with_name('snapshot.py').read_bytes()
    need(sha(own) == config['source_sha256']['hosted_snapshot.py'] and sha(source) == config['source_sha256']['snapshot.py'],
         'SNAPSHOT_LOCAL_SOURCE_CHANGED')
    packet = {'action': action, 'operation': operation, 'configuration': base64.b64encode(configuration_raw).decode(),
        'configuration_sha256': config_sha, 'release': base64.b64encode(release_raw).decode(),
        'backup': str(backup) if backup is not None else None, 'backup_completion_sha256': backup_completion_sha256,
        'own': base64.b64encode(own).decode(), 'snapshot': base64.b64encode(source).decode()}
    loader = "import json,base64,types,sys;p=json.load(sys.stdin);a=base64.b64decode(p.pop('own'),validate=True);b=base64.b64decode(p.pop('snapshot'),validate=True);s=types.ModuleType('snapshot');exec(compile(b,'<snapshot>','exec'),s.__dict__);m=types.ModuleType('hosted_snapshot');exec(compile(a,'<hosted_snapshot>','exec'),m.__dict__);print(json.dumps(m._safe_host_entry(p,s,a,b),sort_keys=True))"
    return loader, canonical(packet)


def _safe_host_entry(packet, s, own_raw, snapshot_raw):
    try:
        return _host_entry(packet, s, own_raw, snapshot_raw)
    except Exception as error:
        code = str(error) if type(error) in (SnapshotOperationError, s.SnapshotError) else ''
        if not re.fullmatch('[A-Z][A-Z0-9_]{2,100}', code):
            code = 'SNAPSHOT_INTERNAL_FAILURE_DETAILS_WITHHELD'
        return {'status': 'ATTENTION', 'code': code, 'automatic_replay_permitted': False,
                'next_action': 'READ_SAME_OPERATION_AND_RECONCILE_NO_REPLAY'}


def execute_under_lock(authority, *, action, operation, apply=False, backup=None, backup_completion_sha256=None):
    """Explicit writes require the same actual held lease around the host action."""
    need(type(authority) is CaptureAuthority, 'SNAPSHOT_TYPED_AUTHORITY_REQUIRED')
    config = authority.require_active()
    need(action in ('capture', 'restore') and apply is True, 'SNAPSHOT_EXPLICIT_APPLY_REQUIRED')
    loader, packet = _wire(config, authority.raw, authority.digest, authority.release_raw,
        action=action, operation=operation, backup=backup, backup_completion_sha256=backup_completion_sha256)
    try:
        if config['mode'] == 'hosted':
            from qa.operator import runtime_provider
            raw = runtime_provider.selected_hosted().execute_host(loader, packet, timeout=1100)
        else:
            clean = authority.owner.components.clean
            raw = clean.run_process([*clean.SSH, config['python']['path'] + ' -I -B -c ' + shlex.quote(loader)],
                                    data=packet, timeout=1100)
        authority.require_active()
        result = json.loads(raw)
        need(type(result) is dict and result.get('status') in ('COMPLETE', 'ATTENTION')
             and result.get('automatic_replay_permitted') is False, 'SNAPSHOT_RESPONSE_INVALID')
        return result
    except Exception:
        raise SnapshotOperationError('SNAPSHOT_OUTCOME_UNCONFIRMED_READ_SAME_OPERATION_NO_REPLAY') from None


def _read_operation(configuration_raw, *, expected_sha256, operation, action):
    need(action in ('status', 'measure'), 'SNAPSHOT_READ_ONLY_OPERATION_REQUIRED')
    config = configuration_document(configuration_raw, expected_sha256)
    loader, packet = _wire(config, configuration_raw, expected_sha256, b'', action=action,
                          operation=operation, backup=None, backup_completion_sha256=None)
    try:
        if config['mode'] == 'hosted':
            from qa.operator import runtime_provider
            provider = runtime_provider.selected_hosted()
            need(provider is not None and provider.sha256 == config['provider_configuration_sha256'],
                 'SNAPSHOT_STATUS_PROVIDER_CHANGED')
            raw = provider.execute_host(loader, packet, timeout=240)
        else:
            from qa.operator import clean_install
            raw = clean_install.run_process([*clean_install.SSH,
                config['python']['path'] + ' -I -B -c ' + shlex.quote(loader)], data=packet, timeout=240)
        result = json.loads(raw)
        need(type(result) is dict, 'SNAPSHOT_RESPONSE_INVALID')
        status = result.get('status')
        allowed = ('CAPACITY_ESTIMATE', 'ATTENTION') if action == 'measure' else ('COMPLETE', 'ATTENTION')
        need(status in allowed and (status == 'CAPACITY_ESTIMATE'
             or result.get('automatic_replay_permitted') is False), 'SNAPSHOT_RESPONSE_INVALID')
        return result
    except Exception:
        raise SnapshotOperationError('SNAPSHOT_STATUS_UNCONFIRMED_NO_REPLAY') from None


def read_status(configuration_raw, *, expected_sha256, operation):
    """No lease/restart needed to inspect a lost result; this exposes no writes."""
    return _read_operation(configuration_raw, expected_sha256=expected_sha256, operation=operation, action='status')


def measure(configuration_raw, *, expected_sha256):
    """Metadata-only capacity estimate before downtime; not a consistent backup."""
    return _read_operation(configuration_raw, expected_sha256=expected_sha256, operation='capacity-check', action='measure')


def require_project_aware_rollback(fox_data, candidate_manifest_raw):
    """Conservative read-only compatibility gate, not permission to activate code."""
    from qa.operator import product_queue_transport
    from qa.operator import snapshot as s
    document = parse(candidate_manifest_raw)
    # G predates the current code-inventory shape. Recognize only its exact
    # immutable historical bytes, never reinterpret an arbitrary v1 manifest.
    if sha(candidate_manifest_raw) == G_RELEASE:
        manifest = document
        need(manifest.get('schema_version') == 1, 'SNAPSHOT_HISTORICAL_G_CHANGED')
    else:
        try:
            manifest = product_queue_transport.validate_release(document)
        except Exception:
            raise SnapshotOperationError('SNAPSHOT_CANDIDATE_RELEASE_UNSUPPORTED') from None
    jobs = s._path(Path(fox_data)) / 'jobs'
    need(jobs.is_dir(), 'SNAPSHOT_JOB_HISTORY_REQUIRED')
    project = False
    for index, job in enumerate(jobs.iterdir()):
        need(index < 10000 and not job.is_symlink(), 'SNAPSHOT_JOB_HISTORY_UNSAFE')
        if not job.is_dir():
            continue
        source = job / 'source-snapshot.json'
        need(source.is_file(), 'SNAPSHOT_UNKNOWN_JOB_BLOCKS_ROLLBACK')
        try:
            value = s._load(s._read(source))
        except Exception:
            raise SnapshotOperationError('SNAPSHOT_SOURCE_IDENTITY_INVALID') from None
        need(value.get('conversion_profile') in ('native-table-form-v1', 'native-project-v1'),
             'SNAPSHOT_UNKNOWN_JOB_PROFILE_BLOCKS_ROLLBACK')
        project |= value.get('conversion_profile') == 'native-project-v1'
        project |= any((job / name).exists() for name in ('native-project-pipeline', 'project-technical-verification'))
    need(not project or manifest['schema_version'] in (2, 3), 'SNAPSHOT_LEGACY_ROLLBACK_BLOCKED_BY_PROJECT_HISTORY')
    return {'project_history_present': project, 'candidate_has_project_contract': manifest['schema_version'] in (2, 3),
            'activation_authorized': False, 'data_restore_authorized': False}
