"""Offline adapter tests; real private snapshots run in a local user namespace.

No test uses JSN, Oracle, real secrets, service changes, image/container creation
or a network connection. Host guard tests replace only external observations.
The namespace class runs the actual copying, SQLite, archive and restore code.
"""
from contextlib import closing, contextmanager
from copy import deepcopy
import base64
import io
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
for folder in (ROOT, ROOT / 'fox', ROOT / 'converter'):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))
from qa.operator import hosted_snapshot as h
from qa.operator import snapshot as s

SECRET = b'SYNTHETIC_ONLY_SNAPSHOT_SECRET_91ef\n'
DIRS = {'opaf-client', 'sqlcl-connections', 'wallet', 'converter-config',
        'release-metadata', 'operator-configuration', 'retirement-archive'}


def config(mode='hosted', base='/synthetic-only/fox-snapshot'):
    names = h.PROTECTED_REQUIRED | (h.PROTECTED_OPTIONAL if mode == 'hosted' else set())
    value = {'schema_version': 1, 'scope': h.SCOPE, 'mode': mode, 'target': dict(h.TARGET),
        'operator_release_sha256': h.G_RELEASE if mode == 'pre-hosted-g' else 'd' * 64,
        'provider_configuration_sha256': 'e' * 64 if mode == 'hosted' else None,
        'authority_source_sha256': 'f' * 64 if mode == 'pre-hosted-g' else None,
        'python': {'path': '/usr/bin/python3.11', 'sha256': 'a' * 64},
        'runtime': {name: {'id': digit * 64, 'image': 'sha256:' + digit * 64}
                    for name, digit in zip(('fox', 'converter', 'tls'), ('1', '2', '3'))},
        'role_paths': {name: base + '/roles/' + name for name in
                       (('fox-data', 'converter-jobs', 'operator-state') if mode == 'hosted'
                        else ('fox-data', 'converter-jobs'))},
        'protected_sources': {name: {'path': base + '/protected/' + name,
            'kind': 'directory' if name in DIRS else 'file', 'sha256': None} for name in names},
        'output_root': base + '/output',
        'source_sha256': {'snapshot.py': h.sha(Path(s.__file__).read_bytes()),
                          'hosted_snapshot.py': h.sha(Path(h.__file__).read_bytes())}}
    if mode == 'hosted':
        value['protected_sources']['operator-installation']['sha256'] = h.sha(b'synthetic:operator-installation')
    return value


def document(value):
    raw = h.canonical(value)
    return h.configuration_document(raw, h.sha(raw))


def packet(value, action='capture', operation='synthetic-capture'):
    raw = h.canonical(value)
    return {'action': action, 'operation': operation,
        'configuration': base64.b64encode(raw).decode(), 'configuration_sha256': h.sha(raw),
        'release': base64.b64encode(h.canonical({'synthetic_release_fixture': True})).decode(),
        'backup': None, 'backup_completion_sha256': None}


class ConfigurationTests(unittest.TestCase):
    def test_both_explicit_modes(self):
        for mode in ('hosted', 'pre-hosted-g'):
            with self.subTest(mode=mode):
                value = config(mode)
                self.assertEqual(document(value), value)

    def test_required_protected_inventory(self):
        for mode in ('hosted', 'pre-hosted-g'):
            value = config(mode)
            for key in h.PROTECTED_REQUIRED | (h.HOSTED_REQUIRED if mode == 'hosted' else set()):
                changed = deepcopy(value)
                del changed['protected_sources'][key]
                with self.subTest(mode=mode, key=key), self.assertRaises(h.SnapshotOperationError):
                    document(changed)

    def test_required_roles_are_exact_not_optional(self):
        for mode in ('hosted', 'pre-hosted-g'):
            value = config(mode)
            for name in value['role_paths']:
                changed = deepcopy(value)
                del changed['role_paths'][name]
                with self.subTest(mode=mode, name=name), self.assertRaises(h.SnapshotOperationError):
                    document(changed)
            value['role_paths']['unapproved'] = '/synthetic-only/other/path'
            with self.assertRaises(h.SnapshotOperationError):
                document(value)

    def test_protected_source_kinds_are_fixed(self):
        value = config()
        for name, entry in value['protected_sources'].items():
            changed = deepcopy(value)
            changed['protected_sources'][name]['kind'] = 'directory' if entry['kind'] == 'file' else 'file'
            changed['protected_sources'][name]['sha256'] = None
            with self.subTest(name=name), self.assertRaises(h.SnapshotOperationError):
                document(changed)

    def test_hosted_installation_must_be_independently_hash_pinned(self):
        value = config()
        value['protected_sources']['operator-installation']['sha256'] = None
        with self.assertRaisesRegex(h.SnapshotOperationError, 'SNAPSHOT_PINNED_INSTALLATION_REQUIRED'):
            document(value)

    def test_document_binding_and_fields(self):
        value = config()
        raw = h.canonical(value)
        with self.assertRaises(h.SnapshotOperationError):
            h.configuration_document(raw, '0' * 64)
        for key, replacement in [('schema_version', True), ('scope', 'other'), ('mode', 'auto'),
                                 ('operator_release_sha256', 'x'), ('provider_configuration_sha256', None)]:
            changed = deepcopy(value)
            changed[key] = replacement
            with self.subTest(key=key), self.assertRaises(h.SnapshotOperationError):
                document(changed)
        value['automatic_replay'] = True
        with self.assertRaises(h.SnapshotOperationError):
            document(value)

    def test_duplicate_json_and_noncanonical_documents(self):
        for raw in (b'{"x":1,"x":2}\n', b'{"x":1}', b'{ "x": 1 }\n'):
            with self.subTest(raw=raw), self.assertRaises(h.SnapshotOperationError):
                h.parse(raw)

    def test_source_hash_inventory_exact(self):
        for changed in ({}, {'snapshot.py': 'a' * 64},
                        {'snapshot.py': 'a' * 64, 'hosted_snapshot.py': 'a' * 63},
                        {'snapshot.py': 'a' * 64, 'hosted_snapshot.py': 'b' * 64, 'extra': 'c' * 64}):
            value = config()
            value['source_sha256'] = changed
            with self.subTest(changed=changed), self.assertRaises(h.SnapshotOperationError):
                document(value)

    def test_output_cannot_overlap_any_input(self):
        value = config()
        roots = [*value['role_paths'].values(), *(item['path'] for item in value['protected_sources'].values())]
        for root in roots:
            for output in (root, root + '/child', str(Path(root).parent).replace('\\', '/')):
                changed = deepcopy(value)
                changed['output_root'] = output
                with self.subTest(output=output), self.assertRaises(h.SnapshotOperationError):
                    document(changed)

    def test_scope_and_runtime_identity_mismatch(self):
        changes = [lambda v: v['target'].update(compartment_id='other'),
                   lambda v: v['runtime']['fox'].update(id='short'),
                   lambda v: v['runtime']['converter'].update(id=v['runtime']['fox']['id']),
                   lambda v: v['runtime']['tls'].update(image='latest')]
        for change in changes:
            value = config(); change(value)
            with self.subTest(value=value), self.assertRaises(h.SnapshotOperationError):
                document(value)

    def test_unsafe_paths(self):
        for bad in ('/a', '/a/b/../c', '/a//b/c', 'C:/a/b', '/a/b\\c/d', '/a/b/c\n'):
            with self.subTest(path=bad), self.assertRaises(h.SnapshotOperationError):
                h.path(bad)

    def test_authority_is_not_boolean_or_callback(self):
        for fake in (True, {}, lambda: True, SimpleNamespace(require_active=lambda: config())):
            with self.subTest(fake=type(fake).__name__), self.assertRaisesRegex(
                    h.SnapshotOperationError, 'SNAPSHOT_TYPED_AUTHORITY_REQUIRED'):
                h.execute_under_lock(fake, action='capture', operation='synthetic-capture', apply=True)
        value = config(); raw = h.canonical(value)
        with self.assertRaisesRegex(h.SnapshotOperationError, 'SNAPSHOT_TYPED_AUTHORITY_REQUIRED'):
            h.CaptureAuthority(object(), raw, h.sha(raw), True, b'{}\n')

    def test_host_entry_rejects_changed_sources_before_io(self):
        value = config()
        with patch.object(h.subprocess, 'run', side_effect=AssertionError('EXTERNAL_IO_FORBIDDEN')):
            with self.assertRaisesRegex(h.SnapshotOperationError, 'SNAPSHOT_HOST_SOURCE_CHANGED'):
                h._host_entry(packet(value), s, b'changed', Path(s.__file__).read_bytes())

    def test_raw_process_failure_or_timeout_never_exposes_secret(self):
        cases = [subprocess.CompletedProcess(['synthetic'], 1, SECRET, SECRET),
                 subprocess.CompletedProcess(['synthetic'], 0, b'', SECRET)]
        for result in cases:
            with patch.object(h.subprocess, 'run', return_value=result):
                with self.assertRaisesRegex(h.SnapshotOperationError, '^SNAPSHOT_HOST_COMMAND_UNCONFIRMED$') as error:
                    h._command(['synthetic'])
                self.assertNotIn(SECRET.decode().strip(), str(error.exception))
        with patch.object(h.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['synthetic'], 1, SECRET)):
            with self.assertRaisesRegex(h.SnapshotOperationError, '^SNAPSHOT_HOST_COMMAND_UNCONFIRMED$'):
                h._command(['synthetic'])

    def test_read_status_rejects_changed_local_source_before_transport(self):
        value = config()
        value['source_sha256']['hosted_snapshot.py'] = '0' * 64
        raw = h.canonical(value)
        with patch.object(h.subprocess, 'run', side_effect=AssertionError('TRANSPORT_FORBIDDEN')):
            with self.assertRaisesRegex(h.SnapshotOperationError, 'SNAPSHOT_LOCAL_SOURCE_CHANGED'):
                h.read_status(raw, expected_sha256=h.sha(raw), operation='synthetic-capture')

    def test_safe_host_entry_keeps_only_closed_error_categories(self):
        cases = [(h.SnapshotOperationError('SNAPSHOT_EXACT_JSN_REQUIRED'), 'SNAPSHOT_EXACT_JSN_REQUIRED'),
                 (s.SnapshotError('PRIVATE_OWNER_STORAGE_REQUIRED'), 'PRIVATE_OWNER_STORAGE_REQUIRED'),
                 (RuntimeError(SECRET.decode()), 'SNAPSHOT_INTERNAL_FAILURE_DETAILS_WITHHELD'),
                 (h.SnapshotOperationError('private detail ' + SECRET.decode()), 'SNAPSHOT_INTERNAL_FAILURE_DETAILS_WITHHELD')]
        for error, code in cases:
            with self.subTest(error=type(error).__name__), patch.object(h, '_host_entry', side_effect=error):
                result = h._safe_host_entry({}, s, b'', b'')
            self.assertEqual(result, {'status': 'ATTENTION', 'code': code,
                'automatic_replay_permitted': False, 'next_action': 'READ_SAME_OPERATION_AND_RECONCILE_NO_REPLAY'})
            self.assertNotIn(SECRET.decode().strip(), json.dumps(result))

    def test_actual_generated_wire_calls_safe_entry_on_binding_failure(self):
        value = config()
        raw = h.canonical(value)
        loader, encoded = h._wire(value, raw, h.sha(raw), b'', action='status',
                                  operation='synthetic-capture', backup=None, backup_completion_sha256=None)
        wire = json.loads(encoded)
        wire['configuration_sha256'] = '0' * 64
        result = subprocess.run([sys.executable, '-I', '-B', '-c', loader], input=h.canonical(wire),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b'')
        self.assertEqual(json.loads(result.stdout), {'status': 'ATTENTION', 'code': 'SNAPSHOT_PLAN_HASH_CHANGED',
            'automatic_replay_permitted': False, 'next_action': 'READ_SAME_OPERATION_AND_RECONCILE_NO_REPLAY'})


@contextmanager
def external_host(configured, *, service_changes=None, container_changes=None, extra_writers=None, metadata=None,
                  keep_deployment_python_path=False, namespace_run=None):
    """External observations only; actual host guard and filesystem hash run."""
    import pwd
    value = deepcopy(configured)
    # Local WSL Python is 3.14, not the deployment's fixed 3.11. This is a guard
    # unit test, not a validated deployment configuration or VM observation.
    executable = Path(sys.executable).resolve()
    value['python'] = {'path': '/usr/bin/python3.11' if keep_deployment_python_path else str(executable),
                       'sha256': h.sha(executable.read_bytes())}
    observed = {'id': h.TARGET['instance_id'], 'compartmentId': h.TARGET['compartment_id'],
                'canonicalRegionName': h.TARGET['region']}
    observed.update(metadata or {})
    services = {}
    for name in h.SERVICE_NAMES:
        installed = name != 'verifier' or value['mode'] == 'hosted'
        services[name] = {'Id': h.SERVICE_NAMES[name], 'LoadState': 'loaded' if installed else 'not-found',
            'ActiveState': 'inactive', 'SubState': 'dead', 'MainPID': '0',
            'FragmentPath': value['protected_sources'][name + '-unit']['path'] if installed else ''}
    for name, changes in (service_changes or {}).items():
        services[name].update(changes)
    mount_map = {'fox': {'/data': value['role_paths']['fox-data'],
        '/run/fox-opaf': value['protected_sources']['opaf-client']['path'],
        '/run/fox-native/profile.json': value['protected_sources']['baseline-fox-profile']['path']},
        'converter': {'/opt/forms2apex/outputs/jobs': value['role_paths']['converter-jobs'],
            '/home/converter/.dbtools': value['protected_sources']['sqlcl-connections']['path'],
            '/opt/forms2apex/wallet': value['protected_sources']['wallet']['path'],
            '/run/fox-target/profile.json': value['protected_sources']['baseline-target-profile']['path']}, 'tls': {}}
    containers = {name: {'Id': pin['id'], 'Image': pin['image'], 'Name': h.CONTAINER_NAMES[name],
        'State': {'Running': False, 'Pid': 0, 'Status': 'exited'},
        'Mounts': [{'Destination': destination, 'Source': source, 'RW': False}
                   for destination, source in mount_map[name].items()]} for name, pin in value['runtime'].items()}
    for name, changes in (container_changes or {}).items():
        containers[name].update(changes)
    extra_writers = [] if extra_writers is None else extra_writers
    by_id = {item['Id']: item for item in [*containers.values(), *extra_writers]}
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        if 'unshare' in argv and namespace_run is not None:
            return namespace_run(argv, kwargs)
        if 'systemctl' in Path(argv[0]).name:
            name = next(name for name, unit in h.SERVICE_NAMES.items() if unit in argv)
            raw = '\n'.join(key + '=' + item for key, item in services[name].items()).encode() + b'\n'
        elif 'inspect' in argv:
            raw = json.dumps([by_id[argv[-1]]]).encode()
        elif 'ps' in argv:
            raw = ('\n'.join(item['Id'] for item in extra_writers) + ('\n' if extra_writers else '')).encode()
        else:
            raise AssertionError('Unexpected external command: ' + repr(argv))
        return subprocess.CompletedProcess(argv, 0, raw, b'')

    def urlopen(request, timeout):
        assert request.full_url == 'http://169.254.169.254/opc/v2/instance/'
        assert request.get_header('Authorization') == 'Bearer Oracle' and timeout == 5
        return io.BytesIO(json.dumps(observed).encode())

    with patch.object(h.subprocess, 'run', side_effect=run), \
         patch.object(h.urllib.request, 'urlopen', side_effect=urlopen), \
         patch.object(pwd, 'getpwuid', return_value=SimpleNamespace(pw_name='opc')):
        yield value, calls


@unittest.skipUnless(os.name == 'posix' and os.getuid() == os.getgid() == 1000,
                     'Guard unit tests use actual local unprivileged POSIX uid1000.')
class HostGuardTests(unittest.TestCase):
    def test_stopped_hosted_and_uninstalled_baseline_observations(self):
        for mode in ('hosted', 'pre-hosted-g'):
            with external_host(config(mode)) as (value, calls):
                result = h._host_guard(value)
                self.assertEqual(result['target'], h.TARGET)
                self.assertEqual(result['runtime'], value['runtime'])
                self.assertTrue(any('systemctl' in arg for call in calls for arg in call))
                self.assertFalse(any(action in call for call in calls for action in ('stop', 'start', 'restart', 'create', 'run')))

    def test_active_or_unknown_host_verifier_blocks(self):
        for changes in ({'ActiveState': 'active', 'SubState': 'running', 'MainPID': '123'},
                        {'MainPID': '123'}, {'LoadState': 'not-found'}, {'FragmentPath': '/changed/unit'}):
            with self.subTest(changes=changes), external_host(config(), service_changes={'verifier': changes}) as (value, calls):
                with self.assertRaises(h.SnapshotOperationError):
                    h._host_guard(value)

    def test_prehosted_mode_rejects_preexisting_host_service(self):
        with external_host(config('pre-hosted-g'), service_changes={'verifier': {'LoadState': 'loaded'}}) as (value, _):
            with self.assertRaisesRegex(h.SnapshotOperationError, 'SNAPSHOT_HOSTED_WRITER_ALREADY_INSTALLED'):
                h._host_guard(value)

    def test_wrong_imds_target_stops_before_podman(self):
        with external_host(config(), metadata={'compartmentId': 'different-compartment'}) as (value, calls):
            with self.assertRaisesRegex(h.SnapshotOperationError, 'SNAPSHOT_EXACT_JSN_REQUIRED'):
                h._host_guard(value)
            self.assertEqual(calls, [])

    def test_any_expected_container_still_running_blocks(self):
        for name in h.CONTAINER_NAMES:
            with self.subTest(container=name), external_host(config(), container_changes={name:
                    {'State': {'Running': True, 'Pid': 99, 'Status': 'running'}}}) as (value, _):
                with self.assertRaisesRegex(h.SnapshotOperationError, 'SNAPSHOT_EXACT_STOPPED_CONTAINERS_REQUIRED'):
                    h._host_guard(value)

    def test_other_container_writing_any_backed_root_blocks(self):
        value = config()
        roots = [*value['role_paths'].values(), *(item['path'] for item in value['protected_sources'].values()), value['output_root']]
        for root in roots:
            writer = {'Id': '9' * 64, 'State': {'Running': True}, 'Mounts': [{'RW': True, 'Source': root}]}
            with self.subTest(root=root), external_host(value, extra_writers=[writer]) as (prepared, _):
                with self.assertRaisesRegex(h.SnapshotOperationError, 'SNAPSHOT_OTHER_WRITER_MOUNT_PRESENT'):
                    h._host_guard(prepared)

    def test_readonly_unrelated_container_is_permitted(self):
        value = config()
        writer = {'Id': '9' * 64, 'State': {'Running': True},
                  'Mounts': [{'RW': False, 'Source': value['role_paths']['converter-jobs']}]}
        with external_host(value, extra_writers=[writer]) as (prepared, _):
            self.assertEqual(h._host_guard(prepared)['target'], h.TARGET)

    def test_missing_or_changed_mount_blocks(self):
        with external_host(config(), container_changes={'fox': {'Mounts': []}}) as (value, _):
            with self.assertRaisesRegex(h.SnapshotOperationError, 'SNAPSHOT_ROLE_MOUNT_CHANGED'):
                h._host_guard(value)


def rootless_namespace():
    if os.name != 'posix' or os.getuid() != 0 or os.getgid() != 0:
        return False
    return all(Path('/proc/self/' + kind + '_map').read_text().splitlines()[0].split() == ['0', '1000', '1']
               for kind in ('uid', 'gid'))


@unittest.skipUnless(rootless_namespace(), 'Actual isolated rootless namespace required; no identity/privacy mock.')
class NamespaceAssemblyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fox-hosted-snapshot-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.config = config(base=str(self.root))
        for value in self.config['role_paths'].values():
            Path(value).mkdir(parents=True, mode=0o700)
        Path(self.config['output_root']).mkdir(mode=0o700)
        protected = self.root / 'protected'; protected.mkdir(mode=0o700)
        for key, value in self.config['protected_sources'].items():
            destination = Path(value['path'])
            if value['kind'] == 'directory':
                destination.mkdir(mode=0o700)
                destination = destination / '.synthetic-retained'
            destination.write_bytes(SECRET if key == 'admin-secret' else ('synthetic:' + key).encode())
            destination.chmod(0o600)
        database = Path(self.config['role_paths']['fox-data']) / 'fox.sqlite3'
        with closing(sqlite3.connect(database)) as connection, connection:
            connection.executescript("CREATE TABLE projects(id TEXT PRIMARY KEY); INSERT INTO projects VALUES('synthetic');")
        database.chmod(0o600)
        jobs = Path(self.config['role_paths']['converter-jobs'])
        (jobs / '.native-schema').mkdir(mode=0o700)
        (jobs / '.native-schema/identity.json').write_bytes(b'original-registry')
        (jobs / '.native-schema-index.json').write_bytes(b'original-registry')
        self.stage = Path(self.config['output_root']) / 'capture-one'; self.stage.mkdir(mode=0o700)
        self.packet = dict(packet(self.config, operation=self.stage.name), stage=str(self.stage))

    def completion(self, stage, action, result, *, backup=None, backup_sha=None):
        """Authored outer/exit fixture bound to actual engine output.

        The exit observation is synthetic in these receipt-validator tests;
        actual child exit is proven separately by HostEntryIntegrationTests.
        """
        config_sha = h.sha(h.canonical(self.config))
        intent = {'action': action, 'operation': stage.name, 'configuration_sha256': config_sha,
                  'backup': str(backup) if backup is not None else None, 'backup_completion_sha256': backup_sha}
        receipt = {'schema_version': 1, 'scope': 'fox-hosted-snapshot-completion-v1',
            'action': action, 'configuration_sha256': config_sha, 'operation': stage.name, 'result': result,
            'completed_at_utc': '2026-10-27T00:00:00+00:00', 'live_data_restored': False,
            'services_changed': False, 'opaf_repository_recovery_proven': False, 'automatic_replay_permitted': False}
        observation = {'scope': 'fox-stopped-writer-observation-v1', 'target': self.config['target'],
                       'runtime': self.config['runtime'], 'synthetic_guard_fixture': True}
        receipt['writer_observations_sha256'] = {}
        for name in ('before.json', 'after.json'):
            content = h.canonical(observation)
            (stage / name).write_bytes(content); (stage / name).chmod(0o600)
            receipt['writer_observations_sha256'][name] = h.sha(content)
        worker_raw = (stage / 'namespace-worker.json').read_bytes()
        work_raw = (stage / 'namespace-work-result.json').read_bytes()
        exited = {'schema_version': 1, 'scope': 'fox-snapshot-namespace-exit-observation-v1',
            'worker_sha256': h.sha(worker_raw), 'work_result_sha256': h.sha(work_raw),
            'launcher_returncode': 0, 'observed_by': 'synchronous_host_subprocess'}
        (stage / 'namespace-worker-exit.json').write_bytes(h.canonical(exited))
        (stage / 'namespace-worker-exit.json').chmod(0o600)
        receipt['worker_evidence_sha256'] = {'namespace-worker.json': h.sha(worker_raw),
            'namespace-work-result.json': h.sha(work_raw), 'namespace-worker-exit.json': h.sha(h.canonical(exited))}
        for name, value in (('intent.json', intent), ('completion.json', receipt)):
            (stage / name).write_bytes(h.canonical(value)); (stage / name).chmod(0o600)
        return receipt

    def completed_capture(self):
        result = h._worker(self.packet, s)
        return self.completion(self.stage, 'capture', result)

    def test_actual_protected_copy_and_complete_snapshot_roundtrip(self):
        original = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        result = h._worker(self.packet, s)
        self.assertEqual(result['status'], 'BACKUP_VERIFIED')
        self.assertEqual(result['result']['roles'], sorted(s.ROLES))
        self.assertNotIn(SECRET.decode().strip(), json.dumps(result))
        for path, raw in original.items():
            self.assertEqual(path.read_bytes(), raw)
        restore = Path(self.config['output_root']) / 'restore-one'; restore.mkdir(mode=0o700)
        restored = h._worker(dict(self.packet, action='restore', operation=restore.name,
                                 stage=str(restore), backup=str(self.stage / 'snapshot')), s)
        self.assertEqual(restored['status'], 'RESTORE_TEST_PASSED')
        self.assertEqual((restore / 'restored-copy/restored/protected-config/admin-secret').read_bytes(), SECRET)
        self.assertEqual((restore / 'restored-copy/restored/converter-jobs/.native-schema-index.json').read_bytes(), b'original-registry')
        self.assertFalse(restored['result']['live_data_restored'])

    def test_same_capture_never_replays_or_replaces(self):
        h._worker(self.packet, s)
        before = {p.relative_to(self.stage).as_posix(): p.read_bytes() for p in self.stage.rglob('*') if p.is_file()}
        with self.assertRaises((s.SnapshotError, FileExistsError)):
            h._worker(self.packet, s)
        self.assertEqual(before, {p.relative_to(self.stage).as_posix(): p.read_bytes() for p in self.stage.rglob('*') if p.is_file()})

    def test_protected_file_expected_hash_blocks_before_copy(self):
        changed = deepcopy(self.config)
        changed['protected_sources']['admin-secret']['sha256'] = '0' * 64
        with self.assertRaisesRegex(h.SnapshotOperationError, 'SNAPSHOT_PROTECTED_FILE_CHANGED'):
            h._worker(dict(packet(changed, operation=self.stage.name), stage=str(self.stage)), s)
        self.assertEqual({p.name for p in self.stage.iterdir()}, {'namespace-worker.json'})

    def test_protected_symlink_never_followed(self):
        target = Path(self.config['protected_sources']['wallet']['path']) / 'bad-link'
        target.symlink_to(Path(self.config['protected_sources']['admin-secret']['path']))
        with self.assertRaises(s.SnapshotError):
            h._worker(self.packet, s)
        self.assertEqual({p.name for p in self.stage.iterdir()}, {'namespace-worker.json'})

    def test_exact_outer_completion_binds_actual_inner_snapshot(self):
        receipt = self.completed_capture()
        checked = h._verified_completion(s, self.stage, self.config,
            h.sha(h.canonical(self.config)), expected_sha=h.sha(h.canonical(receipt)))
        self.assertEqual(checked, receipt)

    def test_outer_completion_cannot_borrow_different_inner_hash(self):
        receipt = self.completed_capture()
        receipt['result']['result']['archive_sha256'] = '0' * 64
        (self.stage / 'completion.json').write_bytes(h.canonical(receipt))
        with self.assertRaisesRegex(h.SnapshotOperationError, 'SNAPSHOT_WORKER_EVIDENCE_CHANGED'):
            h._verified_completion(s, self.stage, self.config, h.sha(h.canonical(self.config)))

    def test_outer_completion_expected_sha_cannot_be_refreshed(self):
        receipt = self.completed_capture()
        with self.assertRaisesRegex(h.SnapshotOperationError, 'SNAPSHOT_TRUSTED_BACKUP_REQUIRED'):
            h._verified_completion(s, self.stage, self.config,
                h.sha(h.canonical(self.config)), expected_sha='0' * 64)

    def test_status_rechecks_original_protected_inventory(self):
        self.completed_capture()
        (self.stage / 'protected-source-inventory.json').write_bytes(b'{}\n')
        with self.assertRaisesRegex(h.SnapshotOperationError, 'SNAPSHOT_INNER_BACKUP_BINDING_CHANGED'):
            h._verified_completion(s, self.stage, self.config, h.sha(h.canonical(self.config)))

    def test_restore_completion_rechecks_every_restored_byte(self):
        capture = self.completed_capture()
        restore = Path(self.config['output_root']) / 'restore-one'; restore.mkdir(mode=0o700)
        result = h._worker(dict(self.packet, action='restore', operation=restore.name,
                               stage=str(restore), backup=str(self.stage / 'snapshot')), s)
        receipt = self.completion(restore, 'restore', result, backup=self.stage / 'snapshot',
                                  backup_sha=h.sha(h.canonical(capture)))
        self.assertEqual(h._verified_completion(s, restore, self.config, h.sha(h.canonical(self.config))), receipt)
        (restore / 'restored-copy/restored/protected-config/admin-secret').write_bytes(b'changed')
        with self.assertRaisesRegex(h.SnapshotOperationError, 'SNAPSHOT_RESTORED_CONTENT_CHANGED'):
            h._verified_completion(s, restore, self.config, h.sha(h.canonical(self.config)))

    def test_capture_intent_cannot_be_changed_into_restore(self):
        self.completed_capture()
        intent = json.loads((self.stage / 'intent.json').read_bytes())
        intent['action'] = 'restore'
        (self.stage / 'intent.json').write_bytes(h.canonical(intent))
        with self.assertRaisesRegex(h.SnapshotOperationError, 'SNAPSHOT_INTENT_CHANGED'):
            h._verified_completion(s, self.stage, self.config, h.sha(h.canonical(self.config)))

    def test_writer_observation_tamper_blocks_status(self):
        self.completed_capture()
        (self.stage / 'after.json').write_bytes(b'{}\n')
        with self.assertRaisesRegex(h.SnapshotOperationError, 'SNAPSHOT_WRITER_EVIDENCE_CHANGED'):
            h._verified_completion(s, self.stage, self.config, h.sha(h.canonical(self.config)))

    def test_worker_records_actual_identity_and_return_but_not_exit(self):
        result = h._worker(self.packet, s)
        worker_raw = (self.stage / 'namespace-worker.json').read_bytes()
        worker = h.parse(worker_raw)
        self.assertEqual(worker['identity'], h._process_identity(os.getpid()))
        self.assertEqual(worker['operation'], self.stage.name)
        self.assertEqual(worker['configuration_sha256'], self.packet['configuration_sha256'])
        returned = h.parse((self.stage / 'namespace-work-result.json').read_bytes())
        self.assertEqual(returned['worker_sha256'], h.sha(worker_raw))
        self.assertEqual(returned['result_sha256'], h.sha(h.canonical(result)))
        self.assertTrue(returned['work_returned'])
        self.assertFalse(returned['process_exit_confirmed'])
        self.assertFalse((self.stage / 'namespace-worker-exit.json').exists())

    def test_worker_identity_tamper_blocks_outer_completion(self):
        self.completed_capture()
        worker = h.parse((self.stage / 'namespace-worker.json').read_bytes())
        worker['identity']['start_ticks'] += 1
        (self.stage / 'namespace-worker.json').write_bytes(h.canonical(worker))
        with self.assertRaisesRegex(h.SnapshotOperationError, 'SNAPSHOT_WORKER_EVIDENCE_CHANGED'):
            h._verified_completion(s, self.stage, self.config, h.sha(h.canonical(self.config)))

    def test_work_result_or_exit_tamper_blocks_outer_completion(self):
        self.completed_capture()
        for name in ('namespace-work-result.json', 'namespace-worker-exit.json'):
            target = self.stage / name
            saved = target.read_bytes()
            target.write_bytes(b'{}\n')
            with self.subTest(name=name), self.assertRaisesRegex(h.SnapshotOperationError, 'SNAPSHOT_WORKER_EVIDENCE_CHANGED'):
                h._verified_completion(s, self.stage, self.config, h.sha(h.canonical(self.config)))
            target.write_bytes(saved)

    def test_measurement_uses_metadata_only_and_writes_nothing(self):
        before = {p.relative_to(self.root).as_posix(): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        with patch.object(s, '_read', side_effect=AssertionError('SOURCE_CONTENT_READ_FORBIDDEN')):
            result = h._worker(dict(self.packet, action='measure'), s)
        self.assertEqual(result['status'], 'CAPACITY_ESTIMATE')
        self.assertTrue(result['fits_current_limits'])
        self.assertFalse(result['source_contents_read'])
        self.assertFalse(result['files_written'])
        self.assertFalse(result['consistent_capture_proven'])
        self.assertNotIn(SECRET.decode().strip(), json.dumps(result))
        self.assertEqual(before, {p.relative_to(self.root).as_posix(): p.read_bytes() for p in self.root.rglob('*') if p.is_file()})

    def test_capacity_overflow_is_reported_not_silently_truncated(self):
        large = Path(self.config['role_paths']['converter-jobs']) / 'synthetic-large'
        with large.open('wb') as stream:
            stream.truncate(s.MAX_MEMBER_BYTES + 1)
        result = h._worker(dict(self.packet, action='measure'), s)
        self.assertFalse(result['fits_current_limits'])
        self.assertIn('member_bytes', result['exceeded_limits'])
        self.assertEqual(result['next_action'], 'REVIEW_BOUNDED_CAPACITY_CHANGE_NO_AUTOMATIC_EXPANSION')
        self.assertEqual(list(self.stage.iterdir()), [])


class RollbackTests(unittest.TestCase):
    def test_unknown_duplicate_or_malformed_source_identity_blocks_rollback(self):
        raw = (ROOT / 'work/product-history-transport-bind-20261019a/operator-release/current-release-manifest.json').read_bytes()
        for source in (b'{"conversion_profile":"native-project-v2"}',
                       b'{"conversion_profile":"native-project-v1","conversion_profile":"native-table-form-v1"}',
                       b'[]', b'null', b'{broken'):
            with self.subTest(source=source), tempfile.TemporaryDirectory(prefix='fox-rollback-') as temporary:
                root = Path(temporary)
                job = root / 'jobs/fox-synthetic'; job.mkdir(parents=True)
                (job / 'source-snapshot.json').write_bytes(source)
                with self.assertRaises(h.SnapshotOperationError):
                    h.require_project_aware_rollback(root, raw)

    def test_retained_g_refuses_project_history(self):
        raw = (ROOT / 'work/product-history-transport-bind-20261019a/operator-release/current-release-manifest.json').read_bytes()
        with tempfile.TemporaryDirectory(prefix='fox-rollback-') as temporary:
            root = Path(temporary)
            job = root / 'jobs/fox-synthetic'; job.mkdir(parents=True)
            (job / 'source-snapshot.json').write_text(json.dumps({'conversion_profile': 'native-project-v1'}))
            with self.assertRaisesRegex(h.SnapshotOperationError, 'SNAPSHOT_LEGACY_ROLLBACK_BLOCKED_BY_PROJECT_HISTORY'):
                h.require_project_aware_rollback(root, raw)

    def test_project_cache_marker_cannot_be_hidden_by_legacy_snapshot(self):
        raw = (ROOT / 'work/product-history-transport-bind-20261019a/operator-release/current-release-manifest.json').read_bytes()
        with tempfile.TemporaryDirectory(prefix='fox-rollback-') as temporary:
            root = Path(temporary)
            job = root / 'jobs/fox-synthetic'; job.mkdir(parents=True)
            (job / 'source-snapshot.json').write_text(json.dumps({'conversion_profile': 'native-table-form-v1'}))
            (job / 'native-project-pipeline').mkdir()
            with self.assertRaisesRegex(h.SnapshotOperationError, 'SNAPSHOT_LEGACY_ROLLBACK_BLOCKED_BY_PROJECT_HISTORY'):
                h.require_project_aware_rollback(root, raw)

    def test_empty_history_is_not_activation_permission(self):
        raw = (ROOT / 'work/product-history-transport-bind-20261019a/operator-release/current-release-manifest.json').read_bytes()
        with tempfile.TemporaryDirectory(prefix='fox-rollback-') as temporary:
            root = Path(temporary); (root / 'jobs').mkdir()
            result = h.require_project_aware_rollback(root, raw)
            self.assertFalse(result['activation_authorized'])
            self.assertFalse(result['data_restore_authorized'])


@unittest.skipUnless(os.name == 'posix', 'Actual Linux proc identity required.')
class ProcessObservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fox-snapshot-process-')
        self.addCleanup(self.temp.cleanup)
        self.stage = Path(self.temp.name); self.stage.chmod(0o700)
        self.config_sha = 'a' * 64

    def marker(self, identity=None, **changes):
        value = {'schema_version': 1, 'scope': 'fox-snapshot-namespace-worker-v1',
            'identity': h._process_identity(os.getpid()) if identity is None else identity,
            'operation': self.stage.name, 'action': 'capture', 'configuration_sha256': self.config_sha}
        value.update(changes)
        target = self.stage / 'namespace-worker.json'
        target.write_bytes(h.canonical(value)); target.chmod(0o600)
        return value

    def observe(self):
        return h._worker_observation(s, self.stage, self.config_sha)

    def test_missing_marker_is_not_exit_or_retry_permission(self):
        self.assertEqual(self.observe(), {'state': 'NO_WORKER_IDENTITY_OBSERVED', 'exit_confirmed': False})

    def test_actual_matching_process_is_observed_without_exit_claim(self):
        self.marker()
        self.assertEqual(self.observe(), {'state': 'MATCHING_PROCESS_PRESENT',
                                          'pid': os.getpid(), 'exit_confirmed': False})

    def test_actual_child_exit_is_absent_not_inferred_success(self):
        child = subprocess.Popen([sys.executable, '-B', '-c', 'import sys;sys.stdin.buffer.read()'],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.marker(h._process_identity(child.pid))
            self.assertEqual(self.observe()['state'], 'MATCHING_PROCESS_PRESENT')
            out, err = child.communicate(input=b'', timeout=15)
            self.assertEqual((child.returncode, out, err), (0, b'', b''))
            self.assertEqual(self.observe(), {'state': 'RECORDED_PROCESS_ABSENT',
                                              'pid': child.pid, 'exit_confirmed': False})
        finally:
            if child.poll() is None:
                child.terminate(); child.communicate(timeout=15)

    def test_different_start_ticks_are_not_matching_or_successful_exit(self):
        identity = h._process_identity(os.getpid()); identity['start_ticks'] += 1
        self.marker(identity)
        self.assertEqual(self.observe(), {'state': 'RECORDED_IDENTITY_NO_LONGER_PRESENT',
                                          'pid': os.getpid(), 'exit_confirmed': False})

    def test_other_operation_config_or_invalid_identity_is_rejected(self):
        for changes in ({'operation': 'another-operation'}, {'configuration_sha256': 'b' * 64},
                        {'action': 'replay'}, {'identity': {'pid': True, 'start_ticks': 1, 'boot_id': 'a' * 36}}):
            with self.subTest(changes=changes):
                self.marker(**changes)
                with patch.object(h, '_process_identity', side_effect=AssertionError('UNBOUND_PROCESS_OBSERVATION')):
                    with self.assertRaises(h.SnapshotOperationError):
                        self.observe()


@unittest.skipUnless(os.name == 'posix' and os.getuid() == os.getgid() == 1000
                     and os.environ.get('FOX_SNAPSHOT_TEST_NAMESPACE', '').startswith('/tmp/fox-snapshot-namespace-'),
                     'Opt-in existing isolated Podman namespace directory required.')
class HostEntryIntegrationTests(unittest.TestCase):
    """Full adapter/worker chain; only external host observations are authored.

    The explicit test plan pins the existing local Python3.14 executable. No
    guard, validator or file read is patched. This is actual copying/namespace/
    SQLite evidence, not a claim of Oracle Linux3.11 deployment validation.
    """
    setUp = NamespaceAssemblyTests.setUp

    @contextmanager
    def host_boundary(self, *, services=None):
        namespace = Path(os.environ['FOX_SNAPSHOT_TEST_NAMESPACE'])
        self.assertTrue(namespace.is_dir())
        self.assertEqual(namespace.stat().st_uid, os.getuid())
        actual_run = subprocess.run
        executable = Path(sys.executable).resolve()

        def namespace_run(argv, kwargs):
            self.assertEqual(argv[:3], ['/usr/bin/podman', 'unshare', str(executable)])
            self.assertEqual(argv[3:6], ['-I', '-B', '-c'])
            args = ['/usr/bin/podman', '--log-level=error', '--runroot', str(namespace / 'run'),
                    '--root', str(namespace / 'store'), 'unshare', str(executable), *argv[3:]]
            return actual_run(args, **kwargs, env={**os.environ, 'XDG_RUNTIME_DIR': str(namespace),
                                                  'PYTHONDONTWRITEBYTECODE': '1'})

        with external_host(self.config, namespace_run=namespace_run, service_changes=services) as (value, calls):
            self.config = value
            yield value, calls

    def entry(self, value, action, operation, **extra):
        selected = {**packet(value, action=action, operation=operation), **extra}
        return h._host_entry(selected, s, Path(h.__file__).read_bytes(), Path(s.__file__).read_bytes())

    def test_actual_capture_status_restore_and_replay_refusal(self):
        original = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        with self.host_boundary() as (value, calls):
            captured = self.entry(value, 'capture', 'complete-capture')
            self.assertEqual(captured['status'], 'COMPLETE')
            captured_stage = Path(value['output_root']) / 'complete-capture'
            exited = h.parse((captured_stage / 'namespace-worker-exit.json').read_bytes())
            self.assertEqual(exited['launcher_returncode'], 0)
            self.assertEqual(exited['observed_by'], 'synchronous_host_subprocess')
            worker = h.parse((captured_stage / 'namespace-worker.json').read_bytes())
            self.assertNotEqual(worker['identity']['pid'], os.getpid())
            observation = h._worker_observation(s, captured_stage, h.sha(h.canonical(value)))
            self.assertEqual(observation['state'], 'RECORDED_PROCESS_ABSENT')
            self.assertFalse(observation['exit_confirmed'])
            self.assertEqual(self.entry(value, 'status', 'complete-capture'), captured)
            backup = Path(value['output_root']) / 'complete-capture/snapshot'
            restored = self.entry(value, 'restore', 'complete-restore', backup=str(backup),
                                  backup_completion_sha256=captured['completion_sha256'])
            self.assertEqual(restored['status'], 'COMPLETE')
            self.assertEqual(self.entry(value, 'status', 'complete-restore'), restored)
            self.assertEqual((Path(value['output_root']) / 'complete-restore/restored-copy/restored/protected-config/admin-secret').read_bytes(), SECRET)
            self.assertFalse(restored['receipt']['live_data_restored'])
            with self.assertRaises(s.SnapshotError):
                self.entry(value, 'capture', 'complete-capture')
            self.assertEqual(sum('unshare' in call for call in calls), 2)
        for path, raw in original.items():
            self.assertEqual(path.read_bytes(), raw)
        self.assertNotIn(SECRET.decode().strip(), json.dumps(captured))
        self.assertNotIn(SECRET.decode().strip(), json.dumps(restored))

    def test_actual_status_does_not_require_restart_or_stopped_services(self):
        with self.host_boundary() as (value, _):
            captured = self.entry(value, 'capture', 'complete-capture')
        active = {'fox': {'ActiveState': 'active', 'SubState': 'running', 'MainPID': '123'},
                  'verifier': {'ActiveState': 'active', 'SubState': 'running', 'MainPID': '456'}}
        with self.host_boundary(services=active) as (value, calls):
            self.assertEqual(self.entry(value, 'status', 'complete-capture'), captured)
            self.assertEqual(calls, [])

    def test_actual_measure_and_partial_status_perform_no_mutations(self):
        with self.host_boundary() as (value, calls):
            before = {p.relative_to(self.root).as_posix(): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
            measured = self.entry(value, 'measure', 'capacity-check')
            self.assertEqual(measured['status'], 'CAPACITY_ESTIMATE')
            self.assertFalse(measured['files_written'])
            status = self.entry(value, 'status', self.stage.name)
            self.assertEqual(status['status'], 'ATTENTION')
            self.assertFalse(status['automatic_replay_permitted'])
            self.assertEqual(before, {p.relative_to(self.root).as_posix(): p.read_bytes() for p in self.root.rglob('*') if p.is_file()})
            self.assertEqual(sum('unshare' in call for call in calls), 1)


@unittest.skipUnless(os.name == 'posix' and os.getuid() > 0,
                     'Actual unprivileged POSIX fd/ownership fixture required.')
class LeaseLifetimeTests(unittest.TestCase):
    def test_actual_lease_fd_lifetime_and_wrong_release_block_capture_authority(self):
        import fcntl
        from qa.operator import runtime_provider as runtime
        from qa.operator.failed_verification import HeldOperatorLock, _LEASE_KEY, FailureResolutionError
        from qa.operator.tests.hosted_provider_fixture import create_hosted_fixture
        with tempfile.TemporaryDirectory(prefix='fox-snapshot-lease-') as temporary:
            root = Path(temporary); root.chmod(0o700)
            provider_document = create_hosted_fixture(root / 'installation')
            provider_document.update(schema_version=2, scope=runtime.IMAGE_SCOPE,
                                     images={'fox': 'sha256:' + '1' * 64, 'converter': 'sha256:' + '2' * 64})
            provider_raw = h.canonical(provider_document)
            # Actual pure provider validation; only selected-provider lookup is
            # redirected to these real synthetic private files. No hosted
            # factory, IMDS admission or service readiness success is claimed.
            runtime.configuration_document(provider_raw, expected_sha256=h.sha(provider_raw))
            provider = runtime.HostedProvider(provider_raw, h.sha(provider_raw))
            value = config(base=str(root / 'snapshot'))
            value['provider_configuration_sha256'] = provider.sha256
            value['role_paths']['operator-state'] = provider_document['state_root']
            value['protected_sources']['admin-secret']['path'] = provider_document['admin_secret_file']
            raw = h.canonical(value)
            journal = provider.path('journal') / value['operator_release_sha256'][:16]
            journal.mkdir(mode=0o700)
            lock = journal / 'worker.lock'; lock.write_bytes(b'0'); lock.chmod(0o600)
            with lock.open('r+b') as stream:
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                lease = HeldOperatorLock(_LEASE_KEY, value['operator_release_sha256'], journal, stream)
                authority = h.CaptureAuthority(h._KEY, raw, h.sha(raw), lease, b'synthetic-only-release')
                with patch.object(runtime, 'selected_hosted', return_value=provider):
                    self.assertEqual(authority.require_active(), value)
                    with lock.open('r+b') as second:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(second.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    with self.assertRaises(FailureResolutionError):
                        lease.require_active('0' * 64, journal)
                    lease._active = False
                    with self.assertRaises(FailureResolutionError):
                        authority.require_active()
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            with patch.object(runtime, 'selected_hosted', return_value=provider):
                with self.assertRaises(FailureResolutionError):
                    authority.require_active()


if __name__ == '__main__':
    unittest.main()
