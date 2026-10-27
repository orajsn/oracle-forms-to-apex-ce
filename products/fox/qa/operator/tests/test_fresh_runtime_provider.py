"""Actual private source/S0/F selection; external host I/O is synthetic only.

No OCI, SSH, Oracle, real container, credential or service operation occurs.
Each POSIX case runs in a new -I -B process with a source-only temporary copy.
"""
from contextlib import contextmanager, redirect_stdout, redirect_stderr
from copy import deepcopy
from dataclasses import FrozenInstanceError
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.request


ROOT = Path(__file__).resolve().parents[3]
POSIX = os.name == 'posix' and hasattr(os, 'geteuid') and os.geteuid() > 0


@contextmanager
def host_boundary(runtime, provider, config, *, mutate=None, during=None):
    roles = config['runtime']['roles']
    inspected = []
    for index, name in enumerate(('fox', 'converter', 'opaf'), 1):
        role = roles[name]
        inspected.append({'Id': str(index) * 64, 'Name': '/' + role['name'], 'Image': role['image'],
            'State': {'Running': True}, 'Config': {'User': role['user']},
            'HostConfig': {'ReadonlyRootfs': role['read_only_rootfs']},
            'Mounts': [{'Type': 'bind', 'Source': row['source'], 'Destination': row['destination'],
                        'RW': not row['read_only']} for row in role['mounts']]})
    inspected[0]['HostConfig']['Tmpfs'] = {'/tmp': 'rw,noexec,nosuid,nodev,size=64m,mode=1777'}
    inspected[0]['Mounts'].append({'Type': 'tmpfs', 'Source': '', 'Destination': '/tmp', 'RW': True})
    if mutate:
        mutate(inspected)
    target = config['target_profile']['oci']
    events = []

    def imds(request, *, timeout):
        assert request.full_url == 'http://169.254.169.254/opc/v2/instance/'
        assert request.get_header('Authorization') == 'Bearer Oracle' and timeout == 5
        events.append('imds')
        return io.BytesIO(json.dumps({'id': target['instance_id'], 'compartmentId': target['compartment_id'],
            'canonicalRegionName': target['region'], 'regionInfo': {'regionIdentifier': target['region']}}).encode())

    def execute(args, **options):
        if args[:3] == ['/usr/bin/podman', 'inspect', '--']:
            assert args[3:] == [roles[name]['name'] for name in ('fox', 'converter', 'opaf')]
            assert options == {'stdout': subprocess.PIPE, 'stderr': subprocess.PIPE, 'timeout': 20}
            events.append(tuple(args))
            if during:
                during()
            return subprocess.CompletedProcess(args, 0, json.dumps(inspected).encode(), b'')
        assert args[:4] == [config['python']['path'], '-I', '-B', '-c'] and len(args) == 5
        assert options['cwd'] == '/' and options['timeout'] == 40
        framed, data = options['input'].split(b'\n', 1)
        program = base64.b64decode(framed, validate=True).decode()
        assert program == runtime.HOST_IDENTITY_GUARD + '\n' + runtime.fresh_mount_program()
        stdout, stderr = io.StringIO(), io.StringIO()
        stdin = io.TextIOWrapper(io.BytesIO(data), encoding='utf-8')
        try:
            with patch.object(sys, 'stdin', stdin), redirect_stdout(stdout), redirect_stderr(stderr):
                exec(compile(program, '<synthetic-fresh-host-boundary>', 'exec'), {})
            return subprocess.CompletedProcess(args, 0, stdout.getvalue().encode(), stderr.getvalue().encode())
        except Exception:
            return subprocess.CompletedProcess(args, 1, b'', b'SYNTHETIC_EXTERNAL_FAILURE_WITHHELD')

    with patch.object(urllib.request, 'urlopen', side_effect=imds), patch.object(subprocess, 'run', side_effect=execute):
        yield events


def scenario(name, original):
    support = runpy.run_path(str(original / 'qa/operator/tests/test_fresh_backend.py'))
    with tempfile.TemporaryDirectory(prefix='frp-') as temporary:
        parent = Path(temporary); parent.chmod(0o700)
        source = parent / 'release'
        support['copy_source_closure'](original, source)
        fixture = support['Fixture'](parent, source)
        if name in ('positive_alternate', 'mount_alternate'):
            projected = deepcopy(fixture.values['projection'])
            projected['converter_endpoint'] = 'http://127.0.0.1:18973'
            fixture.put('projection', Path(fixture.refs['projection']['path']), projected)
            changed = deepcopy(fixture.values['provider'])
            changed['app_projection'] = fixture.refs['projection']
            changed['runtime']['converter_endpoint'] = projected['converter_endpoint']
            changed['runtime']['settings']['fox_origin'] = 'http://127.0.0.1:18173'
            for role in ('fox', 'converter', 'opaf'):
                changed['runtime']['roles'][role]['name'] += '-alternate'
            fixture.put('provider', Path(fixture.refs['provider']['path']), changed)
            release = deepcopy(fixture.values['release'])
            release['hosted_runtime_configuration_sha256'] = fixture.refs['provider']['sha256']
            fixture.put('release', Path(fixture.refs['release']['path']), release)
        backend = fixture.call()['backend_initialization']
        from qa.operator import runtime_provider as runtime
        config = fixture.values['provider']
        admin = Path(config['admin_secret_file'])
        # Allocate the synthetic private parent first; mkdir(parents=True)
        # otherwise creates intermediate directories using the ambient umask.
        admin.parent.mkdir(mode=0o700)
        # Only ordinary synthetic directories needed to inspect declared mounts.
        for role in config['runtime']['roles'].values():
            for mount in role['mounts']:
                path = Path(mount['source'])
                if not path.exists():
                    path.mkdir(mode=0o700, parents=True)

        def select():
            return runtime.configure_fresh(fixture.refs['provider'], fixture.refs['release'], backend, layout=fixture.layout)

        if name == 'prior_legacy_selection':
            assert runtime.hosted() is None
            before = support['snapshot'](parent)
            try:
                select()
            except runtime.ProviderError as error:
                assert str(error) == 'OPERATOR_RUNTIME_ALREADY_SELECTED'
            else:
                raise AssertionError('FRESH_SWITCHED_FROM_LEGACY')
            assert support['snapshot'](parent) == before
            return {'status': 'PASSED'}

        if name in ('source_drift', 'backend_drift', 'provider_mode', 'python_drift', 'admin_mode', 'admin_link'):
            if name == 'source_drift':
                path = source / 'fox/fox/worker.py'; path.write_bytes(path.read_bytes() + b'\n# synthetic drift\n')
            elif name == 'backend_drift':
                fixture.output.write_bytes(fixture.output.read_bytes() + b' ')
            elif name == 'provider_mode':
                Path(fixture.refs['provider']['path']).chmod(0o644)
            elif name in ('admin_mode', 'admin_link'):
                if name == 'admin_mode':
                    admin.write_bytes(b'SYNTHETIC_NEVER_READ'); admin.chmod(0o644)
                else:
                    admin.symlink_to(parent / 'synthetic-absent-secret')
            else:
                changed = deepcopy(config); changed['python']['sha256'] = '0' * 64
                fixture.put('provider', Path(fixture.refs['provider']['path']), changed)
            before = support['snapshot'](parent)
            with support['no_external_actions']():
                try:
                    select()
                except runtime.ProviderError:
                    pass
                else:
                    raise AssertionError('UNBOUND_FRESH_PROVIDER_SELECTED')
            assert runtime._selected is runtime._UNSELECTED
            assert support['snapshot'](parent) == before
            return {'status': 'PASSED'}

        before = support['snapshot'](parent)
        with support['no_external_actions'](), patch.object(sqlite3, 'connect', side_effect=AssertionError('NO_SQLITE_DURING_SELECTION')):
            assert select() == fixture.refs['provider']['sha256']
            provider = runtime.hosted()
            assert type(provider) is runtime.FreshHostedProvider
            projection = runtime.execution_runtime()
            assert projection['provider_configuration_sha256'] == fixture.refs['provider']['sha256']
            assert projection['release_sha256'] == fixture.refs['release']['sha256']
            assert projection['backend_initialization_sha256'] == backend['sha256']
            assert projection['installation_id'] == fixture.identity
            assert projection['runtime'] == config['runtime']
        assert support['snapshot'](parent) == before

        if name in ('positive', 'positive_alternate'):
            projection['runtime']['roles']['fox']['name'] = 'fox'
            assert runtime.execution_runtime()['runtime'] == config['runtime']
            try:
                provider.raw = b'{}'
            except FrozenInstanceError:
                pass
            else:
                raise AssertionError('FRESH_PROVIDER_MUTABLE')
            assert not admin.exists()
        elif name == 'reselection':
            with support['no_external_actions']():
                for call in (select, lambda: runtime.configure_hosted(b'{}\n', expected_sha256='0' * 64)):
                    try:
                        call()
                    except runtime.ProviderError as error:
                        assert str(error) == 'OPERATOR_RUNTIME_ALREADY_SELECTED'
                    else:
                        raise AssertionError('RUNTIME_RESELECTED')
        elif name == 'legacy_execution_refused':
            with support['no_external_actions']():
                for call in (lambda: provider.execute_host('print("legacy")', b'{}', timeout=1),
                             provider.admin_secret,
                             lambda: runtime.execute_host('print("legacy")', b'{}', timeout=1,
                                 legacy_argv=['must-not-call'], legacy_runner=lambda *a, **k: (_ for _ in ()).throw(AssertionError('LEGACY_FALLBACK')))):
                    try:
                        call()
                    except runtime.ProviderError as error:
                        assert str(error) == 'FRESH_BOUND_TRANSPORT_AND_ADMISSION_REQUIRED'
                    else:
                        raise AssertionError('UNADAPTED_EXECUTION_ALLOWED')
            assert not admin.exists()
        elif name == 'anchors_drift_after_selection':
            fixture.output.write_bytes(fixture.output.read_bytes() + b' ')
            with support['no_external_actions']():
                try:
                    runtime.execution_runtime()
                except runtime.ProviderError:
                    pass
                else:
                    raise AssertionError('STALE_PROJECTION_RETURNED')
        elif name.startswith('oci_'):
            target = config['target_profile']['oci']
            observed = {'database_id': target['database_id'], 'database_compartment_id': target['compartment_id'],
                'instance_id': target['instance_id'], 'instance_compartment_id': target['compartment_id'],
                'region': target['region'], 'database_lifecycle_state': 'AVAILABLE',
                'instance_lifecycle_state': 'RUNNING', 'database_db_name': 'JSNF2APEX'}
            if name == 'oci_wrong_target':
                observed['region'] = 'ap-singapore-1'
            if name == 'oci_stopped':
                observed['database_lifecycle_state'] = 'STOPPED'
            if name == 'oci_unknown_state':
                observed['database_lifecycle_state'] = 'UPDATING'
            def scope_response(instance, program, data, *, timeout):
                assert instance is provider and program == runtime._OCI_PROGRAM and timeout == 240
                packet = json.loads(data)
                assert packet['profile'] == config['target_profile']
                assert packet['require_database_available'] is (name != 'oci_stopped')
                for member, encoded in packet['sources'].items():
                    assert hashlib.sha256(base64.b64decode(encoded, validate=True)).hexdigest() == config['converter_sources'][member]
                if name == 'oci_anchor_drift':
                    fixture.output.write_bytes(fixture.output.read_bytes() + b' ')
                return json.dumps(observed).encode()
            with patch.object(runtime.HostedProvider, 'execute_host', scope_response), support['no_external_actions']():
                if name in ('oci_positive', 'oci_stopped'):
                    result = provider.oci_scope(require_database_available=name != 'oci_stopped')
                    assert result['database_state'] == observed['database_lifecycle_state']
                    assert result['compartment_id'] == target['compartment_id']
                else:
                    try:
                        provider.oci_scope(require_database_available=True)
                    except runtime.ProviderError:
                        pass
                    else:
                        raise AssertionError('UNBOUND_OCI_RESULT_ACCEPTED')
        elif name.startswith('mount_'):
            mutations = {
                'mount_name': lambda rows: rows[0].update(Name='/fox'),
                'mount_image': lambda rows: rows[1].update(Image='sha256:' + '0' * 64),
                'mount_user': lambda rows: rows[0]['Config'].update(User='0'),
                'mount_rootfs': lambda rows: rows[0]['HostConfig'].update(ReadonlyRootfs=False),
                'mount_stopped': lambda rows: rows[2]['State'].update(Running=False),
                'mount_rw': lambda rows: rows[0]['Mounts'][1].update(RW=True),
                'mount_source': lambda rows: rows[0]['Mounts'][0].update(Source=str(parent)),
                'mount_duplicate': lambda rows: rows[0]['Mounts'].__setitem__(1, deepcopy(rows[0]['Mounts'][0])),
                'mount_duplicate_id': lambda rows: rows[2].update(Id=rows[0]['Id']),
                'mount_private': lambda rows: rows[0]['Mounts'].append({'Type': 'bind', 'Source': str(admin.parent), 'Destination': '/unreviewed', 'RW': True}),
            }
            if name == 'mount_link':
                path = Path(config['runtime']['roles']['opaf']['mounts'][0]['source'])
                retained = parent / 'synthetic-retained-opaf-volume'
                path.rename(retained); path.symlink_to(retained, target_is_directory=True)
            during = (lambda: fixture.output.write_bytes(fixture.output.read_bytes() + b' ')) if name == 'mount_anchor_drift' else None
            with host_boundary(runtime, provider, config, mutate=mutations.get(name), during=during) as events:
                if name in ('mount_positive', 'mount_alternate'):
                    observed = provider.check_public_mounts()
                    assert observed['safe'] is True and set(observed['observed_roles']) == {'fox', 'converter', 'opaf'}
                else:
                    try:
                        provider.check_public_mounts()
                    except runtime.ProviderError:
                        pass
                    else:
                        raise AssertionError('UNSAFE_FRESH_MOUNTS_ACCEPTED')
                assert events[0] == 'imds' and len(events) == 2
                assert all(value not in events[1] for value in ('fox', 'forms2apex-mcp'))
            assert not admin.exists()
        else:
            raise AssertionError('UNKNOWN_SCENARIO')
        return {'status': 'PASSED', 'connected_admission': False, 'automatic_replay_permitted': False}


class FreshRuntimePureTests(unittest.TestCase):
    def test_import_is_inert_and_legacy_runtime_projection_is_absent(self):
        program = """import sys,pathlib,subprocess,socket,sqlite3\nfrom unittest.mock import patch\nr=pathlib.Path(sys.argv[1]);sys.path[:0]=[str(r),str(r/'fox'),str(r/'converter')]\ndef no(*a,**k):raise AssertionError('IMPORT_SIDE_EFFECT')\nwith patch.object(subprocess,'run',side_effect=no),patch.object(socket.socket,'connect',side_effect=no),patch.object(sqlite3,'connect',side_effect=no):\n from qa.operator import runtime_provider as m\n assert m._selected is m._UNSELECTED\n assert m.execution_runtime() is None\nprint('PASSED')\n"""
        result = subprocess.run([sys.executable, '-I', '-B', '-c', program, str(ROOT)], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'PASSED')

    @unittest.skipIf(POSIX, 'Windows/root rejection only')
    def test_non_posix_cannot_select_fresh(self):
        program = """import sys,pathlib\nr=pathlib.Path(sys.argv[1]);sys.path[:0]=[str(r),str(r/'fox'),str(r/'converter')]\nfrom qa.operator import runtime_provider as m\ntry:m.configure_fresh({}, {}, {}, layout={})\nexcept m.ProviderError as e:assert str(e)=='HOSTED_UNPRIVILEGED_POSIX_REQUIRED'\nelse:raise AssertionError('POSIX_FAKED')\nassert m._selected is m._UNSELECTED\nprint('PASSED')\n"""
        result = subprocess.run([sys.executable, '-I', '-B', '-c', program, str(ROOT)], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'PASSED')


@unittest.skipUnless(POSIX, 'Genuine nonroot POSIX source selection required')
class FreshRuntimePosixTests(unittest.TestCase):
    def run_scenario(self, name):
        result = subprocess.run([sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--scenario', name, str(ROOT)],
                                capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(json.loads(result.stdout)['status'], 'PASSED')


SCENARIOS = ('positive', 'positive_alternate', 'prior_legacy_selection', 'source_drift', 'backend_drift', 'provider_mode',
    'python_drift', 'admin_mode', 'admin_link', 'reselection', 'legacy_execution_refused', 'anchors_drift_after_selection',
    'oci_positive', 'oci_stopped', 'oci_wrong_target', 'oci_unknown_state', 'oci_anchor_drift',
    'mount_positive', 'mount_alternate', 'mount_name', 'mount_image', 'mount_user', 'mount_rootfs', 'mount_stopped',
    'mount_rw', 'mount_source', 'mount_duplicate', 'mount_duplicate_id', 'mount_private', 'mount_anchor_drift', 'mount_link')
for _name in SCENARIOS:
    def _test(self, name=_name):
        self.run_scenario(name)
    setattr(FreshRuntimePosixTests, 'test_' + _name, _test)


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--scenario':
        print(json.dumps(scenario(sys.argv[2], Path(sys.argv[3])), sort_keys=True))
    else:
        unittest.main()
