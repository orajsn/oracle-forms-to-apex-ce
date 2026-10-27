"""Real private files/processes; only external IMDS/Podman IO is synthetic.

Run with stdlib unittest on an unprivileged POSIX host for hosted checks.
Windows runs the inert-import, legacy framing and non-POSIX rejection checks.
No test performs an OCI call, SSH, DPAPI access or real Podman operation.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager, redirect_stdout, redirect_stderr
from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import urllib.request


ROOT = Path(__file__).resolve().parents[3]
for folder in (ROOT, ROOT / 'converter', ROOT / 'fox'):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

from qa.operator import runtime_provider as runtime
from qa.operator.tests.hosted_provider_fixture import (
    SYNTHETIC_ADMIN, canonical_bytes, configure_fixture, create_hosted_fixture, digest)


POSIX = os.name == 'posix' and hasattr(os, 'geteuid') and os.geteuid() > 0


@contextmanager
def external_host_boundary(provider, config, *, metadata=None, mount_sources=None,
                           podman_returncode=0, running=True):
    """Execute the generated guarded program; fake only external IO results."""
    target = config['target_profile']['oci']
    observed = {'id': target['instance_id'], 'compartmentId': target['compartment_id'],
                'canonicalRegionName': target['region'],
                'regionInfo': {'regionIdentifier': target['region']}, 'region': 'iad'}
    if metadata is not None:
        observed = metadata
    sources = mount_sources if mount_sources is not None else config['public_mount_roots']
    events, calls = [], []

    def metadata_read(request, *, timeout):
        events.append('imds')
        assert request.full_url == 'http://169.254.169.254/opc/v2/instance/'
        assert request.get_header('Authorization') == 'Bearer Oracle' and timeout == 5
        return io.BytesIO(json.dumps(observed).encode())

    def process(args, **options):
        calls.append((list(args), dict(options)))
        if args == ['/usr/bin/podman', 'inspect', 'fox']:
            events.append('podman')
            assert options == {'stdout': subprocess.PIPE, 'stderr': subprocess.PIPE, 'timeout': 20}
            body = [{'State': {'Running': running}, 'Mounts': [{'Source': source} for source in sources]}]
            return subprocess.CompletedProcess(args, podman_returncode, json.dumps(body).encode(), b'')
        assert args[:4] == [config['python']['path'], '-I', '-B', '-c']
        assert len(args) == 5 and options['cwd'] == '/'
        framed, data = options['input'].split(b'\n', 1)
        program = base64.b64decode(framed, validate=True).decode()
        assert program.startswith(provider.HOST_IDENTITY_GUARD)
        stdout, stderr = io.StringIO(), io.StringIO()
        stdin = io.TextIOWrapper(io.BytesIO(data), encoding='utf-8')
        try:
            with patch.object(sys, 'stdin', stdin), patch.dict(os.environ, options['env'], clear=True), \
                 redirect_stdout(stdout), redirect_stderr(stderr):
                exec(compile(program, '<actual-hosted-guard-fixture>', 'exec'), {})
            return subprocess.CompletedProcess(args, 0, stdout.getvalue().encode(), stderr.getvalue().encode())
        except Exception:
            # Authored transport diagnostic must not escape into caller errors.
            return subprocess.CompletedProcess(args, 1, b'', SYNTHETIC_ADMIN)

    with patch.object(urllib.request, 'urlopen', side_effect=metadata_read), \
         patch.object(provider.subprocess, 'run', side_effect=process):
        yield events, calls


def external_oci_sdk(config, *, database_name='JSNF2APEX', state='AVAILABLE'):
    """Only an SDK/network boundary double; all source-bound guards are real."""
    target = config['target_profile']['oci']
    reads = []
    no_retry = object()

    def client(endpoint, operation, resource_id, lifecycle_state):
        resource = SimpleNamespace(id=resource_id, compartment_id=target['compartment_id'],
                                   lifecycle_state=lifecycle_state)
        if operation == 'get_autonomous_database' and database_name is not None:
            resource.db_name = database_name
        def response(**arguments):
            reads.append((operation, arguments))
            return SimpleNamespace(status=200, data=resource)
        base = SimpleNamespace(endpoint=endpoint + '/20160918', timeout=(3, 15),
            config={'region': target['region'], 'log_requests': False},
            session=SimpleNamespace(verify=False, trust_env=True, close=Mock()))
        return SimpleNamespace(base_client=base, **{operation: Mock(side_effect=response)})

    db = client('https://database.us-ashburn-1.oraclecloud.com', 'get_autonomous_database',
                target['database_id'], state)
    vm = client('https://iaas.us-ashburn-1.oraclecloud.com', 'get_instance', target['instance_id'], 'RUNNING')
    sessions = [SimpleNamespace(requests_session=SimpleNamespace(close=Mock())) for _ in range(3)]
    signer = SimpleNamespace(region=target['region'], federation_client=sessions[0],
        leaf_certificate_retriever=sessions[1], intermediate_certificate_retriever=sessions[2],
        refresh_security_token=Mock())
    module = ModuleType('oci')
    module.__version__ = '2.188.0'
    module.retry = SimpleNamespace(NoneRetryStrategy=Mock(return_value=no_retry))
    module.auth = SimpleNamespace(signers=SimpleNamespace(
        InstancePrincipalsSecurityTokenSigner=Mock(return_value=signer)))
    module.database = SimpleNamespace(DatabaseClient=Mock(return_value=db))
    module.core = SimpleNamespace(ComputeClient=Mock(return_value=vm))
    module.config = SimpleNamespace(from_file=Mock(side_effect=AssertionError('No user-key authentication')))
    return SimpleNamespace(module=module, db=db, vm=vm, signer=signer, reads=reads, no_retry=no_retry)


class LegacyProviderTests(unittest.TestCase):
    def setUp(self):
        importlib.reload(runtime)

    def test_import_is_inert_and_does_not_select_or_spawn(self):
        with patch.object(subprocess, 'run', side_effect=AssertionError('No process during import')):
            importlib.reload(runtime)
        self.assertIs(runtime._selected, runtime._UNSELECTED)

    def test_legacy_argv_and_exact_framing_are_unchanged(self):
        argv = ['ssh', '-o', 'BatchMode=yes', 'approved-host', 'exact legacy loader']
        data = b'{"synthetic":"OnlySynthetic9!"}\n'
        calls = []
        def runner(args, **options):
            calls.append((args, options))
            return b'{"ok":true}'
        result = runtime.execute_host('print("ready")', data, timeout=180,
                                      legacy_argv=argv, legacy_runner=runner)
        self.assertEqual(result, b'{"ok":true}')
        self.assertIs(calls[0][0], argv)
        self.assertEqual(calls[0][1], {'data': base64.b64encode(b'print("ready")') + b'\n' + data,
                                     'timeout': 180})
        self.assertNotIn('OnlySynthetic9!', repr(argv))
        self.assertIsNone(runtime.hosted())

    def test_legacy_path_selection_cannot_later_switch_provider(self):
        path = Path('unchanged-legacy-root')
        self.assertEqual(runtime.private_root('native', path), path)
        with self.assertRaisesRegex(runtime.ProviderError, 'ALREADY_SELECTED'):
            runtime.configure_hosted(b'{}\n', expected_sha256='0' * 64)

    def test_oversized_legacy_wire_is_rejected_before_runner_or_selection(self):
        with patch.object(subprocess, 'run', side_effect=AssertionError('Must not launch')):
            with self.assertRaisesRegex(runtime.ProviderError, 'PROTECTED_REQUEST_TOO_LARGE'):
                runtime.execute_host('print(1)', b'oversized', timeout=1, maximum=1,
                    legacy_argv=[], legacy_runner=lambda *a, **k: self.fail('Must not run'))
        self.assertIs(runtime._selected, runtime._UNSELECTED)

    @unittest.skipIf(POSIX, 'Non-POSIX rejection runs on Windows/root only')
    def test_hosted_selection_does_not_fake_posix_permissions(self):
        with self.assertRaisesRegex(runtime.ProviderError, 'UNPRIVILEGED_POSIX_REQUIRED'):
            runtime.configure_hosted(b'{}\n', expected_sha256=digest(b'{}\n'))


@unittest.skipUnless(POSIX, 'Real hosted validation requires an unprivileged POSIX filesystem')
class HostedProviderTests(unittest.TestCase):
    def setUp(self):
        importlib.reload(runtime)
        self.temporary = tempfile.TemporaryDirectory(prefix='fox-hosted-provider-')
        self.base = Path(self.temporary.name) / 'installed'
        self.config = create_hosted_fixture(self.base)

    def tearDown(self):
        self.temporary.cleanup()

    def configured(self):
        return configure_fixture(self.config, runtime)

    def rejected_config(self, config, code=None):
        raw = canonical_bytes(config)
        with self.assertRaises(runtime.ProviderError) as error:
            runtime.configure_hosted(raw, expected_sha256=digest(raw))
        self.assertNotIn(SYNTHETIC_ADMIN.decode(), str(error.exception))
        if code:
            self.assertIn(code, str(error.exception))
        self.assertIs(runtime._selected, runtime._UNSELECTED)

    def test_real_config_is_immutable_one_time_and_has_no_workspace_fallback(self):
        provider = self.configured()
        expected = {'native': 'clean-install', 'project': 'project-clean-install',
                    'journal': 'product-verifier', 'handoff': 'handoffs'}
        for kind, name in expected.items():
            self.assertEqual(runtime.private_root(kind, Path('/must-not-use-workspace')),
                             Path(self.config['state_root']) / name)
        copied = provider.configuration
        copied['state_root'] = '/altered'
        self.assertEqual(provider.configuration['state_root'], self.config['state_root'])
        with self.assertRaises(FrozenInstanceError):
            provider.raw = b'{}'
        with self.assertRaisesRegex(runtime.ProviderError, 'ALREADY_SELECTED'):
            configure_fixture(self.config, runtime)

    def test_config_hash_canonical_json_and_duplicate_keys_fail_closed(self):
        raw = canonical_bytes(self.config)
        with self.assertRaisesRegex(runtime.ProviderError, 'CONFIGURATION_HASH_INVALID'):
            runtime.configure_hosted(raw, expected_sha256='0' * 64)
        for modified in (raw.rstrip(), b' ' + raw,
                         raw.replace(b'{', b'{"schema_version":1,', 1)):
            with self.subTest(raw_length=len(modified)), self.assertRaises(runtime.ProviderError):
                runtime.configure_hosted(modified, expected_sha256=digest(modified))
        self.assertIs(runtime._selected, runtime._UNSELECTED)

    def test_exact_config_schema_owner_provider_target_and_runtime_bindings(self):
        cases = [
            (('owner_uid',), self.config['owner_uid'] + 1),
            (('schema_version',), True), (('unknown_secret',), 'forbidden'),
            (('provider_sha256',), '0' * 64), (('target_profile_sha256',), '0' * 64),
            (('target_profile', 'oci', 'region'), 'ap-singapore-1'),
            (('python', 'sha256'), '0' * 64),
            (('python', 'version'), [3, 11, 999]),
            (('converter_sources', 'forms2apex/oci_identity.py'), '0' * 64),
        ]
        for path, value in cases:
            config = deepcopy(self.config)
            cursor = config
            for key in path[:-1]:
                cursor = cursor[key]
            cursor[path[-1]] = value
            with self.subTest(field=path):
                self.rejected_config(config)

    def test_real_state_and_admin_modes_are_required(self):
        for path in (Path(self.config['state_root']), Path(self.config['admin_secret_file']).parent):
            path.chmod(0o755)
            try:
                self.rejected_config(self.config, 'PRIVATE_DIRECTORY_REQUIRED')
            finally:
                path.chmod(0o700)
        path = Path(self.config['admin_secret_file'])
        path.chmod(0o644)
        try:
            self.rejected_config(self.config, 'PRIVATE_FILE_REQUIRED')
        finally:
            path.chmod(0o600)

    def test_source_file_symlink_and_changed_bytes_are_rejected(self):
        member = Path(self.config['converter_root']) / 'forms2apex/oci_identity.py'
        old = member.read_bytes()
        member.write_bytes(old + b'\n# changed\n')
        self.rejected_config(self.config, 'SOURCE_CHANGED')
        member.write_bytes(old)
        real = member.with_suffix('.retained')
        member.rename(real)
        member.symlink_to(real)
        self.rejected_config(self.config, 'PATH_LINK_FORBIDDEN')

    def test_secret_symlink_hardlink_and_public_overlap_are_rejected(self):
        secret = Path(self.config['admin_secret_file'])
        link = secret.with_name('another-link')
        os.link(secret, link)
        self.rejected_config(self.config, 'PRIVATE_FILE_REQUIRED')
        link.unlink()
        secret.rename(link)
        secret.symlink_to(link)
        self.rejected_config(self.config, 'PATH_LINK_FORBIDDEN')
        secret.unlink(); link.rename(secret)
        for root in (str(secret.parent), self.config['state_root']):
            config = deepcopy(self.config)
            config['public_mount_roots'] = [root]
            self.rejected_config(config, 'OVERLAPS_PUBLIC_OR_STATE')

    def test_missing_secret_is_not_provisioned_by_configure(self):
        path = Path(self.config['admin_secret_file'])
        path.unlink()
        provider = self.configured()
        self.assertFalse(path.exists())
        with external_host_boundary(runtime, self.config) as (events, _):
            self.assertEqual(provider.check_public_mounts(), {'safe': True})
        self.assertEqual(events, ['imds', 'podman'])
        self.assertFalse(path.exists())
        with external_host_boundary(runtime, self.config), self.assertRaises(runtime.ProviderError) as error:
            provider.admin_secret()
        self.assertNotIn(str(path), str(error.exception))

    def test_actual_child_uses_protected_stdin_and_clean_environment(self):
        provider = self.configured()
        run = subprocess.run
        observed = []
        def actual(args, **kwargs):
            observed.append((list(args), dict(kwargs)))
            return run(args, **kwargs)
        program = ('import hashlib,json,os,sys; value=sys.stdin.buffer.read(); '
                   'print(json.dumps({"sha256":hashlib.sha256(value).hexdigest(),'
                   '"leaked_env":[x for x in os.environ if x.startswith("OCI_") or x=="HTTP_PROXY"],'
                   '"isolated":sys.flags.isolated,"no_bytecode":sys.dont_write_bytecode}))')
        with patch.dict(os.environ, {'OCI_CONFIG_FILE': '/must-not-be-read', 'HTTP_PROXY': 'http://invalid'}), \
             patch.object(runtime.subprocess, 'run', side_effect=actual):
            result = json.loads(provider._spawn(program, SYNTHETIC_ADMIN, 15))
        self.assertEqual(result, {'sha256': digest(SYNTHETIC_ADMIN), 'leaked_env': [],
                                  'isolated': 1, 'no_bytecode': True})
        self.assertNotIn(SYNTHETIC_ADMIN.decode(), repr(observed[0][0]))
        self.assertEqual(observed[0][1]['input'].split(b'\n', 1)[1], SYNTHETIC_ADMIN)

    def test_actual_child_failure_timeout_and_output_bound_hide_diagnostics(self):
        provider = self.configured()
        program = 'import sys;sys.stderr.write(sys.stdin.read());raise RuntimeError("secret-withheld")'
        with self.assertRaises(runtime.ProviderError) as error:
            provider._spawn(program, SYNTHETIC_ADMIN, 15)
        self.assertNotIn(SYNTHETIC_ADMIN.decode(), str(error.exception))
        self.assertNotIn('secret-withheld', str(error.exception))
        with self.assertRaisesRegex(runtime.ProviderError, 'UNCERTAIN_NO_REPLAY'):
            provider._spawn('import time;time.sleep(1)', b'', 0.02)
        with patch.object(runtime, 'MAX_WIRE', 1000), \
             self.assertRaisesRegex(runtime.ProviderError, 'PROTECTED_RESPONSE_TOO_LARGE'):
            provider._spawn('print("x"*1001)', b'', 15)

    def test_exact_imds_guard_precedes_host_payload_and_checks_region(self):
        provider = self.configured()
        packet = b'{"value":7}\n'
        with external_host_boundary(runtime, self.config) as (events, calls):
            result = provider.execute_host('import json,sys;print(json.dumps(json.load(sys.stdin)))', packet, timeout=15)
        self.assertEqual(json.loads(result), {'value': 7})
        self.assertEqual(events, ['imds'])
        self.assertNotIn('ssh', calls[0][0])
        invalid = {'id': 'other-instance', 'compartmentId': self.config['target_profile']['oci']['compartment_id'],
                   'canonicalRegionName': 'us-ashburn-1'}
        with external_host_boundary(runtime, self.config, metadata=invalid) as (events, _), \
             self.assertRaisesRegex(runtime.ProviderError, 'OUTPUT_WITHHELD'):
            provider.execute_host('raise AssertionError("payload must not execute")', b'', timeout=15)
        self.assertEqual(events, ['imds'])

    def test_secret_read_uses_real_file_and_guarded_actual_mount_projection(self):
        provider = self.configured()
        with external_host_boundary(runtime, self.config) as (events, calls):
            value = provider.admin_secret()
        self.assertEqual(value.encode(), SYNTHETIC_ADMIN)
        self.assertEqual(events, ['imds', 'podman'])
        self.assertTrue(all(SYNTHETIC_ADMIN.decode() not in repr(args) for args, _ in calls))
        self.assertTrue(all(SYNTHETIC_ADMIN not in options.get('input', b'') for _, options in calls))

    def test_live_mount_containing_secret_or_state_is_rejected_before_read(self):
        provider = self.configured()
        for source in (str(Path(self.config['admin_secret_file']).parent), self.config['state_root']):
            opened = []
            actual_open = os.open
            def record_open(path, *args, **kwargs):
                opened.append(Path(path))
                return actual_open(path, *args, **kwargs)
            with self.subTest(source=source), external_host_boundary(runtime, self.config, mount_sources=[source]), \
                 patch.object(runtime.os, 'open', side_effect=record_open), \
                 self.assertRaisesRegex(runtime.ProviderError, 'OUTPUT_WITHHELD'):
                provider.admin_secret()
            self.assertNotIn(Path(self.config['admin_secret_file']), opened)

    def test_secret_mode_links_oversize_and_format_are_checked_again_at_use(self):
        provider = self.configured()
        path = Path(self.config['admin_secret_file'])
        for raw in (b'x' * 131, b'short\n', SYNTHETIC_ADMIN + b'\nsecond-line', b' ' + SYNTHETIC_ADMIN):
            path.write_bytes(raw)
            with self.subTest(bytes=len(raw)), external_host_boundary(runtime, self.config), \
                 self.assertRaises(runtime.ProviderError):
                provider.admin_secret()
        path.write_bytes(SYNTHETIC_ADMIN)
        path.chmod(0o644)
        with external_host_boundary(runtime, self.config), self.assertRaisesRegex(runtime.ProviderError, 'PRIVATE_FILE_REQUIRED'):
            provider.admin_secret()
        path.chmod(0o600)
        link = path.with_name('hardlink')
        os.link(path, link)
        with external_host_boundary(runtime, self.config), self.assertRaisesRegex(runtime.ProviderError, 'REGULAR_FILE_REQUIRED'):
            provider.admin_secret()
        link.unlink()
        path.rename(link); path.symlink_to(link)
        with external_host_boundary(runtime, self.config), self.assertRaisesRegex(runtime.ProviderError, 'LINK_FORBIDDEN'):
            provider.admin_secret()

    def test_state_permissions_and_source_hashes_are_rechecked_at_use(self):
        provider = self.configured()
        state = Path(self.config['state_root'])
        state.chmod(0o755)
        with self.assertRaisesRegex(runtime.ProviderError, 'PRIVATE_DIRECTORY_REQUIRED'):
            provider.path('journal')
        state.chmod(0o700)
        source = Path(self.config['converter_root']) / 'forms2apex/oci_identity.py'
        source.write_bytes(source.read_bytes() + b'\n# changed\n')
        with self.assertRaisesRegex(runtime.ProviderError, 'SOURCE_CHANGED'):
            provider.identity_sources()

    def test_private_read_does_not_treat_access_time_refresh_as_content_mutation(self):
        self.configured()
        path = Path(self.config['admin_secret_file'])
        before = path.stat()
        # Force relatime to refresh atime on the real read. Identity, mode,
        # ownership, length and modification/change timestamps remain guarded.
        os.utime(path, ns=(1, before.st_mtime_ns))
        self.assertEqual(runtime._read(path, 130, private=True), SYNTHETIC_ADMIN + b'\n')

    def test_private_destination_rejects_other_installation_and_symlink_parent(self):
        provider = self.configured()
        foreign = self.base / 'foreign'
        foreign.mkdir(mode=0o700)
        with self.assertRaisesRegex(runtime.ProviderError, 'OUTSIDE_STATE'):
            provider.private_destination(foreign / 'plan.json')
        journal = provider.path('journal')
        link = journal / 'linked'
        link.symlink_to(foreign, target_is_directory=True)
        with self.assertRaisesRegex(runtime.ProviderError, 'LINK_FORBIDDEN'):
            provider.private_destination(link / 'plan.json')

    def test_generated_oci_program_runs_source_bound_collector_and_exact_two_gets(self):
        provider = self.configured()
        target = self.config['target_profile']['oci']
        for state, required in (('AVAILABLE', True), ('STOPPED', False)):
            sdk = external_oci_sdk(self.config, state=state)
            # The generated loader creates its own source-bound forms2apex
            # modules. Restore that isolated module namespace after each run.
            with self.subTest(state=state), patch.dict(sys.modules, {'oci': sdk.module}), \
                 external_host_boundary(runtime, self.config) as (events, calls):
                result = provider.oci_scope(require_database_available=required)
            self.assertEqual(result['database_db_name'], 'JSNF2APEX')
            self.assertEqual(result['database_state'], state)
            self.assertEqual(result['instance_state'], 'RUNNING')
            self.assertEqual(result['database_id'], target['database_id'])
            self.assertEqual(result['instance_id'], target['instance_id'])
            self.assertEqual(result['compartment_id'], target['compartment_id'])
            self.assertEqual(result['region'], target['region'])
            self.assertEqual(set(result), {'database_db_name', 'database_state', 'instance_state',
                'database_id', 'instance_id', 'compartment_id', 'region', 'observed_at_utc'})
            self.assertEqual(events, ['imds'])
            self.assertEqual(len(calls), 1)
            self.assertEqual(sdk.reads, [
                ('get_autonomous_database', {'autonomous_database_id': target['database_id'], 'retry_strategy': sdk.no_retry}),
                ('get_instance', {'instance_id': target['instance_id'], 'retry_strategy': sdk.no_retry})])
            sdk.module.config.from_file.assert_not_called()
            for client in (sdk.db, sdk.vm):
                self.assertIs(client.base_client.session.verify, True)
                self.assertIs(client.base_client.session.trust_env, False)
                client.base_client.session.close.assert_called_once_with()
            sdk.module.auth.signers.InstancePrincipalsSecurityTokenSigner.assert_called_once_with(
                federation_endpoint='https://auth.us-ashburn-1.oraclecloud.com/v1/x509',
                federation_client_cert_bundle_verify=True, federation_client_retry_strategy=sdk.no_retry,
                retry_strategy=sdk.no_retry, log_requests=False)

    def test_generated_oci_program_rejects_missing_wrong_name_and_stopped_write_readiness(self):
        provider = self.configured()
        cases = [(None, 'AVAILABLE', False), ('OTHER', 'AVAILABLE', False),
                 ('JSNF2APEX', 'STOPPED', True)]
        for name, state, required in cases:
            sdk = external_oci_sdk(self.config, database_name=name, state=state)
            with self.subTest(name=name, state=state), patch.dict(sys.modules, {'oci': sdk.module}), \
                 external_host_boundary(runtime, self.config), \
                 self.assertRaisesRegex(runtime.ProviderError, 'OUTPUT_WITHHELD'):
                provider.oci_scope(require_database_available=required)
            self.assertEqual([name for name, _ in sdk.reads], ['get_autonomous_database'])
            sdk.vm.get_instance.assert_not_called()
            sdk.module.config.from_file.assert_not_called()

    def test_private_destination_caller_kinds_do_not_cross_native_project_roots(self):
        provider = self.configured()
        native = provider.path('native') / 'new-private-entry'
        project = provider.path('project') / 'new-private-entry'
        provider.private_destination(native, kinds=('native',))
        runtime.private_destination(project, kinds=('project',))
        for path, kinds in ((project, ('native',)), (native, ('project',))):
            with self.subTest(kinds=kinds), self.assertRaisesRegex(runtime.ProviderError, 'OUTSIDE_STATE'):
                provider.private_destination(path, kinds=kinds)
        for kinds in ((), ['native'], ('native', 'native'), ('unknown',)):
            with self.subTest(kinds=kinds), self.assertRaisesRegex(runtime.ProviderError, 'STORAGE_KIND_INVALID'):
                provider.private_destination(native, kinds=kinds)
        # The actual native/project wrappers are exercised in the separate
        # state-path suite, including its full converter dependency closure.
        self.assertFalse(native.exists())
        self.assertFalse(project.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
