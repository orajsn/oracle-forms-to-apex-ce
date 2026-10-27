"""Offline CLI tests: all OCI/SSH/DPAPI subprocess boundaries are mocked."""
import base64
import ast
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
import sqlite3
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
import urllib.request
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'converter'))
from qa.operator import clean_install as cli
from qa.operator import contracts as c
from qa.operator.tests.test_remote import fixture, NAME, TIME, CODE, ADMIN


class TransportTests(unittest.TestCase):
    def test_exact_measured_product_fox_and_unchanged_h_converter_pins(self):
        self.assertEqual(cli.IMAGE, 'sha256:c7fdb53bc04450e297cbbbc89fb834be714e106d5a164b1c80dc77d544db5a1b')
        self.assertEqual(cli.FOX_IMAGE, 'sha256:8ac18481bfcb0e991582f93b351ed66203372d8d9b9a11cc28ede7fd8d618f8d')

    def test_embedded_guards_remain_active_under_python_optimization(self):
        for program in (cli.HOST_PREFIX, cli.SOURCE_CODE, cli.EXECUTOR_CODE):
            self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(ast.parse(program))))
        meta = {'id': 'wrong-vm', 'compartmentId': c.COMPARTMENT, 'canonicalRegionName': c.REGION}
        packet = {'cli_scope': {'instance_id': 'wrong-vm', 'compartment_id': c.COMPARTMENT, 'database_id': c.DATABASE}}
        for optimize in (0, 1, 2):
            with patch.object(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(json.dumps(packet).encode()))), \
                 patch.object(urllib.request, 'urlopen', return_value=io.BytesIO(json.dumps(meta).encode())):
                with self.subTest(optimize=optimize), self.assertRaisesRegex(RuntimeError, 'PINNED_HOST_GUARD_FAILED'):
                    exec(compile(cli.HOST_PREFIX, '<host-guard-test>', 'exec', optimize=optimize), {})
            with patch.object(sys, 'stdin', io.StringIO('{"job_id":"bad-job","package_sha256":"bad-hash"}')):
                with self.assertRaisesRegex(RuntimeError, 'RETAINED_SOURCE_GUARD_FAILED'):
                    exec(compile(cli.SOURCE_CODE, '<source-guard-test>', 'exec', optimize=optimize), {})
            with patch.object(sys, 'stdin', io.StringIO('{"code":{}}')):
                with self.assertRaisesRegex(RuntimeError, 'EXECUTOR_CODE_GUARD_FAILED'):
                    exec(compile(cli.EXECUTOR_CODE, '<executor-guard-test>', 'exec', optimize=optimize), {})

    def test_wire_larger_than_contract_bound_preserves_exact_bytes_via_stdin(self):
        packet = {'binary_b64': base64.b64encode(b'X' * 100_000).decode(), 'secret': ADMIN}
        with patch.object(cli, 'run_process', return_value=b'{"status":"OK"}') as run:
            self.assertEqual(cli.ssh_json('print("ready")', packet), {'status': 'OK'})
        args, kwargs = run.call_args
        self.assertNotIn(ADMIN, repr(args))
        script, body = kwargs['data'].split(b'\n', 1)
        self.assertEqual(base64.b64decode(script), b'print("ready")')
        self.assertEqual(json.loads(body), packet)
        self.assertGreater(len(body), c.MAX_JSON_BYTES)
        self.assertLess(len(kwargs['data']), cli.MAX_WIRE)

    def test_transport_bound_rejected_before_any_process(self):
        with patch.object(cli, 'MAX_WIRE', 100), patch.object(cli, 'run_process') as run:
            with self.assertRaisesRegex(cli.OperatorError, 'PROTECTED_REQUEST_TOO_LARGE'):
                cli.ssh_json('X' * 100, {'secret': ADMIN})
            run.assert_not_called()

    def test_subprocess_failure_and_timeout_do_not_expose_captured_diagnostics(self):
        for outcome in (SimpleNamespace(returncode=1, stdout=ADMIN.encode(), stderr=ADMIN.encode()),
                        subprocess.TimeoutExpired('unused', 1, output=ADMIN.encode())):
            kwargs = {'side_effect': outcome} if isinstance(outcome, Exception) else {'return_value': outcome}
            with patch.object(cli.subprocess, 'run', **kwargs), self.assertRaises(cli.OperatorError) as error:
                cli.run_process(['fixed-command'], data=ADMIN.encode())
            self.assertNotIn(ADMIN, str(error.exception))

    def test_admin_secret_is_captured_from_existing_dpapi_reader_only(self):
        with patch.object(cli, 'run_process', return_value=(ADMIN + '\r\n').encode()) as run:
            self.assertEqual(cli.admin_secret(), ADMIN)
        args = run.call_args.args[0]
        self.assertEqual(args[-1], cli.ADMIN_SECRET)
        self.assertIn('Get-JsnSecret.ps1', args[3])
        self.assertNotIn(ADMIN, repr(args))

    def test_code_bundle_is_exact_four_files_with_deterministic_hash(self):
        contents, actual = cli.code_bundle()
        self.assertEqual(set(contents), {'contracts.py', 'clean_install.py', 'remote.py', 'runtime_provider.py'})
        self.assertEqual(actual, c.digest(c.canonical_bytes({name: c.digest(raw) for name, raw in contents.items()})))

    def test_scope_uses_fixed_jsn_cli_profile_and_exact_resource_ids(self):
        vm = {'id': c.INSTANCE, 'compartment-id': c.COMPARTMENT, 'lifecycle-state': 'RUNNING'}
        adb = {'id': c.DATABASE, 'compartment-id': c.COMPARTMENT, 'lifecycle-state': 'AVAILABLE', 'db-name': 'JSNF2APEX'}
        with patch.object(cli, 'run_process', side_effect=[json.dumps(value).encode() for value in (vm, adb)]) as run:
            scope = cli.oci_scope(require_database_available=True)
        self.assertEqual(scope['database_id'], c.DATABASE)
        for call in run.call_args_list:
            self.assertEqual(call.args[0][:5], ['oci', '--profile', 'JSN', '--region', c.REGION])
            self.assertTrue(call.kwargs['oci_json'])
        for key, value in (('id', 'other'), ('compartment-id', 'other'), ('lifecycle-state', 'STOPPED')):
            with patch.object(cli, 'run_process', side_effect=[json.dumps(vm).encode(), json.dumps({**adb, key: value}).encode()]):
                with self.subTest(key=key), self.assertRaises(cli.OperatorError):
                    cli.oci_scope(require_database_available=True)

    def test_oci_projects_only_required_fields_and_excludes_non_ascii_metadata(self):
        sources = [
            {'id': c.INSTANCE, 'compartment-id': c.COMPARTMENT, 'lifecycle-state': 'RUNNING'},
            {'id': c.DATABASE, 'compartment-id': c.COMPARTMENT, 'lifecycle-state': 'AVAILABLE', 'db-name': 'JSNF2APEX'},
        ]
        original_env = dict(os.environ)
        def projected_response(args, **kwargs):
            database = args[5] == 'db'
            required = sources[int(database)]
            metadata = {**required, 'display-name': 'Pr\u00e9sales', 'metadata': {'ssh_authorized_keys': 'UNRELATED_KEY'},
                        'defined-tags': {'notes': 'R\u00e9sum\u00e9'}}
            # The full response reproduces the legacy-encoding failure, but
            # those fields must never be requested by this operator.
            with self.assertRaises(UnicodeDecodeError):
                json.dumps(metadata, ensure_ascii=False).encode('cp1252').decode('utf-8')
            query = 'data.{id:id,"compartment-id":"compartment-id","lifecycle-state":"lifecycle-state"'
            if database:
                query += ',"db-name":"db-name"'
            self.assertEqual(args[args.index('--query') + 1], query + '}')
            self.assertEqual(kwargs['env']['PYTHONIOENCODING'], 'utf-8:strict')
            self.assertEqual(kwargs['env']['PYTHONUTF8'], '1')
            return SimpleNamespace(returncode=0, stdout=json.dumps(required).encode('utf-8'), stderr=b'')
        with patch.object(cli.subprocess, 'run', side_effect=projected_response) as run:
            scope = cli.oci_scope(require_database_available=True)
        self.assertEqual(scope['instance_id'], c.INSTANCE)
        self.assertEqual(scope['database_id'], c.DATABASE)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(dict(os.environ), original_env)

    def test_oci_rejects_non_utf8_unknown_fields_and_duplicate_json_without_fallback(self):
        for raw in (b'{"id":"\xe9"}', b'{"data":{}}', b'{"id":"x","id":"y"}'):
            with patch.object(cli, 'run_process', return_value=raw), self.subTest(raw=raw), self.assertRaises(cli.OperatorError):
                cli.oci_scope(require_database_available=True)

    def test_oci_auth_errors_and_warnings_stop_without_exposing_provider_text(self):
        for result, expected in (
            (SimpleNamespace(returncode=1, stdout=b'{}', stderr=b'Auth failure ' + ADMIN.encode()), 'OCI_CLI_FAILED_OUTPUT_WITHHELD'),
            (SimpleNamespace(returncode=0, stdout=b'{}', stderr=b'Warning ' + ADMIN.encode()), 'OCI_DIAGNOSTIC_OUTPUT_REVIEW_REQUIRED'),
        ):
            with patch.object(cli.subprocess, 'run', return_value=result), self.assertRaisesRegex(cli.OperatorError, expected) as error:
                cli.run_process(['oci'], oci_json=True)
            self.assertNotIn(ADMIN, str(error.exception))
        with patch.object(cli.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=b'{}', stderr=b'')) as run:
            cli.run_process(['non-oci'])
        self.assertNotIn('env', run.call_args.kwargs)


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.plan, self.package, self.raw = fixture()
        self.source = self.plan['source_origin']
        patch.object(cli, 'now', return_value=datetime.fromisoformat(TIME.replace('Z', '+00:00'))).start()
        patch.object(cli, 'validate_native_package', return_value=self.package).start()
        self.addCleanup(patch.stopall)

    def response(self):
        return {'source_attestation': self.source, 'package_b64': base64.b64encode(self.raw).decode()}

    def test_source_read_requires_live_container_image_and_exact_source_package(self):
        with patch.object(cli, 'ssh_json', return_value=self.response()) as ssh:
            raw, source, package = cli.fetch_source(self.source['job_id'], self.source['package_sha256'], {})
        self.assertEqual(raw, self.raw)
        self.assertEqual(source, self.source)
        program, packet = ssh.call_args.args
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(ast.parse(program))))
        self.assertEqual(packet['fox_image'], cli.FOX_IMAGE)
        self.assertIn("['podman','inspect','fox']", program)
        self.assertIn("mode=ro", cli.SOURCE_CODE)
        self.assertNotIn('admin_password', packet)
        meta = {'id': c.INSTANCE, 'compartmentId': c.COMPARTMENT, 'canonicalRegionName': c.REGION}
        packet['cli_scope'] = {'instance_id': c.INSTANCE, 'compartment_id': c.COMPARTMENT, 'database_id': c.DATABASE}
        old = SimpleNamespace(returncode=0, stdout=json.dumps([{'State': {'Running': True},
            'Image': 'sha256:7541b79d1ecf7452bed6004596eba86061d93f2ee251073b08ade855d3d7a05d'}]).encode(), stderr=b'')
        with patch.object(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(json.dumps(packet).encode()))), \
             patch.object(urllib.request, 'urlopen', return_value=io.BytesIO(json.dumps(meta).encode())), \
             patch.object(subprocess, 'run', return_value=old) as run:
            with self.assertRaisesRegex(RuntimeError, 'PINNED_HOST_GUARD_FAILED'):
                exec(compile(program, '<old-fox-image-guard-test>', 'exec', optimize=2), {})
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0], ['podman', 'inspect', 'fox'])

    def test_source_age_count_and_identity_fail_closed(self):
        for key, value in (('package_bytes', len(self.raw) + 1), ('job_id', 'fox-' + 'b' * 20),
                           ('observed_at_utc', '2026-10-16T01:00:00Z'), ('instance_id', 'other')):
            response = self.response()
            response['source_attestation'] = {**self.source, key: value}
            with patch.object(cli, 'ssh_json', return_value=response), self.subTest(key=key), self.assertRaises((cli.OperatorError, c.ContractError)):
                cli.fetch_source(self.source['job_id'], self.source['package_sha256'], {})

    def test_fetch_and_plan_share_five_second_skew_without_rewriting_observations(self):
        current = datetime.fromisoformat(TIME.replace('Z', '+00:00'))
        for seconds in (5, -300, 5.000001, -300.000001):
            response = self.response()
            observed = (current + timedelta(seconds=seconds)).isoformat()
            response['source_attestation'] = {**self.source, 'observed_at_utc': observed}
            with patch.object(cli, 'ssh_json', return_value=response), self.subTest(seconds=seconds):
                if seconds in (5, -300):
                    raw, source, package = cli.fetch_source(self.source['job_id'], self.source['package_sha256'], {})
                    plan = c.make_plan(source, package, NAME, TIME, native_spec_sha256=cli.native_digest(raw), operator_code_sha256=CODE)
                    self.assertEqual(plan['source_origin']['observed_at_utc'], observed)
                    self.assertEqual(plan['created_at_utc'], TIME)
                else:
                    with self.assertRaisesRegex(cli.OperatorError, 'SOURCE_OBSERVATION_NOT_FRESH'):
                        cli.fetch_source(self.source['job_id'], self.source['package_sha256'], {})

    def test_source_reader_binds_retained_run_row_source_hash_to_release(self):
        job, source_hash = self.source['job_id'], self.source['source_manifest_sha256']
        package_file, release_file, root, base = (MagicMock() for _ in range(4))
        package_file.read_bytes.return_value = self.raw
        release_file.read_bytes.return_value = json.dumps({'job_id': job, 'source_manifest_sha256': source_hash}).encode()
        for file in (package_file, release_file):
            file.is_file.return_value = True
            file.is_symlink.return_value = False
        root.resolve.return_value = root
        root.__truediv__.side_effect = {'apex-package.zip': package_file, 'release-evidence.json': release_file}.__getitem__
        base.__truediv__.return_value = root
        packet = {'job_id': job, 'package_sha256': self.source['package_sha256']}
        for retained_hash in (source_hash, '9' * 64, None):
            database, output = MagicMock(), io.StringIO()
            database.execute.return_value.fetchone.return_value = ('QA_REQUIRED', 'jobs/' + job + '/apex-package.zip', retained_hash)
            connection = MagicMock()
            connection.__enter__.return_value = database
            with self.subTest(retained_hash=retained_hash), patch('pathlib.Path', return_value=base), \
                 patch.object(sqlite3, 'connect', return_value=connection) as connect, \
                 patch.object(sys, 'stdin', io.StringIO(json.dumps(packet))), patch.object(sys, 'stdout', output):
                if retained_hash == source_hash:
                    exec(compile(cli.SOURCE_CODE, '<retained-source-test>', 'exec', optimize=2), {})
                    self.assertEqual(json.loads(output.getvalue())['source_attestation']['source_manifest_sha256'], source_hash)
                else:
                    with self.assertRaisesRegex(RuntimeError, 'RETAINED_SOURCE_GUARD_FAILED'):
                        exec(compile(cli.SOURCE_CODE, '<retained-source-test>', 'exec', optimize=2), {})
                    self.assertEqual(output.getvalue(), '')
                connect.assert_called_once_with('file:/data/fox.sqlite3?mode=ro', uri=True)
                database.execute.assert_called_once_with('select state,artifact,source_hash from runs where id=?', (job,))


class CliTests(unittest.TestCase):
    def setUp(self):
        self.plan, self.package, self.raw = fixture()
        patch.object(cli, 'validate_native_package', return_value=self.package).start()
        patch.object(cli, 'code_bundle', return_value=({'contracts.py': b'c', 'clean_install.py': b'l', 'remote.py': b'r'}, CODE)).start()
        patch.object(cli, 'oci_scope', return_value={'fixed': 'scope'}).start()
        patch.object(cli, 'fetch_source', return_value=(self.raw, self.plan['source_origin'], self.package)).start()
        patch.object(cli, 'read_plan', return_value=(c.canonical_bytes(self.plan), self.plan)).start()
        self.addCleanup(patch.stopall)

    def test_apply_requires_exact_plan_hash_phase_flag_before_remote_or_secret(self):
        for arguments in ({}, {'apply': True}, {'phase': 'allocate', 'apply': True},
                          {'phase': 'allocate', 'apply': True, 'expected_sha': '0' * 64}):
            with patch.object(cli, 'ssh_json') as ssh, patch.object(cli, 'admin_secret') as secret:
                with self.subTest(arguments=arguments), self.assertRaises(cli.OperatorError):
                    cli.dispatch('apply', 'plan.json', **arguments)
                ssh.assert_not_called(); secret.assert_not_called()

    def test_check_and_status_cannot_accept_apply_or_target_phase(self):
        for command in ('check', 'status'):
            for arguments in ({'apply': True}, {'phase': 'allocate'}):
                with patch.object(cli, 'ssh_json') as ssh, self.subTest(command=command, arguments=arguments), self.assertRaises(cli.OperatorError):
                    cli.dispatch(command, 'plan.json', **arguments)
                ssh.assert_not_called()

    def test_old_f_and_h_plans_check_and_all_apply_phases_stop_before_external_calls(self):
        actual_sources = {name: (cli.HERE / name).read_bytes() for name in ('contracts.py', 'clean_install.py', 'remote.py')}
        actual_hash = c.digest(c.canonical_bytes({name: c.digest(raw) for name, raw in actual_sources.items()}))
        for old_code in ('9064f20608c6b9ac3109727f34331f694141c846dc89097419e7eaed93231ec3',
                         'b7c4f3276bed4a505d7fb0660eb556743087634a96fd13185666d190ef008b28'):
            old_plan = c.load_json(c.canonical_bytes(self.plan))
            old_plan['operator_code_sha256'] = old_code
            old_raw = c.canonical_bytes(c.validate_plan(old_plan))
            self.assertNotEqual(actual_hash, old_code)
            with patch.object(cli, 'read_plan', return_value=(old_raw, old_plan)), \
                 patch.object(cli, 'code_bundle', return_value=(actual_sources, actual_hash)), \
                 patch.object(cli, 'oci_scope') as scope, patch.object(cli, 'fetch_source') as source, \
                 patch.object(cli, 'ssh_json') as ssh, patch.object(cli, 'admin_secret') as secret:
                for command, phase in [('check', None), *[('apply', phase) for phase in ('allocate', 'schema', 'import', 'verify')]]:
                    with self.subTest(old_code=old_code, command=command, phase=phase), self.assertRaisesRegex(cli.OperatorError, 'OPERATOR_CODE_CHANGED_REPREPARE_OR_REVIEW'):
                        cli.dispatch(command, 'plan.json', expected_sha=c.digest(old_raw), phase=phase, apply=command == 'apply')
                scope.assert_not_called(); source.assert_not_called(); ssh.assert_not_called(); secret.assert_not_called()

    def test_dispatch_captures_secrets_only_in_private_wire_and_status_needs_none(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'plan.json'
            # Fixture files contain no credentials. Production uses create-only
            # save_new; tests exercise that writer rather than a shell shortcut.
            cli.save_new(path.parent / 'apex-package.zip', self.raw)
            captured = []
            def exchange(program, packet):
                captured.append((program, dict(packet)))
                return {'status': 'OK'}
            with patch.object(cli, 'ssh_json', side_effect=exchange), patch.object(cli, 'admin_secret', return_value=ADMIN) as secret:
                cli.dispatch('check', path)
                cli.dispatch('status', path)
            self.assertEqual(secret.call_count, 1)
            self.assertEqual(captured[0][1]['admin_password'], ADMIN)
            self.assertNotIn(ADMIN, captured[0][0])
            self.assertNotIn('admin_password', captured[1][1])
            self.assertEqual(captured[0][1]['image'], cli.IMAGE)
            self.assertIn("'PYTHONNOUSERSITE')=='1'", captured[0][0])
            self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(ast.parse(captured[0][0]))))
            meta = {'id': c.INSTANCE, 'compartmentId': c.COMPARTMENT, 'canonicalRegionName': c.REGION}
            packet = {**captured[0][1], 'cli_scope': {'instance_id': c.INSTANCE, 'compartment_id': c.COMPARTMENT, 'database_id': c.DATABASE}}
            for image in ('sha256:wrong', 'sha256:44bad1b844363b374a3fd62da2dd94208f61ead2cf675eeb25bf30bf66020fbd'):
                wrong = SimpleNamespace(returncode=0, stdout=json.dumps([{'State': {'Running': True}, 'Image': image}]).encode(), stderr=b'')
                with self.subTest(image=image), patch.object(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(json.dumps(packet).encode()))), \
                     patch.object(urllib.request, 'urlopen', return_value=io.BytesIO(json.dumps(meta).encode())), \
                     patch.object(subprocess, 'run', return_value=wrong) as run:
                    with self.assertRaisesRegex(RuntimeError, 'PINNED_HOST_GUARD_FAILED'):
                        exec(compile(captured[0][0], '<image-guard-test>', 'exec', optimize=2), {})
                    run.assert_called_once()
                    self.assertEqual(run.call_args.args[0], ['podman', 'inspect', 'forms2apex-mcp'])

    def test_save_new_never_overwrites_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'plan.json'
            cli.save_new(path, b'original')
            with self.assertRaises(cli.OperatorError):
                cli.save_new(path, b'replacement')
            self.assertEqual(path.read_bytes(), b'original')

    def test_local_dispatch_filters_failed_response_fields_again(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'plan.json'
            cli.save_new(path.parent / 'apex-package.zip', self.raw)
            diagnostic = {'category': 'SQL_EXECUTION_FAILED', 'error_codes': ['ORA-01031'], 'return_code': 1}
            supplied = {'status': 'STOPPED', 'code': 'SQL_FAILED_OUTPUT_WITHHELD', 'phase': ADMIN,
                        'diagnostics': diagnostic, 'provider_text': ADMIN, 'automatic_replay_permitted': True}
            with patch.object(cli, 'ssh_json', return_value=supplied), patch.object(cli, 'admin_secret', return_value=ADMIN):
                result = cli.dispatch('check', path)
            self.assertEqual(result, {'status': 'STOPPED', 'code': 'SQL_FAILED_OUTPUT_WITHHELD', 'phase': None,
                                     'diagnostics': diagnostic, 'automatic_replay_permitted': False})
            self.assertNotIn(ADMIN, json.dumps(result))
            self.assertIn(".failure_response(exc,p.get('phase'))", cli.EXECUTOR_CODE)

    def test_main_prepare_rejects_mutation_flags_without_dispatch(self):
        with patch.object(cli, 'prepare') as prepare:
            for option in (['--apply'], ['--phase', 'allocate'], ['--plan', 'anything']):
                with self.subTest(option=option), self.assertRaises(cli.OperatorError):
                    cli.main(['prepare', *option])
            prepare.assert_not_called()


@unittest.skipUnless(os.name == 'nt', 'Windows ACL verification requires Windows.')
class WindowsPrivatePlanTests(unittest.TestCase):
    def test_real_temporary_owner_only_acl_supports_plan_readback(self):
        # Local temporary files only; no OCI, SSH, DPAPI or database calls.
        plan, _, _ = fixture()
        raw = c.canonical_bytes(plan)
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory).resolve() / 'private'
            private.mkdir()
            destination = private / c.digest(raw)
            with patch.object(cli, 'PRIVATE', private):
                cli.private_directory(destination)
                cli.save_new(destination / 'plan.json', raw)
                self.assertEqual(cli.read_plan(destination / 'plan.json'), (raw, plan))


if __name__ == '__main__':
    unittest.main()
