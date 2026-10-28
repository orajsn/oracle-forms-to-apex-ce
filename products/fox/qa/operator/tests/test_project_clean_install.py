"""Offline project CLI protocol tests; no OCI, SSH, SQLcl or secret access.

The package fixture below is deliberately not an Oracle package. Package
validation is the separately tested project_contracts boundary; these tests
exercise local path/flag/transport behavior, not external execution success.
"""
import ast
import base64
from datetime import datetime, timedelta
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
for location in (ROOT, ROOT / 'converter'):
    if str(location) not in sys.path:
        sys.path.insert(0, str(location))
from qa.operator import contracts as c
from qa.operator import project_contracts as pc
from qa.operator import project_clean_install as cli
from qa.operator import clean_install as native_cli

TIME = '2026-10-25T01:02:03+00:00'
NAME = 'FOX_QA_261025_89ABCDEF'
JOB = 'fox-' + 'a' * 20
CODE = 'b' * 64
ADMIN = 'Aa9!' + 'c' * 26


def fixture():
    raw = b'CLI protocol fixture only; not an Oracle package.'
    binding = {'job_id': JOB, 'profile_id': 'native-project-v1',
        'source_manifest_sha256': '1' * 64, 'package_sha256': c.digest(raw),
        'sql_sha256': '2' * 64, 'schema_script_sha256': '3' * 64,
        'project_spec_sha256': '4' * 64, 'source_to_apex_sha256': '5' * 64,
        'source_application_id': 123, 'source_application_alias': 'F2A_' + JOB.upper().replace('-', '_'),
        'source_reimport_application_id': 456,
        'source_reimport_application_alias': 'F2A_' + JOB.upper().replace('-', '_') + '_SQLCHECK',
        'sql_member': 'sql/f123.sql', 'schema_member': 'schema/01_synthetic_schema.sql',
        'tables': ['FOX_NATIVE_FIRST', 'FOX_NATIVE_SHARED'], 'original_parsing_schema': 'FORMS2APEX_POC'}
    source = {'schema_version': 1, 'scope': c.SOURCE_SCOPE, 'observed_at_utc': TIME,
        'instance_id': c.INSTANCE, 'compartment_id': c.COMPARTMENT, 'region': c.REGION,
        'job_id': JOB, 'run_state': 'QA_REQUIRED', 'package_sha256': c.digest(raw),
        'package_bytes': len(raw), 'source_manifest_sha256': binding['source_manifest_sha256']}
    package = {'binding': binding, 'package_bytes': len(raw)}
    plan = pc.make_plan(source, package, NAME, TIME, operator_code_sha256=CODE)
    return plan, package, raw


class CodeAndTransportTests(unittest.TestCase):
    def test_project_paths_and_reused_constants_do_not_mutate_native_operator(self):
        self.assertEqual(cli.PRIVATE, ROOT / 'work/private/project-clean-install')
        self.assertEqual(native_cli.PRIVATE, ROOT / 'work/private/clean-install')
        self.assertEqual(cli.IMAGE, native_cli.IMAGE)
        self.assertEqual(cli.FOX_IMAGE, native_cli.FOX_IMAGE)
        self.assertEqual(cli.HOST_PREFIX, native_cli.HOST_PREFIX)
        self.assertEqual(cli.SOURCE_CODE, native_cli.SOURCE_CODE)
        self.assertIsNot(cli.SSH, native_cli.SSH)

    def test_code_manifest_covers_project_and_reused_helper_closure(self):
        with patch.object(Path, 'read_bytes', autospec=True, side_effect=lambda path: path.name.encode()):
            code, digest = cli.code_bundle()
            self.assertEqual(set(code), {'contracts.py', 'remote.py', 'clean_install.py', 'runtime_provider.py',
            'project_contracts.py', 'project_remote.py', 'project_clean_install.py'})
        self.assertEqual(digest, c.digest(c.canonical_bytes({name: c.digest(raw) for name, raw in code.items()})))
        self.assertIn("('contracts.py','remote.py','project_contracts.py','project_remote.py')", cli.EXECUTOR_CODE)
        self.assertIn("sys.modules['qa.operator.project_remote'].execute", cli.EXECUTOR_CODE)
        self.assertNotIn("sys.modules['qa.operator.remote'].execute", cli.EXECUTOR_CODE)

    def test_executor_requires_paired_dependencies_before_project_dispatch(self):
        for dependency in ('from forms2apex.project_release import validate_project_package',
                           'from forms2apex.native_project import render_project_schema',
                           'from fox.project_qa_plan import derive_project_qa_plan,derive_project_qa_profile'):
            self.assertLess(cli.EXECUTOR_CODE.index(dependency), cli.EXECUTOR_CODE.index(".execute(p['command']"))
        self.assertIn('paired', cli.__doc__)
        self.assertNotIn('pip install', cli.EXECUTOR_CODE)

    def test_guarded_programs_do_not_use_optimization_disabled_asserts(self):
        for program in (cli.SOURCE_CODE, cli.HOST_PREFIX, cli.EXECUTOR_CODE, cli.SOURCE_HOST, cli.EXECUTOR_HOST):
            self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(ast.parse(program))))
        for optimize in (0, 1, 2):
            with patch.object(sys, 'stdin', io.StringIO('{"code":{}}')):
                with self.subTest(optimize=optimize), self.assertRaisesRegex(RuntimeError, 'PROJECT_EXECUTOR_CODE_GUARD_FAILED'):
                    exec(compile(cli.EXECUTOR_CODE, '<project-code-guard>', 'exec', optimize=optimize), {})

    def test_source_host_checks_existing_fox_image_and_readonly_database(self):
        self.assertIn("['podman','inspect','fox']", cli.SOURCE_HOST)
        self.assertIn("v['Image'].split(':')[-1]==p['fox_image'].split(':')[-1]", cli.SOURCE_HOST)
        self.assertIn('file:/data/fox.sqlite3?mode=ro', cli.SOURCE_CODE)
        self.assertNotIn('admin_password', cli.SOURCE_CODE)
        self.assertIn("e.get('TNS_ADMIN')=='/opt/forms2apex/wallet'", cli.EXECUTOR_HOST)
        self.assertIn("'python3.11','-B','-c'", cli.EXECUTOR_HOST)

    def test_wire_preserves_bytes_and_secret_only_on_stdin(self):
        packet = {'package_b64': base64.b64encode(b'X' * 100_000).decode(), 'admin_password': ADMIN}
        with patch.object(cli, 'run_process', return_value=b'{"status":"OK"}') as run:
            self.assertEqual(cli.ssh_json('print("ok")', packet), {'status': 'OK'})
        self.assertNotIn(ADMIN, repr(run.call_args.args))
        program, document = run.call_args.kwargs['data'].split(b'\n', 1)
        self.assertEqual(base64.b64decode(program), b'print("ok")')
        self.assertEqual(json.loads(document), packet)
        self.assertIn('python3 -B', run.call_args.args[0][-1])

    def test_oversize_or_duplicate_transport_response_fails_closed(self):
        with patch.object(cli, 'MAX_WIRE', 20), patch.object(cli, 'run_process') as run:
            with self.assertRaisesRegex(cli.OperatorError, 'PROTECTED_REQUEST_TOO_LARGE'):
                cli.ssh_json('X' * 20, {})
            run.assert_not_called()
        with patch.object(cli, 'run_process', return_value=b'{"status":"OK","status":"OTHER"}'):
            with self.assertRaises(c.ContractError):
                cli.ssh_json('', {})


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.plan, self.package, self.raw = fixture()
        self.source = self.plan['source_origin']

    def response(self):
        return {'source_attestation': dict(self.source), 'package_b64': base64.b64encode(self.raw).decode()}

    def test_source_bytes_run_identity_and_project_validator_are_bound(self):
        with patch.object(cli, 'ssh_json', return_value=self.response()) as ssh, \
             patch.object(cli, 'now', return_value=datetime.fromisoformat(TIME)), \
             patch.object(pc, 'load_package', return_value=self.package) as validate:
            raw, source, package = cli.fetch_source(JOB, c.digest(self.raw), {'scope': 'test'})
        self.assertEqual((raw, source, package), (self.raw, self.source, self.package))
        validate.assert_called_once_with(self.raw, c.digest(self.raw))
        self.assertEqual(ssh.call_args.args[1]['fox_image'], cli.FOX_IMAGE)
        self.assertNotIn('admin_password', ssh.call_args.args[1])

    def test_malformed_identity_stops_before_remote_read(self):
        for job, digest in ((None, 'a' * 64), (JOB, None), ('fox-invalid', 'a' * 64), (JOB, 'bad')):
            with patch.object(cli, 'ssh_json') as ssh, self.subTest(job=job, digest=digest):
                with self.assertRaises(cli.OperatorError):
                    cli.fetch_source(job, digest, {})
                ssh.assert_not_called()

    def test_stale_or_changed_source_stops_before_package_validation(self):
        changes = ({'package_bytes': len(self.raw) + 1}, {'instance_id': 'other'},
                   {'observed_at_utc': (datetime.fromisoformat(TIME) - timedelta(seconds=301)).isoformat()})
        for change in changes:
            response = self.response()
            response['source_attestation'].update(change)
            with patch.object(cli, 'ssh_json', return_value=response), \
                 patch.object(cli, 'now', return_value=datetime.fromisoformat(TIME)), \
                 patch.object(pc, 'load_package', return_value=self.package), self.subTest(change=change):
                with self.assertRaises((cli.OperatorError, c.ContractError)):
                    cli.fetch_source(JOB, c.digest(self.raw), {})


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.plan, self.package, self.raw = fixture()
        self.plan_raw = c.canonical_bytes(self.plan)
        self.code = {name: name.encode() for name in cli.CODE_FILES}
        for target, name, value in ((cli, 'read_plan', (self.plan_raw, self.plan)),
                                  (cli, 'code_bundle', (self.code, CODE)),
                                  (cli, '_private_file', self.raw),
                                  (pc, 'load_package', self.package),
                                  (cli, 'oci_scope', {'fixed': 'scope'}),
                                  (cli, 'fetch_source', (self.raw, self.plan['source_origin'], self.package))):
            patch.object(target, name, return_value=value).start()
        self.addCleanup(patch.stopall)

    def test_apply_needs_explicit_boolean_phase_and_exact_hash_before_external_calls(self):
        for options in ({}, {'apply': True}, {'apply': True, 'phase': 'schema'},
                        {'apply': True, 'phase': 'schema', 'expected_sha': '0' * 64},
                        {'apply': 1, 'phase': 'schema', 'expected_sha': c.digest(self.plan_raw)}):
            with patch.object(cli, 'ssh_json') as ssh, patch.object(cli, 'admin_secret') as secret, \
                 patch.object(cli, 'oci_scope') as scope, self.subTest(options=options):
                with self.assertRaises(cli.OperatorError):
                    cli.dispatch('apply', 'plan.json', **options)
                ssh.assert_not_called(); secret.assert_not_called(); scope.assert_not_called()

    def test_fresh_program_is_selected_before_secret_and_never_falls_back_on_failure(self):
        with patch.object(native_cli,'fresh_host_program',return_value='SYNTHETIC_FRESH_HOST_PROGRAM') as selected, \
             patch.object(cli,'admin_secret',return_value=ADMIN),patch.object(cli,'ssh_json',return_value={'state':'SYNTHETIC_TRANSPORT_ONLY'}) as ssh:
            cli.dispatch('apply','plan.json',expected_sha=c.digest(self.plan_raw),phase='allocate',apply=True)
        selected.assert_called_once_with('project')
        self.assertEqual(ssh.call_args.args[0],'SYNTHETIC_FRESH_HOST_PROGRAM')
        with patch.object(native_cli,'fresh_host_program',side_effect=RuntimeError('SOURCE_BINDING_CHANGED')), \
             patch.object(cli,'admin_secret') as secret,patch.object(cli,'ssh_json') as ssh:
            with self.assertRaisesRegex(RuntimeError,'SOURCE_BINDING_CHANGED'):
                cli.dispatch('apply','plan.json',expected_sha=c.digest(self.plan_raw),phase='allocate',apply=True)
        secret.assert_not_called();ssh.assert_not_called()

    def test_check_status_reject_apply_flag_and_phase(self):
        for command in ('check', 'status'):
            for options in ({'apply': True}, {'phase': 'import'}):
                with patch.object(cli, 'ssh_json') as ssh, self.subTest(command=command, options=options):
                    with self.assertRaises(cli.OperatorError):
                        cli.dispatch(command, 'plan.json', **options)
                    ssh.assert_not_called()

    def test_code_drift_blocks_all_new_checks_and_phase_writes_before_oci(self):
        with patch.object(cli, 'code_bundle', return_value=(self.code, 'f' * 64)), \
             patch.object(cli, 'oci_scope') as scope, patch.object(cli, 'admin_secret') as secret:
            for command, phase in [('check', None), *[('apply', phase) for phase in c.PHASES]]:
                with self.subTest(command=command, phase=phase), self.assertRaisesRegex(cli.OperatorError, 'OPERATOR_CODE_CHANGED'):
                    cli.dispatch(command, 'plan.json', expected_sha=c.digest(self.plan_raw), phase=phase, apply=command == 'apply')
            scope.assert_not_called(); secret.assert_not_called()

    def test_dispatch_routes_project_executor_and_keeps_status_secret_free(self):
        captured = []
        def exchange(program, packet):
            captured.append((program, dict(packet), packet))
            return {'status': 'OK'}
        with patch.object(cli, 'ssh_json', side_effect=exchange), patch.object(cli, 'admin_secret', return_value=ADMIN) as secret:
            cli.dispatch('check', 'plan.json')
            cli.dispatch('status', 'plan.json')
            cli.dispatch('apply', 'plan.json', expected_sha=c.digest(self.plan_raw), phase='schema', apply=True)
        self.assertEqual(secret.call_count, 2)
        self.assertEqual(captured[0][1]['admin_password'], ADMIN)
        self.assertNotIn('admin_password', captured[1][1])
        self.assertEqual(captured[2][1]['phase'], 'schema')
        self.assertTrue(captured[2][1]['apply'])
        for program, snapshot, original in captured:
            self.assertEqual(program, cli.EXECUTOR_HOST)
            self.assertEqual(base64.b64decode(snapshot['executor_b64']), cli.EXECUTOR_CODE.encode())
            self.assertEqual(base64.b64decode(snapshot['package_b64']), self.raw)
            self.assertEqual(base64.b64decode(snapshot['plan_b64']), self.plan_raw)
            self.assertNotIn(ADMIN, program)
            self.assertNotIn('admin_password', original)

    def test_status_does_not_fetch_live_source_or_read_admin_secret(self):
        with patch.object(cli, 'fetch_source') as source, patch.object(cli, 'admin_secret') as secret, \
             patch.object(cli, 'ssh_json', return_value={'state': 'PREPARED'}):
            cli.dispatch('status', 'plan.json')
        source.assert_not_called(); secret.assert_not_called()
        cli.oci_scope.assert_called_once_with(require_database_available=False)

    def test_changed_live_package_and_remote_error_do_not_leak_or_replay(self):
        with patch.object(cli, 'fetch_source', return_value=(b'changed', self.plan['source_origin'], self.package)), \
             patch.object(cli, 'admin_secret') as secret, patch.object(cli, 'ssh_json') as ssh:
            with self.assertRaisesRegex(cli.OperatorError, 'LIVE_PRIVATE_JOB_DIFFERS'):
                cli.dispatch('check', 'plan.json')
            secret.assert_not_called(); ssh.assert_not_called()
        with patch.object(cli, 'admin_secret', return_value=ADMIN), \
             patch.object(cli, 'ssh_json', return_value={'status': 'STOPPED', 'code': ADMIN, 'error': ADMIN}):
            result = cli.dispatch('check', 'plan.json')
        self.assertFalse(result['automatic_replay_permitted'])
        self.assertNotIn(ADMIN, json.dumps(result))

    def test_cli_rejects_prepare_execution_flags_and_target_overrides(self):
        invalid = [('prepare', '--job', JOB, '--package-sha256', '1' * 64, '--apply'),
                   ('prepare', '--job', JOB, '--package-sha256', '1' * 64, '--phase', 'schema'),
                   ('prepare',), ('status', '--plan', 'plan.json', '--namespace', NAME),
                   ('check', '--plan', 'plan.json', '--job', JOB)]
        with patch.object(cli, 'prepare') as prepare, patch.object(cli, 'dispatch') as dispatch:
            for arguments in invalid:
                with self.subTest(arguments=arguments), self.assertRaises(cli.OperatorError):
                    cli.main(list(arguments))
            prepare.assert_not_called(); dispatch.assert_not_called()


class PrivatePathTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'nt', 'Requires real Windows owner-only ACL observation')
    def test_real_windows_private_plan_read_without_mocked_acl_guard(self):
        """Synthetic files only; preserve inherited PSModulePath and real guard."""
        plan, _, raw = fixture()
        plan_raw = c.canonical_bytes(plan)
        with tempfile.TemporaryDirectory(prefix='project-plan-acl-') as directory:
            private = Path(directory).resolve()
            destination = private / c.digest(plan_raw)
            # Only route this test to its own disposable directory. Directory
            # protection, file creation, PowerShell subprocess and ACL reads
            # execute their actual code; no secrets, OCI, SSH or SQL are used.
            with patch.object(cli, 'PRIVATE', private):
                cli.private_directory(destination)
                cli.save_new(destination / 'plan.json', plan_raw)
                cli.save_new(destination / 'apex-package.zip', raw)
                self.assertEqual(cli.read_plan(destination / 'plan.json'), (plan_raw, plan))
                self.assertEqual(cli._private_file(destination / 'apex-package.zip', len(raw)), raw)

    def test_invalid_prepare_identity_stops_before_oci_or_private_files(self):
        for job, digest, namespace in ((None, 'a' * 64, None), (JOB, 'bad', None),
                                       (JOB, 'a' * 64, 'FORMS2APEX_POC')):
            with patch.object(cli, 'oci_scope') as scope, patch.object(cli, 'private_directory') as private:
                with self.subTest(job=job, namespace=namespace), self.assertRaises((cli.OperatorError, c.ContractError)):
                    cli.prepare(job, digest, namespace)
                scope.assert_not_called(); private.assert_not_called()

    def test_paths_cannot_adopt_existing_native_plan_or_non_hash_directory(self):
        for path in (native_cli.PRIVATE / ('a' * 64) / 'plan.json',
                     cli.PRIVATE / 'friendly-name' / 'plan.json',
                     cli.PRIVATE / ('a' * 64) / 'other.json'):
            with self.subTest(path=str(path)), self.assertRaises(cli.OperatorError):
                cli.read_plan(path)

    def test_prepare_writes_only_project_paths_and_refuses_overwrite(self):
        plan, package, raw = fixture()
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory).resolve() / 'project-clean-install'
            with patch.object(cli, 'PRIVATE', private), \
                 patch.object(cli, 'oci_scope', return_value={}), \
                 patch.object(cli, 'fetch_source', return_value=(raw, plan['source_origin'], package)), \
                 patch.object(cli, 'now', return_value=datetime.fromisoformat(TIME)), \
                 patch.object(cli, 'code_bundle', return_value=({}, CODE)), \
                 patch.object(cli, 'run_process', return_value=b'PRIVATE_DIRECTORY_PROTECTED'):
                result = cli.prepare(JOB, c.digest(raw), NAME)
                path = Path(result['plan_path'])
                self.assertEqual(path.parent.parent, private)
                self.assertEqual(path.read_bytes(), c.canonical_bytes(plan))
                self.assertEqual((path.parent / 'apex-package.zip').read_bytes(), raw)
                self.assertFalse(result['remote_writes'])
                self.assertFalse(result['clean_install_passed'])
                self.assertTrue(result['paired_project_release_required'])
                with self.assertRaisesRegex(cli.OperatorError, 'LOCAL_PLAN_DESTINATION_MUST_BE_NEW'):
                    cli.prepare(JOB, c.digest(raw), NAME)
                with self.assertRaises(cli.OperatorError):
                    cli.save_new(path, b'changed')

    def test_private_read_requires_exact_hash_bound_and_package_permissions(self):
        plan, _, raw = fixture()
        plan_raw = c.canonical_bytes(plan)
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory).resolve()
            destination = private / c.digest(plan_raw)
            destination.mkdir(mode=0o700)
            with patch.object(cli, 'PRIVATE', private), patch.object(cli, 'run_process', return_value=b'PRIVATE_PATH_VERIFIED'):
                cli.save_new(destination / 'plan.json', plan_raw)
                cli.save_new(destination / 'apex-package.zip', raw)
                self.assertEqual(cli.read_plan(destination / 'plan.json'), (plan_raw, plan))
                self.assertEqual(cli._private_file(destination / 'apex-package.zip', len(raw)), raw)
                with self.assertRaisesRegex(cli.OperatorError, 'PRIVATE_FILE_PERMISSIONS'):
                    cli._private_file(destination / 'apex-package.zip', len(raw) - 1)
                with self.assertRaises(cli.OperatorError):
                    cli.save_new(destination / 'credentials.json', b'not allowed')


if __name__ == '__main__':
    unittest.main()
