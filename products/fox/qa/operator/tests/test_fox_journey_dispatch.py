"""Local-only wrapper tests; every remote/DPAPI boundary is mocked."""
from contextlib import redirect_stdout, redirect_stderr
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from qa.operator import fox_journey_dispatch as d


def stage_result(source):
    return {'status': 'STAGED', 'source_sha256': source,
            'stage': d.remote.STAGE_ROOT.as_posix() + '/' + source,
            'launch_key': d.remote.LAUNCH_KEY, 'qa_image_id': d.remote.IMAGES['qa']}


def run_result(source):
    result = stage_result(source)
    directory = result['stage'] + '/results/FOXJ-20261017T120000-aabbccdd'
    result.update(status='PASSED', exit_code=0, result_directory=directory,
                  report_path=directory + '/fox-journey-result.json', post_count=6,
                  automatic_replay_permitted=False,
                  projects={
                      'happy': {'project_id': 'a' * 32, 'job_id': 'fox-' + 'b' * 20,
                                'source_hash': 'b7ba121603d8ebb046ec2d889b33a0b1e7a97a946f1aaf92c107f6767e9f09d7',
                                'state': 'QA_REQUIRED', 'application_id': 123456},
                      'blocked': {'project_id': 'c' * 32,
                                  'source_hash': 'ed4ad70b2bad380d9172a8ef3219d9a2d055373e43f2926b1da4b00bdbc9476e',
                                  'process_post_count': 0}})
    return result


class BundleTests(unittest.TestCase):
    def test_actual_bundle_has_only_pinned_public_files_and_code(self):
        with (patch.object(d.clean, 'run_process', side_effect=AssertionError('must not execute')),
                patch.object(d.clean, 'ssh_json', side_effect=AssertionError('must not connect')),
                patch.object(d.clean, 'oci_scope', side_effect=AssertionError('must not query')),
                patch.object(d, 'fox_credentials', side_effect=AssertionError('must not decrypt'))):
            files, remote_raw, descriptor, source = d.bundle()
        self.assertEqual(set(files), set(d.remote.PINNED_FILES))
        self.assertEqual(len(files), 10)
        self.assertEqual(descriptor['files'], {name: d.digest(raw) for name, raw in files.items()})
        self.assertEqual(source, d.digest(d.remote.canonical(descriptor)))
        self.assertEqual(descriptor['remote_sha256'], d.digest(remote_raw))
        self.assertEqual(descriptor['fixture_generator_sha256'], d.GENERATOR_SHA)
        self.assertFalse(any(name.endswith('.dpapi') or '/input/' in name or name.endswith('/manifest.json') for name in files))

    def test_manifest_is_local_and_does_not_emit_file_bytes_or_credentials(self):
        output = io.StringIO()
        with (patch.object(d.clean, 'run_process', side_effect=AssertionError('must not execute')),
                patch.object(d, 'fox_credentials', side_effect=AssertionError('must not decrypt')),
                redirect_stdout(output)):
            self.assertEqual(d.main(['manifest']), 0)
        value = json.loads(output.getvalue())
        self.assertEqual(value['status'], 'LOCAL_MANIFEST')
        self.assertIs(value['live_activation_verified'], False)
        self.assertIs(value['parent_dispatch_required'], True)
        self.assertNotIn('files', value)
        self.assertNotIn('password', output.getvalue())
        self.assertNotIn('fox-web-admin.dpapi', output.getvalue())

    def test_changed_frozen_source_is_blocked_locally(self):
        original = d.local_bytes
        def changed(file, *args, **kwargs):
            raw = original(file, *args, **kwargs)
            return raw + b' ' if Path(file) == d.ROOT / 'qa/run-fox-journey.mjs' else raw
        with patch.object(d, 'local_bytes', side_effect=changed), self.assertRaises(RuntimeError):
            d.bundle()


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.source = 'f' * 64
        self.bundle = ({'safe': b'bytes'}, b'remote-code', {'remote_sha256': d.digest(b'remote-code')}, self.source)
        self.ready = patch.object(d.remote, 'PINS_READY', True)
        self.state = patch.object(d.remote, 'PIN_STATE', 'READY_H')
        self.ready.start(); self.state.start()
        self.addCleanup(self.ready.stop); self.addCleanup(self.state.stop)

    def test_pending_h_pins_block_all_boundaries(self):
        for command in ('stage', 'run'):
            with (patch.object(d.remote, 'PINS_READY', False),
                  patch.object(d, 'bundle', side_effect=AssertionError('must not read')),
                  patch.object(d.clean, 'oci_scope', side_effect=AssertionError('must not query')),
                  patch.object(d, 'fox_credentials', side_effect=AssertionError('must not decrypt')),
                  self.assertRaises(RuntimeError)):
                d.dispatch(command, self.source, apply=True)

    def test_unarmed_wrong_action_or_bad_hash_stops_before_any_boundary(self):
        for command, source, apply in [('run', self.source, False), ('stage', self.source, 1),
                                        ('accept', self.source, True), ('run', 'bad', True)]:
            with (self.subTest(command=command, apply=apply), patch.object(d, 'bundle', side_effect=AssertionError('must not read')),
                    patch.object(d.clean, 'oci_scope', side_effect=AssertionError('must not query')),
                    self.assertRaises(RuntimeError)):
                d.dispatch(command, source, apply=apply)

    def test_mismatched_reviewed_source_stops_before_cloud_or_secret(self):
        with (patch.object(d, 'bundle', return_value=self.bundle), patch.object(d.clean, 'oci_scope', side_effect=AssertionError('must not query')),
                patch.object(d, 'fox_credentials', side_effect=AssertionError('must not decrypt')), self.assertRaises(RuntimeError)):
            d.dispatch('run', '0' * 64, apply=True)

    def test_stage_reuses_scope_stdin_transport_without_credentials_or_clean_check(self):
        with (patch.object(d, 'bundle', return_value=self.bundle), patch.object(d.clean, 'oci_scope', return_value={'fixed': 'scope'}) as scope,
                patch.object(d.clean, 'ssh_json', return_value=stage_result(self.source)) as ssh,
                patch.object(d.clean, 'dispatch', side_effect=AssertionError('must not query DB')),
                patch.object(d, 'fox_credentials', side_effect=AssertionError('must not decrypt'))):
            result = d.dispatch('stage', self.source, apply=True)
        self.assertEqual(result['status'], 'STAGED')
        scope.assert_called_once_with(require_database_available=True)
        host, packet = ssh.call_args.args
        self.assertNotIn('credentials', packet)
        self.assertEqual(packet['command'], 'stage')
        self.assertIn("namespace['execute'](p)", host)
        self.assertNotIn('admin_password', packet)

    def test_run_sends_captured_credentials_only_in_stdin_packet(self):
        credentials = {'username': 'jason', 'password': 'SYNTHETIC-UNIT-TEST-ONLY'}
        with (patch.object(d, 'bundle', return_value=self.bundle), patch.object(d.clean, 'oci_scope', return_value={'fixed': 'scope'}),
                patch.object(d.clean, 'ssh_json', return_value=run_result(self.source)) as ssh,
                patch.object(d.clean, 'dispatch', side_effect=AssertionError('must not query DB')),
                patch.object(d, 'fox_credentials', return_value=credentials)):
            result = d.dispatch('run', self.source, apply=True)
        host, packet = ssh.call_args.args
        self.assertEqual(packet['credentials'], credentials)
        self.assertNotIn(credentials['password'], host)
        self.assertNotIn(credentials['password'], json.dumps(result))
        self.assertEqual(result['post_count'], 6)

    def test_secret_in_remote_result_is_withheld_even_before_shape_validation(self):
        with (patch.object(d, 'bundle', return_value=self.bundle), patch.object(d.clean, 'oci_scope', return_value={}),
                patch.object(d, 'fox_credentials', return_value={'username': 'jason', 'password': 'SYNTHETIC-ONLY'}),
                patch.object(d.clean, 'ssh_json', return_value={'failure': 'SYNTHETIC-ONLY'}), self.assertRaises(RuntimeError)):
            d.dispatch('run', self.source, apply=True)

    def test_remote_stopped_shape_is_preserved_without_retry(self):
        with (patch.object(d, 'bundle', return_value=self.bundle), patch.object(d.clean, 'oci_scope', return_value={}),
                patch.object(d, 'fox_credentials', return_value={'username': 'jason', 'password': 'SYNTHETIC-ONLY'}),
                patch.object(d.clean, 'ssh_json', return_value=dict(d.STOPPED)) as ssh):
            self.assertEqual(d.dispatch('run', self.source, apply=True), d.STOPPED)
        ssh.assert_called_once()

    def test_invalid_arguments_never_echo_arbitrary_input(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(d.main(['run', '--password=SYNTHETIC-SECRET-NOT-TO-ECHO']), 2)
        self.assertEqual(json.loads(out.getvalue()), d.STOPPED)
        self.assertNotIn('SYNTHETIC-SECRET', out.getvalue() + err.getvalue())


class CredentialTests(unittest.TestCase):
    def test_existing_dpapi_reader_is_fixed_and_output_is_captured(self):
        with tempfile.TemporaryDirectory() as folder:
            secret = Path(folder).resolve() / 'dummy.dpapi'
            secret.write_text('inert encrypted-fixture placeholder')
            with patch.object(d, 'SECRET_FILE', secret), patch.object(d.clean, 'run_process', return_value=b'SYNTHETIC-ONLY\r\n') as process:
                self.assertEqual(d.fox_credentials(), {'username': 'jason', 'password': 'SYNTHETIC-ONLY'})
            args = process.call_args.args[0]
            self.assertIn(str(d.SECRET_READER), args)
            self.assertEqual(args[-2:], ['-SecretFile', str(secret)])
            self.assertNotIn('SYNTHETIC-ONLY', str(args))

    def test_invalid_secret_bytes_are_not_returned(self):
        with tempfile.TemporaryDirectory() as folder:
            secret = Path(folder).resolve() / 'dummy.dpapi'
            secret.write_text('inert encrypted-fixture placeholder')
            for raw in [b'', b'\xff', b'\r\n', b'a\nb', b'a\0b', b'x' * 4097]:
                with self.subTest(raw_length=len(raw)), patch.object(d, 'SECRET_FILE', secret), patch.object(d.clean, 'run_process', return_value=raw), self.assertRaises(Exception):
                    d.fox_credentials()


class ResultTests(unittest.TestCase):
    def test_exact_stage_and_run_results_pass(self):
        source = 'f' * 64
        self.assertEqual(d.validate_result(stage_result(source), 'stage', source)['status'], 'STAGED')
        self.assertEqual(d.validate_result(run_result(source), 'run', source)['projects']['happy']['state'], 'QA_REQUIRED')

    def test_out_of_scope_partial_or_free_text_results_are_not_printable(self):
        source = 'f' * 64
        for mutate in [lambda v: v.update(extra='private text'), lambda v: v.update(status='INCOMPLETE'),
                       lambda v: v.update(post_count=True), lambda v: v.update(exit_code=False),
                       lambda v: v.update(automatic_replay_permitted=True), lambda v: v.update(report_path='/etc/private'),
                       lambda v: v['projects']['happy'].update(application_id=True), lambda v: v['projects']['happy'].update(state='ACCEPTED'),
                       lambda v: v['projects']['blocked'].update(process_post_count=1),
                       lambda v: v['projects']['blocked'].update(project_id=v['projects']['happy']['project_id'])]:
            value = run_result(source); mutate(value)
            with self.assertRaises(RuntimeError): d.validate_result(value, 'run', source)


if __name__ == '__main__':
    unittest.main()
