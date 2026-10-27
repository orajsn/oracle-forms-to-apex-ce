"""Offline-only QA staging tests. All remote/process/write boundaries are mocked."""
from copy import deepcopy
import base64
import ast
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from qa.operator import native_qa_dispatch as cli
from qa.operator import native_qa_remote as remote
from qa.operator import contracts as C
from qa.operator import remote as clean_remote
from qa.operator.tests.test_remote import fixture


def packet(command='stage'):
    files, code, descriptor, source_hash = cli.bundle()
    plan, package, package_raw = fixture()
    plan['operator_code_sha256'] = descriptor['clean_operator_code_sha256']
    raw = C.canonical_bytes(plan)
    value = {'command': command, 'apply': command != 'collect', 'plan_sha256': C.digest(raw),
             'plan_b64': base64.b64encode(raw).decode(), 'source_sha256': source_hash, 'descriptor': descriptor,
             'files': {name: base64.b64encode(data).decode() for name, data in files.items()},
             'contracts_b64': base64.b64encode(cli.clean.code_bundle()[0]['contracts.py']).decode(),
             'remote_b64': base64.b64encode(code).decode()}
    allocated = clean_remote._make_allocation(plan, {'workspace_id': '22042420337195501', 'application_id': 34567}, C.VERSIONS)
    allocation_raw = C.canonical_bytes(allocated)
    profile_raw = C.canonical_bytes(C.make_verification_profile(plan, allocation_raw))
    imported = {'scope': 'fox-clean-package-install-v2', 'passed': True,
                'allocation_receipt_sha256': C.digest(allocation_raw), 'verification_profile_sha256': C.digest(profile_raw),
                **{key: plan['binding'][key] for key in ('package_sha256', 'source_manifest_sha256', 'job_id', 'native_spec_sha256')}}
    with zipfile.ZipFile(io.BytesIO(package_raw)) as archive: native = archive.read('native-form-spec.json')
    handoff = {'package.zip': package_raw, 'native-form-spec.json': native, 'allocate.evidence.json': allocation_raw,
               'verification-profile.json': profile_raw, 'verify.evidence.json': C.canonical_bytes(imported),
               'runtime-credentials.json': C.canonical_bytes({'username': 'FOX_QA_A', 'password': 'FakePrimary9!',
                   'second_username': 'FOX_QA_B', 'second_password': 'FakeSecondary8!'})}
    return value, handoff


class SourceTests(unittest.TestCase):
    def test_manifest_is_local_readonly_and_binds_exact_allowlist(self):
        with patch.object(cli.clean, 'oci_scope') as oci, patch.object(cli.clean, 'ssh_json') as ssh:
            files, _, descriptor, value = cli.bundle()
        self.assertEqual(set(files), remote.FILES)
        self.assertEqual(value, remote.digest(remote.canonical(descriptor)))
        self.assertEqual(set(descriptor['clean_operator_manifest']),
                         {'contracts.py', 'clean_install.py', 'remote.py', 'runtime_provider.py'})
        oci.assert_not_called(); ssh.assert_not_called()

    def test_host_wrapper_stays_python36_compatible_and_canonical_validation_runs_in_converter(self):
        code = Path(remote.__file__).read_text()
        ast.parse(code, feature_version=(3, 6))
        self.assertNotIn('from __future__ import annotations', code)
        self.assertNotIn('.removeprefix(', code)
        self.assertIn("c.validate_allocation(files['allocate.evidence.json'],plan)", remote.HANDOFF_READER)
        self.assertIn("'python3.11', '-B', '-c', HANDOFF_READER", code)

    def test_source_tamper_and_action_flags_fail_before_any_remote_operation(self):
        original, _ = packet()
        mutations = [lambda p: p.update(apply=False), lambda p: p.update(command='deploy'),
                     lambda p: p.update(source_sha256='a' * 64),
                     lambda p: p['files'].update({'run-native.mjs': base64.b64encode(b'changed').decode()}),
                     lambda p: p['files'].update({'schema-credentials.json': 'e30='}),
                     lambda p: p['descriptor'].update(base_qa_image='sha256:' + 'a' * 64)]
        for mutate in mutations:
            value = deepcopy(original); mutate(value)
            with self.subTest(value=value.get('command')), self.assertRaises(RuntimeError): remote.source_packet(value)

    def test_untampered_raw_allocation_and_profile_are_bound_by_existing_contract(self):
        value, handoff = packet()
        self.assertEqual(remote.validate_handoff(value, handoff), C.digest(handoff['allocate.evidence.json']))
        for name in ('allocate.evidence.json', 'verification-profile.json', 'package.zip', 'native-form-spec.json'):
            broken = dict(handoff); broken[name] += b'\n'
            with self.subTest(name=name), self.assertRaises((RuntimeError, C.ContractError, ValueError)):
                remote.validate_handoff(value, broken)

    def test_runtime_credentials_have_only_two_distinct_runtime_accounts(self):
        value, handoff = packet()
        credentials = json.loads(handoff['runtime-credentials.json'])
        for mutation in ({'schema_password': 'NeverCopy9!'}, {'second_username': 'fox_qa_a'}, {'password': None}):
            broken = dict(handoff); broken['runtime-credentials.json'] = C.canonical_bytes({**credentials, **mutation})
            with self.assertRaises(RuntimeError): remote.validate_handoff(value, broken)

    def test_missing_explicit_apply_fails_before_plan_or_oci_read(self):
        with patch.object(cli.clean, 'read_plan') as read, patch.object(cli.clean, 'oci_scope') as oci:
            with self.assertRaises(cli.clean.OperatorError): cli.dispatch('run', 'ignored', 'a' * 64, 'b' * 64)
        read.assert_not_called(); oci.assert_not_called()

    def test_collector_uses_short_create_only_child_with_full_source_binding(self):
        value, _ = packet('collect'); raw = base64.b64decode(value['plan_b64']); plan = json.loads(raw)
        plan_path = ROOT / 'work/private/clean-install' / value['plan_sha256'] / 'plan.json'
        with patch.object(cli.clean, 'read_plan', return_value=(raw, plan)), patch.object(cli.clean, 'oci_scope', return_value={}), \
             patch.object(cli.clean, 'dispatch') as check, patch.object(cli.clean, 'ssh_json', return_value={'status':'COLLECTED'}), \
             patch.object(cli.clean, 'private_directory', side_effect=FileExistsError) as create:
            with self.assertRaises(FileExistsError):
                cli.dispatch('collect', str(plan_path), value['plan_sha256'], value['source_sha256'])
        check.assert_not_called()
        destination = create.call_args.args[0]
        self.assertEqual(destination.parent, plan_path.parent)
        self.assertEqual(destination.name, 'qa-' + value['source_sha256'][:16])
        self.assertLess(len(str(destination / 'collection-manifest.json')), 240)

    def test_container_preparation_is_offline_restricted_and_has_no_ports(self):
        with patch.object(remote.os, 'getuid', return_value=1000, create=True), patch.object(remote.os, 'getgid', return_value=1000, create=True):
            args = remote.podman_args(remote.BASE_IMAGE, volumes=[(Path('/private/input'), '/inputs/input', 'ro')])
        for flag in ('--network=none', '--read-only', '--pull=never', '--cap-drop=all', '--security-opt=no-new-privileges'):
            self.assertIn(flag, args)
        self.assertFalse(any('publish' in arg or 'privileged' in arg or 'host' == arg for arg in args))
        self.assertIn('/private/input:/inputs/input:ro,Z', args)


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.packet, self.handoff = packet()
        self.storage, self.commands = {}, []
        self.new_image = 'sha256:' + 'd' * 64
        self.patches = [patch.object(remote, 'inspect_baselines'), patch.object(remote, 'handoff', return_value=self.handoff),
            patch.object(remote, 'private_dir', side_effect=lambda path, **_: Path(path)),
            patch.object(remote, 'create', side_effect=self.create), patch.object(remote, 'read_private', side_effect=lambda path, **_: self.storage[str(path)]),
            patch.object(remote, 'command', side_effect=self.command), patch.object(remote.os, 'getuid', return_value=1000, create=True),
            patch.object(remote.os, 'getgid', return_value=1000, create=True)]
        for item in self.patches: item.start()
        self.addCleanup(lambda: [item.stop() for item in reversed(self.patches)])

    def create(self, path, raw):
        key = str(path)
        if key in self.storage: raise RuntimeError('CREATE_ONLY_NO_REPLAY')
        self.storage[key] = raw

    def command(self, args, **kwargs):
        self.commands.append((args, kwargs))
        code, out = 0, b''
        if args[:3] == ['podman', 'image', 'exists']: code = 1
        elif args[:3] == ['podman', 'image', 'inspect']: out = self.new_image.encode()
        elif '-e' in args:
            out = remote.canonical({'version': '1.64.0', **{name: self.packet['descriptor']['files'][name] for name in ('package.json', 'package-lock.json')}})
        elif '/opt/fox-qa/prepare-target.mjs' in args:
            stage = self.stage
            self.create(stage / 'prepared/target.json', b'{"fixture":true}')
            self.create(stage / 'prepared/profile.json', b'{"fixture":true}')
        return SimpleNamespace(returncode=code, stdout=out, stderr=b'')

    @property
    def stage(self):
        return remote.ROOT / 'v2-stages' / self.packet['plan_sha256'] / self.packet['source_sha256']

    def test_stage_builds_only_unique_offline_overlay_and_excludes_secret_from_preparation(self):
        result = remote.execute(self.packet)
        self.assertEqual(result['status'], 'STAGED')
        build = next(args for args, _ in self.commands if args[:2] == ['podman', 'build'])
        self.assertIn('--pull=never', build); self.assertIn('--network=none', build)
        self.assertNotIn('localhost/fox-native-qa:pw1.64.0', build)
        prep = next(args for args, _ in self.commands if '/opt/fox-qa/prepare-target.mjs' in args)
        self.assertFalse(any('runtime-credentials' in value for value in prep))
        self.assertNotIn('npm', repr(self.commands)); self.assertNotIn('podman pull', repr(self.commands))
        self.assertTrue(all('schema-credentials' not in key for key in self.storage))
        wrapper = self.storage[str(self.stage / 'source/run-native-v2.sh')]
        original = base64.b64decode(self.packet['files']['run-jsn-qa.sh'])
        self.assertEqual(wrapper, original.replace(b"image='localhost/fox-native-qa:pw1.64.0'", ("image='" + self.new_image + "'").encode()))

    def test_run_creates_allocation_keyed_launch_intent_before_wrapper_and_refuses_replay(self):
        remote.execute(self.packet)
        self.packet['command'] = 'run'
        result = remote.execute(self.packet)
        self.assertEqual(result['status'], 'PASSED')
        allocation_hash = C.digest(self.handoff['allocate.evidence.json'])
        launch = str(remote.ROOT / 'launch-v2' / (allocation_hash + '.json'))
        self.assertIn(launch, self.storage)
        args = next(args for args, _ in self.commands if args[0] == 'bash')
        self.assertEqual(len(args), 10)
        self.assertNotIn('FakePrimary9!', repr(args))
        self.assertFalse(any('dispatch-v2' in key for key in self.storage), 'Wrapper must not preconsume the runner journal')
        before = len(self.commands)
        with self.assertRaisesRegex(RuntimeError, 'CREATE_ONLY_NO_REPLAY'): remote.execute(self.packet)
        self.assertFalse(any(args[0] == 'bash' for args, _ in self.commands[before:]))

    def test_changed_staged_or_live_bytes_block_before_launch(self):
        remote.execute(self.packet)
        self.packet['command'] = 'run'
        target = str(self.stage / 'prepared/target.json')
        self.storage[target] += b' '
        with self.assertRaisesRegex(RuntimeError, 'STAGED_BYTES_CHANGED'): remote.execute(self.packet)
        self.assertFalse(any(args[0] == 'bash' for args, _ in self.commands))

    def test_collection_is_nonsecret_raw_bytes_with_hashes_and_excludes_logs(self):
        remote.execute(self.packet)
        report = self.stage / 'results/FQ-20261017T010203-0123abcd/qa-result.json'
        self.storage[str(report)] = remote.canonical({'run_id': report.parent.name, 'status': 'INCOMPLETE', 'dispatch_state': 'PREFLIGHT_BLOCKED', 'write_attempts': []})
        allocation_hash = C.digest(self.handoff['allocate.evidence.json'])
        self.storage[str(remote.ROOT / 'dispatch-v2' / (allocation_hash + '.json'))] = b'{"scope":"fixture"}'
        self.storage[str(remote.ROOT / 'launch-v2' / (allocation_hash + '.json'))] = b'{"scope":"fixture-launch"}'
        self.packet.update(command='collect', apply=False)
        with patch.object(Path, 'glob', return_value=[report]): result = remote.execute(self.packet)
        self.assertEqual(result['status'], 'COLLECTED')
        self.assertNotIn('runtime-credentials.json', result['files'])
        self.assertIn('launch-intent.json', result['files'])
        self.assertNotIn('dispatch-receipt.json', result['files'], 'Preflight-blocked run has no runtime dispatch journal')
        self.assertTrue(all(not name.endswith('.log') for name in result['files']))
        for name, data in result['files'].items(): self.assertEqual(C.digest(base64.b64decode(data)), result['sha256'][name])
        self.storage[str(report)] = remote.canonical({'run_id': report.parent.name, 'bad': 'FakePrimary9!'})
        with patch.object(Path, 'glob', return_value=[report]), self.assertRaisesRegex(RuntimeError, 'SECRET_FOUND'):
            remote.execute(self.packet)

    def test_attempted_run_cannot_collect_without_its_runtime_dispatch_journal(self):
        remote.execute(self.packet)
        report = self.stage / 'results/FQ-20261017T010203-0123abcd/qa-result.json'
        self.storage[str(report)] = remote.canonical({'run_id': report.parent.name, 'dispatch_state': 'ATTEMPT_INCOMPLETE', 'write_attempts': []})
        allocation_hash = C.digest(self.handoff['allocate.evidence.json'])
        self.storage[str(remote.ROOT / 'launch-v2' / (allocation_hash + '.json'))] = b'{}'
        self.packet.update(command='collect', apply=False)
        with patch.object(Path, 'glob', return_value=[report]), self.assertRaisesRegex(RuntimeError, 'DISPATCH_RECEIPT_MISSING'):
            remote.execute(self.packet)


if __name__ == '__main__': unittest.main()
