"""Offline bridge tests. No subprocess, OCI, SSH, secret resolution or live DB."""
import ast
import base64
from contextlib import ExitStack, closing, contextmanager, redirect_stdout
import copy
import gc
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import urllib.request

ROOT = Path(__file__).resolve().parents[3]
for folder in (ROOT, ROOT / 'fox'):
    sys.path.insert(0, str(folder))
from qa.operator import product_queue_transport as bridge
from qa.operator import contracts as C
from fox import native_verification as gate
from fox import technical_release as release_gate
from fox import verification_queue as queue_module

A, B = 'a' * 64, 'b' * 64
FUTURE = 'sha256:' + 'f' * 64
JOB = 'fox-' + 'a' * 20
TOKEN = 'c' * 32
PROOF = 'd' * 64
PACKAGE = b'private synthetic package'
PACKAGE_SHA = hashlib.sha256(PACKAGE).hexdigest()
SECRET = 'DoNotExposeProviderOutputOrCredential'
PROFILE = b'fixed synthetic native profile'
PROFILE_SHA = hashlib.sha256(PROFILE).hexdigest()
PROFILE_HOST = '/home/opc/fox/releases/native-beta-20261017h/deployment/native-beta-profile.json'


def manifest():
    return {'schema_version': 1, 'scope': bridge.SCOPE, 'enabled': True,
            'images': {'fox': FUTURE, 'converter': bridge.clean.IMAGE},
            'modules': {name: A for name in bridge.MODULES}, 'code': {name: A for name in bridge.CODE},
            'clean_operator_code_sha256': A, 'qa_source_sha256': A, 'promotion_transport_sha256': A,
            'native_profile_sha256': PROFILE_SHA,
            'target': dict(C.FIXED_TARGET)}


def binding(release):
    return queue_module.VerificationBinding(JOB, A, PACKAGE_SHA, release)


def request(op, *, document=None, claim=None, reason=None, proof=None):
    document = manifest() if document is None else document
    release = bridge.release_sha256(document)
    bound = binding(release)
    return {'operation': op, 'apply': op != 'status', 'manifest': document, 'release_sha256': release,
            'binding': None if op in {'heartbeat', 'claim'} else bound.payload(),
            'claim': None if claim is None else {'binding': claim.binding.payload(), 'attempt_token': claim.attempt_token},
            'code': reason, 'proof_sha256': proof}


def row(release, state='running', proof=None, code=None):
    return {**binding(release).payload(), 'state': state, 'proof_sha256': proof, 'attention_code': code,
            'created_at_utc': '2026-10-17T00:00:00+00:00', 'updated_at_utc': '2026-10-17T00:00:00+00:00'}


def ready(stack):
    stack.enter_context(patch.object(bridge.clean, 'FOX_IMAGE', FUTURE))
    stack.enter_context(patch.object(bridge, '_file_sha', side_effect=lambda path:
        PROFILE_SHA if path == ROOT / 'deployment/native-beta-profile.json' else A))
    stack.enter_context(patch.object(bridge.clean, 'code_bundle', return_value=({}, A)))
    stack.enter_context(patch.object(bridge.native_qa, 'bundle', return_value=({}, b'', {}, A)))


class ReleaseTests(unittest.TestCase):
    def test_exact_canonical_release_digest_and_copied_manifest(self):
        value = manifest()
        self.assertEqual(bridge.release_sha256(value), C.digest(C.canonical_bytes(value)))
        copied = bridge.validate_release(value)
        copied['images']['fox'] = 'changed'
        self.assertEqual(value['images']['fox'], FUTURE)

    def test_exact_fields_types_digests_images_and_target(self):
        mutations = [lambda m: m.update(secret=SECRET), lambda m: m.update(schema_version=True),
                     lambda m: m.update(enabled=1), lambda m: m['code'].update(extra=A),
                     lambda m: m['code'].pop('runtime_provider.py'),
                     lambda m: m['modules'].pop('verification_queue.py'),
                     lambda m: m['images'].update(fox='not-an-image'),
                     lambda m: m.update(qa_source_sha256=SECRET),
                     lambda m: m['target'].update(database_id='another-database')]
        for mutate in mutations:
            value = manifest(); mutate(value)
            with self.subTest(value=value), self.assertRaises(bridge.QueueTransportError) as caught:
                bridge.validate_release(value)
            self.assertNotIn(SECRET, str(caught.exception))

    def test_disabled_and_h_refuse_every_operation_before_any_process(self):
        for op in bridge.OPERATIONS:
            for mode in ('disabled', 'h'):
                value = manifest()
                if mode == 'disabled': value['enabled'] = False
                else: value['images']['fox'] = bridge.H_FOX_IMAGE
                with self.subTest(op=op, mode=mode), patch.object(bridge.clean, 'run_process') as process, \
                     patch.object(bridge.clean, 'oci_scope') as oci, patch.object(bridge.clean, 'ssh_json') as ssh, \
                     patch.object(bridge, '_file_sha') as read, self.assertRaises(bridge.QueueTransportError):
                    bridge.dispatch(op, value, expected_release_sha256=bridge.release_sha256(value), apply=op != 'status')
                for mock in (process, oci, ssh, read): mock.assert_not_called()

    def test_future_manifest_still_refuses_frozen_h_clean_pin(self):
        with patch.object(bridge.clean, 'run_process') as process, self.assertRaisesRegex(
                bridge.QueueTransportError, 'CLEAN_DEPLOYMENT_PINS_DIFFER'):
            bridge.require_ready(manifest(), bridge.release_sha256(manifest()))
        process.assert_not_called()

    def test_ready_requires_every_exact_local_release_component(self):
        value = manifest(); digest = bridge.release_sha256(value)
        with ExitStack() as stack:
            ready(stack)
            self.assertEqual(bridge.require_ready(value, digest), value)
            for field in ('modules', 'code', 'clean_operator_code_sha256', 'qa_source_sha256',
                          'promotion_transport_sha256', 'native_profile_sha256'):
                changed = copy.deepcopy(value)
                if field in {'modules', 'code'}: changed[field][next(iter(changed[field]))] = B
                else: changed[field] = B
                with self.subTest(field=field), self.assertRaises(bridge.QueueTransportError):
                    bridge.require_ready(changed, bridge.release_sha256(changed))
            with self.assertRaisesRegex(bridge.QueueTransportError, 'EXACT_VERIFIER_RELEASE_REQUIRED'):
                bridge.require_ready(value, B)

    def test_local_file_hash_rejects_missing_and_reads_real_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'source.py'
            with self.assertRaises(bridge.QueueTransportError): bridge._file_sha(path)
            path.write_bytes(b'fixture')
            self.assertEqual(bridge._file_sha(path), C.digest(b'fixture'))


class DispatchTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close); ready(self.stack)
        self.oci = self.stack.enter_context(patch.object(bridge.clean, 'oci_scope', return_value={'fixed': 'scope'}))
        self.ssh = self.stack.enter_context(patch.object(bridge.clean, 'ssh_json'))
        self.value = manifest(); self.release = bridge.release_sha256(self.value)
        self.bound = binding(self.release); self.claim = queue_module.Claim(self.bound, TOKEN)

    def response(self, **values):
        return {'host_scope_verified': True, 'fox_image': FUTURE, 'verifier_release_sha256': self.release, **values}

    def dispatch(self, op, **options):
        return bridge.dispatch(op, self.value, expected_release_sha256=self.release, **options)

    def test_heartbeat_fixed_projection_ignores_unknown_values(self):
        self.ssh.return_value = self.response(status='CONTACT_RECORDED', secret=SECRET, claim={'attempt_token': TOKEN})
        self.assertEqual(self.dispatch('heartbeat', apply=True), {'status': 'CONTACT_RECORDED',
            'verifier_release_sha256': self.release, 'automatic_replay_permitted': False})
        self.oci.assert_called_once_with(require_database_available=False)

    def test_claim_is_the_only_private_token_response(self):
        self.ssh.return_value = self.response(status='CLAIMED', claim={'binding': self.bound.payload(), 'attempt_token': TOKEN})
        got = self.dispatch('claim', apply=True)
        self.assertEqual(got['claim']['attempt_token'], TOKEN)
        self.assertEqual(self.ssh.call_args.args[1]['request']['operation'], 'claim')

    def test_idle_projection_has_no_claim(self):
        self.ssh.return_value = self.response(status='IDLE', claim={'attempt_token': TOKEN})
        self.assertNotIn(TOKEN, repr(self.dispatch('claim', apply=True)))

    def test_status_is_read_only_and_drops_tokens_and_unknown_fields(self):
        self.ssh.return_value = self.response(status='STATUS', queue={**row(self.release), 'claim_token': TOKEN, 'extra': SECRET})
        result = self.dispatch('status', binding=self.bound)
        self.assertNotIn(TOKEN, repr(result)); self.assertNotIn(SECRET, repr(result))
        self.assertIs(self.ssh.call_args.args[1]['request']['apply'], False)

    def test_status_missing_queue_is_rejected_but_null_is_valid(self):
        self.ssh.return_value = self.response(status='STATUS')
        with self.assertRaises(bridge.QueueTransportError): self.dispatch('status', binding=self.bound)
        self.ssh.return_value = self.response(status='STATUS', queue=None)
        self.assertIsNone(self.dispatch('status', binding=self.bound)['queue'])

    def test_attention_and_complete_receive_claim_only_in_private_packet(self):
        for op, state, proof, reason in (('attention', 'attention', None, 'BACKEND_OUTCOME_UNCONFIRMED'),
                                         ('complete', 'completed', PROOF, None)):
            self.ssh.return_value = self.response(status='ATTENTION' if op == 'attention' else 'COMPLETED',
                queue=row(self.release, state, proof, reason))
            result = self.dispatch(op, apply=True, claim=self.claim, code=reason, proof_sha256=proof)
            self.assertNotIn(TOKEN, repr(result))
            self.assertEqual(self.ssh.call_args.args[1]['request']['claim']['attempt_token'], TOKEN)

    def test_invalid_flags_operations_arguments_stop_before_oci(self):
        cases = [('claim', {}), ('status', {'binding': self.bound, 'apply': True}),
                 ('status', {'claim': self.claim}), ('recover_running', {'apply': True}),
                 ('attention', {'apply': True, 'claim': self.claim, 'code': SECRET}),
                 ('complete', {'apply': True, 'claim': self.claim, 'proof_sha256': None}),
                 ('heartbeat', {'apply': True, 'binding': self.bound}),
                 ('claim', {'apply': True, 'proof_sha256': PROOF})]
        for op, options in cases:
            with self.subTest(op=op, options=options), self.assertRaises(bridge.QueueTransportError):
                self.dispatch(op, **options)
        self.oci.assert_not_called(); self.ssh.assert_not_called()

    def test_binding_release_or_claim_mismatch_stops_before_oci(self):
        different = queue_module.VerificationBinding(JOB, A, B, self.release)
        for options in ({'binding': different, 'claim': self.claim}, {'binding': binding(B)}):
            with self.assertRaises(bridge.QueueTransportError):
                self.dispatch('reconcile', apply=True, **options)
        self.oci.assert_not_called()

    def test_ssh_loss_has_bounded_error_and_no_retry(self):
        self.ssh.side_effect = RuntimeError(SECRET)
        with self.assertRaises(bridge.QueueTransportError) as caught: self.dispatch('claim', apply=True)
        self.assertEqual(str(caught.exception), 'QUEUE_TRANSPORT_OUTCOME_UNCONFIRMED_NO_REPLAY')
        self.ssh.assert_called_once()

    def test_response_drift_and_malformed_fields_are_never_returned(self):
        good = self.response(status='STATUS', queue=row(self.release))
        mutations = [lambda x: x.update(host_scope_verified=False), lambda x: x.update(fox_image=bridge.H_FOX_IMAGE),
                     lambda x: x.update(verifier_release_sha256=B), lambda x: x['queue'].update(package_sha256=B),
                     lambda x: x['queue'].update(created_at_utc=SECRET), lambda x: x['queue'].update(state=SECRET),
                     lambda x: x['queue'].update(updated_at_utc='2026-99-99T00:00:00Z')]
        for mutate in mutations:
            value = copy.deepcopy(good); mutate(value); self.ssh.return_value = value
            with self.subTest(value=value), self.assertRaises(bridge.QueueTransportError) as caught:
                self.dispatch('status', binding=self.bound)
            self.assertNotIn(SECRET, str(caught.exception))


class RealQueueTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='bridge-'); self.addCleanup(self.temp.cleanup)
        self.addCleanup(gc.collect)
        self.root = Path(self.temp.name).resolve()
        # A Windows sandbox can deny strict resolution of the user home. The
        # production reader runs on POSIX; only the root/path shim is replaced,
        # never proof validation, in these queue orchestration tests.
        if os.name == 'nt':
            guard = patch.object(gate, '_safe_path', side_effect=lambda path: Path(path).absolute())
            guard.start(); self.addCleanup(guard.stop)
        self.value = manifest(); self.release = bridge.release_sha256(self.value); self.bound = binding(self.release)
        with closing(sqlite3.connect(self.root / 'fox.sqlite3')) as db, db:
            db.execute('CREATE TABLE runs(id TEXT PRIMARY KEY,source_hash TEXT,state TEXT,artifact TEXT)')
            db.execute('INSERT INTO runs VALUES(?,?,?,?)', (JOB, A, 'QA_REQUIRED', str(Path('jobs') / JOB / 'apex-package.zip')))
            db.execute('CREATE TABLE acceptances(run TEXT,note TEXT)')
            db.execute('INSERT INTO acceptances VALUES(?,?)', ('original-owner-record', 'unchanged'))
            db.execute('CREATE TABLE technical_verifications(run TEXT,proof_sha256 TEXT,artifact_sha256 TEXT)')
        self.queue = queue_module.VerificationQueue(self.root / 'fox.sqlite3', enabled=True, verifier_release_sha256=self.release)
        self.queue.initialize(); self.queue.enqueue(self.bound)
        self.runtime = SimpleNamespace(operator_heartbeat=Mock(return_value={'private': SECRET}))

    def execute(self, op, **options):
        return bridge.container_execute(request(op, document=self.value, **options), queue_module, gate, self.runtime, root=self.root)

    @contextmanager
    def verified(self, state='VERIFIED'):
        with closing(sqlite3.connect(self.root / 'fox.sqlite3')) as db, db:
            db.execute('UPDATE runs SET state=? WHERE id=?', (state, JOB))
            db.execute('INSERT INTO technical_verifications VALUES(?,?,?)', (JOB, PROOF, PACKAGE_SHA))
        # The native retained reader is used by the historical v1 bridge;
        # the queue now independently rechecks through the profile dispatcher.
        checked = Mock(return_value={'package': PACKAGE, 'proof': {
            'job_id': JOB, 'source_manifest_sha256': A, 'package_sha256': PACKAGE_SHA, 'human_acceptance_recorded': False}})
        with patch.object(gate, 'checked_native_release', checked), patch.object(release_gate, 'checked_release', checked):
            yield checked

    def assert_acceptance_unchanged(self):
        with closing(sqlite3.connect(self.root / 'fox.sqlite3')) as db:
            self.assertEqual(db.execute('SELECT * FROM acceptances').fetchall(), [('original-owner-record', 'unchanged')])

    def test_claim_commits_once_and_lost_reply_never_redispatches(self):
        first = self.execute('claim'); self.assertEqual(first['status'], 'CLAIMED')
        self.assertEqual(self.queue.get(JOB)['state'], 'running')
        self.assertEqual(self.execute('claim')['status'], 'IDLE')
        self.assert_acceptance_unchanged()

    def test_status_does_not_heartbeat_initialize_or_change_database(self):
        before = (self.root / 'fox.sqlite3').read_bytes()
        with patch.object(queue_module.VerificationQueue, 'initialize', side_effect=AssertionError('initialization forbidden')):
            self.assertEqual(self.execute('status')['queue']['state'], 'queued')
        self.assertEqual(before, (self.root / 'fox.sqlite3').read_bytes())
        self.runtime.operator_heartbeat.assert_not_called()

    def test_heartbeat_ignores_return_and_does_not_claim(self):
        got = self.execute('heartbeat')
        self.assertEqual(got['status'], 'CONTACT_RECORDED'); self.assertNotIn(SECRET, repr(got))
        self.assertEqual(self.queue.get(JOB)['state'], 'queued')
        self.runtime.operator_heartbeat.assert_called_once_with(self.root, self.release)

    def test_attention_requires_existing_claim_and_preserves_no_replay_state(self):
        claim = self.queue.claim_next()
        self.assertEqual(self.execute('attention', claim=claim, reason='INTERRUPTED_OUTCOME')['queue']['state'], 'attention')
        self.assertEqual(self.execute('claim')['status'], 'IDLE')
        self.assert_acceptance_unchanged()

    def test_complete_calls_real_queue_checked_gate_and_remains_idempotent(self):
        claim = self.queue.claim_next()
        with self.verified('ACCEPTED') as checked:
            self.assertEqual(self.execute('complete', claim=claim, proof=PROOF)['queue']['state'], 'completed')
            self.assertEqual(self.execute('complete', claim=claim, proof=PROOF)['queue']['proof_sha256'], PROOF)
            self.assertEqual(checked.call_count, 2)
        self.assert_acceptance_unchanged()

    def test_fabricated_proof_rejected_by_actual_existing_reader(self):
        claim = self.queue.claim_next()
        with closing(sqlite3.connect(self.root / 'fox.sqlite3')) as db, db:
            db.execute("UPDATE runs SET state='VERIFIED'")
            db.execute('INSERT INTO technical_verifications VALUES(?,?,?)', (JOB, PROOF, PACKAGE_SHA))
        with self.assertRaises(queue_module.QueueError): self.execute('complete', claim=claim, proof=PROOF)
        self.assertEqual(self.queue.get(JOB)['state'], 'attention')
        self.assert_acceptance_unchanged()

    def test_reconcile_attention_reads_proof_then_rechecks_real_completion_gate(self):
        claim = self.queue.claim_next(); self.queue.attention(claim)
        with self.verified() as checked, patch.object(gate, 'promote_native_run', side_effect=AssertionError('no promotion')):
            result = self.execute('reconcile')
            self.assertEqual(result['queue']['state'], 'completed'); self.assertEqual(checked.call_count, 2)
        self.assert_acceptance_unchanged()

    def test_reconcile_running_or_completed_requires_retained_private_claim(self):
        claim = self.queue.claim_next()
        with self.verified() as checked:
            with self.assertRaisesRegex(bridge.QueueTransportError, 'RETAINED_PRIVATE_CLAIM_REQUIRED'): self.execute('reconcile')
            checked.assert_not_called()
            self.assertEqual(self.execute('reconcile', claim=claim)['queue']['state'], 'completed')
            self.assertEqual(self.execute('reconcile', claim=claim)['queue']['state'], 'completed')
        self.assert_acceptance_unchanged()

    def test_reconcile_queued_or_missing_proof_never_recovers_or_dispatches(self):
        with patch.object(queue_module.VerificationQueue, 'recover_running', side_effect=AssertionError('no recovery')):
            with self.assertRaisesRegex(bridge.QueueTransportError, 'QUEUE_RECONCILIATION_STATE_INVALID'):
                self.execute('reconcile')
            claim = self.queue.claim_next(); self.queue.attention(claim)
            with self.assertRaises(gate.VerificationError): self.execute('reconcile')
        self.assertEqual(self.queue.get(JOB)['state'], 'attention')
        self.assert_acceptance_unchanged()


def container_inspect():
    return {'Id': 'e' * 64, 'Image': FUTURE, 'State': {'Running': True},
            'Config': {'User': '1000:1000', 'Env': ['FOX_VERIFICATION_ENABLED=1']},
            'HostConfig': {'UsernsMode': '', 'ReadonlyRootfs': True, 'Tmpfs': {'/tmp': 'rw,noexec,nosuid'}},
            'Mounts': [{'Type': 'bind', 'Source': '/home/opc/fox/data', 'Destination': '/data', 'RW': True},
                       {'Type': 'bind', 'Source': PROFILE_HOST, 'Destination': '/run/fox-native/profile.json', 'RW': False},
                       {'Type': 'bind', 'Source': '/home/opc/fox/secure/opaf-client', 'Destination': '/run/fox-opaf', 'RW': False}]}


class GeneratedHostTests(unittest.TestCase):
    def run_host(self, inspected=None, metadata=None, *, optimize=0, profile=PROFILE,
                 profile_link=False, profile_file=True, profile_size=None, legacy_string=False):
        req = request('claim')
        packet = {'request': req, 'cli_scope': {'instance_id': C.INSTANCE, 'compartment_id': C.COMPARTMENT, 'database_id': C.DATABASE}}
        meta = metadata or {'id': C.INSTANCE, 'compartmentId': C.COMPARTMENT, 'canonicalRegionName': C.REGION}
        captured = io.StringIO()
        successful = {'status': 'IDLE', 'verifier_release_sha256': req['release_sha256']}
        outcomes = [SimpleNamespace(returncode=0, stdout=json.dumps([inspected or container_inspect()]).encode(), stderr=b''),
                    SimpleNamespace(returncode=0, stdout=json.dumps(successful).encode(), stderr=b'')]
        parse_json = json.loads
        class Python36String(str):
            def __getattribute__(self, name):
                if name in {'removeprefix', 'removesuffix'}:
                    raise AttributeError('STRING_METHOD_NOT_AVAILABLE_ON_PYTHON36')
                return super().__getattribute__(name)
        def parse_host_json(*args, **kwargs):
            parsed = parse_json(*args, **kwargs)
            if legacy_string and type(parsed) is list and parsed and type(parsed[0]) is dict and 'Image' in parsed[0]:
                parsed[0]['Image'] = Python36String(parsed[0]['Image'])
            return parsed
        with patch.object(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(json.dumps(packet).encode()))), \
             patch.object(urllib.request, 'urlopen', return_value=io.BytesIO(json.dumps(meta).encode())), \
             patch.object(json, 'loads', side_effect=parse_host_json), \
             patch.object(Path, 'resolve', lambda path, **kwargs: path), \
             patch.object(Path, 'is_file', return_value=profile_file), \
             patch.object(Path, 'is_symlink', return_value=profile_link), \
             patch.object(Path, 'stat', return_value=SimpleNamespace(st_size=len(profile) if profile_size is None else profile_size)), \
             patch.object(Path, 'open', return_value=io.BytesIO(profile)), \
             patch.object(subprocess, 'run', side_effect=outcomes) as run, redirect_stdout(captured):
            exec(compile(bridge.host_source(), '<offline-host>', 'exec', optimize=optimize), {})
        return json.loads(captured.getvalue()), run

    def test_fixed_host_exec_by_container_id_uses_isolated_framed_stdin(self):
        result, run = self.run_host()
        self.assertIs(result['host_scope_verified'], True)
        args = run.call_args.args[0]
        self.assertEqual(args[:8], ['podman', 'exec', '-i', 'e' * 64, '/usr/local/bin/python', '-I', '-B', '-c'])
        script, body = run.call_args.kwargs['input'].split(b'\n', 1)
        self.assertEqual(base64.b64decode(script).decode(), bridge.container_source())
        self.assertEqual(json.loads(body)['operation'], 'claim')

    def test_wrong_host_fails_before_any_container_process_under_optimization(self):
        for optimize in (0, 1, 2):
            result, run = self.run_host(metadata={'id': 'wrong', 'compartmentId': C.COMPARTMENT, 'canonicalRegionName': C.REGION}, optimize=optimize)
            self.assertEqual(result['status'], 'STOPPED'); run.assert_not_called()

    def test_wrong_image_user_rootfs_mount_or_interpreter_overlay_fails_preexec(self):
        mutations = [lambda v: v.update(Image=bridge.H_FOX_IMAGE), lambda v: v['Config'].update(User='0:0'),
                     lambda v: v['HostConfig'].update(ReadonlyRootfs=False),
                     lambda v: v['HostConfig'].update(UsernsMode='other'),
                     lambda v: v['Mounts'][0].update(Source='/different/data'),
                     lambda v: v['Mounts'][0].update(Destination='/app'),
                     lambda v: v['Mounts'][1].update(Source='/different/profile.json'),
                     lambda v: v['Mounts'][1].update(RW=True),
                     lambda v: v['Mounts'].pop(1),
                     lambda v: v['Mounts'].clear(),
                     lambda v: v['Mounts'].append({'Destination': '/usr/local', 'Type': 'bind', 'Source': '/changed', 'RW': False}),
                     lambda v: v['HostConfig'].update(Tmpfs={'/usr/local': 'rw'}),
                     lambda v: v['Config']['Env'].append('LD_PRELOAD=/data/evil.so')]
        for mutate in mutations:
            inspected = container_inspect(); mutate(inspected)
            result, run = self.run_host(inspected)
            self.assertEqual(result['status'], 'STOPPED'); self.assertEqual(run.call_count, 1)

    def test_native_profile_hash_and_file_guards_precede_container_execution(self):
        for options in ({'profile': SECRET.encode()}, {'profile_link': True}, {'profile_file': False},
                        {'profile_size': 65537}, {'profile': b''}, {'profile': b'x' * 65537}):
            with self.subTest(options=options):
                result, run = self.run_host(**options)
                self.assertEqual(result['status'], 'STOPPED'); self.assertEqual(run.call_count, 1)
                self.assertNotIn(SECRET, repr(result))

    def test_host_image_normalization_runs_without_python39_string_methods(self):
        # Execute, do not merely AST-parse: Python 3.6 accepts the syntax of
        # str.removeprefix but does not supply that method at runtime.
        for image in (FUTURE, FUTURE[7:]):
            inspected = container_inspect(); inspected['Image'] = image
            result, run = self.run_host(inspected, legacy_string=True)
            self.assertEqual(result['status'], 'IDLE'); self.assertEqual(run.call_count, 2)

    def test_generated_sources_have_no_assert_or_arbitrary_operation_dispatch(self):
        for source in (bridge.host_source(), bridge.container_source()):
            tree = ast.parse(source)
            self.assertFalse(any(isinstance(n, ast.Assert) for n in ast.walk(tree)))
        self.assertNotIn('recover_running(', bridge.container_source())
        self.assertNotIn('promote_native_run(', bridge.container_source())


class InstalledLoaderTests(unittest.TestCase):
    def run_loader(self, *, bad_module=None, disabled=False, release_mismatch=False, effective_uid=1000,
                   optimize=0, heartbeat=None, profile=PROFILE, profile_link=False):
        modules = {name: b'import builtins\nbuiltins._queue_bridge_test_effect(__name__)\n' for name in bridge.MODULES}
        if heartbeat is not None:
            modules['verification_queue.py'] += b'class VerificationQueue:\n def __init__(self,*args,**kwargs):pass\n'
            modules['verification_runtime.py'] += (b'def operator_heartbeat(root,release):\n'
                b' return builtins._queue_bridge_test_heartbeat(root,release)\n')
        value = manifest(); value['modules'] = {name: C.digest(raw) for name, raw in modules.items()}
        req = request('heartbeat', document=value)
        if bad_module: modules[bad_module] += SECRET.encode()
        env = {'FOX_VERIFICATION_ENABLED': '0' if disabled else '1',
               'FOX_VERIFIER_RELEASE_SHA256': B if release_mismatch else req['release_sha256']}
        effects = Mock(); out = io.StringIO()
        profile_path = Path('/run/fox-native/profile.json')
        def open_source(path, *args, **kwargs):
            return io.BytesIO(profile if path == profile_path else modules[path.name])
        with ExitStack() as stack:
            stack.enter_context(patch.dict(sys.modules))
            stack.enter_context(patch.dict(os.environ, env))
            stack.enter_context(patch.object(os, 'geteuid', return_value=effective_uid, create=True))
            stack.enter_context(patch.object(os, 'getegid', return_value=1000, create=True))
            stack.enter_context(patch('builtins._queue_bridge_test_effect', effects, create=True))
            stack.enter_context(patch('builtins._queue_bridge_test_heartbeat', heartbeat, create=True))
            stack.enter_context(patch.object(Path, 'resolve', lambda p, **kwargs: p))
            stack.enter_context(patch.object(Path, 'is_file', return_value=True))
            stack.enter_context(patch.object(Path, 'is_symlink', lambda p: profile_link if p == profile_path else False))
            stack.enter_context(patch.object(Path, 'stat', return_value=SimpleNamespace(st_size=100)))
            stack.enter_context(patch.object(Path, 'open', open_source))
            stack.enter_context(patch.object(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(json.dumps(req).encode()))))
            stack.enter_context(redirect_stdout(out))
            exec(compile(bridge.container_source(), '<offline-container>', 'exec', optimize=optimize), {})
        return json.loads(out.getvalue()), effects

    def test_all_four_module_hashes_checked_before_any_import_or_side_effect(self):
        for name in bridge.MODULES:
            result, effects = self.run_loader(bad_module=name)
            self.assertEqual(result['status'], 'STOPPED'); effects.assert_not_called()
            self.assertNotIn(SECRET, repr(result))

    def test_runtime_env_and_effective_user_gate_precede_installed_imports(self):
        for options in ({'disabled': True}, {'release_mismatch': True}, {'effective_uid': 0}):
            result, effects = self.run_loader(**options)
            self.assertEqual(result['status'], 'STOPPED'); effects.assert_not_called()

    def test_host_valid_but_mounted_profile_stale_stops_before_import_or_queue_action(self):
        host_result, _ = GeneratedHostTests().run_host()
        self.assertIs(host_result['host_scope_verified'], True)
        for options in ({'profile': b'stale bound inode'}, {'profile_link': True},
                        {'profile': b''}, {'profile': b'x' * 65537}):
            result, effects = self.run_loader(**options)
            self.assertEqual(result['status'], 'STOPPED'); effects.assert_not_called()

    def test_checked_bytes_are_compiled_without_loading_fox_initializer_or_pyc(self):
        for optimize in (0, 1, 2):
            result, effects = self.run_loader(optimize=optimize)
            # Stub modules deliberately omit APIs; they execute from checked
            # bytes before the bounded, expected missing-API failure.
            self.assertEqual(result['status'], 'STOPPED')
            self.assertEqual([call.args[0] for call in effects.call_args_list],
                ['fox.native_verification_policy', 'fox.verification_queue', 'fox.native_verification', 'fox.verification_runtime'])

    def test_generated_loader_success_has_fixed_projection_and_suppresses_module_logs(self):
        def beat(root, release):
            print(SECRET)
            return {'secret': SECRET, 'claim_token': TOKEN}
        result, effects = self.run_loader(heartbeat=beat)
        self.assertEqual(result['status'], 'CONTACT_RECORDED')
        self.assertNotIn(SECRET, repr(result)); self.assertNotIn(TOKEN, repr(result))
        self.assertEqual(effects.call_count, 4)

    def test_generated_loader_module_exception_text_is_never_returned(self):
        result, _ = self.run_loader(heartbeat=Mock(side_effect=RuntimeError(SECRET)))
        self.assertEqual(result, {'status': 'STOPPED', 'code': 'QUEUE_CONTAINER_OUTCOME_UNCONFIRMED_NO_REPLAY',
                                 'automatic_replay_permitted': False})


if __name__ == '__main__':
    unittest.main()
