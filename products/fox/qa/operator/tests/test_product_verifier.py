"""Offline pump tests: temporary SQLite, fake phases, no external execution.

Positive proof fixtures mock the existing checked_native_release reader. They
prove orchestration and queue binding, not an APEX import or runtime QA pass.
Only the fake promotion boundary changes product state; acceptance is untouched.
"""
from contextlib import ExitStack, closing, redirect_stderr, redirect_stdout
import copy
import io
import json
from pathlib import Path
import runpy
import socket
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[3]
for folder in (ROOT, ROOT / 'fox'):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))
from qa.operator import product_verifier as p
from qa.operator import product_queue_transport as bridge
from qa.operator import contracts as C
from fox import native_verification as gate
from fox import technical_release as release_gate
from fox import verification_queue as q

FUTURE = 'sha256:' + 'f' * 64
SECRET = 'DoNotExposeCredentialOrProviderOutput'
STEPS = ('prepare', 'clean_check', 'allocate', 'schema', 'import', 'verify',
         'qa_stage', 'qa_run', 'qa_collect', 'promotion_check', 'promotion_apply', 'queue_complete')


class FakeClock:
    def __init__(self):
        self.value = 0
        self.sleeps = []

    def __call__(self):
        return self.value

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.value += seconds


class FakePhases:
    """Replies shaped like guarded operators; never calls those operators."""
    def __init__(self, harness):
        self.h = harness
        self.calls = []
        self.failures = {}
        self.extra = None
        self.qa_exit = 0

    def perform(self, step, binding, context):
        self.calls.append((step, binding.job_id))
        self.h.trace.append(step)
        self.h.assert_intent(step)
        before = self.h.product_rows()
        if self.failures.get(step) == 'unknown':
            return {'status': 'UNKNOWN', 'provider_output': SECRET}
        plan = C.digest(('plan ' + binding.job_id).encode())
        result = {
            'prepare': {'plan_sha256': plan, 'job_id': binding.job_id,
                        'source_manifest_sha256': binding.source_manifest_sha256,
                        'package_sha256': binding.package_sha256,
                        'operator_code_sha256': self.h.manifest['clean_operator_code_sha256']},
            'clean_check': {'state': 'PREPARED', 'plan_sha256': plan},
            'qa_stage': {'status': 'STAGED', 'plan_sha256': plan,
                         'source_sha256': self.h.manifest['qa_source_sha256'],
                         'allocation_receipt_sha256': 'a' * 64, 'image_id': FUTURE},
            'qa_run': {'status': 'PASSED' if self.qa_exit == 0 else 'QA_FAILED_OR_INCOMPLETE',
                       'exit_code': self.qa_exit, 'plan_sha256': plan,
                       'source_sha256': self.h.manifest['qa_source_sha256'], 'image_id': FUTURE},
            'qa_collect': {'status': 'COLLECTED', 'plan_sha256': plan,
                           'source_sha256': self.h.manifest['qa_source_sha256'],
                           'collection_manifest_sha256': 'b' * 64},
            'promotion_check': {'status': 'READY_NOT_APPLIED', 'job_id': binding.job_id,
                                'human_acceptance_recorded': False},
        }.get(step)
        if step in ('allocate', 'schema', 'import', 'verify'):
            result = {'state': 'QA_READY' if step == 'verify' else 'PHASE_COMPLETE',
                      'action': 'COMPLETED_ONCE', 'plan_sha256': plan, 'evidence_sha256': 'c' * 64}
        if step == 'promotion_apply':
            result = {'status': 'VERIFIED', 'job_id': binding.job_id,
                      'human_acceptance_recorded': False, 'proof_sha256': self.h.publish_fixture(binding)}
        else:
            assert self.h.product_rows() == before
        if self.failures.get(step) == 'lost':
            raise RuntimeError(SECRET)
        if self.extra == step:
            result['provider_output'] = SECRET
        return result


class FakeTransport:
    """Use the actual fixed bridge dispatcher against an isolated queue."""
    def __init__(self, harness):
        self.h = harness
        self.calls = []
        self.failures = {}
        self.extra = False
        self.claims = []

    def __call__(self, operation, manifest, *, expected_release_sha256, apply=False,
                 claim=None, binding=None, code=None, proof_sha256=None):
        self.calls.append(operation)
        self.h.trace.append(operation)
        assert manifest == self.h.manifest
        assert expected_release_sha256 == self.h.release
        assert apply is (operation != 'status')
        if operation in ('claim', 'complete'):
            self.h.assert_intent('claim' if operation == 'claim' else 'queue_complete')
        if self.failures.get(operation) == 'unknown':
            return {'status': 'UNKNOWN', 'provider_output': SECRET}
        binding = claim.binding if claim is not None else binding
        request = {'operation': operation, 'apply': apply, 'manifest': manifest,
                   'release_sha256': expected_release_sha256,
                   'binding': binding.payload() if binding else None,
                   'claim': p._claim_payload(claim) if claim else None,
                   'code': code, 'proof_sha256': proof_sha256}
        before = self.h.product_rows()
        result = bridge.container_execute(request, q,
            SimpleNamespace(verify_existing_native_run=self.h.existing_proof),
            SimpleNamespace(operator_heartbeat=lambda root, release: self.h.heartbeats.append((root, release))),
            root=self.h.root)
        assert self.h.product_rows() == before, 'QUEUE_MUST_NOT_CHANGE_PRODUCT_TABLES'
        if result.get('claim'):
            self.claims.append(result['claim']['attempt_token'])
        if self.failures.get(operation) == 'lost':
            raise RuntimeError(SECRET)
        if self.extra:
            result['provider_output'] = SECRET
            if 'queue' in result:
                result['queue']['private_detail'] = SECRET
        return result


class Harness:
    def __init__(self):
        self.stack = ExitStack()
        try:
            self._initialize()
        except BaseException:
            self.stack.close()
            raise

    def _initialize(self):
        self.temp = self.stack.enter_context(tempfile.TemporaryDirectory(prefix='fox-pump-'))
        self.root = Path(self.temp).resolve()
        self.private = self.root / 'private'
        self.private.mkdir()
        self.stack.enter_context(patch.object(p.clean, 'PRIVATE', self.private))
        self.stack.enter_context(patch.object(p, 'JOURNAL_ROOT', self.private / 'pump'))
        self.stack.enter_context(patch.object(p.clean, 'private_directory', side_effect=lambda path: path.mkdir(mode=0o700)))
        self.stack.enter_context(patch.object(p.promotion, 'private_inputs', return_value=None))
        self.stack.enter_context(patch.object(p.clean, 'FOX_IMAGE', FUTURE))
        for module, name in ((subprocess, 'run'), (subprocess, 'Popen'),
                             (socket, 'create_connection'), (socket.socket, 'connect'),
                             (p.clean, 'oci_scope'), (p.clean, 'ssh_json')):
            self.stack.enter_context(patch.object(module, name, side_effect=AssertionError('EXTERNAL_ACTION_FORBIDDEN')))
        self.manifest = p.build_manifest({'schema_version': 1,
            'scope': 'fox-product-verifier-operator-config-v1', 'enabled': True,
            'images': {'fox': FUTURE, 'converter': p.clean.IMAGE}})
        self.release = bridge.release_sha256(self.manifest)
        self.database = self.root / 'fox.sqlite3'
        with closing(sqlite3.connect(self.database)) as db, db:
            db.executescript('''
                CREATE TABLE runs(id TEXT PRIMARY KEY, source_hash TEXT, state TEXT, artifact TEXT);
                CREATE TABLE technical_verifications(run TEXT PRIMARY KEY,source_hash TEXT,artifact_sha256 TEXT,
                    proof_sha256 TEXT,proof_json TEXT,created REAL);
                CREATE TABLE acceptances(run TEXT,owner TEXT,notes TEXT);
                INSERT INTO acceptances VALUES('existing-fixture','synthetic-owner','untouched');
                CREATE TABLE events(action TEXT,object_id TEXT);
                INSERT INTO events VALUES('existing-fixture','untouched');
            ''')
        self.queue = q.VerificationQueue(self.database, enabled=True, verifier_release_sha256=self.release)
        self.queue.initialize()
        self.packages = {}
        self.trace = []
        self.heartbeats = []
        self.gate_calls = []
        self.real_checked_gate = release_gate.checked_release
        self.stack.enter_context(patch.object(release_gate, 'checked_release', side_effect=self.checked_fixture))
        self.clock = FakeClock()
        self.transport = FakeTransport(self)
        self.phases = FakePhases(self)
        self.journal = p.PrivateJournal(self.release)

    def close(self):
        self.stack.close()

    def verifier(self, **kwargs):
        return p.ProductVerifier(self.manifest, self.release, transport=self.transport,
            phases=self.phases, journal=self.journal, clock=self.clock, sleeper=self.clock.sleep, **kwargs)

    def add_job(self, number=1):
        job = 'fox-' + format(number, '020x')
        package = ('synthetic package ' + job).encode()
        self.packages[job] = package
        bound = q.VerificationBinding(job, C.digest(('source ' + job).encode()), C.digest(package), self.release)
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute('INSERT INTO runs VALUES(?,?,?,?)', (job, bound.source_manifest_sha256, 'QA_REQUIRED',
                       str(Path('jobs') / job / 'apex-package.zip')))
        self.queue.enqueue(bound)
        return bound

    def assert_intent(self, step):
        label = step.replace('_', '-')
        candidates = list(self.journal.root.glob('session-*/p????-' + label + '.intent.json'))
        assert candidates, 'DURABLE_INTENT_REQUIRED_BEFORE_DISPATCH'

    def product_rows(self):
        with closing(sqlite3.connect(self.database)) as db:
            return {name: db.execute('SELECT * FROM ' + name + ' ORDER BY 1').fetchall()
                    for name in ('runs', 'technical_verifications', 'acceptances', 'events')}

    def publish_fixture(self, binding):
        """The sole fake promotion action, never an assertion of real QA."""
        proof = {'job_id': binding.job_id, 'source_manifest_sha256': binding.source_manifest_sha256,
                 'package_sha256': binding.package_sha256, 'human_acceptance_recorded': False}
        raw = C.canonical_bytes(proof)
        digest = C.digest(raw)
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute("UPDATE runs SET state='VERIFIED' WHERE id=?", (binding.job_id,))
            db.execute('INSERT INTO technical_verifications VALUES(?,?,?,?,?,?)',
                (binding.job_id, binding.source_manifest_sha256, binding.package_sha256, digest, raw.decode(), 1.0))
        return digest

    def checked_fixture(self, db, root, run):
        assert root == self.root
        self.gate_calls.append(run['id'])
        row = db.execute('SELECT proof_json FROM technical_verifications WHERE run=?', (run['id'],)).fetchone()
        return {'proof': json.loads(row[0]), 'package': self.packages[run['id']]}

    def existing_proof(self, *, root, run_id):
        assert root == self.root
        with closing(sqlite3.connect(self.database)) as db:
            state = db.execute('SELECT state FROM runs WHERE id=?', (run_id,)).fetchone()[0]
            row = db.execute('SELECT proof_sha256 FROM technical_verifications WHERE run=?', (run_id,)).fetchone()
        if row is None:
            raise RuntimeError(SECRET)
        return {'id': run_id, 'state': state, 'read_only': True, 'idempotent': True,
                'active_policy_applied': False, 'proof_sha256': row[0]}


class ProductVerifierTests(unittest.TestCase):
    def setUp(self):
        self.h = Harness()
        self.addCleanup(self.h.close)

    def assert_safe(self, result):
        rendered = json.dumps(result)
        self.assertNotIn(SECRET, rendered)
        for token in self.h.transport.claims:
            self.assertNotIn(token, rendered)
        self.assertIs(result['automatic_replay_permitted'], False)
        for path in self.h.journal.root.glob('session-*/*.json'):
            self.assertNotIn(SECRET.encode(), path.read_bytes())

    def assert_blocked_reconnect(self):
        before_calls = list(self.h.transport.calls)
        before_phases = list(self.h.phases.calls)
        before_files = {str(path): path.read_bytes() for path in self.h.journal.root.rglob('*') if path.is_file()}
        with self.assertRaisesRegex(p.ProductVerifierError, 'UNRESOLVED_SESSION_NO_NEW_DISPATCH'):
            self.h.verifier().pump(apply=True)
        self.assertEqual(self.h.transport.calls, before_calls)
        self.assertEqual(self.h.phases.calls, before_phases)
        self.assertEqual({str(path): path.read_bytes() for path in self.h.journal.root.rglob('*') if path.is_file()}, before_files)

    def test_exact_phase_order_and_create_only_evidence(self):
        binding = self.h.add_job()
        before = self.h.product_rows()
        result = self.h.verifier().pump(apply=True)
        self.assertEqual(p.STEPS, STEPS)
        self.assertEqual(result['status'], 'SESSION_COMPLETE')
        self.assertEqual([step for step, _ in self.h.phases.calls], list(STEPS[:-1]))
        self.assertEqual(self.h.transport.calls.count('claim'), 1)
        self.assertEqual(self.h.transport.calls.count('complete'), 1)
        self.assertEqual(self.h.transport.calls.count('heartbeat'), 1 + len(STEPS))
        self.assertEqual(self.h.queue.get(binding.job_id)['state'], 'completed')
        self.assertEqual(self.h.gate_calls, [binding.job_id])
        after = self.h.product_rows()
        self.assertEqual(after['acceptances'], before['acceptances'])
        self.assertEqual(after['events'], before['events'])
        self.assertEqual(after['runs'][0][2], 'VERIFIED')
        self.assertEqual(len(after['technical_verifications']), 1)
        directory = Path(result['private_session'])
        self.assertEqual(len(list(directory.glob('*.intent.json'))), 1 + len(STEPS))
        self.assertEqual(len(list(directory.glob('*.complete.json'))), 1 + len(STEPS))
        self.assertEqual(self.h.journal.pending(), [])
        first = (directory / 'p0001-prepare.intent.json').read_bytes()
        with self.assertRaises(p.clean.OperatorError):
            self.h.journal.intent(directory, 'p0001-prepare', binding)
        self.assertEqual((directory / 'p0001-prepare.intent.json').read_bytes(), first)
        self.assert_safe(result)

    def test_actual_local_manifest_hashes_and_expected_sha_are_checked_before_writes(self):
        self.assertEqual(self.h.manifest['code']['product_verifier.py'], C.digest(Path(p.__file__).read_bytes()))
        self.assertEqual(bridge.require_ready(self.h.manifest, self.h.release), self.h.manifest)
        verifier = p.ProductVerifier(self.h.manifest, '0' * 64, transport=self.h.transport, phases=self.h.phases)
        with self.assertRaisesRegex(bridge.QueueTransportError, 'EXACT_VERIFIER_RELEASE_REQUIRED'):
            verifier.pump(apply=True)
        self.assertFalse(p.JOURNAL_ROOT.exists())
        self.assertEqual(self.h.transport.calls, [])

    def test_unknown_operator_config_fields_reject_before_source_reads_or_writes(self):
        config = {**p.read_config(), 'enabled': True, 'authorization': SECRET}
        with patch.object(p, 'source_bytes') as source, self.assertRaisesRegex(
                p.ProductVerifierError, 'OPERATOR_CONFIG_INVALID') as caught:
            p.build_manifest(config)
        source.assert_not_called()
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertFalse(p.JOURNAL_ROOT.exists())
        self.assertEqual(self.h.transport.calls, [])

    def test_failed_harness_initialization_cleans_temporary_files_and_patches(self):
        private, journal_root, process = p.clean.PRIVATE, p.JOURNAL_ROOT, subprocess.run
        failed = Harness.__new__(Harness)
        with patch.object(p, 'build_manifest', side_effect=RuntimeError('FIXTURE_SETUP_FAILURE')), \
             self.assertRaisesRegex(RuntimeError, 'FIXTURE_SETUP_FAILURE'):
            failed.__init__()
        self.assertFalse(failed.root.exists())
        self.assertEqual(p.clean.PRIVATE, private)
        self.assertEqual(p.JOURNAL_ROOT, journal_root)
        self.assertIs(subprocess.run, process)

    def test_real_byte_hash_drift_in_each_release_family_stops_before_private_files(self):
        changes = ('modules', 'code', 'clean_operator_code_sha256', 'qa_source_sha256',
                   'promotion_transport_sha256', 'native_profile_sha256')
        for field in changes:
            manifest = copy.deepcopy(self.h.manifest)
            if field in ('modules', 'code'):
                manifest[field][next(iter(manifest[field]))] = '0' * 64
            else:
                manifest[field] = '0' * 64
            with self.subTest(field=field), self.assertRaises(bridge.QueueTransportError):
                p.ProductVerifier(manifest, bridge.release_sha256(manifest), transport=self.h.transport,
                                  phases=self.h.phases).pump(apply=True)
            self.assertFalse(p.JOURNAL_ROOT.exists())
        self.assertEqual(self.h.transport.calls, [])

    def test_source_drift_between_phases_stops_before_next_phase(self):
        binding = self.h.add_job()
        original = self.h.phases.perform
        def perform(step, bound, context):
            result = original(step, bound, context)
            if step == 'prepare':
                self.h.stack.enter_context(patch.object(bridge, '_file_sha', return_value='0' * 64))
            return result
        self.h.phases.perform = perform
        result = self.h.verifier().pump(apply=True)
        self.assertEqual(result['status'], 'ATTENTION')
        self.assertEqual(self.h.phases.calls, [('prepare', binding.job_id)])
        self.assertEqual(self.h.transport.calls, ['heartbeat', 'claim', 'heartbeat'])
        self.assert_safe(result)

    def test_disabled_and_actual_h_manifest_never_lock_write_or_contact(self):
        for enabled, image, code in ((False, FUTURE, 'VERIFIER_RELEASE_DISABLED'),
                                      (True, bridge.H_FOX_IMAGE, 'LIVE_H_QUEUE_UNAVAILABLE')):
            manifest = copy.deepcopy(self.h.manifest)
            manifest['enabled'], manifest['images']['fox'] = enabled, image
            journal = Mock()
            verifier = p.ProductVerifier(manifest, bridge.release_sha256(manifest),
                transport=self.h.transport, phases=self.h.phases, journal=journal)
            with self.subTest(code=code), self.assertRaisesRegex(bridge.QueueTransportError, code):
                verifier.pump(apply=True)
            journal.lock.assert_not_called()
            self.assertFalse(p.JOURNAL_ROOT.exists())
        self.assertEqual(self.h.transport.calls, [])

    def test_explicit_startup_and_finite_integer_bounds_required_before_contact(self):
        cases = ({}, {'apply': 1}, {'apply': True, 'max_jobs': 0}, {'apply': True, 'max_jobs': 6},
                 {'apply': True, 'max_jobs': 2, 'max_polls': 1}, {'apply': True, 'max_polls': 121},
                 {'apply': True, 'max_seconds': 0}, {'apply': True, 'max_seconds': 7201},
                 {'apply': True, 'poll_seconds': 0}, {'apply': True, 'poll_seconds': 61},
                 {'apply': True, 'max_jobs': True}, {'apply': True, 'max_seconds': 1.5})
        for options in cases:
            with self.subTest(options=options), self.assertRaises(p.ProductVerifierError):
                self.h.verifier().pump(**options)
        self.assertFalse(p.JOURNAL_ROOT.exists())
        self.assertEqual(self.h.transport.calls, [])

    def test_finite_loop_processes_multiple_jobs_with_heartbeats_and_safe_result(self):
        bindings = [self.h.add_job(number) for number in range(1, 4)]
        self.h.transport.extra = True
        result = self.h.verifier().pump(apply=True, max_jobs=2, max_polls=4, max_seconds=30, poll_seconds=2)
        self.assertEqual([row['job_id'] for row in result['completed_jobs']], [b.job_id for b in bindings[:2]])
        self.assertEqual(self.h.queue.get(bindings[2].job_id)['state'], 'queued')
        self.assertEqual(self.h.transport.calls.count('claim'), 2)
        self.assertEqual(self.h.transport.calls.count('complete'), 2)
        self.assertEqual(len(self.h.heartbeats), 2 * (1 + len(STEPS)))
        self.assertEqual(self.h.clock.sleeps, [2])
        self.assert_safe(result)

    def test_idle_polling_is_bounded_by_poll_count(self):
        result = self.h.verifier().pump(apply=True, max_polls=3, max_seconds=30, poll_seconds=2)
        self.assertEqual(result['completed_jobs'], [])
        self.assertEqual(self.h.transport.calls, ['heartbeat', 'claim'] * 3)
        self.assertEqual(self.h.clock.sleeps, [2, 2])
        self.assertEqual(self.h.phases.calls, [])
        self.assert_safe(result)

    def test_elapsed_bound_prevents_another_poll_and_caps_sleep(self):
        result = self.h.verifier().pump(apply=True, max_polls=5, max_seconds=3, poll_seconds=5)
        self.assertEqual(result['status'], 'SESSION_COMPLETE')
        self.assertEqual(self.h.transport.calls, ['heartbeat', 'claim'])
        self.assertEqual(self.h.clock.sleeps, [3])

    def test_terminal_sessions_allow_fresh_poll_but_never_replay_completed_job(self):
        binding = self.h.add_job()
        first = self.h.verifier().pump(apply=True)
        old = {path.name: path.read_bytes() for path in Path(first['private_session']).iterdir()}
        phases = list(self.h.phases.calls)
        second = self.h.verifier().pump(apply=True)
        self.assertEqual(second['completed_jobs'], [])
        self.assertEqual(self.h.phases.calls, phases)
        self.assertEqual(self.h.queue.get(binding.job_id)['state'], 'completed')
        self.assertEqual({path.name: path.read_bytes() for path in Path(first['private_session']).iterdir()}, old)

    def test_known_qa_failure_collects_readonly_evidence_then_blocks_promotion(self):
        binding = self.h.add_job()
        before = self.h.product_rows()
        self.h.phases.qa_exit = 2
        result = self.h.verifier().pump(apply=True)
        self.assertEqual(result['status'], 'ATTENTION')
        self.assertEqual([step for step, _ in self.h.phases.calls], list(STEPS[:9]))
        self.assertTrue((Path(result['private_session']) / 'p0001-qa-collect.complete.json').is_file())
        self.assertEqual(self.h.queue.get(binding.job_id)['state'], 'attention')
        self.assertEqual(self.h.product_rows(), before)
        self.assertNotIn('complete', self.h.transport.calls)
        self.assert_blocked_reconnect()
        self.assert_safe(result)

    def test_unknown_phase_provider_fields_are_rejected_without_retention(self):
        self.h.add_job()
        self.h.phases.extra = 'prepare'
        result = self.h.verifier().pump(apply=True)
        self.assertEqual(result['status'], 'ATTENTION')
        self.assertEqual(len(self.h.phases.calls), 1)
        self.assert_safe(result)

    def test_existing_real_proof_gate_rejects_synthetic_claim_without_retained_evidence(self):
        binding = self.h.add_job()
        before = self.h.product_rows()['acceptances']
        with patch.object(release_gate, 'checked_release', side_effect=self.h.real_checked_gate) as checked:
            result = self.h.verifier().pump(apply=True)
        self.assertEqual(result['status'], 'ATTENTION')
        checked.assert_called_once()
        self.assertEqual(self.h.queue.get(binding.job_id)['state'], 'attention')
        self.assertEqual(self.h.product_rows()['acceptances'], before)
        self.assertFalse((Path(result['private_session']) / 'p0001-queue-complete.complete.json').exists())
        self.assert_safe(result)

    def test_exact_stored_proof_hash_is_rechecked_before_queue_completion(self):
        binding = self.h.add_job()
        original = self.h.phases.perform
        def perform(step, bound, context):
            result = original(step, bound, context)
            if step == 'promotion_apply':
                result['proof_sha256'] = '0' * 64
            return result
        self.h.phases.perform = perform
        result = self.h.verifier().pump(apply=True)
        self.assertEqual(result['status'], 'ATTENTION')
        self.assertEqual(self.h.queue.get(binding.job_id)['state'], 'attention')
        self.assertEqual(self.h.gate_calls, [binding.job_id])
        self.assert_blocked_reconnect()
        self.assert_safe(result)

    def test_lost_heartbeat_before_claim_has_no_claim_or_phase_and_blocks_reconnect(self):
        self.h.add_job()
        before = self.h.product_rows()
        self.h.transport.failures['heartbeat'] = 'lost'
        result = self.h.verifier().pump(apply=True)
        self.assertEqual(self.h.transport.calls, ['heartbeat'])
        self.assertEqual(self.h.phases.calls, [])
        self.assertEqual(self.h.product_rows(), before)
        self.assert_blocked_reconnect()
        self.assert_safe(result)

    def test_reconcile_uses_existing_proof_only_and_preserves_genuine_later_acceptance(self):
        binding = self.h.add_job()
        self.h.phases.failures['promotion_apply'] = 'lost'
        result = self.h.verifier().pump(apply=True)
        with closing(sqlite3.connect(self.h.database)) as db, db:
            db.execute("UPDATE runs SET state='ACCEPTED' WHERE id=?", (binding.job_id,))
            db.execute('INSERT INTO acceptances VALUES(?,?,?)', (binding.job_id, 'fixture-owner', 'genuine fixture decision'))
        before = self.h.product_rows()
        phases = list(self.h.phases.calls)
        self.h.transport.calls.clear()
        reconciled = self.h.verifier().reconcile(result['private_session'], apply=True)
        self.assertEqual(reconciled['status'], 'PROOF_RECONCILED')
        self.assertEqual(self.h.transport.calls, ['heartbeat', 'reconcile'])
        self.assertEqual(self.h.phases.calls, phases)
        self.assertEqual(self.h.product_rows(), before)
        self.assertEqual(self.h.queue.get(binding.job_id)['state'], 'completed')
        self.assertEqual(self.h.journal.pending(), [])
        self.assert_safe(reconciled)

    def test_reconcile_after_lost_queue_completion_rechecks_without_duplicate_proof(self):
        binding = self.h.add_job()
        self.h.transport.failures['complete'] = 'lost'
        result = self.h.verifier().pump(apply=True)
        before = self.h.product_rows()
        self.h.transport.calls.clear()
        reconciled = self.h.verifier().reconcile(result['private_session'], apply=True)
        self.assertEqual(reconciled['status'], 'PROOF_RECONCILED')
        self.assertEqual(self.h.transport.calls, ['heartbeat', 'reconcile'])
        self.assertEqual(self.h.product_rows(), before)
        self.assertEqual(self.h.gate_calls, [binding.job_id, binding.job_id])
        self.assertEqual(self.h.journal.pending(), [])

    def test_missing_proof_reconciliation_only_rechecks_and_cannot_restart_phases(self):
        self.h.add_job()
        self.h.phases.failures['allocate'] = 'lost'
        result = self.h.verifier().pump(apply=True)
        phases = list(self.h.phases.calls)
        self.h.transport.calls.clear()
        with self.assertRaises(RuntimeError):
            self.h.verifier().reconcile(result['private_session'], apply=True)
        self.assertEqual(self.h.transport.calls, ['heartbeat', 'reconcile'])
        self.assertEqual(self.h.phases.calls, phases)
        intent = Path(result['private_session']) / 'proof-reconcile.intent.json'
        original_intent = intent.read_bytes()
        self.h.transport.calls.clear()
        with self.assertRaises(RuntimeError):
            self.h.verifier().reconcile(result['private_session'], apply=True)
        self.assertEqual(self.h.transport.calls, ['heartbeat', 'reconcile'])
        self.assertEqual(self.h.phases.calls, phases)
        self.assertEqual(intent.read_bytes(), original_intent)
        self.assert_blocked_reconnect()

    def test_explicit_reconcile_after_lost_reply_preserves_intent_and_all_phase_receipts(self):
        binding = self.h.add_job()
        self.h.transport.failures['complete'] = 'lost'
        result = self.h.verifier().pump(apply=True)
        directory = Path(result['private_session'])
        before_product = self.h.product_rows()
        before_phases = list(self.h.phases.calls)
        before_receipts = {path.name: path.read_bytes() for path in directory.iterdir()}
        self.assertIn(directory, self.h.journal.pending())

        self.h.transport.failures['reconcile'] = 'lost'
        self.h.transport.calls.clear()
        with self.assertRaises(RuntimeError):
            self.h.verifier().reconcile(directory, apply=True)
        self.assertEqual(self.h.transport.calls, ['heartbeat', 'reconcile'])
        self.assertEqual(self.h.queue.get(binding.job_id)['state'], 'completed')
        self.assertIn(directory, self.h.journal.pending())
        intent = directory / 'proof-reconcile.intent.json'
        original_intent = intent.read_bytes()
        self.assertFalse((directory / 'proof-reconcile.complete.json').exists())
        self.assertFalse((directory / 'reconciled.json').exists())

        del self.h.transport.failures['reconcile']
        self.h.transport.calls.clear()
        reconciled = self.h.verifier().reconcile(directory, apply=True)
        self.assertEqual(reconciled['status'], 'PROOF_RECONCILED')
        self.assertEqual(self.h.transport.calls, ['heartbeat', 'reconcile'])
        self.assertEqual(intent.read_bytes(), original_intent)
        self.assertEqual(self.h.journal.pending(), [])
        for name, raw in before_receipts.items():
            self.assertEqual((directory / name).read_bytes(), raw)

        sealed_bytes = {str(path): path.read_bytes() for path in self.h.journal.root.rglob('*') if path.is_file()}
        self.h.transport.calls.clear()
        repeated = self.h.verifier().reconcile(directory, apply=True)
        self.assertEqual(repeated, reconciled)
        self.assertEqual(self.h.transport.calls, ['heartbeat', 'reconcile'])
        self.assertEqual({str(path): path.read_bytes() for path in self.h.journal.root.rglob('*') if path.is_file()}, sealed_bytes)
        self.assertEqual(self.h.phases.calls, before_phases)
        self.assertEqual(self.h.product_rows(), before_product)
        self.assert_safe(repeated)

    def test_tampered_reconcile_intent_rejects_before_heartbeat_or_proof_transport(self):
        self.h.add_job()
        self.h.transport.failures['complete'] = 'lost'
        result = self.h.verifier().pump(apply=True)
        directory = Path(result['private_session'])
        self.h.transport.failures['reconcile'] = 'lost'
        with self.assertRaises(RuntimeError):
            self.h.verifier().reconcile(directory, apply=True)
        intent = directory / 'proof-reconcile.intent.json'
        intent.write_bytes(intent.read_bytes() + b' ')
        before = {path.name: path.read_bytes() for path in directory.iterdir()}
        phases = list(self.h.phases.calls)
        del self.h.transport.failures['reconcile']
        self.h.transport.calls.clear()
        with self.assertRaisesRegex(p.ProductVerifierError, 'JOURNAL_EXISTING_BYTES_DIFFER'):
            self.h.verifier().reconcile(directory, apply=True)
        self.assertEqual(self.h.transport.calls, [])
        self.assertEqual(self.h.phases.calls, phases)
        self.assertEqual({path.name: path.read_bytes() for path in directory.iterdir()}, before)
        self.assert_blocked_reconnect()

    def test_reconcile_requires_explicit_authority_and_exact_session(self):
        with self.assertRaisesRegex(p.ProductVerifierError, 'EXPLICIT_RECONCILIATION_AUTHORITY_REQUIRED'):
            self.h.verifier().reconcile(self.h.root)
        with self.assertRaisesRegex(p.ProductVerifierError, 'EXACT_PRIVATE_SESSION_REQUIRED'):
            self.h.verifier().reconcile(self.h.root, apply=True)
        self.assertFalse(p.JOURNAL_ROOT.exists())
        self.assertEqual(self.h.transport.calls, [])

    def test_raw_completed_journal_tamper_blocks_contact_and_new_session(self):
        self.h.add_job()
        result = self.h.verifier().pump(apply=True)
        path = Path(result['private_session']) / 'p0001-prepare.complete.json'
        path.write_bytes(path.read_bytes() + b' ')
        calls = list(self.h.transport.calls)
        with self.assertRaisesRegex(p.ProductVerifierError, 'JOURNAL_RETAINED_BYTES_CHANGED'):
            self.h.verifier().pump(apply=True)
        self.assertEqual(self.h.transport.calls, calls)

    def test_raw_claim_intent_tamper_blocks_reconciliation_before_contact(self):
        self.h.add_job()
        self.h.phases.failures['prepare'] = 'lost'
        result = self.h.verifier().pump(apply=True)
        path = Path(result['private_session']) / 'p0001-claim.intent.json'
        path.write_bytes(path.read_bytes() + b' ')
        calls = list(self.h.transport.calls)
        with self.assertRaisesRegex(p.ProductVerifierError, 'JOURNAL_STEP_BINDING_CHANGED'):
            self.h.verifier().reconcile(result['private_session'], apply=True)
        self.assertEqual(self.h.transport.calls, calls)

    def test_real_workspace_journal_paths_fit_windows_bound_without_creating_files(self):
        real_root = ROOT / 'work/private/clean-install/product-verifier'
        with patch.object(p, 'JOURNAL_ROOT', real_root), patch.object(p.clean, 'save_new') as write, \
             patch.object(p.clean, 'private_directory') as directory:
            journal = p.PrivateJournal(self.h.release)
            self.assertEqual(journal.root, real_root / self.h.release[:16])
            longest = journal.root / ('session-' + '0' * 24) / 'p0120-promotion-apply.complete.json'
            self.assertLessEqual(len(str(longest)), 240)
            write.assert_not_called()
            directory.assert_not_called()
        with patch.object(p, 'JOURNAL_ROOT', Path('C:/') / ('x' * 220)), \
             self.assertRaisesRegex(p.ProductVerifierError, 'JOURNAL_PATH_EXCEEDS_PORTABLE_BOUND'):
            p.PrivateJournal(self.h.release)

    def test_release_prefix_collision_rejects_before_lock_or_contact_and_preserves_header(self):
        self.h.verifier().pump(apply=True)
        before = {str(path): path.read_bytes() for path in self.h.journal.root.rglob('*') if path.is_file()}
        changed = self.h.release[:16] + ('0' if self.h.release[16] != '0' else '1') + self.h.release[17:]
        collision = p.PrivateJournal(changed)
        self.assertEqual(collision.root, self.h.journal.root)
        calls = list(self.h.transport.calls)
        with self.assertRaisesRegex(p.ProductVerifierError, 'JOURNAL_RELEASE_PREFIX_COLLISION'):
            with collision.lock():
                self.fail('COLLIDING_RELEASE_MUST_NOT_OBTAIN_LOCK')
        self.assertEqual(self.h.transport.calls, calls)
        self.assertEqual({str(path): path.read_bytes() for path in self.h.journal.root.rglob('*') if path.is_file()}, before)
        self.assertEqual(json.loads((collision.root / 'release.json').read_bytes())['release_sha256'], self.h.release)

    def test_parser_does_not_echo_invalid_values_or_exception_text(self):
        for args in ([SECRET], ['pump', '--max-jobs', SECRET], ['pump', '--' + SECRET]):
            output, errors = io.StringIO(), io.StringIO()
            with self.subTest(args=args), patch.object(sys, 'argv', [str(Path(p.__file__)), *args]), \
                 redirect_stdout(output), redirect_stderr(errors), self.assertRaises(SystemExit) as caught:
                runpy.run_path(str(Path(p.__file__)), run_name='__main__')
            self.assertEqual(caught.exception.code, 2)
            self.assertEqual(json.loads(output.getvalue()), {'status': 'STOPPED',
                'code': 'PRODUCT_VERIFIER_GUARD_FAILED', 'automatic_replay_permitted': False})
            self.assertEqual(errors.getvalue(), '')
            self.assertNotIn(SECRET, output.getvalue())
        self.assertEqual(self.h.transport.calls, [])
        self.assertFalse(p.JOURNAL_ROOT.exists())


def failure_case(step, failure):
    def test(self):
        binding = self.h.add_job()
        before = self.h.product_rows()
        if step in ('claim', 'queue_complete'):
            self.h.transport.failures['claim' if step == 'claim' else 'complete'] = failure
        else:
            self.h.phases.failures[step] = failure
        result = self.h.verifier().pump(apply=True)
        self.assertEqual(result['status'], 'ATTENTION')
        self.assertEqual(self.h.transport.calls.count('claim'), 1)
        expected = [] if step == 'claim' else list(STEPS[:min(STEPS.index(step) + 1, len(STEPS) - 1)])
        self.assertEqual([name for name, _ in self.h.phases.calls], expected)
        state = self.h.queue.get(binding.job_id)['state']
        if step == 'claim':
            self.assertEqual(state, 'running' if failure == 'lost' else 'queued')
            self.assertNotIn('attention', self.h.transport.calls)
            self.assertEqual(self.h.product_rows(), before)
            calls = list(self.h.transport.calls)
            with self.assertRaisesRegex(p.ProductVerifierError, 'UNKNOWN_CLAIM_REQUIRES_OPERATOR_REVIEW'):
                self.h.verifier().reconcile(result['private_session'], apply=True)
            self.assertEqual(self.h.transport.calls, calls)
        else:
            self.assertEqual(state, 'completed' if step == 'queue_complete' and failure == 'lost' else 'attention')
            self.assertEqual(self.h.transport.calls.count('attention'), 1)
            if STEPS.index(step) < STEPS.index('promotion_apply') or (step == 'promotion_apply' and failure == 'unknown'):
                self.assertEqual(self.h.product_rows(), before)
        after = self.h.product_rows()
        self.assertEqual(after['acceptances'], before['acceptances'])
        self.assertEqual(after['events'], before['events'])
        self.assert_blocked_reconnect()
        self.assert_safe(result)
    return test


for _step in ('claim', *STEPS):
    for _failure in ('unknown', 'lost'):
        setattr(ProductVerifierTests, 'test_' + _failure + '_response_at_' + _step, failure_case(_step, _failure))


class GuardedPhaseTests(unittest.TestCase):
    """Check adapter delegation without running any existing external operator."""
    def setUp(self):
        self.h = Harness()
        self.addCleanup(self.h.close)
        self.bound = self.h.add_job()
        self.phases = p.GuardedPhases(self.h.manifest)
        self.context = {'plan_sha256': 'a' * 64, 'collection_manifest_sha256': 'b' * 64}
        self.plan = self.h.private / self.context['plan_sha256'] / 'plan.json'

    def test_prepare_uses_existing_operator_and_requires_exact_binding_and_plan_hash(self):
        plan = {'binding': {key: value for key, value in self.bound.payload().items()
                            if key != 'verifier_release_sha256'},
                'operator_code_sha256': self.h.manifest['clean_operator_code_sha256']}
        raw = C.canonical_bytes(plan)
        with patch.object(p.clean, 'prepare', return_value={'plan_path': str(self.plan), 'plan_sha256': C.digest(raw)}) as prepare, \
             patch.object(p.clean, 'read_plan', return_value=(raw, plan)):
            value = self.phases.perform('prepare', self.bound, {})
            prepare.assert_called_once_with(self.bound.job_id, self.bound.package_sha256)
            self.assertEqual(value['plan_sha256'], C.digest(raw))
            self.assertEqual(p.safe_phase('prepare', value, self.bound, {}, self.h.manifest), value)
            plan['binding']['package_sha256'] = '0' * 64
            with self.assertRaisesRegex(p.ProductVerifierError, 'PREPARED_PLAN_BINDING_DIFFERS'):
                self.phases.perform('prepare', self.bound, {})

    def test_clean_check_requires_fresh_unattempted_plan(self):
        value = {'state': 'PREPARED', 'plan_sha256': self.context['plan_sha256'],
                 'phases': {name: 'unattempted' for name in ('allocate', 'schema', 'import', 'verify')}}
        with patch.object(p.clean, 'dispatch', return_value=value) as dispatch:
            self.phases.perform('clean_check', self.bound, self.context)
            dispatch.assert_called_once_with('check', self.plan, expected_sha=self.context['plan_sha256'])
            value['phases']['allocate'] = 'complete'
            with self.assertRaisesRegex(p.ProductVerifierError, 'FRESH_PLAN_NOT_UNATTEMPTED'):
                self.phases.perform('clean_check', self.bound, self.context)

    def test_each_clean_apply_reuses_exact_plan_and_existing_guard(self):
        for step in ('allocate', 'schema', 'import', 'verify'):
            value = {'state': 'QA_READY' if step == 'verify' else 'PHASE_COMPLETE', 'action': 'COMPLETED_ONCE',
                     'plan_sha256': self.context['plan_sha256'], 'evidence_sha256': 'c' * 64, 'provider_output': SECRET}
            with self.subTest(step=step), patch.object(p.clean, 'dispatch', return_value=value) as dispatch:
                result = self.phases.perform(step, self.bound, self.context)
                dispatch.assert_called_once_with('apply', self.plan, expected_sha=self.context['plan_sha256'], phase=step, apply=True)
                self.assertNotIn(SECRET, json.dumps(result))
                self.assertEqual(p.safe_phase(step, result, self.bound, self.context, self.h.manifest), result)

    def test_native_qa_stage_run_reuse_existing_dispatch_without_journey_or_install(self):
        for step, status in (('qa_stage', 'STAGED'), ('qa_run', 'PASSED')):
            value = {'status': status, 'plan_sha256': self.context['plan_sha256'],
                     'source_sha256': self.h.manifest['qa_source_sha256'], 'image_id': FUTURE,
                     'allocation_receipt_sha256': 'c' * 64, 'exit_code': 0, 'provider_output': SECRET}
            with self.subTest(step=step), patch.object(p.qa, 'dispatch', return_value=value) as dispatch:
                result = self.phases.perform(step, self.bound, self.context)
                dispatch.assert_called_once_with(step[3:], self.plan, self.context['plan_sha256'],
                                                 self.h.manifest['qa_source_sha256'], apply=True)
                self.assertNotIn(SECRET, json.dumps(result))
                context = {**self.context, 'image_id': FUTURE}
                self.assertEqual(p.safe_phase(step, result, self.bound, context, self.h.manifest), result)

    def test_collection_is_read_only_and_uses_exact_retained_directory_and_hash(self):
        directory = self.plan.parent / ('qa-' + self.h.manifest['qa_source_sha256'][:16])
        directory.mkdir(parents=True)
        saved = {'status': 'COLLECTED', 'credentials_and_logs_excluded': True,
                 'plan_sha256': self.context['plan_sha256'], 'source_sha256': self.h.manifest['qa_source_sha256']}
        raw = C.canonical_bytes(saved)
        (directory / 'collection-manifest.json').write_bytes(raw)
        with patch.object(p.qa, 'dispatch', return_value={'local_directory': str(directory)}) as dispatch:
            result = self.phases.perform('qa_collect', self.bound, self.context)
            dispatch.assert_called_once_with('collect', self.plan, self.context['plan_sha256'],
                                             self.h.manifest['qa_source_sha256'], apply=False)
            self.assertEqual(result['collection_manifest_sha256'], C.digest(raw))
            dispatch.return_value = {'local_directory': str(self.h.root)}
            with self.assertRaisesRegex(p.ProductVerifierError, 'COLLECTION_LOCATION_DIFFERS'):
                self.phases.perform('qa_collect', self.bound, self.context)

    def test_technical_promotion_uses_existing_guard_and_never_accepts(self):
        for step in ('promotion_check', 'promotion_apply'):
            value = {'status': 'READY_NOT_APPLIED' if step == 'promotion_check' else 'VERIFIED',
                     'job_id': self.bound.job_id, 'human_acceptance_recorded': False,
                     'event_count': 1, 'proof_count': 1, 'proof_sha256': 'd' * 64, 'provider_output': SECRET}
            with self.subTest(step=step), patch.object(p.promotion, 'dispatch', return_value=value) as dispatch:
                result = self.phases.perform(step, self.bound, self.context)
                dispatch.assert_called_once_with('check' if step == 'promotion_check' else 'apply',
                    self.plan.parent / ('qa-' + self.h.manifest['qa_source_sha256'][:16]),
                    collection_sha256=self.context['collection_manifest_sha256'], expected_image=FUTURE,
                    module_sha256=self.h.manifest['modules']['native_verification.py'], apply=step == 'promotion_apply')
                self.assertNotIn(SECRET, json.dumps(result))
                self.assertEqual(p.safe_phase(step, result, self.bound, self.context, self.h.manifest), result)
                value['human_acceptance_recorded'] = True
                with self.assertRaisesRegex(p.ProductVerifierError, 'TECHNICAL_PROMOTION_BINDING_DIFFERS'):
                    self.phases.perform(step, self.bound, self.context)


if __name__ == '__main__':
    unittest.main()
