"""Local queue foundation tests: temp SQLite, fake backend, no external actions.

Positive coordinator cases mock only the already-existing retained-proof gate.
They prove queue orchestration, not APEX/runtime evidence. A separate negative
case calls the real gate and rejects a fabricated summary without retained files.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'fox'))
from fox import technical_release as gate
from fox import verification_queue as q

RELEASE = 'a' * 64
OTHER_RELEASE = 'b' * 64
SECRET = 'never-emit-private-provider-content'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class FakeBackend:
    verifier_release_sha256 = RELEASE

    def __init__(self, action):
        self.action, self.claims = action, []

    def verify(self, claim):
        self.claims.append(claim)
        return self.action(claim)


class VerificationQueueTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='verification-queue-', dir=ROOT / 'work')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
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
        self.queue = q.VerificationQueue(self.database, enabled=True, verifier_release_sha256=RELEASE)
        self.queue.initialize()
        self.packages = {}
        for target in ((socket, 'create_connection'), (socket.socket, 'connect'),
                       (subprocess, 'run'), (subprocess, 'Popen')):
            guard = patch.object(*target, side_effect=AssertionError('EXTERNAL_ACTION_FORBIDDEN'))
            guard.start(); self.addCleanup(guard.stop)

    def binding(self, number=1):
        job = 'fox-' + format(number, '020x')
        package = ('synthetic package ' + job).encode()
        self.packages[job] = package
        source = sha(('synthetic source ' + job).encode())
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute('INSERT OR IGNORE INTO runs VALUES(?,?,?,?)',
                       (job, source, 'QA_REQUIRED', str(Path('jobs') / job / 'apex-package.zip')))
        return q.VerificationBinding(job, source, sha(package), RELEASE)

    def publish_fake_technical_result(self, claim):
        """Simulates the separate production promoter; queue must not do this."""
        binding = claim.binding
        proof = {'job_id': binding.job_id, 'source_manifest_sha256': binding.source_manifest_sha256,
                 'package_sha256': binding.package_sha256, 'human_acceptance_recorded': False}
        raw = json.dumps(proof, sort_keys=True)
        digest = sha(raw.encode())
        with closing(sqlite3.connect(self.database)) as db, db:
            self.assertEqual(db.execute('SELECT state FROM verification_queue WHERE job_id=?',
                                        (binding.job_id,)).fetchone()[0], 'running')
            db.execute("UPDATE runs SET state='VERIFIED' WHERE id=?", (binding.job_id,))
            db.execute('INSERT INTO technical_verifications VALUES(?,?,?,?,?,?)',
                       (binding.job_id, binding.source_manifest_sha256, binding.package_sha256, digest, raw, 1.0))
        return q.TechnicalProofResult(digest)

    def fake_checked_gate(self, db, root, run):
        self.assertEqual(root, self.root)
        row = db.execute('SELECT proof_json FROM technical_verifications WHERE run=?', (run['id'],)).fetchone()
        return {'proof': json.loads(row[0]), 'package': self.packages[run['id']]}

    def product_rows(self):
        with closing(sqlite3.connect(self.database)) as db, db:
            return {name: db.execute('SELECT * FROM ' + name + ' ORDER BY 1').fetchall()
                    for name in ('runs', 'technical_verifications', 'acceptances', 'events')}

    def test_default_disabled_is_inert_and_cannot_touch_storage_or_backend(self):
        path = self.root / 'must-not-exist.sqlite3'
        disabled = q.VerificationQueue(path)
        binding = self.binding()
        backend = FakeBackend(lambda _: self.fail('BACKEND_MUST_NOT_RUN'))
        actions = [disabled.initialize, lambda: disabled.enqueue(binding), disabled.claim_next,
                   disabled.recover_running, lambda: q.coordinate_one(disabled, backend)]
        for action in actions:
            with self.assertRaisesRegex(q.QueueError, 'VERIFICATION_QUEUE_DISABLED'):
                action()
        self.assertFalse(path.exists())
        self.assertEqual(backend.claims, [])

    def test_enable_flag_and_release_are_explicit(self):
        for kwargs in ({'enabled': 'true'}, {'enabled': True}, {'enabled': True, 'verifier_release_sha256': 'not-hash'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(q.QueueError):
                q.VerificationQueue(self.database, **kwargs)

    def test_initialize_never_manufactures_run_store_and_preserves_product_tables(self):
        other = self.root / 'empty.sqlite3'
        sqlite3.connect(other).close()
        with self.assertRaises(q.QueueError):
            q.VerificationQueue(other, enabled=True, verifier_release_sha256=RELEASE).initialize()
        before = self.product_rows()
        self.queue.initialize()
        self.assertEqual(self.product_rows(), before)

    def test_public_binding_has_no_target_command_credentials_or_free_text(self):
        binding = self.binding()
        self.assertEqual(q.VerificationBinding.from_payload(binding.payload()), binding)
        for key in ('password', 'command', 'target_url', 'compartment_id', 'notes'):
            with self.subTest(key=key), self.assertRaises(q.QueueError) as error:
                q.VerificationBinding.from_payload({**binding.payload(), key: SECRET})
            self.assertNotIn(SECRET, str(error.exception))
        for value in ('fox-' + '1' * 19, 'fox-' + '1' * 20 + '\n', SECRET):
            with self.assertRaises(q.QueueError):
                replace(binding, job_id=value)

    def test_enqueue_is_idempotent_without_rewriting_bytes_or_time(self):
        binding = self.binding()
        before = self.product_rows()
        first = self.queue.enqueue(binding)
        self.assertEqual(self.queue.enqueue(binding), first)
        self.assertEqual(self.product_rows(), before)
        with closing(sqlite3.connect(self.database)) as db, db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM verification_queue').fetchone()[0], 1)

    def test_a_job_cannot_be_rebound_to_different_source_package_or_release(self):
        binding = self.binding(); original = self.queue.enqueue(binding)
        for key in ('source_manifest_sha256', 'package_sha256', 'verifier_release_sha256'):
            changed = replace(binding, **{key: OTHER_RELEASE})
            queue = self.queue if key != 'verifier_release_sha256' else q.VerificationQueue(
                self.database, enabled=True, verifier_release_sha256=OTHER_RELEASE)
            with self.subTest(key=key), self.assertRaisesRegex(q.QueueError, 'REBIND_FORBIDDEN'):
                queue.enqueue(changed)
        self.assertEqual(self.queue.get(binding.job_id), original)

    def test_enqueue_requires_actual_qa_required_run_source_and_fixed_artifact(self):
        binding = self.binding()
        for field, value in (('state', 'VERIFIED'), ('source_hash', '0' * 64), ('artifact', '/other/package.zip')):
            with closing(sqlite3.connect(self.database)) as db, db:
                before = db.execute('SELECT ' + field + ' FROM runs WHERE id=?', (binding.job_id,)).fetchone()[0]
                db.execute('UPDATE runs SET ' + field + '=? WHERE id=?', (value, binding.job_id))
            with self.subTest(field=field), self.assertRaises(q.QueueError):
                self.queue.enqueue(binding)
            with closing(sqlite3.connect(self.database)) as db, db:
                db.execute('UPDATE runs SET ' + field + '=? WHERE id=?', (before, binding.job_id))
        self.assertIsNone(self.queue.get(binding.job_id))

    def test_native_worker_artifact_path_is_used_without_portability_guessing(self):
        binding = self.binding()
        with closing(sqlite3.connect(self.database)) as db, db:
            artifact = db.execute('SELECT artifact FROM runs WHERE id=?', (binding.job_id,)).fetchone()[0]
        self.assertEqual(artifact, str(Path('jobs') / binding.job_id / 'apex-package.zip'))
        self.assertEqual(self.queue.enqueue(binding)['state'], 'queued')

    def test_run_source_tamper_after_enqueue_blocks_before_claim(self):
        binding = self.binding(); self.queue.enqueue(binding)
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute('UPDATE runs SET source_hash=? WHERE id=?', ('f' * 64, binding.job_id))
        with self.assertRaisesRegex(q.QueueError, 'RUN_BINDING_OR_STATE_CHANGED'):
            self.queue.claim_next()
        self.assertEqual(self.queue.get(binding.job_id)['state'], 'queued')

    def test_single_claim_is_durable_and_capability_is_not_public(self):
        binding = self.binding(); self.queue.enqueue(binding)
        claim = self.queue.claim_next()
        self.assertEqual(claim.binding, binding)
        self.assertEqual(len(claim.attempt_token), 32)
        self.assertNotIn(claim.attempt_token, repr(claim))
        self.assertNotIn('claim_token', self.queue.get(binding.job_id))
        self.assertEqual(self.queue.get(binding.job_id)['state'], 'running')
        self.assertIsNone(self.queue.claim_next())

    def test_concurrent_connections_claim_exactly_one_job_globally(self):
        for i in range(1, 4):
            self.queue.enqueue(self.binding(i))
        barrier = threading.Barrier(8)
        def claim(_):
            queue = q.VerificationQueue(self.database, enabled=True, verifier_release_sha256=RELEASE)
            barrier.wait()
            return queue.claim_next()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(claim, range(8)))
        self.assertEqual(sum(item is not None for item in results), 1)
        with closing(sqlite3.connect(self.database)) as db, db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM verification_queue WHERE state='running'").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM verification_queue WHERE state='queued'").fetchone()[0], 2)

    def test_concurrent_idempotent_enqueue_keeps_one_row(self):
        binding = self.binding(); barrier = threading.Barrier(8)
        def enqueue(_):
            queue = q.VerificationQueue(self.database, enabled=True, verifier_release_sha256=RELEASE)
            barrier.wait()
            return queue.enqueue(binding)
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(enqueue, range(8)))
        self.assertTrue(all(value == results[0] for value in results))

    def test_restart_never_takes_over_or_requeues_an_unknown_running_attempt(self):
        binding = self.binding(); self.queue.enqueue(binding); self.queue.claim_next()
        reopened = q.VerificationQueue(self.database, enabled=True, verifier_release_sha256=RELEASE)
        self.assertEqual(reopened.get(binding.job_id)['state'], 'running')
        self.assertIsNone(reopened.claim_next())
        recovered = reopened.recover_running()
        self.assertEqual(recovered[0]['state'], 'attention')
        self.assertEqual(recovered[0]['attention_code'], 'INTERRUPTED_OUTCOME')
        self.assertEqual(reopened.recover_running(), [])
        self.assertEqual(reopened.enqueue(binding), recovered[0])
        backend = FakeBackend(lambda _: self.fail('NO_REDISPATCH'))
        self.assertIsNone(q.coordinate_one(reopened, backend))
        self.assertEqual(backend.claims, [])

    def test_completion_requires_existing_gate_and_does_not_promote_or_accept(self):
        binding = self.binding(); self.queue.enqueue(binding); claim = self.queue.claim_next()
        result = self.publish_fake_technical_result(claim)
        before = self.product_rows()
        with patch.object(gate, 'checked_release', side_effect=self.fake_checked_gate) as validated:
            completed = self.queue.complete(claim, result)
        self.assertEqual(completed['state'], 'completed')
        self.assertEqual(completed['proof_sha256'], result.proof_sha256)
        validated.assert_called_once()
        self.assertEqual(self.product_rows(), before)

    def test_real_gate_rejects_fabricated_summary_without_retained_evidence(self):
        binding = self.binding(); self.queue.enqueue(binding); claim = self.queue.claim_next()
        result = self.publish_fake_technical_result(claim)
        with self.assertRaisesRegex(q.QueueError, 'TECHNICAL_PROOF_NOT_VALIDATED'):
            self.queue.complete(claim, result)
        self.assertEqual(self.queue.get(binding.job_id)['state'], 'attention')

    def test_passed_boolean_or_human_acceptance_claim_is_not_a_technical_result(self):
        binding = self.binding(); self.queue.enqueue(binding); claim = self.queue.claim_next()
        with self.assertRaises(q.QueueError):
            self.queue.complete(claim, {'passed': True, 'human_acceptance_recorded': True})
        self.assertEqual(self.queue.get(binding.job_id)['state'], 'attention')
        self.assertEqual(self.product_rows()['runs'][0][2], 'QA_REQUIRED')
        self.assertEqual(len(self.product_rows()['acceptances']), 1)

    def _assert_tampered_proof_rejected(self, key):
        # Each mutation has its own database: an unresolved attention row must
        # continue to block all later claims, even across unrelated jobs.
        binding = self.binding(); self.queue.enqueue(binding); claim = self.queue.claim_next()
        result = self.publish_fake_technical_result(claim)
        def tampered(db, root, run):
            value = self.fake_checked_gate(db, root, run)
            if key == 'package_bytes': value['package'] += b'changed'
            else: value['proof'][key] = True if key == 'human_acceptance_recorded' else 'different'
            return value
        with patch.object(gate, 'checked_release', side_effect=tampered), self.assertRaises(q.QueueError):
            self.queue.complete(claim, result)
        self.assertEqual(self.queue.get(binding.job_id)['state'], 'attention')

    def test_verified_proof_must_match_job(self):
        self._assert_tampered_proof_rejected('job_id')

    def test_verified_proof_must_match_source(self):
        self._assert_tampered_proof_rejected('source_manifest_sha256')

    def test_verified_proof_must_match_package(self):
        self._assert_tampered_proof_rejected('package_sha256')

    def test_verified_proof_must_not_record_acceptance(self):
        self._assert_tampered_proof_rejected('human_acceptance_recorded')

    def test_verified_proof_must_match_package_bytes(self):
        self._assert_tampered_proof_rejected('package_bytes')

    def test_wrong_proof_digest_is_not_completed(self):
        binding = self.binding(); self.queue.enqueue(binding); claim = self.queue.claim_next()
        self.publish_fake_technical_result(claim)
        with patch.object(gate, 'checked_release', side_effect=self.fake_checked_gate), self.assertRaises(q.QueueError):
            self.queue.complete(claim, q.TechnicalProofResult('f' * 64))
        self.assertEqual(self.queue.get(binding.job_id)['state'], 'attention')

    def test_stale_claim_cannot_complete_or_fence_the_current_owner(self):
        binding = self.binding(); self.queue.enqueue(binding); claim = self.queue.claim_next()
        with patch.object(gate, 'checked_release') as validate:
            with self.assertRaisesRegex(q.QueueError, 'STALE_OR_CHANGED_CLAIM'):
                self.queue.complete(replace(claim, attempt_token='0' * 32), q.TechnicalProofResult('f' * 64))
            validate.assert_not_called()
        self.assertEqual(self.queue.get(binding.job_id)['state'], 'running')

    def test_interruption_fences_late_completion_until_explicit_proof_reconciliation(self):
        binding = self.binding(); self.queue.enqueue(binding); claim = self.queue.claim_next()
        result = self.publish_fake_technical_result(claim)
        self.queue.recover_running()
        with patch.object(gate, 'checked_release', side_effect=self.fake_checked_gate) as validate:
            with self.assertRaisesRegex(q.QueueError, 'RECONCILIATION_REQUIRED'):
                self.queue.complete(claim, result)
            validate.assert_not_called()
            before = self.product_rows()
            completed = self.queue.reconcile_completed(binding, result)
        self.assertEqual(completed['state'], 'completed')
        self.assertEqual(self.product_rows(), before)

    def test_repeated_completion_is_idempotent_but_rechecks_proof(self):
        binding = self.binding(); self.queue.enqueue(binding); claim = self.queue.claim_next()
        result = self.publish_fake_technical_result(claim)
        with patch.object(gate, 'checked_release', side_effect=self.fake_checked_gate) as validate:
            first = self.queue.complete(claim, result)
            self.assertEqual(self.queue.complete(claim, result), first)
            self.assertEqual(validate.call_count, 2)
        with patch.object(gate, 'checked_release', side_effect=gate.VerificationError(SECRET)), self.assertRaises(q.QueueError) as error:
            self.queue.complete(claim, result)
        self.assertNotIn(SECRET, str(error.exception))
        self.assertEqual(self.queue.get(binding.job_id), first)

    def test_completed_readback_preserves_later_genuine_synthetic_owner_acceptance(self):
        binding = self.binding(); self.queue.enqueue(binding); claim = self.queue.claim_next()
        result = self.publish_fake_technical_result(claim)
        with patch.object(gate, 'checked_release', side_effect=self.fake_checked_gate):
            first = self.queue.complete(claim, result)
        # Separate test-only owner action, not a queue/coordinator capability.
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute("UPDATE runs SET state='ACCEPTED' WHERE id=?", (binding.job_id,))
            db.execute('INSERT INTO acceptances VALUES(?,?,?)', (binding.job_id, 'synthetic-owner', 'fixture review'))
            db.execute('INSERT INTO events VALUES(?,?)', ('human_accepted_fixture', binding.job_id))
        before = self.product_rows()
        with patch.object(gate, 'checked_release', side_effect=self.fake_checked_gate) as validate:
            self.assertEqual(self.queue.complete(claim, result), first)
            validate.assert_called_once()
        self.assertEqual(self.product_rows(), before)
        self.assertEqual(self.product_rows()['runs'][0][2], 'ACCEPTED')

    def test_tampered_sqlite_binding_or_attempt_fails_closed(self):
        binding = self.binding(); self.queue.enqueue(binding)
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute('UPDATE verification_queue SET package_sha256=? WHERE job_id=?', ('f' * 64, binding.job_id))
        with self.assertRaises(q.QueueError): self.queue.get(binding.job_id)
        with self.assertRaises(q.QueueError): self.queue.claim_next()

    def test_wrong_backend_release_stops_before_claim(self):
        binding = self.binding(); self.queue.enqueue(binding)
        backend = FakeBackend(lambda _: self.fail('WRONG_BACKEND'))
        backend.verifier_release_sha256 = OTHER_RELEASE
        with self.assertRaisesRegex(q.QueueError, 'BACKEND_RELEASE_MISMATCH'):
            q.coordinate_one(self.queue, backend)
        self.assertEqual(self.queue.get(binding.job_id)['state'], 'queued')
        self.assertEqual(backend.claims, [])

    def test_backend_metadata_failure_is_bounded_before_claim(self):
        binding = self.binding(); self.queue.enqueue(binding)
        class BrokenBackend:
            @property
            def verifier_release_sha256(self):
                raise RuntimeError(SECRET)
        with self.assertRaisesRegex(q.QueueError, 'BACKEND_METADATA_UNAVAILABLE') as error:
            q.coordinate_one(self.queue, BrokenBackend())
        self.assertNotIn(SECRET, str(error.exception))
        self.assertEqual(self.queue.get(binding.job_id)['state'], 'queued')

    def test_coordinator_claim_commits_before_backend_and_calls_it_once(self):
        binding = self.binding(); self.queue.enqueue(binding)
        backend = FakeBackend(self.publish_fake_technical_result)
        with patch.object(gate, 'checked_release', side_effect=self.fake_checked_gate):
            result = q.coordinate_one(self.queue, backend)
        self.assertEqual(result['state'], 'completed')
        self.assertIsNone(q.coordinate_one(self.queue, backend))
        self.assertEqual(len(backend.claims), 1)

    def test_backend_release_change_and_failure_are_attention_without_provider_text(self):
        binding = self.binding(); self.queue.enqueue(binding)
        def fail(_): raise RuntimeError(SECRET)
        backend = FakeBackend(fail)
        output = io.StringIO()
        with patch.object(sys, 'stdout', output), patch.object(sys, 'stderr', output):
            result = q.coordinate_one(self.queue, backend)
        self.assertEqual(result['state'], 'attention')
        self.assertNotIn(SECRET, json.dumps(result))
        self.assertEqual(output.getvalue(), '')
        self.assertIsNone(q.coordinate_one(self.queue, backend))
        self.assertEqual(len(backend.claims), 1)

    def test_backend_release_change_during_verification_is_attention(self):
        binding = self.binding(); self.queue.enqueue(binding)
        backend = FakeBackend(None)
        def changed(claim):
            result = self.publish_fake_technical_result(claim)
            backend.verifier_release_sha256 = OTHER_RELEASE
            return result
        backend.action = changed
        self.assertEqual(q.coordinate_one(self.queue, backend)['state'], 'attention')

    def test_process_exit_keeps_running_until_explicit_restart_reconciliation(self):
        binding = self.binding(); self.queue.enqueue(binding)
        def exit_process(_): raise SystemExit(9)
        backend = FakeBackend(exit_process)
        with self.assertRaises(SystemExit): q.coordinate_one(self.queue, backend)
        self.assertEqual(self.queue.get(binding.job_id)['state'], 'running')
        self.assertIsNone(q.coordinate_one(self.queue, backend))
        self.queue.recover_running()
        self.assertEqual(self.queue.get(binding.job_id)['state'], 'attention')
        self.assertIsNone(q.coordinate_one(self.queue, backend))
        self.assertEqual(len(backend.claims), 1)


if __name__ == '__main__':
    unittest.main()
