"""Offline failed-verification closure tests; no retained or remote data access.

Fixtures create a disposable product-verifier journal with a known failed QA
result. Shared evidence validation may be mocked to isolate local journaling;
that never constitutes an APEX import, QA result, promotion, or acceptance.
"""
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import copy
import io
import json
from pathlib import Path
import runpy
import sys
import unittest
from unittest.mock import Mock, patch

from qa.operator import contracts as C
from qa.operator import product_verifier as p
from qa.operator import failed_verification as f
from qa.operator.tests.test_product_verifier import Harness
from fox.verification_recovery import ReviewedSynchronousLaunch

SECRET = 'NeverEmitFailedVerificationPrivateProviderOutput'
NOW = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)


class SimulatedCrash(BaseException):
    pass


def snapshot(directory):
    return {str(path.relative_to(directory)): path.read_bytes()
            for path in directory.rglob('*') if path.is_file()}


def save_fixture(path, value):
    """Test construction only; all paths belong to this test's temporary root."""
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = C.canonical_bytes(value)
    path.write_bytes(raw)
    return C.digest(raw)


class FailureFixture:
    """Generate actual journal shapes using the existing isolated pump fixture."""
    def __init__(self):
        self.h = Harness()
        try:
            self.h.stack.enter_context(patch.object(p, 'JOURNAL_ROOT', self.h.private / 'product-verifier'))
            self.h.journal = p.PrivateJournal(self.h.release)
            self.h.phases.qa_exit = 2
            self.binding = self.h.add_job()
            result = self.h.verifier().pump(apply=True)
            assert result['status'] == 'ATTENTION'
            self.session = Path(result['private_session'])
            self.claim = self.h.journal.completed_result(self.session, 'p0001-claim')['claim']
            self.prepare = self.h.journal.completed_result(self.session, 'p0001-prepare')
            # Minimal fake plan: the existing plan validator is mocked in these
            # local-journal tests. Raw-byte/binding checks remain real.
            self.plan = {'binding': {key: value for key, value in self.binding.payload().items()
                                     if key != 'verifier_release_sha256'},
                         'operator_code_sha256': self.h.manifest['clean_operator_code_sha256']}
            plan_raw = C.canonical_bytes(self.plan)
            self.plan_sha256 = C.digest(plan_raw)
            self.qa_source_sha256 = self.h.manifest['qa_source_sha256']
            self.collection_dir = self.h.private / self.plan_sha256 / ('qa-' + self.qa_source_sha256[:16])
            self.collection_dir.mkdir(parents=True)
            (self.collection_dir.parent / 'plan.json').write_bytes(plan_raw)
            self.package = self.h.packages[self.binding.job_id]
            (self.collection_dir.parent / 'apex-package.zip').write_bytes(self.package)
            self.files = {name: C.canonical_bytes({'synthetic_fixture': name}) for name in f.FILES}
            self.files['package.zip'] = self.package
            for name, raw in self.files.items():
                (self.collection_dir / name).write_bytes(raw)
            self.collection = {'status': 'COLLECTED', 'credentials_and_logs_excluded': True,
                               'plan_sha256': self.plan_sha256, 'source_sha256': self.qa_source_sha256,
                               'sha256': {name: C.digest(raw) for name, raw in self.files.items()}}
            self.collection_sha256 = save_fixture(self.collection_dir / 'collection-manifest.json', self.collection)
            for step in f.STEPS:
                self.replace_result(step, lambda result: result.update(plan_sha256=self.plan_sha256))
            allocation_sha = C.digest(self.files['allocation-receipt.json'])
            self.replace_result('allocate', lambda result: result.update(evidence_sha256=allocation_sha))
            self.replace_result('verify', lambda result: result.update(
                evidence_sha256=C.digest(self.files['clean-import-receipt.json'])))
            self.replace_result('qa_stage', lambda result: result.update(allocation_receipt_sha256=allocation_sha))
            self.replace_result('qa_collect', lambda result: result.update(collection_manifest_sha256=self.collection_sha256))
            self.privacy_check = Mock(return_value=None)
        except BaseException:
            self.h.close()
            raise

    def close(self):
        self.h.close()

    def result(self, name):
        return self.h.journal.completed_result(self.session, 'p0001-' + name.replace('_', '-'))

    def replace_result(self, name, mutate):
        path = self.session / ('p0001-' + name.replace('_', '-') + '.complete.json')
        value = json.loads(path.read_bytes())
        mutate(value['result'])
        save_fixture(path, value)

    def assert_old_bytes(self, testcase, before):
        for name, raw in before.items():
            testcase.assertEqual((self.session / name).read_bytes(), raw, name)

    def resolver(self, *, transport=None, allow_apply=False, **kwargs):
        return f.FailureResolver(manifest=self.h.manifest, expected_release_sha256=self.h.release,
            session=self.session, expected_collection_sha256=self.collection_sha256,
            private_root=self.h.private, transport=transport, allow_apply=allow_apply,
            privacy_check=self.privacy_check, now=lambda: NOW, **kwargs)


class FakeRecovery:
    """Explicit stand-in for the separately tested shared evidence validator."""
    ReviewedSynchronousLaunch = ReviewedSynchronousLaunch

    def __init__(self):
        self.validations = []
        self.retry_requests = []
        self.fail = False

    @staticmethod
    def claim_sha256(claim):
        return C.digest(C.canonical_bytes(p._claim_payload(claim)))

    @staticmethod
    def disposition_sha256(document):
        return C.digest(C.canonical_bytes(document))

    canonical_bytes = staticmethod(C.canonical_bytes)

    def make_retry_request(self, document, *, request_id, attempt_id, verifier_release_sha256):
        request = {'request_id': request_id, 'attempt_id': attempt_id,
                   'old_binding': document['binding'], 'verifier_release_sha256': verifier_release_sha256}
        self.retry_requests.append(request)
        return request

    def validate_failed_evidence(self, *, binding, package, plan_raw, collection_raw, files,
                                 journal_summary, producer, now, wrapper_raw=None, reviewed_synchronous_launch=None):
        self.validations.append({'producer': copy.deepcopy(producer), 'now': now,
                                 'journal_summary': copy.deepcopy(journal_summary),
                                 'wrapper_raw': wrapper_raw,
                                 'reviewed_synchronous_launch': reviewed_synchronous_launch})
        if self.fail or type(producer) is not dict or producer.get('stopped') is not True:
            raise RuntimeError(SECRET)
        return {'schema_version': 1, 'scope': 'synthetic-failed-evidence-test-only',
                'binding': binding.payload(), 'package_sha256': C.digest(package),
                'collection_sha256': C.digest(collection_raw),
                'journal_summary_sha256': C.digest(C.canonical_bytes(journal_summary)),
                'producer': copy.deepcopy(producer)}


class FakeTransport:
    def __init__(self, fixture):
        self.fixture = fixture
        self.calls = []
        self.inputs = []
        self.leases = []
        self.failures = {}
        self.records = {}
        self.producer = {'stopped': True, 'identity': 'synthetic-private-qa-process',
                         'observed_at_utc': NOW.isoformat()}

    def __call__(self, operation, *, claim, evidence, operator_lease=None):
        assert type(operator_lease) is f.HeldOperatorLock, 'REAL_OPERATOR_LEASE_REQUIRED'
        operator_lease.require_active(self.fixture.h.release, self.fixture.h.journal.root)
        self.leases.append(operator_lease)
        self.calls.append(operation)
        self.inputs.append((operation, copy.deepcopy(evidence)))
        if self.failures.get(operation) == 'before':
            raise RuntimeError(SECRET)
        if self.failures.get(operation) == 'unknown':
            return {'status': 'UNKNOWN', 'provider_output': SECRET}
        if operation == 'observe':
            return copy.deepcopy(self.producer)
        if operation not in ('resolve_failure', 'lookup_resolution'):
            raise AssertionError('UNEXPECTED_OPERATION')
        assert (self.fixture.session / 'failed-resolution.intent.json').is_file(), 'DURABLE_INTENT_REQUIRED'
        digest, document = evidence['disposition_sha256'], evidence['disposition']
        if operation == 'resolve_failure':
            assert digest not in self.records, 'NO_DUPLICATE_RESOLUTION'
            self.records[digest] = {'status': 'FAILED_QA_RECORDED', 'disposition_sha256': digest,
                                    'disposition': copy.deepcopy(document)}
        result = copy.deepcopy(self.records.get(digest, {'status': 'UNKNOWN'}))
        if self.failures.get(operation) == 'after':
            raise RuntimeError(SECRET)
        return result


class FailedVerificationTests(unittest.TestCase):
    def setUp(self):
        self.fx = FailureFixture()
        self.addCleanup(self.fx.close)
        self.recovery = FakeRecovery()
        self.fx.h.stack.enter_context(patch.object(f, '_recovery', return_value=self.recovery))
        self.plan_validator = self.fx.h.stack.enter_context(patch.object(C, 'validate_plan',
            side_effect=lambda raw, **kwargs: C.load_json(raw)))
        self.transport = FakeTransport(self.fx)
        self.resolver = self.fx.resolver(transport=self.transport, allow_apply=True)
        self.original = snapshot(self.fx.session)
        self.original_product = self.fx.h.product_rows()
        self.original_phases = list(self.fx.h.phases.calls)
        self.forbidden = []
        for module, method in ((p.clean, 'prepare'), (p.clean, 'dispatch'),
                               (p.qa, 'dispatch'), (p.promotion, 'dispatch')):
            self.forbidden.append(self.fx.h.stack.enter_context(patch.object(
                module, method, side_effect=AssertionError('PHASE_REPLAY_FORBIDDEN'))))

    def tearDown(self):
        for method in getattr(self, 'forbidden', []):
            method.assert_not_called()
        if hasattr(self, 'fx'):
            self.assertEqual(self.fx.h.product_rows(), self.original_product)
            self.assertEqual(self.fx.h.phases.calls, self.original_phases)

    def ready(self):
        return self.resolver.check()

    def apply_ready(self, ready=None, *, resolver=None, **options):
        ready = self.ready() if ready is None else ready
        return (resolver or self.resolver).apply(disposition=ready['disposition'],
            expected_disposition_sha256=ready['disposition_sha256'], **options)

    def assert_safe(self, result):
        raw = json.dumps(result)
        self.assertNotIn(SECRET, raw)
        self.assertNotIn(self.fx.claim['attempt_token'], raw)
        if 'technical_verification_passed' in result:
            self.assertIs(result['technical_verification_passed'], False)
        if 'human_acceptance_recorded' in result:
            self.assertIs(result['human_acceptance_recorded'], False)

    def test_default_check_is_local_readonly_and_not_resolution_ready(self):
        before = snapshot(self.fx.h.root)
        result = self.fx.resolver().check()
        self.assertEqual(result['status'], 'LOCAL_EVIDENCE_ONLY')
        self.assertIs(result['resolution_permitted'], False)
        self.assertIs(result['apply_available'], False)
        self.assertEqual(snapshot(self.fx.h.root), before)
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(self.recovery.validations, [])

    def test_complete_clean_failed_qa_and_collection_allow_only_failed_resolution(self):
        before = snapshot(self.fx.h.root)
        result = self.ready()
        self.assertEqual(result['status'], 'FAILED_QA_RESOLUTION_READY')
        self.assertEqual(self.transport.calls, ['observe'])
        self.assertEqual(snapshot(self.fx.h.root), before)
        summary = self.recovery.validations[0]['journal_summary']
        self.assertEqual(list(summary['phases']), list(f.STEPS))
        self.assertEqual(summary['phases']['qa_run']['result']['exit_code'], 2)
        self.assertEqual(summary['unresolved_intents'], [])
        self.assertIs(summary['promotion_attempted'], False)
        self.assertIs(summary['queue_completion_attempted'], False)
        self.assert_safe(result)

    def test_structural_parent_need_not_have_owner_only_acl_but_all_private_children_do(self):
        checked = []
        def owner_only(paths):
            checked.extend(paths)
            if self.fx.h.private in paths:
                raise PermissionError(SECRET)
        self.resolver.privacy_check = owner_only
        before = snapshot(self.fx.h.root)
        result = self.ready()
        self.assertEqual(result['status'], 'FAILED_QA_RESOLUTION_READY')
        self.assertNotIn(self.fx.h.private, checked)
        required = {self.resolver.root.parent, self.resolver.root, self.fx.session,
                    self.resolver.root / 'release.json', self.resolver.root / 'worker.lock',
                    self.fx.collection_dir.parent, self.fx.collection_dir,
                    self.fx.collection_dir.parent / 'plan.json',
                    self.fx.collection_dir.parent / 'apex-package.zip',
                    self.fx.collection_dir / 'collection-manifest.json'}
        required.update(self.fx.collection_dir / name for name in f.FILES)
        self.assertTrue(required <= set(checked), required - set(checked))
        self.assertTrue(all(path.is_relative_to(self.fx.h.private) for path in checked))
        self.assertEqual(snapshot(self.fx.h.root), before)

    def test_private_child_journal_collection_and_file_acl_failures_block_before_transport(self):
        denied_paths = (self.resolver.root.parent, self.resolver.root, self.fx.session,
                        self.resolver.root / 'release.json', self.resolver.root / 'worker.lock',
                        self.fx.session / 'session.json', self.fx.collection_dir.parent,
                        self.fx.collection_dir, self.fx.collection_dir.parent / 'plan.json',
                        self.fx.collection_dir.parent / 'apex-package.zip',
                        self.fx.collection_dir / 'collection-manifest.json',
                        self.fx.collection_dir / 'package.zip',
                        self.fx.collection_dir / 'clean-import-receipt.json')
        before = snapshot(self.fx.h.root)
        for denied in denied_paths:
            checked = []
            def owner_only(paths):
                checked.extend(paths)
                if denied in paths:
                    raise PermissionError(SECRET)
            self.resolver.privacy_check = owner_only
            with self.subTest(path=str(denied.relative_to(self.fx.h.private))), \
                 self.assertRaisesRegex(f.FailureResolutionError, 'FAILED_RESOLUTION_GUARD_FAILED') as caught:
                self.ready()
            self.assertIn(denied, checked)
            self.assertNotIn(self.fx.h.private, checked)
            self.assertNotIn(SECRET, str(caught.exception))
            self.assertEqual(self.transport.calls, [])
            self.assertEqual(snapshot(self.fx.h.root), before)

    def test_structural_parent_must_be_an_existing_directory_before_any_acl_or_transport(self):
        regular_file = self.fx.h.root / 'not-a-directory'
        regular_file.write_bytes(b'synthetic parent path fixture')
        for parent in (regular_file, self.fx.h.root / 'missing-parent'):
            privacy = Mock(return_value=None)
            resolver = f.FailureResolver(manifest=self.fx.h.manifest, expected_release_sha256=self.fx.h.release,
                private_root=parent, session=parent / 'product-verifier' / self.fx.h.release[:16] / self.fx.session.name,
                expected_collection_sha256=self.fx.collection_sha256, transport=self.transport,
                privacy_check=privacy, now=lambda: NOW)
            before = snapshot(self.fx.h.root)
            with self.subTest(parent=parent.name), self.assertRaises(f.FailureResolutionError) as caught:
                resolver.check()
            self.assertNotIn(SECRET, str(caught.exception))
            privacy.assert_not_called()
            self.assertEqual(self.transport.calls, [])
            self.assertEqual(snapshot(self.fx.h.root), before)

    def test_structural_parent_symlink_or_junction_metadata_is_rejected_before_acl_or_transport(self):
        # Model link metadata/resolved junction target only; no link or junction
        # is created on Windows and no real permission is modified.
        for method in ('is_symlink', 'resolve'):
            original = getattr(Path, method)
            def linked(path, *args, **kwargs):
                if path == self.fx.h.private:
                    return True if method == 'is_symlink' else self.fx.h.root / 'different-junction-target'
                return original(path, *args, **kwargs)
            self.fx.privacy_check.reset_mock()
            before = snapshot(self.fx.h.root)
            with self.subTest(kind=method), patch.object(Path, method, new=linked), \
                 self.assertRaises(f.FailureResolutionError):
                self.ready()
            self.fx.privacy_check.assert_not_called()
            self.assertEqual(self.transport.calls, [])
            self.assertEqual(snapshot(self.fx.h.root), before)

    def test_apply_is_disabled_by_default_and_requires_explicit_boolean_authority(self):
        ready = self.ready()
        for resolver, options, code in ((self.fx.resolver(transport=self.transport), {'apply': True}, 'LIVE_RECOVERY_NOT_INTEGRATED'),
                                        (self.fx.resolver(allow_apply=True), {'apply': True}, 'LIVE_RECOVERY_NOT_INTEGRATED'),
                                        (self.resolver, {}, 'EXPLICIT_FAILURE_RESOLUTION_REQUIRED'),
                                        (self.resolver, {'apply': 1}, 'EXPLICIT_FAILURE_RESOLUTION_REQUIRED')):
            before_calls = list(self.transport.calls)
            with self.subTest(code=code), self.assertRaisesRegex(f.FailureResolutionError, code):
                self.apply_ready(ready, resolver=resolver, **options)
            self.assertEqual(self.transport.calls, before_calls)
            self.assertEqual(snapshot(self.fx.session), self.original)

    def test_live_or_unknown_producer_refuses_without_intent_or_resolution(self):
        for producer in ({'stopped': False}, {'state': 'UNKNOWN'}, None):
            self.transport.producer = producer
            with self.subTest(producer=producer), self.assertRaisesRegex(
                    f.FailureResolutionError, 'FAILED_EVIDENCE_OR_PRODUCER_UNCONFIRMED') as caught:
                self.ready()
            self.assertNotIn(SECRET, str(caught.exception))
            self.assertEqual(snapshot(self.fx.session), self.original)
            self.assertNotIn('resolve_failure', self.transport.calls)

    def test_os_lock_unavailable_blocks_before_observation_or_files(self):
        # Windows can reject the existing lock's read before the lock syscall;
        # both failures must stay bounded and occur before any contact.
        with self.fx.h.journal.lock(), self.assertRaises(f.FailureResolutionError) as caught:
            self.ready()
        self.assertIn(str(caught.exception), ('LOCAL_PRODUCER_LOCK_UNAVAILABLE', 'FAILED_RESOLUTION_GUARD_FAILED'))
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(snapshot(self.fx.session), self.original)

    def test_missing_lock_does_not_create_it_or_start_a_producer(self):
        lock = self.fx.h.journal.root / 'worker.lock'
        lock.unlink()
        with self.assertRaises(Exception):
            self.ready()
        self.assertFalse(lock.exists())
        self.assertEqual(self.transport.calls, [])

    def test_missing_import_completion_or_unknown_import_blocks_before_contact(self):
        path = self.fx.session / 'p0001-import.complete.json'
        raw = path.read_bytes()
        path.unlink()
        with self.assertRaises(Exception):
            self.ready()
        path.write_bytes(raw)
        self.fx.replace_result('import', lambda value: value.update(state='UNKNOWN'))
        with self.assertRaises(Exception):
            self.ready()
        self.assertEqual(self.transport.calls, [])

    def test_unfinished_or_nonterminal_qa_is_not_a_known_failed_attempt(self):
        for status, code in (('QA_FAILED_OR_INCOMPLETE', 124), ('QA_FAILED_OR_INCOMPLETE', 137), ('PASSED', 0)):
            self.fx.replace_result('qa_run', lambda value: value.update(status=status, exit_code=code))
            with self.subTest(code=code), self.assertRaisesRegex(f.FailureResolutionError, 'KNOWN_TERMINAL_QA_FAILURE_REQUIRED'):
                self.ready()
        self.assertEqual(self.transport.calls, [])

    def test_missing_collection_completion_blocks_before_contact(self):
        (self.fx.session / 'p0001-qa-collect.complete.json').unlink()
        with self.assertRaises(Exception):
            self.ready()
        self.assertEqual(self.transport.calls, [])

    def test_unknown_future_import_or_promotion_intent_is_never_discarded(self):
        for name in ('p0002-import.intent.json', 'p0001-promotion-check.intent.json', 'p0001-promotion-apply.intent.json',
                     'p0001-queue-complete.intent.json'):
            path = self.fx.session / name
            path.write_bytes(b'{}\n')
            before = snapshot(self.fx.session)
            with self.subTest(name=name), self.assertRaisesRegex(f.FailureResolutionError, 'UNKNOWN_STEP_OR_PROMOTION_PRESENT'):
                self.ready()
            self.assertEqual(snapshot(self.fx.session), before)
            path.unlink()
        self.assertEqual(self.transport.calls, [])

    def test_claim_intent_tamper_blocks_before_contact(self):
        path = self.fx.session / 'p0001-claim.intent.json'
        path.write_bytes(path.read_bytes() + b' ')
        with self.assertRaisesRegex(f.FailureResolutionError, 'JOURNAL_STEP_BINDING_CHANGED'):
            self.ready()
        self.assertEqual(self.transport.calls, [])

    def test_plan_raw_tamper_blocks_before_contact_even_with_mocked_plan_validator(self):
        path = self.fx.collection_dir.parent / 'plan.json'
        path.write_bytes(path.read_bytes() + b' ')
        with self.assertRaisesRegex(f.FailureResolutionError, 'PLAN_BYTES_CHANGED'):
            self.ready()
        self.plan_validator.assert_not_called()
        self.assertEqual(self.transport.calls, [])

    def test_collection_raw_tamper_blocks_before_contact(self):
        path = self.fx.collection_dir / 'collection-manifest.json'
        path.write_bytes(path.read_bytes() + b' ')
        with self.assertRaisesRegex(f.FailureResolutionError, 'COLLECTION_BYTES_CHANGED'):
            self.ready()
        self.assertEqual(self.transport.calls, [])

    def test_package_tamper_or_extra_evidence_blocks_before_contact(self):
        package = self.fx.collection_dir / 'package.zip'
        original = package.read_bytes()
        package.write_bytes(original + b'changed')
        with self.assertRaisesRegex(f.FailureResolutionError, 'COLLECTED_FILE_CHANGED'):
            self.ready()
        package.write_bytes(original)
        extra = self.fx.collection_dir / 'private-provider-output.txt'
        extra.write_text(SECRET)
        with self.assertRaisesRegex(f.FailureResolutionError, 'COLLECTION_MEMBERS_INVALID'):
            self.ready()
        self.assertEqual(self.transport.calls, [])

    def test_known_clean_receipt_hash_mismatch_blocks_before_contact(self):
        self.fx.replace_result('verify', lambda value: value.update(evidence_sha256='0' * 64))
        with self.assertRaisesRegex(f.FailureResolutionError, 'CLEAN_PHASE_RECEIPT_CHANGED'):
            self.ready()
        self.assertEqual(self.transport.calls, [])

    def test_shared_failed_evidence_validator_rejection_has_no_fallback(self):
        self.recovery.fail = True
        with self.assertRaisesRegex(f.FailureResolutionError, 'FAILED_EVIDENCE_OR_PRODUCER_UNCONFIRMED') as caught:
            self.ready()
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertEqual(self.transport.calls, ['observe'])
        self.assertEqual(snapshot(self.fx.session), self.original)

    def test_explicit_resolution_is_create_only_and_repeat_uses_lookup(self):
        ready = self.ready()
        result = self.apply_ready(ready, apply=True)
        self.assertEqual(result['status'], 'FAILED_QA_CLOSED')
        self.assertEqual(self.transport.calls.count('resolve_failure'), 1)
        self.assertEqual(set(snapshot(self.fx.session)) - set(self.original), set(f.RESOLUTION_FILES))
        self.fx.assert_old_bytes(self, self.original)
        closed = snapshot(self.fx.session)
        repeated = self.apply_ready(ready, apply=True)
        self.assertEqual(repeated, result)
        self.assertEqual(self.transport.calls.count('resolve_failure'), 1)
        self.assertEqual(self.transport.calls.count('lookup_resolution'), 1)
        self.assertEqual(snapshot(self.fx.session), closed)
        self.assert_safe(result)

    def test_lost_resolution_reply_uses_lookup_on_explicit_retry_never_redispatches(self):
        ready = self.ready()
        self.transport.failures['resolve_failure'] = 'after'
        with self.assertRaisesRegex(f.FailureResolutionError, 'RESOLUTION_OUTCOME_UNCONFIRMED_NO_REDISPATCH'):
            self.apply_ready(ready, apply=True)
        intent = (self.fx.session / 'failed-resolution.intent.json').read_bytes()
        self.assertFalse((self.fx.session / 'failed-resolution.complete.json').exists())
        self.assertFalse((self.fx.session / 'closed-failed.json').exists())
        self.assertEqual(len(self.transport.records), 1)
        self.fx.assert_old_bytes(self, self.original)
        del self.transport.failures['resolve_failure']
        result = self.apply_ready(ready, apply=True)
        self.assertEqual(result['status'], 'FAILED_QA_CLOSED')
        self.assertEqual((self.fx.session / 'failed-resolution.intent.json').read_bytes(), intent)
        self.assertEqual(self.transport.calls.count('resolve_failure'), 1)
        self.assertEqual(self.transport.calls.count('lookup_resolution'), 1)
        self.fx.assert_old_bytes(self, self.original)

    def test_unknown_server_outcome_without_record_stays_blocked_on_lookup(self):
        ready = self.ready()
        self.transport.failures['resolve_failure'] = 'before'
        with self.assertRaises(f.FailureResolutionError):
            self.apply_ready(ready, apply=True)
        del self.transport.failures['resolve_failure']
        with self.assertRaisesRegex(f.FailureResolutionError, 'RESOLUTION_OUTCOME_UNCONFIRMED_NO_REDISPATCH'):
            self.apply_ready(ready, apply=True)
        self.assertEqual(self.transport.calls.count('resolve_failure'), 1)
        self.assertEqual(self.transport.calls.count('lookup_resolution'), 1)
        self.assertFalse((self.fx.session / 'closed-failed.json').exists())
        self.fx.assert_old_bytes(self, self.original)

    def test_crash_after_server_ack_before_local_seal_recovers_by_lookup(self):
        ready = self.ready()
        with patch.object(self.resolver, '_seal', side_effect=SimulatedCrash()):
            with self.assertRaises(SimulatedCrash):
                self.apply_ready(ready, apply=True)
        receipt = (self.fx.session / 'failed-resolution.complete.json').read_bytes()
        self.assertFalse((self.fx.session / 'closed-failed.json').exists())
        result = self.apply_ready(ready, apply=True)
        self.assertEqual(result['status'], 'FAILED_QA_CLOSED')
        self.assertEqual((self.fx.session / 'failed-resolution.complete.json').read_bytes(), receipt)
        self.assertEqual(self.transport.calls.count('resolve_failure'), 1)
        self.assertEqual(self.transport.calls.count('lookup_resolution'), 1)
        self.fx.assert_old_bytes(self, self.original)

    def test_wrong_disposition_sha_rejects_before_observation_or_intent(self):
        ready = self.ready()
        self.transport.calls.clear()
        with self.assertRaisesRegex(f.FailureResolutionError, 'EXACT_DISPOSITION_REQUIRED'):
            self.resolver.apply(disposition=ready['disposition'], expected_disposition_sha256='0' * 64, apply=True)
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(snapshot(self.fx.session), self.original)

    def synchronous_fixture(self):
        directory = self.fx.h.private / 'reviewed-synthetic-wrapper'
        directory.mkdir()
        wrapper = directory / 'run-native-v2.sh'
        # Opaque fake bytes only. The wrapper is never executed by these tests.
        raw = b'synthetic reviewed wrapper fixture; not executable evidence\n'
        wrapper.write_bytes(raw)
        contract = ReviewedSynchronousLaunch(verifier_release_sha256=self.fx.h.release,
            qa_source_sha256=self.fx.h.manifest['qa_source_sha256'], wrapper_sha256=C.digest(raw),
            original_wrapper_sha256=C.digest(b'synthetic original wrapper'), image_id='sha256:' + 'e' * 64)
        return contract, wrapper

    def test_synchronous_inventory_requires_exact_trusted_type_and_matching_release_and_qa(self):
        contract, wrapper = self.synchronous_fixture()
        cases = ((vars(contract), wrapper),
                 (replace(contract, verifier_release_sha256='0' * 64), wrapper),
                 (replace(contract, qa_source_sha256='0' * 64), wrapper),
                 (contract, None))
        before = snapshot(self.fx.h.root)
        for reviewed, path in cases:
            with self.subTest(kind=type(reviewed).__name__, path=path), self.assertRaisesRegex(
                    f.FailureResolutionError, 'TRUSTED_SYNCHRONOUS_INVENTORY_REQUIRED'):
                self.fx.resolver(transport=self.transport,
                    reviewed_synchronous_launch=reviewed, wrapper_path=path)
            self.assertEqual(self.transport.calls, [])
            self.assertEqual(snapshot(self.fx.h.root), before)
        with self.assertRaisesRegex(f.FailureResolutionError, 'RECOVERY_PRODUCER_VARIANTS_MIXED'):
            self.fx.resolver(transport=self.transport, wrapper_path=wrapper)

    def test_synchronous_wrapper_path_must_be_private_and_outside_old_session_and_collection(self):
        contract, wrapper = self.synchronous_fixture()
        before = snapshot(self.fx.h.root)
        for path in (self.fx.h.root / 'outside-private.sh', self.fx.session / 'session.json'):
            with self.subTest(path=path), self.assertRaisesRegex(
                    f.FailureResolutionError, 'TRUSTED_SYNCHRONOUS_INVENTORY_REQUIRED'):
                self.fx.resolver(transport=self.transport,
                    reviewed_synchronous_launch=contract, wrapper_path=path)
        resolver = self.fx.resolver(transport=self.transport, reviewed_synchronous_launch=contract,
            wrapper_path=self.fx.collection_dir / 'launch-receipt.json')
        with self.assertRaisesRegex(f.FailureResolutionError, 'WRAPPER_MUST_REMAIN_OUTSIDE_RETAINED_COLLECTION'):
            resolver.check()
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(snapshot(self.fx.h.root), before)

    def test_synchronous_wrapper_bytes_are_hashed_before_transport(self):
        contract, wrapper = self.synchronous_fixture()
        resolver = self.fx.resolver(transport=self.transport,
            reviewed_synchronous_launch=contract, wrapper_path=wrapper)
        wrapper.write_bytes(wrapper.read_bytes() + b'changed')
        before = snapshot(self.fx.h.root)
        with self.assertRaisesRegex(f.FailureResolutionError, 'REVIEWED_WRAPPER_BYTES_CHANGED'):
            resolver.check()
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(snapshot(self.fx.h.root), before)

    def test_synchronous_wrapper_link_and_resolved_path_drift_block_before_transport(self):
        contract, wrapper = self.synchronous_fixture()
        resolver = self.fx.resolver(transport=self.transport,
            reviewed_synchronous_launch=contract, wrapper_path=wrapper)
        for method in ('is_symlink', 'resolve'):
            original = getattr(Path, method)
            def changed(path, *args, **kwargs):
                if path == wrapper:
                    return True if method == 'is_symlink' else self.fx.h.root / 'different-wrapper-target'
                return original(path, *args, **kwargs)
            with self.subTest(method=method), patch.object(Path, method, new=changed), \
                 self.assertRaisesRegex(f.FailureResolutionError, 'PRIVATE_PATH_UNSAFE'):
                resolver.check()
        self.assertEqual(self.transport.calls, [])
        self.fx.assert_old_bytes(self, self.original)

    def test_synchronous_wrapper_and_parent_acl_rejection_blocks_before_transport(self):
        contract, wrapper = self.synchronous_fixture()
        resolver = self.fx.resolver(transport=self.transport,
            reviewed_synchronous_launch=contract, wrapper_path=wrapper)
        before = snapshot(self.fx.h.root)
        for denied in (wrapper.parent, wrapper):
            checked = []
            def owner_only(paths):
                checked.extend(paths)
                if denied in paths:
                    raise PermissionError(SECRET)
            resolver.privacy_check = owner_only
            with self.subTest(path=denied.name), self.assertRaisesRegex(
                    f.FailureResolutionError, 'FAILED_RESOLUTION_GUARD_FAILED') as caught:
                resolver.check()
            self.assertIn(denied, checked)
            self.assertNotIn(SECRET, str(caught.exception))
            self.assertEqual(self.transport.calls, [])
            self.assertEqual(snapshot(self.fx.h.root), before)

    def test_missing_or_oversized_synchronous_wrapper_blocks_before_transport(self):
        contract, wrapper = self.synchronous_fixture()
        resolver = self.fx.resolver(transport=self.transport,
            reviewed_synchronous_launch=contract, wrapper_path=wrapper)
        wrapper.unlink()
        with self.assertRaises(f.FailureResolutionError):
            resolver.check()
        self.assertFalse(wrapper.exists())
        wrapper.write_bytes(b'x' * 65_537)
        with self.assertRaisesRegex(f.FailureResolutionError, 'PRIVATE_EVIDENCE_SIZE_INVALID'):
            resolver.check()
        self.assertEqual(self.transport.calls, [])
        self.fx.assert_old_bytes(self, self.original)

    def test_trusted_synchronous_contract_goes_only_to_validator_not_transport_evidence(self):
        contract, wrapper = self.synchronous_fixture()
        resolver = self.fx.resolver(transport=self.transport, allow_apply=True,
            reviewed_synchronous_launch=contract, wrapper_path=wrapper)
        before_collection = snapshot(self.fx.collection_dir)
        raw = wrapper.read_bytes()
        result = resolver.check()
        self.assertEqual(result['status'], 'FAILED_QA_RESOLUTION_READY')
        self.assertEqual(self.recovery.validations[-1]['wrapper_raw'], raw)
        self.assertIs(self.recovery.validations[-1]['reviewed_synchronous_launch'], contract)
        closed = self.apply_ready(result, resolver=resolver, apply=True)
        self.assertEqual(closed['status'], 'FAILED_QA_CLOSED')
        for operation, evidence in self.transport.inputs:
            self.assertEqual(evidence['wrapper_raw'], raw, operation)
            self.assertNotIn('reviewed_synchronous_launch', evidence)
            self.assertFalse(any(isinstance(value, ReviewedSynchronousLaunch) for value in evidence.values()))
        self.assertTrue(all(value['reviewed_synchronous_launch'] is contract for value in self.recovery.validations))
        self.assertEqual(snapshot(self.fx.collection_dir), before_collection)
        self.fx.assert_old_bytes(self, self.original)
        self.assert_safe(closed)

    def test_container_variant_passes_no_synchronous_options_or_wrapper_bytes(self):
        with patch.object(self.recovery, 'validate_failed_evidence', wraps=self.recovery.validate_failed_evidence) as validate:
            result = self.ready()
        self.assertEqual(result['status'], 'FAILED_QA_RESOLUTION_READY')
        self.assertNotIn('wrapper_raw', validate.call_args.kwargs)
        self.assertNotIn('reviewed_synchronous_launch', validate.call_args.kwargs)
        for _, evidence in self.transport.inputs:
            self.assertNotIn('wrapper_raw', evidence)
            self.assertNotIn('reviewed_synchronous_launch', evidence)
        self.assertEqual(snapshot(self.fx.session), self.original)

    def test_synchronous_shared_validator_rejection_stays_fail_closed(self):
        contract, wrapper = self.synchronous_fixture()
        resolver = self.fx.resolver(transport=self.transport, allow_apply=True,
            reviewed_synchronous_launch=contract, wrapper_path=wrapper)
        self.recovery.fail = True
        with self.assertRaisesRegex(f.FailureResolutionError, 'FAILED_EVIDENCE_OR_PRODUCER_UNCONFIRMED') as caught:
            resolver.check()
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertEqual(self.transport.calls, ['observe'])
        self.assertEqual(snapshot(self.fx.session), self.original)

    def test_constructor_owned_wrapper_bytes_work_without_a_local_wrapper_file(self):
        contract, path = self.synchronous_fixture()
        raw = path.read_bytes()
        path.unlink()
        resolver = self.fx.resolver(transport=self.transport, reviewed_synchronous_launch=contract, wrapper_raw=raw)
        before = snapshot(self.fx.h.root)
        result = resolver.check()
        self.assertEqual(result['status'], 'FAILED_QA_RESOLUTION_READY')
        self.assertIsNone(resolver.wrapper_path)
        self.assertFalse(path.exists())
        self.assertEqual(self.recovery.validations[-1]['wrapper_raw'], raw)
        self.assertIs(self.recovery.validations[-1]['reviewed_synchronous_launch'], contract)
        self.assertEqual(self.transport.inputs[-1][1]['wrapper_raw'], raw)
        self.assertNotIn('reviewed_synchronous_launch', self.transport.inputs[-1][1])
        self.assertEqual(snapshot(self.fx.h.root), before)
        self.assert_safe(result)

    def test_wrapper_bytes_reject_mixed_modes_missing_trust_or_json_contract(self):
        contract, path = self.synchronous_fixture()
        raw = path.read_bytes()
        cases = (({'reviewed_synchronous_launch': contract, 'wrapper_path': path, 'wrapper_raw': raw},
                  'TRUSTED_SYNCHRONOUS_INVENTORY_REQUIRED'),
                 ({'wrapper_raw': raw}, 'RECOVERY_PRODUCER_VARIANTS_MIXED'),
                 ({'reviewed_synchronous_launch': vars(contract), 'wrapper_raw': raw},
                  'TRUSTED_SYNCHRONOUS_INVENTORY_REQUIRED'))
        before = snapshot(self.fx.h.root)
        for index, (options, code) in enumerate(cases):
            with self.subTest(case=index), self.assertRaisesRegex(f.FailureResolutionError, code):
                self.fx.resolver(transport=self.transport, **options)
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(snapshot(self.fx.h.root), before)

    def test_constructor_wrapper_bytes_require_exact_immutable_type_size_and_reviewed_hash(self):
        contract, path = self.synchronous_fixture()
        raw = path.read_bytes()
        class ByteSubclass(bytes):
            pass
        values = (bytearray(raw), memoryview(raw), raw.decode(), {'wrapper': raw.hex()},
                  ByteSubclass(raw), b'', b'x' * 65_537, raw + b'changed')
        before = snapshot(self.fx.h.root)
        for index, value in enumerate(values):
            with self.subTest(case=index, value_type=type(value).__name__), self.assertRaisesRegex(
                    f.FailureResolutionError, 'REVIEWED_WRAPPER_BYTES_CHANGED'):
                self.fx.resolver(transport=self.transport, reviewed_synchronous_launch=contract, wrapper_raw=value)
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(snapshot(self.fx.h.root), before)

    def test_constructor_owned_wrapper_bytes_are_rechecked_under_lease_before_transport(self):
        contract, path = self.synchronous_fixture()
        raw = path.read_bytes()
        resolver = self.fx.resolver(transport=self.transport, reviewed_synchronous_launch=contract, wrapper_raw=raw)
        before = snapshot(self.fx.h.root)
        for value in (raw + b'changed', bytearray(raw)):
            resolver._configured_wrapper_raw = value
            with self.subTest(value_type=type(value).__name__), self.assertRaisesRegex(
                    f.FailureResolutionError, 'REVIEWED_WRAPPER_BYTES_CHANGED'):
                resolver.check()
            self.assertEqual(self.transport.calls, [])
            self.assertIsNone(resolver._active_lease)
            self.assertEqual(snapshot(self.fx.h.root), before)

    def test_prior_idle_polls_are_preserved_and_only_latest_failed_claim_is_resolved(self):
        for path in list(self.fx.session.glob('p0001-*.json')):
            path.rename(path.with_name(path.name.replace('p0001-', 'p0002-', 1)))
        for intent in self.fx.session.glob('p0002-*.intent.json'):
            value = json.loads(intent.read_bytes())
            value['step'] = value['step'].replace('p0001-', 'p0002-', 1)
            digest = save_fixture(intent, value)
            complete = intent.with_name(intent.name.replace('.intent.json', '.complete.json'))
            record = json.loads(complete.read_bytes())
            record['intent_sha256'] = digest
            save_fixture(complete, record)
        digest = self.fx.h.journal.intent(self.fx.session, 'p0001-claim')
        self.fx.h.journal.completed(self.fx.session, 'p0001-claim', digest, {'status': 'IDLE'})
        before = snapshot(self.fx.session)
        result = self.apply_ready(apply=True)
        self.assertEqual(result['status'], 'FAILED_QA_CLOSED')
        self.fx.assert_old_bytes(self, before)
        self.assertEqual(self.transport.calls, ['observe', 'observe', 'resolve_failure'])

    def test_lost_producer_observation_is_bounded_and_creates_no_intent(self):
        self.transport.failures['observe'] = 'before'
        with self.assertRaisesRegex(f.FailureResolutionError, 'PRODUCER_OBSERVATION_UNCONFIRMED') as caught:
            self.ready()
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertEqual(snapshot(self.fx.session), self.original)

    def test_producer_identity_change_between_check_and_apply_blocks_resolution(self):
        ready = self.ready()
        self.transport.producer['identity'] = 'different-synthetic-process'
        with self.assertRaisesRegex(f.FailureResolutionError, 'PRODUCER_IDENTITY_CHANGED'):
            self.apply_ready(ready, apply=True)
        self.assertEqual(self.transport.calls, ['observe', 'observe'])
        self.assertEqual(snapshot(self.fx.session), self.original)

    def test_live_producer_at_apply_blocks_even_if_check_was_ready(self):
        ready = self.ready()
        self.transport.producer['stopped'] = False
        with self.assertRaisesRegex(f.FailureResolutionError, 'FAILED_EVIDENCE_OR_PRODUCER_UNCONFIRMED'):
            self.apply_ready(ready, apply=True)
        self.assertNotIn('resolve_failure', self.transport.calls)
        self.assertEqual(snapshot(self.fx.session), self.original)

    def test_retained_intent_recheck_uses_historical_time_but_fresh_observation(self):
        ready = self.ready()
        self.transport.failures['resolve_failure'] = 'after'
        with self.assertRaises(f.FailureResolutionError):
            self.apply_ready(ready, apply=True)
        original_intent = (self.fx.session / 'failed-resolution.intent.json').read_bytes()
        later = NOW + timedelta(hours=1)
        self.resolver.now = lambda: later
        self.transport.producer['observed_at_utc'] = later.isoformat()
        del self.transport.failures['resolve_failure']
        self.recovery.validations.clear()
        result = self.apply_ready(ready, apply=True)
        self.assertEqual(result['status'], 'FAILED_QA_CLOSED')
        self.assertEqual([value['now'] for value in self.recovery.validations], [NOW, later])
        self.assertEqual((self.fx.session / 'failed-resolution.intent.json').read_bytes(), original_intent)
        self.assertEqual(self.transport.calls.count('resolve_failure'), 1)
        self.assertEqual(self.transport.calls.count('lookup_resolution'), 1)

    def test_resolution_intent_raw_tamper_rejects_before_any_contact(self):
        ready = self.ready()
        self.transport.failures['resolve_failure'] = 'after'
        with self.assertRaises(f.FailureResolutionError):
            self.apply_ready(ready, apply=True)
        path = self.fx.session / 'failed-resolution.intent.json'
        path.write_bytes(path.read_bytes() + b' ')
        self.transport.calls.clear()
        before = snapshot(self.fx.session)
        with self.assertRaisesRegex(f.FailureResolutionError, 'RESOLUTION_INTENT_CHANGED'):
            self.apply_ready(ready, apply=True)
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(snapshot(self.fx.session), before)

    def test_closed_failed_check_is_readonly_and_never_contacts_transport(self):
        result = self.apply_ready(apply=True)
        self.transport.calls.clear()
        before = snapshot(self.fx.h.root)
        checked = self.resolver.check()
        self.assertEqual(checked, result)
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(snapshot(self.fx.h.root), before)

    def test_transport_receives_only_live_fd_bound_lease_and_it_is_closed_after_return(self):
        ready = self.ready()
        self.apply_ready(ready, apply=True)
        self.assertEqual(self.transport.calls, ['observe', 'observe', 'resolve_failure'])
        self.assertEqual(len(self.transport.leases), len(self.transport.calls))
        for lease in self.transport.leases:
            self.assertIs(type(lease), f.HeldOperatorLock)
            with self.assertRaisesRegex(f.FailureResolutionError, 'ACTIVE_MATCHING_OPERATOR_LEASE_REQUIRED'):
                lease.require_active(self.fx.h.release, self.resolver.root)
        self.assertIsNone(self.resolver._active_lease)

    def test_absent_wrong_release_and_closed_leases_reject_before_closed_evidence_read(self):
        with patch.object(self.resolver, '_local') as local:
            for lease in (None, {'held': True, 'release': self.fx.h.release}):
                with self.subTest(lease=lease), self.assertRaisesRegex(
                        f.FailureResolutionError, 'ACTIVE_MATCHING_OPERATOR_LEASE_REQUIRED'):
                    self.resolver._validated_closed_under_lock(lease)
            with self.assertRaisesRegex(f.FailureResolutionError, 'ACTIVE_MATCHING_OPERATOR_LEASE_REQUIRED'):
                self.resolver._require_lease()
            with self.resolver._lock() as lease:
                lease.require_active(self.fx.h.release, self.resolver.root)
                with self.assertRaisesRegex(f.FailureResolutionError, 'ACTIVE_MATCHING_OPERATOR_LEASE_REQUIRED'):
                    lease.require_active('0' * 64)
                with patch.object(self.resolver, 'release', '0' * 64), self.assertRaisesRegex(
                        f.FailureResolutionError, 'ACTIVE_MATCHING_OPERATOR_LEASE_REQUIRED'):
                    self.resolver._validated_closed_under_lock(lease)
            with self.assertRaisesRegex(f.FailureResolutionError, 'ACTIVE_MATCHING_OPERATOR_LEASE_REQUIRED'):
                self.resolver._validated_closed_under_lock(lease)
            local.assert_not_called()
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(snapshot(self.fx.session), self.original)

    def test_lock_lease_cannot_be_constructed_from_public_boolean_or_dictionary(self):
        with self.assertRaisesRegex(f.FailureResolutionError, 'INTERNAL_OPERATOR_LEASE_REQUIRED'):
            f.HeldOperatorLock({'held': True}, self.fx.h.release, self.resolver.root, None)
        self.assertEqual(self.transport.calls, [])

    def test_closed_reader_validates_full_ack_under_one_lock_without_writes_or_contact(self):
        result = self.apply_ready(apply=True)
        stored_ack = json.loads((self.fx.session / 'failed-resolution.complete.json').read_bytes())['acknowledgement']
        self.transport.calls.clear()
        before = snapshot(self.fx.h.root)
        received = []
        def consumer(summary, acknowledgement, lease):
            lease.require_active(self.fx.h.release, self.resolver.root)
            self.assertIs(lease, self.resolver._active_lease)
            self.assertEqual(summary, result)
            self.assertEqual(acknowledgement, stored_ack)
            # The internal validated read may reuse the actual held lease; it
            # must not attempt a nested acquisition or contact the transport.
            self.assertEqual(self.resolver._validated_closed_under_lock(lease), stored_ack)
            received.append(lease)
            return {'status': 'SYNTHETIC_READBACK_CONFIRMED', 'job_id': summary['job_id']}
        with patch.object(self.resolver, '_lock', wraps=self.resolver._lock) as lock:
            readback = self.resolver.read_closed_resolution(consumer)
        lock.assert_called_once_with()
        self.assertEqual(readback['status'], 'SYNTHETIC_READBACK_CONFIRMED')
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(snapshot(self.fx.h.root), before)
        self.assertEqual(len(received), 1)
        with self.assertRaisesRegex(f.FailureResolutionError, 'ACTIVE_MATCHING_OPERATOR_LEASE_REQUIRED'):
            received[0].require_active(self.fx.h.release)
        self.assertIsNone(self.resolver._active_lease)

    def test_closed_reader_rejects_unsealed_failure_without_calling_consumer(self):
        consumer = Mock()
        before = snapshot(self.fx.h.root)
        with self.assertRaisesRegex(f.FailureResolutionError, 'CLOSED_FAILED_DISPOSITION_REQUIRED'):
            self.resolver.read_closed_resolution(consumer)
        consumer.assert_not_called()
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(snapshot(self.fx.h.root), before)
        self.assertIsNone(self.resolver._active_lease)

    def test_closed_reader_callback_error_is_bounded_and_still_closes_lease(self):
        self.apply_ready(apply=True)
        self.transport.calls.clear()
        before = snapshot(self.fx.h.root)
        captured = []
        def consumer(summary, acknowledgement, lease):
            lease.require_active(self.fx.h.release)
            captured.append(lease)
            raise RuntimeError(SECRET)
        with self.assertRaisesRegex(f.FailureResolutionError, 'FAILED_RESOLUTION_GUARD_FAILED') as caught:
            self.resolver.read_closed_resolution(consumer)
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(snapshot(self.fx.h.root), before)
        self.assertEqual(len(captured), 1)
        with self.assertRaisesRegex(f.FailureResolutionError, 'ACTIVE_MATCHING_OPERATOR_LEASE_REQUIRED'):
            captured[0].require_active(self.fx.h.release)
        self.assertIsNone(self.resolver._active_lease)

    def test_sealed_old_receipt_or_seal_tamper_rejects_before_contact(self):
        ready = self.ready()
        self.apply_ready(ready, apply=True)
        for name in ('p0001-prepare.complete.json', 'closed-failed.json', 'failed-resolution.complete.json'):
            path = self.fx.session / name
            raw = path.read_bytes()
            path.write_bytes(raw + b' ')
            self.transport.calls.clear()
            expected = 'RESOLUTION_COMPLETION_CHANGED' if name == 'failed-resolution.complete.json' else 'CLOSED_FAILURE_SEAL_CHANGED'
            with self.subTest(name=name), self.assertRaisesRegex(f.FailureResolutionError, expected):
                self.apply_ready(ready, apply=True)
            self.assertEqual(self.transport.calls, [])
            self.assertEqual(path.read_bytes(), raw + b' ')
            path.write_bytes(raw)

    def test_completion_whitespace_tamper_before_seal_rejects_check_and_apply_without_contact(self):
        ready = self.ready()
        with patch.object(self.resolver, '_seal', side_effect=SimulatedCrash()), self.assertRaises(SimulatedCrash):
            self.apply_ready(ready, apply=True)
        path = self.fx.session / 'failed-resolution.complete.json'
        path.write_bytes(path.read_bytes() + b' ')
        self.assertFalse((self.fx.session / 'closed-failed.json').exists())
        self.transport.calls.clear()
        before = snapshot(self.fx.session)
        for action in (self.resolver.check, lambda: self.apply_ready(ready, apply=True)):
            with self.assertRaisesRegex(f.FailureResolutionError, 'RESOLUTION_COMPLETION_CHANGED'):
                action()
            self.assertEqual(self.transport.calls, [])
            self.assertEqual(snapshot(self.fx.session), before)

    def test_changed_evidence_bound_to_existing_unsealed_intent_rejects_before_contact(self):
        ready = self.ready()
        self.transport.failures['resolve_failure'] = 'after'
        with self.assertRaises(f.FailureResolutionError):
            self.apply_ready(ready, apply=True)
        self.assertFalse((self.fx.session / 'closed-failed.json').exists())
        # A semantically identical but byte-changed old receipt changes the
        # disposition's retained-byte binding, even before a final seal exists.
        path = self.fx.session / 'p0001-import.complete.json'
        path.write_bytes(path.read_bytes() + b' ')
        self.transport.calls.clear()
        before = snapshot(self.fx.session)
        for action in (self.resolver.check, lambda: self.apply_ready(ready, apply=True)):
            with self.assertRaisesRegex(f.FailureResolutionError, 'DISPOSITION_EVIDENCE_CHANGED'):
                action()
            self.assertEqual(self.transport.calls, [])
            self.assertEqual(snapshot(self.fx.session), before)

    def test_unknown_acknowledgement_fields_are_not_retained_or_returned(self):
        ready = self.ready()
        transport = self.resolver.transport
        def response(operation, **kwargs):
            value = transport(operation, **kwargs)
            if operation == 'resolve_failure':
                value['provider_output'] = SECRET
            return value
        self.resolver.transport = response
        with self.assertRaisesRegex(f.FailureResolutionError, 'RESOLUTION_OUTCOME_UNCONFIRMED_NO_REDISPATCH') as caught:
            self.apply_ready(ready, apply=True)
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertFalse((self.fx.session / 'failed-resolution.complete.json').exists())
        for raw in snapshot(self.fx.session).values():
            self.assertNotIn(SECRET.encode(), raw)

    def test_prepare_attempt_is_readonly_request_only_after_sealed_failure(self):
        from qa.operator import product_queue_transport as bridge
        manifest = copy.deepcopy(self.fx.h.manifest)
        manifest['qa_source_sha256'] = '0' * 64
        release = bridge.release_sha256(manifest)
        options = {'new_manifest': manifest, 'expected_new_release_sha256': release,
                   'request_id': 'synthetic-request', 'attempt_id': 'synthetic-attempt'}
        with self.assertRaisesRegex(f.FailureResolutionError, 'CLOSED_FAILED_DISPOSITION_REQUIRED'):
            self.resolver.prepare_attempt(**options)
        self.assertEqual(self.transport.calls, [])
        self.apply_ready(apply=True)
        self.transport.calls.clear()
        before = snapshot(self.fx.h.root)
        result = self.resolver.prepare_attempt(**options)
        self.assertEqual(result['status'], 'NEW_ATTEMPT_REQUEST_ONLY')
        self.assertIs(result['authorization_applied'], False)
        self.assertIs(result['target_allocated'], False)
        self.assertIs(result['prior_allocation_reuse_permitted'], False)
        self.assertIs(result['automatic_retry_permitted'], False)
        self.assertEqual(result['request']['old_binding'], self.fx.binding.payload())
        self.assertEqual(result['request']['verifier_release_sha256'], release)
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(snapshot(self.fx.h.root), before)
        self.assert_safe(result)

    def test_prepare_attempt_refuses_same_release_or_unchanged_qa(self):
        from qa.operator import product_queue_transport as bridge
        manifest = copy.deepcopy(self.fx.h.manifest)
        for changed in (False, True):
            if changed:
                manifest['promotion_transport_sha256'] = '0' * 64
            with self.subTest(changed=changed), self.assertRaisesRegex(
                    f.FailureResolutionError, 'NEW_REVIEWED_QA_RELEASE_REQUIRED'):
                self.resolver.prepare_attempt(new_manifest=manifest,
                    expected_new_release_sha256=bridge.release_sha256(manifest),
                    request_id='synthetic-request', attempt_id='synthetic-attempt')
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(snapshot(self.fx.session), self.original)

    def test_cli_apply_authorization_and_invalid_arguments_never_echo_inputs(self):
        cases = [[SECRET], ['apply', '--manifest', SECRET, '--release-sha256', 'a' * 64,
                            '--session', SECRET, '--collection-sha256', 'b' * 64, '--apply'],
                 ['authorize-attempt', '--manifest', SECRET, '--release-sha256', 'a' * 64,
                  '--session', SECRET, '--collection-sha256', 'b' * 64, '--apply'],
                 ['check', '--manifest', SECRET, '--release-sha256', 'a' * 64, '--session', SECRET,
                  '--collection-sha256', 'b' * 64, '--reviewed-synchronous-launch', SECRET],
                 ['check', '--manifest', SECRET, '--release-sha256', 'a' * 64, '--session', SECRET,
                  '--collection-sha256', 'b' * 64, '--wrapper-raw', SECRET]]
        for args in cases:
            output, errors = io.StringIO(), io.StringIO()
            with self.subTest(command=args[0]), patch.object(sys, 'argv', [str(Path(f.__file__)), *args]), \
                 redirect_stdout(output), redirect_stderr(errors), self.assertRaises(SystemExit) as caught:
                runpy.run_path(str(Path(f.__file__)), run_name='__main__')
            self.assertEqual(caught.exception.code, 2)
            self.assertEqual(json.loads(output.getvalue()), {'status': 'BLOCKED',
                'code': 'FAILED_RESOLUTION_GUARD_FAILED', 'automatic_replay_permitted': False})
            self.assertEqual(errors.getvalue(), '')
            self.assertNotIn(SECRET, output.getvalue())
        self.assertEqual(self.transport.calls, [])
        self.assertEqual(snapshot(self.fx.session), self.original)


if __name__ == '__main__':
    unittest.main()
