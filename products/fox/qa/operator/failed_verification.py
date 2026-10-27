"""Inert failed-QA resolution preparation; NOT a live recovery transport.

Only a stopped, fully retained terminal QA failure is eligible. Unknown imports,
unfinished QA, missing receipts and missing producer observations fail closed.
Default check is local/read-only; CLI apply is unavailable in this increment.
An injected test transport may exercise explicit create-only resolution records.
Nothing here runs clean phases, QA, promotion, models, or human acceptance.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
for folder in (ROOT, ROOT / 'fox'):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))
from qa.operator import clean_install as clean
from qa.operator import contracts as C
from qa.operator import product_verifier as product
from qa.operator import product_queue_transport as bridge
from qa.operator import promote_native as promotion
from fox.verification_queue import Claim, VerificationBinding

STEPS = ('prepare', 'clean_check', 'allocate', 'schema', 'import', 'verify', 'qa_stage', 'qa_run', 'qa_collect')
FILES = frozenset({'package.zip', 'native-form-spec.json', 'allocation-receipt.json',
    'verification-profile.json', 'clean-import-receipt.json', 'qa-profile.json',
    'target-receipt.json', 'qa-result.json', 'stage-receipt.json', 'launch-intent.json',
    'dispatch-receipt.json', 'launch-receipt.json'})
RESOLUTION_FILES = frozenset({'failed-resolution.intent.json', 'failed-resolution.complete.json', 'closed-failed.json'})
SHA = re.compile(r'[a-f0-9]{64}\Z')
SESSION = re.compile(r'session-[a-f0-9]{24}\Z')
_LEASE_KEY = object()


class FailureResolutionError(RuntimeError):
    """Only fixed categories; never exception/provider/file/credential text."""


def require(ok, code):
    if not ok:
        raise FailureResolutionError(code)


def _sha(value):
    return type(value) is str and SHA.fullmatch(value) is not None


def _recovery():
    # Shared terminal-failure validator, deliberately separate from the passed
    # technical-proof gate. There is no permissive local fallback validator.
    from fox import verification_recovery
    return verification_recovery


def _bounded(method):
    def checked(*args, **kwargs):
        try:
            return method(*args, **kwargs)
        except FailureResolutionError:
            raise
        except Exception:
            raise FailureResolutionError('FAILED_RESOLUTION_GUARD_FAILED') from None
    return checked


class HeldOperatorLock:
    """Internal, process-local lease for the actual held fd; never a JSON flag."""
    __slots__ = ('_key', '_release', '_root', '_stream', '_identity', '_pid', '_active')

    def __init__(self, key, release, root, stream):
        require(key is _LEASE_KEY, 'INTERNAL_OPERATOR_LEASE_REQUIRED')
        self._key, self._release, self._root, self._stream = key, release, root, stream
        info = os.fstat(stream.fileno())
        self._identity = (info.st_dev, info.st_ino)
        self._pid, self._active = os.getpid(), True

    def require_active(self, expected_release, expected_root=None):
        require(type(self) is HeldOperatorLock and self._key is _LEASE_KEY and self._active
                and self._pid == os.getpid() and not self._stream.closed
                and self._release == expected_release
                and (expected_root is None or self._root == Path(expected_root).absolute()),
                'ACTIVE_MATCHING_OPERATOR_LEASE_REQUIRED')
        try:
            info = os.fstat(self._stream.fileno())
            current = (self._root / 'worker.lock').stat()
        except (OSError, ValueError):
            raise FailureResolutionError('OPERATOR_LEASE_FILE_CHANGED') from None
        require(self._identity == (info.st_dev, info.st_ino) == (current.st_dev, current.st_ino)
                and stat.S_ISREG(info.st_mode) and info.st_nlink == current.st_nlink == 1,
                'OPERATOR_LEASE_FILE_CHANGED')


class FailureResolver:
    def __init__(self, *, manifest, expected_release_sha256, session,
                 expected_collection_sha256, private_root=None, transport=None,
                 allow_apply=False, privacy_check=promotion.private_inputs,
                 reviewed_synchronous_launch=None, wrapper_path=None, wrapper_raw=None,
                 now=lambda: datetime.now(timezone.utc)):
        self.manifest = bridge.validate_release(manifest)
        require(_sha(expected_release_sha256) and bridge.release_sha256(self.manifest) == expected_release_sha256,
                'EXACT_HISTORICAL_RELEASE_REQUIRED')
        require(_sha(expected_collection_sha256), 'EXACT_FAILED_COLLECTION_REQUIRED')
        require(type(allow_apply) is bool, 'APPLY_CONFIGURATION_INVALID')
        self.release = expected_release_sha256
        self.private = Path(clean.PRIVATE if private_root is None else private_root).absolute()
        self.root = self.private / 'product-verifier' / self.release[:16]
        self.session = Path(session).absolute()
        require(self.session.parent == self.root and SESSION.fullmatch(self.session.name), 'EXACT_OLD_SESSION_REQUIRED')
        self.collection_sha = expected_collection_sha256
        self.transport, self.allow_apply = transport, allow_apply
        self.privacy_check, self.now = privacy_check, now
        self._active_lease = None
        # Installation-owned typed inventory, never a producer/request JSON
        # declaration. Raw wrapper evidence remains outside the old collection.
        self.reviewed_synchronous_launch = reviewed_synchronous_launch
        self.wrapper_path = Path(wrapper_path).absolute() if wrapper_path is not None else None
        self._configured_wrapper_raw = wrapper_raw
        if reviewed_synchronous_launch is None:
            require(wrapper_path is None and wrapper_raw is None, 'RECOVERY_PRODUCER_VARIANTS_MIXED')
        else:
            require(type(reviewed_synchronous_launch) is _recovery().ReviewedSynchronousLaunch
                    and reviewed_synchronous_launch.verifier_release_sha256 == self.release
                    and reviewed_synchronous_launch.qa_source_sha256 == self.manifest['qa_source_sha256']
                    and ((self.wrapper_path is not None) != (wrapper_raw is not None)),
                    'TRUSTED_SYNCHRONOUS_INVENTORY_REQUIRED')
            if self.wrapper_path is not None:
                require(self.private in self.wrapper_path.parents and self.session not in self.wrapper_path.parents,
                        'TRUSTED_SYNCHRONOUS_INVENTORY_REQUIRED')
            else:
                require(type(wrapper_raw) is bytes and 0 < len(wrapper_raw) <= 65_536
                        and C.digest(wrapper_raw) == reviewed_synchronous_launch.wrapper_sha256,
                        'REVIEWED_WRAPPER_BYTES_CHANGED')

    def _safe(self, path, *, directory=False):
        path = Path(path)
        require(path.is_absolute() and path.resolve() == path and not path.is_symlink(), 'PRIVATE_PATH_UNSAFE')
        info = path.stat()
        require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                'PRIVATE_PATH_UNSAFE')
        self.privacy_check([path])
        return path

    def _raw(self, path, maximum=C.MAX_JSON_BYTES):
        path = self._safe(path)
        require(0 < path.stat().st_size <= maximum, 'PRIVATE_EVIDENCE_SIZE_INVALID')
        raw = path.read_bytes()
        require(0 < len(raw) <= maximum, 'PRIVATE_EVIDENCE_SIZE_INVALID')
        return raw

    def _json(self, path):
        return C.load_json(self._raw(path))

    @contextmanager
    def _lock(self):
        """Lock existing owner-private file, without mkdir/startup/metadata writes."""
        require(self._active_lease is None, 'NESTED_OPERATOR_LOCK_FORBIDDEN')
        # Match the established PrivateJournal boundary: the shared clean-plan
        # parent is structural only. Every actual journal/collection directory
        # and evidence file below it remains subject to owner-only ACL checks.
        require(self.private.is_dir() and not self.private.is_symlink()
                and self.private.resolve() == self.private, 'PRIVATE_OPERATOR_ROOT_UNSAFE')
        for path in (self.root.parent, self.root, self.session):
            self._safe(path, directory=True)
        require(self._json(self.root / 'release.json') == {
            'scope': 'fox-product-verifier-journal-v1', 'release_sha256': self.release}, 'JOURNAL_RELEASE_DIFFERS')
        path = self._safe(self.root / 'worker.lock')
        require(self._raw(path, 1) == b'0', 'EXISTING_OPERATOR_LOCK_REQUIRED')
        stream = path.open('r+b')
        held, lease = False, None
        try:
            try:
                if os.name == 'nt':
                    import msvcrt
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                held = True
            except OSError:
                raise FailureResolutionError('LOCAL_PRODUCER_LOCK_UNAVAILABLE') from None
            lease = HeldOperatorLock(_LEASE_KEY, self.release, self.root, stream)
            self._active_lease = lease
            yield lease
        finally:
            if lease is not None:
                lease._active = False
            self._active_lease = None
            if held:
                if os.name == 'nt':
                    import msvcrt
                    stream.seek(0)
                    msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            stream.close()

    def _step(self, label, binding=None):
        raw_intent = self._raw(self.session / (label + '.intent.json'))
        raw_completion = self._raw(self.session / (label + '.complete.json'))
        intent, completion = C.load_json(raw_intent), C.load_json(raw_completion)
        expected = {'scope': 'fox-product-verifier-step-v1', 'release_sha256': self.release,
                    'step': label, 'binding_sha256': C.digest(C.canonical_bytes(binding.payload())) if binding else None}
        require(intent == expected and set(completion) == {'scope', 'release_sha256', 'intent_sha256', 'result'}
                and completion['scope'] == 'fox-product-verifier-step-result-v1'
                and completion['release_sha256'] == self.release
                and completion['intent_sha256'] == C.digest(raw_intent), 'JOURNAL_STEP_BINDING_CHANGED')
        require(type(completion['result']) is dict, 'JOURNAL_STEP_RESULT_INVALID')
        return {'intent_sha256': C.digest(raw_intent), 'completion_sha256': C.digest(raw_completion),
                'result': completion['result']}

    def _local(self):
        header = self._json(self.session / 'session.json')
        require(set(header) == {'scope', 'release_sha256', 'started_at_utc', 'bounds', 'startup_authorized'}
                and header['scope'] == 'fox-product-verifier-session-v1' and header['release_sha256'] == self.release
                and header['startup_authorized'] is True, 'JOURNAL_HEADER_INVALID')
        members = {path.name for path in self.session.iterdir()}
        claim_labels = sorted(name[:-12] for name in members if re.fullmatch(r'p[0-9]{4}-claim\.intent\.json', name))
        require(bool(claim_labels), 'KNOWN_CLAIM_REQUIRED')
        allowed = {'session.json', 'attention.json'} | set(RESOLUTION_FILES)
        selected = None
        for index, label in enumerate(claim_labels, 1):
            require(label == 'p' + str(index).zfill(4) + '-claim', 'JOURNAL_POLL_ORDER_INVALID')
            allowed.update({label + '.intent.json', label + '.complete.json'})
            result = self._step(label)['result']
            if result == {'status': 'IDLE'}:
                require(selected is None, 'CLAIM_AFTER_FAILED_ATTEMPT')
                continue
            require(selected is None and set(result) == {'status', 'claim'} and result['status'] == 'CLAIMED'
                    and label == claim_labels[-1], 'EXACT_SINGLE_FAILED_CLAIM_REQUIRED')
            claim = product._claim(result['claim'], self.release)
            selected = (label[:5], claim)
        require(selected is not None, 'KNOWN_CLAIM_REQUIRED')
        prefix, claim = selected
        phases, context = {}, {}
        for step in STEPS:
            label = prefix + '-' + step.replace('_', '-')
            allowed.update({label + '.intent.json', label + '.complete.json'})
            value = self._step(label, claim.binding)
            checked = product.safe_phase(step, value['result'], claim.binding, context, self.manifest)
            context.update(checked)
            phases[step] = value
        require(phases['qa_run']['result']['status'] == 'QA_FAILED_OR_INCOMPLETE'
                and phases['qa_run']['result']['exit_code'] == 2, 'KNOWN_TERMINAL_QA_FAILURE_REQUIRED')
        require(members <= allowed, 'UNKNOWN_STEP_OR_PROMOTION_PRESENT')
        if 'attention.json' in members:
            require(self._json(self.session / 'attention.json') == {
                'status': 'ATTENTION', 'release_sha256': self.release, 'known_claim': True,
                'code': 'OUTCOME_UNCONFIRMED_PRESERVE_AND_RECONCILE', 'automatic_replay_permitted': False},
                'ATTENTION_RECORD_CHANGED')
        plan_path = self.private / context['plan_sha256'] / 'plan.json'
        self._safe(plan_path.parent, directory=True)
        plan_raw = self._raw(plan_path)
        require(C.digest(plan_raw) == context['plan_sha256'], 'PLAN_BYTES_CHANGED')
        plan = C.validate_plan(plan_raw, operator_code_sha256=self.manifest['clean_operator_code_sha256'])
        require(all(plan['binding'][key] == item for key, item in claim.binding.payload().items()
                    if key != 'verifier_release_sha256'), 'PLAN_JOB_BINDING_DIFFERS')
        directory = plan_path.parent / ('qa-' + self.manifest['qa_source_sha256'][:16])
        self._safe(directory, directory=True)
        collection_raw = self._raw(directory / 'collection-manifest.json')
        require(C.digest(collection_raw) == self.collection_sha == context['collection_manifest_sha256'], 'COLLECTION_BYTES_CHANGED')
        collection = C.load_json(collection_raw)
        require(collection.get('status') == 'COLLECTED' and collection.get('credentials_and_logs_excluded') is True
                and collection.get('plan_sha256') == context['plan_sha256']
                and collection.get('source_sha256') == self.manifest['qa_source_sha256']
                and type(collection.get('sha256')) is dict and set(collection['sha256']) == FILES,
                'COLLECTION_BINDING_INVALID')
        require({path.name for path in directory.iterdir()} == FILES | {'collection-manifest.json'}, 'COLLECTION_MEMBERS_INVALID')
        files = {name: self._raw(directory / name, 8_000_000 if name == 'package.zip' else 2_000_000) for name in FILES}
        require(all(C.digest(raw) == collection['sha256'][name] for name, raw in files.items()), 'COLLECTED_FILE_CHANGED')
        require(C.digest(files['package.zip']) == claim.binding.package_sha256
                and self._raw(plan_path.parent / 'apex-package.zip', 8_000_000) == files['package.zip'], 'PACKAGE_BYTES_CHANGED')
        require(C.digest(files['allocation-receipt.json']) == phases['allocate']['result']['evidence_sha256']
                == phases['qa_stage']['result']['allocation_receipt_sha256']
                and C.digest(files['clean-import-receipt.json']) == phases['verify']['result']['evidence_sha256'],
                'CLEAN_PHASE_RECEIPT_CHANGED')
        original = {name: C.digest(self._raw(self.session / name)) for name in members - RESOLUTION_FILES}
        summary = {'schema_version': 1, 'scope': 'fox-verification-failed-journal-summary-v1',
                   'session_id': self.session.name, 'release_sha256': self.release,
                   'binding_sha256': C.digest(C.canonical_bytes(claim.binding.payload())),
                   'claim_sha256': _recovery().claim_sha256(claim), 'retained_sha256': original,
                   'phases': phases, 'unresolved_intents': [], 'promotion_attempted': False,
                   'queue_completion_attempted': False}
        self._check_resolution_records()
        evidence = {'binding': claim.binding, 'package': files['package.zip'], 'plan_raw': plan_raw,
                    'collection_raw': collection_raw, 'files': files, 'journal_summary': summary}
        if self.reviewed_synchronous_launch is not None:
            # The collection stays byte-for-byte unchanged. Wrapper evidence
            # comes from a protected file or immutable constructor-owned bytes;
            # its approved digest is not learned from an untrusted observation.
            if self.wrapper_path is not None:
                require(directory not in self.wrapper_path.parents, 'WRAPPER_MUST_REMAIN_OUTSIDE_RETAINED_COLLECTION')
                self._safe(self.wrapper_path.parent, directory=True)
                wrapper = self._raw(self.wrapper_path, 65_536)
            else:
                # Protected constructor-owned bytes can be independently
                # reconstructed from a reviewed original. This does not claim
                # they were fetched; the authoritative observer must still
                # match the actual remote wrapper hash under the same lease.
                wrapper = self._configured_wrapper_raw
                require(type(wrapper) is bytes and 0 < len(wrapper) <= 65_536,
                        'REVIEWED_WRAPPER_BYTES_CHANGED')
            require(C.digest(wrapper) == self.reviewed_synchronous_launch.wrapper_sha256,
                    'REVIEWED_WRAPPER_BYTES_CHANGED')
            evidence['wrapper_raw'] = wrapper
        return claim, evidence

    def _check_resolution_records(self):
        """Any retained recovery record is checked before even read-only contact."""
        intent_path = self.session / 'failed-resolution.intent.json'
        completion_path = self.session / 'failed-resolution.complete.json'
        seal_path = self.session / 'closed-failed.json'
        if not intent_path.exists():
            require(not completion_path.exists() and not seal_path.exists(), 'RESOLUTION_CHAIN_INCOMPLETE')
            return
        intent_raw = self._raw(intent_path)
        intent = C.load_json(intent_raw)
        require(set(intent) == {'scope', 'release_sha256', 'disposition_sha256', 'disposition'}
                and intent['scope'] == 'fox-verification-failed-resolution-intent-v1'
                and intent['release_sha256'] == self.release and intent_raw == C.canonical_bytes(intent)
                and _recovery().disposition_sha256(intent['disposition']) == intent['disposition_sha256'],
                'RESOLUTION_INTENT_CHANGED')
        if not completion_path.exists():
            require(not seal_path.exists(), 'RESOLUTION_CHAIN_INCOMPLETE')
            return
        completion_raw = self._raw(completion_path)
        completion = C.load_json(completion_raw)
        require(set(completion) == {'scope', 'intent_sha256', 'acknowledgement'}
                and completion['scope'] == 'fox-verification-failed-resolution-complete-v1'
                and completion['intent_sha256'] == C.digest(intent_raw)
                and completion_raw == C.canonical_bytes(completion), 'RESOLUTION_COMPLETION_CHANGED')
        self._ack(completion['acknowledgement'], intent['disposition'], intent['disposition_sha256'])
        if seal_path.exists():
            expected = self._seal_document(completion['acknowledgement'])
            require(self._raw(seal_path) == C.canonical_bytes(expected), 'CLOSED_FAILURE_SEAL_CHANGED')

    def _observe(self, claim, evidence):
        require(self.transport is not None, 'AUTHORITATIVE_PRODUCER_OBSERVATION_REQUIRED')
        try:
            lease = self._require_lease()
            return self.transport('observe', claim=claim, evidence=evidence, operator_lease=lease)
        except Exception:
            raise FailureResolutionError('PRODUCER_OBSERVATION_UNCONFIRMED') from None

    def _require_lease(self):
        require(type(self._active_lease) is HeldOperatorLock, 'ACTIVE_MATCHING_OPERATOR_LEASE_REQUIRED')
        self._active_lease.require_active(self.release, self.root)
        return self._active_lease

    def _validate(self, evidence, producer, *, historical=False):
        try:
            now = self.now()
            if historical:
                observed = datetime.fromisoformat(producer['observed_at_utc'].replace('Z', '+00:00'))
                require(observed.tzinfo is not None and (now - observed).total_seconds() >= -5,
                        'RESOLUTION_TIME_INVALID')
                now = observed
            options = ({'reviewed_synchronous_launch': self.reviewed_synchronous_launch}
                       if self.reviewed_synchronous_launch is not None else {})
            return _recovery().validate_failed_evidence(**evidence, producer=producer, now=now, **options)
        except Exception:
            raise FailureResolutionError('FAILED_EVIDENCE_OR_PRODUCER_UNCONFIRMED') from None

    @_bounded
    def check(self):
        with self._lock():
            claim, evidence = self._local()
            if (self.session / 'failed-resolution.intent.json').exists():
                saved = self._json(self.session / 'failed-resolution.intent.json')['disposition']
                require(self._validate(evidence, saved['producer'], historical=True) == saved,
                        'DISPOSITION_EVIDENCE_CHANGED')
            if (self.session / 'closed-failed.json').is_file():
                acknowledgement = self._json(self.session / 'failed-resolution.complete.json')['acknowledgement']
                document = acknowledgement['disposition']
                require(self._validate(evidence, document['producer'], historical=True) == document,
                        'DISPOSITION_EVIDENCE_CHANGED')
                return {'status': 'FAILED_QA_CLOSED', 'job_id': claim.binding.job_id,
                        'disposition_sha256': acknowledgement['disposition_sha256'],
                        'technical_verification_passed': False, 'human_acceptance_recorded': False,
                        'automatic_replay_permitted': False}
            if self.transport is None:
                return {'status': 'LOCAL_EVIDENCE_ONLY', 'code': 'AUTHORITATIVE_PRODUCER_OBSERVATION_REQUIRED',
                        'job_id': claim.binding.job_id, 'apply_available': False, 'resolution_permitted': False}
            document = self._validate(evidence, self._observe(claim, evidence))
            return {'status': 'FAILED_QA_RESOLUTION_READY', 'disposition': document,
                    'disposition_sha256': _recovery().disposition_sha256(document),
                    'apply_available': self.allow_apply, 'technical_verification_passed': False,
                    'human_acceptance_recorded': False}

    def _save_identical(self, name, value):
        path, raw = self.session / name, C.canonical_bytes(value)
        if path.exists():
            require(self._raw(path) == raw, 'RESOLUTION_EXISTING_BYTES_DIFFER')
        else:
            clean.save_new(path, raw)

    @staticmethod
    def _ack(value, document, digest):
        require(type(value) is dict and set(value) == {'status', 'disposition_sha256', 'disposition'}
                and value['status'] == 'FAILED_QA_RECORDED' and value['disposition_sha256'] == digest
                and value['disposition'] == document, 'SERVER_RESOLUTION_UNCONFIRMED')
        return value

    def _seal_document(self, acknowledgement):
        retained = {path.name: C.digest(self._raw(path)) for path in self.session.iterdir() if path.name != 'closed-failed.json'}
        return {'scope': 'fox-product-verifier-closed-failed-v1',
            'status': 'FAILED_QA_CLOSED', 'release_sha256': self.release,
            'disposition_sha256': acknowledgement['disposition_sha256'], 'retained_sha256': retained,
            'technical_verification_passed': False, 'human_acceptance_recorded': False,
            'automatic_replay_permitted': False}

    def _seal(self, acknowledgement):
        self._save_identical('closed-failed.json', self._seal_document(acknowledgement))

    @_bounded
    def apply(self, *, disposition, expected_disposition_sha256, apply=False):
        require(apply is True, 'EXPLICIT_FAILURE_RESOLUTION_REQUIRED')
        require(self.allow_apply and self.transport is not None, 'LIVE_RECOVERY_NOT_INTEGRATED')
        require(_sha(expected_disposition_sha256)
                and _recovery().disposition_sha256(disposition) == expected_disposition_sha256, 'EXACT_DISPOSITION_REQUIRED')
        with self._lock():
            claim, evidence = self._local()
            existing = (self.session / 'failed-resolution.intent.json').exists()
            if existing:
                saved = self._json(self.session / 'failed-resolution.intent.json')
                require(saved['disposition'] == disposition and saved['disposition_sha256'] == expected_disposition_sha256,
                        'RESOLUTION_EXISTING_BYTES_DIFFER')
            verified = self._validate(evidence, disposition.get('producer'), historical=existing)
            require(verified == disposition, 'DISPOSITION_EVIDENCE_CHANGED')
            fresh = self._validate(evidence, self._observe(claim, evidence))
            require({key: value for key, value in fresh.items() if key != 'producer'} ==
                    {key: value for key, value in disposition.items() if key != 'producer'}
                    and {key: value for key, value in fresh['producer'].items() if key != 'observed_at_utc'} ==
                    {key: value for key, value in disposition['producer'].items() if key != 'observed_at_utc'},
                    'PRODUCER_IDENTITY_CHANGED')
            intent = {'scope': 'fox-verification-failed-resolution-intent-v1', 'release_sha256': self.release,
                      'disposition_sha256': expected_disposition_sha256, 'disposition': disposition}
            self._save_identical('failed-resolution.intent.json', intent)
            operation = 'lookup_resolution' if existing else 'resolve_failure'
            try:
                reply = self.transport(operation, claim=claim, evidence={**evidence, 'disposition': disposition,
                    'disposition_sha256': expected_disposition_sha256}, operator_lease=self._require_lease())
                acknowledgement = self._ack(reply, disposition, expected_disposition_sha256)
            except Exception:
                raise FailureResolutionError('RESOLUTION_OUTCOME_UNCONFIRMED_NO_REDISPATCH') from None
            self._save_identical('failed-resolution.complete.json', {
                'scope': 'fox-verification-failed-resolution-complete-v1',
                'intent_sha256': C.digest(C.canonical_bytes(intent)), 'acknowledgement': acknowledgement})
            self._seal(acknowledgement)
            return {'status': 'FAILED_QA_CLOSED', 'job_id': claim.binding.job_id,
                    'disposition_sha256': expected_disposition_sha256, 'technical_verification_passed': False,
                    'human_acceptance_recorded': False, 'automatic_replay_permitted': False}

    def _validated_closed_under_lock(self, lease):
        """Trusted wrapper hook: validate an existing closure without reacquiring."""
        require(type(lease) is HeldOperatorLock, 'ACTIVE_MATCHING_OPERATOR_LEASE_REQUIRED')
        lease.require_active(self.release, self.root)
        claim, evidence = self._local()
        require((self.session / 'closed-failed.json').is_file(), 'CLOSED_FAILED_DISPOSITION_REQUIRED')
        acknowledgement = self._json(self.session / 'failed-resolution.complete.json')['acknowledgement']
        document = acknowledgement['disposition']
        require(self._validate(evidence, document['producer'], historical=True) == document,
                'DISPOSITION_EVIDENCE_CHANGED')
        return C.load_json(C.canonical_bytes(acknowledgement))

    @_bounded
    def read_closed_resolution(self, consumer):
        """Run a trusted read-only consumer while the one existing lock is held.

        The consumer receives a safe summary, exact validated retained server
        acknowledgement and the fd-bound lease. It may compare server lookup
        and eligibility; it is not a public payload or a lock-held assertion.
        """
        require(callable(consumer), 'CLOSED_RESOLUTION_READER_REQUIRED')
        with self._lock() as lease:
            acknowledgement = self._validated_closed_under_lock(lease)
            document = acknowledgement['disposition']
            summary = {'status': 'FAILED_QA_CLOSED', 'job_id': document['binding']['job_id'],
                       'disposition_sha256': acknowledgement['disposition_sha256'],
                       'technical_verification_passed': False, 'human_acceptance_recorded': False,
                       'automatic_replay_permitted': False}
            return consumer(summary, acknowledgement, lease)

    @_bounded
    def prepare_attempt(self, *, new_manifest, expected_new_release_sha256, request_id, attempt_id):
        """Generate a request only. No enqueue, target allocation or authorization.

        Later integration must reserve atomically on the backend, then create a
        fresh clean plan/namespace and reject reuse of the old allocation. This
        increment does not dispatch that request or choose an application ID.
        """
        checked = bridge.validate_release(new_manifest)
        require(checked['enabled'] and _sha(expected_new_release_sha256)
                and bridge.release_sha256(checked) == expected_new_release_sha256
                and expected_new_release_sha256 != self.release
                and checked['qa_source_sha256'] != self.manifest['qa_source_sha256'], 'NEW_REVIEWED_QA_RELEASE_REQUIRED')
        with self._lock():
            claim, evidence = self._local()
            require((self.session / 'closed-failed.json').is_file(), 'CLOSED_FAILED_DISPOSITION_REQUIRED')
            completed = self._json(self.session / 'failed-resolution.complete.json')
            document = completed['acknowledgement']['disposition']
            require(self._validate(evidence, document['producer'], historical=True) == document,
                    'DISPOSITION_EVIDENCE_CHANGED')
            request = _recovery().make_retry_request(document, request_id=request_id, attempt_id=attempt_id,
                                                     verifier_release_sha256=expected_new_release_sha256)
            return {'status': 'NEW_ATTEMPT_REQUEST_ONLY', 'request': request,
                    'request_sha256': C.digest(_recovery().canonical_bytes(request)),
                    'authorization_applied': False, 'target_allocated': False,
                    'fresh_namespace_required': True, 'prior_allocation_reuse_permitted': False,
                    'human_acceptance_recorded': False, 'automatic_retry_permitted': False}


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise FailureResolutionError('RESOLUTION_ARGUMENTS_INVALID') from None


def main(argv=None):
    parser = SafeParser(description=__doc__)
    parser.add_argument('command', choices=('check', 'apply', 'authorize-attempt'))
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--release-sha256', required=True)
    parser.add_argument('--session', required=True)
    parser.add_argument('--collection-sha256', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    # Deliberately no live transport/enable flag. Root must review an integration
    # before either recovery mutation or new attempt authorization can exist.
    require(args.command == 'check' and not args.apply, 'LIVE_RECOVERY_NOT_INTEGRATED')
    raw = Path(args.manifest).read_bytes()
    require(C.digest(raw) == args.release_sha256, 'EXACT_HISTORICAL_RELEASE_REQUIRED')
    resolver = FailureResolver(manifest=C.load_json(raw), expected_release_sha256=args.release_sha256,
        session=args.session, expected_collection_sha256=args.collection_sha256)
    print(json.dumps(resolver.check(), sort_keys=True))
    return 2


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        print('{"status":"BLOCKED","code":"FAILED_RESOLUTION_GUARD_FAILED","automatic_replay_permitted":false}')
        raise SystemExit(2)
