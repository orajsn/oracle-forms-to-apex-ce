"""Protected workstation verifier: explicit, bounded startup; no live-H dispatch.

This is not a service installer or a public FOX capability. Existing operator
credentials remain behind their current private transports. The deployment must
first supply a reviewed queue-aware release; the known H release is ineligible.
Unknown outcomes stop with private create-only journals, never a fresh plan or
automatic replay. The separate reconcile action checks existing proof only.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
for directory in (ROOT, ROOT / 'fox'):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))
from fox.verification_queue import Claim, VerificationBinding
from qa.operator import clean_install as clean
from qa.operator import contracts as C
from qa.operator import native_qa_dispatch as qa
from qa.operator import promote_native as promotion
from qa.operator import product_queue_transport as bridge
from qa.operator import runtime_provider

HERE = Path(__file__).resolve().parent
JOURNAL_ROOT = clean.PRIVATE / 'product-verifier'
STEPS = ('prepare', 'clean_check', 'allocate', 'schema', 'import', 'verify',
         'qa_stage', 'qa_run', 'qa_collect', 'promotion_check', 'promotion_apply', 'queue_complete')
_HASH = re.compile(r'[a-f0-9]{64}\Z')
_SESSION = re.compile(r'session-[a-f0-9]{24}\Z')


class ProductVerifierError(RuntimeError):
    """Bounded categories; never raw exception, SQL, credential or provider text."""


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise ProductVerifierError('OPERATOR_ARGUMENTS_INVALID') from None


def require(value, code):
    if not value:
        raise ProductVerifierError(code)


def _hash(value):
    return type(value) is str and _HASH.fullmatch(value) is not None


def admission_state(receipt):
    """Check a concrete reader's state; this alone grants no admission."""
    require(type(receipt) is dict and type(receipt.get('admission_state')) is str
            and receipt['admission_state'] in ('READY', 'WAIT'), 'HOSTED_ADMISSION_STATE_INVALID')
    return receipt['admission_state']


def source_bytes(path):
    path = Path(path).absolute()
    require(path.is_file() and not path.is_symlink() and path.resolve() == path
            and 0 < path.stat().st_size <= 2_000_000, 'LOCAL_SOURCE_UNAVAILABLE_OR_UNSAFE')
    raw = path.read_bytes()
    require(0 < len(raw) <= 2_000_000, 'LOCAL_SOURCE_BOUND_REQUIRED')
    return raw


def _operator_config(value):
    require(type(value) is dict, 'OPERATOR_CONFIG_INVALID')
    version = value.get('schema_version')
    fields = {'schema_version', 'scope', 'enabled', 'images'}
    require(type(version) is int and version in (1, 2, 3)
            and set(value) == fields | ({'hosted_runtime_configuration_sha256', 'opaf_profile'} if version == 3 else set())
            and value['scope'] == 'fox-product-verifier-operator-config-v' + str(value['schema_version'])
            and type(value['enabled']) is bool, 'OPERATOR_CONFIG_INVALID')
    try:
        pins = runtime_provider.validated_image_pins(value['images'])
    except runtime_provider.ProviderError:
        raise ProductVerifierError('OPERATOR_CONFIG_IMAGE_PINS_DIFFER') from None
    result = {**value, 'images': pins}
    if version == 3:
        require(_hash(value['hosted_runtime_configuration_sha256']), 'OPERATOR_CONFIG_INVALID')
        result['opaf_profile'] = bridge._profile_reference(value['opaf_profile'])
    else:
        require(pins == {'fox': clean.FOX_IMAGE, 'converter': clean.IMAGE}, 'OPERATOR_CONFIG_IMAGE_PINS_DIFFER')
    return result


def read_config(path=None):
    if path is None:
        return {'schema_version': 1, 'scope': 'fox-product-verifier-operator-config-v1', 'enabled': False,
                'images': {'fox': clean.FOX_IMAGE, 'converter': clean.IMAGE}}
    return _operator_config(C.load_json(source_bytes(path)))


def build_manifest(config=None, *, hosted_configuration=None):
    """Offline source declaration, not runtime admission or deployment authority.

    Explicit configuration bytes support an offline build without selecting a
    runtime. Execution independently requires the same owner-checked selection.
    """
    config = _operator_config(read_config() if config is None else config)
    version = config['schema_version']
    profile_path = 'deployment/native-beta-profile.json'
    if version == 3:
        if hosted_configuration is None:
            provider = runtime_provider.selected_hosted()
            require(provider is not None, 'HOSTED_CONFIGURATION_DECLARATION_REQUIRED')
            hosted_configuration = provider.raw
        declared = runtime_provider.configuration_document(hosted_configuration,
            expected_sha256=config['hosted_runtime_configuration_sha256'])
        require(declared['schema_version'] == 2 and declared['images'] == config['images'],
                'HOSTED_CONFIGURATION_IMAGE_PINS_DIFFER')
        require(declared['provider_sha256'] == C.digest(source_bytes(HERE / 'runtime_provider.py'))
                and declared['converter_sources'] == {name: C.digest(source_bytes(ROOT / 'converter' / name))
                    for name in runtime_provider._SOURCE_FILES}, 'HOSTED_CONFIGURATION_SOURCE_DIFFERS')
        profile_reference = bridge.reviewed_profile(config['opaf_profile'], declared)
        profile_path = config['opaf_profile']['path']
    else:
        require(hosted_configuration is None, 'LEGACY_CONFIGURATION_HAS_NO_HOSTED_BINDING')
    modules = {name: C.digest(source_bytes(ROOT / 'fox/fox' / name)) for name in
               ('verification_queue.py', 'verification_runtime.py', 'native_verification.py', 'native_verification_policy.py')}
    result = {'schema_version': 1, 'scope': 'fox-product-verifier-release-v1', 'enabled': config['enabled'],
              'images': dict(config['images']), 'modules': modules,
              'code': {name: C.digest(source_bytes(HERE / name)) for name in (bridge.HOSTED_CODE if version == 3 else bridge.CODE)},
              'clean_operator_code_sha256': clean.code_bundle()[1], 'qa_source_sha256': qa.bundle(images=config['images'])[3],
              'promotion_transport_sha256': C.digest(source_bytes(HERE / 'promote_native.py')),
              'native_profile_sha256': C.digest(source_bytes(ROOT / profile_path)),
              'target': dict(C.FIXED_TARGET)}
    if version in (2, 3):
        result.update(schema_version=version, scope=bridge.PROJECT_SCOPE if version == 2 else bridge.HOSTED_SCOPE,
                      project=bridge.project_manifest(images=config['images']))
    if version == 3:
        result.update(hosted_runtime_configuration_sha256=config['hosted_runtime_configuration_sha256'],
                      opaf_profile=profile_reference)
    return bridge.validate_release(result)


def _claim(value, release):
    require(type(value) is dict and set(value) == {'binding', 'attempt_token'}, 'PRIVATE_CLAIM_SHAPE_INVALID')
    result = Claim(VerificationBinding.from_payload(value['binding']), value['attempt_token'])
    require(result.binding.verifier_release_sha256 == release, 'PRIVATE_CLAIM_RELEASE_DIFFERS')
    return result


def _claim_payload(claim):
    return {'binding': claim.binding.payload(), 'attempt_token': claim.attempt_token}


class PrivateJournal:
    """Owner-private local evidence. OS lock prevents overlapping pump sessions."""
    def __init__(self, release_sha256):
        require(_hash(release_sha256), 'JOURNAL_RELEASE_INVALID')
        self.release = release_sha256
        self.journal_root = runtime_provider.private_root('journal', JOURNAL_ROOT)
        self.root = self.journal_root / release_sha256[:16]
        longest = self.root / ('session-' + '0' * 24) / 'p0120-promotion-apply.complete.json'
        require(len(str(longest)) <= 240, 'JOURNAL_PATH_EXCEEDS_PORTABLE_BOUND')

    @staticmethod
    def _directory(path):
        if path.exists():
            promotion.private_inputs([path])
            require(path.is_dir(), 'JOURNAL_DIRECTORY_REQUIRED')
        else:
            clean.private_directory(path)

    @contextmanager
    def lock(self, *, create=True):
        require(type(create) is bool, 'JOURNAL_LOCK_MODE_INVALID')
        provider = runtime_provider.selected_hosted()
        if provider is not None:
            # This gate must precede even the lock/release metadata writes.
            provider.check_public_mounts()
        private = clean.private_root()
        require(private.is_dir() and private.resolve() == private, 'PRIVATE_OPERATOR_ROOT_REQUIRED')
        if create:
            self._directory(self.journal_root)
            self._directory(self.root)
        else:
            require(self.journal_root.is_dir() and self.root.is_dir(), 'EXISTING_JOURNAL_REQUIRED')
            promotion.private_inputs([self.journal_root, self.root])
        binding_path = self.root / 'release.json'
        binding = {'scope': 'fox-product-verifier-journal-v1', 'release_sha256': self.release}
        if binding_path.exists():
            require(self.read(self.root, binding_path.name) == binding, 'JOURNAL_RELEASE_PREFIX_COLLISION')
        else:
            require(create, 'EXISTING_JOURNAL_BINDING_REQUIRED')
            try:
                self.write(self.root, binding_path.name, binding)
            except Exception:
                require(binding_path.exists() and self.read(self.root, binding_path.name) == binding,
                        'JOURNAL_RELEASE_PREFIX_COLLISION')
        lock = self.root / 'worker.lock'
        if not lock.exists():
            require(create, 'EXISTING_JOURNAL_LOCK_REQUIRED')
            try:
                clean.save_new(lock, b'0')
            except Exception:
                require(lock.exists(), 'JOURNAL_LOCK_UNAVAILABLE')
        promotion.private_inputs([self.root, lock])
        require(lock.is_file() and not lock.is_symlink() and lock.stat().st_nlink == 1, 'JOURNAL_LOCK_UNSAFE')
        stream = lock.open('r+b')
        locked, lease = False, None
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
            # Lazy import avoids the legacy failed-verification reader cycle.
            # Issued only after this fd acquired the actual OS lock; invalidated
            # before unlock. The hosted release measures both source files.
            from qa.operator.failed_verification import HeldOperatorLock, _LEASE_KEY
            lease = HeldOperatorLock(_LEASE_KEY, self.release, self.root, stream)
            lease.require_active(self.release, self.root)
            yield lease
        except OSError:
            raise ProductVerifierError('ANOTHER_PRODUCT_VERIFIER_ACTIVE_OR_LOCK_UNAVAILABLE') from None
        finally:
            if lease is not None:
                lease._active = False
            if locked:
                if os.name == 'nt':
                    import msvcrt
                    stream.seek(0); msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
            stream.close()

    def raw(self, directory, name):
        path = directory / name
        promotion.private_inputs([directory, path])
        require(path.is_file() and path.stat().st_nlink == 1 and path.stat().st_size <= C.MAX_JSON_BYTES,
                'JOURNAL_FILE_UNSAFE')
        return path.read_bytes()

    def read(self, directory, name):
        return C.load_json(self.raw(directory, name))

    def write(self, directory, name, value, *, allow_identical=False):
        require(re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,95}', name) is not None, 'JOURNAL_NAME_INVALID')
        raw = C.canonical_bytes(value)
        if allow_identical and (directory / name).exists():
            require(self.raw(directory, name) == raw, 'JOURNAL_EXISTING_BYTES_DIFFER')
            return C.digest(raw)
        clean.save_new(directory / name, raw)
        return C.digest(raw)

    def pending(self):
        result = []
        for path in self.root.iterdir():
            if path.name in ('worker.lock', 'release.json'):
                continue
            require(_SESSION.fullmatch(path.name) and path.is_dir() and not path.is_symlink(), 'JOURNAL_MEMBER_UNEXPECTED')
            header = self.read(path, 'session.json')
            require(header.get('release_sha256') == self.release, 'JOURNAL_RELEASE_CHANGED')
            terminal = path / 'complete.json'
            reconciled = path / 'reconciled.json'
            require(not (terminal.exists() and reconciled.exists()), 'JOURNAL_TERMINALS_CONFLICT')
            if terminal.exists():
                value = self.read(path, terminal.name)
                require(value.get('release_sha256') == self.release and value.get('status') == 'SESSION_COMPLETE',
                        'JOURNAL_COMPLETION_INVALID')
                self._check_seal(path, value)
            elif reconciled.exists():
                value = self.read(path, reconciled.name)
                require(value.get('release_sha256') == self.release and value.get('status') == 'PROOF_RECONCILED'
                        and _hash(value.get('proof_sha256')), 'JOURNAL_RECONCILIATION_INVALID')
                self._check_seal(path, value)
            else:
                result.append(path)
        return result

    def _retained(self, directory):
        result = {}
        for path in directory.iterdir():
            if path.name in ('complete.json', 'reconciled.json'):
                continue
            require(path.name in ('session.json', 'attention.json')
                    or re.fullmatch(r'(?:p[0-9]{4}-[a-z-]+|proof-reconcile)\.(?:intent|complete)\.json', path.name),
                    'JOURNAL_MEMBER_UNEXPECTED')
            result[path.name] = C.digest(self.raw(directory, path.name))
        return result

    def _check_seal(self, directory, value):
        require(type(value.get('retained_sha256')) is dict
                and value['retained_sha256'] == self._retained(directory)
                and 'session.json' in value['retained_sha256'], 'JOURNAL_RETAINED_BYTES_CHANGED')

    def seal(self, directory, name, value, *, allow_identical=False):
        self.write(directory, name, {**value, 'retained_sha256': self._retained(directory)},
                   allow_identical=allow_identical)

    def new(self, bounds):
        require(not self.pending(), 'UNRESOLVED_SESSION_NO_NEW_DISPATCH')
        directory = self.root / ('session-' + secrets.token_hex(12))
        self._directory(directory)
        self.write(directory, 'session.json', {'scope': 'fox-product-verifier-session-v1',
            'release_sha256': self.release, 'started_at_utc': datetime.now(timezone.utc).isoformat(),
            'bounds': bounds, 'startup_authorized': True})
        return directory

    def intent(self, directory, label, binding=None, *, allow_identical=False):
        return self.write(directory, label + '.intent.json', {'scope': 'fox-product-verifier-step-v1',
            'release_sha256': self.release, 'step': label,
            'binding_sha256': C.digest(C.canonical_bytes(binding.payload())) if binding else None},
            allow_identical=allow_identical)

    def completed(self, directory, label, intent_sha, result, *, allow_identical=False):
        self.write(directory, label + '.complete.json', {'scope': 'fox-product-verifier-step-result-v1',
            'release_sha256': self.release, 'intent_sha256': intent_sha, 'result': result},
            allow_identical=allow_identical)

    def completed_result(self, directory, label):
        intent = directory / (label + '.intent.json')
        value = self.read(directory, label + '.complete.json')
        require(value.get('release_sha256') == self.release
                and value.get('intent_sha256') == C.digest(self.raw(directory, intent.name)), 'JOURNAL_STEP_BINDING_CHANGED')
        return value['result']


class GuardedPhases:
    """No new SQL/QA/promotion implementation; call existing guarded functions."""
    def __init__(self, manifest):
        self.manifest = manifest

    @staticmethod
    def plan(context):
        return clean.private_root() / context['plan_sha256'] / 'plan.json'

    def perform(self, step, binding, context):
        if self.manifest['schema_version'] in (2, 3):
            from qa.operator.project_operator import perform
            return perform(step, binding, context, self.manifest, self._native_perform)
        return self._native_perform(step, binding, context)

    def _native_perform(self, step, binding, context):
        if step == 'prepare':
            result = clean.prepare(binding.job_id, binding.package_sha256)
            raw, plan = clean.read_plan(Path(result['plan_path']))
            require(result['plan_sha256'] == C.digest(raw)
                    and all(plan['binding'][key] == value for key, value in {
                        'job_id': binding.job_id, 'source_manifest_sha256': binding.source_manifest_sha256,
                        'package_sha256': binding.package_sha256}.items())
                    and plan['operator_code_sha256'] == self.manifest['clean_operator_code_sha256'], 'PREPARED_PLAN_BINDING_DIFFERS')
            return {'plan_sha256': result['plan_sha256'], 'job_id': binding.job_id,
                    'source_manifest_sha256': binding.source_manifest_sha256, 'package_sha256': binding.package_sha256,
                    'operator_code_sha256': plan['operator_code_sha256']}
        path = self.plan(context)
        if step == 'clean_check':
            value = clean.dispatch('check', path, expected_sha=context['plan_sha256'])
            require(value.get('state') == 'PREPARED' and all(value.get('phases', {}).get(name) == 'unattempted'
                    for name in ('allocate', 'schema', 'import', 'verify')), 'FRESH_PLAN_NOT_UNATTEMPTED')
            return {'state': 'PREPARED', 'plan_sha256': value['plan_sha256']}
        if step in ('allocate', 'schema', 'import', 'verify'):
            value = clean.dispatch('apply', path, expected_sha=context['plan_sha256'], phase=step, apply=True)
            require(value.get('state') == ('QA_READY' if step == 'verify' else 'PHASE_COMPLETE')
                    and value.get('action') in ('COMPLETED_ONCE', 'ALREADY_COMPLETE_NO_REPLAY'), 'CLEAN_PHASE_NOT_CONFIRMED')
            return {key: value[key] for key in ('state', 'action', 'plan_sha256', 'evidence_sha256')}
        if step in ('qa_stage', 'qa_run', 'qa_collect'):
            command = step[3:]
            value = qa.dispatch(command, path, context['plan_sha256'], self.manifest['qa_source_sha256'], apply=command != 'collect')
            if step == 'qa_stage':
                return {key: value[key] for key in ('status', 'plan_sha256', 'source_sha256', 'allocation_receipt_sha256', 'image_id')}
            if step == 'qa_run':
                return {key: value[key] for key in ('status', 'exit_code', 'plan_sha256', 'source_sha256', 'image_id')}
            directory = path.parent / ('qa-' + self.manifest['qa_source_sha256'][:16])
            require(value.get('local_directory') == str(directory), 'COLLECTION_LOCATION_DIFFERS')
            raw = (directory / 'collection-manifest.json').read_bytes()
            saved = C.load_json(raw)
            require(saved.get('status') == 'COLLECTED' and saved.get('credentials_and_logs_excluded') is True,
                    'COLLECTION_NOT_CONFIRMED')
            return {'status': 'COLLECTED', 'plan_sha256': saved['plan_sha256'], 'source_sha256': saved['source_sha256'],
                    'collection_manifest_sha256': C.digest(raw)}
        require(step in ('promotion_check', 'promotion_apply'), 'UNKNOWN_PROTECTED_PHASE')
        directory = path.parent / ('qa-' + self.manifest['qa_source_sha256'][:16])
        value = promotion.dispatch('check' if step == 'promotion_check' else 'apply', directory,
            collection_sha256=context['collection_manifest_sha256'], expected_image=self.manifest['images']['fox'],
            module_sha256=self.manifest['modules']['native_verification.py'], apply=step == 'promotion_apply')
        require(value.get('human_acceptance_recorded') is False and value.get('job_id') == binding.job_id,
                'TECHNICAL_PROMOTION_BINDING_DIFFERS')
        result = {'status': value['status'], 'job_id': binding.job_id, 'human_acceptance_recorded': False}
        if step == 'promotion_apply':
            require(value.get('event_count') == value.get('proof_count') == 1, 'TECHNICAL_PROMOTION_COUNT_DIFFERS')
            result['proof_sha256'] = value['proof_sha256']
        return result


def safe_phase(step, value, binding, context, manifest):
    """Closed projection: phase result strings cannot become provider logs."""
    require(type(value) is dict, 'PHASE_RESULT_INVALID')
    original = value
    if manifest['schema_version'] in (2, 3):
        profile = value.get('conversion_profile') if step == 'prepare' else context.get('conversion_profile')
        require(profile in ('native-table-form-v1', 'native-project-v1'), 'PROTECTED_CONVERSION_PROFILE_REQUIRED')
        if step == 'prepare':
            value = {key: item for key, item in value.items() if key != 'conversion_profile'}
        if profile == 'native-project-v1':
            manifest = {**manifest, **{key: manifest['project'][key]
                        for key in ('clean_operator_code_sha256', 'qa_source_sha256')}}
    if step == 'prepare':
        keys = {'plan_sha256', 'job_id', 'source_manifest_sha256', 'package_sha256', 'operator_code_sha256'}
        require(set(value) == keys and _hash(value['plan_sha256']) and value['job_id'] == binding.job_id
                and value['source_manifest_sha256'] == binding.source_manifest_sha256
                and value['package_sha256'] == binding.package_sha256
                and value['operator_code_sha256'] == manifest['clean_operator_code_sha256'], 'PREPARED_PLAN_BINDING_DIFFERS')
    elif step == 'clean_check':
        require(set(value) == {'state', 'plan_sha256'} and value['state'] == 'PREPARED', 'CLEAN_CHECK_RESULT_INVALID')
    elif step in ('allocate', 'schema', 'import', 'verify'):
        require(set(value) == {'state', 'action', 'plan_sha256', 'evidence_sha256'}
                and value['state'] == ('QA_READY' if step == 'verify' else 'PHASE_COMPLETE')
                and value['action'] in ('COMPLETED_ONCE', 'ALREADY_COMPLETE_NO_REPLAY') and _hash(value['evidence_sha256']),
                'CLEAN_PHASE_RESULT_INVALID')
    elif step == 'qa_stage':
        require(set(value) == {'status', 'plan_sha256', 'source_sha256', 'allocation_receipt_sha256', 'image_id'}
                and value['status'] == 'STAGED' and _hash(value['allocation_receipt_sha256']), 'QA_STAGE_RESULT_INVALID')
    elif step == 'qa_run':
        require(set(value) == {'status', 'exit_code', 'plan_sha256', 'source_sha256', 'image_id'}
                and type(value['exit_code']) is int and value['exit_code'] in (0, 2, 124, 137)
                and value['status'] == ('PASSED' if value['exit_code'] == 0 else 'QA_FAILED_OR_INCOMPLETE')
                and value['image_id'] == context['image_id'], 'QA_RUN_RESULT_INVALID')
    elif step == 'qa_collect':
        require(set(value) == {'status', 'plan_sha256', 'source_sha256', 'collection_manifest_sha256'}
                and value['status'] == 'COLLECTED' and _hash(value['collection_manifest_sha256']), 'QA_COLLECTION_RESULT_INVALID')
    else:
        keys = {'status', 'job_id', 'human_acceptance_recorded'} | ({'proof_sha256'} if step == 'promotion_apply' else set())
        require(step in ('promotion_check', 'promotion_apply') and set(value) == keys
                and value['status'] == ('READY_NOT_APPLIED' if step == 'promotion_check' else 'VERIFIED')
                and value['job_id'] == binding.job_id and value['human_acceptance_recorded'] is False
                and (step != 'promotion_apply' or _hash(value['proof_sha256'])), 'PROMOTION_RESULT_INVALID')
    if 'plan_sha256' in value and step != 'prepare':
        require(value['plan_sha256'] == context['plan_sha256'], 'PHASE_PLAN_DIFFERS')
    if 'source_sha256' in value:
        require(value['source_sha256'] == manifest['qa_source_sha256'], 'QA_RELEASE_DIFFERS')
    if 'image_id' in value:
        require(type(value['image_id']) is str and re.fullmatch(r'(?:sha256:)?[a-f0-9]{64}', value['image_id']), 'QA_IMAGE_INVALID')
    return dict(original)


class ProductVerifier:
    def __init__(self, manifest, expected_release_sha256, *, transport=None, phases=None, journal=None,
                 clock=time.monotonic, sleeper=time.sleep, hosted_admission=None,
                 stop_requested=None):
        self.manifest = bridge.validate_release(manifest)
        self.release = expected_release_sha256
        self.transport = transport or bridge.dispatch
        self.phases = phases or GuardedPhases(self.manifest)
        self.journal = journal or PrivateJournal(expected_release_sha256)
        self.clock, self.sleeper = clock, sleeper
        self.hosted_admission = hosted_admission
        self.stop_requested = stop_requested or (lambda: False)

    def _admission(self, lease=None):
        version = self.manifest['schema_version']
        if type(version) is int and version in (1, 2):
            require(self.hosted_admission is None, 'HOSTED_ADMISSION_REQUIRES_V3')
            return 'READY'
        # Future schemas must gain their own concrete authority branch. Merely
        # accepting a new manifest version cannot inherit legacy readiness.
        require(type(version) is int and version == 3, 'HOSTED_RELEASE_VERSION_UNSUPPORTED')
        from qa.operator.hosted_service import HostedAdmission
        require(type(self.hosted_admission) is HostedAdmission
                and self.hosted_admission.release == self.release,
                'INSTALLED_HOSTED_ADMISSION_REQUIRED')
        if lease is None:
            self.hosted_admission.preflight()
            return 'READY'
        return admission_state(self.hosted_admission.require_under_lock(lease, self.journal.root))

    def _ready(self):
        bridge.require_ready(self.manifest, self.release)

    def _call(self, operation, **kwargs):
        self._ready()
        return self.transport(operation, self.manifest, expected_release_sha256=self.release,
                              apply=operation != 'status', **kwargs)

    def heartbeat(self):
        value = self._call('heartbeat')
        require(value.get('status') == 'CONTACT_RECORDED' and value.get('verifier_release_sha256') == self.release,
                'OPERATOR_CONTACT_UNCONFIRMED')

    def _job(self, directory, prefix, claim):
        context = {}
        known_qa_failure = False
        for step in STEPS:
            require(not self.stop_requested(), 'STOP_REQUESTED_WITH_ACTIVE_CLAIM')
            self.heartbeat()
            require(not self.stop_requested(), 'STOP_REQUESTED_WITH_ACTIVE_CLAIM')
            label = prefix + '-' + step.replace('_', '-')
            intent_sha = self.journal.intent(directory, label, claim.binding)
            if step == 'queue_complete':
                value = self._call('complete', claim=claim, proof_sha256=context['proof_sha256'])
                row = value.get('queue', {})
                require(value.get('status') == 'COMPLETED' and row.get('state') == 'completed'
                        and row.get('proof_sha256') == context['proof_sha256']
                        and all(row.get(key) == value for key, value in claim.binding.payload().items()), 'QUEUE_COMPLETION_UNCONFIRMED')
                result = {'status': 'COMPLETED', 'job_id': claim.binding.job_id, 'proof_sha256': context['proof_sha256']}
            else:
                value = self.phases.perform(step, claim.binding, context)
                result = safe_phase(step, value, claim.binding, context, self.manifest)
                context.update(result)
            self.journal.completed(directory, label, intent_sha, result)
            if step == 'qa_run':
                known_qa_failure = result['status'] != 'PASSED'
            if step == 'qa_collect' and known_qa_failure:
                raise ProductVerifierError('QA_FAILED_PROOF_UNCONFIRMED')
        return {'job_id': claim.binding.job_id, 'state': 'completed', 'proof_sha256': context['proof_sha256']}

    def pump(self, *, apply=False, max_jobs=1, max_polls=1, max_seconds=1800, poll_seconds=5):
        require(apply is True, 'EXPLICIT_STARTUP_AUTHORITY_REQUIRED')
        require(all(type(value) is int for value in (max_jobs, max_polls, max_seconds, poll_seconds))
                and 1 <= max_jobs <= 5 and 1 <= max_polls <= 120 and max_jobs <= max_polls
                and 1 <= max_seconds <= 7200 and 1 <= poll_seconds <= 60, 'BOUNDED_PUMP_LIMITS_REQUIRED')
        self._ready()  # Must precede private files, OCI, SSH, or secret access.
        self._admission()  # Hosted mount/source gates precede even lock metadata.
        bounds = {'max_jobs': max_jobs, 'max_polls': max_polls, 'max_seconds': max_seconds, 'poll_seconds': poll_seconds}
        completed = []
        with self.journal.lock() as lease:
            require(not self.journal.pending(), 'UNRESOLVED_SESSION_NO_NEW_DISPATCH')
            if self.stop_requested():
                return {'status': 'STOPPED_NO_SESSION', 'release_sha256': self.release,
                        'automatic_replay_permitted': False}
            if self._admission(lease) == 'WAIT':
                return {'status': 'WAIT', 'release_sha256': self.release,
                        'automatic_replay_permitted': False}
            directory = self.journal.new(bounds)
            started = self.clock()
            claim = None
            try:
                for index in range(1, max_polls + 1):
                    if self.stop_requested() or self.clock() - started >= max_seconds or len(completed) >= max_jobs:
                        break
                    if self._admission(lease) == 'WAIT':
                        break  # No open claim; a bounded session can close safely.
                    if self.stop_requested():
                        break
                    self.heartbeat()
                    if self.stop_requested():
                        break
                    prefix = 'p' + str(index).zfill(4)
                    intent_sha = self.journal.intent(directory, prefix + '-claim')
                    value = self._call('claim')
                    require(value.get('verifier_release_sha256') == self.release and value.get('status') in ('IDLE', 'CLAIMED'),
                            'CLAIM_RESPONSE_UNCONFIRMED')
                    claim = _claim(value['claim'], self.release) if value['status'] == 'CLAIMED' else None
                    private = {'status': value['status'], **({'claim': _claim_payload(claim)} if claim else {})}
                    self.journal.completed(directory, prefix + '-claim', intent_sha, private)
                    if claim is not None:
                        completed.append(self._job(directory, prefix, claim))
                        claim = None
                    if index < max_polls and len(completed) < max_jobs:
                        remaining = max_seconds - (self.clock() - started)
                        if remaining <= 0:
                            break
                        self.sleeper(min(poll_seconds, remaining))
                self.journal.seal(directory, 'complete.json', {'status': 'SESSION_COMPLETE', 'release_sha256': self.release,
                    'completed_jobs': completed, 'automatic_replay_permitted': False})
                return {'status': 'SESSION_COMPLETE', 'release_sha256': self.release, 'completed_jobs': completed,
                        'private_session': str(directory), 'automatic_replay_permitted': False}
            except Exception:
                if claim is not None:
                    try:
                        self._call('attention', claim=claim, code='BACKEND_OUTCOME_UNCONFIRMED')
                    except Exception:
                        pass
                try:
                    self.journal.write(directory, 'attention.json', {'status': 'ATTENTION', 'release_sha256': self.release,
                        'known_claim': claim is not None, 'code': 'OUTCOME_UNCONFIRMED_PRESERVE_AND_RECONCILE',
                        'automatic_replay_permitted': False})
                except Exception:
                    pass
                return {'status': 'ATTENTION', 'release_sha256': self.release, 'private_session': str(directory),
                        'code': 'OUTCOME_UNCONFIRMED_PRESERVE_AND_RECONCILE', 'automatic_replay_permitted': False}

    def reconcile(self, session, *, apply=False):
        require(apply is True, 'EXPLICIT_RECONCILIATION_AUTHORITY_REQUIRED')
        self._ready()
        directory = Path(session).absolute()
        require(directory.parent == self.journal.root and _SESSION.fullmatch(directory.name)
                and directory.resolve() == directory, 'EXACT_PRIVATE_SESSION_REQUIRED')
        with self.journal.lock():
            pending = self.journal.pending()  # Also verifies existing terminal seals.
            require(directory in pending or (directory / 'reconciled.json').is_file(), 'SESSION_NOT_PENDING')
            intents = sorted(directory.glob('p????-claim.intent.json'))
            require(bool(intents), 'NO_KNOWN_CLAIM_REQUIRES_OPERATOR_REVIEW')
            latest = intents[-1].name.removesuffix('.intent.json')
            require((directory / (latest + '.complete.json')).is_file(), 'UNKNOWN_CLAIM_REQUIRES_OPERATOR_REVIEW')
            value = self.journal.completed_result(directory, latest)
            require(value.get('status') == 'CLAIMED', 'NO_KNOWN_CLAIM_REQUIRES_OPERATOR_REVIEW')
            claim = _claim(value['claim'], self.release)
            # Explicit proof-only rechecks may reuse this exact intent after a
            # lost response. Other phase intents remain strictly create-only.
            intent_sha = self.journal.intent(directory, 'proof-reconcile', claim.binding, allow_identical=True)
            self.heartbeat()
            # The bridge rechecks already-retained technical proof. It cannot
            # allocate/import/run QA/promote or invent missing phase outcomes.
            value = self._call('reconcile', claim=claim, binding=claim.binding)
            row = value.get('queue', {})
            require(value.get('status') == 'COMPLETED' and row.get('state') == 'completed'
                    and _hash(row.get('proof_sha256'))
                    and all(row.get(key) == value for key, value in claim.binding.payload().items()), 'EXISTING_PROOF_RECONCILIATION_UNCONFIRMED')
            result = {'status': 'PROOF_RECONCILED', 'release_sha256': self.release,
                      'job_id': claim.binding.job_id, 'proof_sha256': row['proof_sha256'], 'automatic_replay_permitted': False}
            self.journal.completed(directory, 'proof-reconcile', intent_sha, result, allow_identical=True)
            self.journal.seal(directory, 'reconciled.json', result, allow_identical=True)
            return result


def main(argv=None):
    parser = SafeParser(description=__doc__)
    parser.add_argument('command', choices=('manifest', 'run-once', 'pump', 'reconcile'))
    parser.add_argument('--release-config'); parser.add_argument('--release-sha256')
    parser.add_argument('--apply', action='store_true'); parser.add_argument('--session')
    parser.add_argument('--max-jobs', type=int, default=1); parser.add_argument('--max-polls', type=int, default=1)
    parser.add_argument('--max-seconds', type=int, default=1800); parser.add_argument('--poll-seconds', type=int, default=5)
    args = parser.parse_args(argv)
    manifest = build_manifest(read_config(args.release_config))
    digest = bridge.release_sha256(manifest)
    if args.command == 'manifest':
        require(not args.apply and args.release_sha256 is None and args.session is None, 'MANIFEST_IS_LOCAL_READ_ONLY')
        try:
            bridge.require_ready(manifest, digest)
            ready = True
        except Exception:
            ready = False
        result = {'status': 'LOCAL_MANIFEST', 'verifier_release_sha256': digest, 'dispatch_ready': ready,
                  'live_queue_deployment_verified': False, 'manifest': manifest}
    else:
        require(args.apply and _hash(args.release_sha256), 'EXACT_REVIEWED_RELEASE_AND_STARTUP_AUTHORITY_REQUIRED')
        verifier = ProductVerifier(manifest, args.release_sha256)
        if args.command == 'reconcile':
            require(args.session is not None, 'PRIVATE_SESSION_REQUIRED')
            result = verifier.reconcile(args.session, apply=True)
        else:
            require(args.session is None, 'PUMP_CANNOT_SELECT_EXISTING_ATTEMPT')
            result = verifier.pump(apply=True, max_jobs=1 if args.command == 'run-once' else args.max_jobs,
                max_polls=1 if args.command == 'run-once' else args.max_polls,
                max_seconds=args.max_seconds, poll_seconds=args.poll_seconds)
    print(json.dumps(result, sort_keys=True))
    return 2 if result.get('status') == 'ATTENTION' else 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        print(json.dumps({'status': 'STOPPED', 'code': 'PRODUCT_VERIFIER_GUARD_FAILED', 'automatic_replay_permitted': False}))
        raise SystemExit(2)
