"""Classify retained, single-claim read-only precheck failures without replay.

This is NOT a technical pass, retry authorization or live closure adapter.
Inputs are private captures from a separately guarded observer. File hashes
bind those bytes; neither JSON nor this classifier attests a live host. A
protected recovery writer must obtain a fresh observation under exclusion and
retain a complete export before any append-only failure disposition.
"""
from __future__ import annotations

import base64
from datetime import datetime
import hashlib
import json
from pathlib import PurePosixPath
import re

from . import contracts as C
from fox.verification_queue import Claim, VerificationBinding, VerificationQueue


SCOPE = 'fox-read-only-precheck-assessment-v1'
CAPTURE_SCOPE = 'fox-precheck-read-only-capture-v1'
_SHA = re.compile(r'[a-f0-9]{64}\Z')
_SESSION = re.compile(r'session-[a-f0-9]{24}\Z')
_QA_FILES = {'__init__.py', 'intake.py', 'native_source.py', 'project_conversion.py',
             'native_qa_plan.py', 'project_qa_plan.py'}


class PrecheckEvidenceError(ValueError):
    """Fixed categories only; never private claim tokens or provider output."""


def need(value, code):
    if not value:
        raise PrecheckEvidenceError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _json(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 2_000_000, 'PRECHECK_JSON_BOUND')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'PRECHECK_DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except PrecheckEvidenceError:
        raise
    except Exception:
        raise PrecheckEvidenceError('PRECHECK_JSON_INVALID') from None
    need(type(value) is dict, 'PRECHECK_JSON_OBJECT_REQUIRED')
    return value


def _bytes(raw, maximum):
    need(type(raw) is str and len(raw) <= (maximum * 4 // 3 + 8), 'PRECHECK_ENCODED_BOUND')
    try:
        value = base64.b64decode(raw, validate=True)
    except Exception:
        raise PrecheckEvidenceError('PRECHECK_ENCODING_INVALID') from None
    need(0 < len(value) <= maximum, 'PRECHECK_BYTES_BOUND')
    return value


def _intent(document, release, label, binding_hash):
    need(document == {'scope': 'fox-product-verifier-step-v1',
        'release_sha256': release, 'step': label, 'binding_sha256': binding_hash},
        'PRECHECK_INTENT_BINDING_CHANGED')


def _completion(document, release, intent_raw):
    need(set(document) == {'scope', 'release_sha256', 'intent_sha256', 'result'}
         and document['scope'] == 'fox-product-verifier-step-result-v1'
         and document['release_sha256'] == release
         and document['intent_sha256'] == sha(intent_raw)
         and type(document['result']) is dict, 'PRECHECK_COMPLETION_CHANGED')
    return document['result']


def assess_capture(capture, *, expected_release_sha256, expected_operator_code_sha256):
    """Inspect exact retained bytes; no filesystem/network/DB writes or authority."""
    need(type(capture) is dict and set(capture) == {
        'scope', 'writes_requested', 'service', 'session', 'journal', 'fox', 'converter'},
        'PRECHECK_CAPTURE_FIELDS')
    need(capture['scope'] == CAPTURE_SCOPE and capture['writes_requested'] is False,
         'PRECHECK_CAPTURE_SCOPE')
    need(all(type(value) is str and _SHA.fullmatch(value)
             for value in (expected_release_sha256, expected_operator_code_sha256)),
         'PRECHECK_REVIEWED_RELEASE_REQUIRED')
    need(type(capture['session']) is str and _SESSION.fullmatch(capture['session']), 'PRECHECK_SESSION_INVALID')
    service = capture['service']
    need(type(service) is dict and service.get('ActiveState') == 'failed'
         and service.get('SubState') == 'failed' and service.get('MainPID') == '0'
         and service.get('LoadState') == 'loaded', 'PRECHECK_PRODUCER_NOT_STOPPED')
    converter = capture['converter']
    need(type(converter) is dict and set(converter) == {'qa_files', 'active_sqlcl_pids'}
         and converter['active_sqlcl_pids'] == [] and type(converter['active_sqlcl_pids']) is list,
         'PRECHECK_SQL_EXECUTOR_UNCONFIRMED')
    available = converter['qa_files']
    need(type(available) is dict and set(available) == _QA_FILES
         and all(type(value) is bool for value in available.values())
         and available['project_qa_plan.py'] is False, 'PRECHECK_MISSING_DEPENDENCY_UNCONFIRMED')
    fox = capture['fox']
    need(type(fox) is dict and {'queue', 'run', 'job_files', 'profile', 'acceptance_count',
         'verification_tables'} == set(fox), 'PRECHECK_PRODUCT_SNAPSHOT_FIELDS')
    need(type(fox['acceptance_count']) is int and fox['acceptance_count'] == 0,
         'PRECHECK_ACCEPTANCE_EXISTS')
    try:
        queue = VerificationQueue._record(fox['queue'])
        need(queue is not None, 'PRECHECK_QUEUE_MISSING')
        binding = VerificationBinding.from_payload({key: queue[key] for key in
            ('job_id', 'source_manifest_sha256', 'package_sha256', 'verifier_release_sha256')})
    except PrecheckEvidenceError:
        raise
    except Exception:
        raise PrecheckEvidenceError('PRECHECK_QUEUE_INVALID') from None
    need(binding.verifier_release_sha256 == expected_release_sha256
         and queue['state'] == 'attention' and queue['proof_sha256'] is None,
         'PRECHECK_QUEUE_OR_RELEASE_CHANGED')
    run = fox['run']
    need(type(run) is dict and run.get('id') == binding.job_id and run.get('state') == 'QA_REQUIRED'
         and run.get('source_hash') == binding.source_manifest_sha256
         and type(run.get('artifact')) is str
         and run['artifact'].replace('\\', '/') == f'jobs/{binding.job_id}/apex-package.zip',
         'PRECHECK_RUN_BINDING_CHANGED')
    files = fox['job_files']
    need(type(files) is dict and {'apex-package.zip', 'source-snapshot.json', 'release-evidence.json'} <= set(files)
         and len(files) == 4 and all(type(name) is str and not PurePosixPath(name).is_absolute()
             and '..' not in PurePosixPath(name).parts and '\\' not in name for name in files),
         'PRECHECK_PACKAGE_FILES_CHANGED')
    package = _bytes(files['apex-package.zip'], 8_000_000)
    need(sha(package) == binding.package_sha256, 'PRECHECK_PACKAGE_BYTES_CHANGED')
    source_raw = _bytes(files['source-snapshot.json'], 2_000_000)
    release_raw = _bytes(files['release-evidence.json'], 2_000_000)
    source, release = _json(source_raw), _json(release_raw)
    need(source.get('source_hash') == binding.source_manifest_sha256
         and release.get('job_id') == binding.job_id
         and release.get('source_manifest_sha256') == binding.source_manifest_sha256
         and all(source.get('approvals', {}).get(key) is True
                 for key in ('redacted_source', 'external_ai', 'synthetic_prototype')),
         'PRECHECK_RETAINED_SOURCE_CHANGED')
    need(fox['profile'] in ('native-table-form-v1', 'native-project-v1'), 'PRECHECK_PROFILE_UNSUPPORTED')
    journal = capture['journal']
    need(type(journal) is dict and len(journal) == 7, 'PRECHECK_SINGLE_CLAIM_JOURNAL_REQUIRED')
    checks = [name for name in journal if type(name) is str and re.fullmatch(r'p[0-9]{4}-clean-check\.intent\.json', name)]
    need(len(checks) == 1, 'PRECHECK_ONLY_READ_ONLY_INTENT_REQUIRED')
    prefix = checks[0].split('-', 1)[0]
    expected = {'session.json', 'attention.json', *(prefix + '-' + part + suffix
        for part, suffix in [('claim', '.intent.json'), ('claim', '.complete.json'),
                             ('prepare', '.intent.json'), ('prepare', '.complete.json'),
                             ('clean-check', '.intent.json')])}
    need(set(journal) == expected, 'PRECHECK_WRITE_OR_UNKNOWN_PHASE_PRESENT')
    raw = {name: _bytes(value, 65_536) for name, value in journal.items()}
    documents = {name: _json(value) for name, value in raw.items()}
    header = documents['session.json']
    need(set(header) == {'scope', 'release_sha256', 'started_at_utc', 'bounds', 'startup_authorized'}
         and header['scope'] == 'fox-product-verifier-session-v1'
         and header['release_sha256'] == expected_release_sha256 and header['startup_authorized'] is True,
         'PRECHECK_SESSION_BINDING_CHANGED')
    try:
        started = datetime.fromisoformat(header['started_at_utc'].replace('Z', '+00:00'))
        need(started.utcoffset() is not None and started.utcoffset().total_seconds() == 0,
             'PRECHECK_SESSION_TIME_INVALID')
    except PrecheckEvidenceError:
        raise
    except Exception:
        raise PrecheckEvidenceError('PRECHECK_SESSION_TIME_INVALID') from None
    bounds = header['bounds']
    need(type(bounds) is dict and set(bounds) == {'max_jobs', 'max_polls', 'max_seconds', 'poll_seconds'}
         and all(type(value) is int for value in bounds.values()) and bounds['max_jobs'] == 1
         and 1 <= bounds['max_polls'] <= 120 and 1 <= bounds['max_seconds'] <= 7200
         and 1 <= bounds['poll_seconds'] <= 60, 'PRECHECK_SESSION_BOUNDS_INVALID')
    attention = documents['attention.json']
    need(attention == {'status': 'ATTENTION', 'release_sha256': expected_release_sha256,
        'known_claim': True, 'code': 'OUTCOME_UNCONFIRMED_PRESERVE_AND_RECONCILE',
        'automatic_replay_permitted': False}, 'PRECHECK_ATTENTION_CHANGED')
    binding_hash = C.digest(C.canonical_bytes(binding.payload()))
    for step in ('claim', 'prepare', 'clean-check'):
        label = prefix + '-' + step
        _intent(documents[label + '.intent.json'], expected_release_sha256, label,
                None if step == 'claim' else binding_hash)
    claimed = _completion(documents[prefix + '-claim.complete.json'], expected_release_sha256,
                          raw[prefix + '-claim.intent.json'])
    need(set(claimed) == {'status', 'claim'} and claimed['status'] == 'CLAIMED'
         and claimed['claim'] == {'binding': binding.payload(), 'attempt_token': queue['claim_token']},
         'PRECHECK_ORIGINAL_CLAIM_CHANGED')
    prepared = _completion(documents[prefix + '-prepare.complete.json'], expected_release_sha256,
                           raw[prefix + '-prepare.intent.json'])
    need(set(prepared) == {'conversion_profile', 'job_id', 'operator_code_sha256',
         'package_sha256', 'plan_sha256', 'source_manifest_sha256'}
         and prepared['conversion_profile'] == fox['profile']
         and prepared['operator_code_sha256'] == expected_operator_code_sha256
         and type(prepared['plan_sha256']) is str and _SHA.fullmatch(prepared['plan_sha256'])
         and all(prepared[key] == value for key, value in binding.payload().items()
                 if key != 'verifier_release_sha256'), 'PRECHECK_PREPARE_BINDING_CHANGED')
    return {'schema_version': 1, 'scope': SCOPE,
        'status': 'CLASSIFIED_PRECHECK_FAILURE_REQUIRES_PROTECTED_RECOVERY',
        'binding': binding.payload(), 'session': capture['session'],
        'legacy_record_sha256': queue['record_sha256'],
        'claim_sha256': sha(C.canonical_bytes({'binding': binding.payload(), 'attempt_token': queue['claim_token']})),
        'retained_sha256': {name: sha(value) for name, value in sorted(raw.items())},
        'package_sha256': sha(package), 'source_snapshot_sha256': sha(source_raw),
        'release_evidence_sha256': sha(release_raw), 'plan_sha256': prepared['plan_sha256'],
        'operator_code_sha256': expected_operator_code_sha256,
        'failed_phase': 'clean_check', 'missing_dependency': 'fox.project_qa_plan',
        'current_admission_blocks': True, 'closure_performed': False,
        'technical_success': False, 'human_acceptance_recorded': False,
        'automatic_replay_permitted': False,
        'scope_note': 'Retained evidence classification only. No host authority, closure, import, retry or readiness is granted.'}
