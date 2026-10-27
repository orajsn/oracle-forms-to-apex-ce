"""Server-side verification handoff; no privileged execution or public control API.

The deployment enables this explicitly. A protected operator claims the queue
through its separate transport. Contact recency is an observation, not proof that
an operator is still running. Queue status never authorizes package download.
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import time

from .intake import checked_source, inventory, MAX_CONVERSION_BYTES
from .verification_queue import QueueError, VerificationBinding, VerificationQueue
from .verification_recovery import RecoveryError, VerificationRecovery

_SHA = re.compile(r'[a-f0-9]{64}\Z')
_JOB = re.compile(r'fox-[a-f0-9]{20}\Z')
_PROFILE = 'native-table-form-v1'
_PROJECT_PROFILE = 'native-project-v1'
_CONTACT_WINDOW = 120


class VerificationRuntimeError(RuntimeError):
    pass


def _require(condition, code):
    if not condition:
        raise VerificationRuntimeError(code)


@dataclass(frozen=True)
class VerificationConfig:
    enabled: bool = False
    release_sha256: str | None = None

    def __post_init__(self):
        _require(type(self.enabled) is bool, 'VERIFICATION_ENABLE_FLAG_INVALID')
        _require(self.release_sha256 is None or (type(self.release_sha256) is str
                 and _SHA.fullmatch(self.release_sha256)), 'VERIFICATION_RELEASE_INVALID')
        _require(not self.enabled or self.release_sha256 is not None, 'VERIFICATION_RELEASE_REQUIRED')


def configuration(environ=None):
    values = os.environ if environ is None else environ
    flag = values.get('FOX_VERIFICATION_ENABLED', '0')
    _require(flag in ('0', '1'), 'VERIFICATION_ENABLE_FLAG_INVALID')
    release = values.get('FOX_VERIFIER_RELEASE_SHA256')
    return VerificationConfig(flag == '1', release)


def configured_queue(root, config=None):
    config = configuration() if config is None else config
    return VerificationQueue(Path(root) / 'fox.sqlite3', enabled=config.enabled,
                             verifier_release_sha256=config.release_sha256)


def _database(root):
    path = Path(root).absolute() / 'fox.sqlite3'
    _require(path.is_file() and not path.is_symlink() and path.resolve() == path,
             'VERIFICATION_DATABASE_UNSAFE')
    return path


def initialize_contact_schema(connection: sqlite3.Connection) -> None:
    """Initialize contact metadata without owning the connection/transaction.

    This performs no contact update, queue initialization or operator action.
    """
    connection.execute('''CREATE TABLE IF NOT EXISTS verification_operator_contact(
            singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            release_sha256 TEXT NOT NULL, last_seen REAL NOT NULL)''')
    _require([row[1] for row in connection.execute('PRAGMA table_info(verification_operator_contact)')]
             == ['singleton', 'release_sha256', 'last_seen'], 'VERIFICATION_CONTACT_SCHEMA_CHANGED')


def initialize(root, config=None):
    config = configuration() if config is None else config
    if not config.enabled:
        return
    configured_queue(root, config).initialize()
    with closing(sqlite3.connect(_database(root).as_uri() + '?mode=rw', uri=True, timeout=30)) as db, db:
        initialize_contact_schema(db)


def _read(path, maximum):
    _require(path.is_file() and not path.is_symlink() and path.resolve() == path
             and 0 < path.stat().st_size <= maximum, 'VERIFICATION_INPUT_UNAVAILABLE')
    with path.open('rb') as stream:
        raw = stream.read(maximum + 1)
    _require(0 < len(raw) <= maximum, 'VERIFICATION_INPUT_TOO_LARGE')
    return raw


def _handoff_profile(job, snapshot, release):
    """A retained project marker can never select a single-form cache."""
    _require(type(snapshot) is dict and type(release) is dict, 'VERIFICATION_NATIVE_BINDING_REQUIRED')
    profile = snapshot.get('conversion_profile')
    cache = job / 'native-project-pipeline'
    project_marked = (cache.exists() or cache.is_symlink() or 'native_project' in snapshot
                      or release.get('conversion_profile') == _PROJECT_PROFILE)
    _require(type(profile) is str and profile in {_PROFILE, _PROJECT_PROFILE}
             and release.get('conversion_profile') == profile
             and (not project_marked or profile == _PROJECT_PROFILE),
             'VERIFICATION_NATIVE_BINDING_REQUIRED')
    return profile, 'native-project-pipeline' if profile == _PROJECT_PROFILE else 'native-pipeline'


def _project_handoff(job, snapshot, release, package):
    """Validate the complete frozen project and exact retained target cache.

    The queue schema stays unchanged: the package digest binds the packaged
    target evidence, and the real project validator checks that evidence
    against this exact cache. This is scheduling, never technical promotion.
    """
    from .native_project_pipeline import verify_project_package
    from .opaf import canonical_hash, OpafError
    from .project_conversion import assess_project_conversion
    try:
        plan = assess_project_conversion(snapshot['files'], project_id=snapshot['project_id'],
            project_name=snapshot['project_name'], source_hash=snapshot['source_hash'])
        _require(plan['state'] == 'READY' and plan['can_generate'] is True
                 and plan['rendering_spec'] == snapshot.get('native_project')
                 and plan['plan_sha256'] == snapshot.get('plan_sha256')
                 and snapshot.get('project') == snapshot['project_id'],
                 'VERIFICATION_PROJECT_SOURCE_BINDING_CHANGED')
        envelope = json.loads(_read(job / 'native-project-pipeline' / 'target-profile.json', 65_536))
        _require(type(envelope) is dict and set(envelope) == {'target_profile', 'target_profile_sha256'}
                 and type(envelope['target_profile']) is dict
                 and envelope['target_profile_sha256'] == canonical_hash(envelope['target_profile']),
                 'VERIFICATION_PROJECT_TARGET_BINDING_CHANGED')
        _require(verify_project_package(package, release, snapshot['native_project'], envelope['target_profile'])
                 == hashlib.sha256(package).hexdigest(), 'VERIFICATION_PROJECT_PACKAGE_CHANGED')
    except (OSError, ValueError, TypeError, KeyError, AttributeError, OpafError):
        raise VerificationRuntimeError('VERIFICATION_PROJECT_HANDOFF_REQUIRES_OPERATOR') from None


def enqueue_native(root, run_id, config=None):
    """Derive an immutable scheduling identity from retained server-side bytes.

    This is not a new release validator. The protected backend must still run
    the existing package/target checks before any external action, and only the
    existing technical gate can promote the run.
    """
    config = configuration() if config is None else config
    if not config.enabled:
        return None
    _require(type(run_id) is str and _JOB.fullmatch(run_id), 'VERIFICATION_JOB_INVALID')
    root = Path(root).absolute()
    job = root / 'jobs' / run_id
    try:
        snapshot = json.loads(_read(job / 'source-snapshot.json', 2_000_000))
        release = json.loads(_read(job / 'release-evidence.json', 2_000_000))
        profile, pipeline = _handoff_profile(job, snapshot, release)
        downloaded = json.loads(_read(job / pipeline / 'download.json', 16_384))
        package = _read(job / 'apex-package.zip', 8_000_000)
        package_hash = hashlib.sha256(package).hexdigest()
        _require(release.get('job_id') == run_id, 'VERIFICATION_NATIVE_BINDING_REQUIRED')
        files = snapshot['files']
        _require(type(files) is list and 0 < len(files) <= 50, 'VERIFICATION_SOURCE_SET_INVALID')
        raw_files = []
        for item in files:
            raw = item['text'].encode('utf-8')
            # Intake retains the raw byte digest but strips a UTF-8 BOM from
            # text. Restore it only when its exact recorded digest proves it.
            if hashlib.sha256(raw).hexdigest() != item['sha256'] and hashlib.sha256(b'\xef\xbb\xbf' + raw).hexdigest() == item['sha256']:
                raw = b'\xef\xbb\xbf' + raw
            raw_files.append(raw)
        _require(sum(len(item['text'].encode('utf-8')) for item in files) <= MAX_CONVERSION_BYTES,
                 'VERIFICATION_SOURCE_SET_TOO_LARGE')
        checked = [checked_source(item['name'], raw) for item, raw in zip(files, raw_files)]
        _require(len({item['name'] for item in checked}) == len(checked)
                 and all(all(original[key] == verified[key] for key in ('name', 'text', 'bytes', 'sha256'))
                         for original, verified in zip(files, checked)), 'VERIFICATION_SOURCE_BYTES_CHANGED')
        source_hash = inventory(checked)['source_hash']
        _require(source_hash == snapshot['source_hash'] == release['source_manifest_sha256']
                 and downloaded == {'source_hash': source_hash, 'package_sha256': package_hash},
                 'VERIFICATION_PACKAGE_BINDING_CHANGED')
        _require(all(snapshot.get('approvals', {}).get(key) is True
                     for key in ('redacted_source', 'external_ai', 'synthetic_prototype')),
                 'VERIFICATION_SOURCE_APPROVAL_REQUIRED')
        if profile == _PROJECT_PROFILE:
            _project_handoff(job, snapshot, release, package)
            with closing(sqlite3.connect(_database(root).as_uri() + '?mode=ro', uri=True, timeout=30)) as db:
                run = db.execute('SELECT project,source_hash FROM runs WHERE id=?', (run_id,)).fetchone()
            _require(run is not None and run == (snapshot['project_id'], source_hash),
                     'VERIFICATION_PROJECT_RUN_BINDING_CHANGED')
        binding = VerificationBinding(run_id, source_hash, package_hash, config.release_sha256)
        return configured_queue(root, config).enqueue(binding)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, sqlite3.Error, QueueError):
        raise VerificationRuntimeError('VERIFICATION_HANDOFF_REQUIRES_OPERATOR') from None


def operator_heartbeat(root, release_sha256):
    """Protected operator transport only; no route exposes this write."""
    config = configuration()
    _require(config.enabled and type(release_sha256) is str and release_sha256 == config.release_sha256,
             'VERIFICATION_OPERATOR_RELEASE_MISMATCH')
    with closing(sqlite3.connect(_database(root).as_uri() + '?mode=rw', uri=True, timeout=30)) as db, db:
        db.execute('INSERT INTO verification_operator_contact VALUES(1,?,?) '
                   'ON CONFLICT(singleton) DO UPDATE SET release_sha256=excluded.release_sha256,last_seen=excluded.last_seen',
                   (release_sha256, time.time()))
    return {'contact_recorded': True}


def _contact(root, config):
    with closing(sqlite3.connect(_database(root).as_uri() + '?mode=ro', uri=True, timeout=30)) as db:
        row = db.execute('SELECT release_sha256,last_seen FROM verification_operator_contact WHERE singleton=1').fetchone()
    if row is None:
        return 'not_reported', None
    if row[0] != config.release_sha256 or not isinstance(row[1], (int, float)) or not math.isfinite(row[1]):
        return 'unknown', None
    age = time.time() - row[1]
    if age < -5:
        return 'unknown', None
    at = datetime.fromtimestamp(row[1], timezone.utc).isoformat()
    return ('recent' if age <= _CONTACT_WINDOW else 'stale'), at


def public_status(root, run, config=None):
    """Owner authorization is performed by the enclosing project handler."""
    config = configuration() if config is None else config
    if run['state'] not in {'QA_REQUIRED', 'VERIFIED', 'ACCEPTED'}:
        return None
    if not config.enabled:
        return {'configured': False, 'state': 'disabled', 'operator_contact': 'not_reported',
                'operator_last_seen_at_utc': None, 'queue_updated_at_utc': None,
                'message': 'Managed verification is not configured. The FOX operator must verify this package.'}
    try:
        contact, seen = _contact(root, config)
        row = configured_queue(root, config).get(run['id'])
        recovery = VerificationRecovery(Path(root) / 'fox.sqlite3', enabled=True)
        with recovery._db() as connection:
            connection.execute('BEGIN')
            if recovery._recovery_available(connection):
                eligibility = recovery._eligibility(connection, run['id'])
                attempt_row = connection.execute('SELECT attempt_id FROM verification_retry_attempts WHERE job_id=?',
                                                  (run['id'],)).fetchone()
                attempt = recovery._attempt(connection, attempt_row['attempt_id']) if attempt_row else None
                recovery_state = eligibility['recovery_state']
                if attempt is not None:
                    _require(attempt['binding']['source_manifest_sha256'] == run['source_hash']
                             and (attempt['state'] == 'completed'
                                  or attempt['binding']['verifier_release_sha256'] == config.release_sha256),
                             'VERIFICATION_RECOVERY_RELEASE_CHANGED')
                    recovery_state = 'retry_' + attempt['state']
                recovery_messages = {
                    'failed_closed': 'This verification attempt failed and is closed. No successful technical proof or automatic retry is implied.',
                    'retry_reserved': 'A separate verification retry is reserved. The original failed attempt is preserved.',
                    'retry_running': 'A separate verification retry has started. Its result has not yet been recorded.',
                    'retry_attention': 'The retry needs operator reconciliation. It will not be replayed automatically.',
                    'retry_completed': 'The retry has a recorded technical proof. Business acceptance remains separate.',
                }
                if recovery_state in recovery_messages:
                    _require(recovery_state != 'retry_completed' or run['state'] in {'VERIFIED', 'ACCEPTED'},
                             'VERIFICATION_RECOVERY_STATUS_INCONSISTENT')
                    return {'configured': True, 'state': recovery_state, 'operator_contact': contact,
                            'operator_last_seen_at_utc': seen,
                            'queue_updated_at_utc': attempt['created_at_utc'] if attempt else row['updated_at_utc'],
                            'message': recovery_messages[recovery_state]}
        state = row['state'] if row else 'not_queued'
        if row and row['source_manifest_sha256'] != run['source_hash']:
            raise VerificationRuntimeError('VERIFICATION_STATUS_BINDING_CHANGED')
        if row and state != 'completed' and row['verifier_release_sha256'] != config.release_sha256:
            raise VerificationRuntimeError('VERIFICATION_OPERATOR_RELEASE_CHANGED')
        if state == 'completed' and run['state'] not in {'VERIFIED', 'ACCEPTED'}:
            raise VerificationRuntimeError('VERIFICATION_STATUS_INCONSISTENT')
        messages = {
            'not_queued': 'The package is waiting for an operator to reconcile its verification handoff.',
            'queued': 'The package is queued for the protected verification operator.',
            'running': 'A verification attempt has started. Its result has not yet been recorded.',
            'attention': 'Verification needs operator reconciliation. It will not be retried automatically.',
            'completed': 'Technical verification is recorded. Business review and acceptance remain separate.',
        }
        return {'configured': True, 'state': state, 'operator_contact': contact,
                'operator_last_seen_at_utc': seen, 'queue_updated_at_utc': row['updated_at_utc'] if row else None,
                'message': messages[state]}
    except (OSError, ValueError, TypeError, KeyError, OverflowError, sqlite3.Error, QueueError, RecoveryError, VerificationRuntimeError):
        return {'configured': True, 'state': 'unavailable', 'operator_contact': 'unknown',
                'operator_last_seen_at_utc': None, 'queue_updated_at_utc': None,
                'message': 'Verification status is unavailable. Ask the FOX operator to reconcile the retained job.'}
