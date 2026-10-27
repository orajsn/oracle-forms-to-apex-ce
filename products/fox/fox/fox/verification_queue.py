"""Disabled-by-default verification queue foundation; NOT wired into live FOX.

Only this queue table is written. The existing promotion gate remains responsible
for private receipt provenance and QA_REQUIRED -> VERIFIED. Completion below
rechecks its retained technical proof; it never promotes a run or accepts one.
No network, subprocess, credential resolution or target selection is implemented.

Bindings are server-derived identities, not browser authorization. Backend release
identity comes from trusted deployment configuration; this module does not attest
executable/container bytes. SQLite/file ownership remains the host trust boundary.
Record hashes detect accidental/tampered rows, not a privileged database rewrite.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
import sqlite3
from typing import Protocol


_JOB = re.compile(r'fox-[a-f0-9]{20}\Z')
_SHA = re.compile(r'[a-f0-9]{64}\Z')
_TOKEN = re.compile(r'[a-f0-9]{32}\Z')
_BINDING_KEYS = ('job_id', 'source_manifest_sha256', 'package_sha256', 'verifier_release_sha256')
_STATES = frozenset({'queued', 'running', 'attention', 'completed'})
_ATTENTION = frozenset({'BACKEND_OUTCOME_UNCONFIRMED', 'PROOF_UNCONFIRMED', 'INTERRUPTED_OUTCOME'})
_COLUMNS = (*_BINDING_KEYS, 'binding_sha256', 'state', 'claim_token', 'proof_sha256',
            'attention_code', 'created_at_utc', 'updated_at_utc', 'record_sha256')


class QueueError(RuntimeError):
    """Fixed diagnostic categories only; never submitted values or exceptions."""


def _require(condition, code):
    if not condition:
        raise QueueError(code)


def _sha(value):
    return type(value) is str and _SHA.fullmatch(value) is not None


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def _now():
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class VerificationBinding:
    job_id: str
    source_manifest_sha256: str
    package_sha256: str
    verifier_release_sha256: str

    def __post_init__(self):
        _require(type(self.job_id) is str and _JOB.fullmatch(self.job_id), 'QUEUE_JOB_ID_INVALID')
        _require(all(_sha(getattr(self, key)) for key in _BINDING_KEYS[1:]), 'QUEUE_DIGEST_INVALID')

    @classmethod
    def from_payload(cls, value):
        _require(type(value) is dict and set(value) == set(_BINDING_KEYS), 'QUEUE_BINDING_FIELDS_INVALID')
        return cls(**value)

    def payload(self):
        return {key: getattr(self, key) for key in _BINDING_KEYS}


@dataclass(frozen=True)
class Claim:
    binding: VerificationBinding
    attempt_token: str = field(repr=False)

    def __post_init__(self):
        _require(type(self.binding) is VerificationBinding, 'QUEUE_BINDING_REQUIRED')
        _require(type(self.attempt_token) is str and _TOKEN.fullmatch(self.attempt_token), 'QUEUE_CLAIM_INVALID')


@dataclass(frozen=True)
class TechnicalProofResult:
    """A proof reference only, NOT a trusted passed=True assertion."""
    proof_sha256: str

    def __post_init__(self):
        _require(_sha(self.proof_sha256), 'QUEUE_PROOF_DIGEST_INVALID')


class VerificationBackend(Protocol):
    verifier_release_sha256: str

    def verify(self, claim: Claim) -> TechnicalProofResult: ...


def initialize_schema(connection: sqlite3.Connection) -> None:
    """Initialize queue metadata on the caller's connection and transaction.

    This does not open storage, commit, roll back, enable a queue or claim work.
    The caller must explicitly establish its write transaction before calling.
    """
    # Require the existing FOX run store; never manufacture product runs.
    connection.execute('SELECT id,source_hash,state,artifact FROM runs LIMIT 0')
    connection.execute('''CREATE TABLE IF NOT EXISTS verification_queue(
                job_id TEXT PRIMARY KEY REFERENCES runs(id),
                source_manifest_sha256 TEXT NOT NULL, package_sha256 TEXT NOT NULL,
                verifier_release_sha256 TEXT NOT NULL, binding_sha256 TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('queued','running','attention','completed')),
                claim_token TEXT, proof_sha256 TEXT, attention_code TEXT,
                created_at_utc TEXT NOT NULL, updated_at_utc TEXT NOT NULL, record_sha256 TEXT NOT NULL,
                CHECK((state='queued' AND claim_token IS NULL AND proof_sha256 IS NULL AND attention_code IS NULL)
                   OR (state='running' AND claim_token IS NOT NULL AND proof_sha256 IS NULL AND attention_code IS NULL)
                   OR (state='attention' AND claim_token IS NOT NULL AND proof_sha256 IS NULL AND attention_code IS NOT NULL)
                   OR (state='completed' AND claim_token IS NOT NULL AND proof_sha256 IS NOT NULL AND attention_code IS NULL))
            )''')
    _require(tuple(row[1] for row in connection.execute('PRAGMA table_info(verification_queue)')) == _COLUMNS,
             'QUEUE_SCHEMA_MISMATCH')
    connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS verification_queue_one_running ON verification_queue(state) WHERE state='running'")


class VerificationQueue:
    """Explicit local initialization; opening/importing never creates a database.

    ``database`` is installation-owned, not a public payload. It must be the
    existing FOX SQLite file beside its jobs directory. No leases, requeue,
    automatic takeover or retry API exists. Only queued entries can be claimed.
    ``recover_running`` is an explicit startup/reconciliation action after the
    old executor is known stopped; it must not race a live executor.
    """

    def __init__(self, database: Path, *, enabled: bool = False, verifier_release_sha256: str | None = None):
        _require(type(enabled) is bool, 'QUEUE_ENABLE_FLAG_INVALID')
        _require(verifier_release_sha256 is None or _sha(verifier_release_sha256), 'QUEUE_RELEASE_INVALID')
        _require(not enabled or verifier_release_sha256 is not None, 'QUEUE_RELEASE_REQUIRED')
        self._database = Path(database).absolute()
        self._enabled = enabled
        self._release = verifier_release_sha256

    def _enabled_only(self):
        _require(self._enabled, 'VERIFICATION_QUEUE_DISABLED')

    def _bound(self, binding):
        _require(type(binding) is VerificationBinding, 'QUEUE_BINDING_REQUIRED')
        _require(binding.verifier_release_sha256 == self._release, 'QUEUE_RELEASE_MISMATCH')

    @contextmanager
    def _db(self, *, write=False):
        connection = None
        try:
            _require(self._database.is_file() and not self._database.is_symlink()
                     and self._database.resolve() == self._database, 'QUEUE_DATABASE_UNSAFE')
            connection = sqlite3.connect(self._database.as_uri() + ('?mode=rw' if write else '?mode=ro'),
                                         uri=True, timeout=30, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute('PRAGMA foreign_keys=ON')
            if write:
                connection.execute('PRAGMA synchronous=FULL')
                connection.execute('BEGIN IMMEDIATE')
            yield connection
            if write:
                connection.commit()
        except sqlite3.Error:
            raise QueueError('QUEUE_STORAGE_UNAVAILABLE') from None
        finally:
            if connection is not None:
                if connection.in_transaction:
                    connection.rollback()
                connection.close()

    def initialize(self):
        self._enabled_only()
        with self._db(write=True) as db:
            initialize_schema(db)

    @staticmethod
    def _record(value):
        if value is None:
            return None
        row = dict(value)
        _require(set(row) == set(_COLUMNS), 'QUEUE_RECORD_FIELDS_INVALID')
        binding = VerificationBinding.from_payload({key: row[key] for key in _BINDING_KEYS})
        _require(row['binding_sha256'] == _digest(binding.payload()) and row['state'] in _STATES,
                 'QUEUE_RECORD_BINDING_CHANGED')
        _require(row['record_sha256'] == _digest({key: row[key] for key in _COLUMNS if key != 'record_sha256'}),
                 'QUEUE_RECORD_CHANGED')
        token, proof, reason, state = (row[key] for key in ('claim_token', 'proof_sha256', 'attention_code', 'state'))
        _require((state == 'queued' and token is proof is reason is None)
                 or (state != 'queued' and type(token) is str and _TOKEN.fullmatch(token)
                     and ((state == 'running' and proof is reason is None)
                          or (state == 'attention' and proof is None and reason in _ATTENTION)
                          or (state == 'completed' and _sha(proof) and reason is None))), 'QUEUE_RECORD_STATE_INVALID')
        return row

    @staticmethod
    def _public(row):
        if row is None:
            return None
        return {key: row[key] for key in (*_BINDING_KEYS, 'state', 'proof_sha256', 'attention_code',
                                         'created_at_utc', 'updated_at_utc')}

    @staticmethod
    def _save(db, row, *, insert=False):
        row = dict(row)
        row['record_sha256'] = _digest({key: row[key] for key in _COLUMNS if key != 'record_sha256'})
        VerificationQueue._record(row)
        if insert:
            db.execute('INSERT INTO verification_queue VALUES(' + ','.join('?' for _ in _COLUMNS) + ')',
                       tuple(row[key] for key in _COLUMNS))
        else:
            # Only transition fields may change; bindings are never updated.
            keys = ('state', 'claim_token', 'proof_sha256', 'attention_code', 'updated_at_utc', 'record_sha256')
            cursor = db.execute('UPDATE verification_queue SET ' + ','.join(key + '=?' for key in keys) + ' WHERE job_id=?',
                                (*[row[key] for key in keys], row['job_id']))
            _require(cursor.rowcount == 1, 'QUEUE_UPDATE_LOST')
        return row

    @staticmethod
    def _run(db, binding, *, states):
        run = db.execute('SELECT * FROM runs WHERE id=?', (binding.job_id,)).fetchone()
        _require(run is not None and run['source_hash'] == binding.source_manifest_sha256
                 and run['artifact'] == str(Path('jobs') / binding.job_id / 'apex-package.zip')
                 and run['state'] in states, 'QUEUE_RUN_BINDING_OR_STATE_CHANGED')
        return dict(run)

    def get(self, job_id):
        _require(type(job_id) is str and _JOB.fullmatch(job_id), 'QUEUE_JOB_ID_INVALID')
        with self._db() as db:
            return self._public(self._record(db.execute('SELECT * FROM verification_queue WHERE job_id=?', (job_id,)).fetchone()))

    def enqueue(self, binding: VerificationBinding):
        self._enabled_only(); self._bound(binding)
        with self._db(write=True) as db:
            row = self._record(db.execute('SELECT * FROM verification_queue WHERE job_id=?', (binding.job_id,)).fetchone())
            if row is not None:
                _require(all(row[key] == value for key, value in binding.payload().items()), 'QUEUE_JOB_REBIND_FORBIDDEN')
                return self._public(row)
            self._run(db, binding, states={'QA_REQUIRED'})
            at = _now()
            row = {**binding.payload(), 'binding_sha256': _digest(binding.payload()), 'state': 'queued',
                   'claim_token': None, 'proof_sha256': None, 'attention_code': None,
                   'created_at_utc': at, 'updated_at_utc': at, 'record_sha256': ''}
            return self._public(self._save(db, row, insert=True))

    def claim_next(self):
        self._enabled_only()
        with self._db(write=True) as db:
            if db.execute("SELECT 1 FROM verification_queue WHERE state='running'").fetchone():
                return None
            row = self._record(db.execute("SELECT * FROM verification_queue WHERE state='queued' ORDER BY created_at_utc,job_id LIMIT 1").fetchone())
            if row is None:
                return None
            binding = VerificationBinding.from_payload({key: row[key] for key in _BINDING_KEYS})
            self._bound(binding)
            self._run(db, binding, states={'QA_REQUIRED'})
            from .verification_recovery import VerificationRecovery
            if not VerificationRecovery(self._database, enabled=True).normal_claim_allowed(db, binding):
                return None
            token = secrets.token_hex(16)
            self._save(db, {**row, 'state': 'running', 'claim_token': token, 'updated_at_utc': _now()})
            return Claim(binding, token)

    def attention(self, claim: Claim, code='BACKEND_OUTCOME_UNCONFIRMED'):
        self._enabled_only()
        _require(type(claim) is Claim and type(code) is str and code in _ATTENTION, 'QUEUE_ATTENTION_INPUT_INVALID')
        self._bound(claim.binding)
        with self._db(write=True) as db:
            row = self._claimed(db, claim)
            _require(row['state'] in {'running', 'attention'}, 'QUEUE_ATTENTION_STATE_INVALID')
            if row['state'] == 'attention':
                return self._public(row)
            return self._public(self._save(db, {**row, 'state': 'attention', 'attention_code': code, 'updated_at_utc': _now()}))

    def recover_running(self):
        """Explicitly fence interrupted work; does not dispatch or requeue it."""
        self._enabled_only()
        with self._db(write=True) as db:
            rows = [self._record(row) for row in db.execute("SELECT * FROM verification_queue WHERE state='running'")]
            result = []
            for row in rows:
                self._bound(VerificationBinding.from_payload({key: row[key] for key in _BINDING_KEYS}))
                result.append(self._public(self._save(db, {**row, 'state': 'attention',
                    'attention_code': 'INTERRUPTED_OUTCOME', 'updated_at_utc': _now()})))
            return result

    def _claimed(self, db, claim):
        _require(type(claim) is Claim, 'QUEUE_CLAIM_REQUIRED')
        self._bound(claim.binding)
        row = self._record(db.execute('SELECT * FROM verification_queue WHERE job_id=?', (claim.binding.job_id,)).fetchone())
        _require(row is not None and row['claim_token'] == claim.attempt_token
                 and all(row[key] == value for key, value in claim.binding.payload().items()), 'QUEUE_STALE_OR_CHANGED_CLAIM')
        return row

    def _validated_proof(self, db, binding, result):
        _require(type(result) is TechnicalProofResult, 'QUEUE_TECHNICAL_PROOF_RESULT_REQUIRED')
        # Genuine later acceptance does not invalidate the technical proof.
        # This readback neither creates nor changes that acceptance decision.
        run = self._run(db, binding, states={'VERIFIED', 'ACCEPTED'})
        # The existing production gate is mandatory, not an injectable callback
        # or a new parallel validator. No promotion or human action is performed.
        from .technical_release import checked_release
        try:
            checked = checked_release(db, self._database.parent, run)
            stored = db.execute('SELECT proof_sha256,artifact_sha256 FROM technical_verifications WHERE run=?',
                                (binding.job_id,)).fetchone()
            _require(checked is not None and stored is not None
                     and stored['proof_sha256'] == result.proof_sha256
                     and stored['artifact_sha256'] == binding.package_sha256
                     and hashlib.sha256(checked['package']).hexdigest() == binding.package_sha256
                     and all(checked['proof'][key] == value for key, value in {
                         'job_id': binding.job_id, 'source_manifest_sha256': binding.source_manifest_sha256,
                         'package_sha256': binding.package_sha256}.items())
                     and checked['proof']['human_acceptance_recorded'] is False, 'QUEUE_PROOF_BINDING_CHANGED')
        except Exception:
            raise QueueError('QUEUE_TECHNICAL_PROOF_NOT_VALIDATED') from None

    def complete(self, claim: Claim, result: TechnicalProofResult):
        self._enabled_only()
        try:
            with self._db(write=True) as db:
                row = self._claimed(db, claim)
                _require(row['state'] in {'running', 'completed'}, 'QUEUE_RECONCILIATION_REQUIRED')
                self._validated_proof(db, claim.binding, result)
                if row['state'] == 'completed':
                    _require(row['proof_sha256'] == result.proof_sha256, 'QUEUE_PROOF_REBIND_FORBIDDEN')
                    return self._public(row)
                return self._public(self._save(db, {**row, 'state': 'completed',
                    'proof_sha256': result.proof_sha256, 'updated_at_utc': _now()}))
        except QueueError:
            if type(claim) is Claim:
                try:
                    self.attention(claim, 'PROOF_UNCONFIRMED')
                except QueueError:
                    pass
            raise

    def reconcile_completed(self, binding: VerificationBinding, result: TechnicalProofResult):
        """Explicit retained-proof-only reconciliation; never invokes a backend."""
        self._enabled_only(); self._bound(binding)
        with self._db(write=True) as db:
            row = self._record(db.execute('SELECT * FROM verification_queue WHERE job_id=?', (binding.job_id,)).fetchone())
            _require(row is not None and row['state'] == 'attention'
                     and all(row[key] == value for key, value in binding.payload().items()), 'QUEUE_RECONCILIATION_STATE_INVALID')
            self._validated_proof(db, binding, result)
            return self._public(self._save(db, {**row, 'state': 'completed', 'attention_code': None,
                'proof_sha256': result.proof_sha256, 'updated_at_utc': _now()}))


def coordinate_one(queue: VerificationQueue, backend: VerificationBackend):
    """Call a trusted, configured backend once after the durable claim commit.

    Exceptions are converted to attention without logging their content. Process
    termination leaves running durable for explicit recover_running; no retries.
    Backend implementation/provenance remains a future integration responsibility.
    """
    _require(type(queue) is VerificationQueue, 'QUEUE_INSTANCE_REQUIRED')
    queue._enabled_only()
    try:
        valid_backend = (getattr(backend, 'verifier_release_sha256', None) == queue._release
                         and callable(getattr(backend, 'verify', None)))
    except Exception:
        raise QueueError('QUEUE_BACKEND_METADATA_UNAVAILABLE') from None
    _require(valid_backend, 'QUEUE_BACKEND_RELEASE_MISMATCH')
    claim = queue.claim_next()
    if claim is None:
        return None
    try:
        result = backend.verify(claim)
        _require(getattr(backend, 'verifier_release_sha256', None) == claim.binding.verifier_release_sha256,
                 'QUEUE_BACKEND_RELEASE_CHANGED')
        return queue.complete(claim, result)
    except Exception:
        return queue.attention(claim, 'BACKEND_OUTCOME_UNCONFIRMED')
