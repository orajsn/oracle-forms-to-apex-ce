"""Inert failed-QA bridge interfaces; no live dispatcher, service or endpoint.

All execution is an explicitly injected LOCAL TEST seam. A real protected host
observer and separately approved adapter are not implemented here. Generating
source or passing identity/configuration objects establishes no live authority.
The immutable backend is compiled in memory; it is never installed into FOX.
"""
from __future__ import annotations

import base64
from contextlib import closing, redirect_stderr, redirect_stdout
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime, timezone
import hashlib
import inspect
import io
import json
from pathlib import Path
import re
import sqlite3
import sys
import types

ROOT = Path(__file__).resolve().parents[2]
ACTIVE_RELEASE = '2f7065ac0531793a645902be739870e553f37a8513d64fdcfcfee96f04b1af67'
FOX_IMAGE = 'sha256:8ac18481bfcb0e991582f93b351ed66203372d8d9b9a11cc28ede7fd8d618f8d'
FOX_CONTAINER = '48b9fbd91652ee4fdac85e2883e360ebd2d923e094c405023fbb62f735ff2cc6'
BACKEND_SHA256 = 'c6ee062a4539553238f7402f46e7e28cd096bf24db5e92d35e2b102f3fe9251f'
INSTANCE = 'ocid1.instance.oc1.iad.anuwcljtc7x6gxic5w37qsyp3rst64betkt4uk2pdcrtmy3okspcpbv77qea'
COMPARTMENT = 'ocid1.compartment.oc1..aaaaaaaa2q5aelkapmt5mhumvxadcynq5chez2faeucy5plefhy3ylmahtba'
REGION = 'us-ashburn-1'
OPS = frozenset({'observe', 'resolve_failure', 'lookup_resolution', 'read_closed_state'})
BYTE_KEYS = ('package', 'plan_raw', 'collection_raw')
FILE_NAMES = frozenset({'package.zip', 'native-form-spec.json', 'allocation-receipt.json',
    'verification-profile.json', 'clean-import-receipt.json', 'qa-profile.json', 'target-receipt.json',
    'qa-result.json', 'stage-receipt.json', 'launch-intent.json', 'dispatch-receipt.json', 'launch-receipt.json'})
PROBE_FILES = ('stage-receipt.json', 'launch-receipt.json', 'launch-intent.json', 'dispatch-receipt.json', 'qa-result.json')
REVIEW_FIELDS = ('verifier_release_sha256', 'qa_source_sha256', 'wrapper_sha256', 'original_wrapper_sha256', 'image_id')
MAX_PACKET = 24_000_000


class RecoveryTransportError(RuntimeError):
    """Fixed categories only; never source, token, provider or exception text."""


def _need(ok, code):
    if not ok:
        raise RecoveryTransportError(code)


def _sha(value):
    return type(value) is str and re.fullmatch(r'[a-f0-9]{64}', value) is not None


def _image(value):
    _need(type(value) is str and re.fullmatch(r'(?:sha256:)?[a-f0-9]{64}', value), 'RECOVERY_IMAGE_INVALID')
    return value if value.startswith('sha256:') else 'sha256:' + value


def _canonical(value):
    try:
        return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                           allow_nan=False) + '\n').encode('utf-8')
    except Exception:
        raise RecoveryTransportError('RECOVERY_TRANSPORT_JSON_INVALID') from None


def _digest(raw):
    _need(type(raw) is bytes, 'RECOVERY_TRANSPORT_EXACT_BYTES_REQUIRED')
    return hashlib.sha256(raw).hexdigest()


def _json(raw, maximum=2_000_000):
    _need(type(raw) is bytes and 0 < len(raw) <= maximum, 'RECOVERY_TRANSPORT_SIZE_INVALID')
    def unique(pairs):
        value = {}
        for key, item in pairs:
            _need(key not in value, 'RECOVERY_TRANSPORT_JSON_INVALID')
            value[key] = item
        return value
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        _need(type(value) is dict, 'RECOVERY_TRANSPORT_JSON_INVALID')
        return value
    except Exception:
        raise RecoveryTransportError('RECOVERY_TRANSPORT_JSON_INVALID') from None


def _manifest(value, expected):
    raw = _canonical(value)
    _need(type(value) is dict and len(raw) <= 65_536 and expected == ACTIVE_RELEASE
          and _digest(raw) == ACTIVE_RELEASE and value.get('enabled') is True
          and value.get('images', {}).get('fox') == FOX_IMAGE,
          'EXACT_ACTIVE_C_RELEASE_REQUIRED')
    return _json(raw, 65_536)


def backend_source():
    """Read only the frozen backend source, not private records or credentials."""
    path = ROOT / 'fox/fox/verification_recovery.py'
    _need(path.is_file() and not path.is_symlink() and path.resolve() == path
          and 0 < path.stat().st_size <= 200_000, 'RECOVERY_BACKEND_SOURCE_UNSAFE')
    raw = path.read_bytes()
    _need(0 < len(raw) <= 200_000 and _digest(raw) == BACKEND_SHA256, 'RECOVERY_BACKEND_SOURCE_CHANGED')
    return raw


def _load_backend(raw):
    _need(type(raw) is bytes and 0 < len(raw) <= 200_000 and _digest(raw) == BACKEND_SHA256,
          'RECOVERY_BACKEND_SOURCE_CHANGED')
    sys.dont_write_bytecode = True
    # Installed FOX dependencies remain the protected adapter's pinned-image
    # boundary. The backend itself executes exactly these checked source bytes.
    name = 'fox._protected_recovery_once'
    prior = sys.modules.get(name)
    module = types.ModuleType(name); module.__package__ = 'fox'; module.__file__ = '<pinned-recovery-memory>'
    sys.modules[name] = module
    try:
        exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    finally:
        if prior is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = prior
    return module


@dataclass(frozen=True)
class PinnedIdentity:
    """Out-of-band adapter observation. Constructing it is NOT attestation."""
    instance_id: str
    compartment_id: str
    region: str
    container_id: str
    image_id: str
    release_sha256: str
    module_sha256: tuple

    def check(self, manifest):
        _need((self.instance_id, self.compartment_id, self.region, self.container_id,
               self.image_id, self.release_sha256) ==
              (INSTANCE, COMPARTMENT, REGION, FOX_CONTAINER, FOX_IMAGE, ACTIVE_RELEASE),
              'RECOVERY_PINNED_C_IDENTITY_REQUIRED')
        _need(type(self.module_sha256) is tuple
              and self.module_sha256 == tuple(sorted(manifest['modules'].items())),
              'RECOVERY_INSTALLED_MODULES_CHANGED')


@dataclass(frozen=True)
class HostProbeInput:
    """Exact inputs to a configured host observer; no submitted outcome/counts."""
    binding: object
    session_id: str
    qa_run_id: str
    image_id: str
    raw_evidence: tuple = field(repr=False)
    journal_summary_raw: bytes = field(repr=False)


@dataclass(frozen=True)
class NextReaderCapability:
    """LOCAL compatibility seam only; not evidence of a deployed next release.

    The caller supplies a separately reviewed reader. It is exercised against
    the frozen admission predicate before bootstrap. No caller Boolean or JSON
    field can grant this capability, and no current runtime file is modified.
    """
    release_sha256: str
    reader_sha256: str
    reader: object = field(repr=False)

    def check(self):
        _need(_sha(self.release_sha256) and self.release_sha256 != ACTIVE_RELEASE
              and _sha(self.reader_sha256) and type(self.reader) is types.FunctionType,
              'NEXT_READER_CAPABILITY_REQUIRED')
        source_file = inspect.getsourcefile(self.reader)
        _need(type(source_file) is str, 'NEXT_READER_SOURCE_UNAVAILABLE')
        path = Path(source_file).absolute()
        _need(path.is_file() and not path.is_symlink() and path.resolve() == path
              and 0 < path.stat().st_size <= 2_000_000, 'NEXT_READER_SOURCE_UNAVAILABLE')
        raw = path.read_bytes()
        _need(0 < len(raw) <= 2_000_000 and _digest(raw) == self.reader_sha256,
              'NEXT_READER_SOURCE_CHANGED')
        compiled = compile(raw, self.reader.__code__.co_filename, 'exec', dont_inherit=True)
        matches = [value for value in compiled.co_consts if isinstance(value, types.CodeType)
                   and value.co_name == self.reader.__name__ and value.co_firstlineno == self.reader.__code__.co_firstlineno]
        _need(len(matches) == 1 and matches[0] == self.reader.__code__, 'NEXT_READER_CALLABLE_CHANGED')


def _bytes(raw, maximum):
    _need(type(raw) is bytes and 0 < len(raw) <= maximum, 'RECOVERY_TRANSPORT_SIZE_INVALID')
    return base64.b64encode(raw).decode('ascii')


def _unbytes(value, maximum):
    _need(type(value) is str and len(value) <= ((maximum + 2) // 3) * 4,
          'RECOVERY_TRANSPORT_SIZE_INVALID')
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        raise RecoveryTransportError('RECOVERY_TRANSPORT_BYTES_INVALID') from None
    _need(0 < len(raw) <= maximum and _bytes(raw, maximum) == value, 'RECOVERY_TRANSPORT_BYTES_INVALID')
    return raw


def _evidence_fields(evidence, operation):
    required = {'binding', *BYTE_KEYS, 'files', 'journal_summary'}
    if 'wrapper_raw' in evidence:
        required.add('wrapper_raw')
    if operation != 'observe':
        required.update({'disposition', 'disposition_sha256'})
    _need(type(evidence) is dict and set(evidence) == required, 'RECOVERY_EVIDENCE_FIELDS_INVALID')


def _wire(operation, claim, evidence, manifest, release, apply):
    from fox.verification_queue import Claim, VerificationBinding
    _need(type(operation) is str and operation in OPS and type(apply) is bool
          and apply is (operation == 'resolve_failure'), 'RECOVERY_OPERATION_OR_APPLY_INVALID')
    _need(type(claim) is Claim and type(evidence) is dict, 'RECOVERY_CLAIM_REQUIRED')
    _evidence_fields(evidence, operation)
    _need(type(evidence['binding']) is VerificationBinding and evidence['binding'] == claim.binding
          and claim.binding.verifier_release_sha256 == ACTIVE_RELEASE, 'RECOVERY_EVIDENCE_BINDING_CHANGED')
    _need(type(evidence['files']) is dict and set(evidence['files']) == FILE_NAMES, 'RECOVERY_EVIDENCE_FILES_INVALID')
    encoded = {'binding': claim.binding.payload(), **{key: _bytes(evidence[key],
        8_000_000 if key == 'package' else 65_536) for key in BYTE_KEYS},
        'files': {name: _bytes(raw, 8_000_000 if name == 'package.zip' else 2_000_000)
                  for name, raw in evidence['files'].items()},
        'journal_summary': _json(_canonical(evidence['journal_summary']), 65_536)}
    if 'wrapper_raw' in evidence:
        encoded['wrapper_raw'] = _bytes(evidence['wrapper_raw'], 65_536)
    if operation != 'observe':
        encoded.update(disposition=_json(_canonical(evidence['disposition']), 65_536),
                       disposition_sha256=evidence['disposition_sha256'])
    packet = {'schema_version': 1, 'scope': 'fox-failure-recovery-injected-request-v1',
              'operation': operation, 'apply': apply, 'release_sha256': release,
              'manifest': _manifest(manifest, release), 'backend_sha256': BACKEND_SHA256,
              'claim': {'binding': claim.binding.payload(), 'attempt_token': claim.attempt_token}, 'evidence': encoded}
    _need(len(_canonical(packet)) <= MAX_PACKET, 'RECOVERY_TRANSPORT_SIZE_INVALID')
    return packet


def _decode(packet, backend):
    packet = _json(_canonical(packet), MAX_PACKET)
    _need(set(packet) == {'schema_version', 'scope', 'operation', 'apply', 'release_sha256',
                         'manifest', 'backend_sha256', 'claim', 'evidence'}
          and type(packet['schema_version']) is int and packet['schema_version'] == 1
          and packet['scope'] == 'fox-failure-recovery-injected-request-v1'
          and packet['backend_sha256'] == BACKEND_SHA256, 'RECOVERY_REQUEST_INVALID')
    _manifest(packet['manifest'], packet['release_sha256'])
    op = packet['operation']
    _need(type(op) is str and op in OPS and type(packet['apply']) is bool
          and packet['apply'] is (op == 'resolve_failure'), 'RECOVERY_OPERATION_OR_APPLY_INVALID')
    value = packet['claim']
    _need(type(value) is dict and set(value) == {'binding', 'attempt_token'}, 'RECOVERY_CLAIM_REQUIRED')
    claim = backend.Claim(backend.VerificationBinding.from_payload(value['binding']), value['attempt_token'])
    _need(claim.binding.verifier_release_sha256 == ACTIVE_RELEASE, 'RECOVERY_CLAIM_RELEASE_CHANGED')
    encoded = packet['evidence']; _evidence_fields(encoded, op)
    _need(encoded['binding'] == claim.binding.payload() and type(encoded['files']) is dict
          and set(encoded['files']) == FILE_NAMES, 'RECOVERY_EVIDENCE_BINDING_CHANGED')
    evidence = {key: _unbytes(encoded[key], 8_000_000 if key == 'package' else 65_536) for key in BYTE_KEYS}
    evidence.update(files={name: _unbytes(raw, 8_000_000 if name == 'package.zip' else 2_000_000)
                           for name, raw in encoded['files'].items()},
                    journal_summary=_json(_canonical(encoded['journal_summary']), 65_536))
    _need(evidence['journal_summary'].get('claim_sha256') == backend.claim_sha256(claim),
          'RECOVERY_JOURNAL_CLAIM_CHANGED')
    if 'wrapper_raw' in encoded:
        evidence['wrapper_raw'] = _unbytes(encoded['wrapper_raw'], 65_536)
    document = None
    if op != 'observe':
        document = backend._disposition(encoded['disposition'])
        _need(backend.disposition_sha256(document) == encoded['disposition_sha256']
              and document['binding'] == claim.binding.payload()
              and document['claim_sha256'] == backend.claim_sha256(claim), 'RECOVERY_EXACT_DISPOSITION_REQUIRED')
        _observation_projection(backend, document['producer'], claim, evidence)
    return packet, claim, evidence, document


def _snapshot(database, claim, backend):
    # Logical reads only. SQLite may maintain WAL/shared-memory bookkeeping on
    # a live WAL database; immutable=1 would conceal current state and is unsafe.
    _need(database.is_file() and not database.is_symlink() and database.resolve() == database,
          'RECOVERY_DATABASE_UNSAFE')
    with closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=30)) as db:
        db.row_factory = sqlite3.Row
        db.execute('BEGIN')
        run = backend.VerificationQueue._run(db, claim.binding, states={'QA_REQUIRED'})
        legacy = backend.VerificationQueue._record(db.execute('SELECT * FROM verification_queue WHERE job_id=?',
                                                              (claim.binding.job_id,)).fetchone())
        _need(legacy is not None and legacy['state'] == 'attention' and legacy['proof_sha256'] is None
              and legacy['claim_token'] == claim.attempt_token
              and all(legacy[key] == value for key, value in claim.binding.payload().items()),
              'RECOVERY_CURRENT_PRIVATE_CLAIM_CHANGED')
        acceptance_count = db.execute('SELECT COUNT(*) FROM acceptances WHERE run=?', (claim.binding.job_id,)).fetchone()[0]
        exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='technical_verifications'").fetchone()
        proof_count = (db.execute('SELECT COUNT(*) FROM technical_verifications WHERE run=?',
                                  (claim.binding.job_id,)).fetchone()[0] if exists else 0)
        _need(proof_count == acceptance_count == 0, 'RECOVERY_EXISTING_OUTCOME_BLOCKS_RESOLUTION')
        # Readiness must bind the current retained server bytes, not only the
        # operator's copy. Reuse the same read-only gate used before recording.
        run = backend.VerificationRecovery(database, enabled=True)._server_run(db, claim.binding, unverified=True)
        return {'run': run, 'legacy': legacy, 'technical_proof_count': proof_count, 'human_acceptance_count': acceptance_count}


def _reviewed(backend, configured, claim, evidence):
    _need(type(configured) in (tuple, list), 'RECOVERY_REVIEW_CONFIGURATION_REQUIRED')
    approved = []
    for item in configured:
        _need(is_dataclass(item) and type(item).__name__ == 'ReviewedSynchronousLaunch'
              and tuple(member.name for member in fields(item)) == REVIEW_FIELDS,
              'RECOVERY_REVIEW_CONFIGURATION_REQUIRED')
        approved.append(backend.ReviewedSynchronousLaunch(**{key: getattr(item, key) for key in REVIEW_FIELDS}))
    if 'wrapper_raw' not in evidence:
        return None, tuple(approved)
    qa = _json(evidence['files']['qa-result.json'])
    source = _json(evidence['collection_raw'], 65_536)['source_sha256']
    matches = [item for item in approved if item.verifier_release_sha256 == claim.binding.verifier_release_sha256
               and item.qa_source_sha256 == source and item.wrapper_sha256 == _digest(evidence['wrapper_raw'])
               and item.image_id == _image(qa.get('runtime', {}).get('image_id'))]
    _need(len(matches) == 1, 'RECOVERY_REVIEWED_SYNCHRONOUS_LAUNCH_REQUIRED')
    return matches[0], tuple(approved)


def _probe(backend, database, observer, claim, evidence, now, reviewed):
    _need(callable(observer), 'TRUSTED_HOST_OBSERVER_UNAVAILABLE')
    before = _snapshot(database, claim, backend)
    summary = evidence['journal_summary']; qa = _json(evidence['files']['qa-result.json'])
    session, run, image = summary.get('session_id'), qa.get('run_id'), _image(qa.get('runtime', {}).get('image_id'))
    _need(type(session) is str and re.fullmatch(r'session-[a-f0-9]{24}', session)
          and type(run) is str and re.fullmatch(r'FQ-[0-9]{8}T[0-9]{6}-[a-f0-9]{8}', run), 'RECOVERY_PROBE_BINDING_INVALID')
    raw = tuple((name, evidence['files'][name]) for name in PROBE_FILES)
    if reviewed is not None:
        raw += (('wrapper_raw', evidence['wrapper_raw']),)
    probe = HostProbeInput(claim.binding, session, run, image, raw, _canonical(summary))
    host = observer(probe)
    _need(type(host) is dict and 'technical_proof_count' not in host and 'human_acceptance_count' not in host,
          'HOST_OBSERVER_MUST_NOT_SUPPLY_DATABASE_COUNTS')
    host = _json(_canonical(host), 65_536)
    after = _snapshot(database, claim, backend)
    _need(before == after, 'RECOVERY_SERVER_STATE_CHANGED_DURING_OBSERVATION')
    producer = {**host, 'technical_proof_count': after['technical_proof_count'],
                'human_acceptance_count': after['human_acceptance_count']}
    # Mandatory shared validator checks terminality, freshness, every receipt
    # link, exact reviewed wrapper pair/image, and the zero-producer inventory.
    backend.validate_failed_evidence(binding=claim.binding, **evidence, producer=producer, now=now,
                                     reviewed_synchronous_launch=reviewed)
    return producer, after


def _reader_check(capability, backend, snapshot, claim, document):
    _need(type(capability) is NextReaderCapability, 'NEXT_READER_CAPABILITY_REQUIRED')
    capability.check()
    closed = backend.ClosedFailure(claim.binding, backend.disposition_sha256(document), snapshot['legacy']['record_sha256'])
    # An independently loaded copy owns its own ClosedFailure dataclass. Adapt
    # only this validated projection, never a caller-provided closed assertion.
    reader_closed_type = capability.reader.__globals__.get('ClosedFailure')
    _need(isinstance(reader_closed_type, type) and is_dataclass(reader_closed_type)
          and tuple(member.name for member in fields(reader_closed_type)) ==
          ('binding', 'disposition_sha256', 'legacy_record_sha256'), 'NEXT_READER_INTERFACE_UNPROVEN')
    reader_closed = reader_closed_type(closed.binding, closed.disposition_sha256, closed.legacy_record_sha256)
    cases = ((snapshot['run'], snapshot['legacy'], None, None),
             (snapshot['run'], snapshot['legacy'], closed, None),
             ({**snapshot['run'], 'state': 'PROCESSING'}, snapshot['legacy'], closed, None),
             (snapshot['run'], {**snapshot['legacy'], 'record_sha256': '0' * 64}, closed, None))
    for run, legacy, closure, retry in cases:
        expected = backend.admission_status(run, legacy, closure, retry)
        actual = capability.reader(dict(run), dict(legacy), reader_closed if closure is not None else None, retry)
        _need(type(actual) is dict and actual == expected, 'NEXT_READER_COMPATIBILITY_UNPROVEN')
    _need(backend.admission_status(*cases[1]) ==
          {'blocks_admission': False, 'recovery_state': 'failed_closed', 'retry_eligible': True},
          'NEXT_READER_CLOSED_PROJECTION_INVALID')


def _ack(backend, value, expected):
    if value is None:
        return None
    _need(type(value) is dict and set(value) == {'status', 'disposition_sha256', 'disposition'}
          and value['status'] == 'FAILED_QA_RECORDED' and value['disposition'] == expected
          and value['disposition_sha256'] == backend.disposition_sha256(expected),
          'RECOVERY_ACKNOWLEDGEMENT_UNCONFIRMED')
    return _json(_canonical(value), 65_536)


def _eligibility_projection(value):
    _need(type(value) is dict and set(value) == {'blocks_admission', 'recovery_state', 'retry_eligible'}
          and type(value['blocks_admission']) is bool and type(value['retry_eligible']) is bool
          and type(value['recovery_state']) is str, 'RECOVERY_ELIGIBILITY_UNCONFIRMED')
    state = value['recovery_state']
    _need((state == 'failed_closed' and value['blocks_admission'] is False)
          or (state == 'no_active_verification' and value['blocks_admission'] is False and value['retry_eligible'] is False)
          or (state in {'unavailable', 'unresolved', 'conversion_active', 'retry_reserved', 'retry_running', 'retry_attention'}
              and value['blocks_admission'] is True and value['retry_eligible'] is False),
          'RECOVERY_ELIGIBILITY_UNCONFIRMED')
    return dict(value)


def _closed_state_projection(backend, value, document):
    _need(type(value) is dict and set(value) == {'acknowledgement', 'eligibility', 'union_ready'}
          and type(value['union_ready']) is bool, 'RECOVERY_CLOSED_STATE_UNCONFIRMED')
    acknowledgement = _ack(backend, value['acknowledgement'], document)
    eligibility = _eligibility_projection(value['eligibility'])
    _need((acknowledgement is not None or (eligibility['blocks_admission'] and not value['union_ready']))
          and (not value['union_ready'] or not eligibility['blocks_admission']), 'RECOVERY_CLOSED_STATE_UNCONFIRMED')
    return {'acknowledgement': acknowledgement, 'eligibility': eligibility, 'union_ready': value['union_ready']}


def _read_closed_snapshot(backend, database, claim, document):
    """One read transaction: exact closure and all admission-bearing identities.

    Missing/malformed schema or unknown target records remain blocked. An
    unknown *other* union member prevents union readiness without discarding
    the independently validated target closure. No schema bootstrap or probe.
    """
    blocked = {'acknowledgement': None,
               'eligibility': {'blocks_admission': True, 'recovery_state': 'unavailable', 'retry_eligible': False},
               'union_ready': False}
    store = backend.VerificationRecovery(database, enabled=True)
    try:
        with store._db() as db:
            db.execute('BEGIN')
            required = {'runs', 'verification_queue', 'acceptances', *backend.VerificationRecovery._TABLES}
            available = {row['name'] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ("
                         + ','.join('?' for _ in required) + ')', tuple(sorted(required)))}
            if not required <= available:
                return blocked
            for table, columns in backend.VerificationRecovery._TABLES.items():
                if tuple(row['name'] for row in db.execute('PRAGMA table_info(' + table + ')')) != columns:
                    return blocked
            fences = {table + '_no_' + action for table in backend.VerificationRecovery._TABLES
                      for action in ('update', 'delete')}
            fences.update({'verification_closed_legacy_no_update', 'verification_closed_legacy_no_delete'})
            present_fences = {row['name'] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger' AND name IN ("
                + ','.join('?' for _ in fences) + ')', tuple(sorted(fences)))}
            if not fences <= present_fences:
                return blocked
            closed, saved = store._closed(db, claim.binding.job_id)
            if closed is None or saved != document:
                return blocked
            acknowledgement = _ack(backend, {'status': 'FAILED_QA_RECORDED', 'disposition': saved,
                'disposition_sha256': closed.disposition_sha256}, document)
            eligibility = _eligibility_projection(store._eligibility(db, claim.binding.job_id))
            union_ready = not eligibility['blocks_admission']
            identities = list(db.execute('SELECT id AS job_id FROM runs UNION SELECT job_id FROM verification_queue '
                                         'UNION SELECT job_id FROM verification_retry_attempts'))
            if not identities or not any(row['job_id'] == claim.binding.job_id for row in identities):
                union_ready = False
            for row in identities:
                try:
                    current = _eligibility_projection(store._eligibility(db, row['job_id']))
                    if current['blocks_admission']:
                        union_ready = False
                except Exception:
                    union_ready = False
            return _closed_state_projection(backend, {'acknowledgement': acknowledgement,
                'eligibility': eligibility, 'union_ready': union_ready}, document)
    except Exception:
        return blocked


def _observation_projection(backend, value, claim, evidence):
    _need(type(value) is dict, 'RECOVERY_OBSERVATION_UNCONFIRMED')
    synchronous = value.get('scope') == backend.SYNCHRONOUS_SCOPE
    expected = backend._SYNCHRONOUS_KEYS if synchronous else backend._PRODUCER_KEYS
    _need(set(value) == expected, 'RECOVERY_OBSERVATION_FIELDS_INVALID')
    result = _json(_canonical(value), 65_536)
    qa = _json(evidence['files']['qa-result.json'])
    _need(type(result['schema_version']) is int and result['schema_version'] == 1
          and result['scope'] in {backend.SYNCHRONOUS_SCOPE, 'fox-verification-producer-observation-v1'}
          and result['binding_sha256'] == _digest(_canonical(claim.binding.payload()))
          and result['session_id'] == evidence['journal_summary']['session_id']
          and result['qa_run_id'] == qa['run_id'] and result['image_id'] == _image(qa['runtime']['image_id'])
          and result['state'] == 'STOPPED' and type(result['exit_code']) is int and result['exit_code'] == 2,
          'RECOVERY_OBSERVATION_UNCONFIRMED')
    backend._time(result['observed_at_utc'])
    _need(all(type(result[key]) is int and result[key] == 0 for key in
          ('live_producer_count', 'unresolved_phase_count', 'technical_proof_count', 'human_acceptance_count')),
          'RECOVERY_OBSERVATION_UNCONFIRMED')
    if synchronous:
        _need(all(_sha(result[key]) for key in backend._SYNCHRONOUS_LINKS)
              and result['termination_basis'] == 'synchronous_foreground_exit'
              and result['container_forensic_attribution'] is False and result['detached'] is False
              and result['timed_out'] is False and result['signal_number'] is None
              and result['producer_inventory_complete'] is True
              and type(result['unknown_producer_count']) is int and result['unknown_producer_count'] == 0,
              'RECOVERY_OBSERVATION_UNCONFIRMED')
    else:
        _need(_sha(result['container_id']), 'RECOVERY_OBSERVATION_UNCONFIRMED')
    return result


def execute_injected(packet, *, source, root, identity, observer=None,
                     approved_synchronous_launches=(), next_reader=None, allow_apply=False, now=None):
    """LOCAL fake-adapter seam. No observation object is accepted from JSON.

    Actual target attestation, installed dependency provenance and exclusion
    locking are the future protected adapter's responsibility, not established
    by these injected objects. This function has no network/process capability.
    """
    try:
        _need(type(identity) is PinnedIdentity and type(packet) is dict, 'RECOVERY_PINNED_C_IDENTITY_REQUIRED')
        identity.check(_manifest(packet.get('manifest'), packet.get('release_sha256')))
        _need(type(allow_apply) is bool, 'RECOVERY_APPLY_CONFIGURATION_INVALID')
        backend = _load_backend(source)
        packet, claim, evidence, document = _decode(packet, backend)
        op = packet['operation']; database = Path(root).absolute() / 'fox.sqlite3'
        clock = now or datetime.now(timezone.utc)
        _need(isinstance(clock, datetime) and clock.tzinfo is not None, 'RECOVERY_CLOCK_REQUIRED')
        if op == 'read_closed_state':
            return _read_closed_snapshot(backend, database, claim, document)
        reviewed, configured = _reviewed(backend, approved_synchronous_launches, claim, evidence)
        if op == 'lookup_resolution':
            store = backend.VerificationRecovery(database, enabled=True, approved_synchronous_launches=configured)
            with store._db() as db:
                exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='verification_failed_dispositions'").fetchone()
            return _ack(backend, store.lookup_resolution(backend.disposition_sha256(document)) if exists else None, document)
        _need(op != 'resolve_failure' or allow_apply is True, 'EXPLICIT_RECOVERY_APPLY_REQUIRED')
        producer, snapshot = _probe(backend, database, observer, claim, evidence, now, reviewed)
        if op == 'observe':
            return producer
        _need(type(next_reader) is NextReaderCapability, 'NEXT_READER_CAPABILITY_REQUIRED')
        # Historical disposition bytes remain unchanged. A fresh probe may
        # differ only in observation time, never in identity/outcome evidence.
        original_time = backend._time(document['producer']['observed_at_utc'])
        _need(original_time <= clock.timestamp() + 5, 'RECOVERY_DISPOSITION_TIME_INVALID')
        original = backend.validate_failed_evidence(binding=claim.binding, **evidence, producer=document['producer'],
            now=datetime.fromtimestamp(original_time, timezone.utc), reviewed_synchronous_launch=reviewed)
        _need(original == document and {k: v for k, v in producer.items() if k != 'observed_at_utc'} ==
              {k: v for k, v in document['producer'].items() if k != 'observed_at_utc'}, 'RECOVERY_OBSERVATION_CHANGED')
        _reader_check(next_reader, backend, snapshot, claim, document)
        def fresh_probe(binding, session, qa_run):
            _need(binding == claim.binding and session == document['session_id'] and qa_run == document['qa_run_id'],
                  'RECOVERY_PROBE_REBOUND')
            return _probe(backend, database, observer, claim, evidence, now, reviewed)[0]
        store = backend.VerificationRecovery(database, enabled=True, producer_probe=fresh_probe,
                                              approved_synchronous_launches=configured)
        # Never bootstrap until the separately configured reader passed. This
        # is the only schema/fence write path, and it requires explicit apply.
        store.initialize()
        return _ack(backend, store.record_failure(claim, backend.canonical_bytes(document), evidence=evidence, now=now), document)
    except RecoveryTransportError:
        raise
    except Exception:
        raise RecoveryTransportError('RECOVERY_INJECTED_OUTCOME_UNCONFIRMED_NO_REPLAY') from None


class FailureRecoveryTransport:
    """FailureResolver-compatible callable. No executor means hard unavailable."""
    def __init__(self, manifest, expected_release_sha256, *, executor=None, allow_apply=False):
        self.manifest = _manifest(manifest, expected_release_sha256)
        _need(executor is None or callable(executor), 'RECOVERY_EXECUTOR_INVALID')
        _need(type(allow_apply) is bool, 'RECOVERY_APPLY_CONFIGURATION_INVALID')
        self.executor, self.allow_apply = executor, allow_apply
        self.attempted = set()

    def __call__(self, operation, *, claim, evidence, operator_lease=None):
        # The existing resolver issues this capability only while its actual
        # OS lock descriptor is held. It never travels in the JSON packet.
        from qa.operator.failed_verification import HeldOperatorLock
        try:
            _need(type(operator_lease) is HeldOperatorLock, 'ACTIVE_OPERATOR_LEASE_REQUIRED')
            operator_lease.require_active(ACTIVE_RELEASE)
        except Exception:
            raise RecoveryTransportError('ACTIVE_OPERATOR_LEASE_REQUIRED') from None
        _need(type(operation) is str and operation in OPS, 'RECOVERY_OPERATION_INVALID')
        _need(self.executor is not None, 'LIVE_RECOVERY_TRANSPORT_UNAVAILABLE')
        _need(operation != 'resolve_failure' or self.allow_apply, 'EXPLICIT_RECOVERY_APPLY_REQUIRED')
        packet = _wire(operation, claim, evidence, self.manifest, ACTIVE_RELEASE, operation == 'resolve_failure')
        if operation == 'resolve_failure':
            key = packet['evidence']['disposition_sha256']
            _need(key not in self.attempted, 'RECOVERY_LOOKUP_ONLY_AFTER_ATTEMPT')
            self.attempted.add(key)
        try:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                source = backend_source()
                operator_lease.require_active(ACTIVE_RELEASE)
                result = self.executor(packet, source=source, operator_lease=operator_lease)
                operator_lease.require_active(ACTIVE_RELEASE)
            # Do not return arbitrary executor fields/logs. The frozen backend
            # validates observation/acknowledgement again at both boundaries.
            backend = _load_backend(backend_source())
            _, bound_claim, decoded, document = _decode(packet, backend)
            if operation == 'observe':
                # Full proof validation is owned by FailureResolver and by the
                # injected protected executor, which has the reviewed contract.
                return _observation_projection(backend, result, bound_claim, decoded)
            if operation == 'read_closed_state':
                return _closed_state_projection(backend, result, document)
            return _ack(backend, result, document)
        except Exception:
            raise RecoveryTransportError('RECOVERY_TRANSPORT_OUTCOME_UNCONFIRMED_LOOKUP_ONLY') from None


class ClosedFailureReadAdapter:
    """Exact-type local closure bridge; one locked read-only transport call.

    The resolver and transport must be real configured instances, never duck
    types or subclasses. A missing real executor remains unavailable. No lock
    acquisition, observation, initialization or resolution is performed here.
    """
    def __init__(self, resolver, transport):
        from qa.operator.failed_verification import FailureResolver
        _need(type(resolver) is FailureResolver and type(transport) is FailureRecoveryTransport,
              'EXACT_CLOSED_READ_ADAPTER_COMPONENTS_REQUIRED')
        _need(resolver.release == ACTIVE_RELEASE
              and _canonical(resolver.manifest) == _canonical(_manifest(transport.manifest, ACTIVE_RELEASE)),
              'RECOVERY_CLOSED_READER_RELEASE_CHANGED')
        self.resolver, self.transport = resolver, transport

    def read_closed_state(self, disposition_sha256, job_id, lease):
        from qa.operator.failed_verification import FailureResolver, HeldOperatorLock
        try:
            _need(type(self) is ClosedFailureReadAdapter and type(self.resolver) is FailureResolver
                  and type(self.transport) is FailureRecoveryTransport and type(lease) is HeldOperatorLock,
                  'EXACT_CLOSED_READ_ADAPTER_COMPONENTS_REQUIRED')
            lease.require_active(ACTIVE_RELEASE, self.resolver.root)
            _need(self.resolver._require_lease() is lease and self.resolver.release == ACTIVE_RELEASE
                  and _canonical(self.resolver.manifest) == _canonical(_manifest(self.transport.manifest, ACTIVE_RELEASE)),
                  'RECOVERY_CLOSED_READER_RELEASE_CHANGED')
            _need(_sha(disposition_sha256) and type(job_id) is str and re.fullmatch(r'fox-[a-f0-9]{20}', job_id),
                  'RECOVERY_CLOSED_READER_BINDING_INVALID')
            acknowledgement = self.resolver._validated_closed_under_lock(lease)
            document = acknowledgement['disposition']
            _need(acknowledgement['disposition_sha256'] == disposition_sha256
                  and document['binding']['job_id'] == job_id
                  and document['binding']['verifier_release_sha256'] == ACTIVE_RELEASE,
                  'RECOVERY_CLOSED_READER_BINDING_CHANGED')
            claim, evidence = self.resolver._local()
            _need(claim.binding.payload() == document['binding']
                  and self.resolver._validate(evidence, document['producer'], historical=True) == document,
                  'RECOVERY_CLOSED_READER_EVIDENCE_CHANGED')
            lease.require_active(ACTIVE_RELEASE, self.resolver.root)
            return self.transport('read_closed_state', claim=claim, evidence={**evidence,
                'disposition': document, 'disposition_sha256': disposition_sha256}, operator_lease=lease)
        except Exception:
            raise RecoveryTransportError('RECOVERY_CLOSED_READ_UNCONFIRMED') from None


def dispatch(*args, **kwargs):
    """There is intentionally no real executor or enabling flag in this slice."""
    raise RecoveryTransportError('LIVE_RECOVERY_TRANSPORT_UNAVAILABLE')


def container_source():
    """Generate an inert library, not an SSH command, launcher or ready service.

    A future separately reviewed adapter must provide target attestation,
    exclusion locking, installed-dependency checks and a real trusted observer.
    Merely executing these definitions performs no DB/file/process/network I/O.
    """
    constants = ('ACTIVE_RELEASE', 'FOX_IMAGE', 'FOX_CONTAINER', 'BACKEND_SHA256', 'INSTANCE', 'COMPARTMENT',
                 'REGION', 'OPS', 'BYTE_KEYS', 'FILE_NAMES', 'PROBE_FILES', 'REVIEW_FIELDS', 'MAX_PACKET')
    source = ('import base64,hashlib,inspect,io,json,re,sqlite3,sys,types\n'
              'from contextlib import closing,redirect_stdout,redirect_stderr\n'
              'from dataclasses import dataclass,field,fields,is_dataclass\n'
              'from datetime import datetime,timezone\nfrom pathlib import Path\n'
              + '\n'.join(key + '=' + repr(globals()[key]) for key in constants) + '\n')
    source += '\n'.join(inspect.getsource(item) for item in (RecoveryTransportError, _need, _sha, _image, _canonical,
        _digest, _json, _manifest, _load_backend, PinnedIdentity, HostProbeInput, NextReaderCapability,
        _bytes, _unbytes, _evidence_fields, _decode, _snapshot, _reviewed, _probe, _reader_check, _ack,
        _eligibility_projection, _closed_state_projection, _read_closed_snapshot, _observation_projection,
        execute_injected, dispatch))
    return source + '\nPINNED_BACKEND_B64=' + repr(base64.b64encode(backend_source()).decode('ascii')) + '\n'
