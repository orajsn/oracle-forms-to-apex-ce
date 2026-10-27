"""Synthetic local-only recovery ledger tests; no private/live journal is used."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from copy import deepcopy
from datetime import timedelta
import io
import importlib.util
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import tempfile
from threading import Barrier

import pytest

_IMPORT = tempfile.TemporaryDirectory(prefix='fox-recovery-import-')
_OLD_ENV = {key: os.environ.get(key) for key in ('FOX_DATA_DIR', 'FOX_VERIFICATION_ENABLED')}
os.environ.update(FOX_DATA_DIR=_IMPORT.name, FOX_VERIFICATION_ENABLED='0')
try:
    from fox import verification_recovery as recovery
    from fox.verification_queue import Claim, VerificationBinding, VerificationQueue, TechnicalProofResult
    from test_native_pipeline import harness, valid_package, NativeHarness
    from test_native_verification import proof_case, NOW
    from test_native_verification_policy import v2_case, independent_case
finally:
    for _key, _value in _OLD_ENV.items():
        if _value is None:
            os.environ.pop(_key, None)
        else:
            os.environ[_key] = _value

OLD_RELEASE, NEW_RELEASE = 'a' * 64, 'b' * 64
IMAGE, QA_SOURCE = 'sha256:' + 'c' * 64, 'd' * 64
SESSION, QA_RUN = 'session-' + 'e' * 24, 'FQ-20261017T001000-aaaaaaaa'
cb, sha = recovery.canonical_bytes, recovery.digest


@pytest.fixture(autouse=True)
def no_external_actions(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail('Recovery tests must not use network or subprocess')
    monkeypatch.setattr(socket, 'create_connection', blocked)
    monkeypatch.setattr(socket.socket, 'connect', blocked)
    monkeypatch.setattr(subprocess, 'run', blocked)
    monkeypatch.setattr(subprocess, 'Popen', blocked)
    # Generate fresh mocked packages with the real operator's job-derived alias;
    # do not mutate a sealed package or the shared fixture implementation.
    original_identity, original_evidence = NativeHarness.import_identity, NativeHarness.evidence
    def identity(self):
        value = original_identity(self)
        value['application_alias'] = 'F2A_' + self.job.name.upper().replace('-', '_')
        return value
    def evidence(self):
        value = original_evidence(self)
        value['package_reimport']['application_alias'] = identity(self)['application_alias'] + '_SQLCHECK'
        return value
    monkeypatch.setattr(NativeHarness, 'import_identity', identity)
    monkeypatch.setattr(NativeHarness, 'evidence', evidence)


def failed_bundle(original):
    """Build exact synthetic FAILED receipts, never a fabricated passing copy."""
    case = deepcopy(original)
    binding = VerificationBinding(case['release']['job_id'], case['snapshot']['source_hash'],
                                  sha(case['package']), OLD_RELEASE)
    allocation = json.loads(case['allocation_raw'])
    release, target = case['release'], allocation['target']
    with recovery.zipfile.ZipFile(io.BytesIO(case['package'])) as archive:
        native_raw = archive.read('native-form-spec.json')
        sql_member, schema_member = 'sql/f' + str(release['application_id']) + '.sql', 'schema/01_synthetic_schema.sql'
        native = json.loads(native_raw)
        plan = {'schema_version': 1, 'scope': 'fox-clean-install-plan-v2', 'policy_id': 'jsn-clean-native-v2',
            'created_at_utc': '2026-10-17T00:00:00Z', 'operator_code_sha256': 'f' * 64,
            'source_origin': {'schema_version': 1, 'scope': 'fox-private-job-package-read-v1',
                'observed_at_utc': '2026-10-16T23:59:00Z', 'instance_id': target['instance_id'],
                'compartment_id': target['compartment_id'], 'region': target['region'],
                **plan_raw_identity(binding), 'package_bytes': len(case['package']), 'run_state': 'QA_REQUIRED'},
            'target': {key: value for key, value in target.items() if key not in {'workspace_id', 'application_id'}},
            'expected_versions': case['verification_policy'].versions,
            'binding': {**plan_raw_identity(binding), 'source_application_id': release['application_id'],
                'source_application_alias': release['application_alias'],
                'source_reimport_application_id': release['package_reimport']['application_id'],
                'source_reimport_application_alias': release['package_reimport']['application_alias'],
                'sql_member': sql_member, 'schema_member': schema_member,
                'sql_sha256': sha(archive.read(sql_member)), 'schema_script_sha256': sha(archive.read(schema_member)),
                'native_spec_sha256': sha(native_raw), 'table_name': native['table_name'], 'profile_id': native['profile_id']}}
    plan_raw = cb(plan)
    allocation.update(plan_sha256=sha(plan_raw), allocated_at_utc='2026-10-17T00:00:00Z')
    allocation_raw = cb(allocation)
    profile = case['verification_policy'].document
    profile['binding']['allocation_receipt_sha256'] = sha(allocation_raw)
    policy_raw = cb(profile)
    clean = case['clean']; clean.update(allocation_receipt_sha256=sha(allocation_raw), verification_profile_sha256=sha(policy_raw))
    target = case['target']; target.update(allocation_receipt_sha256=sha(allocation_raw),
        verification_profile_sha256=sha(policy_raw), import_receipt_sha256=sha(cb(clean)), profile_sha256=sha(cb(case['profile'])))
    qa = case['qa']; qa.update(status='FAILED', dispatch_state='ATTEMPT_INCOMPLETE', run_id=QA_RUN,
        target=target, target_receipt_sha256=sha(cb(target)), runtime={'image_id': IMAGE})
    qa['binding'].update(verification_profile_sha256=sha(policy_raw), allocation_receipt_sha256=sha(allocation_raw))
    failed = next(item for item in qa['tests'] if item['name'] == 'concurrent_edit')
    failed.update(status='FAILED', field_results=[], evidence={}, reason='Synthetic requests did not settle before concurrent saves')
    stage = {'status': 'STAGED', 'plan_sha256': sha(plan_raw), 'source_sha256': QA_SOURCE,
             'allocation_receipt_sha256': sha(allocation_raw), 'image_id': IMAGE}
    launch = {'status': 'QA_FAILED_OR_INCOMPLETE', 'exit_code': 2, 'plan_sha256': sha(plan_raw),
              'source_sha256': QA_SOURCE, 'image_id': IMAGE, 'automatic_replay_permitted': False}
    intent = {'scope': 'fox-native-qa-launch-v2', 'state': 'LAUNCH_INTENT_NO_AUTOMATIC_REPLAY',
              'allocation_receipt_sha256': sha(allocation_raw), 'plan_sha256': sha(plan_raw),
              'source_sha256': QA_SOURCE, 'image_id': IMAGE}
    dispatch = {'scope': 'fox-native-qa-dispatch-v2', 'state': 'ATTEMPT_STARTED_NO_AUTOMATIC_REPLAY',
                'run_id': QA_RUN, 'job_id': binding.job_id, 'package_sha256': binding.package_sha256,
                'allocation_receipt_sha256': sha(allocation_raw), 'verification_profile_sha256': sha(policy_raw),
                'target_receipt_sha256': sha(cb(target)), 'profile_sha256': sha(cb(case['profile'])),
                'test_plan_sha256': qa['test_plan_sha256'], 'image_id': IMAGE}
    files = {'package.zip': case['package'], 'native-form-spec.json': native_raw,
             'allocation-receipt.json': allocation_raw, 'verification-profile.json': policy_raw,
             'clean-import-receipt.json': cb(clean), 'qa-profile.json': cb(case['profile']),
             'target-receipt.json': cb(target), 'qa-result.json': cb(qa),
             'stage-receipt.json': cb(stage), 'launch-receipt.json': cb(launch),
             'launch-intent.json': cb(intent), 'dispatch-receipt.json': cb(dispatch)}
    collection = {'status': 'COLLECTED', 'plan_sha256': sha(plan_raw), 'source_sha256': QA_SOURCE,
                  'credentials_and_logs_excluded': True, 'sha256': {name: sha(raw) for name, raw in files.items()}}
    collection_raw = cb(collection)
    results = {
        'prepare': {**plan_raw_identity(binding), 'plan_sha256': sha(plan_raw), 'operator_code_sha256': 'f' * 64},
        'clean_check': {'state': 'PREPARED', 'plan_sha256': sha(plan_raw)},
        'qa_stage': stage,
        'qa_run': {key: launch[key] for key in ('status', 'exit_code', 'plan_sha256', 'source_sha256', 'image_id')},
        'qa_collect': {'status': 'COLLECTED', 'plan_sha256': sha(plan_raw), 'source_sha256': QA_SOURCE,
                       'collection_manifest_sha256': sha(collection_raw)},
    }
    for phase in ('allocate', 'schema', 'import', 'verify'):
        results[phase] = {'state': 'QA_READY' if phase == 'verify' else 'PHASE_COMPLETE',
                         'action': 'COMPLETED_ONCE', 'plan_sha256': sha(plan_raw),
                         'evidence_sha256': sha(files['allocation-receipt.json']) if phase == 'allocate'
                         else sha(files['clean-import-receipt.json']) if phase == 'verify' else sha(phase.encode())}
    retained, phases = {'session.json': sha(b'synthetic session'), 'attention.json': sha(b'synthetic attention')}, {}
    for index, phase in enumerate(recovery.PHASES):
        intention = cb({'phase': phase, 'binding': binding.payload()})
        completion = cb({'intent_sha256': sha(intention), 'result': results[phase]})
        retained[f'p0001-{phase.replace("_", "-")}.intent.json'] = sha(intention)
        retained[f'p0001-{phase.replace("_", "-")}.complete.json'] = sha(completion)
        phases[phase] = {'intent_sha256': sha(intention), 'completion_sha256': sha(completion), 'result': results[phase]}
    summary = {'schema_version': 1, 'scope': 'fox-verification-failed-journal-summary-v1',
               'session_id': SESSION, 'release_sha256': OLD_RELEASE,
               'binding_sha256': sha(cb(binding.payload())), 'claim_sha256': '0' * 64,
               'retained_sha256': retained, 'phases': phases, 'unresolved_intents': [],
               'promotion_attempted': False, 'queue_completion_attempted': False}
    producer = {'schema_version': 1, 'scope': 'fox-verification-producer-observation-v1',
                'binding_sha256': sha(cb(binding.payload())), 'session_id': SESSION, 'qa_run_id': QA_RUN,
                'container_id': '1' * 64, 'image_id': IMAGE, 'state': 'STOPPED', 'exit_code': 2,
                'observed_at_utc': NOW.isoformat(), 'live_producer_count': 0, 'unresolved_phase_count': 0,
                'technical_proof_count': 0, 'human_acceptance_count': 0}
    return {'binding': binding, 'package': case['package'], 'plan_raw': plan_raw, 'collection_raw': collection_raw,
            'files': files, 'journal_summary': summary, 'producer': producer, 'now': NOW,
            'snapshot': case['snapshot'], 'release': case['release']}


def plan_raw_identity(binding):
    return {key: value for key, value in binding.payload().items() if key != 'verifier_release_sha256'}


def arguments(bundle):
    return {key: value for key, value in bundle.items() if key not in ('snapshot', 'release')}


def reseal_collection(bundle):
    """Rebind downstream raw hashes so negatives exercise the intended guard."""
    collection = json.loads(bundle['collection_raw'])
    collection['sha256'] = {name: sha(raw) for name, raw in bundle['files'].items()}
    bundle['collection_raw'] = cb(collection)
    summary = bundle['journal_summary']
    result = summary['phases']['qa_collect']['result']
    result['collection_manifest_sha256'] = sha(bundle['collection_raw'])
    completion = cb({'intent_sha256': summary['phases']['qa_collect']['intent_sha256'], 'result': result})
    summary['phases']['qa_collect']['completion_sha256'] = sha(completion)
    summary['retained_sha256']['p0001-qa-collect.complete.json'] = sha(completion)


def seed(root, bundle):
    root.mkdir(exist_ok=True)
    database = root / 'fox.sqlite3'
    with closing(sqlite3.connect(database)) as db, db:
        db.executescript('''
            CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY,project TEXT,source_hash TEXT,state TEXT,
                message TEXT,created REAL,updated REAL,artifact TEXT);
            CREATE TABLE IF NOT EXISTS acceptances(run TEXT,owner TEXT,notes TEXT);
            CREATE TABLE IF NOT EXISTS events(action TEXT,object_id TEXT);
            CREATE TABLE IF NOT EXISTS technical_verifications(run TEXT PRIMARY KEY,source_hash TEXT,
                artifact_sha256 TEXT,proof_sha256 TEXT,proof_json TEXT,created REAL);
        ''')
        binding = bundle['binding']; job = root / 'jobs' / binding.job_id
        db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)', (binding.job_id, 'synthetic-recovery',
            binding.source_manifest_sha256, 'QA_REQUIRED', 'Synthetic failed verification', 1.0, 1.0,
            str((job / 'apex-package.zip').relative_to(root))))
    (job / 'native-pipeline').mkdir(parents=True)
    (job / 'apex-package.zip').write_bytes(bundle['package'])
    (job / 'source-snapshot.json').write_bytes(cb(bundle['snapshot']))
    (job / 'release-evidence.json').write_bytes(cb(bundle['release']))
    (job / 'native-pipeline/download.json').write_bytes(cb({
        'source_hash': binding.source_manifest_sha256, 'package_sha256': binding.package_sha256}))
    queue = VerificationQueue(database, enabled=True, verifier_release_sha256=OLD_RELEASE)
    queue.initialize(); queue.enqueue(binding); claim = queue.claim_next(); queue.attention(claim)
    bundle['journal_summary']['claim_sha256'] = recovery.claim_sha256(claim)
    return database, queue, claim


@pytest.fixture
def example(v2_case, tmp_path):
    bundle = failed_bundle(v2_case)
    database, queue, claim = seed(tmp_path / 'recovery', bundle)
    probes = []
    def probe(binding, session, qa_run):
        assert (binding, session, qa_run) == (bundle['binding'], SESSION, QA_RUN)
        probes.append(1)
        return deepcopy(bundle['producer'])
    store = recovery.VerificationRecovery(database, enabled=True, producer_probe=probe,
                                          approved_retry_releases=[NEW_RELEASE])
    store.initialize()
    return bundle, database, queue, claim, store, probes


def disposition(example):
    return recovery.validate_failed_evidence(**arguments(example[0]))


def record(example):
    bundle, _, _, claim, store, _ = example
    document = disposition(example)
    evidence = {key: bundle[key] for key in ('package', 'plan_raw', 'collection_raw', 'files', 'journal_summary')}
    return store.record_failure(claim, cb(document), evidence=evidence, now=NOW)


def request(document, *, number=1, release=NEW_RELEASE):
    return recovery.make_retry_request(document, request_id='request-' + f'{number:032x}',
        attempt_id='attempt-' + f'{number:032x}', verifier_release_sha256=release)


def preserved(database):
    with closing(sqlite3.connect(database)) as db:
        return {table: list(db.execute('SELECT * FROM ' + table)) for table in
                ('runs', 'verification_queue', 'technical_verifications', 'acceptances', 'events')}


def count(database, table):
    with closing(sqlite3.connect(database)) as db:
        return db.execute('SELECT COUNT(*) FROM ' + table).fetchone()[0]


def test_disabled_store_is_inert_without_storage_or_transport(tmp_path, monkeypatch):
    calls = []
    store = recovery.VerificationRecovery(tmp_path / 'absent.sqlite3', producer_probe=lambda *args: calls.append(args))
    monkeypatch.setattr(sqlite3, 'connect', lambda *a, **k: pytest.fail('disabled storage access'))
    with pytest.raises(recovery.RecoveryError, match='DISABLED'): store.initialize()
    assert store.eligibility('fox-' + 'a' * 20)['blocks_admission'] is True
    assert not (tmp_path / 'absent.sqlite3').exists() and calls == []


def test_terminal_failed_disposition_is_not_success_and_is_create_only(example):
    bundle, database, _, claim, store, probes = example
    original, files = preserved(database), {path: path.read_bytes() for path in database.parent.rglob('*') if path.is_file() and path.name != 'fox.sqlite3'}
    first = record(example)
    assert first['status'] == 'FAILED_QA_RECORDED'
    assert first['disposition']['failure_class'] == 'TERMINAL_QA_FAILED'
    assert first['disposition']['human_acceptance_recorded'] is False
    assert first['disposition']['automatic_retry_permitted'] is False
    assert claim.attempt_token not in json.dumps(first)
    assert preserved(database) == original and len(probes) == 1
    assert {path: path.read_bytes() for path in files} == files
    assert store.eligibility(claim.binding.job_id) == {
        'blocks_admission': False, 'recovery_state': 'failed_closed', 'retry_eligible': True}
    # Lost reply: immutable readback succeeds; an identical explicit request
    # cannot append another disposition or re-observe/re-run the producer.
    assert store.lookup_resolution(first['disposition_sha256']) == first
    again = store.record_failure(claim, cb(first['disposition']), evidence=None, now=NOW + timedelta(days=10))
    assert again == first and len(probes) == 1
    assert count(database, 'verification_failed_dispositions') == 1


@pytest.mark.parametrize('mutation,code', [
    ('incomplete', 'TERMINAL_FAILED_REPORT_REQUIRED'), ('passed', 'TERMINAL_FAILED_REPORT_REQUIRED'),
    ('missing_finished', 'UTC_REQUIRED'), ('wrong_dispatch', 'TERMINAL_FAILED_REPORT_REQUIRED'),
    ('no_failed_case', 'APPLICABLE_FAILURE_REQUIRED'), ('wrong_plan', 'PLAN_DIFFERS'),
    ('missing_case', 'CASE_SET_INVALID'), ('duplicate_case', 'CASE_SET_INVALID'),
    ('invalid_na', 'APPLICABILITY_CHANGED'), ('wrong_field_results', 'FIELD_RESULTS_CHANGED'),
    ('unknown_status', 'CASE_OUTCOME_UNKNOWN')])
def test_unknown_or_malformed_failed_reports_never_close(example, mutation, code):
    bundle = deepcopy(example[0]); qa = json.loads(bundle['files']['qa-result.json'])
    failed = next(item for item in qa['tests'] if item['name'] == 'concurrent_edit')
    if mutation == 'incomplete': qa['status'] = 'INCOMPLETE'
    if mutation == 'passed': qa['status'] = 'PASSED'
    if mutation == 'missing_finished': del qa['finished_at']
    if mutation == 'wrong_dispatch': qa['dispatch_state'] = 'ATTEMPT_COMPLETED'
    if mutation == 'no_failed_case':
        failed.update(status='NOT_RUN', reason='Not reached')
    if mutation == 'wrong_plan': qa['test_plan_sha256'] = '0' * 64
    if mutation == 'missing_case': qa['tests'].pop()
    if mutation == 'duplicate_case': qa['tests'][-1] = deepcopy(qa['tests'][0])
    if mutation == 'invalid_na': failed.update(status='NOT_APPLICABLE', applicable=False, required=False, field_names=[], field_results=[])
    if mutation == 'wrong_field_results': failed['field_results'] = [{'field_name': 'UNKNOWN', 'status': 'PASSED'}]
    if mutation == 'unknown_status': failed['status'] = 'UNKNOWN'
    bundle['files']['qa-result.json'] = cb(qa)
    reseal_collection(bundle)
    with pytest.raises(recovery.RecoveryError, match=code): recovery.validate_failed_evidence(**arguments(bundle))
    assert count(example[1], 'verification_failed_dispositions') == 0


def test_positive_failed_fixture_retains_full_canonical_operator_plan(example):
    path = Path(__file__).resolve().parents[2] / 'qa/operator/contracts.py'
    spec = importlib.util.spec_from_file_location('recovery_test_clean_contracts', path)
    contracts = importlib.util.module_from_spec(spec); spec.loader.exec_module(contracts)
    plan = contracts.validate_plan(example[0]['plan_raw'])
    assert plan['binding']['package_sha256'] == example[0]['binding'].package_sha256
    assert disposition(example)['failure_class'] == 'TERMINAL_QA_FAILED'


@pytest.mark.parametrize('mutation,code', [
    ('scope', 'CONTRACT_CHANGED'), ('version_bool', 'CONTRACT_CHANGED'), ('unknown_key', 'CONTRACT_CHANGED'),
    ('binding_only', 'CONTRACT_CHANGED'), ('noncanonical', 'CONTRACT_CHANGED'),
    ('target', 'TARGET_CHANGED'), ('versions', 'TARGET_CHANGED'), ('namespace_date', 'TARGET_CHANGED'),
    ('future_creation', 'TARGET_CHANGED'), ('origin_scope', 'ORIGIN_CHANGED'),
    ('origin_instance', 'ORIGIN_CHANGED'), ('origin_stale', 'ORIGIN_CHANGED'),
    ('origin_package_count', 'ORIGIN_CHANGED'), ('origin_job', 'ORIGIN_CHANGED'),
    ('sql_hash', 'PACKAGE_CHANGED'), ('member', 'PACKAGE_CHANGED'), ('source_app', 'PACKAGE_CHANGED'),
    ('source_alias', 'PACKAGE_CHANGED'), ('native_hash', 'PACKAGE_CHANGED')])
def test_clean_plan_contract_is_checked_independently_of_outer_hashes(example, mutation, code):
    bundle = example[0]; plan = json.loads(bundle['plan_raw'])
    if mutation == 'scope': plan['scope'] = 'other'
    if mutation == 'version_bool': plan['schema_version'] = True
    if mutation == 'unknown_key': plan['unexpected'] = True
    if mutation == 'binding_only': plan = {key: plan[key] for key in ('schema_version', 'scope', 'binding')}
    if mutation == 'target': plan['target']['workspace'] = 'FOX_QA_261017_DEADBEEF'
    if mutation == 'versions': plan['expected_versions']['apex'] = 'unknown'
    if mutation == 'namespace_date': plan['created_at_utc'] = '2026-10-16T23:59:00Z'
    if mutation == 'future_creation': plan['created_at_utc'] = '2026-10-17T00:00:01Z'
    if mutation == 'origin_scope': plan['source_origin']['scope'] = 'untrusted-upload'
    if mutation == 'origin_instance': plan['source_origin']['instance_id'] = 'elsewhere'
    if mutation == 'origin_stale': plan['source_origin']['observed_at_utc'] = '2026-10-15T00:00:00Z'
    if mutation == 'origin_package_count': plan['source_origin']['package_bytes'] += 1
    if mutation == 'origin_job': plan['source_origin']['job_id'] = 'fox-' + '9' * 20
    if mutation == 'sql_hash': plan['binding']['sql_sha256'] = '0' * 64
    if mutation == 'member': plan['binding']['sql_member'] = 'sql/f99999.sql'
    if mutation == 'source_app': plan['binding']['source_application_id'] += 1
    if mutation == 'source_alias': plan['binding']['source_application_alias'] = 'OTHER'
    if mutation == 'native_hash': plan['binding']['native_spec_sha256'] = '0' * 64
    raw = cb(plan) + (b'\n' if mutation == 'noncanonical' else b'')
    policy = recovery.BoundVerificationPolicy(bundle['files']['verification-profile.json'], historical=True)
    allocation = recovery.validate_allocation_receipt(bundle['files']['allocation-receipt.json'], policy)
    with recovery.zipfile.ZipFile(io.BytesIO(bundle['package'])) as archive:
        member_hashes = {name: sha(archive.read(name)) for name in
            ('sql/f' + str(bundle['release']['application_id']) + '.sql', 'schema/01_synthetic_schema.sql')}
    with pytest.raises(recovery.RecoveryError, match='CLEAN_PLAN_' + code):
        recovery._retained_plan(plan, raw, binding=bundle['binding'], package=bundle['package'],
            native=bundle['snapshot']['native_form'], native_raw=bundle['files']['native-form-spec.json'],
            release=bundle['release'], member_hashes=member_hashes, policy=policy, allocation=allocation)


def browser_failure_bundle(example, count=1):
    bundle = deepcopy(example[0]); qa = json.loads(bundle['files']['qa-result.json'])
    case = next(item for item in qa['tests'] if item['name'] == 'browser_runtime_errors')
    case.update(status='FAILED', field_results=[], evidence={'unhandled_error_count': count})
    case.pop('reason', None)
    qa['browser_errors'] = [{'message': 'Synthetic unhandled browser error'}]
    bundle['files']['qa-result.json'] = cb(qa); reseal_collection(bundle)
    return bundle


def test_actual_browser_error_failure_shape_is_known_failure_not_success(example):
    bundle = browser_failure_bundle(example)
    assert recovery.validate_failed_evidence(**arguments(bundle))['failure_class'] == 'TERMINAL_QA_FAILED'


@pytest.mark.parametrize('count', [0, 2, True, '1', None])
def test_browser_error_without_reason_needs_exact_positive_error_count(example, count):
    with pytest.raises(recovery.RecoveryError, match='FAILED_OR_UNRUN_REASON_REQUIRED'):
        recovery.validate_failed_evidence(**arguments(browser_failure_bundle(example, count)))


def test_other_failed_case_cannot_borrow_browser_error_exception(example):
    bundle = deepcopy(example[0]); qa = json.loads(bundle['files']['qa-result.json'])
    case = next(item for item in qa['tests'] if item['name'] == 'concurrent_edit')
    case.pop('reason'); case['evidence'] = {'unhandled_error_count': 1}
    qa['browser_errors'] = [{'message': 'Synthetic error'}]
    bundle['files']['qa-result.json'] = cb(qa); reseal_collection(bundle)
    with pytest.raises(recovery.RecoveryError, match='FAILED_OR_UNRUN_REASON_REQUIRED'):
        recovery.validate_failed_evidence(**arguments(bundle))


@pytest.mark.parametrize('key,value', [('state', 'RUNNING'), ('exit_code', 124), ('exit_code', 137),
    ('live_producer_count', 1), ('unresolved_phase_count', 1), ('technical_proof_count', 1),
    ('human_acceptance_count', 1), ('container_id', 'unknown'), ('observed_at_utc', '2026-10-16T00:00:00Z')])
def test_live_unknown_or_stale_producer_fails_closed(example, key, value):
    bundle = deepcopy(example[0]); bundle['producer'][key] = value
    with pytest.raises(recovery.RecoveryError): recovery.validate_failed_evidence(**arguments(bundle))


@pytest.mark.parametrize('phase', recovery.PHASES)
def test_missing_or_changed_phase_completion_is_not_a_closed_failure(example, phase):
    bundle = deepcopy(example[0])
    del bundle['journal_summary']['phases'][phase]
    with pytest.raises(recovery.RecoveryError): recovery.validate_failed_evidence(**arguments(bundle))


@pytest.mark.parametrize('mutation', ['all_session_hash', 'swapped_phase_hash', 'unpaired_intent', 'promotion_intent'])
def test_phase_hashes_must_bind_their_exact_role_and_claim_prefix(example, mutation):
    bundle = deepcopy(example[0]); summary = bundle['journal_summary']
    if mutation == 'all_session_hash':
        for value in summary['phases'].values():
            value['intent_sha256'] = value['completion_sha256'] = summary['retained_sha256']['session.json']
    elif mutation == 'swapped_phase_hash':
        summary['phases']['schema']['intent_sha256'] = summary['phases']['import']['intent_sha256']
    elif mutation == 'unpaired_intent':
        summary['retained_sha256']['p9999-prepare.intent.json'] = '9' * 64
    else:
        summary['retained_sha256'].update({'p0001-promotion-apply.intent.json': '8' * 64,
                                           'p0001-promotion-apply.complete.json': '7' * 64})
    with pytest.raises(recovery.RecoveryError): recovery.validate_failed_evidence(**arguments(bundle))


def test_valid_request_json_without_authoritative_probe_cannot_record(example):
    bundle, database, _, claim, _, _ = example
    store = recovery.VerificationRecovery(database, enabled=True)
    document = disposition(example)
    evidence = {key: bundle[key] for key in ('package', 'plan_raw', 'collection_raw', 'files', 'journal_summary')}
    with pytest.raises(recovery.RecoveryError, match='AUTHORITATIVE_PROBE'):
        store.record_failure(claim, cb(document), evidence=evidence, now=NOW)
    assert count(database, 'verification_failed_dispositions') == 0


def test_authoritative_probe_must_match_request_and_still_be_stopped(example):
    document = disposition(example)
    example[0]['producer']['state'] = 'RUNNING'
    evidence = {key: example[0][key] for key in ('package', 'plan_raw', 'collection_raw', 'files', 'journal_summary')}
    with pytest.raises(recovery.RecoveryError):
        example[4].record_failure(example[3], cb(document), evidence=evidence, now=NOW)
    assert count(example[1], 'verification_failed_dispositions') == 0


def test_first_explicit_record_after_delay_keeps_original_digest_but_requires_fresh_probe(example):
    bundle, database, _, claim, store, _ = example
    document = disposition(example); expected = recovery.disposition_sha256(document)
    later = NOW + timedelta(hours=1)
    bundle['producer']['observed_at_utc'] = later.isoformat()
    evidence = {key: bundle[key] for key in ('package', 'plan_raw', 'collection_raw', 'files', 'journal_summary')}
    result = store.record_failure(claim, cb(document), evidence=evidence, now=later)
    assert result['disposition_sha256'] == expected and result['disposition'] == document
    assert count(database, 'verification_failed_dispositions') == 1


def test_retry_is_distinct_release_identity_and_blocks_admission_until_reconciled(example):
    _, database, _, old_claim, store, _ = example
    original = preserved(database)
    closed = record(example); new = request(closed['disposition'])
    first = store.reserve_retry(cb(new), now=NOW)
    assert first['attempt']['state'] == 'reserved' and first['idempotent'] is False
    assert first['attempt']['binding']['verifier_release_sha256'] == NEW_RELEASE
    assert store.eligibility(old_claim.binding.job_id)['blocks_admission'] is True
    second = store.reserve_retry(cb(new), now=NOW)
    assert second['idempotent'] is True and second['attempt'] == first['attempt']
    claim = store.claim_retry(new['attempt_id'])
    assert claim.attempt_token != old_claim.attempt_token
    assert claim.attempt_token not in json.dumps(store.get_attempt(new['attempt_id']))
    with pytest.raises(recovery.RecoveryError): store.claim_retry(new['attempt_id'])
    assert store.mark_retry_attention(claim)['state'] == 'attention'
    assert store.mark_retry_attention(claim)['state'] == 'attention'
    assert store.eligibility(old_claim.binding.job_id)['blocks_admission'] is True
    assert preserved(database) == original
    with pytest.raises(Exception): store.complete_retry(claim, TechnicalProofResult('f' * 64))
    assert preserved(database) == original


@pytest.mark.parametrize('release', [OLD_RELEASE, 'f' * 64])
def test_retry_requires_new_trusted_approved_release(example, release):
    closed = record(example)
    with pytest.raises(recovery.RecoveryError):
        example[4].reserve_retry(cb(request(closed['disposition'], release=release)), now=NOW)
    assert count(example[1], 'verification_retry_attempts') == 0


def test_changed_request_and_second_request_cannot_reuse_closed_failure(example):
    closed = record(example); store = example[4]; first = request(closed['disposition'])
    store.reserve_retry(cb(first), now=NOW)
    changed = deepcopy(first); changed['attempt_id'] = 'attempt-' + 'f' * 32
    with pytest.raises(recovery.RecoveryError): store.reserve_retry(cb(changed), now=NOW)
    with pytest.raises(recovery.RecoveryError): store.reserve_retry(cb(request(closed['disposition'], number=2)), now=NOW)
    assert count(example[1], 'verification_retry_attempts') == 1


def test_closed_failure_fences_existing_legacy_reconciliation(example, monkeypatch):
    _, database, queue, claim, _, _ = example
    record(example); original = preserved(database)
    # Isolate the append-only fence from proof validation: even a future valid
    # proof must not mutate the retired legacy attempt through the old API.
    monkeypatch.setattr(queue, '_validated_proof', lambda *args: None)
    with pytest.raises(Exception): queue.reconcile_completed(claim.binding, TechnicalProofResult('f' * 64))
    assert preserved(database) == original
    with closing(sqlite3.connect(database)) as db, db:
        with pytest.raises(sqlite3.IntegrityError):
            db.execute('DELETE FROM verification_queue WHERE job_id=?', (claim.binding.job_id,))


@pytest.mark.parametrize('table', ['verification_failed_dispositions', 'verification_retry_attempts', 'verification_retry_events'])
def test_recovery_records_are_append_only(example, table):
    closed = record(example); example[4].reserve_retry(cb(request(closed['disposition'])), now=NOW)
    with closing(sqlite3.connect(example[1])) as db, db:
        with pytest.raises(sqlite3.IntegrityError): db.execute('DELETE FROM ' + table)


@pytest.mark.parametrize('side', ['disposition', 'reservation'])
def test_transaction_crashes_leave_no_half_record_and_explicit_request_can_retry(example, monkeypatch, side):
    store, database = example[4], example[1]
    closed = record(example) if side == 'reservation' else None
    original = store._insert
    def crash(db, table, value):
        result = original(db, table, value)
        if table == ('verification_failed_dispositions' if side == 'disposition' else 'verification_retry_attempts'):
            raise OSError('synthetic crash before transaction commit')
        return result
    monkeypatch.setattr(store, '_insert', crash)
    with pytest.raises(OSError):
        record(example) if side == 'disposition' else store.reserve_retry(cb(request(closed['disposition'])), now=NOW)
    table = 'verification_failed_dispositions' if side == 'disposition' else 'verification_retry_attempts'
    assert count(database, table) == 0
    monkeypatch.setattr(store, '_insert', original)
    record(example) if side == 'disposition' else store.reserve_retry(cb(request(closed['disposition'])), now=NOW)
    assert count(database, table) == 1


def test_reservation_race_across_distinct_failed_jobs_has_only_one_active_attempt(example, tmp_path, monkeypatch):
    first = record(example)
    other = failed_bundle(independent_case(tmp_path, monkeypatch, job_letter='b', token='261017_1234ABCD'))
    database, _, claim = seed(example[1].parent, other)
    stores = [
        example[4],
        recovery.VerificationRecovery(database, enabled=True, approved_retry_releases=[NEW_RELEASE],
                                      producer_probe=lambda *args: deepcopy(other['producer']))]
    second_doc = recovery.validate_failed_evidence(**arguments(other))
    evidence = {key: other[key] for key in ('package', 'plan_raw', 'collection_raw', 'files', 'journal_summary')}
    stores[1].record_failure(claim, cb(second_doc), evidence=evidence, now=NOW)
    requests = [request(first['disposition']), request(second_doc, number=2)]
    barrier = Barrier(2)
    def reserve(pair):
        store, value = pair; barrier.wait(timeout=10)
        try: return store.reserve_retry(cb(value), now=NOW)['status']
        except recovery.RecoveryError: return 'BLOCKED'
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(reserve, zip(stores, requests)))
    assert sorted(results) == ['BLOCKED', 'RETRY_RESERVED']
    assert count(database, 'verification_retry_attempts') == 1


@pytest.mark.parametrize('artifact', ['apex-package.zip', 'source-snapshot.json'])
def test_changed_server_artifact_reblocks_closed_failure(example, artifact):
    record(example)
    path = example[1].parent / 'jobs' / example[3].binding.job_id / artifact
    if artifact == 'source-snapshot.json':
        value = json.loads(path.read_bytes()); value['files'][0]['text'] += '\nchanged'
        path.write_bytes(cb(value))
    else: path.write_bytes(path.read_bytes() + b'changed')
    assert example[4].eligibility(example[3].binding.job_id)['blocks_admission'] is True


def test_tampered_closed_record_is_not_an_admission_exception(example):
    acknowledgement = record(example)
    with closing(sqlite3.connect(example[1])) as db, db:
        db.execute('DROP TRIGGER verification_failed_dispositions_no_update')
        db.execute("UPDATE verification_failed_dispositions SET record_sha256=?", ('0' * 64,))
    assert example[4].eligibility(example[3].binding.job_id)['blocks_admission'] is True
    with pytest.raises(recovery.RecoveryError): example[4].lookup_resolution(acknowledgement['disposition_sha256'])


@pytest.mark.parametrize('state', ['ATTENTION', 'UNKNOWN', '', None])
def test_unknown_conversion_state_is_never_a_nonblocking_admission_state(state):
    assert recovery.admission_status({'id': 'fox-' + 'a' * 20, 'source_hash': 'f' * 64, 'state': state}, None)['blocks_admission'] is True


@pytest.mark.parametrize('state', ['QUEUED', 'PROCESSING', 'ATTENTION', 'UNKNOWN'])
def test_other_unresolved_conversion_blocks_retry_reservation(example, state):
    closed = record(example)
    with closing(sqlite3.connect(example[1])) as db, db:
        db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)', (
            'fox-' + '9' * 20, 'synthetic-other', '9' * 64, state, 'Unknown synthetic outcome', 1, 1, None))
    with pytest.raises(recovery.RecoveryError):
        example[4].reserve_retry(cb(request(closed['disposition'])), now=NOW)
    assert count(example[1], 'verification_retry_attempts') == 0


def synchronous_bundle(example):
    """Synthetic reviewed source, separate from immutable collection members."""
    bundle = deepcopy(example[0])
    original = (b"#!/usr/bin/env bash\nset -euo pipefail\nimage='synthetic-reviewed-image'\n"
                b'timeout --signal=TERM --kill-after=20s 900s podman run --rm "$image"\n')
    wrapper = original.replace(b'synthetic-reviewed-image', IMAGE.encode())
    reviewed = recovery.ReviewedSynchronousLaunch(OLD_RELEASE, QA_SOURCE, sha(wrapper), sha(original), IMAGE)
    stage = json.loads(bundle['files']['stage-receipt.json'])
    stage['bound_files'] = {'source/run-jsn-qa.sh': sha(original), 'source/run-native-v2.sh': sha(wrapper),
        **{name: sha(bundle['files'][source]) for name, source in {
            'inputs/package.zip': 'package.zip', 'inputs/native-form-spec.json': 'native-form-spec.json',
            'inputs/allocate.evidence.json': 'allocation-receipt.json',
            'inputs/verification-profile.json': 'verification-profile.json',
            'inputs/verify.evidence.json': 'clean-import-receipt.json',
            'prepared/target.json': 'target-receipt.json', 'prepared/profile.json': 'qa-profile.json'}.items()}}
    bundle['files']['stage-receipt.json'] = cb(stage)
    reseal_collection(bundle)
    producer = {key: value for key, value in bundle['producer'].items() if key != 'container_id'}
    producer.update(scope=recovery.SYNCHRONOUS_SCOPE, termination_basis='synchronous_foreground_exit',
        container_forensic_attribution=False, detached=False, timed_out=False, signal_number=None,
        producer_inventory_complete=True, unknown_producer_count=0, qa_source_sha256=QA_SOURCE,
        wrapper_sha256=sha(wrapper), original_wrapper_sha256=sha(original),
        stage_receipt_sha256=sha(bundle['files']['stage-receipt.json']),
        launch_receipt_sha256=sha(bundle['files']['launch-receipt.json']),
        launch_intent_sha256=sha(bundle['files']['launch-intent.json']),
        dispatch_receipt_sha256=sha(bundle['files']['dispatch-receipt.json']),
        qa_report_sha256=sha(bundle['files']['qa-result.json']),
        qa_run_intent_sha256=bundle['journal_summary']['phases']['qa_run']['intent_sha256'],
        qa_run_completion_sha256=bundle['journal_summary']['phases']['qa_run']['completion_sha256'])
    bundle.update(producer=producer, wrapper_raw=wrapper, reviewed_synchronous_launch=reviewed)
    return bundle


def synchronous_store(example, bundle, **options):
    return recovery.VerificationRecovery(example[1], enabled=True,
        producer_probe=options.get('producer_probe', lambda *args: deepcopy(bundle['producer'])),
        approved_retry_releases=[NEW_RELEASE],
        approved_synchronous_launches=options.get('approved_synchronous_launches', [bundle['reviewed_synchronous_launch']]))


def synchronous_evidence(bundle):
    return {key: bundle[key] for key in
        ('package', 'plan_raw', 'collection_raw', 'files', 'journal_summary', 'wrapper_raw')}


def test_synchronous_terminal_failure_is_distinct_and_preserves_old_rows_and_receipts(example):
    bundle = synchronous_bundle(example)
    prior, raw_files = preserved(example[1]), deepcopy(bundle['files'])
    document = recovery.validate_failed_evidence(**arguments(bundle))
    assert document['producer']['container_forensic_attribution'] is False
    assert 'container_id' not in document['producer']
    store = synchronous_store(example, bundle)
    result = store.record_failure(example[3], cb(document), evidence=synchronous_evidence(bundle), now=NOW)
    assert result['disposition'] == document
    assert result['status'] == 'FAILED_QA_RECORDED'
    assert preserved(example[1]) == prior and bundle['files'] == raw_files
    assert store.lookup_resolution(result['disposition_sha256']) == result
    # A committed lost reply is read-only and independent of stale observations.
    assert store.record_failure(example[3], cb(document), evidence=None, now=NOW + timedelta(days=1)) == result
    assert count(example[1], 'verification_failed_dispositions') == 1
    assert store.reserve_retry(cb(request(document)), now=NOW)['attempt']['state'] == 'reserved'
    assert preserved(example[1]) == prior


@pytest.mark.parametrize('code', [0, 1, 124, 125, 126, 127, 137, 143, -9, -15, None, '2', True])
def test_synchronous_observation_rejects_nonterminal_timeout_signal_unknown_status(example, code):
    bundle = synchronous_bundle(example); bundle['producer']['exit_code'] = code
    with pytest.raises(recovery.RecoveryError, match='SYNCHRONOUS_TERMINALITY_UNPROVEN'):
        recovery.validate_failed_evidence(**arguments(bundle))


@pytest.mark.parametrize('code', [0, 124, 125, 126, 127, 137, 143, -9, -15, None, '2', True])
def test_synchronous_launch_receipt_must_itself_prove_exit_two(example, code):
    bundle = synchronous_bundle(example)
    launch = json.loads(bundle['files']['launch-receipt.json']); launch['exit_code'] = code
    bundle['files']['launch-receipt.json'] = cb(launch); reseal_collection(bundle)
    bundle['producer']['launch_receipt_sha256'] = sha(cb(launch))
    with pytest.raises(recovery.RecoveryError, match='TERMINAL_LAUNCH_REQUIRED'):
        recovery.validate_failed_evidence(**arguments(bundle))


@pytest.mark.parametrize('name', ['launch-receipt.json', 'launch-intent.json', 'dispatch-receipt.json',
                                 'stage-receipt.json', 'qa-result.json'])
def test_synchronous_terminal_proof_cannot_omit_a_receipt(example, name):
    bundle = synchronous_bundle(example)
    del bundle['files'][name]; reseal_collection(bundle)
    with pytest.raises(recovery.RecoveryError, match='EVIDENCE_SET_INVALID'):
        recovery.validate_failed_evidence(**arguments(bundle))


@pytest.mark.parametrize('field,value', [
    ('detached', True), ('detached', 0), ('timed_out', True), ('timed_out', None),
    ('signal_number', 9), ('signal_number', 15), ('signal_number', 0), ('signal_number', False),
    ('state', 'RUNNING'), ('state', 'UNKNOWN'), ('state', 'INCOMPLETE'),
    ('termination_basis', 'container_removed'), ('container_forensic_attribution', True),
    ('producer_inventory_complete', False), ('producer_inventory_complete', 1),
    ('live_producer_count', 1), ('unknown_producer_count', 1), ('unknown_producer_count', False),
    ('technical_proof_count', 1), ('human_acceptance_count', 1), ('unresolved_phase_count', 1)])
def test_synchronous_observation_does_not_accept_detached_partial_live_or_inferred_outcomes(example, field, value):
    bundle = synchronous_bundle(example); bundle['producer'][field] = value
    with pytest.raises(recovery.RecoveryError):
        recovery.validate_failed_evidence(**arguments(bundle))


@pytest.mark.parametrize('field', sorted(recovery._SYNCHRONOUS_LINKS))
def test_synchronous_observation_hash_links_are_exact(example, field):
    bundle = synchronous_bundle(example); bundle['producer'][field] = '0' * 64
    with pytest.raises(recovery.RecoveryError, match='SYNCHRONOUS_EVIDENCE_CHANGED'):
        recovery.validate_failed_evidence(**arguments(bundle))


@pytest.mark.parametrize('key', ['source/run-jsn-qa.sh', 'source/run-native-v2.sh',
    'inputs/package.zip', 'inputs/native-form-spec.json', 'inputs/allocate.evidence.json',
    'inputs/verification-profile.json', 'inputs/verify.evidence.json', 'prepared/target.json', 'prepared/profile.json'])
def test_synchronous_stage_bound_files_cannot_be_missing_or_changed(example, key):
    bundle = synchronous_bundle(example)
    stage = json.loads(bundle['files']['stage-receipt.json']); stage['bound_files'][key] = '0' * 64
    bundle['files']['stage-receipt.json'] = cb(stage); reseal_collection(bundle)
    bundle['producer']['stage_receipt_sha256'] = sha(cb(stage))
    with pytest.raises(recovery.RecoveryError, match='SYNCHRONOUS_STAGE_BINDING_CHANGED'):
        recovery.validate_failed_evidence(**arguments(bundle))


@pytest.mark.parametrize('mutation', ['missing', 'changed', 'detached', 'background'])
def test_unreviewed_wrapper_bytes_cannot_establish_synchronous_terminality(example, mutation):
    bundle = synchronous_bundle(example)
    if mutation == 'missing': bundle['wrapper_raw'] = None
    elif mutation == 'changed': bundle['wrapper_raw'] += b'\nchanged\n'
    elif mutation == 'detached': bundle['wrapper_raw'] = bundle['wrapper_raw'].replace(b'podman run --rm', b'podman run -d --rm')
    else: bundle['wrapper_raw'] = bundle['wrapper_raw'].rstrip() + b' &\n'
    with pytest.raises(recovery.RecoveryError, match='REVIEWED_WRAPPER_CHANGED'):
        recovery.validate_failed_evidence(**arguments(bundle))


@pytest.mark.parametrize('mutation', ['missing_contract', 'json_contract', 'wrong_release', 'wrong_source'])
def test_synchronous_report_needs_a_separately_reviewed_typed_contract(example, mutation):
    bundle = synchronous_bundle(example); reviewed = bundle['reviewed_synchronous_launch']
    if mutation == 'missing_contract': bundle['reviewed_synchronous_launch'] = None
    elif mutation == 'json_contract': bundle['reviewed_synchronous_launch'] = dict(vars(reviewed))
    else:
        values = dict(vars(reviewed))
        values['verifier_release_sha256' if mutation == 'wrong_release' else 'qa_source_sha256'] = '0' * 64
        bundle['reviewed_synchronous_launch'] = recovery.ReviewedSynchronousLaunch(**values)
    with pytest.raises(recovery.RecoveryError):
        recovery.validate_failed_evidence(**arguments(bundle))


@pytest.mark.parametrize('mutation', ['sync_with_container_id', 'sync_as_container', 'container_without_id',
    'container_with_sync_field', 'container_as_sync', 'container_with_wrapper'])
def test_container_and_synchronous_variants_cannot_be_mixed_or_downgraded(example, mutation):
    bundle = synchronous_bundle(example) if mutation.startswith('sync_') else deepcopy(example[0])
    if mutation == 'sync_with_container_id': bundle['producer']['container_id'] = '1' * 64
    if mutation == 'sync_as_container': bundle['producer']['scope'] = 'fox-verification-producer-observation-v1'
    if mutation == 'container_without_id': del bundle['producer']['container_id']
    if mutation == 'container_with_sync_field': bundle['producer']['termination_basis'] = 'synchronous_foreground_exit'
    if mutation == 'container_as_sync': bundle['producer']['scope'] = recovery.SYNCHRONOUS_SCOPE
    if mutation == 'container_with_wrapper': bundle['wrapper_raw'] = b'synthetic wrapper'
    with pytest.raises(recovery.RecoveryError):
        recovery.validate_failed_evidence(**arguments(bundle))


@pytest.mark.parametrize('mode', ['no_server_approval', 'no_probe', 'caller_contract', 'probe_different_hash',
                                  'probe_stale', 'probe_live', 'probe_unknown', 'probe_wrong_variant'])
def test_synchronous_json_and_local_review_never_replace_server_authority(example, mode):
    bundle = synchronous_bundle(example); document = recovery.validate_failed_evidence(**arguments(bundle))
    options, evidence = {}, synchronous_evidence(bundle)
    if mode == 'no_server_approval': options['approved_synchronous_launches'] = ()
    if mode == 'no_probe': options['producer_probe'] = None
    if mode == 'caller_contract': evidence['reviewed_synchronous_launch'] = bundle['reviewed_synchronous_launch']
    if mode.startswith('probe_'):
        observed = deepcopy(bundle['producer'])
        if mode == 'probe_different_hash': observed['qa_report_sha256'] = '0' * 64
        if mode == 'probe_stale': observed['observed_at_utc'] = (NOW - timedelta(minutes=6)).isoformat()
        if mode == 'probe_live': observed['live_producer_count'] = 1
        if mode == 'probe_unknown': observed['unknown_producer_count'] = 1
        if mode == 'probe_wrong_variant': observed = deepcopy(example[0]['producer'])
        options['producer_probe'] = lambda *args: observed
    store = synchronous_store(example, bundle, **options)
    prior = preserved(example[1])
    with pytest.raises(recovery.RecoveryError):
        store.record_failure(example[3], cb(document), evidence=evidence, now=NOW)
    assert preserved(example[1]) == prior and count(example[1], 'verification_failed_dispositions') == 0


def test_synchronous_first_apply_reobserves_fresh_terminal_identity_without_rebinding_document(example):
    bundle = synchronous_bundle(example); document = recovery.validate_failed_evidence(**arguments(bundle))
    later = NOW + timedelta(hours=2)
    observed = deepcopy(bundle['producer']); observed['observed_at_utc'] = later.isoformat()
    store = synchronous_store(example, bundle, producer_probe=lambda *args: observed)
    result = store.record_failure(example[3], cb(document), evidence=synchronous_evidence(bundle), now=later)
    assert result['disposition'] == document
    assert result['disposition_sha256'] == recovery.disposition_sha256(document)


@pytest.mark.parametrize('image', ['c' * 64, 'sha256:' + 'C' * 64, 'sha256:bad', '', None, 1])
def test_reviewed_synchronous_contract_requires_a_canonical_approved_image(image):
    with pytest.raises(recovery.RecoveryError, match='REVIEWED_IMAGE_INVALID'):
        recovery.ReviewedSynchronousLaunch(OLD_RELEASE, QA_SOURCE, 'e' * 64, 'f' * 64, image)


def test_fully_resealed_image_substitution_cannot_change_reviewed_wrapper_image(example):
    bundle = synchronous_bundle(example)
    original_wrapper = bundle['wrapper_raw']; original_review = bundle['reviewed_synchronous_launch']
    other_image = 'sha256:' + '8' * 64
    for name in ('stage-receipt.json', 'launch-receipt.json', 'launch-intent.json', 'dispatch-receipt.json'):
        value = json.loads(bundle['files'][name]); value['image_id'] = other_image
        bundle['files'][name] = cb(value)
    qa = json.loads(bundle['files']['qa-result.json']); qa['runtime']['image_id'] = other_image
    bundle['files']['qa-result.json'] = cb(qa)
    summary = bundle['journal_summary']
    for phase in ('qa_stage', 'qa_run'):
        item = summary['phases'][phase]; item['result']['image_id'] = other_image
        completion = cb({'intent_sha256': item['intent_sha256'], 'result': item['result']})
        item['completion_sha256'] = sha(completion)
        summary['retained_sha256']['p0001-' + phase.replace('_', '-') + '.complete.json'] = sha(completion)
    reseal_collection(bundle)
    bundle['producer'].update(image_id=other_image,
        qa_run_completion_sha256=summary['phases']['qa_run']['completion_sha256'],
        **{key: sha(bundle['files'][name]) for key, name in recovery._SYNCHRONOUS_FILES.items()})
    assert bundle['wrapper_raw'] == original_wrapper and bundle['reviewed_synchronous_launch'] == original_review
    with pytest.raises(recovery.RecoveryError, match='SYNCHRONOUS_EVIDENCE_CHANGED'):
        recovery.validate_failed_evidence(**arguments(bundle))
