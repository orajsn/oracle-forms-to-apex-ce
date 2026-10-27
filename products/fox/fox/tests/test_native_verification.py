"""Synthetic local proof tests only: no Oracle services or real QA claims."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3

import pytest

from fox import native_verification as gate
from test_native_pipeline import harness, valid_package, package_bytes
from test_fox import client, signed_in, project


NOW = datetime(2026, 10, 17, 2, tzinfo=timezone.utc)
POLICY = gate.VerificationPolicy(apex='26.1.5', sqlcl='26.1.2.0', database='23.26.4.1.0', mmd='26.1.0+3102')


def raw(value):
    return json.dumps(value, sort_keys=True).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


@pytest.fixture
def proof_case(valid_package, harness):
    members, release, native = valid_package
    release.update(dict.fromkeys(('reviewer_approved', 'reviewer_execution_verified', 'sqlcl_valid',
                                 'import_passed', 'runtime_smoke_passed', 'package_reimport_passed',
                                 'business_acceptance_required'), True))
    members['evidence/release-evidence.json'] = raw(release)
    package = package_bytes(members)
    profile = {'schema_version': 1, 'profile_id': gate.PROFILE_ID, 'data_mode': 'synthetic_test_only',
               'table_name': native['table_name'], 'fields': [
                   {'name': column['name'], 'label': column['label'], 'data_type': column['data_type'],
                    'required': not column['nullable'], **({'max_length': column['length']} if 'length' in column else {})}
                   for column in native['columns'] if not column['primary_key']]}
    clean = {'schema_version': 1, 'scope': 'fox-clean-package-install-v1', 'passed': True,
             'profile_id': gate.PROFILE_ID, 'db_name': gate.DB_NAME, 'observed_versions': POLICY.versions,
             'job_id': release['job_id'], 'compartment_id': gate.COMPARTMENT, 'database_id': gate.DATABASE,
             'region': 'us-ashburn-1', 'workspace': gate.WORKSPACE, 'parsing_schema': gate.WORKSPACE,
             'workspace_id': gate.WORKSPACE_ID,
             'table_name': native['table_name'], 'application_id': 34567, 'application_alias': 'F2A_QA_UNIT',
             'application_url': gate.ORDS + '/r/fox_qa_261017a/f2a_qa_unit/',
             'package_sha256': sha(package), 'source_manifest_sha256': release['source_manifest_sha256'],
             'sql_sha256': sha(members['sql/f12345.sql']), 'native_spec_sha256': sha(members['native-form-spec.json']),
             'schema_script_sha256': sha(members['schema/01_synthetic_schema.sql']),
             'started_at_utc': '2026-10-17T00:00:00Z', 'finished_at_utc': '2026-10-17T00:05:00Z',
             'clean_install': {'passed': True, 'workspace_created_fresh': True, 'schema_created_fresh': True,
                'before_install': {'passed': True, 'application_count': 0, 'user_object_count': 0},
                'after_install': {'passed': True, 'application_count': 1, 'native_table_count': 1,
                                  'unexpected_schema_dependency_count': 0}}}
    target = {key: clean[key] for key in ('job_id', 'compartment_id', 'database_id', 'region', 'workspace',
        'parsing_schema', 'workspace_id', 'db_name', 'table_name', 'application_id', 'package_sha256', 'source_manifest_sha256',
        'sql_sha256', 'native_spec_sha256', 'schema_script_sha256')}
    target.update(schema_version=1, clean_install=True, synthetic_qa_approved=True,
                  alias=clean['application_alias'], url=clean['application_url'],
                  profile_sha256=sha(raw(profile)), import_receipt_sha256=sha(raw(clean)))
    qa = {'schema_version': 1, 'status': 'PASSED', 'test_scope': 'authenticated_browser_native_table_form_synthetic_only',
          'target': target, 'target_receipt_sha256': sha(raw(target)), 'two_independent_accounts': True,
          'credentials_recorded': False, 'browser_storage_saved': False, 'human_acceptance_recorded': False,
          'browser_errors': [], 'network_denials': [], 'started_at': '2026-10-17T00:10:00Z',
          'finished_at': '2026-10-17T00:15:00Z', 'binding': {**dict.fromkeys((
              'profile_bytes_verified', 'package_bytes_verified', 'native_spec_bytes_verified',
              'import_receipt_bytes_verified', 'package_manifest_verified', 'clean_install_verified'), True),
              'package_sha256': sha(package), 'scope': 'exact-package-clean-install'},
          'tests': [{'name': name, 'required': True, 'status': 'PASSED', 'evidence': {}} for name in sorted(gate.REQUIRED_TESTS)]}
    tests = {test['name']: test for test in qa['tests']}
    tests['login']['evidence'] = {'authenticated': True, 'rendered_application_id': 34567}
    tests['concurrent_edit']['evidence'] = {'independent_browser_contexts': 2, 'two_independent_accounts': True,
                                           'first_writer_retained': True, 'stale_writer_rejected': True}
    tests['browser_runtime_errors']['evidence'] = {'unhandled_error_count': 0}
    return {'package': package, 'snapshot': deepcopy(harness.snapshot), 'release': release,
            'clean': clean, 'qa': qa, 'target': target, 'profile': profile}


def arguments(case):
    return dict(package=case['package'], snapshot=case['snapshot'], release=case['release'],
                clean_install_raw=raw(case['clean']), qa_result_raw=raw(case['qa']),
                qa_target_raw=raw(case['target']), qa_profile_raw=raw(case['profile']),
                policy=POLICY, now=NOW, run_created=datetime(2026, 10, 16, tzinfo=timezone.utc).timestamp())


def test_exact_package_proof_is_technical_only(proof_case):
    proof = gate.verify_detached_proof(**arguments(proof_case))
    assert proof['authenticated_runtime_passed'] is proof['clean_schema_install_passed'] is True
    assert proof['human_acceptance_recorded'] is False and proof['business_acceptance_required'] is True
    assert proof['package_sha256'] == sha(proof_case['package'])


@pytest.mark.parametrize('part,key,value', [
    ('clean', 'job_id', 'fox-' + 'b' * 20), ('clean', 'package_sha256', '0' * 64),
    ('clean', 'database_id', 'another-db'), ('clean', 'compartment_id', 'another-compartment'),
    ('clean', 'workspace', 'FORMS2APEX_POC'), ('clean', 'parsing_schema', 'FORMS2APEX_POC'),
    ('clean', 'workspace_id', 22042420337195497), ('target', 'workspace_id', '22042420337195496'),
    ('target', 'db_name', 'ANOTHER_DATABASE'),
    ('clean', 'region', 'ap-singapore-1'), ('clean', 'profile_id', 'legacy-html-prototype-v1'),
    ('clean', 'sql_sha256', '0' * 64), ('clean', 'native_spec_sha256', '0' * 64),
    ('clean', 'schema_script_sha256', '0' * 64), ('clean', 'source_manifest_sha256', '0' * 64),
    ('clean', 'application_id', 12345), ('clean', 'application_id', True),
    ('clean', 'application_alias', 'F2A_NATIVE_UNIT_TEST'), ('clean', 'application_url', 'https://bad.invalid/'),
    ('clean', 'passed', False), ('clean', 'observed_versions', {}), ('clean', 'clean_install', []),
    ('qa', 'status', 'FAILED'), ('qa', 'two_independent_accounts', False),
    ('qa', 'browser_errors', ['unexpected']), ('qa', 'network_denials', ['unexpected']),
    ('qa', 'human_acceptance_recorded', True), ('qa', 'credentials_recorded', True),
    ('qa', 'target_receipt_sha256', '0' * 64), ('qa', 'tests', []),
    ('target', 'application_id', 179063360), ('target', 'clean_install', False),
    ('target', 'import_receipt_sha256', '0' * 64), ('profile', 'fields', []),
])
def test_unbound_or_failed_receipt_rejected(proof_case, part, key, value):
    proof_case[part][key] = value
    with pytest.raises(gate.VerificationError):
        gate.verify_detached_proof(**arguments(proof_case))


@pytest.mark.parametrize('mutation', ['duplicate', 'not_run', 'optional_failed', 'concurrent', 'login', 'binding', 'fresh', 'dependencies', 'bool_count'])
def test_test_matrix_and_clean_scope_are_not_just_boolean_flags(proof_case, mutation):
    qa, install = proof_case['qa'], proof_case['clean']['clean_install']
    tests = {test['name']: test for test in qa['tests']}
    if mutation == 'duplicate': qa['tests'].append(deepcopy(qa['tests'][0]))
    if mutation == 'not_run': tests['required_fields']['status'] = 'NOT_RUN'
    if mutation == 'optional_failed': qa['tests'].append({'name': 'extra', 'status': 'FAILED', 'required': False})
    if mutation == 'concurrent': tests['concurrent_edit']['evidence']['first_writer_retained'] = False
    if mutation == 'login': tests['login']['evidence']['rendered_application_id'] = 12345
    if mutation == 'binding': qa['binding']['package_bytes_verified'] = False
    if mutation == 'fresh': install['workspace_created_fresh'] = False
    if mutation == 'dependencies': install['after_install']['unexpected_schema_dependency_count'] = 1
    if mutation == 'bool_count': install['before_install']['application_count'] = False
    with pytest.raises(gate.VerificationError): gate.verify_detached_proof(**arguments(proof_case))


@pytest.mark.parametrize('part,key,value', [
    ('clean', 'started_at_utc', '2026-10-15T00:00:00Z'),
    ('qa', 'finished_at', '2026-10-15T00:15:00Z'),
    ('qa', 'finished_at', '2026-10-18T00:15:00Z'),
    ('qa', 'started_at', '2026-10-17T00:04:00Z'),
    ('qa', 'started_at', '2026-10-17T00:10:00'),
])
def test_receipt_time_order_and_freshness(proof_case, part, key, value):
    proof_case[part][key] = value
    with pytest.raises(gate.VerificationError): gate.verify_detached_proof(**arguments(proof_case))


def test_changed_source_text_cannot_reuse_original_hash(proof_case):
    proof_case['snapshot']['files'][0]['text'] += '\n'
    with pytest.raises(gate.VerificationError): gate.verify_detached_proof(**arguments(proof_case))


@pytest.mark.parametrize('payload', [b'{"schema_version":1,"schema_version":1}', b'NaN', b'[]', b'bad',
                                      b'{"nested":' + b'[' * 10_000 + b'0' + b']' * 10_000 + b'}'])
def test_ambiguous_receipt_json_rejected(proof_case, payload):
    args = arguments(proof_case); args['clean_install_raw'] = payload
    with pytest.raises(gate.VerificationError): gate.verify_detached_proof(**args)


@pytest.fixture
def promotion_case(client, proof_case, monkeypatch, tmp_path):
    c, root = signed_in(client); pid = project(c)
    for source in proof_case['snapshot']['files']:
        assert c.post(f'/api/projects/{pid}/sources', files={'files': (source['name'], source['text'].encode())}).status_code == 200
    proof_case['snapshot']['project'] = pid
    rid = proof_case['release']['job_id']
    job = root / 'jobs' / rid; (job / 'native-pipeline').mkdir(parents=True)
    (job / 'source-snapshot.json').write_bytes(raw(proof_case['snapshot']))
    (job / 'release-evidence.json').write_bytes(raw(proof_case['release']))
    (job / 'apex-package.zip').write_bytes(proof_case['package'])
    (job / 'native-pipeline' / 'download.json').write_bytes(raw({'package_sha256': sha(proof_case['package']), 'source_hash': proof_case['snapshot']['source_hash']}))
    operator = tmp_path.parent / (tmp_path.name + '-operator'); operator.mkdir()
    for name, key in zip(gate.RECEIPT_NAMES, ('clean', 'qa', 'target', 'profile')):
        (operator / name).write_bytes(raw(proof_case[key]))
    # Transaction/content logic is portable. POSIX ownership has separate tests;
    # native Windows tests do not pretend to verify Windows ACLs.
    monkeypatch.setattr(gate, '_private', lambda path, directory=False: gate._safe_path(path))
    monkeypatch.setattr(gate, '_sync_dir', lambda path: None)
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)', (rid, pid, proof_case['snapshot']['source_hash'],
                   'QA_REQUIRED', 'Pending', arguments(proof_case)['run_created'], 1, str((job / 'apex-package.zip').relative_to(root))))
    return c, root, pid, rid, job, operator, proof_case


def promote(case):
    _, root, _, rid, _, operator, _ = case
    return gate.promote_native_run(root=root, run_id=rid, operator_receipt_dir=operator, policy=POLICY, now=NOW)


def acceptance(case):
    return dict(source_hash=case[-1]['snapshot']['source_hash'], business_flow_tested=True,
                remediation_reviewed=True, notes='Synthetic test fixture only; not real user acceptance.')


def test_atomic_promotion_idempotency_and_separate_acceptance(promotion_case):
    c, root, pid, rid, job, operator, _ = promotion_case
    first, second = promote(promotion_case), promote(promotion_case)
    assert first['state'] == second['state'] == 'VERIFIED' and second['idempotent'] is True
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM technical_verifications').fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM events WHERE action='native_technical_verified'").fetchone()[0] == 1
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0] == 0
    base = f'/api/projects/{pid}/runs/{rid}'
    assert c.get(base + '/download').status_code == 409
    evidence = c.get(base + '/evidence').json()
    assert evidence['technical_verification']['human_acceptance_recorded'] is False
    assert c.post(base + '/accept', json=acceptance(promotion_case)).status_code == 200
    assert c.get(base + '/download').content == (job / 'apex-package.zip').read_bytes()
    later = gate.promote_native_run(root=root, run_id=rid, operator_receipt_dir=operator,
                                   policy=POLICY, now=datetime(2026, 11, 1, tzinfo=timezone.utc))
    assert later['state'] == 'ACCEPTED' and later['idempotent'] is True
    assert c.post(f'/api/projects/{pid}/sources', files={'files': ('new-version.txt', b'New synthetic source version')}).status_code == 200
    assert promote(promotion_case)['idempotent'] is True
    assert c.get(base + '/download').content == (job / 'apex-package.zip').read_bytes()


@pytest.mark.parametrize('point', ['before_accept', 'after_accept'])
def test_tampered_package_cannot_be_accepted_or_downloaded(promotion_case, point):
    c, _, pid, rid, job, _, _ = promotion_case
    promote(promotion_case); base = f'/api/projects/{pid}/runs/{rid}'
    if point == 'after_accept': assert c.post(base + '/accept', json=acceptance(promotion_case)).status_code == 200
    (job / 'apex-package.zip').write_bytes(b'changed after technical proof')
    assert c.post(base + '/accept', json=acceptance(promotion_case)).status_code == 409
    assert c.get(base + '/download').status_code == 409
    assert c.get(base + '/evidence').status_code == 409


def test_native_review_required_without_attestation_rejected(promotion_case):
    c, root, pid, rid, _, _, _ = promotion_case
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute("UPDATE runs SET state='REVIEW_REQUIRED' WHERE id=?", (rid,))
    assert c.post(f'/api/projects/{pid}/runs/{rid}/accept', json=acceptance(promotion_case)).status_code == 409


@pytest.mark.parametrize('file', [*gate.RECEIPT_NAMES, 'verification.json', 'attempt.json'])
def test_retained_receipt_tamper_invalidates_acceptance(promotion_case, file):
    c, _, pid, rid, job, _, _ = promotion_case
    promote(promotion_case)
    (job / 'technical-verification' / file).write_bytes(b'{}')
    assert c.post(f'/api/projects/{pid}/runs/{rid}/accept', json=acceptance(promotion_case)).status_code == 409


def test_changed_source_and_differing_retry_cannot_promote(promotion_case):
    c, root, pid, rid, job, operator, _ = promotion_case
    c.post(f'/api/projects/{pid}/sources', files={'files': ('extra.txt', b'Synthetic supporting note')})
    with pytest.raises(gate.VerificationError, match='sources changed'): promote(promotion_case)
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT state FROM runs WHERE id=?', (rid,)).fetchone()[0] == 'QA_REQUIRED'
    # Retained exact bytes survive a failed transaction, never overwritten.
    (operator / 'qa-result.json').write_bytes(b'{}')
    with pytest.raises(gate.VerificationError): promote(promotion_case)


def test_crash_after_retained_receipts_recovers_after_freshness_window(promotion_case, monkeypatch):
    _, root, _, rid, job, operator, _ = promotion_case
    original = gate._save_once
    def interrupted(path, payload):
        if path.name == 'verification.json':
            raise OSError('Synthetic crash before SQLite transaction')
        original(path, payload)
    monkeypatch.setattr(gate, '_save_once', interrupted)
    with pytest.raises(OSError, match='Synthetic crash'): promote(promotion_case)
    assert (job / 'technical-verification' / 'attempt.json').is_file()
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT state FROM runs WHERE id=?', (rid,)).fetchone()[0] == 'QA_REQUIRED'
    monkeypatch.setattr(gate, '_save_once', original)
    later = gate.promote_native_run(root=root, run_id=rid, operator_receipt_dir=operator,
                                   policy=POLICY, now=datetime(2026, 11, 1, tzinfo=timezone.utc))
    assert later['state'] == 'VERIFIED' and later['idempotent'] is False
    again = gate.promote_native_run(root=root, run_id=rid, operator_receipt_dir=operator,
                                   policy=POLICY, now=datetime(2026, 11, 2, tzinfo=timezone.utc))
    assert again['state'] == 'VERIFIED' and again['idempotent'] is True


def test_transaction_failure_rolls_back_state_and_recovers_without_duplicate_event(promotion_case):
    _, root, _, rid, _, operator, _ = promotion_case
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        db.execute("CREATE TRIGGER fail_proof_event BEFORE INSERT ON events WHEN NEW.action='native_technical_verified' "
                   "BEGIN SELECT RAISE(ABORT,'synthetic transaction failure'); END")
    with pytest.raises(sqlite3.IntegrityError, match='synthetic transaction failure'): promote(promotion_case)
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT state FROM runs WHERE id=?', (rid,)).fetchone()[0] == 'QA_REQUIRED'
        assert db.execute("SELECT COUNT(*) FROM events WHERE action='native_technical_verified'").fetchone()[0] == 0
        db.execute('DROP TRIGGER fail_proof_event')
    result = gate.promote_native_run(root=root, run_id=rid, operator_receipt_dir=operator,
                                    policy=POLICY, now=datetime(2026, 11, 1, tzinfo=timezone.utc))
    assert result['state'] == 'VERIFIED'
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM technical_verifications').fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM events WHERE action='native_technical_verified'").fetchone()[0] == 1


def test_different_valid_operator_receipt_cannot_replace_committed_proof(promotion_case):
    _, _, _, _, _, operator, proof_case = promotion_case
    promote(promotion_case)
    changed = deepcopy(proof_case['qa']); changed['operator_note'] = 'A different receipt'
    (operator / 'qa-result.json').write_bytes(raw(changed))
    with pytest.raises(gate.VerificationError, match='different technical verification attempt'):
        promote(promotion_case)


@pytest.mark.parametrize('column,value', [('artifact_sha256', '0' * 64), ('source_hash', '0' * 64), ('proof_sha256', '0' * 64)])
def test_changed_stored_proof_blocks_human_acceptance(promotion_case, column, value):
    c, root, pid, rid, _, _, _ = promotion_case
    promote(promotion_case)
    with sqlite3.connect(root / 'fox.sqlite3') as db:
        # Column is selected solely from this static parametrized test matrix.
        db.execute('UPDATE technical_verifications SET ' + column + '=? WHERE run=?', (value, rid))
    assert c.post(f'/api/projects/{pid}/runs/{rid}/accept', json=acceptance(promotion_case)).status_code == 409


def test_non_posix_operator_entrypoint_does_not_claim_acl_validation(tmp_path):
    if os.name == 'posix': pytest.skip('Windows rejection case only')
    with pytest.raises(gate.VerificationError, match='POSIX'): gate._private(tmp_path, directory=True)


@pytest.mark.skipif(os.name != 'posix', reason='Actual ownership/mode checks need POSIX')
def test_operator_private_modes_enforced(tmp_path):
    path = tmp_path / 'receipt.json'; path.write_bytes(b'{}'); path.chmod(0o644)
    with pytest.raises(gate.VerificationError): gate._private(path)
    path.chmod(0o600)
    assert gate._private(path) == path
