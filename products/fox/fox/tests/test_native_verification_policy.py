"""Local synthetic v2 policy, receipt and historical-decision regressions."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import zipfile
from xml.sax.saxutils import escape

import pytest

from fox import native_verification as gate
from fox import native_verification_policy as policy_module
from fox.native_verification_policy import BoundVerificationPolicy, VerificationPolicyError, validate_allocation_receipt
from fox.native_qa_plan import derive_native_qa_plan, derive_native_qa_profile, qa_plan_sha256
from fox.intake import checked_source, inventory
from fox.native_source import assess_native_source
from test_native_verification import (proof_case, promotion_case, arguments, raw, sha,
                                     NOW, POLICY, promote, acceptance)
from test_native_pipeline import harness, valid_package, package_bytes, NativeHarness
from test_fox import client

FIXTURE = Path(__file__).parent / 'fixtures/native-verification-profile-v2.json'


def policy_document():
    return json.loads(FIXTURE.read_bytes())


def bind_v2(case, token='261017_89ABCDEF', workspace_id='22042420337195501', app_id=34567):
    case = deepcopy(case)
    profile = policy_document()
    profile['binding'].update(job_id=case['release']['job_id'], source_manifest_sha256=case['snapshot']['source_hash'],
                              package_sha256=sha(case['package']))
    profile['target'].update(workspace='FOX_QA_' + token, parsing_schema='FOX_QA_' + token,
                             workspace_id=workspace_id, application_id=app_id, application_alias='F2A_QA_' + token)
    allocation = {'schema_version': 1, 'scope': 'fox-clean-allocation-v2', 'passed': True,
                  'plan_sha256': '4' * 64, 'allocated_at_utc': '2026-10-16T23:50:00Z',
                  'binding': {key: profile['binding'][key] for key in ('job_id', 'source_manifest_sha256', 'package_sha256')},
                  'target': {**profile['target'], 'instance_id': policy_module.INSTANCE},
                  'observed_versions': profile['expected_versions'],
                  'fresh_namespace': {'workspace_created_fresh': True, 'schema_created_fresh': True,
                                      'application_count': 0, 'user_object_count': 0}}
    case['allocation_raw'] = raw(allocation)
    profile['binding']['allocation_receipt_sha256'] = sha(case['allocation_raw'])
    policy = BoundVerificationPolicy(raw(profile))
    case['verification_policy'] = policy
    clean = case['clean']
    clean.update(schema_version=2, scope='fox-clean-package-install-v2', **policy.target,
                 verification_profile_sha256=policy.sha256,
                 allocation_receipt_sha256=policy.binding['allocation_receipt_sha256'])
    clean['application_url'] = gate.ORDS + '/r/' + policy.target['workspace'].lower() + '/' + policy.target['application_alias'].lower() + '/'
    clean['clean_install']['after_install']['initial_row_count'] = 0
    native = case['snapshot']['native_form']
    case['profile'] = derive_native_qa_profile(native)
    target = case['target']
    target.update(schema_version=2, **{key: value for key, value in policy.target.items() if key != 'application_alias'},
                  alias=clean['application_alias'], url=clean['application_url'], profile_sha256=sha(raw(case['profile'])),
                  import_receipt_sha256=sha(raw(clean)), verification_profile_sha256=policy.sha256,
                  allocation_receipt_sha256=policy.binding['allocation_receipt_sha256'])
    qa = case['qa']
    qa.update(schema_version=2, target=target, target_receipt_sha256=sha(raw(target)))
    qa['binding'].update(scope='exact-package-clean-install-v2',
                         verification_profile_bytes_verified=True, verification_profile_sha256=policy.sha256)
    plan = derive_native_qa_plan(native, clean['native_spec_sha256'])
    prior = {test['name']: test for test in qa['tests']}
    qa['test_plan'], qa['test_plan_sha256'] = plan, qa_plan_sha256(plan)
    qa['tests'] = [{**deepcopy(prior[item['name']]), 'applicable': item['applicable'], 'required': item['applicable'],
                    'status': 'PASSED' if item['applicable'] else 'NOT_APPLICABLE', 'reason_code': item['reason_code'],
                    'field_names': item['field_names'],
                    'field_results': [{'field_name': name, 'status': 'PASSED'} for name in item['field_names']]}
                   for item in plan['cases']]
    qa['additional_checks'] = [{'name': name, 'required': False, 'status': 'NOT_RUN', 'reason': 'Separate explicit evidence, not a runtime claim.'}
                               for name in ('database_constraints', 'database_sql_readback')]
    indexed = {test['name']: test for test in qa['tests']}
    indexed['login']['evidence']['rendered_application_id'] = app_id
    indexed['concurrent_edit']['evidence']['field'] = plan['edit_field']
    key = {'name': plan['primary_key']['name'], 'value': '9007199254741001'}
    qa['initial_primary_keys'] = []
    qa['row_tracking'] = {'mode': 'clean_empty_then_observed_pk', 'initial_primary_keys': [],
                          'retained_primary_key': key, 'final_observed_primary_keys': [key['value']], 'single_row_preserved': True}
    qa['retained_records'] = [{'table': native['table_name'], 'primary_key': key, 'write_state': 'CREATED_AND_REREAD'}]
    edited = {'VARCHAR2': 'B', 'NUMBER': '2', 'DATE': '2026-01-02'}
    winner = {'VARCHAR2': 'D', 'NUMBER': '4', 'DATE': '2026-01-04'}
    qa['final_expected_record'] = {'primary_key': key, 'expected_values': {
        column['name']: (winner if column['name'] == plan['edit_field'] else edited)[column['data_type']]
        for column in native['columns'] if not column.get('primary_key')}}
    qa['pk_set_checks'] = [{'test_name': name, 'expected_primary_keys': [] if name == 'preflight' else [key['value']],
                            'observed_primary_keys': [] if name == 'preflight' else [key['value']], 'passed': True}
                           for name in ('preflight', 'create', 'reread', 'edit_save', 'cancel_edit', 'cancel_create', 'concurrent_edit', 'final')]
    for item in plan['cases']:
        if item['name'] in {'required_fields', 'invalid_number', 'invalid_date', 'maximum_length'}:
            qa['pk_set_checks'].extend({'test_name': item['name'], 'field_name': name,
                                        'expected_primary_keys': [key['value']], 'observed_primary_keys': [key['value']], 'passed': True}
                                       for name in item['field_names'])
    return case


def v2_arguments(case):
    value = arguments(case)
    value['policy'] = case['verification_policy']
    value['allocation_receipt_raw'] = case['allocation_raw']
    return value


def independent_case(tmp_path, monkeypatch, *, job_letter, token, minimal=False):
    """Use the existing mocked package generator, not a mutated sealed ZIP."""
    folder = tmp_path / ('independent-' + job_letter)
    folder.mkdir()
    synthetic = NativeHarness(folder, monkeypatch)
    new_job = synthetic.job.with_name('fox-' + job_letter * 20)
    synthetic.job.rename(new_job); synthetic.job = new_job; synthetic.path = '/fox/jobs/' + new_job.name
    if minimal:
        files = [checked_source('minimal.xml', b'<FormModule Name="SYNTHETIC"><Block Name="TINY" QueryDataSourceName="FOX_NATIVE_TINY" QueryDataSourceType="Table"><Item Name="RECORD_KEY"/><Item Name="WHEN_DUE"/></Block></FormModule>'),
                 checked_source('minimal.sql', b'CREATE TABLE FOX_NATIVE_TINY (RECORD_KEY NUMBER GENERATED BY DEFAULT ON NULL AS IDENTITY PRIMARY KEY, WHEN_DUE DATE);')]
        assessed = assess_native_source(files)
        assert assessed['state'] == 'READY'
        synthetic.snapshot.update(files=files, source_hash=inventory(files)['source_hash'], native_form=assessed['native_form'])
    (synthetic.job / 'source-snapshot.json').write_bytes(raw(synthetic.snapshot))
    members = valid_package.__wrapped__(synthetic)
    case = proof_case.__wrapped__(members, synthetic)
    return bind_v2(case, token=token, workspace_id='2204242033719550' + str(2 if job_letter == 'b' else 3),
                   app_id=34568 if job_letter == 'b' else 34569)


@pytest.fixture
def v2_case(proof_case):
    return bind_v2(proof_case)


@pytest.fixture
def v2_promotion(promotion_case):
    c, root, pid, rid, job, operator, old = promotion_case
    case = bind_v2(old)
    for name, key in zip(gate.RECEIPT_NAMES, ('clean', 'qa', 'target', 'profile')):
        (operator / name).write_bytes(raw(case[key]))
    (operator / 'verification-profile.json').write_bytes(case['verification_policy'].raw)
    (operator / 'allocation-receipt.json').write_bytes(case['allocation_raw'])
    return c, root, pid, rid, job, operator, case


def promote_v2(case, now=NOW):
    return gate.promote_native_run(root=case[1], run_id=case[3], operator_receipt_dir=case[5],
                                  policy=case[6]['verification_policy'], now=now)


def test_shared_profile_fixture_is_strict_and_not_mutable():
    policy = BoundVerificationPolicy(FIXTURE.read_bytes())
    assert policy.target['workspace_id'] == '22042420337195501'
    document = policy.document; document['target']['workspace'] = 'FORMS2APEX_POC'
    assert policy.target['workspace'] == 'FOX_QA_261017_89ABCDEF'


def test_exact_38_digit_workspace_id_is_preserved_as_string():
    document = policy_document(); document['target']['workspace_id'] = '9' * 38
    assert BoundVerificationPolicy(raw(document)).target['workspace_id'] == '9' * 38
    document['target']['workspace_id'] = '9' * 39
    with pytest.raises(VerificationPolicyError): BoundVerificationPolicy(raw(document))


@pytest.mark.parametrize('section,key,value', [
    ('target', 'compartment_id', 'another-compartment'), ('target', 'database_id', 'another-db'),
    ('target', 'region', 'ap-singapore-1'), ('target', 'db_name', 'ANOTHER_DB'),
    ('target', 'workspace', 'FORMS2APEX_POC'), ('target', 'workspace', 'FOX_QA_261017A'),
    ('target', 'workspace', 'FOX_QA_991332_89ABCDEF'), ('target', 'parsing_schema', 'FORMS2APEX_POC'),
    ('target', 'workspace_id', 22042420337195501), ('target', 'workspace_id', '001'),
    ('target', 'workspace_id', '1.0'), ('target', 'workspace_id', '1e20'),
    ('target', 'application_id', True), ('target', 'application_id', 9_007_199_254_740_992),
    ('target', 'application_alias', 'F2A_ARBITRARY'), ('binding', 'job_id', 'not-a-job'),
    ('binding', 'package_sha256', 'G' * 64), ('binding', 'source_manifest_sha256', 'short'),
    ('binding', 'allocation_receipt_sha256', None), ('expected_versions', 'apex', '26.1.6'),
    ('expected_versions', 'sqlcl', '26.1.2.9999'), ('expected_versions', 'database', '23.26.4.2.0'),
])
def test_operator_profile_rejects_unapproved_or_unbound_values(section, key, value):
    document = policy_document(); document[section][key] = value
    with pytest.raises(VerificationPolicyError): BoundVerificationPolicy(raw(document))


@pytest.mark.parametrize('value', [True, 0, 604801, '86400'])
def test_invalid_freshness_values(value):
    document = policy_document(); document['max_evidence_age_seconds'] = value
    with pytest.raises(VerificationPolicyError): BoundVerificationPolicy(raw(document))


@pytest.mark.parametrize('key,value', [('credentials', {}), ('ords_base_url', 'https://untrusted.invalid'),
                                     ('required_tests', []), ('schema_version', True), ('policy_id', 'customer-anywhere')])
def test_policy_cannot_add_credential_url_or_gate_overrides(key, value):
    document = policy_document(); document[key] = value
    with pytest.raises(VerificationPolicyError): BoundVerificationPolicy(raw(document))


@pytest.mark.parametrize('value', [b'{}', b'[]', b'{"scope":1,"scope":2}', b'NaN', b'x' * 16385,
                                 b'{"nested":' + b'[' * 1000 + b'0' + b']' * 1000 + b'}'])
def test_malformed_profile_fails_bounded(value):
    with pytest.raises(VerificationPolicyError): BoundVerificationPolicy(value)


def test_v2_exact_policy_and_qa_plan_embedded(v2_case):
    proof = gate.verify_detached_proof(**v2_arguments(v2_case))
    assert proof['schema_version'] == 2
    assert proof['verification_profile'] == v2_case['verification_policy'].document
    assert proof['verification_profile_sha256'] == v2_case['verification_policy'].sha256
    assert proof['test_plan_sha256'] == v2_case['qa']['test_plan_sha256']
    assert proof['target']['workspace_id'] == '22042420337195501'
    assert proof['human_acceptance_recorded'] is False


def test_actual_shaped_v2_binding_scope_is_exact_and_byte_flags_remain_required(v2_case):
    assert v2_case['qa']['schema_version'] == 2
    assert v2_case['qa']['binding']['scope'] == 'exact-package-clean-install-v2'
    assert gate.verify_detached_proof(**v2_arguments(v2_case))['schema_version'] == 2
    for flag in ('profile_bytes_verified', 'package_bytes_verified', 'native_spec_bytes_verified',
                 'import_receipt_bytes_verified', 'package_manifest_verified', 'clean_install_verified',
                 'verification_profile_bytes_verified'):
        changed = deepcopy(v2_case)
        changed['qa']['binding'][flag] = False
        with pytest.raises(gate.VerificationError):
            gate.verify_detached_proof(**v2_arguments(changed))


@pytest.mark.parametrize('scope', ['exact-package-clean-install', 'exact-package-clean-install-v3',
                                 'exact-package-clean-install-v2 ', None])
def test_v2_rejects_legacy_or_ambiguous_runtime_binding_scope(v2_case, scope):
    v2_case['qa']['binding']['scope'] = scope
    with pytest.raises(gate.VerificationError, match='all mounted input bytes'):
        gate.verify_detached_proof(**v2_arguments(v2_case))


def test_v1_rejects_v2_runtime_binding_scope_without_upgrading_historical_policy(proof_case):
    proof_case['qa']['binding']['scope'] = 'exact-package-clean-install-v2'
    with pytest.raises(gate.VerificationError, match='all mounted input bytes'):
        gate.verify_detached_proof(**arguments(proof_case))


@pytest.mark.parametrize('mutation', ['conflicting_root_key', 'repeated_root_key',
                                    'conflicting_column_key', 'float_length'])
def test_v2_independently_parses_exact_packaged_native_spec(proof_case, mutation):
    case = deepcopy(proof_case)
    with zipfile.ZipFile(io.BytesIO(case['package'])) as archive:
        members = {name: archive.read(name) for name in archive.namelist() if name != 'manifest.json'}
    native_raw = members['native-form-spec.json']
    if mutation in {'conflicting_root_key', 'repeated_root_key'}:
        table = 'FOX_NATIVE_CONFLICT' if mutation == 'conflicting_root_key' else case['snapshot']['native_form']['table_name']
        native_raw = b'{"table_name":' + json.dumps(table).encode() + b',' + native_raw[1:]
    elif mutation == 'conflicting_column_key':
        native_raw = native_raw.replace(b'"data_type":', b'"data_type":"CLOB","data_type":', 1)
    else:
        native = json.loads(native_raw)
        field = next(column for column in native['columns'] if column['data_type'] == 'VARCHAR2')
        field['length'] = float(field['length'])
        native_raw = raw(native)
    members['native-form-spec.json'] = native_raw
    case['package'] = package_bytes(members)
    for part in ('clean', 'target'):
        case[part].update(package_sha256=sha(case['package']), native_spec_sha256=sha(native_raw))
    case['qa']['binding']['package_sha256'] = sha(case['package'])
    case = bind_v2(case)
    # The old package reader's last-key/equal-number behavior is not the v2
    # verification reader's metadata authority, even with a valid new manifest.
    assert gate.verify_package(case['package'], case['release'], case['snapshot']['native_form']) == sha(case['package'])
    with pytest.raises(gate.VerificationError):
        gate.verify_detached_proof(**v2_arguments(case))


@pytest.mark.parametrize('mutation', ['target_app_float', 'result_target_app_float',
                                    'profile_length_float', 'context_count_float'])
def test_v2_integer_metadata_does_not_use_python_numeric_equality(v2_case, mutation):
    if mutation == 'target_app_float':
        v2_case['target']['application_id'] = float(v2_case['target']['application_id'])
    elif mutation == 'result_target_app_float':
        v2_case['qa']['target'] = deepcopy(v2_case['target'])
        v2_case['qa']['target']['application_id'] = float(v2_case['target']['application_id'])
    elif mutation == 'profile_length_float':
        field = next(field for field in v2_case['profile']['fields'] if field['data_type'] == 'VARCHAR2')
        field['max_length'] = float(field['max_length'])
        v2_case['target']['profile_sha256'] = sha(raw(v2_case['profile']))
    else:
        test = next(test for test in v2_case['qa']['tests'] if test['name'] == 'concurrent_edit')
        test['evidence']['independent_browser_contexts'] = 2.0
    v2_case['qa']['target_receipt_sha256'] = sha(raw(v2_case['target']))
    with pytest.raises(gate.VerificationError):
        gate.verify_detached_proof(**v2_arguments(v2_case))


@pytest.mark.parametrize('label', ['SELECT value FROM sample', 'Title;note',
                                  '<b>markup</b>', 'hidden\u200bcontrol', '\u0378', '   '])
def test_structural_qa_plan_cannot_authorize_invalid_producer_package(harness, monkeypatch, label):
    # Reseal the synthetic harness honestly around its altered source/spec.
    # Integrity and a derivable QA plan must not replace producer authorization.
    files = harness.snapshot['files']
    xml = files[0]['text'].replace('Prompt="Work title"', 'Prompt="' + escape(label, {'"': '&quot;'}) + '"')
    files[0] = checked_source(files[0]['name'], xml.encode())
    harness.snapshot['source_hash'] = inventory(files)['source_hash']
    harness.snapshot['native_form']['columns'][1]['label'] = label
    packaged = valid_package.__wrapped__(harness)
    case = bind_v2(proof_case.__wrapped__(packaged, harness))
    native = case['snapshot']['native_form']
    assert case['profile']['fields'][0]['label'] == label
    assert derive_native_qa_plan(native, case['clean']['native_spec_sha256']) == case['qa']['test_plan']
    assert gate.verify_package(case['package'], case['release'], native) == sha(case['package'])
    with pytest.raises(gate.VerificationError, match='canonical native producer contract'):
        gate.verify_detached_proof(**v2_arguments(case))

    # The unchanged installer's offline validator independently calls its own
    # canonical producer contract before schema SQL or release authorization.
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / 'converter'))
    from forms2apex import clean_package
    original = clean_package.validate_native_spec
    calls = []
    def observed_contract(spec):
        calls.append(spec)
        return original(spec)
    monkeypatch.setattr(clean_package, 'validate_native_spec', observed_contract)
    with pytest.raises(clean_package.PackageValidationError):
        clean_package.validate_native_package(case['package'], sha(case['package']))
    assert calls == [native]


def test_v2_package_verification_precedes_structural_qa_planning(v2_case, monkeypatch):
    from fox import native_qa_plan
    calls = []
    original = gate.verify_package
    def observed_package(*args, **kwargs):
        calls.append('package')
        return original(*args, **kwargs)
    original_plan = native_qa_plan.derive_native_qa_plan
    def observed_plan(*args, **kwargs):
        assert calls == ['package']
        calls.append('plan')
        return original_plan(*args, **kwargs)
    monkeypatch.setattr(gate, 'verify_package', observed_package)
    monkeypatch.setattr(native_qa_plan, 'derive_native_qa_plan', observed_plan)
    gate.verify_detached_proof(**v2_arguments(v2_case))
    assert calls == ['package', 'plan']


def test_authorized_unicode_label_is_exact_not_normalized(harness):
    label = 'Cafe\u0301'
    files = harness.snapshot['files']
    files[0] = checked_source(files[0]['name'], files[0]['text'].replace('Work title', label).encode())
    harness.snapshot['source_hash'] = inventory(files)['source_hash']
    harness.snapshot['native_form']['columns'][1]['label'] = label
    case = bind_v2(proof_case.__wrapped__(valid_package.__wrapped__(harness), harness))
    assert case['profile']['fields'][0]['label'] == label
    assert gate.verify_detached_proof(**v2_arguments(case))['schema_version'] == 2
    case['profile']['fields'][0]['label'] = 'Caf\u00e9'
    case['target']['profile_sha256'] = sha(raw(case['profile']))
    case['qa']['target_receipt_sha256'] = sha(raw(case['target']))
    with pytest.raises(gate.VerificationError):
        gate.verify_detached_proof(**v2_arguments(case))


def test_two_separately_bound_jobs_accept_own_policy_only(tmp_path, monkeypatch):
    first = independent_case(tmp_path, monkeypatch, job_letter='b', token='261017_1234ABCD')
    second = independent_case(tmp_path, monkeypatch, job_letter='c', token='261017_5678ABCD')
    first_proof = gate.verify_detached_proof(**v2_arguments(first))
    second_proof = gate.verify_detached_proof(**v2_arguments(second))
    assert first_proof['job_id'] != second_proof['job_id']
    assert first_proof['package_sha256'] != second_proof['package_sha256']
    assert first_proof['target']['workspace_id'] != second_proof['target']['workspace_id']
    second['verification_policy'] = first['verification_policy']
    with pytest.raises(gate.VerificationError): gate.verify_detached_proof(**v2_arguments(second))


def test_minimal_native_package_has_only_computed_not_applicable_cases(tmp_path, monkeypatch):
    case = independent_case(tmp_path, monkeypatch, job_letter='b', token='261017_90ABCDEF', minimal=True)
    proof = gate.verify_detached_proof(**v2_arguments(case))
    tests = {item['name']: item for item in case['qa']['tests']}
    assert tests['invalid_number']['status'] == 'NOT_APPLICABLE'  # NUMBER PK is not editable.
    assert tests['required_fields']['status'] == 'NOT_APPLICABLE'
    assert tests['maximum_length']['status'] == 'NOT_APPLICABLE'
    assert tests['invalid_date']['status'] == 'PASSED'
    assert len(proof['required_tests']) == 11
    tests['invalid_date'].update(applicable=False, required=False, status='NOT_APPLICABLE',
                                 reason_code='NO_EDITABLE_DATE_FIELDS', field_names=[], field_results=[])
    with pytest.raises(gate.VerificationError): gate.verify_detached_proof(**v2_arguments(case))


@pytest.mark.parametrize('change', ['wrong_app', 'wrong_workspace', 'wrong_vm', 'bool_app', 'float_workspace',
                                   'profile_hash_cycle', 'not_fresh', 'bool_count', 'different_package'])
def test_actual_allocation_bytes_must_match_reserved_identity(v2_case, change):
    allocation = json.loads(v2_case['allocation_raw'])
    if change == 'wrong_app': allocation['target']['application_id'] += 1
    if change == 'wrong_workspace': allocation['target']['workspace_id'] = '22042420337195502'
    if change == 'wrong_vm': allocation['target']['instance_id'] = 'another-instance'
    if change == 'bool_app': allocation['target']['application_id'] = True
    if change == 'float_workspace': allocation['target']['workspace_id'] = 22042420337195501
    if change == 'profile_hash_cycle': allocation['verification_profile_sha256'] = 'a' * 64
    if change == 'not_fresh': allocation['fresh_namespace']['schema_created_fresh'] = False
    if change == 'bool_count': allocation['fresh_namespace']['application_count'] = False
    if change == 'different_package': allocation['binding']['package_sha256'] = 'a' * 64
    altered = raw(allocation)
    document = v2_case['verification_policy'].document
    document['binding']['allocation_receipt_sha256'] = sha(altered)
    policy = BoundVerificationPolicy(raw(document))
    with pytest.raises(VerificationPolicyError): validate_allocation_receipt(altered, policy)


@pytest.mark.parametrize('key,value', [('job_id', 'fox-' + 'b' * 20), ('source_manifest_sha256', 'b' * 64),
                                     ('package_sha256', 'b' * 64), ('allocation_receipt_sha256', 'b' * 64)])
def test_cross_job_package_source_allocation_policy_substitution_rejected(v2_case, key, value):
    document = v2_case['verification_policy'].document; document['binding'][key] = value
    v2_case['verification_policy'] = BoundVerificationPolicy(raw(document))
    with pytest.raises(gate.VerificationError): gate.verify_detached_proof(**v2_arguments(v2_case))


@pytest.mark.parametrize('part,key,value', [
    ('clean', 'schema_version', 1), ('clean', 'scope', 'fox-clean-package-install-v1'),
    ('clean', 'verification_profile_sha256', 'b' * 64), ('clean', 'allocation_receipt_sha256', 'b' * 64),
    ('target', 'schema_version', 1), ('target', 'verification_profile_sha256', 'b' * 64),
    ('qa', 'schema_version', 1), ('qa', 'test_plan_sha256', 'b' * 64),
    ('qa', 'initial_primary_keys', ['1']), ('qa', 'retained_records', []),
    ('qa', 'pk_set_checks', []), ('qa', 'row_tracking', {}), ('qa', 'final_expected_record', {}),
])
def test_v2_receipts_cannot_be_substituted_or_downgraded(v2_case, part, key, value):
    v2_case[part][key] = value
    with pytest.raises(gate.VerificationError): gate.verify_detached_proof(**v2_arguments(v2_case))


@pytest.mark.parametrize('change', ['wrong_edit_field', 'float_pk', 'null_pk', 'duplicate_pk', 'extra_pk', 'missing_cancel',
                                   'missing_field', 'extra_field', 'failed_set', 'wrong_final_value', 'unverified_profile'])
def test_v2_row_and_field_coverage_is_not_top_level_pass(v2_case, change):
    qa = v2_case['qa']; tests = {item['name']: item for item in qa['tests']}
    if change == 'wrong_edit_field': tests['concurrent_edit']['evidence']['field'] = 'AMOUNT'
    if change == 'float_pk': qa['row_tracking']['retained_primary_key']['value'] = 1.0
    if change == 'null_pk': qa['row_tracking']['retained_primary_key']['value'] = None
    if change == 'duplicate_pk': qa['row_tracking']['final_observed_primary_keys'] *= 2
    if change == 'extra_pk': qa['row_tracking']['final_observed_primary_keys'].append('9007199254741002')
    if change == 'missing_cancel': qa['pk_set_checks'] = [item for item in qa['pk_set_checks'] if item['test_name'] != 'cancel_create']
    if change == 'missing_field': qa['pk_set_checks'] = [item for item in qa['pk_set_checks'] if item.get('field_name') != 'DUE_DATE']
    if change == 'extra_field': qa['pk_set_checks'][-1]['field_name'] = 'UNDECLARED'
    if change == 'failed_set': qa['pk_set_checks'][-1]['passed'] = False
    if change == 'wrong_final_value': qa['final_expected_record']['expected_values']['TITLE'] = 'E'
    if change == 'unverified_profile': qa['binding']['verification_profile_bytes_verified'] = False
    with pytest.raises(gate.VerificationError): gate.verify_detached_proof(**v2_arguments(v2_case))


def test_v2_promotion_keeps_raw_profile_and_human_acceptance_separate(v2_promotion):
    c, root, pid, rid, job, operator, case = v2_promotion
    outcome = promote_v2(v2_promotion)
    assert outcome['state'] == 'VERIFIED'
    assert (job / 'technical-verification/verification-profile.json').read_bytes() == case['verification_policy'].raw
    assert (job / 'technical-verification/allocation-receipt.json').read_bytes() == case['allocation_raw']
    base = f'/api/projects/{pid}/runs/{rid}'
    assert c.get(base + '/download').status_code == 409
    assert c.get(base + '/evidence').json()['technical_verification']['schema_version'] == 2
    assert c.post(base + '/accept', json=acceptance(v2_promotion)).status_code == 200
    assert c.get(base + '/download').content == case['package']


def test_v2_historical_recheck_needs_no_current_profile_or_version_allowlist(v2_promotion, monkeypatch):
    c, root, pid, rid, job, operator, case = v2_promotion
    first = promote_v2(v2_promotion)
    original = (job / 'technical-verification/verification.json').read_bytes()
    monkeypatch.setattr(policy_module, 'SUPPORTED_ACTIVE_VERSIONS', frozenset())
    assert promote_v2(v2_promotion, datetime(2027, 1, 1, tzinfo=timezone.utc))['idempotent'] is True
    monkeypatch.setattr(gate, 'load_verification_profile', lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError('Current operator policy must not be opened')))
    existing = gate.verify_existing_native_run(root=root, run_id=rid)
    assert existing['read_only'] is True and existing['proof_sha256'] == first['proof_sha256']
    assert (job / 'technical-verification/verification.json').read_bytes() == original
    assert c.post(f'/api/projects/{pid}/runs/{rid}/accept', json=acceptance(v2_promotion)).status_code == 200
    assert c.get(f'/api/projects/{pid}/runs/{rid}/download').content == case['package']


def test_v1_proof_bytes_survive_v2_active_policy_changes(promotion_case, monkeypatch):
    c, root, pid, rid, job, _, case = promotion_case
    original = promote(promotion_case)
    raw_proof = (job / 'technical-verification/verification.json').read_bytes()
    monkeypatch.setattr(policy_module, 'SUPPORTED_ACTIVE_VERSIONS', frozenset())
    monkeypatch.setattr(gate, 'load_verification_profile', lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError('v1 must not read current v2 policy')))
    assert promote(promotion_case)['proof_sha256'] == original['proof_sha256']
    assert gate.verify_existing_native_run(root=root, run_id=rid)['proof_sha256'] == original['proof_sha256']
    assert (job / 'technical-verification/verification.json').read_bytes() == raw_proof
    assert c.post(f'/api/projects/{pid}/runs/{rid}/accept', json=acceptance(promotion_case)).status_code == 200
    assert c.get(f'/api/projects/{pid}/runs/{rid}/download').content == case['package']


@pytest.mark.parametrize('mutation', ['missing', 'different_bytes', 'different_object'])
def test_retained_v2_profile_tamper_blocks_acceptance(v2_promotion, mutation):
    c, root, pid, rid, job, _, case = v2_promotion
    promote_v2(v2_promotion)
    path = job / 'technical-verification/verification-profile.json'
    if mutation == 'missing': path.rename(path.with_name('retained-profile-preserved.json'))
    if mutation == 'different_bytes': path.write_bytes(path.read_bytes() + b'\n')
    if mutation == 'different_object':
        document = case['verification_policy'].document; document['target']['workspace_id'] = '22042420337195502'
        path.write_bytes(raw(document))
    assert c.post(f'/api/projects/{pid}/runs/{rid}/accept', json=acceptance(v2_promotion)).status_code == 409
    with pytest.raises(gate.VerificationError): gate.verify_existing_native_run(root=root, run_id=rid)


def test_different_profile_cannot_replace_v2_decision(v2_promotion):
    promote_v2(v2_promotion)
    case = v2_promotion[6]
    changed = BoundVerificationPolicy(case['verification_policy'].raw + b'\n')
    (v2_promotion[5] / 'verification-profile.json').write_bytes(changed.raw)
    case['verification_policy'] = changed
    with pytest.raises(gate.VerificationError, match='different operator profile'): promote_v2(v2_promotion)


def test_new_decision_cannot_use_historical_mode_to_bypass_active_versions(v2_promotion, monkeypatch):
    monkeypatch.setattr(policy_module, 'SUPPORTED_ACTIVE_VERSIONS', frozenset())
    with pytest.raises(gate.VerificationError, match='unsupported for a new technical decision'): promote_v2(v2_promotion)
    with sqlite3.connect(v2_promotion[1] / 'fox.sqlite3') as db:
        assert db.execute('SELECT state FROM runs').fetchone()[0] == 'QA_REQUIRED'


def test_historical_flag_never_authorizes_even_supported_new_decision(v2_promotion):
    case = v2_promotion[6]
    case['verification_policy'] = BoundVerificationPolicy(case['verification_policy'].raw, historical=True)
    with pytest.raises(gate.VerificationError, match='historical policy cannot authorize a new'): promote_v2(v2_promotion)
    assert not (v2_promotion[4] / 'technical-verification').exists()


def test_retained_allocation_bytes_cannot_be_replaced(v2_promotion):
    promote_v2(v2_promotion)
    retained = v2_promotion[4] / 'technical-verification/allocation-receipt.json'
    retained.write_bytes(retained.read_bytes() + b'\n')
    with pytest.raises(gate.VerificationError):
        gate.verify_existing_native_run(root=v2_promotion[1], run_id=v2_promotion[3])


@pytest.mark.parametrize('interruption_file', ['clean-install.json', 'verification.json'])
def test_v2_precommit_retry_uses_retained_policy_and_original_time(v2_promotion, monkeypatch, interruption_file):
    original = gate._save_once
    def crash(path, payload):
        if path.name == interruption_file: raise OSError('Synthetic v2 interrupted commit')
        original(path, payload)
    monkeypatch.setattr(gate, '_save_once', crash)
    with pytest.raises(OSError): promote_v2(v2_promotion)
    attempt = v2_promotion[4] / 'technical-verification/attempt.json'
    original_attempt = attempt.read_bytes()
    monkeypatch.setattr(gate, '_save_once', original)
    monkeypatch.setattr(policy_module, 'SUPPORTED_ACTIVE_VERSIONS', frozenset())
    case = v2_promotion[6]
    case['verification_policy'] = BoundVerificationPolicy(case['verification_policy'].raw, historical=True)
    assert promote_v2(v2_promotion, datetime(2027, 1, 1, tzinfo=timezone.utc))['state'] == 'VERIFIED'
    assert attempt.read_bytes() == original_attempt
    with sqlite3.connect(v2_promotion[1] / 'fox.sqlite3') as db:
        assert db.execute('SELECT created FROM technical_verifications').fetchone()[0] == NOW.timestamp()


@pytest.mark.parametrize('filename', ['verification-profile.json', 'allocation-receipt.json'])
@pytest.mark.parametrize('mutation', ['missing', 'changed'])
def test_historical_retry_requires_exact_retained_profile_and_allocation(v2_promotion, monkeypatch, filename, mutation):
    original = gate._save_once
    def crash(path, payload):
        if path.name == 'clean-install.json': raise OSError('Synthetic interrupted receipt persistence')
        original(path, payload)
    monkeypatch.setattr(gate, '_save_once', crash)
    with pytest.raises(OSError): promote_v2(v2_promotion)
    monkeypatch.setattr(gate, '_save_once', original)
    retained = v2_promotion[4] / 'technical-verification' / filename
    if mutation == 'missing':
        retained.rename(retained.with_suffix('.preserved.json'))
    else:
        retained.write_bytes(retained.read_bytes() + b'\n')
    case = v2_promotion[6]
    case['verification_policy'] = BoundVerificationPolicy(case['verification_policy'].raw, historical=True)
    with pytest.raises(gate.VerificationError): promote_v2(v2_promotion)
    with sqlite3.connect(v2_promotion[1] / 'fox.sqlite3') as db:
        assert db.execute('SELECT state FROM runs').fetchone()[0] == 'QA_REQUIRED'
        assert db.execute("SELECT COUNT(*) FROM events WHERE action='native_technical_verified'").fetchone()[0] == 0


def test_cli_historical_mode_cannot_take_an_active_policy(v2_promotion, capsys):
    promote_v2(v2_promotion)
    root, rid = v2_promotion[1], v2_promotion[3]
    assert gate.main(['--data-dir', str(root), '--run-id', rid, '--verify-existing']) == 0
    assert '"active_policy_applied": false' in capsys.readouterr().out
    assert gate.main(['--data-dir', str(root), '--run-id', rid, '--verify-existing',
                      '--profile', 'jsn-clean-native-beta-20261017-v1']) == 1
