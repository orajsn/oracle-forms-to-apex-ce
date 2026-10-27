"""Pure project clean-install contracts; native single-form plans stay unchanged.

Allocation/profile formats deliberately remain the established JSN v2 formats.
Only the project plan and phase journal have new identities. Package integrity
is not target authority: the caller must re-observe its private source and VM.
"""
from __future__ import annotations

import io
import re
import zipfile

from . import contracts as c
from forms2apex import native_project
from forms2apex.project_release import validate_project_package

PLAN_SCOPE = 'fox-project-clean-install-plan-v1'
PHASE_SCOPE = 'fox-project-clean-operator-phase-v1'
PROFILE_ID = 'native-project-v1'
HASH_KEYS = {'source_manifest_sha256', 'package_sha256', 'sql_sha256',
             'schema_script_sha256', 'project_spec_sha256', 'source_to_apex_sha256'}
BINDING_KEYS = HASH_KEYS | {'job_id', 'profile_id', 'source_application_id',
    'source_application_alias', 'source_reimport_application_id',
    'source_reimport_application_alias', 'sql_member', 'schema_member', 'tables',
    'original_parsing_schema'}


def load_package(raw, expected_sha256):
    c._require(type(raw) is bytes and 0 < len(raw) <= 8_000_000
               and c.digest(raw) == c._sha(expected_sha256), 'Project package byte identity differs.')
    checked = validate_project_package(raw)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        project_raw = archive.read('native-project-spec.json')
        trace_raw = archive.read('source-to-apex.json')
        historical = c.load_json(archive.read('evidence/target-profile.json'))
        sql_member = f"sql/f{checked['evidence']['application_id']}.sql"
        application_sql = archive.read(sql_member)
        schema_sql = archive.read('schema/01_synthetic_schema.sql')
    original = historical['database']['parsing_schema']
    c._require(type(original) is str and re.fullmatch(r'[A-Z][A-Z0-9_]{0,29}', original),
               'Original parsing schema is not an unquoted identifier.')
    # Never run package-supplied DDL, even after ZIP validation: regenerate it.
    generated = native_project.render_project_schema(checked['project']).encode('utf-8')
    c._require(generated == schema_sql, 'Project schema does not match canonical metadata.')
    release = checked['evidence']
    c._require(all(release.get(key) is True for key in ('reviewer_approved',
        'reviewer_execution_verified', 'sqlcl_valid', 'import_passed', 'package_reimport_passed')),
        'Project release technical gates are incomplete.')
    # Spec v2 and trace v2 retain this clean-plan format: both exact byte
    # identities already bind every original source reference and recomputed
    # storage mapping. Only physical table names belong in executable QA.
    # The package validator requires the visible storage-mapping artifact for
    # v2; a legacy v1 package is not reinterpreted as an optional mapped schema.
    binding = {'job_id': release['job_id'], 'profile_id': PROFILE_ID,
        'source_manifest_sha256': checked['project']['source_manifest_sha256'],
        'package_sha256': c.digest(raw), 'sql_sha256': c.digest(application_sql),
        'schema_script_sha256': c.digest(generated), 'project_spec_sha256': c.digest(project_raw),
        'source_to_apex_sha256': c.digest(trace_raw), 'source_application_id': release['application_id'],
        'source_application_alias': release['application_alias'],
        'source_reimport_application_id': release['package_reimport']['application_id'],
        'source_reimport_application_alias': release['package_reimport']['application_alias'],
        'sql_member': sql_member, 'schema_member': 'schema/01_synthetic_schema.sql',
        'tables': sorted({form['native_form']['table_name'] for form in checked['project']['forms']}),
        'original_parsing_schema': original}
    _binding(binding)
    return {**checked, 'binding': binding, 'package_bytes': len(raw), 'project_raw': project_raw, 'trace_raw': trace_raw,
            'application_sql': application_sql, 'schema_sql': generated}


def _binding(value):
    c._keys(value, BINDING_KEYS, 'Project package binding fields differ.')
    c._require(type(value['job_id']) is str and c._JOB.fullmatch(value['job_id'])
               and value['profile_id'] == PROFILE_ID, 'Project identity differs.')
    for key in HASH_KEYS:
        c._sha(value[key])
    app, other = c._integer(value['source_application_id']), c._integer(value['source_reimport_application_id'])
    alias = 'F2A_' + value['job_id'].upper().replace('-', '_')
    c._require(app != other and value['source_application_alias'] == alias
               and value['source_reimport_application_alias'] == alias + '_SQLCHECK'
               and value['sql_member'] == f'sql/f{app}.sql'
               and value['schema_member'] == 'schema/01_synthetic_schema.sql', 'Project source application identity differs.')
    tables = value['tables']
    c._require(type(tables) is list and 0 < len(tables) <= native_project.MAX_FORMS
               and all(type(name) is str and re.fullmatch(r'FOX_NATIVE_[A-Z0-9_]{1,19}', name) for name in tables)
               and tables == sorted(set(tables)), 'Project physical tables differ.')
    c._require(type(value['original_parsing_schema']) is str
               and re.fullmatch(r'[A-Z][A-Z0-9_]{0,29}', value['original_parsing_schema']), 'Invalid original schema.')


def make_plan(source, package, namespace, created_at, *, operator_code_sha256):
    namespace = c._namespace(namespace)
    return validate_plan({'schema_version': 1, 'scope': PLAN_SCOPE, 'policy_id': c.POLICY_ID,
        'created_at_utc': created_at, 'operator_code_sha256': operator_code_sha256,
        'source_origin': c.validate_source_attestation(source), 'binding': package['binding'],
        'target': {**c.FIXED_TARGET, 'workspace': namespace, 'parsing_schema': namespace,
                   'application_alias': 'F2A_QA_' + namespace[7:]}, 'expected_versions': dict(c.VERSIONS)})


def validate_plan(value, *, package=None, source_attestation=None, operator_code_sha256=None):
    plan = c._document(value)
    if type(value) is bytes:
        c._require(value == c.canonical_bytes(plan), 'Project plan is not exact canonical bytes.')
    c._keys(plan, c._PLAN_KEYS, 'Project plan fields differ.')
    c._require(type(plan['schema_version']) is int and plan['schema_version'] == 1
               and plan['scope'] == PLAN_SCOPE and plan['policy_id'] == c.POLICY_ID, 'Project plan scope differs.')
    created = c._timestamp(plan['created_at_utc'])
    c._sha(plan['operator_code_sha256']); c._target(plan['target']); c._versions(plan['expected_versions'])
    _binding(plan['binding'])
    origin = c.validate_source_attestation(plan['source_origin'])
    c._require(-c.MAX_CLOCK_SKEW_SECONDS <= (created - c._timestamp(origin['observed_at_utc'])).total_seconds() <= 86400
               and plan['target']['workspace'][7:13] == created.strftime('%y%m%d'), 'Plan source time differs.')
    c._require(all(origin[key] == plan['binding'][key] for key in ('job_id', 'package_sha256', 'source_manifest_sha256'))
               and plan['target']['parsing_schema'] != plan['binding']['original_parsing_schema'], 'Plan source binding differs.')
    if package is not None:
        c._require(plan['binding'] == package['binding'] and origin['package_bytes'] == package['package_bytes'],
                   'Exact project package differs from plan.')
    if source_attestation is not None:
        current = c.validate_source_attestation(source_attestation)
        c._require(all(origin[key] == current[key] for key in c._SOURCE_KEYS - {'observed_at_utc', 'run_state'})
                   and c._timestamp(current['observed_at_utc']) >= c._timestamp(origin['observed_at_utc']),
                   'Private project source re-observation differs.')
    if operator_code_sha256 is not None:
        c._require(plan['operator_code_sha256'] == c._sha(operator_code_sha256), 'Operator code differs from project plan.')
    return plan


def plan_sha256(plan):
    return c.digest(c.canonical_bytes(validate_plan(plan)))


def validate_allocation(value, plan):
    plan, value = validate_plan(plan), c._document(value)
    c._keys(value, c._ALLOCATION_KEYS, 'Project allocation fields differ.')
    c._require(type(value['schema_version']) is int and value['schema_version'] == 1
               and value['scope'] == c.ALLOCATION_SCOPE and value['passed'] is True
               and value['plan_sha256'] == plan_sha256(plan)
               and c._timestamp(value['allocated_at_utc']) >= c._timestamp(plan['created_at_utc']), 'Project allocation identity differs.')
    c._require(value['binding'] == {key: plan['binding'][key] for key in ('job_id', 'source_manifest_sha256', 'package_sha256')},
               'Project allocation package differs.')
    c._target(value['target'], allocated=True); c._versions(value['observed_versions'])
    c._require(all(value['target'][key] == expected for key, expected in plan['target'].items())
               and value['target']['application_id'] not in {plan['binding']['source_application_id'],
                    plan['binding']['source_reimport_application_id'], *c.PROTECTED_APPLICATION_IDS}, 'Project clean identity is not fresh.')
    fresh = value['fresh_namespace']
    c._keys(fresh, {'workspace_created_fresh', 'schema_created_fresh', 'application_count', 'user_object_count'}, 'Allocation emptiness fields differ.')
    c._require(fresh['workspace_created_fresh'] is True and fresh['schema_created_fresh'] is True
               and all(type(fresh[key]) is int and fresh[key] == 0 for key in ('application_count', 'user_object_count')),
               'Project allocation is not fresh and empty.')
    return value


def make_verification_profile(plan, allocation_raw):
    c._require(type(allocation_raw) is bytes, 'Exact allocation bytes are required.')
    allocation = validate_allocation(allocation_raw, plan)
    return {'schema_version': 1, 'scope': c.PROFILE_SCOPE, 'policy_id': c.POLICY_ID,
        'binding': {**allocation['binding'], 'allocation_receipt_sha256': c.digest(allocation_raw)},
        'target': {key: value for key, value in allocation['target'].items() if key != 'instance_id'},
        'expected_versions': dict(c.VERSIONS), 'max_evidence_age_seconds': 86400}


def validate_phase_record(value, plan, phase):
    validate_plan(plan)
    c._require(phase in c.PHASES, 'Invalid project operator phase.')
    if value is None:
        return 'unattempted'
    record = c._document(value)
    c._keys(record, {'schema_version', 'scope', 'plan_sha256', 'phase', 'state', 'started_at_utc', 'finished_at_utc', 'evidence_sha256'},
            'Project phase fields differ.')
    c._require(type(record['schema_version']) is int and record['schema_version'] == 1
               and record['scope'] == PHASE_SCOPE and record['plan_sha256'] == plan_sha256(plan)
               and record['phase'] == phase and record['state'] in ('intent', 'complete', 'attention'), 'Project phase identity differs.')
    started = c._timestamp(record['started_at_utc'])
    c._require(started >= c._timestamp(plan['created_at_utc']), 'Project phase predates plan.')
    if record['state'] == 'complete':
        c._require(c._timestamp(record['finished_at_utc']) >= started, 'Project completion predates dispatch.')
        c._sha(record['evidence_sha256'])
        return 'complete'
    c._require(record['evidence_sha256'] is None and (record['finished_at_utc'] is None
        or record['state'] == 'attention' and c._timestamp(record['finished_at_utc']) >= started), 'Incomplete project phase claims evidence.')
    return 'attention'
