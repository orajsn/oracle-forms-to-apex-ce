"""Offline operator tests. No network, database, VM or real credentials."""
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'converter'))
from qa.operator import contracts as c
from qa.operator import remote as r

TIME = '2026-10-17T01:02:03.000000Z'
LATER = '2026-10-17T02:02:03.000000Z'
NAME = 'FOX_QA_261017_89ABCDEF'
CODE = 'b' * 64
ADMIN = 'NotARealPassword9!'


def vendor_sql(schema='FORMS2APEX_POC', workspace='9009446931169094', app=123,
               alias='F2A_FOX_AAAAAAAAAAAAAAAAAAAA', offset=0):
    header = f",p_default_workspace_id=>{workspace}\n,p_default_application_id=>{app}\n,p_default_owner=>'{schema}'\n"
    flow = f"wwv_imp_workspace.create_flow(\n,p_owner=>nvl(wwv_flow_application_install.get_schema,'{schema}')\n,p_alias=>nvl(wwv_flow_application_install.get_application_alias,'{alias}')\n"
    flow += '\n'.join(',' + name + '=>null' for name in r.FLOW_FIELDS) + '\n);\n'
    pages = ''.join(f'wwv_flow_imp_page.create_page(\np_id=>wwv_flow_imp.id({index + offset})\n);\n' for index in range(1, 31))
    return (header + flow + pages).encode()


def fixture():
    native = {'profile_id': 'native-table-form-v1', 'data_mode': 'synthetic_test_only', 'table_name': 'FOX_NATIVE_TEST',
              'supported_operations': ['query', 'insert', 'update'],
              'columns': [{'name': 'TEST_ID', 'data_type': 'NUMBER', 'nullable': False, 'label': 'ID', 'identity': True, 'primary_key': True},
                          {'name': 'TITLE', 'data_type': 'VARCHAR2', 'nullable': False, 'label': 'Title', 'length': 100, 'identity': False, 'primary_key': False}]}
    native_raw = (json.dumps(native, indent=2) + '\n').encode()
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        archive.writestr('native-form-spec.json', native_raw)
    raw = stream.getvalue()
    source = {'schema_version': 1, 'scope': c.SOURCE_SCOPE, 'observed_at_utc': TIME, 'instance_id': c.INSTANCE,
              'compartment_id': c.COMPARTMENT, 'region': c.REGION, 'job_id': 'fox-aaaaaaaaaaaaaaaaaaaa',
              'run_state': 'QA_REQUIRED', 'package_sha256': c.digest(raw), 'package_bytes': len(raw), 'source_manifest_sha256': '2' * 64}
    sql, schema = vendor_sql(), b'-- exact fixture DDL bytes\r\nCREATE TABLE FOX_NATIVE_TEST(TEST_ID NUMBER);\r\n'
    package = {'package_sha256': c.digest(raw), 'job_id': source['job_id'], 'source_manifest_sha256': source['source_manifest_sha256'],
               'application_id': 123, 'application_alias': 'F2A_FOX_AAAAAAAAAAAAAAAAAAAA', 'native_form': native,
               'schema_member': 'schema/01_synthetic_schema.sql', 'application_member': 'sql/f123.sql',
               'schema_sql': schema, 'application_sql': sql,
               'selected_member_sha256': {'schema/01_synthetic_schema.sql': c.digest(schema), 'sql/f123.sql': c.digest(sql)},
               'validation_scope': 'package_integrity_and_synthetic_schema_only', 'review_proof_scope': 'fixture',
               'historical_model_environment_verified': False, 'historical_target_profile': None,
               'current_target_authorized': False, 'customer_compatibility_verified': False}
    package['release_evidence'] = {'job_id': source['job_id'], 'application_id': 123, 'application_alias': package['application_alias'],
                                   'source_manifest_sha256': source['source_manifest_sha256'],
                                   'package_reimport': {'passed': True, 'application_id': 456, 'application_alias': package['application_alias'] + '_SQLCHECK'}}
    plan = c.make_plan(source, package, NAME, TIME, native_spec_sha256=c.digest(native_raw), operator_code_sha256=CODE)
    return plan, package, raw


class MemoryStore:
    def __init__(self):
        self.files, self.writes, self.path = {}, [], '/fixed/private/fixture'
        self.locked = False

    def read(self, name):
        return self.files.get(name)

    def create(self, name, raw):
        if name in self.files:
            raise r.RemoteError('CREATE_ONCE')
        self.files[name] = raw
        self.writes.append(name)

    def acquire(self):
        self.locked = True


class MockDriver:
    def __init__(self):
        self.level, self.calls, self.fail, self.bad = 0, [], None, {}
        self.ids = {'workspace_id': '22042420337195501', 'application_id': 34567}

    def scope(self, plan):
        self.calls.append('scope')

    def versions(self, admin):
        self.calls.append('versions')
        return dict(c.VERSIONS)

    def observe(self, plan, admin, allocation=None):
        self.calls.append('observe')
        state = {key: 0 for key in r._counts_sql(plan, 34567 if allocation else None)[1]}
        state['workspace_id'] = None
        if self.level:
            state.update(SCHEMA_COUNT=1, WORKSPACE_COUNT=1, MAPPING_COUNT=1, CORRECT_MAPPING_COUNT=1,
                         PRIVILEGE_COUNT=3, QUOTA_COUNT=1, CORRECT_QUOTA_COUNT=1, ACCOUNT_COUNT=1,
                         USER_COUNT=2, RUNTIME_USER_COUNT=2, workspace_id=self.ids['workspace_id'])
        if self.level >= 2:
            state['OBJECT_COUNT'] = 3
        if self.level >= 3:
            state.update(APPLICATION_COUNT=1, ALIAS_COUNT=1, ID_COUNT=1, EXACT_APP_COUNT=1)
        state.update(self.bad)
        return state

    def _step(self, name):
        self.calls.append(name)
        if self.fail == name:
            raise RuntimeError('do not expose secret SQL ' + ADMIN)

    def allocate(self, plan, admin, credentials):
        self._step('allocate')
        self.level = 1
        return dict(self.ids)

    def schema(self, plan, allocation, package, password):
        self._step('schema')
        self.level = 2

    def import_application(self, plan, allocation, package, password):
        self._step('import')
        self.level = 3

    def table(self, plan, allocation, package, password):
        self._step('table')
        spec = package['native_form']
        return r.verify_table(table_markers(spec), spec, NAME)

    def export(self, plan, allocation, password):
        self._step('export')
        return vendor_sql(NAME, self.ids['workspace_id'], self.ids['application_id'], plan['target']['application_alias'], 1000)


def table_markers(spec):
    markers = [('TABLE_COUNT', '1'), ('NATIVE_TABLE_COUNT', '1'), ('ROW_COUNT', '0'), ('PK_COUNT', '1')]
    for col in spec['columns']:
        markers.append(('COLUMN', '|'.join((col['name'], col['data_type'], 'Y' if col['nullable'] else 'N',
                                           str(col.get('length', 0)), 'YES' if col['identity'] else 'NO'))))
    markers.append(('PK', next(col['name'] for col in spec['columns'] if col['primary_key']) + '|1|ENABLED|VALIDATED'))
    markers.extend((key, '0') for key in ('TRIGGER_COUNT', 'SYNONYM_COUNT', 'DB_LINK_COUNT', 'INVALID_OBJECT_COUNT',
                                        'UNEXPECTED_OBJECT_COUNT', 'UNEXPECTED_SCHEMA_DEPENDENCY_COUNT'))
    return markers


class RemoteTests(unittest.TestCase):
    def setUp(self):
        self.plan, self.package, self.raw = fixture()
        self.store, self.driver = MemoryStore(), MockDriver()
        self.validator = patch.object(r, 'validate_native_package', return_value=self.package).start()
        patch.object(r, 'utc_now', return_value=LATER).start()
        self.addCleanup(patch.stopall)

    def run_operator(self, command='apply', phase='allocate', **kwargs):
        values = dict(expected_plan_sha256=c.plan_sha256(self.plan), phase=phase, apply=command == 'apply',
                      admin_password=ADMIN, operator_code_sha256=CODE, driver=self.driver, store=self.store)
        values.update(kwargs)
        return r.execute(command, c.canonical_bytes(self.plan), self.raw, **values)

    def through(self, last):
        for phase in r.ORDER[:r.ORDER.index(last) + 1]:
            result = self.run_operator(phase=phase)
        return result

    def test_check_and_status_are_file_and_database_read_only(self):
        for command in ('check', 'status'):
            result = self.run_operator(command, None)
            self.assertEqual(result['state'], 'PREPARED')
        self.assertEqual(self.store.writes, [])
        self.assertFalse(self.store.locked)
        self.assertFalse(set(self.driver.calls) & {'allocate', 'schema', 'import', 'export'})

    def test_apply_requires_explicit_phase_and_approval(self):
        for phase, approved in ((None, True), ('allocate', False), ('all', True), ('allocate', 'true')):
            with self.subTest(phase=phase, approved=approved), self.assertRaises(r.RemoteError):
                self.run_operator(phase=phase, apply=approved)
        self.assertEqual(self.store.writes, [])
        self.assertEqual(self.driver.calls, [])

    def test_read_only_commands_cannot_smuggle_apply_or_phase(self):
        for values in ({'apply': True, 'phase': None}, {'apply': False, 'phase': 'allocate'}):
            with self.subTest(values=values), self.assertRaises(r.RemoteError):
                self.run_operator('check', **values)

    def test_approved_plan_and_operator_hash_are_required(self):
        for values in ({'expected_plan_sha256': '0' * 64}, {'operator_code_sha256': '0' * 64}, {'operator_code_sha256': None}):
            with self.subTest(values=values), self.assertRaises(r.RemoteError):
                self.run_operator(**values)
        self.assertFalse(self.driver.calls)

    def test_raw_plan_must_be_canonical_bytes(self):
        with self.assertRaises(r.RemoteError):
            r.execute('check', json.dumps(self.plan).encode(), self.raw, expected_plan_sha256=c.plan_sha256(self.plan),
                      operator_code_sha256=CODE, driver=self.driver, store=self.store)
        self.assertFalse(self.driver.calls)

    def test_pinned_targets_reject_old_namespace_other_cloud_or_region(self):
        for key, value in (('workspace', 'FOX_QA_261017A'), ('parsing_schema', 'FORMS2APEX_POC'),
                           ('compartment_id', 'other'), ('database_id', 'other'), ('region', 'ap-singapore-1'), ('instance_id', 'other')):
            old = self.plan['target'][key]
            self.plan['target'][key] = value
            with self.subTest(key=key), self.assertRaises((r.RemoteError, c.ContractError)):
                self.run_operator()
            self.plan['target'][key] = old
        self.assertFalse(self.driver.calls)

    def test_validator_called_before_any_driver_operation(self):
        self.validator.side_effect = ValueError('unsafe zip')
        with self.assertRaises(r.RemoteError):
            self.run_operator()
        self.assertEqual(self.driver.calls, [])
        self.assertFalse(self.store.writes)

    def test_native_member_binding_rechecked(self):
        self.plan['binding']['native_spec_sha256'] = '0' * 64
        with self.assertRaises(r.RemoteError):
            self.run_operator()
        self.assertFalse(self.driver.calls)

    def test_sql_member_bytes_cannot_change_after_validation(self):
        self.package['application_sql'] += b'\n-- tampered'
        with self.assertRaises(r.RemoteError):
            self.run_operator()
        self.assertFalse(self.driver.calls)

    def test_package_size_must_match_attested_source(self):
        self.plan['source_origin']['package_bytes'] += 1
        with self.assertRaises(r.RemoteError):
            self.run_operator()
        self.assertFalse(self.driver.calls)

    def test_allocate_preserves_independent_credentials_and_intent(self):
        result = self.run_operator()
        self.assertEqual(result['state'], 'PHASE_COMPLETE')
        self.assertEqual(self.store.files['plan.json'], c.canonical_bytes(self.plan))
        self.assertEqual(self.store.files['package.zip'], self.raw)
        schema = c.load_json(self.store.files['schema-credentials.json'])
        users = c.load_json(self.store.files['runtime-credentials.json'])
        values = [schema['schema_password'], users['password'], users['second_password']]
        self.assertEqual(len(set(values)), 3)
        for password in values:
            self.assertEqual(len(password), 30)
            self.assertTrue(r.PASSWORD.fullmatch(password))
            self.assertNotIn(password, json.dumps(result))
            self.assertNotIn(password, self.store.files['allocate.evidence.json'].decode())
        self.assertLess(self.store.writes.index('allocate.intent.json'), self.store.writes.index('allocate.evidence.json'))
        allocation = c.validate_allocation(self.store.files['allocate.evidence.json'], self.plan)
        self.assertIsInstance(allocation['target']['workspace_id'], str)

    def test_existing_namespace_stops_before_intent_or_password_creation(self):
        self.driver.level = 1
        with self.assertRaisesRegex(r.RemoteError, 'NAMESPACE_NOT_UNUSED'):
            self.run_operator()
        self.assertEqual(self.store.writes, [])

    def test_successful_phase_is_not_replayed(self):
        self.run_operator()
        before = deepcopy(self.store.files)
        result = self.run_operator()
        self.assertEqual(result['action'], 'ALREADY_COMPLETE_NO_REPLAY')
        self.assertEqual(before, self.store.files)
        self.assertEqual(self.driver.calls.count('allocate'), 1)

    def test_failed_allocate_preserves_intent_and_never_replays(self):
        self.driver.fail = 'allocate'
        with self.assertRaisesRegex(r.RemoteError, '^PHASE_UNCONFIRMED_NO_REPLAY$') as error:
            self.run_operator()
        self.assertNotIn(ADMIN, str(error.exception))
        self.assertIn('allocate.intent.json', self.store.files)
        self.assertIn('allocate.attention.json', self.store.files)
        self.driver.fail = None
        with self.assertRaisesRegex(r.RemoteError, 'NO_REPLAY'):
            self.run_operator()
        self.assertEqual(self.driver.calls.count('allocate'), 1)

    def test_read_only_check_returns_numeric_sql_diagnostics_without_files(self):
        safe = {'category': 'SQL_EXECUTION_FAILED', 'error_codes': ['ORA-01031'], 'return_code': 1}
        with patch.object(self.driver, 'versions', side_effect=r.RemoteError('SQL_FAILED_OUTPUT_WITHHELD', diagnostics=safe)):
            with self.assertRaises(r.RemoteError) as failure:
                self.run_operator('check', None)
        self.assertEqual(r.failure_response(failure.exception)['diagnostics'], safe)
        self.assertEqual(self.store.writes, [])

    def test_apply_preserves_safe_sql_diagnostics_but_not_replay_or_proof_changes(self):
        self.run_operator()
        safe = {'category': 'SQL_EXECUTION_FAILED', 'error_codes': ['ORA-01031', 'ORA-06512'], 'return_code': 1}
        writes = list(self.store.writes)
        with patch.object(self.driver, 'schema', side_effect=r.RemoteError('SQL_FAILED_OUTPUT_WITHHELD', diagnostics=safe)):
            with self.assertRaisesRegex(r.RemoteError, '^PHASE_UNCONFIRMED_NO_REPLAY$') as failure:
                self.run_operator(phase='schema')
        public = r.failure_response(failure.exception, 'schema')
        self.assertEqual(public['diagnostics'], safe)
        self.assertEqual(public['phase'], 'schema')
        self.assertFalse(public['automatic_replay_permitted'])
        self.assertEqual(self.store.writes[len(writes):], ['schema.intent.json', 'schema.attention.json'])
        self.assertNotIn('schema.evidence.json', self.store.files)
        self.assertNotIn('schema.complete.json', self.store.files)
        with self.assertRaisesRegex(r.RemoteError, 'NO_REPLAY'):
            self.run_operator(phase='schema')

    def test_unknown_exception_messages_and_tampered_diagnostics_are_not_public(self):
        for error in (RuntimeError('SQL_FAILED_OUTPUT_WITHHELD'), RuntimeError('UPPERCASE_SECRET'), r.RemoteError('UPPERCASE_SECRET')):
            self.assertEqual(r.failure_response(error, 'schema')['code'], 'OPERATOR_GUARD_FAILED_OUTPUT_WITHHELD')
        error = r.RemoteError('SQL_FAILED_OUTPUT_WITHHELD')
        error.diagnostics = {'category': 'SQL_EXECUTION_FAILED', 'error_codes': ['ORA-01031'], 'return_code': 1, 'sql': ADMIN}
        self.assertNotIn('diagnostics', r.failure_response(error, 'schema'))
        self.assertNotIn(ADMIN, json.dumps(r.failure_response(error, 'schema')))

    def test_status_of_uncertain_phase_never_attempts_repair(self):
        self.driver.fail = 'allocate'
        with self.assertRaises(r.RemoteError):
            self.run_operator()
        before = deepcopy(self.store.files)
        result = self.run_operator('status', None)
        self.assertEqual(result['state'], 'ATTENTION')
        self.assertEqual(before, self.store.files)

    def test_schema_cannot_run_before_allocate(self):
        with self.assertRaisesRegex(r.RemoteError, 'PHASE_NOT_STARTABLE'):
            self.run_operator(phase='schema')
        self.assertFalse(self.store.writes)

    def test_schema_existing_objects_stop_without_replay(self):
        self.run_operator()
        self.driver.bad['OBJECT_COUNT'] = 1
        with self.assertRaisesRegex(r.RemoteError, 'SCHEMA_NOT_EMPTY'):
            self.run_operator(phase='schema')
        self.assertNotIn('schema.intent.json', self.store.files)

    def test_schema_write_occurs_once_and_then_read_only_table_check(self):
        self.through('schema')
        self.assertEqual(self.driver.calls.count('schema'), 1)
        self.assertEqual(r.phase_state(self.store, self.plan, 'schema'), 'complete')
        result = self.run_operator(phase='schema')
        self.assertEqual(result['action'], 'ALREADY_COMPLETE_NO_REPLAY')
        self.assertEqual(self.driver.calls.count('schema'), 1)

    def test_failed_schema_cannot_be_followed_by_import(self):
        self.run_operator()
        self.driver.fail = 'schema'
        with self.assertRaises(r.RemoteError):
            self.run_operator(phase='schema')
        with self.assertRaises(r.RemoteError):
            self.run_operator(phase='import')
        self.assertNotIn('import', self.driver.calls)

    def test_import_refuses_existing_alias_or_id(self):
        self.through('schema')
        for key in ('APPLICATION_COUNT', 'ALIAS_COUNT', 'ID_COUNT'):
            self.driver.bad = {key: 1}
            with self.subTest(key=key), self.assertRaisesRegex(r.RemoteError, 'APPLICATION_ALREADY_EXISTS'):
                self.run_operator(phase='import')
        self.assertNotIn('import.intent.json', self.store.files)

    def test_changed_privileges_mapping_and_runtime_roles_fail_before_writes(self):
        self.run_operator()
        for key, value in (('ROLE_COUNT', 1), ('PRIVILEGE_COUNT', 4), ('GRANT_COUNT', 1), ('CORRECT_MAPPING_COUNT', 0),
                           ('RUNTIME_USER_COUNT', 1), ('CORRECT_QUOTA_COUNT', 0), ('POC_DEPENDENCY_COUNT', 1)):
            self.driver.bad = {key: value}
            with self.subTest(key=key), self.assertRaisesRegex(r.RemoteError, 'TARGET_ISOLATION_MISMATCH'):
                self.run_operator(phase='schema')
        self.assertNotIn('schema.intent.json', self.store.files)

    def test_version_drift_blocks_all_writes(self):
        self.driver.versions = lambda _: {**c.VERSIONS, 'apex': '26.2.0'}
        with self.assertRaisesRegex(r.RemoteError, 'TESTED_VERSION_PROFILE_MISMATCH'):
            self.run_operator()
        self.assertFalse(self.store.writes)

    def test_complete_receipt_is_bound_to_exact_allocation_and_profile_bytes(self):
        result = self.through('verify')
        self.assertEqual(result['state'], 'QA_READY')
        clean = c.load_json(self.store.files['verify.evidence.json'])
        self.assertEqual(clean['schema_version'], 2)
        self.assertEqual(clean['scope'], 'fox-clean-package-install-v2')
        self.assertEqual(clean['allocation_receipt_sha256'], c.digest(self.store.files['allocate.evidence.json']))
        self.assertEqual(clean['verification_profile_sha256'], c.digest(self.store.files['verification-profile.json']))
        self.assertFalse(clean['human_business_acceptance'])
        self.assertFalse(clean['authenticated_runtime_passed'])
        self.assertEqual(clean['clean_install']['after_install']['initial_row_count'], 0)
        self.assertEqual(clean['table_metadata']['primary_key']['columns'], ['TEST_ID'])
        self.assertTrue(clean['compiled_native_components']['passed'])
        self.assertFalse(clean['compiled_native_components']['p_with_original_ids'])
        self.assertTrue(all(state == 'complete' for state in result['phases'].values()))

    def test_tampered_completion_evidence_never_counted_as_completed(self):
        self.run_operator()
        self.store.files['allocate.evidence.json'] += b' '
        with self.assertRaisesRegex(r.RemoteError, 'PHASE_COMPLETION_INVALID'):
            self.run_operator('status', None)

    def test_completed_verify_rechecks_retained_profile_export_and_source_bytes(self):
        self.through('verify')
        original = deepcopy(self.store.files)
        for name in ('verification-profile.json', 'compiled-application.sql', 'native-form-spec.json',
                     'package.zip', 'plan.json'):
            for changed in (None, b'{}\n'):
                self.store.files = deepcopy(original)
                if changed is None:
                    del self.store.files[name]
                else:
                    self.store.files[name] = changed
                for command in ('check', 'status'):
                    with self.subTest(name=name, changed=changed, command=command), self.assertRaises(r.RemoteError):
                        self.run_operator(command, None)

    def test_digest_matching_but_invalid_schema_import_verify_proof_is_rejected(self):
        self.through('verify')
        original = deepcopy(self.store.files)
        for phase in ('schema', 'import', 'verify'):
            self.store.files = deepcopy(original)
            raw = b'{"passed":true}\n'
            self.store.files[phase + '.evidence.json'] = raw
            complete = c.load_json(self.store.files[phase + '.complete.json'])
            complete['evidence_sha256'] = c.digest(raw)
            self.store.files[phase + '.complete.json'] = c.canonical_bytes(complete)
            with self.subTest(phase=phase), self.assertRaises(r.RemoteError):
                self.run_operator('status', None)

    def test_check_and_completed_skip_verify_current_database_postconditions(self):
        self.through('verify')
        writes = list(self.store.writes)
        for key, value in (('ROLE_COUNT', 1), ('CORRECT_MAPPING_COUNT', 0), ('EXACT_APP_COUNT', 0),
                           ('ID_COUNT', 2), ('ALIAS_COUNT', 0)):
            self.driver.bad = {key: value}
            for command, phase in (('check', None), ('apply', 'verify'), ('apply', 'allocate')):
                with self.subTest(key=key, command=command, phase=phase), self.assertRaises(r.RemoteError):
                    self.run_operator(command, phase)
        self.assertEqual(writes, self.store.writes)

    def test_status_remains_historical_without_sql_or_credential_reads(self):
        self.through('verify')
        self.driver.calls.clear()
        del self.store.files['schema-credentials.json']
        result = self.run_operator('status', None)
        self.assertEqual(result['state'], 'QA_READY_HISTORICAL')
        self.assertEqual(self.driver.calls, ['scope'])
        self.assertFalse(result['database_checked'])

    def test_handoff_only_returns_bound_private_paths_not_passwords(self):
        result = self.through('verify')
        self.assertEqual(result['qa_handoff']['allocation_receipt'], self.store.path + '/allocate.evidence.json')
        self.assertEqual(result['qa_handoff']['import_receipt'], self.store.path + '/verify.evidence.json')
        for value in c.load_json(self.store.files['runtime-credentials.json']).values():
            self.assertNotIn(value, json.dumps(result))

    def test_each_phase_interrupted_journal_never_replays_or_advances(self):
        for phase in r.ORDER:
            self.store, self.driver = MemoryStore(), MockDriver()
            for earlier in r.ORDER[:r.ORDER.index(phase)]:
                self.run_operator(phase=earlier)
            self.store.create(phase + '.intent.json', c.canonical_bytes(r._phase_record(self.plan, phase, 'intent', LATER)))
            original = deepcopy(self.store.files)
            for later in r.ORDER[r.ORDER.index(phase):]:
                with self.subTest(phase=phase, later=later), self.assertRaises(r.RemoteError):
                    self.run_operator(phase=later)
            self.assertEqual(original, self.store.files)
            self.assertEqual(self.run_operator('status', None)['state'], 'ATTENTION')

    def test_orphan_completion_does_not_look_unattempted(self):
        self.run_operator()
        del self.store.files['allocate.intent.json']
        with self.assertRaisesRegex(r.RemoteError, 'ORPHAN_PHASE_EVIDENCE'):
            self.run_operator('status', None)

    def test_partial_credential_creation_fails_without_regeneration(self):
        self.store.files['schema-credentials.json'] = b'{}\n'
        with self.assertRaisesRegex(r.RemoteError, 'CREDENTIAL_WRITE_INCOMPLETE'):
            self.run_operator()
        self.assertNotIn('runtime-credentials.json', self.store.files)
        self.assertNotIn('allocate.intent.json', self.store.files)

    def test_schema_and_import_sql_preserve_exact_package_bytes(self):
        allocation = r._make_allocation(self.plan, self.driver.ids, c.VERSIONS)
        schema = r.schema_sql(self.plan, allocation, self.package)
        imported = r.import_sql(self.plan, allocation, self.package)
        self.assertEqual(schema.count(self.package['schema_sql']), 1)
        self.assertEqual(imported.count(self.package['application_sql']), 1)
        self.assertNotIn(self.package['schema_sql'], imported)
        for body in (schema, imported):
            self.assertLess(body.index(b"sys_context('USERENV','SESSION_USER')"),
                            body.index(self.package['schema_sql'] if body is schema else self.package['application_sql']))
            self.assertNotIn(b"SESSION_USER')<>'ADMIN'", body)
        self.assertIn(b'apex_application_install.set_auto_install_sup_obj(false)', imported)
        self.assertIn(b'apex_application_install.generate_offset', imported)
        self.assertIn(b'Application exists; no overwrite', imported)

    def test_allocation_only_has_narrow_create_grants_and_runtime_users(self):
        credentials = r.generated_credentials()
        sql = r.allocation_sql(self.plan, credentials).decode()
        self.assertIn('grant create session, create table, create sequence to ' + NAME, sql)
        self.assertIn('quota 20M on DATA', sql)
        for denied in ('grant dba', 'grant resource', 'grant dwrole', 'create any', 'alter user', 'drop ', 'FORMS2APEX_POC', 'FOX_QA_261017A'):
            self.assertNotIn(denied.lower(), sql.lower())
        self.assertEqual(sql.count('p_developer_privs=>NULL'), 2)
        self.assertEqual(sql.count("p_allow_app_building_yn=>'N'"), 2)
        self.assertGreaterEqual(sql.count("sys_context('USERENV','SESSION_USER')<>'ADMIN'"), 5)

    def test_generated_passwords_reject_command_sql_and_duplicate_content(self):
        credentials = r.generated_credentials()
        for bad in ('abc\nexit', "' OR 1=1", '"; drop user', 'Aa9!' + 'a' * 26):
            values = dict(credentials)
            values['password'] = bad
            if bad.startswith('Aa9!'):
                values['second_password'] = bad
            with self.subTest(kind=bad[:3]), self.assertRaises(r.RemoteError):
                r.allocation_sql(self.plan, values)

    def test_table_validation_rejects_rows_triggers_dependencies_missing_pk_and_columns(self):
        markers = table_markers(self.package['native_form'])
        for key in ('ROW_COUNT', 'TRIGGER_COUNT', 'SYNONYM_COUNT', 'DB_LINK_COUNT', 'INVALID_OBJECT_COUNT', 'UNEXPECTED_SCHEMA_DEPENDENCY_COUNT'):
            changed = [(k, '1' if k == key else v) for k, v in markers]
            with self.subTest(key=key), self.assertRaises(r.RemoteError):
                r.verify_table(changed, self.package['native_form'], NAME)
        for changed in ([pair for pair in markers if pair[0] != 'PK'], [pair for pair in markers if pair[0] != 'COLUMN']):
            with self.assertRaises(r.RemoteError):
                r.verify_table(changed, self.package['native_form'], NAME)

    def test_export_current_identity_and_component_semantics_are_both_required(self):
        allocation = r._make_allocation(self.plan, self.driver.ids, c.VERSIONS)
        actual = self.driver.export(self.plan, allocation, 'unused')
        self.assertTrue(r.verify_compiled(self.package['application_sql'], actual, allocation)['passed'])
        for changed in (actual.replace(b'p_browser_cache=>null', b"p_browser_cache=>'Y'"),
                        actual.replace(NAME.encode(), b'FORMS2APEX_POC'),
                        actual.replace(b'p_default_application_id=>34567', b'p_default_application_id=>103')):
            with self.assertRaises(r.RemoteError):
                r.verify_compiled(self.package['application_sql'], changed, allocation)

    def test_export_never_uses_original_ids(self):
        sql = r.export_sql(34567)
        self.assertIn(b'p_with_original_ids=>false', sql)
        self.assertNotIn(b'p_with_original_ids=>true', sql)


class DriverSafetyTests(unittest.TestCase):
    def setUp(self):
        patch.dict(os.environ, {'TNS_ADMIN': r.WALLET}).start()
        self.addCleanup(patch.stopall)

    def test_password_goes_only_to_stdin_and_environment_is_preserved(self):
        result = SimpleNamespace(returncode=0, stdout=b'FOX_OPERATOR_IDENTITY=VERIFIED\n', stderr=b'')
        with patch.dict(os.environ, {'TNS_ADMIN': r.WALLET, 'F2A_KEEP_SETTING': 'unchanged'}), patch.object(r.subprocess, 'run', return_value=result) as run:
            self.assertEqual(r.SqlclDriver().sql(NAME, ADMIN, b'select 1 from dual;'), [('IDENTITY', 'VERIFIED')])
        args, kwargs = run.call_args
        self.assertEqual(args[0], [r.SQLCL, '-nohistory', '-S', '/nolog'])
        self.assertNotIn(ADMIN, repr(args))
        self.assertNotIn(ADMIN, repr(kwargs['env']))
        self.assertIn(ADMIN.encode(), kwargs['input'])
        self.assertEqual(kwargs['env']['F2A_KEEP_SETTING'], 'unchanged')
        self.assertNotIn('shell', kwargs)

    def test_bad_wallet_rejected_before_subprocess(self):
        with patch.dict(os.environ, {'TNS_ADMIN': '/other'}), patch.object(r.subprocess, 'run') as run:
            with self.assertRaisesRegex(r.RemoteError, 'WALLET_ENVIRONMENT_MISMATCH'):
                r.SqlclDriver().sql(NAME, ADMIN, b'select 1 from dual;')
            run.assert_not_called()

    def test_sql_failure_extracts_only_unique_known_numeric_codes_and_return_code(self):
        result = SimpleNamespace(returncode=255, stdout=('ORA-01031: ' + ADMIN + '\nORA-01031\nORA-06512: at SQL').encode(),
                                 stderr=b'SP2-0552: provider content\nORA-010310 ORA-01031_SUFFIX')
        with patch.object(r.subprocess, 'run', return_value=result), self.assertRaises(r.RemoteError) as failure:
            r.SqlclDriver().sql(NAME, ADMIN, b'secret SQL text')
        self.assertEqual(failure.exception.diagnostics, {
            'category': 'SQL_EXECUTION_FAILED', 'error_codes': ['ORA-01031', 'ORA-06512', 'SP2-0552'], 'return_code': 255})
        self.assertNotIn(ADMIN, json.dumps(r.failure_response(failure.exception)))
        self.assertNotIn('provider content', json.dumps(r.failure_response(failure.exception)))

    def test_sql_numeric_diagnostics_limit_and_timeout_remain_safe(self):
        output = ' '.join('ORA-' + str(i).zfill(5) for i in range(20))
        self.assertEqual(len(r.sql_diagnostics('SQL_EXECUTION_FAILED', 1, output)['error_codes']), 8)
        timeout = subprocess.TimeoutExpired('secret argv', 1, output=('ORA-01031 ' + ADMIN).encode(), stderr=b'provider content')
        with patch.object(r.subprocess, 'run', side_effect=timeout), self.assertRaises(r.RemoteError) as failure:
            r.SqlclDriver().sql(NAME, ADMIN, b'secret SQL')
        self.assertEqual(failure.exception.diagnostics, {
            'category': 'SQL_EXECUTION_TIMEOUT', 'error_codes': ['ORA-01031'], 'return_code': None})
        self.assertNotIn(ADMIN, json.dumps(r.failure_response(failure.exception)))

    def test_sql_failure_and_timeout_never_expose_sql_password_or_output(self):
        cases = [SimpleNamespace(returncode=1, stdout=('ORA-01031 ' + ADMIN).encode(), stderr=b'SQL statement'),
                 SimpleNamespace(returncode=0, stdout=('ORA-01031 ' + ADMIN).encode(), stderr=b'')]
        for result in cases:
            with patch.object(r.subprocess, 'run', return_value=result), self.assertRaises(r.RemoteError) as failure:
                r.SqlclDriver().sql(NAME, ADMIN, b'select 1 from dual;')
            self.assertNotIn(ADMIN, str(failure.exception))
            self.assertNotIn('ORA-', str(failure.exception))
        with patch.object(r.subprocess, 'run', side_effect=subprocess.TimeoutExpired('sql', 1, output=ADMIN.encode())), self.assertRaisesRegex(r.RemoteError, '^SQL_TIMEOUT_UNCERTAIN_NO_REPLAY$'):
            r.SqlclDriver().sql(NAME, ADMIN, b'select 1 from dual;')

    def test_vm_metadata_wrong_scope_rejected(self):
        plan, _, _ = fixture()
        for patch_key, patch_value in (('id', 'other'), ('compartmentId', 'other'), ('canonicalRegionName', 'ap-tokyo-1')):
            meta = {'id': c.INSTANCE, 'compartmentId': c.COMPARTMENT, 'canonicalRegionName': c.REGION}
            meta[patch_key] = patch_value
            response = io.BytesIO(json.dumps(meta).encode())
            with patch.object(r.urllib.request, 'urlopen', return_value=response), self.assertRaisesRegex(r.RemoteError, 'VM_SCOPE_MISMATCH'):
                r.SqlclDriver().scope(plan)

    def test_sql_connection_accepts_only_admin_or_fresh_namespace(self):
        for username in ('FORMS2APEX_POC', 'FOX_QA_261017A', NAME + ';drop', 'SYS'):
            with self.subTest(username=username), patch.object(r.subprocess, 'run') as run, self.assertRaises(r.RemoteError):
                r.SqlclDriver().sql(username, ADMIN, b'select 1 from dual;')
            run.assert_not_called()

    def test_markers_do_not_accept_duplicate_or_non_integer_counts(self):
        for markers in ([('COUNT', '1'), ('COUNT', '2')], [('COUNT', '-1')], [('COUNT', '1.0')], [('COUNT', 'True')]):
            with self.subTest(markers=markers), self.assertRaises(r.RemoteError):
                r.number(markers, 'COUNT')

    def test_fixed_private_store_has_no_input_path_argument(self):
        import inspect
        self.assertEqual(list(inspect.signature(r.PrivateStore).parameters), ['plan_hash', 'create'])
        self.assertEqual(str(r.PRIVATE_ROOT).replace('\\', '/'), '/opt/forms2apex/outputs/jobs/.operator-clean')


@unittest.skipUnless(os.name == 'posix', 'Descriptor-mode private-store checks require POSIX; offline Windows run does not claim them.')
class PosixPrivateStoreTests(unittest.TestCase):
    def test_read_only_check_does_not_create_directory(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(r, 'PRIVATE_ROOT', Path(directory) / '.operator-clean'):
            store = r.PrivateStore('a' * 64)
            self.assertIsNone(store.read('plan.json'))
            self.assertFalse((Path(directory) / '.operator-clean').exists())
            store.close()

    def test_create_once_rejects_symlinks_and_permission_drift(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(r, 'PRIVATE_ROOT', Path(directory) / '.operator-clean'):
            store = r.PrivateStore('a' * 64, create=True)
            store.create('plan.json', b'{}\n')
            with self.assertRaises(r.RemoteError):
                store.create('plan.json', b'changed')
            path = Path(store.path)
            self.assertEqual((path / 'plan.json').stat().st_mode & 0o777, 0o600)
            os.symlink(path / 'plan.json', path / 'link.json')
            with self.assertRaises(r.RemoteError):
                store.read('link.json')
            os.chmod(path / 'plan.json', 0o644)
            with self.assertRaises(r.RemoteError):
                store.read('plan.json')
            store.close()


if __name__ == '__main__':
    unittest.main()
