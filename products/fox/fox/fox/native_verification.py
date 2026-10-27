"""Developer-only release gate for exact-package native lab evidence.

Receipts are operator attestations, not vendor signatures. This module is not an
HTTP endpoint: promotion accepts only owner-private POSIX files, retains their
exact bytes create-only, and commits a technical decision atomically. It cannot
record human/business acceptance or make an APEX/OCI call.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import sqlite3
import stat
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .intake import inventory
from .native_pipeline import verify_package
from .native_source import PROFILE_ID, assess_native_source
from .opaf import OpafError, canonical_hash
from .native_verification_policy import (BoundVerificationPolicy, VerificationPolicyError,
                                        validate_allocation_receipt, POLICY_ID as V2_POLICY_ID)


class VerificationError(RuntimeError):
    """A bounded, source/credential-free operator failure."""


COMPARTMENT = 'ocid1.compartment.oc1..aaaaaaaa2q5aelkapmt5mhumvxadcynq5chez2faeucy5plefhy3ylmahtba'
DATABASE = 'ocid1.autonomousdatabase.oc1.iad.anuwcljrc7x6gxiapkxouj7emfbelvnvompwjcpoxx5vg727cegjsqkbp4rq'
WORKSPACE = 'FOX_QA_261017A'
WORKSPACE_ID = '22042420337195497'  # Preserve exact Oracle ID beyond JavaScript's safe integer range.
DB_NAME = 'ASZ8EQWFM8UNCA2_JSNF2APEX'
ORDS = 'https://asz8eqwfm8unca2-jsnf2apex.adb.us-ashburn-1.oraclecloudapps.com/ords'
REQUIRED_TESTS = frozenset({
    'login', 'create', 'search_positive', 'search_negative', 'reread',
    'edit_save', 'cancel_edit', 'cancel_create', 'required_fields',
    'invalid_number', 'invalid_date', 'maximum_length', 'concurrent_edit',
    'browser_runtime_errors',
})
RECEIPT_NAMES = ('clean-install.json', 'qa-result.json', 'qa-target.json', 'qa-profile.json')


@dataclass(frozen=True)
class VerificationPolicy:
    """An explicit supported lab profile, never loaded from arbitrary env.

    Exact observed strings must be selected by the operator after checking the
    installed versions. A different release/target needs a reviewed code/profile
    change; this is deliberately not yet a customer-target authorization API.
    """
    apex: str
    sqlcl: str
    database: str
    mmd: str
    max_evidence_age_seconds: int = 86_400

    def __post_init__(self):
        if (self.apex != '26.1.5'
                or not re.fullmatch(r'26\.1\.2(?:[.+][0-9]+)*', self.sqlcl)
                or self.database != '23.26.4.1.0'
                or self.mmd != '26.1.0+3102'
                or type(self.max_evidence_age_seconds) is not int
                or not 60 <= self.max_evidence_age_seconds <= 604_800):
            raise VerificationError('The explicit verification version policy is unsupported.')

    @property
    def versions(self):
        return {key: getattr(self, key) for key in ('apex', 'sqlcl', 'database', 'mmd')}


def _require(condition, message):
    if not condition:
        raise VerificationError(message)


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate key')
        value[key] = item
    return value


def _json(raw):
    try:
        _require(isinstance(raw, bytes) and 0 < len(raw) <= 2_000_000,
                 'A detached receipt is missing or oversized.')
        result = json.loads(raw, object_pairs_hook=_pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        _require(isinstance(result, dict), 'A detached receipt is not an object.')
        return result
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise VerificationError('A detached receipt is malformed.') from None


def _time(value):
    try:
        _require(isinstance(value, str) and re.fullmatch(
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)', value),
            'Verification timestamps must be explicit UTC values.')
        return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()
    except ValueError:
        raise VerificationError('Verification timestamp is invalid.') from None


def _validate_v2_row_tracking(qa, native, plan):
    """Bind fresh-row and per-field non-persistence evidence to the spec plan.
    These remain trusted runner assertions, not independent SQL execution.
    """
    tracking = qa.get('row_tracking', {})
    key = tracking.get('retained_primary_key', {})
    _require(isinstance(key, dict) and set(key) == {'name', 'value'}
             and key['name'] == plan['primary_key']['name'] and isinstance(key['value'], str)
             and re.fullmatch(r'[1-9][0-9]{0,37}', key['value']),
             'The v2 runtime row key must be an observed exact decimal string.')
    keys = [key['value']]
    _require(qa.get('initial_primary_keys') == [] and tracking.get('mode') == 'clean_empty_then_observed_pk'
             and tracking.get('initial_primary_keys') == [] and tracking.get('final_observed_primary_keys') == keys
             and tracking.get('single_row_preserved') is True,
             'The v2 runtime did not preserve exactly its observed synthetic row.')
    retained = qa.get('retained_records')
    _require(isinstance(retained, list) and len(retained) == 1 and isinstance(retained[0], dict)
             and retained[0].get('table') == native['table_name'] and retained[0].get('primary_key') == key
             and retained[0].get('write_state') == 'CREATED_AND_REREAD',
             'The retained runtime record does not match the observed native key.')
    edit_values = {'VARCHAR2': 'B', 'NUMBER': '2', 'DATE': '2026-01-02'}
    winner_values = {'VARCHAR2': 'D', 'NUMBER': '4', 'DATE': '2026-01-04'}
    expected_values = {column['name']: (winner_values if column['name'] == plan['edit_field'] else edit_values)[column['data_type']]
                       for column in native['columns'] if not column.get('primary_key')}
    expected = qa.get('final_expected_record', {})
    _require(expected.get('primary_key') == key and expected.get('expected_values') == expected_values,
             'Final runtime values differ from the deterministic edit and first-writer result.')
    checks = qa.get('pk_set_checks')
    _require(isinstance(checks, list) and checks, 'Fresh primary-key set checks are missing.')
    cases = {case['name']: case for case in plan['cases']}
    conditional = {'required_fields', 'invalid_number', 'invalid_date', 'maximum_length'}
    seen, field_seen = set(), {name: set() for name in conditional}
    for check in checks:
        _require(isinstance(check, dict) and {'test_name', 'expected_primary_keys', 'observed_primary_keys', 'passed'} <= set(check)
                 and set(check) <= {'test_name', 'expected_primary_keys', 'observed_primary_keys', 'passed', 'field_name'},
                 'A v2 primary-key set check is malformed.')
        name = check['test_name']
        _require(isinstance(name, str) and name in set(cases) | {'preflight', 'final'}, 'Unknown primary-key set check case.')
        _require(name in {'preflight', 'final'} or cases[name]['applicable'], 'An inapplicable test reported row checks.')
        expected_keys = [] if name == 'preflight' else keys
        _require(check['passed'] is True and check['expected_primary_keys'] == expected_keys
                 and check['observed_primary_keys'] == expected_keys,
                 'A cancelled or invalid operation changed the complete observed row set.')
        if name in conditional:
            _require(check.get('field_name') in cases[name]['field_names'], 'A conditional row check has an extra or missing field.')
            field_seen[name].add(check['field_name'])
        else:
            _require('field_name' not in check, 'A universal row check contains an unexpected field override.')
        seen.add(name)
    _require({'preflight', 'final', 'create', 'reread', 'edit_save', 'cancel_edit', 'cancel_create', 'concurrent_edit'} <= seen,
             'A required fresh runtime row-set check is missing.')
    _require(all(field_seen[name] == set(cases[name]['field_names']) for name in conditional),
             'Per-field invalid-input non-persistence coverage is incomplete.')


def _verify_detached_proof(*, package: bytes, snapshot: dict, release: dict,
                          clean_install_raw: bytes, qa_result_raw: bytes,
                          qa_target_raw: bytes, qa_profile_raw: bytes,
                          policy: VerificationPolicy, now: datetime,
                          run_created: float, allocation_receipt_raw: bytes | None = None) -> dict:
    """Pure verification; callers must separately establish operator provenance."""
    _require(type(policy) in (VerificationPolicy, BoundVerificationPolicy), 'An explicit verification policy is required.')
    version2 = type(policy) is BoundVerificationPolicy
    _require(now.tzinfo is not None, 'Verification time must include a timezone.')
    _require(isinstance(snapshot, dict) and isinstance(release, dict), 'Native source evidence is missing.')
    job = release.get('job_id')
    source = release.get('source_manifest_sha256')
    native = snapshot.get('native_form')
    _require(isinstance(job, str) and re.fullmatch(r'fox-[a-f0-9]{20}', job)
             and isinstance(source, str) and re.fullmatch('[a-f0-9]{64}', source)
             and snapshot.get('source_hash') == source
             and snapshot.get('conversion_profile') == PROFILE_ID
             and release.get('conversion_profile') == PROFILE_ID
             and isinstance(native, dict) and native.get('profile_id') == PROFILE_ID
             and native.get('data_mode') == 'synthetic_test_only', 'Native job, source or conversion profile differs.')
    try:
        for item in snapshot['files']:
            encoded = item['text'].encode('utf-8')
            _require(any(len(raw) == item['bytes'] and _digest(raw) == item['sha256']
                         for raw in (encoded, b'\xef\xbb\xbf' + encoded)),
                     'Frozen source text differs from its upload hash.')
        _require(inventory(snapshot['files'])['source_hash'] == source,
                 'The frozen source files differ from their source hash.')
        if version2:
            # Structural QA-plan derivation is not producer authorization.
            # Reuse the unchanged canonical source assessment before trusting
            # the package; do not copy its label/Unicode policy into QA code.
            assessed = assess_native_source(snapshot['files'])
            _require(assessed['state'] == 'READY'
                     and canonical_hash(assessed['native_form']) == canonical_hash(native),
                     'The frozen source does not satisfy the canonical native producer contract.')
        package_sha = verify_package(package, release, native)
        with zipfile.ZipFile(io.BytesIO(package)) as archive:
            manifest = _json(archive.read('manifest.json'))
            native_raw = archive.read('native-form-spec.json')
        if version2:
            # The independent reader derives coverage from these exact bytes,
            # not an equivalent-looking snapshot or JSON's last duplicate key.
            # Keep the historical v1 package interpretation unchanged.
            packaged_native = _json(native_raw)
            _require(canonical_hash(packaged_native) == canonical_hash(native),
                     'Packaged native metadata differs from the frozen source.')
            native = packaged_native
    except (KeyError, TypeError, ValueError, OpafError, zipfile.BadZipFile):
        raise VerificationError('The exact native package did not pass integrity verification.') from None
    _require(all(release.get(key) is True for key in (
        'reviewer_approved', 'reviewer_execution_verified', 'sqlcl_valid',
        'import_passed', 'runtime_smoke_passed', 'package_reimport_passed'))
        and release.get('business_acceptance_required') is True,
        'Upstream release gates are incomplete.')
    if version2:
        _require(policy.binding['job_id'] == job and policy.binding['source_manifest_sha256'] == source
                 and policy.binding['package_sha256'] == package_sha,
                 'The operator verification profile is bound to another job, source or package.')
        allocation = validate_allocation_receipt(allocation_receipt_raw, policy)

    clean, qa, target, profile = map(_json, (clean_install_raw, qa_result_raw, qa_target_raw, qa_profile_raw))
    member_hashes = {
        'package_sha256': package_sha,
        'native_spec_sha256': manifest['native-form-spec.json'],
        'schema_script_sha256': manifest['schema/01_synthetic_schema.sql'],
        'sql_sha256': manifest['sql/f' + str(release['application_id']) + '.sql'],
        'source_manifest_sha256': source,
    }
    identity = {
        'job_id': job, 'compartment_id': COMPARTMENT, 'database_id': DATABASE,
        'region': 'us-ashburn-1', 'workspace': WORKSPACE, 'parsing_schema': WORKSPACE,
        'workspace_id': WORKSPACE_ID, 'db_name': DB_NAME, 'table_name': native.get('table_name'),
    }
    if version2:
        identity = {'job_id': job, 'table_name': native.get('table_name'),
                    **{key: value for key, value in policy.target.items() if key not in {'application_id', 'application_alias'}}}
    versions = clean.get('observed_versions')
    _require(isinstance(versions, dict) and set(versions) <= set(policy.versions) | {'mmd_source', 'mmd_jar_sha256'}
             and all(versions.get(key) == value for key, value in policy.versions.items())
             and ('mmd_source' not in versions or isinstance(versions['mmd_source'], str) and 0 < len(versions['mmd_source']) <= 512)
             and ('mmd_jar_sha256' not in versions or isinstance(versions['mmd_jar_sha256'], str) and re.fullmatch('[a-f0-9]{64}', versions['mmd_jar_sha256'])),
             'Observed runtime versions differ from the explicit verification policy.')
    expected_schema = 2 if version2 else 1
    _require(type(clean.get('schema_version')) is int and clean['schema_version'] == expected_schema
             and clean.get('scope') == ('fox-clean-package-install-v2' if version2 else 'fox-clean-package-install-v1')
             and clean.get('passed') is True and clean.get('profile_id') == PROFILE_ID
             and clean.get('db_name') == DB_NAME
             and all(clean.get(key) == value for key, value in {**identity, **member_hashes}.items()),
             'The clean-install receipt is not bound to this package and approved target.')
    if version2:
        _require(clean.get('verification_profile_sha256') == policy.sha256
                 and clean.get('allocation_receipt_sha256') == policy.binding['allocation_receipt_sha256'],
                 'The clean-install receipt is not bound to the operator profile and allocation.')
    app_id, alias = clean.get('application_id'), clean.get('application_alias')
    _require(type(app_id) is int and app_id > 0
             and app_id not in {release['application_id'], release.get('package_reimport', {}).get('application_id')}
             and isinstance(alias, str) and re.fullmatch(r'F2A_[A-Z0-9_]{1,60}', alias)
             and alias not in {release['application_alias'], release.get('package_reimport', {}).get('application_alias')},
             'The clean import must have its own explicit application identity.')
    if version2:
        _require(app_id == policy.target['application_id'] and alias == policy.target['application_alias'],
                 'Clean application identity differs from the operator allocation.')
    app_url = ORDS + '/r/' + identity['workspace'].lower() + '/' + alias.lower() + '/'
    _require(isinstance(clean.get('application_url'), str)
             and clean['application_url'].lower() == app_url,
             'Clean application URL differs from the approved target.')
    install = clean.get('clean_install', {})
    before, after = install.get('before_install', {}), install.get('after_install', {})
    _require(all(install.get(key) is True for key in ('passed', 'workspace_created_fresh', 'schema_created_fresh'))
             and before.get('passed') is True and before.get('application_count') == 0
             and before.get('user_object_count') == 0
             and after.get('passed') is True and after.get('application_count') == 1
             and after.get('native_table_count') == 1
             and after.get('unexpected_schema_dependency_count') == 0,
             'The clean namespace or dependency proof is incomplete.')
    # bool is an int in Python: do not accept false/true as SQL count evidence.
    for container, keys in ((before, ('application_count', 'user_object_count')),
                            (after, ('application_count', 'native_table_count', 'unexpected_schema_dependency_count'))):
        _require(all(type(container[key]) is int for key in keys), 'Clean-install counts must be integers.')
    if version2:
        _require(type(after.get('initial_row_count')) is int and after['initial_row_count'] == 0,
                 'The v2 clean package must have an explicitly empty initial table.')

    target_expected = {**identity, **member_hashes, 'application_id': app_id,
                       'alias': alias, 'profile_sha256': _digest(qa_profile_raw),
                       'import_receipt_sha256': _digest(clean_install_raw)}
    if version2:
        target_expected.update(verification_profile_sha256=policy.sha256,
                               allocation_receipt_sha256=policy.binding['allocation_receipt_sha256'])
    _require(type(target.get('schema_version')) is int and target['schema_version'] == expected_schema and target.get('clean_install') is True
             and target.get('synthetic_qa_approved') is True
             and all(target.get(key) == value for key, value in target_expected.items())
             and isinstance(target.get('url'), str) and target['url'].lower() == app_url,
             'The browser target receipt differs from the clean package install.')
    _require(type(profile.get('schema_version')) is int and profile['schema_version'] == expected_schema and profile.get('profile_id') == PROFILE_ID
             and profile.get('data_mode') == 'synthetic_test_only'
             and profile.get('table_name') == native.get('table_name')
             and isinstance(profile.get('fields'), list), 'The authenticated QA profile differs from the package.')
    columns = {column['name']: column for column in native['columns'] if not column.get('primary_key')}
    fields = profile['fields']
    _require(len(fields) == len(columns) and len({field.get('name') for field in fields}) == len(fields),
             'The QA profile does not cover each editable package column exactly once.')
    for field in fields:
        column = columns.get(field.get('name'))
        expected_label = column.get('label') if column else None
        _require(column is not None and field.get('label') == expected_label
                 and field.get('data_type') == column.get('data_type')
                 and field.get('required') is (not column.get('nullable'))
                 and (column.get('data_type') != 'VARCHAR2' or field.get('max_length') == column.get('length')),
                 'An authenticated QA field differs from the packaged native column.')
    if version2:
        from .native_qa_plan import derive_native_qa_profile
        _require(canonical_hash(profile) == canonical_hash(derive_native_qa_profile(native)),
                 'The v2 QA field profile is not the deterministic profile for these package bytes.')

    _require(type(qa.get('schema_version')) is int and qa['schema_version'] == expected_schema and qa.get('status') == 'PASSED'
             and qa.get('test_scope') == 'authenticated_browser_native_table_form_synthetic_only'
             and qa.get('target') == target and qa.get('target_receipt_sha256') == _digest(qa_target_raw)
             and qa.get('two_independent_accounts') is True
             and qa.get('credentials_recorded') is False and qa.get('browser_storage_saved') is False
             and qa.get('human_acceptance_recorded') is False
             and qa.get('browser_errors') == [] and qa.get('network_denials') == [],
             'Authenticated runtime verification is incomplete or has reported errors.')
    binding = qa.get('binding', {})
    _require(all(binding.get(key) is True for key in (
        'profile_bytes_verified', 'package_bytes_verified', 'native_spec_bytes_verified',
        'import_receipt_bytes_verified', 'package_manifest_verified', 'clean_install_verified'))
        and binding.get('package_sha256') == package_sha
        and binding.get('scope') == ('exact-package-clean-install-v2' if version2 else 'exact-package-clean-install'),
        'The browser result did not verify all mounted input bytes.')
    if version2:
        from .native_qa_plan import derive_native_qa_plan, qa_plan_sha256, validate_native_qa_result_cases
        _require(type(target.get('application_id')) is int
                 and type(qa.get('target', {}).get('application_id')) is int,
                 'The v2 browser application identity must be an exact integer.')
        test_plan = derive_native_qa_plan(native, _digest(native_raw))
        indexed = validate_native_qa_result_cases(qa, test_plan)
        _require(binding.get('verification_profile_bytes_verified') is True
                 and binding.get('verification_profile_sha256') == policy.sha256,
                 'The runtime did not verify the mounted operator profile bytes.')
        _validate_v2_row_tracking(qa, native, test_plan)
        required_tests = sorted(case['name'] for case in test_plan['cases'] if case['applicable'])
    else:
        tests = qa.get('tests')
        _require(isinstance(tests, list) and all(isinstance(test, dict) for test in tests), 'Runtime tests are missing.')
        names = [test.get('name') for test in tests]
        _require(all(isinstance(name, str) for name in names) and len(set(names)) == len(names)
                 and REQUIRED_TESTS <= set(names), 'A required runtime test is missing or duplicated.')
        indexed = dict(zip(names, tests))
        _require(all(test.get('status') != 'FAILED' and test.get('status') in {'PASSED', 'NOT_RUN'} for test in tests)
                 and all(indexed[name].get('required') is True and indexed[name].get('status') == 'PASSED' for name in REQUIRED_TESTS)
                 and all(test.get('status') == 'PASSED' for test in tests if test.get('required') is True),
                 'A required or attempted runtime test did not pass.')
        required_tests = sorted(REQUIRED_TESTS)
    login = indexed['login'].get('evidence', {})
    concurrency = indexed['concurrent_edit'].get('evidence', {})
    if version2:
        _require(concurrency.get('field') == test_plan['edit_field']
                 and type(concurrency.get('independent_browser_contexts')) is int,
                 'Runtime concurrency used a different field or an inexact context count.')
    _require(login.get('authenticated') is True and login.get('rendered_application_id') == app_id
             and type(login.get('rendered_application_id')) is int
             and concurrency.get('independent_browser_contexts') == 2
             and all(concurrency.get(key) is True for key in ('two_independent_accounts', 'first_writer_retained', 'stale_writer_rejected'))
             and indexed['browser_runtime_errors'].get('evidence', {}).get('unhandled_error_count') == 0
             and type(indexed['browser_runtime_errors'].get('evidence', {}).get('unhandled_error_count')) is int,
             'Login identity or concurrent-write behavior is unproven.')
    started, finished = _time(clean.get('started_at_utc')), _time(clean.get('finished_at_utc'))
    qa_started, qa_finished = _time(qa.get('started_at')), _time(qa.get('finished_at'))
    _require(type(run_created) in (float, int) and run_created <= started <= finished <= qa_started <= qa_finished
             and qa_finished <= now.timestamp() + 300
             and now.timestamp() - qa_finished <= policy.max_evidence_age_seconds,
             'Verification evidence is stale, future-dated or out of sequence.')
    if version2:
        _require(run_created <= _time(allocation['allocated_at_utc']) <= started,
                 'Allocation time does not precede this exact clean installation.')
    proof = {
        'schema_version': expected_schema, 'scope': 'fox-native-technical-verification-v2' if version2 else 'fox-native-technical-verification-v1',
        'policy_id': V2_POLICY_ID if version2 else 'jsn-clean-native-beta-20261017-v1', 'job_id': job,
        'source_manifest_sha256': source, 'conversion_profile': PROFILE_ID,
        'package_sha256': package_sha, 'clean_application_id': app_id,
        'source_snapshot_sha256': canonical_hash(snapshot),
        'release_evidence_sha256': canonical_hash(release),
        'clean_application_alias': alias, 'clean_application_url': app_url,
        'target': identity, 'observed_versions': versions,
        'receipt_sha256': dict(zip(RECEIPT_NAMES, map(_digest, (
            clean_install_raw, qa_result_raw, qa_target_raw, qa_profile_raw)))),
        'authenticated_runtime_passed': True, 'clean_schema_install_passed': True,
        'required_tests': required_tests, 'qa_finished_at': qa['finished_at'],
        'business_acceptance_required': True, 'human_acceptance_recorded': False,
        'scope_limit': 'Exact synthetic native profile package only; no customer business equivalence claim.',
        'provenance': 'Owner-private operator receipts; not vendor-signed attestations.',
    }
    if version2:
        proof.update(verification_profile=policy.document, verification_profile_sha256=policy.sha256,
                     allocation_receipt_sha256=policy.binding['allocation_receipt_sha256'],
                     test_plan=test_plan, test_plan_sha256=qa_plan_sha256(test_plan))
    return proof


def verify_detached_proof(**arguments) -> dict:
    """Validate untrusted structures without exposing parser/source excerpts."""
    try:
        return _verify_detached_proof(**arguments)
    except (TypeError, ValueError, KeyError, AttributeError, UnicodeError, zipfile.BadZipFile):
        raise VerificationError('Native detached verification evidence is malformed.') from None


def _safe_path(path: Path):
    try:
        path = path.absolute()
        _require(path.resolve(strict=True) == path and not path.is_symlink(), 'Unsafe verification path.')
        for parent in path.parents:
            _require(not parent.is_symlink() and parent.resolve(strict=True) == parent, 'Unsafe verification parent path.')
        return path
    except (OSError, ValueError):
        raise VerificationError('Verification input path is missing or unsafe.') from None


def _private(path: Path, directory=False):
    _require(os.name == 'posix', 'Operator promotion requires POSIX ownership checks on the existing lab VM.')
    path = _safe_path(path)
    info = path.stat()
    _require(info.st_uid == os.geteuid() and (info.st_mode & 0o077) == 0
             and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)),
             'Operator receipts must be owner-private regular files and directories.')
    return path


def load_verification_profile(path: Path, *, root: Path, operator_receipt_dir: Path,
                              historical: bool = False) -> BoundVerificationPolicy:
    """Read exact private operator bytes. Historical parsing is explicit and
    cannot authorize a first decision; promotion requires a durable matching
    attempt/decision before it can use that mode.
    """
    root = _safe_path(Path(root))
    operator = _private(Path(operator_receipt_dir), directory=True)
    _require(root != operator and root not in operator.parents, 'Operator profile must remain outside FOX data.')
    path = _private(Path(path))
    _require(path.parent == operator and path.name == 'verification-profile.json',
             'Use the exact verification-profile.json alongside the private proof inputs.')
    try:
        return BoundVerificationPolicy(_read(path, 16_384), historical=historical)
    except VerificationPolicyError:
        raise VerificationError('The private verification profile is invalid.') from None


def _read(path: Path, maximum=2_000_000):
    path = _safe_path(path)
    before = path.stat()
    _require(stat.S_ISREG(before.st_mode) and before.st_size <= maximum, 'Verification input is not a bounded regular file.')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        _require((before.st_ino, before.st_dev) == (opened.st_ino, opened.st_dev), 'Verification input changed while opening.')
        result = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    _require(len(result) <= maximum and (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns),
             'Verification input changed while reading.')
    return result


def _sync_dir(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _save_once(path: Path, raw: bytes):
    if path.exists() or path.is_symlink():
        _private(path)
        _require(_read(path) == raw, 'A different detached receipt is already retained; no overwrite.')
        return
    descriptor, name = tempfile.mkstemp(prefix='.verification-', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            _private(path)
            _require(_read(path) == raw, 'Concurrent verification receipt differs; no overwrite.')
        _sync_dir(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def promote_native_run(*, root: Path, run_id: str, operator_receipt_dir: Path,
                       policy: VerificationPolicy | BoundVerificationPolicy, now: datetime | None = None) -> dict:
    """Local operator-only atomic QA_REQUIRED -> VERIFIED, never ACCEPTED.

    Input directory contains exactly named clean-install/qa-result/qa-target/
    qa-profile JSON files. It must be outside FOX's writable data tree. No network
    calls or database application writes occur. Byte-identical retry is idempotent.
    """
    _require(isinstance(run_id, str) and re.fullmatch(r'fox-[a-f0-9]{20}', run_id), 'Invalid native run ID.')
    root = _safe_path(Path(root))
    operator = _private(Path(operator_receipt_dir), directory=True)
    _require(root != operator and root not in operator.parents, 'Operator evidence must be outside the FOX data tree.')
    raws = [_read(_private(operator / name)) for name in RECEIPT_NAMES]
    version2 = type(policy) is BoundVerificationPolicy
    _require(type(policy) in (VerificationPolicy, BoundVerificationPolicy), 'An explicit verification policy is required.')
    if version2:
        requested_historical_mode = policy.historical
        # This read establishes private-file provenance only. Initial active
        # compatibility is enforced below after distinguishing durable retries.
        private_policy = load_verification_profile(operator / 'verification-profile.json', root=root, operator_receipt_dir=operator, historical=True)
        _require(private_policy.raw == policy.raw, 'Operator profile differs from the supplied policy.')
        policy = private_policy
        allocation_raw = _read(_private(operator / 'allocation-receipt.json'), 16_384)
        try:
            validate_allocation_receipt(allocation_raw, policy)
        except VerificationPolicyError:
            raise VerificationError('The private allocation receipt differs from the verification profile.') from None
    else:
        allocation_raw = None
    job = _safe_path(root / 'jobs' / run_id)
    snapshot_raw = _read(job / 'source-snapshot.json')
    release_raw = _read(job / 'release-evidence.json')
    download_raw = _read(job / 'native-pipeline' / 'download.json')
    package_path = job / 'apex-package.zip'
    package = _read(package_path, 8_000_000)
    snapshot, release, download = map(_json, (snapshot_raw, release_raw, download_raw))
    _require(release.get('job_id') == run_id and download == {
        'package_sha256': _digest(package), 'source_hash': snapshot.get('source_hash')},
        'The release and downloaded artifact are not bound to this run.')
    database = _safe_path(root / 'fox.sqlite3')
    with sqlite3.connect(database, timeout=30) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute('PRAGMA foreign_keys=ON')
        row = connection.execute('SELECT * FROM runs WHERE id=?', (run_id,)).fetchone()
        _require(row is not None, 'Native run was not found.')
        _require(row['state'] in {'QA_REQUIRED', 'VERIFIED', 'ACCEPTED'}, 'The native run is not eligible for technical verification.')
        table_exists = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='technical_verifications'").fetchone()
        prior = connection.execute('SELECT * FROM technical_verifications WHERE run=?', (run_id,)).fetchone() if table_exists else None
        if prior:
            # Historical replay is an integrity check, not a new release
            # decision. Never reopen a current version allowlist/freshness gate
            # or rewrite the original proof bytes merely to return idempotently.
            checked = checked_native_release(connection, root, dict(row))
            _require(checked is not None and checked['proof']['receipt_sha256'] == dict(zip(RECEIPT_NAMES, map(_digest, raws))),
                     'A different technical verification attempt already exists.')
            if version2:
                _require(checked['proof'].get('schema_version') == 2 and checked['proof'].get('verification_profile_sha256') == policy.sha256,
                         'A different operator profile cannot replace an existing technical decision.')
            else:
                _require(checked['proof'].get('schema_version') == 1, 'The existing decision requires its retained v2 profile.')
            return {'id': run_id, 'state': row['state'], 'idempotent': True, 'proof_sha256': prior['proof_sha256']}
        retained = job / 'technical-verification'
        attempt_path = retained / 'attempt.json'
        attempt_identity = {'schema_version': 2 if version2 else 1, 'job_id': run_id,
            'source_manifest_sha256': snapshot.get('source_hash'), 'package_sha256': _digest(package),
            'policy_id': V2_POLICY_ID if version2 else 'jsn-clean-native-beta-20261017-v1', 'observed_versions': policy.versions,
            'receipt_sha256': dict(zip(RECEIPT_NAMES, map(_digest, raws)))}
        if version2:
            attempt_identity['verification_profile_sha256'] = policy.sha256
            attempt_identity['allocation_receipt_sha256'] = _digest(allocation_raw)
        # A durable create-only attempt is written only after full validation.
        # It preserves the freshness decision if a crash occurs before SQLite
        # commit, so an identical safe retry never needs deletion or a new app.
        if attempt_path.exists() or attempt_path.is_symlink():
            _private(retained, directory=True)
            if version2:
                retained_policy = _read(_private(retained / 'verification-profile.json'), 16_384)
                _require(retained_policy == policy.raw, 'The unfinished attempt belongs to a different retained profile.')
                policy = BoundVerificationPolicy(retained_policy, historical=True)
                _require(_read(_private(retained / 'allocation-receipt.json'), 16_384) == allocation_raw,
                         'The unfinished attempt belongs to a different allocation receipt.')
            attempt_raw = _read(_private(attempt_path))
            attempt = _json(attempt_raw)
            _require(set(attempt) == set(attempt_identity) | {'verified_at_utc'}
                     and all(attempt.get(key) == value for key, value in attempt_identity.items()),
                     'A different technical verification attempt already exists.')
            verification_time = datetime.fromtimestamp(_time(attempt['verified_at_utc']), timezone.utc)
            _require(verification_time.timestamp() <= (now or datetime.now(timezone.utc)).timestamp() + 300,
                     'The persisted verification attempt is future-dated.')
            if prior:
                _require(prior['created'] == verification_time.timestamp(), 'Technical decision time differs from its persisted attempt.')
        else:
            _require(prior is None, 'The technical decision has lost its immutable attempt receipt.')
            if version2:
                _require(not requested_historical_mode, 'A historical policy cannot authorize a new technical decision.')
                try:
                    policy = BoundVerificationPolicy(policy.raw)  # Active compatibility only for a new decision.
                except VerificationPolicyError:
                    raise VerificationError('The profile version tuple is unsupported for a new technical decision.') from None
            verification_time = now or datetime.now(timezone.utc)
            attempt_raw = json.dumps({**attempt_identity, 'verified_at_utc': verification_time.astimezone(timezone.utc).isoformat()},
                                     sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        proof = verify_detached_proof(package=package, snapshot=snapshot, release=release,
            clean_install_raw=raws[0], qa_result_raw=raws[1], qa_target_raw=raws[2],
            qa_profile_raw=raws[3], policy=policy, now=verification_time,
            run_created=row['created'], allocation_receipt_raw=allocation_raw)
        proof['operator_attempt_sha256'] = _digest(attempt_raw)
        proof_raw = json.dumps(proof, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        retained.mkdir(mode=0o700, exist_ok=True)
        _private(retained, directory=True)
        if version2:
            _save_once(retained / 'allocation-receipt.json', allocation_raw)
            _save_once(retained / 'verification-profile.json', policy.raw)
        _save_once(attempt_path, attempt_raw)
        for name, raw in zip(RECEIPT_NAMES, raws):
            _save_once(retained / name, raw)
        _save_once(retained / 'verification.json', proof_raw)
        # Receipt persistence precedes the transactional decision. A crash leaves
        # retained evidence, never a VERIFIED row without evidence files.
        connection.execute('BEGIN IMMEDIATE')
        current = connection.execute('SELECT * FROM runs WHERE id=?', (run_id,)).fetchone()
        _require(current is not None and current['source_hash'] == proof['source_manifest_sha256']
                 and current['project'] == snapshot.get('project')
                 and current['artifact'] == str(package_path.relative_to(root)),
                 'The run changed or points to a different artifact.')
        _require(_read(package_path, 8_000_000) == package
                 and _read(job / 'source-snapshot.json') == snapshot_raw
                 and _read(job / 'release-evidence.json') == release_raw
                 and _read(job / 'native-pipeline' / 'download.json') == download_raw,
                 'Run evidence changed before the verification commit.')
        connection.execute('CREATE TABLE IF NOT EXISTS technical_verifications('
            'run TEXT PRIMARY KEY REFERENCES runs(id),source_hash TEXT NOT NULL,'
            'artifact_sha256 TEXT NOT NULL,proof_sha256 TEXT NOT NULL,proof_json TEXT NOT NULL,created REAL NOT NULL)')
        existing = connection.execute('SELECT * FROM technical_verifications WHERE run=?', (run_id,)).fetchone()
        if existing:
            _require(current['state'] in {'VERIFIED', 'ACCEPTED'}
                     and existing['proof_sha256'] == _digest(proof_raw)
                     and existing['proof_json'] == proof_raw.decode()
                     and existing['source_hash'] == current['source_hash']
                     and existing['artifact_sha256'] == _digest(package),
                     'A different or inconsistent technical decision already exists.')
            return {'id': run_id, 'state': current['state'], 'idempotent': True, 'proof_sha256': _digest(proof_raw)}
        _require(current['state'] == 'QA_REQUIRED', 'Only a native QA_REQUIRED run can receive its first technical verification.')
        # Share the exact source-selection reader with the API. Global latest
        # per-file rows are history, not the user's selected complete version.
        from .source_history import selected_sources, SourceHistoryError
        try:
            sources = selected_sources(connection, current['project'])
        except SourceHistoryError:
            raise VerificationError('Selected source version is unavailable; operator reconciliation is required.') from None
        _require(inventory(sources)['source_hash'] == proof['source_manifest_sha256'], 'Current project sources changed; old proof cannot promote them.')
        timestamp = (now or datetime.now(timezone.utc)).timestamp()
        connection.execute('INSERT INTO technical_verifications VALUES(?,?,?,?,?,?)',
            (run_id, current['source_hash'], _digest(package), _digest(proof_raw), proof_raw.decode(), verification_time.timestamp()))
        updated = connection.execute("UPDATE runs SET state='VERIFIED',message=?,updated=? WHERE id=? AND state='QA_REQUIRED'",
            ('Exact package passed clean-install and authenticated runtime checks. Human business review is still required.', timestamp, run_id))
        _require(updated.rowcount == 1, 'The native run was concurrently changed.')
        connection.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
            ('developer-operator', 'native_technical_verified', run_id, timestamp))
    return {'id': run_id, 'state': 'VERIFIED', 'idempotent': False, 'proof_sha256': _digest(proof_raw)}


def _checked_native_release(connection: sqlite3.Connection, root: Path, run: dict):
    """Recheck the immutable technical decision before acceptance/download.

    Returns None for an established legacy job; otherwise returns the detached
    proof and exact checked bytes. No age expiry applies after promotion, but
    any byte/source/identity change invalidates the stored technical decision.
    """
    job = root / 'jobs' / run['id']
    snapshot_path, release_path = job / 'source-snapshot.json', job / 'release-evidence.json'
    snapshot = _json(_read(snapshot_path)) if snapshot_path.exists() else {}
    release = _json(_read(release_path)) if release_path.exists() else {}
    table_exists = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='technical_verifications'").fetchone()
    stored = connection.execute('SELECT * FROM technical_verifications WHERE run=?', (run['id'],)).fetchone() if table_exists else None
    native = (snapshot.get('conversion_profile') == PROFILE_ID
              or release.get('conversion_profile') == PROFILE_ID or stored is not None)
    if not native:
        return None
    _require(stored is not None and run.get('state') in {'VERIFIED', 'ACCEPTED'},
             'Native technical verification is required before human acceptance or download.')
    stored = dict(stored)
    _require(isinstance(stored.get('proof_json'), str), 'The stored technical decision is malformed.')
    raw = stored['proof_json'].encode()
    proof = _json(raw)
    retained = _safe_path(job / 'technical-verification')
    _require(type(proof.get('schema_version')) is int and proof['schema_version'] in (1, 2),
             'The retained technical proof version is unsupported.')
    version2 = proof['schema_version'] == 2
    _require(proof.get('scope') == ('fox-native-technical-verification-v2' if version2 else 'fox-native-technical-verification-v1')
             and proof.get('policy_id') == (V2_POLICY_ID if version2 else 'jsn-clean-native-beta-20261017-v1'),
             'The retained technical proof scope or policy is unsupported.')
    _require(_read(retained / 'verification.json') == raw
             and _digest(_read(retained / 'attempt.json')) == proof.get('operator_attempt_sha256')
             and _digest(raw) == stored.get('proof_sha256')
             and proof.get('job_id') == run['id']
             and proof.get('source_manifest_sha256') == run.get('source_hash') == stored.get('source_hash')
             and proof.get('source_snapshot_sha256') == canonical_hash(snapshot)
             and proof.get('release_evidence_sha256') == canonical_hash(release)
             and proof.get('authenticated_runtime_passed') is True
             and proof.get('clean_schema_install_passed') is True
             and proof.get('human_acceptance_recorded') is False,
             'The retained technical decision or source evidence has changed.')
    if version2:
        profile_raw = _read(retained / 'verification-profile.json', 16_384)
        try:
            historical_policy = BoundVerificationPolicy(profile_raw, historical=True)
            allocation = validate_allocation_receipt(_read(retained / 'allocation-receipt.json', 16_384), historical_policy)
        except VerificationPolicyError:
            raise VerificationError('The retained verification profile is invalid.') from None
        attempt = _json(_read(retained / 'attempt.json'))
        target = historical_policy.target
        binding = historical_policy.binding
        expected_target = {'job_id': run['id'], 'table_name': snapshot.get('native_form', {}).get('table_name'),
                           **{key: value for key, value in target.items() if key not in {'application_id', 'application_alias'}}}
        _require(proof.get('verification_profile_sha256') == historical_policy.sha256
                 and proof.get('verification_profile') == historical_policy.document
                 and attempt.get('schema_version') == 2 and attempt.get('policy_id') == V2_POLICY_ID
                 and attempt.get('verification_profile_sha256') == historical_policy.sha256
                 and attempt.get('allocation_receipt_sha256') == binding['allocation_receipt_sha256']
                 and proof.get('allocation_receipt_sha256') == binding['allocation_receipt_sha256']
                 and binding['job_id'] == run['id'] and binding['source_manifest_sha256'] == run['source_hash']
                 and binding['package_sha256'] == proof.get('package_sha256')
                 and proof.get('target') == expected_target
                 and proof.get('clean_application_id') == target['application_id']
                 and proof.get('clean_application_alias') == target['application_alias']
                 and proof.get('clean_application_url') == ORDS + '/r/' + target['workspace'].lower() + '/' + target['application_alias'].lower() + '/'
                 and all(proof.get('observed_versions', {}).get(key) == value for key, value in historical_policy.versions.items())
                 and _time(attempt.get('verified_at_utc')) == stored['created'],
                 'Historical verification profile or target binding changed.')
        _require(_time(allocation['allocated_at_utc']) <= stored['created'], 'Retained allocation postdates the original decision.')
    else:
        _require(not any(key in proof for key in ('verification_profile', 'verification_profile_sha256', 'test_plan', 'test_plan_sha256')),
                 'A v2 proof cannot be interpreted through the historical v1 reader.')
    receipts = proof.get('receipt_sha256', {})
    _require(set(receipts) == set(RECEIPT_NAMES)
             and all(_digest(_read(retained / name)) == receipts[name] for name in RECEIPT_NAMES),
             'Detached verification receipt bytes changed after promotion.')
    path = job / 'apex-package.zip'
    _require(run.get('artifact') == str(path.relative_to(root)), 'The verified run points to a different artifact.')
    package = _read(path, 8_000_000)
    _require(_digest(package) == stored.get('artifact_sha256') == proof.get('package_sha256'),
             'The native package changed after technical verification.')
    return {'proof': proof, 'package': package}


def checked_native_release(connection: sqlite3.Connection, root: Path, run: dict):
    try:
        return _checked_native_release(connection, root, run)
    except (OSError, TypeError, ValueError, KeyError, AttributeError):
        raise VerificationError('Retained native technical evidence is unavailable or malformed.') from None


def verify_existing_native_run(*, root: Path, run_id: str) -> dict:
    """Offline read-only historical recheck: no active profile or receipt-dir
    access, freshness reevaluation, event insertion or state transition.
    """
    _require(isinstance(run_id, str) and re.fullmatch(r'fox-[a-f0-9]{20}', run_id), 'Invalid native run ID.')
    root = _safe_path(Path(root))
    database = _safe_path(root / 'fox.sqlite3')
    with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=30) as connection:
        connection.row_factory = sqlite3.Row
        row = connection.execute('SELECT * FROM runs WHERE id=?', (run_id,)).fetchone()
        _require(row is not None, 'Native run was not found.')
        result = checked_native_release(connection, root, dict(row))
        _require(result is not None, 'This run has no retained native technical decision.')
        stored = connection.execute('SELECT proof_sha256 FROM technical_verifications WHERE run=?', (run_id,)).fetchone()
        return {'id': run_id, 'state': row['state'], 'idempotent': True, 'read_only': True,
                'proof_sha256': stored['proof_sha256'], 'active_policy_applied': False}


def main(argv=None):
    """Restricted lab operator entrypoint; intentionally not an end-user API."""
    import argparse
    parser = argparse.ArgumentParser(description='Record exact-package technical verification in the existing FOX lab.')
    parser.add_argument('--data-dir', required=True, type=Path)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--receipt-dir', type=Path)
    profile = parser.add_mutually_exclusive_group()
    profile.add_argument('--profile', choices=['jsn-clean-native-beta-20261017-v1'])
    profile.add_argument('--policy-file', type=Path)
    parser.add_argument('--resume-retained', action='store_true', help='Use historical v2 policy only for an already durable matching attempt/decision.')
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--apply', action='store_true', help='Explicitly authorize the local technical-state transaction.')
    action.add_argument('--verify-existing', action='store_true', help='Read only the retained decision; never apply a current operator policy.')
    args = parser.parse_args(argv)
    try:
        if args.verify_existing:
            _require(args.receipt_dir is None and args.profile is None and args.policy_file is None and not args.resume_retained,
                     'Historical verification must not receive a current profile or operator receipts.')
            result = verify_existing_native_run(root=args.data_dir, run_id=args.run_id)
        else:
            _require(args.receipt_dir is not None and (args.profile is not None or args.policy_file is not None),
                     'A new decision requires explicit private receipts and a selected verification policy.')
            _require(not args.resume_retained or args.policy_file is not None, 'Historical resume requires an explicit retained v2 profile.')
            policy = (load_verification_profile(args.policy_file, root=args.data_dir, operator_receipt_dir=args.receipt_dir,
                                               historical=args.resume_retained)
                      if args.policy_file else VerificationPolicy(apex='26.1.5', sqlcl='26.1.2.0', database='23.26.4.1.0', mmd='26.1.0+3102'))
            result = promote_native_run(root=args.data_dir, run_id=args.run_id,
                operator_receipt_dir=args.receipt_dir, policy=policy)
    except VerificationError as exc:
        print(json.dumps({'status': 'BLOCKED', 'message': str(exc)}))
        return 1
    except (OSError, sqlite3.Error):
        print(json.dumps({'status': 'BLOCKED', 'message': 'Local verification storage is unavailable; existing state was preserved.'}))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
