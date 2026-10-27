"""Pure, fixed-JSN operator policy parser; never selects a target from env/UI.

An active profile authorizes only verification of one allocated synthetic lab
package. It authorizes no OCI or application database operation. Historical
parsing preserves a previously recorded decision without reapplying today's
version allowlist; callers must first authenticate its retained byte hashes.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import re


POLICY_ID = 'jsn-clean-native-v2'
PROFILE_SCOPE = 'fox-native-verification-profile-v2'
COMPARTMENT = 'ocid1.compartment.oc1..aaaaaaaa2q5aelkapmt5mhumvxadcynq5chez2faeucy5plefhy3ylmahtba'
DATABASE = 'ocid1.autonomousdatabase.oc1.iad.anuwcljrc7x6gxiapkxouj7emfbelvnvompwjcpoxx5vg727cegjsqkbp4rq'
INSTANCE = 'ocid1.instance.oc1.iad.anuwcljtc7x6gxic5w37qsyp3rst64betkt4uk2pdcrtmy3okspcpbv77qea'
DB_NAME = 'ASZ8EQWFM8UNCA2_JSNF2APEX'
FIXED_TARGET = {'compartment_id': COMPARTMENT, 'database_id': DATABASE,
                'db_name': DB_NAME, 'region': 'us-ashburn-1'}
VERSION_KEYS = ('apex', 'sqlcl', 'database', 'mmd')
SUPPORTED_ACTIVE_VERSIONS = frozenset({('26.1.5', '26.1.2.0', '23.26.4.1.0', '26.1.0+3102')})


class VerificationPolicyError(ValueError):
    """A bounded policy-validation error with no submitted values."""


def _require(condition, message):
    if not condition:
        raise VerificationPolicyError(message)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, 'Duplicate verification profile keys are not allowed.')
        result[key] = value
    return result


def _object(raw):
    _require(isinstance(raw, bytes) and 0 < len(raw) <= 16_384, 'Verification profile must be bounded exact bytes.')
    try:
        value = json.loads(raw, object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise VerificationPolicyError('Verification profile JSON is invalid.') from None
    _require(isinstance(value, dict), 'Verification profile must be an object.')
    return value


def _sha(value):
    return isinstance(value, str) and re.fullmatch(r'[a-f0-9]{64}', value) is not None


def _validate(value, active):
    _require(set(value) == {'schema_version', 'scope', 'policy_id', 'binding', 'target',
                            'expected_versions', 'max_evidence_age_seconds'},
             'Verification profile has missing or unknown fields.')
    _require(type(value['schema_version']) is int and value['schema_version'] == 1
             and value['scope'] == PROFILE_SCOPE and value['policy_id'] == POLICY_ID,
             'Verification profile version or scope is unsupported.')
    binding = value['binding']
    _require(isinstance(binding, dict) and set(binding) == {
        'job_id', 'source_manifest_sha256', 'package_sha256', 'allocation_receipt_sha256'},
        'Verification profile package binding is incomplete.')
    _require(isinstance(binding['job_id'], str) and re.fullmatch(r'fox-[a-f0-9]{20}', binding['job_id'])
             and all(_sha(binding[key]) for key in ('source_manifest_sha256', 'package_sha256', 'allocation_receipt_sha256')),
             'Verification profile package identity is invalid.')
    target = value['target']
    _require(isinstance(target, dict) and set(target) == set(FIXED_TARGET) | {
        'workspace', 'parsing_schema', 'workspace_id', 'application_id', 'application_alias'},
        'Verification profile target is incomplete.')
    _require(all(target.get(key) == expected for key, expected in FIXED_TARGET.items()),
             'Verification is limited to the existing pinned JSN database and region.')
    workspace = target['workspace']
    _require(isinstance(workspace, str) and re.fullmatch(r'FOX_QA_[0-9]{6}_[A-F0-9]{8}', workspace)
             and len(workspace) <= 30 and target['parsing_schema'] == workspace,
             'Verification requires an explicit fresh QA-only workspace and matching schema.')
    try:
        datetime.strptime(workspace[7:13], '%y%m%d')
    except ValueError:
        raise VerificationPolicyError('Verification workspace allocation token is invalid.') from None
    _require(isinstance(target['workspace_id'], str)
             and re.fullmatch(r'[1-9][0-9]{0,37}', target['workspace_id']),
             'Workspace ID must be an exact nonzero decimal string.')
    # This is the consumer serialization bound, not an assertion about Oracle's
    # allocation maximum. The actual allocated receipt must match independently.
    _require(type(target['application_id']) is int and 0 < target['application_id'] <= 9_007_199_254_740_991
             and target['application_alias'] == 'F2A_QA_' + workspace[7:],
             'Verification requires an exact reserved application ID and allocation alias.')
    versions = value['expected_versions']
    _require(isinstance(versions, dict) and set(versions) == set(VERSION_KEYS)
             and all(isinstance(versions[key], str) and re.fullmatch(r'[0-9][0-9.+]{1,63}', versions[key]) for key in VERSION_KEYS),
             'Verification profile version tuple is invalid.')
    if active:
        _require(tuple(versions[key] for key in VERSION_KEYS) in SUPPORTED_ACTIVE_VERSIONS,
                 'Version tuple is not supported for a new technical decision.')
    age = value['max_evidence_age_seconds']
    _require(type(age) is int and 60 <= age <= 604_800, 'Verification freshness bound is invalid.')


@dataclass(frozen=True)
class BoundVerificationPolicy:
    raw: bytes
    historical: bool = False

    def __post_init__(self):
        _require(type(self.historical) is bool, 'Verification policy mode is invalid.')
        _validate(_object(self.raw), active=not self.historical)

    @property
    def document(self):
        # Return a new object so callers cannot mutate the validated policy.
        return _object(self.raw)

    @property
    def sha256(self):
        return hashlib.sha256(self.raw).hexdigest()

    @property
    def binding(self):
        return self.document['binding']

    @property
    def target(self):
        return self.document['target']

    @property
    def versions(self):
        return self.document['expected_versions']

    @property
    def max_evidence_age_seconds(self):
        return self.document['max_evidence_age_seconds']


def validate_allocation_receipt(raw: bytes, policy: BoundVerificationPolicy) -> dict:
    """Bind actual immutable allocation bytes to the private target profile.

    The allocator separately validates its pre-allocation plan. Here its plan
    hash is retained provenance, while actual target/app identity, source/ZIP,
    measured versions and fresh-empty namespace evidence are checked directly.
    Allocation cannot contain a profile hash, avoiding a circular byte binding.
    """
    _require(type(policy) is BoundVerificationPolicy, 'An exact bound verification policy is required.')
    value = _object(raw)
    _require(hashlib.sha256(raw).hexdigest() == policy.binding['allocation_receipt_sha256'],
             'Actual allocation receipt bytes differ from the operator profile.')
    _require(set(value) == {'schema_version', 'scope', 'passed', 'plan_sha256', 'allocated_at_utc',
                           'binding', 'target', 'observed_versions', 'fresh_namespace'},
             'Allocation receipt contains missing or unknown fields.')
    _require(type(value['schema_version']) is int and value['schema_version'] == 1
             and value['scope'] == 'fox-clean-allocation-v2' and value['passed'] is True
             and _sha(value['plan_sha256']), 'Allocation receipt scope or provenance is invalid.')
    timestamp = value['allocated_at_utc']
    _require(isinstance(timestamp, str) and re.fullmatch(
        r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)', timestamp),
        'Allocation time must be explicit UTC.')
    try:
        datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
    except ValueError:
        raise VerificationPolicyError('Allocation timestamp is invalid.') from None
    _require(value['binding'] == {key: policy.binding[key] for key in ('job_id', 'source_manifest_sha256', 'package_sha256')},
             'Allocation job, source or package differs from the profile.')
    target = value['target']
    _require(isinstance(target, dict) and type(target.get('application_id')) is int
             and isinstance(target.get('workspace_id'), str)
             and target == {**policy.target, 'instance_id': INSTANCE},
             'Allocated workspace or reserved application differs from the profile.')
    _require(value['observed_versions'] == policy.versions, 'Allocation version evidence differs from the profile.')
    fresh = value['fresh_namespace']
    _require(isinstance(fresh, dict) and set(fresh) == {
        'workspace_created_fresh', 'schema_created_fresh', 'application_count', 'user_object_count'}
        and fresh['workspace_created_fresh'] is True and fresh['schema_created_fresh'] is True
        and all(type(fresh[key]) is int and fresh[key] == 0 for key in ('application_count', 'user_object_count')),
        'Allocation must prove its exact fresh empty namespace.')
    return value
