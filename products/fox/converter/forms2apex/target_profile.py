"""Strict, secret-free target configuration and read-only preflight contract.

This module performs no SQL, HTTP, OCI, subprocess or credential operations.
The caller must collect the observed values through its guarded read-only
adapters. A passing receipt is an operator/executor attestation, not a vendor
signature, live connectivity test, authorization to write, or business proof.

Only reviewed configurations of the existing JSN product target are allowlisted.
The configured file plus its bound deployment settings select the current tuple;
there is no process-global active selection. Workspace and parsing schema are
separate fields even though they happen to match for this target.
The separate clean-QA target is intentionally NOT an active product target.
Customer deployment requires explicit approval, new acceptance evidence and an
audited allowlist change; editing a JSON file cannot authorize it here.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from .config import PINNED_COMPARTMENT_OCID


MAX_PROFILE_BYTES = 32_768
MAX_PREFLIGHT_AGE_SECONDS = 300
MAX_FUTURE_SKEW_SECONDS = 5
TRUST_BOUNDARY = 'operator_attestation_not_vendor_proof'

_PROFILE_JSN_20261017 = {
    'schema_version': 1,
    'profile_id': 'jsn-native-beta-v1',
    'active': True,
    'scope': {
        'conversion_profile': 'native-table-form-v1',
        'data_mode': 'synthetic_test_only',
        'supported_operations': ['query', 'insert', 'update'],
        'customer_deployment_authorized': False,
        'existing_resources_only': True,
    },
    'oci': {
        'compartment_id': 'ocid1.compartment.oc1..aaaaaaaa2q5aelkapmt5mhumvxadcynq5chez2faeucy5plefhy3ylmahtba',
        'database_id': 'ocid1.autonomousdatabase.oc1.iad.anuwcljrc7x6gxiapkxouj7emfbelvnvompwjcpoxx5vg727cegjsqkbp4rq',
        'instance_id': 'ocid1.instance.oc1.iad.anuwcljtc7x6gxic5w37qsyp3rst64betkt4uk2pdcrtmy3okspcpbv77qea',
        'region': 'us-ashburn-1',
    },
    'database': {
        'db_name': 'ASZ8EQWFM8UNCA2_JSNF2APEX',
        'session_user': 'FORMS2APEX_POC',
        'parsing_schema': 'FORMS2APEX_POC',
    },
    'apex': {
        'workspace': 'FORMS2APEX_POC',
        # Decimal string avoids loss of this >2**53 identifier in JS clients.
        'workspace_id': '9009446931169094',
        'ords_origin': 'https://asz8eqwfm8unca2-jsnf2apex.adb.us-ashburn-1.oraclecloudapps.com',
        'ords_base_path': '/ords',
    },
    'sqlcl': {'saved_connection': 'F2A_APEX'},
    'opaf': {
        'base_url': 'https://localhost:8080/agentFactory',
        'certificate_sha256': '68be4eeb6c362a46c0f1cb8bc4eda4585772a8f8a778dbace28cb60992830f93',
        'model_authentication': 'oci_instance_principal',
        'version_number': 264000,
        'build_id': 1780444486153,
        'roles': {
            'mapper': {
                'workflow_id': '5DF531D447B84A08E063F35A000ADBB1',
                'model': 'xai.grok-4.3',
                'graph_sha256': '50c146086c2506b7198cc65aeb6dd3c4fee244847c4643f853de4c07c41bc0e8',
            },
            'reviewer': {
                'workflow_id': '5DF534D10C2D4E6AE063F35A000A3487',
                'model': 'xai.grok-4.3',
                'graph_sha256': '6f75f0d521c5771b759e7b18a67857a937317f9640d087ef4ce4d11de681c89f',
            },
        },
    },
    'tested_versions': {
        'apex': '26.1.5',
        'sqlcl': '26.1.2.0',
        'apexlang_mmd': '26.1.0+3102',
        'opaf': '26.4.0.0.0',
    },
}

# A separate reviewed snapshot: do not mutate the original native-beta tuple.
_PROFILE_JSN_PROJECT_20261025 = {
    'schema_version': 1,
    'profile_id': 'jsn-native-project-v2',
    # Locally approved/selectable, not evidence of hosted activation or inference.
    'active': True,
    'scope': {
        'conversion_profile': 'native-table-form-v1',
        'data_mode': 'synthetic_test_only',
        'supported_operations': ['query', 'insert', 'update'],
        'customer_deployment_authorized': False,
        'existing_resources_only': True,
        'project_mapping': {
            'native_project_schema_versions': [1, 2],
            'storage_mapping_scope': 'fox-project-storage-v1',
            'module_execution_scope': 'fox-project-module-execution-v2',
        },
    },
    'oci': {
        'compartment_id': 'ocid1.compartment.oc1..aaaaaaaa2q5aelkapmt5mhumvxadcynq5chez2faeucy5plefhy3ylmahtba',
        'database_id': 'ocid1.autonomousdatabase.oc1.iad.anuwcljrc7x6gxiapkxouj7emfbelvnvompwjcpoxx5vg727cegjsqkbp4rq',
        'instance_id': 'ocid1.instance.oc1.iad.anuwcljtc7x6gxic5w37qsyp3rst64betkt4uk2pdcrtmy3okspcpbv77qea',
        'region': 'us-ashburn-1',
    },
    'database': {
        'db_name': 'ASZ8EQWFM8UNCA2_JSNF2APEX',
        'session_user': 'FORMS2APEX_POC',
        'parsing_schema': 'FORMS2APEX_POC',
    },
    'apex': {
        'workspace': 'FORMS2APEX_POC',
        'workspace_id': '9009446931169094',
        'ords_origin': 'https://asz8eqwfm8unca2-jsnf2apex.adb.us-ashburn-1.oraclecloudapps.com',
        'ords_base_path': '/ords',
    },
    'sqlcl': {'saved_connection': 'F2A_APEX'},
    'opaf': {
        'base_url': 'https://localhost:8080/agentFactory',
        'certificate_sha256': '68be4eeb6c362a46c0f1cb8bc4eda4585772a8f8a778dbace28cb60992830f93',
        'model_authentication': 'oci_instance_principal',
        'version_number': 264000,
        'build_id': 1780444486153,
        'roles': {
            'mapper': {
                'workflow_id': '5EAC28A46C40361FE063F35A000AE03C',
                'model': 'xai.grok-4.3',
                'graph_sha256': '897c6ff34f011fd53084623532d843a21d284308f9490ac0c1fee3a11ec3e22e',
            },
            'reviewer': {
                'workflow_id': '5EAC291433A43793E063F35A000AEAC9',
                'model': 'xai.grok-4.3',
                'graph_sha256': '882434ecc24994eee8945cbad7a9e14986d5e4b53b35ea0c46f473a45709bdb9',
            },
        },
    },
    'tested_versions': {
        'apex': '26.1.5',
        'sqlcl': '26.1.2.0',
        'apexlang_mmd': '26.1.0+3102',
        'opaf': '26.4.0.0.0',
    },
}

# Append reviewed snapshots under new digests; never edit historical documents.
# These legacy aliases remain for compatibility, not as runtime selectors.
_ACTIVE_PROFILE_SHA256 = '7c7b73d43febc9befb1d43e47449a02cc7894b879dd4bc32904cec538e5f95e6'
_JSN_PROFILE = _PROFILE_JSN_20261017
_PROJECT_PROFILE_SHA256 = '7170d60927b7e5b7aed5d56174f97efbeff3052be247b244911deff768701ed3'
_KNOWN_HISTORICAL_PROFILES = {
    _ACTIVE_PROFILE_SHA256: _PROFILE_JSN_20261017,
    _PROJECT_PROFILE_SHA256: _PROFILE_JSN_PROJECT_20261025,
}

# Explicit current eligibility, independent of historical recognition. Adding a
# historical snapshot alone never authorizes a deployment. Current operations
# must also call bound_target_profile(settings), reloading the configured file.
_DEPLOYABLE_TARGET_PROFILES = {
    _ACTIVE_PROFILE_SHA256: _PROFILE_JSN_20261017,
    _PROJECT_PROFILE_SHA256: _PROFILE_JSN_PROJECT_20261025,
}


class TargetProfileError(ValueError):
    """A bounded error that does not repeat supplied values or credentials."""


def _canonical_bytes(value) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=False, allow_nan=False).encode('utf-8')
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise TargetProfileError('Target evidence must contain canonical JSON data') from None


def _digest(value) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _exact(value, expected, location: str) -> None:
    """Reject unknown fields and Python bool/int equality at every level."""
    if type(value) is not type(expected):
        raise TargetProfileError(f'{location}: invalid type')
    if isinstance(expected, dict):
        if set(value) != set(expected):
            raise TargetProfileError(f'{location}: missing or unsupported fields')
        for key in expected:
            _exact(value[key], expected[key], f'{location}.{key}')
    elif isinstance(expected, list):
        if len(value) != len(expected):
            raise TargetProfileError(f'{location}: unsupported value')
        for index, item in enumerate(expected):
            _exact(value[index], item, f'{location}[{index}]')
    elif value != expected:
        raise TargetProfileError(f'{location}: does not match the approved JSN target')


def validate_target_profile(value: dict) -> dict:
    """Recognize an exact approved selectable tuple, not a deployment selection.

    Inactive/customer/unregistered files fail closed. The configured file and
    bound deployment settings, not this pure validator or a historical cache,
    determine the current choice. `active` means approved for local selection,
    not hosted activation, successful inference, or authorization to write.
    The exact versions are a tested compatibility tuple, not a minimum version
    rule or a statement that those releases are currently the vendor's latest.
    A newer patch/build requires explicit revalidation before updating this tuple.
    """
    if not isinstance(value, dict):
        raise TargetProfileError('Target profile must be a JSON object')
    if value.get('active') is not True:
        raise TargetProfileError('Inactive target profiles cannot connect or authorize execution')
    digest = _digest(value)
    approved = _DEPLOYABLE_TARGET_PROFILES.get(digest)
    if approved is None:
        raise TargetProfileError('Target profile is not an approved selectable JSN configuration')
    if (approved['oci']['compartment_id'] != PINNED_COMPARTMENT_OCID
            or _digest(approved) != digest):
        raise TargetProfileError('Deployable target profile registry binding is invalid')
    _exact(value, approved, 'profile')
    return json.loads(_canonical_bytes(value))


def validate_historical_target_profile(value: dict) -> dict:
    """Recognize a known immutable evidence snapshot, with no current authority.

    This must never replace active target checks for a new connection or write.
    It exists so a sealed historical model proof/package can be verified without
    fetching OPAF or silently applying today's different deployment settings.
    """
    if not isinstance(value,dict):raise TargetProfileError('Historical target profile must be a JSON object')
    digest=_digest(value)
    known=_KNOWN_HISTORICAL_PROFILES.get(digest)
    if known is None or _digest(known)!=digest:
        raise TargetProfileError('Historical target profile is not a registered immutable snapshot')
    _exact(value,known,'historical_profile')
    return json.loads(_canonical_bytes(value))


def target_profile_sha256(value: dict) -> str:
    """Canonical content digest, not a signature or independent approval."""
    return _digest(validate_target_profile(value))


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise TargetProfileError('Duplicate JSON field in target profile')
        value[key] = item
    return value


def load_target_profile(path: str | Path) -> dict:
    """Read only a bounded regular JSON file; no credentials or network access."""
    target = Path(path).absolute()
    try:
        if target.is_symlink() or target.resolve(strict=True) != target:
            raise TargetProfileError('Target profile must not use linked paths')
        before = target.stat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_PROFILE_BYTES:
            raise TargetProfileError('Target profile must be a bounded regular file')
        with target.open('rb') as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise TargetProfileError('Target profile changed while opening')
            raw = stream.read(MAX_PROFILE_BYTES + 1)
        if len(raw) > MAX_PROFILE_BYTES:
            raise TargetProfileError('Target profile exceeds the size limit')
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_object)
    except TargetProfileError:
        raise
    except (OSError, ValueError, UnicodeError, RuntimeError):
        raise TargetProfileError('Target profile is unavailable or malformed') from None
    return validate_target_profile(value)


def _utc_timestamp(value: str) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)', value, re.ASCII):
        raise TargetProfileError('Preflight timestamp must be explicit UTC')
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise TargetProfileError('Preflight timestamp is invalid') from None


def verify_target_preflight(profile: dict, observed: dict, *, now: datetime) -> dict:
    """Compare fresh operator-observed identity/version metadata, without I/O.

    Collect all observations in one bounded read-only preflight run. `now` must
    come from the executor clock, not the supplied observation. Maximum age is
    fixed at five minutes; at most five seconds of positive clock skew is
    accepted. The caller must rerun checks immediately before protected writes.

    This is deliberately not a grant, source approval, reviewer receipt, native
    schema proof, clean-install proof or runtime/business acceptance certificate.
    """
    return _verify_preflight(profile, observed, now=now, include_model_environment=True)


def verify_deterministic_target_preflight(profile: dict, observed: dict, *, now: datetime) -> dict:
    """Verify only components used after a sealed review, without live OPAF.

    The workflow must independently verify the existing sealed historical review
    and artifact binding. This receipt does not claim a fresh model invocation.
    OPAF/model availability is deliberately irrelevant to deterministic recovery.
    """
    return _verify_preflight(profile, observed, now=now, include_model_environment=False)


def _verify_preflight(profile, observed, *, now, include_model_environment):
    profile = validate_target_profile(profile)
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != timedelta(0):
        raise TargetProfileError('Preflight verification requires a trusted UTC clock')
    if not isinstance(observed, dict):
        raise TargetProfileError('Preflight evidence must be a JSON object')
    checked_at = now.astimezone(timezone.utc)
    observed_at = _utc_timestamp(observed.get('observed_at_utc'))
    age = (checked_at - observed_at).total_seconds()
    if age > MAX_PREFLIGHT_AGE_SECONDS:
        raise TargetProfileError('Preflight evidence is stale; collect new read-only observations')
    if age < -MAX_FUTURE_SKEW_SECONDS:
        raise TargetProfileError('Preflight evidence is in the future beyond allowed clock skew')
    oci, database, apex, opaf = (profile[key] for key in ('oci', 'database', 'apex', 'opaf'))
    expected = {
        'schema_version': 1,
        'trust_boundary': TRUST_BOUNDARY,
        'profile_sha256': target_profile_sha256(profile),
        'observed_at_utc': observed['observed_at_utc'],
        'oci': {
            'database_id': oci['database_id'], 'database_compartment_id': oci['compartment_id'],
            'instance_id': oci['instance_id'], 'instance_compartment_id': oci['compartment_id'],
            'region': oci['region'], 'database_lifecycle_state': 'AVAILABLE', 'instance_lifecycle_state': 'RUNNING',
        },
        'database': {
            'db_name': database['db_name'], 'session_user': database['session_user'],
            'current_schema': database['parsing_schema'],
        },
        'apex': {
            **apex, 'parsing_schema': database['parsing_schema'],
            'workspace_schema_mapping_count': 1, 'https_reachable': True,
        },
        'sqlcl': profile['sqlcl'],
        'opaf': {
            'base_url': opaf['base_url'], 'certificate_sha256': opaf['certificate_sha256'],
            'model_authentication': opaf['model_authentication'],
            'version_number': opaf['version_number'], 'build_id': opaf['build_id'],
            'roles': {role: {**value, 'published': True} for role, value in opaf['roles'].items()},
        },
        'versions': profile['tested_versions'],
    }
    versions = profile['tested_versions']
    if not include_model_environment:
        del expected['opaf']
        versions = {key: versions[key] for key in ('apex', 'sqlcl', 'apexlang_mmd')}
        expected['versions'] = versions
    _exact(observed, expected, 'preflight')
    return {
        'schema_version': 1,
        'scope': 'jsn-native-target-preflight-v1' if include_model_environment else 'jsn-native-deterministic-target-preflight-v1',
        'passed': True,
        'profile_id': profile['profile_id'], 'profile_sha256': target_profile_sha256(profile),
        'observation_sha256': _digest(observed), 'trust_boundary': TRUST_BOUNDARY,
        'observed_at_utc': observed_at.isoformat(), 'checked_at_utc': checked_at.isoformat(),
        'valid_until_utc': (observed_at + timedelta(seconds=MAX_PREFLIGHT_AGE_SECONDS)).isoformat(),
        'max_age_seconds': MAX_PREFLIGHT_AGE_SECONDS, 'max_future_skew_seconds': MAX_FUTURE_SKEW_SECONDS,
        'target': {**oci, **database, **apex, **profile['sqlcl']},
        'tested_versions': versions, 'read_only': True,
        'authorizes_oci_changes': False, 'business_behavior_verified': False,
    }
