"""Read-only native target probes; no database/OCI mutation or ADMIN login.

At model execution FOX observes its authenticated OPAF environment; a separate
contract binds that historical observation to each actual model invocation.
Deterministic operations independently measure SQLcl/compiler, saved-schema
identity, IMDS, OCI resources and ORDS. They do not contact or require live OPAF.
No protected write is implemented here. Callers must verify the sealed historical
review and run this fresh target gate immediately before their protected write.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import json
from pathlib import Path
import re
import ssl
import subprocess
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlsplit
import zipfile

from .security import validate_job_id
from .sqlcl import _run_script, _target_guard
from .target_profile import (
    TargetProfileError, TRUST_BOUNDARY, _canonical_bytes, _exact, _utc_timestamp,
    load_target_profile, target_profile_sha256, validate_target_profile,
    validate_historical_target_profile, verify_deterministic_target_preflight,
)


OPAF_ATTESTATION_TRUST = 'authenticated_fox_executor_not_vendor_attestation'
MAX_MODEL_OBSERVATION_LEAD_SECONDS = 120
PROTECTED_ACTIONS = frozenset({'validate', 'import', 'reconcile', 'release',
                               'prepare-schema', 'reconcile-schema'})
IMDS_URL = 'http://169.254.169.254/opc/v2/instance/'


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _same_ords_base(value: str, expected: str) -> bool:
    try:
        if not isinstance(value, str) or value != value.strip() or any(c in value for c in '\r\n\t'):
            return False
        actual, wanted = urlsplit(value), urlsplit(expected)
        return (actual.scheme == wanted.scheme == 'https' and actual.hostname == wanted.hostname
                and actual.port in (None, 443) and actual.path.rstrip('/') == wanted.path
                and actual.username is None and actual.password is None and not actual.query and not actual.fragment)
    except ValueError:
        return False


def bound_target_profile(settings) -> dict:
    """Load the allowlisted profile and reject unbound environment settings."""
    path = getattr(settings, 'target_profile_path', None)
    if path is None:
        raise TargetProfileError('Native protected operations require an active target profile')
    profile = load_target_profile(path)
    values = {
        'apex_workspace': profile['apex']['workspace'],
        'apex_parsing_schema': profile['database']['parsing_schema'],
        'sqlcl_connection_name': profile['sqlcl']['saved_connection'],
        'generator_model': profile['opaf']['roles']['mapper']['model'],
        'reviewer_model': profile['opaf']['roles']['reviewer']['model'],
        'opaf_mapper_workflow_id': profile['opaf']['roles']['mapper']['workflow_id'],
        'opaf_reviewer_workflow_id': profile['opaf']['roles']['reviewer']['workflow_id'],
    }
    for field, expected in values.items():
        if getattr(settings, field, None) != expected:
            raise TargetProfileError(f'Target settings mismatch: {field}')
    base = profile['apex']['ords_origin'] + profile['apex']['ords_base_path']
    if not _same_ords_base(settings.apex_base_url, base):
        raise TargetProfileError('Target settings mismatch: apex_base_url')
    return profile


def validate_model_environment_observation(profile, value, *, job_id, source_manifest_sha256,
                                           role, invocation):
    """Validate historical model environment against its actual invocation.

    Call while sealing a new versioned review receipt and on later verification.
    There is no current-wall-clock age check: a correctly sealed old candidate
    remains usable for deterministic steps while OPAF is stopped. Existing older
    receipt formats must retain their explicit older proof scope, not get invented
    version fields. The containing receipt binds both observations and candidate.
    """
    profile = validate_historical_target_profile(profile)
    validate_job_id(job_id)
    if role not in {'mapper', 'reviewer'} or not isinstance(source_manifest_sha256, str) or not re.fullmatch(r'[a-f0-9]{64}', source_manifest_sha256):
        raise TargetProfileError('Model observation requires an exact role and source manifest hash')
    if not isinstance(value, dict) or len(_canonical_bytes(value)) > 16_384:
        raise TargetProfileError('Invalid model environment observation')
    if not isinstance(invocation, dict):
        raise TargetProfileError('An actual model invocation is required')
    started = _utc_timestamp(invocation.get('started_at_utc'))
    completed = _utc_timestamp(invocation.get('completed_at_utc'))
    observed_at = _utc_timestamp(value.get('observed_at_utc'))
    lead = (started - observed_at).total_seconds()
    if completed < started or lead > MAX_MODEL_OBSERVATION_LEAD_SECONDS or lead < -5:
        raise TargetProfileError('Model environment observation is outside its invocation time window')
    opaf = profile['opaf']
    expected_role = opaf['roles'][role]
    for field in ('workflow_id', 'model', 'graph_sha256'):
        if invocation.get(field) != expected_role[field]:
            raise TargetProfileError('Model invocation differs from its environment role binding')
    expected = {
        'schema_version': 1, 'scope': 'opaf-model-environment-v1', 'trust_boundary': OPAF_ATTESTATION_TRUST,
        'job_id': job_id, 'role': role, 'source_manifest_sha256': source_manifest_sha256,
        'target_profile_sha256': hashlib.sha256(_canonical_bytes(profile)).hexdigest(),
        'observed_at_utc': value['observed_at_utc'],
        'opaf': {key: opaf[key] for key in ('base_url', 'certificate_sha256', 'model_authentication', 'version_number', 'build_id')},
        'workflow': {**expected_role, 'published': True},
        'opaf_version': profile['tested_versions']['opaf'],
    }
    _exact(value, expected, 'model_environment')
    return json.loads(_canonical_bytes(value))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise TargetProfileError('Metadata redirects are not allowed')


def collect_imds_identity(profile) -> dict:
    profile = validate_target_profile(profile)
    request = urllib.request.Request(IMDS_URL, headers={'Authorization': 'Bearer Oracle'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=5) as response:
            if response.status != 200 or response.geturl() != IMDS_URL:
                raise TargetProfileError('IMDS identity could not be verified')
            raw = response.read(65_537)
        if len(raw) > 65_536:
            raise TargetProfileError('IMDS identity exceeded its bounded response size')
        metadata = json.loads(raw)
        value = {'instance_id': metadata['id'], 'compartment_id': metadata['compartmentId'],
                 'region': metadata['canonicalRegionName']}
        expected = {key: profile['oci'][key] for key in value}
        _exact(value, expected, 'imds')
        return value
    except TargetProfileError:
        raise
    except (OSError, ValueError, KeyError, TypeError):
        raise TargetProfileError('Read-only IMDS identity probe failed') from None


def collect_tooling_versions(settings, profile) -> dict:
    profile = validate_target_profile(profile)
    executable = Path(settings.sqlcl_path)
    compiler = executable.parent.parent/'lib/apexlang-compiler.jar'
    if not executable.is_file() or compiler.is_symlink() or not compiler.is_file() or compiler.stat().st_size > 256 * 1024 * 1024:
        raise TargetProfileError('Installed SQLcl/compiler files are unavailable or unsupported')
    try:
        result = subprocess.run([str(executable), '-V'], capture_output=True, text=True,
                                encoding='utf-8', errors='strict', timeout=30, check=False)
        if result.returncode != 0 or result.stderr.strip() or len(result.stdout) > 8192:
            raise TargetProfileError('SQLcl version probe failed')
        match = re.fullmatch(r'\s*SQLcl: Release ([0-9.]+) Production Build: ([0-9.]+)\s*', result.stdout)
        if not match:
            raise TargetProfileError('SQLcl version output is not the supported marker format')
        with zipfile.ZipFile(compiler) as archive:
            names = archive.namelist()
            if names.count('apexlang_meta_data.json') != 1 or archive.getinfo('apexlang_meta_data.json').file_size > 8 * 1024 * 1024:
                raise TargetProfileError('Compiler metadata is missing or exceeds its bound')
            metadata = json.loads(archive.read('apexlang_meta_data.json'))
        mmd = metadata['buildID']
        if match[1] != profile['tested_versions']['sqlcl'] or mmd != profile['tested_versions']['apexlang_mmd']:
            raise TargetProfileError('Measured SQLcl/compiler version differs from the tested target profile')
        digest = hashlib.sha256()
        with compiler.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(chunk)
        return {'sqlcl': match[1], 'sqlcl_build': match[2], 'apexlang_mmd': mmd,
                'compiler_jar_sha256': digest.hexdigest(),
                'sqlcl_source': 'sqlcl_-V',
                'mmd_source': 'apexlang-compiler.jar!apexlang_meta_data.json#buildID'}
    except TargetProfileError:
        raise
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile, subprocess.SubprocessError):
        raise TargetProfileError('Read-only SQLcl/compiler version probe failed') from None


def collect_database_identity(settings, profile, job_root) -> dict:
    """Use only the saved parsing-schema connection, never ADMIN or a password."""
    profile = validate_target_profile(profile)
    root = Path(job_root)
    if not root.is_dir() or root.is_symlink() or root.parent.resolve() != Path(settings.jobs_root).resolve():
        raise TargetProfileError('Target probe requires an existing direct job directory')
    workspace, schema = profile['apex']['workspace'], profile['database']['parsing_schema']
    commands = [
        'set sqlformat default', 'set pagesize 0', 'set linesize 32767', 'set trimout on', 'set define off',
        'whenever oserror exit failure rollback', _target_guard(profile['database']['session_user']),
        "select 'FOX_TARGET_BEGIN=1' from dual;",
        "select 'FOX_TARGET_DB_NAME='||sys_context('USERENV','DB_NAME') from dual;",
        "select 'FOX_TARGET_SESSION_USER='||sys_context('USERENV','SESSION_USER') from dual;",
        "select 'FOX_TARGET_CURRENT_SCHEMA='||sys_context('USERENV','CURRENT_SCHEMA') from dual;",
        "select 'FOX_TARGET_APEX_VERSION='||version_no from apex_release;",
        "select 'FOX_TARGET_MAPPING='||workspace_name||'|'||schema||'|'||to_char(workspace_id,'TM9') "
        f"from apex_workspace_schemas where workspace_name='{workspace}' and schema='{schema}';",
        "select 'FOX_TARGET_MAPPING_COUNT='||to_char(count(*),'TM9') from apex_workspace_schemas "
        f"where workspace_name='{workspace}';",
        "select 'FOX_TARGET_END=1' from dual;",
    ]
    try:
        result = _run_script(settings.sqlcl_path, ['-S', '-L', '-name', profile['sqlcl']['saved_connection']],
                             commands, root, timeout=60)
        if result.returncode != 0 or result.stderr.strip() or len(result.stdout) > 16_384:
            raise TargetProfileError('Saved-schema target identity probe failed')
        values = {}
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if not lines or lines[0] != 'FOX_TARGET_BEGIN=1' or lines[-1] != 'FOX_TARGET_END=1':
            raise TargetProfileError('Saved-schema identity marker protocol did not complete')
        for line in lines:
            match = re.fullmatch(r'FOX_TARGET_([A-Z_]+)=([A-Za-z0-9_.|]+)', line)
            if not match or match[1] in values:
                raise TargetProfileError('Saved-schema identity returned unknown or duplicate markers')
            values[match[1]] = match[2]
        expected = {
            'BEGIN': '1', 'END': '1', 'DB_NAME': profile['database']['db_name'],
            'SESSION_USER': profile['database']['session_user'], 'CURRENT_SCHEMA': schema,
            'APEX_VERSION': profile['tested_versions']['apex'],
            'MAPPING': f"{workspace}|{schema}|{profile['apex']['workspace_id']}", 'MAPPING_COUNT': '1',
        }
        _exact(values, expected, 'saved_schema')
        actual_workspace, actual_schema, actual_workspace_id = values['MAPPING'].split('|')
        return {'database': {'db_name': values['DB_NAME'], 'session_user': values['SESSION_USER'], 'current_schema': values['CURRENT_SCHEMA']},
                'apex': {'workspace': actual_workspace, 'workspace_id': actual_workspace_id,
                         'parsing_schema': actual_schema, 'workspace_schema_mapping_count': int(values['MAPPING_COUNT'])},
                'apex_version': values['APEX_VERSION']}
    except TargetProfileError:
        raise
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        raise TargetProfileError('Read-only saved-schema identity probe failed') from None


def collect_ords_reachability(profile) -> dict:
    profile = validate_target_profile(profile)
    apex = profile['apex']
    base = apex['ords_origin'] + apex['ords_base_path'] + '/'
    url = urlsplit(base)
    connection = http.client.HTTPSConnection(url.hostname, 443, context=ssl.create_default_context(), timeout=10)
    try:
        connection.request('HEAD', url.path, headers={'Accept': 'text/html'})
        response = connection.getresponse()
        if response.status not in {200, 301, 302, 303, 307, 308}:
            raise TargetProfileError('Managed ORDS HTTPS base is not available')
        if response.status != 200:
            redirected = urlsplit(urljoin(base, response.getheader('Location', '')))
            if (redirected.scheme != 'https' or redirected.hostname != url.hostname or redirected.port not in (None, 443)
                    or redirected.username or redirected.password):
                raise TargetProfileError('ORDS redirected outside the pinned HTTPS origin')
        return {'ords_origin': apex['ords_origin'], 'ords_base_path': apex['ords_base_path'], 'https_reachable': True}
    except TargetProfileError:
        raise
    except (OSError, ValueError, http.client.HTTPException):
        raise TargetProfileError('Read-only ORDS reachability probe failed') from None
    finally:
        connection.close()


def collect_deterministic_preflight(settings, job_root, *, job_id, action, source_manifest_sha256,
                                    clock=None) -> dict:
    """Fresh target/compiler gate; sealed review is checked by the caller.

    No live OPAF call, model credential, new MCP argument or Windows-side refresh
    is needed. Only invoke for actual target operations, not local cached-package
    download or reconciliation that reads already-persisted evidence.
    """
    clock = clock or _now
    started = clock()
    profile = bound_target_profile(settings)
    validate_job_id(job_id)
    if action not in PROTECTED_ACTIONS or not isinstance(source_manifest_sha256, str) or not re.fullmatch(r'[a-f0-9]{64}', source_manifest_sha256):
        raise TargetProfileError('Preflight requires a protected action and exact source manifest hash')
    if Path(job_root).name != job_id:
        raise TargetProfileError('Preflight job directory does not match its action binding')
    imds = collect_imds_identity(profile)
    tooling = collect_tooling_versions(settings, profile)
    database = collect_database_identity(settings, profile, job_root)
    from .oci_identity import collect_oci_identity
    oci = collect_oci_identity(profile, imds)
    ords = collect_ords_reachability(profile)
    observed = {
        'schema_version': 1, 'trust_boundary': TRUST_BOUNDARY,
        'profile_sha256': target_profile_sha256(profile),
        'observed_at_utc': started.isoformat(),
        'oci': oci, 'database': database['database'], 'apex': {**database['apex'], **ords},
        'sqlcl': {'saved_connection': profile['sqlcl']['saved_connection']},
        'versions': {'apex': database['apex_version'], 'sqlcl': tooling['sqlcl'],
                     'apexlang_mmd': tooling['apexlang_mmd']},
    }
    completed = clock()
    receipt = verify_deterministic_target_preflight(profile, observed, now=completed)
    value = {
        'schema_version': 1, 'scope': 'jsn-native-deterministic-action-preflight-v1', 'passed': True,
        'job_id': job_id, 'action': action, 'source_manifest_sha256': source_manifest_sha256,
        'profile_sha256': receipt['profile_sha256'],
        'target_preflight': receipt, 'observations': observed, 'tooling_measurements': tooling,
        'valid_until_utc': receipt['valid_until_utc'],
        'authorizes_oci_changes': False, 'sealed_historical_review_required': True,
    }
    value['receipt_sha256'] = hashlib.sha256(_canonical_bytes(value)).hexdigest()
    return value


def verify_action_preflight(receipt, profile, *, job_id, action, source_manifest_sha256, now):
    """Recheck a persisted gate after lock/prechecks, immediately before a write.

    This is local verification of the original observation, not a refresh of its
    timestamp or a replay of model/provider calls. Expired proof must stop.
    """
    if action not in PROTECTED_ACTIONS:
        raise TargetProfileError('Preflight action is unsupported')
    profile=validate_target_profile(profile)
    fields={'schema_version','scope','passed','job_id','action','source_manifest_sha256','profile_sha256',
            'target_preflight','observations','tooling_measurements','valid_until_utc',
            'authorizes_oci_changes','sealed_historical_review_required','receipt_sha256'}
    if not isinstance(receipt,dict) or set(receipt)!=fields:
        raise TargetProfileError('Action preflight receipt is missing or unsupported')
    unsigned={key:value for key,value in receipt.items() if key!='receipt_sha256'}
    if hashlib.sha256(_canonical_bytes(unsigned)).hexdigest()!=receipt.get('receipt_sha256'):
        raise TargetProfileError('Action preflight receipt changed')
    expected={'schema_version':1,'scope':'jsn-native-deterministic-action-preflight-v1','passed':True,
              'job_id':job_id,'action':action,'source_manifest_sha256':source_manifest_sha256,
              'profile_sha256':target_profile_sha256(profile),'authorizes_oci_changes':False,
              'sealed_historical_review_required':True}
    for key,value in expected.items():_exact(receipt.get(key),value,'action_preflight.'+key)
    original=receipt.get('target_preflight')
    if not isinstance(original,dict):raise TargetProfileError('Target preflight receipt is missing')
    original_checked=_utc_timestamp(original.get('checked_at_utc'))
    recreated=verify_deterministic_target_preflight(profile,receipt['observations'],now=original_checked)
    _exact(original,recreated,'action_preflight.target_preflight')
    _exact(receipt['valid_until_utc'],original['valid_until_utc'],'action_preflight.valid_until_utc')
    # This check deliberately uses the current executor time AFTER any lock
    # wait/read-only allocation query, never the stored original check time.
    verify_deterministic_target_preflight(profile,receipt['observations'],now=now)
    return receipt
