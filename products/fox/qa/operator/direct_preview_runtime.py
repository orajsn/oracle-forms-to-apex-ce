"""Protected host-only direct preview runtime factory; inert until configured.

Set FOX_DIRECT_RUNTIME_CONFIG_FILE to a mode-0600 operator JSON file, then use
qa.operator.prototype_runtime_worker pending/run --factory
qa.operator.direct_preview_runtime:configure. No setup/install/account changes.
Configuration selects only existing tools, synthetic credentials and local jobs.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
from types import SimpleNamespace

from forms2apex import runtime_preflight, sqlcl
from forms2apex.project_reviews import digest
from forms2apex.prototype_authority_client import PrototypeAuthorityClient
from forms2apex.prototype_runtime_bridge import LocalJobIO
from .prototype_browser import PrototypeBrowser, PrototypeBrowserConfig, private, DB_NAME, ORIGIN
from .prototype_runtime_worker import RuntimeWorkerConfig

_FIELDS = {'schema_version', 'jobs_root', 'staging_jobs_root', 'qa_root', 'image_id',
           'credentials_file', 'credentials_sha256', 'username', 'target_profile_file',
           'sqlcl_path', 'bearer_token_file', 'authority_origin', 'synthetic_identity_approved'}
_SHA = re.compile(r'[a-f0-9]{64}\Z')


def need(value):
    if not value:
        raise RuntimeError('DIRECT_PREVIEW_RUNTIME_CONFIGURATION_OR_AUTHORITY_UNAVAILABLE')


def read_private(path, *, limit=65536):
    path = private(path, secret=True)
    need(path.stat().st_size <= limit)
    raw = path.read_bytes()
    need(0 < len(raw) <= limit)
    return raw


def load_json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            need(key not in value)
            value[key] = item
        return value
    try:
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda _: need(False))
    except (ValueError, TypeError, UnicodeError):
        raise RuntimeError('DIRECT_PREVIEW_RUNTIME_CONFIGURATION_OR_AUTHORITY_UNAVAILABLE') from None


def build(config, *, settings, authority):
    """Construct using explicit trusted settings; no subprocess or secret read.

    Credential bytes are checked only immediately before the real browser call.
    The protected config is the operator's explicit authorization for this one
    synthetic account, while fresh SQLcl verifies account and target existence.
    """
    config = deepcopy(config)
    need(type(config) is dict and set(config) == _FIELDS
         and type(config['schema_version']) is int and config['schema_version'] == 1
         and config['synthetic_identity_approved'] is True and callable(authority))
    need(type(config['username']) is str
         and re.fullmatch(r'[A-Za-z][A-Za-z0-9_.@-]{0,127}', config['username'])
         and config['username'].lower() not in {'jason', 'admin', 'administrator'}
         and type(config['credentials_sha256']) is str
         and _SHA.fullmatch(config['credentials_sha256'])
         and type(config['image_id']) is str
         and re.fullmatch(r'sha256:[a-f0-9]{64}', config['image_id']))
    need(all(type(config[key]) is str and Path(config[key]).is_absolute()
             and '..' not in Path(config[key]).parts for key in (
                 'jobs_root', 'staging_jobs_root', 'qa_root', 'credentials_file',
                 'target_profile_file', 'sqlcl_path', 'bearer_token_file')))
    need(type(config['authority_origin']) is str and re.fullmatch(
        r'http://127\.0\.0\.1:[1-9][0-9]{0,4}', config['authority_origin'])
        and int(config['authority_origin'].rsplit(':', 1)[1]) <= 65535)
    jobs = private(config['jobs_root'], directory=True)
    staging = private(config['staging_jobs_root'], directory=True)
    qa = private(config['qa_root'], directory=True)
    need(jobs != staging and not jobs.is_relative_to(staging)
         and not staging.is_relative_to(jobs))
    credential = private(config['credentials_file'], secret=True)
    profile = runtime_preflight.bound_target_profile(settings)
    need(profile.get('design_provider', {}).get('provider') == 'oci_genai'
         and profile['apex']['workspace'] == 'FORMS2APEX_POC'
         and profile['apex']['ords_origin'] == ORIGIN
         and profile['database']['db_name'] == DB_NAME
         and profile['sqlcl']['saved_connection'] == 'F2A_APEX')
    reference = digest(config)

    def current(request):
        original = deepcopy(request)
        need(authority(request) == original and request == original)
        need(runtime_preflight.bound_target_profile(settings) == profile)
        return request

    def credential_authority(request, *, credential_file):
        current(deepcopy(request))
        need(Path(credential_file) == credential)
        raw = read_private(credential, limit=8192)
        need(hashlib.sha256(raw).hexdigest() == config['credentials_sha256'])
        accounts = load_json(raw)
        need(type(accounts) is dict and set(accounts) <= {
            'username', 'password', 'second_username', 'second_password'}
            and accounts.get('username') == config['username']
            and type(accounts.get('password')) is str and 0 < len(accounts['password']) <= 1024)
        # Username has a strict identifier alphabet above; no source/model SQL.
        username = config['username'].upper()
        commands = ['set pagesize 0', 'set linesize 32767', 'set trimout on',
                    'set define off', 'whenever oserror exit failure rollback',
                    sqlcl._target_guard('FORMS2APEX_POC'),
                    "select 'FOX_RUNTIME_ACCOUNT='||count(*) from apex_workspace_apex_users "
                    "where workspace_name='FORMS2APEX_POC' "
                    f"and upper(user_name)='{username}' and account_locked='No';"]
        observed = sqlcl._run_script(settings.sqlcl_path,
                    ['-S', '-L', '-name', 'F2A_APEX'], commands, staging, timeout=60)
        need(observed.returncode == 0 and not observed.stderr.strip()
             and observed.stdout.strip() == 'FOX_RUNTIME_ACCOUNT=1')
        need(read_private(credential, limit=8192) == raw)
        current(deepcopy(request))
        return {'schema_version': 1, 'scope': 'fox-prototype-runtime-credentials-target-v1',
                'workspace': 'FORMS2APEX_POC', 'db_name': DB_NAME, 'ords_origin': ORIGIN,
                'credentials_sha256': hashlib.sha256(raw).hexdigest(),
                'username_sha256': hashlib.sha256(config['username'].strip().lower().encode()).hexdigest(),
                'authorization_reference_sha256': reference}

    browser = PrototypeBrowser(PrototypeBrowserConfig(staging, qa, config['image_id'],
                    credential, os.getuid(), os.getgid()), credential_authorizer=credential_authority)
    return RuntimeWorkerConfig(LocalJobIO(jobs), staging, browser, current)


def configure():
    """Read only the explicitly selected protected config; make no network calls."""
    config = load_json(read_private(os.environ['FOX_DIRECT_RUNTIME_CONFIG_FILE']))
    need(type(config) is dict and set(config) == _FIELDS)
    profile_path = private(config['target_profile_file'], secret=True)
    from forms2apex.target_profile import load_target_profile
    profile = load_target_profile(profile_path)
    provider = profile['design_provider']
    token = read_private(config['bearer_token_file']).decode('utf-8')
    need(token == token.strip() and 32 <= len(token) <= 8192)
    settings = SimpleNamespace(jobs_root=Path(config['jobs_root']),
        sqlcl_path=Path(config['sqlcl_path']), target_profile_path=profile_path,
        sqlcl_connection_name='F2A_APEX', apex_workspace=profile['apex']['workspace'],
        apex_parsing_schema=profile['database']['parsing_schema'],
        apex_base_url=profile['apex']['ords_origin'] + profile['apex']['ords_base_path'],
        generator_model=provider['roles']['mapper']['model'],
        reviewer_model=provider['roles']['reviewer']['model'], bearer_token=token)
    origin = config['authority_origin']
    authority = PrototypeAuthorityClient(settings,
        authority_url=origin + '/api/internal/prototype/authorize',
        authority_origin=origin, allow_loopback_http=True)
    return build(config, settings=settings, authority=authority)
