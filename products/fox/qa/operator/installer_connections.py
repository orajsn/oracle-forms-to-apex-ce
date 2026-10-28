"""Create-only protected setup inputs, not connectivity or service admission.

Produces the actual project-profile/client formats consumed by FOX. No network,
Oracle connection, application import, subprocess or model invocation occurs here.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import secrets

from . import installer_storage as step

DIRECTORY = 'configuration'
SCOPE = 'fox-installer-connections-v1'
FILES = ('target-profile.json', 'opaf-profile.json', 'opaf/client.json',
         'private/fox-access.json', 'private/converter-token')
MAPPING = {'native_project_schema_versions': [1, 2],
           'storage_mapping_scope': 'fox-project-storage-v1',
           'module_execution_scope': 'fox-project-module-execution-v2'}


class InstallerConnectionError(ValueError):
    """Closed codes only; credential values must not enter diagnostics."""


def need(value, code):
    if not value:raise InstallerConnectionError(code)


def canonical(value):
    return step.storage.canonical(value)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def targets():
    # This is an explicitly registered test target, not portable customer
    # authority. Keep generic/customer onboarding visibly unfinished.
    return [{'profile_id': 'jsn-native-project-v2',
             'label': 'Existing JSN synthetic-test target',
             'customer_target': False}]


def target(profile_id):
    from forms2apex.target_profile import select_target_profile
    need(type(profile_id) is str and profile_id in {x['profile_id'] for x in targets()},
         'REGISTERED_SETUP_TARGET_REQUIRED')
    value = select_target_profile(profile_id)
    need(value['scope'].get('project_mapping') == MAPPING, 'PROJECT_SETUP_TARGET_REQUIRED')
    return value


def native_profile(value):
    opaf = value['opaf']
    return {'schema_version': 2, 'profile_id': 'native-project-v1', **MAPPING,
            'opaf_base_url': opaf['base_url'], 'certificate_sha256': opaf['certificate_sha256'],
            **opaf['roles']}


def _base(plan, expected):
    observed = step.inspect(plan, expected_plan_sha256=expected)
    need(observed['status'] == 'STORAGE_OBSERVED_NOT_INSTALLED', 'VERIFIED_SETUP_STORAGE_REQUIRED')
    return Path(plan['installation_root']) / DIRECTORY, observed


def _intent(plan, expected, observed, profile):
    return {'schema_version': 1, 'scope': SCOPE, 'installation_id': observed['installation_id'],
            'storage_plan_sha256': expected,
            'storage_completion_sha256': observed['storage_completion_sha256'],
            'target_profile_id': profile['profile_id'],
            'target_profile_sha256': sha(canonical(profile)),
            'writer_sha256': sha(Path(__file__).read_bytes())}


def _inventory(root):
    step.storage._private_dir(root)
    allowed = {'intent.json', 'complete.json', 'opaf', 'private', *FILES}
    seen = set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(directory) / name; relative = path.relative_to(root).as_posix()
            need(relative in allowed and relative not in seen, 'CONNECTION_CONTENTS_REQUIRE_REVIEW')
            seen.add(relative)
            if relative in ('opaf', 'private'):step.storage._private_dir(path)
            else:step.storage._read(path, maximum=32768)
    need(seen == allowed, 'PARTIAL_CONNECTION_SETUP_REQUIRES_REVIEW')


def inspect(plan, *, expected_plan_sha256):
    root, observed = _base(plan, expected_plan_sha256)
    if not os.path.lexists(root):
        return {'status': 'CONNECTIONS_NOT_SAVED', 'read_only': True, 'connectivity_checked': False}
    _inventory(root)
    intent_raw = step.storage._read(root / 'intent.json', maximum=8192)
    intent = json.loads(intent_raw)
    profile = target(intent.get('target_profile_id'))
    expected = _intent(plan, expected_plan_sha256, observed, profile)
    need(intent_raw == canonical(expected), 'CONNECTION_SETUP_BINDING_CHANGED')
    contents = {name: step.storage._read(root / name, maximum=32768) for name in FILES}
    complete = {'scope': SCOPE, 'intent_sha256': sha(intent_raw),
                'files': {name: sha(raw) for name, raw in contents.items()}}
    need(step.storage._read(root / 'complete.json', maximum=8192) == canonical(complete),
         'CONNECTION_SETUP_CONTENT_CHANGED')
    need(contents['target-profile.json'] == canonical(profile)
         and contents['opaf-profile.json'] == canonical(native_profile(profile)),
         'CONNECTION_PROFILE_CHANGED')
    client = json.loads(contents['opaf/client.json']); access = json.loads(contents['private/fox-access.json'])
    need(set(client) == {'username', 'password', 'converter_token'}
         and set(access) == {'username', 'password_verifier'}, 'PROTECTED_CONNECTION_FORMAT_CHANGED')
    need(contents['private/converter-token'] == (client['converter_token'] + '\n').encode(),
         'INTERNAL_TOKEN_BINDING_CHANGED')
    # No credential, password hash, secret-file digest or operator path escapes
    # this result. The installer service binder must use these retained files.
    return {'status': 'CONNECTION_INPUTS_SAVED_NOT_TESTED', 'read_only': True,
            'target_profile_id': profile['profile_id'], 'connectivity_checked': False,
            'services_started': False, 'conversion_ready': False}


def validate_body(body):
    """Validate operator input before an attempt is marked or anything written."""
    need(type(body) is dict and set(body) == {'target_profile_id', 'fox_username', 'fox_password',
         'opaf_username', 'opaf_password'}, 'CONNECTION_REQUEST_FIELDS_INVALID')
    for name in ('fox_username', 'opaf_username'):
        need(type(body[name]) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}', body[name]),
             'SETUP_USERNAME_INVALID')
    for name in ('fox_password', 'opaf_password'):
        minimum = 12 if name == 'fox_password' else 1
        need(type(body[name]) is str and minimum <= len(body[name]) <= 256
             and not any(ord(c) < 32 or ord(c) == 127 for c in body[name]), 'SETUP_PASSWORD_INVALID')
    return target(body['target_profile_id'])


def prepare(plan, *, expected_plan_sha256, body, apply=False):
    need(apply is True, 'EXPLICIT_CONNECTION_SETUP_APPROVAL_REQUIRED')
    profile = validate_body(body)
    root, observed = _base(plan, expected_plan_sha256)
    if os.path.lexists(root):
        result = inspect(plan, expected_plan_sha256=expected_plan_sha256)
        need(result['target_profile_id'] == profile['profile_id'], 'SAVED_TARGET_REQUIRES_EXPLICIT_RECONFIGURATION')
        return {**result, 'credentials_unchanged': True}
    salt = secrets.token_hex(16)
    verifier = salt + ':' + hashlib.scrypt(body['fox_password'].encode(), salt=bytes.fromhex(salt),
                                          n=16384, r=8, p=1).hex()
    token = secrets.token_urlsafe(48)
    contents = {'target-profile.json': canonical(profile),
                'opaf-profile.json': canonical(native_profile(profile)),
                'opaf/client.json': canonical({'username': body['opaf_username'],
                    'password': body['opaf_password'], 'converter_token': token}),
                'private/fox-access.json': canonical({'username': body['fox_username'],
                                                    'password_verifier': verifier}),
                'private/converter-token': (token + '\n').encode()}
    intent = _intent(plan, expected_plan_sha256, observed, profile)
    # Exclusive allocation: no adoption, deletion, permission repair or write
    # replay over a partial/unknown configuration directory.
    step.storage._mkdir(root)
    step.storage._write(root / 'intent.json', canonical(intent))
    for name in ('opaf', 'private'):step.storage._mkdir(root / name)
    for name, raw in contents.items():step.storage._write(root / name, raw)
    complete = {'scope': SCOPE, 'intent_sha256': sha(canonical(intent)),
                'files': {name: sha(raw) for name, raw in contents.items()}}
    step.storage._write(root / 'complete.json', canonical(complete))
    result = inspect(plan, expected_plan_sha256=expected_plan_sha256)
    return {**result, 'read_only': False, 'credentials_unchanged': False}
