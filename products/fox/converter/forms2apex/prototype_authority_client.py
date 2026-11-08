"""TLS-verified read-only FOX authority callback; no grants, redirects or retries."""
from __future__ import annotations

import hashlib
import http.client
import json
import ssl
from urllib.parse import urlsplit

from . import runtime_preflight

AUTHORITY_PATH = '/api/internal/prototype/authorize'
RESPONSE_SCOPE = 'fox-prototype-current-authority-v1'
MAX_RESPONSE_BYTES = 8192
MAX_REQUEST_BYTES = 2_000_000
DEFAULT_AUTHORITY_TIMEOUT_SECONDS = 30


def _bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')


def _hash(value):
    return hashlib.sha256(_bytes(value)).hexdigest()


def execution_target(profile):
    """Wire v1 projection; mirrored in FOX authority, parity-tested."""
    for name, fields in {
        'oci': {'compartment_id', 'database_id', 'instance_id', 'region'},
        'database': {'db_name', 'session_user', 'parsing_schema'},
        'apex': {'workspace', 'workspace_id', 'ords_origin', 'ords_base_path'},
        'sqlcl': {'saved_connection'},
        'tested_versions': {'apex', 'sqlcl', 'apexlang_mmd', 'opaf'},
    }.items():
        item = profile[name]
        if (type(item) is not dict or set(item) != fields
                or any(type(value) is not str or not value or len(value) > 2048 for value in item.values())):
            raise ValueError('Incomplete execution destination')
    scope = profile['scope']
    if (profile['active'] is not True or scope['data_mode'] != 'synthetic_test_only'
            or scope['existing_resources_only'] is not True
            or scope['customer_deployment_authorized'] is not False
            or scope['supported_operations'] != ['query', 'insert', 'update']):
        raise ValueError('Unsupported execution scope')
    return {'schema_version': 1, 'active': True,
            **{key: profile[key] for key in ('oci', 'database', 'apex', 'sqlcl')},
            'tested_versions': {key: profile['tested_versions'][key]
                                for key in ('apex', 'sqlcl', 'apexlang_mmd')},
            'scope': {key: scope[key] for key in ('data_mode', 'existing_resources_only',
                      'customer_deployment_authorized', 'supported_operations')}}


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('Duplicate response field')
        value[key] = item
    return value


class PrototypeAuthorityClient:
    def __init__(self, settings, *, authority_url, authority_origin, timeout=DEFAULT_AUTHORITY_TIMEOUT_SECONDS):
        # These arguments come only from trusted startup, never an MCP/request.
        url = urlsplit(authority_url)
        origin = urlsplit(authority_origin)
        if (url.scheme != 'https' or not url.hostname or url.port not in (None, 443)
                or url.path != AUTHORITY_PATH or url.query or url.fragment or url.username or url.password
                or authority_origin != 'https://' + url.netloc
                or origin.path or origin.query or origin.fragment
                or any(c.isspace() for c in authority_url + authority_origin)
                or type(timeout) not in (int, float) or not 0 < timeout <= 30):
            raise ValueError('Trusted exact HTTPS FOX authority URL/origin required')
        token = settings.bearer_token
        if (not isinstance(token, str) or not 16 <= len(token) <= 8192
                or any(ord(c) < 33 or ord(c) > 126 for c in token)):
            raise ValueError('Existing converter bearer token required')
        self.settings, self.url, self.origin, self.timeout = settings, url, authority_origin, timeout

    def __call__(self, request):
        try:
            if not isinstance(request, dict):
                raise ValueError('Request must be an object')
            raw = _bytes(request)
            if len(raw) > MAX_REQUEST_BYTES:
                raise ValueError('Authority request oversized')
            expected_target = _hash(execution_target(runtime_preflight.bound_target_profile(self.settings)))
            # http.client bypasses HTTP(S)_PROXY environment entirely, does not
            # follow redirects, and performs no automatic application retry.
            connection = http.client.HTTPSConnection(self.url.hostname, 443,
                context=ssl.create_default_context(), timeout=self.timeout)
            try:
                connection.request('POST', AUTHORITY_PATH, body=raw, headers={
                    'Authorization': 'Bearer ' + self.settings.bearer_token, 'Origin': self.origin,
                    'Content-Type': 'application/json', 'Accept': 'application/json'})
                response = connection.getresponse()
                if response.status != 200:
                    raise ValueError('Authority rejected request')
                body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise ValueError('Authority response oversized')
                value = json.loads(body, object_pairs_hook=_unique,
                    parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            finally:
                connection.close()
            fields = {'schema_version', 'scope', 'request_sha256', 'job_id', 'project_id',
                      'source_binding', 'target_profile_sha256', 'execution_target_sha256'}
            if (not isinstance(value, dict) or set(value) != fields or type(value['schema_version']) is not int
                    or value['schema_version'] != 1 or value['scope'] != RESPONSE_SCOPE
                    or value['request_sha256'] != _hash(request)
                    or any(value[key] != request[key] for key in ('job_id', 'project_id', 'source_binding'))
                    or value['execution_target_sha256'] != expected_target
                    or not isinstance(value['target_profile_sha256'], str)
                    or len(value['target_profile_sha256']) != 64
                    or any(c not in '0123456789abcdef' for c in value['target_profile_sha256'])
                    or expected_target != _hash(execution_target(runtime_preflight.bound_target_profile(self.settings)))):
                raise ValueError('Authority binding changed')
            return request  # Preserve exact caller object, never fabricate authority.
        except (OSError, ValueError, TypeError, KeyError, AttributeError, RuntimeError,
                http.client.HTTPException, RecursionError, OverflowError):
            raise RuntimeError('PROTOTYPE_CURRENT_AUTHORITY_UNAVAILABLE_NO_RETRY') from None
