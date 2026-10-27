"""Pure, secret-free configuration for a fresh FOX application's endpoint.

This projection is data, not connected admission, storage initialization,
target authorization or a substitute for migration/retirement evidence.
Importing this module performs no filesystem, database or network access.
"""
from __future__ import annotations

import hashlib
import json
import re


PROJECTION_SCOPE = 'fox-fresh-app-projection-v1'
MAX_PROJECTION_BYTES = 4096
_FIELDS = frozenset(('schema_version', 'scope', 'installation_mode',
    'installation_id', 'storage_plan_sha256', 'storage_completion_sha256',
    'converter_endpoint'))
_SHA = re.compile(r'[a-f0-9]{64}\Z')
_INSTALLATION_ID = re.compile(r'fst-[a-f0-9]{32}\Z')
_ENDPOINT = re.compile(r'http://127\.0\.0\.1:([1-9][0-9]{0,4})\Z')


class FreshProjectionError(ValueError):
    """Bounded diagnostics; never echo supplied values or credentials."""


def _need(condition, code):
    if not condition:
        raise FreshProjectionError(code)


def _hash(value):
    return type(value) is str and _SHA.fullmatch(value) is not None


def _installation_id(value):
    return type(value) is str and _INSTALLATION_ID.fullmatch(value) is not None


def converter_port(endpoint):
    """Return an unprivileged port from the exact literal loopback origin.

    Validate the raw string instead of relying on URL-parser normalization.
    A trailing slash, escaped host, whitespace or userinfo is not an origin in
    this declaration. This check establishes no listener or service identity.
    """
    _need(type(endpoint) is str and len(endpoint) <= 22,
          'FRESH_CONVERTER_ENDPOINT_INVALID')
    match = _ENDPOINT.fullmatch(endpoint)
    _need(match is not None, 'FRESH_CONVERTER_ENDPOINT_INVALID')
    port = int(match[1])
    _need(1024 <= port <= 65535, 'FRESH_CONVERTER_ENDPOINT_INVALID')
    return port


def validate_projection(value):
    """Validate exact P fields and return a detached configuration document."""
    _need(type(value) is dict and set(value) == _FIELDS,
          'FRESH_PROJECTION_FIELDS_INVALID')
    _need(type(value['schema_version']) is int and value['schema_version'] == 1
          and type(value['scope']) is str and value['scope'] == PROJECTION_SCOPE
          and type(value['installation_mode']) is str and value['installation_mode'] == 'fresh',
          'FRESH_PROJECTION_MODE_INVALID')
    _need(_installation_id(value['installation_id']), 'FRESH_INSTALLATION_ID_INVALID')
    _need(_hash(value['storage_plan_sha256']) and _hash(value['storage_completion_sha256']),
          'FRESH_STORAGE_BINDING_INVALID')
    converter_port(value['converter_endpoint'])
    # Every accepted value is an immutable scalar. No caller-owned nested
    # structure or readiness/credential object is retained.
    return dict(value)


def projection_bytes(value):
    """Canonical P file bytes, including one terminal newline."""
    checked = validate_projection(value)
    return (json.dumps(checked, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')


def projection_sha256(value):
    return hashlib.sha256(projection_bytes(value)).hexdigest()


def _unique_pairs(items):
    value = {}
    for key, item in items:
        _need(key not in value, 'FRESH_PROJECTION_DUPLICATE_KEY')
        value[key] = item
    return value


def _invalid_constant(_value):
    raise FreshProjectionError('FRESH_PROJECTION_JSON_INVALID')


def parse_projection(raw, *, expected_sha256):
    """Parse already-read, explicitly hash-bound canonical P bytes.

    The caller owns file/path permissions and the independent expected hash.
    A matching hash only proves byte identity, never installation readiness.
    """
    _need(type(raw) is bytes and 0 < len(raw) <= MAX_PROJECTION_BYTES,
          'FRESH_PROJECTION_BYTES_INVALID')
    _need(_hash(expected_sha256) and hashlib.sha256(raw).hexdigest() == expected_sha256,
          'FRESH_PROJECTION_HASH_CHANGED')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_pairs,
                           parse_constant=_invalid_constant)
    except FreshProjectionError:
        raise
    except (ValueError, UnicodeError, RecursionError, TypeError):
        raise FreshProjectionError('FRESH_PROJECTION_JSON_INVALID') from None
    checked = validate_projection(value)
    _need(projection_bytes(checked) == raw, 'FRESH_PROJECTION_NOT_CANONICAL')
    return checked


def bind_projection(value, *, installation_id, storage_plan_sha256,
                    storage_completion_sha256):
    """Compare P with independently supplied S0 identity/hash values.

    This validates data correspondence, not the truth or authority of an S0
    receipt. The connected installer must perform that separate verification.
    """
    checked = validate_projection(value)
    _need(_installation_id(installation_id) and _hash(storage_plan_sha256)
          and _hash(storage_completion_sha256), 'FRESH_EXPECTED_STORAGE_BINDING_INVALID')
    _need(checked['installation_id'] == installation_id
          and checked['storage_plan_sha256'] == storage_plan_sha256
          and checked['storage_completion_sha256'] == storage_completion_sha256,
          'FRESH_PROJECTION_STORAGE_BINDING_CHANGED')
    return checked
