"""Bounded public manifest for selecting locally prepared readable sources.

This contract proves only that the selected names, byte counts and digests match
the declaration. It is not evidence of Oracle tooling, redaction, completeness
or permission to submit source to a model. Callers must pass checked_source
results computed from the original uploaded bytes, not user-supplied metadata.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath

from .intake import ALLOWED, MAX_FILE_BYTES, MAX_PROJECT_BYTES


UPLOAD_MANIFEST_NAME = 'fox-readable-upload.json'
MAX_MANIFEST_BYTES = 32_768
_TOP_FIELDS = {'format', 'schema_version', 'extraction_job_id',
               'readable_source_hash', 'files'}
_FILE_FIELDS = {'name', 'sha256', 'bytes'}
_FORMAT = 'FOX-READABLE-UPLOAD'
_ERROR = 'Invalid prepared-source manifest or selected files.'
_RESERVED = {'CON', 'PRN', 'AUX', 'NUL',
             *(f'COM{i}' for i in range(1, 10)),
             *(f'LPT{i}' for i in range(1, 10))}


class PreparedSourceError(ValueError):
    """Safe diagnostic: never include source content or private paths."""


def _reject() -> None:
    raise PreparedSourceError(_ERROR)


def _job_id(value: object) -> str:
    if type(value) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}', value):
        _reject()
    return value


def _sha256(value: object) -> str:
    if type(value) is not str or not re.fullmatch(r'[a-f0-9]{64}', value):
        _reject()
    return value


def _name(value: object) -> str:
    # Mirror extractor.safe_name without importing extractor: preparation uses
    # this module to publish its manifest, so that import would be circular.
    if (type(value) is not str
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_. -]{0,119}', value)
            or '..' in value or value.endswith((' ', '.'))
            or value.split('.')[0].upper() in _RESERVED
            or value.casefold() == UPLOAD_MANIFEST_NAME.casefold()
            or PurePosixPath(value).suffix.lower() not in ALLOWED):
        _reject()
    return value


def _files(value: object, *, declared: bool) -> list[dict]:
    if type(value) is not list or not 1 <= len(value) <= 50:
        _reject()
    result, names, total = [], set(), 0
    for entry in value:
        if (type(entry) is not dict or not _FILE_FIELDS.issubset(entry)
                or (declared and set(entry) != _FILE_FIELDS)):
            _reject()
        name = _name(entry['name'])
        digest = _sha256(entry['sha256'])
        size = entry['bytes']
        if (type(size) is not int or not 1 <= size <= MAX_FILE_BYTES
                or name.casefold() in names):
            _reject()
        names.add(name.casefold())
        total += size
        if total > MAX_PROJECT_BYTES:
            _reject()
        # Whitelist only public metadata. Never retain text, local paths,
        # backend details or caller-supplied approval information.
        result.append({'name': name, 'sha256': digest, 'bytes': size})
    return sorted(result, key=lambda item: item['name'])


def _combined_hash(files: list[dict]) -> str:
    # Same exact-name sorting and formula as intake.inventory.
    manifest = '\n'.join(item['name'] + ':' + item['sha256'] for item in files)
    return hashlib.sha256(manifest.encode('utf-8')).hexdigest()


def _manifest(value: object) -> dict:
    if (type(value) is not dict or set(value) != _TOP_FIELDS
            or type(value['format']) is not str or value['format'] != _FORMAT
            or type(value['schema_version']) is not int or value['schema_version'] != 1):
        _reject()
    job_id = _job_id(value['extraction_job_id'])
    files = _files(value['files'], declared=True)
    digest = _sha256(value['readable_source_hash'])
    if digest != _combined_hash(files):
        _reject()
    return {'format': _FORMAT, 'schema_version': 1,
            'extraction_job_id': job_id, 'readable_source_hash': digest,
            'files': files}


def _canonical(value: dict) -> bytes:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True,
                     separators=(',', ':'), allow_nan=False).encode('utf-8')
    if len(raw) > MAX_MANIFEST_BYTES:
        _reject()
    return raw


def make_upload_manifest(extraction_job_id: str, files: list[dict]) -> dict:
    """Build public metadata from upstream checked_source results only."""
    job_id = _job_id(extraction_job_id)
    selected = _files(files, declared=False)
    result = {'format': _FORMAT, 'schema_version': 1,
              'extraction_job_id': job_id,
              'readable_source_hash': _combined_hash(selected), 'files': selected}
    _canonical(result)
    return result


def _object(pairs: list[tuple]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            _reject()
        result[key] = value
    return result


def _nonfinite(_: str) -> None:
    _reject()


def _bounded_depth(text: str) -> None:
    """Reject nested containers before the JSON parser can recurse deeply."""
    depth, in_string, escaped = 0, False, False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in '[{':
            depth += 1
            # The permitted shape is object -> files array -> file object.
            if depth > 3:
                _reject()
        elif char in ']}':
            depth -= 1
            if depth < 0:
                _reject()


def parse_upload_manifest(raw: bytes) -> dict:
    """Parse exact public fields, verify the declared hash and normalize order."""
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_MANIFEST_BYTES:
        _reject()
    try:
        text = raw.decode('utf-8', errors='strict')
        _bounded_depth(text)
        value = json.loads(text, object_pairs_hook=_object, parse_constant=_nonfinite)
        return _manifest(value)
    except (ValueError, TypeError, RecursionError, OverflowError):
        raise PreparedSourceError(_ERROR) from None


def verify_upload_manifest(raw: bytes, files: list[dict]) -> dict:
    """Match the exact selected set against original-byte checked metadata."""
    manifest = parse_upload_manifest(raw)
    if manifest['files'] != _files(files, declared=False):
        _reject()
    return manifest


def encode_upload_manifest(value: dict) -> bytes:
    """Canonical JSON: exact-name file order, sorted keys, no whitespace/BOM."""
    return _canonical(_manifest(value))
