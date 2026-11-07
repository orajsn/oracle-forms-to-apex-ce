"""Bounded HTTP handoff of retained prototype authority to the converter.

This adapter receives an ALREADY configured ConverterClient, inheriting its
loopback endpoint/projection and bearer handling. It reads no credentials.
Only the exact reviewed-source authority closure under prototype-pipeline is
transferred, never original-upload directories, arbitrary paths or job files.
Source redaction/destination consent remains the owning project's obligation;
neither artifact staging nor a hash grants Oracle-write or model permission.

POST /fox/prototype/jobs/{job_id}/authority stages one immutable bundle. GET
on the same path reconciles staging without replay. Stage POST/GET endpoints
are /fox/prototype/jobs/{job_id}/stages/{stage}. A pending staging POST with no
confirmed GET result blocks; it is never retried automatically.

The local default renderer requires forms2apex.native_blueprint and its existing
native/native-project/template closure in the app-worker package. Transport does
not install/copy code or pretend a missing renderer is available.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
from pathlib import Path
import re
import zipfile

from .intake import SECRETS
from .native_pipeline import _json, _save_once
from .opaf import ConverterClient, OpafError, canonical_hash
from .prototype_pipeline import (CONVERTER_STAGES, _check_converter_receipt,
                                 authorize_prototype_request)

MAX_AUTHORITY_BYTES = 64 * 1024 * 1024
MAX_AUTHORITY_MEMBER_BYTES = 20_000_000
MAX_AUTHORITY_FILES = 2048
MAX_AUTHORITY_WIRE_BYTES = 96 * 1024 * 1024
_ROOT_FILES = ('binding.json', 'sources-manifest.json', 'packet.json', 'review-index.json',
               'merged-blueprint.json', 'native-plan.json', 'rendered.json', 'candidate-apexlang.zip')
_FOCUS_FILES = ('request.json', 'mapper.json', 'mapper-target.json', 'reviewer.json',
                'reviewer-target.json', 'review-receipt.json')
_FOCUS = re.compile(r'focus-[0-9a-f]{24}\Z')
_PRIVATE_KEY = re.compile(r'(?:password|passwd|pwd|api[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token|private[_-]?key)\Z', re.I)
_ABSOLUTE = re.compile(r'(?i)(?:\b[A-Z]:[\\/]|/(?:Users|home|root|opt|var|tmp)/)')


def _screen_text(raw):
    """Reuse intake's secret checks; reject credential keys/private paths too."""
    try:
        text = raw.decode('utf-8')
    except UnicodeError:
        raise OpafError('Prototype authority text is not valid UTF-8.') from None
    if any(re.search(pattern, text) for pattern in SECRETS) or _ABSOLUTE.search(text):
        raise OpafError('Prototype authority contains a suspected secret or private absolute path.')
    if text.lstrip().startswith(('{', '[')):
        def visit(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if _PRIVATE_KEY.fullmatch(key):
                        raise OpafError('Prototype authority contains a credential field.')
                    visit(item)
            elif isinstance(value, list):
                for item in value:
                    visit(item)
            elif isinstance(value, str) and (any(re.search(pattern, value) for pattern in SECRETS)
                                            or _ABSOLUTE.search(value)):
                raise OpafError('Prototype authority contains a suspected secret or private absolute path.')
        try:
            visit(json.loads(text))
        except (ValueError, RecursionError):
            raise OpafError('Prototype authority JSON is malformed or unbounded.') from None


def authority_manifest(bundle):
    """Canonical descriptor manifest: same envelope, no base64 or own digest."""
    return {key: value for key, value in bundle.items() if key not in ('files', 'manifest_sha256')} | {
        'files': [{key: row[key] for key in ('path', 'sha256', 'bytes')} for row in bundle['files']]}


def _screen_candidate(raw):
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = archive.infolist()
            if (len(members) > 512 or len({row.filename for row in members}) != len(members)
                    or sum(row.file_size for row in members) > 32 * 1024 * 1024):
                raise OpafError('Prototype candidate archive exceeds its structure bound.')
            for row in members:
                if (row.is_dir() or row.flag_bits & 1 or '\\' in row.filename or ':' in row.filename
                        or any(part in ('', '.', '..') for part in row.filename.split('/'))):
                    raise OpafError('Prototype candidate archive contains an unsafe path.')
                _screen_text(archive.read(row))
    except (ValueError, zipfile.BadZipFile, RuntimeError):
        raise OpafError('Prototype candidate archive is invalid or unsafe.') from None


def build_authority_bundle(job: Path, request: dict) -> dict:
    """Read-only export from a fresh, fully revalidated retained pipeline job."""
    job = Path(job)
    authorize_prototype_request(job, request)
    root = job / 'prototype-pipeline'
    source_manifest = _json(root / 'sources-manifest.json')
    review_index = _json(root / 'review-index.json')
    names = list(_ROOT_FILES)
    names.extend(f'sources/source-{index:03}.xml' for index in range(len(source_manifest['files'])))
    focuses = [row['focus_id'] for row in review_index['focuses']]
    if len(focuses) != len(set(focuses)) or any(not _FOCUS.fullmatch(focus) for focus in focuses):
        raise OpafError('Prototype authority focus index is invalid.')
    names.extend(f'{focus}/{name}' for focus in focuses for name in _FOCUS_FILES)
    for row in review_index['focuses']:
        if 'mapper-resolution_sha256' in row:
            names.extend(f'{row["focus_id"]}/{name}' for name in ('mapper-resolved.json', 'mapper-resolution.json'))
    if len(names) > MAX_AUTHORITY_FILES:
        raise OpafError('Prototype authority exceeds the file-count bound.')
    rows, total = [], 0
    for name in sorted(names):
        path = root.joinpath(*name.split('/'))
        if (path.is_symlink() or path.parent.is_symlink() or not path.is_file()
                or path.stat().st_size > MAX_AUTHORITY_MEMBER_BYTES):
            raise OpafError('Prototype authority member is missing, oversized or unsafe.')
        total += path.stat().st_size
        if total > MAX_AUTHORITY_BYTES:
            raise OpafError('Prototype authority exceeds the aggregate byte bound.')
        raw = path.read_bytes()
        if len(raw) != path.stat().st_size:
            raise OpafError('Prototype authority changed during export.')
        if name.endswith('.zip'):
            _screen_candidate(raw)
        else:
            _screen_text(raw)
        rows.append({'path': name, 'sha256': hashlib.sha256(raw).hexdigest(),
                     'bytes': len(raw), 'content_base64': base64.b64encode(raw).decode('ascii')})
    bundle = {'schema_version': 1, 'scope': 'fox-prototype-authority-bundle-v1',
              'job_id': job.name, 'source_binding': request['source_binding'],
              'source_authority': request['source_authority'], 'files': rows}
    bundle['manifest_sha256'] = canonical_hash(authority_manifest(bundle))
    if len(json.dumps(bundle, ensure_ascii=False, allow_nan=False).encode('utf-8')) > MAX_AUTHORITY_WIRE_BYTES:
        raise OpafError('Prototype authority exceeds the wire-size bound.')
    # Close a source/artifact change between the initial validation and reads.
    authorize_prototype_request(job, request)
    return bundle


def _staging_receipt(bundle, value):
    expected = {'schema_version': 1, 'scope': 'fox-prototype-authority-staging-receipt-v1',
                'job_id': bundle['job_id'], 'source_binding': bundle['source_binding'],
                'source_authority': bundle['source_authority'], 'manifest_sha256': bundle['manifest_sha256'],
                'staged': True, 'source_review_authorized': False}
    if not isinstance(value, dict) or any(value.get(key) != item for key, item in expected.items()):
        raise OpafError('Converter authority staging receipt is missing or unbound.')
    # Staging is transport, never inferred reviewer or business approval.
    if value.get('staged') is not True or value.get('source_review_authorized') is not False:
        raise OpafError('Converter authority staging cannot assert source-review authorization.')
    return value


class PrototypeHttpConverterAdapter:
    """Concrete ConverterClient transport; no new endpoint/token configuration."""

    def __init__(self, job: Path, converter_client: ConverterClient):
        if not isinstance(converter_client, ConverterClient):
            raise OpafError('Prototype HTTP adapter requires the guarded ConverterClient.')
        self.job, self.client = Path(job), converter_client
        if not re.fullmatch(r'fox-[0-9a-f]{20}', self.job.name):
            raise OpafError('Invalid prototype transport job identity.')
        self.path = '/fox/prototype/jobs/' + self.job.name

    def supports(self, stage):
        if stage in CONVERTER_STAGES[:3]:
            return True
        if stage not in CONVERTER_STAGES:
            return False
        # Negotiate actual runtime/export adapters before recording a stage
        # intent. A healthy HTTP service does not imply a browser is configured.
        value = self._get('/fox/prototype/capabilities')
        if value is None:
            return False
        if (not isinstance(value, dict) or set(value) != {'schema_version', 'scope', 'stages'}
                or type(value['schema_version']) is not int or value['schema_version'] != 1
                or value['scope'] != 'fox-prototype-capabilities-v1'
                or not isinstance(value['stages'], list)
                or any(not isinstance(item, str) or item not in CONVERTER_STAGES for item in value['stages'])
                or len(set(value['stages'])) != len(value['stages'])):
            raise OpafError('Prototype converter capabilities could not be verified.')
        return stage in value['stages']

    def _get(self, path):
        try:
            return self.client.request('GET', path)
        except OpafError as error:
            if error.status_code == 404:
                return None
            raise

    def _stage_authority(self, request):
        bundle = build_authority_bundle(self.job, request)
        root = self.job / 'prototype-transport'
        if root.is_symlink():
            raise OpafError('Unsafe prototype transport checkpoint directory.')
        root.mkdir(exist_ok=True)
        intent, complete = root / 'authority-intent.json', root / 'authority.json'
        binding = {'job_id': self.job.name, 'source_binding': request['source_binding'],
                   'source_authority': request['source_authority'], 'manifest_sha256': bundle['manifest_sha256']}
        if (intent.exists() or intent.is_symlink()) and _json(intent) != binding:
            raise OpafError('Prototype authority staging intent changed; no replay.')
        if complete.exists() or complete.is_symlink():
            _staging_receipt(bundle, _json(complete))
        value = self._get(self.path + '/authority')
        if value is not None:
            receipt = _staging_receipt(bundle, value)
            _save_once(complete, receipt)
            return receipt
        if intent.exists() or complete.exists():
            raise OpafError('Prototype authority staging is uncertain; reconcile with GET, without replay.')
        _save_once(intent, binding)
        try:
            receipt = _staging_receipt(bundle, self.client.request('POST', self.path + '/authority', bundle))
            _save_once(complete, receipt)
            return receipt
        except Exception:
            raise OpafError('Prototype authority staging result is uncertain; reconcile with GET, without replay.') from None

    def run_stage(self, stage, request):
        if not self.supports(stage):
            raise OpafError('Prototype converter stage is not implemented by this adapter.')
        self._stage_authority(request)
        try:
            value = self.client.request('POST', self.path + '/stages/' + stage, request)
            return _check_converter_receipt(stage, request, value)
        except Exception:
            raise OpafError('Prototype converter stage result is unconfirmed; reconcile with GET, without replay.') from None

    def recover_stage(self, stage, request):
        """GET-only recovery: no staging POST and no local checkpoint writes."""
        if not self.supports(stage):
            return None
        authorize_prototype_request(self.job, request)
        value = self._get(self.path + '/stages/' + stage)
        if value is None:
            return None
        return _check_converter_receipt(stage, request, value)

    def read_package(self, request, export_receipt):
        """Fixed-path, bounded GET only; no staging, recovery POST or retry."""
        from .prototype_download import validate_generated_package
        if request.get('job_id') != self.job.name:
            raise OpafError('Prototype download job differs from the retained request.')
        authorize_prototype_request(self.job, request)
        raw = self.client.request('GET', self.path + '/package', binary=True)
        validate_generated_package(raw, request=request, export_receipt=export_receipt)
        authorize_prototype_request(self.job, request)
        return raw
