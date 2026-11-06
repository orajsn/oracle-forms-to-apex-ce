"""Private host-only FMB preparation: paired native XML, derivation, redaction.

This is not extractor.prepare's ordinary upload path. Masked business DML is
checked by the existing prototype-source gate after conservative redaction.
No queue, network, model, database, DDL inference or acceptance is performed.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import uuid

from defusedxml import ElementTree as ET

from .extractor import MAX_RAW_BYTES, NS, _output_name, digest, safe_name
from .forms_effective_view import derive_effective_view
from .forms_redaction import redact_forms_xml
from .linux_forms import LinuxOracleFormsBackend, MAX_READABLE_BYTES, _path, _read_bounded
from .prototype_source import validate_redacted_prototype_source

STATUS = 'PREPARED_REDACTED_REVIEW_REQUIRED'
SCOPE = 'fox-host-native-preparation-v1'
MAX_RECEIPT_BYTES = 24 * 1024 * 1024


class NativePreparationError(ValueError):
    """Safe host diagnostic; never contains native output, code or source values."""


def _json(value) -> bytes:
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                     allow_nan=False).encode('utf-8')
    if len(raw) > MAX_RECEIPT_BYTES:
        raise NativePreparationError('Preparation metadata exceeds its bounded limit.')
    return raw


def _write(path: Path, raw: bytes) -> None:
    _path(path)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
        stream.write(raw)


def prepare_native_source(source: Path, output_root: Path, *, oracle_home=None,
                          java_home=None, backend_factory=None, job_id: str | None = None) -> Path:
    """Return a fresh private job only after actual paired-backend calls and gates.

    FMB-only in this bounded slice; no other selected file is silently ignored.
    Trusted startup may inject factory(mode)->backend for an installed launcher
    or labelled tests. Otherwise explicit homes construct the real Linux backend.
    An injected backend is not an Oracle attestation. Callers must not expose raw
    job directories or treat a redaction receipt as transfer/import permission.
    """
    try:
        source, output_root = _path(source), _path(output_root)
        safe_name(source.name)
        if source.suffix.lower() != '.fmb':
            raise NativePreparationError('Native redacted preparation currently supports one FMB file only; other formats require a separate supported path.')
        if (output_root == source.parent or output_root.is_relative_to(source.parent)
                or source.parent.is_relative_to(output_root)):
            raise NativePreparationError('Original source and preparation output must use separate non-nested directories.')
        original = _read_bounded(source, MAX_RAW_BYTES)
        binary_hash = digest(original)
        xml_name = _output_name(source.name)
        job_id = 'native-prep-' + uuid.uuid4().hex if job_id is None else job_id
        if not isinstance(job_id, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}', job_id):
            raise NativePreparationError('Use a bounded preparation job identifier without paths.')
        if backend_factory is None:
            if oracle_home is None or java_home is None:
                raise NativePreparationError('Configure explicit Oracle and Java homes for native preparation.')
            oracle_home, java_home = _path(oracle_home), _path(java_home)

            def backend_factory(mode):
                return LinuxOracleFormsBackend(oracle_home, java_home, dump_mode=mode)
        elif not callable(backend_factory):
            raise NativePreparationError('Configure a trusted native backend factory.')
        output_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        job = output_root / job_id
        job.mkdir(mode=0o700, exist_ok=False)
    except NativePreparationError:
        raise
    except Exception:
        raise NativePreparationError('Native preparation prerequisites are unavailable; no job was released.') from None

    files, tool_runs = [], []
    stage = 'PRESERVE_ORIGINAL'

    def save(relative, raw, role):
        target = job / relative
        _write(target, raw)
        if digest(_read_bounded(target, max(MAX_RAW_BYTES, MAX_RECEIPT_BYTES))) != digest(raw):
            raise NativePreparationError('Private preparation artifact identity changed.')
        record = {'role': role, 'path': relative, 'sha256': digest(raw), 'bytes': len(raw)}
        files.append(record)
        return record

    def original_unchanged():
        if digest(_read_bounded(source, MAX_RAW_BYTES)) != binary_hash:
            raise NativePreparationError('Original FMB changed during preparation; no output was released.')

    try:
        for folder in ('original', 'native', 'native/overridden', 'native/all', 'effective', 'redacted'):
            (job / folder).mkdir(mode=0o700)
        save('original/' + source.name, original, 'original_binary')
        paired = {}
        for mode in ('OVERRIDDEN', 'ALL'):
            stage = 'NATIVE_' + mode
            original_unchanged()
            backend = backend_factory(mode)
            name = getattr(backend, 'name', None)
            if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,79}', name)
                    or getattr(backend, 'dump_mode', None) != mode):
                raise NativePreparationError('Native backend does not declare the requested bounded dump mode.')
            destination = job / 'native' / mode.lower()
            result = backend.extract(source, destination)
            expected = destination / xml_name
            if Path(result) != expected or getattr(backend, 'dump_mode', None) != mode:
                raise NativePreparationError('Native backend returned an unexpected artifact or dump mode.')
            raw = _read_bounded(result, MAX_READABLE_BYTES)
            root = ET.fromstring(raw)
            if root.tag != NS + 'Module' or len(root) != 1 or root[0].tag != NS + 'FormModule':
                raise NativePreparationError('Native FMB output is not the expected Forms module.')
            if list(destination.iterdir()) != [expected]:
                raise NativePreparationError('Native backend produced additional artifacts; no prepared output was released.')
            original_unchanged()
            paired[mode] = raw
            output_hash = digest(raw)
            relative = expected.relative_to(job).as_posix()
            files.append({'role': 'native_' + mode.lower(), 'path': relative,
                          'sha256': output_hash, 'bytes': len(raw)})
            tool_runs.append({'dump_mode': mode, 'backend': name,
                              'input_sha256': binary_hash, 'output_sha256': output_hash,
                              'original_unchanged': True})

        stage = 'DERIVE_EFFECTIVE_VIEW'
        effective = derive_effective_view(xml_name, paired['OVERRIDDEN'], paired['ALL'], binary_sha256=binary_hash)
        derived, derivation = effective['derived_xml'], effective['receipt']
        if (derivation['binary_sha256'] != binary_hash
                or derivation['original_sha256'] != digest(paired['OVERRIDDEN'])
                or derivation['all_sha256'] != digest(paired['ALL'])
                or derivation['derived_sha256'] != digest(derived)):
            raise NativePreparationError('Effective-view provenance does not match the exact native pair.')
        save('effective/' + xml_name, derived, 'effective_xml')
        save('effective/derivation-receipt.json', _json(derivation), 'derivation_receipt')

        stage = 'REDACT_AND_VALIDATE'
        redacted = redact_forms_xml(xml_name, derived)
        masked, receipt = redacted['redacted_xml'], redacted['receipt']
        if receipt['original_sha256'] != digest(derived):
            raise NativePreparationError('Redaction provenance does not match the exact effective XML.')
        checked = validate_redacted_prototype_source(xml_name, masked, receipt)
        if (checked['name'] != xml_name or checked['sha256'] != digest(masked)
                or checked['bytes'] != len(masked)):
            raise NativePreparationError('Redacted source validation returned a different source identity.')
        original_unchanged()
        save('redacted/' + xml_name, masked, 'redacted_xml')
        save('redacted/redaction-receipt.json', _json(receipt), 'redaction_receipt')

        stage = 'SEAL_MANIFEST'
        # Recheck every retained artifact before emitting the body-free manifest.
        for record in files:
            raw = _read_bounded(job / record['path'], max(MAX_RAW_BYTES, MAX_RECEIPT_BYTES))
            if len(raw) != record['bytes'] or digest(raw) != record['sha256']:
                raise NativePreparationError('Private preparation evidence changed before sealing.')
        original_unchanged()
        manifest = {
            'schema_version': 1, 'scope': SCOPE, 'job_id': job_id, 'status': STATUS,
            'source': {'name': source.name, 'sha256': binary_hash, 'bytes': len(original)},
            'tool_runs': tool_runs, 'files': files,
            'redacted_source': {**{key: checked[key] for key in ('name', 'sha256', 'bytes')},
                                'xml_path': 'redacted/' + xml_name,
                                'receipt_path': 'redacted/redaction-receipt.json'},
            'safety': {'original_unchanged': True, 'raw_sources_local_only': True,
                       'code_executed': False, 'network_calls': False, 'model_calls': False,
                       'model_submission_allowed': False, 'database_calls': False,
                       'import_allowed': False, 'native_generation_allowed': False,
                       'business_accepted': False, 'oracle_provenance_attested': False},
            'limitations': ['FMB-only preparation; related libraries and other module types are not converted here.',
                            'No DDL was supplied or verified; missing schema and business behavior remain unknown.',
                            'Masked code is analysis-only; retained technical names still require review.',
                            'Preparation and receipts do not authorize transfer, generation, import or business acceptance.'],
        }
        _write(job / 'manifest.json', _json(manifest))
        _write(job / 'status.json', _json({'schema_version': 1, 'scope': SCOPE, 'job_id': job_id,
                                         'status': STATUS, 'stage': 'COMPLETE'}))
        return job
    except Exception:
        # Retain original/native/effective evidence, but never relay tool output,
        # customer code, absolute paths or arbitrary exception details.
        try:
            _write(job / 'status.json', _json({'schema_version': 1, 'scope': SCOPE, 'job_id': job_id,
                                             'status': 'BLOCKED', 'stage': stage,
                                             'code': 'NATIVE_PREPARATION_FAILED'}))
        except (OSError, ValueError):
            pass
        raise NativePreparationError('Native preparation failed; private job evidence is retained and no approved output was released.') from None
