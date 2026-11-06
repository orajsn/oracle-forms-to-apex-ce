"""Private, bounded FMB queue; no daemon, remote authority or automatic replay.

The root is a trusted operator-configured private local directory, never supplied
by an HTTP caller. Filesystem access to it is an authority boundary. POSIX modes
do not configure Windows ACLs. A trusted on-demand host processor injects native
preparation; submission and status never invoke it. Results remain analysis-only.
"""
from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

from .extractor import MAX_RAW_BYTES, _output_name, assert_local_path, digest, safe_name
from .prototype_source import validate_redacted_prototype_source

SCOPE = 'fox-hosted-forms-job-v1'
PREPARED = 'PREPARED_REDACTED_REVIEW_REQUIRED'
MAX_METADATA_BYTES = 24 * 1024 * 1024
MAX_XML_BYTES = 5 * 1024 * 1024


class HostedFormsJobError(ValueError):
    """Body-free, path-free diagnostic suitable for an HTTP boundary."""


class HostedFormsJobConflict(HostedFormsJobError):
    """An existing request cannot be reused with different inputs."""


def _fail():
    raise HostedFormsJobError('Private extraction job is unavailable or failed identity validation.') from None


def _id(value):
    if type(value) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}', value):
        _fail()
    # IDs become directories, including on Windows developer machines.
    try:
        safe_name(value)
    except ValueError:
        _fail()
    return value


def _sha(value):
    if type(value) is not str or not re.fullmatch(r'[a-f0-9]{64}', value):
        _fail()
    return value


def _owner(value):
    if type(value) is not str or not 1 <= len(value) <= 256 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        _fail()
    return value


def _path(value):
    try:
        path = Path(value)
        if not path.is_absolute() or '..' in path.parts or any(c in str(path) for c in ('\x00', '\r', '\n')):
            _fail()
        if ':' in str(path)[2:] or (os.name != 'nt' and ':' in str(path)):
            _fail()
        return assert_local_path(path)
    except (OSError, ValueError, TypeError):
        _fail()


def _json(value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                     allow_nan=False).encode('utf-8')
    if len(raw) > MAX_METADATA_BYTES:
        _fail()
    return raw


def _write(path, raw):
    path = _path(path)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                           getattr(os, 'O_NOFOLLOW', 0), 0o600), 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _read(path, limit):
    path = _path(path)
    try:
        with os.fdopen(os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)), 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= limit:
                _fail()
            raw = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            if (len(raw) != info.st_size or len(raw) > limit
                    or any(getattr(after, key) != getattr(info, key)
                           for key in ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))):
                _fail()
            return raw
    except (OSError, ValueError):
        _fail()


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail()
        result[key] = value
    return result


def _decode(raw):
    try:
        return json.loads(raw, object_pairs_hook=_object, parse_constant=lambda _: _fail())
    except (ValueError, TypeError, RecursionError, UnicodeError):
        _fail()


def _load(path):
    return _decode(_read(path, MAX_METADATA_BYTES))


def _relative(root, value):
    if type(value) is not str or '\\' in value:
        _fail()
    relative = PurePosixPath(value)
    if relative.is_absolute() or not relative.parts or relative.as_posix() != value:
        _fail()
    for part in relative.parts:
        safe_name(part)
    target = _path(root / value)
    if not target.is_relative_to(root):
        _fail()
    return target


class HostedFormsJobs:
    """Explicit private root, immutable submissions, at-most-once host claims."""

    def __init__(self, root: Path, *, max_raw_bytes: int = MAX_RAW_BYTES,
                 max_pending: int = 5, max_retained_raw_bytes: int = 200 * 1024 * 1024):
        self.root = _path(root)
        if type(max_raw_bytes) is not int or not 1 <= max_raw_bytes <= MAX_RAW_BYTES:
            _fail()
        self.max_raw_bytes = max_raw_bytes
        if (type(max_pending) is not int or not 1 <= max_pending <= 100
                or type(max_retained_raw_bytes) is not int
                or not 1 <= max_retained_raw_bytes <= 2 * 1024 * 1024 * 1024):
            _fail()
        self.max_pending = max_pending
        self.max_retained_raw_bytes = max_retained_raw_bytes

    def _job(self, job_id):
        return _path(self.root / _id(job_id))

    def _input(self, job_id):
        job = self._job(job_id)
        raw = _read(job / 'input-manifest.json', MAX_METADATA_BYTES)
        marker = _load(job / 'ready.json')
        manifest = _decode(raw)
        try:
            if (set(manifest) != {'schema_version', 'scope', 'job_id', 'request_id', 'project_id',
                                 'owner_id', 'source_set_sha256', 'selected_source_set_id', 'source'}
                    or type(manifest['schema_version']) is not int or manifest['schema_version'] != 1
                    or manifest['scope'] != SCOPE or manifest['job_id'] != job_id
                    or manifest['request_id'] != job_id
                    or marker != {'job_id': job_id, 'input_manifest_sha256': digest(raw)}):
                _fail()
            _id(manifest['project_id'])
            _owner(manifest['owner_id'])
            _sha(manifest['source_set_sha256'])
            if manifest['selected_source_set_id'] is not None:
                _id(manifest['selected_source_set_id'])
            source = manifest['source']
            if set(source) != {'name', 'sha256', 'bytes'}:
                _fail()
            safe_name(source['name'])
            _output_name(source['name'])
            if Path(source['name']).suffix.lower() != '.fmb':
                _fail()
            _sha(source['sha256'])
            if type(source['bytes']) is not int or not 1 <= source['bytes'] <= self.max_raw_bytes:
                _fail()
            original = _read(job / 'input' / source['name'], self.max_raw_bytes)
            if len(original) != source['bytes'] or digest(original) != source['sha256']:
                _fail()
            return job, manifest, digest(raw)
        except (KeyError, TypeError, ValueError, OSError):
            _fail()

    def submit(self, *, request_id: str, project_id: str, owner_id: str,
               source_set_sha256: str, name: str, raw: bytes,
               selected_source_set_id: str | None = None) -> dict:
        """Idempotent only for exactly the same binding, filename and bytes.

        The caller obtains owner/project/source-set from trusted current project
        state. A browser-supplied binding is not authorization. Incomplete writes
        retain their request ID and cannot be automatically resubmitted.
        """
        try:
            job_id, project_id, owner_id = _id(request_id), _id(project_id), _owner(owner_id)
            safe_name(name)
            _output_name(name)
            if Path(name).suffix.lower() != '.fmb' or type(raw) is not bytes or not 1 <= len(raw) <= self.max_raw_bytes:
                _fail()
            manifest = {'schema_version': 1, 'scope': SCOPE, 'job_id': job_id, 'request_id': request_id,
                        'project_id': project_id, 'owner_id': owner_id,
                        'source_set_sha256': _sha(source_set_sha256),
                        'selected_source_set_id': None if selected_source_set_id is None else _id(selected_source_set_id),
                        'source': {'name': name, 'sha256': digest(raw), 'bytes': len(raw)}}
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            job = self._job(job_id)
            if job.exists():
                try:
                    _, existing, _ = self._input(job_id)
                    if existing != manifest or _read(job / 'input' / name, self.max_raw_bytes) != raw:
                        raise HostedFormsJobConflict('Request identifier already belongs to different or incomplete extraction inputs.')
                except HostedFormsJobError:
                    raise HostedFormsJobConflict('Request identifier already belongs to different or incomplete extraction inputs.') from None
                return self.status(job_id, project_id=project_id, owner_id=owner_id)
            # Exclusive short submission lock makes global quota checks atomic.
            # A lost lock is retained and requires operator reconciliation.
            lock = _path(self.root / '.submission-lock')
            try:
                _write(lock, b'LOCK')
            except FileExistsError:
                raise HostedFormsJobConflict('Private extraction submission is busy; reconcile retained requests before retrying.') from None
            try:
                jobs = self._entries()
                pending, retained = 0, 0
                for existing_id in jobs:
                    _, existing, _ = self._input(existing_id)
                    retained += existing['source']['bytes']
                    current = self.status(existing_id, project_id=existing['project_id'], owner_id=existing['owner_id'])
                    pending += current['status'] in {'QUEUED', 'PROCESSING_UNKNOWN'}
                if pending >= self.max_pending or retained + len(raw) > self.max_retained_raw_bytes:
                    raise HostedFormsJobConflict('Private extraction queue capacity reached; no source was accepted.')
                job.mkdir(mode=0o700)
                (job / 'input').mkdir(mode=0o700)
                _write(job / 'input' / name, raw)
                encoded = _json(manifest)
                _write(job / 'input-manifest.json', encoded)
                _write(job / 'ready.json', _json({'job_id': job_id, 'input_manifest_sha256': digest(encoded)}))
            finally:
                lock.unlink()
            return self.status(job_id, project_id=project_id, owner_id=owner_id)
        except HostedFormsJobError:
            raise
        except Exception:
            _fail()

    def _authorized(self, job_id, project_id, owner_id, source_set_sha256=None,
                    selected_source_set_id=None):
        job, manifest, identity = self._input(job_id)
        if (manifest['project_id'] != _id(project_id) or manifest['owner_id'] != _owner(owner_id)
                or source_set_sha256 is not None and manifest['source_set_sha256'] != _sha(source_set_sha256)):
            _fail()
        if source_set_sha256 is not None and manifest['selected_source_set_id'] != selected_source_set_id:
            _fail()
        return job, manifest, identity

    def status(self, job_id: str, *, project_id: str, owner_id: str) -> dict:
        """Body-free status; claimed without sealed outcome is deliberately unknown."""
        job, manifest, _ = self._authorized(job_id, project_id, owner_id)
        state = 'QUEUED'
        if _path(job / 'claim.json').exists():
            # Exclusive file creation is the claim, not a successful JSON write.
            # A process can die between create/write/fsync; never replay that ID.
            state = 'PROCESSING_UNKNOWN'
            try:
                if _path(job / 'failure.json').exists():
                    if _load(job / 'failure.json') == {'job_id': job_id, 'code': 'NATIVE_PREPARATION_FAILED'}:
                        state = 'BLOCKED'
                elif _path(job / 'result.json').exists():
                    # A partial seal or corrupt artifact is not a ready result.
                    self._result(job_id)
                    state = PREPARED
            except HostedFormsJobError:
                pass
        return {'job_id': job_id, 'status': state, 'model_submission_allowed': False,
                'business_accepted': False, 'name': manifest['source']['name'],
                'source': dict(manifest['source']), 'source_set_sha256': manifest['source_set_sha256'],
                'selected_source_set_id': manifest['selected_source_set_id']}

    def _entries(self):
        if not _path(self.root).exists():
            return []
        result = []
        try:
            with os.scandir(self.root) as entries:
                for entry in entries:
                    if entry.name == '.submission-lock':
                        continue
                    _id(entry.name)
                    if not _path(Path(entry.path)).is_dir() or len(result) >= 1000:
                        _fail()
                    result.append(entry.name)
        except OSError:
            _fail()
        return sorted(result)

    def list_jobs(self, *, project_id: str, owner_id: str, limit: int = 50) -> list[dict]:
        """Bounded safe project projection for refresh/recovery, not a file listing."""
        _id(project_id)
        _owner(owner_id)
        if type(limit) is not int or not 1 <= limit <= 100:
            _fail()
        result = []
        for job_id in self._entries():
            _, manifest, _ = self._input(job_id)
            if manifest['project_id'] == project_id and manifest['owner_id'] == owner_id:
                result.append(self.status(job_id, project_id=project_id, owner_id=owner_id))
                if len(result) >= limit:
                    break
        return result

    def list_pending(self, *, limit: int = 5) -> list[str]:
        """Trusted host discovery only; never returns claimed/uncertain jobs."""
        if type(limit) is not int or not 1 <= limit <= 100:
            _fail()
        result = []
        for job_id in self._entries():
            job, _, _ = self._input(job_id)
            if not _path(job / 'claim.json').exists():
                result.append(job_id)
                if len(result) >= limit:
                    break
        return result

    def _result(self, job_id):
        job, manifest, identity = self._input(job_id)
        marker = _load(job / 'result.json')
        prepared = _path(job / 'prepared' / job_id)
        try:
            if (set(marker) != {'job_id', 'input_manifest_sha256', 'prepared_manifest_sha256'}
                    or marker['job_id'] != job_id or marker['input_manifest_sha256'] != identity):
                _fail()
            if digest(_read(prepared / 'manifest.json', MAX_METADATA_BYTES)) != marker['prepared_manifest_sha256']:
                _fail()
            return self._validate_prepared(prepared, manifest)
        except (KeyError, TypeError, ValueError, OSError):
            _fail()

    def _validate_prepared(self, prepared, manifest):
        result = _load(prepared / 'manifest.json')
        try:
            if (type(result['schema_version']) is not int or result['schema_version'] != 1
                    or result['scope'] != 'fox-host-native-preparation-v1'
                    or result['job_id'] != manifest['job_id'] or result['status'] != PREPARED
                    or result['source'] != manifest['source']):
                _fail()
            files = result['files']
            if type(files) is not list or not 1 <= len(files) <= 16:
                _fail()
            by_role, paths = {}, set()
            for record in files:
                if (set(record) != {'role', 'path', 'sha256', 'bytes'}
                        or type(record['role']) is not str or record['role'] in by_role
                        or record['path'] in paths or type(record['bytes']) is not int):
                    _fail()
                _sha(record['sha256'])
                content = _read(_relative(prepared, record['path']), MAX_METADATA_BYTES)
                if len(content) != record['bytes'] or digest(content) != record['sha256']:
                    _fail()
                by_role[record['role']] = record
                paths.add(record['path'])
            if set(by_role) != {'original_binary', 'native_overridden', 'native_all',
                                'effective_xml', 'derivation_receipt', 'redacted_xml', 'redaction_receipt'}:
                _fail()
            if (by_role['original_binary']['sha256'] != manifest['source']['sha256']
                    or by_role['original_binary']['bytes'] != manifest['source']['bytes']):
                _fail()
            source = result['redacted_source']
            if set(source) != {'name', 'sha256', 'bytes', 'xml_path', 'receipt_path'}:
                _fail()
            if source['name'] != _output_name(manifest['source']['name']):
                _fail()
            xml_record, receipt_record = by_role['redacted_xml'], by_role['redaction_receipt']
            if (xml_record['path'] != source['xml_path'] or receipt_record['path'] != source['receipt_path']
                    or xml_record['sha256'] != source['sha256'] or xml_record['bytes'] != source['bytes']):
                _fail()
            raw = _read(_relative(prepared, source['xml_path']), MAX_XML_BYTES)
            receipt = _load(_relative(prepared, source['receipt_path']))
            if receipt['original_sha256'] != by_role['effective_xml']['sha256']:
                _fail()
            derivation = _load(_relative(prepared, by_role['derivation_receipt']['path']))
            if (derivation['binary_sha256'] != manifest['source']['sha256']
                    or derivation['original_sha256'] != by_role['native_overridden']['sha256']
                    or derivation['all_sha256'] != by_role['native_all']['sha256']
                    or derivation['derived_sha256'] != by_role['effective_xml']['sha256']):
                _fail()
            checked = validate_redacted_prototype_source(source['name'], raw, receipt)
            return {'document': checked, 'receipt': receipt}
        except (KeyError, TypeError, ValueError, OSError):
            _fail()

    def process(self, job_id: str, *, prepare) -> dict:
        """Trusted host entry point. Claim once; never resume even after failure.

        `prepare(source_path, output_root, job_id=job_id)` must be a trusted closure
        over prepare_native_source and operator-approved Oracle/Java configuration.
        Exceptions are suppressed; private native errors never become status.
        """
        job, manifest, identity = self._input(job_id)
        if not callable(prepare):
            _fail()
        try:
            _write(job / 'claim.json', _json({'job_id': job_id, 'input_manifest_sha256': identity}))
        except FileExistsError:
            return self.status(job_id, project_id=manifest['project_id'], owner_id=manifest['owner_id'])
        except OSError:
            _fail()
        try:
            output_root = _path(job / 'prepared')
            expected = output_root / job_id
            actual = prepare(job / 'input' / manifest['source']['name'], output_root, job_id=job_id)
            if _path(actual) != expected:
                _fail()
            self._input(job_id)  # Native preparation must not mutate queue inputs.
            self._validate_prepared(expected, manifest)
            marker = {'job_id': job_id, 'input_manifest_sha256': identity,
                      'prepared_manifest_sha256': digest(_read(expected / 'manifest.json', MAX_METADATA_BYTES))}
            _write(job / 'result.json', _json(marker))
        except Exception:
            try:
                _write(job / 'failure.json', _json({'job_id': job_id, 'code': 'NATIVE_PREPARATION_FAILED'}))
            except (OSError, HostedFormsJobError):
                pass  # An unsealed failure remains claimed/unknown, never replayable.
        return self.status(job_id, project_id=manifest['project_id'], owner_id=manifest['owner_id'])

    def read_result(self, job_id: str, *, project_id: str, owner_id: str,
                    source_set_sha256: str, selected_source_set_id: str | None = None) -> dict:
        """Internal adoption only: freshly checked redacted document and receipt.

        Caller must compare current project source set, then atomically adopt via
        its normal source-history path. This does not grant external model consent.
        """
        self._authorized(job_id, project_id, owner_id, source_set_sha256, selected_source_set_id)
        if self.status(job_id, project_id=project_id, owner_id=owner_id)['status'] != PREPARED:
            _fail()
        return self._result(job_id)
