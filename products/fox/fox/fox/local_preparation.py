"""Opt-in localhost preparation, never hosted intake or conversion authority.

Trusted local startup supplies storage, authentication and an installed backend.
Requests supply selected bytes only. This module is inert until registered and
never uploads, calls a model/database, reads a caller-selected path or installs
Oracle tooling. Native tooling is the existing extractor's responsibility.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import threading
from urllib.parse import urlsplit
import uuid

from fastapi import APIRouter, HTTPException, Request
from starlette.datastructures import UploadFile
from starlette.formparsers import MultiPartException, MultiPartParser
from starlette.responses import JSONResponse, Response

from . import extractor
from .intake import ALLOWED
from .prepared_source import MAX_MANIFEST_BYTES, UPLOAD_MANIFEST_NAME, parse_upload_manifest


PREFIX = '/api/local-preparation'
MAX_FILES = 50
MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_SELECTED_BYTES = 25 * 1024 * 1024
MAX_REQUEST_BYTES = 26 * 1024 * 1024
MAX_SESSION_JOBS = 20
_JOB = re.compile(r'prep-[0-9a-f]{32}\Z')
_FILE = re.compile(r'file-[0-9a-f]{32}\Z')


def _error(status, message):
    return JSONResponse({'detail': message}, status_code=status,
                        headers={'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})


def _read(path, maximum):
    path = extractor.assert_local_path(path)
    if not path.is_file() or path.stat().st_size > maximum:
        raise ValueError('Local artifact is unavailable.')
    with path.open('rb') as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError('Local artifact exceeds its bound.')
    return raw


@dataclass
class _Job:
    identifier: str
    owner: str
    directory: Path
    state: str = 'RUNNING'
    code: str = 'PREPARING_LOCALLY'
    prepared: Path | None = None
    manifest_sha256: str | None = None
    files: dict = field(default_factory=dict)
    missing_dependencies: int = 0


class LocalPreparationService:
    """One active extraction per local session, with create-only retained files."""

    def __init__(self, root, configured_backend=None):
        base = extractor.assert_local_path(root)
        self.root = base / 'p'
        self.inputs = base / 'i'
        self.backend = configured_backend
        self._lock = threading.RLock()
        self._busy = False
        self._closed = False
        self._jobs = {}
        self._future = None
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='fox-local-preparation')

    def close(self):
        with self._lock:
            self._closed = True
        # No automatic cancellation/retry of native tools or incomplete output.
        self._executor.shutdown(wait=True, cancel_futures=True)

    def capabilities(self):
        formats = []
        if self.backend is not None:
            try:
                check = getattr(self.backend, 'check', None)
                declared = check().get('formats', []) if check else sorted(extractor.BINARY)
                formats = sorted(ext for ext in extractor.BINARY if ext in declared)
            except Exception:
                formats = []
        return {'local_only': True, 'readable_formats': sorted(ALLOWED), 'native_formats': formats,
                'tool_presence_only': True, 'native_extraction_verified': False,
                'max_files': MAX_FILES, 'max_file_bytes': MAX_FILE_BYTES,
                'max_selected_bytes': MAX_SELECTED_BYTES, 'max_session_jobs': MAX_SESSION_JOBS,
                'automatic_upload': False, 'conversion_available': False,
                'note': 'Installed-tool presence is not compatibility, entitlement or redaction approval.'}

    def reserve(self):
        with self._lock:
            if self._closed:
                raise HTTPException(503, 'Local preparation is stopping.')
            if self._busy:
                raise HTTPException(409, 'One local preparation is already active; inspect its existing job.')
            if len(self._jobs) >= MAX_SESSION_JOBS:
                raise HTTPException(429, 'Local session preparation limit reached; existing evidence is retained.')
            self._busy = True

    def release(self):
        with self._lock:
            self._busy = False

    def submit_reserved(self, owner, selected):
        identifier = 'prep-' + uuid.uuid4().hex
        directory = self.inputs / identifier
        source = directory / 's'
        extractor.validate_path_budget(source, self.root, [name for name, _ in selected], identifier,
                                       self.backend, private_paths=[directory / 'local-status.json'])
        try:
            extractor.assert_local_path(self.root)
            extractor.assert_local_path(self.inputs)
            # Windows children inherit the launcher's protected session DACL.
            # Python's special 0700 handling would replace that inheritance.
            # This creates new directories only; it never repairs old ACLs.
            directory_mode = 0o777 if os.name == 'nt' else 0o700
            self.inputs.mkdir(parents=True, exist_ok=True, mode=directory_mode)
            directory.mkdir(mode=directory_mode)
            source.mkdir(mode=directory_mode)
            for name, raw in selected:
                with (source / name).open('xb') as stream:
                    stream.write(raw)
            job = _Job(identifier, owner, directory)
            with self._lock:
                self._jobs[identifier] = job
                self._record(job)
                self._future = self._executor.submit(self._prepare, job, source)
                return self._public(job)
        except Exception:
            raise HTTPException(503, 'Local staging could not complete; no preparation was released.') from None

    def _record(self, job):
        # Private local diagnostics only, never served through output routes.
        target = extractor.assert_local_path(job.directory / 'local-status.json')
        target.write_text(json.dumps({'job_id': job.identifier, 'state': job.state, 'code': job.code}), encoding='utf-8')

    def _prepare(self, job, source):
        try:
            prepared = extractor.prepare(source, self.root, self.backend, job.identifier)
            extractor.verify(prepared)
            raw_manifest = _read(prepared / 'ready' / UPLOAD_MANIFEST_NAME, MAX_MANIFEST_BYTES)
            manifest = parse_upload_manifest(raw_manifest)
            inventory = json.loads(_read(prepared / 'inventory.json', 1024 * 1024))
            missing = inventory.get('missing_count', 0)
            if type(missing) is not int or missing < 0:
                raise ValueError('Invalid inventory summary.')
            entries = [*manifest['files'], {'name': UPLOAD_MANIFEST_NAME,
                       'bytes': len(raw_manifest), 'sha256': hashlib.sha256(raw_manifest).hexdigest()}]
            with self._lock:
                job.prepared = prepared
                job.manifest_sha256 = hashlib.sha256(raw_manifest).hexdigest()
                job.files = {'file-' + uuid.uuid4().hex: dict(item) for item in entries}
                job.missing_dependencies = missing
                job.state, job.code = 'PREPARED_REVIEW_REQUIRED', 'REVIEW_READABLE_OUTPUT'
                self._record(job)
        except Exception:
            # Never disclose source, Oracle diagnostics, paths or exception text.
            with self._lock:
                job.state, job.code = 'BLOCKED', 'LOCAL_PREPARATION_FAILED'
                job.files = {}
                try:
                    self._record(job)
                except (OSError, ValueError):
                    pass
        finally:
            self.release()

    def _owned(self, identifier, owner):
        if not _JOB.fullmatch(identifier) or identifier not in self._jobs:
            raise HTTPException(404, 'Local preparation not found.')
        job = self._jobs[identifier]
        if job.owner != owner:
            raise HTTPException(404, 'Local preparation not found.')
        return job

    def _verified(self, job):
        if job.state != 'PREPARED_REVIEW_REQUIRED' or job.prepared is None:
            raise HTTPException(409, 'No verified readable output is available.')
        try:
            extractor.verify(job.prepared)
            raw = _read(job.prepared / 'ready' / UPLOAD_MANIFEST_NAME, MAX_MANIFEST_BYTES)
            if hashlib.sha256(raw).hexdigest() != job.manifest_sha256:
                raise ValueError('Changed manifest.')
        except Exception:
            job.state, job.code = 'BLOCKED', 'PREPARED_OUTPUT_CHANGED'
            job.files = {}
            try:
                self._record(job)
            except (OSError, ValueError):
                pass
            raise HTTPException(409, 'Prepared output changed or is unavailable; do not reuse it.') from None

    @staticmethod
    def _public(job):
        return {'job_id': job.identifier, 'state': job.state, 'code': job.code,
                'requires_human_review': True, 'approved_for_upload': False,
                'automatic_upload': False, 'conversion_started': False,
                'missing_dependency_count': job.missing_dependencies,
                'files': [{'file_id': identifier, **entry} for identifier, entry in job.files.items()],
                'note': 'Review/redact all readable output before an explicit handoff. Integrity is not approval.'}

    def status(self, identifier, owner):
        with self._lock:
            job = self._owned(identifier, owner)
            if job.state == 'PREPARED_REVIEW_REQUIRED':
                self._verified(job)
            return self._public(job)

    def output(self, identifier, file_id, owner):
        with self._lock:
            job = self._owned(identifier, owner)
            self._verified(job)
            if not _FILE.fullmatch(file_id) or file_id not in job.files:
                raise HTTPException(404, 'Readable output not found.')
            entry = job.files[file_id]
            try:
                raw = _read(job.prepared / 'ready' / entry['name'], 5 * 1024 * 1024)
                if len(raw) != entry['bytes'] or hashlib.sha256(raw).hexdigest() != entry['sha256']:
                    raise ValueError('Changed output.')
            except Exception:
                raise HTTPException(409, 'Prepared output changed or is unavailable; do not reuse it.') from None
            return raw, entry['name']


class _LocalGate:
    """Authenticate and check the real peer/Host/Origin before consuming bodies."""

    def __init__(self, app, *, owner_callback, origin, host):
        self.app, self.owner_callback, self.origin, self.host = app, owner_callback, origin, host

    async def __call__(self, scope, receive, send):
        path = scope.get('path', '')
        if scope['type'] != 'http' or not (path == PREFIX or path.startswith(PREFIX + '/')):
            return await self.app(scope, receive, send)
        headers = scope.get('headers', [])
        hosts = [v.decode('latin-1') for k, v in headers if k.lower() == b'host']
        origins = [v.decode('latin-1') for k, v in headers if k.lower() == b'origin']
        peer = (scope.get('client') or ('', 0))[0]
        mutate = scope['method'] not in {'GET', 'HEAD'}
        if (peer != '127.0.0.1' or hosts != [self.host] or len(origins) > 1
                or (origins and origins != [self.origin]) or (mutate and origins != [self.origin])):
            return await _error(403, 'Local preparation requires its exact localhost origin.')(scope, receive, send)
        try:
            who = self.owner_callback(Request(scope, receive))
            who = await who if inspect.isawaitable(who) else who
            if type(who) is not str or not who:
                raise HTTPException(401, 'Please sign in.')
        except HTTPException as error:
            return await _error(error.status_code if error.status_code in (401, 403) else 403,
                                'Local preparation requires an authenticated session.')(scope, receive, send)
        except Exception:
            return await _error(403, 'Local preparation authentication is unavailable.')(scope, receive, send)
        scope.setdefault('state', {})['local_preparation_owner'] = who
        return await self.app(scope, receive, send)


class _SelectedFileParser(MultiPartParser):
    def on_headers_finished(self):
        # Browser file pickers emit this form. Reject paths/extended/duplicate
        # parameters BEFORE python-multipart's legacy Windows-path normalization.
        disposition = self._current_part.content_disposition
        if not re.fullmatch(rb'form-data;\s*name="files";\s*filename="[A-Za-z0-9][A-Za-z0-9_. -]{0,119}"\s*', disposition):
            raise MultiPartException('Only selected safe file basenames are accepted.')
        super().on_headers_finished()


def register_local_preparation(app, root, owner_callback, configured_backend=None, *, origin='http://127.0.0.1:8100'):
    """Explicit trusted-local registration. Return the service for lifecycle tests.

    GET Origin may be absent (normal same-origin browser fetch); any supplied
    Origin must match. Every mutation requires it. Host and peer are exact on
    every route. No environment variable or HTTP field can enable this feature.
    """
    parsed = urlsplit(origin)
    try:
        port = parsed.port
    except ValueError:
        port = None
    if (parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or not port
            or not 1024 <= port <= 65535 or parsed.netloc != f'127.0.0.1:{port}'
            or parsed.path or parsed.query or parsed.fragment or not callable(owner_callback)):
        raise ValueError('An explicit loopback origin and existing owner callback are required.')
    if getattr(app.state, 'local_preparation_service', None) is not None:
        raise ValueError('Local preparation is already registered.')
    service = LocalPreparationService(root, configured_backend)

    @asynccontextmanager
    async def lifespan(_app):
        try:
            yield
        finally:
            service.close()

    router = APIRouter(prefix=PREFIX, lifespan=lifespan)

    @router.get('/capabilities')
    def capabilities():
        return JSONResponse(service.capabilities(), headers={'Cache-Control': 'no-store'})

    @router.post('/jobs', status_code=202)
    async def prepare(request: Request):
        service.reserve()
        submitted = False
        try:
            lengths = request.headers.getlist('content-length')
            if len(lengths) > 1 or (lengths and not re.fullmatch(r'[0-9]+', lengths[0])):
                raise HTTPException(400, 'Invalid local request length.')
            if lengths and int(lengths[0]) > MAX_REQUEST_BYTES:
                raise HTTPException(413, 'Local preparation request exceeds its bound.')
            if not request.headers.get('content-type', '').lower().startswith('multipart/form-data;'):
                raise HTTPException(415, 'Select files through the local preparation picker.')
            body = bytearray()
            async for chunk in request.stream():
                if len(body) + len(chunk) > MAX_REQUEST_BYTES:
                    raise HTTPException(413, 'Local preparation request exceeds its bound.')
                body.extend(chunk)
            # Parse only after the actual streamed envelope is bounded. No user
            # source directory is created until all selected bytes are validated.
            request._body = bytes(body)
            selected, names, total = [], set(), 0
            try:
                parser = _SelectedFileParser(request.headers, request.stream(), max_files=MAX_FILES,
                                             max_fields=0, max_part_size=MAX_FILE_BYTES)
                form = await parser.parse()
                try:
                    for field_name, upload in form.multi_items():
                        if field_name != 'files' or not isinstance(upload, UploadFile):
                            raise HTTPException(422, 'Only selected file bytes are accepted.')
                        name = upload.filename or ''
                        try:
                            extractor.safe_name(name)
                        except ValueError:
                            raise HTTPException(422, 'Use a safe basename, not a path.') from None
                        if name.casefold() in names or Path(name).suffix.lower() not in ALLOWED | extractor.BINARY:
                            raise HTTPException(422, 'Unsupported source type or duplicate basename.')
                        raw = await upload.read(MAX_FILE_BYTES + 1)
                        total += len(raw)
                        if not raw or len(raw) > MAX_FILE_BYTES or total > MAX_SELECTED_BYTES or len(selected) >= MAX_FILES:
                            raise HTTPException(413, 'Selected files exceed local preparation limits or contain an empty file.')
                        names.add(name.casefold())
                        selected.append((name, raw))
                finally:
                    await form.close()
            except HTTPException:
                raise
            except Exception:
                raise HTTPException(422, 'Invalid local multipart file selection.') from None
            if not selected:
                raise HTTPException(422, 'Select at least one source file.')
            requested = {Path(name).suffix.lower() for name, _ in selected} & extractor.BINARY
            if requested - set(service.capabilities()['native_formats']):
                raise HTTPException(409, 'Selected binaries require the configured installed Oracle tools; readable preparation remains available.')
            try:
                result = service.submit_reserved(request.state.local_preparation_owner, selected)
            except extractor.PathBudgetError:
                return _error(422, {'code': 'LOCAL_PATH_BUDGET_EXCEEDED', 'message': extractor.PATH_BUDGET_MESSAGE})
            submitted = True
            return JSONResponse(result, status_code=202, headers={'Cache-Control': 'no-store'})
        finally:
            if not submitted:
                service.release()

    @router.get('/jobs/{identifier}')
    def status(identifier: str, request: Request):
        return JSONResponse(service.status(identifier, request.state.local_preparation_owner),
                            headers={'Cache-Control': 'no-store'})

    @router.get('/jobs/{identifier}/files/{file_id}')
    def output(identifier: str, file_id: str, request: Request):
        raw, name = service.output(identifier, file_id, request.state.local_preparation_owner)
        return Response(raw, media_type='application/json' if name == UPLOAD_MANIFEST_NAME else 'text/plain',
                        headers={'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
                                 'Content-Disposition': f'attachment; filename="{name}"'})

    app.include_router(router)
    app.add_middleware(_LocalGate, owner_callback=owner_callback, origin=origin, host=parsed.netloc)
    app.state.local_preparation_service = service
    return service
