from __future__ import annotations
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
import uuid
import zipfile
from contextlib import asynccontextmanager, closing
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException, UploadFile, File, Form
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.gzip import GZipMiddleware
from pydantic import BaseModel, Field

from .intake import checked_source, inventory, MAX_FILE_BYTES, MAX_PROJECT_BYTES
from .native_source import assess_native_source, PROFILE_ID as NATIVE_PROFILE
from .project_conversion import (assess_project_conversion, ProjectConversionInputError,
                                 PROFILE_ID as PROJECT_PROFILE)
from .prepared_source import (UPLOAD_MANIFEST_NAME, MAX_MANIFEST_BYTES,
                              encode_upload_manifest, parse_upload_manifest,
                              verify_upload_manifest)
from . import source_history
from .storage import initialize_schema as initialize_storage_schema

LEGACY_PROFILE = 'legacy-html-prototype-v1'
_NO_INSTALLATION_PROJECTION = object()
MAX_HISTORY_JSON_BYTES = 256 * 1024
HISTORY_RESPONSE_TOO_LARGE = ('Source history could not be displayed within the response limit. '
                              'No source version was changed. Refresh or ask the operator for help.')
HISTORY_EXPORT_TOO_LARGE = ('This source version is too large for one readable export. '
                            'Its files remain saved; use a smaller coherent version or ask the operator for an approved export.')


class SourceHistoryResponseTooLarge(ValueError):
    pass


def history_json_response(value: dict) -> JSONResponse:
    """Size-check exact response bytes before a mutation transaction commits."""
    response = JSONResponse(value)
    if len(response.body) > MAX_HISTORY_JSON_BYTES:
        raise SourceHistoryResponseTooLarge(HISTORY_RESPONSE_TOO_LARGE)
    return response


def history_assessment_summary(sources: list[dict]) -> dict:
    """Bounded metadata only; never return source-controlled identifier text."""
    assessed = inventory(sources)
    profile = os.getenv('FOX_CONVERSION_PROFILE', LEGACY_PROFILE).strip()
    profile = profile if profile in {LEGACY_PROFILE, NATIVE_PROFILE, PROJECT_PROFILE} else 'unconfigured'
    native = assess_native_source(sources) if profile == NATIVE_PROFILE else None
    project_plan = (assess_project_conversion(sources, project_id='source-history',
                    project_name='Source version', source_hash=assessed['source_hash'])
                    if profile == PROJECT_PROFILE else None)
    blockers = (project_plan['project_findings'] + [finding for form in project_plan['forms']
                 for finding in form['findings']] if project_plan else
                assessed['conversion_blockers'] + (native['blockers'] if native else []))
    codes = sorted({item['code'] for item in blockers})
    if len(codes) > 64 or any(not isinstance(code, str) or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,63}', code) for code in codes):
        raise source_history.SourceHistoryError('Assessment summary is unavailable.')
    native_state = (('READY' if project_plan['can_generate'] else 'BLOCKED') if project_plan else
                    native['state'] if native else None)
    if native_state not in {None, 'READY', 'BLOCKED'}:
        raise source_history.SourceHistoryError('Assessment summary is unavailable.')
    return {
        'source_hash': assessed['source_hash'], 'conversion_profile': profile,
        'source_checks_passed': bool(profile != 'unconfigured' and assessed['conversion_eligible']
                                     and (native_state is None or native_state == 'READY')),
        'file_count': len(sources), 'source_bytes': assessed['source_bytes'],
        'conversion_source_bytes': assessed['conversion_source_bytes'],
        'max_conversion_bytes': assessed['max_conversion_bytes'],
        'max_conversion_files': assessed['max_conversion_files'],
        'missing_dependency_count': assessed['missing_count'],
        'assessment_finding_count': len(assessed['issues']),
        'conversion_blocker_count': len(blockers), 'blocker_codes': codes,
        'native_state': native_state,
    }


def public_project_plan(plan: dict) -> dict:
    """Describe a server-derived plan without accepting executable client specs.

    plan_sha256 identifies the full server plan, including its rendering spec;
    it is not a digest of this smaller public projection. Processing must derive
    the full plan again from the exact selected source version.
    """
    result = {key: value for key, value in plan.items() if key != 'rendering_spec'}
    result['forms'] = [{key: value for key, value in form.items() if key != 'native_form'}
                       for form in plan['forms']]
    return result

NATIVE_STAGE_MESSAGES = {
    'preparing': 'Checking the approved source and conversion profile.',
    'inspecting': 'Building the Forms inventory and dependency evidence.',
    'mapping': 'OPAF is mapping the supplied fields to the native APEX profile.',
    'reviewing': 'The independent OPAF reviewer is checking the proposed mapping.',
    'generating': 'Generating native APEX components from the reviewed mapping.',
    'validating': 'SQLcl is validating the generated APEX application.',
    'importing': 'Importing a new test application without replacing existing apps.',
    'reconciling': 'Checking the existing import before deciding the next safe step.',
    'packaging': 'Exporting and verifying the APEX package.',
    'downloaded': 'The package has reached FOX; release verification is being checked.',
}

PROJECT_RUN_MESSAGES = {
    'QUEUED': 'Waiting to convert all selected forms into one application.',
    'PROCESSING': 'Converting the complete project. Generated output and technical checks are reported separately.',
    'ATTENTION': 'Processing needs attention. Check the saved run before continuing.',
    'FAILED': 'Conversion stopped. Your sources and completed work remain saved.',
    'QA_REQUIRED': 'The generated package is waiting for technical verification.',
    'REVIEW_REQUIRED': 'The retained project result needs technical verification before human review.',
    'VERIFIED': 'Technical checks are recorded. Review the evidence and validate the business behavior.',
    'ACCEPTED': 'Human review is recorded. Download availability is checked against the exact accepted package.',
}


def native_progress(root: Path, run: dict) -> dict:
    """Expose only whitelisted progress from a bounded, local regular file."""
    if run.get('state') not in {'PROCESSING', 'ATTENTION'} or not re.fullmatch(r'fox-[a-f0-9]{20}', run.get('id', '')):
        return {}
    jobs, job = root/'jobs', root/'jobs'/run['id']
    path = job/'native-progress.json'
    try:
        # Reject symlinks/junctions in both the job path and the progress file.
        if any(item.is_symlink() or item.resolve(strict=True) != item for item in (jobs, job, path)):
            return {}
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 2048:
            return {}
        with path.open('rb') as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                return {}
            raw = stream.read(2049)
        if len(raw) > 2048:
            return {}
        value = json.loads(raw)
        if not isinstance(value, dict) or set(value) != {'stage', 'updated_at_utc'}:
            return {}
        stage, updated = value['stage'], value['updated_at_utc']
        if not isinstance(stage, str) or stage not in NATIVE_STAGE_MESSAGES:
            return {}
        if not isinstance(updated, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)', updated, flags=re.ASCII):
            return {}
        timestamp = datetime.fromisoformat(updated.replace('Z', '+00:00')).astimezone(timezone.utc)
        return {'stage': stage, 'stage_message': NATIVE_STAGE_MESSAGES[stage], 'stage_updated_at_utc': timestamp.isoformat()}
    except (OSError, RuntimeError, ValueError, TypeError):
        # Progress is advisory; a partial writer or unavailable file must not
        # hide the saved project or disclose provider/source text.
        return {}


def conversion_configuration(*, installation_projection=_NO_INSTALLATION_PROJECTION) -> dict:
    """Describe operator configuration without reading or exposing credentials.

    Configured is not a connectivity, model, APEX or release acceptance test.
    The native profile is explicit so an unknown value cannot enable legacy flow.
    """
    profile = os.getenv('FOX_CONVERSION_PROFILE', LEGACY_PROFILE).strip()
    checks = []
    project_schema_versions = []

    def check(code, ready, message):
        checks.append({'code': code, 'ready': bool(ready), 'message': message})

    check('SUPPORTED_PROFILE', profile in {LEGACY_PROFILE, NATIVE_PROFILE, PROJECT_PROFILE}, 'The operator must select a supported conversion profile.')
    if installation_projection is not _NO_INSTALLATION_PROJECTION:
        check('FRESH_PROJECT_PROFILE', profile == PROJECT_PROFILE,
              'Fresh installations require the native project conversion profile.')
    if profile in {NATIVE_PROFILE, PROJECT_PROFILE}:
        from .opaf import ConverterClient, load_native_profile
        try:
            profile_path = os.getenv('FOX_NATIVE_PROFILE_FILE', '')
            profile_ready = bool(profile_path) and Path(profile_path).is_file()
            if profile_ready:
                if profile == PROJECT_PROFILE:
                    from .native_project_pipeline import load_project_profile
                    loaded_profile = load_project_profile(profile_path)
                    project_schema_versions = [1, 2] if loaded_profile['schema_version'] == 2 else [1]
                else:
                    load_native_profile(profile_path)
        except (OSError, ValueError, TypeError, KeyError, RuntimeError):
            profile_ready = False
        check('NATIVE_WORKFLOW_PROFILE', profile_ready, 'The native mapper and independent reviewer deployment profile is not configured correctly.')
        try:
            converter_url = os.getenv('FOX_CONVERTER_URL', '')
            if installation_projection is _NO_INSTALLATION_PROJECTION:
                ConverterClient(converter_url, '')
            else:
                ConverterClient(converter_url, '', projection=installation_projection)
            converter_ready = True
        except (ValueError, TypeError, RuntimeError):
            converter_ready = False
        check('INTERNAL_CONVERTER', converter_ready, 'The internal converter endpoint is not configured correctly.')
        try:
            credential_path = os.getenv('FOX_OPAF_CREDENTIAL_FILE', '')
            credential_ready = bool(credential_path) and Path(credential_path).is_file()
        except OSError:
            credential_ready = False
        check('PROTECTED_CREDENTIAL_FILE', credential_ready, 'The protected integration credential file is not mounted.')
        check('EMBEDDED_ADAPTER', os.getenv('FOX_RUN_ADAPTER') == 'embedded-opaf', 'The embedded conversion adapter is not selected.')
        if profile == PROJECT_PROFILE:
            from .native_project_pipeline import project_configuration_readiness
            project_config = (project_configuration_readiness()
                              if installation_projection is _NO_INSTALLATION_PROJECTION else
                              project_configuration_readiness(installation_projection=installation_projection))
            check('PROJECT_CONFIGURATION', project_config['configured'], 'The project conversion adapter is not configured correctly.')
    elif profile == LEGACY_PROFILE:
        check('LEGACY_WORKFLOW', bool(os.getenv('FOX_OPAF_RUN_URL')), 'The legacy workflow integration is not configured.')
    return {'conversion_profile': profile, 'conversion_configured': all(item['ready'] for item in checks),
            'configured_project_schema_versions': project_schema_versions,
            'configuration_checks': checks,
            'configuration_scope': 'Configuration only; connectivity and all technical release gates are checked during conversion.'}

def password_hash(password: str, salt: str | None = None) -> str:
    salt=salt or secrets.token_hex(16)
    return salt+':'+hashlib.scrypt(password.encode(),salt=bytes.fromhex(salt),n=16384,r=8,p=1).hex()

def check_password(password: str, stored: str) -> bool:
    try: return hmac.compare_digest(password_hash(password,stored.split(':')[0]),stored)
    except (ValueError,IndexError): return False

class ProjectInput(BaseModel):
    customer: str = Field(min_length=1,max_length=100)
    name: str = Field(min_length=1,max_length=120)
    description: str = Field(default='',max_length=1000)

class LoginInput(BaseModel):
    username: str = Field(max_length=100)
    password: str = Field(max_length=256)

class RunInput(BaseModel):
    model_config = {'extra': 'forbid', 'strict': True}
    source_hash: str = Field(pattern=r'^[a-f0-9]{64}$')
    approved_redacted_source: bool
    approved_external_ai: bool
    approved_prototype_scope: bool
    expected_current_source_set_id: str | None = Field(default=None, pattern=r'^ss-[a-f0-9]{32}$')
    plan_sha256: str | None = Field(default=None, pattern=r'^[a-f0-9]{64}$')

class AcceptanceInput(BaseModel):
    source_hash: str = Field(min_length=64,max_length=64)
    business_flow_tested: bool
    remediation_reviewed: bool
    notes: str = Field(min_length=1,max_length=2000)

class SourceSelectionInput(BaseModel):
    model_config = {'extra': 'forbid', 'strict': True}
    expected_current_source_set_id: str | None = Field(pattern=r'^ss-[a-f0-9]{32}$')

class SourceExclusionInput(BaseModel):
    model_config = {'extra': 'forbid', 'strict': True}
    expected_current_source_set_id: str = Field(pattern=r'^ss-[a-f0-9]{32}$')
    excluded_file_ids: list[str] = Field(min_length=1, max_length=50)

def create_app(data_dir: Path | None = None, enable_worker: bool = True, *,
               enable_local_preparation: bool = False, local_preparation_backend=None) -> FastAPI:
    if type(enable_local_preparation) is not bool or (enable_local_preparation and enable_worker):
        raise ValueError('Local preparation requires an explicit assessment-only application.')
    if local_preparation_backend is not None and not enable_local_preparation:
        raise ValueError('Local preparation backend requires explicit local registration.')
    # Select/validate fresh mode before even mkdir or SQLite's default-create
    # connection behavior. A missing fresh mount must never create a new store.
    from .fresh_startup import configured_fence, FreshStartupError
    candidate = data_dir or Path(os.getenv('FOX_DATA_DIR','data'))
    fresh = configured_fence(candidate)
    root = fresh.root if fresh else Path(candidate).resolve()
    if fresh is None:
        root.mkdir(parents=True,exist_ok=True)
    database=root/'fox.sqlite3'
    origin=os.getenv('FOX_PUBLIC_ORIGIN','http://127.0.0.1:8100').rstrip('/')
    admin=os.getenv('FOX_ADMIN_USERNAME','jason')
    stored_hash=os.getenv('FOX_PASSWORD_HASH','')
    def db():
        c=sqlite3.connect(database.as_uri() + '?mode=rw',uri=True,timeout=30) if fresh else sqlite3.connect(database,timeout=30)
        c.row_factory=sqlite3.Row
        c.execute('PRAGMA foreign_keys=ON')
        return c
    if fresh is None:
        with db() as c:
            initialize_storage_schema(c)
    from .worker_observability import WorkerMonitor, observed_poll
    from .verification_runtime import configuration as verification_configuration, initialize as initialize_verification, public_status as verification_status
    verifier_config = verification_configuration()
    if fresh is None:
        initialize_verification(root, verifier_config)
    stop=threading.Event()
    worker_monitor=WorkerMonitor(enabled=enable_worker)
    worker_thread=None
    lifecycle_lock = threading.RLock()
    lifecycle_active = False
    lifecycle_started = False
    fresh_attention = False

    def perform_normal_start():
        nonlocal worker_thread, fresh_attention
        if fresh is not None:
            # F hands off DELETE mode so fenced reads create no WAL sidecars.
            # Only the admitted transition restores normal WAL operation.
            with closing(db()) as c:
                if c.execute('PRAGMA journal_mode=WAL').fetchone()[0] != 'wal':
                    raise FreshStartupError('FRESH_WAL_TRANSITION_UNCONFIRMED')
            initialize_verification(root, verifier_config)
        with db() as c:
            c.execute("UPDATE runs SET state='ATTENTION',message='Interrupted. Existing run evidence must be reconciled before retry.',updated=? WHERE state='PROCESSING'",(time.time(),))
        if enable_worker:
            from .worker import process_one
            def process_configured_job(connection, data_root):
                if fresh is None:
                    return process_one(connection, data_root)
                # The lifecycle and each poll have already refreshed A and
                # actual storage. P selects transport; it grants no admission.
                return process_one(connection, data_root,
                                   installation_projection=fresh.projection)
            def loop():
                nonlocal fresh_attention
                worker_monitor.started()
                try:
                    while not stop.is_set():
                        if fresh is not None:
                            try:
                                if not fresh.refresh():
                                    raise FreshStartupError('FRESH_ADMISSION_REQUIRED')
                            except FreshStartupError:
                                fresh_attention = True
                                worker_monitor.failed('WORKER_RECONCILIATION_REQUIRED')
                                stop.set()
                                break
                        observed_poll(process_configured_job,db,root,worker_monitor)
                        stop.wait(2)
                finally:
                    worker_monitor.stopped()
            worker_thread=threading.Thread(target=loop,daemon=True,name='fox-worker');worker_thread.start()

    def start_normal_lifecycle():
        nonlocal lifecycle_started, fresh_attention
        with lifecycle_lock:
            if lifecycle_started:
                return
            if fresh is not None and (fresh_attention or not fresh.refresh()):
                return
            # Mark once before every mutation, including initializer/update.
            # An uncertain partial start must never reopen through a new poll.
            lifecycle_started = True
            try:
                perform_normal_start()
            except Exception:
                if fresh is None:
                    raise
                fresh_attention = True
                stop.set()
                raise FreshStartupError('FRESH_STARTUP_OUTCOME_UNCONFIRMED') from None

    @asynccontextmanager
    async def lifespan(app):
        nonlocal lifecycle_active
        if not stored_hash: raise RuntimeError('FOX_PASSWORD_HASH must be configured before serving.')
        stop.clear()
        lifecycle_active = True
        start_normal_lifecycle()
        try:
            yield
        finally:
            lifecycle_active = False
            stop.set()
            worker_monitor.stopping()
    app=FastAPI(title='FOX',docs_url=None,redoc_url=None,openapi_url=None,lifespan=lifespan)
    app.state.worker_monitor=worker_monitor
    app.state.fresh_startup=fresh
    def configured_conversion():
        return (conversion_configuration() if fresh is None else
                conversion_configuration(installation_projection=fresh.projection))
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    @app.exception_handler(source_history.SourceHistoryNotFound)
    async def missing_source_set(request, exc):
        return JSONResponse({'detail': 'Source version not found.'}, status_code=404)
    @app.exception_handler(SourceHistoryResponseTooLarge)
    async def oversized_source_history_response(request, exc):
        return JSONResponse({'detail': HISTORY_RESPONSE_TOO_LARGE,
                             'code': 'SOURCE_HISTORY_RESPONSE_TOO_LARGE'}, status_code=409)
    @app.exception_handler(source_history.SourceHistoryExportTooLarge)
    async def oversized_source_history_export(request, exc):
        return JSONResponse({'detail': HISTORY_EXPORT_TOO_LARGE,
                             'code': 'SOURCE_HISTORY_EXPORT_TOO_LARGE'}, status_code=409)
    @app.exception_handler(source_history.SourceHistoryConflict)
    async def changed_source_selection(request, exc):
        return JSONResponse({'detail': 'The selected source version changed. Refresh before choosing a version.',
                             'code': 'SOURCE_SELECTION_CHANGED'}, status_code=409)
    @app.exception_handler(source_history.SourceHistoryInputError)
    async def invalid_source_history_action(request, exc):
        return JSONResponse({'detail': str(exc), 'code': 'SOURCE_HISTORY_INPUT'}, status_code=422)
    @app.exception_handler(source_history.SourceHistoryError)
    async def unavailable_source_history(request, exc):
        return JSONResponse({'detail': 'Saved source history could not be verified. Ask the operator to reconcile it; no source version was changed.',
                             'code': 'SOURCE_HISTORY_UNAVAILABLE'}, status_code=409)
    def owner(request:Request):
        token=hashlib.sha256(request.cookies.get('fox_session','').encode()).hexdigest()
        with db() as c: row=c.execute('SELECT owner FROM sessions WHERE token=? AND expires>?',(token,time.time())).fetchone()
        if not row: raise HTTPException(401,'Please sign in.')
        return row['owner']
    def project(request,pid):
        who=owner(request)
        with db() as c: row=c.execute('SELECT * FROM projects WHERE id=? AND owner=?',(pid,who)).fetchone()
        if not row: raise HTTPException(404,'Project not found.')
        return dict(row)
    def current_sources(pid, connection=None):
        if connection is not None:
            return source_history.selected_sources(connection, pid)
        with db() as c:
            c.execute('BEGIN')
            return source_history.selected_sources(c, pid)
    def source_preparation(pid, source_hash):
        # The latest upload event can refer to an existing deduplicated receipt.
        # A receipt proves only its uploaded set, never supersedes source history.
        with db() as c:
            row = c.execute("SELECT p.* FROM prepared_uploads p JOIN events e ON e.object_id=p.id AND e.action='prepared_sources_verified' WHERE p.project=? ORDER BY e.id DESC LIMIT 1", (pid,)).fetchone()
        if not row:
            return {'mode': 'DIRECT_READABLE', 'matches_current_source': False,
                    'scope': 'No prepared-set integrity receipt. Direct readable uploads remain supported.'}
        try:
            manifest = parse_upload_manifest(row['manifest_json'].encode('utf-8'))
            canonical = encode_upload_manifest(manifest)
            if (hashlib.sha256(canonical).hexdigest() != row['canonical_manifest_sha256']
                    or manifest['readable_source_hash'] != row['readable_source_hash']
                    or manifest['extraction_job_id'] != row['extraction_job_id']):
                raise ValueError('Stored preparation receipt does not match.')
        except (ValueError, TypeError, AttributeError):
            return {'mode': 'PREPARED_RECEIPT_UNAVAILABLE', 'matches_current_source': False,
                    'scope': 'The saved preparation receipt cannot be verified; current source assessment remains separate.'}
        matches = manifest['readable_source_hash'] == source_hash
        return {'mode': 'PREPARED_SET_MATCH' if matches else 'PREPARED_SET_PARTIAL_OR_CHANGED',
                'receipt_id': row['id'], 'extraction_job_id': manifest['extraction_job_id'],
                'canonical_manifest_sha256': row['canonical_manifest_sha256'],
                'readable_source_hash': manifest['readable_source_hash'], 'files': manifest['files'],
                'matches_current_source': matches,
                'scope': 'Exact uploaded-file integrity only; not proof of Oracle tooling, redaction, complete dependencies or processing permission.'}
    def source_assessment(sources, pid, connection=None, *, include_preparation=True):
        result = inventory(sources)
        if include_preparation:
            result['source_preparation'] = source_preparation(pid, result['source_hash'])
        if connection is not None:
            result['selected_source_set_id'] = source_history.selected_source_set_id(connection, pid)
        else:
            with db() as c:
                result['selected_source_set_id'] = source_history.selected_source_set_id(c, pid)
        result['conversion_profile'] = os.getenv('FOX_CONVERSION_PROFILE', LEGACY_PROFILE).strip()
        if result['conversion_profile'] == NATIVE_PROFILE:
            result['native_assessment'] = assess_native_source(sources)
        if result['conversion_profile'] == PROJECT_PROFILE:
            result['project_assessment'] = history_assessment_summary(sources)
        return result

    def selected_project_plan(c, p):
        sources = current_sources(p['id'], c)
        source_hash = inventory(sources)['source_hash']
        plan = assess_project_conversion(sources, project_id=p['id'],
                                         project_name=p['name'], source_hash=source_hash)
        return {**public_project_plan(plan),
                'selected_source_set_id': source_history.selected_source_set_id(c, p['id'])}
    @app.middleware('http')
    async def protect(request,call_next):
        nonlocal fresh_attention
        if fresh is not None:
            with lifecycle_lock:
                try:
                    admitted = not fresh_attention and fresh.refresh()
                    if admitted and lifecycle_active:
                        start_normal_lifecycle()
                except FreshStartupError:
                    fresh_attention = True
                    stop.set()
                    admitted = False
                if not admitted and (fresh_attention or request.method != 'GET'
                        or request.url.path not in {'/api/health', '/api/installation'}):
                    return JSONResponse({'detail': 'Fresh installation is fenced; operator admission is required.',
                        'code': 'FRESH_INSTALLATION_ATTENTION' if fresh_attention else 'FRESH_ADMISSION_REQUIRED'},503)
        if request.method not in {'GET','HEAD','OPTIONS'} and request.headers.get('origin') != origin:
            return JSONResponse({'detail':'Request origin is not allowed.'},403)
        if request.url.path.startswith('/api'):
            try:
                length=int(request.headers.get('content-length','0'))
            except ValueError: return JSONResponse({'detail':'Invalid request length.'},400)
            if length > MAX_PROJECT_BYTES+1024*1024: return JSONResponse({'detail':'Request exceeds 25 MB.'},413)
        response=await call_next(request)
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['X-Frame-Options']='DENY'
        response.headers['Referrer-Policy']='no-referrer'
        response.headers['Cache-Control']='no-store' if request.url.path.startswith('/api') else 'no-cache'
        if response.status_code == 200 and re.fullmatch(r'/assets/[\w-]+-[\w-]+\.(js|css)', request.url.path):
            response.headers['Cache-Control']='public, max-age=31536000, immutable'
        response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        return response
    @app.get('/api/health')
    def health():
        if fresh is not None and fresh.identity()['state'] == 'FENCED':
            return JSONResponse({'status':'fenced','product':'FOX','version':'0.1.0',
                'installation':fresh.identity()},status_code=200)
        worker=worker_monitor.snapshot(thread_alive=worker_thread.is_alive() if worker_thread else False)
        # Existing healthy consumers retain status/product/version and HTTP 200.
        # Error/stale workers deliberately return 503; no provider is called here.
        return JSONResponse({'status':'ok' if worker['healthy'] else 'degraded',
            'product':'FOX','version':'0.1.0','worker':worker},status_code=200 if worker['healthy'] else 503)
    if fresh is not None:
        @app.get('/api/installation')
        def installation_identity():
            return fresh.identity()
    @app.post('/api/login')
    def login(body:LoginInput,request:Request):
        ip=request.client.host if request.client else 'unknown'
        now=time.time()
        with db() as c:
            c.execute('DELETE FROM attempts WHERE created<?',(now-900,))
            if c.execute('SELECT COUNT(*) FROM attempts WHERE ip=?',(ip,)).fetchone()[0]>=10:
                raise HTTPException(429,'Too many attempts. Try again in 15 minutes.')
            c.execute('INSERT INTO attempts VALUES(?,?)',(ip,now))
        if body.username != admin or not check_password(body.password,stored_hash): raise HTTPException(401,'Username or password is incorrect.')
        token=secrets.token_urlsafe(32)
        with db() as c:
            c.execute('DELETE FROM attempts WHERE ip=?',(ip,))
            c.execute('DELETE FROM sessions WHERE expires<?',(now,))
            c.execute('INSERT INTO sessions VALUES(?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),admin,now+28800))
        response=JSONResponse({'username':admin})
        response.set_cookie('fox_session',token,httponly=True,secure=origin.startswith('https:'),samesite='strict',max_age=28800,path='/')
        return response
    @app.post('/api/logout')
    def logout(request:Request):
        with db() as c: c.execute('DELETE FROM sessions WHERE token=?',(hashlib.sha256(request.cookies.get('fox_session','').encode()).hexdigest(),))
        response=JSONResponse({'ok':True});response.delete_cookie('fox_session');return response
    @app.get('/api/session')
    def session(request:Request): return {'username':owner(request),'mode':'Internal MVP',**configured_conversion()}
    @app.get('/api/projects')
    def projects(request:Request):
        who=owner(request)
        with db() as c:
            c.execute('BEGIN')
            rows = [dict(r) for r in c.execute('SELECT p.*,(SELECT COUNT(*) FROM runs WHERE project=p.id) AS run_count FROM projects p WHERE owner=? ORDER BY created DESC',(who,))]
            for row in rows:
                row['file_count'] = len(source_history.selected_sources(c, row['id']))
            return rows
    @app.post('/api/projects',status_code=201)
    def add_project(body:ProjectInput,request:Request):
        who=owner(request);pid=uuid.uuid4().hex;now=time.time()
        if not body.name.strip() or not body.customer.strip(): raise HTTPException(422,'Customer and project names are required.')
        try:
            # Apply the same display-name bounds as the deterministic renderer;
            # existing projects remain readable, but new unusable names are not saved.
            assess_project_conversion([], project_id=pid, project_name=body.name,
                                      source_hash=inventory([])['source_hash'])
        except ProjectConversionInputError as error:
            raise HTTPException(422, str(error)) from None
        with db() as c:
            c.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)',(pid,who,body.customer.strip(),body.name.strip(),body.description.strip(),now))
            source_history.create_project_selection(c, pid, now)
            c.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',(who,'project_created',pid,now))
        return {'id':pid}
    @app.get('/api/projects/{pid}')
    def get_project(pid:str,request:Request):
        p=project(request,pid)
        with db() as c:
            c.execute('BEGIN')
            p['inventory']=source_assessment(current_sources(pid, c), pid, c)
            try:
                p['project_plan'] = selected_project_plan(c, p)
                p['project_plan_error'] = None
            except ProjectConversionInputError as error:
                # Existing projects remain readable even if a new renderer's
                # project-name/input bounds need attention. No run is created.
                p['project_plan'] = None
                p['project_plan_error'] = {'code': error.code, 'message': str(error)}
            configuration = configured_conversion()
            configured = configuration['conversion_configured']
            plan_ready = bool(p['project_plan'] and p['project_plan']['can_generate'])
            mapped_plan = bool(p['project_plan'] and any('storage_mapping' in form for form in p['project_plan']['forms']))
            storage_configured = not mapped_plan or 2 in configuration['configured_project_schema_versions']
            p['project_capabilities'] = {
                'upload': {'enabled': True}, 'select_version': {'enabled': True},
                'process': {'enabled': configured and plan_ready and storage_configured,
                    'reason': ('Resolve every selected form\u2019s findings before converting.' if not plan_ready else
                               'Processing these original table names needs the mapped-project workflow configuration.' if not storage_configured else
                               'Conversion is not configured for this deployment.')},
                'local_preparation': {'enabled': enable_local_preparation},
            }
            p['processing_notice'] = ('Conversion uses embedded OPAF and the configured AI provider. '
                'Only source approved for that processing route may be submitted. '
                'Do not upload credentials or production records; generated test data is synthetic.')
            from .project_run_status import is_project_run, project_run_status, historical_native_run_status
            p['runs'] = []
            for row in c.execute('SELECT * FROM runs WHERE project=? ORDER BY created DESC', (pid,)).fetchall():
                run = dict(row)
                # Public flags are a display projection, never authorization.
                # Mutations/download re-read the retained proof independently.
                if is_project_run(root, run):
                    presentation = project_run_status(c, root, run, p['inventory']['source_hash'])
                elif run['state'] in {'VERIFIED', 'ACCEPTED'}:
                    presentation = historical_native_run_status(c, root, run, p['inventory']['source_hash'])
                else:
                    presentation = None
                if presentation is not None:
                    run.update(presentation)
                    run['message'] = PROJECT_RUN_MESSAGES.get(run['state'], 'Run status is unavailable. Contact the FOX support team.')
                    if run.get('error'):
                        run['message'] = run['error']['message']
                    elif run['state'] in {'QA_REQUIRED', 'REVIEW_REQUIRED', 'VERIFIED', 'ACCEPTED'} and not run['artifact_generated']:
                        run['message'] = 'APEX generation has not been confirmed. Check the saved run before continuing.'
                    elif run['state'] in {'VERIFIED', 'ACCEPTED'} and not run['technical_verified']:
                        run['message'] = 'Technical verification evidence is unavailable. Check the saved run before continuing.'
                    elif run['state'] == 'ACCEPTED' and not run['human_accepted']:
                        run['message'] = 'Human review could not be verified against this package. Download remains locked.'
                else:
                    run.update(native_progress(root, run))
                    run['downloadable'] = bool(run['artifact'] and run['state'] == 'ACCEPTED')
                run['project_id'] = pid
                run['verification_status'] = verification_status(root, run, verifier_config)
                run.pop('artifact', None)
                run.pop('project', None)
                p['runs'].append(run)
        return p
    @app.get('/api/projects/{pid}/conversion-plan')
    def get_conversion_plan(pid:str,request:Request):
        p=project(request,pid)
        with db() as c:
            c.execute('BEGIN')
            try:
                value = selected_project_plan(c, p)
            except ProjectConversionInputError as error:
                raise HTTPException(422, str(error)) from None
            return history_json_response(value)
    @app.post('/api/projects/{pid}/sources')
    async def upload(pid:str,request:Request,files:list[UploadFile]=File(...),prepared_manifest:UploadFile|None=File(None),
                     expected_current_source_set_id:str|None=Form(None)):
        p=project(request,pid)
        if expected_current_source_set_id is not None and expected_current_source_set_id != 'null' and not re.fullmatch(r'ss-[a-f0-9]{32}', expected_current_source_set_id):
            raise HTTPException(422, 'The expected source version is invalid. Refresh the project.')
        if len(files)>50: raise HTTPException(422,'Add at most 50 files per upload.')
        checked=[];total=0
        try:
            for f in files:
                raw=await f.read(MAX_FILE_BYTES+1);total+=len(raw)
                if total>MAX_PROJECT_BYTES: raise ValueError('Upload exceeds 25 MB.')
                checked.append(checked_source(f.filename or '',raw))
        except ValueError as exc: raise HTTPException(422,str(exc)) from None
        if len({f['name'] for f in checked}) != len(checked): raise HTTPException(422,'Duplicate filenames in upload.')
        prepared = None
        if prepared_manifest is not None:
            try:
                if prepared_manifest.filename != UPLOAD_MANIFEST_NAME:
                    raise ValueError('Select fox-readable-upload.json, not the private extraction manifest.')
                prepared = verify_upload_manifest(await prepared_manifest.read(MAX_MANIFEST_BYTES+1), checked)
            except ValueError as exc:
                raise HTTPException(422, str(exc)) from None
        now=time.time()
        with db() as c:
            c.execute('BEGIN IMMEDIATE')
            if expected_current_source_set_id is not None:
                expected = None if expected_current_source_set_id == 'null' else expected_current_source_set_id
                if source_history.selected_source_set_id(c, pid) != expected:
                    raise source_history.SourceHistoryConflict('Source selection changed.')
            source_history.publish_upload(c, pid, checked, now, p['owner'])
            c.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',(p['owner'],'sources_added',pid,now))
            if prepared is not None:
                # Fingerprint canonical content, not the uploaded JSON's formatting.
                canonical = encode_upload_manifest(prepared)
                digest = hashlib.sha256(canonical).hexdigest()
                c.execute('INSERT OR IGNORE INTO prepared_uploads VALUES(?,?,?,?,?,?,?)',
                          (uuid.uuid4().hex,pid,prepared['extraction_job_id'],prepared['readable_source_hash'],digest,canonical.decode('utf-8'),now))
                receipt = c.execute('SELECT id FROM prepared_uploads WHERE project=? AND canonical_manifest_sha256=?',(pid,digest)).fetchone()
                c.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',(p['owner'],'prepared_sources_verified',receipt['id'],now))
        with db() as c:
            c.execute('BEGIN')
            return source_assessment(current_sources(pid, c), pid, c)
    @app.get('/api/projects/{pid}/assessment')
    def assessment(pid:str,request:Request):
        project(request,pid)
        with db() as c:
            c.execute('BEGIN')
            value = source_assessment(current_sources(pid, c), pid, c)
        return JSONResponse(value,headers={'Content-Disposition':'attachment; filename="fox-assessment.json"'})
    @app.get('/api/projects/{pid}/source-sets')
    def source_sets(pid:str,request:Request,before:str|None=None):
        project(request,pid)
        with db() as c:
            c.execute('BEGIN')
            return history_json_response(source_history.list_source_sets(c, pid, before=before, limit=50))
    @app.get('/api/projects/{pid}/source-sets/{sid}')
    def source_set(pid:str,sid:str,request:Request,files_after:str|None=None):
        project(request,pid)
        with db() as c:
            c.execute('BEGIN')
            value = source_history.source_set_page(c, pid, sid, after=files_after, limit=50)
            value['assessment_summary'] = history_assessment_summary(source_history.source_set_sources(c, pid, sid))
            return history_json_response(value)
    def selection_response(c, pid, sid, changed):
        detail = source_history.source_set_metadata(c, pid, sid)
        selected = detail.pop('selected_source_set_id')
        # This function is called inside the caller's BEGIN IMMEDIATE block.
        # A size error must roll back the selection and audit, not publish a
        # successful write followed by a misleading "no version changed" error.
        return history_json_response({'selected_source_set_id': selected, 'source_set': detail,
                'assessment_summary': history_assessment_summary(current_sources(pid, c)),
                'selection_changed': changed})
    @app.post('/api/projects/{pid}/source-sets/{sid}/select')
    def select_source_set(pid:str,sid:str,body:SourceSelectionInput,request:Request):
        p=project(request,pid)
        with db() as c:
            c.execute('BEGIN IMMEDIATE')
            changed = source_history.select_source_set(c, pid, sid, body.expected_current_source_set_id, time.time(), p['owner'])
            return selection_response(c, pid, sid, changed)
    @app.post('/api/projects/{pid}/source-sets/{sid}/exclude')
    def exclude_source_files(pid:str,sid:str,body:SourceExclusionInput,request:Request):
        p=project(request,pid)
        with db() as c:
            c.execute('BEGIN IMMEDIATE')
            result = source_history.exclude_sources(c, pid, sid, body.excluded_file_ids,
                                                    body.expected_current_source_set_id, time.time(), p['owner'])
            selected = source_history.selected_source_set_id(c, pid)
            return selection_response(c, pid, selected, result['changed'])
    @app.get('/api/projects/{pid}/source-sets/{sid}/download')
    def export_source_set(pid:str,sid:str,request:Request):
        project(request,pid)
        with db() as c:
            c.execute('BEGIN')
            package = source_history.export_source_set(c, pid, sid)
        return Response(package,media_type='application/zip',
                        headers={'Content-Disposition': 'attachment; filename="fox-source-set-'+sid+'.zip"'})
    @app.post('/api/projects/{pid}/runs',status_code=202)
    def submit_run(pid:str,body:RunInput,request:Request):
        p=project(request,pid)
        with db() as c:
            c.execute('BEGIN')
            sources=current_sources(pid, c);inv=source_assessment(sources, pid, c)
        project_plan = None
        if not sources: raise HTTPException(409,'Add readable source files first.')
        if inv['source_hash']!=body.source_hash: raise HTTPException(409,'Sources changed. Review the current assessment.')
        native = inv.get('native_assessment')
        if inv['conversion_profile'] == NATIVE_PROFILE and (not native or native['state'] != 'READY'):
            messages = ' '.join(item['message'] for item in (native or {}).get('blockers', []))
            raise HTTPException(409, messages or 'The native source profile is not ready. Review the assessment.')
        if inv['conversion_profile'] == PROJECT_PROFILE:
            if (body.expected_current_source_set_id is None
                    or body.expected_current_source_set_id != inv['selected_source_set_id']
                    or body.plan_sha256 is None):
                raise HTTPException(409,'The selected source version and project plan are required. Refresh the project before converting.')
            try:
                project_plan = assess_project_conversion(sources, project_id=pid,
                    project_name=p['name'], source_hash=body.source_hash)
            except ProjectConversionInputError as error:
                raise HTTPException(409, str(error)) from None
            if project_plan['plan_sha256'] != body.plan_sha256:
                raise HTTPException(409,'The project plan changed. Review every selected form before converting.')
            if not project_plan['can_generate'] or project_plan['state'] != 'READY':
                raise HTTPException(409,'Resolve the missing inputs, unsupported features or human decisions for every selected form. No partial application will be generated.')
        if not inv['conversion_eligible']:
            raise HTTPException(409,' '.join(item['message'] for item in inv['conversion_blockers']))
        if not all([body.approved_redacted_source,body.approved_external_ai,body.approved_prototype_scope]):
            raise HTTPException(422,'Confirm redaction, AI processing and prototype scope.')
        configuration = configured_conversion()
        if not configuration['conversion_configured']: raise HTTPException(503,'Conversion integration is not ready. Your project is saved; assessment remains available.')
        if (project_plan is not None and project_plan['rendering_spec']['schema_version']
                not in configuration['configured_project_schema_versions']):
            raise HTTPException(503,'Processing these original table names needs the mapped-project workflow configuration. Your sources are saved; no conversion was queued.')
        rid='fox-'+uuid.uuid4().hex[:20];now=time.time()
        with db() as c:
            c.execute('BEGIN IMMEDIATE')
            # Recheck after acquiring the write lock: an upload can have completed
            # between the first assessment and queue creation.
            locked_sources = current_sources(pid, c)
            if inventory(locked_sources)['source_hash'] != body.source_hash:
                raise HTTPException(409,'Sources changed. Review the current assessment.')
            if project_plan is not None:
                if source_history.selected_source_set_id(c, pid) != body.expected_current_source_set_id:
                    raise HTTPException(409,'The selected source version changed. Refresh the project before converting.')
                locked_project = c.execute('SELECT name FROM projects WHERE id=?', (pid,)).fetchone()
                try:
                    locked_plan = assess_project_conversion(locked_sources, project_id=pid,
                        project_name=locked_project['name'], source_hash=body.source_hash)
                except ProjectConversionInputError as error:
                    raise HTTPException(409, str(error)) from None
                if (locked_plan['plan_sha256'] != body.plan_sha256 or not locked_plan['can_generate']
                        or locked_plan != project_plan):
                    raise HTTPException(409,'The project plan changed. Review every selected form before converting.')
            old=c.execute('SELECT id,state FROM runs WHERE project=? AND source_hash=?',(pid,body.source_hash)).fetchone()
            if old:
                saved = root/'jobs'/old['id']/'source-snapshot.json'
                try:
                    old_profile = json.loads(saved.read_text(encoding='utf-8')).get('conversion_profile', LEGACY_PROFILE)
                except (OSError, ValueError, TypeError, AttributeError):
                    raise HTTPException(409,'The existing run requires operator reconciliation; it will not be replaced.') from None
                if old_profile != inv['conversion_profile']:
                    raise HTTPException(409,'This source version already has a run under another conversion profile. Use a separate project; the existing run is preserved.')
                return dict(old)
            from .verification_recovery import VerificationRecovery
            if verifier_config.enabled and not VerificationRecovery(database, enabled=True).admission_allowed(c):
                # The bounded managed workflow serializes conversion through
                # technical verification. This preserves the existing promotion
                # guard requiring no concurrently queued/processing conversions.
                # VERIFIED does not wait for a person's business acceptance.
                raise HTTPException(429,'Another conversion or technical verification is in progress. Your sources are saved; start this run after those technical checks finish.')
            if c.execute("SELECT COUNT(*) FROM runs WHERE state IN ('QUEUED','PROCESSING')").fetchone()[0]>=5: raise HTTPException(429,'Queue is full. Try again after an active job completes.')
            job=root/'jobs'/rid;job.mkdir(parents=True)
            snapshot = {'project':pid,'source_hash':body.source_hash,'files':sources,'inventory':inv,
                        'conversion_profile':inv['conversion_profile'],
                        'approvals':{'redacted_source':True,'external_ai':True,'synthetic_prototype':True,'owner':p['owner'],'approved_at':now}}
            if native is not None:
                snapshot['native_form'] = native['native_form']
            if project_plan is not None:
                snapshot.update(project_id=pid, project_name=project_plan['project_name'],
                    plan_sha256=project_plan['plan_sha256'], native_project=project_plan['rendering_spec'],
                    selected_source_set_id=body.expected_current_source_set_id)
            (job/'source-snapshot.json').write_text(json.dumps(snapshot),encoding='utf-8')
            c.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',(rid,pid,body.source_hash,'QUEUED','Waiting for the conversion worker.',now,now,None))
            c.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',(p['owner'],'approved_conversion',rid,now))
        return {'id':rid,'state':'QUEUED'}
    @app.post('/api/projects/{pid}/runs/{rid}/accept')
    def accept_run(pid:str,rid:str,body:AcceptanceInput,request:Request):
        from .technical_release import checked_release, VerificationError
        p=project(request,pid)
        if not body.business_flow_tested or not body.remediation_reviewed or not body.notes.strip():
            raise HTTPException(422,'Confirm the business test and remediation, and record your test notes.')
        with db() as c:
            c.execute('BEGIN IMMEDIATE')
            r=c.execute('SELECT * FROM runs WHERE id=? AND project=?',(rid,pid)).fetchone()
            if not r or r['state'] not in {'REVIEW_REQUIRED','VERIFIED'} or not r['artifact']:
                raise HTTPException(409,'Technical checks must pass before human acceptance.')
            if r['source_hash'] != body.source_hash or inventory(current_sources(pid, c))['source_hash'] != body.source_hash:
                raise HTTPException(409,'Sources changed. Test and accept the current source version.')
            try:
                technical = checked_release(c, root, dict(r))
            except VerificationError:
                raise HTTPException(409,'Native technical proof is missing or changed. Operator verification is required.') from None
            path=(root/r['artifact']).resolve()
            if root not in path.parents or not path.is_file():
                raise HTTPException(409,'The tested package is unavailable.')
            digest=hashlib.sha256(technical['package'] if technical else path.read_bytes()).hexdigest()
            now=time.time()
            c.execute('INSERT INTO acceptances VALUES(?,?,?,?,?,?)',(rid,p['owner'],body.source_hash,digest,body.notes.strip(),now))
            c.execute("UPDATE runs SET state='ACCEPTED',message='Technical checks passed and human acceptance recorded.',updated=? WHERE id=?",(now,rid))
            c.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',(p['owner'],'human_accepted',rid,now))
        return {'id':rid,'state':'ACCEPTED','artifact_sha256':digest}
    @app.get('/api/projects/{pid}/runs/{rid}/evidence')
    def run_evidence(pid:str,rid:str,request:Request):
        from .technical_release import checked_release, VerificationError
        from .native_verification import _read, _json
        project(request,pid)
        with db() as c:
            row=c.execute('SELECT * FROM runs WHERE id=? AND project=?',(rid,pid)).fetchone()
            if not row or not re.fullmatch(r'fox-[a-f0-9]{20}',rid): raise HTTPException(404,'Run not found.')
            path=root/'jobs'/rid/'release-evidence.json'
            try:
                evidence = _json(_read(path))
            except (VerificationError, OSError):
                raise HTTPException(409,'Release evidence is unavailable or changed. Check the saved run; no new conversion was started.') from None
            # Keep the original package evidence unchanged. Post-package QA is
            # explicitly detached, rather than rewriting the frozen ZIP.
            if row['state'] in {'VERIFIED','ACCEPTED'}:
                try:
                    technical=checked_release(c,root,dict(row))
                except VerificationError:
                    raise HTTPException(409,'Native technical proof is missing or changed. Operator verification is required.') from None
                if technical:
                    evidence={**evidence,'technical_verification':technical['proof']}
        return JSONResponse(evidence,headers={'Content-Disposition':'inline; filename="fox-release-evidence.json"'})
    @app.get('/api/projects/{pid}/runs/{rid}/download')
    def download(pid:str,rid:str,request:Request):
        from .technical_release import checked_release, VerificationError
        project(request,pid)
        with db() as c:
            r=c.execute("SELECT r.*,a.artifact_sha256 FROM runs r JOIN acceptances a ON a.run=r.id "
                        "JOIN projects p ON p.id=r.project WHERE r.id=? AND r.project=? AND r.state='ACCEPTED' "
                        "AND a.owner=p.owner AND a.source_hash=r.source_hash",(rid,pid)).fetchone()
            if not r or not r['artifact']: raise HTTPException(409,'A verified package is not available for this run.')
            try:
                technical=checked_release(c,root,dict(r))
            except VerificationError:
                raise HTTPException(409,'Native technical proof is missing or changed. Download is blocked.') from None
        if technical:
            if hashlib.sha256(technical['package']).hexdigest()!=r['artifact_sha256']:
                raise HTTPException(409,'Package changed after acceptance. Download is blocked.')
            # Send the exact bytes just checked, not a subsequently reopened file.
            return Response(technical['package'],media_type='application/zip',
                            headers={'Content-Disposition':'attachment; filename="'+rid+'-apex.zip"'})
        path=(root/r['artifact']).resolve()
        if root not in path.parents or not path.is_file(): raise HTTPException(404,'Artifact not found.')
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=r['artifact_sha256']:
            raise HTTPException(409,'Package changed after acceptance. Download is blocked.')
        return Response(raw,media_type='application/zip',
                        headers={'Content-Disposition':'attachment; filename="'+rid+'-apex.zip"'})
    if enable_local_preparation:
        # Trusted localhost startup only. Reuse the exact existing session owner
        # check; HTTP requests and environment settings cannot enable this route.
        from .local_preparation import register_local_preparation
        register_local_preparation(app, root, owner, local_preparation_backend, origin=origin)
    dist=Path(__file__).resolve().parent.parent/'dist'
    if dist.is_dir():
        app.mount('/assets',StaticFiles(directory=dist/'assets'),name='assets')
        @app.get('/')
        def ui(): return FileResponse(dist/'index.html')
    return app

app=create_app()
