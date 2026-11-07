"""Read-only converter callback backed by current FOX ownership and originals.

This is not a portable grant or user approval endpoint. Keep normal application
Origin middleware; enabling it requires explicit trusted startup configuration.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit

from fastapi import Request
from starlette.responses import JSONResponse

from . import source_history
from .opaf import canonical_hash
from .prototype_job import (load_prototype_profile, read_prototype_snapshot,
                            validate_prototype_snapshot)
from .prototype_pipeline import (CONVERTER_STAGES, _check_converter_receipt,
                                 authorize_prototype_request)

AUTHORITY_PATH = '/api/internal/prototype/authorize'
MAX_REQUEST_BYTES = 2_000_000
RESPONSE_SCOPE = 'fox-prototype-current-authority-v1'


def execution_target(profile):
    """Wire v1 projection; mirrored in converter client, parity-tested.

    OPAF workflow identity and conversion design scope are not SQLcl destinations.
    SQLcl still independently applies its full allowlisted target preflight.
    """
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
            raise ValueError('Duplicate JSON key')
        value[key] = item
    return value


def _json(raw):
    return json.loads(raw, object_pairs_hook=_unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))


def _origin(value):
    if not isinstance(value, str):
        raise ValueError('Exact HTTPS authority origin required')
    url = urlsplit(value)
    if (url.scheme != 'https' or not url.hostname or url.port not in (None, 443)
            or url.username or url.password or url.path or url.query or url.fragment
            or any(c.isspace() for c in value) or value != value.rstrip('/')):
        raise ValueError('Exact HTTPS authority origin required')
    return value


def _protected_token(path):
    path = Path(path)
    if (path.is_symlink() or not path.is_file() or path.stat().st_size > 65_536
            or (os.name != 'nt' and stat.S_IMODE(path.stat().st_mode) & 0o077)):
        raise ValueError('Protected converter credential unavailable')
    token = _json(path.read_bytes()).get('converter_token')
    if (not isinstance(token, str) or not 16 <= len(token) <= 8192
            or any(ord(c) < 33 or ord(c) > 126 for c in token)):
        raise ValueError('Protected converter credential invalid')
    return token


def _profile(path):
    path = Path(path)
    if (path.is_symlink() or not path.is_file() or path.stat().st_size > 65_536
            or (os.name != 'nt' and stat.S_IMODE(path.stat().st_mode) & 0o022)):
        raise ValueError('Protected prototype profile unavailable')
    raw = path.read_bytes()
    value = _json(raw)
    envelope = load_prototype_profile(path)
    if envelope != value or path.read_bytes() != raw:
        raise ValueError('Prototype profile changed while reading')
    execution_target(envelope['target_profile'])
    return envelope


def _retained_request(job, request):
    """Match ordered prior receipts; no caller-authored stage progression."""
    fields = {'schema_version', 'scope', 'job_id', 'project_id', 'source_binding', 'plan_sha256',
              'rendering_spec', 'rendered_zip_sha256', 'source_authority', 'prior_receipts'}
    prior = request.get('prior_receipts')
    if (set(request) != fields or type(request['schema_version']) is not int
            or request['schema_version'] != 1 or request['scope'] != 'fox-prototype-converter-request-v1'
            or type(prior) is not dict or len(prior) >= len(CONVERTER_STAGES)
            or set(prior) != set(CONVERTER_STAGES[:len(prior)])):
        raise ValueError('Unsupported stage request')
    root = job / 'prototype-pipeline'
    previous = {}
    for stage in CONVERTER_STAGES[:len(prior)]:
        previous_request = {**request, 'prior_receipts': dict(previous)}
        path = root / (stage + '.json')
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_REQUEST_BYTES:
            raise ValueError('Retained prior receipt unavailable')
        receipt = _check_converter_receipt(stage, previous_request, _json(path.read_bytes()))
        intent = root / (stage + '-intent.json')
        if (receipt != prior[stage] or receipt.get('status') != 'COMPLETE'
                or receipt.get('business_behavior_accepted') is not False
                or intent.is_symlink() or not intent.is_file() or intent.stat().st_size > 1024
                or _json(intent.read_bytes()) != {'request_sha256': canonical_hash(previous_request)}):
            raise ValueError('Retained prior receipt differs from request')
        previous[stage] = receipt
    stage = CONVERTER_STAGES[len(prior)]
    intent = root / (stage + '-intent.json')
    if intent.exists() or intent.is_symlink():
        if (intent.is_symlink() or not intent.is_file() or intent.stat().st_size > 1024
                or _json(intent.read_bytes()) != {'request_sha256': canonical_hash(request)}):
            raise ValueError('Retained current stage intent differs from request')


def authorize_current(root, db, profile_path, request):
    """No writes, model calls, SQLcl, HTTP or request-selected filesystem paths."""
    if not isinstance(request, dict) or not re.fullmatch(r'fox-[a-f0-9]{20}', request.get('job_id', '')):
        raise ValueError('Invalid job')
    root = Path(root)
    jobs = root / 'jobs'
    job = jobs / request['job_id']
    if root.is_symlink() or jobs.is_symlink() or not jobs.is_dir() or job.is_symlink():
        raise ValueError('Unsafe private job root')
    snapshot, original = read_prototype_snapshot(job)
    _json(original)  # Reject ambiguous duplicate/nonfinite original JSON too.
    documents = validate_prototype_snapshot(snapshot)
    if (request.get('project_id') != snapshot['project_id']
            or request.get('source_binding') != snapshot['prototype']['source_binding']):
        raise ValueError('Snapshot binding mismatch')

    def current():
        envelope = _profile(profile_path)
        if envelope['target_profile_sha256'] != snapshot['prototype']['target_profile_sha256']:
            raise ValueError('Prototype destination changed')
        with db() as c:
            # This connection is exclusively owned by this callback. Enforce
            # read-only SQLite even when the application factory normally writes.
            c.execute('PRAGMA query_only=ON')
            c.execute('BEGIN')
            row = c.execute('SELECT p.owner,r.project,r.source_hash,r.state FROM runs r '
                            'JOIN projects p ON p.id=r.project WHERE r.id=?', (job.name,)).fetchone()
            if (not row or row['owner'] != snapshot['approvals']['owner']
                    or row['state'] not in ('PROCESSING', 'GENERATED')
                    or row['project'] != snapshot['project_id']
                    or row['source_hash'] != snapshot['source_hash']
                    or source_history.selected_source_set_id(c, row['project']) != snapshot['selected_source_set_id']):
                raise ValueError('Owner or selection changed')
            sources = source_history.selected_sources(c, row['project'])
            if (source_history._hash(sources) != snapshot['source_hash']
                    or [(row['name'], source_history.readable_source_bytes(row)) for row in sources] != documents):
                raise ValueError('Current source bytes changed')
        if read_prototype_snapshot(job)[1] != original:
            raise ValueError('Original snapshot changed')
        return envelope, row['state']

    envelope, state = current()
    # Bind historical model identities too, rather than trusting transferred
    # reviewer manifests which contain no current owner/synthetic consent.
    binding_path = job / 'prototype-pipeline' / 'binding.json'
    if binding_path.is_symlink() or not binding_path.is_file() or binding_path.stat().st_size > 65_536:
        raise ValueError('Retained binding unavailable')
    binding = _json(binding_path.read_bytes())
    if (binding.get('profile_sha256') != canonical_hash(envelope['target_profile']['opaf']['roles'])
            or binding.get('focus_plan_sha256') != snapshot['prototype']['focus_plan_sha256']):
        raise ValueError('Reviewed roles or focus changed')
    authorize_prototype_request(job, request)
    # Current DB/event authority additionally rechecks the operator's fixed
    # outside-job clause pins when an explicit epoch three is active. The
    # converter's copied descriptor is never an independent consent grant.
    _retained_request(job, request)
    from .prototype_mapping_epochs import converter_phase
    from .prototype_mapping_continuation import validate_job_continuation
    phase = converter_phase(job, snapshot, original, CONVERTER_STAGES[len(request['prior_receipts'])], request)
    validate_job_continuation(job, snapshot, original, phase=phase)
    if state == 'GENERATED':
        # A finished run authorizes only the exact retained export request,
        # never a new stage/action or a caller's substitute prior receipts.
        from .prototype_download import retained_export_request
        retained, _ = retained_export_request(job, snapshot, envelope)
        if retained != request:
            raise ValueError('Generated run only authorizes its retained export')
    envelope, final_state = current()  # Fresh read after reconstruction.
    if final_state != state:
        raise ValueError('Prototype state changed during authorization')
    return {'schema_version': 1, 'scope': RESPONSE_SCOPE, 'request_sha256': canonical_hash(request),
            'job_id': job.name, 'project_id': snapshot['project_id'],
            'source_binding': snapshot['prototype']['source_binding'],
            'target_profile_sha256': envelope['target_profile_sha256'],
            'execution_target_sha256': canonical_hash(execution_target(envelope['target_profile']))}


def attach_prototype_authority(app, *, root, db, enabled=False, profile_path=None,
                               credential_path=None, allowed_origin=None):
    """Attach only when opted in. No credential reads at import/disabled startup."""
    if enabled is not True:
        return False
    origin = _origin(allowed_origin)
    if not profile_path or not credential_path:
        raise ValueError('Explicit authority profile and protected credential paths required')
    _profile(profile_path)

    @app.post(AUTHORITY_PATH, include_in_schema=False)
    async def authorize(request: Request):
        headers = {'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'}
        authorization = request.headers.get('authorization', '')
        if (len(request.headers.getlist('authorization')) != 1 or not authorization.startswith('Bearer ')
                or not 16 <= len(authorization[7:]) <= 8192):
            return JSONResponse({'detail': 'Unauthorized'}, 401, headers=headers)
        if request.headers.getlist('origin') != [origin]:
            return JSONResponse({'detail': 'Request origin is not allowed.'}, 403, headers=headers)
        try:
            # Normal application/fresh-admission middleware has already run.
            # Never cache a credential through rotation or read it while fenced.
            token = await asyncio.to_thread(_protected_token, credential_path)
        except (ValueError, OSError, KeyError, TypeError, AttributeError):
            return JSONResponse({'detail': 'Prototype authority credential is unavailable.'}, 503, headers=headers)
        if not hmac.compare_digest(authorization.encode(), ('Bearer ' + token).encode()):
            return JSONResponse({'detail': 'Unauthorized'}, 401, headers=headers)
        try:
            raw = bytearray()
            async for chunk in request.stream():
                if len(raw) + len(chunk) > MAX_REQUEST_BYTES:
                    return JSONResponse({'detail': 'Authority request too large'}, 413, headers=headers)
                raw.extend(chunk)
            value = _json(raw)
            result = await asyncio.to_thread(authorize_current, root, db, profile_path, value)
            return JSONResponse(result, headers=headers)
        except (ValueError, TypeError, KeyError, AttributeError, OSError, RuntimeError,
                RecursionError, OverflowError):
            return JSONResponse({'detail': 'Current prototype authority could not be verified. No operation was retried.'},
                                409, headers=headers)
    return True
