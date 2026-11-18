"""Compile one fully reviewed retained design with exact source-block screen inheritance."""
import json
import time

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, StrictBool

from . import source_history
from .provider_reexecution_routes import _private, _create
from .opaf import OpafError, canonical_hash
from .prototype_job import read_prototype_snapshot, validate_prototype_snapshot
from .source_processing_policy import current_processing_approval
from . import prototype_compiler_continuation as protocol


class CompilerContinuationInput(BaseModel):
    model_config = {'extra': 'forbid'}
    plan_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    approved_compiler_completion: StrictBool


def attach(app, *, root, db, project, current_sources, target_reader):
    operation = 'development-compiler-continuation'
    def checked(c, pid, rid, owner):
        row = c.execute('SELECT * FROM runs WHERE id=? AND project=?', (rid, pid)).fetchone()
        if not row:
            raise HTTPException(404, 'Prototype run not found.')
        job = root / 'jobs' / rid
        if (root / 'jobs').is_symlink() or job.is_symlink():
            raise OpafError('Unsafe continuation storage.')
        snapshot, original = read_prototype_snapshot(job)
        validate_prototype_snapshot(snapshot)
        selected = snapshot['prototype']
        locked = c.execute('SELECT owner FROM projects WHERE id=?', (pid,)).fetchone()
        sources = current_sources(pid, c)
        if (not locked or locked['owner'] != owner or snapshot['approvals']['owner'] != owner
                or snapshot['project_id'] != pid or snapshot['project'] != pid
                or row['source_hash'] != snapshot['source_hash']
                or source_history._hash(sources) != snapshot['source_hash']
                or source_history.selected_source_set_id(c, pid) != snapshot['selected_source_set_id']
                or selected.get('processing_mode') != 'development'
                or selected.get('delivery_mode') != 'apexlang_package'
                or 'chunk_evidence_policy' in selected
                or not current_processing_approval(c, snapshot, rid, sources)):
            raise OpafError('Original development source approval is no longer current.')
        target = target_reader()
        if (target['target_profile_sha256'] != selected['target_profile_sha256']
                or canonical_hash(target['target_profile']) != selected['target_profile_sha256']):
            raise OpafError('The original processing destination changed.')
        from .prototype_prose_continuation import validate_owner as validate_provider_owner
        if validate_provider_owner(job, snapshot, original, c) is None:
            raise OpafError('The preserved reviewed-prose authority is unavailable.')
        recorded = protocol.validate_owner(job, snapshot, original, c)
        if recorded is not None:
            technical = protocol.technical(job / 'prototype-pipeline')
            return row, job, snapshot, original, technical['plan'], recorded
        if row['state'] != 'ATTENTION' or row['artifact'] is not None:
            raise OpafError('Only the exact stopped fully reviewed outcome can continue.')
        plan = protocol.inspect(job, snapshot, original, target['target_profile'])
        return row, job, snapshot, original, plan, None

    def response(row, plan, recorded):
        return {'project_id': plan['project_id'], 'run_id': plan['job_id'],
                'state': row['state'], 'eligible': recorded is None,
                'continuation_recorded': recorded is not None,
                'plan_sha256': canonical_hash(plan), 'source_hash': plan['source_hash'],
                'completed_item_links': plan['completion_count'],
                'repeated_mapper_calls': 0, 'new_model_calls': 0, 'business_behavior_accepted': False,
                'reason': ('The continuation is already recorded. Check this run; it will not be queued again.'
                           if recorded is not None else
                           'Complete only the exact source-block screen links during compilation, then validate and package. All original AI responses and reviews stay unchanged; no model call is permitted.')}

    @app.get(f'/api/projects/{{pid}}/prototype-runs/{{rid}}/{operation}')
    def inspect_resume(pid: str, rid: str, request: Request):
        owner = project(request, pid)['owner']
        try:
            with db() as c:
                c.execute('BEGIN')
                row, job, snapshot, original, plan, recorded = checked(c, pid, rid, owner)
                return JSONResponse(response(row, plan, recorded), headers={'Cache-Control': 'no-store'})
        except HTTPException:
            raise
        except (OpafError, ValueError, TypeError, KeyError, OSError):
            raise HTTPException(409, 'No exact retained compiler continuation is available. Retained and uncertain outcomes are preserved.') from None

    @app.post(f'/api/projects/{{pid}}/prototype-runs/{{rid}}/{operation}', status_code=202)
    def submit_resume(pid: str, rid: str, body: CompilerContinuationInput, request: Request):
        owner = project(request, pid)['owner']
        if body.approved_compiler_completion is not True:
            raise HTTPException(422, 'Explicit approval of the exact exact deterministic compiler completion is required.')
        try:
            with db() as c:
                c.execute('BEGIN IMMEDIATE')
                row, job, snapshot, original, plan, recorded = checked(c, pid, rid, owner)
                if body.plan_sha256 != canonical_hash(plan):
                    raise OpafError('Compiler continuation plan changed.')
                if recorded is not None:
                    value = response(row, plan, recorded)
                    value['already_recorded'] = True
                    return JSONResponse(value, status_code=202, headers={'Cache-Control': 'no-store'})
                if c.execute("SELECT 1 FROM runs WHERE state IN ('QUEUED','PROCESSING') LIMIT 1").fetchone():
                    raise HTTPException(429, 'Another conversion is active. The saved result is preserved.')
                now = time.time()
                authorization = protocol.records(plan, owner, now)
                path = protocol.path(job)
                if path.exists() or path.is_symlink():
                    raise OpafError('An existing continuation requires reconciliation.')
                _private(path.parent.parent)
                _private(path.parent)
                _create(path, authorization)
                if read_prototype_snapshot(job)[1] != original:
                    raise OpafError('Original source snapshot changed.')
                changed = c.execute("UPDATE runs SET state='QUEUED',message=?,updated=? WHERE id=? AND project=? AND state='ATTENTION' AND artifact IS NULL",
                    ('Reviewing exact deterministic compiler completion in the saved mapping; completed model calls are retained.', now, rid, pid))
                if changed.rowcount != 1:
                    raise OpafError('Stopped run state changed.')
                c.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
                    (owner, protocol.EVENT, rid + ':' + canonical_hash(authorization), now))
                protocol.validate_owner(job, snapshot, original, c)
                value = response({'state': 'QUEUED'}, plan, authorization)
                value['already_recorded'] = False
            return JSONResponse(value, status_code=202, headers={'Cache-Control': 'no-store'})
        except HTTPException:
            raise
        except (OpafError, ValueError, TypeError, KeyError, OSError):
            raise HTTPException(409, 'Compiler continuation was not confirmed. Inspect the retained record before any further action; no model call was replayed.') from None
