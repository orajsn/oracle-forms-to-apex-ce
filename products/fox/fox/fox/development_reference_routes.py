"""One exact same-run development reference continuation; no generic retry."""
import json
import time

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, StrictBool

from . import source_history
from .native_pipeline import _save_once
from .opaf import OpafError, canonical_hash
from .prototype_job import read_prototype_snapshot, validate_prototype_snapshot
from .source_processing_policy import current_processing_approval
from . import prototype_development_reference_resume as resume


class ReferenceResumeInput(BaseModel):
    model_config = {'extra': 'forbid'}
    plan_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    approved_source_reference_correction: StrictBool


def attach(app, *, root, db, project, current_sources, target_reader, followup=False):
    if followup:
        from . import prototype_development_reference_followup as protocol
    else:
        protocol = resume
    operation = 'development-reference-followup' if followup else 'development-reference-resume'
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
        recorded = protocol.validate_owner(job, snapshot, original, c)
        if not followup:
            from .prototype_development_reference_followup import validate_owner as validate_followup_owner
            validate_followup_owner(job, snapshot, original, c)
        if recorded is not None:
            technical = protocol.technical(job / 'prototype-pipeline')
            return row, job, snapshot, original, technical['plan'], recorded
        if row['state'] != 'ATTENTION' or row['artifact'] is not None:
            raise OpafError('Only the exact stopped first-mapper outcome can continue.')
        plan = protocol.inspect(job, snapshot, original, target['target_profile'])
        return row, job, snapshot, original, plan, None

    def response(row, plan, recorded):
        return {'project_id': plan['project_id'], 'run_id': plan['job_id'],
                'state': row['state'], 'eligible': recorded is None,
                'continuation_recorded': recorded is not None,
                'plan_sha256': canonical_hash(plan), 'source_hash': plan['source_hash'],
                'reference_corrections': plan['projection_claim_count'],
                'repeated_mapper_calls': 0, 'business_behavior_accepted': False,
                'reason': ('The continuation is already recorded. Check this run; it will not be queued again.'
                           if recorded is not None else
                           'Resolve exact source references, independently review the saved mapping, then continue only unstarted sections. The original mapper result stays unchanged.')}

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
            raise HTTPException(409, 'No exact source-reference continuation is available. Retained and uncertain outcomes are preserved.') from None

    @app.post(f'/api/projects/{{pid}}/prototype-runs/{{rid}}/{operation}', status_code=202)
    def submit_resume(pid: str, rid: str, body: ReferenceResumeInput, request: Request):
        owner = project(request, pid)['owner']
        if body.approved_source_reference_correction is not True:
            raise HTTPException(422, 'Explicit approval of the exact source-reference correction is required.')
        try:
            with db() as c:
                c.execute('BEGIN IMMEDIATE')
                row, job, snapshot, original, plan, recorded = checked(c, pid, rid, owner)
                if body.plan_sha256 != canonical_hash(plan):
                    raise OpafError('Reference continuation plan changed.')
                if recorded is not None:
                    value = response(row, plan, recorded)
                    value['already_recorded'] = True
                    return JSONResponse(value, status_code=202, headers={'Cache-Control': 'no-store'})
                if c.execute("SELECT 1 FROM runs WHERE state IN ('QUEUED','PROCESSING') LIMIT 1").fetchone():
                    raise HTTPException(429, 'Another conversion is active. The saved result is preserved.')
                now = time.time()
                technical, authorization = protocol.records(plan, owner, now)
                paths = (job / 'prototype-pipeline' / protocol.TECHNICAL, job / protocol.OWNER_RECORD)
                if any(path.exists() or path.is_symlink() for path in paths):
                    raise OpafError('An existing continuation requires reconciliation.')
                _save_once(paths[0], technical)
                _save_once(paths[1], authorization)
                if read_prototype_snapshot(job)[1] != original:
                    raise OpafError('Original source snapshot changed.')
                changed = c.execute("UPDATE runs SET state='QUEUED',message=?,updated=? WHERE id=? AND project=? AND state='ATTENTION' AND artifact IS NULL",
                    ('Reviewing exact source references in the saved mapping; completed model calls are retained.', now, rid, pid))
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
            raise HTTPException(409, 'Source-reference continuation was not confirmed. Inspect the retained record before any further action; no model call was replayed.') from None
