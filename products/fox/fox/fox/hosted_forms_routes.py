"""Authenticated raw-FMB preparation, separate from AI and database execution."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import time

from fastapi import File, Form, HTTPException, Request, UploadFile

from . import source_history
from .extractor import MAX_RAW_BYTES, safe_name
from .intake import inventory
from .partial_draft import saved_draft_scope


def attach_hosted_forms_routes(app, *, db, project, current_sources, queue=None):
    """The public process only stages bytes and adopts validated host results.

    The Oracle Home, process executor and host credentials are never available
    to these routes. A trusted operator configures the private shared directory.
    """
    if queue is None and os.environ.get('FOX_HOSTED_FORMS_QUEUE'):
        from .hosted_forms_jobs import HostedFormsJobs
        queue = HostedFormsJobs(Path(os.environ['FOX_HOSTED_FORMS_QUEUE']))

    def available():
        if queue is None:
            raise HTTPException(503, 'Server-side Forms preparation is not enabled. Your project is unchanged.')
        return queue

    def binding(c, pid, owner):
        locked = c.execute('SELECT owner FROM projects WHERE id=?', (pid,)).fetchone()
        if not locked or locked['owner'] != owner:
            raise HTTPException(409, 'Project ownership changed. Refresh the project.')
        return (source_history.selected_source_set_id(c, pid),
                inventory(current_sources(pid, c))['source_hash'])

    @app.get('/api/projects/{pid}/native-preparations')
    def preparations(pid: str, request: Request):
        p = project(request, pid)
        if queue is None:
            return {'enabled': False, 'formats': [], 'jobs': [], 'model_processing_started': False}
        try:
            jobs = queue.list_jobs(project_id=pid, owner_id=p['owner'])
        except (ValueError, OSError):
            raise HTTPException(503, 'Saved preparation jobs need operator attention. Nothing was restarted.') from None
        return {'enabled': True, 'formats': ['.fmb'], 'jobs': jobs,
                'max_file_bytes': MAX_RAW_BYTES, 'model_processing_started': False}

    @app.post('/api/projects/{pid}/native-preparations', status_code=202)
    async def submit(pid: str, request: Request, file: UploadFile = File(...),
                     request_id: str = Form(...), expected_current_source_set_id: str = Form(...)):
        p = project(request, pid)
        q = available()
        if expected_current_source_set_id != 'null' and not re.fullmatch(r'ss-[a-f0-9]{32}', expected_current_source_set_id):
            raise HTTPException(422, 'The expected source version is invalid. Refresh the project.')
        raw = await file.read(MAX_RAW_BYTES + 1)
        # Only errors proven before queue writes are definitive rejections.
        try:
            safe_name(file.filename or '')
            safe_name(request_id)
            if (Path(file.filename or '').suffix.lower() != '.fmb'
                    or not 1 <= len(raw) <= MAX_RAW_BYTES
                    or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}', request_id)):
                raise ValueError('Invalid FMB input.')
        except ValueError:
            raise HTTPException(422, 'Choose one FMB up to 20 MiB with a safe filename and a new request identifier.') from None
        with db() as c:
            c.execute('BEGIN IMMEDIATE')
            selected, digest = binding(c, pid, p['owner'])
            expected = None if expected_current_source_set_id == 'null' else expected_current_source_set_id
            if selected != expected:
                raise HTTPException(409, 'Source selection changed. Refresh before uploading the FMB.')
            if saved_draft_scope(c, pid, digest) is not None:
                raise HTTPException(409, 'Return to the original source version before adding files.')
            try:
                result = q.submit(request_id=request_id, project_id=pid, owner_id=p['owner'],
                                  source_set_sha256=digest, selected_source_set_id=selected,
                                  name=file.filename or '', raw=raw)
            except (ValueError, OSError):
                raise HTTPException(503, 'The preparation submission outcome needs confirmation. Keep this request identifier, check its status, and do not upload it again.') from None
            # Submission is idempotent in the queue; the event is recorded once.
            if not c.execute('SELECT 1 FROM events WHERE owner=? AND action=? AND object_id=?',
                             (p['owner'], 'native_preparation_submitted', request_id)).fetchone():
                c.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
                          (p['owner'], 'native_preparation_submitted', request_id, time.time()))
        return result

    @app.get('/api/projects/{pid}/native-preparations/{jid}')
    def status(pid: str, jid: str, request: Request):
        p = project(request, pid)
        try:
            return available().status(jid, project_id=pid, owner_id=p['owner'])
        except (ValueError, OSError):
            raise HTTPException(404, 'Preparation job is unavailable for this project. Nothing was restarted.') from None

    @app.post('/api/projects/{pid}/native-preparations/{jid}/adopt')
    def adopt(pid: str, jid: str, request: Request):
        p = project(request, pid)
        q = available()
        try:
            job_status = q.status(jid, project_id=pid, owner_id=p['owner'])
        except (ValueError, OSError):
            raise HTTPException(404, 'Preparation job is unavailable for this project.') from None
        with db() as c:
            c.execute('BEGIN IMMEDIATE')
            selected, digest = binding(c, pid, p['owner'])
            if c.execute('SELECT 1 FROM events WHERE owner=? AND action=? AND object_id=?',
                         (p['owner'], 'native_preparation_adopted', jid)).fetchone():
                # A lost response never causes a second source publication.
                try:
                    prior = q.read_result(jid, project_id=pid, owner_id=p['owner'],
                                          source_set_sha256=job_status['source_set_sha256'],
                                          selected_source_set_id=job_status['selected_source_set_id'])['document']
                except (ValueError, OSError, KeyError, TypeError):
                    raise HTTPException(409, 'The earlier preparation evidence needs operator reconciliation. Nothing was republished.') from None
                if not any(s['name'] == prior['name'] and s['sha256'] == prior['sha256'] for s in current_sources(pid, c)):
                    raise HTTPException(409, 'This prepared form was already added to a different saved source version. Select that version in source history; the current selection was not changed.')
                return {'adopted': True, 'already_adopted': True, 'source_hash': digest,
                        'selected_source_set_id': selected, 'processing_approved': False}
            if saved_draft_scope(c, pid, digest) is not None:
                raise HTTPException(409, 'Return to the original source version before adding prepared files.')
            try:
                result = q.read_result(jid, project_id=pid, owner_id=p['owner'],
                                       source_set_sha256=digest, selected_source_set_id=selected)
                source, receipt = result['document'], result['receipt']
                # Revalidate at publication, even though the private reader did so.
                from .prototype_source import validate_redacted_prototype_source
                source = validate_redacted_prototype_source(source['name'], source['text'].encode('utf-8'), receipt)
                canonical = json.dumps(receipt, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
                receipt_hash = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
            except (ValueError, OSError, KeyError, TypeError):
                raise HTTPException(409, 'Preparation is incomplete, changed, or belongs to a different source version. Check its status; no files were replaced.') from None
            existing = c.execute('SELECT receipt_sha256,owner FROM source_redaction_receipts WHERE project=? AND name=? AND sha256=?',
                                 (pid, source['name'], source['sha256'])).fetchone()
            if existing and (existing['receipt_sha256'] != receipt_hash or existing['owner'] != p['owner']):
                raise HTTPException(409, 'Different provenance is already retained for this source. Ask the operator to reconcile it.')
            now = time.time()
            if not existing:
                c.execute('INSERT INTO source_redaction_receipts VALUES(?,?,?,?,?,?,?)',
                          (pid, source['name'], source['sha256'], canonical, receipt_hash, p['owner'], now))
            source_history.publish_upload(c, pid, [source], now, p['owner'])
            c.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
                      (p['owner'], 'native_preparation_adopted', jid, now))
            selected, digest = binding(c, pid, p['owner'])
        return {'adopted': True, 'already_adopted': False, 'source_hash': digest,
                'selected_source_set_id': selected, 'processing_approved': False}
