"""Authenticated project admission for the explicit native prototype workflow."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import time
import uuid

from fastapi import HTTPException, Request, UploadFile, File, Form
from pydantic import BaseModel, Field, StrictBool

from . import source_history
from .intake import inventory, MAX_FILE_BYTES
from .partial_draft import saved_draft_scope
from .opaf import OpafError
from .prototype_admission import (PROFILE_ID, describe_prototype_sources,
                                  prepare_prototype_admission)


class PrototypeRunInput(BaseModel):
    source_hash: str = Field(pattern=r'^[0-9a-f]{64}$')
    source_binding: str = Field(pattern=r'^[0-9a-f]{64}$')
    expected_current_source_set_id: str = Field(min_length=1, max_length=128)
    target_profile_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    approved_chunk_hashes: dict[str, str] = Field(max_length=4096)
    approved_redacted_source: StrictBool
    approved_external_ai: StrictBool
    approved_prototype_scope: StrictBool


def source_documents(sources):
    documents = []
    for source in sources:
        raw = source['text'].encode('utf-8')
        if hashlib.sha256(raw).hexdigest() != source['sha256']:
            raw = b'\xef\xbb\xbf' + raw
        if hashlib.sha256(raw).hexdigest() != source['sha256']:
            raise ValueError('Stored source bytes do not match their original hash.')
        documents.append((source['name'], raw))
    return documents


def configured_target():
    # Separate opt-in profile: never modify or reinterpret the legacy profile.
    from .prototype_job import load_prototype_profile
    path = os.environ.get('FOX_PROTOTYPE_PROFILE_FILE', '')
    if not path:
        raise ValueError('Prototype workflow is not configured.')
    return load_prototype_profile(Path(path))


def attach_prototype_project_routes(app, *, root, db, project, current_sources,
                                    admission_allowed, target_reader=configured_target):
    def target_hash():
        try:
            envelope = target_reader()
            digest = envelope['target_profile_sha256']
            if not isinstance(digest, str) or len(digest) != 64:
                raise ValueError('Invalid target binding.')
            return digest
        except (ValueError, OSError, KeyError, TypeError, ImportError, OpafError):
            raise HTTPException(503, 'The prototype workflow is not configured. Your source files remain saved.') from None

    @app.post('/api/projects/{pid}/prototype-sources')
    async def upload_redacted_prototype(pid: str, request: Request,
            files: list[UploadFile] = File(...), receipts: list[UploadFile] = File(...),
            expected_current_source_set_id: str = Form(...)):
        p = project(request, pid)
        if not 1 <= len(files) <= 4 or len(receipts) != len(files):
            raise HTTPException(422, 'Choose one to four redacted Forms XML files and one redaction receipt for each.')
        try:
            from .prototype_source import validate_redacted_prototype_source
            def unique_pairs(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError('Duplicate receipt property.')
                    result[key] = value
                return result
            receipt_map = {}
            for upload in receipts:
                name = upload.filename or ''
                if not name.endswith('.redaction.json'):
                    raise ValueError('Receipt filename must be XML filename plus .redaction.json.')
                source_name = name[:-len('.redaction.json')]
                raw = await upload.read(2_000_001)
                if len(raw) > 2_000_000 or source_name in receipt_map:
                    raise ValueError('Duplicate or oversized receipt.')
                value = json.loads(raw, object_pairs_hook=unique_pairs,
                                   parse_constant=lambda value: (_ for _ in ()).throw(ValueError('Nonfinite receipt value.')))
                receipt_map[source_name] = value
            checked, provenance = [], []
            for upload in files:
                name = upload.filename or ''
                receipt = receipt_map.pop(name)
                source = validate_redacted_prototype_source(name, await upload.read(MAX_FILE_BYTES + 1), receipt)
                canonical = json.dumps(receipt, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
                checked.append(source)
                provenance.append((source, canonical, hashlib.sha256(canonical.encode('utf-8')).hexdigest()))
            if receipt_map or len({row['name'] for row in checked}) != len(checked):
                raise ValueError('Source and receipt membership differ.')
        except (ValueError, KeyError, TypeError, ImportError, RecursionError):
            raise HTTPException(422, 'The redacted Forms files or matching receipts could not be verified. Prepare them locally again; no original source was replaced.') from None
        with db() as c:
            c.execute('BEGIN IMMEDIATE')
            selected = source_history.selected_source_set_id(c, pid)
            expected = None if expected_current_source_set_id == 'null' else expected_current_source_set_id
            if selected != expected:
                raise HTTPException(409, 'Source selection changed. Refresh the project before uploading.')
            if saved_draft_scope(c, pid, inventory(current_sources(pid, c))['source_hash']) is not None:
                raise HTTPException(409, 'Return to the original source version before adding prepared files.')
            now = time.time()
            for source, receipt_json, digest in provenance:
                existing = c.execute('SELECT receipt_sha256,owner FROM source_redaction_receipts WHERE project=? AND name=? AND sha256=?',
                                     (pid, source['name'], source['sha256'])).fetchone()
                if existing:
                    if existing['receipt_sha256'] != digest or existing['owner'] != p['owner']:
                        raise HTTPException(409, 'Different provenance is already retained for this exact source. Ask the operator to reconcile it.')
                else:
                    c.execute('INSERT INTO source_redaction_receipts VALUES(?,?,?,?,?,?,?)',
                              (pid, source['name'], source['sha256'], receipt_json, digest, p['owner'], now))
            published = source_history.publish_upload(c, pid, checked, now, p['owner'])
            c.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
                      (p['owner'], 'redacted_prototype_sources_added', pid, now))
            selected = source_history.selected_source_set_id(c, pid)
            digest = inventory(current_sources(pid, c))['source_hash']
        return {'source_hash': digest, 'selected_source_set_id': selected,
                'changed': published['changed'], 'processing_approved': False,
                'message': 'Redacted analysis-only Forms source saved. Review scope and permissions before processing.'}

    @app.get('/api/projects/{pid}/prototype-assessment')
    def prototype_assessment(pid: str, request: Request):
        project(request, pid)
        with db() as c:
            c.execute('BEGIN')
            sources = current_sources(pid, c)
            selected = source_history.selected_source_set_id(c, pid)
            try:
                result = describe_prototype_sources(source_documents(sources))
            except (ValueError, KeyError, TypeError):
                raise HTTPException(409, 'Select valid, redacted Forms XML files for prototype assessment. Original files are preserved.') from None
            result.update(source_hash=inventory(sources)['source_hash'], selected_source_set_id=selected)
        try:
            result.update(target_profile_sha256=target_hash(), conversion_configured=True)
        except HTTPException:
            result.update(target_profile_sha256=None, conversion_configured=False)
        return result

    @app.post('/api/projects/{pid}/prototype-runs', status_code=202)
    def submit_prototype(pid: str, body: PrototypeRunInput, request: Request):
        p = project(request, pid)
        digest = target_hash()
        if digest != body.target_profile_sha256:
            raise HTTPException(409, 'The processing destination changed. Review the prototype assessment again.')
        with db() as c:
            c.execute('BEGIN IMMEDIATE')
            sources = current_sources(pid, c)
            inv = inventory(sources)
            if (inv['source_hash'] != body.source_hash or
                    source_history.selected_source_set_id(c, pid) != body.expected_current_source_set_id):
                raise HTTPException(409, 'The selected source version changed. Review it before converting.')
            saved_draft_scope(c, pid, body.source_hash)
            try:
                admission = prepare_prototype_admission(source_documents(sources),
                    expected_source_binding=body.source_binding,
                    approved_chunk_hashes=body.approved_chunk_hashes,
                    target_profile_sha256=digest,
                    approved_redacted_source=body.approved_redacted_source,
                    approved_external_ai=body.approved_external_ai,
                    approved_prototype_scope=body.approved_prototype_scope)
            except (ValueError, KeyError, TypeError):
                raise HTTPException(409, 'Source approval is missing or changed. Review the exact files, code selection and processing permissions again.') from None
            old = c.execute('SELECT id,state FROM runs WHERE project=? AND source_hash=?', (pid, body.source_hash)).fetchone()
            if old:
                # Never create a second charged execution or overwrite earlier proof.
                raise HTTPException(409, 'This source version already has a conversion run. Open that run; it has not been restarted or replaced.')
            if not admission_allowed(c):
                raise HTTPException(429, 'Another conversion or verification requires completion. Your source files are saved.')
            if c.execute("SELECT COUNT(*) FROM runs WHERE state IN ('QUEUED','PROCESSING')").fetchone()[0] >= 5:
                raise HTTPException(429, 'The conversion queue is full. Try again after an active run finishes.')
            locked = c.execute('SELECT owner,name FROM projects WHERE id=?', (pid,)).fetchone()
            if not locked or locked['owner'] != p['owner']:
                raise HTTPException(409, 'Project ownership changed. Refresh the project.')
            now = time.time()
            rid = 'fox-' + uuid.uuid4().hex[:20]
            snapshot = {'project': pid, 'project_id': pid, 'project_name': locked['name'],
                'source_hash': body.source_hash, 'conversion_profile': PROFILE_ID,
                'selected_source_set_id': body.expected_current_source_set_id,
                'files': sources, 'prototype': admission['prototype'],
                'approvals': {'redacted_source': True, 'external_ai': True,
                              'synthetic_prototype': True, 'owner': p['owner'], 'approved_at': now}}
            raw = json.dumps(snapshot, ensure_ascii=False, allow_nan=False).encode('utf-8')
            if len(raw) > 20_000_000:
                raise HTTPException(413, 'The selected source version exceeds the prototype job limit.')
            job = root / 'jobs' / rid
            if (root / 'jobs').is_symlink():
                raise HTTPException(503, 'Job storage requires operator attention.')
            job.mkdir(parents=True)
            with (job / 'source-snapshot.json').open('xb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            c.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
                      (rid, pid, body.source_hash, 'QUEUED', 'Waiting for source-bound prototype analysis.', now, now, None))
            c.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
                      (p['owner'], 'approved_prototype_conversion', rid, now))
        return {'id': rid, 'state': 'QUEUED', 'conversion_profile': PROFILE_ID,
                'summary': admission['summary']}
