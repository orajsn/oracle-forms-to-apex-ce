"""Authenticated project admission for the explicit native prototype workflow."""
from __future__ import annotations

import hashlib
from copy import deepcopy
import json
import os
import sqlite3
from pathlib import Path
import time
import uuid

from fastapi import HTTPException, Request, UploadFile, File, Form
from fastapi.responses import Response
from pydantic import BaseModel, Field, StrictBool, StrictInt

from . import source_history
from .intake import inventory, MAX_FILE_BYTES
from .partial_draft import saved_draft_scope
from .opaf import OpafError, canonical_hash
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


class PrototypeContinuationInput(PrototypeRunInput):
    checkpoint_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')


class PrototypeEpochInput(PrototypeContinuationInput):
    expected_epoch_number: StrictInt = Field(ge=1, le=1000000)
    expected_predecessor_sha256: str = Field(pattern=r'^[0-9a-f]{64}$')
    expected_clause_proof_sha256: str | None = Field(default=None, pattern=r'^[0-9a-f]{64}$')
    expected_container_proof_sha256: str | None = Field(default=None, pattern=r'^[0-9a-f]{64}$')
    expected_partition_proof_sha256: str | None = Field(default=None, pattern=r'^[0-9a-f]{64}$')


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
                                    admission_allowed, target_reader=configured_target,
                                    installation_projection=None, download_client_factory=None):
    def target_hash():
        try:
            envelope = target_reader()
            digest = envelope['target_profile_sha256']
            if not isinstance(digest, str) or len(digest) != 64:
                raise ValueError('Invalid target binding.')
            return digest
        except (ValueError, OSError, KeyError, TypeError, ImportError, OpafError):
            raise HTTPException(503, 'The prototype workflow is not configured. Your source files remain saved.') from None

    def generated_prototype(pid: str, rid: str, request: Request, *, metadata_only=False):
        from .prototype_download import configured_download_client, retained_export_request
        from .prototype_job import read_prototype_snapshot, validate_prototype_snapshot
        from .prototype_transport import PrototypeHttpConverterAdapter
        from .prototype_read_scope import epoch_read_scope
        import re
        import zipfile
        p = project(request, pid)  # Authentication and owner check precede all job reads.
        if not re.fullmatch(r'fox-[a-f0-9]{20}', rid):
            raise HTTPException(404, 'Prototype run not found.')
        job = root / 'jobs' / rid
        try:
            if (root / 'jobs').is_symlink():
                raise OpafError('Unsafe prototype storage.')
            snapshot, original = read_prototype_snapshot(job)
            validate_prototype_snapshot(snapshot)
            def current():
                owner = project(request, pid)['owner']
                with db() as c:
                    c.execute('BEGIN')
                    run = c.execute('SELECT * FROM runs WHERE id=? AND project=?', (rid, pid)).fetchone()
                    if not run:
                        raise HTTPException(404, 'Prototype run not found.')
                    locked = c.execute('SELECT owner FROM projects WHERE id=?', (pid,)).fetchone()
                    if (not locked or locked['owner'] != owner or owner != p['owner']
                            or snapshot['approvals']['owner'] != owner
                            or snapshot['project_id'] != pid or snapshot['project'] != pid
                            or run['state'] != 'GENERATED' or run['artifact'] is not None
                            or run['source_hash'] != snapshot['source_hash']
                            or inventory(current_sources(pid, c))['source_hash'] != snapshot['source_hash']
                            or source_history.selected_source_set_id(c, pid) != snapshot['selected_source_set_id']):
                        raise OpafError('Prototype owner, source selection or run is no longer current.')
                    from .prototype_mapping_epochs import validate_epoch_chain
                    validate_epoch_chain(job, snapshot, original, c)
                target = target_reader()
                if target['target_profile_sha256'] != snapshot['prototype']['target_profile_sha256']:
                    raise OpafError('Prototype target changed.')
                if read_prototype_snapshot(job)[1] != original:
                    raise OpafError('Prototype snapshot changed.')
                return target
            with epoch_read_scope(job / 'prototype-pipeline'):
                target = current()
                export_request, receipt = retained_export_request(job, snapshot, target)
                if metadata_only:
                    current()
            if metadata_only:
                # Local retained-proof projection only. This does not fetch a
                # package, execute a stage, or claim a clean reimport passed.
                return Response(json.dumps({
                    'schema_version': 1, 'scope': 'fox-generated-prototype-output-v1',
                    'project_id': pid, 'run_id': rid,
                    'source_hash': snapshot['source_hash'],
                    'selected_source_set_id': snapshot['selected_source_set_id'],
                    'source_binding': snapshot['prototype']['source_binding'],
                    'status': 'APEX_GENERATED',
                    'download_path': f'/api/projects/{pid}/prototype-runs/{rid}/download',
                    'business_behavior_accepted': False,
                    'clean_schema_install_passed': False,
                    'package_reimport_passed': False,
                }), media_type='application/json', headers={'Cache-Control': 'no-store'})
            factory = download_client_factory or configured_download_client
            client = factory(snapshot['prototype']['target_profile_sha256'],
                             installation_projection=installation_projection)
            raw = PrototypeHttpConverterAdapter(job, client).read_package(export_request, receipt)
            # Recheck after HTTP, so a source/owner/profile change cannot serve
            # an export selected using stale authorization.
            with epoch_read_scope(job / 'prototype-pipeline'):
                retained_export_request(job, snapshot, current())
            return Response(raw, media_type='application/zip', headers={
                'Content-Disposition': f'attachment; filename="{rid}-generated-prototype.zip"',
                'X-FOX-Output-Scope': 'generated-synthetic-prototype-not-business-accepted',
                'X-Content-SHA256': hashlib.sha256(raw).hexdigest(),
                'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff'})
        except HTTPException:
            raise
        except (ValueError, KeyError, TypeError, AttributeError, ImportError, OSError,
                RuntimeError, zipfile.BadZipFile):
            raise HTTPException(409, 'Generated prototype export is unavailable or its retained source, permission or technical proof could not be verified. No operation was retried.') from None

    @app.get('/api/projects/{pid}/prototype-runs/{rid}/output')
    def generated_prototype_output(pid: str, rid: str, request: Request):
        return generated_prototype(pid, rid, request, metadata_only=True)

    @app.get('/api/projects/{pid}/prototype-runs/{rid}/download')
    def download_generated_prototype(pid: str, rid: str, request: Request):
        return generated_prototype(pid, rid, request)

    def recovery_context(c, pid, rid, owner):
        from .prototype_job import read_prototype_snapshot, validate_prototype_snapshot
        from .prototype_mapping_recovery import RUN_ID, mapping_recovery_proof, retry_run_id, STRATEGY
        if not RUN_ID.fullmatch(rid):
            raise HTTPException(404, 'Prototype run not found.')
        run = c.execute('SELECT * FROM runs WHERE id=? AND project=?', (rid, pid)).fetchone()
        if not run:
            raise HTTPException(404, 'Prototype run not found.')
        if (root / 'jobs').is_symlink():
            raise ValueError('Unsafe mapping-recovery storage.')
        snapshot, original = read_prototype_snapshot(root / 'jobs' / rid)
        documents = validate_prototype_snapshot(snapshot)
        locked = c.execute('SELECT owner FROM projects WHERE id=?', (pid,)).fetchone()
        sources = current_sources(pid, c)
        if (not locked or locked['owner'] != owner or snapshot['approvals']['owner'] != owner
                or snapshot['project_id'] != pid or snapshot['project'] != pid
                or run['state'] != 'ATTENTION' or run['artifact'] is not None
                or run['source_hash'] != snapshot['source_hash']
                or inventory(sources)['source_hash'] != snapshot['source_hash']
                or source_documents(sources) != documents
                or source_history.selected_source_set_id(c, pid) != snapshot['selected_source_set_id']
                or c.execute('SELECT 1 FROM acceptances WHERE run=?', (rid,)).fetchone()
                or not c.execute('SELECT 1 FROM events WHERE owner=? AND action=? AND object_id=?',
                    (owner, 'approved_prototype_conversion', rid)).fetchone()):
            raise ValueError('Mapping-recovery permission or current source is stale.')
        target = target_reader()
        if canonical_hash(target['target_profile']) != target['target_profile_sha256']:
            raise ValueError('Mapping-recovery target changed.')
        proof, retained_target = mapping_recovery_proof(root / 'jobs' / rid, snapshot, original)
        current_target = target['target_profile']
        role_only = deepcopy(retained_target)
        role_only['opaf']['roles'] = deepcopy(current_target['opaf']['roles'])
        if (canonical_hash(role_only) != target['target_profile_sha256'] or any(
                current_target['opaf']['roles'][name]['model'] != retained_target['opaf']['roles'][name]['model']
                for name in ('mapper', 'reviewer'))):
            raise ValueError('Mapping-recovery execution destination or model changed.')
        selected = snapshot['prototype']
        if len(selected['approved_chunk_hashes']) > 4096:
            raise ValueError('Mapping-recovery selection exceeds the admission bound.')
        admission = prepare_prototype_admission(documents,
            expected_source_binding=selected['source_binding'],
            approved_chunk_hashes=selected['approved_chunk_hashes'],
            target_profile_sha256=target['target_profile_sha256'],
            approved_redacted_source=True, approved_external_ai=True,
            approved_prototype_scope=True, schema_version=2)
        child_id = retry_run_id(rid)
        child = c.execute('SELECT * FROM runs WHERE id=?', (child_id,)).fetchone()
        child_job = root / 'jobs' / child_id
        exists = child_job.exists() or child_job.is_symlink()
        if bool(child) != exists:
            raise ValueError('Orphan mapping-recovery state requires reconciliation.')
        others = c.execute('SELECT id FROM runs WHERE project=? AND source_hash=?',
                           (pid, snapshot['source_hash'])).fetchall()
        if any(row['id'] not in (rid, child_id) for row in others):
            raise ValueError('Unrecognized same-source execution requires reconciliation.')
        digest = hashlib.sha256(original).hexdigest()
        metadata = {'schema_version': 1, 'strategy': STRATEGY, 'parent_snapshot_sha256': digest}
        if child:
            saved, child_raw = read_prototype_snapshot(child_job)
            validate_prototype_snapshot(saved)
            expected = deepcopy(snapshot)
            expected.update(retry_of=rid, mapping_recovery=metadata, prototype=admission['prototype'])
            expected['approvals']['approved_at'] = saved['approvals']['approved_at']
            if (canonical_hash(saved) != canonical_hash(expected) or child['project'] != pid or child['source_hash'] != snapshot['source_hash']
                    or child['state'] not in ('QUEUED', 'PROCESSING', 'ATTENTION', 'GENERATED')
                    or child['artifact'] is not None
                    or c.execute('SELECT COUNT(*) FROM events WHERE owner=? AND action=? AND object_id=?',
                        (owner, 'approved_prototype_mapping_retry', child_id)).fetchone()[0] != 1):
                raise ValueError('Existing mapping-recovery child differs from its approved parent.')
            # Never interpret an uncertain outcome as permission to submit a
            # second execution, even when the previous HTTP response was lost.
            for path in child_job.rglob('*'):
                if path.is_symlink():
                    raise ValueError('Unsafe existing mapping-recovery child.')
                if path.name.endswith('-intent.json') and not path.with_name(
                        path.name.replace('-intent.json', '.json')).is_file():
                    raise ValueError('Existing mapping-recovery outcome is uncertain.')
            if read_prototype_snapshot(child_job)[1] != child_raw:
                raise ValueError('Existing mapping-recovery child changed.')
            proof.update(eligible=False, reason='A mapping retry already exists. Open that run; it has not been restarted.')
        if read_prototype_snapshot(root / 'jobs' / rid)[1] != original:
            raise ValueError('Mapping-recovery parent changed.')
        projection = {'schema_version': 1, 'scope': 'fox-prototype-mapping-recovery-v1',
            'project_id': pid, 'run_id': rid, 'source_hash': snapshot['source_hash'],
            'source_binding': selected['source_binding'],
            'selected_source_set_id': snapshot['selected_source_set_id'],
            'target_profile_sha256': target['target_profile_sha256'],
            'parent_target_profile_sha256': selected['target_profile_sha256'],
            'target_profile_changed': target['target_profile_sha256'] != selected['target_profile_sha256'],
            'approved_chunk_hashes': dict(selected['approved_chunk_hashes']),
            'parent_snapshot_sha256': digest, 'strategy': STRATEGY,
            'existing_retry_run_id': child_id if child else None, **proof}
        return projection, snapshot, original, admission, child_id, child, metadata

    recovery_errors = (ValueError, KeyError, TypeError, AttributeError, OSError,
                       RuntimeError, ImportError, RecursionError, OverflowError)

    @app.get('/api/projects/{pid}/prototype-runs/{rid}/mapping-recovery')
    def inspect_mapping_recovery(pid: str, rid: str, request: Request):
        p = project(request, pid)  # Owner check precedes every filesystem read.
        try:
            with db() as c:
                c.execute('BEGIN')
                projection = recovery_context(c, pid, rid, p['owner'])[0]
            return Response(json.dumps(projection), media_type='application/json',
                            headers={'Cache-Control': 'no-store'})
        except HTTPException:
            raise
        except recovery_errors:
            raise HTTPException(409, 'Mapping recovery is unavailable because the current source, permission or retained first-mapper proof is unsafe, stale or needs reconciliation. No operation was retried.') from None

    @app.post('/api/projects/{pid}/prototype-runs/{rid}/retry-mapping', status_code=202)
    def retry_mapping(pid: str, rid: str, body: PrototypeRunInput, request: Request):
        from .native_pipeline import _sync
        p = project(request, pid)
        try:
            with db() as c:
                c.execute('BEGIN IMMEDIATE')
                projection, parent, original, admission, child_id, child, metadata = recovery_context(c, pid, rid, p['owner'])
                selected = parent['prototype']
                if (body.source_hash != parent['source_hash']
                        or body.source_binding != selected['source_binding']
                        or body.expected_current_source_set_id != parent['selected_source_set_id']
                        or body.target_profile_sha256 != projection['target_profile_sha256']
                        or body.approved_chunk_hashes != selected['approved_chunk_hashes']
                        or not all(value is True for value in (body.approved_redacted_source,
                            body.approved_external_ai, body.approved_prototype_scope))):
                    raise ValueError('Exact parent scope and explicit approvals are required.')
                result = {'id': child_id, 'state': child['state'] if child else 'QUEUED',
                          'conversion_profile': PROFILE_ID, 'summary': admission['summary'], 'retry_of': rid}
                if child:
                    return Response(json.dumps(result), status_code=200, media_type='application/json',
                                    headers={'Cache-Control': 'no-store'})
                if not projection['eligible']:
                    raise ValueError('This run is not eligible for bounded mapping recovery.')
                if not admission_allowed(c):
                    raise HTTPException(429, 'Another conversion or verification requires completion. Your existing run is preserved.')
                if c.execute("SELECT COUNT(*) FROM runs WHERE state IN ('QUEUED','PROCESSING')").fetchone()[0] >= 5:
                    raise HTTPException(429, 'The conversion queue is full. Your existing run is preserved.')
                snapshot = deepcopy(parent)
                snapshot.update(retry_of=rid, mapping_recovery=metadata, prototype=admission['prototype'])
                now = time.time()
                snapshot['approvals']['approved_at'] = now
                raw = json.dumps(snapshot, ensure_ascii=False, allow_nan=False).encode('utf-8')
                if len(raw) > 20_000_000:
                    raise HTTPException(413, 'The source-bound retry exceeds the prototype job limit.')
                # Any partial filesystem write is preserved. A lost/failed DB
                # commit leaves an orphan that the next request must block.
                job = root / 'jobs' / child_id
                job.mkdir()
                with (job / 'source-snapshot.json').open('xb') as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                _sync(job)
                _sync(job.parent)
                if (root / 'jobs' / rid / 'source-snapshot.json').read_bytes() != original:
                    raise ValueError('Mapping-recovery parent changed before queueing.')
                c.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)', (child_id, pid, parent['source_hash'],
                    'QUEUED', 'Waiting for explicit smaller-batch mapping recovery.', now, now, None))
                c.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
                          (p['owner'], 'approved_prototype_mapping_retry', child_id, now))
            return Response(json.dumps(result), status_code=202, media_type='application/json',
                            headers={'Cache-Control': 'no-store'})
        except HTTPException:
            raise
        except recovery_errors:
            raise HTTPException(409, 'Mapping recovery was not queued: exact source approval, eligible first-mapper proof or prior retry state could not be verified. The original run is preserved; uncertain operations were not replayed.') from None

    def continuation_context(c, pid, rid, owner):
        from .prototype_job import read_prototype_snapshot, validate_prototype_snapshot
        from .prototype_mapping_recovery import RUN_ID
        from .prototype_mapping_continuation import inspect_continuation, continuation_event_id, RECORD, EVENT, SCOPE
        if not RUN_ID.fullmatch(rid):
            raise HTTPException(404, 'Prototype run not found.')
        run = c.execute('SELECT * FROM runs WHERE id=? AND project=?', (rid, pid)).fetchone()
        if not run:
            raise HTTPException(404, 'Prototype run not found.')
        if (root / 'jobs').is_symlink():
            raise ValueError('Unsafe continuation storage.')
        job = root / 'jobs' / rid
        snapshot, original = read_prototype_snapshot(job)
        documents = validate_prototype_snapshot(snapshot)
        selected, sources = snapshot['prototype'], current_sources(pid, c)
        locked = c.execute('SELECT owner FROM projects WHERE id=?', (pid,)).fetchone()
        target = target_reader()
        if (not locked or locked['owner'] != owner or snapshot['approvals']['owner'] != owner
                or snapshot['project_id'] != pid or snapshot['project'] != pid
                or run['state'] not in ('ATTENTION', 'QUEUED', 'PROCESSING', 'GENERATED') or run['artifact'] is not None
                or run['source_hash'] != snapshot['source_hash']
                or inventory(sources)['source_hash'] != snapshot['source_hash'] or source_documents(sources) != documents
                or source_history.selected_source_set_id(c, pid) != snapshot['selected_source_set_id']
                or target['target_profile_sha256'] != selected['target_profile_sha256']
                or canonical_hash(target['target_profile']) != selected['target_profile_sha256']
                or len(selected['approved_chunk_hashes']) > 4096):
            raise ValueError('Continuation owner, source, selection or target is no longer current.')
        origin = 'approved_prototype_mapping_retry' if 'retry_of' in snapshot else 'approved_prototype_conversion'
        original_events = c.execute('SELECT owner,created FROM events WHERE action=? AND object_id=?', (origin, rid)).fetchall()
        if (len(original_events) != 1 or original_events[0]['owner'] != owner
                or original_events[0]['created'] != snapshot['approvals']['approved_at']):
            raise ValueError('Continuation has no exact original source-owner admission event.')
        tables = {row[0] for row in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for table, column in (('verification_queue', 'job_id'), ('verification_failed_dispositions', 'job_id'),
                ('verification_retry_attempts', 'job_id'), ('verification_precheck_failures', 'job_id'),
                ('verification_qa_stage_failures', 'job_id'), ('verification_project_prewrite_failures', 'job_id'),
                ('technical_verifications', 'run'), ('acceptances', 'run')):
            if table in tables and c.execute('SELECT 1 FROM ' + table + ' WHERE ' + column + '=? LIMIT 1', (rid,)).fetchone():
                raise ValueError('Verification or acceptance history conflicts with mapping continuation.')
        events = c.execute('SELECT owner,object_id,created FROM events WHERE action=? AND '
            '(object_id=? OR object_id LIKE ?)', (EVENT, rid, rid + ':%')).fetchall()
        recorded = (job / RECORD).exists() or (job / RECORD).is_symlink()
        if bool(events) != recorded or (not recorded and run['state'] != 'ATTENTION'):
            raise ValueError('Continuation state is orphaned or not terminal.')
        proof, closure = inspect_continuation(job, snapshot, original, target['target_profile'])
        if recorded:
            from .native_pipeline import _json
            record = _json(job / RECORD)
            if (len(events) != 1 or events[0]['owner'] != owner or events[0]['created'] != record['approved_at']
                    or events[0]['object_id'] != continuation_event_id(rid, record)):
                raise ValueError('Continuation event does not bind its exclusive durable record.')
        if read_prototype_snapshot(job)[1] != original:
            raise ValueError('Continuation source snapshot changed.')
        projection = {'schema_version': 1, 'scope': SCOPE, 'project_id': pid, 'run_id': rid,
            'source_hash': snapshot['source_hash'], 'source_binding': selected['source_binding'],
            'selected_source_set_id': snapshot['selected_source_set_id'],
            'target_profile_sha256': selected['target_profile_sha256'],
            'approved_chunk_hashes': dict(selected['approved_chunk_hashes']),
            'strategy': 'resolve-code-unit-owners-v1', **proof}
        return projection, snapshot, original, closure, run

    @app.get('/api/projects/{pid}/prototype-runs/{rid}/mapping-continuation')
    def mapping_continuation(pid: str, rid: str, request: Request):
        p = project(request, pid)
        try:
            with db() as c:
                c.execute('BEGIN')
                projection = continuation_context(c, pid, rid, p['owner'])[0]
            return Response(json.dumps(projection), media_type='application/json', headers={'Cache-Control': 'no-store'})
        except HTTPException:
            raise
        except recovery_errors:
            raise HTTPException(409, 'Mapping continuation is unavailable: current approval or the exact retained checkpoint could not be verified. No operation was replayed.') from None

    @app.post('/api/projects/{pid}/prototype-runs/{rid}/continue-mapping', status_code=202)
    def continue_mapping(pid: str, rid: str, body: PrototypeContinuationInput, request: Request):
        from .native_pipeline import _save_once
        from .prototype_mapping_continuation import RECORD, EVENT, SCOPE, continuation_event_id
        p = project(request, pid)
        try:
            with db() as c:
                c.execute('BEGIN IMMEDIATE')
                projection, snapshot, original, closure, run = continuation_context(c, pid, rid, p['owner'])
                if (body.checkpoint_sha256 != projection['checkpoint_sha256']
                        or body.source_hash != projection['source_hash'] or body.source_binding != projection['source_binding']
                        or body.expected_current_source_set_id != projection['selected_source_set_id']
                        or body.target_profile_sha256 != projection['target_profile_sha256']
                        or body.approved_chunk_hashes != projection['approved_chunk_hashes']
                        or not all(value is True for value in (body.approved_redacted_source,
                            body.approved_external_ai, body.approved_prototype_scope))):
                    raise ValueError('Exact checkpoint and three fresh processing consents are required.')
                result = {'id': rid, 'state': run['state'] if projection['continuation_recorded'] else 'QUEUED',
                          'conversion_profile': PROFILE_ID, 'continued': True}
                if projection['continuation_recorded']:
                    return Response(json.dumps(result), status_code=200, media_type='application/json', headers={'Cache-Control': 'no-store'})
                if not projection['eligible']:
                    raise ValueError('This checkpoint is not eligible for continuation.')
                if not admission_allowed(c):
                    raise HTTPException(429, 'Other unresolved work blocks continuation. This run has not been restarted.')
                now = time.time()
                record = {'schema_version': 1, 'scope': SCOPE, 'strategy': projection['strategy'],
                    'job_id': rid, 'project_id': pid, 'snapshot_sha256': hashlib.sha256(original).hexdigest(),
                    'checkpoint_sha256': body.checkpoint_sha256, 'files': closure,
                    **{key: projection[key] for key in ('completed_focuses', 'blocked_focus_id', 'resolved_claim_owners')},
                    'owner': p['owner'], 'approved_at': now,
                    'approvals': {'redacted_source': True, 'external_ai': True, 'synthetic_prototype': True}}
                _save_once(root / 'jobs' / rid / RECORD, record)
                if (root / 'jobs' / rid / 'source-snapshot.json').read_bytes() != original:
                    raise ValueError('Immutable continuation source changed.')
                changed = c.execute("UPDATE runs SET state='QUEUED',message=?,updated=? WHERE id=? AND state='ATTENTION' AND artifact IS NULL",
                    ('Continuing from the retained source-bound mapping checkpoint.', now, rid))
                if changed.rowcount != 1:
                    raise ValueError('Continuation run state changed before queueing.')
                c.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
                          (p['owner'], EVENT, continuation_event_id(rid, record), now))
            return Response(json.dumps(result), status_code=202, media_type='application/json', headers={'Cache-Control': 'no-store'})
        except HTTPException:
            raise
        except (*recovery_errors, sqlite3.Error):
            raise HTTPException(409, 'Continuation was not queued: checkpoint approval or durable state could not be verified. Original outcomes remain preserved; uncertain operations were not replayed.') from None

    def epoch_context(c, pid, rid, owner):
        from .prototype_job import read_prototype_snapshot, validate_prototype_snapshot
        from .prototype_mapping_recovery import RUN_ID
        from .prototype_mapping_epochs import inspect_next_epoch, SCOPE, STRATEGY, NUMBER
        if not RUN_ID.fullmatch(rid):
            raise HTTPException(404, 'Prototype run not found.')
        run = c.execute('SELECT * FROM runs WHERE id=? AND project=?', (rid, pid)).fetchone()
        if not run:
            raise HTTPException(404, 'Prototype run not found.')
        if (root / 'jobs').is_symlink():
            raise ValueError('Unsafe epoch storage.')
        job = root / 'jobs' / rid
        snapshot, original = read_prototype_snapshot(job)
        documents = validate_prototype_snapshot(snapshot)
        selected, sources = snapshot['prototype'], current_sources(pid, c)
        locked = c.execute('SELECT owner FROM projects WHERE id=?', (pid,)).fetchone()
        target = target_reader()
        if (not locked or locked['owner'] != owner or snapshot['approvals']['owner'] != owner
                or snapshot['project_id'] != pid or snapshot['project'] != pid
                or run['state'] not in ('ATTENTION', 'QUEUED', 'PROCESSING', 'GENERATED') or run['artifact'] is not None
                or run['source_hash'] != snapshot['source_hash'] or inventory(sources)['source_hash'] != snapshot['source_hash']
                or source_documents(sources) != documents
                or source_history.selected_source_set_id(c, pid) != snapshot['selected_source_set_id']
                or target['target_profile_sha256'] != selected['target_profile_sha256']
                or canonical_hash(target['target_profile']) != selected['target_profile_sha256']
                or len(selected['approved_chunk_hashes']) > 4096):
            raise ValueError('Epoch source, selected version, owner or target changed.')
        origin = 'approved_prototype_mapping_retry' if 'retry_of' in snapshot else 'approved_prototype_conversion'
        events = c.execute('SELECT owner,created FROM events WHERE action=? AND object_id=?', (origin, rid)).fetchall()
        if len(events) != 1 or events[0]['owner'] != owner or events[0]['created'] != snapshot['approvals']['approved_at']:
            raise ValueError('Epoch run has no exact source-owner origin event.')
        tables = {row[0] for row in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for table, column in (('verification_queue', 'job_id'), ('verification_failed_dispositions', 'job_id'),
                ('verification_retry_attempts', 'job_id'), ('verification_precheck_failures', 'job_id'),
                ('verification_qa_stage_failures', 'job_id'), ('verification_project_prewrite_failures', 'job_id'),
                ('technical_verifications', 'run'), ('acceptances', 'run')):
            if table in tables and c.execute('SELECT 1 FROM ' + table + ' WHERE ' + column + '=? LIMIT 1', (rid,)).fetchone():
                raise ValueError('Later verification or acceptance work conflicts with this epoch.')
        plan, before, record, checkpoint, predecessor = inspect_next_epoch(job, snapshot, original, target['target_profile'], c)
        from . import prototype_clause_epoch as clause
        from . import prototype_container_epoch as container
        from . import prototype_partition_review_epoch as partition
        number = (partition.NUMBER if 'partition_proof_sha256' in plan else container.NUMBER if 'container_proof_sha256' in plan
            else clause.NUMBER if 'clause_proof_sha256' in plan else NUMBER)
        if record is None and run['state'] != 'ATTENTION':
            raise ValueError('Only a known terminal checkpoint can start this epoch.')
        if read_prototype_snapshot(job)[1] != original:
            raise ValueError('Epoch source snapshot changed during inspection.')
        public_fields = ('ai_approved_focuses', 'source_checked_focuses', 'repair_focus_id', 'projection_focus_id',
            'source_fact_violations', 'planned_corrective_operations', 'remaining_focus_count', 'continue_remaining_run')
        projection = {'schema_version': 1, 'scope': SCOPE, 'project_id': pid, 'run_id': rid,
            'source_hash': snapshot['source_hash'], 'source_binding': selected['source_binding'],
            'selected_source_set_id': snapshot['selected_source_set_id'], 'target_profile_sha256': selected['target_profile_sha256'],
            'approved_chunk_hashes': dict(selected['approved_chunk_hashes']), 'epoch_number': number,
            'predecessor_sha256': predecessor, 'checkpoint_sha256': checkpoint, 'eligible': record is None,
            'reason': ('The next epoch repairs unsupported clause facts and reviews the exact projection, then continues the remaining selected sections.'
                if record is None else 'This epoch is already recorded. Open the same run; no operation was replayed.'),
            'epoch_recorded': record is not None, **{key: plan[key] for key in public_fields}}
        if number == clause.NUMBER:
            projection.update(strategy=clause.STRATEGY, expected_clause_proof_sha256=plan['clause_proof_sha256'],
                **{key: plan[key] for key in ('new_clause_analysis_calls', 'repeated_clause_review_calls',
                    'corrective_projection_review_calls', 'analysis_role')})
            if record is None:
                projection['reason'] = ('Reuse the retained approved clause diagnostic without new clause analysis or repeat clause review; '
                    'review the adjacent technical projection once, then continue the remaining sections of this same run.')
        if number == container.NUMBER:
            projection.update(strategy=container.STRATEGY, expected_container_proof_sha256=plan['container_proof_sha256'],
                **{key: plan[key] for key in ('container_corrections', 'new_container_review_calls',
                    'repeated_root_mapper_calls', 'repeated_projection_mapper_calls', 'corrective_projection_review_calls')})
            if record is None:
                projection['reason'] = ('Reuse the retained independently approved container correction and clause proof without '
                    'repeating root mapping, root review or projection mapping; review the unchanged projection once with '
                    'validated screen and ancestor context, then continue the remaining sections of this same run.')
        if number == partition.NUMBER:
            projection.update(strategy=partition.STRATEGY, expected_partition_proof_sha256=plan['partition_proof_sha256'],
                **{key: plan[key] for key in ('reused_review_focuses', 'new_corrective_model_calls',
                    'repeated_mapper_calls', 'repeated_reviewer_calls')})
            if record is None:
                projection['reason'] = ('Reuse the completed independent review and unchanged mapping, then continue the remaining '
                    'sections of this same run without repeating mapping or review. Validation and import remain pending.')
        return projection, snapshot, original, plan, before, record, run

    @app.get('/api/projects/{pid}/prototype-runs/{rid}/mapping-epochs/next')
    def next_mapping_epoch(pid: str, rid: str, request: Request):
        p = project(request, pid)
        try:
            with db() as c:
                c.execute('BEGIN')
                projection = epoch_context(c, pid, rid, p['owner'])[0]
            return Response(json.dumps(projection), media_type='application/json', headers={'Cache-Control': 'no-store'})
        except HTTPException:
            raise
        except recovery_errors:
            raise HTTPException(409, 'The next mapping epoch is unavailable: exact source, consent, predecessor or terminal proof could not be verified. No operation was replayed.') from None

    @app.post('/api/projects/{pid}/prototype-runs/{rid}/mapping-epochs', status_code=202)
    def submit_mapping_epoch(pid: str, rid: str, body: PrototypeEpochInput, request: Request):
        from .prototype_mapping_epochs import RECORD, PREFIX, EVENT, SCOPE, STRATEGY, NUMBER, POLICY, event_id, save, read
        p = project(request, pid)
        try:
            with db() as c:
                c.execute('BEGIN IMMEDIATE')
                projection, snapshot, original, plan, before, record, run = epoch_context(c, pid, rid, p['owner'])
                from . import prototype_clause_epoch as clause
                from . import prototype_container_epoch as container
                from . import prototype_partition_review_epoch as partition
                clause_epoch = projection['epoch_number'] == clause.NUMBER
                container_epoch = projection['epoch_number'] == container.NUMBER
                partition_epoch = projection['epoch_number'] == partition.NUMBER
                if (body.expected_epoch_number != projection['epoch_number']
                        or body.expected_predecessor_sha256 != projection['predecessor_sha256']
                        or body.checkpoint_sha256 != projection['checkpoint_sha256']
                        or body.source_hash != projection['source_hash'] or body.source_binding != projection['source_binding']
                        or body.expected_current_source_set_id != projection['selected_source_set_id']
                        or body.target_profile_sha256 != projection['target_profile_sha256']
                        or body.approved_chunk_hashes != projection['approved_chunk_hashes']
                        or body.expected_clause_proof_sha256 != projection.get('expected_clause_proof_sha256')
                        or body.expected_container_proof_sha256 != projection.get('expected_container_proof_sha256')
                        or body.expected_partition_proof_sha256 != projection.get('expected_partition_proof_sha256')
                        or not all(value is True for value in (body.approved_redacted_source, body.approved_external_ai, body.approved_prototype_scope))):
                    raise ValueError('Epoch needs the exact plan and three fresh source-processing consents.')
                result = {'id': rid, 'state': run['state'] if record else 'QUEUED', 'conversion_profile': PROFILE_ID,
                          'continued': True, 'epoch_number': projection['epoch_number']}
                if record:
                    return Response(json.dumps(result), status_code=200, media_type='application/json', headers={'Cache-Control': 'no-store'})
                if not admission_allowed(c):
                    raise HTTPException(429, 'Other unresolved work blocks this epoch. Existing outcomes remain preserved.')
                now = time.time()
                record = {'schema_version': 1, 'scope': SCOPE,
                    'strategy': partition.STRATEGY if partition_epoch else container.STRATEGY if container_epoch else clause.STRATEGY if clause_epoch else STRATEGY, 'epoch_number': projection['epoch_number'],
                    'predecessor_sha256': projection['predecessor_sha256'], 'checkpoint_sha256': projection['checkpoint_sha256'],
                    'job_id': rid, 'project_id': pid, 'snapshot_sha256': hashlib.sha256(original).hexdigest(),
                    'source_hash': snapshot['source_hash'], 'source_binding': snapshot['prototype']['source_binding'],
                    'target_profile_sha256': snapshot['prototype']['target_profile_sha256'], 'owner': p['owner'], 'approved_at': now,
                    'approvals': {'redacted_source': True, 'external_ai': True, 'synthetic_prototype': True},
                    'before_files': before, 'plan': plan, 'normalization_policy': partition.POLICY if partition_epoch else container.POLICY if container_epoch else clause.POLICY if clause_epoch else POLICY}
                job = root / 'jobs' / rid
                if partition_epoch:
                    record['partition_proof_sha256'] = projection['expected_partition_proof_sha256']
                    partition.adopt(job, snapshot, original, record)
                elif container_epoch:
                    record['container_proof_sha256'] = projection['expected_container_proof_sha256']
                    container.adopt(job, snapshot, original, record)
                elif clause_epoch:
                    record['clause_proof_sha256'] = projection['expected_clause_proof_sha256']
                    clause.adopt(job, snapshot, original, record)
                else:
                    save(job / RECORD, record, True)
                    save(job / 'prototype-pipeline' / PREFIX / 'epoch-record.json', record, True)
                    save(job / 'prototype-pipeline' / PREFIX / 'predecessor-record.json', read(job / 'mapping-continuation.json'), True)
                if (job / 'source-snapshot.json').read_bytes() != original:
                    raise ValueError('Epoch immutable source changed before queueing.')
                updated = c.execute("UPDATE runs SET state='QUEUED',message=?,updated=? WHERE id=? AND state='ATTENTION' AND artifact IS NULL",
                    ('Continuing the same run with a bounded source-fact repair and reviewed technical projection.', now, rid))
                if updated.rowcount != 1:
                    raise ValueError('Epoch row changed before queueing.')
                c.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
                          (p['owner'], EVENT, event_id(rid, record), now))
            return Response(json.dumps(result), status_code=202, media_type='application/json', headers={'Cache-Control': 'no-store'})
        except HTTPException:
            raise
        except (*recovery_errors, sqlite3.Error):
            raise HTTPException(409, 'The epoch was not queued: source approval or durable epoch state could not be verified. Original operations remain preserved; uncertain calls were not replayed.') from None

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
                    approved_prototype_scope=body.approved_prototype_scope, schema_version=2)
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
