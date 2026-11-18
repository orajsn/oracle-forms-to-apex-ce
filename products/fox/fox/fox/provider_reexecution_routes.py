"""Explicit one-extra-attempt operator action; never automatic inference retry."""
import json
import os
import time
from pathlib import Path

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, StrictBool

from . import source_history
from . import prototype_provider_reexecution as repeat
from .design_provider import roles
from .native_pipeline import _sync
from .oci_genai import OciGenAiClient
from .opaf import OpafError, canonical_hash
from .provider_receipts import LocalProviderReceiptStore, _safe_metadata
from .prototype_job import read_prototype_snapshot, validate_prototype_snapshot
from .source_processing_policy import current_processing_approval


class ExtraAttemptInput(BaseModel):
    model_config = {'extra': 'forbid'}
    plan_sha256: str = Field(pattern=r'^[a-f0-9]{64}$')
    acknowledged_unknown_outcome: StrictBool
    acknowledged_possible_extra_charge: StrictBool


def _private(path):
    path = Path(path)
    LocalProviderReceiptStore._parents(path.parent)
    path.mkdir(mode=0o700, exist_ok=True)
    _safe_metadata(path.lstat(), directory=True)
    if os.name != 'nt' and path.stat().st_mode & 0o077:
        raise OpafError('Provider attempt storage must be private.')


def _create(path, value):
    """Strict exclusive publication: identical existing bytes are not reusable."""
    path = Path(path)
    LocalProviderReceiptStore._parents(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()
    with os.fdopen(os.open(path, flags, 0o600), 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    _sync(path.parent)


def _event(c, event, rid, record, timestamp):
    c.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
        (record['owner'], event, rid + ':' + canonical_hash(record), record[timestamp]))


class _ApprovedAttemptStore:
    """Compare the SDK's actual prepared binding before durable intent/POST."""
    def __init__(self, store, expected):
        self.store, self.expected = store, expected

    def begin(self, binding, **kwargs):
        if canonical_hash(binding) != canonical_hash(self.expected):
            raise OpafError('Actual prepared SDK request differs from the approved new-attempt binding.')
        return self.store.begin(binding, **kwargs)

    def capture(self, *args, **kwargs):
        return self.store.capture(*args, **kwargs)


def _expected_binding(plan, target, identity, effective):
    from .design_provider import DIRECT, PROMPTS
    from .genai_prompts import prompt_hash
    role = roles(target)['mapper']
    return {'schema_version': 1, 'provider': DIRECT, 'job_id': plan['job_id'],
        'source_manifest_sha256': plan['source_binding'], 'identity_sha256': canonical_hash(identity),
        'target_profile_sha256': plan['target_profile_sha256'], 'client_target_sha256': canonical_hash(target),
        'role': 'mapper', 'model': role['model'], 'role_sha256': canonical_hash(role),
        'prompt_version': PROMPTS['mapper'], 'prompt_sha256': prompt_hash('mapper'),
        'request_sha256': canonical_hash(effective), 'wire_request_sha256': plan['expected_new_wire_sha256']}


def attach(app, *, root, db, project, current_sources, target_reader):
    def checked(c, pid, rid, owner, *, require_inactive=False):
        row = c.execute('SELECT * FROM runs WHERE id=? AND project=?', (rid, pid)).fetchone()
        if not row:
            raise HTTPException(404, 'Prototype run not found.')
        job = root / 'jobs' / rid
        if (root / 'jobs').is_symlink() or job.is_symlink():
            raise OpafError('Unsafe provider attempt storage.')
        snapshot, original = read_prototype_snapshot(job)
        validate_prototype_snapshot(snapshot)
        selected = snapshot['prototype']
        locked = c.execute('SELECT owner FROM projects WHERE id=?', (pid,)).fetchone()
        sources = current_sources(pid, c)
        if (not locked or locked['owner'] != owner or snapshot['approvals']['owner'] != owner
                or snapshot['project_id'] != pid or snapshot['project'] != pid
                or row['source_hash'] != snapshot['source_hash'] or row['artifact'] is not None
                or source_history._hash(sources) != snapshot['source_hash']
                or source_history.selected_source_set_id(c, pid) != snapshot['selected_source_set_id']
                or selected.get('processing_mode') != 'development'
                or selected.get('delivery_mode') != 'apexlang_package'
                or not current_processing_approval(c, snapshot, rid, sources)):
            raise OpafError('Original development processing authority is no longer current.')
        target = target_reader()
        if (target['target_profile_sha256'] != selected['target_profile_sha256']
                or canonical_hash(target['target_profile']) != selected['target_profile_sha256']):
            raise OpafError('The original provider destination changed.')
        authority = repeat.validate_owner(job, snapshot, original, c)
        if require_inactive and row['state'] != 'ATTENTION':
            raise OpafError('The provider attempt requires the exact inactive run.')
        return row, job, snapshot, original, target['target_profile'], authority

    def make_plan(job, snapshot, original, target):
        from .forms_focus import build_focus_plan
        from .prototype_admission import bound_focus_limit
        from .prototype_dsc_identity_repair import model_task
        selected = snapshot['prototype']
        docs = validate_prototype_snapshot(snapshot)
        plan = build_focus_plan(docs, expected_source_binding=selected['source_binding'],
            approved_chunk_hashes=selected['approved_chunk_hashes'], max_owned_objects=bound_focus_limit(selected))
        request = plan['requests'][repeat.PIVOT_INDEX]
        effective = model_task(job / 'prototype-pipeline' / request['focus_id'], 'mapper', request, write=False)
        client = OciGenAiClient(target)
        _, _, wire = client._prepare_request(roles(target)['mapper'], effective)
        return repeat.inspect(job, snapshot, original, target, wire), effective, client

    @app.get('/api/projects/{pid}/prototype-runs/{rid}/provider-reexecution')
    def inspect_attempt(pid: str, rid: str, request: Request):
        owner = project(request, pid)['owner']
        try:
            with db() as c:
                c.execute('BEGIN')
                row, job, snapshot, original, target, authority = checked(c, pid, rid, owner)
                if authority is not None:
                    paths = repeat.paths(job)
                    return JSONResponse({'run_id': rid, 'state': row['state'], 'eligible': False,
                        'authority_recorded': True, 'plan_sha256': authority['plan_sha256'],
                        'consumed': paths['consumed'].exists(), 'adopted': paths['adoption'].exists(),
                        'reason': 'The one-attempt authority is already recorded. Inspect retained evidence; do not submit again.'},
                        headers={'Cache-Control': 'no-store'})
                if row['state'] != 'ATTENTION':
                    raise OpafError('The exact uncertain attempt is not inactive.')
                plan, _, _ = make_plan(job, snapshot, original, target)
                return JSONResponse({'run_id': rid, 'state': row['state'], 'eligible': True,
                    'authority_recorded': False, 'plan_sha256': canonical_hash(plan),
                    'source_hash': plan['source_hash'], 'pivot_focus_id': plan['pivot_focus_id'],
                    'approved_prefix_focuses': len(plan['prefix_proofs_sha256']),
                    'additional_attempt_limit': 1, 'historical_outcome': 'unknown',
                    'reason': 'One new fourth-mapper attempt may incur an additional inference charge. The original unknown intent and all approved sections remain unchanged.'},
                    headers={'Cache-Control': 'no-store'})
        except HTTPException:
            raise
        except (OpafError, ValueError, TypeError, KeyError, OSError):
            raise HTTPException(409, 'No exact inactive one-attempt plan is available; retained outcomes remain unchanged.') from None

    @app.post('/api/projects/{pid}/prototype-runs/{rid}/provider-reexecution')
    def execute_attempt(pid: str, rid: str, body: ExtraAttemptInput, request: Request):
        owner = project(request, pid)['owner']
        if body.acknowledged_unknown_outcome is not True or body.acknowledged_possible_extra_charge is not True:
            raise HTTPException(422, 'Explicit acknowledgement of the unknown outcome and one possible extra charge is required.')
        reserved = False
        try:
            with db() as c:
                c.execute('BEGIN IMMEDIATE')
                row, job, snapshot, original, target, existing = checked(c, pid, rid, owner)
                if existing is not None:
                    if body.plan_sha256 != existing['plan_sha256']:
                        raise OpafError('Recorded one-attempt authority differs.')
                    return JSONResponse({'run_id': rid, 'state': row['state'], 'authority_recorded': True,
                        'already_recorded': True, 'inference_repeated_by_this_request': False}, headers={'Cache-Control': 'no-store'})
                if row['state'] != 'ATTENTION' or c.execute("SELECT 1 FROM runs WHERE state IN ('QUEUED','PROCESSING') LIMIT 1").fetchone():
                    raise OpafError('An exclusive inactive job is required.')
                plan, effective, client = make_plan(job, snapshot, original, target)
                if canonical_hash(plan) != body.plan_sha256:
                    raise OpafError('One-attempt plan changed.')
                now = time.time()
                authority = repeat.records(plan, owner, now, acknowledged_unknown_outcome=True,
                    acknowledged_possible_extra_charge=True)
                paths = repeat.paths(job)
                for directory in (paths['ledger'].parent, paths['ledger'], paths['receipts'].parent):
                    _private(directory)
                _create(paths['authority'], authority)
                _event(c, repeat.EVENT, rid, authority, 'approved_at')
                changed = c.execute("UPDATE runs SET state='PROCESSING',message=?,updated=? WHERE id=? AND project=? AND state='ATTENTION' AND artifact IS NULL",
                    ('Preparing one explicitly approved new mapper attempt; the original unknown outcome is preserved.', now, rid, pid))
                if changed.rowcount != 1:
                    raise OpafError('Inactive job ownership changed.')
            reserved = True
            # This directory is not the one-attempt allowance. The separate
            # strict consumed latch/event below survives loss of receipt storage.
            store = LocalProviderReceiptStore(paths['receipts'], sealed_job_root=job)

            def before_invoke(environment):
                with db() as c:
                    c.execute('BEGIN IMMEDIATE')
                    current, same_job, same_snapshot, same_original, same_target, bound = checked(c, pid, rid, owner)
                    if (current['state'] != 'PROCESSING' or same_original != original
                            or canonical_hash(same_target) != canonical_hash(target)
                            or canonical_hash(bound) != canonical_hash(authority)):
                        raise OpafError('One-attempt authority changed before submission.')
                    repeat.require_unconsumed(job, authority, c)
                    latch = repeat.consumption_record(authority, time.time())
                    _create(paths['consumed'], latch)  # O_EXCL, never idempotent reuse.
                    _event(c, repeat.CONSUMED_EVENT, rid, latch, 'consumed_at')
                    repeat.validate_consumed(job, authority, c)
                # The DB transaction is committed before the SDK can POST.

            identity = {'job_id': rid, 'source_hash': snapshot['prototype']['source_binding']}
            bound_store = _ApprovedAttemptStore(store, _expected_binding(plan, target, identity, effective))
            client.invoke_prepared(roles(target)['mapper'], effective, identity,
                role_name='mapper', target_profile=target, before_invoke=before_invoke, receipt_store=bound_store)
            with db() as c:
                c.execute('BEGIN IMMEDIATE')
                current, _, _, same_original, same_target, bound = checked(c, pid, rid, owner)
                if (current['state'] != 'PROCESSING' or same_original != original
                        or canonical_hash(same_target) != canonical_hash(target)
                        or canonical_hash(bound) != canonical_hash(authority)):
                    raise OpafError('Captured response no longer has current adoption authority.')
                consumed = repeat.validate_consumed(job, authority, c)
                saved, evidence = repeat.captured_checkpoint(job, authority)
                checkpoint = job / 'prototype-pipeline' / plan['pivot_focus_id'] / 'mapper.json'
                _create(checkpoint, saved)
                adoption = repeat.adoption_record(authority, consumed, saved, evidence, time.time())
                _create(paths['adoption'], adoption)
                _event(c, repeat.ADOPTION_EVENT, rid, adoption, 'adopted_at')
                repeat.validate_checkpoint(checkpoint.parent, 'mapper', saved, connection=c)
                changed = c.execute("UPDATE runs SET state='QUEUED',message=?,updated=? WHERE id=? AND project=? AND state='PROCESSING' AND artifact IS NULL",
                    ('New captured mapper attempt adopted; continuing only unstarted review and mapping.', time.time(), rid, pid))
                if changed.rowcount != 1:
                    raise OpafError('Captured response publication state changed.')
            return JSONResponse({'run_id': rid, 'state': 'QUEUED', 'authority_recorded': True,
                'already_recorded': False, 'new_attempt_adopted': True,
                'original_outcome': 'unknown', 'additional_attempts': 1,
                'business_behavior_accepted': False}, status_code=202, headers={'Cache-Control': 'no-store'})
        except HTTPException:
            raise
        except Exception:
            if reserved:
                with db() as c:
                    c.execute("UPDATE runs SET state='ATTENTION',message=?,updated=? WHERE id=? AND project=? AND state='PROCESSING'",
                        ('The explicitly approved attempt needs receipt reconciliation. No further inference is permitted automatically.', time.time(), rid, pid))
            raise HTTPException(409, 'The one-attempt action did not complete. Retained authority, consumed budget and any response must be reconciled; do not repeat the request.') from None
