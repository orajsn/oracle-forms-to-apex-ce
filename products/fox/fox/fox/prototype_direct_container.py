"""Bounded source-container projection and one retained direct-review correction.

No source behavior is translated. Originals and old reviews stay immutable;
only a new review can approve the derived unresolved structural container.
"""
from copy import deepcopy
import hashlib
from pathlib import Path
import re

from .opaf import OpafError, canonical_hash
from .native_pipeline import _json, _save_once
from .design_provider import is_direct, roles, invocation_id

POLICY = 'source-form-container-retention-v1'
SCOPE = 'fox-direct-container-correction-v1'
OWNER_RECORD = 'container-correction.json'
EVENT = 'approved_prototype_container_correction'
PREFIX = 'container-review'
TECHNICAL = PREFIX + '/correction.json'
FILES = {'correction.json', 'request.json', 'candidate.json', 'projection.json',
         'reviewer.json', 'reviewer-intent.json', 'reviewer-target.json',
         'reviewer-metadata-task.json', 'review-receipt.json'}


def member(name):
    return type(name) is str and name.startswith(PREFIX + '/') and name[len(PREFIX) + 1:] in FILES


def present(root):
    path = Path(root) / TECHNICAL
    return path.exists() or path.is_symlink()


def project(packet, request, candidate):
    """Retain source-proven module metadata; never repair Blocks or behavior."""
    if any(row['kind'] == 'Block' for row in request['owned_objects']):
        return candidate, None
    objects = {r['id']: r for e in packet['sources'] for r in e['facts']['objects']}
    owned = {r['id']: r for r in request['owned_objects']}
    modules = {r['module_id'] for r in objects.values() if r['kind'] == 'Block'}
    result, changes = deepcopy(candidate), []
    for index, row in enumerate(result['blueprint']['objects']):
        source = owned[row['source_object_id']]
        if (source['kind'] == 'FormModule' and row['disposition'] == 'omitted'
                and source['id'] in modules and source['parent_id'] is None):
            row['disposition'] = 'unresolved'
            row['reason'] = 'Source module retained as structural metadata; descendant mappings and behavior remain separately reviewed.'
            changes.append({'object_index': index, 'source_object_id': source['id'],
                            'before': 'omitted', 'after': 'unresolved',
                            'source_container': {k: source[k] for k in ('id','kind','parent_id')},
                            'descendant_blocks': [{k: block[k] for k in ('id','kind','module_id','parent_id')}
                                for block in objects.values() if block['kind']=='Block' and block['module_id']==source['id']]})
    if not changes: return candidate, None
    return result, {'schema_version': 1, 'scope': POLICY, 'source_binding': request['source_binding'],
        'focus_id': request['focus_id'], 'request_sha256': canonical_hash(request),
        'raw_candidate_sha256': canonical_hash(candidate), 'candidate_sha256': canonical_hash(result),
        'changes': changes, 'business_behavior_accepted': False}


def initial(packet, request, candidate, directory, *, write, direct):
    """New direct calls project before review; old sealed reviews never upgrade."""
    path = directory / 'projection-receipt.json'
    retained = path.is_file() and _json(path).get('scope') == POLICY
    if not direct or not retained and (not write or (directory / 'reviewer.json').exists()):
        return candidate, None
    return project(packet, request, candidate)


def _baseline(root, packet, plan, target):
    from .prototype_mapping_epochs import _active_focus
    if not is_direct(target) or (root / 'epochs').exists():
        raise OpafError('Container correction requires an initial direct-design run.')
    views = []
    for request in plan['requests']:
        view = _active_focus(root, packet, plan, request, target, views, None, '')
        if not view['checked']['approved_structured_design']:
            raise OpafError('Container correction requires every original review to be approved.')
        views.append(view)
    return views


def derive(root, packet, plan, target):
    """Reconstruct exact baseline and sole structural conflict, with no effects."""
    from .forms_focus_merge import merge_focus_blueprints
    views = _baseline(root, packet, plan, target)
    replacements = []
    for index, (request, view) in enumerate(zip(plan['requests'], views)):
        candidate, projection = project(packet, request, view['candidate'])
        if projection is not None:
            replacements.append((index, candidate, projection))
    if len(replacements) != 1 or len(replacements[0][2]['changes']) != 1:
        raise OpafError('No unique source-container correction is available.')
    try:
        merge_focus_blueprints(_documents(root), plan, [v['candidate'] for v in views])
    except ValueError as error:
        if str(error) != 'A proposed source object cannot descend from an omitted source block or form module.':
            raise OpafError('A different mapping defect requires separate review.') from None
    else:
        raise OpafError('This mapping has no omitted-container merge conflict.')
    index, candidate, projection = replacements[0]
    candidates = [v['candidate'] for v in views]
    candidates[index] = candidate
    merge_focus_blueprints(_documents(root), plan, candidates)
    before = {}
    allowed = {'binding.json', 'sources-manifest.json', 'packet.json', 'assessment.json'}
    for name in allowed:
        before[name] = _file_hash(root / name)
    focuses = {r['focus_id'] for r in plan['requests']}
    focus_files = {'request.json', 'mapper.json', 'mapper-intent.json', 'mapper-target.json',
        'reviewer.json', 'reviewer-intent.json', 'reviewer-target.json', 'review-receipt.json',
        'mapper-resolved.json', 'mapper-resolution.json', 'mapper-metadata-task.json',
        'reviewer-metadata-task.json', 'reviewer-request.json', 'projection-candidate.json', 'projection-receipt.json'}
    for focus in focuses:
        for path in (root / focus).iterdir():
            if path.name not in focus_files: raise OpafError('Unknown original mapping artifact.')
            before[focus + '/' + path.name] = _file_hash(path)
    for path in (root / 'sources').iterdir():
        if not re.fullmatch(r'source-00[0-3]\.xml', path.name): raise OpafError('Unknown retained source artifact.')
        before['sources/' + path.name] = _file_hash(path)
    record = {'schema_version': 1, 'scope': SCOPE, 'policy': POLICY,
        'source_binding': plan['source_binding'], 'focus_plan_sha256': canonical_hash(plan),
        'target_profile_sha256': canonical_hash(target), 'focus_id': plan['requests'][index]['focus_id'],
        'candidate_sha256': canonical_hash(candidate), 'projection_sha256': canonical_hash(projection),
        'before_files': dict(sorted(before.items())), 'original_proofs_sha256': canonical_hash([v['proof'] for v in views]),
        'retained_model_calls': len(views) * 2, 'new_reviewer_calls': 1, 'business_behavior_accepted': False}
    return record, views, index, candidate, projection


def _documents(root):
    manifest = _json(root / 'sources-manifest.json')
    return [(r['name'], (root / 'sources' / f'source-{i:03}.xml').read_bytes()) for i, r in enumerate(manifest['files'])]


def _file_hash(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 20_000_000:
        raise OpafError('Container correction has missing or unsafe original evidence.')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reconstruct(job, snapshot, original, target):
    from .prototype_job import validate_prototype_snapshot
    from .forms_focus import build_focus_plan
    from .forms_understanding_packet import local_packet
    from .prototype_admission import bound_focus_limit
    documents = validate_prototype_snapshot(snapshot)
    selected = snapshot['prototype']
    if canonical_hash(target) != selected['target_profile_sha256']:
        raise OpafError('Container correction target changed.')
    packet = local_packet(documents)
    plan = build_focus_plan(documents, expected_source_binding=selected['source_binding'],
        approved_chunk_hashes=selected['approved_chunk_hashes'], max_owned_objects=bound_focus_limit(selected))
    if canonical_hash(plan) != selected['focus_plan_sha256']:
        raise OpafError('Container correction source plan changed.')
    return packet, plan


def inspect(job, snapshot, original, target):
    packet, plan = reconstruct(job, snapshot, original, target)
    record, views, index, candidate, projection = derive(job / 'prototype-pipeline', packet, plan, target)
    return record, packet, plan


def validate_owner(job, snapshot, original, connection):
    path = job / OWNER_RECORD
    if not (path.exists() or path.is_symlink()):
        if present(job / 'prototype-pipeline'):
            raise OpafError('Container correction lost its durable owner record.')
        return
    value = _json(path)
    technical = _json(job / 'prototype-pipeline' / TECHNICAL)
    if (set(value) != {'schema_version', 'scope', 'job_id', 'project_id', 'owner', 'approved_at',
            'snapshot_sha256', 'checkpoint_sha256', 'approvals'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['scope'] != SCOPE or value['job_id'] != job.name
            or value['project_id'] != snapshot['project_id'] or value['owner'] != snapshot['approvals']['owner']
            or value['snapshot_sha256'] != hashlib.sha256(original).hexdigest()
            or value['checkpoint_sha256'] != canonical_hash(technical)
            or value['approvals'] != {'redacted_source': True, 'external_ai': True, 'synthetic_prototype': True}):
        raise OpafError('Container correction differs from original source-owner permission.')
    rows = connection.execute('SELECT owner,object_id,created FROM events WHERE action=? AND object_id LIKE ?',
        (EVENT, job.name + ':%')).fetchall()
    if [tuple(row) for row in rows] != [(value['owner'], job.name + ':' + canonical_hash(value), value['approved_at'])]:
        raise OpafError('Container correction has no exact durable owner event.')
    for name, digest in technical['before_files'].items():
        if (type(name) is not str or name.startswith('/') or chr(92) in name or ':' in name
                or any(part in ('', '.', '..') for part in name.split('/'))
                or _file_hash(job / 'prototype-pipeline' / name) != digest):
            raise OpafError('Original container correction evidence changed.')


def active_focus(root, packet, plan, request, target, previous, *, runtime=None):
    """Preserve original calls; permit only the separate new reviewer."""
    record, views, index, candidate, projection = derive(root, packet, plan, target)
    if _json(root / TECHNICAL) != record:
        raise OpafError('Container correction technical lineage changed.')
    position = next(i for i, row in enumerate(plan['requests']) if row['focus_id'] == request['focus_id'])
    if position != index: return views[position]
    from .prototype_mapping_epochs import _role, extended_review
    from .forms_design_review import validate_design_review
    from .prototype_focus_projection import source_fact_gate
    payload = extended_review(request, candidate, views[index]['candidate'], 'source_container_retention',
        {'policy': POLICY, 'projection': projection, 'original_proofs_sha256': record['original_proofs_sha256'],
         'retained_model_calls': record['retained_model_calls'],
         'review_instruction': 'Review only retention of the source-proven FormModule as unresolved structural metadata. Descendant proposals remain independently reviewed; do not invent behavior or change their dispositions.'})
    directory = root / PREFIX
    for name, value in [('request.json', payload), ('candidate.json', candidate), ('projection.json', projection)]:
        if runtime is not None: _save_once(directory / name, value)
        if _json(directory / name) != value: raise OpafError('Derived container review input changed.')
    review, invocation = _role(directory, 'reviewer', payload, target,
        {'job_id': root.parent.name, 'source_hash': plan['source_binding']}, runtime)
    original_ids = {invocation_id(v['proof'][name]) for v in views
                    for name in ('mapper_invocation', 'reviewer_invocation')}
    if invocation_id(invocation) in original_ids:
        raise OpafError('Container correction requires one new independent reviewer invocation.')
    checked = validate_design_review(request, candidate, review)
    if runtime is not None: _save_once(directory / 'review-receipt.json', checked)
    if _json(directory / 'review-receipt.json') != checked:
        raise OpafError('Container correction review receipt changed.')
    proof = {**views[index]['proof'], 'candidate_sha256': canonical_hash(candidate),
        'source_fact_check': source_fact_gate(packet, request, candidate),
        'review_request_sha256': canonical_hash(payload), 'review_sha256': canonical_hash(review),
        'review_receipt_sha256': canonical_hash(checked), 'active_directory': PREFIX,
        'reviewer_invocation': invocation, 'technical_evidence_sha256': canonical_hash(record)}
    return {'candidate': candidate, 'checked': checked, 'proof': proof}


def attach_routes(app, *, root, db, project_owner, current_sources, admission_allowed, target_reader, input_model):
    """Owner-authenticated same-run admission; never patches the run database externally."""
    import json
    import time
    import sqlite3
    from fastapi import Request, HTTPException
    from fastapi.responses import Response
    from . import source_history
    from .prototype_job import read_prototype_snapshot, validate_prototype_snapshot
    errors = (ValueError, KeyError, TypeError, AttributeError, OSError, RuntimeError, RecursionError, sqlite3.Error)

    def context(c, pid, rid, owner):
        if not re.fullmatch(r'fox-[a-f0-9]{20}', rid): raise HTTPException(404, 'Run not found.')
        row = c.execute('SELECT * FROM runs WHERE id=? AND project=?', (rid, pid)).fetchone()
        job = root / 'jobs' / rid
        if not row or job.is_symlink() or (root/'jobs').is_symlink(): raise ValueError()
        run = dict(row)
        snapshot, original = read_prototype_snapshot(job)
        docs = validate_prototype_snapshot(snapshot)
        sources = current_sources(pid, c)
        envelope = target_reader()
        locked = c.execute('SELECT owner FROM projects WHERE id=?', (pid,)).fetchone()
        selected = snapshot['prototype']
        if (not locked or locked['owner'] != owner or snapshot['approvals']['owner'] != owner
                or snapshot['project_id'] != pid or run['source_hash'] != snapshot['source_hash']
                or run['artifact'] is not None or run['state'] not in ('ATTENTION','QUEUED','PROCESSING','GENERATED')
                or source_history._hash(sources) != snapshot['source_hash']
                or source_history.selected_source_set_id(c, pid) != snapshot['selected_source_set_id']
                or [(s['name'], source_history.readable_source_bytes(s)) for s in sources] != docs
                or envelope['target_profile_sha256'] != selected['target_profile_sha256']
                or canonical_hash(envelope['target_profile']) != selected['target_profile_sha256']):
            raise ValueError('Current source ownership or destination changed.')
        origin = 'approved_prototype_mapping_retry' if 'retry_of' in snapshot else 'approved_prototype_conversion'
        events = c.execute('SELECT owner,created FROM events WHERE action=? AND object_id=?', (origin,rid)).fetchall()
        if [tuple(r) for r in events] != [(owner,snapshot['approvals']['approved_at'])]: raise ValueError()
        technical, packet, plan = inspect(job, snapshot, original, envelope['target_profile'])
        recorded = (job / OWNER_RECORD).exists() or (job / OWNER_RECORD).is_symlink()
        if recorded:
            validate_owner(job, snapshot, original, c)
            if _json(job/'prototype-pipeline'/TECHNICAL) != technical: raise ValueError()
        else:
            if run['state'] != 'ATTENTION' or (job/'prototype-pipeline'/PREFIX).exists(): raise ValueError()
            allowed = {'binding.json','sources-manifest.json','packet.json','assessment.json','sources',
                       *{r['focus_id'] for r in plan['requests']}}
            if any(p.name not in allowed for p in (job/'prototype-pipeline').iterdir()): raise ValueError()
            if any(p.name != 'source-snapshot.json' and p.name != 'prototype-pipeline' for p in job.iterdir()): raise ValueError()
            if c.execute('SELECT 1 FROM events WHERE action=? AND object_id LIKE ?', (EVENT,rid+':%')).fetchone(): raise ValueError()
        value = {'schema_version':1,'scope':SCOPE,'project_id':pid,'run_id':rid,
            'source_hash':snapshot['source_hash'],'source_binding':selected['source_binding'],
            'selected_source_set_id':snapshot['selected_source_set_id'],
            'target_profile_sha256':selected['target_profile_sha256'],
            'approved_chunk_hashes':dict(selected['approved_chunk_hashes']),
            'checkpoint_sha256':canonical_hash(technical),'eligible':not recorded,
            'continuation_recorded':recorded,'retained_model_calls':technical['retained_model_calls'],
            'new_reviewer_calls':1,'container_corrections':1,'business_behavior_accepted':False,
            'next_action':'open_run' if recorded else 'confirm_container_correction',
            'reason':'Retain the source module as structural metadata and request one new independent review; saved model calls remain unchanged.'}
        return value, job, snapshot, original, technical, run

    route = '/api/projects/{pid}/prototype-runs/{rid}/container-correction'
    @app.get(route)
    def get_correction(pid: str, rid: str, request: Request):
        owner = project_owner(request,pid)['owner']
        try:
            with db() as c:
                c.execute('BEGIN')
                value = context(c,pid,rid,owner)[0]
            return Response(json.dumps(value),media_type='application/json',headers={'Cache-Control':'no-store'})
        except HTTPException: raise
        except errors:
            raise HTTPException(409,'No safe container correction is available. Saved outcomes remain unchanged.') from None

    @app.post(route,status_code=202)
    def post_correction(pid: str, rid: str, body: input_model, request: Request):
        owner = project_owner(request,pid)['owner']
        try:
            with db() as c:
                c.execute('BEGIN IMMEDIATE')
                value,job,snapshot,original,technical,run = context(c,pid,rid,owner)
                if (body.checkpoint_sha256 != value['checkpoint_sha256'] or body.source_hash != value['source_hash']
                        or body.source_binding != value['source_binding']
                        or body.expected_current_source_set_id != value['selected_source_set_id']
                        or body.target_profile_sha256 != value['target_profile_sha256']
                        or body.approved_chunk_hashes != value['approved_chunk_hashes']
                        or not all(v is True for v in (body.approved_redacted_source,body.approved_external_ai,body.approved_prototype_scope))):
                    raise ValueError()
                result = {'id':rid,'state':run['state'] if value['continuation_recorded'] else 'QUEUED',
                    'conversion_profile':'native-blueprint-prototype-v1','continued':True,
                    'continuation_recorded':True,'next_action':'open_run','business_behavior_accepted':False}
                if value['continuation_recorded']:
                    return Response(json.dumps(result),status_code=200,media_type='application/json',headers={'Cache-Control':'no-store'})
                if not admission_allowed(c): raise HTTPException(429,'Other unresolved work blocks correction.')
                now = time.time()
                authorization = {'schema_version':1,'scope':SCOPE,'job_id':rid,'project_id':pid,'owner':owner,
                    'approved_at':now,'snapshot_sha256':hashlib.sha256(original).hexdigest(),
                    'checkpoint_sha256':value['checkpoint_sha256'],
                    'approvals':{'redacted_source':True,'external_ai':True,'synthetic_prototype':True}}
                (job/'prototype-pipeline'/PREFIX).mkdir()
                _save_once(job/'prototype-pipeline'/TECHNICAL,technical)
                _save_once(job/OWNER_RECORD,authorization)
                if read_prototype_snapshot(job)[1] != original: raise ValueError()
                changed = c.execute("UPDATE runs SET state='QUEUED',message=?,updated=? WHERE id=? AND state='ATTENTION' AND artifact IS NULL",
                    ('Retaining the source container for one new independent review; saved calls are preserved.',now,rid))
                if changed.rowcount != 1: raise ValueError()
                c.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
                    (owner,EVENT,rid+':'+canonical_hash(authorization),now))
            return Response(json.dumps(result),status_code=202,media_type='application/json',headers={'Cache-Control':'no-store'})
        except HTTPException: raise
        except errors:
            raise HTTPException(409, 'Container correction was not queued. Retained or uncertain outcomes require reconciliation; no call was replayed.') from None
