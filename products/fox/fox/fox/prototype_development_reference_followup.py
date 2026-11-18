"""Append-only proof for the exact third-focus echo/reference continuation.

Two approved V1 focuses and every completed call remain immutable. No I/O
mutation, provider invocation or moving-frontier recovery is implemented here.
"""
from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path
import re

from . import prototype_development_reference_resume as parent
from .opaf import OpafError, canonical_hash
from .prototype_chunk_evidence import POLICY as V1_POLICY, project_chunk_evidence
from .prototype_reference_echo import POLICY, project

SCOPE = 'fox-prototype-development-reference-followup-v1'
OWNER_RECORD = TECHNICAL = 'development-reference-followup.json'
EVENT = 'approved_prototype_development_reference_followup'
PIVOT_INDEX = 2
_OLD_FIRST_KEYS = {'first_focus_id', 'first_request_sha256', 'first_mapper_sha256',
                   'first_mapper_invocation_sha256'}
_PLAN_KEYS = (parent._PLAN_KEYS - _OLD_FIRST_KEYS) | {'parent_technical_sha256',
    'parent_owner_sha256', 'parent_event_id', 'prefix_proofs_sha256', 'pivot_index',
    'pivot_focus_id', 'pivot_request_sha256', 'pivot_mapper_sha256', 'pivot_mapper_invocation_sha256'}


def _fail():
    raise OpafError('Development reference follow-up is changed, uncertain or outside its exact third-focus scope.') from None


def _parent(root, snapshot):
    technical_record = parent.technical(root)
    if technical_record is None:
        _fail()
    authorization = parent._read(root.parent / parent.OWNER_RECORD)
    expected = parent.records(technical_record['plan'], snapshot['approvals']['owner'],
                              authorization['approved_at'])[1]
    parent._same(authorization, expected)
    return technical_record, authorization


def _base_names(documents, focus, selected, prefix):
    names = parent._baseline_names(documents, focus, selected)
    names.update({parent.OWNER_RECORD, 'prototype-pipeline/' + parent.TECHNICAL})
    completed = parent._FIRST | {'reviewer.json', 'reviewer-intent.json',
                                'reviewer-target.json', 'review-receipt.json'}
    for request, view in zip(focus['requests'][:PIVOT_INDEX], prefix):
        child = 'prototype-pipeline/' + request['focus_id']
        names.update(child + '/' + name for name in completed)
        if view['proof']['technical_evidence_sha256'] is not None:
            names.update(child + '/' + name for name in ('projection-candidate.json',
                'projection-receipt.json', 'reviewer-request.json'))
        if 'metadata_task_policy' in selected:
            names.update(child + '/' + role + '-metadata-task.json' for role in ('mapper', 'reviewer'))
    pivot = 'prototype-pipeline/' + focus['requests'][PIVOT_INDEX]['focus_id']
    names.update(pivot + '/' + name for name in parent._FIRST)
    if 'metadata_task_policy' in selected:
        names.add(pivot + '/mapper-metadata-task.json')
    return names


def _closure(job, files, directories, documents, focus, selected, prefix, *, continued):
    # V1 recognizes the two child record filenames only; it never dispatches here.
    parent._closure(job, files, directories, documents, focus, selected, continued=True)
    names = _base_names(documents, focus, selected, prefix)
    if not names <= files.keys():
        _fail()
    if not continued:
        allowed_dirs = {'prototype-pipeline', 'prototype-pipeline/sources',
            *{'prototype-pipeline/' + row['focus_id'] for row in focus['requests'][:PIVOT_INDEX + 1]}}
        if files.keys() != names or not directories <= allowed_dirs:
            _fail()
    else:
        frozen = {'prototype-pipeline/' + row['focus_id'] for row in focus['requests'][:PIVOT_INDEX]}
        if any(name not in names and name.rsplit('/', 1)[0] in frozen for name in files):
            _fail()
    return names


def _derive(job, snapshot, original, target, *, before_files=None):
    root = job / 'prototype-pipeline'
    parent_record, parent_owner = _parent(root, snapshot)
    documents, packet, focus = parent._reconstruct(job, snapshot, original, target)
    if len(focus['requests']) <= PIVOT_INDEX:
        _fail()
    selected = snapshot['prototype']
    from .prototype_development_reference_view import _active_focus
    from .design_provider import invocation_id
    prefix, used = [], set()
    for request in focus['requests'][:PIVOT_INDEX]:
        view = _active_focus(root, packet, focus, request, target, prefix, policy=V1_POLICY, runtime=None)
        if view['checked']['approved_structured_design'] is not True:
            _fail()
        for role in ('mapper_invocation', 'reviewer_invocation'):
            identity = invocation_id(view['proof'][role])
            if identity in used:
                _fail()
            used.add(identity)
        prefix.append(view)
    files, directories = parent._tree(job)
    names = _closure(job, files, directories, documents, focus, selected, prefix,
                     continued=before_files is not None)
    baseline = {name: parent._hash(files[name]) for name in sorted(names)}
    if before_files is not None:
        parent._same(baseline, before_files)
    pivot = focus['requests'][PIVOT_INDEX]
    child = root / pivot['focus_id']
    parent._same(parent._read(child / 'request.json'), pivot)
    from .prototype_mapping_epochs import _role as existing_role
    raw, invocation = existing_role(child, 'mapper', pivot, target,
        {'job_id': job.name, 'source_hash': selected['source_binding']})
    if invocation_id(invocation) in used:
        _fail()
    candidate, receipt = project(documents, packet, pivot, raw, target)
    if receipt is None or receipt['echo_removal'] != {
            'operation': 'remove_matching_source_binding_echo', 'path': ['source_binding'],
            'before': selected['source_binding']}:
        _fail()
    inner = receipt['v1_projection']
    if (inner is None or inner['chunk_evidence'] is None or not inner['chunk_evidence']['changes']
            or any(inner[key] is not None for key in ('owner_resolution', 'candidate_format', 'container_retention'))):
        _fail()
    prepared = deepcopy(raw)
    del prepared['source_binding']
    exact_candidate, exact_receipt = project_chunk_evidence(documents, pivot, prepared)
    parent._same(candidate, exact_candidate)
    parent._same(inner['chunk_evidence'], exact_receipt)
    from .prototype_focus_projection import source_fact_gate
    try:
        source_fact_gate(packet, pivot, raw)
    except ValueError:
        pass
    else:
        _fail()
    source_fact_gate(packet, pivot, candidate)
    remaining = [{'focus_id': pivot['focus_id'], 'role': 'reviewer'}]
    for request in focus['requests'][PIVOT_INDEX + 1:]:
        remaining.extend({'focus_id': request['focus_id'], 'role': role} for role in ('mapper', 'reviewer'))
    remaining.extend({'stage': stage} for stage in ('render', 'offline_validate', 'package'))
    plan = {key: deepcopy(value) for key, value in parent_record['plan'].items() if key not in _OLD_FIRST_KEYS}
    plan.update({'scope': SCOPE, 'policy': POLICY, 'before_files': baseline,
        'parent_technical_sha256': canonical_hash(parent_record),
        'parent_owner_sha256': canonical_hash(parent_owner),
        'parent_event_id': job.name + ':' + canonical_hash(parent_owner),
        'prefix_proofs_sha256': [canonical_hash(view['proof']) for view in prefix],
        'pivot_index': PIVOT_INDEX, 'pivot_focus_id': pivot['focus_id'],
        'pivot_request_sha256': canonical_hash(pivot),
        'pivot_mapper_sha256': canonical_hash(parent._read(child / 'mapper.json')),
        'pivot_mapper_invocation_sha256': canonical_hash(invocation),
        'raw_candidate_sha256': canonical_hash(raw), 'projected_candidate_sha256': canonical_hash(candidate),
        'projection_receipt_sha256': canonical_hash(receipt),
        'projection_claim_count': len(inner['chunk_evidence']['changes']), 'remaining_operations': remaining})
    return plan, candidate, receipt


def inspect(job, snapshot, original, target):
    """Pure initial-only plan; current parent event is checked by validate_owner."""
    return _derive(Path(job), snapshot, original, target)[0]


def records(plan, owner, approved_at):
    if (type(plan) is not dict or set(plan) != _PLAN_KEYS
            or type(plan['schema_version']) is not int or plan['schema_version'] != 1
            or plan['scope'] != SCOPE or plan['policy'] != POLICY or plan['owner'] != owner
            or type(owner) is not str or not owner
            or type(plan['pivot_index']) is not int or plan['pivot_index'] != PIVOT_INDEX
            or type(plan['prefix_proofs_sha256']) is not list or len(plan['prefix_proofs_sha256']) != PIVOT_INDEX
            or type(approved_at) not in (int, float) or not math.isfinite(approved_at) or approved_at <= 0):
        _fail()
    technical_record = {'schema_version': 1, 'scope': SCOPE, 'plan': deepcopy(plan),
                        'plan_sha256': canonical_hash(plan)}
    authorization = {'schema_version': 1, 'scope': SCOPE, 'job_id': plan['job_id'],
        'project_id': plan['project_id'], 'owner': owner, 'approved_at': approved_at,
        **{key: plan[key] for key in ('snapshot_sha256', 'development_processing_sha256',
            'original_consent_sha256', 'parent_technical_sha256', 'parent_owner_sha256', 'parent_event_id')},
        'plan_sha256': canonical_hash(plan), 'technical_sha256': canonical_hash(technical_record)}
    return technical_record, authorization


def technical(root):
    root = Path(root)
    parent._safe(root.parent, directory=True)
    parent._safe(root, directory=True)
    path = root / TECHNICAL
    if not (path.exists() or path.is_symlink()):
        owner = root.parent / OWNER_RECORD
        if owner.exists() or owner.is_symlink():
            _fail()
        return None
    return validate_technical(root)


def validate_technical(root, record=None):
    root = Path(root)
    parent._safe(root.parent, directory=True)
    parent._safe(root, directory=True)
    if root.name != 'prototype-pipeline':
        _fail()
    saved = parent._read(root / TECHNICAL)
    if record is not None:
        parent._same(saved, record)
    plan = saved['plan']
    if (type(plan['pivot_index']) is not int or plan['pivot_index'] != PIVOT_INDEX
            or not re.fullmatch(r'focus-[a-f0-9]{24}', plan['pivot_focus_id'])):
        _fail()
    path = root.parent / 'source-snapshot.json'
    parent._safe(path)
    original = path.read_bytes()
    snapshot = json.loads(original)
    target = parent._read(root / plan['pivot_focus_id'] / 'mapper-target.json')
    expected, candidate, receipt = _derive(root.parent, snapshot, original, target,
                                           before_files=plan['before_files'])
    parent._same(plan, expected)
    parent._same(saved, records(expected, expected['owner'], 1.0)[0])
    child = root / plan['pivot_focus_id']
    for name, value in (('projection-candidate.json', candidate), ('projection-receipt.json', receipt)):
        path = child / name
        if path.exists() or path.is_symlink():
            parent._same(parent._read(path), value)
    return saved


def validate_owner(job, snapshot, original, connection):
    job = Path(job)
    # Required even before child records exist: the new route must validate
    # its exact durable V1 parent in the same admission transaction.
    parent_owner = parent.validate_owner(job, snapshot, original, connection)
    rows = connection.execute('SELECT owner,object_id,created FROM events WHERE action=? AND '
        '(object_id=? OR substr(object_id,1,?)=?)',
        (EVENT, job.name, len(job.name) + 1, job.name + ':')).fetchall()
    owner_path = job / OWNER_RECORD
    technical_path = job / 'prototype-pipeline' / TECHNICAL
    has_owner = owner_path.exists() or owner_path.is_symlink()
    has_technical = technical_path.exists() or technical_path.is_symlink()
    if not has_owner and not has_technical and not rows:
        return None
    if parent_owner is None or not has_owner or not has_technical:
        _fail()
    saved = validate_technical(job / 'prototype-pipeline')
    authorization = parent._read(owner_path)
    plan = saved['plan']
    parent._same(authorization, records(plan, snapshot['approvals']['owner'], authorization['approved_at'])[1])
    if ((job / 'source-snapshot.json').read_bytes() != original or json.loads(original) != snapshot
            or hashlib.sha256(original).hexdigest() != plan['snapshot_sha256']
            or canonical_hash(parent_owner) != plan['parent_owner_sha256']
            or [tuple(row) for row in rows] != [(authorization['owner'],
                job.name + ':' + canonical_hash(authorization), authorization['approved_at'])]):
        _fail()
    return authorization
