"""Zero-inference compiler constraint completion with immutable original reviews."""
from copy import deepcopy
import json
import math
import os
from pathlib import Path
import re

from . import prototype_development_reference_resume as base
from . import prototype_provider_reexecution as provider
from . import prototype_prose_continuation as prose
from .opaf import OpafError, canonical_hash
from .prototype_item_screen_inheritance import POLICY, project

SCOPE = 'fox-prototype-compiler-continuation-v1'
EVENT = 'approved_prototype_compiler_continuation'


def _fail():
    raise OpafError('Compiler continuation is changed or outside exact zero-inference constraint completion.') from None


def path(job):
    job = Path(os.path.abspath(job))
    data = job.parent.parent if job.parent.name == 'jobs' else job.parent
    name = job.name if re.fullmatch(r'fox-[a-f0-9]{20}', job.name) else 'legacy-' + canonical_hash(job.name)[:20]
    return data / 'compiler-continuations' / name / 'validation.json'


def _read(job):
    from .provider_receipts import LocalProviderReceiptStore, _safe_metadata
    location = path(job)
    LocalProviderReceiptStore._parents(location.parent)
    for directory in (location.parent.parent, location.parent):
        _safe_metadata(directory.lstat(), directory=True)
        if os.name != 'nt' and directory.stat().st_mode & 0o077:
            _fail()
    _safe_metadata(location.lstat())
    if os.name != 'nt' and location.stat().st_mode & 0o077:
        _fail()
    value = base._read(location)
    base._same(value, records(value['plan'], value['owner'], value['approved_at']))
    return value


def _original_names(documents, focus, selected, views):
    from . import prototype_development_reference_followup as followup
    names = base._baseline_names(documents, focus, selected)
    names.update({base.OWNER_RECORD, 'prototype-pipeline/' + base.TECHNICAL,
                  followup.OWNER_RECORD, 'prototype-pipeline/' + followup.TECHNICAL})
    for request, view in zip(focus['requests'], views, strict=True):
        child = 'prototype-pipeline/' + request['focus_id']
        names.update(child + '/' + name for name in base._FIRST | {
            'reviewer.json', 'reviewer-intent.json', 'reviewer-target.json', 'review-receipt.json'})
        if view['proof']['technical_evidence_sha256'] is not None:
            names.update(child + '/' + name for name in ('projection-candidate.json', 'projection-receipt.json', 'reviewer-request.json'))
        if 'metadata_task_policy' in selected:
            names.update(child + '/' + role + '-metadata-task.json' for role in ('mapper', 'reviewer'))
    return names


def _derive(job, snapshot, original, target, *, previous=None):
    root = job / 'prototype-pipeline'
    old_prose = prose.technical(root)
    if old_prose is None:
        _fail()
    documents, packet, focus = base._reconstruct(job, snapshot, original, target)
    if len(focus['requests']) != 6:
        _fail()
    from .prototype_development_reference_view import _active_focus
    from .prototype_chunk_evidence import POLICY as V1
    from .prototype_reference_echo import POLICY as V2
    from .prototype_prose_segments import POLICY as V3
    from .design_provider import invocation_id
    views, invocations = [], set()
    for request, policy in zip(focus['requests'], (V1, V1, V2, V2, V3, V3), strict=True):
        view = _active_focus(root, packet, focus, request, target, views, policy=policy, runtime=None)
        if view['checked']['approved_structured_design'] is not True:
            _fail()
        for role in ('mapper_invocation', 'reviewer_invocation'):
            identity = invocation_id(view['proof'][role])
            if identity in invocations:
                _fail()
            invocations.add(identity)
        views.append(view)
    original_responses = [view['candidate'] for view in views]
    responses, receipt = project(documents, focus, original_responses)
    if (receipt is None or len(receipt['changes']) != 2
            or {row['focus_id'] for row in receipt['changes']} != {focus['requests'][5]['focus_id']}
            or len({row['source_block_id'] for row in receipt['changes']}) != 1):
        _fail()
    from .forms_focus_merge import merge_focus_blueprints
    merged = merge_focus_blueprints(documents, focus, responses)
    files, directories = base._tree(job)
    base._closure(job, files, directories, documents, focus, snapshot['prototype'], continued=True)
    names = _original_names(documents, focus, snapshot['prototype'], views)
    if not names <= files.keys():
        _fail()
    if previous is None:
        allowed_dirs = {'prototype-pipeline', 'prototype-pipeline/sources',
            *{'prototype-pipeline/' + request['focus_id'] for request in focus['requests']}}
        if files.keys() != names or not directories <= allowed_dirs:
            _fail()
    else:
        focuses = {'prototype-pipeline/' + request['focus_id'] for request in focus['requests']}
        if any(name not in names and name.rsplit('/', 1)[0] in focuses for name in files):
            _fail()
    before = {name: base._hash(files[name]) for name in sorted(names)}
    authority = provider._authority(job)
    consumed = provider.validate_consumed(job, authority)
    adoption = provider._read_external(job, 'adoption')
    keys = {adoption['receipt_binding_sha256']}
    for request in focus['requests']:
        for role in ('mapper', 'reviewer'):
            saved = base._read(root / request['focus_id'] / (role + '.json'))
            if 'provider_response_receipt' in saved:
                keys.add(saved['provider_response_receipt']['receipt_binding_sha256'])
    if len(keys) != 6:
        _fail()
    receipts = prose._receipt_inventory(job, keys)
    external = {kind: base._hash(provider.paths(job)[kind]) for kind in ('authority', 'consumed', 'adoption')}
    external['prose'] = base._hash(prose.path(job))
    plan = {key: deepcopy(old_prose['plan'][key]) for key in ('job_id', 'project_id', 'owner', 'snapshot_sha256',
        'source_hash', 'source_binding', 'selected_source_set_id', 'development_processing_sha256',
        'original_consent_sha256', 'source_provenance_sha256', 'target_profile_sha256', 'focus_plan_sha256',
        'approved_chunk_hashes', 'parent_technical_sha256', 'parent_owner_sha256', 'parent_event_id',
        'followup_technical_sha256', 'followup_owner_sha256', 'followup_event_id')}
    plan.update(schema_version=1, scope=SCOPE, policy=POLICY,
        focus_ids=[request['focus_id'] for request in focus['requests']],
        original_proofs_sha256=[canonical_hash(view['proof']) for view in views],
        original_candidate_sha256=[canonical_hash(view['candidate']) for view in views],
        original_review_sha256=[view['proof']['review_sha256'] for view in views],
        original_review_request_sha256=[view['proof']['review_request_sha256'] for view in views],
        original_review_receipt_sha256=[view['proof']['review_receipt_sha256'] for view in views],
        provider_authority_sha256=canonical_hash(authority), provider_consumed_sha256=canonical_hash(consumed),
        provider_adoption_sha256=canonical_hash(adoption), prose_record_sha256=canonical_hash(old_prose),
        prose_event_id=job.name + ':' + canonical_hash(old_prose), before_files=before,
        before_external_files=external, before_receipt_files=receipts,
        original_responses_sha256=canonical_hash(original_responses),
        completed_responses_sha256=canonical_hash(responses), compiler_receipt_sha256=canonical_hash(receipt),
        merged_result_sha256=canonical_hash(merged), merged_blueprint_sha256=canonical_hash(merged['blueprint']),
        merge_validation_sha256=canonical_hash(merged['validation']), completion_count=len(receipt['changes']),
        completed_candidate_sha256=[canonical_hash(response) for response in responses],
        completions=[{key: row[key] for key in ('focus_id', 'source_object_id', 'source_block_id',
                                              'before_row_sha256', 'after_row_sha256')}
                     | {'screen_id': row['after']['screen_id']} for row in receipt['changes']],
        new_model_operations=0, historical_reviews_relabelled=False,
        remaining_operations=[{'stage': stage} for stage in ('render', 'offline_validate', 'package')])
    if previous is not None:
        base._same(previous, plan)
    return plan, views, responses, receipt, merged


def inspect(job, snapshot, original, target):
    return _derive(Path(job), snapshot, original, target)[0]


def records(plan, owner, approved_at):
    if (type(approved_at) not in (int, float) or not math.isfinite(approved_at) or approved_at <= 0
            or type(owner) is not str or not owner or plan.get('owner') != owner
            or plan.get('scope') != SCOPE or plan.get('policy') != POLICY
            or type(plan.get('new_model_operations')) is not int or plan['new_model_operations'] != 0
            or plan.get('historical_reviews_relabelled') is not False):
        _fail()
    return {'schema_version': 1, 'scope': SCOPE, 'owner': owner, 'approved_at': approved_at,
            'plan': deepcopy(plan), 'plan_sha256': canonical_hash(plan)}


def reconstruction(root):
    root = Path(root)
    if not provider._exists(path(root.parent)):
        return None
    value = _read(root.parent)
    from .prototype_job import read_prototype_snapshot
    snapshot, original = read_prototype_snapshot(root.parent)
    ids = value['plan']['focus_ids']
    if (root.name != 'prototype-pipeline' or type(ids) is not list or len(ids) != 6
            or any(type(fid) is not str or not re.fullmatch(r'focus-[a-f0-9]{24}', fid) for fid in ids)):
        _fail()
    target = base._read(root / ids[0] / 'mapper-target.json')
    _, views, responses, receipt, merged = _derive(root.parent, snapshot, original, target, previous=value['plan'])
    return {'record': value, 'views': views, 'responses': responses, 'receipt': receipt, 'merged': merged}


def technical(root):
    value = reconstruction(root)
    return value['record'] if value is not None else None


def validate_owner(job, snapshot, original, connection):
    job = Path(job)
    value = _read(job) if provider._exists(path(job)) else None
    provider._event(connection, EVENT, job, value, 'approved_at')
    if value is None:
        return None
    if prose.validate_owner(job, snapshot, original, connection) is None:
        _fail()
    base._same(value, technical(job / 'prototype-pipeline'))
    return value


def index_evidence(root):
    value = technical(root)
    if value is None:
        return None
    plan = value['plan']
    return {'schema_version': 1, 'scope': SCOPE, 'policy': POLICY,
        'continuation_sha256': canonical_hash(value), 'plan_sha256': value['plan_sha256'],
        'original_proofs_sha256': list(plan['original_proofs_sha256']),
        'original_candidate_sha256': list(plan['original_candidate_sha256']),
        'completed_candidate_sha256': list(plan['completed_candidate_sha256']),
        'compiler_receipt_sha256': plan['compiler_receipt_sha256'],
        'completed_responses_sha256': plan['completed_responses_sha256'],
        'merged_result_sha256': plan['merged_result_sha256'], 'merged_blueprint_sha256': plan['merged_blueprint_sha256'],
        'merge_validation_sha256': plan['merge_validation_sha256'], 'completion_count': plan['completion_count'],
        'completions': deepcopy(plan['completions']), 'new_model_operations': 0, 'review_authority_granted': False,
        'historical_reviews_relabelled': False, 'semantic_equivalence_attested': False,
        'business_behavior_accepted': False}
