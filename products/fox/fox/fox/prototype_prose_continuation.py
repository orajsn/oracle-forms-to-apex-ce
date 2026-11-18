"""One external validation record for lossless prose on the fixed fifth focus.

No writes, provider calls, mapper replay or generic-role dispatch hooks. Old
source, reviews, new-attempt evidence and captured receipt pairs stay immutable.
"""
from copy import deepcopy
import hashlib
import json
import math
import os
from pathlib import Path
import re

from . import prototype_development_reference_resume as base
from . import prototype_provider_reexecution as provider
from .opaf import OpafError, canonical_hash
from .prototype_prose_segments import POLICY, project

SCOPE = 'fox-prototype-prose-continuation-v1'
EVENT = 'approved_prototype_prose_continuation'
PIVOT_INDEX = 4


def _fail():
    raise OpafError('Prose continuation is missing, changed or outside its fixed lossless validation scope.') from None


def path(job):
    job = Path(os.path.abspath(job))
    data = job.parent.parent if job.parent.name == 'jobs' else job.parent
    name = job.name if re.fullmatch(r'fox-[a-f0-9]{20}', job.name) else 'legacy-' + canonical_hash(job.name)[:20]
    return data / 'prose-continuations' / name / 'validation.json'


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


def _effective(child, name, payload, target, job, source):
    from .prototype_dsc_identity_repair import model_task
    from .design_provider import roles
    effective = model_task(child, name, payload, write=False)
    base._same(base._read(child / (name + '-target.json')), target)
    base._same(base._read(child / (name + '-intent.json')), {
        'role': roles(target)[name], 'request_sha256': canonical_hash(effective),
        'job_id': job.name, 'source_hash': source})
    return effective


def _future_inputs(job, packet, focus, target, views, candidate, receipt):
    """Only inputs whose normal job intent is already sealed may have receipts."""
    from .prototype_mapping_epochs import _role, extended_review
    from .prototype_development_reference_view import _active_focus
    root, result = job / 'prototype-pipeline', []
    fifth, sixth = focus['requests'][4:6]
    child = root / fifth['focus_id']
    def add(directory, name, payload):
        if not provider._exists(directory / (name + '-intent.json')):
            return
        if name == 'mapper':
            base._same(base._read(directory / 'request.json'), payload)
        elif provider._exists(directory / 'reviewer-request.json'):
            base._same(base._read(directory / 'reviewer-request.json'), payload)
        effective = _effective(directory, name, payload, target, job, focus['source_binding'])
        result.append((directory.name, name, effective))
    raw = base._read(child / 'mapper.json')['output']
    payload = extended_review(fifth, candidate, raw, 'development_source_reference_projection', receipt)
    add(child, 'reviewer', payload)
    if not (provider._exists(child / 'reviewer.json') and provider._exists(child / 'review-receipt.json')):
        return result
    fifth_view = _active_focus(root, packet, focus, fifth, target, views, policy=POLICY, runtime=None)
    if fifth_view['checked']['approved_structured_design'] is not True:
        return result
    child = root / sixth['focus_id']
    add(child, 'mapper', sixth)
    if not provider._exists(child / 'reviewer-intent.json'):
        return result
    raw, _ = _role(child, 'mapper', sixth, target,
        {'job_id': job.name, 'source_hash': focus['source_binding']}, runtime=None)
    from .prototype_dsc_identity_repair import documents
    candidate, receipt = project(documents(root), packet, sixth, raw, target)
    payload = (extended_review(sixth, candidate, raw, 'development_source_reference_projection', receipt)
               if receipt is not None else {'request': sixth, 'candidate': candidate, 'candidate_sha256': canonical_hash(candidate)})
    add(child, 'reviewer', payload)
    return result


def _receipt_inventory(job, keys, future=()):
    from .provider_receipts import LocalProviderReceiptStore, _metadata, _timestamp
    from .design_provider import DIRECT, PROMPTS, roles
    from .genai_prompts import prompt_hash
    store = LocalProviderReceiptStore.read_only(provider.paths(job)['receipts'], sealed_job_root=job)
    members = {}
    for member in store.root.iterdir():
        match = re.fullmatch(r'([a-f0-9]{64})\.(intent|response)\.json', member.name)
        if not match:
            _fail()
        base._safe(member)
        members.setdefault(match[1], {})[match[2]] = member
    if not set(keys) <= members.keys():
        _fail()
    target = None
    allowed, used = {}, set()
    for fid, role_name, request, current_target, source in future:
        target = current_target
        role = roles(target)[role_name]
        expected = {'schema_version': 1, 'provider': DIRECT, 'job_id': job.name,
            'source_manifest_sha256': source, 'identity_sha256': canonical_hash({'job_id': job.name, 'source_hash': source}),
            'target_profile_sha256': canonical_hash(target), 'client_target_sha256': canonical_hash(target),
            'role': role_name, 'model': role['model'], 'role_sha256': canonical_hash(role),
            'prompt_version': PROMPTS[role_name], 'prompt_sha256': prompt_hash(role_name),
            'request_sha256': canonical_hash(request)}
        allowed[canonical_hash(expected)] = (fid, role_name, expected)
    for key, files in members.items():
        if 'intent' not in files:
            _fail()
        intent = store._read(key, 'intent')
        if (set(intent) != {'binding', 'client_request_id', 'started_at_utc', 'environment'}
                or canonical_hash(intent['binding']) != key):
            _fail()
        _metadata(intent['binding'], intent['environment'])
        _timestamp(intent['started_at_utc'])
        if not re.fullmatch(r'fox-[a-f0-9]{32}', intent['client_request_id']):
            _fail()
        if key not in keys:
            binding = dict(intent['binding'])
            wire = binding.pop('wire_request_sha256')
            if not re.fullmatch(r'[a-f0-9]{64}', wire):
                _fail()
            operation = allowed.get(canonical_hash(binding))
            if operation is None or operation[:2] in used:
                _fail()
            used.add(operation[:2])
            if intent['environment']['compartment_id'] != target['oci']['compartment_id']:
                _fail()
        if 'response' in files:
            store.read(intent['binding'])
        elif key in keys:
            _fail()
    return {member.name: base._hash(member) for key in keys for member in members[key].values()}


def _derive(job, snapshot, original, target, *, previous=None):
    authority = provider._authority(job)
    provider._validate_plan(job, authority)
    consumed = provider.validate_consumed(job, authority)
    docs, packet, focus, views, first, first_owner, second, second_owner = provider._prefix(job, snapshot, original, target)
    if len(focus['requests']) != 6:
        _fail()
    from .prototype_development_reference_view import _active_focus
    from .prototype_reference_echo import POLICY as V2
    from .prototype_mapping_epochs import _role
    from .design_provider import invocation_id
    fourth = focus['requests'][3]
    view = _active_focus(job / 'prototype-pipeline', packet, focus, fourth, target, views, policy=V2, runtime=None)
    if view['checked']['approved_structured_design'] is not True:
        _fail()
    views.append(view)
    invocations = [invocation_id(view['proof'][role]) for view in views for role in ('mapper_invocation', 'reviewer_invocation')]
    if len(set(invocations)) != 8:
        _fail()
    root, selected = job / 'prototype-pipeline', snapshot['prototype']
    pivot = focus['requests'][PIVOT_INDEX]
    child = root / pivot['focus_id']
    base._same(base._read(child / 'request.json'), pivot)
    raw, invocation = _role(child, 'mapper', pivot, target,
        {'job_id': job.name, 'source_hash': selected['source_binding']}, runtime=None)
    if invocation_id(invocation) in invocations:
        _fail()
    saved = base._read(child / 'mapper.json')
    if type(saved.get('provider_response_receipt')) is not dict:
        _fail()
    candidate, receipt = project(docs, packet, pivot, raw, target)
    if receipt is None or not receipt['changes']:
        _fail()
    from .prototype_focus_projection import source_fact_gate
    try:
        source_fact_gate(packet, pivot, raw)
    except ValueError:
        pass
    else:
        _fail()
    source_fact_gate(packet, pivot, candidate)
    files, directories = base._tree(job)
    base._closure(job, files, directories, docs, focus, selected, continued=True)
    names = set(authority['plan']['before_files'])
    fourth_child = 'prototype-pipeline/' + fourth['focus_id']
    names.add(fourth_child + '/mapper.json')
    names.update(fourth_child + '/' + name for name in ('reviewer.json', 'reviewer-target.json', 'reviewer-intent.json', 'review-receipt.json'))
    if views[3]['proof']['technical_evidence_sha256'] is not None:
        names.update(fourth_child + '/' + name for name in ('projection-candidate.json', 'projection-receipt.json', 'reviewer-request.json'))
    if 'metadata_task_policy' in selected:
        names.add(fourth_child + '/reviewer-metadata-task.json')
    relative = 'prototype-pipeline/' + pivot['focus_id']
    names.update(relative + '/' + name for name in base._FIRST)
    if 'metadata_task_policy' in selected:
        names.add(relative + '/mapper-metadata-task.json')
    if not names <= files.keys():
        _fail()
    if previous is None:
        allowed_dirs = {'prototype-pipeline', 'prototype-pipeline/sources',
            *{'prototype-pipeline/' + row['focus_id'] for row in focus['requests'][:5]}}
        if files.keys() != names or not directories <= allowed_dirs:
            _fail()
    else:
        frozen = {'prototype-pipeline/' + row['focus_id'] for row in focus['requests'][:4]}
        if any(name not in names and name.rsplit('/', 1)[0] in frozen for name in files):
            _fail()
    before = {name: base._hash(files[name]) for name in sorted(names)}
    adoption = provider._read_external(job, 'adoption')
    fourth_review = base._read(root / fourth['focus_id'] / 'reviewer.json')
    keys = {adoption['receipt_binding_sha256'], fourth_review['provider_response_receipt']['receipt_binding_sha256'],
            saved['provider_response_receipt']['receipt_binding_sha256']}
    if len(keys) != 3:
        _fail()
    future = [] if previous is None else [(fid, role, request, target, selected['source_binding'])
        for fid, role, request in _future_inputs(job, packet, focus, target, views, candidate, receipt)]
    receipts = _receipt_inventory(job, keys, future)
    external = {kind: base._hash(provider.paths(job)[kind]) for kind in ('authority', 'consumed', 'adoption')}
    plan = {key: deepcopy(authority['plan'][key]) for key in ('job_id', 'project_id', 'owner', 'snapshot_sha256',
        'source_hash', 'source_binding', 'selected_source_set_id', 'development_processing_sha256',
        'original_consent_sha256', 'source_provenance_sha256', 'target_profile_sha256', 'focus_plan_sha256',
        'approved_chunk_hashes', 'parent_technical_sha256', 'parent_owner_sha256', 'parent_event_id',
        'followup_technical_sha256', 'followup_owner_sha256', 'followup_event_id')}
    plan.update(schema_version=1, scope=SCOPE, policy=POLICY, pivot_index=PIVOT_INDEX,
        pivot_focus_id=pivot['focus_id'], prefix_proofs_sha256=[canonical_hash(view['proof']) for view in views],
        provider_authority_sha256=canonical_hash(authority), provider_consumed_sha256=canonical_hash(consumed),
        provider_adoption_sha256=canonical_hash(adoption), pivot_request_sha256=canonical_hash(pivot),
        pivot_mapper_sha256=canonical_hash(saved), pivot_invocation_sha256=canonical_hash(invocation),
        pivot_provider_receipt_sha256=canonical_hash(saved['provider_response_receipt']),
        raw_candidate_sha256=canonical_hash(raw), projected_candidate_sha256=canonical_hash(candidate),
        projection_receipt_sha256=canonical_hash(receipt), projection_claim_count=len(receipt['changes']),
        before_files=before, before_external_files=external, before_receipt_files=receipts,
        additional_mapper_replays=0, independent_review_required=True,
        remaining_operations=[{'focus_id': pivot['focus_id'], 'role': 'reviewer'},
            *[{'focus_id': focus['requests'][5]['focus_id'], 'role': role} for role in ('mapper', 'reviewer')],
            *[{'stage': stage} for stage in ('render', 'offline_validate', 'package')]])
    if previous is not None:
        base._same(previous, plan)
    return plan


def inspect(job, snapshot, original, target):
    return _derive(Path(job), snapshot, original, target)


def records(plan, owner, approved_at):
    if (type(approved_at) not in (int, float) or not math.isfinite(approved_at) or approved_at <= 0
            or type(owner) is not str or not owner or owner != plan.get('owner')
            or plan.get('scope') != SCOPE or plan.get('policy') != POLICY
            or type(plan.get('pivot_index')) is not int or plan['pivot_index'] != PIVOT_INDEX
            or type(plan.get('additional_mapper_replays')) is not int or plan['additional_mapper_replays'] != 0):
        _fail()
    return {'schema_version': 1, 'scope': SCOPE, 'owner': owner, 'approved_at': approved_at,
            'plan': deepcopy(plan), 'plan_sha256': canonical_hash(plan)}


def technical(root):
    root = Path(root)
    if not provider._exists(path(root.parent)):
        return None
    value = _read(root.parent)
    from .prototype_job import read_prototype_snapshot
    snapshot, original = read_prototype_snapshot(root.parent)
    plan = value['plan']
    if root.name != 'prototype-pipeline' or not re.fullmatch(r'focus-[a-f0-9]{24}', plan['pivot_focus_id']):
        _fail()
    target = base._read(root / plan['pivot_focus_id'] / 'mapper-target.json')
    _derive(root.parent, snapshot, original, target, previous=plan)
    return value


def validate_owner(job, snapshot, original, connection):
    job = Path(job)
    value = _read(job) if provider._exists(path(job)) else None
    provider._event(connection, EVENT, job, value, 'approved_at')
    if value is None:
        return None
    if provider.validate_owner(job, snapshot, original, connection) is None:
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
        'pivot_index': plan['pivot_index'], 'pivot_focus_id': plan['pivot_focus_id'],
        'prefix_proofs_sha256': list(plan['prefix_proofs_sha256']),
        'original_prose_bytes_preserved': True, 'independent_review_required': True,
        'additional_mapper_replays': 0, 'business_behavior_accepted': False}
