"""One acknowledged NEW provider attempt; no retries, writes or provider calls."""
from copy import deepcopy
import hashlib
import json
import math
import os
from pathlib import Path
import re

from . import prototype_development_reference_resume as parent
from . import prototype_development_reference_followup as followup
from .opaf import OpafError, canonical_hash

SCOPE = 'fox-prototype-provider-reexecution-v1'
EVENT = 'approved_prototype_provider_reexecution'
CONSUMED_EVENT = 'consumed_prototype_provider_reexecution'
ADOPTION_EVENT = 'adopted_prototype_provider_reexecution'
PIVOT_INDEX = 3


def _fail():
    raise OpafError('Provider reexecution authority or captured new attempt is missing, changed or uncertain.') from None


def _time(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
        _fail()


def _epoch_microseconds(value):
    """Compare at captured ISO timestamp precision, never invent finer order."""
    from datetime import datetime, timezone
    from decimal import Decimal, ROUND_FLOOR
    if isinstance(value, str):
        stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if stamp.tzinfo is None:
            _fail()
        delta = stamp.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
        return (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds
    _time(value)
    return int((Decimal(str(value)) * 1000000).to_integral_value(rounding=ROUND_FLOOR))


def paths(job):
    job = Path(os.path.abspath(job))
    if not re.fullmatch(r'fox-[a-f0-9]{20}', job.name):
        _fail()
    data = job.parent.parent if job.parent.name == 'jobs' else job.parent
    ledger = data / 'provider-reexecution' / job.name
    return {'ledger': ledger, 'authority': ledger / 'authority.json',
        'consumed': ledger / 'consumed.json', 'adoption': ledger / 'adoption.json',
        'receipts': data / 'provider-receipts' / job.name}


def _read_external(job, kind):
    from .provider_receipts import _safe_metadata, LocalProviderReceiptStore
    path = paths(job)[kind]
    LocalProviderReceiptStore._parents(path.parent)
    for directory in (path.parent.parent, path.parent):
        _safe_metadata(directory.lstat(), directory=True)
        if os.name != 'nt' and directory.stat().st_mode & 0o077:
            _fail()
    _safe_metadata(path.lstat())
    if os.name != 'nt' and path.stat().st_mode & 0o077:
        _fail()
    return parent._read(path)


def _exists(path):
    return path.exists() or path.is_symlink()


def _event(connection, action, job, record, timestamp):
    rows = connection.execute('SELECT owner,object_id,created FROM events WHERE action=? AND '
        '(object_id=? OR substr(object_id,1,?)=?)',
        (action, job.name, len(job.name) + 1, job.name + ':')).fetchall()
    expected = [] if record is None else [(record['owner'], job.name + ':' + canonical_hash(record), record[timestamp])]
    if [tuple(row) for row in rows] != expected:
        _fail()


def _prefix(job, snapshot, original, target):
    root = job / 'prototype-pipeline'
    original_record = parent.technical(root)
    next_record = followup.technical(root)
    if original_record is None or next_record is None:
        _fail()
    original_owner = parent._read(job / parent.OWNER_RECORD)
    next_owner = parent._read(job / followup.OWNER_RECORD)
    parent._same(original_owner, parent.records(original_record['plan'], snapshot['approvals']['owner'], original_owner['approved_at'])[1])
    parent._same(next_owner, followup.records(next_record['plan'], snapshot['approvals']['owner'], next_owner['approved_at'])[1])
    documents, packet, focus = parent._reconstruct(job, snapshot, original, target)
    if len(focus['requests']) <= PIVOT_INDEX:
        _fail()
    from .prototype_development_reference_view import _active_focus
    from .prototype_chunk_evidence import POLICY as V1
    from .prototype_reference_echo import POLICY as V2
    from .design_provider import invocation_id
    views, used = [], set()
    for index, request in enumerate(focus['requests'][:PIVOT_INDEX]):
        view = _active_focus(root, packet, focus, request, target, views,
                             policy=V1 if index < 2 else V2, runtime=None)
        if view['checked']['approved_structured_design'] is not True:
            _fail()
        for role in ('mapper_invocation', 'reviewer_invocation'):
            identity = invocation_id(view['proof'][role])
            if identity in used:
                _fail()
            used.add(identity)
        views.append(view)
    return documents, packet, focus, views, original_record, original_owner, next_record, next_owner


def _derive(job, snapshot, original, target, wire, *, before_files=None):
    if type(wire) is not str or not re.fullmatch(r'[a-f0-9]{64}', wire):
        _fail()
    docs, packet, focus, views, first, first_owner, second, second_owner = _prefix(job, snapshot, original, target)
    root, selected = job / 'prototype-pipeline', snapshot['prototype']
    files, directories = parent._tree(job)
    parent._closure(job, files, directories, docs, focus, selected, continued=True)
    names = followup._base_names(docs, focus, selected, views[:2])
    names.update({followup.OWNER_RECORD, 'prototype-pipeline/' + followup.TECHNICAL})
    completed = {'reviewer.json', 'reviewer-intent.json', 'reviewer-target.json', 'review-receipt.json'}
    third = 'prototype-pipeline/' + focus['requests'][2]['focus_id']
    names.update(third + '/' + name for name in completed)
    if views[2]['proof']['technical_evidence_sha256'] is not None:
        names.update(third + '/' + name for name in ('projection-candidate.json', 'projection-receipt.json', 'reviewer-request.json'))
    if 'metadata_task_policy' in selected:
        names.add(third + '/reviewer-metadata-task.json')
    pivot = focus['requests'][PIVOT_INDEX]
    relative = 'prototype-pipeline/' + pivot['focus_id']
    names.update(relative + '/' + name for name in ('request.json', 'mapper-intent.json', 'mapper-target.json'))
    if 'metadata_task_policy' in selected:
        names.add(relative + '/mapper-metadata-task.json')
    if not names <= files.keys():
        _fail()
    if before_files is None:
        allowed_dirs = {'prototype-pipeline', 'prototype-pipeline/sources',
            *{'prototype-pipeline/' + row['focus_id'] for row in focus['requests'][:PIVOT_INDEX + 1]}}
        if files.keys() != names or not directories <= allowed_dirs:
            _fail()
    else:
        frozen = {'prototype-pipeline/' + row['focus_id'] for row in focus['requests'][:PIVOT_INDEX]}
        if any(name not in names and name.rsplit('/', 1)[0] in frozen for name in files):
            _fail()
    baseline = {name: parent._hash(files[name]) for name in sorted(names)}
    if before_files is not None:
        parent._same(baseline, before_files)
    child = root / pivot['focus_id']
    parent._same(parent._read(child / 'request.json'), pivot)
    parent._same(parent._read(child / 'mapper-target.json'), target)
    from .prototype_dsc_identity_repair import model_task
    from .design_provider import roles
    effective = model_task(child, 'mapper', pivot, write=False)
    unknown = {'role': roles(target)['mapper'], 'request_sha256': canonical_hash(effective),
               'job_id': job.name, 'source_hash': selected['source_binding']}
    parent._same(parent._read(child / 'mapper-intent.json'), unknown)
    remaining = [{'focus_id': pivot['focus_id'], 'role': 'reviewer'}]
    for request in focus['requests'][PIVOT_INDEX + 1:]:
        remaining.extend({'focus_id': request['focus_id'], 'role': role} for role in ('mapper', 'reviewer'))
    remaining.extend({'stage': stage} for stage in ('render', 'offline_validate', 'package'))
    plan = {'schema_version': 1, 'scope': SCOPE, 'job_id': job.name, 'project_id': snapshot['project_id'],
        'owner': snapshot['approvals']['owner'], 'snapshot_sha256': hashlib.sha256(original).hexdigest(),
        **{key: deepcopy(second['plan'][key]) for key in ('source_hash', 'source_binding', 'selected_source_set_id',
            'development_processing_sha256', 'original_consent_sha256', 'target_profile_sha256',
            'focus_plan_sha256', 'approved_chunk_hashes')},
        'source_provenance_sha256': canonical_hash(selected['development_processing']['source_provenance']),
        'parent_technical_sha256': canonical_hash(first), 'parent_owner_sha256': canonical_hash(first_owner),
        'parent_event_id': job.name + ':' + canonical_hash(first_owner),
        'followup_technical_sha256': canonical_hash(second), 'followup_owner_sha256': canonical_hash(second_owner),
        'followup_event_id': job.name + ':' + canonical_hash(second_owner),
        'prefix_proofs_sha256': [canonical_hash(view['proof']) for view in views],
        'pivot_index': PIVOT_INDEX, 'pivot_focus_id': pivot['focus_id'],
        'request_sha256': canonical_hash(pivot), 'effective_request_sha256': canonical_hash(effective),
        'original_unknown_intent_sha256': canonical_hash(unknown), 'expected_new_wire_sha256': wire,
        'historical_wire_sha256': None, 'historical_outcome': 'unknown', 'additional_attempt_limit': 1,
        'before_files': baseline, 'remaining_operations': remaining}
    return plan


def inspect(job, snapshot, original, target, expected_new_wire_sha256):
    return _derive(Path(job), snapshot, original, target, expected_new_wire_sha256)


def records(plan, owner, approved_at, *, acknowledged_unknown_outcome, acknowledged_possible_extra_charge):
    _time(approved_at)
    if (plan.get('scope') != SCOPE or plan.get('owner') != owner or type(owner) is not str or not owner
            or type(plan.get('pivot_index')) is not int or plan['pivot_index'] != PIVOT_INDEX
            or type(plan.get('additional_attempt_limit')) is not int or plan['additional_attempt_limit'] != 1
            or acknowledged_unknown_outcome is not True or acknowledged_possible_extra_charge is not True):
        _fail()
    return {'schema_version': 1, 'scope': SCOPE, 'owner': owner, 'approved_at': approved_at,
        'acknowledged_unknown_outcome': True, 'acknowledged_possible_extra_charge': True,
        'additional_attempt_limit': 1, 'plan': deepcopy(plan), 'plan_sha256': canonical_hash(plan)}


def _authority(job):
    value = _read_external(job, 'authority')
    parent._same(value, records(value['plan'], value['owner'], value['approved_at'],
        acknowledged_unknown_outcome=value['acknowledged_unknown_outcome'],
        acknowledged_possible_extra_charge=value['acknowledged_possible_extra_charge']))
    return value


def _validate_plan(job, authority):
    plan = authority['plan']
    snapshot_path = job / 'source-snapshot.json'
    parent._safe(snapshot_path)
    original = snapshot_path.read_bytes()
    snapshot = json.loads(original)
    if not re.fullmatch(r'focus-[a-f0-9]{24}', plan['pivot_focus_id']):
        _fail()
    target = parent._read(job / 'prototype-pipeline' / plan['pivot_focus_id'] / 'mapper-target.json')
    parent._same(plan, _derive(job, snapshot, original, target, plan['expected_new_wire_sha256'], before_files=plan['before_files']))
    return snapshot, original, target


def validate_owner(job, snapshot, original, connection):
    job = Path(job)
    prior = followup.validate_owner(job, snapshot, original, connection)
    value = _authority(job) if _exists(paths(job)['authority']) else None
    _event(connection, EVENT, job, value, 'approved_at')
    if value is None:
        if any(_exists(paths(job)[kind]) for kind in ('consumed', 'adoption')):
            _fail()
        _event(connection, CONSUMED_EVENT, job, None, 'consumed_at')
        _event(connection, ADOPTION_EVENT, job, None, 'adopted_at')
        return None
    if prior is None:
        _fail()
    actual, raw, _ = _validate_plan(job, value)
    parent._same(actual, snapshot)
    if raw != original:
        _fail()
    if _exists(paths(job)['consumed']):
        validate_consumed(job, value, connection)
    else:
        _event(connection, CONSUMED_EVENT, job, None, 'consumed_at')
    child = job / 'prototype-pipeline' / value['plan']['pivot_focus_id']
    if _exists(child / 'mapper.json') or _exists(paths(job)['adoption']):
        validate_checkpoint(child, 'mapper', parent._read(child / 'mapper.json'), connection=connection)
    else:
        _event(connection, ADOPTION_EVENT, job, None, 'adopted_at')
    return value


def consumption_record(authority, consumed_at):
    _time(consumed_at)
    if consumed_at < authority['approved_at']:
        _fail()
    return {'schema_version': 1, 'scope': SCOPE, 'owner': authority['owner'], 'consumed_at': consumed_at,
        'authority_sha256': canonical_hash(authority), 'attempt_number': 1,
        'job_id': authority['plan']['job_id'], 'plan_sha256': authority['plan_sha256']}


def require_unconsumed(job, authority, connection):
    job = Path(job)
    parent._same(_authority(job), authority)
    if any(_exists(paths(job)[kind]) for kind in ('consumed', 'adoption')):
        _fail()
    _event(connection, CONSUMED_EVENT, job, None, 'consumed_at')
    _event(connection, ADOPTION_EVENT, job, None, 'adopted_at')
    from .prototype_job import read_prototype_snapshot
    snapshot, original = read_prototype_snapshot(job)
    parent._same(validate_owner(job, snapshot, original, connection), authority)
    return True


def validate_consumed(job, authority, connection=None):
    job = Path(job)
    value = _read_external(job, 'consumed')
    parent._same(value, consumption_record(authority, value['consumed_at']))
    if connection is not None:
        _event(connection, CONSUMED_EVENT, job, value, 'consumed_at')
    return value


def read_captured_role(job, *, role_name, request, target, expected_wire_sha256):
    """Return exact parsed receipt values; source/review gates stay with caller."""
    job = Path(job)
    from .design_provider import DIRECT, PROMPTS, roles, validate_environment
    from .genai_prompts import prompt_hash
    from .provider_receipts import LocalProviderReceiptStore
    from .oci_genai import OciGenAiClient
    if role_name not in PROMPTS or type(expected_wire_sha256) is not str or not re.fullmatch(r'[a-f0-9]{64}', expected_wire_sha256):
        _fail()
    identity = {'job_id': job.name, 'source_hash': parent._read(job / 'prototype-pipeline/binding.json')['source_binding']}
    role = roles(target)[role_name]
    binding = {'schema_version': 1, 'provider': DIRECT, 'job_id': job.name,
        'source_manifest_sha256': identity['source_hash'], 'identity_sha256': canonical_hash(identity),
        'target_profile_sha256': canonical_hash(target), 'client_target_sha256': canonical_hash(target),
        'role': role_name, 'model': role['model'], 'role_sha256': canonical_hash(role),
        'prompt_version': PROMPTS[role_name], 'prompt_sha256': prompt_hash(role_name),
        'request_sha256': canonical_hash(request), 'wire_request_sha256': expected_wire_sha256}
    store = LocalProviderReceiptStore.read_only(paths(job)['receipts'], sealed_job_root=job)
    intent, response = store.read(binding)
    output, invocation = OciGenAiClient._parse_response(role, request, name=role_name,
        wire_hash=expected_wire_sha256, client_request_id=intent['client_request_id'],
        started=intent['started_at_utc'], completed=response['completed_at_utc'], body=response['body'],
        status=response['status'], request_id=response['request_id'])
    environment = intent['environment']
    validate_environment(environment, target, role_name, identity, invocation)
    evidence = {'receipt_binding_sha256': canonical_hash(binding), 'receipt_intent_sha256': canonical_hash(intent),
                'receipt_response_sha256': canonical_hash(response)}
    return output, invocation, environment, evidence


def captured_checkpoint(job, authority):
    """Parse the captured SDK body directly, without SDK/auth/network or clocks."""
    job = Path(job)
    parent._same(_authority(job), authority)
    snapshot, _, target = _validate_plan(job, authority)
    consumed = validate_consumed(job, authority)
    plan = authority['plan']
    from .prototype_job import validate_prototype_snapshot
    from .prototype_dsc_identity_repair import model_task
    request = parent._read(job / 'prototype-pipeline' / plan['pivot_focus_id'] / 'request.json')
    effective = model_task(job / 'prototype-pipeline' / plan['pivot_focus_id'], 'mapper', request, write=False)
    output, invocation, environment, evidence = read_captured_role(job, role_name='mapper', request=effective,
        target=target, expected_wire_sha256=plan['expected_new_wire_sha256'])
    from datetime import datetime
    if _epoch_microseconds(invocation['started_at_utc']) < _epoch_microseconds(consumed['consumed_at']):
        _fail()
    documents = validate_prototype_snapshot(snapshot)
    from .forms_understanding_packet import local_packet
    from .prototype_reference_echo import project
    candidate, receipt = project(documents, local_packet(documents), request, output, target)
    label = {'schema_version': 1, 'scope': SCOPE, 'new_attempt': True, 'attempt_number': 1,
        'authority_sha256': canonical_hash(authority), 'consumed_sha256': canonical_hash(consumed),
        'receipt_binding_sha256': evidence['receipt_binding_sha256'],
        'original_unknown_intent_sha256': plan['original_unknown_intent_sha256']}
    saved = {'binding': parent._read(job / 'prototype-pipeline' / plan['pivot_focus_id'] / 'mapper-intent.json'), 'output': output,
        'output_sha256': canonical_hash(output), 'invocation': invocation, 'model_environment': environment,
        'model_environment_sha256': canonical_hash(environment), 'provider_reexecution': label}
    evidence.update(projected_candidate_sha256=canonical_hash(candidate), projection_receipt_sha256=canonical_hash(receipt))
    return saved, evidence


def adoption_record(authority, consumed, saved, evidence, adopted_at):
    _time(adopted_at)
    from datetime import datetime
    if (adopted_at < consumed['consumed_at']
            or _epoch_microseconds(adopted_at) < _epoch_microseconds(saved['invocation']['completed_at_utc'])):
        _fail()
    return {'schema_version': 1, 'scope': SCOPE, 'owner': authority['owner'], 'adopted_at': adopted_at,
        'kind': 'new_provider_attempt_checkpoint', 'attempt_number': 1,
        'authority_sha256': canonical_hash(authority), 'consumed_sha256': canonical_hash(consumed),
        'mapper_checkpoint_sha256': canonical_hash(saved), **deepcopy(evidence)}


def validate_checkpoint(directory, name, saved, *, connection=None):
    directory = Path(directory)
    job = directory.parent.parent
    if directory.parent.name != 'prototype-pipeline' or not re.fullmatch(r'fox-[a-f0-9]{20}', job.name):
        if isinstance(saved, dict) and 'provider_reexecution' in saved:
            _fail()
        return None
    authority_path = paths(job)['authority']
    if not _exists(authority_path):
        if isinstance(saved, dict) and 'provider_reexecution' in saved:
            _fail()
        return None
    authority = _authority(job)
    if name != 'mapper' or directory.name != authority['plan']['pivot_focus_id']:
        return None
    consumed = validate_consumed(job, authority, connection)
    expected, evidence = captured_checkpoint(job, authority)
    parent._same(saved, expected)
    marker = _read_external(job, 'adoption')
    parent._same(marker, adoption_record(authority, consumed, expected, evidence, marker['adopted_at']))
    if connection is not None:
        _event(connection, ADOPTION_EVENT, job, marker, 'adopted_at')
    return marker
