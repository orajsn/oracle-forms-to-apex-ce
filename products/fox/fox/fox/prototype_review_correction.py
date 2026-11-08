"""One explicit review-scope correction beneath an existing epoch-six record.

The failed response remains invalid evidence, never a historical review receipt.
Only its deterministic context-only finding defect admits a distinct review task.
"""
from copy import deepcopy
import hashlib
import json
import math

from . import forms_design_review as review
from . import prototype_mapping_epochs as epochs
from .opaf import OpafError, canonical_hash

SCOPE = 'fox-prototype-review-scope-correction-v1'
EVENT = 'approved_prototype_review_scope_correction'
PREFIX = 'epochs/epoch-000006/review-correction'
RECORD = PREFIX + '/authorization.json'
ATTEMPT = PREFIX + '/attempt-000001'
REASON = 'Review response referred to an object outside this section. Your saved mapping is preserved.'
FILES = {'authorization.json', *{'attempt-000001/reviewer' + suffix for suffix in
    ('-request.json', '-target.json', '-intent.json', '.json')}, 'attempt-000001/review-receipt.json'}


def _fail():
    raise OpafError('The saved review correction is changed, uncertain or not explicitly authorized.') from None


class NotApplicable(ValueError):
    """A structurally valid review is not a review-scope correction candidate."""


def present(root):
    path = root / RECORD
    return path.exists() or path.is_symlink()


def event_id(job_id, record):
    return job_id + ':review-correction:000006:' + canonical_hash(record)


def scope_defect(request, candidate, output):
    """Prove that scope attribution alone invalidates an otherwise valid review.

    Unknown IDs, mixed genuine findings, malformed envelopes and semantic
    negatives do not qualify. Replacing IDs in a COPY is a validator probe only;
    neither that copy nor a receipt for it is persisted or used as approval.
    """
    owned = {row['id'] for row in request['owned_objects']}
    context = {row['id'] for row in request['context_objects']}
    if (type(output) is not dict or output.get('verdict') != 'CHANGES_REQUIRED'
            or type(output.get('findings')) is not list or not output['findings']):
        _fail()
    findings = output['findings']
    if any(type(row) is not dict or row.get('source_object_id') not in context - owned for row in findings):
        _fail()
    probe = deepcopy(output)
    for row in probe['findings']:
        row['source_object_id'] = None
    review.validate_design_review(request, candidate, probe)
    try:
        review.validate_design_review(request, candidate, output)
    except ValueError:
        return {'kind': 'CONTEXT_ONLY_FINDING_ATTRIBUTION',
                'non_owned_finding_ids': sorted({row['source_object_id'] for row in findings})}
    _fail()


def _pins(directory, payload, target, identity):
    epochs.same(epochs.read(directory / 'reviewer-request.json'), payload)
    output, invocation = epochs._role(directory, 'reviewer', payload, target, identity)
    try:
        review.validate_design_review(payload['request'], payload['candidate'], output)
    except ValueError:
        pass
    else:
        raise NotApplicable()
    defect = scope_defect(payload['request'], payload['candidate'], output)
    if (directory / 'review-receipt.json').exists() or (directory / 'review-receipt.json').is_symlink():
        _fail()
    return {'failed_request_sha256': hashlib.sha256((directory / 'reviewer-request.json').read_bytes()).hexdigest(),
        'failed_response_sha256': hashlib.sha256((directory / 'reviewer.json').read_bytes()).hexdigest(),
        'failed_task_sha256': canonical_hash(payload), 'failed_output_sha256': canonical_hash(output),
        'failed_invocation_sha256': canonical_hash(invocation), **defect}, invocation


def ownership_ledger(payload):
    request = payload['request']
    compact = payload['design_context']
    inherited = []
    for row in compact['owned_rows']:
        screen = row['screen_context']
        if screen is not None and screen['borrowed_from_prior_focus']:
            value = {key: screen[key] for key in ('source_ref', 'mapping_ref', 'owner_ref', 'screen_ref')}
            value['declaration'] = deepcopy(compact['tables']['screens'][screen['screen_ref']])
            if value not in inherited:
                inherited.append(value)
    return {'owned_objects': [{'id': row['id'], 'kind': row['kind']} for row in request['owned_objects']],
        'context_only_objects': [{'id': row['id'], 'kind': row['kind']} for row in request['context_objects']],
        'inherited_screens': inherited,
        'rule': 'Only owned_objects may be finding source_object_id values. Context grants no ownership. '
                'Inherited screens need no local declaration without an owned Block. '
                'Use null for an application-level finding; genuine semantic defects still block.'}


def correction_task(payload, pins):
    task = deepcopy(payload)
    task['scope'] = SCOPE
    task['ownership_ledger'] = ownership_ledger(payload)
    task['correction_of'] = deepcopy(pins)
    task['task_guidance'] += (' The explicit ownership_ledger is authoritative for section ownership. '
        'This is a new independent review of the unchanged candidate, not acceptance of the old response. '
        'The prior response was rejected structurally and is not a semantic review receipt. '
        'Do not force approval; identify any genuine defects in the owned mapping.')
    task.pop('task_binding')
    task['task_binding'] = canonical_hash(task)
    review._canonical(task, 650_000)
    if len(json.dumps(task, ensure_ascii=False, allow_nan=False).encode('utf-8')) > 650_000:
        _fail()
    return task


def future_review_task(payload):
    """Clarify new later calls only; this pure task grants no new authority."""
    task = deepcopy(payload)
    task['ownership_ledger'] = ownership_ledger(payload)
    task['task_guidance'] += (' The explicit ownership_ledger distinguishes owned objects from context-only '
        'objects and inherited screens. Only owned IDs (or null for a global finding) may be used in '
        'findings. Context grants no ownership. Reject genuine semantic defects; do not force approval.')
    task.pop('task_binding')
    task['task_binding'] = canonical_hash(task)
    review._canonical(task, 650_000)
    if len(json.dumps(task, ensure_ascii=False, allow_nan=False).encode('utf-8')) > 650_000:
        _fail()
    return task


def _plan(root, epoch, packet, plan, target, previous):
    # Immutable technical derivation only. No DB consent, current owner/selection
    # or execution result crosses the existing operation-local fenced scope.
    from .prototype_read_scope import cached_read
    return cached_read(root, 'active_focus', {'purpose': 'review-correction-plan-v1',
        'epoch': epoch, 'packet': packet, 'plan': plan, 'target': target, 'previous': previous},
        lambda: _derive_plan(root, epoch, packet, plan, target, previous))


def _derive_plan(root, epoch, packet, plan, target, previous):
    from . import prototype_context_screen_epoch as screen
    request = plan['requests'][8]
    directory = epochs._safe_path(root, screen.PREFIX + '/' + request['focus_id'])
    # The historical formatter stays unchanged and is reconstructed byte-for-byte.
    raw, mapper = screen._saved_mapper_nine(root, packet, plan, target)
    candidate, evidence = screen._projection(root, packet, plan, request, target, previous, raw, raw, None, False)
    epochs.same(epochs.read(directory / 'projection-candidate.json'), candidate)
    epochs.same(epochs.read(directory / 'projection-receipt.json'), evidence)
    payload = screen._review_task(root, packet, plan, request, target, previous, candidate,
        {'raw_candidate': raw, 'raw_candidate_sha256': canonical_hash(raw), 'evidence': evidence}, False)
    pins, invocation = _pins(directory, payload, target,
        {'job_id': root.parent.name, 'source_hash': packet['source_binding']})
    if invocation['room_id'] == mapper['room_id']: _fail()
    task = correction_task(payload, pins)
    proposed = {**pins, 'pending_review_focus_id': request['focus_id'], 'candidate_sha256': canonical_hash(candidate),
        'design_context_sha256': payload['design_context_sha256'], 'corrected_task_sha256': canonical_hash(task),
        'ownership_ledger_sha256': canonical_hash(task['ownership_ledger']), 'ai_approved_focuses': len(previous),
        'saved_mapping_focuses': 1, 'unstarted_focus_count': len(plan['requests']) - 9,
        'remaining_focus_count': len(plan['requests']) - 8, 'new_reviewer_calls': 1, 'repeated_mapper_calls': 0}
    return proposed, task, invocation


def checkpoint(epoch, before, plan):
    return canonical_hash({'scope': SCOPE, 'epoch_record_sha256': canonical_hash(epoch),
        'before_files': before, 'plan': plan})


def validate_authorization(root, epoch, packet, plan, target, previous, *, full_job=False):
    record = epochs.read(epochs._safe_path(root, RECORD))
    proposed, task, invocation = _plan(root, epoch, packet, plan, target, previous)
    expected_keys = {'schema_version', 'scope', 'epoch_number', 'epoch_record_sha256', 'job_id', 'project_id',
        'snapshot_sha256', 'source_hash', 'source_binding', 'target_profile_sha256', 'owner', 'approvals',
        'approved_at', 'before_files', 'plan', 'checkpoint_sha256'}
    if (set(record) != expected_keys or type(record['schema_version']) is not int or record['schema_version'] != 1
            or record['scope'] != SCOPE or type(record['epoch_number']) is not int or record['epoch_number'] != 6
            or record['epoch_record_sha256'] != canonical_hash(epoch) or record['plan'] != proposed
            or type(record['approved_at']) not in (int, float) or not math.isfinite(record['approved_at'])
            or record['approved_at'] <= epoch['approved_at']
            or record['checkpoint_sha256'] != checkpoint(epoch, record['before_files'], proposed)):
        _fail()
    for key in ('job_id', 'project_id', 'snapshot_sha256', 'source_hash', 'source_binding',
                'target_profile_sha256', 'owner', 'approvals'):
        epochs.same(record[key], epoch[key])
    epochs._descriptors(record['before_files'])
    if full_job:
        epochs._before_unchanged(root.parent, {name: digest for name, digest in record['before_files'].items()
            if name != 'prototype-result.json'})
    else:
        # Receiver has inert pipeline provenance, not FOX's private job/DB files.
        epochs._before_unchanged(root, {name[len('prototype-pipeline/'):]: digest
            for name, digest in record['before_files'].items() if name.startswith('prototype-pipeline/')})
    # The baseline cannot authorize hidden future work or omit the failed evidence.
    for path in (root / 'epochs/epoch-000006' / plan['requests'][8]['focus_id']).iterdir():
        relative = path.relative_to(root.parent).as_posix()
        if relative not in record['before_files']:
            _fail()
    return record, task, invocation


def validate_event(root, record, db):
    rows = db.execute('SELECT owner,object_id,created FROM events WHERE action=? AND object_id LIKE ?',
        (EVENT, root.parent.name + ':review-correction:%')).fetchall()
    if record is None:
        if rows: _fail()
    elif len(rows) != 1 or tuple(rows[0]) != (record['owner'], event_id(root.parent.name, record), record['approved_at']):
        _fail()


def inspect(job, snapshot, original, target, db):
    from . import prototype_context_screen_epoch as screen
    root = job / 'prototype-pipeline'
    if not present(root):
        transport = job / 'prototype-transport'
        facts = root / screen.PREFIX / 'source-facts'
        if (transport.exists() or transport.is_symlink() or facts.is_symlink()
                or facts.exists() and (not facts.is_dir() or any(facts.iterdir()))):
            _fail()  # The invalid-review stop cannot have downstream authority or facts.
    epoch = screen.validate_record(job, snapshot, original, db)
    packet, plan = epochs.reconstruct(job, snapshot, original, target)
    old = epochs.read(root / screen.PREFIX / 'predecessor-record.json')
    previous = screen._first_eight(root, packet, plan, target, old)
    proposed, task, invocation = _plan(root, epoch, packet, plan, target, previous)
    if present(root):
        record, _, _ = validate_authorization(root, epoch, packet, plan, target, previous, full_job=True)
        validate_event(root, record, db)
        epochs.validate_epoch_chain(job, snapshot, original, db)
        return proposed, record['before_files'], record, record['checkpoint_sha256'], epoch
    validate_event(root, None, db)
    if (root / PREFIX).exists() or (root / PREFIX).is_symlink(): _fail()
    row = db.execute('SELECT state FROM runs WHERE id=?', (job.name,)).fetchone()
    if row is None or row[0] != 'ATTENTION': _fail()
    if (job / screen.RESULT_BASE / 'publication.json').exists(): _fail()
    for request in plan['requests'][9:]:
        path = root / screen.PREFIX / request['focus_id']
        if path.exists() or path.is_symlink(): _fail()
    forbidden = ['merged-blueprint.json', 'native-plan.json', 'review-index.json', 'rendered.json', 'candidate-apexlang.zip',
        *{stage + suffix for stage in ('validate', 'prepare_schema', 'import', 'verify_runtime', 'export')
          for suffix in ('.json', '-intent.json')}, screen.PREFIX + '/source-facts/' + plan['requests'][8]['focus_id'] + '.json']
    if any((root / name).exists() or (root / name).is_symlink() for name in forbidden): _fail()
    before = epochs._closure(job, record=epoch, known_focuses={row['focus_id'] for row in plan['requests']})
    return proposed, before, None, checkpoint(epoch, before, proposed), epoch


def review_attempt(root, epoch, packet, plan, target, previous, request, candidate, mapper, runtime, preview):
    record, task, failed_invocation = validate_authorization(root, epoch, packet, plan, target, previous)
    directory = root / ATTEMPT
    epochs.save(directory / 'reviewer-request.json', task, runtime is not None)
    if preview:
        return {'review_request': task}
    output, invocation = epochs._role(directory, 'reviewer', task, target,
        {'job_id': root.parent.name, 'source_hash': packet['source_binding']}, runtime)
    prior_rooms = {failed_invocation['room_id'], mapper['room_id']}
    def rooms(value):
        if type(value) is dict:
            if type(value.get('room_id')) is str: prior_rooms.add(value['room_id'])
            for child in value.values(): rooms(child)
        elif type(value) is list:
            for child in value: rooms(child)
    rooms([view['proof'] for view in previous])
    if invocation['room_id'] in prior_rooms: _fail()
    checked = review.validate_design_review(request, candidate, output)
    epochs.save(directory / 'review-receipt.json', checked, runtime is not None)
    return checked, invocation, task, directory, canonical_hash(record)
