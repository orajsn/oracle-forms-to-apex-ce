"""Explicit epoch five: reuse one retained compact approval, continue once.

Operator staging is data, not consent. Original epoch-four rejection/publication,
source and target remain immutable history; the first NEW operation is mapper9.
"""
from copy import deepcopy
import hashlib
import math
from pathlib import Path
import sqlite3

from . import prototype_mapping_epochs as epochs, prototype_container_epoch as container
from . import prototype_clause_epoch as clause
from .opaf import OpafError, canonical_hash
from .prototype_partition_review import build_partition_review_task
from .prototype_partition_review_proof import FILES, FORMATTER_SHA256, validate_partition_review_members
from .prototype_clause_proof import MAX_FILE_BYTES, MAX_TOTAL_BYTES, _check_names
from .prototype_focus_projection import source_fact_gate

NUMBER = 5
NAME = 'epoch-000005'
PREFIX = 'epochs/' + NAME
RECORD = 'mapping-epochs/' + NAME + '.json'
STRATEGY = 'retained-compact-review-v1'
STAGING_SCOPE = 'fox-prototype-partition-proof-staging-v1'
POLICY = {**container.POLICY, 'partition_review': STRATEGY,
          'corrective_projection_review_calls': 0,
          'new_corrective_model_calls': 0, 'repeated_mapper_calls': 0, 'repeated_reviewer_calls': 0}
TECHNICAL_FILES = {'epoch-record.json', 'predecessor-record.json', 'partition-proof-descriptor.json',
                   *{'partition-proof/' + name for name in FILES}}
RESULT_BASE = 'prototype-result-publications/' + NAME
RESULT_FILES = {RESULT_BASE + '/' + name for name in ('previous-result.json', 'publication.json')}
DIRECTORIES = {RESULT_BASE, 'prototype-pipeline/' + PREFIX, 'prototype-pipeline/' + PREFIX + '/source-facts',
    *{'prototype-pipeline/' + PREFIX + '/partition-proof' + suffix for suffix in ('', '/review')}}


def _fail():
    raise OpafError('Retained partition review epoch is incomplete, changed or not explicitly authorized.') from None


def _stage(job):
    return job.parent.parent / 'prototype-partition-review-proofs' / job.name


def staging_present(job):
    path = _stage(Path(job))
    return path.exists() or path.is_symlink()


def _descriptor(value, *, job_id, project_id, owner, snapshot_sha256, source_hash,
                source_binding, original_target_sha256, predecessor_sha256):
    keys = {'schema_version', 'scope', 'job_id', 'project_id', 'owner', 'snapshot_sha256',
        'source_hash', 'source_binding', 'original_target_sha256', 'predecessor_sha256',
        'formatter_sha256', 'original_manifest', 'original_manifest_sha256', 'original_files',
        'original_files_sha256', 'candidate_sha256', 'review_task_sha256', 'expected_history_pins'}
    if (type(value) is not dict or set(value) != keys or type(value['schema_version']) is not int
            or value['schema_version'] != 1 or value['scope'] != STAGING_SCOPE
            or value['formatter_sha256'] != FORMATTER_SHA256
            or value['original_manifest_sha256'] != canonical_hash(value['original_manifest'])
            or value['original_files_sha256'] != canonical_hash(value['original_files'])):
        _fail()
    bindings = locals()
    for key in ('job_id', 'project_id', 'owner', 'snapshot_sha256', 'source_hash', 'source_binding',
                'original_target_sha256', 'predecessor_sha256'):
        epochs.same(value[key], bindings[key])
    epochs._descriptors(value['original_files'])
    if type(value['expected_history_pins']) is not dict or set(value['expected_history_pins']) != {'request_sha256', 'receipt_sha256', 'output_sha256'}:
        _fail()
    for digest in [value['candidate_sha256'], value['review_task_sha256'], *value['expected_history_pins'].values()]:
        epochs._descriptor('pin', digest)
    return value


def _fresh_descriptor(job, snapshot, original, predecessor_sha):
    base = _stage(job)
    for path in (base.parent, base, base / 'json', base / 'json/review'):
        clause._protected(path, directory=True)
    epochs.same(sorted(path.name for path in base.iterdir()), ['descriptor.json', 'json'])
    clause._protected(base / 'descriptor.json')
    return _descriptor(epochs.read(base / 'descriptor.json'), job_id=job.name,
        project_id=snapshot['project_id'], owner=snapshot['approvals']['owner'],
        snapshot_sha256=hashlib.sha256(original).hexdigest(), source_hash=snapshot['source_hash'],
        source_binding=snapshot['prototype']['source_binding'],
        original_target_sha256=snapshot['prototype']['target_profile_sha256'], predecessor_sha256=predecessor_sha)


def _members(directory, *, protected=False):
    epochs._safe_path(directory.parent, directory.name)
    _check_names(directory, {name for name in FILES if '/' not in name} | {'review'})
    epochs._safe_path(directory, 'review')
    _check_names(directory / 'review', {'reviewer.json', 'reviewer-intent.json', 'reviewer-target.json'})
    raw = {}
    for name in sorted(FILES):
        path = epochs._safe_path(directory, name)
        if protected:
            clause._protected(path)
        metadata = path.stat()
        if not path.is_file() or metadata.st_nlink != 1 or not 0 < metadata.st_size <= MAX_FILE_BYTES:
            _fail()
        with path.open('rb') as stream:
            body = stream.read(MAX_FILE_BYTES + 1)
        if len(body) != metadata.st_size:
            _fail()
        raw[name] = body
        if sum(map(len, raw.values())) > MAX_TOTAL_BYTES:
            _fail()
    return raw


def _historical(root, packet, plan, target, predecessor):
    """Force the fixed epoch-four head; never current-head or cache dispatch."""
    if (predecessor['epoch_number'] != container.NUMBER or len(plan['requests']) < 9
            or plan['requests'][7]['focus_id'] != predecessor['plan']['projection_focus_id']):
        _fail()
    views = []
    for request in plan['requests'][:8]:
        view = container._historical_active_focus(root, packet, plan, request, target, views, predecessor)
        if view['checked']['approved_structured_design'] is not (len(views) < 7):
            _fail()
        views.append(view)
    for prefix in ('', epochs.PREFIX, clause.PREFIX, container.PREFIX):
        for request in plan['requests'][8:]:
            path = root / prefix / request['focus_id']
            if path.exists() or path.is_symlink():
                _fail()
    for name in ('merged-blueprint.json', 'native-plan.json', 'review-index.json', 'rendered.json', 'candidate-apexlang.zip',
            *{stage + suffix for stage in ('validate', 'prepare_schema', 'import', 'verify_runtime', 'export')
              for suffix in ('.json', '-intent.json')}):
        # Downstream evidence is forbidden only at adoption. Head-five itself
        # can later legitimately create these fixed pipeline stage artifacts.
        if (root / PREFIX).exists():
            break
        if (root / name).exists() or (root / name).is_symlink():
            _fail()
    directory = root / container.PREFIX / plan['requests'][7]['focus_id']
    return views[:7], views[7], epochs.read(directory / 'reviewer-request.json'), epochs.read(directory / 'reviewer.json')


def _proof(root, packet, plan, target, predecessor, descriptor, members):
    views, rejected, request, receipt = _historical(root, packet, plan, target, predecessor)
    pins = {'request_sha256': canonical_hash(request), 'receipt_sha256': canonical_hash(receipt),
            'output_sha256': canonical_hash(receipt['output'])}
    epochs.same(pins, descriptor['expected_history_pins'])
    candidate, checked, provenance = validate_partition_review_members(members,
        approved_manifest=descriptor['original_manifest'], expected_manifest_sha256=descriptor['original_manifest_sha256'],
        formatter_sha256=descriptor['formatter_sha256'], packet=packet, full_plan=plan, historical_views=views,
        rejected_request=request, rejected_receipt=receipt, original_target=target,
        identity={'job_id': root.parent.name, 'source_hash': packet['source_binding']},
        original_files=descriptor['original_files'], expected_history_pins=pins)
    if (canonical_hash(candidate) != descriptor['candidate_sha256']
            or provenance['review_request_sha256'] != descriptor['review_task_sha256']):
        _fail()
    epochs.same(candidate, rejected['candidate'])
    return candidate, checked, provenance


def _plan(predecessor, descriptor, previous_result):
    return {**predecessor['plan'], 'ai_approved_focuses': 8, 'source_checked_focuses': 8,
        'source_fact_violations': 0,
        'partition_proof_sha256': canonical_hash(descriptor), 'reused_review_focuses': 1,
        'new_corrective_model_calls': 0, 'repeated_mapper_calls': 0, 'repeated_reviewer_calls': 0,
        'planned_corrective_operations': [], 'previous_result': previous_result}


def _checkpoint(predecessor, before, plan):
    return canonical_hash({'epoch_number': NUMBER, 'predecessor_sha256': predecessor,
        'before_files': before, 'plan': plan, 'normalization_policy': POLICY})


def inspect_next(job, snapshot, original, target, db, record):
    if record['epoch_number'] == NUMBER:
        return record['plan'], record['before_files'], record, record['checkpoint_sha256'], record['predecessor_sha256']
    if record['epoch_number'] != container.NUMBER:
        _fail()
    packet, plan = epochs.reconstruct(job, snapshot, original, target)
    predecessor = canonical_hash(record)
    descriptor = _fresh_descriptor(job, snapshot, original, predecessor)
    _proof(job / 'prototype-pipeline', packet, plan, target, record, descriptor, _members(_stage(job) / 'json', protected=True))
    before = epochs._closure(job, record=record, known_focuses={row['focus_id'] for row in plan['requests']})
    epochs.same(descriptor['original_files'], before)
    epochs._before_unchanged(job, before)
    from .prototype_result_publication import previous_result
    proposed = _plan(record, descriptor, previous_result(job, before, plan['requests'][7]['focus_id'], packet['source_binding']))
    return proposed, before, None, _checkpoint(predecessor, before, proposed), predecessor


def adopt(job, snapshot, original, record):
    descriptor = _fresh_descriptor(job, snapshot, original, record['predecessor_sha256'])
    if canonical_hash(descriptor) != record['partition_proof_sha256']:
        _fail()
    epochs.same(descriptor['original_files'], record['before_files'])
    epochs._before_unchanged(job, record['before_files'])
    members = _members(_stage(job) / 'json', protected=True)
    root = job / 'prototype-pipeline'
    predecessor = epochs.read(job / container.RECORD)
    target = epochs.read(root / record['plan']['repair_focus_id'] / 'mapper-target.json')
    packet, plan = epochs.reconstruct(job, snapshot, original, target)
    _proof(root, packet, plan, target, predecessor, descriptor, members)
    from .prototype_result_publication import preserve_previous
    preserve_previous(job, record)
    epochs.save(job / RECORD, record, True)
    base = root / PREFIX
    epochs.save(base / 'epoch-record.json', record, True)
    epochs.save(base / 'predecessor-record.json', predecessor, True)
    epochs.save(base / 'partition-proof-descriptor.json', descriptor, True)
    from .prototype_pipeline import _save_bytes_once
    for name, raw in members.items():
        path = epochs._safe_path(base, 'partition-proof/' + name)
        path.parent.mkdir(parents=True, exist_ok=True)
        _save_bytes_once(path, raw)
    if _fresh_descriptor(job, snapshot, original, record['predecessor_sha256']) != descriptor or _members(_stage(job) / 'json', protected=True) != members:
        _fail()


def _shape(record, predecessor, descriptor):
    if (set(record) != (set(predecessor) - {'container_proof_sha256'}) | {'partition_proof_sha256'}
            or type(record['epoch_number']) is not int or record['epoch_number'] != NUMBER
            or record['strategy'] != STRATEGY or record['scope'] != epochs.SCOPE
            or type(record['schema_version']) is not int or record['schema_version'] != 1
            or record['predecessor_sha256'] != canonical_hash(predecessor)
            or record['partition_proof_sha256'] != canonical_hash(descriptor)
            or record['plan'] != _plan(predecessor, descriptor, record['plan']['previous_result'])
            or record['normalization_policy'] != POLICY
            or type(record['approved_at']) not in (int, float) or not math.isfinite(record['approved_at'])
            or record['approved_at'] <= predecessor['approved_at']
            or record['checkpoint_sha256'] != _checkpoint(record['predecessor_sha256'], record['before_files'], record['plan'])):
        _fail()
    for key in ('job_id', 'project_id', 'snapshot_sha256', 'source_hash', 'source_binding',
                'target_profile_sha256', 'owner', 'approvals'):
        epochs.same(record[key], predecessor[key])
    epochs._descriptors(record['before_files'])
    epochs.same(descriptor['original_files'], record['before_files'])


def technical_record(root):
    base = epochs._safe_path(root, PREFIX + '/epoch-record.json').parent
    record = epochs.read(base / 'epoch-record.json')
    epochs._descriptors(record['before_files'])
    predecessor = container.technical_record(root)
    epochs.same(epochs.read(base / 'predecessor-record.json'), predecessor)
    descriptor = epochs.read(base / 'partition-proof-descriptor.json')
    _descriptor(descriptor, job_id=record['job_id'], project_id=record['project_id'], owner=record['owner'],
        snapshot_sha256=record['snapshot_sha256'], source_hash=record['source_hash'], source_binding=record['source_binding'],
        original_target_sha256=record['target_profile_sha256'], predecessor_sha256=canonical_hash(predecessor))
    _shape(record, predecessor, descriptor)
    for name, digest in epochs._descriptors(record['before_files']):
        if name.startswith('prototype-pipeline/'):
            path = epochs._safe_path(root, name[len('prototype-pipeline/'):])
            if not path.is_file() or path.stat().st_size > 20_000_000 or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                _fail()
    return record


def validate_record(job, snapshot, original, db=None):
    close = db is None
    if close:
        database = epochs._safe_path(job.parent.parent, 'fox.sqlite3')
        db = sqlite3.connect(database.absolute().as_uri() + '?mode=ro', uri=True)
    try:
        predecessor = container._validated_historical_four(job, snapshot, original, db)
        record = technical_record(job / 'prototype-pipeline')
        epochs.same(epochs.read(job / RECORD), record)
        descriptor = _fresh_descriptor(job, snapshot, original, canonical_hash(predecessor))
        epochs.same(epochs.read(job / 'prototype-pipeline' / PREFIX / 'partition-proof-descriptor.json'), descriptor)
        _shape(record, predecessor, descriptor)
        rows = db.execute('SELECT owner,object_id,created FROM events WHERE action=? AND object_id LIKE ?',
            (epochs.EVENT, job.name + ':epoch:%')).fetchall()
        chain = [epochs.read(job / epochs.RECORD), epochs.read(job / clause.RECORD), predecessor, record]
        expected = {(row['owner'], epochs.event_id(job.name, row), row['approved_at']) for row in chain}
        if len(rows) != 4 or {tuple(row) for row in rows} != expected:
            _fail()
        epochs._before_unchanged(job, {name: digest for name, digest in record['before_files'].items() if name != 'prototype-result.json'})
        from .prototype_result_publication import validate_publication
        validate_publication(job, record)
        root = job / 'prototype-pipeline'
        target = epochs.read(root / record['plan']['repair_focus_id'] / 'mapper-target.json')
        packet, plan = epochs.reconstruct(job, snapshot, original, target)
        members = _members(root / PREFIX / 'partition-proof')
        _proof(root, packet, plan, target, predecessor, descriptor, members)
        if members != _members(_stage(job) / 'json', protected=True):
            _fail()
        return record
    finally:
        if close:
            db.close()


def active_focus(root, packet, plan, request, target, previous, record, *, runtime=None, preview=False):
    index = next(i for i, row in enumerate(plan['requests']) if row['focus_id'] == request['focus_id'])
    if len(previous) != index:
        _fail()
    if previous:
        container._prefix(packet, plan, previous, target)
    predecessor = epochs.read(root / PREFIX / 'predecessor-record.json')
    if index < 7:
        return container._historical_active_focus(root, packet, plan, request, target, previous, predecessor)
    if index == 7:
        descriptor = epochs.read(root / PREFIX / 'partition-proof-descriptor.json')
        candidate, checked, provenance = _proof(root, packet, plan, target, predecessor, descriptor,
            _members(root / PREFIX / 'partition-proof'))
        proof = {'focus_id': request['focus_id'], 'kind': 'RETAINED_COMPACT_PARTITION_REVIEW',
            'candidate_sha256': canonical_hash(candidate), 'source_fact_check': source_fact_gate(packet, request, candidate),
            'active_directory': PREFIX + '/partition-proof', 'partition_proof_sha256': canonical_hash(descriptor),
            'reviewer_invocation': provenance['review_invocation'], 'review_request_sha256': provenance['review_request_sha256'],
            'review_receipt_sha256': provenance['review_receipt_sha256'], 'review_sha256': provenance['review_output_sha256'],
            'prior_review_request_sha256': provenance['prior_review_request_sha256'],
            'prior_review_checkpoint_sha256': provenance['prior_review_checkpoint_sha256'],
            'full_audit_context_sha256': provenance['full_audit_context_sha256'],
            'formatter_sha256': provenance['formatter_sha256'], 'file_manifest_sha256': provenance['file_manifest_sha256']}
        return {'candidate': candidate, 'checked': checked, 'proof': proof}
    def context(candidate, payload):
        task, audit = build_partition_review_task(packet, plan, [view['candidate'] for view in previous] + [candidate],
            container._refs(plan, previous, target), expected_target_sha256=canonical_hash(target),
            expected_candidate_sha256=canonical_hash(candidate), review_context=payload.get('review_context'))
        epochs.save(root / PREFIX / request['focus_id'] / 'full-audit-context.json', audit, runtime is not None)
        return task
    return epochs._active_focus(root, packet, plan, request, target, previous, record, PREFIX,
        runtime=runtime, preview=preview, review_context=context)


def model_fence(job, snapshot, record):
    from .prototype_job import validate_prototype_snapshot
    from .forms_focus import build_focus_plan
    from .prototype_admission import bound_focus_limit
    selected = snapshot['prototype']
    plan = build_focus_plan(validate_prototype_snapshot(snapshot), expected_source_binding=selected['source_binding'],
        approved_chunk_hashes=selected['approved_chunk_hashes'], max_owned_objects=bound_focus_limit(selected))
    if canonical_hash(plan) != selected['focus_plan_sha256']:
        _fail()
    root = job / 'prototype-pipeline'
    packet = epochs.read(root / 'packet.json')
    target = epochs.read(root / plan['requests'][0]['focus_id'] / 'mapper-target.json')
    previous, incomplete = [], False
    for index, request in enumerate(plan['requests']):
        if index < 8:
            previous.append(active_focus(root, packet, plan, request, target, previous, record))
            continue
        if not incomplete:
            container._prefix(packet, plan, previous, target)
        directory = root / PREFIX / request['focus_id']
        for name in ('mapper', 'reviewer'):
            paths = [directory / (name + suffix) for suffix in ('-request.json', '-target.json', '-intent.json', '.json')]
            exists = [path.exists() or path.is_symlink() for path in paths]
            if incomplete and any(exists):
                _fail()
            if not exists[2] and not exists[3]:
                if any(exists):
                    if not exists[0]:
                        _fail()
                    payload = request if name == 'mapper' else active_focus(root, packet, plan, request,
                        target, previous, record, preview=True)['review_request']
                    epochs.same(epochs.read(paths[0]), payload)
                    if exists[1]:
                        epochs.same(epochs.read(paths[1]), target)
                incomplete = True
                continue
            if not all(exists):
                _fail()
            if name == 'mapper':
                epochs.same(epochs.read(paths[0]), request)
                epochs._role(directory, name, request, target, {'job_id': job.name, 'source_hash': plan['source_binding']})
                active_focus(root, packet, plan, request, target, previous, record, preview=True)
        if not incomplete:
            view = active_focus(root, packet, plan, request, target, previous, record)
            previous.append(view)
            if not view['checked']['approved_structured_design']:
                incomplete = True
    return {row['focus_id'] for row in plan['requests']}
