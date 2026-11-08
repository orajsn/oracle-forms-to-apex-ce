"""Explicit epoch6: review one sealed mapper9 projection, then continue once.

No retained approval is reinterpreted. Projection derives from original source
and exact prior reviewed views; only new independent review can approve it.
"""
from copy import deepcopy
import hashlib
import math
from pathlib import Path
import sqlite3

from . import prototype_mapping_epochs as epochs, prototype_partition_review_epoch as partition
from . import prototype_container_epoch as container, prototype_clause_epoch as clause
from .opaf import OpafError, canonical_hash
from .prototype_claim_resolution import resolve_claim_owners
from .prototype_focus_projection import source_fact_gate
from .prototype_context_screen_projection import project_context_screens
from .prototype_partition_review import build_partition_review_task

NUMBER = 6
NAME = 'epoch-000006'
PREFIX = 'epochs/' + NAME
RECORD = 'mapping-epochs/' + NAME + '.json'
STRATEGY = 'context-screen-projection-v1'
PROJECTOR_SHA256 = '67577835743872632bc14daaf0f168b58bd0d0ba3f515a7915f2d96357cca022'
POLICY = {**partition.POLICY, 'context_screen_projection': STRATEGY,
    'projector_sha256': PROJECTOR_SHA256, 'new_corrective_model_calls': 1,
    'repeated_mapper_calls': 0, 'repeated_reviewer_calls': 0}
TECHNICAL_FILES = {'epoch-record.json', 'predecessor-record.json', 'screen-projection-receipt.json'}
RESULT_BASE = 'prototype-result-publications/' + NAME
RESULT_FILES = {RESULT_BASE + '/' + name for name in ('previous-result.json', 'publication.json')}
DIRECTORIES = {RESULT_BASE, 'prototype-pipeline/' + PREFIX, 'prototype-pipeline/' + PREFIX + '/source-facts'}
SCREEN_FILES = {'screen-input-candidate.json', 'screen-projection-receipt.json'}


def _fail():
    raise OpafError('The sealed context-screen continuation is changed, uncertain or not explicitly authorized.') from None


def _historical_five_focus(root, packet, plan, request, target, previous, record):
    if record['epoch_number'] != partition.NUMBER:
        _fail()
    from .prototype_read_scope import cached_read
    return cached_read(root, 'active_focus', {'purpose': 'sealed-epoch-five-prereview-v1',
        'record_sha256': canonical_hash(record), 'packet': packet, 'plan': plan, 'request': request,
        'target': target, 'previous': previous},
        lambda: partition.active_focus(root, packet, plan, request, target, previous, record))


def _first_eight(root, packet, plan, target, record):
    if len(plan['requests']) < 10:
        _fail()
    previous = []
    for request in plan['requests'][:8]:
        view = _historical_five_focus(root, packet, plan, request, target, previous, record)
        if view['checked']['approved_structured_design'] is not True:
            _fail()
        previous.append(view)
    return previous


def _saved_mapper_nine(root, packet, plan, target):
    request = plan['requests'][8]
    directory = root / partition.PREFIX / request['focus_id']
    expected = {'mapper' + suffix for suffix in ('-request.json', '-target.json', '-intent.json', '.json')}
    epochs._safe_path(directory.parent, directory.name)
    if {path.name for path in directory.iterdir()} != expected:
        _fail()
    epochs.same(epochs.read(directory / 'mapper-request.json'), request)
    raw, invocation = epochs._role(directory, 'mapper', request, target,
        {'job_id': root.parent.name, 'source_hash': packet['source_binding']})
    candidate, owner_receipt = resolve_claim_owners(request, raw)
    # This recovery is screen-only. Do not fold a new owner repair into it.
    if owner_receipt is not None or canonical_hash(candidate) != canonical_hash(raw):
        _fail()
    source_fact_gate(packet, request, raw)
    return raw, invocation


def _project(packet, plan, request, raw, previous, target):
    return project_context_screens(packet, plan, [view['candidate'] for view in previous] + [raw],
        container._refs(plan, previous, target), expected_source_binding=packet['source_binding'],
        expected_plan_sha256=canonical_hash(plan), expected_focus_id=request['focus_id'],
        expected_request_sha256=canonical_hash(request), expected_raw_candidate_sha256=canonical_hash(raw),
        expected_target_sha256=canonical_hash(target))


def _sealed_five_layout(root, plan, record):
    request = plan['requests'][8]
    allowed = set(partition.TECHNICAL_FILES) | {
        request['focus_id'] + '/mapper' + suffix for suffix in ('-request.json', '-target.json', '-intent.json', '.json')}
    expected_directories = {name.rsplit('/', depth)[0] for name in allowed
        for depth in range(1, name.count('/') + 1)}
    actual, directories = set(), set()
    for path in (root / partition.PREFIX).rglob('*'):
        relative = path.relative_to(root / partition.PREFIX).as_posix()
        epochs._safe_path(root / partition.PREFIX, relative)
        if path.is_file(): actual.add(relative)
        elif path.is_dir(): directories.add(relative)
        else: _fail()
    if actual != allowed or directories != expected_directories:
        _fail()
    # Original/old epoch namespaces cannot acquire later work either.
    for prefix in ('', epochs.PREFIX, clause.PREFIX, container.PREFIX):
        for future in plan['requests'][8:]:
            path = root / prefix / future['focus_id']
            if path.exists() or path.is_symlink(): _fail()


def _read_unpublished_five_record(job, snapshot, original, db, *, historical_six):
    """Identity/event/proof reader ONLY for the exact unpublished pre-review5."""
    predecessor = container._validated_historical_four(job, snapshot, original, db,
        historical_head=NUMBER if historical_six else partition.NUMBER)
    root = job / 'prototype-pipeline'
    record = partition.technical_record(root)
    epochs.same(epochs.read(job / partition.RECORD), record)
    descriptor = partition._fresh_descriptor(job, snapshot, original, canonical_hash(predecessor))
    epochs.same(epochs.read(root / partition.PREFIX / 'partition-proof-descriptor.json'), descriptor)
    partition._shape(record, predecessor, descriptor)
    rows = db.execute('SELECT owner,object_id,created FROM events WHERE action=? AND object_id LIKE ?',
        (epochs.EVENT, job.name + ':epoch:%')).fetchall()
    chain = [epochs.read(job / epochs.RECORD), epochs.read(job / clause.RECORD), predecessor, record]
    expected = {(row['owner'], epochs.event_id(job.name, row), row['approved_at']) for row in chain}
    if historical_six:
        rows = [row for row in rows if row[1].startswith(tuple(job.name + ':epoch:' + f'{n:06d}' + ':' for n in (2, 3, 4, 5)))]
    if len(rows) != 4 or {tuple(row) for row in rows} != expected: _fail()
    epochs._before_unchanged(job, {name: digest for name, digest in record['before_files'].items() if name != 'prototype-result.json'})
    from .prototype_result_publication import _validate_previous, validate_publication
    publication = job / partition.RESULT_BASE / 'publication.json'
    if publication.exists() or publication.is_symlink(): _fail()
    _validate_previous(job, record)  # Actual epoch5 archive of latest4; not a fifth result.
    if not historical_six and validate_publication(job, record) is not None: _fail()
    target = epochs.read(root / record['plan']['repair_focus_id'] / 'mapper-target.json')
    packet, plan = epochs.reconstruct(job, snapshot, original, target)
    members = partition._members(root / partition.PREFIX / 'partition-proof')
    partition._proof(root, packet, plan, target, predecessor, descriptor, members)
    if members != partition._members(partition._stage(job) / 'json', protected=True): _fail()
    _sealed_five_layout(root, plan, record)
    previous = _first_eight(root, packet, plan, target, record)
    raw, invocation = _saved_mapper_nine(root, packet, plan, target)
    candidate, receipt = _project(packet, plan, plan['requests'][8], raw, previous, target)
    if receipt['status'] != 'PROJECTED_UNREVIEWED' or len(receipt['removed_screens']) != 1:
        _fail()
    return record, packet, plan, target, previous, raw, candidate, receipt


def sealed_head_five_prereview(job, snapshot, original, target, db):
    """Narrow terminal admission, never a relaxed general validate_epoch_chain."""
    job = Path(job)
    row = db.execute('SELECT state FROM runs WHERE id=?', (job.name,)).fetchone()
    if row is None or row[0] != 'ATTENTION': _fail()
    if (job / RECORD).exists() or (job / 'prototype-pipeline' / PREFIX).exists(): _fail()
    data = _read_unpublished_five_record(job, snapshot, original, db, historical_six=False)
    epochs.same(data[3], target)
    root = job / 'prototype-pipeline'
    for name in ('merged-blueprint.json', 'native-plan.json', 'review-index.json', 'rendered.json', 'candidate-apexlang.zip',
        *{stage + suffix for stage in ('validate', 'prepare_schema', 'import', 'verify_runtime', 'export')
          for suffix in ('.json', '-intent.json')}):
        if (root / name).exists() or (root / name).is_symlink(): _fail()
    epochs._closure(job, record=data[0], known_focuses={row['focus_id'] for row in data[2]['requests']})
    return data


def terminal_candidate_present(job, plan, db):
    if (job / RECORD).exists() or (job / RECORD).is_symlink(): return False
    if not (job / partition.RECORD).exists() or len(plan['requests']) < 10: return False
    row = db.execute('SELECT state FROM runs WHERE id=?', (job.name,)).fetchone()
    return (row is not None and row[0] == 'ATTENTION'
        and (job / 'prototype-pipeline' / partition.PREFIX / plan['requests'][8]['focus_id'] / 'mapper.json').exists()
        and not (job / partition.RESULT_BASE / 'publication.json').exists())


def _plan(predecessor, receipt, previous_result, plan):
    return {**predecessor['plan'], 'ai_approved_focuses': 8, 'source_checked_focuses': 8,
        'source_fact_violations': 0, 'saved_mapping_focuses': 1, 'saved_mapping_source_checked': True,
        'pending_review_focus_id': plan['requests'][8]['focus_id'], 'unstarted_focus_count': len(plan['requests']) - 9,
        'remaining_focus_count': len(plan['requests']) - 8, 'projected_context_screens': 1,
        'new_corrective_model_calls': 1, 'repeated_mapper_calls': 0, 'repeated_reviewer_calls': 0,
        'planned_corrective_operations': ['review_saved_projection'], 'screen_projection_sha256': canonical_hash(receipt),
        'previous_result': previous_result}


def _checkpoint(predecessor, before, plan):
    return canonical_hash({'epoch_number': NUMBER, 'predecessor_sha256': predecessor,
        'before_files': before, 'plan': plan, 'normalization_policy': POLICY})


def inspect_next(job, snapshot, original, target, db, record=None):
    if record is not None and record['epoch_number'] == NUMBER:
        return record['plan'], record['before_files'], record, record['checkpoint_sha256'], record['predecessor_sha256']
    old, packet, plan, target, previous, raw, candidate, receipt = sealed_head_five_prereview(job, snapshot, original, target, db)
    before = epochs._closure(job, record=old, known_focuses={row['focus_id'] for row in plan['requests']})
    from .prototype_result_publication import previous_result
    proposed = _plan(old, receipt, previous_result(job, before, old['plan']['projection_focus_id'], packet['source_binding']), plan)
    predecessor = canonical_hash(old)
    return proposed, before, None, _checkpoint(predecessor, before, proposed), predecessor


def adopt(job, snapshot, original, record):
    # The same transaction still holds owner/source permission; this checks the
    # complete terminal evidence again, before ANY archive/record write.
    database = epochs._safe_path(job.parent.parent, 'fox.sqlite3')
    with sqlite3.connect(database.absolute().as_uri() + '?mode=ro', uri=True) as db:
        target = epochs.read(job / 'prototype-pipeline' / record['plan']['repair_focus_id'] / 'mapper-target.json')
        data = sealed_head_five_prereview(job, snapshot, original, target, db)
    old, packet, plan, target, previous, raw, candidate, receipt = data
    if canonical_hash(receipt) != record['screen_projection_sha256'] or canonical_hash(old) != record['predecessor_sha256']:
        _fail()
    epochs._before_unchanged(job, record['before_files'])
    from .prototype_result_publication import preserve_previous
    preserve_previous(job, record)
    epochs.save(job / RECORD, record, True)
    base = job / 'prototype-pipeline' / PREFIX
    epochs.save(base / 'epoch-record.json', record, True)
    epochs.save(base / 'predecessor-record.json', old, True)
    epochs.save(base / 'screen-projection-receipt.json', receipt, True)


def _shape(record, old, receipt, plan):
    if (set(record) != (set(old) - {'partition_proof_sha256'}) | {'screen_projection_sha256'}
        or type(record['schema_version']) is not int or record['schema_version'] != 1
        or record['scope'] != epochs.SCOPE or record['strategy'] != STRATEGY
        or type(record['epoch_number']) is not int or record['epoch_number'] != NUMBER
        or record['predecessor_sha256'] != canonical_hash(old)
        or record['screen_projection_sha256'] != canonical_hash(receipt)
        or record['normalization_policy'] != POLICY
        or record['plan'] != _plan(old, receipt, record['plan']['previous_result'], plan)
        or type(record['approved_at']) not in (int, float) or not math.isfinite(record['approved_at'])
        or record['approved_at'] <= old['approved_at']
        or record['checkpoint_sha256'] != _checkpoint(record['predecessor_sha256'], record['before_files'], record['plan'])): _fail()
    for key in ('job_id', 'project_id', 'snapshot_sha256', 'source_hash', 'source_binding',
        'target_profile_sha256', 'owner', 'approvals'): epochs.same(record[key], old[key])
    epochs._descriptors(record['before_files'])


def technical_record(root):
    base = epochs._safe_path(root, PREFIX + '/epoch-record.json').parent
    record = epochs.read(base / 'epoch-record.json')
    epochs._descriptors(record['before_files'])
    old = partition.technical_record(root)
    epochs.same(epochs.read(base / 'predecessor-record.json'), old)
    target = epochs.read(root / record['plan']['repair_focus_id'] / 'mapper-target.json')
    packet = epochs.read(root / 'packet.json')
    # No source snapshot/DB in the receiver: full plan from preserved sources.
    from .prototype_pipeline import _artifact_json
    from .forms_focus import build_focus_plan
    from .prototype_admission import bound_focus_limit
    manifest = epochs.read(root / 'sources-manifest.json')
    documents = [(row['name'], epochs._safe_path(root, 'sources/' + f'source-{i:03}.xml').read_bytes())
        for i, row in enumerate(manifest['files'])]
    binding = epochs.read(root / 'binding.json')
    plan = build_focus_plan(documents, expected_source_binding=binding['source_binding'],
        approved_chunk_hashes=manifest['selected_chunk_hashes'], max_owned_objects=bound_focus_limit(binding))
    if canonical_hash(plan) != binding['focus_plan_sha256']: _fail()
    _sealed_five_layout(root, plan, old)
    previous = _first_eight(root, packet, plan, target, old)
    raw, invocation = _saved_mapper_nine(root, packet, plan, target)
    candidate, receipt = _project(packet, plan, plan['requests'][8], raw, previous, target)
    epochs.same(epochs.read(base / 'screen-projection-receipt.json'), receipt)
    _shape(record, old, receipt, plan)
    for name, digest in epochs._descriptors(record['before_files']):
        if name.startswith('prototype-pipeline/'):
            path = epochs._safe_path(root, name[len('prototype-pipeline/'):])
            if not path.is_file() or path.stat().st_size > 20_000_000 or hashlib.sha256(path.read_bytes()).hexdigest() != digest: _fail()
    return record


def validate_record(job, snapshot, original, db=None):
    close = db is None
    if close:
        database = epochs._safe_path(job.parent.parent, 'fox.sqlite3')
        db = sqlite3.connect(database.absolute().as_uri() + '?mode=ro', uri=True)
    try:
        old, packet, plan, target, previous, raw, candidate, receipt = _read_unpublished_five_record(job, snapshot, original, db, historical_six=True)
        record = technical_record(job / 'prototype-pipeline')
        epochs.same(epochs.read(job / RECORD), record)
        _shape(record, old, receipt, plan)
        rows = db.execute('SELECT owner,object_id,created FROM events WHERE action=? AND object_id LIKE ?',
            (epochs.EVENT, job.name + ':epoch:%')).fetchall()
        chain = [epochs.read(job / epochs.RECORD), epochs.read(job / clause.RECORD),
            epochs.read(job / container.RECORD), old, record]
        expected = {(row['owner'], epochs.event_id(job.name, row), row['approved_at']) for row in chain}
        if len(rows) != 5 or {tuple(row) for row in rows} != expected: _fail()
        epochs._before_unchanged(job, {n: d for n, d in record['before_files'].items() if n != 'prototype-result.json'})
        from .prototype_result_publication import validate_publication
        validate_publication(job, record)
        return record
    finally:
        if close: db.close()


def _review_task(root, packet, plan, request, target, previous, candidate, evidence, write):
    payload, audit = build_partition_review_task(packet, plan, [v['candidate'] for v in previous] + [candidate],
        container._refs(plan, previous, target), expected_target_sha256=canonical_hash(target),
        expected_candidate_sha256=canonical_hash(candidate), review_context=evidence)
    epochs.save(root / PREFIX / request['focus_id'] / 'full-audit-context.json', audit, write)
    return payload


def _projection(root, packet, plan, request, target, previous, candidate, raw, base_evidence, write):
    projected, receipt = _project(packet, plan, request, candidate, previous, target)
    directory = root / PREFIX / request['focus_id']
    epochs.save(directory / 'screen-input-candidate.json', candidate, write)
    epochs.save(directory / 'screen-projection-receipt.json', receipt, write)
    return projected, {'schema_version': 1, 'scope': 'fox-focus-context-screen-normalization-v1',
        'base_technical_evidence': deepcopy(base_evidence), 'context_screen_projection': receipt,
        'raw_mapper_candidate_sha256': canonical_hash(raw)}


def active_focus(root, packet, plan, request, target, previous, record, *, runtime=None, preview=False):
    index = next(i for i, row in enumerate(plan['requests']) if row['focus_id'] == request['focus_id'])
    if len(previous) != index: _fail()
    if previous: container._prefix(packet, plan, previous, target)
    old = epochs.read(root / PREFIX / 'predecessor-record.json')
    if index < 8:
        return _historical_five_focus(root, packet, plan, request, target, previous, old)
    write = runtime is not None
    if index == 8:
        raw, mapper = _saved_mapper_nine(root, packet, plan, target)
        candidate, evidence = _projection(root, packet, plan, request, target, previous, raw, raw, None, write)
        receipt = evidence['context_screen_projection']
        if canonical_hash(receipt) != record['screen_projection_sha256']: _fail()
        directory = root / PREFIX / request['focus_id']
        epochs.save(directory / 'projection-candidate.json', candidate, write)
        epochs.save(directory / 'projection-receipt.json', evidence, write)
        payload = _review_task(root, packet, plan, request, target, previous, candidate,
            {'raw_candidate': raw, 'raw_candidate_sha256': canonical_hash(raw), 'evidence': evidence}, write)
        epochs.save(directory / 'reviewer-request.json', payload, write)
        if preview: return {'review_request': payload}
        output, reviewer = epochs._role(directory, 'reviewer', payload, target,
            {'job_id': root.parent.name, 'source_hash': packet['source_binding']}, runtime)
        if mapper['room_id'] == reviewer['room_id']: _fail()
        checked = epochs._review(request, candidate, output, directory)
        epochs.save(directory / 'review-receipt.json', checked, write)
        gate = source_fact_gate(packet, request, candidate)
        epochs.save(root / PREFIX / 'source-facts' / (request['focus_id'] + '.json'), gate, write)
        return {'candidate': candidate, 'checked': checked, 'proof': {
            'focus_id': request['focus_id'], 'kind': 'REVIEWED_CONTEXT_SCREEN_PROJECTION',
            'candidate_sha256': canonical_hash(candidate), 'source_fact_check': gate,
            'active_directory': directory.relative_to(root).as_posix(), 'mapper_invocation': mapper,
            'retained_mapper_directory': partition.PREFIX + '/' + request['focus_id'],
            'reviewer_invocation': reviewer, 'review_request_sha256': canonical_hash(payload),
            'review_sha256': canonical_hash(output), 'review_receipt_sha256': canonical_hash(checked),
            'technical_evidence_sha256': canonical_hash(evidence)}}
    def projection(candidate, raw, evidence):
        return _projection(root, packet, plan, request, target, previous, candidate, raw, evidence, write)
    def context(candidate, payload):
        return _review_task(root, packet, plan, request, target, previous, candidate, payload.get('review_context'), write)
    return epochs._active_focus(root, packet, plan, request, target, previous, record, PREFIX,
        runtime=runtime, preview=preview, review_context=context, candidate_projection=projection)


def model_fence(job, snapshot, record):
    root = job / 'prototype-pipeline'
    target = epochs.read(root / record['plan']['repair_focus_id'] / 'mapper-target.json')
    packet, plan = epochs.reconstruct(job, snapshot, (job / 'source-snapshot.json').read_bytes(), target)
    previous, incomplete = [], False
    for index, request in enumerate(plan['requests']):
        if index < 8:
            previous.append(active_focus(root, packet, plan, request, target, previous, record)); continue
        if not incomplete: container._prefix(packet, plan, previous, target)
        directory = root / PREFIX / request['focus_id']
        for name in ('reviewer',) if index == 8 else ('mapper', 'reviewer'):
            paths = [directory / (name + suffix) for suffix in ('-request.json', '-target.json', '-intent.json', '.json')]
            exists = [path.exists() or path.is_symlink() for path in paths]
            if incomplete and any(exists): _fail()
            if not exists[2] and not exists[3]:
                if any(exists):
                    if not exists[0]: _fail()
                    payload = request if name == 'mapper' else active_focus(root, packet, plan, request, target, previous, record, preview=True)['review_request']
                    epochs.same(epochs.read(paths[0]), payload)
                    if exists[1]: epochs.same(epochs.read(paths[1]), target)
                incomplete = True; continue
            if not all(exists): _fail()
            if name == 'mapper':
                epochs.same(epochs.read(paths[0]), request)
                epochs._role(directory, name, request, target, {'job_id': job.name, 'source_hash': plan['source_binding']})
                active_focus(root, packet, plan, request, target, previous, record, preview=True)
        if not incomplete:
            view = active_focus(root, packet, plan, request, target, previous, record)
            previous.append(view)
            if not view['checked']['approved_structured_design']: incomplete = True
    return {row['focus_id'] for row in plan['requests']}
