"""Explicit epoch four: adopt one retained root review, review context once.

Fixed operator data is not authority. The owner DB event, original source and
all previous calls remain mandatory. No archived Python is copied or executed.
"""
from copy import deepcopy
import hashlib
import math
from pathlib import Path
import re
import sqlite3

from . import prototype_mapping_epochs as epochs, prototype_clause_epoch as clause
from .opaf import OpafError, canonical_hash
from .prototype_container_proof import JSON_FILES, CONTEXT_MODULE_SHA256, validate_container_proof_members
from .prototype_clause_proof import MAX_FILE_BYTES, MAX_TOTAL_BYTES
from .prototype_design_context import validate_prefix_context, build_review_context, REFERENCE_SCOPE
from .prototype_focus_projection import source_fact_gate

NUMBER = 4
NAME = 'epoch-000004'
PREFIX = 'epochs/' + NAME
RECORD = 'mapping-epochs/' + NAME + '.json'
STRATEGY = 'retained-container-review-context-v1'
STAGING_SCOPE = 'fox-prototype-container-proof-staging-v1'
OPERATIONS = ['projection_review']
POLICY = {**clause.POLICY, 'container_proof': STRATEGY, 'prefix_context': 'exact-active-prefix-v1',
          'new_container_review_calls': 0, 'repeated_root_mapper_calls': 0,
          'repeated_projection_mapper_calls': 0, 'corrective_projection_review_calls': 1}
TECHNICAL_FILES = {'epoch-record.json', 'predecessor-record.json', 'container-proof-descriptor.json',
                   *{'container-proof/' + name for name in JSON_FILES}}
RESULT_BASE = 'prototype-result-publications/' + NAME
RESULT_FILES = {RESULT_BASE + '/' + name for name in ('previous-result.json', 'publication.json')}
DIRECTORIES = {'prototype-result-publications', RESULT_BASE, 'prototype-pipeline/' + PREFIX,
    'prototype-pipeline/' + PREFIX + '/source-facts',
    *{'prototype-pipeline/' + PREFIX + '/container-proof' + suffix for suffix in ('', '/review')}}


def _fail():
    raise OpafError('Container continuation proof is incomplete, changed or not explicitly authorized.') from None


def _stage(job):
    return job.parent.parent / 'prototype-container-proofs' / job.name


def staging_present(job):
    path = _stage(Path(job))
    return path.exists() or path.is_symlink()


def _descriptor(value, snapshot, original, job_id, predecessor_sha):
    keys = {'schema_version', 'scope', 'job_id', 'project_id', 'owner', 'snapshot_sha256',
        'source_hash', 'source_binding', 'original_target_sha256', 'predecessor_sha256', 'module_id',
        'context_module_sha256', 'original_manifest', 'original_manifest_sha256', 'original_files',
        'original_files_sha256', 'original_candidate_sha256', 'candidate_sha256'}
    if (type(value) is not dict or set(value) != keys or type(value['schema_version']) is not int
            or value['schema_version'] != 1 or value['scope'] != STAGING_SCOPE
            or value['context_module_sha256'] != CONTEXT_MODULE_SHA256
            or value['original_manifest_sha256'] != canonical_hash(value['original_manifest'])
            or value['original_files_sha256'] != canonical_hash(value['original_files'])):
        _fail()
    for key, expected in {'job_id': job_id, 'project_id': snapshot['project_id'],
            'owner': snapshot['approvals']['owner'], 'snapshot_sha256': hashlib.sha256(original).hexdigest(),
            'source_hash': snapshot['source_hash'], 'source_binding': snapshot['prototype']['source_binding'],
            'original_target_sha256': snapshot['prototype']['target_profile_sha256'],
            'predecessor_sha256': predecessor_sha}.items():
        epochs.same(value[key], expected)
    epochs._descriptors(value['original_files'])
    for name in ('original_candidate_sha256', 'candidate_sha256', 'predecessor_sha256'):
        epochs._descriptor('pin', value[name])
    return value


def _fresh_descriptor(job, snapshot, original, predecessor_sha):
    base = _stage(job)
    for path in (base.parent, base, base / 'json', base / 'json/review'):
        clause._protected(path, directory=True)
    epochs.same(sorted(path.name for path in base.iterdir()), ['descriptor.json', 'json'])
    clause._protected(base / 'descriptor.json')
    return _descriptor(epochs.read(base / 'descriptor.json'), snapshot, original, job.name, predecessor_sha)


def _members(directory, *, protected=False):
    from .prototype_clause_proof import _check_names
    epochs._safe_path(directory.parent, directory.name)
    _check_names(directory, {name for name in JSON_FILES if '/' not in name} | {'review'})
    epochs._safe_path(directory, 'review')
    _check_names(directory / 'review', {'reviewer.json', 'reviewer-intent.json', 'reviewer-target.json'})
    raw = {}
    for name in sorted(JSON_FILES):
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
    """Read the exact epoch-three head, never redispatch through current head."""
    if (len(plan['requests']) < 8 or plan['requests'][6]['focus_id'] != predecessor['plan']['repair_focus_id']
            or plan['requests'][7]['focus_id'] != predecessor['plan']['projection_focus_id']):
        _fail()
    views = []
    for request in plan['requests'][:8]:
        view = clause.active_focus(root, packet, plan, request, target, views, predecessor)
        if view['checked']['approved_structured_design'] is (len(views) == 7):
            _fail()
        views.append(view)
    # Epoch three must have stopped at its rejected projection, not later work.
    base = root / clause.PREFIX
    for request in plan['requests'][8:]:
        if (base / request['focus_id']).exists() or (base / request['focus_id']).is_symlink():
            _fail()
    rejected_dir = base / plan['requests'][7]['focus_id']
    review = epochs.read(rejected_dir / 'reviewer.json')
    return views[:7], views[7], review


def _proof(root, packet, plan, target, predecessor, descriptor, members):
    """Reuse a complete technical result only inside this exact fenced operation.

    Pipeline files (including historical role/normalization/source sidecars) are
    entry/exit fenced. The two installed module files are outside that fence:
    their original exact-byte/manifest checks therefore run on EVERY hit.
    No caller authority, current owner, DB/event or processing check is cached.
    """
    from . import prototype_read_scope as scope
    current = scope.current_read_root()
    if current is None:
        return _proof_uncached(root, packet, plan, target, predecessor, descriptor, members)
    if current != Path(root).absolute():
        scope._fail()
    from .forms_blueprint import _index_cache_eligible
    inputs = [packet, plan, target, predecessor, descriptor]
    # Only ordinary bounded inputs can form keys. Unsupported inputs retain the
    # old validation, including its original errors, rather than being rejected
    # or canonically colliding with a previously checked plain value.
    if (root.name != 'prototype-pipeline' or not _index_cache_eligible(inputs)
            or type(plan) is not dict or type(plan.get('requests')) is not list
            or len(plan['requests']) < 8
            or any(type(row) is not dict or type(row.get('focus_id')) is not str
                   or not re.fullmatch('focus-[a-f0-9]{24}', row['focus_id']) for row in plan['requests'])
            or type(members) is not dict or set(members) != JSON_FILES
            or any(type(body) is not bytes or not 0 < len(body) <= MAX_FILE_BYTES for body in members.values())
            or sum(map(len, members.values())) > MAX_TOTAL_BYTES):
        return _proof_uncached(root, packet, plan, target, predecessor, descriptor, members)
    # Retain potentially failing existence/directory checks, even on hits.
    active = root / PREFIX
    if active.exists():
        allowed = {request['focus_id'] for request in plan['requests'][7:]}
        for path in active.iterdir():
            if path.name.startswith('focus-') and path.name not in allowed:
                _fail()
    for request in plan['requests'][8:]:
        path = root / clause.PREFIX / request['focus_id']
        if path.exists() or path.is_symlink():
            _fail()
    from . import prototype_container_proof as proof, prototype_clause_proof as clause_proof
    # Preserve the public receiver's error normalization for its original guard.
    try:
        checked_members, manifest = proof._guard_members(members,
            descriptor['context_module_sha256'], descriptor['original_manifest'])
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError,
            OverflowError, UnicodeError, OpafError):
        proof._fail()
    # Read CURRENT descriptor bytes, never an earlier successful module pin.
    clause_descriptor = epochs.read(root / clause.PREFIX / 'clause-proof-descriptor.json', 65_536)
    if not _index_cache_eligible(clause_descriptor):
        return _proof_uncached(root, packet, plan, target, predecessor, descriptor, members)
    try:
        clause_proof._manifest(clause_descriptor['original_manifest'])
        clause_proof._guard_installed_module(clause_descriptor['original_manifest'])
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError,
            OverflowError, UnicodeError, OpafError):
        clause_proof._fail()
    identity = canonical_hash({'purpose': 'complete-retained-container-proof-v1',
        'inputs': inputs, 'manifest': manifest, 'clause_descriptor': clause_descriptor,
        'members': {name: {'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
                    for name, body in checked_members.items()}})
    return scope.optional_container_proof(root, identity,
        lambda: _proof_uncached(root, packet, plan, target, predecessor, descriptor, members))


def _proof_uncached(root, packet, plan, target, predecessor, descriptor, members):
    active = root / PREFIX
    if active.exists():
        allowed = {request['focus_id'] for request in plan['requests'][7:]}
        for path in active.iterdir():
            if path.name.startswith('focus-') and path.name not in allowed:
                _fail()
    views, rejected, review = _historical(root, packet, plan, target, predecessor)
    candidate, checked, provenance = validate_container_proof_members(members,
        context_module_sha256=descriptor['context_module_sha256'], approved_manifest=descriptor['original_manifest'],
        packet=packet, full_plan=plan, historical_views=views, rejected_candidate=rejected['candidate'],
        rejected_review=review['output'], rejected_invocation=review['invocation'], original_target=target,
        identity={'job_id': root.parent.name, 'source_hash': packet['source_binding']},
        module_id=descriptor['module_id'], original_files=descriptor['original_files'])
    if (provenance['candidate_sha256'] != descriptor['candidate_sha256']
            or provenance['original_candidate_sha256'] != descriptor['original_candidate_sha256']):
        _fail()
    return candidate, checked, provenance


def _plan(predecessor, descriptor, previous_result):
    return {**predecessor['plan'], 'planned_corrective_operations': list(OPERATIONS),
        'container_proof_sha256': canonical_hash(descriptor), 'container_corrections': 1,
        'new_container_review_calls': 0, 'repeated_root_mapper_calls': 0,
        'repeated_projection_mapper_calls': 0, 'corrective_projection_review_calls': 1,
        'previous_result': previous_result}


def _checkpoint(predecessor, before, plan):
    return canonical_hash({'epoch_number': NUMBER, 'predecessor_sha256': predecessor,
        'before_files': before, 'plan': plan, 'normalization_policy': POLICY})


def inspect_next(job, snapshot, original, target, db, record):
    if record['epoch_number'] == NUMBER:
        return record['plan'], record['before_files'], record, record['checkpoint_sha256'], record['predecessor_sha256']
    if record['epoch_number'] != clause.NUMBER:
        _fail()
    packet, plan = epochs.reconstruct(job, snapshot, original, target)
    predecessor = canonical_hash(record)
    descriptor = _fresh_descriptor(job, snapshot, original, predecessor)
    _proof(job / 'prototype-pipeline', packet, plan, target, record, descriptor, _members(_stage(job) / 'json', protected=True))
    before = epochs._closure(job, record=record, known_focuses={row['focus_id'] for row in plan['requests']})
    epochs._before_unchanged(job, descriptor['original_files'])
    from .prototype_result_publication import previous_result
    proposed = _plan(record, descriptor, previous_result(job, before, plan['requests'][7]['focus_id'], packet['source_binding']))
    return proposed, before, None, _checkpoint(predecessor, before, proposed), predecessor


def adopt(job, snapshot, original, record):
    descriptor = _fresh_descriptor(job, snapshot, original, record['predecessor_sha256'])
    if canonical_hash(descriptor) != record['container_proof_sha256']:
        _fail()
    epochs._before_unchanged(job, record['before_files'])
    epochs._before_unchanged(job, descriptor['original_files'])
    members = _members(_stage(job) / 'json', protected=True)
    root = job / 'prototype-pipeline'
    predecessor = epochs.read(job / clause.RECORD)
    target = epochs.read(root / record['plan']['repair_focus_id'] / 'mapper-target.json')
    packet, plan = epochs.reconstruct(job, snapshot, original, target)
    _proof(root, packet, plan, target, predecessor, descriptor, members)
    from .prototype_result_publication import preserve_previous
    preserve_previous(job, record)
    epochs.save(job / RECORD, record, True)
    base = root / PREFIX
    epochs.save(base / 'epoch-record.json', record, True)
    epochs.save(base / 'predecessor-record.json', predecessor, True)
    epochs.save(base / 'container-proof-descriptor.json', descriptor, True)
    from .prototype_pipeline import _save_bytes_once
    for name, raw in members.items():
        path = epochs._safe_path(base, 'container-proof/' + name)
        path.parent.mkdir(parents=True, exist_ok=True)
        _save_bytes_once(path, raw)
    if _fresh_descriptor(job, snapshot, original, record['predecessor_sha256']) != descriptor or _members(_stage(job) / 'json', protected=True) != members:
        _fail()


def _shape(record, predecessor, descriptor):
    if (set(record) != (set(predecessor) - {'clause_proof_sha256'}) | {'container_proof_sha256'}
            or type(record['epoch_number']) is not int or record['epoch_number'] != NUMBER
            or record['strategy'] != STRATEGY or record['scope'] != epochs.SCOPE
            or type(record['schema_version']) is not int or record['schema_version'] != 1
            or record['predecessor_sha256'] != canonical_hash(predecessor)
            or record['container_proof_sha256'] != canonical_hash(descriptor)
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
    for name, digest in epochs._descriptors(descriptor['original_files']):
        if record['before_files'].get(name) != digest:
            _fail()


def technical_record(root):
    base = epochs._safe_path(root, PREFIX + '/epoch-record.json').parent
    record = epochs.read(base / 'epoch-record.json')
    epochs._descriptors(record['before_files'])
    predecessor = clause.technical_record(root)
    epochs.same(epochs.read(base / 'predecessor-record.json'), predecessor)
    descriptor = epochs.read(base / 'container-proof-descriptor.json')
    # The technical receiver has no snapshot/DB; compare all identity pins to
    # the immutable predecessor, while the FOX callback checks actual consent.
    for key, expected in {'job_id': record['job_id'], 'project_id': record['project_id'],
        'owner': record['owner'], 'snapshot_sha256': record['snapshot_sha256'],
        'source_hash': record['source_hash'], 'source_binding': record['source_binding'],
        'original_target_sha256': record['target_profile_sha256'], 'predecessor_sha256': canonical_hash(predecessor)}.items():
        epochs.same(descriptor[key], expected)
    _shape(record, predecessor, descriptor)
    for name, digest in epochs._descriptors(record['before_files']):
        if name.startswith('prototype-pipeline/'):
            path = epochs._safe_path(root, name[len('prototype-pipeline/'):])
            if not path.is_file() or path.stat().st_size > 20_000_000 or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                _fail()
    return record


def validate_record(job, snapshot, original, db=None):
    return _validate_record(job, snapshot, original, db, historical=False)


def _validated_historical_four(job, snapshot, original, db, *, historical_head=5):
    """Private predecessor reader for the sole known pre-DB rejected head4."""
    return _validate_record(job, snapshot, original, db, historical=True, historical_head=historical_head)


def _historical_active_focus(root, packet, plan, request, target, previous, record):
    """Reuse exact readonly record4 views for current4 or sealed4, never current5."""
    if record['epoch_number'] != NUMBER:
        _fail()
    from .prototype_read_scope import cached_read
    return cached_read(root, 'active_focus', {'purpose': 'sealed-epoch-four-predecessor-v1',
        'record_sha256': canonical_hash(record), 'packet': packet, 'plan': plan,
        'request': request, 'target': target, 'previous': previous},
        lambda: active_focus(root, packet, plan, request, target, previous, record))


def _validate_record(job, snapshot, original, db, *, historical, historical_head=5):
    close = db is None
    if close:
        database = epochs._safe_path(job.parent.parent, 'fox.sqlite3')
        db = sqlite3.connect(database.absolute().as_uri() + '?mode=ro', uri=True)
    try:
        predecessor = clause.validate_record(job, snapshot, original, db, historical=True,
                                             historical_head=historical_head if historical else 4)
        record = technical_record(job / 'prototype-pipeline')
        epochs.same(epochs.read(job / RECORD), record)
        descriptor = _fresh_descriptor(job, snapshot, original, canonical_hash(predecessor))
        epochs.same(epochs.read(job / 'prototype-pipeline' / PREFIX / 'container-proof-descriptor.json'), descriptor)
        _shape(record, predecessor, descriptor)
        rows = db.execute('SELECT owner,object_id,created FROM events WHERE action=? AND object_id LIKE ?',
            (epochs.EVENT, job.name + ':epoch:%')).fetchall()
        if historical:
            rows = [row for row in rows if row[1].startswith(tuple(job.name + ':epoch:' + f'{number:06d}' + ':' for number in (2, 3, 4)))]
        chain = [epochs.read(job / epochs.RECORD), predecessor, record]
        expected = {(row['owner'], epochs.event_id(job.name, row), row['approved_at']) for row in chain}
        if len(rows) != 3 or {tuple(row) for row in rows} != expected:
            _fail()
        from .prototype_result_publication import validate_publication, _validate_historical_four_publication
        if historical:
            _validate_historical_four_publication(job, record)
        else:
            validate_publication(job, record)
        epochs._before_unchanged(job, {name: digest for name, digest in record['before_files'].items() if name != 'prototype-result.json'})
        root = job / 'prototype-pipeline'
        target = epochs.read(root / record['plan']['repair_focus_id'] / 'mapper-target.json')
        packet, plan = epochs.reconstruct(job, snapshot, original, target)
        members = _members(root / PREFIX / 'container-proof')
        _proof(root, packet, plan, target, predecessor, descriptor, members)
        if members != _members(_stage(job) / 'json', protected=True):
            _fail()
        return record
    finally:
        if close:
            db.close()


def _refs(plan, previous, target):
    return {request['focus_id']: {'scope': REFERENCE_SCOPE, 'focus_id': request['focus_id'],
        'source_binding': plan['source_binding'], 'focus_request_sha256': canonical_hash(request),
        'candidate_sha256': canonical_hash(view['candidate']), 'target_profile_sha256': canonical_hash(target),
        'proof_sha256': canonical_hash(view['proof'])}
        for request, view in zip(plan['requests'], previous, strict=False)}


def _prefix(packet, plan, previous, target):
    if any(view['checked']['approved_structured_design'] is not True for view in previous):
        _fail()
    return validate_prefix_context(packet, plan, [view['candidate'] for view in previous],
        _refs(plan, previous, target), expected_target_sha256=canonical_hash(target))


def active_focus(root, packet, plan, request, target, previous, record, *, runtime=None, preview=False):
    index = next(i for i, row in enumerate(plan['requests']) if row['focus_id'] == request['focus_id'])
    if len(previous) != index:
        _fail()
    if previous:
        _prefix(packet, plan, previous, target)  # BEFORE any next mapper/provider.
    predecessor = epochs.read(root / PREFIX / 'predecessor-record.json')
    if index == 0:
        descriptor = epochs.read(root / PREFIX / 'container-proof-descriptor.json')
        candidate, checked, provenance = _proof(root, packet, plan, target, predecessor, descriptor,
            _members(root / PREFIX / 'container-proof'))
        proof = {'focus_id': request['focus_id'], 'kind': 'DERIVED_APPROVED_CONTAINER_PROPOSAL',
            'candidate_sha256': canonical_hash(candidate), 'source_fact_check': source_fact_gate(packet, request, candidate),
            'active_directory': PREFIX + '/container-proof', 'container_proof_sha256': canonical_hash(descriptor),
            'reviewer_invocation': provenance['review_invocation'],
            'review_request_sha256': provenance['review_request_sha256'],
            'review_receipt_sha256': provenance['review_receipt_sha256'],
            'proposal_sha256': provenance['proposal_sha256'], 'file_manifest_sha256': provenance['file_manifest_sha256']}
        return {'candidate': candidate, 'checked': checked, 'proof': proof}
    if index < 7:
        return clause.active_focus(root, packet, plan, request, target, previous, predecessor)
    def context(candidate, payload):
        payload = deepcopy(payload)
        payload['design_context'] = build_review_context(packet, plan,
            [view['candidate'] for view in previous] + [candidate], _refs(plan, previous, target),
            expected_target_sha256=canonical_hash(target), focus_id=request['focus_id'])
        if index == 7:
            rejected = epochs.read(root / clause.PREFIX / request['focus_id'] / 'reviewer.json')
            payload['retained_rejection'] = {'review': rejected['output'], 'invocation': rejected['invocation'],
                'checkpoint_sha256': canonical_hash(rejected), 'candidate_unchanged': True}
        return payload
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
        if index < 7:
            previous.append(_historical_active_focus(root, packet, plan, request, target, previous, record))
            continue
        if not incomplete:
            _prefix(packet, plan, previous, target)
        directory = root / PREFIX / request['focus_id']
        names = ('reviewer',) if index == 7 else ('mapper', 'reviewer')
        for name in names:
            paths = [directory / (name + suffix) for suffix in ('-request.json', '-target.json', '-intent.json', '.json')]
            exists = [path.exists() or path.is_symlink() for path in paths]
            if incomplete and any(exists):
                _fail()
            if not exists[2] and not exists[3]:
                if any(exists):
                    if not exists[0]:
                        _fail()
                    if name == 'mapper':
                        epochs.same(epochs.read(paths[0]), request)
                    else:
                        epochs.same(epochs.read(paths[0]), active_focus(root, packet, plan, request,
                            target, previous, record, preview=True)['review_request'])
                    if exists[1]:
                        epochs.same(epochs.read(paths[1]), target)
                incomplete = True
                continue
            if not all(exists):
                _fail()
            if name == 'mapper':
                epochs.same(epochs.read(paths[0]), request)
                epochs._role(directory, name, request, target, {'job_id': job.name, 'source_hash': plan['source_binding']})
                # A sealed but not-yet-reviewed candidate must pass the complete
                # context gate before provider configuration is ever loaded.
                active_focus(root, packet, plan, request, target, previous, record, preview=True)
        if not incomplete:
            view = _historical_active_focus(root, packet, plan, request, target, previous, record)
            previous.append(view)
            if not view['checked']['approved_structured_design']:
                incomplete = True
    return {row['focus_id'] for row in plan['requests']}
