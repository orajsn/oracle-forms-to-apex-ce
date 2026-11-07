"""Explicit epoch three: reuse one approved retained clause diagnostic, not calls.

Operator staging is outside jobs at the fixed data-root/prototype-clause-proofs/
<job>/descriptor.json and json/<13 fixed JSON members>. Presence is not consent.
Only an owner-bound append-only epoch record/event authorizes same-run work.
Original snapshot, target, epochs and failed results remain historical bytes.
"""
from copy import deepcopy
import hashlib
import math
import os
from pathlib import Path
import sqlite3
import stat

from . import prototype_mapping_epochs as epochs
from .opaf import OpafError, canonical_hash
from .prototype_clause_proof import (JSON_FILES, ASSEMBLER_SHA256, MAX_FILE_BYTES,
                                    MAX_TOTAL_BYTES, validate_clause_proof_members)
from .prototype_focus_projection import validate_repair, source_fact_gate

NUMBER = 3
NAME = 'epoch-000003'
PREFIX = 'epochs/' + NAME
RECORD = 'mapping-epochs/' + NAME + '.json'
STRATEGY = 'retained-clause-diagnostic-v1'
STAGING_SCOPE = 'fox-prototype-clause-proof-staging-v1'
OPERATIONS = ['projection_review']
POLICY = {**epochs.POLICY, 'clause_proof': STRATEGY, 'new_clause_analysis_calls': 0,
          'repeated_clause_review_calls': 0, 'corrective_projection_review_calls': 1}
TECHNICAL_FILES = {'epoch-record.json', 'predecessor-record.json', 'clause-proof-descriptor.json',
                   *{'clause-proof/' + name for name in JSON_FILES}}


def _fail():
    raise OpafError('Retained clause epoch proof is incomplete, changed or not explicitly authorized.') from None


def _stage(job):
    return job.parent.parent / 'prototype-clause-proofs' / job.name


def staging_present(job):
    path = _stage(Path(job))
    return path.exists() or path.is_symlink()


def _protected(path, *, directory=False):
    epochs._safe_path(path.parent, path.name)
    value = path.lstat()
    if (not (stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode))
            or not directory and value.st_nlink != 1
            or os.name != 'nt' and (value.st_uid != os.geteuid()
                or stat.S_IMODE(value.st_mode) & (0o077 if directory else 0o022))):
        _fail()


def _descriptor(value, *, job_id, project_id, owner, snapshot_sha256,
                source_hash, source_binding, original_target_sha256):
    fields = {'schema_version', 'scope', 'job_id', 'project_id', 'owner', 'snapshot_sha256',
              'source_hash', 'source_binding', 'original_target_sha256', 'analysis_role',
              'assembler_sha256', 'original_manifest', 'original_manifest_sha256', 'candidate_sha256'}
    if (type(value) is not dict or set(value) != fields or type(value['schema_version']) is not int
            or value['schema_version'] != 1 or value['scope'] != STAGING_SCOPE
            or value['assembler_sha256'] != ASSEMBLER_SHA256
            or value['original_manifest_sha256'] != canonical_hash(value['original_manifest'])):
        _fail()
    for key, expected in {'job_id': job_id, 'project_id': project_id, 'owner': owner,
            'snapshot_sha256': snapshot_sha256, 'source_hash': source_hash,
            'source_binding': source_binding, 'original_target_sha256': original_target_sha256}.items():
        if value[key] != expected:
            _fail()
    return value


def _fresh_descriptor(job, snapshot, original):
    base = _stage(job)
    for path in (base.parent, base, base / 'json', base / 'json/analysis', base / 'json/review'):
        _protected(path, directory=True)
    epochs.same(sorted(path.name for path in base.iterdir()), ['descriptor.json', 'json'])
    _protected(base / 'descriptor.json')
    value = epochs.read(base / 'descriptor.json', 65_536)
    selected = snapshot['prototype']
    return _descriptor(value, job_id=job.name, project_id=snapshot['project_id'], owner=snapshot['approvals']['owner'],
        snapshot_sha256=hashlib.sha256(original).hexdigest(), source_hash=snapshot['source_hash'],
        source_binding=selected['source_binding'], original_target_sha256=selected['target_profile_sha256'])


def _members(directory, *, protected=False):
    from .prototype_clause_proof import _check_names
    epochs._safe_path(directory.parent, directory.name)
    _check_names(directory, {name for name in JSON_FILES if '/' not in name} | {'analysis', 'review'})
    for folder, role in (('analysis', 'mapper'), ('review', 'reviewer')):
        epochs._safe_path(directory, folder)
        _check_names(directory / folder, {role + suffix for suffix in ('.json', '-intent.json', '-target.json')})
    raw = {}
    for name in sorted(JSON_FILES):
        path = epochs._safe_path(directory, name)
        if protected:
            _protected(path)
        metadata = path.stat()
        if not path.is_file() or metadata.st_nlink != 1 or not 0 < metadata.st_size <= MAX_FILE_BYTES:
            _fail()
        with path.open('rb') as handle:
            body = handle.read(MAX_FILE_BYTES + 1)
        if len(body) != metadata.st_size:
            _fail()
        raw[name] = body
        if sum(len(value) for value in raw.values()) > MAX_TOTAL_BYTES:
            _fail()
    return raw


def _proof(root, packet, plan, target, predecessor, descriptor, members):
    request = next(row for row in plan['requests'] if row['focus_id'] == predecessor['plan']['repair_focus_id'])
    directory = root / request['focus_id']
    original = epochs.read(directory / 'mapper.json')['output']
    original, _ = epochs.resolved_mapper(directory, request, original)
    result = validate_clause_proof_members(members, approved_manifest=descriptor['original_manifest'],
        assembler_sha256=descriptor['assembler_sha256'], packet=packet, focus_request=request,
        original_candidate=original, original_target=target, analysis_role=descriptor['analysis_role'],
        identity={'job_id': root.parent.name, 'source_hash': plan['source_binding']})
    if result[2]['candidate_sha256'] != descriptor['candidate_sha256']:
        _fail()
    return result


def _sealed_failed_two(root, packet, plan, target, predecessor):
    """Only the sealed deletion-only coverage failure can precede adoption."""
    directory = root / epochs.PREFIX
    request = next(row for row in plan['requests'] if row['focus_id'] == predecessor['plan']['repair_focus_id'])
    expected = {'epoch-record.json', 'predecessor-record.json', *{
        request['focus_id'] + '/mapper' + suffix for suffix in ('-request.json', '-target.json', '-intent.json', '.json')}}
    repair = next(i for i, row in enumerate(plan['requests']) if row['focus_id'] == request['focus_id'])
    for preceding in plan['requests'][:repair]:
        relative = 'source-facts/' + preceding['focus_id'] + '.json'
        path = directory / relative
        if path.exists():
            raw = epochs.read(root / preceding['focus_id'] / 'mapper.json')['output']
            candidate, _ = epochs.resolved_mapper(root / preceding['focus_id'], preceding, raw)
            epochs.same(epochs.read(path), source_fact_gate(packet, preceding, candidate))
            expected.add(relative)
    actual = {path.relative_to(directory).as_posix() for path in directory.rglob('*') if path.is_file()}
    if actual != expected:
        _fail()
    payload = epochs.read(directory / request['focus_id'] / 'mapper-request.json')
    historical = epochs.read(root / request['focus_id'] / 'mapper.json')['output']
    historical, _ = epochs.resolved_mapper(root / request['focus_id'], request, historical)
    required = predecessor['plan']['repair_requirements']
    expected_payload = deepcopy(request)
    expected_payload['repair_context'] = epochs._repair_context(request, historical, required)
    epochs.same(payload, expected_payload)
    candidate, _ = epochs._role(directory / request['focus_id'], 'mapper', payload, target,
                                {'job_id': root.parent.name, 'source_hash': plan['source_binding']})
    deleted = {row['defective_claim_id'] for row in required['required_behavior_units']}
    expected_candidate = deepcopy(historical)
    expected_candidate['blueprint']['claims'] = [row for row in historical['blueprint']['claims'] if row['id'] not in deleted]
    epochs.same(candidate, expected_candidate)
    try:
        validate_repair(packet, request, historical, candidate, required)
    except ValueError as error:
        if str(error) == 'Repaired clause needs evidenced behavior.intent and an action reference.':
            return
    _fail()


def _plan(predecessor, descriptor):
    return {**predecessor['plan'], 'source_checked_focuses': predecessor['plan']['ai_approved_focuses'],
            'planned_corrective_operations': list(OPERATIONS), 'new_clause_analysis_calls': 0,
            'repeated_clause_review_calls': 0, 'corrective_projection_review_calls': 1,
            'clause_proof_sha256': canonical_hash(descriptor), 'analysis_role': deepcopy(descriptor['analysis_role'])}


def _checkpoint(predecessor_sha, before, plan):
    return canonical_hash({'epoch_number': NUMBER, 'predecessor_sha256': predecessor_sha,
                          'before_files': before, 'plan': plan, 'normalization_policy': POLICY})


def inspect_next(job, snapshot, original, target, db, record):
    packet, plan = epochs.reconstruct(job, snapshot, original, target)
    if record['epoch_number'] == NUMBER:
        return record['plan'], record['before_files'], record, record['checkpoint_sha256'], record['predecessor_sha256']
    _sealed_failed_two(job / 'prototype-pipeline', packet, plan, target, record)
    descriptor = _fresh_descriptor(job, snapshot, original)
    _proof(job / 'prototype-pipeline', packet, plan, target, record, descriptor, _members(_stage(job) / 'json', protected=True))
    before = epochs._closure(job, record=record, known_focuses={row['focus_id'] for row in plan['requests']})
    proposed = _plan(record, descriptor)
    predecessor = canonical_hash(record)
    return proposed, before, None, _checkpoint(predecessor, before, proposed), predecessor


def adopt(job, snapshot, original, record):
    """Create-only owner-approved adoption. Never copy archived Python."""
    descriptor = _fresh_descriptor(job, snapshot, original)
    if canonical_hash(descriptor) != record['clause_proof_sha256']:
        _fail()
    members = _members(_stage(job) / 'json', protected=True)
    target = epochs.read(job / 'prototype-pipeline' / record['plan']['repair_focus_id'] / 'mapper-target.json')
    packet, plan = epochs.reconstruct(job, snapshot, original, target)
    predecessor = epochs.read(job / epochs.RECORD)
    _sealed_failed_two(job / 'prototype-pipeline', packet, plan, target, predecessor)
    _proof(job / 'prototype-pipeline', packet, plan, target, predecessor, descriptor, members)
    epochs.save(job / RECORD, record, True)
    base = job / 'prototype-pipeline' / PREFIX
    epochs.save(base / 'epoch-record.json', record, True)
    epochs.save(base / 'predecessor-record.json', epochs.read(job / epochs.RECORD), True)
    epochs.save(base / 'clause-proof-descriptor.json', descriptor, True)
    from .prototype_pipeline import _save_bytes_once
    for name, raw in members.items():
        path = epochs._safe_path(base, 'clause-proof/' + name)
        path.parent.mkdir(parents=True, exist_ok=True)
        _save_bytes_once(path, raw)
    if _fresh_descriptor(job, snapshot, original) != descriptor or _members(_stage(job) / 'json', protected=True) != members:
        _fail()


def _shape(record, predecessor, descriptor):
    if (set(record) != set(predecessor) | {'clause_proof_sha256'}
            or type(record['epoch_number']) is not int or record['epoch_number'] != NUMBER
            or record['strategy'] != STRATEGY or record['scope'] != epochs.SCOPE
            or type(record['schema_version']) is not int or record['schema_version'] != 1
            or record['predecessor_sha256'] != canonical_hash(predecessor)
            or record['clause_proof_sha256'] != canonical_hash(descriptor)
            or record['plan'] != _plan(predecessor, descriptor)
            or record['normalization_policy'] != POLICY
            or type(record['approved_at']) not in (int, float) or not math.isfinite(record['approved_at'])
            or record['approved_at'] <= predecessor['approved_at']
            or record['checkpoint_sha256'] != _checkpoint(record['predecessor_sha256'], record['before_files'], record['plan'])):
        _fail()
    for key in ('job_id', 'project_id', 'snapshot_sha256', 'source_hash', 'source_binding',
                'target_profile_sha256', 'owner', 'approvals'):
        epochs.same(record[key], predecessor[key])
    epochs.same(record['plan'], _plan(predecessor, descriptor))
    epochs.same(record['normalization_policy'], POLICY)
    epochs._descriptors(record['before_files'])


def technical_record(root):
    base = epochs._safe_path(root, PREFIX + '/epoch-record.json')
    record = epochs.read(base)
    # Validate descriptors before ANY descriptor-selected historical file read.
    epochs._descriptors(record['before_files'])
    predecessor = epochs._technical_epoch_two(root)
    epochs.same(epochs.read(base.parent / 'predecessor-record.json'), predecessor)
    descriptor = epochs.read(base.parent / 'clause-proof-descriptor.json', 65_536)
    _descriptor(descriptor, job_id=record['job_id'], project_id=record['project_id'], owner=record['owner'],
        snapshot_sha256=record['snapshot_sha256'], source_hash=record['source_hash'],
        source_binding=record['source_binding'], original_target_sha256=record['target_profile_sha256'])
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
        database = job.parent.parent / 'fox.sqlite3'
        epochs._safe_path(database.parent, database.name)
        db = sqlite3.connect(database.absolute().as_uri() + '?mode=ro', uri=True)
    try:
        predecessor = epochs._validated_epoch_record(job, snapshot, original, db, historical=True)
        record = technical_record(job / 'prototype-pipeline')
        epochs.same(epochs.read(job / RECORD), record)
        descriptor = _fresh_descriptor(job, snapshot, original)
        epochs.same(epochs.read(job / 'prototype-pipeline' / PREFIX / 'clause-proof-descriptor.json'), descriptor)
        _shape(record, predecessor, descriptor)
        rows = db.execute('SELECT owner,object_id,created FROM events WHERE action=? AND object_id LIKE ?',
                          (epochs.EVENT, job.name + ':epoch:%')).fetchall()
        expected = {(predecessor['owner'], epochs.event_id(job.name, predecessor), predecessor['approved_at']),
                    (record['owner'], epochs.event_id(job.name, record), record['approved_at'])}
        if len(rows) != 2 or {tuple(row) for row in rows} != expected:
            _fail()
        epochs._before_unchanged(job, record['before_files'])
        root = job / 'prototype-pipeline'
        target = epochs.read(root / record['plan']['repair_focus_id'] / 'mapper-target.json')
        packet, plan = epochs.reconstruct(job, snapshot, original, target)
        _sealed_failed_two(root, packet, plan, target, predecessor)
        members = _members(root / PREFIX / 'clause-proof')
        _proof(root, packet, plan, target, predecessor, descriptor, members)
        if members != _members(_stage(job) / 'json', protected=True):
            _fail()
        return record
    finally:
        if close:
            db.close()


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
    repair = next(i for i, row in enumerate(plan['requests']) if row['focus_id'] == record['plan']['repair_focus_id'])
    projection = next(i for i, row in enumerate(plan['requests']) if row['focus_id'] == record['plan']['projection_focus_id'])
    if projection != repair + 1:
        _fail()
    target = epochs.read(root / plan['requests'][0]['focus_id'] / 'mapper-target.json')
    previous, incomplete = [], False
    for index, request in enumerate(plan['requests']):
        if index <= repair:
            previous.append(active_focus(root, epochs.read(root / 'packet.json'), plan, request, target, previous, record))
            continue
        directory = root / PREFIX / request['focus_id']
        names = ('reviewer',) if index == projection else ('mapper', 'reviewer')
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
                        preview = epochs._active_focus(root, epochs.read(root / 'packet.json'), plan, request,
                            target, previous, record, PREFIX, preview=True)
                        epochs.same(epochs.read(paths[0]), preview['review_request'])
                    if exists[1]:
                        epochs.same(epochs.read(paths[1]), target)
                incomplete = True
                continue
            if not all(exists):
                _fail()
            # A sealed mapper may precede its not-yet-started reviewer. Validate
            # its exact request/role now; active_focus reconstructs complete views.
            if name == 'mapper':
                epochs.same(epochs.read(paths[0]), request)
                epochs._role(directory, name, request, target, {'job_id': job.name, 'source_hash': plan['source_binding']})
        if not incomplete:
            previous.append(active_focus(root, epochs.read(root / 'packet.json'), plan, request, target, previous, record))
    return {row['focus_id'] for row in plan['requests']}


def active_focus(root, packet, plan, request, target, previous, record, *, runtime=None):
    if request['focus_id'] != record['plan']['repair_focus_id']:
        index = next(i for i, row in enumerate(plan['requests']) if row['focus_id'] == request['focus_id'])
        repair = next(i for i, row in enumerate(plan['requests']) if row['focus_id'] == record['plan']['repair_focus_id'])
        if index < repair:
            # Keep sections one through six's exact historical active proof.
            return epochs._active_focus(root, packet, plan, request, target, previous, None, PREFIX, runtime=runtime)
        return epochs._active_focus(root, packet, plan, request, target, previous, record, PREFIX, runtime=runtime)
    base = root / PREFIX
    descriptor = epochs.read(base / 'clause-proof-descriptor.json', 65_536)
    predecessor = epochs.read(base / 'predecessor-record.json')
    candidate, checked, provenance = _proof(root, packet, plan, target, predecessor, descriptor, _members(base / 'clause-proof'))
    gate = source_fact_gate(packet, request, candidate)
    # Typed DERIVED proof, never a fake full-blueprint mapper checkpoint.
    proof = {'focus_id': request['focus_id'], 'kind': 'DERIVED_CLAUSE_DIAGNOSTIC',
             'candidate_sha256': canonical_hash(candidate), 'source_fact_check': gate,
             'active_directory': PREFIX + '/clause-proof', 'clause_proof_sha256': canonical_hash(descriptor),
             'analysis_invocation': provenance['analysis_invocation'],
             'reviewer_invocation': provenance['review_invocation'],
             'review_request_sha256': provenance['review_request_sha256'],
             'assembly_binding': provenance['assembly_binding'], 'file_manifest_sha256': provenance['file_manifest_sha256']}
    return {'candidate': candidate, 'checked': checked, 'proof': proof}
