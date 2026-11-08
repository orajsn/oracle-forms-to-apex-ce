"""Append-only source-bound epochs and active focused-design provenance.

Epoch two permits one targeted clause repair, its independent review and one
context-projection review, then the untouched remainder. No repair loop exists.
Original source/model/epoch-one artifacts are never replaced.
"""
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import math
from pathlib import Path
import re
import sqlite3

from . import forms_design_review
from .forms_focus import build_focus_plan
from .forms_understanding_packet import local_packet
from .native_pipeline import _save_once
from .opaf import OpafError, canonical_hash, parse_model_message
from .prototype_admission import bound_focus_limit
from .prototype_claim_resolution import resolved_mapper, resolve_claim_owners
from .prototype_focus_projection import (STRATEGY, source_fact_gate, fact_diagnostics,
    repair_requirements, validate_repair, project_context)

SCOPE = 'fox-prototype-mapping-epoch-v1'
EVENT = 'approved_prototype_mapping_epoch'
NUMBER = 2
NAME = 'epoch-000002'
RECORD = 'mapping-epochs/' + NAME + '.json'
PREFIX = 'epochs/' + NAME
OPERATIONS = ['mapper_repair', 'repair_review', 'projection_review']
POLICY = {'source_facts': 'exact-existing-whitelist-v1',
          'legacy_owner_resolution': 'resolve-code-unit-owners-v1-immutable',
          'new_context_alias_projection': 'exact-active-owner-context-v2',
          'future_mapper_repairs_permitted': False, 'continue_remaining_run': True}
_PHASE_SEAL = object()


def _descriptor(name, digest):
    if (type(name) is not str or not 1 <= len(name) <= 1024 or '\\' in name or ':' in name
            or name.startswith('/') or any(ord(char) < 32 for char in name)
            or any(part in ('', '.', '..') for part in name.split('/'))
            or type(digest) is not str or not re.fullmatch('[a-f0-9]{64}', digest)):
        raise OpafError('Epoch baseline descriptor is invalid.')
    return name, digest


def _descriptors(files):
    if type(files) is not dict or not 1 <= len(files) <= 4096:
        raise OpafError('Epoch baseline closure is invalid.')
    # Validate EVERY descriptor before reading ANY descriptor-selected file.
    return [_descriptor(name, digest) for name, digest in files.items()]


def _safe_path(root, relative):
    _descriptor(relative, '0' * 64)
    root = Path(root).absolute()
    path = root.joinpath(*relative.split('/'))
    for parent in reversed((path, *path.parents)):
        try:
            metadata = parent.lstat()
        except FileNotFoundError:
            continue
        if parent.is_symlink() or getattr(metadata, 'st_file_attributes', 0) & 0x400:
            raise OpafError('Epoch proof has a linked ancestor.')
    if not path.resolve(strict=False).is_relative_to(root.resolve(strict=False)):
        raise OpafError('Epoch proof escapes its configured root.')
    return path


@dataclass(frozen=True)
class _ConverterPhase:
    seal: object
    job: str
    epoch_sha256: str
    stage: str
    request_sha256: str


def read(path, maximum=20_000_000):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= maximum:
        raise OpafError('Epoch proof file is missing, linked or unbounded.')
    raw = path.read_bytes()
    if not raw.lstrip().startswith(b'{'):
        raise OpafError('Epoch proof must be an unambiguous JSON object.')
    return parse_model_message(raw.decode('utf-8'))


def same(left, right):
    if canonical_hash(left) != canonical_hash(right):
        raise OpafError('Epoch proof differs from deterministic reconstruction.')


def save(path, value, write):
    if write:
        if path.parent.is_symlink():
            raise OpafError('Epoch storage is unsafe.')
        path.parent.mkdir(parents=True, exist_ok=True)
        _save_once(path, value)
    same(read(path), value)


def event_id(rid, record):
    return rid + ':epoch:' + f"{record['epoch_number']:06d}" + ':' + canonical_hash(record)


def _closure(job, *, initial=False, phase=None, record=None, known_focuses=None):
    """Exact known producer files; unknown files and unsealed calls block."""
    names = {}
    from . import prototype_clause_epoch as clause
    from . import prototype_container_epoch as container
    from . import prototype_partition_review_epoch as partition
    from . import prototype_context_screen_epoch as screen
    from . import prototype_review_correction as correction
    from . import prototype_dsc_identity_repair as dsc
    dsc_repair = dsc.present(job/'prototype-pipeline')
    screen_epoch = record is not None and record.get('epoch_number') == screen.NUMBER
    partition_epoch = record is not None and record.get('epoch_number') in (partition.NUMBER, screen.NUMBER)
    container_epoch = record is not None and record.get('epoch_number') in (container.NUMBER, partition.NUMBER, screen.NUMBER)
    clause_epoch = record is not None and record.get('epoch_number') in (clause.NUMBER, container.NUMBER, partition.NUMBER, screen.NUMBER)
    prefixes = '(?:' + '|'.join([PREFIX, clause.PREFIX] + ([container.PREFIX] if container_epoch else [])
        + ([partition.PREFIX] if partition_epoch else []) + ([screen.PREFIX] if screen_epoch else [])) + ')' if clause_epoch else PREFIX
    root_files = {'source-snapshot.json', 'mapping-continuation.json', 'prototype-result.json', RECORD}
    if clause_epoch:
        root_files.add(clause.RECORD)
    if container_epoch:
        root_files.add(container.RECORD)
        root_files.update(container.RESULT_FILES)
    if partition_epoch:
        root_files.add(partition.RECORD)
        root_files.update(partition.RESULT_FILES)
    if screen_epoch:
        root_files.add(screen.RECORD)
        root_files.update(screen.RESULT_FILES)
        if dsc_repair: root_files.update(dsc.RESULT_FILES)
    pipeline_files = {'binding.json', 'sources-manifest.json', 'packet.json', 'assessment.json',
        'merged-blueprint.json', 'native-plan.json', 'review-index.json', 'rendered.json', 'candidate-apexlang.zip',
        *{stage + suffix for stage in ('validate', 'prepare_schema', 'import', 'verify_runtime', 'export')
          for suffix in ('.json', '-intent.json')}}
    focus_files = {'request.json', 'mapper-request.json', 'mapper.json', 'mapper-intent.json', 'mapper-target.json',
        'reviewer-request.json', 'reviewer.json', 'reviewer-intent.json', 'reviewer-target.json', 'review-receipt.json',
        'mapper-resolved.json', 'mapper-resolution.json', 'projection-candidate.json', 'projection-receipt.json'}
    task_binding=job/'prototype-pipeline/binding.json'
    declared=read(task_binding) if task_binding.exists() else {}
    policy=declared.get('metadata_task_policy')
    if 'metadata_task_policy' in declared and policy!=dsc.TASK_POLICY:
        raise OpafError('Unknown epoch metadata task policy.')
    if policy==dsc.TASK_POLICY or dsc_repair:
        focus_files.update({'mapper-metadata-task.json','reviewer-metadata-task.json'})
    pending = [job]
    while pending:
        for path in pending.pop().iterdir():
            rel = path.relative_to(job).as_posix()
            _safe_path(job, rel)
            if path.is_symlink():
                raise OpafError('Epoch storage contains a link.')
            if path.is_dir():
                valid = (rel in {'prototype-pipeline', 'prototype-pipeline/sources', 'mapping-epochs',
                    'prototype-pipeline/epochs', 'prototype-pipeline/' + PREFIX,
                    'prototype-pipeline/' + PREFIX + '/source-facts', 'prototype-results', 'prototype-transport'}
                    or clause_epoch and rel in {'prototype-pipeline/' + clause.PREFIX,
                        'prototype-pipeline/' + clause.PREFIX + '/source-facts',
                        *{'prototype-pipeline/' + clause.PREFIX + '/clause-proof' + suffix for suffix in ('', '/analysis', '/review')}}
                    or container_epoch and rel in container.DIRECTORIES
                    or partition_epoch and rel in partition.DIRECTORIES
                    or screen_epoch and rel in screen.DIRECTORIES
                    or screen_epoch and rel in {'prototype-pipeline/' + correction.PREFIX,
                        'prototype-pipeline/' + correction.ATTEMPT}
                    or dsc_repair and (rel in {dsc.RESULT_BASE,'prototype-pipeline/'+dsc.PREFIX}
                        or re.fullmatch('prototype-pipeline/'+dsc.PREFIX+r'/focus-[a-f0-9]{24}',rel))
                    or re.fullmatch(r'prototype-pipeline/(?:' + prefixes + r'/)?focus-[a-f0-9]{24}', rel))
                if not valid or initial and rel.startswith(('mapping-epochs', 'prototype-pipeline/epochs')):
                    raise OpafError('Unknown epoch directory or competing head requires reconciliation.')
                match = re.fullmatch(r'prototype-pipeline/(?:' + prefixes + r'/)?(focus-[a-f0-9]{24})', rel)
                if clause_epoch and rel == 'prototype-pipeline/' + clause.PREFIX + '/' + record['plan']['repair_focus_id']:
                    raise OpafError('Derived clause proof cannot masquerade as a new mapper/reviewer focus.')
                if container_epoch and match and rel.startswith('prototype-pipeline/' + container.PREFIX + '/'):
                    original_prefix = 'prototype-pipeline/' + match[1] + '/'
                    if (match[1] != record['plan']['projection_focus_id']
                            and any(name.startswith(original_prefix) for name in record['before_files'])):
                        raise OpafError('Retained container and prefix proofs cannot masquerade as new calls.')
                if partition_epoch and rel.startswith('prototype-pipeline/epochs/'):
                    active_prefix = screen.PREFIX if screen_epoch else partition.PREFIX
                    if rel == 'prototype-pipeline/' + active_prefix or rel.startswith('prototype-pipeline/' + active_prefix + '/'):
                        if match and any(name.startswith('prototype-pipeline/' + match[1] + '/') for name in record['before_files']):
                            raise OpafError('Retained partition approval cannot masquerade as a repeated model call.')
                    elif not any(name.startswith(rel + '/') for name in record['before_files']):
                        raise OpafError('New historical epoch directory requires reconciliation.')
                if match and known_focuses is not None and match[1] not in known_focuses:
                    raise OpafError('Foreign focus directory is outside the bound source plan.')
                pending.append(path)
                continue
            valid = rel in root_files
            if (screen_epoch and rel.startswith('prototype-pipeline/' + screen.PREFIX + '/' + record['plan']['pending_review_focus_id'] + '/mapper')):
                raise OpafError('Saved mapper9 cannot be repeated or copied into the new epoch.')
            if (partition_epoch and rel.startswith('prototype-pipeline/epochs/')
                    and not rel.startswith('prototype-pipeline/' + (screen.PREFIX if screen_epoch else partition.PREFIX) + '/')
                    and rel not in record['before_files']):
                raise OpafError('New work appeared under a frozen historical epoch.')
            if record is not None and re.match(r'prototype-pipeline/focus-[a-f0-9]{24}/', rel) and rel not in record['before_files']:
                raise OpafError('New work appeared outside the epoch version namespace.')
            if rel.startswith('prototype-pipeline/'):
                tail = rel[len('prototype-pipeline/'):]
                valid = (tail in pipeline_files or re.fullmatch(r'sources/source-00[0-3]\.xml', tail)
                    or re.fullmatch(r'(?:' + prefixes + r'/)?focus-[a-f0-9]{24}/(?:' + '|'.join(re.escape(name) for name in focus_files) + ')', tail)
                    or tail in {PREFIX + '/epoch-record.json', PREFIX + '/predecessor-record.json'}
                    or clause_epoch and tail in {clause.PREFIX + '/' + name for name in clause.TECHNICAL_FILES}
                    or container_epoch and tail in {container.PREFIX + '/' + name for name in container.TECHNICAL_FILES}
                    or partition_epoch and tail in {partition.PREFIX + '/' + name for name in partition.TECHNICAL_FILES}
                    or screen_epoch and tail in {screen.PREFIX + '/' + name for name in screen.TECHNICAL_FILES}
                    or screen_epoch and tail in {correction.PREFIX + '/' + name for name in correction.FILES}
                    or dsc_repair and dsc.authority_member(tail)
                    or partition_epoch and re.fullmatch((screen.PREFIX if screen_epoch else partition.PREFIX) + r'/focus-[a-f0-9]{24}/full-audit-context\.json', tail)
                    or screen_epoch and re.fullmatch(screen.PREFIX + r'/focus-[a-f0-9]{24}/(?:' + '|'.join(re.escape(n) for n in screen.SCREEN_FILES) + ')', tail)
                    or re.fullmatch(prefixes + r'/source-facts/focus-[a-f0-9]{24}\.json', tail))
            elif rel.startswith('prototype-results/'):
                valid = re.fullmatch(r'prototype-results/[a-f0-9]{64}\.json', rel) is not None
            elif rel.startswith('prototype-transport/'):
                valid = rel in {'prototype-transport/authority.json', 'prototype-transport/authority-intent.json'}
            if (not valid or not path.is_file() or path.stat().st_size > 20_000_000
                    or initial and rel not in {'source-snapshot.json', 'mapping-continuation.json'} and
                       (not rel.startswith('prototype-pipeline/') or rel[len('prototype-pipeline/'):] in pipeline_files -
                        {'binding.json', 'sources-manifest.json', 'packet.json', 'assessment.json'})):
                raise OpafError('Unknown or downstream epoch proof prevents bounded continuation.')
            raw = path.read_bytes()
            if path.suffix == '.json':
                read(path)
            diagnostic_summary = (clause_epoch and rel == 'prototype-pipeline/' + clause.PREFIX + '/clause-proof/diagnostic-intent.json'
                or container_epoch and rel == 'prototype-pipeline/' + container.PREFIX + '/container-proof/diagnostic-intent.json')
            diagnostic_summary = diagnostic_summary or (partition_epoch and rel == 'prototype-pipeline/' + partition.PREFIX + '/partition-proof/diagnostic-intent.json')
            if path.name.endswith('-intent.json') and not diagnostic_summary and not path.with_name(path.name.replace('-intent.json', '.json')).is_file():
                if (type(phase) is not _ConverterPhase or phase.seal is not _PHASE_SEAL
                        or phase.job != str(job.absolute())
                        or rel != 'prototype-pipeline/' + phase.stage + '-intent.json'
                        or read(path) != {'request_sha256': phase.request_sha256}):
                    raise OpafError('A prior epoch operation is uncertain; no automatic replay.')
            names[rel] = hashlib.sha256(raw).hexdigest()
            if len(names) > 4096:
                raise OpafError('Epoch proof exceeds its file bound.')
    return dict(sorted(names.items()))


def _model_fence(job, snapshot, record):
    """Require a sealed contiguous model-operation prefix before new work.

    Request/target metadata may exist for the NEXT operation only. A pending
    inference, orphan result, forged cache or future competing operation blocks.
    This reads caches through the production role validator; it never invokes.
    """
    from . import prototype_clause_epoch as clause
    from . import prototype_container_epoch as container
    from . import prototype_partition_review_epoch as partition
    from . import prototype_context_screen_epoch as screen
    if record.get('epoch_number') == screen.NUMBER:
        return screen.model_fence(job, snapshot, record)
    if record.get('epoch_number') == partition.NUMBER:
        return partition.model_fence(job, snapshot, record)
    if record.get('epoch_number') == container.NUMBER:
        return container.model_fence(job, snapshot, record)
    if record.get('epoch_number') == clause.NUMBER:
        return clause.model_fence(job, snapshot, record)
    from .prototype_job import validate_prototype_snapshot
    selected = snapshot['prototype']
    plan = build_focus_plan(validate_prototype_snapshot(snapshot), expected_source_binding=selected['source_binding'],
        approved_chunk_hashes=selected['approved_chunk_hashes'], max_owned_objects=bound_focus_limit(selected))
    if canonical_hash(plan) != selected['focus_plan_sha256']:
        raise OpafError('Epoch operation fence has a stale focus plan.')
    root = Path(job) / 'prototype-pipeline'
    target = read(root / plan['requests'][0]['focus_id'] / 'mapper-target.json')
    repair = next(i for i, row in enumerate(plan['requests']) if row['focus_id'] == record['plan']['repair_focus_id'])
    projection = next(i for i, row in enumerate(plan['requests']) if row['focus_id'] == record['plan']['projection_focus_id'])
    if projection != repair + 1:
        raise OpafError('Epoch corrective operations are not contiguous.')
    operations = []
    for index, request in enumerate(plan['requests'][repair:], start=repair):
        if index != projection:
            operations.append((request, 'mapper', index == repair))
        operations.append((request, 'reviewer', False))
    incomplete = False
    identity = {'job_id': job.name, 'source_hash': plan['source_binding']}
    for request, name, is_repair in operations:
        directory = root / PREFIX / request['focus_id']
        files = [directory / (name + suffix) for suffix in ('-request.json', '-target.json', '-intent.json', '.json')]
        exists = [path.exists() or path.is_symlink() for path in files]
        if incomplete and any(exists):
            raise OpafError('A future model operation competes with the current epoch phase.')
        if not exists[2] and not exists[3]:
            incomplete = True
            continue
        if not all(exists):
            raise OpafError('An epoch model operation is unsealed or orphaned.')
        payload = read(files[0])
        if name == 'mapper':
            original_request = {key: value for key, value in payload.items() if key != 'repair_context'}
            same(original_request, request)
            if is_repair:
                historical = read(root / request['focus_id'] / 'mapper.json')['output']
                historical, _ = resolved_mapper(root / request['focus_id'], request, historical)
                expected = deepcopy(request)
                expected['repair_context'] = _repair_context(request, historical, record['plan']['repair_requirements'])
                same(payload, expected)
            else:
                same(payload, request)
        else:
            same(payload['request'], request)
            if payload.get('candidate_sha256') != canonical_hash(payload['candidate']):
                raise OpafError('Epoch reviewer request changed its candidate.')
            if 'review_context' in payload:
                context = payload['review_context']
                expected_operation = 'repair_review' if request['focus_id'] == record['plan']['repair_focus_id'] else 'projection_review'
                if context.get('operation') != expected_operation:
                    raise OpafError('Epoch reviewer uses an unknown operation contract.')
                same(payload, extended_review(request, payload['candidate'], context['raw_candidate'],
                    context['operation'], context['evidence']))
            elif set(payload) != {'request', 'candidate', 'candidate_sha256'}:
                raise OpafError('Unknown epoch reviewer request contract.')
            elif request['focus_id'] in (record['plan']['repair_focus_id'], record['plan']['projection_focus_id']):
                raise OpafError('Corrective reviewers require the full bound context.')
        _role(directory, name, payload, target, identity)
    return {request['focus_id'] for request in plan['requests']}


def _before_unchanged(job, files):
    # Validate EVERY descriptor before a lookup or any selected-file read.
    descriptors = _descriptors(files)
    from .prototype_read_scope import baseline_read_root, cached_read
    root = baseline_read_root(job, [name for name, _ in descriptors])
    if root is not None:
        return cached_read(root, 'active_focus', {'purpose': 'epoch-baseline-bytes-v1',
            'base': str(Path(job).absolute()), 'files': dict(descriptors)},
            lambda: _check_before_unchanged(job, descriptors))
    return _check_before_unchanged(job, descriptors)


def _check_before_unchanged(job, descriptors):
    for name, digest in descriptors:
        path = _safe_path(job, name)
        if (any(parent.is_symlink() for parent in (path, *path.parents) if parent == job or job in parent.parents)
                or not path.is_file() or path.stat().st_size > 20_000_000
                or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            raise OpafError('An original epoch checkpoint changed.')


def _validated_epoch_record(job, snapshot, original, db=None, *, historical=False, historical_head=3):
    """Validate root record/event and copied technical record; never repair loss."""
    job = Path(job)
    from . import prototype_clause_epoch as clause
    from . import prototype_container_epoch as container
    from . import prototype_partition_review_epoch as partition
    from . import prototype_context_screen_epoch as screen
    if not historical and ((job / screen.RECORD).exists() or (job / screen.RECORD).is_symlink()):
        return screen.validate_record(job, snapshot, original, db)
    if not historical and ((job / partition.RECORD).exists() or (job / partition.RECORD).is_symlink()):
        return partition.validate_record(job, snapshot, original, db)
    if not historical and ((job / container.RECORD).exists() or (job / container.RECORD).is_symlink()):
        return container.validate_record(job, snapshot, original, db)
    if not historical and (job / clause.RECORD).exists():
        return clause.validate_record(job, snapshot, original, db)
    path = _safe_path(job, RECORD)
    technical = _safe_path(job, 'prototype-pipeline/' + PREFIX + '/epoch-record.json')
    database = job.parent.parent / 'fox.sqlite3'
    close = db is None
    if close:
        if database.is_symlink() or not database.is_file():
            if not path.exists() and not technical.exists():
                return None
            raise OpafError('Epoch database is unavailable.')
        db = sqlite3.connect(database.absolute().as_uri() + '?mode=ro', uri=True)
    try:
        rows = db.execute('SELECT owner,object_id,created FROM events WHERE action=? AND object_id LIKE ?',
                          (EVENT, job.name + ':epoch:%')).fetchall()
        root_dir = job / 'mapping-epochs'
        if not path.exists() and not path.is_symlink():
            if rows or technical.exists() or (root_dir.exists() and list(root_dir.iterdir())):
                raise OpafError('Epoch event or technical head lost its durable record.')
            return None
        expected_names = {NAME + '.json', clause.NAME + '.json'} if historical else {NAME + '.json'}
        if historical and historical_head in (container.NUMBER, partition.NUMBER, screen.NUMBER):
            expected_names.add(container.NAME + '.json')
        if historical and historical_head in (partition.NUMBER, screen.NUMBER):
            expected_names.add(partition.NAME + '.json')
        if historical and historical_head == screen.NUMBER:
            expected_names.add(screen.NAME + '.json')
        if root_dir.is_symlink() or {item.name for item in root_dir.iterdir()} != expected_names:
            raise OpafError('Epoch chain is noncontiguous or has a competing head.')
        if historical:
            rows = [row for row in rows if row[1].startswith(job.name + ':epoch:000002:')]
        record = read(path)
        expected = {'schema_version', 'scope', 'strategy', 'epoch_number', 'predecessor_sha256',
            'checkpoint_sha256', 'job_id', 'project_id', 'snapshot_sha256', 'source_hash', 'source_binding',
            'target_profile_sha256', 'owner', 'approved_at', 'approvals', 'before_files', 'plan', 'normalization_policy'}
        if (set(record) != expected or type(record['schema_version']) is not int or record['schema_version'] != 1
                or record['scope'] != SCOPE or record['strategy'] != STRATEGY
                or type(record['epoch_number']) is not int or record['epoch_number'] != NUMBER
                or record['job_id'] != job.name or record['project_id'] != snapshot['project_id']
                or record['snapshot_sha256'] != hashlib.sha256(original).hexdigest()
                or record['source_hash'] != snapshot['source_hash']
                or record['source_binding'] != snapshot['prototype']['source_binding']
                or record['target_profile_sha256'] != snapshot['prototype']['target_profile_sha256']
                or record['owner'] != snapshot['approvals']['owner']
                or type(record['approved_at']) not in (int, float) or not math.isfinite(record['approved_at']) or record['approved_at'] <= 0
                or type(record['approvals']) is not dict or set(record['approvals']) != {'redacted_source', 'external_ai', 'synthetic_prototype'}
                or any(value is not True for value in record['approvals'].values())):
            raise OpafError('Epoch identity, source or explicit consent changed.')
        same(record['normalization_policy'], POLICY)
        predecessor = read(job / 'mapping-continuation.json')
        if canonical_hash(predecessor) != record['predecessor_sha256']:
            raise OpafError('Epoch predecessor changed.')
        from .prototype_mapping_continuation import validate_continuation_record, continuation_event_id, EVENT as OLD_EVENT
        validate_continuation_record(job, snapshot, original, predecessor)
        old = db.execute('SELECT owner,object_id,created FROM events WHERE action=? AND object_id LIKE ?',
                         (OLD_EVENT, job.name + ':%')).fetchall()
        if ([tuple(row) for row in old] != [(predecessor['owner'], continuation_event_id(job.name, predecessor), predecessor['approved_at'])]
                or [tuple(row) for row in rows] != [(record['owner'], event_id(job.name, record), record['approved_at'])]):
            raise OpafError('Epoch chain has no unique matching consent events.')
        _before_unchanged(job, record['before_files'])
        same(read(technical), record)
        same(read(technical.parent / 'predecessor-record.json'), predecessor)
        if canonical_hash({'epoch_number': NUMBER, 'predecessor_sha256': record['predecessor_sha256'],
                'before_files': record['before_files'], 'plan': record['plan'], 'normalization_policy': POLICY}) != record['checkpoint_sha256']:
            raise OpafError('Epoch baseline/plan binding changed.')
        return record
    finally:
        if close:
            db.close()


def validate_epoch_chain(job, snapshot, original, db=None, *, phase=None):
    from .prototype_read_scope import epoch_read_scope
    with epoch_read_scope(Path(job) / 'prototype-pipeline'):
        return _validate_epoch_chain(job, snapshot, original, db, phase=phase)


def _validate_epoch_chain(job, snapshot, original, db=None, *, phase=None):
    record = _validated_epoch_record(job, snapshot, original, db)
    if record is not None:
        if phase is not None and (type(phase) is not _ConverterPhase or phase.seal is not _PHASE_SEAL
                or phase.job != str(Path(job).absolute()) or phase.epoch_sha256 != canonical_hash(record)):
            raise OpafError('Converter phase does not bind the current epoch chain.')
        focuses = _model_fence(Path(job), snapshot, record)
        _closure(Path(job), phase=phase, record=record, known_focuses=focuses)
    return record


def converter_phase(job, snapshot, original, stage, request):
    """Mint one typed phase ONLY from reconstructed reviewed artifact authority.

    A caller dictionary cannot exempt an intent. All source/review/rendering and
    ordered prior-stage bindings must match durable proof before a token exists.
    """
    job = Path(job)
    record = _validated_epoch_record(job, snapshot, original)
    if record is None:
        return None  # Preserve historical jobs without epoch two.
    from .prototype_pipeline import CONVERTER_STAGES, _check_converter_receipt, authorize_prototype_request
    if type(stage) is not str or stage not in CONVERTER_STAGES:
        raise OpafError('Unsupported epoch converter phase.')
    root = job / 'prototype-pipeline'
    native, rendered = read(root / 'native-plan.json'), read(root / 'rendered.json')
    binding, manifest, index = (read(root / name) for name in ('binding.json', 'sources-manifest.json', 'review-index.json'))
    base = {'schema_version': 1, 'scope': 'fox-prototype-converter-request-v1', 'job_id': job.name,
        'project_id': snapshot['project_id'], 'source_binding': snapshot['prototype']['source_binding'],
        'plan_sha256': native['plan_sha256'], 'rendering_spec': native['rendering_spec'],
        'rendered_zip_sha256': rendered['zip_sha256'], 'source_authority': {'schema_version': 1,
            'scope': 'fox-prototype-source-authority-v1', 'binding_sha256': canonical_hash(binding),
            'sources_manifest_sha256': canonical_hash(manifest), 'review_index_sha256': canonical_hash(index)}}
    prior = {}
    for previous in CONVERTER_STAGES[:CONVERTER_STAGES.index(stage)]:
        payload = {**base, 'prior_receipts': dict(prior)}
        same(read(root / (previous + '-intent.json')), {'request_sha256': canonical_hash(payload)})
        prior[previous] = _check_converter_receipt(previous, payload, read(root / (previous + '.json')))
    expected = {**base, 'prior_receipts': prior}
    same(request, expected)
    authorize_prototype_request(job, expected)
    for later in CONVERTER_STAGES[CONVERTER_STAGES.index(stage) + 1:]:
        if (root / (later + '-intent.json')).exists() or (root / (later + '.json')).exists():
            raise OpafError('Competing later converter phase prevents this operation.')
    phase = _ConverterPhase(_PHASE_SEAL, str(job.absolute()), canonical_hash(record), stage, canonical_hash(expected))
    focuses = _model_fence(job, snapshot, record)
    _closure(job, phase=phase, record=record, known_focuses=focuses)
    return phase


def reconstruct(job, snapshot, original, target):
    from .prototype_job import validate_prototype_snapshot
    documents = validate_prototype_snapshot(snapshot)
    selected = snapshot['prototype']; root = job / 'prototype-pipeline'
    if canonical_hash(target) != selected['target_profile_sha256']:
        raise OpafError('Epoch requires the unchanged source-owner-approved target.')
    packet = local_packet(documents)
    plan = build_focus_plan(documents, expected_source_binding=selected['source_binding'],
        approved_chunk_hashes=selected['approved_chunk_hashes'], max_owned_objects=bound_focus_limit(selected))
    if canonical_hash(plan) != selected['focus_plan_sha256']:
        raise OpafError('Epoch full focus plan changed.')
    binding = {'schema_version': selected['schema_version'], 'job_id': job.name, 'project_id': snapshot['project_id'],
        'project_name': snapshot['project_name'], 'source_binding': selected['source_binding'],
        'focus_plan_sha256': selected['focus_plan_sha256'], 'profile_sha256': canonical_hash(target['opaf']['roles']),
        'approved_policy_id': selected['approved_policy_id']}
    if selected['schema_version'] == 2: binding['max_owned_objects'] = 32
    if 'metadata_task_policy' in selected: binding['metadata_task_policy']=selected['metadata_task_policy']
    same(read(root / 'binding.json'), binding)
    same(read(root / 'packet.json'), packet)
    same(read(root / 'sources-manifest.json'), {'source_binding': selected['source_binding'],
        'selected_chunk_hashes': selected['approved_chunk_hashes'], 'files': [
            {'name': name, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)} for name, raw in documents]})
    same(read(root / 'assessment.json'), {'source_binding': selected['source_binding'], 'source_count': len(documents),
        'source_objects': plan['total_source_objects'], 'focus_count': len(plan['requests'])})
    for index, (_, raw) in enumerate(documents):
        path = root / 'sources' / f'source-{index:03}.xml'
        if path.parent.is_symlink() or path.is_symlink() or path.read_bytes() != raw:
            raise OpafError('Epoch original source bytes changed.')
    return packet, plan


def _role(directory, name, payload, target, identity, runtime=None):
    from .prototype_pipeline import _role as invoke
    if runtime is None:
        for suffix in ('.json', '-intent.json', '-target.json'): read(directory / (name + suffix))
    output, invocation = invoke(directory, name, runtime['opaf_client'] if runtime else None,
        target['opaf']['roles'][name], payload, identity,
        runtime['target_profile_loader'] if runtime else None,
        runtime['processing_approval_check'] if runtime else None,
        runtime['approval_context'] if runtime else None)
    same(read(directory / (name + '-target.json')), target)
    same(read(directory / (name + '-intent.json')), read(directory / (name + '.json'))['binding'])
    return output, invocation


def _review(request, candidate, review, directory):
    checked = forms_design_review.validate_design_review(request, candidate, review)
    return checked


def inspect_next_epoch(job, snapshot, original, target, db):
    """Pure plan for exact known repair/projection; no model or artifact writes."""
    from .prototype_read_scope import epoch_read_scope
    with epoch_read_scope(Path(job) / 'prototype-pipeline'):
        return _inspect_next_epoch(job, snapshot, original, target, db)


def _inspect_next_epoch(job, snapshot, original, target, db):
    packet, plan = reconstruct(job, snapshot, original, target)
    from . import prototype_context_screen_epoch as screen
    if screen.terminal_candidate_present(job, plan, db):
        return screen.inspect_next(job, snapshot, original, target, db)
    record = validate_epoch_chain(job, snapshot, original, db)
    if record:
        from . import prototype_clause_epoch as clause
        from . import prototype_container_epoch as container
        from . import prototype_partition_review_epoch as partition
        if record.get('epoch_number') == screen.NUMBER:
            return screen.inspect_next(job, snapshot, original, target, db, record)
        if record.get('epoch_number') == partition.NUMBER or partition.staging_present(job):
            return partition.inspect_next(job, snapshot, original, target, db, record)
        if record.get('epoch_number') == container.NUMBER or container.staging_present(job):
            return container.inspect_next(job, snapshot, original, target, db, record)
        if record.get('epoch_number') == clause.NUMBER or clause.staging_present(job):
            return clause.inspect_next(job, snapshot, original, target, db, record)
        _closure(job)
        return record['plan'], record['before_files'], record, record['checkpoint_sha256'], record['predecessor_sha256']
    predecessor = read(job / 'mapping-continuation.json')
    from .prototype_mapping_continuation import validate_continuation_record, continuation_event_id, EVENT as OLD_EVENT
    validate_continuation_record(job, snapshot, original, predecessor)
    events = db.execute('SELECT owner,object_id,created FROM events WHERE action=? AND object_id LIKE ?',
                        (OLD_EVENT, job.name + ':%')).fetchall()
    if [tuple(row) for row in events] != [(predecessor['owner'], continuation_event_id(job.name, predecessor), predecessor['approved_at'])]:
        raise OpafError('Epoch one is orphaned or changed.')
    before = _closure(job, initial=True)
    identity = {'job_id': job.name, 'source_hash': plan['source_binding']}
    prefix, views, defect = [], [], None
    for index, request in enumerate(plan['requests']):
        directory = job / 'prototype-pipeline' / request['focus_id']
        if not directory.exists(): break
        same(read(directory / 'request.json'), request)
        raw, mapper = _role(directory, 'mapper', request, target, identity)
        if (directory / 'reviewer.json').exists():
            candidate, _ = resolved_mapper(directory, request, raw)
            review, reviewer = _role(directory, 'reviewer', {'request': request, 'candidate': candidate,
                'candidate_sha256': canonical_hash(candidate)}, target, identity)
            checked = _review(request, candidate, review, directory)
            if not checked['approved_structured_design'] or mapper['room_id'] == reviewer['room_id']:
                raise OpafError('Epoch prefix is not independently approved.')
            same(read(directory / 'review-receipt.json'), checked)
            diagnostics = fact_diagnostics(packet, request, candidate)
            if diagnostics:
                if defect is not None: raise OpafError('More than one repair focus is outside this epoch.')
                requirements = repair_requirements(packet, request, candidate)
                defect = {'index': index, 'request': request, 'raw': candidate, 'requirements': requirements}
            elif defect is not None:
                raise OpafError('Only the immediately adjacent projection may follow the defective focus.')
            else:
                source_fact_gate(packet, request, candidate)
            prefix.append(candidate)
            views.append({'mapper_sha256': canonical_hash(read(directory / 'mapper.json')),
                          'reviewer_sha256': canonical_hash(read(directory / 'reviewer.json'))})
        else:
            if defect is None or index != defect['index'] + 1:
                raise OpafError('No exact repair plus adjacent projection checkpoint is available.')
            project_context(packet, request, raw, prefix[-1], canonical_hash(views[-1]), prefix)
            expected_dirs = {row['focus_id'] for row in plan['requests'][:index + 1]}
            actual_dirs = {path.name for path in (job / 'prototype-pipeline').glob('focus-*')}
            if expected_dirs != actual_dirs: raise OpafError('Later or missing focus work blocks this epoch.')
            epoch_plan = {'ai_approved_focuses': len(prefix), 'source_checked_focuses': len(prefix) - 1,
                'repair_focus_id': defect['request']['focus_id'], 'projection_focus_id': request['focus_id'],
                'source_fact_violations': len(defect['requirements']['diagnostics']),
                'planned_corrective_operations': list(OPERATIONS), 'remaining_focus_count': len(plan['requests']) - index - 1,
                'continue_remaining_run': True, 'repair_requirements': defect['requirements'],
                'repair_raw_candidate_sha256': canonical_hash(defect['raw']), 'projection_raw_candidate_sha256': canonical_hash(raw)}
            predecessor_sha = canonical_hash(predecessor)
            checkpoint = canonical_hash({'epoch_number': NUMBER, 'predecessor_sha256': predecessor_sha,
                'before_files': before, 'plan': epoch_plan, 'normalization_policy': POLICY})
            return epoch_plan, before, None, checkpoint, predecessor_sha
    raise OpafError('No exact terminal repair/projection pair exists.')


def extended_review(request, candidate, raw, operation, evidence):
    return {'request': request, 'candidate': candidate, 'candidate_sha256': canonical_hash(candidate),
        'review_context': {'schema_version': 1, 'scope': 'fox-focus-extended-review-v1', 'operation': operation,
            'raw_candidate': raw, 'raw_candidate_sha256': canonical_hash(raw), 'evidence': evidence,
            'trusted_requirements': {'source_fact_values_and_every_ref_must_match_exact_whitelist': True,
                'old_ai_approval_is_not_source_validation': True,
                'review_every_required_clause_body_conditions_effects_and_action_refs': True,
                'generic_or_relabelled_unsupported_facts_must_be_changes_required': True,
                'compare_both_rationales_no_semantic_equivalence_from_machine_match': True,
                'external_semantics_must_remain_uncertain': True,
                'never_repair_candidate_or_accept_business_behavior': True}}}


def _repair_context(request, historical, requirements):
    return {'schema_version': 1, 'scope': 'fox-one-focus-mapper-repair-v1',
        'original_request_sha256': canonical_hash(request), 'raw_candidate': historical,
        'raw_candidate_sha256': canonical_hash(historical), 'requirements': requirements,
        'task': 'Return a replacement for this focus only. Analyze the supplied clauses; do not relabel invented facts. Preserve all unrelated design exactly.'}


def technical_record(root):
    from .prototype_read_scope import cached_read
    return cached_read(root, 'technical_record', {}, lambda: _technical_record(root))


def _technical_record(root):
    from . import prototype_clause_epoch as clause
    from . import prototype_container_epoch as container
    from . import prototype_partition_review_epoch as partition
    from . import prototype_context_screen_epoch as screen
    if (Path(root) / screen.PREFIX).exists() or (Path(root) / screen.PREFIX).is_symlink():
        return screen.technical_record(Path(root))
    if (Path(root) / partition.PREFIX).exists() or (Path(root) / partition.PREFIX).is_symlink():
        return partition.technical_record(Path(root))
    if (Path(root) / container.PREFIX).exists() or (Path(root) / container.PREFIX).is_symlink():
        return container.technical_record(Path(root))
    if (Path(root) / clause.PREFIX).exists() or (Path(root) / clause.PREFIX).is_symlink():
        return clause.technical_record(Path(root))
    return _technical_epoch_two(root)


def _technical_epoch_two(root):
    root = Path(root)
    path = _safe_path(root, PREFIX + '/epoch-record.json')
    if not path.exists() and not path.is_symlink():
        if (root / 'epochs').exists(): raise OpafError('Epoch technical record is missing.')
        return None
    record = read(path)
    if record.get('scope') != SCOPE or record.get('epoch_number') != NUMBER or record.get('strategy') != STRATEGY:
        raise OpafError('Unknown active epoch contract.')
    same(record['normalization_policy'], POLICY)
    descriptors = _descriptors(record['before_files'])
    predecessor = read(_safe_path(root, PREFIX + '/predecessor-record.json'))
    if canonical_hash(predecessor) != record['predecessor_sha256']:
        raise OpafError('Technical epoch predecessor changed.')
    for name, digest in descriptors:
        if name.startswith('prototype-pipeline/'):
            source = _safe_path(root, name[len('prototype-pipeline/'):])
            if source.is_symlink() or not source.is_file() or hashlib.sha256(source.read_bytes()).hexdigest() != digest:
                raise OpafError('Historical model proof changed within active epoch.')
    return record


def active_focus(root, packet, plan, request, target, previous, *, runtime=None):
    """Execute/read one active version; full envelopes are reconstruction inputs."""
    from .prototype_read_scope import cached_read, forbid_execution
    if runtime is not None:
        forbid_execution()
        return _dispatch_active_focus(root, packet, plan, request, target, previous, runtime=runtime)
    from . import prototype_container_epoch as container
    four = Path(root) / container.PREFIX
    if four.exists() or four.is_symlink():
        record = technical_record(root)
        if record is not None and record.get('epoch_number') == container.NUMBER:
            return container._historical_active_focus(root, packet, plan, request, target, previous, record)
    return cached_read(root, 'active_focus', {'packet': packet, 'plan': plan, 'request': request,
        'target': target, 'previous': previous},
        lambda: _dispatch_active_focus(root, packet, plan, request, target, previous))


def _dispatch_active_focus(root, packet, plan, request, target, previous, *, runtime=None):
    record = technical_record(root)
    from . import prototype_clause_epoch as clause
    from . import prototype_container_epoch as container
    from . import prototype_partition_review_epoch as partition
    from . import prototype_context_screen_epoch as screen
    if record is not None and record.get('epoch_number') == screen.NUMBER:
        return screen.active_focus(root, packet, plan, request, target, previous, record, runtime=runtime)
    if record is not None and record.get('epoch_number') == partition.NUMBER:
        return partition.active_focus(root, packet, plan, request, target, previous, record, runtime=runtime)
    if record is not None and record.get('epoch_number') == container.NUMBER:
        return container.active_focus(root, packet, plan, request, target, previous, record, runtime=runtime)
    if record is not None and record.get('epoch_number') == clause.NUMBER:
        return clause.active_focus(root, packet, plan, request, target, previous, record, runtime=runtime)
    return _active_focus(root, packet, plan, request, target, previous, record, PREFIX, runtime=runtime)


def _active_focus(root, packet, plan, request, target, previous, record, prefix, *, runtime=None, preview=False, review_context=None, candidate_projection=None):
    write = runtime is not None
    index = next(i for i, row in enumerate(plan['requests']) if row['focus_id'] == request['focus_id'])
    repair = next(i for i, row in enumerate(plan['requests']) if record and row['focus_id'] == record['plan']['repair_focus_id']) if record else None
    identity = {'job_id': root.parent.name, 'source_hash': plan['source_binding']}
    original = root / request['focus_id']
    directory = root / prefix / request['focus_id'] if record and index >= repair else original
    if write: directory.mkdir(parents=True, exist_ok=True)
    if directory.is_symlink(): raise OpafError('Active epoch focus storage is unsafe.')
    if not record or index < repair:
        if write: save(original / 'request.json', request, True)
        raw, mapper = _role(original, 'mapper', request, target, identity, runtime)
        candidate, _ = resolved_mapper(original, request, raw, write=write)
        gate = source_fact_gate(packet, request, candidate)
        payload = {'request': request, 'candidate': candidate, 'candidate_sha256': canonical_hash(candidate)}
        review, reviewer = _role(original, 'reviewer', payload, target, identity, runtime)
        evidence = None
    elif index == repair:
        historical = read(original / 'mapper.json')['output']
        historical, _ = resolved_mapper(original, request, historical)
        requirements = repair_requirements(packet, request, historical)
        same(requirements, record['plan']['repair_requirements'])
        if canonical_hash(historical) != record['plan']['repair_raw_candidate_sha256']:
            raise OpafError('Repair source candidate changed.')
        mapper_request = deepcopy(request)
        mapper_request['repair_context'] = _repair_context(request, historical, requirements)
        save(directory / 'mapper-request.json', mapper_request, write)
        candidate, mapper = _role(directory, 'mapper', mapper_request, target, identity, runtime)
        gate = validate_repair(packet, request, historical, candidate, requirements)
        evidence = {'repair_requirements': requirements, 'historical_review_sha256': canonical_hash(read(original / 'reviewer.json'))}
        payload = extended_review(request, candidate, historical, 'repair_review', evidence)
        save(directory / 'reviewer-request.json', payload, write)
        review, reviewer = _role(directory, 'reviewer', payload, target, identity, runtime)
    else:
        projection_index = next(i for i, row in enumerate(plan['requests']) if row['focus_id'] == record['plan']['projection_focus_id'])
        mapper_dir = original if index == projection_index else directory
        if mapper_dir == directory: save(directory / 'mapper-request.json', request, write)
        raw, mapper = _role(mapper_dir, 'mapper', request, target, identity, runtime)
        if index == projection_index and canonical_hash(raw) != record['plan']['projection_raw_candidate_sha256']:
            raise OpafError('Projection raw response changed.')
        candidate, evidence = raw, None
        if index != projection_index:
            try:
                candidate, owner_receipt = resolve_claim_owners(request, raw)
                gate = source_fact_gate(packet, request, candidate)
                if owner_receipt is not None:
                    evidence = {'schema_version': 1, 'scope': 'fox-focus-technical-normalization-v2',
                        'raw_candidate_sha256': canonical_hash(raw), 'candidate_sha256': canonical_hash(candidate),
                        'owner_resolution_v1': owner_receipt}
            except ValueError:
                candidate = None
        if index == projection_index or candidate is None:
            extra = [row for row in raw['blueprint']['objects'] if row['source_object_id'] not in {obj['id'] for obj in request['owned_objects']}]
            dependency = None
            if extra:
                dependencies = [view for view in previous if any(row['source_object_id'] == extra[0]['source_object_id'] for row in view['candidate']['blueprint']['objects'])]
                if len(dependencies) != 1 or not dependencies[0]['checked']['approved_structured_design']:
                    raise OpafError('Projection has no unique active approved owner proof.')
                dependency = dependencies[0]
            candidate, projection = project_context(packet, request, raw, dependency['candidate'] if dependency else None,
                canonical_hash(dependency['proof']) if dependency else None, [view['candidate'] for view in previous],
                strict_known_case=index == projection_index)
            evidence = {'projection': projection, 'prior_active_proof': dependency['proof'] if dependency else None}
            gate = source_fact_gate(packet, request, candidate)
        if candidate_projection is not None:
            candidate, evidence = candidate_projection(candidate, raw, evidence)
            gate = source_fact_gate(packet, request, candidate)
        if evidence is not None:
            save(directory / 'projection-candidate.json', candidate, write)
            save(directory / 'projection-receipt.json', evidence, write)
            payload = extended_review(request, candidate, raw, 'projection_review', evidence)
        else:
            payload = {'request': request, 'candidate': candidate, 'candidate_sha256': canonical_hash(candidate)}
        if review_context is not None:
            payload = review_context(candidate, payload)
        save(directory / 'reviewer-request.json', payload, write)
        if preview:
            return {'review_request': payload}
        review, reviewer = _role(directory, 'reviewer', payload, target, identity, runtime)
    if mapper['room_id'] == reviewer['room_id']:
        raise OpafError('Active version requires an independent reviewer invocation.')
    checked = _review(request, candidate, review, directory)
    save(directory / 'review-receipt.json', checked, write)
    if record:
        save(root / prefix / 'source-facts' / (request['focus_id'] + '.json'), gate, write)
    proof = {'focus_id': request['focus_id'], 'candidate_sha256': canonical_hash(candidate),
        'source_fact_check': gate, 'review_request_sha256': canonical_hash(payload),
        'review_sha256': canonical_hash(review), 'review_receipt_sha256': canonical_hash(checked),
        'active_directory': directory.relative_to(root).as_posix(),
        'mapper_invocation': mapper, 'reviewer_invocation': reviewer,
        'technical_evidence_sha256': canonical_hash(evidence) if evidence else None}
    return {'candidate': candidate, 'checked': checked, 'proof': proof}
