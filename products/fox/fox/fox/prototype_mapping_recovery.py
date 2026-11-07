"""Read-only, first-mapper coverage recovery over retained production proof.

No provider calls, diagnostic-output promotion, blueprint repair or executable
replay is permitted here. The authenticated route owns current SQLite state.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re

from . import forms_design_review
from .forms_focus import build_focus_plan
from .forms_understanding_packet import local_packet
from .opaf import OpafError, canonical_hash, parse_model_message
from .prototype_admission import bound_focus_limit

STRATEGY = 'repartition-32-v1'
SCOPE = 'fox-prototype-mapping-recovery-v1'
RUN_ID = re.compile(r'fox-[a-f0-9]{20}\Z')


def retry_run_id(parent):
    if not isinstance(parent, str) or not RUN_ID.fullmatch(parent):
        raise ValueError('Invalid mapping-recovery parent.')
    return 'fox-' + canonical_hash({'parent_run_id': parent, 'strategy': STRATEGY})[:20]


def validate_retry_lineage(snapshot):
    """A retry is one explicit child, never an implicit chain or new scope."""
    if 'retry_of' not in snapshot and 'mapping_recovery' not in snapshot:
        return
    parent, metadata = snapshot.get('retry_of'), snapshot.get('mapping_recovery')
    if (not isinstance(parent, str) or not RUN_ID.fullmatch(parent)
            or type(metadata) is not dict
            or set(metadata) != {'schema_version', 'strategy', 'parent_snapshot_sha256'}
            or type(metadata.get('schema_version')) is not int or metadata['schema_version'] != 1
            or metadata.get('strategy') != STRATEGY
            or not isinstance(metadata.get('parent_snapshot_sha256'), str)
            or not re.fullmatch(r'[a-f0-9]{64}', metadata['parent_snapshot_sha256'])
            or snapshot.get('prototype', {}).get('schema_version') != 2
            or bound_focus_limit(snapshot['prototype']) != 32):
        raise ValueError('Invalid mapping-recovery lineage.')


def _tree_bytes(job, allowed):
    """Exact first-stage allowlist: unknown intents and later work fail closed."""
    retained = {}
    for directory in (job, job / 'prototype-pipeline'):
        if directory.is_symlink() or not directory.is_dir():
            raise OpafError('Mapping-recovery storage is missing or unsafe.')
    pending = [job]
    while pending:
        directory = pending.pop()
        for path in directory.iterdir():
            relative = path.relative_to(job).as_posix()
            if path.is_symlink() or relative not in allowed:
                raise OpafError('Later work or unknown intent requires operator reconciliation.')
            if path.is_dir():
                pending.append(path)
            elif path.is_file() and path.stat().st_size <= 20_000_000:
                raw = path.read_bytes()
                if path.suffix == '.json':
                    if not raw.lstrip().startswith(b'{'):
                        raise ValueError('Invalid retained JSON object.')
                    parse_model_message(raw.decode('utf-8'))
                retained[relative] = raw
            else:
                raise OpafError('Mapping-recovery proof is missing or unbounded.')
    return retained


def mapping_recovery_proof(job: Path, snapshot, original: bytes):
    """Reconstruct exact old focus and sealed first mapper, without any writes."""
    from .prototype_job import read_prototype_snapshot, validate_prototype_snapshot
    from .prototype_pipeline import _artifact_json, _json, _role
    job = Path(job)
    docs = validate_prototype_snapshot(snapshot)
    selected = snapshot['prototype']
    plan = build_focus_plan(docs, expected_source_binding=selected['source_binding'],
        approved_chunk_hashes=selected['approved_chunk_hashes'], max_owned_objects=bound_focus_limit(selected))
    if canonical_hash(plan) != selected['focus_plan_sha256'] or not plan['requests']:
        raise OpafError('Mapping-recovery focus binding is invalid.')
    first = plan['requests'][0]
    focus_dir = 'prototype-pipeline/' + first['focus_id']
    allowed = {'source-snapshot.json', 'prototype-pipeline', 'prototype-pipeline/sources', focus_dir}
    allowed.update('prototype-pipeline/' + name for name in
                   ('binding.json', 'sources-manifest.json', 'packet.json', 'assessment.json'))
    allowed.update(f'prototype-pipeline/sources/source-{i:03}.xml' for i in range(len(docs)))
    allowed.update(focus_dir + '/' + name for name in
                   ('request.json', 'mapper-target.json', 'mapper-intent.json', 'mapper.json'))
    before = _tree_bytes(job, allowed)
    checkpoints = job / 'prototype-pipeline'
    child = checkpoints / first['focus_id']
    target = _json(child / 'mapper-target.json')
    if canonical_hash(target) != selected['target_profile_sha256']:
        raise OpafError('Mapping-recovery retained target is stale.')
    roles = target['opaf']['roles']
    binding = {'schema_version': selected['schema_version'], 'job_id': job.name,
        'project_id': snapshot['project_id'], 'project_name': snapshot['project_name'],
        'source_binding': selected['source_binding'], 'focus_plan_sha256': selected['focus_plan_sha256'],
        'profile_sha256': canonical_hash({name: roles[name] for name in ('mapper', 'reviewer')}),
        'approved_policy_id': selected['approved_policy_id']}
    if selected['schema_version'] == 2:
        binding['max_owned_objects'] = bound_focus_limit(selected)
    if _json(checkpoints / 'binding.json') != binding:
        raise OpafError('Mapping-recovery pipeline binding changed.')
    manifest = {'source_binding': selected['source_binding'],
        'selected_chunk_hashes': selected['approved_chunk_hashes'],
        'files': [{'name': name, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
                  for name, raw in docs]}
    if (_json(checkpoints / 'sources-manifest.json') != manifest
            or _artifact_json(checkpoints / 'packet.json') != local_packet(docs)
            or _json(checkpoints / 'assessment.json') != {
                'source_binding': selected['source_binding'], 'source_count': len(docs),
                'source_objects': plan['total_source_objects'], 'focus_count': len(plan['requests'])}):
        raise OpafError('Mapping-recovery retained source proof changed.')
    for index, (_, raw) in enumerate(docs):
        if before.get(f'prototype-pipeline/sources/source-{index:03}.xml') != raw:
            raise OpafError('Mapping-recovery retained source bytes changed.')
    if _json(child / 'request.json') != first or _json(child / 'mapper-target.json') != target:
        raise OpafError('Mapping-recovery first request or target changed.')
    # Existence is mandatory before _role: its missing-cache path must never
    # observe, invoke, create an intent, or otherwise execute through this GET.
    saved = _json(child / 'mapper.json')
    if _json(child / 'mapper-intent.json') != saved.get('binding'):
        raise OpafError('Mapping-recovery mapper intent was not sealed.')
    candidate, invocation = _role(child, 'mapper', None, roles['mapper'], first,
        {'job_id': job.name, 'source_hash': selected['source_binding']}, None, None, None)
    if (not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', invocation.get('room_id', ''))
            or not re.fullmatch(r'[a-f0-9]{64}', invocation.get('response_sha256', ''))):
        raise OpafError('Mapping-recovery sealed invocation identity is invalid.')
    forms_design_review._canonical(candidate, forms_design_review.MAX_CANDIDATE_BYTES)
    rows = candidate.get('blueprint', {}).get('objects')
    if type(rows) is not list:
        raise OpafError('Mapping-recovery is restricted to missing owned-object coverage.')
    returned = {row['source_object_id'] for row in rows}
    owned = {row['id'] for row in first['owned_objects']}
    if not returned <= owned:
        raise OpafError('Mapping-recovery object ownership is invalid.')
    # The ordinary validator proves every OTHER shape constraint. Restricting
    # its expected set to returned ownership identifies only a missing subset;
    # it does not fill omitted rows or approve any behavior.
    forms_design_review._candidate_shape(candidate, first, returned)
    eligible = returned != owned and 'retry_of' not in snapshot
    reason = ('The first mapping returned incomplete object coverage. Retry once in smaller complete batches.'
              if eligible else 'This mapping already has complete coverage or is a bounded retry; no further mapping retry is available.')
    if _tree_bytes(job, allowed) != before or read_prototype_snapshot(job)[1] != original:
        raise OpafError('Mapping-recovery proof changed during inspection.')
    return {'eligible': eligible, 'expected_objects': len(owned),
            'returned_objects': len(returned), 'reason': reason}, target
