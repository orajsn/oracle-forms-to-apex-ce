"""Read-only checkpoint reconstruction for one explicit same-run continuation."""
import hashlib
import math
import re
import sqlite3
from pathlib import Path

from . import forms_design_review
from .forms_focus import build_focus_plan
from .forms_understanding_packet import local_packet
from .native_pipeline import _json
from .opaf import OpafError, canonical_hash
from .prototype_admission import bound_focus_limit
from .prototype_claim_resolution import resolve_claim_owners, resolved_mapper, STRATEGY
from .prototype_mapping_recovery import _tree_bytes

RECORD = 'mapping-continuation.json'
EVENT = 'approved_prototype_mapping_continuation'
SCOPE = 'fox-prototype-mapping-continuation-v1'


def continuation_event_id(rid, record):
    return rid + ':' + canonical_hash(record)


def validate_job_continuation(job, snapshot, original, *, phase=None):
    """Worker-side durable consent check before configuration or a new call."""
    database = job.parent.parent / 'fox.sqlite3'
    recorded = (job / RECORD).exists() or (job / RECORD).is_symlink()
    from . import prototype_preclaim_continuation as preclaim
    preclaimed = preclaim.present(job/'prototype-pipeline')
    if not recorded and not database.exists() and not database.is_symlink():
        if preclaimed: raise OpafError('Validation continuation requires its durable owner database.')
        if (job / 'mapping-epochs').exists() or (job / 'prototype-pipeline' / 'epochs').exists():
            raise OpafError('Epoch proof cannot fall back to an unrecorded legacy run.')
        return  # Legacy direct callers without a persisted continuation.
    if database.is_symlink() or not database.is_file():
        raise OpafError('Continuation database is missing or unsafe.')
    with sqlite3.connect(database.absolute().as_uri() + '?mode=ro', uri=True) as connection:
        from .prototype_preclaim_continuation import entry_phase
        phase = entry_phase(job,snapshot,original,connection,phase)
        rows = connection.execute('SELECT owner,object_id,created FROM events WHERE action=? AND '
            '(object_id=? OR object_id LIKE ?)', (EVENT, job.name, job.name + ':%')).fetchall()
        if not recorded:
            if rows:
                raise OpafError('Persisted continuation lost its durable record; no new operation is authorized.')
            from .prototype_mapping_epochs import validate_epoch_chain
            validate_epoch_chain(job, snapshot, original, connection, phase=phase)
            return
        record = validate_continuation_record(job, snapshot, original, _json(job / RECORD))
        if rows != [(record['owner'], continuation_event_id(job.name, record), record['approved_at'])]:
            raise OpafError('Continuation has no exact persisted consent event.')
        from .prototype_mapping_epochs import validate_epoch_chain
        validate_epoch_chain(job, snapshot, original, connection, phase=phase)


def validate_continuation_record(job, snapshot, original, record):
    expected = {'schema_version', 'scope', 'strategy', 'job_id', 'project_id', 'snapshot_sha256',
                'checkpoint_sha256', 'files', 'completed_focuses', 'blocked_focus_id',
                'resolved_claim_owners', 'owner', 'approved_at', 'approvals'}
    if (type(record) is not dict or set(record) != expected or type(record['schema_version']) is not int
            or record['schema_version'] != 1 or record['scope'] != SCOPE or record['strategy'] != STRATEGY
            or record['job_id'] != job.name or record['project_id'] != snapshot['project_id']
            or record['snapshot_sha256'] != hashlib.sha256(original).hexdigest()
            or record['owner'] != snapshot['approvals']['owner']
            or type(record['approved_at']) not in (int, float) or not math.isfinite(record['approved_at'])
            or record['approved_at'] <= 0
            or type(record['completed_focuses']) is not int or not 0 <= record['completed_focuses'] < 256
            or type(record['resolved_claim_owners']) is not int or not 1 <= record['resolved_claim_owners'] <= 10000
            or type(record['blocked_focus_id']) is not str or not re.fullmatch(r'focus-[a-f0-9]{24}', record['blocked_focus_id'])
            or type(record['checkpoint_sha256']) is not str or not re.fullmatch(r'[a-f0-9]{64}', record['checkpoint_sha256'])
            or type(record['approvals']) is not dict or set(record['approvals']) != {'redacted_source', 'external_ai', 'synthetic_prototype'}
            or any(value is not True for value in record['approvals'].values())
            or type(record['files']) is not dict or not 1 <= len(record['files']) <= 4096):
        raise OpafError('Continuation record differs from its immutable run and permissions.')
    for name, digest in record['files'].items():
        if (type(name) is not str or name.startswith('/') or '\\' in name or ':' in name
                or any(part in ('', '.', '..') for part in name.split('/'))
                or type(digest) is not str or not re.fullmatch(r'[a-f0-9]{64}', digest)):
            raise OpafError('Continuation record has an unsafe checkpoint path.')
        path = job / name
        if (any(parent.is_symlink() for parent in (path, *path.parents) if parent == job or job in parent.parents)
                or not path.is_file() or path.stat().st_size > 20_000_000
                or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
            raise OpafError('Original continuation checkpoint changed; no automatic replay.')
    proof = {key: record[key] for key in ('files', 'completed_focuses', 'blocked_focus_id', 'resolved_claim_owners')}
    if canonical_hash(proof) != record['checkpoint_sha256']:
        raise OpafError('Continuation checkpoint binding changed.')
    return record


def inspect_continuation(job, snapshot, original, target):
    """Rebuild the whole plan and a contiguous approved prefix; never invoke."""
    from .prototype_job import validate_prototype_snapshot
    from .prototype_pipeline import _artifact_json, _role
    job = Path(job)
    documents = validate_prototype_snapshot(snapshot)
    selected = snapshot['prototype']
    if canonical_hash(target) != selected['target_profile_sha256']:
        raise OpafError('Continuation requires the unchanged approved target.')
    plan = build_focus_plan(documents, expected_source_binding=selected['source_binding'],
        approved_chunk_hashes=selected['approved_chunk_hashes'], max_owned_objects=bound_focus_limit(selected))
    if canonical_hash(plan) != selected['focus_plan_sha256']:
        raise OpafError('Continuation focus plan changed.')
    root = job / 'prototype-pipeline'
    binding = _json(root / 'binding.json')
    expected = {'schema_version': selected['schema_version'], 'job_id': job.name,
        'project_id': snapshot['project_id'], 'project_name': snapshot['project_name'],
        'source_binding': selected['source_binding'], 'focus_plan_sha256': selected['focus_plan_sha256'],
        'profile_sha256': canonical_hash(target['opaf']['roles']), 'approved_policy_id': selected['approved_policy_id']}
    if selected['schema_version'] == 2:
        expected['max_owned_objects'] = bound_focus_limit(selected)
    metadata_policy = selected.get('metadata_task_policy')
    if 'metadata_task_policy' in selected:
        from .prototype_dsc_identity_repair import TASK_POLICY
        if metadata_policy != TASK_POLICY: raise OpafError('Unknown continuation metadata task policy.')
        expected['metadata_task_policy'] = metadata_policy
    if 'candidate_format_policy' in selected:
        from .prototype_candidate_format import POLICY
        if selected['candidate_format_policy'] != POLICY: raise OpafError('Unknown continuation candidate format policy.')
        expected['candidate_format_policy']=selected['candidate_format_policy']
    manifest = {'source_binding': selected['source_binding'], 'selected_chunk_hashes': selected['approved_chunk_hashes'],
        'files': [{'name': name, 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)} for name, raw in documents]}
    if (binding != expected or _json(root / 'sources-manifest.json') != manifest
            or _artifact_json(root / 'packet.json') != local_packet(documents)
            or _json(root / 'assessment.json') != {'source_binding': selected['source_binding'],
                'source_count': len(documents), 'source_objects': plan['total_source_objects'], 'focus_count': len(plan['requests'])}):
        raise OpafError('Continuation retained source/target proof changed.')
    for index, (_, raw) in enumerate(documents):
        path = root / 'sources' / f'source-{index:03}.xml'
        if path.is_symlink() or path.read_bytes() != raw:
            raise OpafError('Continuation retained source bytes changed.')
    record_path = job / RECORD
    if record_path.exists() or record_path.is_symlink():
        record = validate_continuation_record(job, snapshot, original, _json(record_path))
        allowed = set(record['files']) | {'prototype-pipeline', 'prototype-pipeline/sources', RECORD,
            'prototype-result.json', 'prototype-results', 'prototype-transport',
            'prototype-transport/authority.json', 'prototype-transport/authority-intent.json'}
        allowed.update('prototype-pipeline/' + name for name in
            ('review-index.json', 'merged-blueprint.json', 'native-plan.json', 'rendered.json', 'candidate-apexlang.zip'))
        from .prototype_pipeline import CONVERTER_STAGES, authorize_prototype_request, _check_converter_receipt
        allowed.update('prototype-pipeline/' + stage + suffix for stage in CONVERTER_STAGES for suffix in ('.json', '-intent.json'))
        for path in (job / 'prototype-results').glob('*.json'):
            if re.fullmatch(r'[a-f0-9]{64}\.json', path.name):
                allowed.add(path.relative_to(job).as_posix())
        identity = {'job_id': job.name, 'source_hash': selected['source_binding']}
        for request in plan['requests']:
            child = root / request['focus_id']
            if not child.exists():
                continue
            relative = 'prototype-pipeline/' + request['focus_id']
            allowed.add(relative)
            allowed.update(relative + '/' + name for name in ('request.json', 'mapper.json', 'mapper-target.json',
                'mapper-intent.json', 'reviewer.json', 'reviewer-target.json', 'reviewer-intent.json',
                'review-receipt.json', 'mapper-resolved.json', 'mapper-resolution.json'))
            if metadata_policy:
                allowed.update(relative+'/'+name+'-metadata-task.json' for name in ('mapper','reviewer'))
            if _json(child / 'request.json') != request or _json(child / 'mapper-target.json') != target:
                raise OpafError('Continued focus request or target changed.')
            raw, mapper = _role(child, 'mapper', None, target['opaf']['roles']['mapper'], request, identity, None, None, None)
            candidate, resolution = resolve_claim_owners(request, raw)
            if any((child / name).exists() for name in ('mapper-resolved.json', 'mapper-resolution.json')):
                resolved_mapper(child, request, raw)
            if (child / 'reviewer.json').exists():
                if resolution is not None:
                    resolved_mapper(child, request, raw)
                review, reviewer = _role(child, 'reviewer', None, target['opaf']['roles']['reviewer'],
                    {'request': request, 'candidate': candidate, 'candidate_sha256': canonical_hash(candidate)}, identity, None, None, None)
                checked = forms_design_review.validate_design_review(request, candidate, review)
                if (mapper['room_id'] == reviewer['room_id'] or _json(child / 'reviewer-target.json') != target
                        or canonical_hash(_json(child / 'review-receipt.json')) != canonical_hash(checked)):
                    raise OpafError('Continued reviewer proof changed.')
        _tree_bytes(job, allowed)
        if (root / 'rendered.json').exists():
            native, rendered = _artifact_json(root / 'native-plan.json'), _json(root / 'rendered.json')
            index = _json(root / 'review-index.json')
            base = {'schema_version': 1, 'scope': 'fox-prototype-converter-request-v1',
                'job_id': job.name, 'project_id': snapshot['project_id'], 'source_binding': selected['source_binding'],
                'plan_sha256': native['plan_sha256'], 'rendering_spec': native['rendering_spec'],
                'rendered_zip_sha256': rendered['zip_sha256'], 'source_authority': {'schema_version': 1,
                    'scope': 'fox-prototype-source-authority-v1', 'binding_sha256': canonical_hash(binding),
                    'sources_manifest_sha256': canonical_hash(manifest), 'review_index_sha256': canonical_hash(index)}}
            authorize_prototype_request(job, {**base, 'prior_receipts': {}})
            prior = {}
            for stage in CONVERTER_STAGES:
                if not (root / (stage + '.json')).exists():
                    break
                payload = {**base, 'prior_receipts': dict(prior)}
                prior[stage] = _check_converter_receipt(stage, payload, _json(root / (stage + '.json')))
        # A repeated HTTP request is never permission to retry an unsealed call.
        for path in job.rglob('*'):
            if path.is_symlink():
                raise OpafError('Continuation storage is unsafe.')
            if path.name.endswith('-intent.json') and not path.with_name(path.name.replace('-intent.json', '.json')).is_file():
                raise OpafError('Continuation has an uncertain operation; reconcile without replay.')
        return {**{key: record[key] for key in ('checkpoint_sha256', 'completed_focuses',
                    'blocked_focus_id', 'resolved_claim_owners')}, 'eligible': False,
                'reason': 'Continuation is already recorded. Open this run; completed work has not been replayed.',
                'continuation_recorded': True}, record['files']
    allowed = {'source-snapshot.json', 'prototype-pipeline', 'prototype-pipeline/sources'}
    allowed.update('prototype-pipeline/' + name for name in ('binding.json', 'sources-manifest.json', 'packet.json', 'assessment.json'))
    allowed.update(f'prototype-pipeline/sources/source-{index:03}.xml' for index in range(len(documents)))
    identity = {'job_id': job.name, 'source_hash': selected['source_binding']}
    completed, failure = 0, None
    for request in plan['requests']:
        child = root / request['focus_id']
        if not child.exists() or child.is_symlink():
            break
        if failure is not None:
            raise OpafError('Later focus work prevents bounded continuation.')
        relative = 'prototype-pipeline/' + request['focus_id']
        allowed.add(relative)
        allowed.update(relative + '/' + name for name in ('request.json', 'mapper-intent.json', 'mapper.json', 'mapper-target.json'))
        if metadata_policy: allowed.add(relative+'/mapper-metadata-task.json')
        if _json(child / 'request.json') != request or _json(child / 'mapper-target.json') != target:
            raise OpafError('Continuation mapper request or target changed.')
        saved = _json(child / 'mapper.json')
        if _json(child / 'mapper-intent.json') != saved['binding']:
            raise OpafError('Continuation mapper intent is not sealed.')
        raw, mapper = _role(child, 'mapper', None, target['opaf']['roles']['mapper'], request, identity, None, None, None)
        candidate, receipt = resolve_claim_owners(request, raw)
        if (child / 'reviewer.json').exists():
            if receipt is not None:
                resolved_mapper(child, request, raw)
                allowed.update(relative + '/' + name for name in ('mapper-resolved.json', 'mapper-resolution.json'))
            allowed.update(relative + '/' + name for name in ('reviewer-target.json', 'reviewer-intent.json', 'reviewer.json', 'review-receipt.json'))
            if metadata_policy: allowed.add(relative+'/reviewer-metadata-task.json')
            review_request = {'request': request, 'candidate': candidate, 'candidate_sha256': canonical_hash(candidate)}
            review, reviewer = _role(child, 'reviewer', None, target['opaf']['roles']['reviewer'],
                review_request, identity, None, None, None)
            if (_json(child / 'reviewer-target.json') != target or mapper['room_id'] == reviewer['room_id']
                    or _json(child / 'reviewer-intent.json') != _json(child / 'reviewer.json')['binding']):
                raise OpafError('Continuation reviewer is not independently sealed.')
            checked = forms_design_review.validate_design_review(request, candidate, review)
            if checked['approved_structured_design'] is not True or _json(child / 'review-receipt.json') != checked:
                raise OpafError('Human/model changes-required is not a technical owner-ID continuation.')
            completed += 1
        else:
            if receipt is None:
                raise OpafError('Sealed mapper does not have the eligible claim-owner failure.')
            failure = {'completed_focuses': completed, 'blocked_focus_id': request['focus_id'],
                       'resolved_claim_owners': len(receipt['resolutions'])}
    if failure is None:
        raise OpafError('No exact terminal claim-owner checkpoint is available.')
    files = _tree_bytes(job, allowed)
    closure = {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()}
    proof = {'files': closure, **failure}
    return {'checkpoint_sha256': canonical_hash(proof), **failure, 'eligible': True,
            'reason': 'Continue this run using the sealed mapping and approved earlier sections; completed model calls will not repeat.',
            'continuation_recorded': False}, closure
