"""One explicit, pre-review query omission on a sealed initial mapping run.

This is not clause recovery or format normalization. The original model output
is retained, the omitted behavior is unresolved, and a fresh reviewer must
approve the derived partial design before normal technical gates can proceed.
"""
from .design_provider import roles as provider_roles
from copy import deepcopy
import hashlib
import math
from pathlib import Path
import re

from .opaf import OpafError, canonical_hash

SCOPE = 'fox-prototype-redacted-query-omission-continuation-v1'
RECORD = 'redacted-query-omission.json'
EVENT = 'approved_prototype_redacted_query_omission'
APPROVALS = {'redacted_source': True, 'external_ai': True,
             'synthetic_prototype': True, 'query_omission': True}
KEYS = {'schema_version', 'scope', 'job_id', 'project_id', 'snapshot_sha256',
        'source_hash', 'source_binding', 'target_profile_sha256', 'owner',
        'approved_at', 'approvals', 'before_files', 'plan', 'checkpoint_sha256'}


def present(root):
    path = Path(root) / RECORD
    return path.exists() or path.is_symlink()


def _fail():
    raise OpafError('The saved query-omission checkpoint changed or is outside its approved partial scope.')


def event_id(rid, record):
    return rid + ':query-omission:000001:' + canonical_hash(record)


def checkpoint(before, plan):
    return canonical_hash({'scope': SCOPE, 'before_files': before, 'plan': plan})


def _initial_only(root):
    from . import prototype_mapping_epochs as epochs
    from . import prototype_candidate_continuation as cf
    from . import prototype_preclaim_continuation as pc
    if (epochs.technical_record(root) is not None or cf.present(root) or pc.present(root)
            or any((root.parent / name).exists() or (root.parent / name).is_symlink()
                   for name in ('mapping-epochs', 'mapping-continuation.json'))):
        _fail()
    from .prototype_candidate_format import POLICY
    if epochs.read(root / 'binding.json').get('candidate_format_policy') != POLICY:
        _fail()


def _review_payload(request, raw, candidate, receipt):
    return {'request': request, 'candidate': candidate,
        'candidate_sha256': canonical_hash(candidate),
        'review_context': {'scope': SCOPE, 'original_candidate': deepcopy(raw),
            'omission_receipt': deepcopy(receipt),
            'task': 'Review this explicitly partial synthetic prototype. Verify the exact source-linked '
                'query filter and sorting omissions are unresolved and NOT IMPLEMENTED. Do not recover '
                'masked literals or infer global values. Check all unrelated design is preserved, '
                'questions are actionable, and no omitted behavior is claimed as converted. '
                'Approve only this honest partial design, not business equivalence.'}}


def _material(root, packet, plan, target, index):
    """Pure reconstruction: no client, mutable approval, or output writes."""
    from . import prototype_mapping_epochs as epochs
    from .prototype_dsc_identity_repair import documents
    from .prototype_redacted_clause_omission import omit_redacted_clauses
    _initial_only(root)
    if type(index) is not int or not 0 <= index < len(plan['requests']):
        _fail()
    views = []
    for request in plan['requests'][:index]:
        view = epochs._active_focus(root, packet, plan, request, target, views, None, epochs.PREFIX)
        if not view['checked']['approved_structured_design']:
            _fail()
        views.append(view)
    request = plan['requests'][index]
    directory = root / request['focus_id']
    epochs.same(epochs.read(directory / 'request.json'), request)
    raw, mapper = epochs._role(directory, 'mapper', request, target,
        {'job_id': root.parent.name, 'source_hash': plan['source_binding']})
    candidate, receipt = omit_redacted_clauses(documents(root), request, raw,
        expected_original_sha256=canonical_hash(raw), stage='pre_review_mapping')
    payload = _review_payload(request, raw, candidate, receipt)
    summary = {'focus_id': request['focus_id'], 'completed_focus_count': index,
        'remaining_focus_count': len(plan['requests']) - index - 1,
        'prior_proofs_sha256': canonical_hash([v['proof'] for v in views]),
        'request_sha256': canonical_hash(request), 'mapper_invocation_sha256': canonical_hash(mapper),
        'raw_candidate_sha256': canonical_hash(raw), 'candidate_sha256': canonical_hash(candidate),
        'omission_receipt_sha256': canonical_hash(receipt), 'review_request_sha256': canonical_hash(payload),
        'repeated_mapper_calls': 0, 'fresh_reviewer_calls': 1,
        'omissions': ['Original query filter is not implemented.', 'Original query sorting is not implemented.'],
        'business_behavior_accepted': False}
    return summary, candidate, receipt, payload, mapper, views


def _technical(root, packet, plan, target):
    from . import prototype_mapping_epochs as epochs
    record = epochs.read(root / RECORD)
    binding = epochs.read(root / 'binding.json')
    if (set(record) != KEYS or type(record['schema_version']) is not int or record['schema_version'] != 1
            or record['scope'] != SCOPE or record['approvals'] != APPROVALS
            or type(record['approved_at']) not in (int, float) or not math.isfinite(record['approved_at'])
            or record['approved_at'] <= 0 or record['job_id'] != root.parent.name
            or record['project_id'] != binding['project_id'] or record['source_binding'] != plan['source_binding']
            or record['target_profile_sha256'] != canonical_hash(target)
            or binding['focus_plan_sha256'] != canonical_hash(plan)
            or binding['profile_sha256'] != canonical_hash(provider_roles(target))):
        _fail()
    epochs._descriptors(record['before_files'])
    epochs._before_unchanged(root, {n[len('prototype-pipeline/'):]: d
        for n, d in record['before_files'].items() if n.startswith('prototype-pipeline/')})
    material = _material(root, packet, plan, target, record['plan']['completed_focus_count'])
    epochs.same(record['plan'], material[0])
    if record['checkpoint_sha256'] != checkpoint(record['before_files'], material[0]):
        _fail()
    directory = root / material[0]['focus_id']
    for name, value in zip(('projection-candidate.json', 'projection-receipt.json', 'reviewer-request.json'), material[1:4]):
        epochs.same(epochs.read(directory / name), value)
    return record, material


def technical(root, packet, plan, target):
    from .prototype_read_scope import epoch_read_scope, cached_read
    with epoch_read_scope(root):
        return cached_read(root, 'active_focus', {'purpose': SCOPE, 'packet': packet, 'plan': plan,
            'target': target}, lambda: _technical(root, packet, plan, target))


def validate_event(job, record, db):
    rows = db.execute('SELECT owner,object_id,created FROM events WHERE action=? AND object_id LIKE ?',
        (EVENT, job.name + ':query-omission:%')).fetchall()
    expected = [] if record is None else [(record['owner'], event_id(job.name, record), record['approved_at'])]
    if [tuple(row) for row in rows] != expected:
        _fail()


def validate_record(job, snapshot, original, db, *, phase=None):
    from . import prototype_mapping_epochs as epochs
    root = job / 'prototype-pipeline'
    if not present(root):
        validate_event(job, None, db)
        return None
    focus_id = epochs.read(root / RECORD)['plan']['focus_id']
    if type(focus_id) is not str or not re.fullmatch(r'focus-[a-f0-9]{24}', focus_id):
        _fail()
    target = epochs.read(epochs._safe_path(root, focus_id + '/mapper-target.json'))
    packet, plan = epochs.reconstruct(job, snapshot, original, target)
    record, _ = technical(root, packet, plan, target)
    if (record['snapshot_sha256'] != hashlib.sha256(original).hexdigest()
            or record['source_hash'] != snapshot['source_hash']
            or record['owner'] != snapshot['approvals']['owner']
            or record['project_id'] != snapshot['project_id']
            or record['approved_at'] <= snapshot['approvals']['approved_at']):
        _fail()
    epochs._before_unchanged(job, {n: d for n, d in record['before_files'].items()
                                 if n != 'prototype-result.json'})
    validate_event(job, record, db)
    current_frontier(root, packet, plan, target, record, phase=phase)
    return record


def current_frontier(root, packet, plan, target, record, *, phase=None):
    """No foreign/later work or unknown operation can coexist with a new call."""
    from . import prototype_mapping_epochs as epochs
    from .prototype_read_scope import epoch_read_scope
    if phase is not None and (type(phase) is not epochs._ConverterPhase or phase.seal is not epochs._PHASE_SEAL
            or phase.job != str(root.parent.absolute()) or phase.epoch_sha256 != canonical_hash(record)):
        _fail()
    epochs._closure(root.parent, phase=phase, known_focuses={r['focus_id'] for r in plan['requests']})
    views, pending = [], False
    with epoch_read_scope(root):
        for request in plan['requests']:
            directory = root / request['focus_id']
            if pending:
                if directory.exists() or directory.is_symlink(): _fail()
                continue
            if not directory.exists():
                pending = True
                continue
            if (directory / 'reviewer.json').exists():
                view = active_focus(root,packet,plan,request,target,views)
                if not view['checked']['approved_structured_design']: _fail()
                views.append(view)
                continue
            pending = True
            if (directory / 'mapper.json').exists():
                epochs._role(directory,'mapper',request,target,
                    {'job_id':root.parent.name,'source_hash':plan['source_binding']})
            elif any(p.name not in {'request.json','mapper-request.json','mapper-target.json',
                                   'mapper-metadata-task.json'} for p in directory.iterdir()):
                _fail()
        if pending:
            downstream = {'merged-blueprint.json','native-plan.json','review-index.json','rendered.json','candidate-apexlang.zip',
                *{s+suffix for s in ('validate','prepare_schema','import','verify_runtime','export')
                  for suffix in ('.json','-intent.json')}}
            if (phase is not None or any((root/n).exists() for n in downstream)
                    or (root.parent/'prototype-transport').exists()): _fail()


def converter_phase(job, snapshot, original, stage, request):
    """Use the existing typed intent exception, bound to exact reconstructed output."""
    from . import prototype_mapping_epochs as epochs
    from .prototype_pipeline import CONVERTER_STAGES, authorize_prototype_request
    from .prototype_authority import _retained_request
    if stage not in CONVERTER_STAGES or len(request.get('prior_receipts',{})) != CONVERTER_STAGES.index(stage):
        _fail()
    authorize_prototype_request(job,request)
    _retained_request(job,request)
    root = job/'prototype-pipeline'
    for later in CONVERTER_STAGES[CONVERTER_STAGES.index(stage)+1:]:
        if any((root/(later+suffix)).exists() or (root/(later+suffix)).is_symlink()
               for suffix in ('.json','-intent.json')): _fail()
    record = epochs.read(root/RECORD)
    return epochs._ConverterPhase(epochs._PHASE_SEAL,str(job.absolute()),canonical_hash(record),stage,canonical_hash(request))


def inspect(job, snapshot, original, target, db):
    from . import prototype_mapping_epochs as epochs
    from .prototype_candidate_continuation import ArtifactPlan
    from .prototype_read_scope import epoch_read_scope
    root = job / 'prototype-pipeline'
    with epoch_read_scope(root):
        packet, plan = epochs.reconstruct(job, snapshot, original, target)
        if present(root):
            record = validate_record(job, snapshot, original, db)
            return record['plan'], record['before_files'], record, None
        _initial_only(root)
        validate_event(job, None, db)
        row = db.execute('SELECT state,artifact FROM runs WHERE id=?', (job.name,)).fetchone()
        if row is None or row[0] != 'ATTENTION' or row[1] is not None:
            _fail()
        index = next((i for i, r in enumerate(plan['requests'])
            if not (root / r['focus_id'] / 'reviewer.json').exists()), len(plan['requests']))
        if index == len(plan['requests']):
            _fail()
        summary, candidate, receipt, payload, _, _ = _material(root, packet, plan, target, index)
        directory = root / summary['focus_id']
        if any(p.name.startswith('reviewer') or p.name in ('review-receipt.json',
                'projection-candidate.json', 'projection-receipt.json') for p in directory.iterdir()):
            _fail()
        if any((root / r['focus_id']).exists() or (root / r['focus_id']).is_symlink()
               for r in plan['requests'][index + 1:]):
            _fail()
        forbidden = ['merged-blueprint.json', 'native-plan.json', 'review-index.json', 'rendered.json',
            'candidate-apexlang.zip', *{s + suffix for s in
                ('validate', 'prepare_schema', 'import', 'verify_runtime', 'export')
                for suffix in ('.json', '-intent.json')}]
        if (any((root / name).exists() or (root / name).is_symlink() for name in forbidden)
                or (job / 'prototype-transport').exists() or (job / 'prototype-transport').is_symlink()):
            _fail()
        before = epochs._closure(job, known_focuses={r['focus_id'] for r in plan['requests']})
        artifacts = ArtifactPlan(root)
        for name, value in zip(('projection-candidate.json', 'projection-receipt.json', 'reviewer-request.json'),
                               (candidate, receipt, payload)):
            artifacts.save(directory / name, value)
        return summary, before, None, artifacts


def retained_views(root, packet, plan, target):
    return technical(root, packet, plan, target)[1][-1]


def active_focus(root, packet, plan, request, target, previous, *, runtime=None):
    from . import prototype_mapping_epochs as epochs
    record, material = technical(root, packet, plan, target)
    summary, candidate, receipt, payload, mapper, prefix = material
    if request['focus_id'] != summary['focus_id']:
        return epochs._active_focus(root, packet, plan, request, target, previous, None, epochs.PREFIX, runtime=runtime)
    epochs.same([v['proof'] for v in previous], [v['proof'] for v in prefix])
    directory = root / request['focus_id']
    review, reviewer = epochs._role(directory, 'reviewer', payload, target,
        {'job_id': root.parent.name, 'source_hash': plan['source_binding']}, runtime)
    rooms = {mapper['room_id']}
    for view in prefix:
        rooms.update(view['proof'][role]['room_id'] for role in ('mapper_invocation', 'reviewer_invocation'))
    if reviewer['room_id'] in rooms:
        _fail()
    checked = epochs._review(request, candidate, review, directory)
    epochs.save(directory / 'review-receipt.json', checked, runtime is not None)
    gate = epochs.source_fact_gate(packet, request, candidate)
    proof = {'focus_id': request['focus_id'], 'candidate_sha256': canonical_hash(candidate),
        'source_fact_check': gate, 'review_request_sha256': canonical_hash(payload),
        'review_sha256': canonical_hash(review), 'review_receipt_sha256': canonical_hash(checked),
        'active_directory': request['focus_id'], 'mapper_invocation': mapper, 'reviewer_invocation': reviewer,
        'technical_evidence_sha256': canonical_hash(receipt), 'query_omission_record_sha256': canonical_hash(record)}
    return {'candidate': candidate, 'checked': checked, 'proof': proof}
