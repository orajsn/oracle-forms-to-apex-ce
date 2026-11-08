"""Exact-source format policy and explicit, append-only pre-review continuation.

Planning reads sealed replies only. ArtifactPlan is a pure output description,
not an executable runtime/client and not a relaxation of epochs.save(False).
"""
from copy import deepcopy
import hashlib
import math

from .opaf import OpafError, canonical_hash
from . import prototype_candidate_format as format

POLICY = format.POLICY
SCOPE = 'fox-prototype-candidate-format-continuation-v1'
EVENT = 'approved_prototype_candidate_format_continuation'
RECORD = 'candidate-format-continuation.json'
RECORD_KEYS = {'schema_version','scope','policy','job_id','project_id','snapshot_sha256','source_hash',
    'source_binding','target_profile_sha256','owner','approvals','approved_at','epoch_sha256',
    'before_files','plan','checkpoint_sha256'}


def _fail():
    raise OpafError('The saved candidate format checkpoint is changed, uncertain or outside its exact scope.') from None


def present(root):
    return (root / RECORD).exists() or (root / RECORD).is_symlink()


class ArtifactPlan:
    """Collect deterministic missing pre-review outputs without creating files."""
    def __init__(self, root):
        self.root, self.files = root, {}

    def save(self, path, value):
        from . import prototype_mapping_epochs as epochs
        relative = path.relative_to(self.root).as_posix()
        epochs._safe_path(self.root, relative)
        if path.exists() or path.is_symlink():
            epochs.same(epochs.read(path), value)
        self.files[relative] = deepcopy(value)

    def materialize(self):
        from . import prototype_mapping_epochs as epochs
        # Validate all existing destinations before any create-only write.
        for name, value in self.files.items():
            path = epochs._safe_path(self.root, name)
            if path.exists() or path.is_symlink(): epochs.same(epochs.read(path), value)
        for name, value in self.files.items():
            epochs.save(epochs._safe_path(self.root, name), value, True)


def enabled(root, request=None, raw=None):
    from . import prototype_mapping_epochs as epochs
    binding = epochs.read(root / 'binding.json')
    if 'candidate_format_policy' in binding:
        if binding['candidate_format_policy'] != POLICY: _fail()
        return True
    if not present(root): return False
    record = epochs.read(root / RECORD)
    if record.get('scope') != SCOPE or record.get('policy') != POLICY: _fail()
    if request is not None and record['plan']['focus_id'] == request['focus_id']:
        if canonical_hash(raw) != record['plan']['raw_candidate_sha256']: _fail()
    return True


def normalize_remaining(root, request, raw, owner_candidate, owner_receipt, *, authorized=False):
    """Called only AFTER the unchanged owner/context path has failed."""
    if not authorized and not enabled(root, request, raw): raise ValueError('No immutable candidate format policy.')
    from .prototype_dsc_identity_repair import documents
    source = owner_candidate if owner_candidate is not None else raw
    candidate, receipt = format.normalize_candidate(documents(root), request, source)
    if receipt is None: raise ValueError('No exact format defect remains.')
    return candidate, {'schema_version': 1, 'scope': SCOPE,
        'raw_candidate_sha256': canonical_hash(raw),
        'owner_candidate_sha256': canonical_hash(source),
        'candidate_sha256': canonical_hash(candidate),
        'owner_resolution_v1': deepcopy(owner_receipt), 'candidate_format_normalization': receipt}


def event_id(job_id, record):
    return job_id + ':candidate-format:000001:' + canonical_hash(record)


def independent_reviewer(previous, mapper, reviewer, evidence):
    """A normalized candidate needs a new room, not a retained prior review."""
    pending=[evidence];normalized=False
    while pending:
        value=pending.pop()
        if type(value) is dict:
            normalized |= 'candidate_format_normalization' in value
            pending.extend(value.values())
        elif type(value) is list: pending.extend(value)
    if not normalized: return
    pending=[v['proof'] for v in previous]+[mapper];rooms=set()
    while pending:
        value=pending.pop()
        if type(value) is dict:
            if type(value.get('room_id')) is str: rooms.add(value['room_id'])
            pending.extend(value.values())
        elif type(value) is list: pending.extend(value)
    if reviewer['room_id'] in rooms: _fail()


def _derive(job, snapshot, original, target, epoch, *, index=None):
    from .prototype_read_scope import epoch_read_scope
    with epoch_read_scope(job/'prototype-pipeline'):
        return _derive_scoped(job,snapshot,original,target,epoch,index=index)


def _derive_scoped(job, snapshot, original, target, epoch, *, index=None):
    from . import prototype_mapping_epochs as epochs, prototype_dsc_identity_repair as dsc
    packet,plan=epochs.reconstruct(job,snapshot,original,target)
    dsc.validate_authorization(job/'prototype-pipeline',epoch,packet,plan,target,full_job=True)
    return _derive_material(job/'prototype-pipeline',packet,plan,target,epoch,index=index)


def _derive_material(root, packet, plan, target, epoch, *, index=None):
    from . import prototype_mapping_epochs as epochs, prototype_dsc_identity_repair as dsc
    from . import prototype_context_screen_epoch as screen
    job=root.parent
    # This version continues the existing explicit DSC path, not arbitrary jobs.
    if not dsc.present(root): _fail()
    dsc.validate_authorization(root, epoch, packet, plan, target)
    previous = []
    for position, request in enumerate(plan['requests']):
        if index is not None and position == index: break
        directory = root / screen.PREFIX / request['focus_id']
        if index is None and not (directory / 'reviewer.json').exists():
            # DSC projected historical reviews live in their own namespace.
            try:
                view = dsc.active_focus(root, packet, plan, request, target, previous, epoch)
            except (OpafError, ValueError, OSError, KeyError, TypeError):
                break
        else:
            view = dsc.active_focus(root, packet, plan, request, target, previous, epoch)
        if not view['checked']['approved_structured_design']: _fail()
        previous.append(view)
    position = len(previous)
    if position >= len(plan['requests']) or position < 9: _fail()
    request = plan['requests'][position]
    directory = root / screen.PREFIX / request['focus_id']
    # Full envelope validation precedes interpreting the candidate.
    raw, mapper = epochs._role(directory, 'mapper', request, target,
        {'job_id': job.name, 'source_hash': plan['source_binding']})
    artifacts = ArtifactPlan(root)
    proposed = screen._legacy_active_focus(root, packet, plan, request, target, previous, epoch,
        preview=True, artifact_plan=artifacts, allow_format=True)
    normalization = proposed['format_evidence']
    if normalization is None: _fail()
    receipt = normalization['candidate_format_normalization']
    summary = {'focus_id': request['focus_id'], 'completed_focus_count': position,
        'prior_proofs_sha256': canonical_hash([v['proof'] for v in previous]),
        'request_sha256': canonical_hash(request), 'mapper_invocation_sha256': canonical_hash(mapper),
        'raw_candidate_sha256': canonical_hash(raw), 'candidate_sha256': canonical_hash(proposed['candidate']),
        'normalization_receipt_sha256': canonical_hash(receipt),
        'normalization_change_count': len(receipt['changes']),
        'review_request_sha256': canonical_hash(proposed['review_request']),
        'artifacts_sha256': canonical_hash(artifacts.files),
        'remaining_focus_count': len(plan['requests']) - position - 1,
        'repeated_mapper_calls': 0, 'fresh_reviewer_calls': 1,
        'business_behavior_accepted': False}
    return summary, artifacts, plan


def checkpoint(epoch, before, plan):
    return canonical_hash({'scope': SCOPE, 'policy': POLICY, 'epoch_sha256': canonical_hash(epoch),
        'before_files': before, 'plan': plan})


def validate_technical_record(root, packet, plan, target):
    """Same derivation in copied inert authority; never owner/DB consent."""
    from .prototype_read_scope import epoch_read_scope
    with epoch_read_scope(root):
        return _validate_technical_record(root,packet,plan,target)


def _validate_technical_record(root, packet, plan, target):
    from . import prototype_mapping_epochs as epochs
    from .prototype_read_scope import cached_read
    def check():
        record=epochs.read(root/RECORD);epoch=epochs.technical_record(root)
        if (set(record)!=RECORD_KEYS or type(record['schema_version']) is not int or record['schema_version']!=1
                or record.get('scope')!=SCOPE or record.get('policy')!=POLICY or epoch is None
                or record.get('epoch_sha256')!=canonical_hash(epoch)
                or type(record['approved_at']) not in (int,float) or not math.isfinite(record['approved_at'])
                or record['approved_at']<=epoch['approved_at']
                or record.get('approvals')!={'redacted_source':True,'external_ai':True,'synthetic_prototype':True}): _fail()
        for key in ('job_id','project_id','snapshot_sha256','source_hash','source_binding','target_profile_sha256','owner'):
            epochs.same(record[key],epoch[key])
        epochs._descriptors(record['before_files'])
        epochs._before_unchanged(root,{n[len('prototype-pipeline/'):]:d for n,d in record['before_files'].items()
            if n.startswith('prototype-pipeline/')})
        proposed,artifacts,_=_derive_material(root,packet,plan,target,epoch,index=record['plan']['completed_focus_count'])
        epochs.same(record['plan'],proposed)
        if record['checkpoint_sha256']!=checkpoint(epoch,record['before_files'],proposed): _fail()
        for name,value in artifacts.files.items(): epochs.same(epochs.read(root/name),value)
        return record
    return cached_read(root,'active_focus',{'purpose':SCOPE,'packet':packet,'plan':plan,'target':target},check)


def validate_record(job, snapshot, original, target, db=None):
    from . import prototype_mapping_epochs as epochs, prototype_context_screen_epoch as screen
    root = job / 'prototype-pipeline'
    record = epochs.read(root / RECORD)
    epoch = epochs.technical_record(root)
    if (set(record) != RECORD_KEYS or type(record['schema_version']) is not int or record['schema_version'] != 1
            or record['scope'] != SCOPE or record['policy'] != POLICY
            or epoch is None or epoch['epoch_number'] != screen.NUMBER
            or record['epoch_sha256'] != canonical_hash(epoch)
            or record['job_id'] != job.name or record['project_id'] != snapshot['project_id']
            or record['snapshot_sha256'] != hashlib.sha256(original).hexdigest()
            or record['source_hash'] != snapshot['source_hash']
            or record['source_binding'] != snapshot['prototype']['source_binding']
            or record['target_profile_sha256'] != canonical_hash(target)
            or record['owner'] != snapshot['approvals']['owner']
            or record['approvals'] != {'redacted_source':True,'external_ai':True,'synthetic_prototype':True}
            or type(record['approved_at']) not in (int,float) or not math.isfinite(record['approved_at'])
            or record['approved_at'] <= epoch['approved_at']): _fail()
    epochs._before_unchanged(job, {n:d for n,d in record['before_files'].items() if n != 'prototype-result.json'})
    proposed, artifacts, _ = _derive(job,snapshot,original,target,epoch,index=record['plan']['completed_focus_count'])
    epochs.same(proposed, record['plan'])
    if record['checkpoint_sha256'] != checkpoint(epoch,record['before_files'],proposed): _fail()
    for name,value in artifacts.files.items(): epochs.same(epochs.read(root/name),value)
    if db is not None: validate_event(root,record,db)
    return record


def validate_event(root, record, db):
    rows = db.execute('SELECT owner,object_id,created FROM events WHERE action=? AND object_id LIKE ?',
        (EVENT,root.parent.name+':candidate-format:%')).fetchall()
    expected = [] if record is None else [(record['owner'],event_id(root.parent.name,record),record['approved_at'])]
    if [tuple(row) for row in rows] != expected: _fail()


def inspect(job, snapshot, original, target, db):
    from .prototype_read_scope import epoch_read_scope
    with epoch_read_scope(job/'prototype-pipeline'):
        return _inspect(job,snapshot,original,target,db)


def _inspect(job, snapshot, original, target, db):
    from . import prototype_mapping_epochs as epochs, prototype_context_screen_epoch as screen
    from . import prototype_dsc_identity_repair as dsc
    root = job/'prototype-pipeline'
    epoch = screen.validate_record(job,snapshot,original,db)
    if present(root):
        record = validate_record(job,snapshot,original,target,db)
        epochs._model_fence(job,snapshot,epoch)
        epochs._closure(job,record=epoch)
        return record['plan'],record['before_files'],record,record['checkpoint_sha256'],None,epoch
    validate_event(root,None,db)
    state = db.execute('SELECT state,artifact FROM runs WHERE id=?',(job.name,)).fetchone()
    if state is None or state[0] != 'ATTENTION' or state[1] is not None: _fail()
    if (job/'prototype-transport').exists() or (job/'prototype-transport').is_symlink(): _fail()
    if (job/dsc.RESULT_BASE/'publication.json').exists(): _fail()
    proposed, artifacts, plan = _derive(job,snapshot,original,target,epoch)
    position = proposed['completed_focus_count']
    for request in plan['requests'][position:]:
        directory = root/screen.PREFIX/request['focus_id']
        if request['focus_id'] == proposed['focus_id']:
            if any((directory/('reviewer'+suffix)).exists() or (directory/('reviewer'+suffix)).is_symlink()
                    for suffix in ('-request.json','-target.json','-intent.json','.json','-metadata-task.json')): _fail()
        elif directory.exists() or directory.is_symlink(): _fail()
    forbidden = ['merged-blueprint.json','native-plan.json','review-index.json','rendered.json','candidate-apexlang.zip',
        *{stage+suffix for stage in ('validate','prepare_schema','import','verify_runtime','export') for suffix in ('.json','-intent.json')}]
    if any((root/n).exists() or (root/n).is_symlink() for n in forbidden): _fail()
    before = epochs._closure(job,record=epoch,known_focuses={r['focus_id'] for r in plan['requests']})
    return proposed,before,None,checkpoint(epoch,before,proposed),artifacts,epoch
