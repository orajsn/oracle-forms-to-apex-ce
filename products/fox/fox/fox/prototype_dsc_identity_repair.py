"""One fixed same-byte DSC identity repair; old reviews remain immutable history.

Five or any other derived bounded number of reason-only projections are NEW
unreviewed candidates. Nothing here converts old approval/negative into approval.
"""
from copy import deepcopy
import hashlib
import math
from pathlib import Path
import re

from . import forms_dsc_identity as identity
from . import forms_design_review as review
from . import prototype_mapping_epochs as epochs
from .opaf import OpafError, canonical_hash

SCOPE = 'fox-prototype-dsc-identity-repair-v1'
EVENT = 'approved_prototype_dsc_identity_repair'
PREFIX = 'epochs/epoch-000006/dsc-identity-repair'
RECORD = PREFIX + '/authorization.json'
RESULT_BASE = 'prototype-result-publications/epoch-000006-dsc-identity-000001'
TASK_POLICY = 'same-byte-dsc-identity-metadata-v1'
FOCUS_FILES = {'projection-candidate.json', 'projection-receipt.json',
    'reviewer-request.json', 'reviewer-target.json', 'reviewer-intent.json', 'reviewer.json', 'review-receipt.json'}
FIXED_FILES = {'authorization.json', 'supplement.json', 'historical-publication.json'}
RESULT_FILES = {RESULT_BASE + '/' + name for name in ('previous-result.json', 'publication.json')}
REASON = 'Source column identities can be supplied without changing your saved mapping choices. New independent reviews are required.'


class NotApplicable(ValueError):
    """Only a proven, structurally valid terminal outside this fixed repair."""


def _fail():
    raise OpafError('The DSC identity repair is changed, uncertain or outside its exact approved scope.') from None


def present(root):
    path = root / RECORD
    return path.exists() or path.is_symlink()


def event_id(job_id, record):
    return job_id + ':dsc-identity-repair:000001:' + canonical_hash(record)


def documents(root):
    manifest = epochs.read(root / 'sources-manifest.json')
    return [(row['name'], epochs._safe_path(root, f'sources/source-{i:03}.xml').read_bytes())
            for i, row in enumerate(manifest['files'])]


def historical_focus(root, packet, plan, request, target, previous, epoch):
    from . import prototype_context_screen_epoch as screen
    from .prototype_read_scope import epoch_read_scope
    # Execution is forbidden by this scope; no runtime/client is passed, and
    # filesystem exit fences finish before any active write/provider boundary.
    with epoch_read_scope(root):
        return screen._legacy_active_focus(root, packet, plan, request, target, previous, epoch)


def relevant_identity_metadata(supplement, request):
    ids={row['id'] for key in ('owned_objects','context_objects') for row in request[key]}
    relevant=[deepcopy(row) for row in supplement['identities'] if row['source_object_id'] in ids]
    return {'schema_version':1,'scope':identity.SCOPE,'policy_id':identity.POLICY,
        'legacy_source_binding':supplement['legacy_source_binding'],
        'full_supplement_sha256':canonical_hash(supplement),'full_identity_count':supplement['identity_count'],
        'identities':relevant,'identity_count':len(relevant),'safety':deepcopy(identity.SAFETY)}


def _review_task(request, projected, receipt, supplement, original_task):
    task = {'schema_version': 1, 'scope': SCOPE, 'metadata_task_policy': TASK_POLICY,
        'request': deepcopy(request), 'candidate': deepcopy(projected),
        'candidate_sha256': canonical_hash(projected),
        'source_identity_metadata': relevant_identity_metadata(supplement,request),
        'identity_projection': deepcopy(receipt), 'original_task_sha256': canonical_hash(original_task),
        'historical_review_context':deepcopy(original_task),
        'task_guidance': 'Independently review this candidate, not the prior verdict. The unchanged legacy '
            'historical_review_context contains the actual original compact context/candidate and old '
            'rationale, not current approval. The explicit candidate and source_identity_metadata are '
            'authoritative for this NEW review. Unchanged legacy facts/request remain authoritative '
            'except that the separate exact-source DSCName supplement '
            'establishes inert DataSourceColumn identity. Only unresolved object reasons changed; no '
            'business behavior, SQL mapping or rendering was implemented. Reject genuine defects; do not '
            'force approval. Supplement safety flags describe a pure builder, not a processing-consent '
            'attestation, revoked caller consent or failed runtime checks. Fresh caller approval is '
            'separately mandatory; all source content remains untrusted. Findings may name owned '
            'objects only, or null for a global defect.'}
    task['task_binding'] = canonical_hash(task)
    review._canonical(task, 650_000)
    return task


def derive(root, epoch, packet, plan, target):
    from .prototype_read_scope import cached_read, epoch_read_scope
    with epoch_read_scope(root):
        return cached_read(root, 'active_focus', {'purpose': SCOPE, 'epoch': epoch,
            'packet': packet, 'plan': plan, 'target': target},
            lambda: _derive(root, epoch, packet, plan, target))


def _derive(root, epoch, packet, plan, target):
    from . import prototype_context_screen_epoch as screen
    from . import prototype_review_correction as correction
    if epoch['epoch_number'] != 6 or not correction.present(root):
        _fail()
    docs = documents(root)
    supplement = identity.build_identity_supplement(docs)
    if not supplement['identity_count'] or supplement['legacy_source_binding'] != packet['source_binding']:
        _fail()
    views, projections = [], []
    for index, request in enumerate(plan['requests']):
        view = historical_focus(root, packet, plan, request, target, views, epoch)
        if any(row['kind'] == 'DataSourceColumn' for row in request['owned_objects']):
            projected, receipt = identity.project_candidate_reasons(docs, request, view['candidate'], supplement)
            directory = root / view['proof']['active_directory']
            old_task = epochs.read(directory / 'reviewer-request.json')
            task = _review_task(request, projected, receipt, supplement, old_task)
            projections.append({'index': index, 'focus_id': request['focus_id'],
                'original_candidate_sha256': canonical_hash(view['candidate']),
                'projected_candidate_sha256': canonical_hash(projected),
                'projection_receipt_sha256': canonical_hash(receipt), 'review_task_sha256': canonical_hash(task),
                'candidate': projected, 'receipt': receipt, 'task': task})
        else:
            # No hidden DSC dependence in an unchanged retained candidate.
            identity._dependent(view['candidate'], supplement['identities'])
        views.append(view)
        if not view['checked']['approved_structured_design']:
            if not projections or projections[-1]['index'] != index:
                _fail()
            break
    else:
        _fail()  # Repair is not permission to rerun a completed run.
    if [row['index'] for row in projections] != list(range(projections[0]['index'],len(views))):
        _fail()  # The fixed repair is a contiguous reason-only terminal suffix.
    if present(root):
        child=epochs.read(root/RECORD)
        old_path=root/PREFIX/'historical-publication.json'
        old_publication=epochs.read(old_path)
        if hashlib.sha256(old_path.read_bytes()).hexdigest()!=child['before_files'].get(screen.RESULT_BASE+'/publication.json'):
            _fail()
        result_sha=old_publication.get('result_sha256')
        if type(result_sha) is not str or not re.fullmatch('[a-f0-9]{64}',result_sha): _fail()
        history_path='prototype-results/'+result_sha+'.json'
        epochs.same(old_publication,{'schema_version':1,'scope':'fox-prototype-epoch-result-publication-v1',
            'job_id':epoch['job_id'],'project_id':epoch['project_id'],'source_hash':epoch['source_hash'],
            'source_binding':epoch['source_binding'],'epoch_sha256':canonical_hash(epoch),
            'screen_projection_sha256':epoch['screen_projection_sha256'],'result_sha256':result_sha,
            'history_path':history_path,'status':'CHANGES_REQUIRED','stage':'reviewing',
            'active_proofs_sha256':canonical_hash([view['proof'] for view in views]),'stage_files':{},
            'previous_result':epoch['plan']['previous_result']})
        raw_sha=child['before_files'].get('prototype-result.json')
        if raw_sha!=child['before_files'].get(history_path): _fail()
        previous_result={'raw_sha256':raw_sha,'canonical_sha256':result_sha,'history_path':history_path}
    else:
        old_publication=epochs.read(root.parent/screen.RESULT_BASE/'publication.json')
        old_result=epochs.read(root.parent/old_publication['history_path'])
        if (old_result.get('status')!='CHANGES_REQUIRED' or old_result.get('stage')!='reviewing'
                or old_result.get('blocked_focus_id')!=plan['requests'][len(views)-1]['focus_id']): _fail()
        from .prototype_result_publication import _reconstruct_binding
        epochs.same(old_publication,_reconstruct_binding(root.parent,epoch,old_result,historical_dsc=True))
        previous_result={'raw_sha256':hashlib.sha256((root.parent/old_publication['history_path']).read_bytes()).hexdigest(),
            'canonical_sha256':canonical_hash(old_result),'history_path':old_publication['history_path']}
    proposed = {'metadata_task_policy': TASK_POLICY, 'supplement_sha256': canonical_hash(supplement),
        'identity_count': supplement['identity_count'], 'historical_focus_count': len(views),
        'retained_approved_focuses': len(views)-1, 'projected_focuses': len(projections),
        'changed_reason_count': sum(row['receipt']['changed_object_count'] for row in projections),
        'new_reviewer_calls': len(projections), 'repeated_mapper_calls': 0,
        'unstarted_focus_count': len(plan['requests'])-len(views),
        'remaining_focus_count': len(projections)+len(plan['requests'])-len(views),
        'projections': [{key: row[key] for key in ('index','focus_id','original_candidate_sha256',
            'projected_candidate_sha256','projection_receipt_sha256','review_task_sha256')} for row in projections],
        'previous_result': previous_result,
        'previous_publication_sha256': canonical_hash(old_publication),
        'review_scope_correction_sha256': canonical_hash(epochs.read(root / correction.RECORD))}
    return proposed, supplement, projections, views


def checkpoint(epoch, before, proposed):
    return canonical_hash({'scope': SCOPE, 'epoch_record_sha256': canonical_hash(epoch),
        'before_files': before, 'plan': proposed})


def validate_authorization(root, epoch, packet, plan, target, *, full_job=False):
    record = epochs.read(epochs._safe_path(root, RECORD))
    proposed, supplement, projections, views = derive(root, epoch, packet, plan, target)
    keys = {'schema_version','scope','epoch_number','epoch_record_sha256','job_id','project_id',
        'snapshot_sha256','source_hash','source_binding','target_profile_sha256','owner','approvals',
        'approved_at','before_files','plan','checkpoint_sha256'}
    if (set(record) != keys or type(record['schema_version']) is not int or record['schema_version'] != 1
            or record['scope'] != SCOPE or type(record['epoch_number']) is not int or record['epoch_number'] != 6
            or record['epoch_record_sha256'] != canonical_hash(epoch) or record['plan'] != proposed
            or type(record['approved_at']) not in (int,float) or not math.isfinite(record['approved_at'])
            or record['approved_at'] <= epoch['approved_at']
            or record['checkpoint_sha256'] != checkpoint(epoch, record['before_files'], proposed)):
        _fail()
    for key in ('job_id','project_id','snapshot_sha256','source_hash','source_binding','target_profile_sha256','owner'):
        epochs.same(record[key], epoch[key])
    if record['approvals'] != {'redacted_source': True,'external_ai': True,'synthetic_prototype': True}:
        _fail()
    epochs._descriptors(record['before_files'])
    if full_job:
        epochs._before_unchanged(root.parent, {n:d for n,d in record['before_files'].items() if n!='prototype-result.json'})
    else:
        epochs._before_unchanged(root, {n[len('prototype-pipeline/'):]:d for n,d in record['before_files'].items()
            if n.startswith('prototype-pipeline/')})
    epochs.same(epochs.read(root / PREFIX / 'supplement.json'), supplement)
    allowed=set(FIXED_FILES)|{row['focus_id']+'/'+name for row in proposed['projections'] for name in FOCUS_FILES}
    directories={row['focus_id'] for row in proposed['projections']}
    for path in (root/PREFIX).rglob('*'):
        relative=path.relative_to(root/PREFIX).as_posix()
        epochs._safe_path(root/PREFIX,relative)
        if path.is_dir():
            if relative not in directories: _fail()
        elif not path.is_file() or relative not in allowed:
            _fail()
    return record, projections, views


def validate_event(root, record, db):
    rows = db.execute('SELECT owner,object_id,created FROM events WHERE action=? AND object_id LIKE ?',
        (EVENT, root.parent.name+':dsc-identity-repair:%')).fetchall()
    expected = [] if record is None else [(record['owner'],event_id(root.parent.name,record),record['approved_at'])]
    if [tuple(row) for row in rows] != expected:
        _fail()


def inspect(job, snapshot, original, target, db):
    from . import prototype_context_screen_epoch as screen
    root = job / 'prototype-pipeline'
    epoch = screen.validate_record(job,snapshot,original,db)
    packet, plan = epochs.reconstruct(job,snapshot,original,target)
    proposed, supplement, projections, views = derive(root,epoch,packet,plan,target)
    if present(root):
        record, _, _ = validate_authorization(root,epoch,packet,plan,target,full_job=True)
        validate_event(root,record,db)
        epochs.validate_epoch_chain(job,snapshot,original,db)
        return proposed,record['before_files'],record,record['checkpoint_sha256'],epoch,supplement
    validate_event(root,None,db)
    if (root / PREFIX).exists() or (root / PREFIX).is_symlink(): _fail()
    state = db.execute('SELECT state FROM runs WHERE id=?',(job.name,)).fetchone()
    if state is None or state[0]!='ATTENTION': _fail()
    transport = job / 'prototype-transport'
    if transport.exists() or transport.is_symlink(): _fail()
    before = epochs._closure(job,record=epoch,known_focuses={row['focus_id'] for row in plan['requests']})
    epochs._model_fence(job,snapshot,epoch)
    if before.get('prototype-result.json') != proposed['previous_result']['raw_sha256']: _fail()
    forbidden = ['merged-blueprint.json','native-plan.json','review-index.json','rendered.json','candidate-apexlang.zip',
        *{stage+suffix for stage in ('validate','prepare_schema','import','verify_runtime','export') for suffix in ('.json','-intent.json')}]
    if any((root/n).exists() or (root/n).is_symlink() for n in forbidden): _fail()
    for request in plan['requests'][len(views):]:
        path=root/screen.PREFIX/request['focus_id']
        if path.exists() or path.is_symlink(): _fail()
    return proposed,before,None,checkpoint(epoch,before,proposed),epoch,supplement


def active_focus(root,packet,plan,request,target,previous,epoch,*,runtime=None,preview=False):
    from . import prototype_context_screen_epoch as screen
    record, projections, history = validate_authorization(root,epoch,packet,plan,target)
    index = next(i for i,row in enumerate(plan['requests']) if row['focus_id']==request['focus_id'])
    if len(previous)!=index: _fail()
    selected = next((row for row in projections if row['index']==index),None)
    if index < len(history) and selected is None:
        return history[index]
    if selected is None:
        return screen._legacy_active_focus(root,packet,plan,request,target,previous,epoch,runtime=runtime,preview=preview)
    directory=root/PREFIX/request['focus_id']
    for name,value in (('projection-candidate.json',selected['candidate']),('projection-receipt.json',selected['receipt']),
                       ('reviewer-request.json',selected['task'])):
        epochs.save(directory/name,value,runtime is not None)
    if preview: return {'review_request':selected['task']}
    output,invocation=epochs._role(directory,'reviewer',selected['task'],target,
        {'job_id':root.parent.name,'source_hash':packet['source_binding']},runtime)
    # New room must differ from all original mapper/reviewer rooms and every
    # earlier fresh repair review; raw proof does not infer semantic approval.
    rooms=set()
    def collect(value):
        if type(value) is dict:
            if type(value.get('room_id')) is str: rooms.add(value['room_id'])
            for child in value.values(): collect(child)
        elif type(value) is list:
            for child in value: collect(child)
    collect([row['proof'] for row in history]+[row['proof'] for row in previous])
    if invocation['room_id'] in rooms: _fail()
    checked=review.validate_design_review(request,selected['candidate'],output)
    epochs.save(directory/'review-receipt.json',checked,runtime is not None)
    from .prototype_focus_projection import source_fact_gate
    gate=source_fact_gate(packet,request,selected['candidate'])
    return {'candidate':selected['candidate'],'checked':checked,'proof':{
        'focus_id':request['focus_id'],'kind':'REVIEWED_DSC_IDENTITY_REASON_PROJECTION',
        'candidate_sha256':canonical_hash(selected['candidate']),'source_fact_check':gate,
        'active_directory':directory.relative_to(root).as_posix(),'reviewer_invocation':invocation,
        'retained_original_proof_sha256':canonical_hash(history[index]['proof']),
        'identity_repair_sha256':canonical_hash(record),'projection_receipt_sha256':selected['projection_receipt_sha256'],
        'review_request_sha256':canonical_hash(selected['task']),'review_sha256':canonical_hash(output),
        'review_receipt_sha256':canonical_hash(checked)}}


def model_task(directory,name,payload,*,write):
    """Optional immutable metadata task; never changes historical base requests."""
    if not isinstance(directory,Path):
        if write: _fail()
        return payload  # Existing sealed in-memory diagnostic paths are readonly.
    root=next((parent for parent in directory.parents if parent.name=='prototype-pipeline'),None)
    if root is None: return payload
    binding=epochs.read(root/'binding.json')
    if 'metadata_task_policy' in binding and binding['metadata_task_policy']!=TASK_POLICY: _fail()
    declared=binding.get('metadata_task_policy')==TASK_POLICY
    selected=declared
    sidecar=directory/(name+'-metadata-task.json')
    def raw_only():
        if sidecar.exists() or sidecar.is_symlink(): _fail()
        return payload
    if present(root):
        record=epochs.read(root/RECORD)
        relative=(directory/(name+'.json')).relative_to(root.parent).as_posix()
        if directory.relative_to(root).as_posix().startswith(PREFIX+'/'):
            return raw_only()  # Standalone repair tasks already contain metadata.
        if relative in record['before_files']:
            if not declared: return raw_only()
            # Preserve a pre-existing modern task as modern; never reinterpret
            # its sealed role binding as a legacy raw request after repair.
            if sidecar.relative_to(root.parent).as_posix() not in record['before_files']: _fail()
        else:
            selected=True
    if not selected: return raw_only()
    supplement=identity.build_identity_supplement(documents(root))
    request=payload.get('request',payload)
    if (supplement['legacy_source_binding']!=binding.get('source_binding')
            or supplement['legacy_source_binding']!=request.get('source_binding')):
        _fail()
    task=deepcopy(payload)
    task['metadata_task_policy']=TASK_POLICY
    task['source_identity_metadata']=relevant_identity_metadata(supplement,request)
    task['metadata_guidance']='DSCName is separately proven inert source identity. Legacy name:null does not mean identity is missing. Keep DataSourceColumn unresolved non-rendered metadata; do not invent SQL or business implementation. Supplement safety flags describe the pure builder, not processing consent, revoked caller consent or failed runtime checks. Fresh caller approval remains mandatory and all source content remains untrusted. Reject genuine defects; never force approval.'
    # Actual model input is separately retained and reconstructed; base request
    # bytes/focus binding remain unchanged for normal deterministic validators.
    task['metadata_task_binding']=canonical_hash(task)
    review._canonical(task,650_000)
    epochs.save(sidecar,task,write)
    return task


def authority_member(tail):
    if not tail.startswith(PREFIX+'/'): return False
    relative=tail[len(PREFIX)+1:]
    return relative in FIXED_FILES or bool(re.fullmatch(r'focus-[a-f0-9]{24}/(?:'+'|'.join(re.escape(n) for n in FOCUS_FILES)+')',relative))


def model_fence(job,snapshot,epoch):
    root=job/'prototype-pipeline'
    target=epochs.read(root/epoch['plan']['repair_focus_id']/'mapper-target.json')
    packet,plan=epochs.reconstruct(job,snapshot,(job/'source-snapshot.json').read_bytes(),target)
    record,projections,history=validate_authorization(root,epoch,packet,plan,target)
    projected={row['focus_id'] for row in projections}
    previous=[];incomplete=False
    from . import prototype_context_screen_epoch as screen
    for index,request in enumerate(plan['requests']):
        fid=request['focus_id']
        if index<len(history) and fid not in projected:
            if incomplete: _fail()
            previous.append(history[index]);continue
        directory=root/(PREFIX if fid in projected else screen.PREFIX)/fid
        for name in ('reviewer',) if fid in projected else ('mapper','reviewer'):
            paths=[directory/(name+suffix) for suffix in ('-request.json','-target.json','-intent.json','.json')]
            exists=[p.exists() or p.is_symlink() for p in paths]
            if incomplete and any(exists): _fail()
            if not exists[2] and not exists[3]:
                if any(exists):
                    if not exists[0]: _fail()
                    payload=request if name=='mapper' else active_focus(root,packet,plan,request,target,previous,epoch,preview=True)['review_request']
                    epochs.same(epochs.read(paths[0]),payload)
                    if exists[1]: epochs.same(epochs.read(paths[1]),target)
                incomplete=True;continue
            if not all(exists): _fail()
            if name=='mapper':
                epochs.same(epochs.read(paths[0]),request)
                epochs._role(directory,name,request,target,{'job_id':job.name,'source_hash':plan['source_binding']})
                active_focus(root,packet,plan,request,target,previous,epoch,preview=True)
        if not incomplete:
            view=active_focus(root,packet,plan,request,target,previous,epoch)
            previous.append(view)
            if not view['checked']['approved_structured_design']: incomplete=True
    return {row['focus_id'] for row in plan['requests']}


def validate_publication(job,epoch):
    """Fixed revision; the original negative publication/history stay untouched."""
    from .prototype_result_publication import _raw, _binding
    root=job/'prototype-pipeline'
    target=epochs.read(root/epoch['plan']['repair_focus_id']/'mapper-target.json')
    packet,plan=epochs.reconstruct(job,epochs.read(job/'source-snapshot.json'),(job/'source-snapshot.json').read_bytes(),target)
    record,_,_=validate_authorization(root,epoch,packet,plan,target,full_job=True)
    pin=record['plan']['previous_result']
    previous=job/RESULT_BASE/'previous-result.json'
    if hashlib.sha256(_raw(previous)).hexdigest()!=pin['raw_sha256'] or canonical_hash(epochs.read(previous))!=pin['canonical_sha256']:
        _fail()
    latest=_raw(job/'prototype-result.json');path=job/RESULT_BASE/'publication.json'
    expected_history={name for name in record['before_files'] if name.startswith('prototype-results/')}
    if not path.exists() and not path.is_symlink():
        if hashlib.sha256(latest).hexdigest()!=pin['raw_sha256']: _fail()
        if {p.relative_to(job).as_posix() for p in (job/'prototype-results').iterdir()}!=expected_history: _fail()
        return None
    expected=_binding(job,epoch,epochs.read(job/'prototype-result.json'))
    epochs.same(epochs.read(path),expected)
    if _raw(job/expected['history_path'])!=latest: _fail()
    if {p.relative_to(job).as_posix() for p in (job/'prototype-results').iterdir()}!=expected_history|{expected['history_path']}: _fail()
    return expected
