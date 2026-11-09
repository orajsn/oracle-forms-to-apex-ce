"""One explicit continuation of a saved draft proven unclaimed at the receiver.

No missing file, caller flag, witness or consent record alone grants execution.
Original model/source/reviewer authority is always reconstructed independently.
"""
from copy import deepcopy
import hashlib
import math
from pathlib import Path
import re

from .native_pipeline import _json
from .opaf import OpafError, canonical_hash

SCOPE = 'fox-prototype-validate-preclaim-continuation-v1'
RECORD = 'validate-preclaim-continuation.json'
ATTEMPT = 'validate-preclaim-attempt.json'
EVENT = 'approved_prototype_validate_preclaim_continuation'
WITNESS_SCOPE = 'fox-prototype-validate-preclaim-witness-v1'


def present(root):
    path = Path(root) / RECORD
    return path.exists() or path.is_symlink()


def event_id(rid, record):
    return rid + ':validate-preclaim:000001:' + canonical_hash(record)


def _fail():
    raise OpafError('The exact saved validation checkpoint or continuation authority changed; no replay.')


def request_for(job, snapshot):
    """Reconstruct the original first-stage request, never client material."""
    from .prototype_pipeline import _artifact_json
    root = Path(job) / 'prototype-pipeline'
    native, rendered = (_artifact_json(root / name) for name in ('native-plan.json', 'rendered.json'))
    binding, manifest, index = (_json(root / name) for name in ('binding.json', 'sources-manifest.json', 'review-index.json'))
    request = {'schema_version': 1, 'scope': 'fox-prototype-converter-request-v1',
        'job_id': Path(job).name, 'project_id': snapshot['project_id'],
        'source_binding': snapshot['prototype']['source_binding'], 'plan_sha256': native['plan_sha256'],
        'rendering_spec': native['rendering_spec'], 'rendered_zip_sha256': rendered['zip_sha256'],
        'source_authority': {'schema_version': 1, 'scope': 'fox-prototype-source-authority-v1',
            'binding_sha256': canonical_hash(binding), 'sources_manifest_sha256': canonical_hash(manifest),
            'review_index_sha256': canonical_hash(index)}, 'prior_receipts': {}}
    if _json(root / 'validate-intent.json') != {'request_sha256': canonical_hash(request)}:
        _fail()
    return request


def check_witness(request, witness, manifest_sha256, target):
    from .prototype_authority import execution_target
    keys = {'schema_version', 'scope', 'job_id', 'project_id', 'request_sha256', 'source_binding',
        'source_authority', 'manifest_sha256', 'rendered_zip_sha256', 'execution_target_sha256',
        'receiver_sha256', 'source_review_authorized', 'witness_sha256'}
    if (type(witness) is not dict or set(witness) != keys or type(witness['schema_version']) is not int
            or witness['schema_version'] != 1 or witness['scope'] != WITNESS_SCOPE
            or witness['job_id'] != request['job_id'] or witness['project_id'] != request['project_id']
            or witness['request_sha256'] != canonical_hash(request)
            or witness['source_binding'] != request['source_binding']
            or witness['source_authority'] != request['source_authority']
            or witness['manifest_sha256'] != manifest_sha256
            or witness['rendered_zip_sha256'] != request['rendered_zip_sha256']
            or witness['execution_target_sha256'] != canonical_hash(execution_target(target))
            or witness['source_review_authorized'] is not False
            or type(witness['receiver_sha256']) is not str or not re.fullmatch('[a-f0-9]{64}', witness['receiver_sha256'])
            or witness['witness_sha256'] != canonical_hash({k:v for k,v in witness.items() if k != 'witness_sha256'})):
        _fail()
    return witness


def checkpoint(before, request, witness):
    return canonical_hash({'scope': SCOPE, 'before_files': before, 'request': request, 'witness': witness})


def validate_record(job, snapshot, original, connection):
    """Durable owner event and original bytes; not current-owner permission."""
    from . import prototype_mapping_epochs as epochs
    job = Path(job); root = job / 'prototype-pipeline'
    record = epochs.read(root / RECORD)
    keys = {'schema_version', 'scope', 'job_id', 'project_id', 'snapshot_sha256', 'source_hash',
        'source_binding', 'target_profile_sha256', 'owner', 'approved_at', 'approvals', 'before_files',
        'request', 'witness', 'checkpoint_sha256'}
    if (type(record) is not dict or set(record) != keys or type(record['schema_version']) is not int
            or record['schema_version'] != 1 or record['scope'] != SCOPE or record['job_id'] != job.name
            or record['project_id'] != snapshot['project_id'] or record['owner'] != snapshot['approvals']['owner']
            or record['snapshot_sha256'] != hashlib.sha256(original).hexdigest()
            or record['source_hash'] != snapshot['source_hash']
            or record['source_binding'] != snapshot['prototype']['source_binding']
            or record['target_profile_sha256'] != snapshot['prototype']['target_profile_sha256']
            or type(record['approved_at']) not in (int,float) or not math.isfinite(record['approved_at'])
            or record['approved_at'] <= 0 or type(record['approvals']) is not dict
            or set(record['approvals']) != {'redacted_source','external_ai','synthetic_prototype'}
            or any(v is not True for v in record['approvals'].values())):
        _fail()
    before = record['before_files']
    for name, digest in epochs._descriptors(before):
        path = epochs._safe_path(job, name)
        if name == 'prototype-result.json' and path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            # The normal result writer preserves the original terminal summary
            # in its immutable content-addressed history before replacing it.
            retained = [p for p in (job/'prototype-results').glob('*.json')
                        if p.is_file() and not p.is_symlink() and hashlib.sha256(p.read_bytes()).hexdigest() == digest]
            if len(retained) != 1: _fail()
        elif not path.is_file() or path.stat().st_size > 20_000_000 or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            _fail()
    if record['request'] != request_for(job,snapshot) or record['checkpoint_sha256'] != checkpoint(before,record['request'],record['witness']):
        _fail()
    staging = epochs.read(job/'prototype-transport/authority.json')
    target = epochs.read(root / _json(root/'review-index.json')['focuses'][0]['focus_id'] / 'mapper-target.json')
    if canonical_hash(target) != record['target_profile_sha256']: _fail()
    check_witness(record['request'],record['witness'],staging['manifest_sha256'],target)
    rows = connection.execute('SELECT owner,object_id,created FROM events WHERE action=? AND (object_id=? OR object_id LIKE ?)',
        (EVENT,job.name,job.name+':%')).fetchall()
    if [tuple(row) for row in rows] != [(record['owner'],event_id(job.name,record),record['approved_at'])]: _fail()
    attempt = root / ATTEMPT
    if attempt.exists() or attempt.is_symlink():
        if epochs.read(attempt) != {'record_sha256':canonical_hash(record),'request_sha256':canonical_hash(record['request']),
                'witness_sha256':record['witness']['witness_sha256']}: _fail()
    return record


def entry_phase(job,snapshot,original,connection,phase=None):
    from . import prototype_mapping_epochs as epochs
    from .prototype_pipeline import CONVERTER_STAGES
    root = Path(job)/'prototype-pipeline'
    if not present(root):
        if (root/ATTEMPT).exists() or (root/ATTEMPT).is_symlink(): _fail()
        if connection.execute('SELECT 1 FROM events WHERE action=? AND (object_id=? OR object_id LIKE ?)',
                (EVENT,Path(job).name,Path(job).name+':%')).fetchone(): _fail()
        return phase
    record = validate_record(job,snapshot,original,connection)
    if phase is None:
        pending=[stage for stage in CONVERTER_STAGES if (root/(stage+'-intent.json')).exists()
                 and not (root/(stage+'.json')).exists()]
        if len(pending)>1: _fail()
        if pending:
            stage=pending[0]
            request={**record['request'],'prior_receipts':{previous:epochs.read(root/(previous+'.json'))
                for previous in CONVERTER_STAGES[:CONVERTER_STAGES.index(stage)]}}
            return epochs.preclaim_phase(job,snapshot,original,request,stage=stage)
        epochs._closure(Path(job),record=epochs.technical_record(root))
    return phase


def inspect(job,snapshot,original,target,connection):
    """Pure technical plan, leaving networking/current-owner checks to routes."""
    from . import prototype_mapping_epochs as epochs
    from .prototype_mapping_continuation import validate_job_continuation
    from .prototype_pipeline import authorize_prototype_request
    from .prototype_read_scope import epoch_read_scope
    job = Path(job); root = job/'prototype-pipeline'
    with epoch_read_scope(root):
        if canonical_hash(target) != snapshot['prototype']['target_profile_sha256']: _fail()
        request = request_for(job,snapshot)
        authorize_prototype_request(job,request)
        child = validate_record(job,snapshot,original,connection) if present(root) else None
        phase = (epochs.preclaim_phase(job,snapshot,original,request)
                 if child is None or not (root/'validate.json').exists() else None)
        validate_job_continuation(job,snapshot,original,phase=phase)
        if child is None:
            if any((root/(stage+suffix)).exists() or (root/(stage+suffix)).is_symlink()
                   for stage in ('validate','prepare_schema','import','verify_runtime','export')
                   for suffix in ('.json','-intent.json') if (stage,suffix) != ('validate','-intent.json')): _fail()
            before = epochs._closure(job,phase=phase,record=epochs.technical_record(root))
        else:
            before = child['before_files']
        staging = epochs.read(job/'prototype-transport/authority.json')
        if (staging.get('staged') is not True or staging.get('source_review_authorized') is not False
                or staging.get('source_binding') != request['source_binding']
                or staging.get('source_authority') != request['source_authority']): _fail()
        return request,before,child,staging


def retained_views(root,packet,plan,target):
    """All closed model operations are pure; never retry a missing role."""
    from .prototype_mapping_epochs import active_focus
    from .prototype_read_scope import epoch_read_scope
    with epoch_read_scope(root):
        views=[]
        for request in plan['requests']:
            view=active_focus(root,packet,plan,request,target,views,runtime=None)
            if not view['checked']['approved_structured_design']: _fail()
            views.append(view)
        index = _json(Path(root)/'review-index.json')
        if index.get('schema_version') in (2,3):
            if canonical_hash([v['proof'] for v in views]) != canonical_hash(index['focuses']): _fail()
        else:
            from .prototype_pipeline import _review_index
            if _review_index(Path(root),plan) != index: _fail()
        return views
