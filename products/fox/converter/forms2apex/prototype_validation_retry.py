"""One owner-authorized retry of a definitive failed connectionless validation.

Original failed files are immutable. Only this exact second attempt can become
the effective validation receipt; uncertain attempts never fall back or replay.
"""
import hashlib
import io
from pathlib import Path
import tempfile
import zipfile

from .project_reviews import digest, read_object, publish
from .provenance import file_digest, tree_digest

PREFIX = 'validation-attempt-000002'
INTENT = PREFIX + '/intent.json'
RECEIPT = PREFIX + '/receipt.json'
LOG = PREFIX + '/validation.log'
SCOPE = 'fox-prototype-validation-retry-v1'
WITNESS_SCOPE = 'fox-prototype-failed-validation-v1'
FILES = {PREFIX, INTENT, RECEIPT, LOG, 'validate-request.json', 'validate-intent.json', 'validation.log'}


def need(value):
    if not value: raise RuntimeError('PROTOTYPE_VALIDATION_RETRY_LINEAGE_INVALID_NO_REPLAY')


def failed(receipt, request):
    need(type(receipt) is dict and receipt.get('status') == 'FAILED' and receipt.get('passed') is False
        and receipt.get('stage') == 'validate' and receipt.get('request_sha256') == digest(request)
        and receipt.get('source_binding') == request['source_binding'] and receipt.get('plan_sha256') == request['plan_sha256']
        and receipt.get('business_behavior_accepted') is False)
    result = receipt.get('validation')
    need(type(result) is dict and result.get('passed') is False and type(result.get('return_code')) is int
         and result['return_code'] != 0)


def effective(read, exists, stage, request):
    """Shared pure selector for gateway, package reader and runtime JobIO."""
    original = read(stage + '.json', True)
    if stage != 'validate' or not (exists(PREFIX) or exists(INTENT) or exists(RECEIPT) or exists(LOG)):
        return original
    need(exists(INTENT) and exists(RECEIPT))
    intent, receipt = read(INTENT, True), read(RECEIPT, True)
    witness = intent['witness']
    failed(original, request)
    need(intent.get('scope') == SCOPE and type(intent.get('attempt')) is int and intent['attempt'] == 2
         and intent.get('request_sha256') == digest(request) and witness.get('scope') == WITNESS_SCOPE
         and witness.get('request_sha256') == digest(request) and witness.get('rendered_zip_sha256') == request['rendered_zip_sha256']
         and witness.get('failed_receipt_sha256') == digest(original)
         and witness.get('failed_log_sha256') == hashlib.sha256(read('validation.log', False)).hexdigest()
         and read('validate-request.json', True) == request
         and read('validate-intent.json', True) == {'request_sha256':digest(request)}
         and intent.get('witness_sha256') == digest(witness))
    lineage = {'attempt':2,'failed_receipt_sha256':digest(original),
               'witness_sha256':digest(witness),'owner_record_sha256':intent['owner_record_sha256']}
    need(receipt.get('validation_attempt') == lineage and receipt.get('request_sha256') == digest(request)
         and receipt.get('source_binding') == request['source_binding'] and receipt.get('plan_sha256') == request['plan_sha256']
         and receipt.get('stage') == 'validate' and receipt.get('business_behavior_accepted') is False)
    result = receipt.get('validation')
    need(type(result) is dict and type(result.get('return_code')) is int
         and receipt.get('status') in ('COMPLETE','FAILED')
         and receipt.get('passed') is (receipt['status']=='COMPLETE')
         and result.get('passed') is receipt['passed']
         and (result['return_code']==0) is receipt['passed']
         and receipt.get('validation_log_sha256') == hashlib.sha256(read(LOG,False)).hexdigest())
    return receipt


def local_effective(root, stage, request):
    def read(name, json):
        path = root / name
        need(not path.is_symlink() and path.is_file() and path.stat().st_size <= 20_000_000)
        return read_object(path) if json else path.read_bytes()
    return effective(read, lambda name:(root/name).exists() or (root/name).is_symlink(), stage, request)


def witness(gateway, job_id):
    root = gateway._root({'job_id':job_id},create=False)
    request = read_object(root/'validate-request.json')
    spec, raw = gateway._request_inputs('validate',request)
    gateway._snapshot(root,request,spec,raw,create=False)
    original = read_object(root/'validate.json')
    failed(original,request)
    need(read_object(root/'validate-intent.json') == {'request_sha256':digest(request)})
    initial = {'authority-manifest.json','candidate-apexlang.zip','snapshot.json','validate.json',
               'validate-intent.json','validate-request.json','validation.log',PREFIX}
    if not (root/PREFIX).exists():
        need(all(p.name in initial for p in root.iterdir()))
    else:
        local_effective(root,'validate',request)  # partial/orphan attempts are not eligible witnesses
    manifest = gateway.recover_source_authority(job_id)
    need(manifest is not None)
    from .runtime_preflight import bound_target_profile
    from .prototype_authority_client import execution_target
    profile = gateway.target_profile_loader(gateway.settings) if gateway.target_profile_loader else bound_target_profile(gateway.settings)
    return {'schema_version':1,'scope':WITNESS_SCOPE,'attempt':2,'job_id':job_id,
        'request_sha256':digest(request),'source_binding':request['source_binding'],
        'plan_sha256':request['plan_sha256'],'rendered_zip_sha256':request['rendered_zip_sha256'],
        'failed_receipt_sha256':digest(original),'failed_log_sha256':file_digest(root/'validation.log'),
        'execution_target_sha256':digest(execution_target(profile)),
        'manifest_sha256':manifest['manifest_sha256'],'connection_mode':'/nolog','source_review_authorized':False}


def retry(gateway, request, expected_witness, owner_record_sha256):
    # Caller holds gateway's stage lock. This method never touches DB helpers.
    spec, raw = gateway._request('validate',request)
    root = gateway._root(request,create=False)
    need(not (root/PREFIX).exists() and witness(gateway,request['job_id']) == expected_witness)
    callback = getattr(gateway.authorize,'authorize_validation_retry',None)
    need(callable(callback) and callback(request,owner_record_sha256) == request)
    attempt = root/PREFIX
    attempt.mkdir()  # exclusive second-attempt claim; never delete or overwrite
    from .review_receipts import _sync_directory
    _sync_directory(root)
    intent = {'schema_version':1,'scope':SCOPE,'attempt':2,'request_sha256':digest(request),
        'witness':expected_witness,'witness_sha256':digest(expected_witness),'owner_record_sha256':owner_record_sha256}
    publish(root/INTENT,intent)
    with tempfile.TemporaryDirectory(prefix='.p-') as temporary:
        app = Path(temporary)/'apexlang'
        app.mkdir()
        with zipfile.ZipFile(io.BytesIO(raw)) as archive: archive.extractall(app)
        before = tree_digest(app)
        result = gateway.validator(gateway.settings.sqlcl_path,app,root/LOG)
        need(tree_digest(app)==before)
        gateway._authorize(request)
        need(callback(request,owner_record_sha256)==request)
        gateway._snapshot(root,request,spec,raw,create=False)
    passed = result.get('passed') is True and result.get('return_code') == 0
    receipt = gateway._receipt('validate',request,'COMPLETE' if passed else 'FAILED',passed=passed,
        validation=result,draft_sha256=before,artifact_binding=read_object(root/'snapshot.json'),
        validation_attempt={'attempt':2,'failed_receipt_sha256':expected_witness['failed_receipt_sha256'],
            'witness_sha256':digest(expected_witness),'owner_record_sha256':owner_record_sha256},
        validation_log_sha256=file_digest(root/LOG))
    publish(root/RECEIPT,receipt)
    return local_effective(root,'validate',request)
