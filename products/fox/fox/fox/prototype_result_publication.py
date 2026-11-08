"""One checked epoch-four result publication; interrupted writes are not retries."""
import hashlib
import json
import os
from pathlib import Path
import tempfile

from . import prototype_mapping_epochs as epochs
from .opaf import OpafError, canonical_hash


def _fail():
    raise OpafError('Epoch result publication is missing, changed or interrupted; reconcile without replay.') from None


def _raw(path):
    epochs._safe_path(path.parent, path.name)
    epochs.read(path)
    if path.stat().st_nlink != 1:
        _fail()
    return path.read_bytes()


def previous_result(job, before, rejected_focus, source_binding):
    raw = _raw(job / 'prototype-result.json')
    value = epochs.read(job / 'prototype-result.json')
    digest = hashlib.sha256(raw).hexdigest()
    canonical = canonical_hash(value)
    history = 'prototype-results/' + canonical + '.json'
    history_raw = _raw(job / history)
    if (before.get('prototype-result.json') != digest
            or before.get(history) != hashlib.sha256(history_raw).hexdigest()
            or canonical_hash(epochs.read(job / history)) != canonical
            or value.get('schema_version') != 1 or value.get('scope') != 'fox-prototype-pipeline-v1'
            or value.get('job_id') != job.name or value.get('status') != 'CHANGES_REQUIRED'
            or value.get('source_binding') != source_binding
            or value.get('stage') != 'reviewing' or value.get('blocked_focus_id') != rejected_focus
            or value.get('facts', {}).get('business_behavior_accepted') is not False):
        _fail()
    return {'raw_sha256': digest, 'canonical_sha256': canonical, 'history_path': history,
            'history_raw_sha256': hashlib.sha256(history_raw).hexdigest()}


def preserve_previous(job, record):
    RESULT_BASE = _result_module(record).RESULT_BASE
    root = epochs._safe_path(job, RESULT_BASE)
    root.mkdir(parents=True, exist_ok=False)
    from .prototype_pipeline import _save_bytes_once
    raw = _raw(job / 'prototype-result.json')
    if hashlib.sha256(raw).hexdigest() != record['plan']['previous_result']['raw_sha256']:
        _fail()
    _save_bytes_once(root / 'previous-result.json', raw)


def _binding(job, record, result):
    from .prototype_read_scope import epoch_read_scope
    with epoch_read_scope(job / 'prototype-pipeline'):
        return _reconstruct_binding(job, record, result)


def _result_module(record):
    from . import prototype_container_epoch as container, prototype_partition_review_epoch as partition
    from . import prototype_context_screen_epoch as screen
    if type(record['epoch_number']) is int and record['epoch_number'] == container.NUMBER:
        return container
    if type(record['epoch_number']) is int and record['epoch_number'] == partition.NUMBER:
        return partition
    if type(record['epoch_number']) is int and record['epoch_number'] == screen.NUMBER:
        return screen
    _fail()


def _reconstruct_binding(job, record, result, *, historical_four=False, historical_dsc=False):
    from .prototype_pipeline import _artifact_json, _check_converter_receipt, CONVERTER_STAGES
    root = job / 'prototype-pipeline'
    # Exact reconstruction, not acceptance of a self-hashed caller dictionary.
    packet, plan = epochs.reconstruct(job, epochs.read(job / 'source-snapshot.json'),
        (job / 'source-snapshot.json').read_bytes(),
        epochs.read(root / record['plan']['repair_focus_id'] / 'mapper-target.json'))
    target = epochs.read(root / plan['requests'][0]['focus_id'] / 'mapper-target.json')
    facts = {name: False for name in ('native_source_rendered', 'sqlcl_validated', 'schema_prepared',
        'import_verified', 'runtime_verified', 'native_apex_generated', 'package_reimport_passed',
        'clean_schema_install_passed', 'technically_verified', 'business_behavior_accepted', 'download_ready')}
    expected = {'schema_version': 1, 'scope': 'fox-prototype-pipeline-v1', 'job_id': job.name,
        'source_binding': packet['source_binding'], 'status': 'RUNNING', 'stage': 'mapping', 'facts': facts,
        'assessment': epochs.read(root / 'assessment.json'), 'artifacts': {'checkpoint_directory': str(root)}}
    expected['mapping_epoch_sha256'] = canonical_hash(record)
    from . import prototype_dsc_identity_repair as dsc
    active_dsc=(record['epoch_number']==6 and dsc.present(root)
        and not historical_dsc and not historical_four)
    if active_dsc: expected['dsc_identity_repair_sha256']=canonical_hash(epochs.read(root/dsc.RECORD))
    views = []
    proof_files = {}
    for request in plan['requests']:
        if historical_dsc:
            view=dsc.historical_focus(root,packet,plan,request,target,views,record)
        elif historical_four:
            # Explicit fixed predecessor, deliberately bypassing current-head
            # active-view caches. No HTTP selector or path can request this.
            from .prototype_container_epoch import _historical_active_focus
            view = _historical_active_focus(root, packet, plan, request, target, views, record)
        else:
            view = epochs.active_focus(root, packet, plan, request, target, views)
        views.append(view)
        if not view['checked']['approved_structured_design']:
            expected.update(status='CHANGES_REQUIRED', stage='reviewing', blocked_focus_id=request['focus_id'])
            break
    else:
        if historical_four:
            _fail()  # Only the sealed focus8 pre-DB rejection can precede5.
        from .prototype_pipeline import authorize_prototype_request, _review_index
        native, rendered = _artifact_json(root / 'native-plan.json'), _artifact_json(root / 'rendered.json')
        epochs.same(epochs.read(root / 'review-index.json'), _review_index(root, plan))
        expected.update(stage='render', plan_sha256=native['plan_sha256'], review_count=len(views), coverage=native['coverage'])
        archive = root / 'candidate-apexlang.zip'
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if digest != rendered['zip_sha256']:
            _fail()
        expected['artifacts'].update(native_plan=str(root / 'native-plan.json'),
            merged_blueprint=str(root / 'merged-blueprint.json'), candidate_apexlang=str(archive),
            candidate_apexlang_sha256=digest)
        facts['native_source_rendered'] = True
        authority = {'schema_version': 1, 'scope': 'fox-prototype-source-authority-v1',
            'binding_sha256': canonical_hash(epochs.read(root / 'binding.json')),
            'sources_manifest_sha256': canonical_hash(epochs.read(root / 'sources-manifest.json')),
            'review_index_sha256': canonical_hash(epochs.read(root / 'review-index.json'))}
        prior = {}
        for stage in CONVERTER_STAGES:
            request = {'schema_version': 1, 'scope': 'fox-prototype-converter-request-v1', 'job_id': job.name,
                'project_id': record['project_id'], 'source_binding': record['source_binding'],
                'plan_sha256': native['plan_sha256'], 'rendering_spec': native['rendering_spec'],
                'rendered_zip_sha256': digest, 'source_authority': authority, 'prior_receipts': dict(prior)}
            epochs.same(epochs.read(root / (stage + '-intent.json')), {'request_sha256': canonical_hash(request)})
            prior[stage] = _check_converter_receipt(stage, request, epochs.read(root / (stage + '.json')))
            if prior[stage].get('status') != 'COMPLETE' or prior[stage].get('business_behavior_accepted') is not False:
                _fail()
            proof_files[stage + '.json'] = hashlib.sha256((root / (stage + '.json')).read_bytes()).hexdigest()
            facts[{'validate': 'sqlcl_validated', 'prepare_schema': 'schema_prepared', 'import': 'import_verified',
                'verify_runtime': 'runtime_verified', 'export': 'native_apex_generated'}[stage]] = True
        authorize_prototype_request(job, request)
        expected.update(status='APEX_GENERATED', stage='complete', converter_receipts=prior,
            reason='APEX generated; exact-package reimport and clean-schema installation proof remain pending.')
    epochs.same(result, expected)
    proof_key = ('screen_projection_sha256' if record['epoch_number'] == 6 else
        'partition_proof_sha256' if record['epoch_number'] == 5 else 'container_proof_sha256')
    binding = {'schema_version': 1, 'scope': 'fox-prototype-epoch-result-publication-v1',
        'job_id': job.name, 'project_id': record['project_id'], 'source_hash': record['source_hash'],
        'source_binding': record['source_binding'], 'epoch_sha256': canonical_hash(record),
        proof_key: record[proof_key], 'result_sha256': canonical_hash(expected),
        'history_path': 'prototype-results/' + canonical_hash(expected) + '.json',
        'status': expected['status'], 'stage': expected['stage'],
        'active_proofs_sha256': canonical_hash([view['proof'] for view in views]),
        'stage_files': proof_files, 'previous_result': record['plan']['previous_result']}
    if active_dsc:
        binding['dsc_identity_repair_sha256']=expected['dsc_identity_repair_sha256']
        binding['previous_result']=epochs.read(root/dsc.RECORD)['plan']['previous_result']
    return binding


def validate_publication(job, record):
    from .prototype_read_scope import epoch_read_scope
    with epoch_read_scope(job / 'prototype-pipeline'):
        return _validate_publication(job, record)


def _validate_publication(job, record):
    from . import prototype_dsc_identity_repair as dsc
    if record['epoch_number']==6 and dsc.present(job/'prototype-pipeline'):
        return dsc.validate_publication(job,record)
    RESULT_BASE = _result_module(record).RESULT_BASE
    pin = _validate_previous(job, record)
    latest = _raw(job / 'prototype-result.json')
    publication = job / RESULT_BASE / 'publication.json'
    if not publication.exists() and not publication.is_symlink():
        if hashlib.sha256(latest).hexdigest() != pin['raw_sha256']:
            _fail()
        # A new immutable result without its binding is interrupted publication.
        history = job / 'prototype-results'
        expected = {name for name in record['before_files'] if name.startswith('prototype-results/')}
        actual = {path.relative_to(job).as_posix() for path in history.iterdir()}
        if actual != expected:
            _fail()
        return None
    binding = epochs.read(publication)
    value = epochs.read(job / 'prototype-result.json')
    expected = _binding(job, record, value)
    epochs.same(binding, expected)
    history = epochs._safe_path(job, expected['history_path'])
    if _raw(history) != latest:
        _fail()
    expected_history = {name for name in record['before_files'] if name.startswith('prototype-results/')} | {expected['history_path']}
    if {path.relative_to(job).as_posix() for path in (job / 'prototype-results').iterdir()} != expected_history:
        _fail()
    return binding


def _validate_previous(job, record):
    RESULT_BASE = _result_module(record).RESULT_BASE
    pin = record['plan']['previous_result']
    if type(pin) is not dict or set(pin) != {'raw_sha256', 'canonical_sha256', 'history_path', 'history_raw_sha256'}:
        _fail()
    epochs._descriptor('pin', pin['raw_sha256'])
    epochs._descriptor('pin', pin['canonical_sha256'])
    if pin['history_path'] != 'prototype-results/' + pin['canonical_sha256'] + '.json':
        _fail()
    archive = epochs._safe_path(job, RESULT_BASE + '/previous-result.json')
    old = epochs.read(archive)
    if (old.get('schema_version') != 1 or old.get('scope') != 'fox-prototype-pipeline-v1'
            or old.get('job_id') != job.name or old.get('source_binding') != record['source_binding']
            or old.get('status') != 'CHANGES_REQUIRED' or old.get('stage') != 'reviewing'
            or old.get('blocked_focus_id') != record['plan']['projection_focus_id']):
        _fail()
    if (hashlib.sha256(_raw(archive)).hexdigest() != pin['raw_sha256']
            or canonical_hash(epochs.read(archive)) != pin['canonical_sha256']
            or record['before_files'].get('prototype-result.json') != pin['raw_sha256']
            or record['before_files'].get(pin['history_path']) != pin['history_raw_sha256']
            or hashlib.sha256(_raw(job / pin['history_path'])).hexdigest() != pin['history_raw_sha256']
            or canonical_hash(epochs.read(job / pin['history_path'])) != pin['canonical_sha256']):
        _fail()
    return pin


def _validate_historical_four_publication(job, record):
    """Private immutable pre-DB head4 reader; NEVER reads mutable latest as4."""
    from . import prototype_container_epoch as container
    if record['epoch_number'] != container.NUMBER:
        _fail()
    _validate_previous(job, record)
    binding = epochs.read(epochs._safe_path(job, container.RESULT_BASE + '/publication.json'))
    epochs._descriptor('pin', binding['result_sha256'])
    if binding['history_path'] != 'prototype-results/' + binding['result_sha256'] + '.json':
        _fail()
    history = epochs._safe_path(job, binding['history_path'])
    value = epochs.read(history)
    _raw(history)
    if (value.get('status') != 'CHANGES_REQUIRED' or value.get('stage') != 'reviewing'
            or value.get('blocked_focus_id') != record['plan']['projection_focus_id']
            or value.get('mapping_epoch_sha256') != canonical_hash(record)):
        _fail()
    epochs.same(binding, _reconstruct_binding(job, record, value, historical_four=True))
    return binding


def controlled_save_result(job, result, record):
    """Validate -> history -> binding -> atomic latest; any crash fails closed."""
    RESULT_BASE = _result_module(record).RESULT_BASE
    from . import prototype_dsc_identity_repair as dsc
    if record['epoch_number']==6 and dsc.present(job/'prototype-pipeline'): RESULT_BASE=dsc.RESULT_BASE
    from .native_pipeline import _save_once, _sync
    if validate_publication(job, record) is not None:
        _fail()  # A publication is never a permit to rerun this epoch.
    binding = _binding(job, record, result)
    # No operation/model stage can be uncertain when publishing a terminal result.
    epochs._model_fence(job, epochs.read(job / 'source-snapshot.json'), record)
    epochs._closure(job, record=record)
    history = epochs._safe_path(job, binding['history_path'])
    _save_once(history, result)
    epochs.save(job / RESULT_BASE / 'publication.json', binding, True)
    fd, name = tempfile.mkstemp(prefix='.prototype-result-', dir=job)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(history.read_bytes())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, job / 'prototype-result.json')
        _sync(job)
    finally:
        temporary.unlink(missing_ok=True)
    validate_publication(job, record)
