"""Checkpointed native orchestration; AI supplies metadata, never import commands.

One worker owns each job. Completed role outputs are immutable and reused on
resume. Uncertain inference/import calls are retained for operator review,
never blindly replayed. This module does not certify customer business logic.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import tempfile
import zipfile
from pathlib import Path
from datetime import datetime,timezone

from .native_source import assess_native_source, PROFILE_ID
from .opaf import (ConverterClient, OpafClient, OpafError, canonical_hash,
                   load_native_profile, stage_job, validate_model_environment)

TEMPLATE_ID = 'sqlcl-26.1.2-fox-native-v1'
CANDIDATE_FIELDS = {'job_id', 'template_id', 'data_classification', 'generator',
                    'native_form', 'remediation_items', 'mapping_summary'}
# Historical snapshots accepted without a job-local gateway-approved cache.
# This records a tested configuration, not a signature or authorization to use
# that target today. Keep registered historical hashes when active config moves.
HISTORICAL_TARGET_PROFILE_HASHES = frozenset({
    '7c7b73d43febc9befb1d43e47449a02cc7894b879dd4bc32904cec538e5f95e6',
    '7170d60927b7e5b7aed5d56174f97efbeff3052be247b244911deff768701ed3',
})


def _json(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2_000_000:
        raise OpafError('Native checkpoint is missing, oversized or unsafe.')
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
    except (ValueError, OSError):
        raise OpafError('Native checkpoint is unreadable; retained for review.') from None
    if not isinstance(value, dict):
        raise OpafError('Native checkpoint must be an object.')
    return value


def _sync(directory):
    if os.name != 'nt':
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _save_once(path, value):
    """Atomic, create-only JSON; identical retry is safe, replacement is not."""
    if path.exists() or path.is_symlink():
        if _json(path) != value:
            raise OpafError('Native checkpoint differs; existing evidence preserved.')
        return
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False).encode()
    if len(raw) > 2_000_000:
        raise OpafError('Native checkpoint exceeds the configured bound.')
    fd, name = tempfile.mkstemp(prefix='.checkpoint-', dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if _json(path) != value:
                raise OpafError('Concurrent native checkpoint differs; no overwrite.') from None
        _sync(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _progress(job,stage):
    """Operator-safe UI progress only; never provider text or submitted source."""
    if stage not in {'preparing','inspecting','mapping','reviewing','generating','validating','importing','reconciling','packaging','downloaded'}:
        raise ValueError('Unknown native progress stage')
    fd,name=tempfile.mkstemp(prefix='.progress-',dir=job)
    temporary=Path(name)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as handle:
            json.dump({'stage':stage,'updated_at_utc':datetime.now(timezone.utc).isoformat()},handle)
            handle.flush();os.fsync(handle.fileno())
        os.replace(temporary,job/'native-progress.json')
        _sync(job)
    finally:
        temporary.unlink(missing_ok=True)


def _candidate(value, job_id, native_form, model):
    if (not isinstance(value, dict) or set(value) != CANDIDATE_FIELDS
            or value['job_id'] != job_id or value['template_id'] != TEMPLATE_ID
            or value['data_classification'] != 'synthetic_or_stub_only'
            or value['generator'] != {'model': model}
            or value['native_form'] != native_form
            or not isinstance(value['remediation_items'], list)
            or not isinstance(value['mapping_summary'], str)
            or not value['mapping_summary'].strip()):
        raise OpafError('Mapper output does not match the approved native source contract.')
    if len(json.dumps(value).encode()) > 200_000:
        raise OpafError('Mapper output exceeds the native candidate bound.')
    return value


def _role(checkpoints, name, client, role, request, target_profile_loader=None):
    completed = checkpoints / (name + '.json')
    request_digest = canonical_hash(request)
    if completed.exists():
        saved = _json(completed)
        if (saved.get('request_sha256') != request_digest or saved.get('role') != role
                or saved.get('output_sha256') != canonical_hash(saved.get('output'))
                or saved.get('invocation', {}).get('request_sha256') != request_digest):
            raise OpafError('Native role checkpoint changed; no automatic replay.')
        if 'model_environment' in saved:
            target = _json(checkpoints / 'target-profile.json')['target_profile']
            if saved.get('model_environment_sha256') != canonical_hash(saved['model_environment']):
                raise OpafError('Native model environment checkpoint changed.')
            validate_model_environment(saved['model_environment'],target,name,request,saved['invocation'])
        return saved['output'], saved['invocation']
    pending = checkpoints / (name + '-intent.json')
    if pending.exists():
        raise OpafError('A prior model call has an uncertain result; operator reconciliation is required.')
    if target_profile_loader is None:
        raise OpafError('A new model invocation requires its current target profile.')
    target_profile = target_profile_loader()
    _save_once(pending, {'request_sha256': request_digest, 'role': role})
    output, invocation, environment = client.invoke_with_environment(
        role, request, role_name=name, target_profile=target_profile)
    validate_model_environment(environment,target_profile,name,request,invocation)
    _save_once(completed, {'request_sha256': request_digest, 'role': role,
                          'output': output, 'output_sha256': canonical_hash(output),
                          'invocation': invocation, 'model_environment':environment,
                          'model_environment_sha256':canonical_hash(environment)})
    return output, invocation


def _remote_identity(value, job_id, snapshot):
    if (value.get('job_id') != job_id
            or value.get('source_manifest_sha256') != snapshot['source_hash']
            or value.get('conversion_profile') != PROFILE_ID
            or value.get('native_form') != snapshot['native_form']):
        raise OpafError('Remote job identity differs from the approved source version.')
    return value


def _get_job(gateway, path):
    try:
        return gateway.request('GET', path)
    except OpafError as exc:
        if exc.status_code == 404:
            return None
        raise


def verify_package(raw, evidence, native_form, target_profile=None):
    """Validate exact download bytes without extracting or executing members."""
    if not isinstance(raw, bytes) or len(raw) > 8_000_000:
        raise OpafError('Native package exceeds the download bound.')
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            names = [entry.filename for entry in entries]
            if len(names) != len(set(names)) or len(names) > 500:
                raise OpafError('Invalid native package structure.')
            if sum(entry.file_size for entry in entries) > 20_000_000:
                raise OpafError('Native package exceeds the expanded bound.')
            for entry in entries:
                name = entry.filename
                if (not name or name.startswith('/') or '\\' in name or ':' in name
                        or any(part in {'', '.', '..'} for part in name.split('/'))
                        or entry.is_dir() or entry.flag_bits & 1
                        or stat.S_ISLNK(entry.external_attr >> 16)):
                    raise OpafError('Unsafe native package member.')
            manifest = json.loads(archive.read('manifest.json'))
            if not isinstance(manifest, dict) or set(names) != set(manifest) | {'manifest.json'}:
                raise OpafError('Native package manifest is incomplete.')
            for name, digest in manifest.items():
                if not isinstance(digest, str) or not re.fullmatch(r'[a-f0-9]{64}', digest) or hashlib.sha256(archive.read(name)).hexdigest() != digest:
                    raise OpafError('Native package integrity check failed.')
            if json.loads(archive.read('evidence/release-evidence.json')) != evidence:
                raise OpafError('Native packaged evidence differs from the release receipt.')
            if json.loads(archive.read('native-form-spec.json')) != native_form:
                raise OpafError('Native packaged schema differs from approved metadata.')
            if 'schema/01_synthetic_schema.sql' not in names or 'evidence/native-review.json' not in names:
                raise OpafError('Native package lacks schema or independent review evidence.')
            app_id = evidence.get('application_id')
            if type(app_id) is not int or app_id <= 0:
                raise OpafError('Native package has no explicit imported application identity.')
            expected_sql = 'sql/f' + str(app_id) + '.sql'
            if (expected_sql not in names or len(archive.read(expected_sql)) < 1000
                    or 'apexlang/application.apx' not in names
                    or 'evidence/export-completion.json' not in names
                    or 'evidence/export-validation.log' not in names):
                raise OpafError('Native package lacks the actual validated SQL/APEXlang export.')
            review = json.loads(archive.read('evidence/native-review.json'))
            if (not isinstance(review, dict) or type(review.get('schema_version')) is not int or review['schema_version'] not in (1,2)
                    or review.get('receipt_sha256') != evidence.get('review_receipt_sha256')
                    or canonical_hash({key: value for key, value in review.items() if key != 'receipt_sha256'}) != review.get('receipt_sha256')
                    or review.get('job_id') != evidence.get('job_id')
                    or review.get('source_hash') != evidence.get('source_manifest_sha256')
                    or review.get('candidate_sha256') != canonical_hash(review.get('candidate'))
                    or review.get('candidate', {}).get('native_form') != native_form
                    or review.get('review', {}).get('verdict') != 'approve'
                    or review.get('review', {}).get('candidate_sha256') != review.get('candidate_sha256')
                    or review.get('review', {}).get('blocking_findings') != []):
                raise OpafError('Native package reviewer evidence is unbound or changed.')
            if review['schema_version']==2:
                environments=review.get('model_environment')
                if not isinstance(environments,dict) or set(environments)!={'mapper','reviewer'}:
                    raise OpafError('Native v2 package requires its bound historical model environment.')
                historical=review.get('historical_target_profile')
                if not isinstance(historical,dict) or 'evidence/target-profile.json' not in names:
                    raise OpafError('Native v2 package lacks its sealed historical target profile.')
                canonical_profile=json.dumps(historical,sort_keys=True,separators=(',',':'),
                    ensure_ascii=False,allow_nan=False).encode('utf-8')
                if len(canonical_profile)>32_768 or archive.read('evidence/target-profile.json')!=canonical_profile:
                    raise OpafError('Packaged target profile differs from the sealed canonical snapshot.')
                historical_hash=hashlib.sha256(canonical_profile).hexdigest()
                if target_profile is not None:
                    # This argument is the immutable gateway-approved snapshot
                    # saved with the job, never a newly fetched active profile.
                    if canonical_hash(target_profile)!=historical_hash:
                        raise OpafError('Cached historical target profile differs from the package.')
                elif historical_hash not in HISTORICAL_TARGET_PROFILE_HASHES:
                    raise OpafError('Unregistered historical target profile requires its trusted job cache.')
                for role_name in ('mapper','reviewer'):
                    validate_model_environment(environments[role_name],historical,role_name,
                        {'job_id':review['job_id'],'source_hash':review['source_hash']},review[role_name+'_invocation'])
            elif ('model_environment' in review or 'historical_target_profile' in review
                    or 'evidence/target-profile.json' in names):
                raise OpafError('Legacy review evidence cannot invent model environment or target profile observations.')
            completion = json.loads(archive.read('evidence/export-completion.json'))
            if (not isinstance(completion, dict) or completion.get('schema_version') != 1
                    or completion.get('job_id') != evidence.get('job_id')
                    or completion.get('application_id') != app_id
                    or completion.get('application_alias') != evidence.get('application_alias')
                    or completion.get('artifact_binding') != evidence.get('artifact_binding')
                    or completion.get('apexlang_validation_passed') is not True):
                raise OpafError('Native package export completion is unbound.')
            export_files = completion.get('files', {})
            alias_prefix = str(evidence.get('application_alias', '')).lower() + '/'
            expected_apex = {'apexlang/' + key[len(alias_prefix):]: digest
                             for key, digest in export_files.items() if key.startswith(alias_prefix)}
            actual_apex = {key: digest for key, digest in manifest.items() if key.startswith('apexlang/')}
            if (not expected_apex or expected_apex != actual_apex
                    or export_files.get('f' + str(app_id) + '.sql') != manifest[expected_sql]
                    or evidence.get('package_reimport',{}).get('sql_sha256') != manifest[expected_sql]
                    or export_files.get('apexlang-validation.log') != manifest['evidence/export-validation.log']):
                raise OpafError('Native package export tree differs from its completion manifest.')
    except (ValueError, KeyError, TypeError, AttributeError, zipfile.BadZipFile, RuntimeError) as exc:
        if isinstance(exc, OpafError):
            raise
        raise OpafError('Native package is malformed; no release was accepted.') from None
    return hashlib.sha256(raw).hexdigest()


def run_native_job(job: Path):
    if not re.fullmatch(r'fox-[a-f0-9]{20}', job.name) or job.is_symlink():
        raise OpafError('Invalid native FOX job.')
    _progress(job,'preparing')
    snapshot = _json(job / 'source-snapshot.json')
    if snapshot.get('conversion_profile') != PROFILE_ID:
        raise OpafError('Native job profile is missing.')
    approvals = snapshot.get('approvals')
    if not isinstance(approvals, dict) or not all(approvals.get(key) is True for key in ('redacted_source', 'external_ai', 'synthetic_prototype')):
        raise OpafError('Recorded redaction, external AI and synthetic prototype approvals are required.')
    with tempfile.TemporaryDirectory(prefix='fox-native-preflight-') as temp:
        stage_job(job, Path(temp))
    assessed = assess_native_source(snapshot['files'])
    if assessed['state'] != 'READY' or snapshot.get('native_form') != assessed['native_form']:
        raise OpafError('Native source assessment is blocked or has changed.')
    try:
        profile = load_native_profile(os.environ['FOX_NATIVE_PROFILE_FILE'])
        credential_path = Path(os.environ['FOX_OPAF_CREDENTIAL_FILE'])
        if credential_path.is_symlink() or credential_path.stat().st_size > 65_536:
            raise ValueError()
        credentials = json.loads(credential_path.read_text())
        if not isinstance(credentials, dict) or any(not isinstance(credentials.get(k), str) or not credentials[k] for k in ('username', 'password', 'converter_token')):
            raise ValueError()
        gateway = ConverterClient(os.environ['FOX_CONVERTER_URL'], credentials['converter_token'])
    except (KeyError, ValueError, TypeError, OSError, AttributeError):
        # Never expose a JSON parser excerpt of the protected credential file.
        raise OpafError('Native workflow configuration or protected credentials are unavailable.') from None
    client = OpafClient(profile['opaf_base_url'], credentials['username'], credentials['password'], profile['certificate_sha256'])
    checkpoints = job / 'native-pipeline'
    if checkpoints.is_symlink():
        raise OpafError('Unsafe native checkpoint directory.')
    checkpoints.mkdir(exist_ok=True)
    _save_once(checkpoints / 'binding.json', {'schema_version': 1, 'job_id': job.name,
        'source_hash': snapshot['source_hash'], 'profile_sha256': canonical_hash(profile),
        'native_form_sha256': canonical_hash(snapshot['native_form'])})
    def current_target_profile():
        # Called only for an uncompleted model role. Existing sealed review,
        # deterministic resume and package checks never require live OPAF.
        envelope=gateway.request('GET','/fox/target-profile')
        try:
            if not isinstance(envelope,dict) or set(envelope)!={'target_profile','target_profile_sha256'}:
                raise ValueError()
            target=envelope['target_profile']
            if (len(json.dumps(target).encode())>32_768 or canonical_hash(target)!=envelope['target_profile_sha256']
                    or target['active'] is not True or target['scope']['conversion_profile']!=PROFILE_ID
                    or target['opaf']['base_url']!=profile['opaf_base_url']
                    or target['opaf']['certificate_sha256']!=profile['certificate_sha256']
                    or target['opaf']['roles']!={name:profile[name] for name in ('mapper','reviewer')}):
                raise ValueError()
        except (KeyError,ValueError,TypeError,AttributeError):
            raise OpafError('Converter target profile differs from the approved native workflow profile.') from None
        _save_once(checkpoints/'target-profile.json',envelope)
        return target
    path = '/fox/jobs/' + job.name
    state = _get_job(gateway, path)
    if state is None:
        try:
            gateway.request('POST', path, {key: snapshot[key] for key in ('source_hash', 'files', 'conversion_profile', 'native_form')})
        except OpafError as exc:
            if exc.status_code != 409:
                raise
        state = gateway.request('GET', path)
    state = _remote_identity(state, job.name, snapshot)
    if state['state']=='FAILED' and state.get('import_intent_exists'):
        _progress(job,'reconciling')
        gateway.request('POST',path+'/actions/reconcile-import',{})
        state=_remote_identity(gateway.request('GET',path),job.name,snapshot)
    if state['state'] not in {'INTAKE_READY', 'INSPECTED', 'DRAFTED', 'VALID', 'IMPORTED'}:
        raise OpafError('Existing converter job needs reconciliation; it will not be overwritten.')
    inspection_file = checkpoints / 'inspection.json'
    if inspection_file.exists():
        inspection = _json(inspection_file)
    elif state['state'] in {'INTAKE_READY', 'INSPECTED'}:
        _progress(job,'inspecting')
        inspection = gateway.request('POST', path + '/actions/inspect', {})
        _save_once(inspection_file, inspection)
    else:
        raise OpafError('Native inspection checkpoint is absent; reconcile the retained job.')
    request = {'job_id': job.name, 'source_hash': snapshot['source_hash'],
               'inventory': inspection, 'native_form': snapshot['native_form']}
    # Preserve retained v1 proof without upgrading its claims or replaying it.
    old_roles=[name for name in ('mapper','reviewer') if (checkpoints/(name+'.json')).exists()
               and 'model_environment' not in _json(checkpoints/(name+'.json'))]
    if old_roles and (len(old_roles)!=2 or not (checkpoints/'review-receipt.json').is_file()):
        raise OpafError('Unsealed legacy model checkpoints require operator reconciliation; no model replay or invented environment.')
    _progress(job,'mapping')
    candidate, mapper_invocation = _role(checkpoints, 'mapper', client, profile['mapper'], request,current_target_profile)
    _candidate(candidate, job.name, snapshot['native_form'], profile['mapper']['model'])
    review_request = {**request, 'candidate': candidate, 'candidate_sha256': canonical_hash(candidate)}
    _progress(job,'reviewing')
    review, reviewer_invocation = _role(checkpoints, 'reviewer', client, profile['reviewer'], review_request,current_target_profile)
    payload = {'job_id': job.name, 'source_hash': snapshot['source_hash'], 'candidate': candidate,
               'mapper_invocation': mapper_invocation, 'reviewer_invocation': reviewer_invocation, 'review': review}
    target_profile=None
    if not old_roles:
        target_profile=_json(checkpoints/'target-profile.json')['target_profile']
        payload['model_environment']={name:_json(checkpoints/(name+'.json'))['model_environment'] for name in ('mapper','reviewer')}
    sealed = gateway.request('POST', path + '/review', payload)
    _save_once(checkpoints / 'review-receipt.json', sealed)
    if sealed.get('verdict') != 'approve' or sealed.get('candidate_sha256') != canonical_hash(candidate):
        raise OpafError('Independent review did not approve this exact native candidate.')
    state = _remote_identity(gateway.request('GET', path), job.name, snapshot)
    if state['state'] == 'INSPECTED':
        _progress(job,'generating')
        gateway.request('POST', path + '/actions/generate', candidate)
        state = _remote_identity(gateway.request('GET', path), job.name, snapshot)
    if state['state'] == 'DRAFTED':
        _progress(job,'validating')
        gateway.request('POST', path + '/actions/validate', {})
        state = _remote_identity(gateway.request('GET', path), job.name, snapshot)
    if state['state'] not in {'VALID', 'IMPORTED'} or (state.get('validation') or {}).get('passed') is not True:
        raise OpafError('SQLcl validation has not passed; import remains blocked.')
    if state['state'] == 'VALID':
        intent = checkpoints / 'import-intent.json'
        if intent.exists() or state.get('import_intent_exists'):
            _progress(job,'reconciling')
            # This action performs read-only target verification. It fails closed
            # if the prior import lacks a durable complete compiled receipt.
            gateway.request('POST',path+'/actions/reconcile-import',{})
        else:
            _progress(job,'importing')
            _save_once(intent, {'job_id': job.name, 'candidate_sha256': canonical_hash(candidate),
                                'review_receipt_sha256': sealed['receipt_sha256']})
            gateway.request('POST', path + '/actions/import', {})
        state = _remote_identity(gateway.request('GET', path), job.name, snapshot)
    if state['state'] != 'IMPORTED':
        raise OpafError('Native import is not confirmed; retained for reconciliation.')
    _save_once(checkpoints / 'imported.json', state)
    _progress(job,'packaging')
    evidence = gateway.request('POST', path + '/release', {})
    if (evidence.get('job_id') != job.name or evidence.get('source_manifest_sha256') != snapshot['source_hash']
            or evidence.get('conversion_profile') != PROFILE_ID
            or evidence.get('reviewer_execution_verified') is not True
            or evidence.get('review_receipt_sha256') != sealed['receipt_sha256']):
        raise OpafError('Native release evidence is not bound to this reviewed source.')
    imported=state.get('import')
    if (not isinstance(imported,dict) or any(evidence.get(key)!=imported.get(key)
            for key in ('application_id','application_alias','application_url','artifact_binding'))):
        raise OpafError('Native release identity differs from the confirmed imported application.')
    raw = gateway.request('GET', path + '/package', binary=True)
    digest = verify_package(raw, evidence, snapshot['native_form'],target_profile)
    package = job / 'apex-package.zip'
    if package.exists():
        if package.is_symlink() or hashlib.sha256(package.read_bytes()).hexdigest() != digest:
            raise OpafError('Existing downloaded package differs; no overwrite.')
    else:
        fd, temporary = tempfile.mkstemp(prefix='.package-', dir=job)
        try:
            with os.fdopen(fd, 'wb') as handle:
                handle.write(raw); handle.flush(); os.fsync(handle.fileno())
            os.link(temporary, package)
            _sync(job)
        finally:
            Path(temporary).unlink(missing_ok=True)
    _save_once(job / 'release-evidence.json', evidence)
    _save_once(checkpoints / 'download.json', {'package_sha256': digest, 'source_hash': snapshot['source_hash']})
    _progress(job,'downloaded')
    return evidence
