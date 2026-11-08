"""Explicit queued prototype adapter; never a legacy conversion fallback.

The immutable source snapshot retains the ordinary selected file records plus
``prototype`` source/focus/selection/policy/target bindings and the three owner
approvals. The worker rechecks current owner/source selection before EACH new
model or converter operation. Configuration uses an additive protected
FOX_PROTOTYPE_PROFILE_FILE envelope; FOX_NATIVE_PROFILE_FILE stays untouched.
Only actual execution reads the existing protected credential file.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import tempfile

from . import forms_native_plan
from .native_pipeline import _save_once, _sync
from .opaf import ConverterClient, OpafClient, OpafError, canonical_hash
from .project_conversion import _validated_source_bytes
from .prototype_pipeline import run_prototype_pipeline
from .prototype_transport import PrototypeHttpConverterAdapter
from .prototype_admission import PROFILE_ID, bound_focus_limit, prepare_prototype_admission

MAX_SNAPSHOT_BYTES = 20_000_000
_SHA = re.compile(r'[a-f0-9]{64}\Z')


def read_prototype_snapshot(job: Path):
    path = Path(job) / 'source-snapshot.json'
    if Path(job).is_symlink() or path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SNAPSHOT_BYTES:
        raise OpafError('Prototype immutable source snapshot is missing, oversized or unsafe.')
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError()
    except (ValueError, OSError):
        raise OpafError('Prototype immutable source snapshot is unreadable.') from None
    return value, raw


def validate_prototype_snapshot(snapshot):
    """Pure original-byte/consent binding check; no narrow legacy READY gate."""
    try:
        if (not isinstance(snapshot, dict) or snapshot.get('conversion_profile') != PROFILE_ID
                or snapshot.get('project') != snapshot.get('project_id')
                or not isinstance(snapshot.get('project_id'), str)
                or not forms_native_plan._PROJECT_ID.fullmatch(snapshot['project_id'])
                or not forms_native_plan._safe_label(snapshot.get('project_name'))
                or not isinstance(snapshot.get('selected_source_set_id'), str)
                or not re.fullmatch(r'ss-[a-f0-9]{32}', snapshot['selected_source_set_id'])):
            raise ValueError()
        approvals, selected = snapshot['approvals'], snapshot['prototype']
        bound_focus_limit(selected)
        selected_keys = {'schema_version', 'source_binding', 'focus_plan_sha256',
                         'approved_chunk_hashes', 'approved_policy_id', 'target_profile_sha256'}
        if selected['schema_version'] == 2:
            selected_keys.add('max_owned_objects')
        if (not isinstance(approvals, dict) or any(approvals.get(key) is not True for key in
                ('redacted_source', 'external_ai', 'synthetic_prototype'))
                or not isinstance(approvals.get('owner'), str) or not 1 <= len(approvals['owner']) <= 180
                or type(approvals.get('approved_at')) not in (int, float)
                or not math.isfinite(approvals['approved_at']) or approvals['approved_at'] <= 0
                or not isinstance(selected, dict) or set(selected) != selected_keys
                or any(not isinstance(selected.get(key), str) or not _SHA.fullmatch(selected[key])
                       for key in ('source_binding', 'focus_plan_sha256', 'target_profile_sha256'))):
            raise ValueError()
        pairs = _validated_source_bytes(snapshot['files'])
        documents = [(row['name'], raw) for row, raw in pairs]
        manifest = '\n'.join(row['name'] + ':' + row['sha256'] for row, _ in pairs)
        if hashlib.sha256(manifest.encode()).hexdigest() != snapshot.get('source_hash'):
            raise ValueError()
        rebuilt = prepare_prototype_admission(documents,
            expected_source_binding=selected['source_binding'],
            approved_chunk_hashes=selected['approved_chunk_hashes'],
            target_profile_sha256=selected['target_profile_sha256'],
            approved_redacted_source=approvals['redacted_source'],
            approved_external_ai=approvals['external_ai'],
            approved_prototype_scope=approvals['synthetic_prototype'],
            schema_version=selected['schema_version'])
        if rebuilt['prototype'] != selected:
            raise ValueError()
        from .prototype_mapping_recovery import validate_retry_lineage
        validate_retry_lineage(snapshot)
    except (KeyError, ValueError, TypeError, AttributeError, OverflowError):
        raise OpafError('Prototype source, selected scope or persisted permission is invalid or stale.') from None
    return documents


def load_prototype_profile(path):
    """Read-only public metadata envelope; no credentials or model invocation."""
    try:
        path = Path(path)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 65_536:
            raise ValueError()
        envelope = json.loads(path.read_text(encoding='utf-8'))
        if (not isinstance(envelope, dict) or set(envelope) != {'target_profile', 'target_profile_sha256'}
                or not isinstance(envelope['target_profile_sha256'], str)
                or not _SHA.fullmatch(envelope['target_profile_sha256'])):
            raise ValueError()
        target = envelope['target_profile']
        if (canonical_hash(target) != envelope['target_profile_sha256'] or target['active'] is not True
                or target['scope']['data_mode'] != 'synthetic_test_only'
                or target['scope']['existing_resources_only'] is not True
                or target['scope']['customer_deployment_authorized'] is not False):
            raise ValueError()
        roles = target['opaf']['roles']
        if not isinstance(roles, dict) or set(roles) != {'mapper', 'reviewer'}:
            raise ValueError()
        for role in roles.values():
            if (not isinstance(role, dict) or set(role) != {'workflow_id', 'model', 'graph_sha256'}
                    or not isinstance(role['workflow_id'], str) or not re.fullmatch(r'[A-Fa-f0-9]{16,64}', role['workflow_id'])
                    or not isinstance(role['model'], str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', role['model'])
                    or not isinstance(role['graph_sha256'], str) or not _SHA.fullmatch(role['graph_sha256'])):
                raise ValueError()
        if roles['mapper']['workflow_id'].upper() == roles['reviewer']['workflow_id'].upper():
            raise ValueError()
        # Constructor validates only origin/certificate format; no HTTP/secret I/O.
        OpafClient(target['opaf']['base_url'], '', '', target['opaf']['certificate_sha256'])
    except (KeyError, ValueError, TypeError, AttributeError, OSError):
        raise OpafError('The explicit prototype target metadata profile is unavailable or invalid.') from None
    return envelope


def _save_result(job, result):
    """Preserve every result; atomically refresh the current safe job summary."""
    history = job / 'prototype-results'
    if history.is_symlink() or (job / 'prototype-result.json').is_symlink():
        raise OpafError('Prototype result storage is unsafe.')
    history.mkdir(exist_ok=True)
    _save_once(history / (canonical_hash(result) + '.json'), result)
    fd, name = tempfile.mkstemp(prefix='.prototype-result-', dir=job)
    temporary = Path(name)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(result, stream, ensure_ascii=False, allow_nan=False, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, job / 'prototype-result.json')
        _sync(job)
    finally:
        temporary.unlink(missing_ok=True)


def _configuration(approved_target_sha256, *, installation_projection=None):
    """Existing guarded clients/credential source, only at authorized execution."""
    from .prototype_read_scope import forbid_execution
    forbid_execution()
    try:
        profile_path = Path(os.environ['FOX_PROTOTYPE_PROFILE_FILE'])
        def target_loader():
            envelope = load_prototype_profile(profile_path)
            if envelope['target_profile_sha256'] != approved_target_sha256:
                raise OpafError('Prototype processing target changed; fresh source-owner approval is required.')
            return envelope['target_profile']
        target = target_loader()  # Validate approval/public metadata before secret access.
        credential_path = Path(os.environ['FOX_OPAF_CREDENTIAL_FILE'])
        if credential_path.is_symlink() or not credential_path.is_file() or credential_path.stat().st_size > 65_536:
            raise ValueError()
        credentials = json.loads(credential_path.read_text(encoding='utf-8'))
        if any(not isinstance(credentials.get(key), str) or not credentials[key]
               for key in ('username', 'password', 'converter_token')):
            raise ValueError()
        if installation_projection is None:
            if os.getenv('FOX_INSTALLATION_MODE') == 'fresh':
                raise OpafError('Fresh prototype transport requires its admitted installation projection.')
            gateway = ConverterClient(os.environ['FOX_CONVERTER_URL'], credentials['converter_token'])
        else:
            gateway = ConverterClient(os.environ['FOX_CONVERTER_URL'], credentials['converter_token'],
                                      projection=installation_projection)
        client = OpafClient(target['opaf']['base_url'], credentials['username'], credentials['password'],
                            target['opaf']['certificate_sha256'])
        return {'profile': deepcopy(target['opaf']['roles']), 'opaf_client': client,
                'gateway': gateway, 'target_profile_loader': target_loader}
    except (KeyError, ValueError, TypeError, AttributeError, OSError):
        raise OpafError('Prototype workflow configuration or protected execution credentials are unavailable.') from None


def run_prototype_job(job: Path, *, approval_check, installation_projection=None,
                      configuration_loader=None):
    """Run one explicit queue job; return generated facts, never old QA proof."""
    job = Path(job)
    snapshot, raw = read_prototype_snapshot(job)
    documents = validate_prototype_snapshot(snapshot)
    from .prototype_mapping_continuation import validate_job_continuation
    validate_job_continuation(job, snapshot, raw)
    from . import prototype_container_epoch as container
    from . import prototype_partition_review_epoch as partition
    from . import prototype_context_screen_epoch as screen
    current_record = screen.RECORD if (job / screen.RECORD).exists() else partition.RECORD if (job / partition.RECORD).exists() else container.RECORD
    if (job / current_record).exists():
        from .prototype_result_publication import validate_publication
        from .prototype_mapping_epochs import read
        if validate_publication(job, read(job / current_record)) is not None:
            raise OpafError('This epoch already published its terminal result; no operation was replayed.')
    if 'retry_of' in snapshot:
        from .prototype_mapping_recovery import retry_run_id
        if job.name != retry_run_id(snapshot['retry_of']):
            raise OpafError('Prototype mapping-recovery job differs from its bound parent identity.')
    if approval_check(snapshot) is not True:
        raise OpafError('Prototype source-owner approval is no longer current.')
    selected = snapshot['prototype']
    runtime = (configuration_loader or _configuration)(selected['target_profile_sha256'],
                                                        installation_projection=installation_projection)
    def still_approved(context=None, *, phase=None):
        if (job / 'source-snapshot.json').is_symlink() or (job / 'source-snapshot.json').read_bytes() != raw:
            raise OpafError('Prototype immutable source snapshot changed; no further operation is authorized.')
        if approval_check(snapshot) is not True:
            raise OpafError('Prototype source-owner approval is no longer current.')
        validate_job_continuation(job, snapshot, raw, phase=phase)
        return True
    # The transport performs no source/model approval itself. Repeat the same
    # current selected-source/owner check before converter GETs and POSTs too.
    transport = runtime.get('converter_adapter')
    if transport is None:
        transport = PrototypeHttpConverterAdapter(job, runtime['gateway'])
    class ApprovedTransport:
        def supports(self, stage):
            return transport.supports(stage)
        def recover_stage(self, stage, request):
            still_approved()
            return transport.recover_stage(stage, request)
        def run_stage(self, stage, request):
            from .prototype_mapping_epochs import converter_phase
            phase = converter_phase(job, snapshot, raw, stage, request)
            still_approved(phase=phase)
            return transport.run_stage(stage, request)
    result = run_prototype_pipeline(job, documents, project_id=snapshot['project_id'],
        project_name=snapshot['project_name'], expected_source_binding=selected['source_binding'],
        approved_chunk_hashes=selected['approved_chunk_hashes'], approved_policy_id=selected['approved_policy_id'],
        opaf_client=runtime['opaf_client'], profile=runtime['profile'],
        target_profile_loader=runtime['target_profile_loader'], processing_approval_check=still_approved,
        converter_adapter=ApprovedTransport(), renderer=runtime.get('renderer'),
        focus_schema_version=selected['schema_version'])
    still_approved()
    from . import prototype_container_epoch as container
    from .prototype_mapping_epochs import technical_record
    record = technical_record(job / 'prototype-pipeline')
    if record is not None and record['epoch_number'] in (container.NUMBER, partition.NUMBER, screen.NUMBER):
        from .prototype_result_publication import controlled_save_result
        controlled_save_result(job, result, record)
    else:
        _save_result(job, result)
    return result
