"""Project-capable protected phase routing; import performs no external work.

Only an explicitly paired v2 product release calls this router. The retained
package is read and fully checked before selecting a clean operator. A failure
never falls through to the other profile or retries an uncertain phase.
"""
from __future__ import annotations

import base64
from pathlib import Path

from . import contracts as C
from . import clean_install as native_clean
from . import project_clean_install as clean
from . import project_contracts as contracts

PROFILE = 'native-project-v1'
NATIVE_PROFILE = 'native-table-form-v1'


def select_profile(binding):
    """Read exact retained bytes; no allocation, plan creation or fallback."""
    from fox.technical_release import _package_identity
    from fox.verification_queue import VerificationBinding
    native_clean.require(type(binding) is VerificationBinding, 'PROTECTED_PROFILE_BINDING_REQUIRED')
    # Selection reads an existing package; the later clean-check/write phases
    # separately require the database to be available before executing SQL.
    scope = clean.oci_scope(require_database_available=False)
    result = clean.ssh_json(clean.SOURCE_HOST, {
        'cli_scope': scope, 'job_id': binding.job_id, 'package_sha256': binding.package_sha256,
        'reader_b64': base64.b64encode(clean.SOURCE_CODE.encode()).decode(), 'fox_image': clean.image_pins()['fox']})
    native_clean.require(type(result) is dict and set(result) == {'source_attestation', 'package_b64'},
                         'PRIVATE_PROFILE_RESPONSE_INVALID')
    raw = base64.b64decode(result['package_b64'], validate=True)
    native_clean.require(0 < len(raw) <= clean.MAX_PACKAGE and C.digest(raw) == binding.package_sha256,
                         'PRIVATE_PROFILE_PACKAGE_CHANGED')
    source = C.validate_source_attestation(result['source_attestation'])
    age = (clean.now() - C._timestamp(source['observed_at_utc'])).total_seconds()
    native_clean.require(-C.MAX_CLOCK_SKEW_SECONDS <= age <= 300
        and source['run_state'] == 'QA_REQUIRED' and source['package_bytes'] == len(raw)
        and all(source[key] == value for key, value in {
            'job_id': binding.job_id, 'source_manifest_sha256': binding.source_manifest_sha256,
            'package_sha256': binding.package_sha256}.items()), 'PRIVATE_PROFILE_SOURCE_CHANGED')
    kinds = set()
    _package_identity(raw, kinds)
    native_clean.require(kinds in ({'native'}, {'project'}), 'PRIVATE_PROFILE_UNSUPPORTED_OR_CONFLICTING')
    if kinds == {'project'}:
        package = contracts.load_package(raw, binding.package_sha256)
        validated = package['binding']
        profile = PROFILE
    else:
        validated = native_clean.validate_native_package(raw, binding.package_sha256)
        profile = NATIVE_PROFILE
    native_clean.require(all(validated[key] == value for key, value in {
        'job_id': binding.job_id, 'source_manifest_sha256': binding.source_manifest_sha256,
        'package_sha256': binding.package_sha256}.items()), 'PRIVATE_PROFILE_VALIDATED_BINDING_CHANGED')
    return profile


def perform(step, binding, context, manifest, native_perform):
    """Route one already-journaled step; preserve native phase implementation."""
    from . import project_qa_dispatch as qa
    from . import promote_project as promotion
    require = native_clean.require
    profile = select_profile(binding) if step == 'prepare' else context.get('conversion_profile')
    require(profile in (PROFILE, NATIVE_PROFILE), 'PROTECTED_CONVERSION_PROFILE_REQUIRED')
    if profile == NATIVE_PROFILE:
        value = native_perform(step, binding, context)
        return {**value, 'conversion_profile': profile} if step == 'prepare' else value
    release = manifest['project']
    if step == 'prepare':
        result = clean.prepare(binding.job_id, binding.package_sha256)
        raw, plan = clean.read_plan(Path(result['plan_path']))
        require(result['plan_sha256'] == C.digest(raw)
                and all(plan['binding'][key] == value for key, value in {
                    'job_id': binding.job_id, 'source_manifest_sha256': binding.source_manifest_sha256,
                    'package_sha256': binding.package_sha256}.items())
                and plan['binding']['profile_id'] == PROFILE
                and plan['operator_code_sha256'] == release['clean_operator_code_sha256'],
                'PREPARED_PROJECT_PLAN_BINDING_DIFFERS')
        return {'plan_sha256': result['plan_sha256'], 'job_id': binding.job_id,
                'source_manifest_sha256': binding.source_manifest_sha256, 'package_sha256': binding.package_sha256,
                'operator_code_sha256': plan['operator_code_sha256'], 'conversion_profile': PROFILE}
    path = clean.private_root() / context['plan_sha256'] / 'plan.json'
    if step == 'clean_check':
        value = clean.dispatch('check', path, expected_sha=context['plan_sha256'])
        require(value.get('state') == 'PREPARED' and all(value.get('phases', {}).get(name) == 'unattempted'
                for name in ('allocate', 'schema', 'import', 'verify')), 'FRESH_PROJECT_PLAN_NOT_UNATTEMPTED')
        return {'state': 'PREPARED', 'plan_sha256': value['plan_sha256']}
    if step in ('allocate', 'schema', 'import', 'verify'):
        value = clean.dispatch('apply', path, expected_sha=context['plan_sha256'], phase=step, apply=True)
        require(value.get('state') == ('QA_READY' if step == 'verify' else 'PHASE_COMPLETE')
                and value.get('action') in ('COMPLETED_ONCE', 'ALREADY_COMPLETE_NO_REPLAY'),
                'PROJECT_CLEAN_PHASE_NOT_CONFIRMED')
        return {key: value[key] for key in ('state', 'action', 'plan_sha256', 'evidence_sha256')}
    source = release['qa_source_sha256']
    directory = path.parent / ('qa-' + source[:16])
    if step in ('qa_stage', 'qa_run', 'qa_collect'):
        command = step[3:]
        value = qa.dispatch(command, path, context['plan_sha256'], source, apply=command != 'collect')
        if step == 'qa_stage':
            return {key: value[key] for key in ('status', 'plan_sha256', 'source_sha256', 'allocation_receipt_sha256', 'image_id')}
        if step == 'qa_run':
            return {key: value[key] for key in ('status', 'exit_code', 'plan_sha256', 'source_sha256', 'image_id')}
        require(value.get('local_directory') == str(directory), 'PROJECT_COLLECTION_LOCATION_DIFFERS')
        promotion.private_inputs([directory, directory / 'collection-manifest.json'])
        raw = (directory / 'collection-manifest.json').read_bytes()
        saved = C.load_json(raw)
        require(saved.get('status') == 'COLLECTED' and saved.get('credentials_and_logs_excluded') is True
                and saved.get('plan_sha256') == context['plan_sha256'] and saved.get('source_sha256') == source,
                'PROJECT_COLLECTION_NOT_CONFIRMED')
        return {'status': 'COLLECTED', 'plan_sha256': saved['plan_sha256'], 'source_sha256': saved['source_sha256'],
                'collection_manifest_sha256': C.digest(raw)}
    require(step in ('promotion_check', 'promotion_apply'), 'UNKNOWN_PROTECTED_PROJECT_PHASE')
    value = promotion.dispatch('check' if step == 'promotion_check' else 'apply', directory,
        collection_sha256=context['collection_manifest_sha256'], expected_image=manifest['images']['fox'],
        module_sha256=release['modules'], apply=step == 'promotion_apply')
    require(value.get('human_acceptance_recorded') is False and value.get('job_id') == binding.job_id,
            'PROJECT_TECHNICAL_PROMOTION_BINDING_DIFFERS')
    result = {'status': value['status'], 'job_id': binding.job_id, 'human_acceptance_recorded': False}
    if step == 'promotion_apply':
        require(value.get('event_count') == value.get('proof_count') == 1, 'PROJECT_TECHNICAL_PROMOTION_COUNT_DIFFERS')
        result['proof_sha256'] = value['proof_sha256']
    return result
