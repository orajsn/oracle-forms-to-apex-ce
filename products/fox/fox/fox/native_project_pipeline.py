"""Checkpointed, all-or-nothing project orchestration on the existing JSN target.

Each form uses the existing pinned mapper and independent reviewer. Their
approved metadata is composed deterministically into ONE application. This
adapter records technical generation, never human/business acceptance. It
does not replay an uncertain model, schema creation or APEX import request.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from urllib.parse import urlsplit
import zipfile

from .native_pipeline import (HISTORICAL_TARGET_PROFILE_HASHES, _candidate,
                              _get_job, _json, _progress, _role, _save_once, _sync)
from .opaf import (ConverterClient, OpafClient, OpafError, canonical_hash,
                   load_native_profile, stage_job, validate_model_environment)
from .project_conversion import PROFILE_ID, assess_project_conversion, module_execution_binding
from .project_qa_plan import derive_project_qa_plan
from .project_progress import ProjectProgress

TEMPLATE_ID = 'sqlcl-26.1.2-fox-project-v1'
_SHA = re.compile(r'[a-f0-9]{64}\Z')
_REQUIRED_ENV = ('FOX_NATIVE_PROFILE_FILE', 'FOX_OPAF_CREDENTIAL_FILE')
_NO_INSTALLATION_PROJECTION = object()
PROJECT_MAPPING_CAPABILITY = {
    'native_project_schema_versions': [1, 2],
    'storage_mapping_scope': 'fox-project-storage-v1',
    'module_execution_scope': 'fox-project-module-execution-v2',
}


def load_project_profile(path):
    """Accept legacy native profiles or an explicitly activated mapped pair.

    Candidate artifacts deliberately have no workflow IDs. Loading one cannot
    silently enable or repurpose the historical native mapper/reviewer graphs.
    """
    value = _json(Path(path))
    if value.get('schema_version') == 1:
        return load_native_profile(path)
    expected = {'schema_version', 'profile_id', 'opaf_base_url', 'certificate_sha256',
                'mapper', 'reviewer'} | set(PROJECT_MAPPING_CAPABILITY)
    if (set(value) != expected or type(value.get('schema_version')) is not int
            or value['schema_version'] != 2 or value['profile_id'] != PROFILE_ID
            or any(value.get(key) != item for key, item in PROJECT_MAPPING_CAPABILITY.items())):
        raise OpafError('Mapped storage requires the new paired project-v2 deployment profile.')
    for name in ('mapper', 'reviewer'):
        role = value[name]
        if (not isinstance(role, dict) or set(role) != {'workflow_id', 'model', 'graph_sha256'}
                or not isinstance(role.get('workflow_id'), str)
                or not re.fullmatch(r'[A-Fa-f0-9]{16,64}', role['workflow_id'])
                or not isinstance(role.get('graph_sha256'), str) or not _SHA.fullmatch(role['graph_sha256'])
                or role.get('model') != 'xai.grok-4.3'):
            raise OpafError('Project-v2 candidate is not activated with verified paired workflow IDs and graphs.')
    if value['mapper']['workflow_id'].upper() == value['reviewer']['workflow_id'].upper():
        raise OpafError('Mapper and reviewer must be separate workflows.')
    OpafClient(value['opaf_base_url'], '', '', value['certificate_sha256'])
    return value


def _mapping_fields(project, form, execution):
    return ({'storage_mapping': form['storage_mapping'], 'ddl_sources': form['ddl_sources'],
             'module_execution_binding': execution} if project['schema_version'] == 2 else {})


def _form_request(snapshot, form, row, inventory):
    return {'job_id': row['child_job_id'], 'source_hash': snapshot['source_hash'],
            'inventory': inventory, 'native_form': form['native_form'],
            **_mapping_fields(snapshot['native_project'], form, row['binding'])}


def _child_checkpoint_binding(job_id, snapshot, form, row, inventory):
    return {'parent_job_id': job_id, 'module_id': form['module_id'],
            'child_job_id': row['child_job_id'], 'source_hash': snapshot['source_hash'],
            'native_form_sha256': canonical_hash(form['native_form']),
            'inventory_sha256': canonical_hash(inventory),
            **({'schema_version': 2, 'execution_binding': row['binding']}
               if snapshot['native_project']['schema_version'] == 2 else {})}


def _checked_installation_projection(values, installation_projection=_NO_INSTALLATION_PROJECTION):
    """Validate fresh transport data, not the application's admission fence.

    No files, credentials, target probes or network operations occur here.
    The caller must separately establish actual fresh startup/admission.
    """
    mode = values.get('FOX_INSTALLATION_MODE')
    if mode is not None and (type(mode) is not str or mode not in ('legacy', 'fresh')):
        raise OpafError('Project installation mode is invalid; no legacy fallback is permitted.')
    if mode != 'fresh':
        if (any(name.startswith('FOX_FRESH_') for name in values)
                or installation_projection is not _NO_INSTALLATION_PROJECTION):
            raise OpafError('Fresh project configuration requires explicit fresh mode and projection.')
        return _NO_INSTALLATION_PROJECTION
    if installation_projection is _NO_INSTALLATION_PROJECTION:
        raise OpafError('Fresh project conversion requires its validated installation projection.')
    # Keep this dependency out of omitted legacy execution/module closures.
    from .installation import FreshProjectionError, validate_projection
    try:
        projection = validate_projection(installation_projection)
        if (values.get('FOX_CONVERSION_PROFILE') != PROFILE_ID
                or values.get('FOX_RUN_ADAPTER') != 'embedded-opaf'
                or values.get('FOX_CONVERTER_URL') != projection['converter_endpoint']):
            raise FreshProjectionError('FRESH_PROJECT_TRANSPORT_MISMATCH')
    except FreshProjectionError:
        raise OpafError('Fresh project transport differs from its supplied installation projection.') from None
    return projection


def project_configuration_readiness(env=None, *, installation_projection=_NO_INSTALLATION_PROJECTION):
    """Pure configuration presence/shape check; no files, credentials or I/O.

Configured does not mean connected, capability verified, authorized or ready
to deploy. The worker checks the paired converter capability before any POST.
"""
    values = os.environ if env is None else env
    checks = []
    def check(code, ready, message):
        checks.append({'code': code, 'ready': bool(ready), 'message': message})
    try:
        projection = _checked_installation_projection(values, installation_projection)
        projection_valid = True
    except OpafError:
        projection = None
        projection_valid = False
    if projection is not _NO_INSTALLATION_PROJECTION:
        check('INSTALLATION_PROJECTION', projection_valid,
              'Fresh mode requires its exact installation projection and matching project transport.')
    check('PROJECT_PROFILE', values.get('FOX_CONVERSION_PROFILE') == PROFILE_ID,
          'Select the native project conversion profile.')
    check('EMBEDDED_ADAPTER', values.get('FOX_RUN_ADAPTER') == 'embedded-opaf',
          'Select the embedded project adapter.')
    for key in _REQUIRED_ENV:
        check(key, isinstance(values.get(key), str) and bool(values[key].strip()),
              'Configure the protected integration file location.')
    if projection_valid and projection is not _NO_INSTALLATION_PROJECTION:
        valid = values.get('FOX_CONVERTER_URL') == projection['converter_endpoint']
    elif projection_valid:
        try:
            url = urlsplit(values.get('FOX_CONVERTER_URL', ''))
            valid = (url.scheme == 'http' and url.hostname == '127.0.0.1'
                     and url.port == 8091 and url.path in ('', '/')
                     and not any((url.username, url.password, url.query, url.fragment)))
        except (ValueError, TypeError, AttributeError):
            valid = False
    else:
        valid = False
    check('INTERNAL_CONVERTER', valid, 'Configure the existing internal converter loopback endpoint.')
    ready = all(item['ready'] for item in checks)
    return {'profile': PROFILE_ID, 'ready': ready, 'configured': ready, 'checks': checks,
            'scope': 'configuration_only', 'connectivity_checked': False,
            'converter_capability_checked': False}


def _configuration(*, installation_projection=_NO_INSTALLATION_PROJECTION):
    projection = _checked_installation_projection(os.environ, installation_projection)
    try:
        profile_path = Path(os.environ['FOX_NATIVE_PROFILE_FILE'])
        if profile_path.is_symlink() or profile_path.stat().st_size > 65_536:
            raise ValueError()
        profile = load_project_profile(profile_path)
        path = Path(os.environ['FOX_OPAF_CREDENTIAL_FILE'])
        if path.is_symlink() or path.stat().st_size > 65_536:
            raise ValueError()
        credentials = json.loads(path.read_text(encoding='utf-8'))
        if (not isinstance(credentials, dict) or any(not isinstance(credentials.get(key), str)
                or not credentials[key] for key in ('username', 'password', 'converter_token'))):
            raise ValueError()
        if projection is _NO_INSTALLATION_PROJECTION:
            gateway = ConverterClient(os.environ['FOX_CONVERTER_URL'], credentials['converter_token'])
        else:
            gateway = ConverterClient(os.environ['FOX_CONVERTER_URL'], credentials['converter_token'],
                                      projection=projection)
        client = OpafClient(profile['opaf_base_url'], credentials['username'], credentials['password'],
                            profile['certificate_sha256'])
        return profile, gateway, client
    except (KeyError, ValueError, TypeError, OSError, AttributeError):
        raise OpafError('Project workflow configuration or protected credentials are unavailable.') from None


def _capability(gateway, project=None, profile=None):
    value = gateway.request('GET', '/fox/capabilities')
    if (not isinstance(value, dict) or type(value.get('schema_version')) is not int
            or value['schema_version'] != 1 or value.get('project_protocol') != PROFILE_ID
            or value.get('schema_preparation') is not True
            or not isinstance(value.get('conversion_profiles'), list)
            or PROFILE_ID not in value['conversion_profiles']):
        raise OpafError('Paired converter lacks the required project and schema preparation capability.')
    if project is not None and project['schema_version'] == 2:
        mapping = value.get('project_mapping')
        if (mapping != {**PROJECT_MAPPING_CAPABILITY, 'paired_profile_ready': True}
                or not isinstance(profile, dict) or profile.get('schema_version') != 2
                or profile.get('profile_id') != PROFILE_ID
                or any(profile.get(key) != item for key, item in PROJECT_MAPPING_CAPABILITY.items())):
            raise OpafError('Mapped storage is NOT_READY: activate the new registered paired project-v2 mapper/reviewer profile and converter before generation.')
    return value


def _target(gateway, profile, checkpoints):
    envelope = gateway.request('GET', '/fox/target-profile')
    try:
        if not isinstance(envelope, dict) or set(envelope) != {'target_profile', 'target_profile_sha256'}:
            raise ValueError()
        target = envelope['target_profile']
        if (len(json.dumps(target).encode()) > 32_768
                or canonical_hash(target) != envelope['target_profile_sha256']
                or target['active'] is not True
                or target['scope']['conversion_profile'] != 'native-table-form-v1'
                or target['scope']['data_mode'] != 'synthetic_test_only'
                or target['scope']['existing_resources_only'] is not True
                or target['scope']['customer_deployment_authorized'] is not False
                or target['opaf']['base_url'] != profile['opaf_base_url']
                or target['opaf']['certificate_sha256'] != profile['certificate_sha256']
                or target['opaf']['roles'] != {name: profile[name] for name in ('mapper', 'reviewer')}):
            raise ValueError()
        if (profile['schema_version'] == 2
                and target['scope'].get('project_mapping') != PROJECT_MAPPING_CAPABILITY):
            raise ValueError()
    except (KeyError, ValueError, TypeError, AttributeError):
        raise OpafError('Converter target differs from the approved native model/JSN configuration.') from None
    _save_once(checkpoints / 'target-profile.json', envelope)
    return target


def _remote(value, job_id, snapshot):
    if (not isinstance(value, dict) or value.get('job_id') != job_id
            or value.get('source_manifest_sha256') != snapshot['source_hash']
            or value.get('conversion_profile') != PROFILE_ID
            or value.get('native_project') != snapshot['native_project']):
        raise OpafError('Remote project differs from the exact approved source version.')
    return value


def _approved(value, candidate):
    if (not isinstance(value, dict) or value.get('verdict') != 'approve'
            or value.get('candidate_sha256') != canonical_hash(candidate)
            or not isinstance(value.get('receipt_sha256'), str)
            or not _SHA.fullmatch(value['receipt_sha256'])):
        raise OpafError('Independent review did not approve this exact project/form candidate.')
    return value


def _project_candidate(value, job_id, project, model):
    if (not isinstance(value, dict) or set(value) != {'job_id', 'template_id', 'data_classification',
            'generator', 'native_project', 'remediation_items', 'mapping_summary'}
            or value['job_id'] != job_id or value['template_id'] != TEMPLATE_ID
            or value['data_classification'] != 'synthetic_or_stub_only'
            or value['generator'] != {'model': model} or value['native_project'] != project
            or not isinstance(value['remediation_items'], list) or not isinstance(value['mapping_summary'], str)
            or not value['mapping_summary'].strip()):
        raise OpafError('Aggregated candidate does not cover exactly the complete READY project.')
    return value


def _project_approved(value, candidate, plan, job_id, references):
    _approved(value, candidate)
    if candidate['native_project']['schema_version'] != 2:
        return value
    rows = value.get('form_reviews')
    expected = {form['module_id'] for form in candidate['native_project']['forms']}
    if (value.get('schema_version') != 2 or value.get('scope') != 'fox-native-project-review-v2'
            or value.get('project_id') != plan['project_id'] or value.get('plan_sha256') != plan['plan_sha256']
            or value.get('job_id') != job_id or value.get('source_hash') != plan['source_hash']
            or not isinstance(rows, list) or len(rows) != len(expected)
            or any(not isinstance(row, dict) for row in rows)
            or {row.get('module_id') for row in rows} != expected
            or {row['module_id']: row.get('receipt_sha256') for row in rows} != {
                row['module_id']: row['receipt_sha256'] for row in references}
            or any(row.get('execution_binding') != module_execution_binding(
                plan, parent_job_id=job_id, module_id=row['module_id']) for row in rows)):
        raise OpafError('Project-v2 aggregate does not bind every original source and verified storage mapping.')
    return value


def _project_inventories(inspection, snapshot, plan, job_id):
    """Check the compact server inventory, then project only source-bound files.

The complete global manifest remains explicit metadata. A per-form projection
digest is never represented as the complete source hash. No raw source copies
are persisted in each child checkpoint or duplicated in the HTTP inspection.
"""
    shared = inspection.get('shared_inventory')
    if (inspection.get('inspection_format') != 'shared-source-inventory-v1'
            or inspection.get('source_hash') != snapshot['source_hash']
            or not isinstance(shared, dict) or 'job_id' in shared
            or canonical_hash(shared) != inspection.get('shared_inventory_sha256')
            or not isinstance(shared.get('modules'), list)):
        raise OpafError('Project shared source inventory is missing or changed.')
    files = {source['name']: source for source in snapshot['files']}
    modules = shared['modules']
    if (len(modules) != len(files) or any(not isinstance(module, dict) for module in modules)
            or {module.get('file') for module in modules} != set(files)):
        raise OpafError('Project shared inventory does not cover the complete source version.')
    for module in modules:
        source = files[module['file']]
        if (module.get('sha256') != source['sha256'] or module.get('readable_source') != source['text']
                or module.get('bytes') != source['bytes']):
            raise OpafError('Project shared inventory differs from the approved source bytes.')
    expected = {form['module_id']: form for form in snapshot['native_project']['forms']}
    rows = inspection.get('forms')
    if (inspection.get('job_id') != job_id or not isinstance(rows, list) or len(rows) != len(expected)
            or any(not isinstance(row, dict) for row in rows)
            or {row.get('module_id') for row in rows} != set(expected)):
        raise OpafError('Project inspection does not cover every source-bound form exactly once.')
    expanded, children = {}, set()
    for row in rows:
        module_id = row['module_id']; form = expected[module_id]
        child = row.get('child_job_id'); inventory = row.get('inventory')
        binding = module_execution_binding(plan, parent_job_id=job_id, module_id=module_id)
        mapped = snapshot['native_project']['schema_version'] == 2
        trusted_mapping = _mapping_fields(snapshot['native_project'], form, binding)
        projection = {'scope': 'fox-project-module-source-projection-v2' if mapped else 'fox-project-module-source-projection-v1', 'module_id': module_id,
            'source_manifest_sha256': snapshot['source_hash'], 'sources': sorted([
                {'name': source['name'], 'sha256': source['sha256']} for source in plan['source_files']
                if module_id in source['module_ids']], key=lambda source: source['name']), **trusted_mapping}
        if (child != binding['child_job_id'] or child in children or row.get('binding') != binding
                or row.get('source_hash') != snapshot['source_hash'] or not isinstance(inventory, dict)
                or set(inventory) != {'job_id', 'shared_inventory_sha256', 'approved_native_form',
                    'remediation_items', 'project_module', 'source_projection', 'source_projection_sha256'} | set(trusted_mapping)
                or inventory['job_id'] != child
                or inventory['shared_inventory_sha256'] != inspection['shared_inventory_sha256']
                or inventory['source_projection'] != projection
                or inventory['source_projection_sha256'] != canonical_hash(projection)
                or any(inventory.get(key) != item for key, item in trusted_mapping.items())
                or inventory['approved_native_form'] != form['native_form']
                or inventory['project_module'] != {key: form[key] for key in
                    ('module_id', 'form_name', 'source_name', 'source_sha256')}
                or inventory['remediation_items'] != shared.get('remediation_items')):
            raise OpafError('Project form inspection has an ambiguous child/source binding or projection.')
        children.add(child)
        selected = {source['name'] for source in projection['sources']}
        expanded[module_id] = {**shared, **inventory,
            'modules': [module for module in modules if module['file'] in selected],
            'complete_source_manifest': {'scope': 'fox-project-complete-source-manifest-v1',
                'source_manifest_sha256': snapshot['source_hash'], 'files': [
                    {key: files[name][key] for key in ('name', 'sha256', 'bytes')} for name in sorted(files)]}}
    return sorted(rows, key=lambda row: row['module_id']), expanded


def _generation_receipt(state, candidate, job_id):
    binding = state.get('artifact_binding')
    candidate_raw = json.dumps(candidate, sort_keys=True, separators=(',', ':'),
                               ensure_ascii=False, allow_nan=False).encode() + b'\n'
    if (state.get('state') not in {'DRAFTED', 'VALID', 'IMPORTED'} or not isinstance(binding, dict)
            or binding.get('job_id') != job_id or binding.get('template_id') != TEMPLATE_ID
            or binding.get('reviewed_spec_sha256') != hashlib.sha256(candidate_raw).hexdigest()
            or any(not isinstance(binding.get(key), str) or not _SHA.fullmatch(binding[key]) for key in
                ('draft_sha256', 'draft_zip_sha256', 'intake_sha256', 'project_review_sha256', 'project_trace_sha256'))):
        raise OpafError('Project generation lacks its source/review-bound converter artifact receipt.')
    return {'schema_version': candidate['native_project']['schema_version'], 'job_id': job_id, 'source_hash': candidate['native_project']['source_manifest_sha256'],
            'candidate_sha256': canonical_hash(candidate), 'artifact_binding': binding}


def _restore_progress(job, snapshot, plan, progress, *, read=None, restore_role=None):
    """Rebuild known local milestones before any fallible network/config check.

Only complete immutable checkpoints are considered. Calling _role here is
strictly offline because each completed file is checked before the call and
no client or target loader is supplied. Prior advisory progress is never read.
Read-only presentation may supply bounded readers and an in-memory sink; the
execution defaults and their checkpoint behavior remain unchanged.
"""
    read = _json if read is None else read
    restore_role = _role if restore_role is None else restore_role
    checkpoints = job / 'native-project-pipeline'
    if not checkpoints.exists():
        return False
    if checkpoints.is_symlink():
        raise OpafError('Unsafe project checkpoint directory.')
    binding = read(checkpoints / 'binding.json')
    if any(binding.get(key) != expected for key, expected in {
            'schema_version': snapshot['native_project']['schema_version'], 'job_id': job.name, 'source_hash': snapshot['source_hash'],
            'plan_sha256': plan['plan_sha256'],
            'native_project_sha256': canonical_hash(snapshot['native_project'])}.items()):
        raise OpafError('Retained project checkpoint binding changed; no milestone was recovered.')
    if not (checkpoints / 'inspection.json').exists():
        return False
    rows, inventories = _project_inventories(read(checkpoints / 'inspection.json'), snapshot, plan, job.name)
    if not (checkpoints / 'target-profile.json').exists():
        return False
    envelope = read(checkpoints / 'target-profile.json'); target = envelope.get('target_profile')
    if not isinstance(target, dict) or envelope.get('target_profile_sha256') != canonical_hash(target):
        raise OpafError('Retained project model target profile changed.')
    try:
        opaf = target['opaf']
        profile = {'schema_version': 1, 'profile_id': 'native-table-form-v1',
            'opaf_base_url': opaf['base_url'], 'certificate_sha256': opaf['certificate_sha256'],
            **{role: opaf['roles'][role] for role in ('mapper', 'reviewer')}}
        if target.get('scope', {}).get('project_mapping') == PROJECT_MAPPING_CAPABILITY:
            profile.update(schema_version=2, profile_id=PROFILE_ID, **PROJECT_MAPPING_CAPABILITY)
        elif snapshot['native_project']['schema_version'] == 2:
            raise ValueError()
    except (KeyError, TypeError, ValueError):
        raise OpafError('Retained project model target profile is incomplete.') from None
    if binding.get('profile_sha256') != canonical_hash(profile):
        raise OpafError('Retained project model profile is not bound to this job.')
    forms = {form['module_id']: form for form in snapshot['native_project']['forms']}
    reviewed = []
    for row in rows:
        module = row['module_id']; child = checkpoints / module; form = forms[module]
        if child.is_symlink():
            raise OpafError('Unsafe project form checkpoint directory.')
        if not (child / 'mapper.json').exists():
            continue
        progress.active_module = module
        expected_binding = _child_checkpoint_binding(job.name, snapshot, form, row, inventories[module])
        if read(child / 'binding.json') != expected_binding or read(child / 'target-profile.json') != envelope:
            raise OpafError('Retained project form binding changed.')
        for role in ('mapper', 'reviewer'):
            if (child / (role + '.json')).exists() and 'model_environment' not in read(child / (role + '.json')):
                raise OpafError('Project model checkpoint lacks actual environment evidence; no replay.')
        request = _form_request(snapshot, form, row, inventories[module])
        candidate, _ = restore_role(child, 'mapper', None, profile['mapper'], request)
        _candidate(candidate, row['child_job_id'], form['native_form'], profile['mapper']['model'])
        progress.form(module, 'mapped')
        if not (child / 'reviewer.json').exists():
            continue
        review, _ = restore_role(child, 'reviewer', None, profile['reviewer'],
            {**request, 'candidate': candidate, 'candidate_sha256': canonical_hash(candidate)})
        if (not isinstance(review, dict) or review.get('verdict') != 'approve'
                or review.get('candidate_sha256') != canonical_hash(candidate) or review.get('blocking_findings') != []):
            raise OpafError('One retained form review remains unapproved; the whole project is blocked.')
        if not (child / 'review-receipt.json').exists():
            continue
        sealed = _approved(read(child / 'review-receipt.json'), candidate)
        reviewed.append({'module_id': module, 'receipt_sha256': sealed['receipt_sha256']})
        progress.form(module, 'reviewed')
    if len(reviewed) != len(rows) or not (checkpoints / 'generated.json').exists():
        return False
    parent = read(checkpoints / 'review-receipt.json')
    candidate = _project_candidate(parent.get('candidate'), job.name, snapshot['native_project'], profile['mapper']['model'])
    _project_approved(parent, candidate, plan, job.name, reviewed)
    generated = read(checkpoints / 'generated.json')
    expected = _generation_receipt({'state': 'DRAFTED', 'artifact_binding': generated.get('artifact_binding')}, candidate, job.name)
    if generated != expected:
        raise OpafError('Retained project generation receipt changed.')
    progress.generated()
    return True


def _schema_ready(value, job_id):
    return (isinstance(value, dict) and value.get('state') == 'READY'
            and type(value.get('schema_version')) is int and value['schema_version'] == 1
            and value.get('scope') == 'fox-native-schema-preparation-result-v1'
            and value.get('job_id') == job_id
            and isinstance(value.get('schema_plan_sha256'), str)
            and _SHA.fullmatch(value['schema_plan_sha256']) is not None
            and isinstance(value.get('receipt_sha256'), str)
            and _SHA.fullmatch(value['receipt_sha256']) is not None
            and value.get('apex_import_performed_by_operation') is False
            and value.get('human_acceptance_recorded') is False)


def _prepare_schema(gateway, path, state, checkpoints, job, candidate, sealed):
    """No APEX import intent exists until schema readiness is durably recorded."""
    complete = checkpoints / 'schema-prepared.json'
    pending = checkpoints / 'schema-intent.json'
    if complete.exists():
        receipt = _json(complete)
        if not _schema_ready(receipt, job.name):
            raise OpafError('Saved project schema preparation is incomplete.')
        return receipt
    if (pending.exists() or state.get('schema_intent_exists')
            or state.get('import_intent_exists') or state['state'] == 'IMPORTED'):
        _progress(job, 'reconciling')
        checked = gateway.request('POST', path + '/actions/reconcile-schema', {})
        if (not isinstance(checked, dict) or checked.get('state') != 'READY'
                or checked.get('ready_for_import') is not True):
            raise OpafError('Schema preparation is uncertain; read-only reconciliation did not confirm readiness.')
        state = _remote(gateway.request('GET', path), job.name,
                        _json(job / 'source-snapshot.json'))
        receipt = state.get('schema_preparation')
        if not _schema_ready(receipt, job.name) or checked.get('receipt_sha256') != receipt['receipt_sha256']:
            raise OpafError('Schema reconciliation lacks its bound completed receipt.')
    else:
        _progress(job, 'preparing')
        _save_once(pending, {'job_id': job.name, 'candidate_sha256': canonical_hash(candidate),
                             'review_receipt_sha256': sealed['receipt_sha256']})
        receipt = gateway.request('POST', path + '/actions/prepare-schema', {})
        if not _schema_ready(receipt, job.name):
            raise OpafError('Schema preparation did not complete; APEX import remains blocked.')
    _save_once(complete, receipt)
    return receipt


def _store_package(job, raw, digest):
    package = job / 'apex-package.zip'
    if package.exists() or package.is_symlink():
        if package.is_symlink() or hashlib.sha256(package.read_bytes()).hexdigest() != digest:
            raise OpafError('Existing downloaded project package differs; no overwrite.')
        return
    fd, name = tempfile.mkstemp(prefix='.project-package-', dir=job)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(raw); handle.flush(); os.fsync(handle.fileno())
        os.link(name, package)
        _sync(job)
    finally:
        Path(name).unlink(missing_ok=True)


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


def _schema_sql(spec):
    """Offline byte contract paired with converter.native_schema, never execute.

Caller first validates native metadata through the project's QA plan. Keeping
the explicit create-only text here avoids importing the converter runtime into
FOX and lets a downloaded ZIP manifest never authorize arbitrary schema SQL.
"""
    columns = []
    for column in spec['columns']:
        kind = column['data_type']
        if kind == 'VARCHAR2':
            kind += '(' + str(column['length']) + ')'
        line = column['name'] + ' ' + kind
        if column.get('identity'):
            line += ' GENERATED BY DEFAULT ON NULL AS IDENTITY PRIMARY KEY'
        elif not column['nullable']:
            line += ' NOT NULL'
        columns.append('  ' + line)
    return ('-- FOX native-table-form-v1: synthetic test schema only.\n'
        '-- Run only in the explicitly selected empty test parsing schema.\n'
        '-- Existing tables cause failure; no ALTER, DROP, grants or data loads.\n'
        'whenever sqlerror exit failure rollback\n'
        'whenever oserror exit failure rollback\n'
        'set define off\nCREATE TABLE ' + spec['table_name'] + ' (\n' + ',\n'.join(columns) + '\n);\n')


def verify_project_package(raw, evidence, native_project, target_profile=None):
    """Verify exact downloaded artifacts offline, not live runtime acceptance.

Every module must have its own sealed v2 review; a parent aggregate or one
successful form cannot substitute for another form. The historical target
must be registered or match the trusted immutable job cache supplied by caller.
"""
    def need(condition, message):
        if not condition:
            raise OpafError(message)
    def sealed(value):
        return (isinstance(value, dict) and isinstance(value.get('receipt_sha256'), str)
                and _SHA.fullmatch(value['receipt_sha256'])
                and canonical_hash({key: item for key, item in value.items()
                                    if key != 'receipt_sha256'}) == value['receipt_sha256'])
    need(isinstance(raw, bytes) and len(raw) <= 8_000_000, 'Project package exceeds the download bound.')
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist(); names = [entry.filename for entry in entries]
            need(len(names) == len(set(names)) and len(names) <= 500
                 and sum(entry.file_size for entry in entries) <= 20_000_000,
                 'Invalid or oversized project package structure.')
            for entry in entries:
                name = entry.filename
                need(name and not name.startswith('/') and '\\' not in name and ':' not in name
                     and not any(part in {'', '.', '..'} for part in name.split('/'))
                     and not entry.is_dir() and not entry.flag_bits & 1
                     and not stat.S_ISLNK(entry.external_attr >> 16), 'Unsafe project package member.')
            def read(name):
                return json.loads(archive.read(name), object_pairs_hook=_unique_keys,
                                  parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            manifest = read('manifest.json')
            need(isinstance(manifest, dict) and set(names) == set(manifest) | {'manifest.json'},
                 'Project package manifest is incomplete.')
            for name, digest in manifest.items():
                need(isinstance(digest, str) and _SHA.fullmatch(digest)
                     and hashlib.sha256(archive.read(name)).hexdigest() == digest,
                     'Project package integrity check failed.')
            need(read('evidence/release-evidence.json') == evidence
                 and read('native-project-spec.json') == native_project,
                 'Project package source or release identity changed.')
            need(evidence.get('conversion_profile') == PROFILE_ID
                 and evidence.get('source_manifest_sha256') == native_project['source_manifest_sha256']
                 and evidence.get('template_id') == TEMPLATE_ID
                 and type(evidence.get('application_count')) is int and evidence['application_count'] == 1
                 and evidence.get('form_count') == len(native_project['forms'])
                 and evidence.get('reviewer_execution_verified') is True
                 and all(evidence.get(flag) is False for flag in ('human_acceptance_recorded',
                    'authenticated_runtime_passed', 'clean_schema_install_passed')),
                 'Project package has unbound or unsupported acceptance claims.')
            parent = read('evidence/project-review.json')
            project_version = native_project['schema_version']
            need(sealed(parent) and type(parent.get('schema_version')) is int
                 and parent['schema_version'] == project_version
                 and parent.get('scope') == 'fox-native-project-review-v' + str(project_version)
                 and parent.get('trust_boundary') == 'authenticated_fox_executor_not_vendor_attestation'
                 and parent.get('job_id') == evidence['job_id']
                 and parent.get('source_hash') == evidence['source_manifest_sha256']
                 and parent.get('receipt_sha256') == evidence['review_receipt_sha256']
                 and parent.get('verdict') == 'approve', 'Project aggregate review is unbound or changed.')
            historical = read('evidence/target-profile.json')
            canonical_profile = json.dumps(historical, sort_keys=True, separators=(',', ':'),
                ensure_ascii=False, allow_nan=False).encode('utf-8')
            need(len(canonical_profile) <= 32_768 and archive.read('evidence/target-profile.json') == canonical_profile,
                 'Project historical target profile is not its canonical sealed snapshot.')
            historical_hash = canonical_hash(historical)
            need((target_profile is not None and canonical_hash(target_profile) == historical_hash)
                 or (target_profile is None and historical_hash in HISTORICAL_TARGET_PROFILE_HASHES),
                 'Project historical profile requires its trusted immutable job cache.')
            if project_version == 2:
                need(historical.get('scope', {}).get('project_mapping') == PROJECT_MAPPING_CAPABILITY,
                     'Mapped project package requires its explicitly paired mapper/reviewer profile.')
            candidate = _project_candidate(parent.get('candidate'), evidence['job_id'], native_project,
                                           historical['opaf']['roles']['mapper']['model'])
            need(parent.get('candidate_sha256') == canonical_hash(candidate), 'Project candidate hash changed.')
            need(read('evidence/migration-spec.json') == candidate
                 and evidence['artifact_binding'].get('reviewed_spec_sha256') == manifest['evidence/migration-spec.json']
                 and evidence['artifact_binding'].get('project_review_sha256') == manifest['evidence/project-review.json'],
                 'Project package review/candidate bytes differ from their import binding.')
            source_manifest = read('evidence/source-manifest.json')
            source_files = source_manifest['files']
            sources = {row['packaged_name']: row['sha256'] for row in source_files}
            need(source_manifest.get('job_id') == evidence['job_id']
                 and source_manifest.get('source_manifest_sha256') == evidence['source_manifest_sha256']
                 and source_manifest.get('native_project') == native_project
                 and len(source_files) == len(sources)
                 and hashlib.sha256('\n'.join(name + ':' + sources[name] for name in sorted(sources)).encode()).hexdigest()
                    == evidence['source_manifest_sha256']
                 and all(sources.get(form['source_name']) == form['source_sha256'] for form in native_project['forms']),
                 'Project package source manifest does not cover its selected forms.')
            if project_version == 2:
                need(source_manifest.get('project_id') == parent.get('project_id') == native_project['project_id']
                     and isinstance(parent.get('plan_sha256'), str) and _SHA.fullmatch(parent['plan_sha256'])
                     and source_manifest.get('plan_sha256') == parent['plan_sha256']
                     and all(sources.get(reference['name']) == reference['sha256']
                             for form in native_project['forms'] for reference in form['ddl_sources']),
                     'Mapped project package lost its original DDL or complete source-plan binding.')
                # The package's inventory retains ORIGINAL readable sources.
                # Rebuild byte hashes (including a proven UTF-8 BOM) and rerun
                # the planner instead of trusting a rehashed mapping summary.
                from .intake import checked_source
                inspection = read('evidence/normalized-forms-inventory.json')
                original_files = []
                for module in inspection['shared_inventory']['modules']:
                    source_raw = module['readable_source'].encode('utf-8')
                    if hashlib.sha256(source_raw).hexdigest() != module['sha256']:
                        source_raw = b'\xef\xbb\xbf' + source_raw
                    original = checked_source(module['file'], source_raw)
                    need(original['sha256'] == module['sha256'] == sources.get(module['file'])
                         and original['bytes'] == module['bytes'], 'Packaged original source bytes changed.')
                    original_files.append(original)
                source_plan = assess_project_conversion(original_files, project_id=native_project['project_id'],
                    project_name=native_project['project_name'], source_hash=native_project['source_manifest_sha256'])
                need(source_plan.get('state') == 'READY' and source_plan.get('rendering_spec') == native_project
                     and source_plan.get('plan_sha256') == parent['plan_sha256'],
                     'Packaged original source does not reproduce the reviewed storage plan.')
                original_snapshot = {'native_project': native_project, 'files': original_files,
                                     'source_hash': native_project['source_manifest_sha256']}
                mapped_rows, mapped_inventories = _project_inventories(inspection, original_snapshot, source_plan, evidence['job_id'])
                mapped_by_id = {row['module_id']: row for row in mapped_rows}
            forms = {form['module_id']: form for form in native_project['forms']}
            rows = parent.get('form_reviews')
            need(isinstance(rows, list) and len(rows) == len(forms)
                 and all(isinstance(row, dict) for row in rows)
                 and {row.get('module_id') for row in rows} == set(forms)
                 and evidence.get('form_reviews') == rows,
                 'Project package does not independently review every selected form.')
            expected_reviews = {'evidence/form-reviews/' + module + '.json' for module in forms}
            need({name for name in names if name.startswith('evidence/form-reviews/')} == expected_reviews,
                 'Project package form review membership differs from the selected source.')
            children = set()
            for row in rows:
                form = forms[row['module_id']]
                receipt = read('evidence/form-reviews/' + row['module_id'] + '.json')
                child = row.get('child_job_id')
                expected_child = 'fox-' + canonical_hash({'scope': 'fox-project-module-execution-v1',
                    'parent_job_id': evidence['job_id'], 'source_hash': evidence['source_manifest_sha256'],
                    'module_id': row['module_id'], 'native_form': form['native_form']})[:20]
                if project_version == 2:
                    identity = {'scope': 'fox-project-module-execution-v2',
                        'parent_job_id': evidence['job_id'], 'source_hash': evidence['source_manifest_sha256'],
                        'module_id': row['module_id'], 'native_form': form['native_form'],
                        'project_id': native_project['project_id'], 'plan_sha256': parent['plan_sha256'],
                        'storage_mapping': form['storage_mapping'], 'ddl_sources': form['ddl_sources']}
                    expected_child = 'fox-' + canonical_hash(identity)[:20]
                    execution = {'schema_version': 2, 'scope': identity['scope'],
                        'parent_job_id': evidence['job_id'], 'child_job_id': expected_child,
                        'project_id': native_project['project_id'], 'module_id': row['module_id'],
                        'source_hash': evidence['source_manifest_sha256'], 'plan_sha256': parent['plan_sha256'],
                        'source_name': form['source_name'], 'source_sha256': form['source_sha256'],
                        'native_form_sha256': canonical_hash(form['native_form']),
                        'storage_mapping': form['storage_mapping'], 'ddl_sources': form['ddl_sources']}
                    need(row.get('execution_binding') == execution,
                         'Mapped project child review has lost its source-to-storage execution binding.')
                need(isinstance(child, str) and re.fullmatch(r'fox-[a-f0-9]{20}', child)
                     and child == expected_child and child != evidence['job_id'] and child not in children,
                     'Project package child review identity is ambiguous.')
                children.add(child)
                need(sealed(receipt) and type(receipt.get('schema_version')) is int
                     and receipt['schema_version'] == 2
                     and receipt.get('trust_boundary') == 'authenticated_fox_executor_not_vendor_attestation'
                     and receipt.get('job_id') == child
                     and receipt.get('source_hash') == evidence['source_manifest_sha256']
                     and receipt.get('receipt_sha256') == row.get('receipt_sha256')
                     and receipt.get('candidate_sha256') == row.get('candidate_sha256')
                     and receipt.get('candidate_sha256') == canonical_hash(receipt.get('candidate'))
                     and receipt.get('historical_target_profile') == historical,
                     'Project child review evidence is unbound or changed.')
                _candidate(receipt['candidate'], child, form['native_form'], historical['opaf']['roles']['mapper']['model'])
                if project_version == 2:
                    request = _form_request(original_snapshot, form, mapped_by_id[row['module_id']],
                                            mapped_inventories[row['module_id']])
                    need(receipt.get('mapper_invocation', {}).get('request_sha256') == canonical_hash(request)
                         and receipt.get('reviewer_invocation', {}).get('request_sha256') == canonical_hash({
                             **request, 'candidate': receipt['candidate'], 'candidate_sha256': receipt['candidate_sha256']}),
                         'Packaged model reviews do not bind the exact original-source and storage mapping context.')
                review = receipt.get('review')
                need(isinstance(review, dict) and review.get('verdict') == 'approve'
                     and review.get('blocking_findings') == []
                     and review.get('candidate_sha256') == receipt['candidate_sha256']
                     and isinstance(receipt['candidate']['remediation_items'], list),
                     'One packaged form has unresolved independent review findings.')
                environments = receipt.get('model_environment')
                need(isinstance(environments, dict) and set(environments) == {'mapper', 'reviewer'},
                     'Project child lacks bound observed model environments.')
                for role in ('mapper', 'reviewer'):
                    validate_model_environment(environments[role], historical, role,
                        {'job_id': child, 'source_hash': receipt['source_hash']}, receipt[role + '_invocation'])
                mapper, reviewer = receipt['mapper_invocation'], receipt['reviewer_invocation']
                need(mapper.get('room_id') != reviewer.get('room_id')
                     and mapper.get('workflow_id') != reviewer.get('workflow_id')
                     and datetime.fromisoformat(reviewer['started_at_utc'].replace('Z', '+00:00'))
                     >= datetime.fromisoformat(mapper['completed_at_utc'].replace('Z', '+00:00')),
                     'Project form mapper and reviewer are not independent ordered invocations.')
            schema = read('evidence/schema-preparation.json')
            binding = schema.get('binding', {})
            need(schema.get('scope') == 'fox-native-schema-preparation-v1'
                 and evidence.get('schema_preparation_sha256') == manifest['evidence/schema-preparation.json']
                 and schema.get('record_sha256') == canonical_hash({key: value for key, value in schema.items() if key != 'record_sha256'})
                 and schema.get('all_ready') is True and schema.get('business_behavior_verified') is False
                 and schema.get('automatic_replay_permitted') is False
                 and binding.get('job_id') == evidence['job_id']
                 and binding.get('source_manifest_sha256') == evidence['source_manifest_sha256']
                 and binding.get('artifact_binding_sha256') == canonical_hash(evidence['artifact_binding'])
                 and binding.get('review_receipts_sha256') == canonical_hash(parent['form_reviews'])
                 and binding.get('validated_draft_sha256') == evidence['artifact_binding']['draft_sha256'],
                 'Project schema readiness is absent or bound to a different generation.')
            need({row['table_name'] for row in schema['tables']} == {form['native_form']['table_name'] for form in forms.values()}
                 and len(schema['tables']) == len({row['table_name'] for row in schema['tables']}),
                 'Project schema preparation does not cover every distinct table.')
            prepared_tables = {row['table_name']: row for row in schema['tables']}
            for form in forms.values():
                spec = form['native_form']; table = prepared_tables[spec['table_name']]
                contract = {key: spec[key] for key in ('profile_id', 'data_mode', 'table_name')} | {
                    'varchar_semantics': 'BYTE', 'columns': [{key: column[key] for key in
                        ('name', 'data_type', 'nullable', 'primary_key', 'identity', 'length') if key in column}
                        for column in spec['columns']]}
                need(table.get('state') in {'CREATED', 'REUSED'}
                     and table.get('bootstrap_schema_sha256') == canonical_hash(contract)
                     and isinstance(table.get('ownership_sha256'), str) and _SHA.fullmatch(table['ownership_sha256'])
                     and isinstance(table.get('object_identity'), dict), 'Project prepared table identity or schema differs.')
                if project_version == 2:
                    need(table.get('storage_mapping') == form['storage_mapping']
                         and table.get('storage_mapping_sha256') == canonical_hash(form['storage_mapping']),
                         'Project prepared table ownership differs from its complete storage identity.')
            trace = read('source-to-apex.json')
            need(trace.get('rendering_spec_sha256') == canonical_hash(native_project)
                 and trace.get('source_manifest_sha256') == native_project['source_manifest_sha256']
                 and trace.get('application_count') == 1 and trace.get('form_count') == len(forms)
                 and {row['module_id'] for row in trace['forms']} == set(forms)
                 and len(trace['forms']) == len(forms)
                 and trace.get('human_acceptance_recorded') is False
                 and evidence['artifact_binding'].get('project_trace_sha256') == manifest['source-to-apex.json']
                 and evidence.get('forms') == trace['forms'],
                 'Project source-to-APEX trace is incomplete or changed.')
            derive_project_qa_plan(native_project, manifest['native-project-spec.json'], trace, manifest['source-to-apex.json'])
            if project_version == 2:
                mappings = []
                by_table = {}
                for form in native_project['forms']:
                    table = form['native_form']['table_name']
                    item = by_table.setdefault(table, {'storage_mapping': form['storage_mapping'],
                        'ddl_sources': {}, 'module_ids': []})
                    need(item['storage_mapping'] == form['storage_mapping'], 'Shared physical table has conflicting storage identities.')
                    item['module_ids'].append(form['module_id'])
                    for reference in form['ddl_sources']:
                        prior = item['ddl_sources'].setdefault(reference['name'], reference)
                        need(prior == reference, 'Shared DDL evidence changed.')
                for table in sorted(by_table):
                    item = by_table[table]
                    mappings.append({'storage_mapping': item['storage_mapping'],
                        'ddl_sources': [item['ddl_sources'][name] for name in sorted(item['ddl_sources'])],
                        'module_ids': sorted(item['module_ids'])})
                expected_storage = {'schema_version': 1, 'scope': 'fox-project-storage-package-v1',
                    'project_id': native_project['project_id'], 'data_mode': 'synthetic_test_only',
                    'source_manifest_sha256': native_project['source_manifest_sha256'],
                    'data_migration_included': False, 'mappings': mappings}
                need(read('schema/storage-mapping.json') == expected_storage
                     and evidence.get('project_id') == native_project['project_id']
                     and evidence.get('storage_mapping_sha256') == manifest['schema/storage-mapping.json'],
                     'Project downloadable storage mapping is incomplete or changed.')
            table_specs = {form['native_form']['table_name']: form['native_form'] for form in forms.values()}
            need(archive.read('schema/01_synthetic_schema.sql') == '\n'.join(
                    _schema_sql(table_specs[name]) for name in sorted(table_specs)).encode('utf-8')
                 and all(row['schema_sql_sha256'] == hashlib.sha256(_schema_sql(table_specs[row['table_name']]).encode()).hexdigest()
                         for row in trace['tables']), 'Project schema SQL differs from its deterministic create-only contract.')
            app_id = evidence.get('application_id')
            need(type(app_id) is int and app_id > 0, 'Project package lacks one explicit imported application.')
            sql_name = 'sql/f' + str(app_id) + '.sql'
            need(sql_name in names and len(archive.read(sql_name)) >= 1000
                 and {name for name in names if name.startswith('sql/')} == {sql_name}
                 and 'apexlang/application.apx' in names and 'schema/01_synthetic_schema.sql' in names,
                 'Project package lacks actual native exports or schema.')
            completion = read('evidence/export-completion.json')
            need(completion.get('schema_version') == 1 and completion.get('job_id') == evidence['job_id']
                 and evidence.get('export_completion_sha256') == manifest['evidence/export-completion.json']
                 and completion.get('application_id') == app_id
                 and completion.get('application_alias') == evidence['application_alias']
                 and completion.get('artifact_binding') == evidence['artifact_binding']
                 and completion.get('apexlang_validation_passed') is True,
                 'Project export completion is unbound.')
            export_files = completion['files']; prefix = evidence['application_alias'].lower() + '/'
            expected_apex = {'apexlang/' + key[len(prefix):]: digest for key, digest in export_files.items() if key.startswith(prefix)}
            need(expected_apex and expected_apex == {key: value for key, value in manifest.items() if key.startswith('apexlang/')}
                 and export_files.get('f' + str(app_id) + '.sql') == manifest[sql_name]
                 and evidence.get('package_reimport', {}).get('sql_sha256') == manifest[sql_name]
                 and export_files.get('apexlang-validation.log') == manifest['evidence/export-validation.log'],
                 'Project exported bytes differ from their completion evidence.')
            imported = read('evidence/imported-application.json')
            need(imported.get('application_id') == app_id
                 and evidence.get('imported_application_sha256') == manifest['evidence/imported-application.json']
                 and all(imported.get(key) == evidence.get(key) for key in ('application_alias', 'application_url', 'artifact_binding'))
                 and imported.get('compiled_metadata_sha256') == canonical_hash({
                    key[len('apexlang/'):]: digest for key, digest in manifest.items() if key.startswith('apexlang/')})
                 and completion.get('imported_application_sha256') == manifest['evidence/imported-application.json'],
                 'Project imported application evidence is unbound.')
            reimport = read('evidence/package-reimport.json')
            need(reimport == evidence.get('package_reimport') and reimport.get('passed') is True
                 and type(reimport.get('application_id')) is int and reimport['application_id'] > 0
                 and reimport['application_id'] != app_id,
                 'Project SQL reimport is not a separate confirmed application.')
    except OpafError:
        raise
    except (ValueError, KeyError, TypeError, AttributeError, OverflowError, zipfile.BadZipFile, RuntimeError):
        raise OpafError('Project package is malformed or has invalid bound evidence; no release was accepted.') from None
    return hashlib.sha256(raw).hexdigest()


def run_native_project_job(job: Path, *, installation_projection=_NO_INSTALLATION_PROJECTION):
    """Adapter contract: save package + release evidence and return evidence.

The worker, not this adapter, owns queue/QA states. No accepted or VERIFIED
state is created by generation, a reviewer receipt, import or download.
"""
    projection = _checked_installation_projection(os.environ, installation_projection)
    if not re.fullmatch(r'fox-[a-f0-9]{20}', job.name) or job.is_symlink():
        raise OpafError('Invalid project FOX job.')
    snapshot = _json(job / 'source-snapshot.json')
    if snapshot.get('conversion_profile') != PROFILE_ID:
        raise OpafError('Project conversion profile is missing.')
    approvals = snapshot.get('approvals')
    if not isinstance(approvals, dict) or not all(approvals.get(key) is True
            for key in ('redacted_source', 'external_ai', 'synthetic_prototype')):
        raise OpafError('Recorded redaction, external AI and synthetic prototype approvals are required.')
    try:
        plan = assess_project_conversion(snapshot['files'], project_id=snapshot['project_id'],
            project_name=snapshot['project_name'], source_hash=snapshot['source_hash'])
    except (KeyError, TypeError, ValueError):
        raise OpafError('The project source version cannot be replanned safely.') from None
    if (plan['state'] != 'READY' or plan['can_generate'] is not True
            or plan['rendering_spec'] != snapshot.get('native_project')
            or plan['plan_sha256'] != snapshot.get('plan_sha256')):
        raise OpafError('The whole project is blocked or changed; no partial application will be generated.')
    progress = ProjectProgress(job, plan)
    try:
        if projection is _NO_INSTALLATION_PROJECTION:
            return _run_project(job, snapshot, plan, progress)
        return _run_project(job, snapshot, plan, progress, installation_projection=projection)
    except Exception:
        # Public text is selected from static stage messages, never an exception
        # or provider response. Do not hide the original failure if UI I/O fails.
        try:
            progress.attention()
        except (OSError, ValueError):
            pass
        raise


def _run_project(job, snapshot, plan, progress, *, installation_projection=_NO_INSTALLATION_PROJECTION):
    projection = _checked_installation_projection(os.environ, installation_projection)
    restored_generated = _restore_progress(job, snapshot, plan, progress)
    # Strict local source validation only: this does not hand off to a service.
    with tempfile.TemporaryDirectory(prefix='fox-project-preflight-') as temp:
        stage_job(job, Path(temp))
    if projection is _NO_INSTALLATION_PROJECTION:
        profile, gateway, client = _configuration()
    else:
        profile, gateway, client = _configuration(installation_projection=projection)
    _capability(gateway, snapshot['native_project'], profile)  # Before any POST.
    checkpoints = job / 'native-project-pipeline'
    if checkpoints.is_symlink():
        raise OpafError('Unsafe project checkpoint directory.')
    checkpoints.mkdir(exist_ok=True)
    _save_once(checkpoints / 'binding.json', {'schema_version': snapshot['native_project']['schema_version'], 'job_id': job.name,
        'source_hash': snapshot['source_hash'], 'profile_sha256': canonical_hash(profile),
        'plan_sha256': plan['plan_sha256'], 'native_project_sha256': canonical_hash(snapshot['native_project'])})
    if snapshot['native_project']['schema_version'] == 2:
        _target(gateway, profile, checkpoints)  # Verify the exact paired role identity before intake POST.
    _progress(job, 'preparing')
    path = '/fox/jobs/' + job.name
    state = _get_job(gateway, path)
    if state is None:
        try:
            gateway.request('POST', path, {key: snapshot[key] for key in ('source_hash', 'files',
                'conversion_profile', 'native_project', 'project_id', 'project_name', 'plan_sha256')})
        except OpafError as error:
            if error.status_code != 409:
                raise
        state = gateway.request('GET', path)
    state = _remote(state, job.name, snapshot)
    if state['state'] == 'FAILED' and state.get('import_intent_exists'):
        _progress(job, 'reconciling')
        gateway.request('POST', path + '/actions/reconcile-import', {})
        state = _remote(gateway.request('GET', path), job.name, snapshot)
    if state['state'] == 'FAILED' and state.get('schema_intent_exists') and not state.get('import_intent_exists'):
        _progress(job, 'reconciling')
        checked = gateway.request('POST', path + '/actions/reconcile-schema', {})
        if checked.get('ready_for_import') is not True:
            raise OpafError('Failed schema preparation needs operator reconciliation; no replay.')
        state = _remote(gateway.request('GET', path), job.name, snapshot)
    if state['state'] not in {'INTAKE_READY', 'INSPECTED', 'DRAFTED', 'VALID', 'IMPORTED'}:
        raise OpafError('Existing project job needs reconciliation; it will not be overwritten.')
    inspection_path = checkpoints / 'inspection.json'
    if inspection_path.exists():
        inspection = _json(inspection_path)
    elif state['state'] in {'INTAKE_READY', 'INSPECTED'}:
        _progress(job, 'inspecting')
        inspection = gateway.request('POST', path + '/actions/inspect', {})
        _save_once(inspection_path, inspection)
    else:
        raise OpafError('Project inspection checkpoint is missing; reconcile the retained job.')
    rows, inventories = _project_inventories(inspection, snapshot, plan, job.name)
    expected = {form['module_id']: form for form in snapshot['native_project']['forms']}
    form_reviews = []
    for row in rows:
        module_id = row['module_id']; form = expected[module_id]
        child_id = row['child_job_id']
        progress.active_module = module_id
        child = checkpoints / module_id
        if child.is_symlink():
            raise OpafError('Unsafe project form checkpoint directory.')
        child.mkdir(exist_ok=True)
        _save_once(child / 'binding.json', _child_checkpoint_binding(job.name, snapshot, form, row, inventories[module_id]))
        request = _form_request(snapshot, form, row, inventories[module_id])
        def target_loader():
            target = _target(gateway, profile, checkpoints)
            _save_once(child / 'target-profile.json', _json(checkpoints / 'target-profile.json'))
            return target
        # This profile has no historical v1 path: it must never invent a
        # missing environment or silently replay an unsealed old role output.
        for name in ('mapper', 'reviewer'):
            if (child / (name + '.json')).exists() and 'model_environment' not in _json(child / (name + '.json')):
                raise OpafError('Project model checkpoint lacks actual environment evidence; no replay.')
        _progress(job, 'mapping')
        if not restored_generated:
            progress.stage('mapping')
        if not restored_generated and not (child / 'mapper.json').exists():
            progress.form(module_id, 'mapping')
        candidate, mapper = _role(child, 'mapper', client, profile['mapper'], request, target_loader)
        _candidate(candidate, child_id, form['native_form'], profile['mapper']['model'])
        if not restored_generated:
            progress.form(module_id, 'mapped')
        _progress(job, 'reviewing')
        if not restored_generated:
            progress.stage('reviewing')
        if not restored_generated and not (child / 'reviewer.json').exists():
            progress.form(module_id, 'reviewing')
        review, reviewer = _role(child, 'reviewer', client, profile['reviewer'],
            {**request, 'candidate': candidate, 'candidate_sha256': canonical_hash(candidate)}, target_loader)
        if (not isinstance(review, dict) or review.get('verdict') != 'approve' or review.get('candidate_sha256') != canonical_hash(candidate)
                or review.get('blocking_findings') != []):
            raise OpafError('One form was not approved; the whole project remains blocked.')
        payload = {'job_id': child_id, 'source_hash': snapshot['source_hash'], 'candidate': candidate,
            'mapper_invocation': mapper, 'reviewer_invocation': reviewer, 'review': review,
            'model_environment': {name: _json(child / (name + '.json'))['model_environment']
                                  for name in ('mapper', 'reviewer')}}
        sealed_path = child / 'review-receipt.json'
        sealed = _json(sealed_path) if sealed_path.exists() else gateway.request(
            'POST', path + '/reviews/' + module_id, payload)
        _approved(sealed, candidate)
        _save_once(sealed_path, sealed)
        form_reviews.append({'module_id': module_id, 'receipt_sha256': sealed['receipt_sha256']})
        if not restored_generated:
            progress.form(module_id, 'reviewed')
        else:
            progress.active_module = None
    aggregate_path = checkpoints / 'review-receipt.json'
    sealed = _json(aggregate_path) if aggregate_path.exists() else gateway.request('POST', path + '/review',
        {'job_id': job.name, 'source_hash': snapshot['source_hash'], 'form_reviews': form_reviews})
    candidate = _project_candidate(sealed.get('candidate'), job.name, snapshot['native_project'], profile['mapper']['model'])
    _project_approved(sealed, candidate, plan, job.name, form_reviews)
    _save_once(aggregate_path, sealed)
    state = _remote(gateway.request('GET', path), job.name, snapshot)
    if state['state'] == 'INSPECTED':
        _progress(job, 'generating')
        progress.stage('generating')
        gateway.request('POST', path + '/actions/generate', candidate)
        state = _remote(gateway.request('GET', path), job.name, snapshot)
    # No individual form is generated until the ONE parent draft is bound to
    # the independently approved aggregate candidate. Resume rechecks this.
    generated = _generation_receipt(state, candidate, job.name)
    _save_once(checkpoints / 'generated.json', generated)
    progress.generated()
    if state['state'] == 'DRAFTED':
        _progress(job, 'validating')
        progress.stage('validating')
        gateway.request('POST', path + '/actions/validate', {})
        state = _remote(gateway.request('GET', path), job.name, snapshot)
    if state['state'] not in {'VALID', 'IMPORTED'} or (state.get('validation') or {}).get('passed') is not True:
        raise OpafError('Whole-project SQLcl validation has not passed; import remains blocked.')
    progress.stage('schema_preparing')
    schema = _prepare_schema(gateway, path, state, checkpoints, job, candidate, sealed)
    if state['state'] == 'VALID':
        progress.stage('importing')
        intent = checkpoints / 'import-intent.json'
        if intent.exists() or state.get('import_intent_exists'):
            _progress(job, 'reconciling')
            gateway.request('POST', path + '/actions/reconcile-import', {})
        else:
            _progress(job, 'importing')
            _save_once(intent, {'job_id': job.name, 'candidate_sha256': canonical_hash(candidate),
                'review_receipt_sha256': sealed['receipt_sha256'], 'schema_receipt_sha256': schema['receipt_sha256']})
            gateway.request('POST', path + '/actions/import', {})
        state = _remote(gateway.request('GET', path), job.name, snapshot)
    if state['state'] != 'IMPORTED':
        raise OpafError('Project import is unconfirmed; retained for reconciliation.')
    _save_once(checkpoints / 'imported.json', state)
    _progress(job, 'packaging')
    progress.stage('packaging')
    evidence = gateway.request('POST', path + '/release', {})
    if (not isinstance(evidence, dict) or evidence.get('job_id') != job.name
            or evidence.get('source_manifest_sha256') != snapshot['source_hash']
            or evidence.get('conversion_profile') != PROFILE_ID
            or evidence.get('reviewer_execution_verified') is not True
            or evidence.get('review_receipt_sha256') != sealed['receipt_sha256']
            or evidence.get('schema_preparation_sha256') != schema['receipt_sha256']
            or evidence.get('human_acceptance_recorded') is not False):
        raise OpafError('Project release is unbound or makes an unsupported acceptance claim.')
    imported = state.get('import')
    if (not isinstance(imported, dict) or any(evidence.get(key) != imported.get(key)
            for key in ('application_id', 'application_alias', 'application_url', 'artifact_binding'))):
        raise OpafError('Project release differs from the one confirmed imported application.')
    raw = gateway.request('GET', path + '/package', binary=True)
    target = _json(checkpoints / 'target-profile.json')['target_profile']
    digest = verify_project_package(raw, evidence, snapshot['native_project'], target)
    _store_package(job, raw, digest)
    _save_once(job / 'release-evidence.json', evidence)
    _save_once(checkpoints / 'download.json', {'package_sha256': digest, 'source_hash': snapshot['source_hash']})
    _progress(job, 'downloaded')
    progress.stage('downloaded')
    return evidence
