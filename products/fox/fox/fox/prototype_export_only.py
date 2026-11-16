"""Reviewed, offline-validated APEXlang delivery. No target DB or import calls.

This is an explicit new immutable job mode, never an upgrade of a retained run.
The ZIP preserves the renderer's project layout and exact .apx/.apex bytes.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import io
from itertools import islice
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tempfile
import time
import zipfile

from .design_provider import is_direct, roles
from .native_pipeline import _json, _save_once
from .opaf import OpafError, canonical_hash

DELIVERY_MODE = 'apexlang_package'
SCOPE = 'fox-apexlang-package-v1'
SAVED_SCOPE = 'fox-saved-apexlang-package-v1'
MAX_ZIP = 20_000_000
MAX_VALIDATION_LOG = 2_000_000
STAGES = ('mapping', 'render', 'validate', 'package')
NOT_RUN = ('schema_prepared', 'import_verified', 'runtime_verified',
           'package_reimport_passed', 'clean_schema_install_passed',
           'technically_verified', 'business_behavior_accepted')


class OfflineCompilerUnavailable(OpafError):
    """Safe actionable prerequisite error; no provider/connection details."""


def delivery_mode(selected):
    if 'delivery_mode' not in selected:
        return None
    if selected['delivery_mode'] != DELIVERY_MODE:
        raise OpafError('Unknown immutable prototype delivery mode.')
    return DELIVERY_MODE


def _telemetry_directory(job, *, create=False):
    job = Path(job)
    storage = job.parent.parent if job.parent.name == 'jobs' else job.parent
    path = storage
    for part in ('telemetry', job.name):
        path /= part
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or getattr(info, 'st_file_attributes', 0) & 0x400):
                raise OpafError('Unsafe advisory telemetry storage.')
        if create:
            path.mkdir(exist_ok=True)
    return path


def save_provider_timing(directory, role, value, identity):
    """Keep only bounded numeric metadata; no provider payloads or strings."""
    allowed = {'total_seconds', 'environment_seconds', 'before_invoke_seconds',
               'request_seconds', 'setup_seconds', 'request_preparation_seconds',
               'http_requests', 'tls_connections', 'request_body_bytes', 'response_body_bytes',
               'input_tokens', 'output_tokens', 'total_tokens'}
    if not isinstance(value, dict):
        return
    safe = {key: item for key, item in value.items() if key in allowed
            and type(item) in (int, float) and math.isfinite(item) and 0 <= item <= 10**12}
    if safe:
        directory = Path(directory).absolute()
        job = next((p for p in directory.parents if re.fullmatch(r'fox-[a-f0-9]{20}', p.name)), None)
        if job is None or role not in ('mapper', 'reviewer'):
            return
        if job.is_symlink():
            return
        path = _telemetry_directory(job, create=True)
        # Historical validators close the entire job, not only focus directories.
        key = canonical_hash({'directory': directory.relative_to(job).as_posix(), 'role': role})
        _save_once(path / (key + '.json'), {'schema_version': 1, 'scope': 'fox-provider-timing-v1',
            'job_id': identity['job_id'], 'source_binding': identity['source_hash'], 'role': role,
            **({'provider': value['provider']} if value.get('provider') in ('opaf', 'oci_genai') else {}), **safe})


def _sqlcl_path():
    configured = os.getenv('FOX_EXPORT_SQLCL_PATH') or os.getenv('F2A_SQLCL_PATH')
    found = configured or shutil.which('sql')
    if not found or not Path(found).is_file():
        raise OfflineCompilerUnavailable('Offline APEXlang validation requires SQLcl. Configure FOX_EXPORT_SQLCL_PATH and a compatible Java runtime; no database connection is required.')
    return Path(found).absolute()


def package_configuration(approved_target_sha256, *, installation_projection=None):
    """Reuse only the design provider. Never construct a converter/DB client."""
    from .prototype_job import load_prototype_profile
    from .prototype_read_scope import forbid_execution
    forbid_execution()
    from .prototype_initial_direct_read_scope import forbid_execution as forbid_initial_direct_execution
    forbid_initial_direct_execution()
    _sqlcl_path()  # Discover missing compiler before any charged design calls.
    try:
        profile_path = Path(os.environ['FOX_PROTOTYPE_PROFILE_FILE'])
        def target_loader():
            envelope = load_prototype_profile(profile_path)
            if envelope['target_profile_sha256'] != approved_target_sha256:
                raise OpafError('Package processing profile changed; fresh source-owner approval is required.')
            return envelope['target_profile']
        target = target_loader()
        direct = is_direct(target)
        if direct != (os.getenv('FOX_RUN_ADAPTER') == 'oci-genai'):
            raise OpafError('Design provider differs from the explicitly selected run adapter.')
        if direct:
            from .oci_genai import OciGenAiClient
            client = OciGenAiClient(target)
        else:
            from .opaf import OpafClient
            path = Path(os.environ['FOX_OPAF_CREDENTIAL_FILE'])
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 65_536:
                raise ValueError()
            credentials = json.loads(path.read_bytes())
            if any(not isinstance(credentials.get(key), str) or not credentials[key]
                   for key in ('username', 'password')):
                raise ValueError()
            client = OpafClient(target['opaf']['base_url'], credentials['username'],
                                credentials['password'], target['opaf']['certificate_sha256'])
        return {'profile': deepcopy(roles(target)), 'opaf_client': client,
                'target_profile_loader': target_loader}
    except (KeyError, ValueError, TypeError, OSError):
        raise OpafError('Package design-provider configuration is unavailable; no database or converter connection is required.') from None


def _members(raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_ZIP:
        raise OpafError('APEXlang project is missing or oversized.')
    files, total = {}, 0
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for info in archive.infolist():
                name = info.filename
                parts = PurePosixPath(name).parts
                total += info.file_size
                if (not parts or PurePosixPath(name).is_absolute() or '\\' in name or ':' in name
                        or any(part in ('.', '..') for part in name.split('/'))
                        or name in files or info.is_dir() or info.flag_bits & 1
                        or stat.S_ISLNK(info.external_attr >> 16) or len(files) >= 4096
                        or total > MAX_ZIP or info.file_size > MAX_ZIP):
                    raise ValueError()
                files[name] = archive.read(info)
    except (ValueError, OSError, zipfile.BadZipFile, RuntimeError):
        raise OpafError('APEXlang ZIP has unsafe or invalid members.') from None
    if 'application.apx' not in files or '.apex/apexlang.json' not in files:
        raise OpafError('APEXlang project lacks application or compiler metadata.')
    return files


def _raw(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ZIP:
        raise OpafError('Package evidence is missing, oversized or unsafe.')
    return path.read_bytes()


def validate_offline(raw, directory):
    """Real SQLcl /nolog syntax validation; never connects to Oracle."""
    from .prototype_initial_direct_read_scope import forbid_execution
    forbid_execution()
    from forms2apex.sqlcl import validate_apexlang
    files, sqlcl = _members(raw), _sqlcl_path()
    directory = Path(directory)
    if directory.is_symlink():
        raise OpafError('Unsafe offline validation storage.')
    directory.mkdir(exist_ok=True)
    # Only generated APEXlang is extracted. Supporting SQL is never executed.
    with tempfile.TemporaryDirectory(prefix='fox-apx-') as name:
        # Respect the process-private TMPDIR required by the offline SQLcl wrapper.
        # SQLcl's script/CWD live in draft.parent, also beneath this temporary root.
        project = Path(name) / 'project'
        project.mkdir()
        for member, content in files.items():
            path = project / member
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        try:
            version = subprocess.run([str(sqlcl), '-version'], capture_output=True,
                text=True, encoding='utf-8', errors='replace', timeout=30, check=False,
                cwd=project.parent)
            text = (version.stdout + '\n' + version.stderr)[:16_384]
            match = re.search(r'(?:SQLcl|SQL Developer Command Line)[^\r\n]{0,80}?(\d+\.\d+(?:\.\d+){0,5})', text, re.I)
            if version.returncode != 0 or match is None:
                raise OfflineCompilerUnavailable('SQLcl/Java version could not be observed. Check the configured offline compiler and Java runtime.')
            validated = validate_apexlang(sqlcl, project, project / 'validation.log')
            log = (project / 'validation.log').read_bytes()
        except (OSError, subprocess.SubprocessError):
            raise OfflineCompilerUnavailable('Offline SQLcl validation could not run. Check SQLcl, Java and the APEXlang compiler; no database operation was attempted.') from None
    from .prototype_pipeline import _save_bytes_once
    # Safe offline retries preserve failed logs rather than overwriting them.
    _save_bytes_once(directory / ('offline-' + hashlib.sha256(log).hexdigest() + '.log'), log)
    return {'passed': validated.get('passed') is True,
            'return_code': validated.get('return_code'), 'connection_mode': '/nolog',
            'sqlcl_version': match.group(1), 'validation_log_sha256': hashlib.sha256(log).hexdigest()}


def _compatibility(files, trace):
    try:
        config = json.loads(files['.apex/apexlang.json'])
        mmd = config['mmdVersion']
        if not isinstance(mmd, str) or not re.fullmatch(r'[0-9][A-Za-z0-9.+_-]{1,79}', mmd):
            raise ValueError()
    except (KeyError, ValueError, TypeError):
        raise OpafError('Generated APEXlang compiler metadata is invalid.') from None
    return {'mmd_version': mmd, 'mmd_source': '.apex/apexlang.json',
            'apexlang_config_sha256': hashlib.sha256(files['.apex/apexlang.json']).hexdigest(),
            'renderer_template': trace['template'],
            'target_compatibility': 'Requires a matching APEXlang compiler and compatible APEX release. Target import has not been tested.'}


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(',', ':')).encode('utf-8')


def _zip(files):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_STORED) as archive:
        for name, raw in sorted(files.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system, info.external_attr = 3, 0o100644 << 16
            archive.writestr(info, raw)
    return stream.getvalue()


def _package_contents(job, request, validation, *, saved_binding=None):
    from forms2apex.blueprint_profiles import select
    from .prototype_pipeline import _artifact_json
    root = Path(job) / 'prototype-pipeline'
    raw = _raw(root / 'candidate-apexlang.zip')
    files = _members(raw)
    profile = select(request['rendering_spec'])
    # A claimed staged ZIP cannot replace the exact native renderer output.
    if raw != profile.deterministic_prototype_zip(request['rendering_spec']):
        raise OpafError('Package candidate differs from deterministic native rendering.')
    trace = profile.prototype_trace(request['rendering_spec'])
    plan = _artifact_json(root / 'native-plan.json')
    compatibility = _compatibility(files, trace)
    focus_id = _json(root / 'review-index.json')['focuses'][0]['focus_id']
    if not isinstance(focus_id, str) or not re.fullmatch(r'focus-[a-f0-9]{24}', focus_id):
        raise OpafError('Invalid package compatibility evidence identity.')
    declared = _json(root / focus_id / 'mapper-target.json')
    compatibility['declared_target_profile'] = {
        'profile_id': declared.get('profile_id'),
        'versions': {key: declared.get('tested_versions', {})[key]
                     for key in ('apex', 'sqlcl', 'apexlang_mmd')
                     if key in declared.get('tested_versions', {})},
        'evidence': 'configuration_only_not_import_tested'}
    metadata = {'schema_version': 1, 'scope': SCOPE, 'delivery_mode': DELIVERY_MODE,
        'job_id': Path(job).name, 'project_id': request['project_id'],
        'source_binding': request['source_binding'], 'plan_sha256': request['plan_sha256'],
        'source_authority': request['source_authority'], 'candidate_sha256': hashlib.sha256(raw).hexdigest(),
        'format_validated': True, 'validation': validation, 'compatibility': compatibility,
        'prerequisites': ['Compatible APEXlang-capable SQLcl and Java.',
            'A separately authorized compatible APEX workspace and parsing schema for manual import.',
            'Review and explicitly install fox-package/supporting-schema.sql in an isolated synthetic test schema before exercising database pages.'],
        'omissions': plan['remediation'], 'data_mode': 'synthetic_test_only',
        **{key: False for key in NOT_RUN}}
    manifest = _json(root / 'sources-manifest.json')
    metadata['selected_code_scope'] = {
        'approved_chunk_hashes': manifest['selected_chunk_hashes'],
        'selected_code_unit_count': len(manifest['selected_chunk_hashes']),
        'metadata_only': not bool(manifest['selected_chunk_hashes']),
        'focus_plan_sha256': _json(root / 'binding.json')['focus_plan_sha256']}
    if saved_binding is not None:
        metadata.update(scope=SAVED_SCOPE, delivery_mode='retained_apexlang_package',
            delivery_origin='retained_reviewed_candidate',
            preparation_binding_sha256=canonical_hash(saved_binding),
            original_delivery_mode=None, legacy_run_state=saved_binding['legacy_run_state'])
    instructions = ('# FOX APEXlang package\n\n'
        'Generated and format validated only. Not imported, runtime tested, business accepted or guaranteed importable.\n'
        'One project / multiple Forms / one native APEX application. Original sources are preserved separately.\n\n'
        '## Manual handoff\n\n'
        '1. Read metadata.json and remediation.json. Confirm the exact generated MMD version and a compatible SQLcl/Java/APEX combination.\n'
        '2. Extract the whole ZIP, including .apex; retain the project layout.\n'
        '3. Offline check: start SQLcl with /nolog and run `apex validate -input "<extracted-project>"`.\n'
        '4. With separate target authority, review/install supporting-schema.sql in an isolated synthetic test schema. Never use a customer production schema.\n'
        '5. Connect to your approved workspace with a compatible SQLcl. Follow that release\'s `help apex import` instructions to import the whole project with a NEW application ID. FOX has not executed this step.\n'
        '6. Review authentication, authorization, synthetic object names, data and omitted behavior, then test each required business flow separately.\n\n'
        'Legacy triggers, packages, queries, reports and dependencies are not silently implemented. Synthetic keys/tables are prototype storage, not customer-schema facts.\n'
        'No conventional database-derived APEX SQL export is included. No database connection/import/reimport/browser acceptance was performed for this package.\n')
    additions = {'metadata.json': _json_bytes(metadata),
        'remediation.json': _json_bytes(plan['remediation']),
        'source-manifest.json': _json_bytes(_json(root / 'sources-manifest.json')),
        'source-to-page.json': _json_bytes(trace),
        'supporting-schema.sql': profile.render_prototype_schema(request['rendering_spec']).encode('utf-8'),
        'README.md': instructions.encode('utf-8')}
    if any(name.startswith('fox-package/') for name in files):
        raise OpafError('Generated package metadata collision.')
    files.update({'fox-package/' + name: content for name, content in additions.items()})
    return _zip(files), metadata


def _checked_validation(validation):
    keys = ('passed', 'return_code', 'connection_mode', 'sqlcl_version', 'validation_log_sha256')
    if (not isinstance(validation, dict) or validation.get('passed') is not True
            or validation.get('connection_mode') != '/nolog'
            or type(validation.get('return_code')) is not int or validation['return_code'] != 0
            or not isinstance(validation.get('sqlcl_version'), str)
            or not re.fullmatch(r'[A-Za-z0-9.+_-]{1,80}', validation['sqlcl_version'])
            or not isinstance(validation.get('validation_log_sha256'), str)
            or not re.fullmatch(r'[a-f0-9]{64}', validation['validation_log_sha256'])):
        raise OpafError('APEXlang offline format validation did not pass; no package was published.')
    return {key: validation[key] for key in keys}


def _validated_log(directory, validation):
    """Validate the actual retained compiler evidence, not just its digest field."""
    checked = _checked_validation(validation)
    directory = Path(directory)
    path = directory / ('offline-' + checked['validation_log_sha256'] + '.log')
    try:
        for item in (directory, path):
            info = item.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
                raise ValueError()
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or not 0 < before.st_size <= MAX_VALIDATION_LOG):
            raise ValueError()
        def identity(value):
            return tuple(getattr(value, key) for key in
                         ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns'))
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
        with os.fdopen(os.open(path, flags), 'rb') as stream:
            opened = os.fstat(stream.fileno())
            raw = stream.read(MAX_VALIDATION_LOG + 1)
            after = os.fstat(stream.fileno())
        if (len(raw) != before.st_size or identity(before) != identity(opened)
                or identity(before) != identity(after) or identity(before) != identity(path.lstat())
                or hashlib.sha256(raw).hexdigest() != checked['validation_log_sha256']):
            raise ValueError()
    except (OSError, ValueError):
        raise OpafError('Retained offline validation log is missing, unsafe, oversized or changed; no package is authorized.') from None
    return checked


def publish_package(job, request, result, *, validator=None):
    from .prototype_pipeline import authorize_prototype_request, _save_bytes_once
    root = Path(job) / 'prototype-pipeline'
    authorize_prototype_request(job, request)
    _save_once(root / 'package-request.json', request)
    path = root / 'offline-validation.json'
    binding = {'candidate_sha256': request['rendered_zip_sha256'],
               'request_sha256': canonical_hash(request), 'connection_mode': '/nolog'}
    if path.exists() or path.is_symlink():
        receipt = _json(path)
        if (receipt.get('binding') != binding
                or receipt.get('validation') != _checked_validation(receipt.get('validation'))):
            raise OpafError('Retained offline validation differs from this package.')
    else:
        validation = _checked_validation((validator or validate_offline)(
            _raw(root / 'candidate-apexlang.zip'), root))
        _validated_log(root, validation)
        receipt = {'schema_version': 1, 'binding': binding, 'validation': validation}
        _save_once(path, receipt)
    _validated_log(root, receipt['validation'])
    raw, metadata = _package_contents(job, request, receipt['validation'])
    digest = _save_bytes_once(root / 'apexlang-package.zip', raw)
    publication = {'schema_version': 1, 'scope': SCOPE, 'request_sha256': canonical_hash(request),
        'validation_sha256': canonical_hash(receipt), 'package_sha256': digest,
        'package_bytes': len(raw), 'metadata_sha256': canonical_hash(metadata)}
    _save_once(root / 'package-publication.json', publication)
    result['facts'].update(sqlcl_validated=True, native_apex_generated=True, download_ready=True)
    result.update(status='APEX_GENERATED', stage='complete', delivery_mode=DELIVERY_MODE,
        package_format='apexlang_zip', format_validated=True,
        reason='APEXlang package generated and format validated. Database import, runtime and business review were not run.',
        package_publication=publication)
    return result


def retained_package(job, snapshot, target):
    """Reconstruct owner-selected evidence before serving only the fixed ZIP."""
    from .prototype_job import validate_prototype_snapshot
    from .prototype_pipeline import authorize_prototype_request
    documents = validate_prototype_snapshot(snapshot)
    selected = snapshot['prototype']
    if (delivery_mode(selected) != DELIVERY_MODE
            or target['target_profile_sha256'] != selected['target_profile_sha256']
            or canonical_hash(target['target_profile']) != selected['target_profile_sha256']):
        raise OpafError('Package profile or source mode changed.')
    root = Path(job) / 'prototype-pipeline'
    if root.is_symlink() or root.parent.is_symlink():
        raise OpafError('Unsafe package storage.')
    binding = _json(root / 'binding.json')
    selection_keys = ('schema_version', 'max_owned_objects', 'metadata_task_policy',
                      'candidate_format_policy', 'native_input_policy', 'count_guard', 'approved_policy_id')
    if (binding.get('delivery_mode') != DELIVERY_MODE
            or binding.get('project_id') != snapshot['project_id']
            or binding.get('project_name') != snapshot['project_name']
            or binding.get('source_binding') != selected['source_binding']
            or binding.get('focus_plan_sha256') != selected['focus_plan_sha256']
            or binding.get('profile_sha256') != canonical_hash(roles(target['target_profile']))
            or any(binding.get(key) != selected.get(key) for key in selection_keys)):
        raise OpafError('Package differs from its admitted source/role binding.')
    manifest = _json(root / 'sources-manifest.json')
    if (manifest.get('selected_chunk_hashes') != selected['approved_chunk_hashes']
            or manifest.get('files') != [{'name': name, 'sha256': hashlib.sha256(raw).hexdigest(),
                'bytes': len(raw)} for name, raw in documents]):
        raise OpafError('Package differs from its admitted source bytes or code selection.')
    request = _json(root / 'package-request.json')
    authorize_prototype_request(job, request)
    for focus in _json(root / 'review-index.json')['focuses']:
        focus_id = focus['focus_id']
        if not isinstance(focus_id, str) or not re.fullmatch(r'focus-[a-f0-9]{24}', focus_id):
            raise OpafError('Invalid retained package focus identity.')
        if any(canonical_hash(_json(root / focus_id / (name + '-target.json')))
               != selected['target_profile_sha256'] for name in ('mapper', 'reviewer')):
            raise OpafError('Package invocation differs from the admitted processing profile.')
    receipt = _json(root / 'offline-validation.json')
    if (receipt.get('binding') != {'candidate_sha256': request['rendered_zip_sha256'],
            'request_sha256': canonical_hash(request), 'connection_mode': '/nolog'}
            or receipt.get('validation') != _checked_validation(receipt.get('validation'))):
        raise OpafError('Offline validation receipt is not bound or passed.')
    _validated_log(root, receipt['validation'])
    raw, metadata = _package_contents(job, request, receipt['validation'])
    publication = {'schema_version': 1, 'scope': SCOPE, 'request_sha256': canonical_hash(request),
        'validation_sha256': canonical_hash(receipt), 'package_sha256': hashlib.sha256(raw).hexdigest(),
        'package_bytes': len(raw), 'metadata_sha256': canonical_hash(metadata)}
    result = _json(Path(job) / 'prototype-result.json')
    if (_json(root / 'package-publication.json') != publication
            or result.get('package_publication') != publication
            or result.get('job_id') != Path(job).name
            or result.get('source_binding') != selected['source_binding']
            or result.get('delivery_mode') != DELIVERY_MODE or result.get('status') != 'APEX_GENERATED'
            or result.get('format_validated') is not True
            or any(result['facts'].get(key) is not False for key in NOT_RUN)
            or not all(result['facts'].get(key) is True for key in
                ('native_source_rendered', 'sqlcl_validated', 'native_apex_generated', 'download_ready'))
            or _raw(root / 'apexlang-package.zip') != raw):
        raise OpafError('Published package bytes or retained result changed.')
    return raw, metadata, publication


def saved_candidate(job, snapshot, original, target, run):
    """Reconstruct a legacy candidate without executing or rewriting its old run."""
    from .prototype_initial_direct_read_scope import initial_direct_read_scope
    with initial_direct_read_scope(job, target['target_profile']):
        return _saved_candidate(job, snapshot, original, target, run)


def _saved_candidate(job, snapshot, original, target, run):
    from .prototype_job import validate_prototype_snapshot
    from .prototype_pipeline import authorize_prototype_request, _artifact_json
    from forms2apex.blueprint_profiles import select
    job = Path(job)
    documents = validate_prototype_snapshot(snapshot)
    selected = snapshot['prototype']
    if (delivery_mode(selected) is not None or run['state'] not in ('ATTENTION', 'GENERATED')
            or run['id'] != job.name or run['project'] != snapshot['project_id']
            or run['source_hash'] != snapshot['source_hash']
            or target['target_profile_sha256'] != selected['target_profile_sha256']
            or canonical_hash(target['target_profile']) != selected['target_profile_sha256']):
        raise OpafError('Saved-output preparation requires an inactive legacy run with its original approved profile.')
    root = job / 'prototype-pipeline'
    if job.is_symlink() or root.is_symlink():
        raise OpafError('Unsafe retained candidate storage.')
    binding = _json(root / 'binding.json')
    manifest = _json(root / 'sources-manifest.json')
    index = _json(root / 'review-index.json')
    native = _artifact_json(root / 'native-plan.json')
    rendered = _artifact_json(root / 'rendered.json')
    keys = ('schema_version', 'max_owned_objects', 'metadata_task_policy', 'candidate_format_policy',
            'native_input_policy', 'count_guard', 'approved_policy_id', 'source_binding', 'focus_plan_sha256')
    if (binding.get('delivery_mode') is not None or binding.get('job_id') != job.name
            or binding.get('project_id') != snapshot['project_id']
            or binding.get('project_name') != snapshot['project_name']
            or any(binding.get(key) != selected.get(key) for key in keys)
            or binding.get('profile_sha256') != canonical_hash(roles(target['target_profile']))
            or manifest.get('selected_chunk_hashes') != selected['approved_chunk_hashes']
            or manifest.get('files') != [{'name': name, 'sha256': hashlib.sha256(raw).hexdigest(),
                'bytes': len(raw)} for name, raw in documents]):
        raise OpafError('Retained candidate differs from the original approved source selection.')
    request = {'schema_version': 1, 'scope': 'fox-prototype-converter-request-v1',
        'job_id': job.name, 'project_id': snapshot['project_id'], 'source_binding': selected['source_binding'],
        'plan_sha256': native['plan_sha256'], 'rendering_spec': native['rendering_spec'],
        'rendered_zip_sha256': rendered['zip_sha256'], 'prior_receipts': {},
        'source_authority': {'schema_version': 1, 'scope': 'fox-prototype-source-authority-v1',
            'binding_sha256': canonical_hash(binding), 'sources_manifest_sha256': canonical_hash(manifest),
            'review_index_sha256': canonical_hash(index)}}
    authorize_prototype_request(job, request)
    for focus in index['focuses']:
        focus_id = focus['focus_id']
        if not isinstance(focus_id, str) or not re.fullmatch(r'focus-[a-f0-9]{24}', focus_id):
            raise OpafError('Invalid saved-output focus identity.')
        if any(canonical_hash(_json(root / focus_id / (name + '-target.json')))
               != selected['target_profile_sha256'] for name in ('mapper', 'reviewer')):
            raise OpafError('Saved-output design was not executed against the approved profile.')
    candidate = _raw(root / 'candidate-apexlang.zip')
    if candidate != select(native['rendering_spec']).deterministic_prototype_zip(native['rendering_spec']):
        raise OpafError('Saved candidate differs from deterministic native rendering.')
    adoption = {'schema_version': 1, 'scope': 'fox-saved-apexlang-delivery-binding-v1',
        'job_id': job.name, 'project_id': snapshot['project_id'],
        'owner': snapshot['approvals']['owner'], 'snapshot_sha256': hashlib.sha256(original).hexdigest(),
        'source_hash': snapshot['source_hash'], 'source_binding': selected['source_binding'],
        'selected_source_set_id': snapshot['selected_source_set_id'],
        'candidate_sha256': hashlib.sha256(candidate).hexdigest(),
        'request_sha256': canonical_hash(request), 'legacy_run_state': run['state'],
        'legacy_run_sha256': canonical_hash(dict(run))}
    return request, adoption


def _saved_directory(job, *, create=False):
    job = Path(job)
    if job.parent.name != 'jobs' or not re.fullmatch(r'fox-[a-f0-9]{20}', job.name):
        raise OpafError('Invalid saved-output storage identity.')
    # Historical validators enumerate the entire old job. Do not add ANY member there.
    path = job.parent.parent
    for part in ('package-deliveries', job.name, 'apexlang-v1'):
        path /= part
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or getattr(info, 'st_file_attributes', 0) & 0x400):
                raise OpafError('Unsafe saved-output delivery directory.')
        if create:
            path.mkdir(exist_ok=True)
    return path


def _saved_approval(directory, adoption, *, create=False):
    path = directory / 'approval.json'
    expected = {'schema_version': 1, 'owner': adoption['owner'],
        'preparation_binding_sha256': canonical_hash(adoption), 'approved_format_only_delivery': True}
    if create and not path.exists() and not path.is_symlink():
        _save_once(path, {**expected, 'approved_at': time.time()})
    value = _json(path)
    if (set(value) != {*expected, 'approved_at'} or any(value.get(k) != v for k, v in expected.items())
            or type(value.get('approved_at')) not in (int, float)
            or not math.isfinite(value['approved_at']) or value['approved_at'] <= 0):
        raise OpafError('Saved-output explicit format-only approval is missing or changed.')


def prepare_saved_package(job, request, adoption, *, validator=None):
    """Append one explicit offline delivery; never write into the old proof tree."""
    from .prototype_pipeline import _save_bytes_once
    directory = _saved_directory(job, create=True)
    _save_once(directory / 'binding.json', adoption)
    _saved_approval(directory, adoption, create=True)
    validation_path = directory / 'validation.json'
    if validation_path.exists() or validation_path.is_symlink():
        receipt = _json(validation_path)
        if receipt.get('preparation_binding_sha256') != canonical_hash(adoption):
            raise OpafError('Saved-output validation belongs to another explicit handoff.')
    else:
        validation = _checked_validation((validator or validate_offline)(
            _raw(Path(job) / 'prototype-pipeline/candidate-apexlang.zip'), directory))
        _validated_log(directory, validation)
        receipt = {'schema_version': 1, 'scope': SAVED_SCOPE,
            'preparation_binding_sha256': canonical_hash(adoption), 'validation': validation}
        _save_once(validation_path, receipt)
    _validated_log(directory, receipt['validation'])
    raw, metadata = _package_contents(job, request, receipt['validation'], saved_binding=adoption)
    digest = _save_bytes_once(directory / 'apexlang-package.zip', raw)
    publication = {'schema_version': 1, 'scope': SAVED_SCOPE,
        'preparation_binding_sha256': canonical_hash(adoption), 'validation_sha256': canonical_hash(receipt),
        'package_sha256': digest, 'package_bytes': len(raw), 'metadata_sha256': canonical_hash(metadata)}
    _save_once(directory / 'publication.json', publication)
    return raw, metadata, publication


def read_saved_package(job, request, adoption):
    """Recheck retained log/bytes/binding without compiler or other execution."""
    directory = _saved_directory(job)
    if _json(directory / 'binding.json') != adoption:
        raise OpafError('Saved-output owner, source, candidate or original run changed.')
    _saved_approval(directory, adoption)
    receipt = _json(directory / 'validation.json')
    if (receipt.get('scope') != SAVED_SCOPE
            or receipt.get('preparation_binding_sha256') != canonical_hash(adoption)):
        raise OpafError('Saved-output validation does not match this handoff.')
    _validated_log(directory, receipt['validation'])
    raw, metadata = _package_contents(job, request, receipt['validation'], saved_binding=adoption)
    publication = {'schema_version': 1, 'scope': SAVED_SCOPE,
        'preparation_binding_sha256': canonical_hash(adoption), 'validation_sha256': canonical_hash(receipt),
        'package_sha256': hashlib.sha256(raw).hexdigest(), 'package_bytes': len(raw),
        'metadata_sha256': canonical_hash(metadata)}
    if _json(directory / 'publication.json') != publication or _raw(directory / 'apexlang-package.zip') != raw:
        raise OpafError('Saved-output package or publication changed.')
    return raw, metadata, publication


def _timing_summary(job, selected):
    """Bounded advisory metadata only; missing/corrupt telemetry never gates proof."""
    unavailable = {'available': False, 'scope': 'fox-provider-timing-summary-v1'}
    try:
        path = _telemetry_directory(job)
        if path.is_symlink() or not path.is_dir():
            return unavailable
        paths = list(islice(path.glob('*.json'), 129))
        if len(paths) > 128:
            return unavailable
        totals, count = {}, 0
        for item in paths:
            if item.is_symlink() or not item.is_file() or item.stat().st_size > 4096:
                return unavailable
            value = json.loads(item.read_bytes())
            if (value.get('scope') != 'fox-provider-timing-v1' or value.get('job_id') != Path(job).name
                    or value.get('source_binding') != selected['source_binding']
                    or value.get('role') not in ('mapper', 'reviewer')):
                return unavailable
            for key in ('total_seconds', 'environment_seconds', 'before_invoke_seconds', 'request_seconds'):
                number = value.get(key)
                if type(number) in (int, float) and math.isfinite(number) and 0 <= number <= 10**12:
                    totals[key] = totals.get(key, 0) + number
            count += 1
        return {'available': bool(count), 'scope': 'fox-provider-timing-summary-v1',
                'provider_calls': count, **totals}
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError, OpafError):
        return unavailable


def package_progress(metadata, job, result, binding, selected):
    """Cheap retained-stage observations, not permission or technical verification."""
    if binding.get('delivery_mode') != DELIVERY_MODE:
        raise ValueError('Package progress mode changed.')
    root = Path(job) / 'prototype-pipeline'
    result['timing'] = _timing_summary(job, selected)
    rendered = None
    receipt = None
    if metadata.exists(root / 'review-index.json'):
        index = metadata.read(root / 'review-index.json')
        if index.get('source_binding') != selected['source_binding']:
            raise ValueError('Package review source changed.')
        result['stages'][0]['status'] = 'recorded'
    if metadata.exists(root / 'rendered.json'):
        rendered = metadata.read(root / 'rendered.json')
        if (rendered.get('source_binding') != selected['source_binding']
                or result['stages'][0]['status'] != 'recorded'):
            raise ValueError('Package rendered source changed.')
        result['stages'][1]['status'] = 'recorded'
    if metadata.exists(root / 'offline-validation.json'):
        receipt = metadata.read(root / 'offline-validation.json')
        request = metadata.read(root / 'package-request.json')
        if (rendered is None or request.get('job_id') != Path(job).name
                or request.get('source_binding') != selected['source_binding']
                or request.get('rendered_zip_sha256') != rendered['zip_sha256']
                or request.get('plan_sha256') != rendered['plan_sha256']
                or receipt.get('binding') != {'candidate_sha256': rendered['zip_sha256'],
                    'request_sha256': canonical_hash(request), 'connection_mode': '/nolog'}
                or receipt.get('validation') != _checked_validation(receipt.get('validation'))):
            raise ValueError('Package validation not recorded.')
        result['stages'][2]['status'] = 'recorded'
        _validated_log(root, receipt['validation'])
    if metadata.exists(root / 'package-publication.json'):
        publication = metadata.read(root / 'package-publication.json')
        if (receipt is None or publication.get('scope') != SCOPE
                or publication.get('request_sha256') != receipt['binding']['request_sha256']
                or publication.get('validation_sha256') != canonical_hash(receipt)):
            raise ValueError('Package publication not recorded.')
        result['stages'][3]['status'] = 'recorded'
    pending = next((row for row in result['stages'] if row['status'] != 'recorded'), None)
    if pending is not None:
        result['current_stage'] = pending['id']
        if result['state'] in ('PROCESSING', 'ATTENTION'):
            pending['status'] = 'working' if result['state'] == 'PROCESSING' else 'attention'
        result['message'] = 'Preparing the reviewed APEXlang package. Database import and runtime tests are not part of this delivery.'
    else:
        result['message'] = 'APEXlang package generated and format validated. Import, runtime and business review were not run.'
    metadata.unchanged()
    result['progress_available'] = True
    return result
