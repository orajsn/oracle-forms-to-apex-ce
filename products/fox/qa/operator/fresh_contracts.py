"""Pure fresh-install document consistency, never admission or execution.

Callers supply a plain dictionary of canonical absolute paths to already-read
bytes. No reference is opened here. A consistent declaration does not prove
that files, images, containers, schema initialization or live observations exist.
Legacy C1/C2/R1-R3 and migration validators are deliberately not changed.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
from pathlib import PurePosixPath
import re

from fox.installation import bind_projection, converter_port, parse_projection
from forms2apex.target_profile import validate_target_profile, target_profile_sha256
from . import fresh_storage


MAX_DOCUMENT_BYTES = 2_000_000
MAX_ARTIFACTS = 64
MAX_ARTIFACT_BYTES = 16_000_000
SCOPES = {
    'provider': 'fox-fresh-hosted-runtime-v3',
    'release': 'fox-fresh-product-verifier-release-v4',
    'backend': 'fox-fresh-backend-initialization-v1',
    'admission': 'fox-fresh-deployment-v2',
    'installation': 'fox-fresh-product-verifier-installation-v2',
    'transition': 'fox-fresh-live-admission-v1',
}
ROLES = ('fox', 'converter', 'opaf')
PROJECT_MAPPING = {'native_project_schema_versions': [1, 2],
                   'storage_mapping_scope': 'fox-project-storage-v1',
                   'module_execution_scope': 'fox-project-module-execution-v2'}
IDENTITY_SOURCES = ('forms2apex/__init__.py', 'forms2apex/config.py',
                    'forms2apex/target_profile.py', 'forms2apex/oci_identity.py')
MODULES = ('verification_queue.py', 'verification_runtime.py', 'native_verification.py',
           'native_verification_policy.py', 'app.py', 'storage.py', 'installation.py',
           'backend_storage.py', 'fresh_startup.py', 'worker.py', 'worker_observability.py')
CODE = ('product_verifier.py', 'product_queue_transport.py', 'runtime_provider.py',
        'hosted_service.py', 'failed_verification.py', 'fresh_storage.py',
        'fresh_contracts.py', 'fresh_connected.py', 'fresh_remote.py', 'fresh_backend.py', 'fresh_image.py')
PROJECT_MODULES = ('intake.py', 'native_source.py', 'opaf.py', 'native_pipeline.py',
    'native_verification_policy.py', 'native_verification.py', 'native_qa_plan.py',
    'project_conversion.py', 'project_qa_plan.py', 'project_progress.py',
    'native_project_pipeline.py', 'source_history.py', 'project_verification.py',
    'project_verification_runtime.py', 'app.py', 'storage.py', 'installation.py',
    'backend_storage.py', 'fresh_startup.py', 'worker.py', 'worker_observability.py')
QUEUE_MODULES = ('technical_release.py', 'verification_recovery.py')
PROJECT_HASHES = ('clean_operator_code_sha256', 'qa_source_sha256',
                  'promotion_transport_sha256', 'operator_code_sha256')
INITIAL_COUNTS = {name: (1 if name in ('events', 'fox_storage_identity') else 0) for name in (
    'projects', 'sources', 'sessions', 'attempts', 'runs', 'events', 'acceptances',
    'prepared_uploads', 'source_sets', 'source_set_members', 'project_source_selection',
    'fox_storage_identity', 'verification_queue', 'verification_operator_contact',
    'verification_failed_dispositions', 'verification_retry_attempts',
    'verification_retry_events', 'verification_producer_observations')}
PUBLIC_FILENAMES = {'projection_filename': 'projection.json',
    'backend_filename': 'backend-initialization.json', 'admission_filename': 'live-admission.json'}
_SHA = re.compile(r'[a-f0-9]{64}\Z')
_ID = re.compile(r'fst-[a-f0-9]{32}\Z')
_NAME = re.compile(r'[a-z0-9][a-z0-9_.-]{0,62}\Z')


class FreshContractError(ValueError):
    """Closed codes only; submitted values and secret locations are not echoed."""


def need(condition, code):
    if not condition:
        raise FreshContractError(code)


def _tree(value):
    pending, nodes = [(value, 0)], 0
    while pending:
        item, depth = pending.pop(); nodes += 1
        need(nodes <= 20000 and depth <= 32, 'DOCUMENT_STRUCTURE_BOUND')
        if type(item) is dict:
            need(all(type(key) is str and len(key) <= 256 for key in item), 'DOCUMENT_KEY_INVALID')
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            need(len(item) <= 8192 and not any(ord(c) < 32 for c in item), 'DOCUMENT_STRING_INVALID')
        elif type(item) is int:
            need(-(2**63) <= item < 2**63, 'DOCUMENT_INTEGER_BOUND')
        else:
            need(type(item) in (bool, type(None)), 'DOCUMENT_VALUE_INVALID')


def canonical(value):
    _tree(value)
    try:
        return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                           allow_nan=False) + '\n').encode('utf-8')
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise FreshContractError('DOCUMENT_ENCODING_INVALID') from None


def digest(raw):
    need(type(raw) is bytes, 'BYTE_DIGEST_REQUIRED')
    return hashlib.sha256(raw).hexdigest()


def _hash(value):
    return type(value) is str and _SHA.fullmatch(value) is not None


def _keys(value, fields, code):
    need(type(value) is dict and set(value) == set(fields), code)


def _same(a, b):
    return canonical(a) == canonical(b)


def _path(value, *, internal=False):
    need(type(value) is str and 1 < len(value) <= 1024
         and re.fullmatch(r'/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', value), 'CANONICAL_POSIX_PATH_REQUIRED')
    path = PurePosixPath(value)
    need(str(path) == value and '..' not in path.parts and '.' not in path.parts
         and len(path.parts) >= (2 if internal else 4), 'CANONICAL_POSIX_PATH_REQUIRED')
    return path


def _overlap(a, b):
    a, b = PurePosixPath(a), PurePosixPath(b)
    return a == b or a in b.parents or b in a.parents


def _outside(path, roots):
    return all(not _overlap(path, root) for root in roots)


def _ref(value):
    _keys(value, ('path', 'sha256'), 'REFERENCE_FIELDS_INVALID')
    _path(value['path']); need(_hash(value['sha256']), 'REFERENCE_HASH_INVALID')
    return dict(value)


def _utc(value):
    need(type(value) is str and re.fullmatch(
        r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|\+00:00)', value), 'UTC_TIMESTAMP_REQUIRED')
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise FreshContractError('UTC_TIMESTAMP_INVALID') from None


def _loopback(value):
    try:
        return converter_port(value)
    except ValueError:
        raise FreshContractError('LOOPBACK_ENDPOINT_INVALID') from None


def _header(value, version, scope, *, fresh=True):
    need(type(value.get('schema_version')) is int and value['schema_version'] == version
         and value.get('scope') == scope, 'DOCUMENT_HEADER_INVALID')
    if fresh:
        need(value.get('installation_mode') == 'fresh', 'EXPLICIT_FRESH_MODE_REQUIRED')


def _parse(raw, *, canonical_required=True):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_DOCUMENT_BYTES, 'DOCUMENT_BYTE_BOUND')
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'DUPLICATE_DOCUMENT_KEY'); result[key] = value
        return result
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(FreshContractError('NONFINITE_DOCUMENT_VALUE')))
        need(type(value) is dict, 'DOCUMENT_OBJECT_REQUIRED')
        _tree(value)
        need(not canonical_required or canonical(value) == raw, 'CANONICAL_DOCUMENT_REQUIRED')
        return value
    except FreshContractError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise FreshContractError('DOCUMENT_JSON_INVALID') from None


class _Documents:
    def __init__(self, artifacts):
        need(type(artifacts) is dict and 0 < len(artifacts) <= MAX_ARTIFACTS, 'PLAIN_ARTIFACT_DICTIONARY_REQUIRED')
        total = 0
        for path, raw in artifacts.items():
            _path(path)
            need(type(raw) is bytes and 0 < len(raw) <= MAX_DOCUMENT_BYTES, 'ARTIFACT_BYTE_BOUND')
            total += len(raw)
        need(total <= MAX_ARTIFACT_BYTES, 'ARTIFACT_SET_TOO_LARGE')
        self.artifacts, self.used, self.anchors = dict(artifacts), {}, {}

    def read(self, reference, *, anchor=None, canonical_required=True):
        ref = _ref(reference)
        need(ref['path'] in self.artifacts, 'UNRESOLVED_REFERENCE')
        raw = self.artifacts[ref['path']]
        need(digest(raw) == ref['sha256'], 'REFERENCE_BYTES_CHANGED')
        need(ref['path'] not in self.used or self.used[ref['path']] == ref['sha256'], 'REFERENCE_REBOUND')
        if anchor is not None:
            need(anchor not in self.anchors or self.anchors[anchor] == ref['path'], 'ANCHOR_REBOUND')
            need(all(name == anchor or path != ref['path'] for name, path in self.anchors.items()),
                 'SELF_OR_CYCLIC_REFERENCE')
            self.anchors[anchor] = ref['path']
        self.used[ref['path']] = ref['sha256']
        return _parse(raw, canonical_required=canonical_required)


def _hash_map(value, fields, code):
    _keys(value, fields, code)
    need(all(_hash(item) for item in value.values()), code)


def _storage(docs, value):
    _keys(value, ('installation_id', 'plan', 'completion'), 'STORAGE_REFERENCE_FIELDS_INVALID')
    need(type(value['installation_id']) is str and _ID.fullmatch(value['installation_id']), 'INSTALLATION_ID_INVALID')
    plan = docs.read(value['plan'], anchor='storage_plan')
    try:
        plan = fresh_storage._plan(plan, value['plan']['sha256'])  # This existing validator is pure.
    except fresh_storage.FreshStorageError:
        raise FreshContractError('FRESH_STORAGE_PLAN_INVALID') from None
    completed = docs.read(value['completion'], anchor='storage_completion')
    _keys(completed, ('scope', 'installation_id', 'plan_sha256', 'intent_sha256', 'roots_sha256',
                      'schema_observation_sha256', 'completed_at_utc'), 'STORAGE_COMPLETION_FIELDS_INVALID')
    need(completed['scope'] == 'fox-fresh-storage-completion-v1'
         and completed['installation_id'] == value['installation_id']
         and completed['plan_sha256'] == value['plan']['sha256']
         and all(_hash(completed[key]) for key in ('intent_sha256', 'roots_sha256', 'schema_observation_sha256')),
         'STORAGE_COMPLETION_BINDING_CHANGED')
    _utc(completed['completed_at_utc'])
    need(value['completion']['path'] == str(PurePosixPath(plan['roots']['records']) / 'complete.json'),
         'STORAGE_COMPLETION_LOCATION_CHANGED')
    return plan, completed


def _mounts(value):
    need(type(value) is list and 1 <= len(value) <= 8, 'MOUNT_LIST_BOUND')
    destinations = set()
    for mount in value:
        _keys(mount, ('source', 'destination', 'read_only'), 'MOUNT_FIELDS_INVALID')
        _path(mount['source']); _path(mount['destination'], internal=True)
        need(type(mount['read_only']) is bool and mount['destination'] not in destinations,
             'MOUNT_MODE_OR_DESTINATION_INVALID')
        destinations.add(mount['destination'])
    return {mount['destination']: mount for mount in value}


def _runtime(value, config, storage_plan, projection):
    _keys(value, ('roles', 'converter_endpoint', 'qa', 'public_configuration', 'settings',
                  'opaf_profile', 'target_profile'), 'RUNTIME_FIELDS_INVALID')
    need(value['converter_endpoint'] == projection['converter_endpoint'], 'CONVERTER_ENDPOINT_BINDING_CHANGED')
    _loopback(value['converter_endpoint'])
    public = value['public_configuration']
    _keys(public, ('directory', *PUBLIC_FILENAMES), 'PUBLIC_CONFIGURATION_FIELDS_INVALID')
    public_root = _path(public['directory'])
    need(all(public[key] == expected for key, expected in PUBLIC_FILENAMES.items()), 'PUBLIC_FILENAMES_INVALID')
    need(config['app_projection']['path'] == str(public_root / public['projection_filename']),
         'PROJECTION_LOCATION_CHANGED')
    _keys(value['qa'], ('root', 'base_image'), 'QA_LAYOUT_FIELDS_INVALID')
    qa_root = _path(value['qa']['root'])
    need(PurePosixPath(config['state_root']) in qa_root.parents and _image(value['qa']['base_image']), 'QA_LAYOUT_INVALID')
    _keys(value['settings'], ('conversion_profile', 'data_mode', 'fox_origin'), 'STATIC_SETTINGS_FIELDS_INVALID')
    need(value['settings']['conversion_profile'] == 'native-project-v1'
         and value['settings']['data_mode'] == 'synthetic_test_only', 'STATIC_SETTINGS_INVALID')
    _loopback(value['settings']['fox_origin'])
    need(value['settings']['fox_origin'] != value['converter_endpoint'], 'LISTENER_COLLISION')
    _keys(value['roles'], ROLES, 'EXACT_RUNTIME_ROLES_REQUIRED')
    seen_names, maps = set(), {}
    for role in ROLES:
        item = value['roles'][role]
        _keys(item, ('name', 'image', 'user', 'read_only_rootfs', 'mounts'), 'RUNTIME_ROLE_FIELDS_INVALID')
        need(type(item['name']) is str and _NAME.fullmatch(item['name']) and item['name'] not in seen_names,
             'RUNTIME_ROLE_NAME_INVALID')
        seen_names.add(item['name'])
        need(_image(item['image']) and type(item['read_only_rootfs']) is bool, 'RUNTIME_ROLE_IMAGE_OR_ROOTFS_INVALID')
        need(type(item['user']) is str and re.fullmatch(r'(?:0|[1-9][0-9]{0,9})(?::(?:0|[1-9][0-9]{0,9}))?', item['user'])
             and all(int(part) < 2**31 for part in item['user'].split(':')), 'RUNTIME_USER_INVALID')
        if role != 'opaf':
            need(int(item['user'].split(':')[0]) > 0 and item['image'] == config['images'][role], 'UNPRIVILEGED_IMAGE_ROLE_REQUIRED')
            need(item['name'].startswith('fox-fresh-' if role == 'fox' else 'forms2apex-fresh-'),
                 'FRESH_ROLE_MUST_NOT_REPLACE_LEGACY_NAME')
        maps[role] = _mounts(item['mounts'])
    need(value['roles']['fox']['read_only_rootfs'] is True, 'FOX_READ_ONLY_ROOTFS_REQUIRED')
    fox, converter = maps['fox'], maps['converter']
    need(set(fox) == {'/data', '/run/fox-installation', '/run/fox-native/profile.json', '/run/fox-opaf'}
         and set(converter) == {'/opt/forms2apex/outputs/jobs', '/run/fox-installation', '/run/fox-target/profile.json',
              '/opt/sqlcl', '/opt/forms2apex/wallet', '/home/converter/.dbtools'}
         and set(maps['opaf']) == {'/mount'}, 'ROLE_MOUNT_DESTINATIONS_INVALID')
    required = ((fox, '/data', storage_plan['roots']['fox_data'], False),
        (converter, '/opt/forms2apex/outputs/jobs', storage_plan['roots']['converter_jobs'], False),
        (fox, '/run/fox-installation', str(public_root), True),
        (converter, '/run/fox-installation', str(public_root), True),
        (fox, '/run/fox-native/profile.json', value['opaf_profile']['path'], True),
        (converter, '/run/fox-target/profile.json', value['target_profile']['path'], True))
    for mounts, destination, source, readonly in required:
        need(mounts[destination] == {'source': source, 'destination': destination, 'read_only': readonly},
             'ROLE_MOUNT_BINDING_CHANGED')
    need(fox['/run/fox-opaf']['read_only'] is True
         and all(converter[name]['read_only'] is True for name in ('/opt/sqlcl', '/opt/forms2apex/wallet'))
         and converter['/home/converter/.dbtools']['read_only'] is False, 'PROTECTED_MOUNT_POLICY_INVALID')
    expected_public = sorted({mount['source'] for mount in fox.values()})
    need(config['public_mount_roots'] == expected_public, 'PUBLIC_MOUNT_DECLARATION_CHANGED')
    all_mounts = [mount['source'] for group in maps.values() for mount in group.values()]
    readonly_sources = [mount['source'] for group in maps.values() for mount in group.values() if mount['read_only']]
    writable_sources = [mount['source'] for group in maps.values() for mount in group.values() if not mount['read_only']]
    need(all(_outside(source, writable_sources) for source in readonly_sources), 'READ_ONLY_MOUNT_HAS_WRITABLE_ALIAS')
    private_roots = [config['state_root'], storage_plan['roots']['records'], config['admin_secret_file']]
    need(all(_outside(path, all_mounts) for path in private_roots), 'PRIVATE_PATH_EXPOSED_BY_MOUNT')
    need(_outside(config['admin_secret_file'], [config['state_root'], storage_plan['roots']['records']]),
         'ADMIN_SECRET_OVERLAPS_STATE')
    source_root = PurePosixPath(config['converter_root']).parent
    need(_outside(public_root, [source_root, *storage_plan['roots'].values()])
         and all(_outside(path, [source_root]) for path in (*private_roots, *storage_plan['roots'].values())),
         'RUNTIME_ROOTS_OVERLAP')
    need(_outside(config['python']['path'], all_mounts), 'OPERATOR_PYTHON_EXPOSED_BY_MOUNT')
    return all_mounts


def _image(value):
    return type(value) is str and re.fullmatch(r'sha256:[a-f0-9]{64}', value) is not None


def _profile_documents(docs, config):
    runtime = config['runtime']
    _keys(runtime, ('roles', 'converter_endpoint', 'qa', 'public_configuration', 'settings',
                    'opaf_profile', 'target_profile'), 'RUNTIME_FIELDS_INVALID')
    for key in ('opaf_profile', 'target_profile'):
        _ref(runtime[key])
        need(_outside(runtime[key]['path'], [PurePosixPath(config['converter_root']).parent]),
             'FRESH_PROFILE_MUST_REMAIN_OUTSIDE_SOURCE')
    target_file = docs.read(runtime['target_profile'], anchor='target_profile', canonical_required=False)
    need(_same(target_file, config['target_profile']), 'MOUNTED_TARGET_PROFILE_CHANGED')
    opaf_file = docs.read(runtime['opaf_profile'], anchor='opaf_profile', canonical_required=False)
    target = config['target_profile']['opaf']
    expected = {'schema_version': 2, 'profile_id': 'native-project-v1', **PROJECT_MAPPING,
        'opaf_base_url': target['base_url'], 'certificate_sha256': target['certificate_sha256'],
        **target['roles']}
    need(_same(opaf_file, expected), 'MOUNTED_OPAF_PROFILE_CHANGED')


def _provider(docs, reference):
    config = docs.read(reference, anchor='provider')
    _keys(config, ('schema_version', 'scope', 'installation_mode', 'owner_uid', 'provider_sha256',
        'target_profile', 'target_profile_sha256', 'python', 'converter_root', 'converter_sources',
        'state_root', 'admin_secret_file', 'public_mount_roots', 'images', 'storage', 'app_projection', 'runtime'),
        'PROVIDER_FIELDS_INVALID')
    _header(config, 3, SCOPES['provider'])
    need(type(config['owner_uid']) is int and 0 < config['owner_uid'] < 2**31 and _hash(config['provider_sha256']), 'PROVIDER_OWNER_OR_SOURCE_INVALID')
    try:
        target = validate_target_profile(config['target_profile'])
        need(target_profile_sha256(target) == config['target_profile_sha256'], 'TARGET_PROFILE_BINDING_CHANGED')
        need(_same(target['scope'].get('project_mapping'), PROJECT_MAPPING), 'REGISTERED_PROJECT_MAPPING_REQUIRED')
    except FreshContractError:
        raise
    except (ValueError, TypeError, KeyError):
        raise FreshContractError('REGISTERED_JSN_TARGET_REQUIRED') from None
    storage_plan, completed = _storage(docs, config['storage'])
    need(storage_plan['owner_uid'] == config['owner_uid']
         and config['state_root'] == storage_plan['roots']['operator_state'], 'STORAGE_OWNER_OR_STATE_BINDING_CHANGED')
    projection_ref = _ref(config['app_projection'])
    docs.read(projection_ref, anchor='projection')
    try:
        projection = parse_projection(docs.artifacts[projection_ref['path']], expected_sha256=projection_ref['sha256'])
        projection = bind_projection(projection, installation_id=config['storage']['installation_id'],
            storage_plan_sha256=config['storage']['plan']['sha256'], storage_completion_sha256=config['storage']['completion']['sha256'])
    except ValueError:
        raise FreshContractError('APP_PROJECTION_BINDING_CHANGED') from None
    _keys(config['images'], ('fox', 'converter'), 'PAIRED_IMAGES_REQUIRED')
    need(all(_image(value) for value in config['images'].values()), 'PAIRED_IMAGES_INVALID')
    _keys(config['python'], ('path', 'sha256', 'version'), 'PYTHON_REFERENCE_FIELDS_INVALID')
    _path(config['python']['path'])
    need(_hash(config['python']['sha256']) and type(config['python']['version']) is list
         and len(config['python']['version']) == 3 and all(type(v) is int and 0 <= v <= 999 for v in config['python']['version'])
         and config['python']['version'][0] == 3 and config['python']['version'][1] >= 11, 'PYTHON_REFERENCE_INVALID')
    for name in ('converter_root', 'state_root', 'admin_secret_file'):
        _path(config[name])
    need(PurePosixPath(config['converter_root']).name == 'converter', 'CONVERTER_SOURCE_ROOT_REQUIRED')
    _hash_map(config['converter_sources'], IDENTITY_SOURCES, 'IDENTITY_SOURCE_FIELDS_INVALID')
    _profile_documents(docs, config)
    mounts = _runtime(config['runtime'], config, storage_plan, projection)
    need(_outside(reference['path'], [PurePosixPath(config['converter_root']).parent, *mounts]), 'PROVIDER_MUST_NOT_BE_APP_MOUNTED')
    need(_outside(config['storage']['plan']['path'], [PurePosixPath(config['converter_root']).parent, *mounts]),
         'STORAGE_PLAN_MUST_REMAIN_PRIVATE_CONFIGURATION')
    return config, storage_plan, completed


def _layout(docs, layout, config):
    _keys(layout, ('release_root', 'inventory'), 'LAYOUT_FIELDS_INVALID')
    root = _path(layout['release_root'])
    need(root == PurePosixPath(config['converter_root']).parent, 'RELEASE_ROOT_BINDING_CHANGED')
    inventory = docs.read(layout['inventory'], anchor='inventory')
    _keys(inventory, ('schema_version', 'scope', 'files'), 'SOURCE_INVENTORY_FIELDS_INVALID')
    _header(inventory, 1, 'fox-hosted-source-inventory-v1', fresh=False)
    need(type(inventory['files']) is dict and 0 < len(inventory['files']) <= 10000, 'SOURCE_INVENTORY_BOUND')
    for name, value in inventory['files'].items():
        p = PurePosixPath(name) if type(name) is str else None
        need(p is not None and not p.is_absolute() and str(p) == name and '..' not in p.parts and '\\' not in name
             and re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', name)
             and '__pycache__' not in p.parts and _hash(value), 'SOURCE_INVENTORY_MEMBER_INVALID')
    need(_outside(layout['inventory']['path'], [root]), 'INVENTORY_MUST_REMAIN_OUTSIDE_SOURCE')
    _private_reference(layout['inventory'], config)
    return inventory['files']


def _release(docs, reference, provider_reference, layout):
    config, storage_plan, completed = _provider(docs, provider_reference)
    release = docs.read(reference, anchor='release')
    _keys(release, ('schema_version', 'scope', 'installation_mode', 'enabled', 'images', 'modules', 'code',
        'clean_operator_code_sha256', 'qa_source_sha256', 'promotion_transport_sha256', 'native_profile_sha256',
        'target', 'project', 'hosted_runtime_configuration_sha256', 'opaf_profile'), 'RELEASE_FIELDS_INVALID')
    _header(release, 4, SCOPES['release'])
    need(type(release['enabled']) is bool and release['enabled'] is True
         and _same(release['images'], config['images'])
         and release['hosted_runtime_configuration_sha256'] == provider_reference['sha256'], 'RELEASE_PROVIDER_BINDING_CHANGED')
    _hash_map(release['modules'], MODULES, 'RELEASE_MODULE_FIELDS_INVALID')
    _hash_map(release['code'], CODE, 'RELEASE_CODE_FIELDS_INVALID')
    for name in ('clean_operator_code_sha256', 'qa_source_sha256', 'promotion_transport_sha256', 'native_profile_sha256'):
        need(_hash(release[name]), 'RELEASE_DIGEST_INVALID')
    target = config['target_profile']
    expected_target = {**target['oci'], 'db_name': target['database']['db_name']}
    need(_same(release['target'], expected_target), 'RELEASE_TARGET_CHANGED')
    profile = release['opaf_profile']
    _keys(profile, ('path', 'sha256', 'target_profile_sha256'), 'RELEASE_OPAF_REFERENCE_INVALID')
    need({key: profile[key] for key in ('path', 'sha256')} == config['runtime']['opaf_profile']
         and profile['sha256'] == release['native_profile_sha256']
         and profile['target_profile_sha256'] == config['target_profile_sha256'], 'RELEASE_OPAF_BINDING_CHANGED')
    project = release['project']
    _keys(project, (*PROJECT_HASHES, 'modules', 'queue_modules'), 'PROJECT_RELEASE_FIELDS_INVALID')
    need(all(_hash(project[name]) for name in PROJECT_HASHES), 'PROJECT_RELEASE_DIGEST_INVALID')
    _hash_map(project['modules'], PROJECT_MODULES, 'PROJECT_MODULE_FIELDS_INVALID')
    _hash_map(project['queue_modules'], QUEUE_MODULES, 'PROJECT_QUEUE_FIELDS_INVALID')
    need(all(project['modules'][name] == release['modules'][name] for name in set(MODULES) & set(PROJECT_MODULES)),
         'SHARED_SOURCE_BINDING_CHANGED')
    inventory = _layout(docs, layout, config)
    # Check each declaration independently: a later map must not overwrite an
    # inconsistent earlier declaration of the same source file.
    groups = ({'qa/operator/' + name: value for name, value in release['code'].items()},
        {'fox/fox/' + name: value for name, value in release['modules'].items()},
        {'fox/fox/' + name: value for name, value in project['modules'].items()},
        {'fox/fox/' + name: value for name, value in project['queue_modules'].items()},
        {'converter/' + name: value for name, value in config['converter_sources'].items()},
        storage_plan['source_sha256'])
    need(all(inventory.get(name) == value for group in groups for name, value in group.items())
         and release['code']['runtime_provider.py'] == config['provider_sha256'], 'DECLARED_SOURCE_CLOSURE_CHANGED')
    _private_reference(reference, config)
    return config, storage_plan, completed, release


def _private_reference(reference, config):
    roots = [mount['source'] for role in config['runtime']['roles'].values() for mount in role['mounts']]
    need(_outside(reference['path'], [PurePosixPath(config['converter_root']).parent, *roots]),
         'PRIVATE_DECLARATION_EXPOSED_BY_MOUNT')


def _backend(docs, reference, provider_reference, release_reference, layout):
    config, storage_plan, storage_completion, release = _release(docs, release_reference, provider_reference, layout)
    value = docs.read(reference, anchor='backend')
    _keys(value, ('schema_version', 'scope', 'installation_id', 'storage_plan_sha256', 'storage_completion_sha256',
        'app_projection_sha256', 'provider_configuration_sha256', 'release_sha256', 'intent_sha256',
        'backend_schema_sha256', 'initial_counts', 'completed_at_utc'), 'BACKEND_FIELDS_INVALID')
    _header(value, 1, SCOPES['backend'], fresh=False)
    expected = {'installation_id': config['storage']['installation_id'],
        'storage_plan_sha256': config['storage']['plan']['sha256'],
        'storage_completion_sha256': config['storage']['completion']['sha256'],
        'app_projection_sha256': config['app_projection']['sha256'],
        'provider_configuration_sha256': provider_reference['sha256'], 'release_sha256': release_reference['sha256']}
    need(all(value[key] == item for key, item in expected.items())
         and _hash(value['intent_sha256']) and _hash(value['backend_schema_sha256']), 'BACKEND_ANCESTOR_BINDING_CHANGED')
    need(_same(value['initial_counts'], INITIAL_COUNTS), 'BACKEND_INITIAL_COUNTS_INVALID')
    need(_utc(value['completed_at_utc']) >= _utc(storage_completion['completed_at_utc']), 'BACKEND_TIME_ORDER_INVALID')
    public = config['runtime']['public_configuration']
    need(reference['path'] == str(PurePosixPath(public['directory']) / public['backend_filename']), 'BACKEND_PUBLIC_LOCATION_CHANGED')
    return config, release, value


def _admission(docs, reference, provider_reference, release_reference, layout):
    value = docs.read(reference, anchor='admission')
    _keys(value, ('schema_version', 'scope', 'installation_mode', 'installation_id', 'provider_configuration_sha256',
        'release_sha256', 'backend_initialization', 'containers', 'observed_at_utc'), 'ADMISSION_FIELDS_INVALID')
    _header(value, 2, SCOPES['admission'])
    config, release, backend = _backend(docs, value['backend_initialization'], provider_reference, release_reference, layout)
    need(value['installation_id'] == config['storage']['installation_id']
         and value['provider_configuration_sha256'] == provider_reference['sha256']
         and value['release_sha256'] == release_reference['sha256'], 'ADMISSION_ANCESTOR_BINDING_CHANGED')
    _keys(value['containers'], ROLES, 'EXACT_DEPLOYMENT_ROLES_REQUIRED')
    ids = []
    for item in value['containers'].values():
        _hash_map(item, ('id', 'static_runtime_sha256'), 'CONTAINER_IDENTITY_FIELDS_INVALID')
        ids.append(item['id'])
    need(len(set(ids)) == len(ROLES), 'DEPLOYMENT_CONTAINER_IDS_COLLIDE')
    need(_utc(value['observed_at_utc']) >= _utc(backend['completed_at_utc']), 'ADMISSION_TIME_ORDER_INVALID')
    _private_reference(reference, config)
    return config, release, backend, value


def _installation(docs, reference):
    value = docs.read(reference, anchor='installation')
    _keys(value, ('schema_version', 'scope', 'installation_mode', 'provider', 'release', 'admission',
                  'layout', 'bounds', 'batch_pause_seconds'), 'INSTALLATION_FIELDS_INVALID')
    _header(value, 2, SCOPES['installation'])
    config, release, backend, admission = _admission(docs, value['admission'], value['provider'], value['release'], value['layout'])
    limits = {'max_jobs': 5, 'max_polls': 120, 'max_seconds': 7200, 'poll_seconds': 60}
    _keys(value['bounds'], limits, 'BOUNDED_BATCH_FIELDS_REQUIRED')
    need(all(type(value['bounds'][name]) is int and 1 <= value['bounds'][name] <= maximum for name, maximum in limits.items())
         and value['bounds']['max_jobs'] <= value['bounds']['max_polls']
         and type(value['batch_pause_seconds']) is int and 1 <= value['batch_pause_seconds'] <= 60, 'BATCH_BOUNDS_INVALID')
    _private_reference(reference, config)
    return value, config, release, backend, admission


def validate_provider(reference, artifacts):
    """Validate C3 and its supplied S0/P/profile ancestors, without reading files."""
    return _provider(_Documents(artifacts), _ref(reference))[0]


def validate_release(reference, artifacts, *, provider_reference, layout):
    return _release(_Documents(artifacts), _ref(reference), _ref(provider_reference), layout)[3]


def validate_backend_initialization(reference, artifacts, *, provider_reference, release_reference, layout):
    return _backend(_Documents(artifacts), _ref(reference), _ref(provider_reference), _ref(release_reference), layout)[2]


def validate_admission(reference, artifacts, *, provider_reference, release_reference, layout):
    return _admission(_Documents(artifacts), _ref(reference), _ref(provider_reference), _ref(release_reference), layout)[3]


def validate_installation(reference, artifacts):
    return _installation(_Documents(artifacts), _ref(reference))[0]


def validate_chain(installation_reference, artifacts, *, transition_reference=None):
    """Resolve a closed document set; never return READY or execution authority.

    All {path,sha256} references resolve against caller-provided bytes. Opaque
    code aggregates, receipt/observation digests and container configuration
    digests are declarations only; no source file or runtime is inspected here.
    """
    docs = _Documents(artifacts)
    installation_reference = _ref(installation_reference)
    installed, config, release, backend, admission = _installation(docs, installation_reference)
    if transition_reference is not None:
        value = docs.read(transition_reference, anchor='transition')
        hashes = {'storage_completion_sha256': config['storage']['completion']['sha256'],
            'app_projection_sha256': config['app_projection']['sha256'],
            'provider_configuration_sha256': installed['provider']['sha256'],
            'release_sha256': installed['release']['sha256'],
            'backend_initialization_sha256': admission['backend_initialization']['sha256'],
            'admission_sha256': installed['admission']['sha256'], 'installation_sha256': installation_reference['sha256']}
        _keys(value, ('schema_version', 'scope', 'installation_id', *hashes, 'live_observation_sha256',
                      'observed_at_utc', 'transition', 'automatic_replay_permitted'), 'TRANSITION_FIELDS_INVALID')
        _header(value, 1, SCOPES['transition'], fresh=False)
        need(value['installation_id'] == config['storage']['installation_id']
             and all(value[key] == expected for key, expected in hashes.items())
             and _hash(value['live_observation_sha256']) and value['transition'] == 'INITIAL_TO_NORMAL'
             and value['automatic_replay_permitted'] is False, 'TRANSITION_BINDING_CHANGED')
        need(_utc(value['observed_at_utc']) >= _utc(admission['observed_at_utc']), 'TRANSITION_TIME_ORDER_INVALID')
        public = config['runtime']['public_configuration']
        need(transition_reference['path'] == str(PurePosixPath(public['directory']) / public['admission_filename']),
             'TRANSITION_PUBLIC_LOCATION_CHANGED')
    need(set(docs.used) == set(docs.artifacts), 'UNREFERENCED_ARTIFACT')
    return {'scope': 'fox-fresh-declaration-consistency-v1', 'status': 'DECLARATIONS_CONSISTENT_NOT_ADMITTED',
        'installation_id': config['storage']['installation_id'], 'installation_sha256': installation_reference['sha256'],
        'provider_sha256': installed['provider']['sha256'], 'release_sha256': installed['release']['sha256'],
        'admission_sha256': installed['admission']['sha256'], 'transition_bound': transition_reference is not None,
        'resolved_references': dict(sorted(docs.used.items())), 'filesystem_inspected': False,
        'runtime_inspected': False, 'bootstrap_proven': False, 'connected_admission': False,
        'services_started': False, 'automatic_replay_permitted': False}
