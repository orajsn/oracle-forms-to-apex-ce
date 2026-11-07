"""Stopped-candidate checks: saved real Podman shapes, synthetic credentials.

No test connects to a host or creates a container. POSIX declaration tests
copy actual runtime source and run actual C/R validators in a fresh process.
Only image-build receipts and future image IDs are synthetic observations.
"""
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('project_activation_under_test', ROOT / 'deployment/activate_project_release.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
# Normalized public projection of the retained read-only observation, not a
# current host claim. No credential values or private runtime payloads appear.
OBSERVED = json.loads((Path(__file__).parent / 'fixtures/activation-runtime-shape.json').read_bytes())
SECRET = 'SYNTHETIC_ONLY_NOT_A_CREDENTIAL_1234567890'
IMAGES = {'fox': 'sha256:' + 'a' * 64, 'converter': 'sha256:' + 'b' * 64}


def plan():
    b = 'c' * 64
    return {'schema_version': 1, 'scope': M.SCOPE, 'source_bundle_sha256': b,
        'bundle_root': '/home/opc/.local/share/fox-project-builds/' + b + '/bundle',
        'provider': {'path': '/home/opc/.config/fox-project/C.json', 'sha256': 'd' * 64},
        'release': {'path': '/home/opc/.config/fox-project/R.json', 'sha256': 'e' * 64},
        'helper_sha256': 'f' * 64}


def baseline_item(role):
    name = 'fox' if role == 'fox' else 'forms2apex-mcp'
    observed = deepcopy(OBSERVED['containers'][name])
    # Secret values were intentionally not captured by the live observation.
    # Preserve observed names/shapes and provide labelled synthetic values.
    env = {key: 'synthetic-value' for key in observed['environment_names']}
    env.update(observed['public_environment'])
    if role == 'fox':
        env['FOX_PASSWORD_HASH'] = SECRET
    else:
        env.update(F2A_MCP_BEARER_TOKEN=SECRET, F2A_TARGET_PROFILE_PATH='/run/fox-target/profile.json')
    return {'Id': observed['id'], 'Image': observed['image'], 'Name': name,
        'Config': {'Env': [key + '=' + value for key, value in sorted(env.items())],
                   'User': observed['user'], 'WorkingDir': observed['workdir'],
                   'Cmd': observed['cmd'], 'Entrypoint': observed['entrypoint'], 'Labels': {}},
        'HostConfig': observed['host'], 'Mounts': observed['mounts'],
        'NetworkSettings': {'Networks': observed['networks']},
        'State': {'Running': True, 'Pid': 12345, 'Status': 'running', 'StartedAt': '2026-10-19T00:00:00Z'},
        'ProcessLabel': 'system_u:system_r:container_t:s0:c75,c812',
        'MountLabel': 'system_u:object_r:container_file_t:s0:c75,c812'}


def profile():
    return json.loads((ROOT / 'deployment/project-opaf-profile-v2.json').read_bytes())


def prepared(role):
    old, value = baseline_item(role), plan()
    release = {'images': IMAGES}
    env = M.new_environment(role, old, value['release']['sha256'], profile())
    argv, mounts = M.candidate_argv(role, old, value, release, PurePosixPath('/private/stage'))
    item = deepcopy(old)
    item.update(Id=('1' if role == 'fox' else '2') * 64,
                Image=IMAGES[role], Name=M.names(value['release']['sha256'])[role])
    item['State'].update(Running=False, Pid=0, Status='created')
    item['Config']['Env'] = [key + '=' + v for key, v in sorted(env.items())]
    item['Config']['Labels'] = {'com.oracle.jsn.fox.release': value['release']['sha256'],
                              'com.oracle.jsn.fox.source-bundle': value['source_bundle_sha256']}
    item['Mounts'] = [{'Type': 'bind', 'Destination': dest, 'Source': source, 'RW': rw}
                      for dest, (source, rw) in mounts.items()]
    return value, release, env, argv, mounts, old, item


def test_exact_plan_uses_canonical_linux_paths_offline():
    value = plan(); raw = M.canonical(value)
    assert M.plan_document(raw, M.sha(raw)) == value


def upgrade_plan(queue=None):
    value = plan()
    value.update(schema_version=2, scope=M.UPGRADE_SCOPE,
                 current_installation={'path': '/home/opc/private/old-installation.json', 'sha256': '9' * 64})
    if queue is not None:
        value['hosted_forms_queue'] = queue
    return value


def prototype_configuration():
    """Synthetic metadata references; never live installation proof."""
    return {'schema_version': 1, 'scope': M.PROTOTYPE_SCOPE, 'origin': 'https://fox.example.test',
            'profile': {'path': '/home/opc/fox/secure/opaf-client/prototype-focus-test.json', 'sha256': '3' * 64},
            'runtime_worker_sha256': '4' * 64}


def test_prototype_opt_in_is_upgrade_only_hash_bound_and_not_environment_injection():
    value = upgrade_plan('/data/native-preparations'); value['prototype_authority'] = prototype_configuration()
    raw = M.canonical(value)
    assert M.plan_document(raw, M.sha(raw)) == value
    changed = deepcopy(value); changed['prototype_authority']['profile']['sha256'] = '5' * 64
    with pytest.raises(M.ActivationError, match='EXACT_PLAN_REQUIRED'):
        M.plan_document(M.canonical(changed), M.sha(raw))
    legacy = plan(); legacy['prototype_authority'] = prototype_configuration(); raw = M.canonical(legacy)
    with pytest.raises(M.ActivationError, match='PLAN_FIELDS_INVALID'):
        M.plan_document(raw, M.sha(raw))


@pytest.mark.parametrize('fault', ['null', 'extra', 'bool', 'scope', 'http', 'origin-path', 'userinfo', 'port',
    'origin-newline', 'origin-control', 'origin-backslash', 'origin-fragment', 'origin-query',
    'profile-missing', 'profile-extra', 'profile-secret', 'profile-other-root',
    'profile-traversal', 'profile-nested', 'profile-case', 'profile-sha', 'worker-sha', 'worker-bool'])
def test_malformed_or_unbounded_prototype_plan_rejected_offline(fault):
    option = prototype_configuration()
    if fault == 'null': option = None
    elif fault == 'extra': option['environment'] = {'ARBITRARY': '1'}
    elif fault == 'bool': option['schema_version'] = True
    elif fault == 'scope': option['scope'] = 'other'
    elif fault == 'http': option['origin'] = 'http://fox.example.test'
    elif fault == 'origin-path': option['origin'] += '/'
    elif fault == 'userinfo': option['origin'] = 'https://user@fox.example.test'
    elif fault == 'port': option['origin'] += ':444'
    elif fault == 'origin-newline': option['origin'] += '\n'
    elif fault == 'origin-control': option['origin'] += '\x7f'
    elif fault == 'origin-backslash': option['origin'] += '\\other'
    elif fault == 'origin-fragment': option['origin'] += '#other'
    elif fault == 'origin-query': option['origin'] += '?other'
    elif fault == 'profile-missing': del option['profile']['sha256']
    elif fault == 'profile-extra': option['profile']['mount'] = '/arbitrary'
    elif fault == 'profile-secret': option['profile']['path'] = '/home/opc/fox/secure/opaf-client/credentials.json'
    elif fault == 'profile-other-root': option['profile']['path'] = '/tmp/prototype-focus-test.json'
    elif fault == 'profile-traversal': option['profile']['path'] = '/home/opc/fox/secure/opaf-client/../prototype-focus-test.json'
    elif fault == 'profile-nested': option['profile']['path'] = '/home/opc/fox/secure/opaf-client/child/prototype-focus-test.json'
    elif fault == 'profile-case': option['profile']['path'] = '/home/opc/fox/secure/opaf-client/prototype-UPPER.json'
    elif fault == 'profile-sha': option['profile']['sha256'] = 'short'
    elif fault == 'worker-sha': option['runtime_worker_sha256'] = 'A' * 64
    else: option['runtime_worker_sha256'] = True
    value = upgrade_plan(); value['prototype_authority'] = option; raw = M.canonical(value)
    with pytest.raises(M.ActivationError):
        M.plan_document(raw, M.sha(raw))


@pytest.mark.parametrize('role', ['fox', 'converter'])
def test_explicit_prototype_settings_are_role_separated_without_mount_or_target_changes(role, monkeypatch):
    value, release, env, argv, mounts, old, item = prepared(role)
    option = prototype_configuration()
    if role == 'fox':
        env['FOX_PUBLIC_ORIGIN'] = option['origin']
        old['Config']['Env'] = [key + '=' + val for key, val in sorted(env.items())]
    monkeypatch.setenv('FOX_PROTOTYPE_AUTHORITY_ENABLED', '1')
    assert not any(key.startswith('FOX_PROTOTYPE_') for key in M.new_environment(role, old, 'e' * 64, profile()))
    value = upgrade_plan('/data/native-preparations'); value['prototype_authority'] = option
    selected = M.new_environment(role, old, value['release']['sha256'], profile(),
        hosted_forms_queue=value['hosted_forms_queue'], prototype_authority=option)
    assert selected['FOX_PROTOTYPE_AUTHORITY_ENABLED'] == '1'
    if role == 'fox':
        assert selected['FOX_PROTOTYPE_PROFILE_FILE'] == '/run/fox-opaf/prototype-focus-test.json'
        assert selected['FOX_NATIVE_PROFILE_FILE'] == '/run/fox-native/profile.json'
        assert selected['FOX_HOSTED_FORMS_QUEUE'] == value['hosted_forms_queue']
        assert not {'FOX_PROTOTYPE_AUTHORITY_URL', 'FOX_PROTOTYPE_AUTHORITY_ORIGIN',
                    'FOX_PROTOTYPE_RUNTIME_BRIDGE_ENABLED', 'FOX_PROTOTYPE_RUNTIME_WORKER_SHA256'} & set(selected)
    else:
        assert selected['FOX_PROTOTYPE_AUTHORITY_URL'] == option['origin'] + '/api/internal/prototype/authorize'
        assert selected['FOX_PROTOTYPE_AUTHORITY_ORIGIN'] == option['origin']
        assert selected['FOX_PROTOTYPE_RUNTIME_BRIDGE_ENABLED'] == '1'
        assert selected['FOX_PROTOTYPE_RUNTIME_WORKER_SHA256'] == option['runtime_worker_sha256']
        assert selected['F2A_TARGET_PROFILE_PATH'] == '/run/fox-target/profile.json'
        assert 'FOX_PROTOTYPE_PROFILE_FILE' not in selected and 'FOX_HOSTED_FORMS_QUEUE' not in selected
    args, selected_mounts = M.candidate_argv(role, old, value, release, PurePosixPath('/private/stage'))
    assert args == argv and selected_mounts == mounts
    item['Config']['Env'] = [key + '=' + val for key, val in sorted(selected.items())]
    M.check_candidate(item, role, value, release, selected, mounts, baseline_item=old)


@pytest.mark.parametrize('role', ['fox', 'converter'])
@pytest.mark.parametrize('key', ['FOX_PROTOTYPE_AUTHORITY_ENABLED', 'FOX_PROTOTYPE_UNKNOWN',
    'FOX_PROTOTYPE_PROFILE_FILE', 'FOX_PROTOTYPE_RUNTIME_BRIDGE_ENABLED'])
def test_inherited_prototype_settings_need_explicit_role_bound_reauthorization(role, key):
    old = baseline_item(role); old['Config']['Env'].append(key + '=1')
    with pytest.raises(M.ActivationError, match='EXPLICIT_ROLE_BOUND_PROTOTYPE_CONFIGURATION_REQUIRED'):
        M.new_environment(role, old, 'e' * 64, profile())
    if key not in M.prototype_environment(role, prototype_configuration()):
        with pytest.raises(M.ActivationError, match='EXPLICIT_ROLE_BOUND_PROTOTYPE_CONFIGURATION_REQUIRED'):
            M.new_environment(role, old, 'e' * 64, profile(), prototype_authority=prototype_configuration())


def test_prototype_origin_must_match_the_existing_fox_origin():
    with pytest.raises(M.ActivationError, match='PROTOTYPE_PUBLIC_ORIGIN_CHANGED'):
        M.new_environment('fox', baseline_item('fox'), 'e' * 64, profile(), prototype_authority=prototype_configuration())


@pytest.mark.parametrize('role', ['fox', 'converter'])
def test_existing_role_settings_require_a_fresh_explicit_measurement_on_upgrade(role):
    old = baseline_item(role); option = prototype_configuration()
    old_env = M.environment(old); old_env.update(M.prototype_environment(role, option))
    if role == 'fox': old_env['FOX_PUBLIC_ORIGIN'] = option['origin']
    old['Config']['Env'] = [key + '=' + val for key, val in sorted(old_env.items())]
    with pytest.raises(M.ActivationError, match='EXPLICIT_ROLE_BOUND_PROTOTYPE_CONFIGURATION_REQUIRED'):
        M.new_environment(role, old, 'e' * 64, profile())
    fresh = deepcopy(option); fresh['runtime_worker_sha256'] = '5' * 64
    fresh['profile']['path'] = '/home/opc/fox/secure/opaf-client/prototype-next.json'
    env = M.new_environment(role, old, 'e' * 64, profile(), prototype_authority=fresh)
    assert {key: val for key, val in env.items() if key.startswith('FOX_PROTOTYPE_')} == M.prototype_environment(role, fresh)


@pytest.mark.parametrize('role', ['fox', 'converter'])
def test_candidate_cannot_replace_the_project_target_with_the_focused_metadata_envelope(role):
    value, release, env, argv, mounts, old, item = prepared(role)
    option = prototype_configuration(); value = upgrade_plan(); value['prototype_authority'] = option
    env.update(M.prototype_environment(role, option))
    if role == 'fox':
        env['FOX_PUBLIC_ORIGIN'] = option['origin']
        env['FOX_NATIVE_PROFILE_FILE'] = env['FOX_PROTOTYPE_PROFILE_FILE']
    else:
        env['F2A_TARGET_PROFILE_PATH'] = '/run/fox-opaf/prototype-focus-test.json'
    item['Config']['Env'] = [key + '=' + val for key, val in sorted(env.items())]
    with pytest.raises(M.ActivationError, match='CANDIDATE_PROTOTYPE_TARGET_OR_ORIGIN_CHANGED'):
        M.check_candidate(item, role, value, release, env, mounts, baseline_item=old)


@pytest.mark.parametrize('role', ['fox', 'converter'])
@pytest.mark.parametrize('fault', ['unapproved', 'missing', 'changed', 'wrong-role'])
def test_candidate_prototype_cannot_be_adopted_from_a_matching_but_unplanned_env(role, fault):
    value, release, env, argv, mounts, old, item = prepared(role)
    value = upgrade_plan(); option = prototype_configuration()
    if fault != 'unapproved': value['prototype_authority'] = option
    if fault != 'missing': env.update(M.prototype_environment(role, option))
    if fault == 'changed': env['FOX_PROTOTYPE_AUTHORITY_ENABLED'] = '0'
    if fault == 'wrong-role':
        env.update(M.prototype_environment('converter' if role == 'fox' else 'fox', option))
    item['Config']['Env'] = [key + '=' + val for key, val in sorted(env.items())]
    with pytest.raises(M.ActivationError, match='CANDIDATE_PROTOTYPE_CONFIGURATION_CHANGED'):
        M.check_candidate(item, role, value, release, env, mounts, baseline_item=old)


def mapped_metadata_reader(root, monkeypatch):
    """Actual probe/parser/file reads with modelled POSIX UID/mode on Windows.

    This does not claim actual mapped UID or kernel O_NOFOLLOW proof on Windows.
    The serialized production program is executed unchanged, outside __main__.
    """
    import stat
    from types import SimpleNamespace
    namespace = {'__name__': 'profile_probe_under_test'}
    exec(compile(M.PROTOTYPE_PROFILE_PROBE, '<prototype-profile-probe>', 'exec'), namespace)
    actual_lstat, actual_fstat = Path.lstat, os.fstat
    fields = ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_mode','st_uid','st_gid','st_nlink')
    def mapped(info, directory=False):
        result = {key: getattr(info, key) for key in fields}
        result.update(st_uid=1000, st_gid=1000, st_mode=stat.S_IFMT(info.st_mode) | (0o700 if directory else 0o600))
        if os.name == 'nt':
            # Windows lstat/fstat expose different ctime semantics; model the
            # POSIX comparison while retaining real file-content/mtime drift.
            result['st_ctime_ns'] = info.st_mtime_ns
        return SimpleNamespace(**result)
    def lstat(path, **kwargs):
        info = actual_lstat(path, **kwargs)
        return mapped(info, path == root) if path == root or path.parent == root else info
    monkeypatch.setattr(Path, 'lstat', lstat)
    monkeypatch.setattr(os, 'fstat', lambda fd: mapped(actual_fstat(fd)))
    monkeypatch.setattr(os, 'geteuid', lambda: 1000, raising=False)
    monkeypatch.setattr(os, 'getegid', lambda: 1000, raising=False)
    if not hasattr(os, 'O_NOFOLLOW'):
        monkeypatch.setattr(os, 'O_NOFOLLOW', 0, raising=False)
    return namespace['read_profile']


@pytest.mark.parametrize('fault', ['none', 'file-hash', 'worker-hash', 'destination', 'envelope',
    'roles', 'duplicate', 'malformed-json', 'drift', 'origin', 'access', 'response-hash',
    'mount-source', 'mount-writable', 'mount-missing', 'old-runtime-without-new-client'])
def test_prototype_full_envelope_source_projection_and_mapped_access_guards(fault, tmp_path, monkeypatch):
    """Real serialized reader/metadata validators; container/mapped UID are modelled."""
    from fox.opaf import canonical_hash
    from fox import prototype_job
    if fault == 'old-runtime-without-new-client':
        # The 0.9.1 namespace already provides this real metadata loader but has
        # no new authority client. Fence that absent import without changing
        # sys.path, clearing modules or substituting a successful validator.
        import builtins
        from fox.prototype_job import load_prototype_profile
        original_import = builtins.__import__
        def old_namespace_import(name, *args, **kwargs):
            if name == 'forms2apex.prototype_authority_client':
                raise ModuleNotFoundError('Absent from the retained old runtime namespace')
            return original_import(name, *args, **kwargs)
        monkeypatch.setattr(builtins, '__import__', old_namespace_import)
        with pytest.raises(ModuleNotFoundError):
            __import__('forms2apex.prototype_authority_client', fromlist=['execution_target'])
    target = json.loads((ROOT / 'deployment/target-profile.jsn-project-v2.json').read_bytes())
    focused = deepcopy(target)
    focused['profile_id'] = 'synthetic-focused-profile'
    focused['opaf']['roles']['mapper']['workflow_id'] = 'A' * 32
    focused['opaf']['roles']['reviewer']['workflow_id'] = 'B' * 32
    if fault == 'destination': focused['database']['parsing_schema'] = 'OTHER'
    if fault == 'roles': focused['opaf']['roles']['reviewer'] = focused['opaf']['roles']['mapper']
    envelope = {'target_profile': focused, 'target_profile_sha256': canonical_hash(focused)}
    if fault == 'envelope': envelope = focused
    raw = M.canonical(envelope)
    if fault == 'duplicate': raw = raw.rstrip()[:-1] + b',"target_profile_sha256":"' + canonical_hash(focused).encode() + b'"}\n'
    if fault == 'malformed-json': raw = b'{"target_profile":'
    file = tmp_path / 'prototype-focus-test.json'; file.write_bytes(raw)
    reader = mapped_metadata_reader(tmp_path, monkeypatch)
    if fault == 'drift':
        original_loader = prototype_job.load_prototype_profile
        def changed_while_loading(path):
            loaded = original_loader(path)
            path.write_bytes(raw + b' ')
            return loaded
        monkeypatch.setattr(prototype_job, 'load_prototype_profile', changed_while_loading)
    option = prototype_configuration(); option['profile']['sha256'] = M.sha(raw)
    worker = b'synthetic measured worker source'; option['runtime_worker_sha256'] = M.sha(worker)
    if fault == 'file-hash': option['profile']['sha256'] = '0' * 64
    if fault == 'worker-hash': option['runtime_worker_sha256'] = '0' * 64
    value = upgrade_plan(); value['prototype_authority'] = option
    old = baseline_item('fox'); old['Config']['Env'] = ['FOX_PUBLIC_ORIGIN=' + (
        option['origin'] if fault != 'origin' else 'https://different.example.test')]
    mounted = next(row for row in old['Mounts'] if row['Destination'] == '/run/fox-opaf')
    if fault == 'mount-source': mounted['Source'] = '/unbound/opaf-client'
    elif fault == 'mount-writable': mounted['RW'] = True
    elif fault == 'mount-missing': old['Mounts'].remove(mounted)
    host_reads = []
    def host_read(path, **kwargs):
        if path.as_posix().startswith(M.PROTOTYPE_PROFILE_ROOT):
            raise PermissionError('Mapped host UID100999 directory is not host-readable')
        host_reads.append(path)
        return worker
    monkeypatch.setattr(M, 'read', host_read)
    calls = []
    def observe(argv, **kwargs):
        calls.append(argv)
        assert kwargs == {'maximum': 131_072}
        observed = reader(tmp_path, argv[8], argv[9])
        if fault == 'access': observed['status'] = 'other'
        if fault == 'response-hash': observed['profile_sha256'] = '0' * 64
        return M.canonical(observed)
    monkeypatch.setattr(M, 'command', observe)
    before = deepcopy((value, target, old))
    if fault in ('none', 'old-runtime-without-new-client'):
        result = M.validate_prototype_authority(value, {'target_profile': target}, old)
        assert result['status'] == 'PROTOTYPE_CONFIGURATION_CHECKED_NOT_ACTIVATED'
        argv = calls[0]
        assert argv[:7] == ['/usr/bin/podman', 'exec', old['Id'], '/usr/local/bin/python', '-I', '-B', '-c']
        assert argv[8:] == [file.name, option['profile']['sha256']]
        compile(argv[7], '<read-only-profile-access>', 'exec')
        assert not any(action in argv[7] for action in ('chmod', 'chown', 'mkdir', 'write', 'converter_token'))
        assert (value, target, old) == before
    else:
        with pytest.raises(Exception): M.validate_prototype_authority(value, {'target_profile': target}, old)
        assert len(calls) == (0 if fault in ('worker-hash','origin','mount-source','mount-writable','mount-missing') else 1)
    assert len(host_reads) == (0 if fault == 'origin' else 1)
    assert M.validate_prototype_authority(upgrade_plan(), {}, {}) is None


@pytest.mark.parametrize('fault', ['uid', 'gid', 'root-owner', 'root-group', 'root-mode', 'file-owner',
    'file-group', 'file-mode', 'hardlink', 'symlink', 'oversized', 'opened-inode'])
def test_serialized_metadata_reader_rejects_unprotected_or_unstable_mapped_inputs(fault, tmp_path, monkeypatch):
    import stat
    from fox.opaf import canonical_hash
    target = json.loads((ROOT / 'deployment/target-profile.jsn-project-v2.json').read_bytes())
    raw = M.canonical({'target_profile': target, 'target_profile_sha256': canonical_hash(target)})
    path = tmp_path / 'prototype-focus-test.json'; path.write_bytes(raw)
    reader = mapped_metadata_reader(tmp_path, monkeypatch)
    mapped_lstat = Path.lstat
    def unsafe_lstat(selected, **kwargs):
        info = mapped_lstat(selected, **kwargs)
        if selected == tmp_path:
            if fault == 'root-owner': info.st_uid = 0
            if fault == 'root-group': info.st_gid = 0
            if fault == 'root-mode': info.st_mode = stat.S_IFDIR | 0o755
        elif selected == path:
            if fault == 'file-owner': info.st_uid = 0
            if fault == 'file-group': info.st_gid = 0
            if fault == 'file-mode': info.st_mode = stat.S_IFREG | 0o644
            if fault == 'hardlink': info.st_nlink = 2
            if fault == 'symlink': info.st_mode = stat.S_IFLNK | 0o600
            if fault == 'oversized': info.st_size = 65537
        return info
    monkeypatch.setattr(Path, 'lstat', unsafe_lstat)
    if fault == 'uid': monkeypatch.setattr(os, 'geteuid', lambda: 0)
    if fault == 'gid': monkeypatch.setattr(os, 'getegid', lambda: 0)
    if fault == 'opened-inode':
        mapped_fstat = os.fstat
        def changed_inode(fd):
            info = mapped_fstat(fd); info.st_ino += 1
            return info
        monkeypatch.setattr(os, 'fstat', changed_inode)
    with pytest.raises(AssertionError): reader(tmp_path, path.name, M.sha(raw))


@pytest.mark.parametrize('mutation', ['none', 'focus-roles', 'extra-field', 'missing-field', 'empty-value',
    'bool-value', 'oversized-value', 'inactive', 'customer-scope', 'operations'])
def test_deployment_execution_projection_matches_new_converter_contract(mutation):
    from forms2apex.prototype_authority_client import execution_target
    target = json.loads((ROOT / 'deployment/target-profile.jsn-project-v2.json').read_bytes())
    if mutation == 'focus-roles':
        target['opaf']['roles']['mapper']['workflow_id'] = 'A' * 32
        target['profile_id'] = 'synthetic-focused-profile'
    elif mutation == 'extra-field': target['database']['other'] = 'unsupported'
    elif mutation == 'missing-field': del target['apex']['workspace_id']
    elif mutation == 'empty-value': target['oci']['region'] = ''
    elif mutation == 'bool-value': target['sqlcl']['saved_connection'] = True
    elif mutation == 'oversized-value': target['database']['db_name'] = 'a' * 2049
    elif mutation == 'inactive': target['active'] = False
    elif mutation == 'customer-scope': target['scope']['customer_deployment_authorized'] = True
    elif mutation == 'operations': target['scope']['supported_operations'] = ['delete']
    if mutation in ('none', 'focus-roles'):
        assert M.prototype_execution_target(target) == execution_target(target)
    else:
        with pytest.raises(Exception): M.prototype_execution_target(target)
        with pytest.raises(Exception): execution_target(target)


@pytest.mark.parametrize('queue', ['/data/native-preparations', '/data/native-preparations-20261107a'])
def test_queue_opt_in_is_hash_bound_and_only_in_upgrade_plans(queue):
    value = upgrade_plan(queue); raw = M.canonical(value)
    assert M.plan_document(raw, M.sha(raw)) == value
    changed = deepcopy(value); changed['hosted_forms_queue'] += '-changed'
    with pytest.raises(M.ActivationError, match='EXACT_PLAN_REQUIRED'):
        M.plan_document(M.canonical(changed), M.sha(raw))
    legacy = plan(); legacy['hosted_forms_queue'] = queue; raw = M.canonical(legacy)
    with pytest.raises(M.ActivationError, match='PLAN_FIELDS_INVALID'):
        M.plan_document(raw, M.sha(raw))


@pytest.mark.parametrize('queue', [None, True, 1, {}, '', '/data', '/data/', '/data/fox.sqlite3',
    '/tmp/native-preparations', '/database/native-preparations', '/data/native-preparations/child',
    '/data/../data/native-preparations', '/data//native-preparations', '/data/./native-preparations',
    '//data/native-preparations', 'data/native-preparations', 'C:/data/native-preparations',
    '/data/native-preparations/', '/data/native-preparations-', '/data/native-preparations-UPPER',
    '/data/native-preparations-abc\n', '/data/native-preparations\x00', '/data/native-preparations\\other',
    '/data/native-preparations-' + 'a' * 49])
def test_invalid_queue_plan_is_rejected_offline(queue):
    value = upgrade_plan(); value['hosted_forms_queue'] = queue; raw = M.canonical(value)
    with pytest.raises(M.ActivationError, match='BOUNDED_HOSTED_FORMS_QUEUE_REQUIRED'):
        M.plan_document(raw, M.sha(raw))


@pytest.mark.parametrize('role', ['fox', 'converter'])
def test_explicit_queue_changes_only_fox_environment_and_no_mount_or_port(role, monkeypatch):
    monkeypatch.setenv('FOX_HOSTED_FORMS_QUEUE', '/untrusted/ambient')
    value, release, env, argv, mounts, old, item = prepared(role)
    assert 'FOX_HOSTED_FORMS_QUEUE' not in env  # Ambient process env has no authority.
    value = upgrade_plan('/data/native-preparations')
    selected = M.new_environment(role, old, value['release']['sha256'], profile(),
                                 hosted_forms_queue=value['hosted_forms_queue'])
    assert selected == ({**env, 'FOX_HOSTED_FORMS_QUEUE': value['hosted_forms_queue']} if role == 'fox' else env)
    args, selected_mounts = M.candidate_argv(role, old, value, release, PurePosixPath('/private/stage'))
    assert args == argv and selected_mounts == mounts
    item['Config']['Env'] = [key + '=' + val for key, val in sorted(selected.items())]
    M.check_candidate(item, role, value, release, selected, mounts, baseline_item=old)


@pytest.mark.parametrize('role', ['fox', 'converter'])
def test_inherited_queue_requires_explicit_reauthorization(role):
    old = baseline_item(role)
    old['Config']['Env'].append('FOX_HOSTED_FORMS_QUEUE=/data/native-preparations')
    with pytest.raises(M.ActivationError, match='EXPLICIT_HOSTED_FORMS_QUEUE_REQUIRED'):
        M.new_environment(role, old, 'e' * 64, profile())
    if role == 'fox':
        env = M.new_environment(role, old, 'e' * 64, profile(), hosted_forms_queue='/data/native-preparations-new')
        assert env['FOX_HOSTED_FORMS_QUEUE'] == '/data/native-preparations-new'


@pytest.mark.parametrize('planned,observed', [(None, '/data/native-preparations'),
    ('/data/native-preparations', None), ('/data/native-preparations', '/data/native-preparations-wrong')])
def test_candidate_queue_must_match_plan_even_if_supplied_environment_matches_item(planned, observed):
    value, release, env, argv, mounts, old, item = prepared('fox')
    value = upgrade_plan(planned)
    if observed is not None:
        env['FOX_HOSTED_FORMS_QUEUE'] = observed
    item['Config']['Env'] = [key + '=' + val for key, val in sorted(env.items())]
    with pytest.raises(M.ActivationError, match='CANDIDATE_HOSTED_FORMS_QUEUE_CHANGED'):
        M.check_candidate(item, 'fox', value, release, env, mounts, baseline_item=old)


def test_private_queue_check_is_opt_in_read_only_and_uses_mapped_uid(monkeypatch):
    calls = []
    def observe(argv):
        calls.append(argv)
        return M.canonical({'status': 'PRIVATE_HOSTED_FORMS_QUEUE_CHECKED'})
    monkeypatch.setattr(M, 'command', observe)
    assert M.validate_hosted_queue(upgrade_plan(), '/usr/bin/python3') is None
    assert calls == []
    assert M.validate_hosted_queue(upgrade_plan('/data/native-preparations'), '/usr/bin/python3') == {
        'status': 'PRIVATE_HOSTED_FORMS_QUEUE_CHECKED'}
    args = calls[0]
    assert args[:7] == ['/usr/bin/podman', 'unshare', '/usr/bin/python3', '-I', '-B', '-c', args[6]]
    assert args[7:] == ['native-preparations']
    compile(args[6], '<private-queue-check>', 'exec')
    assert 'info.st_uid==1000' in args[6] and 'info.st_gid==1000' in args[6]
    assert 'stat.S_IMODE(info.st_mode)==0o700' in args[6]
    assert not any(action in args[6] for action in ('chmod', 'chown', 'mkdir', 'write'))


def test_unconfirmed_private_queue_check_stops_before_creation(monkeypatch):
    monkeypatch.setattr(M, 'command', lambda _: M.canonical({'status': 'anything-else'}))
    with pytest.raises(M.ActivationError, match='PRIVATE_HOSTED_FORMS_QUEUE_UNCONFIRMED'):
        M.validate_hosted_queue(upgrade_plan('/data/native-preparations'), '/usr/bin/python3')


@pytest.mark.parametrize('mutation', ['hash', 'extra', 'bool', 'bundle', 'inside', 'same', 'relative', 'traversal'])
def test_changed_plan_is_rejected_before_effects(mutation):
    value = plan()
    if mutation == 'extra': value['apply'] = True
    if mutation == 'bool': value['schema_version'] = True
    if mutation == 'bundle': value['bundle_root'] = '/home/opc/different/bundle'
    if mutation == 'inside': value['provider']['path'] = value['bundle_root'] + '/C.json'
    if mutation == 'same': value['provider']['path'] = value['release']['path']
    if mutation == 'relative': value['release']['path'] = 'R.json'
    if mutation == 'traversal': value['provider']['path'] = '/home/opc/../C.json'
    raw = M.canonical(value)
    with pytest.raises(Exception):
        M.plan_document(raw, '0' * 64 if mutation == 'hash' else M.sha(raw))


@pytest.mark.parametrize('raw', [b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'])
def test_duplicate_or_nonfinite_json_rejected(raw):
    with pytest.raises(Exception): M.parse(raw)


@pytest.mark.parametrize('role', ['fox', 'converter'])
def test_actual_saved_shapes_generate_stopped_preserving_arguments(role):
    value, release, env, argv, mounts, old, item = prepared(role)
    assert argv[:2] == ['/usr/bin/podman', 'create']
    assert not {'start', 'stop', 'rm', '--replace', '--rm'} & set(argv)
    assert not any(':Z' in part or ':z' in part or ':U' in part for part in argv)
    assert SECRET not in json.dumps(argv)
    assert SECRET in env.values()
    assert '\\' not in ' '.join(argv)
    assert '--env-file' in argv
    assert argv[-1] == release['images'][role]
    assert '--publish-all' not in argv and '--privileged' not in argv
    assert M.mount_map(old) != mounts  # Only target profile source is selected afresh.
    if role == 'fox':
        assert env['FOX_CONVERSION_PROFILE'] == 'native-project-v1'
        assert env['FOX_VERIFIER_RELEASE_SHA256'] == value['release']['sha256']
        assert argv[argv.index('--network') + 1] == 'host'
        assert '--read-only' in argv and '--cap-drop' in argv
    else:
        assert env['F2A_OPAF_MAPPER_WORKFLOW_ID'] == profile()['mapper']['workflow_id']
        assert env['F2A_OPAF_REVIEWER_WORKFLOW_ID'] == profile()['reviewer']['workflow_id']
        assert argv[argv.index('--publish') + 1] == '127.0.0.1:8091:8090'
        assert argv.count('--network') == 2
        assert 'forms2apex:ip=10.89.1.3' in argv
        assert 'keep-id:uid=10001,gid=10001' in argv
    M.check_candidate(item, role, value, release, env, mounts, baseline_item=old)


@pytest.mark.parametrize('role', ['fox', 'converter'])
@pytest.mark.parametrize('field', ['running', 'pid', 'image', 'extra_mount', 'writable_profile', 'secret',
                                  'network', 'privileged', 'autoremove', 'user', 'command', 'caps', 'memory'])
def test_changed_stopped_candidate_cannot_be_adopted(role, field):
    value, release, env, argv, mounts, old, item = prepared(role)
    if field == 'running': item['State']['Running'] = True
    elif field == 'pid': item['State']['Pid'] = 9
    elif field == 'image': item['Image'] = 'sha256:' + '9' * 64
    elif field == 'extra_mount': item['Mounts'].append({'Type': 'bind', 'Destination': '/private', 'Source': '/secret', 'RW': False})
    elif field == 'writable_profile': next(x for x in item['Mounts'] if x['Destination'].startswith('/run/fox-') and x['Destination'].endswith('profile.json'))['RW'] = True
    elif field == 'secret': item['Config']['Env'].append('UNEXPECTED_SECRET=' + SECRET)
    elif field == 'network': item['HostConfig']['NetworkMode'] = 'none'
    elif field == 'privileged': item['HostConfig']['Privileged'] = True
    elif field == 'autoremove': item['HostConfig']['AutoRemove'] = True
    elif field == 'user': item['Config']['User'] = '0'
    elif field == 'command': item['Config']['Cmd'] = ['python', '-c', 'raise SystemExit(0)']
    elif field == 'caps': item['HostConfig']['CapAdd'] = ['CAP_SYS_ADMIN']
    elif field == 'memory': item['HostConfig']['Memory'] = 2147483648
    with pytest.raises(M.ActivationError):
        M.check_candidate(item, role, value, release, env, mounts, baseline_item=old)


@pytest.mark.parametrize('bad', ['F2A_MCP_BEARER_TOKEN=abc\nINJECT=1', 'A=1\rX=2', 'A=\x00', '9INVALID=value'])
def test_environment_cannot_inject_a_second_record(bad):
    item = baseline_item('converter'); item['Config']['Env'].append(bad)
    with pytest.raises(M.ActivationError): M.environment(item)


def test_duplicate_environment_name_rejected():
    item = baseline_item('converter'); item['Config']['Env'].append('F2A_MCP_BEARER_TOKEN=duplicate')
    with pytest.raises(M.ActivationError): M.environment(item)


def test_implicit_create_has_no_host_effect(monkeypatch):
    monkeypatch.setattr(M, 'load_bindings', lambda *_: pytest.fail('must not import or read a host'))
    with pytest.raises(M.ActivationError, match='EXPLICIT_REVIEWED_CREATE_REQUIRED'):
        M.create_candidates(plan(), expected_plan_sha256=M.sha(M.canonical(plan())))


def test_baseline_signature_ignores_only_transient_exec_records():
    before = {name: baseline_item(role) for name, role in (('fox', 'fox'), ('forms2apex-mcp', 'converter'))}
    transient = deepcopy(before)
    transient['fox'].update(ExecIDs=['synthetic-read-only-exec'], ExecSessions=['synthetic-session'])
    assert M.baseline_signature(before) == M.baseline_signature(transient)
    for mutate in (lambda x: x['fox']['State'].update(Pid=99),
                   lambda x: x['fox']['State'].update(StartedAt='2026-10-27T00:00:00Z'),
                   lambda x: x['fox']['Config']['Env'].append('EXTRA=changed'),
                   lambda x: x['fox']['HostConfig'].update(Privileged=True),
                   lambda x: x['forms2apex-mcp']['NetworkSettings']['Networks']['forms2apex'].update(IPAddress='10.89.1.4')):
        changed = deepcopy(before); mutate(changed)
        assert M.baseline_signature(before) != M.baseline_signature(changed)


@pytest.mark.parametrize('changed', [False, True])
def test_bind_root_identity_uses_metadata_not_private_contents(tmp_path, monkeypatch, changed):
    source = tmp_path / 'private.json'; source.write_text(SECRET)
    items = {name: {'Id': digit * 64, 'Mounts': [{'Type': 'bind', 'Source': str(source), 'Destination': '/private.json'}]}
             for name, digit in (('fox', '1'), ('forms2apex-mcp', '2'))}
    calls = []
    def observed(argv, **kwargs):
        calls.append(argv)
        assert argv[:2] == ['/usr/bin/podman', 'exec']
        info = source.stat()
        return M.canonical({'/private.json': [info.st_dev, info.st_ino + int(changed), M.stat.S_IFMT(info.st_mode)]})
    monkeypatch.setattr(M, 'command', observed)
    monkeypatch.setattr(Path, 'read_bytes', lambda *_: pytest.fail('private contents must not be read'))
    if changed:
        with pytest.raises(M.ActivationError, match='BASELINE_MOUNT_INODE_DIFFERS_FROM_HOST_PATH'):
            M.validate_bound_sources(items)
    else:
        M.validate_bound_sources(items)
        assert len(calls) == 2
    assert SECRET not in json.dumps(calls)


@pytest.mark.skipif(os.name != 'posix', reason='requires symlink creation without Windows privilege changes')
def test_linked_bind_root_rejected_before_container_probe(tmp_path, monkeypatch):
    actual = tmp_path / 'actual'; actual.mkdir()
    linked = tmp_path / 'link'; linked.symlink_to(actual, target_is_directory=True)
    item = {'Id': '1' * 64, 'Mounts': [{'Type': 'bind', 'Source': str(linked), 'Destination': '/data'}]}
    monkeypatch.setattr(M, 'command', lambda *_args, **_kwargs: pytest.fail('must not probe'))
    with pytest.raises(M.ActivationError, match='BASELINE_BIND_SOURCE_LINKED_OR_MISSING'):
        M.validate_bound_sources({'fox': item, 'forms2apex-mcp': item})


@pytest.mark.skipif(os.name != 'posix', reason='requires real POSIX private directory/fsync')
def test_actual_child_exit_is_retained_and_create_is_not_replayed(monkeypatch):
    monkeypatch.setattr(M, 'host_identity', lambda: None)  # Only external IMDS is synthetic.
    with tempfile.TemporaryDirectory(prefix='.fox-create-test-', dir=Path.home()) as directory:
        stage = Path(directory)
        argv = [sys.executable, '-I', '-B', '-c', "print('a'*64)"]
        raw = M.create_once(stage, 'fox', argv, 'b' * 64)
        assert raw.strip() == b'a' * 64
        result = M.parse((stage / 'fox-create-exit.json').read_bytes())
        assert result['exit_code'] == 0 and result['observed_original_process'] is True
        retained = {path.name: path.read_bytes() for path in stage.iterdir()}
        with pytest.raises(FileExistsError):
            M.create_once(stage, 'fox', argv, 'b' * 64)
        assert retained == {path.name: path.read_bytes() for path in stage.iterdir()}


@pytest.mark.skipif(os.name != 'posix', reason='requires real POSIX private journal/fsync')
def test_unknown_child_outcome_preserves_intent_and_disallows_replay(monkeypatch):
    monkeypatch.setattr(M, 'host_identity', lambda: None)
    launched = []
    class Pending:
        pid = 12345
        def __init__(self, argv, **kwargs):
            launched.append(argv); kwargs['stdout'].write(b'synthetic partial output\n')
        def wait(self, timeout):
            raise subprocess.TimeoutExpired(launched[-1], timeout)
    monkeypatch.setattr(M.subprocess, 'Popen', Pending)  # External process observation is synthetic.
    with tempfile.TemporaryDirectory(prefix='.fox-timeout-test-', dir=Path.home()) as directory:
        stage = Path(directory)
        with pytest.raises(M.ActivationError, match='CREATE_OUTCOME_UNCONFIRMED_INSPECT_SAME_PROCESS_NO_REPLAY'):
            M.create_once(stage, 'converter', ['synthetic-command'], 'c' * 64)
        assert (stage / 'converter-create-intent.json').is_file()
        assert (stage / 'converter-create-process.json').is_file()
        assert not (stage / 'converter-create-exit.json').exists()
        assert (stage / 'converter-create.stdout').read_bytes() == b'synthetic partial output\n'
        with pytest.raises(FileExistsError):
            M.create_once(stage, 'converter', ['synthetic-command'], 'c' * 64)
        assert len(launched) == 1


# A fresh process is essential: load_bindings intentionally refuses an existing
# qa/fox/forms2apex namespace. These are actual production validators, not
# replacements returning a made-up "ready" result.
BINDING_PROBE = r'''
import hashlib,importlib,importlib.util,json,os,pathlib,sys,tempfile
repo=pathlib.Path(sys.argv[1]);mutation=sys.argv[2]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
 sys.modules[name]=module;spec.loader.exec_module(module);return module
tool=load('candidate_binding_probe',repo/'deployment/activate_project_release.py')
packer=load('candidate_source_packer',repo/'deployment/prepare_project_release.py')
os.umask(0o077)
with tempfile.TemporaryDirectory(prefix='.fox-activation-bind-',dir=pathlib.Path.home()) as temp:
 stage=pathlib.Path(temp);root=stage/'bundle';root.mkdir(mode=0o700)
 files=packer.source_files(repo)
 for folder in ('forms2apex','fox_source_contract'):
  for path in (repo/'converter'/folder).rglob('*'):
   if path.is_file() and '__pycache__' not in path.parts and path.suffix in ('.py','.json','.apx'):
    files['converter/'+path.relative_to(repo/'converter').as_posix()]=path.read_bytes()
 for name,raw in files.items():
  path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
 profile=root/'deployment/project-opaf-profile-v2.json';profile.chmod(0o644)
 inventory=tool.canonical({'schema_version':1,'scope':'fox-hosted-source-inventory-v1',
  'files':{name:tool.sha(raw) for name,raw in sorted(files.items())}})
 (stage/'source-inventory.json').write_bytes(inventory);b=tool.sha(inventory)
 sys.path[:0]=[str(root),str(root/'fox'),str(root/'converter')]
 from qa.operator import product_verifier as verifier,runtime_provider as runtime
 from forms2apex import target_profile
 target=json.loads((root/'deployment/target-profile.jsn-project-v2.json').read_bytes())
 images={'fox':'sha256:'+'a'*64,'converter':'sha256:'+'b'*64}
 cfg={'schema_version':2,'scope':'fox-hosted-operator-runtime-v2','owner_uid':1000,
  'provider_sha256':tool.sha((root/'qa/operator/runtime_provider.py').read_bytes()),
  'target_profile':target,'target_profile_sha256':target_profile.target_profile_sha256(target),
  'python':{'path':'/synthetic-only/python3.11','sha256':'f'*64,'version':[3,11,13]},
  'converter_root':str(root/'converter'),'converter_sources':{name:tool.sha((root/'converter'/name).read_bytes()) for name in runtime._SOURCE_FILES},
  'state_root':str(stage/'private-state'),'admin_secret_file':str(stage/'private-secret/admin'),
  'public_mount_roots':['/home/opc/fox/data'],'images':images}
 c=tool.canonical(cfg);csha=tool.sha(c)
 op={'schema_version':3,'scope':'fox-product-verifier-operator-config-v3','enabled':True,'images':images,
  'hosted_runtime_configuration_sha256':csha,'opaf_profile':{'path':'deployment/project-opaf-profile-v2.json',
  'sha256':tool.sha(profile.read_bytes()),'target_profile_sha256':cfg['target_profile_sha256']}}
 release=verifier.build_manifest(op,hosted_configuration=c)
 if mutation=='release-source':release['modules']['verification_runtime.py']='9'*64
 if mutation=='provider-source':
  cfg['converter_sources']['forms2apex/config.py']='9'*64;c=tool.canonical(cfg);csha=tool.sha(c)
  release['hosted_runtime_configuration_sha256']=csha
 r=tool.canonical(release);rsha=tool.sha(r)
 (stage/'C.json').write_bytes(c);(stage/'R.json').write_bytes(r)
 for role in images:
  (stage/(role+'-build-complete.json')).write_bytes(tool.canonical({'status':'BUILT_NOT_ACTIVATED',
   'source_bundle_sha256':b,'image':images[role],'synthetic_external_build_observation':True}))
 if mutation=='public-mode':profile.chmod(0o600)
 if mutation=='bundle-source':
  p=root/'qa/operator/clean_install.py';p.write_bytes(p.read_bytes()+b'\n# changed after inventory\n')
 p={'schema_version':1,'scope':tool.SCOPE,'source_bundle_sha256':b,'bundle_root':str(root),
  'provider':{'path':str(stage/'C.json'),'sha256':csha},'release':{'path':str(stage/'R.json'),'sha256':rsha},'helper_sha256':'0'*64}
 for name in tuple(sys.modules):
  if any(name==prefix or name.startswith(prefix+'.') for prefix in ('qa','fox','forms2apex')):sys.modules.pop(name)
 try:
  actual=tool.load_bindings(p)
  assert mutation=='none','CHANGED_INPUT_ACCEPTED'
  assert actual==(cfg,release)
  assert sys.modules['qa.operator.runtime_provider']._selected is sys.modules['qa.operator.runtime_provider']._UNSELECTED
  result={'status':'ACTUAL_VALIDATORS_PASSED','runtime_selected':False,'host_contacted':False}
 except Exception as error:
  if mutation=='none':raise
  code=str(error)
  assert code!='CHANGED_INPUT_ACCEPTED',code
  result={'status':'REJECTED','code':code,'host_contacted':False}
 print(json.dumps(result,sort_keys=True))
'''


@pytest.mark.skipif(os.name != 'posix', reason='requires actual POSIX owner-private source files')
@pytest.mark.parametrize('mutation,code', [
    ('none', None), ('public-mode', 'PUBLIC_PROFILE_NOT_READABLE_BY_FOX_UID'),
    ('release-source', 'RELEASE_DOES_NOT_MATCH_ACTUAL_BUNDLE_SOURCE'),
    ('provider-source', 'HOSTED_CONFIGURATION_SOURCE_DIFFERS'),
    ('bundle-source', 'SOURCE_INVENTORY_CHANGED'),
])
def test_actual_source_c_r_and_public_profile_binding(mutation, code):
    completed = subprocess.run([sys.executable, '-B', '-c', BINDING_PROBE, str(ROOT), mutation],
        capture_output=True, text=True, timeout=90, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    assert completed.returncode == 0, completed.stderr
    value = json.loads(completed.stdout)
    assert value['host_contacted'] is False
    if code:
        assert value['status'] == 'REJECTED' and code in value['code']
    else:
        assert value['status'] == 'ACTUAL_VALIDATORS_PASSED' and value['runtime_selected'] is False

