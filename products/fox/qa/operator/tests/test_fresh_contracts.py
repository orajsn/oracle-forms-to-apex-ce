"""Synthetic in-memory declarations only; no runtime/initialization attestation."""
from copy import deepcopy
from datetime import datetime
import builtins
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import threading
import types

import pytest

ROOT = Path(__file__).resolve().parents[3]
for folder in (ROOT, ROOT / 'fox', ROOT / 'converter'):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))

from qa.operator import fresh_contracts as M
from qa.operator import fresh_storage
from forms2apex.target_profile import _PROFILE_JSN_PROJECT_20261025, _PROFILE_JSN_20261017, target_profile_sha256


def hash_name(name):
    return hashlib.sha256(name.encode()).hexdigest()


def chain(mutations=None, *, transition=True, target_profile=None):
    """Build complete synthetic metadata, never manufacture on-disk evidence."""
    mutations = mutations or {}
    values, refs, artifacts = {}, {}, {}
    root, public = '/synthetic/source/release-a', '/synthetic/public/config'
    install_id = 'fst-' + 'a' * 32
    def put(name, path, value, *, pretty=False):
        value = deepcopy(value)
        if name in mutations:
            mutations[name](value)
        raw = ((json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
               if pretty else M.canonical(value))
        values[name] = value; artifacts[path] = raw
        refs[name] = {'path': path, 'sha256': M.digest(raw)}
        return refs[name]
    source_names = set(fresh_storage.SOURCE_NAMES)
    source_names |= {'qa/operator/' + name for name in M.CODE}
    source_names |= {'fox/fox/' + name for name in (*M.MODULES, *M.PROJECT_MODULES, *M.QUEUE_MODULES)}
    source_names |= {'converter/' + name for name in M.IDENTITY_SOURCES}
    inventory = {name: hash_name('synthetic source: ' + name) for name in sorted(source_names)}
    put('storage_plan', '/synthetic/private/storage-plan.json', {
        'schema_version':1, 'scope':fresh_storage.SCOPE, 'owner_uid':1000,
        'roots':{'fox_data':'/synthetic/storage/data', 'converter_jobs':'/synthetic/storage/jobs',
                 'operator_state':'/synthetic/storage/operator', 'records':'/synthetic/storage/records'},
        'source_sha256':{name:inventory[name] for name in fresh_storage.SOURCE_NAMES},
        'initial_schema_sha256':hash_name('synthetic initial schema')})
    put('storage_completion', '/synthetic/storage/records/complete.json', {
        'scope':'fox-fresh-storage-completion-v1', 'installation_id':install_id,
        'plan_sha256':refs['storage_plan']['sha256'], 'intent_sha256':hash_name('synthetic intent'),
        'roots_sha256':hash_name('synthetic roots'), 'schema_observation_sha256':hash_name('synthetic schema observation'),
        'completed_at_utc':'2026-01-01T00:00:00Z'})
    put('projection', public + '/projection.json', {'schema_version':1,
        'scope':'fox-fresh-app-projection-v1', 'installation_mode':'fresh', 'installation_id':install_id,
        'storage_plan_sha256':refs['storage_plan']['sha256'],
        'storage_completion_sha256':refs['storage_completion']['sha256'],
        'converter_endpoint':'http://127.0.0.1:8291'})
    target = deepcopy(_PROFILE_JSN_PROJECT_20261025 if target_profile is None else target_profile)
    put('target_profile', public + '/target-profile.json', target, pretty=True)
    opaf = target['opaf']
    put('opaf_profile', public + '/native-profile.json', {'schema_version':2, 'profile_id':'native-project-v1',
        'native_project_schema_versions':[1,2], 'storage_mapping_scope':'fox-project-storage-v1',
        'module_execution_scope':'fox-project-module-execution-v2', 'opaf_base_url':opaf['base_url'],
        'certificate_sha256':opaf['certificate_sha256'], **opaf['roles']}, pretty=True)
    def mount(source, destination, read_only=True):
        return {'source':source, 'destination':destination, 'read_only':read_only}
    fox_mounts = [mount('/synthetic/storage/data','/data',False), mount(public,'/run/fox-installation'),
        mount(refs['opaf_profile']['path'],'/run/fox-native/profile.json'),
        mount('/synthetic/secrets/opaf-client','/run/fox-opaf')]
    converter_mounts = [mount('/synthetic/storage/jobs','/opt/forms2apex/outputs/jobs',False),
        mount(public,'/run/fox-installation'), mount(refs['target_profile']['path'],'/run/fox-target/profile.json'),
        mount('/synthetic/tools/sqlcl','/opt/sqlcl'), mount('/synthetic/secrets/wallet','/opt/forms2apex/wallet'),
        mount('/synthetic/secrets/connections','/home/converter/.dbtools',False)]
    images = {'fox':'sha256:' + hash_name('synthetic fox image'), 'converter':'sha256:' + hash_name('synthetic converter image')}
    roles = {
        'fox':{'name':'fox-fresh-test', 'image':images['fox'], 'user':'1000:1000', 'read_only_rootfs':True, 'mounts':fox_mounts},
        'converter':{'name':'forms2apex-fresh-test', 'image':images['converter'], 'user':'10001', 'read_only_rootfs':False,
                     'mounts':converter_mounts},
        'opaf':{'name':'opaf-test', 'image':'sha256:' + hash_name('synthetic opaf image'), 'user':'0:0',
                'read_only_rootfs':False, 'mounts':[mount('/synthetic/opaf/volume','/mount',False)]}}
    put('provider', '/synthetic/private/provider.json', {
        'schema_version':3, 'scope':M.SCOPES['provider'], 'installation_mode':'fresh', 'owner_uid':1000,
        'provider_sha256':inventory['qa/operator/runtime_provider.py'], 'target_profile':target,
        'target_profile_sha256':target_profile_sha256(target),
        'python':{'path':'/synthetic/python/venv/bin/python3.11', 'sha256':hash_name('synthetic python'), 'version':[3,11,13]},
        'converter_root':root + '/converter',
        'converter_sources':{name:inventory['converter/' + name] for name in M.IDENTITY_SOURCES},
        'state_root':'/synthetic/storage/operator', 'admin_secret_file':'/synthetic/secrets/admin/password',
        'public_mount_roots':sorted({row['source'] for row in fox_mounts}), 'images':images,
        'storage':{'installation_id':install_id, 'plan':refs['storage_plan'], 'completion':refs['storage_completion']},
        'app_projection':refs['projection'],
        'runtime':{'roles':roles, 'converter_endpoint':'http://127.0.0.1:8291',
            'qa':{'root':'/synthetic/storage/operator/qa','base_image':'sha256:' + hash_name('synthetic QA image')},
            'public_configuration':{'directory':public, **M.PUBLIC_FILENAMES},
            'settings':{'conversion_profile':'native-project-v1','data_mode':'synthetic_test_only','fox_origin':'http://127.0.0.1:8110'},
            'opaf_profile':refs['opaf_profile'], 'target_profile':refs['target_profile']}})
    put('inventory', '/synthetic/private/source-inventory.json', {
        'schema_version':1,'scope':'fox-hosted-source-inventory-v1','files':inventory})
    layout = {'release_root':root,'inventory':refs['inventory']}
    provider = values['provider']
    put('release', '/synthetic/private/release.json', {
        'schema_version':4,'scope':M.SCOPES['release'],'installation_mode':'fresh','enabled':True,
        'images':provider['images'], 'modules':{name:inventory['fox/fox/' + name] for name in M.MODULES},
        'code':{name:inventory['qa/operator/' + name] for name in M.CODE},
        'clean_operator_code_sha256':hash_name('synthetic clean code'), 'qa_source_sha256':hash_name('synthetic QA source'),
        'promotion_transport_sha256':hash_name('synthetic promotion'), 'native_profile_sha256':refs['opaf_profile']['sha256'],
        'target':{**target['oci'],'db_name':target['database']['db_name']},
        'project':{**{name:hash_name('synthetic project ' + name) for name in M.PROJECT_HASHES},
            'modules':{name:inventory['fox/fox/' + name] for name in M.PROJECT_MODULES},
            'queue_modules':{name:inventory['fox/fox/' + name] for name in M.QUEUE_MODULES}},
        'hosted_runtime_configuration_sha256':refs['provider']['sha256'],
        'opaf_profile':{**refs['opaf_profile'],'target_profile_sha256':provider['target_profile_sha256']}})
    put('backend', public + '/backend-initialization.json', {
        'schema_version':1,'scope':M.SCOPES['backend'],'installation_id':install_id,
        'storage_plan_sha256':refs['storage_plan']['sha256'], 'storage_completion_sha256':refs['storage_completion']['sha256'],
        'app_projection_sha256':refs['projection']['sha256'], 'provider_configuration_sha256':refs['provider']['sha256'],
        'release_sha256':refs['release']['sha256'], 'intent_sha256':hash_name('synthetic backend intent'),
        'backend_schema_sha256':hash_name('synthetic backend schema'), 'initial_counts':M.INITIAL_COUNTS,
        'completed_at_utc':'2026-01-01T00:00:01Z'})
    put('admission', '/synthetic/private/deployment.json', {
        'schema_version':2,'scope':M.SCOPES['admission'],'installation_mode':'fresh','installation_id':install_id,
        'provider_configuration_sha256':refs['provider']['sha256'], 'release_sha256':refs['release']['sha256'],
        'backend_initialization':refs['backend'],
        'containers':{role:{'id':hash_name('synthetic container ' + role),
                            'static_runtime_sha256':hash_name('synthetic runtime ' + role)} for role in M.ROLES},
        'observed_at_utc':'2026-01-01T00:00:02Z'})
    put('installation', '/synthetic/private/installation.json', {
        'schema_version':2,'scope':M.SCOPES['installation'],'installation_mode':'fresh',
        'provider':refs['provider'],'release':refs['release'],'admission':refs['admission'],'layout':layout,
        'bounds':{'max_jobs':2,'max_polls':10,'max_seconds':600,'poll_seconds':5},'batch_pause_seconds':5})
    if transition:
        put('transition', public + '/live-admission.json', {'schema_version':1,'scope':M.SCOPES['transition'],
            'installation_id':install_id, 'storage_completion_sha256':refs['storage_completion']['sha256'],
            'app_projection_sha256':refs['projection']['sha256'],'provider_configuration_sha256':refs['provider']['sha256'],
            'release_sha256':refs['release']['sha256'],'backend_initialization_sha256':refs['backend']['sha256'],
            'admission_sha256':refs['admission']['sha256'],'installation_sha256':refs['installation']['sha256'],
            'live_observation_sha256':hash_name('synthetic live observation'), 'observed_at_utc':'2026-01-01T00:00:03Z',
            'transition':'INITIAL_TO_NORMAL','automatic_replay_permitted':False})
    return types.SimpleNamespace(values=values, refs=refs, artifacts=artifacts, layout=layout)


def checked(fixture):
    return M.validate_chain(fixture.refs['installation'], fixture.artifacts,
                            transition_reference=fixture.refs.get('transition'))


def test_full_chain_returns_consistency_not_authority_and_preserves_inputs():
    fixture = chain(); before = deepcopy(fixture.__dict__)
    result = checked(fixture)
    assert result['status'] == 'DECLARATIONS_CONSISTENT_NOT_ADMITTED'
    assert result['transition_bound'] is True
    assert len(result['resolved_references']) == len(fixture.artifacts) == 12
    assert all(result[key] is False for key in ('filesystem_inspected','runtime_inspected','bootstrap_proven',
                                              'connected_admission','services_started','automatic_replay_permitted'))
    assert fixture.__dict__ == before


def test_pretransition_chain_is_not_admission():
    result = checked(chain(transition=False))
    assert result['transition_bound'] is False and result['connected_admission'] is False


def test_individual_validators_use_complete_supplied_ancestors():
    f = chain()
    common = {'provider_reference':f.refs['provider'],'release_reference':f.refs['release'],'layout':f.layout}
    assert M.validate_provider(f.refs['provider'], f.artifacts) == f.values['provider']
    assert M.validate_release(f.refs['release'], f.artifacts, provider_reference=f.refs['provider'], layout=f.layout) == f.values['release']
    assert M.validate_backend_initialization(f.refs['backend'], f.artifacts, **common) == f.values['backend']
    assert M.validate_admission(f.refs['admission'], f.artifacts, **common) == f.values['admission']
    assert M.validate_installation(f.refs['installation'], f.artifacts) == f.values['installation']


def test_reference_copies_are_detached():
    f = chain()
    value = M.validate_provider(f.refs['provider'], f.artifacts)
    value['runtime']['roles']['fox']['name'] = 'changed'
    assert checked(f)['status'] == 'DECLARATIONS_CONSISTENT_NOT_ADMITTED'


@pytest.mark.parametrize('label', ['storage_plan','storage_completion','projection','target_profile','opaf_profile',
                                  'provider','inventory','release','backend','admission','installation','transition'])
def test_missing_or_changed_reference_refuses(label):
    f = chain(); path = f.refs[label]['path']; f.artifacts.pop(path)
    with pytest.raises(M.FreshContractError): checked(f)
    f = chain(); f.artifacts[path] += b' '
    with pytest.raises(M.FreshContractError): checked(f)


@pytest.mark.parametrize('label,mutation', [
    ('storage_plan', lambda x:x.update(schema_version=True)),
    ('storage_plan', lambda x:x['roots'].update(fox_data='/home/opc/fox/data')),
    ('storage_plan', lambda x:x['roots'].update(converter_jobs=x['roots']['fox_data'])),
    ('storage_completion', lambda x:x.update(installation_id='fst-'+'b'*32)),
    ('storage_completion', lambda x:x.update(completed_at_utc='2026-02-31T00:00:00Z')),
    ('projection', lambda x:x.update(ready=True)),
    ('projection', lambda x:x.update(converter_endpoint='http://localhost:8291')),
    ('target_profile', lambda x:x['oci'].update(region='us-phoenix-1')),
    ('opaf_profile', lambda x:x['mapper'].update(model='unregistered-model')),
    ('provider', lambda x:x.update(schema_version=True)),
    ('provider', lambda x:x.update(schema_version=2)),
    ('provider', lambda x:x.update(installation_mode='migration')),
    ('provider', lambda x:x.update(retirement={})),
    ('provider', lambda x:x.update(release_sha256='b'*64)),
    ('provider', lambda x:x.update(container_ids={'fox':'b'*64})),
    ('provider', lambda x:x.update(owner_uid=True)),
    ('provider', lambda x:x['runtime'].update(converter_endpoint='http://127.0.0.1:8292')),
    ('provider', lambda x:x['runtime']['roles']['fox'].update(name='fox')),
    ('provider', lambda x:x['runtime']['roles']['converter'].update(user='0:0')),
    ('provider', lambda x:x['runtime']['roles']['fox'].update(read_only_rootfs=1)),
    ('provider', lambda x:x['runtime']['roles']['fox']['mounts'][0].update(read_only=0)),
    ('provider', lambda x:x['runtime']['roles']['fox']['mounts'][0].update(source='/other/foreign/data')),
    ('provider', lambda x:x['runtime']['roles']['fox']['mounts'].append(x['runtime']['roles']['fox']['mounts'][0])),
    ('provider', lambda x:x['runtime']['public_configuration'].update(backend_filename='other.json')),
    ('provider', lambda x:x['runtime']['settings'].update(fox_origin=x['runtime']['converter_endpoint'])),
    ('provider', lambda x:x.update(admin_secret_file='/synthetic/storage/data/admin')),
    ('provider', lambda x:x.update(admin_secret_file='/synthetic/storage/operator/admin')),
    ('provider', lambda x:x['python'].update(path='/synthetic/storage/data/python')),
    ('provider', lambda x:x['python'].update(version=[3,True,13])),
    ('provider', lambda x:x.update(public_mount_roots=[])),
    ('release', lambda x:x.update(schema_version=3)),
    ('release', lambda x:x.update(enabled=1)),
    ('release', lambda x:x.update(provider_configuration_sha256='b'*64)),
    ('release', lambda x:x['target'].update(region='us-phoenix-1')),
    ('release', lambda x:x['opaf_profile'].update(sha256='b'*64)),
    ('release', lambda x:x['code'].pop('fresh_contracts.py')),
    ('release', lambda x:x['project']['modules'].update(installation_py='b'*64)),
    ('inventory', lambda x:x['files'].update({'../escape.py':'b'*64})),
    ('inventory', lambda x:x['files'].pop('fox/fox/installation.py')),
    ('backend', lambda x:x.update(storage_completion_sha256='b'*64)),
    ('backend', lambda x:x['initial_counts'].update(runs=1)),
    ('backend', lambda x:x['initial_counts'].update(events=True)),
    ('backend', lambda x:x['initial_counts'].update(unrecognized_table=0)),
    ('backend', lambda x:x.update(completed_at_utc='2025-12-31T23:59:59Z')),
    ('backend', lambda x:x.update(container_ids={'fox':'b'*64})),
    ('admission', lambda x:x.update(schema_version=True)),
    ('admission', lambda x:x.update(installation_id='fst-'+'b'*32)),
    ('admission', lambda x:x['containers']['fox'].update(id=True)),
    ('admission', lambda x:x['containers']['converter'].update(id=x['containers']['fox']['id'])),
    ('admission', lambda x:x['containers']['fox'].update(running=True)),
    ('admission', lambda x:x.update(observed_at_utc='2026-01-01T00:00:00Z')),
    ('installation', lambda x:x.update(retirement={'path':'/synthetic/private/history.json','sha256':'b'*64})),
    ('installation', lambda x:x.update(installation_mode='unknown')),
    ('installation', lambda x:x['bounds'].update(max_jobs=True)),
    ('installation', lambda x:x['bounds'].update(max_seconds=7201)),
    ('installation', lambda x:x.update(batch_pause_seconds=False)),
    ('transition', lambda x:x.update(installation_sha256='b'*64)),
    ('transition', lambda x:x.update(ready=True)),
    ('transition', lambda x:x.update(automatic_replay_permitted=0)),
    ('transition', lambda x:x.update(transition='BOOTSTRAP_AGAIN')),
    ('transition', lambda x:x.update(observed_at_utc='2026-01-01T00:00:01Z')),
])
def test_rehashed_structural_or_cross_binding_mutation_refuses(label, mutation):
    with pytest.raises(M.FreshContractError): checked(chain({label:mutation}))


def test_shared_source_cannot_be_overridden_by_later_storage_map():
    def change(release):
        release['modules']['storage.py'] = 'b'*64
        release['project']['modules']['storage.py'] = 'b'*64
    with pytest.raises(M.FreshContractError, match='SOURCE_CLOSURE'):
        checked(chain({'release':change}))


@pytest.mark.parametrize('name', ['backend_storage.py', 'fresh_startup.py', 'worker.py', 'worker_observability.py'])
@pytest.mark.parametrize('group', ['modules', 'project_modules'])
def test_fresh_backend_and_startup_pins_are_required_in_both_source_groups(name, group):
    def remove(release):
        hashes = release['modules'] if group == 'modules' else release['project']['modules']
        hashes.pop(name)
    with pytest.raises(M.FreshContractError, match='(?:RELEASE_MODULE|PROJECT_MODULE)_FIELDS_INVALID'):
        checked(chain({'release':remove}))


@pytest.mark.parametrize('name', ['backend_storage.py', 'fresh_startup.py', 'worker.py', 'worker_observability.py'])
def test_fresh_backend_and_startup_shared_pins_cannot_conflict(name):
    with pytest.raises(M.FreshContractError, match='SHARED_SOURCE_BINDING_CHANGED'):
        checked(chain({'release':lambda release:release['project']['modules'].update({name:'b'*64})}))


@pytest.mark.parametrize('name', ['backend_storage.py', 'fresh_startup.py', 'worker.py', 'worker_observability.py'])
def test_matching_fresh_module_pins_still_require_inventory_agreement(name):
    def change(release):
        release['modules'][name] = 'b'*64
        release['project']['modules'][name] = 'b'*64
    with pytest.raises(M.FreshContractError, match='DECLARED_SOURCE_CLOSURE_CHANGED'):
        checked(chain({'release':change}))


@pytest.mark.parametrize('name', ['backend_storage.py', 'fresh_startup.py', 'worker.py', 'worker_observability.py'])
def test_fresh_module_cannot_be_omitted_from_source_inventory(name):
    with pytest.raises(M.FreshContractError, match='DECLARED_SOURCE_CLOSURE_CHANGED'):
        checked(chain({'inventory':lambda inventory:inventory['files'].pop('fox/fox/'+name)}))


@pytest.mark.parametrize('name', ['fresh_backend.py', 'fresh_image.py'])
def test_fresh_backend_and_image_code_pin_is_required_and_inventory_bound(name):
    with pytest.raises(M.FreshContractError, match='RELEASE_CODE_FIELDS_INVALID'):
        checked(chain({'release':lambda release:release['code'].pop(name)}))
    with pytest.raises(M.FreshContractError, match='DECLARED_SOURCE_CLOSURE_CHANGED'):
        checked(chain({'release':lambda release:release['code'].update({name:'b'*64})}))
    with pytest.raises(M.FreshContractError, match='DECLARED_SOURCE_CLOSURE_CHANGED'):
        checked(chain({'inventory':lambda inventory:inventory['files'].pop('qa/operator/'+name)}))


def test_actual_backend_and_startup_source_bytes_can_be_declared_without_import_or_io_during_validation(monkeypatch):
    # Read source bytes only as fixture preparation. They are not imported or
    # executed, and the rest of this synthetic chain remains declarative data.
    pins = {name:hashlib.sha256((ROOT/'fox/fox'/name).read_bytes()).hexdigest()
            for name in ('backend_storage.py','fresh_startup.py','worker.py','worker_observability.py')}
    def release_change(release):
        release['modules'].update(pins)
        release['project']['modules'].update(pins)
    f = chain({'inventory':lambda inventory:inventory['files'].update(
                    {'fox/fox/'+name:digest for name,digest in pins.items()}),
               'release':release_change})
    def forbidden(*args, **kwargs): raise AssertionError('PURE_CONTRACT_EXTERNAL_ACTIVITY_FORBIDDEN')
    monkeypatch.setattr(Path,'read_bytes',forbidden)
    monkeypatch.setattr(Path,'read_text',forbidden)
    monkeypatch.setattr(builtins,'open',forbidden)
    monkeypatch.setattr(io,'open',forbidden)
    monkeypatch.setattr(os,'open',forbidden)
    monkeypatch.setattr(sqlite3,'connect',forbidden)
    monkeypatch.setattr(subprocess,'run',forbidden)
    monkeypatch.setattr(subprocess,'Popen',forbidden)
    monkeypatch.setattr(socket,'create_connection',forbidden)
    monkeypatch.setattr(socket.socket,'connect',forbidden)
    result = checked(f)
    assert result['status'] == 'DECLARATIONS_CONSISTENT_NOT_ADMITTED'
    assert result['bootstrap_proven'] is result['connected_admission'] is False


def test_registered_legacy_roles_cannot_be_relabelled_as_mapped_project_roles():
    with pytest.raises(M.FreshContractError, match='REGISTERED_PROJECT_MAPPING_REQUIRED'):
        checked(chain(target_profile=_PROFILE_JSN_20261017))


@pytest.mark.parametrize('role,destination,source', [
    ('converter','/home/converter/.dbtools','/synthetic/public/config'),
    ('opaf','/mount','/synthetic/public/config'),
])
def test_public_projection_directory_has_no_writable_alias(role, destination, source):
    def mutate(config):
        next(row for row in config['runtime']['roles'][role]['mounts']
             if row['destination'] == destination)['source'] = source
    with pytest.raises(M.FreshContractError, match='READ_ONLY_MOUNT_HAS_WRITABLE_ALIAS'):
        checked(chain({'provider':mutate}))


@pytest.mark.parametrize('profile,role,destination,path', [
    ('opaf_profile','fox','/run/fox-native/profile.json','/synthetic/storage/data/native-profile.json'),
    ('target_profile','converter','/run/fox-target/profile.json','/synthetic/storage/jobs/target-profile.json'),
])
def test_profile_file_cannot_be_written_through_another_mount(profile, role, destination, path):
    def mutate(config):
        config['runtime'][profile]['path'] = path
        next(row for row in config['runtime']['roles'][role]['mounts']
             if row['destination'] == destination)['source'] = path
        config['public_mount_roots'] = sorted({row['source'] for row in config['runtime']['roles']['fox']['mounts']})
    f = chain({'provider':mutate})
    f.artifacts[path] = f.artifacts[f.refs[profile]['path']]
    with pytest.raises(M.FreshContractError, match='READ_ONLY_MOUNT_HAS_WRITABLE_ALIAS'):
        M.validate_provider(f.refs['provider'], f.artifacts)


def test_self_and_cyclic_path_references_refuse():
    for source, target in (('provider','installation'),('release','installation'),('admission','installation')):
        f = chain()
        value = deepcopy(f.values['installation'])
        value[source] = dict(f.refs[target])
        raw = M.canonical(value); f.artifacts[f.refs['installation']['path']] = raw
        f.refs['installation']['sha256'] = M.digest(raw)
        with pytest.raises(M.FreshContractError):
            M.validate_installation(f.refs['installation'], f.artifacts)


def test_unused_artifact_is_not_silently_accepted():
    f = chain(); f.artifacts['/synthetic/private/unknown.json'] = M.canonical({'unknown':True})
    with pytest.raises(M.FreshContractError, match='UNREFERENCED_ARTIFACT'): checked(f)


@pytest.mark.parametrize('bad', [None, [], lambda _: {}, {'/synthetic/private/x.json':'not bytes'}])
def test_plain_dictionary_is_required_not_resolver_callback(bad):
    with pytest.raises(M.FreshContractError): M.validate_provider({'path':'/synthetic/private/c.json','sha256':'a'*64},bad)


@pytest.mark.parametrize('raw', [b'{"a":1,"a":2}\n',b'{"a":NaN}\n',b'{"a":1e500}\n',b'{"a": 1}\n',
                               b'{"a":1}',b'[]\n',b'\xff',b'{"a":1.5}\n'])
def test_noncanonical_duplicate_and_nonfinite_json_refuses(raw):
    with pytest.raises(M.FreshContractError): M._parse(raw)


@pytest.mark.parametrize('path', ['/', '/tmp/x', '/a/b/../c', '/a//b/c', '/a/b/./c', 'C:/x/y/z',
                                 '/a/b/c\\x','/a/b/$SECRET', '/a/b/with space','/a/b/\nvalue'])
def test_unsafe_reference_paths_refuse(path):
    with pytest.raises(M.FreshContractError): M._ref({'path':path,'sha256':'a'*64})


def test_no_filesystem_database_network_process_clock_or_thread_activity(monkeypatch):
    f = chain()
    def forbidden(*args, **kwargs): raise AssertionError('PURE_CONTRACT_EXTERNAL_ACTIVITY_FORBIDDEN')
    for name in ('read_bytes','read_text','write_bytes','write_text','mkdir','stat','resolve','open'):
        monkeypatch.setattr(Path,name,forbidden)
    monkeypatch.setattr(builtins,'open',forbidden); monkeypatch.setattr(io,'open',forbidden)
    monkeypatch.setattr(os,'open',forbidden)
    monkeypatch.setattr(sqlite3,'connect',forbidden)
    monkeypatch.setattr(subprocess,'run',forbidden); monkeypatch.setattr(subprocess,'Popen',forbidden)
    monkeypatch.setattr(socket,'create_connection',forbidden); monkeypatch.setattr(socket.socket,'connect',forbidden)
    monkeypatch.setattr(threading.Thread,'start',forbidden)
    monkeypatch.setattr(M,'datetime',types.SimpleNamespace(fromisoformat=datetime.fromisoformat))
    assert checked(f)['connected_admission'] is False


def test_import_has_no_external_activity(monkeypatch):
    source = Path(M.__file__).read_bytes()
    def forbidden(*args, **kwargs): raise AssertionError('PURE_IMPORT_EXTERNAL_ACTIVITY_FORBIDDEN')
    monkeypatch.setattr(Path,'mkdir',forbidden); monkeypatch.setattr(Path,'write_bytes',forbidden)
    monkeypatch.setattr(Path,'write_text',forbidden); monkeypatch.setattr(sqlite3,'connect',forbidden)
    monkeypatch.setattr(builtins,'open',forbidden); monkeypatch.setattr(io,'open',forbidden)
    monkeypatch.setattr(os,'open',forbidden)
    monkeypatch.setattr(subprocess,'run',forbidden); monkeypatch.setattr(subprocess,'Popen',forbidden)
    monkeypatch.setattr(socket,'create_connection',forbidden); monkeypatch.setattr(socket.socket,'connect',forbidden)
    monkeypatch.setattr(threading.Thread,'start',forbidden)
    module = types.ModuleType('qa.operator._fresh_contract_import_check')
    module.__package__ = 'qa.operator'; module.__file__ = M.__file__
    exec(compile(source,M.__file__,'exec'),module.__dict__)
    assert module.SCOPES == M.SCOPES


def test_diagnostics_never_echo_supplied_paths_or_values():
    f = chain({'provider':lambda x:x.update(admin_password='DO_NOT_ECHO_THIS_VALUE')})
    with pytest.raises(M.FreshContractError) as caught: checked(f)
    assert str(caught.value) == 'PROVIDER_FIELDS_INVALID'
    assert 'DO_NOT_ECHO' not in str(caught.value) and '/synthetic' not in str(caught.value)


@pytest.mark.parametrize('field', ['storage','python','runtime','images','converter_sources','public_mount_roots'])
@pytest.mark.parametrize('bad', [None, False, [], 'invalid'])
def test_provider_wrong_container_types_have_closed_diagnostics(field, bad):
    with pytest.raises(M.FreshContractError):
        checked(chain({'provider':lambda x:x.update({field:bad})}))


@pytest.mark.parametrize('field', ['roles','public_configuration','qa','settings','opaf_profile','target_profile'])
@pytest.mark.parametrize('bad', [None, False, [], 'invalid'])
def test_runtime_wrong_container_types_have_closed_diagnostics(field, bad):
    with pytest.raises(M.FreshContractError):
        checked(chain({'provider':lambda x:x['runtime'].update({field:bad})}))


def test_document_and_collection_bounds_are_enforced():
    reference = {'path':'/synthetic/private/x.json','sha256':'a'*64}
    with pytest.raises(M.FreshContractError, match='DOCUMENT_BYTE_BOUND'):
        M._parse(b' ' * (M.MAX_DOCUMENT_BYTES + 1))
    with pytest.raises(M.FreshContractError, match='PLAIN_ARTIFACT'):
        M.validate_provider(reference, {f'/synthetic/private/{i}.json':b'{}\n' for i in range(M.MAX_ARTIFACTS+1)})
    with pytest.raises(M.FreshContractError, match='ARTIFACT_SET_TOO_LARGE'):
        M.validate_provider(reference, {f'/synthetic/private/{i}.json':b' ' * M.MAX_DOCUMENT_BYTES for i in range(9)})
    value = {}
    for _ in range(34): value = {'nested':value}
    with pytest.raises(M.FreshContractError, match='DOCUMENT_STRUCTURE_BOUND'): M.canonical(value)


def test_inventory_and_private_config_cannot_be_mounted_into_application():
    f = chain()
    layout = deepcopy(f.layout)
    layout['inventory']['path'] = '/synthetic/storage/data/inventory.json'
    f.artifacts[layout['inventory']['path']] = f.artifacts[f.refs['inventory']['path']]
    with pytest.raises(M.FreshContractError, match='PRIVATE_DECLARATION_EXPOSED_BY_MOUNT'):
        M.validate_release(f.refs['release'], f.artifacts, provider_reference=f.refs['provider'], layout=layout)
    provider_ref = {'path':'/synthetic/public/config/provider.json','sha256':f.refs['provider']['sha256']}
    f.artifacts[provider_ref['path']] = f.artifacts[f.refs['provider']['path']]
    with pytest.raises(M.FreshContractError, match='PROVIDER_MUST_NOT_BE_APP_MOUNTED'):
        M.validate_provider(provider_ref, f.artifacts)


@pytest.mark.parametrize('endpoint', ['http://localhost:8110','https://127.0.0.1:8110',
    'http://127.0.0.1:8110/','http://127.0.0.1:8110?q=x','http://u:p@127.0.0.1:8110',
    'http://127.0.0.1:80','http://127.0.0.1:65536','http://127.0.0.1:08110',None,False])
def test_invalid_fox_listener_has_closed_diagnostic(endpoint):
    with pytest.raises(M.FreshContractError, match='LOOPBACK_ENDPOINT_INVALID'):
        checked(chain({'provider':lambda x:x['runtime']['settings'].update(fox_origin=endpoint)}))


def test_invalid_unicode_has_closed_diagnostic():
    with pytest.raises(M.FreshContractError): M.canonical({'value':'\ud800'})
    with pytest.raises(M.FreshContractError): M._parse(b'{"value":"\\ud800"}\n')
