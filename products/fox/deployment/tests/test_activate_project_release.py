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

