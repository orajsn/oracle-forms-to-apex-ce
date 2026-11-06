"""Measured-source configuration composition, never a running upgrade."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import pytest
from test_activate_project_release import BINDING_PROBE

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('project_upgrade_config_test',ROOT/'deployment/prepare_project_upgrade.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)


@pytest.mark.parametrize('bundle',[None,True,'short','A'*64])
def test_invalid_bundle_does_not_probe_host_or_write(bundle,monkeypatch):
    monkeypatch.setattr(M.A,'host_identity',lambda:pytest.fail('Invalid request reached host'))
    with pytest.raises(M.A.ActivationError):M.prepare(bundle,{},apply=True)


@pytest.mark.parametrize('queue', ['', '/tmp/native-preparations', '/data/native-preparations/../other', True])
def test_invalid_queue_does_not_probe_host_or_write(queue, monkeypatch):
    monkeypatch.setattr(M.A, 'host_identity', lambda: pytest.fail('Invalid queue reached host'))
    with pytest.raises(M.A.ActivationError, match='BOUNDED_HOSTED_FORMS_QUEUE_REQUIRED'):
        M.prepare('a' * 64, {}, apply=True, hosted_forms_queue=queue)


@pytest.mark.parametrize('queue', [None, '/data/native-preparations'])
@pytest.mark.parametrize('apply', [False, True])
def test_preparation_carries_only_explicit_queue_in_hashed_plan_and_report(queue, apply, tmp_path, monkeypatch):
    """Model the existing host observations; no host or Podman call is made."""
    writes = {}; plans = []; images = {'fox': 'sha256:' + '7' * 64, 'converter': 'sha256:' + '8' * 64}
    monkeypatch.setattr(M, 'CONFIG_ROOT', tmp_path)
    monkeypatch.setattr(M.A, 'host_identity', lambda: None)
    monkeypatch.setattr(M.A, 'source_namespace', lambda root, _: (root, None, None, None))
    current = SimpleNamespace(scope=lambda: None, configuration={})
    monkeypatch.setattr(M.A, 'CurrentBaseline', lambda _: current)
    monkeypatch.setattr(M.A, 'baseline', lambda _: {})
    monkeypatch.setattr(M.A, 'validate_bound_sources', lambda _: None)
    monkeypatch.setattr(M.A, 'private_dir', lambda _: None)
    monkeypatch.setattr(M.A, 'sync', lambda _: None)
    monkeypatch.setattr(M.A, 'plan_document', lambda raw, digest: plans.append((raw, digest)))
    monkeypatch.setattr(M.A, 'create_file', lambda path, raw: writes.update({path.name: raw}))
    def read(path, **kwargs):
        role = path.name.removesuffix('-build-complete.json')
        if role in images:
            return M.A.canonical({'status': 'BUILT_NOT_ACTIVATED', 'exit_code': 0,
                'source_bundle_sha256': 'a' * 64, 'baseline_unchanged': True, 'image': images[role]})
        return b'synthetic measured standalone helper'
    monkeypatch.setattr(M.A, 'read', read)
    monkeypatch.setattr(M.A, 'command', lambda args: M.A.canonical([{'Id': args[-1], 'Architecture': 'amd64',
        'Os': 'linux', 'Labels': {'com.oracle.jsn.fox.source-bundle': 'a' * 64}}]))
    monkeypatch.setattr(M, 'compose', lambda *_: (M.A.canonical({'target_profile_sha256': 'b' * 64}), M.A.canonical({})))
    result = M.prepare('a' * 64, {'path': '/private/old.json', 'sha256': 'c' * 64},
                       apply=apply, hosted_forms_queue=queue)
    raw, digest = plans[0]; plan = M.A.parse(raw)
    assert M.A.sha(raw) == digest == result['plan_sha256']
    assert plan.get('hosted_forms_queue') == queue and result.get('hosted_forms_queue') == queue
    if queue is None:
        assert 'hosted_forms_queue' not in plan and 'hosted_forms_queue' not in result
    if apply:
        assert writes['activation-plan.json'] == raw and result['files_written'] is True
    else:
        assert writes == {} and result['files_written'] is False


PROBE=BINDING_PROBE.split(" for name in tuple(sys.modules):",1)[0]+r'''
 import copy,socket
 def blocked(*args,**kwargs):raise AssertionError('UNEXPECTED_EXTERNAL_ACTION')
 socket.socket.connect=blocked
 preparer=load('configuration_under_test',repo/'deployment/prepare_project_upgrade.py')
 original=copy.deepcopy(cfg)
 next_images={'fox':'sha256:'+'7'*64,'converter':'sha256:'+'8'*64}
 selected=target_profile.select_target_profile('jsn-native-project-2616-v1')
 (root/'deployment/target-profile.jsn-project-v2.json').write_bytes(tool.canonical(selected))
 selected_root=root
 if mutation=='same-image':next_images['fox']=images['fox']
 if mutation=='extra-image':next_images['qa']='sha256:'+'9'*64
 if mutation=='namespace':selected_root=root/'different'
 if mutation=='target':
  selected['oci']['region']='ap-singapore-1'
  (root/'deployment/target-profile.jsn-project-v2.json').write_bytes(tool.canonical(selected))
 try:
  next_c,next_r=preparer.compose(cfg,selected_root,next_images)
  assert mutation=='none','MUTATION_ACCEPTED'
  result_c=json.loads(next_c);result_r=json.loads(next_r)
  assert result_c['target_profile']['profile_id']=='jsn-native-project-2616-v1'
  assert result_c['target_profile']['tested_versions']['apex']=='26.1.6'
  assert result_c['images']==next_images and result_r['images']==next_images
  assert result_r['hosted_runtime_configuration_sha256']==tool.sha(next_c)
  assert result_r['opaf_profile']['target_profile_sha256']==result_c['target_profile_sha256']
  for key in ('owner_uid','python','state_root','admin_secret_file','public_mount_roots'):
   assert result_c[key]==original[key]
  assert cfg==original and runtime._selected is runtime._UNSELECTED
  result={'status':'ACTUAL_COMPOSITION_VERIFIED','runtime_selected':False,'host_contacted':False}
 except Exception as error:
  if mutation=='none':raise
  assert str(error)!='MUTATION_ACCEPTED'
  result={'status':'REJECTED','host_contacted':False}
 print(json.dumps(result,sort_keys=True))
'''


@pytest.mark.skipif(os.name!='posix',reason='Actual owner-controlled POSIX source tree')
@pytest.mark.parametrize('mutation',['none','same-image','extra-image','namespace','target'])
def test_real_source_and_profile_composition_preserve_access_and_state(mutation):
    outcome=subprocess.run([sys.executable,'-B','-c',PROBE,str(ROOT),mutation],
        capture_output=True,text=True,timeout=90,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
    assert outcome.returncode==0,outcome.stderr
    value=json.loads(outcome.stdout)
    assert value['host_contacted'] is False
    assert value['status']==('ACTUAL_COMPOSITION_VERIFIED' if mutation=='none' else 'REJECTED')
