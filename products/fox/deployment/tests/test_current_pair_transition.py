"""Transition contracts only; no cloud, services, journals or live data used."""
from copy import deepcopy
import importlib.util
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import pytest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('current_transition_contracts',ROOT/'deployment/current_pair_transition.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
support_spec=importlib.util.spec_from_file_location('transition_support_contracts',ROOT/'deployment/cutover_project_release.py')
S=importlib.util.module_from_spec(support_spec);support_spec.loader.exec_module(S)


def plan():
    value={'schema_version':1,'scope':M.SCOPE,'controller_sha256':'a'*64}
    for number,name in enumerate(M.REFS):
        value[name]={'path':'/home/opc/private/'+name+'.json','sha256':format(number+1,'x')*64}
    value['old_unit']['path']=M.UNIT.as_posix()
    return value


def test_plan_is_exact_and_returns_no_implicit_authority():
    value=plan();raw=M.cb(value)
    assert M.plan_document(raw,M.sha(raw))==value
    assert 'apply' not in value and 'approved' not in value


def v2_plan():
    value=plan();value.update(schema_version=2,scope=M.SCOPE_V2)
    value['snapshot_adapter']={'path':'/home/opc/new-bundle/qa/operator/hosted_snapshot.py','sha256':'b'*64}
    return value


def test_v2_plan_requires_an_explicit_hash_bound_adapter():
    value=v2_plan();raw=M.cb(value)
    assert M.plan_document(raw,M.sha(raw))==value
    old=plan();old['snapshot_adapter']=value['snapshot_adapter'];raw=M.cb(old)
    with pytest.raises(M.TransitionError):M.plan_document(raw,M.sha(raw))
    del value['snapshot_adapter'];raw=M.cb(value)
    with pytest.raises(M.TransitionError):M.plan_document(raw,M.sha(raw))


def test_v2_can_pin_candidate_plan_without_changing_legacy_transition_contract():
    value = v2_plan()
    value['candidate_plan'] = {'path': '/home/opc/private/activation-plan.json', 'sha256': 'c' * 64}
    raw = M.cb(value)
    assert M.plan_document(raw, M.sha(raw)) == value
    assert 'candidate_plan' in M.references(value)
    legacy = plan(); legacy['candidate_plan'] = value['candidate_plan']; raw = M.cb(legacy)
    with pytest.raises(M.TransitionError, match='TRANSITION_PLAN_INVALID'):
        M.plan_document(raw, M.sha(raw))


@pytest.mark.parametrize('fault', ['none', 'missing', 'path', 'sha'])
@pytest.mark.parametrize('option', ['hosted_forms_queue', 'prototype_authority'])
def test_opt_in_candidate_requires_exact_transition_reference(fault, option):
    from test_activate_project_release import prototype_configuration
    path = Path('/home/opc/private/activation-plan.json')
    candidate = {option: '/data/native-preparations' if option == 'hosted_forms_queue' else prototype_configuration()}
    raw = M.cb(candidate)
    value = v2_plan(); value['candidate_plan'] = {'path': str(path), 'sha256': M.sha(raw)}
    if fault == 'missing': del value['candidate_plan']
    elif fault == 'path': value['candidate_plan']['path'] = '/home/opc/other.json'
    elif fault == 'sha': value['candidate_plan']['sha256'] = '0' * 64
    if fault == 'none': M.validate_candidate_plan_reference(value, path, raw, candidate)
    else:
        with pytest.raises(M.TransitionError):
            M.validate_candidate_plan_reference(value, path, raw, candidate)
    M.validate_candidate_plan_reference(v2_plan(), path, M.cb({}), {})


@pytest.mark.parametrize('queue', [None, '/data/native-preparations'])
@pytest.mark.parametrize('fault', ['none', 'missing', 'changed', 'unapproved'])
@pytest.mark.parametrize('prototype', [False, True])
def test_transition_preflight_rechecks_exact_planned_queue_before_service_actions(queue, fault, prototype, tmp_path, monkeypatch):
    """Real environment/candidate gates with synthetic host observations only."""
    from test_activate_project_release import M as A, prepared, profile, upgrade_plan, prototype_configuration
    context = object.__new__(M.Transition); context.A = A
    context.p = {'old_unit': {'sha256': A.sha(b'synthetic unit')},
                 'new_unit': {'path': '/private/new.service'}}
    context.R = 'e' * 64; context.candidate_plan = upgrade_plan(queue)
    context.cfg = {'python': {'path': '/usr/bin/python3'}, 'state_root': str(tmp_path)}
    rows = {role: prepared(role) for role in ('fox', 'converter')}
    option = prototype_configuration() if prototype else None
    if prototype:
        context.candidate_plan['prototype_authority'] = option
        for role in rows:
            new_env = A.environment(rows[role][6]); new_env.update(A.prototype_environment(role, option))
            if role == 'fox':
                new_env['FOX_PUBLIC_ORIGIN'] = option['origin']
                old_env = A.environment(rows[role][5]); old_env['FOX_PUBLIC_ORIGIN'] = option['origin']
                rows[role][5]['Config']['Env'] = [key + '=' + val for key, val in sorted(old_env.items())]
            rows[role][6]['Config']['Env'] = [key + '=' + val for key, val in sorted(new_env.items())]
    old = {name: rows[role][5] for role, name in (('fox', 'fox'), ('converter', 'forms2apex-mcp'))}
    old['oracle-applied-ai-label'] = {'Id': '3' * 64, 'State': {'Running': True}}
    context.old = SimpleNamespace(preflight=lambda: None)
    context.old_pins = {name: {'id': item['Id']} for name, item in old.items()}
    context.pins = {name: {'id': rows[role][6]['Id']} for role, name in (('fox', 'fox'), ('converter', 'forms2apex-mcp'))}
    context.snapshot = {'runtime': {'tls': {'id': '4' * 64, 'image': 'sha256:' + '5' * 64}}}
    context.snapshot_raw = b'synthetic snapshot'; context.p['snapshot'] = {'sha256': '6' * 64}
    context.release = rows['fox'][1]; context.root = tmp_path; context.retained = {}
    context.scope = lambda: None; context.health = lambda: None
    context.M = SimpleNamespace(validate_snapshot_bindings=lambda *_: None,
        configuration_signature=S.configuration_signature, require_never_started=lambda _: None,
        service_state=lambda *_: {'MainPID': '0', 'ActiveState': 'inactive'}, verify_service_unit=lambda *_: None)
    context.S = SimpleNamespace(_inspect=lambda *_: {'Name': 'fox-https', 'Image': '5' * 64,
        'State': {'Running': True, 'Pid': 100}}, measure=lambda *_args, **_kwargs: {'fits_current_limits': True})
    candidates = {rows[role][6]['Id']: rows[role][6] for role in rows}
    fox = candidates[rows['fox'][6]['Id']]
    if queue is not None and fault != 'missing':
        fox['Config']['Env'].append('FOX_HOSTED_FORMS_QUEUE=' + (queue if fault != 'changed' else queue + '-changed'))
    if fault == 'unapproved' and queue is None:
        fox['Config']['Env'].append('FOX_HOSTED_FORMS_QUEUE=/data/native-preparations')
    calls = []
    monkeypatch.setattr(A, 'inspect_container', lambda name: old[name] if name in old else candidates[name])
    monkeypatch.setattr(A, 'read', lambda path, **kwargs: b'synthetic unit' if path == M.UNIT else A.canonical(profile()))
    monkeypatch.setattr(A, 'validate_hosted_queue', lambda plan, python: calls.append(('private-queue', plan.get('hosted_forms_queue'))))
    monkeypatch.setattr(A, 'validate_prototype_authority', lambda plan, cfg, fox: calls.append(('prototype', plan.get('prototype_authority'))))
    monkeypatch.setattr(A, 'command', lambda argv: (calls.append(('host-observation', argv)) or
        (b'enabled\n' if 'is-enabled' in argv else b'')))
    monkeypatch.setattr(M.os, 'getxattr', lambda *_: b'system_u:object_r:container_file_t:s0:c75,c812', raising=False)
    fails = (queue is not None and fault in ('missing', 'changed')) or (queue is None and fault == 'unapproved')
    if fails:
        with pytest.raises(A.ActivationError, match='STOPPED_CANDIDATE_CONFIGURATION_CHANGED'):
            context.preflight()
        assert calls == [('private-queue', queue), ('prototype', option)]
    else:
        context.preflight()
        assert calls[0] == ('private-queue', queue)
        assert calls[1] == ('prototype', option)


@pytest.mark.parametrize('fault',['path','sha','no-measured-file'])
def test_v2_adapter_cannot_import_outside_the_verified_new_bundle(fault,monkeypatch):
    value=v2_plan();inventory={'files':{'qa/operator/hosted_snapshot.py':'b'*64}}
    if fault=='path':value['snapshot_adapter']['path']='/home/opc/old-bundle/qa/operator/hosted_snapshot.py'
    elif fault=='sha':value['snapshot_adapter']['sha256']='c'*64
    else:inventory['files'].clear()
    monkeypatch.setattr(M,'load',lambda *_:pytest.fail('Unbound adapter reached import'))
    with pytest.raises(M.TransitionError,match='SNAPSHOT_ADAPTER_OUTSIDE_NEW_BUNDLE'):
        M.snapshot_adapter(value,object(),{'layout':{'release_root':'/home/opc/new-bundle'}},inventory)


def test_v1_uses_original_reader_v2_loads_a_distinct_measured_module(monkeypatch):
    baseline=object();adapter=object();calls=[]
    monkeypatch.setattr(M,'load',lambda name,ref:(calls.append((name,ref)) or adapter))
    assert M.snapshot_adapter(plan(),baseline,{}, {}) is baseline and not calls
    value=v2_plan()
    assert M.snapshot_adapter(value,baseline,{'layout':{'release_root':'/home/opc/new-bundle'}},
        {'files':{'qa/operator/hosted_snapshot.py':'b'*64}}) is adapter
    assert calls==[('qa.operator._current_transition_snapshot',value['snapshot_adapter'])]


@pytest.mark.parametrize('fault',['sha','extra','bool','scope','missing','path','traversal','drive','ref-extra','same-I','same-unit'])
def test_invalid_plan_cannot_reach_host_or_effects(fault,monkeypatch):
    value=plan()
    if fault=='extra':value['approved']=True
    elif fault=='bool':value['schema_version']=True
    elif fault=='scope':value['scope']='unknown'
    elif fault=='missing':del value['snapshot']
    elif fault=='path':value['snapshot']['path']='relative'
    elif fault=='traversal':value['snapshot']['path']='/home/opc/../snapshot'
    elif fault=='drive':value['snapshot']['path']='C:/private/file'
    elif fault=='ref-extra':value['helper']['ready']=True
    elif fault=='same-I':value['new_installation']=deepcopy(value['old_installation'])
    elif fault=='same-unit':value['new_unit']['path']=M.UNIT.as_posix()
    raw=M.cb(value)
    monkeypatch.setattr(M,'load',lambda *_:pytest.fail('Invalid plan reached an import'))
    with pytest.raises(M.TransitionError):M.plan_document(raw,'0'*64 if fault=='sha' else M.sha(raw))


@pytest.mark.parametrize('program',['BACKEND','NEW_PROBE'])
def test_actual_serialized_read_only_programs_compile_without_running(program):
    compile(getattr(M,program),program,'exec')


def test_new_probe_does_not_pump_replay_accept_or_run_a_conversion_tool():
    for forbidden in ('.pump(','.reserve_retry(','.complete_retry(','.import_validated_draft(','.generate_apex_draft(','.accept('):
        assert forbidden not in M.NEW_PROBE
    assert "completed_jobs']==[]" in M.NEW_PROBE
    assert 'GENUINE_NEW_VERIFIER_IDLE_CLAIM' in M.NEW_PROBE
    assert "batch_completion_claimed':False" in M.NEW_PROBE
    assert "if not (directory/'complete.json').exists():continue" not in M.NEW_PROBE
    assert 'admission.check()' in M.NEW_PROBE


@pytest.mark.parametrize('new_label,new_process',[
    ('unconfined_u:object_r:data_home_t:s0','system_u:system_r:container_t:s0:c1,c2'),
    ('system_u:object_r:container_file_t:s0:c3,c4','system_u:system_r:container_t:s0:c1,c2'),
    ('system_u:object_r:container_file_t:s0:c1,c2','system_u:system_r:container_t:s0:c3,c4'),
])
def test_wrong_new_profile_access_label_stops_before_service_actions(new_label,new_process):
    with pytest.raises(M.TransitionError,match='PREPARE_NEW_PROFILE_ACCESS_LABELS_FIRST'):
        M.validate_profile_access_labels('system_u:object_r:container_file_t:s0:c1,c2',new_label,
            'system_u:system_r:container_t:s0:c1,c2',new_process)


def test_matching_profile_labels_and_genuinely_unlabelled_hosts_are_distinct_valid_cases():
    label='system_u:object_r:container_file_t:s0:c1,c2';process='system_u:system_r:container_t:s0:c1,c2'
    M.validate_profile_access_labels(label,label,process,process)
    M.validate_profile_access_labels(None,None,'','')


def container():
    return {'Id':'1'*64,'Name':'fox','Image':'a'*64,'Config':{'Env':['SAFE=synthetic']},
        'HostConfig':{},'Mounts':[],'ProcessLabel':'synthetic','MountLabel':'synthetic',
        'State':{'Running':True,'Pid':12,'StartedAt':'2026-11-04T00:00:00Z'}}


@pytest.mark.parametrize('fault',['none','id','name','image','state','pid','config'])
def test_exact_container_observation_cannot_hide_changes(fault):
    item=container();expected=S.configuration_signature(None,item)
    if fault=='id':item['Id']='2'*64
    elif fault=='name':item['Name']='different'
    elif fault=='image':item['Image']='b'*64
    elif fault=='state':item['State']['Running']=False
    elif fault=='pid':item['State']['Pid']=True
    elif fault=='config':item['Config']['Env']=['SAFE=changed']
    context=object.__new__(M.Transition)
    context.A=SimpleNamespace(inspect_container=lambda _id:item);context.M=S
    if fault=='none':assert context.check_container({'id':'1'*64,'image':'sha256:'+'a'*64},'fox',expected,running=True)==item
    else:
        with pytest.raises(M.TransitionError):context.check_container({'id':'1'*64,'image':'sha256:'+'a'*64},'fox',expected,running=True)


def test_effect_scope_is_rechecked_before_the_original_create_once_boundary():
    context=object.__new__(M.Transition);trace=[]
    context.scope=lambda:trace.append('real-scope-boundary')
    context.root=Path('/synthetic/operation');context.digest='a'*64
    context.A=SimpleNamespace(create_once=lambda *args:(trace.append('create-once-boundary') or b''))
    context.effect('synthetic',['synthetic-command'])
    assert trace==['real-scope-boundary','create-once-boundary']


@pytest.mark.skipif(os.name!='posix',reason='Actual no-follow ownership checks')
def test_initial_read_refuses_a_link_even_with_identical_bytes(tmp_path):
    target=tmp_path/'source.py';target.write_bytes(b'synthetic source\n')
    linked=tmp_path/'link.py';linked.symlink_to(target)
    with pytest.raises(M.TransitionError):M.initial_read(linked)


def test_closed_stage_and_clean_check_transcripts_are_distinct_failure_families():
    old={'job_id':'fox-'+'1'*20,'assessment_sha256':'a'*64,
         'retained_sha256':{f'old-{number}.json':'b'*64 for number in range(7)}}
    stage={'job_id':'fox-'+'2'*20,'assessment_sha256':'c'*64,
           'retained_sha256':{f'stage-{number}.json':'d'*64 for number in range(17)}}
    value={'closed_prechecks':{'session-'+'1'*24:old},'closed_qa_stages':{'session-'+'2'*24:stage}}
    result=M.retained_failure_sessions(value)
    assert result['session-'+'1'*24]['failure_family']=='clean_check'
    assert result['session-'+'2'*24]['failure_family']=='qa_stage'
    assert 'failure_family' not in old and 'failure_family' not in stage


def test_completed_prebusiness_qa_has_its_own_exact_22_file_family():
    row={'job_id':'fox-'+'3'*20,'assessment_sha256':'e'*64,
         'retained_sha256':{f'qa-{i}.json':'f'*64 for i in range(22)}}
    value={'closed_prechecks':{},'closed_qa_stages':{},'closed_project_prewrite':{'session-'+'3'*24:row}}
    result=M.retained_failure_sessions(value)
    assert result['session-'+'3'*24]['failure_family']=='project_prewrite'
    assert 'failure_family' not in row
    value['closed_project_prewrite']['session-'+'3'*24]['retained_sha256'].pop('qa-0.json')
    with pytest.raises(M.TransitionError):M.retained_failure_sessions(value)


@pytest.mark.parametrize('fault',['missing','duplicate','wrong-count','unsafe-name','bad-sha'])
def test_failure_family_mismatch_never_exempts_a_pending_session(fault):
    session='session-'+'1'*24
    row={'job_id':'fox-'+'1'*20,'assessment_sha256':'a'*64,
         'retained_sha256':{f'old-{number}.json':'b'*64 for number in range(7)}}
    value={'closed_prechecks':{session:row},'closed_qa_stages':{}}
    if fault=='missing':del value['closed_qa_stages']
    elif fault=='duplicate':value['closed_qa_stages'][session]=row
    elif fault=='wrong-count':row['retained_sha256'].pop('old-0.json')
    elif fault=='unsafe-name':row['retained_sha256']['../outside.json']=row['retained_sha256'].pop('old-0.json')
    else:row['assessment_sha256']='not-a-sha'
    with pytest.raises(M.TransitionError):M.retained_failure_sessions(value)
