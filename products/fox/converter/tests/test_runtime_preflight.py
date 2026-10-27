"""Bounded preflight probes and action binding; external calls are isolated."""
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from types import SimpleNamespace
import zipfile

import pytest

from forms2apex.config import Settings
from forms2apex import runtime_preflight as runtime
from forms2apex.target_profile import TargetProfileError, load_target_profile, target_profile_sha256


ROOT = Path(__file__).resolve().parents[2]
PROFILE_PATH = ROOT/'deployment/target-profile.jsn.json'
PROJECT_PROFILE_PATH = ROOT/'deployment/target-profile.jsn-project-v2.json'
NOW = datetime(2026,10,17,8,tzinfo=timezone.utc)
JOB = 'fox-'+'a'*20
SOURCE_HASH = 'b'*64


@pytest.fixture
def profile():
    return load_target_profile(PROFILE_PATH)


@pytest.fixture
def settings(tmp_path,profile):
    executable = tmp_path/'sqlcl/bin/sql'
    executable.parent.mkdir(parents=True)
    executable.write_text('version fixture; never executed',encoding='utf-8')
    (tmp_path/'sqlcl/lib').mkdir()
    with zipfile.ZipFile(tmp_path/'sqlcl/lib/apexlang-compiler.jar','w') as archive:
        archive.writestr('apexlang_meta_data.json',json.dumps({'buildID':'26.1.0+3102'}))
    jobs = tmp_path/'jobs'
    (jobs/JOB).mkdir(parents=True)
    return Settings(jobs,executable,'F2A_APEX','FORMS2APEX_POC',
        profile['apex']['ords_origin']+'/ords','xai.grok-4.3','xai.grok-4.3','127.0.0.1',8090,'x'*48,
        profile['opaf']['roles']['mapper']['workflow_id'],profile['opaf']['roles']['reviewer']['workflow_id'],
        PROFILE_PATH,'FORMS2APEX_POC')


@pytest.fixture
def attestation(profile):
    opaf = {key:profile['opaf'][key] for key in ('base_url','certificate_sha256','model_authentication','version_number','build_id')}
    return {'schema_version':1,'scope':'opaf-model-environment-v1','trust_boundary':runtime.OPAF_ATTESTATION_TRUST,
        'job_id':JOB,'role':'mapper','source_manifest_sha256':SOURCE_HASH,
        'target_profile_sha256':target_profile_sha256(profile),'observed_at_utc':NOW.isoformat(),
        'opaf':opaf,'workflow':{**profile['opaf']['roles']['mapper'],'published':True},'opaf_version':'26.4.0.0.0'}


def verify_attestation(profile,value,**overrides):
    role=overrides.get('role','mapper')
    invocation={**profile['opaf']['roles'].get(role,{}),'started_at_utc':NOW.isoformat(),
                'completed_at_utc':(NOW+timedelta(seconds=10)).isoformat()}
    args={'job_id':JOB,'role':'mapper','source_manifest_sha256':SOURCE_HASH,'invocation':invocation}
    args.update(overrides)
    return runtime.validate_model_environment_observation(profile,value,**args)


def database_result(profile):
    return {'database':{'db_name':profile['database']['db_name'],'session_user':'FORMS2APEX_POC','current_schema':'FORMS2APEX_POC'},
        'apex':{'workspace':'FORMS2APEX_POC','workspace_id':'9009446931169094','parsing_schema':'FORMS2APEX_POC','workspace_schema_mapping_count':1},
        'apex_version':'26.1.5'}


def sql_output(profile):
    return '\n'.join([
        'FOX_TARGET_BEGIN=1', 'FOX_TARGET_DB_NAME='+profile['database']['db_name'],
        'FOX_TARGET_SESSION_USER=FORMS2APEX_POC','FOX_TARGET_CURRENT_SCHEMA=FORMS2APEX_POC',
        'FOX_TARGET_APEX_VERSION=26.1.5','FOX_TARGET_MAPPING=FORMS2APEX_POC|FORMS2APEX_POC|9009446931169094',
        'FOX_TARGET_MAPPING_COUNT=1','FOX_TARGET_END=1',
    ])


def completed(stdout,code=0,stderr=''):
    return SimpleNamespace(stdout=stdout,stderr=stderr,returncode=code)


def test_settings_defaults_preserve_existing_config_until_profile_enabled(monkeypatch):
    monkeypatch.setenv('F2A_MCP_BEARER_TOKEN','x'*48)
    monkeypatch.delenv('F2A_TARGET_PROFILE_PATH',raising=False)
    monkeypatch.delenv('F2A_APEX_PARSING_SCHEMA',raising=False)
    value=Settings.from_env()
    assert value.target_profile_path is None
    assert value.apex_parsing_schema=='FORMS2APEX_POC'
    with pytest.raises(TargetProfileError,match='active target profile'):
        runtime.bound_target_profile(value)


def test_settings_profile_bindings_and_host_case_are_explicit(settings):
    value=runtime.bound_target_profile(settings)
    assert value['apex']['workspace']=='FORMS2APEX_POC'
    assert value['database']['parsing_schema']=='FORMS2APEX_POC'
    upper=replace(settings,apex_base_url=settings.apex_base_url.replace('asz8eqwfm8unca2-jsnf2apex','ASZ8EQWFM8UNCA2-JSNF2APEX'))
    assert runtime.bound_target_profile(upper)==value


@pytest.mark.parametrize('field,value',[
    ('apex_workspace','OTHER'),('apex_parsing_schema','ADMIN'),('sqlcl_connection_name','OTHER'),
    ('generator_model','other'),('reviewer_model','other'),('opaf_mapper_workflow_id','other'),
    ('opaf_reviewer_workflow_id','other'),('apex_base_url','https://example.invalid/ords'),
    ('apex_base_url','https://user:secret@example.invalid/ords'),
    ('apex_base_url','https://asz8eqwfm8unca2-jsnf2apex.adb.us-ashburn-1.oraclecloudapps.com/ords?secret=value'),
])
def test_settings_drift_fails_before_runtime_probes(settings,field,value):
    with pytest.raises(TargetProfileError,match='settings mismatch'):
        runtime.bound_target_profile(replace(settings,**{field:value}))


def test_enabled_settings_validate_profile_at_startup(monkeypatch,profile,tmp_path):
    env={'F2A_MCP_BEARER_TOKEN':'x'*48,'F2A_TARGET_PROFILE_PATH':str(PROFILE_PATH),
         'F2A_APEX_WORKSPACE':'FORMS2APEX_POC','F2A_APEX_PARSING_SCHEMA':'FORMS2APEX_POC',
         'F2A_SQLCL_CONNECTION_NAME':'F2A_APEX','F2A_APEX_BASE_URL':profile['apex']['ords_origin']+'/ords',
         'F2A_GENERATOR_MODEL':'xai.grok-4.3','F2A_REVIEWER_MODEL':'xai.grok-4.3',
         'F2A_OPAF_MAPPER_WORKFLOW_ID':profile['opaf']['roles']['mapper']['workflow_id'],
         'F2A_OPAF_REVIEWER_WORKFLOW_ID':profile['opaf']['roles']['reviewer']['workflow_id']}
    for key,value in env.items():monkeypatch.setenv(key,value)
    assert Settings.from_env().target_profile_path==PROFILE_PATH
    monkeypatch.setenv('F2A_APEX_PARSING_SCHEMA','OTHER')
    with pytest.raises(TargetProfileError):Settings.from_env()


def test_opaf_attestation_is_exact_and_detached(profile,attestation):
    checked=verify_attestation(profile,attestation)
    assert checked==attestation
    checked['workflow']['model']='changed'
    assert attestation['workflow']['model']=='xai.grok-4.3'


@pytest.mark.parametrize('field,value',[
    ('job_id','fox-'+'c'*20),('role','reviewer'),('source_manifest_sha256','c'*64),
    ('target_profile_sha256','0'*64),('opaf_version','26.4'),('schema_version',True),
    ('trust_boundary','vendor_signature'),('observed_at_utc','2026-10-17T08:00:00'),
])
def test_opaf_attestation_cannot_replay_across_bound_inputs(profile,attestation,field,value):
    attestation[field]=value
    with pytest.raises(TargetProfileError):verify_attestation(profile,attestation)


@pytest.mark.parametrize('field,value',[
    ('base_url','https://other.invalid/agentFactory'),('certificate_sha256','0'*64),
    ('model_authentication','api_key'),('version_number',264001),('build_id',1),
])
def test_opaf_runtime_identity_must_match_measured_pinned_build(profile,attestation,field,value):
    attestation['opaf'][field]=value
    with pytest.raises(TargetProfileError):verify_attestation(profile,attestation)


@pytest.mark.parametrize('role',['mapper','reviewer'])
@pytest.mark.parametrize('field,value',[('published',False),('workflow_id','A'*32),('graph_sha256','0'*64),('model','other')])
def test_both_role_graphs_models_and_published_states_are_bound(profile,attestation,role,field,value):
    attestation['role']=role
    attestation['workflow']={**profile['opaf']['roles'][role],'published':True}
    attestation['workflow'][field]=value
    with pytest.raises(TargetProfileError):verify_attestation(profile,attestation,role=role)


@pytest.mark.parametrize('age,passed',[(0,True),(120,True),(120.000001,False),(-5,True),(-5.000001,False)])
def test_short_action_attestation_clock_bounds(profile,attestation,age,passed):
    attestation['observed_at_utc']=(NOW-timedelta(seconds=age)).isoformat()
    if passed:assert verify_attestation(profile,attestation)
    else:
        with pytest.raises(TargetProfileError):verify_attestation(profile,attestation)


def test_model_observation_unknown_fields_and_invalid_roles_fail(profile,attestation):
    attestation['provider_text']='secret must not leak'
    with pytest.raises(TargetProfileError) as error:verify_attestation(profile,attestation)
    assert 'secret must not leak' not in str(error.value)
    del attestation['provider_text']
    for role in ('delete','admin','generator','inspect'):
        with pytest.raises(TargetProfileError):verify_attestation(profile,attestation,role=role)


def test_historical_model_proof_does_not_expire_after_sealed_review(profile,attestation):
    historical=NOW-timedelta(days=180)
    attestation['observed_at_utc']=historical.isoformat()
    invocation={**profile['opaf']['roles']['mapper'],'started_at_utc':historical.isoformat(),
                'completed_at_utc':(historical+timedelta(seconds=10)).isoformat()}
    assert verify_attestation(profile,attestation,invocation=invocation)==attestation


def test_current_observation_cannot_be_invented_for_old_invocation(profile,attestation):
    historical=NOW-timedelta(days=180)
    invocation={**profile['opaf']['roles']['mapper'],'started_at_utc':historical.isoformat(),
                'completed_at_utc':(historical+timedelta(seconds=10)).isoformat()}
    with pytest.raises(TargetProfileError):verify_attestation(profile,attestation,invocation=invocation)


def test_tooling_reads_actual_sqlcl_display_and_jar_metadata(settings,profile,monkeypatch):
    calls=[]
    def run(args,**kwargs):
        calls.append((args,kwargs))
        return completed('SQLcl: Release 26.1.2.0 Production Build: 26.1.2.132.1334\n')
    monkeypatch.setattr(runtime.subprocess,'run',run)
    value=runtime.collect_tooling_versions(settings,profile)
    assert value['sqlcl']=='26.1.2.0'
    assert value['sqlcl_build']=='26.1.2.132.1334'
    assert value['apexlang_mmd']=='26.1.0+3102'
    assert len(value['compiler_jar_sha256'])==64
    assert calls[0][0]==[str(settings.sqlcl_path),'-V']
    assert calls[0][1]['timeout']==30 and calls[0][1]['check'] is False


@pytest.mark.parametrize('result',[
    completed('SQLcl: Release 26.1.2 Production Build: 26.1.2.132.1334'),
    completed('SQLcl: Release 26.2.0.0 Production Build: 26.2.0.1'),
    completed('unparsed output'),completed('x'*8193),completed('',1,'sensitive provider text'),
])
def test_tooling_wrong_or_unparsed_versions_fail(settings,profile,monkeypatch,result):
    monkeypatch.setattr(runtime.subprocess,'run',lambda *args,**kwargs:result)
    with pytest.raises(TargetProfileError) as error:runtime.collect_tooling_versions(settings,profile)
    assert 'sensitive provider text' not in str(error.value)


@pytest.mark.parametrize('metadata',[{}, {'buildID':'26.1.0+wrong'}, {'buildID':3102}])
def test_real_compiler_resource_must_match(settings,profile,monkeypatch,metadata):
    monkeypatch.setattr(runtime.subprocess,'run',lambda *args,**kwargs:completed('SQLcl: Release 26.1.2.0 Production Build: 26.1.2.132.1334'))
    with zipfile.ZipFile(settings.sqlcl_path.parent.parent/'lib/apexlang-compiler.jar','w') as archive:
        archive.writestr('apexlang_meta_data.json',json.dumps(metadata))
    with pytest.raises(TargetProfileError):runtime.collect_tooling_versions(settings,profile)


def test_saved_schema_probe_is_read_only_and_uses_named_connection(settings,profile,monkeypatch):
    calls=[]
    def script(path,args,commands,root,**kwargs):
        calls.append((path,args,commands,root,kwargs))
        return completed(sql_output(profile))
    monkeypatch.setattr(runtime,'_run_script',script)
    assert runtime.collect_database_identity(settings,profile,settings.jobs_root/JOB)==database_result(profile)
    assert calls[0][1]==['-S','-L','-name','F2A_APEX']
    text='\n'.join(calls[0][2])
    assert 'ADMIN' not in text and 'v$pdbs' not in text.lower()
    assert not any(token in text.lower() for token in ('insert into','update ','delete ','create ','grant ','apex import'))
    assert 'sys_context' in text and 'apex_workspace_schemas' in text


@pytest.mark.parametrize('mutation',[
    lambda text:text.replace('26.1.5','26.1.6'),lambda text:text.replace('FOX_TARGET_END=1',''),
    lambda text:text+'\nORA-00942: sensitive raw text',lambda text:text.replace('MAPPING_COUNT=1','MAPPING_COUNT=2'),
    lambda text:text.replace('SESSION_USER=FORMS2APEX_POC','SESSION_USER=ADMIN'),
    lambda text:text.replace('CURRENT_SCHEMA=FORMS2APEX_POC','CURRENT_SCHEMA=OTHER'),
    lambda text:text+'\nFOX_TARGET_END=1',lambda text:text.replace('9009446931169094','9009446931169095'),
],ids=['patch-drift','missing-end','raw-error','mapping-count','wrong-user','wrong-schema','duplicate','workspace-id'])
def test_saved_schema_wrong_identity_or_incomplete_markers_fail(settings,profile,monkeypatch,mutation):
    monkeypatch.setattr(runtime,'_run_script',lambda *args,**kwargs:completed(mutation(sql_output(profile))))
    with pytest.raises(TargetProfileError):runtime.collect_database_identity(settings,profile,settings.jobs_root/JOB)


class Response:
    def __init__(self,data,status=200,url=runtime.IMDS_URL):self.data=data;self.status=status;self.url=url
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def geturl(self):return self.url
    def read(self,count):return self.data[:count]


def test_imds_requires_exact_scope_and_does_not_use_proxies(profile,monkeypatch):
    metadata={'id':profile['oci']['instance_id'],'compartmentId':profile['oci']['compartment_id'],'canonicalRegionName':'us-ashburn-1'}
    calls=[]
    class Opener:
        def open(self,request,timeout):
            calls.append((request,timeout))
            return Response(json.dumps(metadata).encode())
    def builder(*handlers):
        assert handlers[0].proxies=={}
        assert isinstance(handlers[1],runtime._NoRedirect)
        return Opener()
    monkeypatch.setattr(runtime.urllib.request,'build_opener',builder)
    assert runtime.collect_imds_identity(profile)=={'instance_id':metadata['id'],'compartment_id':metadata['compartmentId'],'region':'us-ashburn-1'}
    assert calls[0][0].full_url==runtime.IMDS_URL and calls[0][1]==5
    assert calls[0][0].get_header('Authorization')=='Bearer Oracle'


@pytest.mark.parametrize('data,status,url',[
    (b'{}',200,runtime.IMDS_URL),(b'not JSON',200,runtime.IMDS_URL),(b'x'*65537,200,runtime.IMDS_URL),
    (b'{}',302,'http://attacker.invalid'),(b'{}',401,runtime.IMDS_URL),
],ids=['missing','invalid-json','oversized','redirect','denied'])
def test_imds_missing_oversized_redirected_or_denied_fails(profile,monkeypatch,data,status,url):
    opener=SimpleNamespace(open=lambda *args,**kwargs:Response(data,status,url))
    monkeypatch.setattr(runtime.urllib.request,'build_opener',lambda *args:opener)
    with pytest.raises(TargetProfileError):runtime.collect_imds_identity(profile)


@pytest.mark.parametrize('status,location,passed',[
    (200,None,True),(302,'/ords/apex',True),(302,'https://evil.invalid/',False),(503,None,False),
    (302,'http://asz8eqwfm8unca2-jsnf2apex.adb.us-ashburn-1.oraclecloudapps.com/',False),
])
def test_ords_probe_never_follows_redirects_outside_pinned_https_origin(profile,monkeypatch,status,location,passed):
    calls=[]
    class Connection:
        def __init__(self,*args,**kwargs):
            calls.append((args,kwargs))
            assert kwargs['context'].check_hostname is True
        def request(self,*args,**kwargs):calls.append((args,kwargs))
        def getresponse(self):return SimpleNamespace(status=status,getheader=lambda key,default:location or default)
        def close(self):calls.append('closed')
    monkeypatch.setattr(runtime.http.client,'HTTPSConnection',Connection)
    if passed:assert runtime.collect_ords_reachability(profile)['https_reachable'] is True
    else:
        with pytest.raises(TargetProfileError):runtime.collect_ords_reachability(profile)
    assert calls[1][0]==('HEAD','/ords/') and calls[-1]=='closed'


def install_full_probe_mocks(monkeypatch,profile):
    calls=[]
    imds={'instance_id':profile['oci']['instance_id'],'compartment_id':profile['oci']['compartment_id'],'region':'us-ashburn-1'}
    tooling={'sqlcl':'26.1.2.0','sqlcl_build':'26.1.2.132.1334','apexlang_mmd':'26.1.0+3102',
        'compiler_jar_sha256':'c'*64,'sqlcl_source':'sqlcl_-V','mmd_source':'apexlang-compiler.jar!apexlang_meta_data.json#buildID'}
    oci={'database_id':profile['oci']['database_id'],'database_compartment_id':profile['oci']['compartment_id'],
         'instance_id':profile['oci']['instance_id'],'instance_compartment_id':profile['oci']['compartment_id'],
         'region':'us-ashburn-1','database_lifecycle_state':'AVAILABLE','instance_lifecycle_state':'RUNNING'}
    def probe(name,value):
        def execute(*args,**kwargs):calls.append(name);return deepcopy(value)
        return execute
    monkeypatch.setattr(runtime,'collect_imds_identity',probe('imds',imds))
    monkeypatch.setattr(runtime,'collect_tooling_versions',probe('tooling',tooling))
    monkeypatch.setattr(runtime,'collect_database_identity',probe('database',database_result(profile)))
    monkeypatch.setattr('forms2apex.oci_identity.collect_oci_identity',probe('oci',oci))
    monkeypatch.setattr(runtime,'collect_ords_reachability',probe('ords',{'ords_origin':profile['apex']['ords_origin'],'ords_base_path':'/ords','https_reachable':True}))
    return calls


def run_full(settings,clock=None):
    return runtime.collect_deterministic_preflight(settings,settings.jobs_root/JOB,job_id=JOB,action='import',
        source_manifest_sha256=SOURCE_HASH,clock=clock or (lambda:NOW))


def test_complete_collector_requires_target_interfaces_but_no_live_opaf(settings,profile,monkeypatch):
    calls=install_full_probe_mocks(monkeypatch,profile)
    receipt=run_full(settings)
    assert calls==['imds','tooling','database','oci','ords']
    assert receipt['passed'] is True and receipt['job_id']==JOB and receipt['action']=='import'
    assert receipt['source_manifest_sha256']==SOURCE_HASH
    assert receipt['observations']['versions']=={key:profile['tested_versions'][key] for key in ('apex','sqlcl','apexlang_mmd')}
    assert receipt['valid_until_utc']==(NOW+timedelta(seconds=300)).isoformat()
    assert receipt['authorizes_oci_changes'] is False
    assert len(receipt['receipt_sha256'])==64
    assert 'opaf' not in receipt['observations'] and 'opaf' not in receipt['observations']['versions']
    assert receipt['sealed_historical_review_required'] is True


def test_wrong_action_stops_before_any_probe(settings,profile,monkeypatch):
    calls=install_full_probe_mocks(monkeypatch,profile)
    with pytest.raises(TargetProfileError):
        runtime.collect_deterministic_preflight(settings,settings.jobs_root/JOB,job_id=JOB,action='delete',
            source_manifest_sha256=SOURCE_HASH,clock=lambda:NOW)
    assert calls==[]


@pytest.mark.parametrize('action', ['prepare-schema', 'reconcile-schema'])
def test_schema_actions_use_the_real_target_gate_and_cannot_authorize_import(settings,profile,monkeypatch,action):
    calls=install_full_probe_mocks(monkeypatch,profile)
    receipt=runtime.collect_deterministic_preflight(settings,settings.jobs_root/JOB,
        job_id=JOB,action=action,source_manifest_sha256=SOURCE_HASH,clock=lambda:NOW)
    assert calls==['imds','tooling','database','oci','ords']
    assert receipt['action']==action and receipt['authorizes_oci_changes'] is False
    assert runtime.verify_action_preflight(receipt,profile,job_id=JOB,action=action,
        source_manifest_sha256=SOURCE_HASH,now=NOW)==receipt
    with pytest.raises(TargetProfileError):
        runtime.verify_action_preflight(receipt,profile,job_id=JOB,action='import',
            source_manifest_sha256=SOURCE_HASH,now=NOW)
    with pytest.raises(TargetProfileError,match='stale'):
        runtime.verify_action_preflight(receipt,profile,job_id=JOB,action=action,
            source_manifest_sha256=SOURCE_HASH,now=NOW+timedelta(seconds=301))


def test_unknown_action_cannot_be_verified_even_with_a_self_consistent_receipt(settings,profile,monkeypatch):
    import hashlib
    install_full_probe_mocks(monkeypatch,profile)
    receipt=run_full(settings)
    receipt['action']='arbitrary-ddl'
    unsigned={key:value for key,value in receipt.items() if key!='receipt_sha256'}
    receipt['receipt_sha256']=hashlib.sha256(runtime._canonical_bytes(unsigned)).hexdigest()
    with pytest.raises(TargetProfileError,match='unsupported'):
        runtime.verify_action_preflight(receipt,profile,job_id=JOB,action='arbitrary-ddl',
            source_manifest_sha256=SOURCE_HASH,now=NOW)


def test_target_snapshot_expiry_during_probes_stops_gate(settings,profile,monkeypatch):
    install_full_probe_mocks(monkeypatch,profile)
    values=iter([NOW,NOW+timedelta(seconds=301)])
    with pytest.raises(TargetProfileError,match='stale'):run_full(settings,clock=lambda:next(values))


def test_oci_denial_does_not_become_partial_pass(settings,profile,monkeypatch):
    calls=install_full_probe_mocks(monkeypatch,profile)
    def denied(*args):raise RuntimeError('Read-only OCI identity lookup denied')
    monkeypatch.setattr('forms2apex.oci_identity.collect_oci_identity',denied)
    with pytest.raises(RuntimeError,match='denied'):run_full(settings)
    assert 'ords' not in calls


def test_action_receipt_freshness_rechecked_locally_after_lock_wait(settings,profile,monkeypatch):
    calls=install_full_probe_mocks(monkeypatch,profile)
    receipt=run_full(settings)
    original=list(calls)
    args={'job_id':JOB,'action':'import','source_manifest_sha256':SOURCE_HASH}
    assert runtime.verify_action_preflight(receipt,profile,**args,now=NOW+timedelta(seconds=299))==receipt
    with pytest.raises(TargetProfileError,match='stale'):
        runtime.verify_action_preflight(receipt,profile,**args,now=NOW+timedelta(seconds=301))
    assert calls==original  # A check must not refresh or replay provider/model calls.


@pytest.mark.parametrize('field,value',[('job_id','another-job'),('action','release'),('source_manifest_sha256','f'*64)])
def test_action_receipt_is_not_transferable_to_another_write(settings,profile,monkeypatch,field,value):
    install_full_probe_mocks(monkeypatch,profile)
    receipt=run_full(settings)
    args={'job_id':JOB,'action':'import','source_manifest_sha256':SOURCE_HASH,'now':NOW}
    args[field]=value
    with pytest.raises(TargetProfileError):runtime.verify_action_preflight(receipt,profile,**args)


def test_mutated_action_receipt_is_rejected_before_write(settings,profile,monkeypatch):
    install_full_probe_mocks(monkeypatch,profile)
    receipt=run_full(settings)
    receipt['valid_until_utc']=(NOW+timedelta(days=1)).isoformat()
    with pytest.raises(TargetProfileError,match='changed'):
        runtime.verify_action_preflight(receipt,profile,job_id=JOB,action='import',source_manifest_sha256=SOURCE_HASH,now=NOW)


def project_settings(settings):
    profile = load_target_profile(PROJECT_PROFILE_PATH)
    return replace(settings, target_profile_path=PROJECT_PROFILE_PATH,
        opaf_mapper_workflow_id=profile['opaf']['roles']['mapper']['workflow_id'],
        opaf_reviewer_workflow_id=profile['opaf']['roles']['reviewer']['workflow_id'])


def test_mapped_profile_is_selected_by_explicit_bound_environment(settings,monkeypatch):
    selected = project_settings(settings)
    profile = runtime.bound_target_profile(selected)
    assert profile['profile_id'] == 'jsn-native-project-v2'
    assert runtime.bound_target_profile(settings)['profile_id'] == 'jsn-native-beta-v1'
    env = {'F2A_MCP_BEARER_TOKEN': 'x'*48, 'F2A_TARGET_PROFILE_PATH': str(PROJECT_PROFILE_PATH),
        'F2A_APEX_WORKSPACE': selected.apex_workspace, 'F2A_APEX_PARSING_SCHEMA': selected.apex_parsing_schema,
        'F2A_SQLCL_CONNECTION_NAME': selected.sqlcl_connection_name, 'F2A_APEX_BASE_URL': selected.apex_base_url,
        'F2A_GENERATOR_MODEL': selected.generator_model, 'F2A_REVIEWER_MODEL': selected.reviewer_model,
        'F2A_OPAF_MAPPER_WORKFLOW_ID': selected.opaf_mapper_workflow_id,
        'F2A_OPAF_REVIEWER_WORKFLOW_ID': selected.opaf_reviewer_workflow_id}
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    assert runtime.bound_target_profile(Settings.from_env()) == profile
    monkeypatch.setenv('F2A_OPAF_MAPPER_WORKFLOW_ID', settings.opaf_mapper_workflow_id)
    with pytest.raises(TargetProfileError, match='settings mismatch'):
        Settings.from_env()


@pytest.mark.parametrize('new_settings', [False, True], ids=['old-settings-new-file', 'new-settings-old-file'])
def test_selectable_profile_swap_blocks_before_any_probe(settings,profile,monkeypatch,new_settings):
    calls = install_full_probe_mocks(monkeypatch, profile)
    wrong = replace(project_settings(settings), target_profile_path=PROFILE_PATH) if new_settings else replace(
        settings, target_profile_path=PROJECT_PROFILE_PATH)
    with pytest.raises(TargetProfileError, match='settings mismatch'):
        run_full(wrong)
    assert calls == []


def test_configured_profile_is_reloaded_and_never_uses_cached_fallback(settings,profile,tmp_path,monkeypatch):
    path = tmp_path/'selected.json'
    path.write_text(json.dumps(profile), encoding='utf-8')
    selected = replace(settings, target_profile_path=path)
    retained = runtime.bound_target_profile(selected)
    calls = install_full_probe_mocks(monkeypatch, profile)
    path.write_bytes(PROJECT_PROFILE_PATH.read_bytes())
    with pytest.raises(TargetProfileError, match='settings mismatch'):
        run_full(selected)
    path.unlink()
    with pytest.raises(TargetProfileError, match='unavailable'):
        run_full(selected)
    with pytest.raises(TargetProfileError, match='active target profile'):
        run_full(replace(selected, target_profile_path=None))
    assert retained == profile and calls == []


def test_old_action_receipt_cannot_authorize_new_selected_profile(settings,profile,monkeypatch):
    install_full_probe_mocks(monkeypatch, profile)
    receipt = run_full(settings)
    current = runtime.bound_target_profile(project_settings(settings))
    with pytest.raises(TargetProfileError, match='profile_sha256'):
        runtime.verify_action_preflight(receipt,current,job_id=JOB,action='import',
            source_manifest_sha256=SOURCE_HASH,now=NOW)


def test_mapped_profile_deterministic_receipt_is_bound_to_selected_tuple(settings,monkeypatch):
    selected = project_settings(settings)
    profile = runtime.bound_target_profile(selected)
    calls = install_full_probe_mocks(monkeypatch, profile)
    receipt = run_full(selected)
    assert calls == ['imds','tooling','database','oci','ords']
    assert receipt['profile_sha256'] == target_profile_sha256(profile)
    assert runtime.verify_action_preflight(receipt,profile,job_id=JOB,action='import',
        source_manifest_sha256=SOURCE_HASH,now=NOW) == receipt


@pytest.mark.parametrize('bind_new_roles', [False, True], ids=['file-only-swap', 'complete-selection-change'])
def test_final_write_gate_reloads_current_profile_after_preflight(settings,profile,tmp_path,monkeypatch,bind_new_roles):
    import hashlib
    from forms2apex.workflow import ConverterWorkflow
    from forms2apex.target_profile import _canonical_bytes

    install_full_probe_mocks(monkeypatch, profile)
    receipt = run_full(settings)
    workflow = ConverterWorkflow(settings)
    root = settings.jobs_root/JOB
    (root/'intake').mkdir()
    (root/'intake/manifest.json').write_text(json.dumps({'source_manifest_sha256': SOURCE_HASH}), encoding='utf-8')
    binding = {'synthetic_fixture_artifact': 'unchanged'}
    monkeypatch.setattr(workflow, 'assert_artifact_binding', lambda _job: binding)
    raw = _canonical_bytes({'schema_version': 1, 'artifact_binding': binding, 'preflight': receipt})
    name = 'target-check-import-'+'a'*16+'.json'
    (root/name).write_bytes(raw)
    reference = {'file': name, 'sha256': hashlib.sha256(raw).hexdigest(), 'action': 'import',
        'profile_sha256': receipt['profile_sha256'], 'receipt_sha256': receipt['receipt_sha256']}
    workflow.settings = project_settings(settings) if bind_new_roles else replace(settings,
        target_profile_path=PROJECT_PROFILE_PATH)
    with pytest.raises(TargetProfileError, match='profile_sha256' if bind_new_roles else 'settings mismatch'):
        workflow.assert_native_preflight_fresh(JOB, reference, 'import')
    assert (root/name).read_bytes() == raw
