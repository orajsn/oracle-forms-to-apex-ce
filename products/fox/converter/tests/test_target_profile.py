"""Pure target/version contracts; no Oracle connections or OCI writes."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest

from forms2apex.target_profile import (
    TargetProfileError, MAX_PROFILE_BYTES, TRUST_BOUNDARY,
    load_target_profile, target_profile_sha256, validate_target_profile,
    verify_target_preflight, verify_deterministic_target_preflight,
    validate_historical_target_profile,
)


ROOT = Path(__file__).resolve().parents[2]
PROFILE_FILE = ROOT/'deployment/target-profile.jsn.json'
PROJECT_PROFILE_FILE = ROOT/'deployment/target-profile.jsn-project-v2.json'
TEMPLATE_FILE = ROOT/'deployment/customer-template.example.json'
NOW = datetime(2026, 10, 17, 8, 0, tzinfo=timezone.utc)


@pytest.fixture(params=[PROFILE_FILE, PROJECT_PROFILE_FILE], ids=['legacy-native', 'mapped-project-v2'])
def profile(request):
    return load_target_profile(request.param)


@pytest.fixture
def observed(profile):
    oci, database, apex, opaf = (profile[key] for key in ('oci','database','apex','opaf'))
    return {
        'schema_version':1, 'trust_boundary':TRUST_BOUNDARY,
        'profile_sha256':target_profile_sha256(profile), 'observed_at_utc':NOW.isoformat(),
        'oci':{
            'database_id':oci['database_id'], 'database_compartment_id':oci['compartment_id'],
            'instance_id':oci['instance_id'], 'instance_compartment_id':oci['compartment_id'],
            'region':oci['region'], 'database_lifecycle_state':'AVAILABLE', 'instance_lifecycle_state':'RUNNING',
        },
        'database':{'db_name':database['db_name'],'session_user':database['session_user'],'current_schema':database['parsing_schema']},
        'apex':{**apex,'parsing_schema':database['parsing_schema'],'workspace_schema_mapping_count':1,'https_reachable':True},
        'sqlcl':deepcopy(profile['sqlcl']),
        'opaf':{
            'base_url':opaf['base_url'], 'certificate_sha256':opaf['certificate_sha256'],
            'model_authentication':opaf['model_authentication'],
            'version_number':opaf['version_number'], 'build_id':opaf['build_id'],
            'roles':{role:{**value,'published':True} for role,value in opaf['roles'].items()},
        },
        'versions':deepcopy(profile['tested_versions']),
    }


def replace(value,path,replacement):
    current=value
    parts=path.split('.')
    for part in parts[:-1]:
        current=current[part]
    current[parts[-1]]=replacement


def test_checked_in_profile_has_canonical_digest_and_detached_values(profile):
    encoded=json.dumps(profile,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
    assert target_profile_sha256(profile)==hashlib.sha256(encoded).hexdigest()
    reordered=dict(reversed(list(profile.items())))
    assert target_profile_sha256(reordered)==target_profile_sha256(profile)
    validated=validate_target_profile(profile)
    validated['scope']['supported_operations'].append('delete')
    assert profile['scope']['supported_operations']==['query','insert','update']
    assert isinstance(profile['apex']['workspace_id'],str)


@pytest.mark.parametrize('path,replacement',[
    ('schema_version',True), ('schema_version',1.0), ('active',1), ('active',False),
    ('profile_id','customer-approved'),
    ('scope.conversion_profile','unrestricted-forms'), ('scope.data_mode','customer_records'),
    ('scope.customer_deployment_authorized',True), ('scope.existing_resources_only',False),
    ('scope.supported_operations',['query','insert','update','delete']),
    ('oci.compartment_id','ocid1.compartment.oc1..other'),
    ('oci.database_id','ocid1.autonomousdatabase.oc1.iad.other'),
    ('oci.instance_id','ocid1.instance.oc1.iad.other'), ('oci.region','ap-singapore-1'),
    ('database.db_name','OTHER_DB'), ('database.session_user','ADMIN'),
    ('database.parsing_schema','OTHER_SCHEMA'), ('apex.workspace','OTHER_WORKSPACE'),
    ('apex.workspace_id',9009446931169094),
    ('apex.ords_origin','https://attacker.invalid'), ('apex.ords_base_path','/other'),
    ('sqlcl.saved_connection','ADMIN'), ('opaf.base_url','https://attacker.invalid/agentFactory'),
    ('opaf.certificate_sha256','0'*64), ('opaf.model_authentication','api_key'),
    ('opaf.roles.mapper.workflow_id','B'*32), ('opaf.roles.reviewer.workflow_id','A'*32),
    ('opaf.roles.mapper.graph_sha256','0'*64), ('opaf.roles.reviewer.graph_sha256','0'*64),
    ('opaf.roles.mapper.model','xai.grok-code-fast-1'), ('opaf.roles.reviewer.model','unknown'),
    ('tested_versions.apex','26.1.6'), ('tested_versions.sqlcl','26.2'),
    ('tested_versions.apexlang_mmd','26.1.0+9999'), ('tested_versions.opaf','26.5'),
])
def test_profile_drift_rejected(profile,path,replacement):
    replace(profile,path,replacement)
    with pytest.raises(TargetProfileError):
        validate_target_profile(profile)


@pytest.mark.parametrize('root',['scope','oci','database','apex','sqlcl','opaf','tested_versions'])
def test_unknown_fields_and_secrets_rejected_without_echo(profile,root):
    profile[root]['password']='sensitive-value-must-not-appear'
    with pytest.raises(TargetProfileError) as error:
        validate_target_profile(profile)
    assert 'sensitive-value' not in str(error.value)
    assert 'password' not in str(error.value)


def test_customer_template_cannot_activate(profile):
    with pytest.raises(TargetProfileError,match='Inactive'):
        load_target_profile(TEMPLATE_FILE)
    template=json.loads(TEMPLATE_FILE.read_text(encoding='utf-8'))
    assert template['active'] is False
    assert template['scope']['data_mode']=='synthetic_test_only'
    template['active']=True
    with pytest.raises(TargetProfileError):
        validate_target_profile(template)
    # Even a filled template cannot authorize a new/customer target.
    profile['database']['parsing_schema']='FOX_QA_261017A'
    profile['database']['session_user']='FOX_QA_261017A'
    profile['apex']['workspace']='FOX_QA_261017A'
    with pytest.raises(TargetProfileError):
        validate_target_profile(profile)


@pytest.mark.parametrize('raw',[
    b'{}',b'[]',b'null',b'not JSON',b'\xff',b' '* (MAX_PROFILE_BYTES+1),
    b'{"active":true,"active":false}',
],ids=['empty-object','array','null','invalid-json','invalid-utf8','oversized','duplicate-key'])
def test_profile_reader_rejects_malformed_and_oversized_files(tmp_path,raw):
    path=tmp_path/'target.json'
    path.write_bytes(raw)
    with pytest.raises(TargetProfileError):
        load_target_profile(path)


def test_reader_rejects_missing_directory_and_linked_paths(tmp_path,monkeypatch):
    with pytest.raises(TargetProfileError):
        load_target_profile(tmp_path/'missing.json')
    with pytest.raises(TargetProfileError):
        load_target_profile(tmp_path)
    original=Path.is_symlink
    monkeypatch.setattr(Path,'is_symlink',lambda path:path==PROFILE_FILE or original(path))
    with pytest.raises(TargetProfileError,match='linked'):
        load_target_profile(PROFILE_FILE)


def test_preflight_is_fresh_bound_operator_attestation_not_authorization(profile,observed):
    receipt=verify_target_preflight(profile,observed,now=NOW)
    assert receipt['passed'] is True
    assert receipt['profile_sha256']==target_profile_sha256(profile)
    assert receipt['trust_boundary']==TRUST_BOUNDARY
    assert receipt['read_only'] is True
    assert receipt['authorizes_oci_changes'] is False
    assert receipt['business_behavior_verified'] is False
    assert receipt['target']['workspace']=='FORMS2APEX_POC'
    assert receipt['target']['parsing_schema']=='FORMS2APEX_POC'
    assert receipt['valid_until_utc']==(NOW+timedelta(seconds=300)).isoformat()
    assert len(receipt['observation_sha256'])==64
    receipt['tested_versions']['apex']='not mutable shared input'
    assert profile['tested_versions']['apex']=='26.1.5'
    assert observed['versions']['apex']=='26.1.5'


@pytest.mark.parametrize('path,replacement',[
    ('schema_version',True), ('trust_boundary','vendor_attestation'), ('profile_sha256','0'*64),
    ('oci.database_id','another database'), ('oci.instance_id','another vm'),
    ('oci.database_compartment_id','another compartment'), ('oci.instance_compartment_id','another compartment'),
    ('oci.region','ap-singapore-1'), ('oci.database_lifecycle_state','STOPPED'), ('oci.instance_lifecycle_state','STOPPED'),
    ('database.db_name','another DB'), ('database.session_user','ADMIN'), ('database.current_schema','OTHER'),
    ('apex.workspace','OTHER'), ('apex.parsing_schema','OTHER'), ('apex.workspace_id','1'),
    ('apex.workspace_schema_mapping_count',True), ('apex.workspace_schema_mapping_count',0),
    ('apex.workspace_schema_mapping_count',2), ('apex.https_reachable',False),
    ('apex.ords_origin','https://attacker.invalid'), ('apex.ords_base_path','/changed'),
    ('sqlcl.saved_connection','OTHER'), ('opaf.base_url','https://attacker.invalid/agentFactory'),
    ('opaf.certificate_sha256','0'*64), ('opaf.model_authentication','api_key'),
    ('opaf.roles.mapper.workflow_id','A'*32), ('opaf.roles.reviewer.workflow_id','B'*32),
    ('opaf.roles.mapper.graph_sha256','0'*64), ('opaf.roles.reviewer.graph_sha256','0'*64),
    ('opaf.roles.mapper.model','different'), ('opaf.roles.reviewer.model','different'),
    ('opaf.roles.mapper.published',False), ('opaf.roles.reviewer.published',False),
    ('versions.apex','26.1.4'), ('versions.sqlcl','26.1.3'),
    ('versions.apexlang_mmd','26.2.0+3102'), ('versions.opaf','26.5'),
])
def test_preflight_wrong_identity_version_or_role_fails(profile,observed,path,replacement):
    replace(observed,path,replacement)
    with pytest.raises(TargetProfileError):
        verify_target_preflight(profile,observed,now=NOW)


@pytest.mark.parametrize('seconds,passed',[
    (0,True),(299,True),(300,True),(300.000001,False),(-5,True),(-5.000001,False),(-60,False),
])
def test_strict_clock_age_and_future_skew_bounds(profile,observed,seconds,passed):
    observed['observed_at_utc']=(NOW-timedelta(seconds=seconds)).isoformat()
    if passed:
        assert verify_target_preflight(profile,observed,now=NOW)['passed'] is True
    else:
        with pytest.raises(TargetProfileError):
            verify_target_preflight(profile,observed,now=NOW)


@pytest.mark.parametrize('timestamp',[None,1,'2026-10-17T08:00:00','2026-10-17T15:00:00+07:00',
    '2026-10-17T08:00:00-00:00','2026-99-17T08:00:00Z','2026-10-17T08:00:00Z secret',
    '2026-10-17T08:00:00.1234567Z'])
def test_utc_timestamp_only(profile,observed,timestamp):
    observed['observed_at_utc']=timestamp
    with pytest.raises(TargetProfileError):
        verify_target_preflight(profile,observed,now=NOW)


@pytest.mark.parametrize('now',[datetime(2026,10,17,8),datetime(2026,10,17,15,tzinfo=timezone(timedelta(hours=7))),None,'2026-10-17T08:00:00Z'])
def test_verification_clock_must_be_trusted_utc_datetime(profile,observed,now):
    with pytest.raises(TargetProfileError):
        verify_target_preflight(profile,observed,now=now)


def test_unknown_preflight_fields_missing_fields_and_free_text_fail_closed(profile,observed):
    observed['provider_output']='secret source text'
    with pytest.raises(TargetProfileError) as error:
        verify_target_preflight(profile,observed,now=NOW)
    assert 'secret source text' not in str(error.value)
    del observed['provider_output']
    del observed['database']['current_schema']
    with pytest.raises(TargetProfileError):
        verify_target_preflight(profile,observed,now=NOW)


def test_profile_and_observation_must_both_match_immutable_allowlist(profile,observed):
    profile['tested_versions']['apex']='26.1.6'
    observed['versions']['apex']='26.1.6'
    with pytest.raises(TargetProfileError):
        verify_target_preflight(profile,observed,now=NOW)


def test_valid_preflight_is_pure_and_does_not_read_files(profile,observed,monkeypatch):
    def no_io(*args,**kwargs):
        raise AssertionError('Pure validation must not touch the filesystem')
    monkeypatch.setattr(Path,'open',no_io)
    monkeypatch.setattr(Path,'read_text',no_io)
    assert verify_target_preflight(profile,observed,now=NOW)['passed'] is True


def test_deterministic_target_proof_is_independent_of_opaf_liveness(profile,observed):
    del observed['opaf']
    del observed['versions']['opaf']
    value=verify_deterministic_target_preflight(profile,observed,now=NOW)
    assert value['passed'] is True
    assert value['scope']=='jsn-native-deterministic-target-preflight-v1'
    assert set(value['tested_versions'])=={'apex','sqlcl','apexlang_mmd'}
    with pytest.raises(TargetProfileError):verify_target_preflight(profile,observed,now=NOW)


def test_deterministic_proof_does_not_accept_unclear_mixed_model_evidence(profile,observed):
    with pytest.raises(TargetProfileError):verify_deterministic_target_preflight(profile,observed,now=NOW)


def test_known_historical_profile_verifies_without_deployable_eligibility(profile,monkeypatch):
    import forms2apex.target_profile as module
    monkeypatch.setattr(module,'_DEPLOYABLE_TARGET_PROFILES',{})
    assert validate_historical_target_profile(profile)==profile
    with pytest.raises(TargetProfileError):validate_target_profile(profile)


def test_changed_historical_document_is_not_reinterpreted(profile):
    profile['tested_versions']['apex']='26.1.6'
    with pytest.raises(TargetProfileError,match='registered immutable'):
        validate_historical_target_profile(profile)


def test_historical_registry_drift_fails_closed(profile,monkeypatch):
    import forms2apex.target_profile as module
    bad=json.loads(json.dumps(profile));bad['database']['parsing_schema']='OTHER'
    monkeypatch.setattr(module,'_KNOWN_HISTORICAL_PROFILES',{target_profile_sha256(profile):bad})
    with pytest.raises(TargetProfileError):validate_historical_target_profile(profile)


def test_old_snapshot_and_new_selectable_tuple_are_exact_and_independent():
    import forms2apex.target_profile as module
    old = load_target_profile(PROFILE_FILE)
    new = load_target_profile(PROJECT_PROFILE_FILE)
    assert target_profile_sha256(old) == '7c7b73d43febc9befb1d43e47449a02cc7894b879dd4bc32904cec538e5f95e6'
    assert target_profile_sha256(new) == '7170d60927b7e5b7aed5d56174f97efbeff3052be247b244911deff768701ed3'
    assert module._JSN_PROFILE == old
    assert module._DEPLOYABLE_TARGET_PROFILES is not module._KNOWN_HISTORICAL_PROFILES
    assert set(module._DEPLOYABLE_TARGET_PROFILES) == {target_profile_sha256(old), target_profile_sha256(new)}
    assert new['profile_id'] == 'jsn-native-project-v2'
    assert new['scope']['project_mapping'] == {
        'native_project_schema_versions': [1, 2],
        'storage_mapping_scope': 'fox-project-storage-v1',
        'module_execution_scope': 'fox-project-module-execution-v2',
    }
    assert 'project_mapping' not in old['scope']
    # Only new identity, mapping scope and the two distinct role bindings differ.
    comparable = deepcopy(new)
    comparable['profile_id'] = old['profile_id']
    del comparable['scope']['project_mapping']
    comparable['opaf']['roles'] = deepcopy(old['opaf']['roles'])
    assert comparable == old
    assert all(new['opaf']['roles'][role] != old['opaf']['roles'][role] for role in ('mapper', 'reviewer'))


def test_addition_to_history_does_not_authorize_selection(profile,monkeypatch):
    import forms2apex.target_profile as module
    profile['profile_id'] = 'historical-only-not-deployable'
    digest = hashlib.sha256(module._canonical_bytes(profile)).hexdigest()
    monkeypatch.setattr(module, '_KNOWN_HISTORICAL_PROFILES', {
        **module._KNOWN_HISTORICAL_PROFILES, digest: deepcopy(profile)})
    assert validate_historical_target_profile(profile) == profile
    with pytest.raises(TargetProfileError, match='approved selectable'):
        validate_target_profile(profile)


@pytest.mark.parametrize('value', [[True, 2], [1, 2.0], [1], [2, 1], [1, 2, 3]])
def test_project_capability_versions_require_exact_types_and_order(value):
    profile = load_target_profile(PROJECT_PROFILE_FILE)
    profile['scope']['project_mapping']['native_project_schema_versions'] = value
    with pytest.raises(TargetProfileError):
        validate_target_profile(profile)


def test_approved_registry_drift_fails_closed(profile,monkeypatch):
    import forms2apex.target_profile as module
    digest = target_profile_sha256(profile)
    changed = deepcopy(profile)
    changed['opaf']['roles']['mapper']['workflow_id'] = 'F' * 32
    monkeypatch.setattr(module, '_DEPLOYABLE_TARGET_PROFILES', {digest: changed})
    with pytest.raises(TargetProfileError, match='registry binding'):
        validate_target_profile(profile)
