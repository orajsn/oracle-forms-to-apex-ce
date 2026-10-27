"""Isolated SDK doubles: no network, installs, credentials or OCI operations."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from forms2apex import oci_identity as probe
from forms2apex.target_profile import load_target_profile


ROOT = Path(__file__).resolve().parents[2]
SECRET = 'provider-error-must-not-be-disclosed-token-password-private-key'


@pytest.fixture
def profile():
    return load_target_profile(ROOT/'deployment/target-profile.jsn.json')


@pytest.fixture
def imds(profile):
    return {key: profile['oci'][key] for key in ('instance_id', 'compartment_id', 'region')}


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    for name in tuple(probe.os.environ):
        if name.upper().startswith('OCI_') or name.upper() in probe._TRANSPORT_OVERRIDES:
            monkeypatch.delenv(name)


@pytest.fixture
def sdk(monkeypatch, profile):
    target = profile['oci']

    def resource(resource_id, state):
        return SimpleNamespace(status=200, data=SimpleNamespace(
            id=resource_id, compartment_id=target['compartment_id'],
            lifecycle_state=state, secret=SECRET))

    def client(endpoint, operation, response):
        base = SimpleNamespace(endpoint=endpoint+'/20160918',
                               timeout=probe.CLIENT_TIMEOUT,
                               config={'region':target['region'], 'log_requests':False},
                               session=SimpleNamespace(verify=False, trust_env=True, close=Mock()))
        return SimpleNamespace(base_client=base, **{operation: Mock(return_value=response)})

    db = client(probe.DATABASE_ENDPOINT, 'get_autonomous_database',
                resource(target['database_id'], 'AVAILABLE'))
    vm = client(probe.COMPUTE_ENDPOINT, 'get_instance',
                resource(target['instance_id'], 'RUNNING'))
    sessions = [SimpleNamespace(requests_session=SimpleNamespace(close=Mock())) for _ in range(3)]
    signer = SimpleNamespace(region=target['region'], federation_client=sessions[0],
                             leaf_certificate_retriever=sessions[1],
                             intermediate_certificate_retriever=sessions[2],
                             refresh_security_token=Mock())
    no_retry = object()
    value = SimpleNamespace(
        __version__=probe.SDK_VERSION,
        retry=SimpleNamespace(NoneRetryStrategy=Mock(return_value=no_retry)),
        auth=SimpleNamespace(signers=SimpleNamespace(
            InstancePrincipalsSecurityTokenSigner=Mock(return_value=signer))),
        database=SimpleNamespace(DatabaseClient=Mock(return_value=db)),
        core=SimpleNamespace(ComputeClient=Mock(return_value=vm)),
        config=SimpleNamespace(from_file=Mock(side_effect=AssertionError('Never load OCI config'))),
    )
    imported = Mock(return_value=value)
    monkeypatch.setattr(probe.importlib, 'import_module', imported)
    return SimpleNamespace(module=value, imported=imported, signer=signer, db=db, vm=vm,
                           no_retry=no_retry, sessions=sessions)


def failed(profile, imds):
    with pytest.raises(RuntimeError) as error:
        probe.collect_oci_identity(profile, imds)
    assert str(error.value) == 'OCI read-only identity preflight failed'
    assert len(str(error.value)) < 100
    assert SECRET not in str(error.value)
    assert error.value.__cause__ is None
    assert error.value.__suppress_context__ is True


def assert_not_started(sdk):
    sdk.imported.assert_not_called()
    sdk.module.auth.signers.InstancePrincipalsSecurityTokenSigner.assert_not_called()
    sdk.module.database.DatabaseClient.assert_not_called()
    sdk.module.core.ComputeClient.assert_not_called()


def test_success_is_exact_observation_and_does_not_mutate_inputs(profile, imds, sdk):
    original_profile, original_imds = deepcopy(profile), deepcopy(imds)
    result = probe.collect_oci_identity(profile, imds)
    target = profile['oci']
    assert result == {
        'database_id': target['database_id'], 'database_compartment_id':target['compartment_id'],
        'instance_id': target['instance_id'], 'instance_compartment_id':target['compartment_id'],
        'region':target['region'], 'database_lifecycle_state':'AVAILABLE', 'instance_lifecycle_state':'RUNNING',
    }
    assert profile == original_profile
    assert imds == original_imds
    assert SECRET not in repr(result)
    sdk.imported.assert_called_once_with('oci')
    sdk.module.config.from_file.assert_not_called()


def test_operator_projection_observes_name_with_same_two_resource_gets(profile, imds, sdk):
    sdk.db.get_autonomous_database.return_value.data.db_name = 'JSNF2APEX'
    result = probe.collect_operator_oci_identity(profile, imds, require_database_available=True)
    assert result['database_db_name'] == 'JSNF2APEX'
    assert len(result) == 8
    sdk.db.get_autonomous_database.assert_called_once_with(
        autonomous_database_id=profile['oci']['database_id'], retry_strategy=sdk.no_retry)
    sdk.vm.get_instance.assert_called_once_with(instance_id=profile['oci']['instance_id'],
                                               retry_strategy=sdk.no_retry)
    sdk.module.config.from_file.assert_not_called()
    legacy = probe.collect_oci_identity(profile, imds)
    assert len(legacy) == 7 and 'database_db_name' not in legacy


@pytest.mark.parametrize('name', [None, '', 'OTHER', 'jsnf2apex', True, 123])
def test_operator_name_missing_or_wrong_is_not_a_pinned_label(profile, imds, sdk, name):
    if name is not None:
        sdk.db.get_autonomous_database.return_value.data.db_name = name
    with pytest.raises(RuntimeError, match='OCI read-only identity preflight failed'):
        probe.collect_operator_oci_identity(profile, imds, require_database_available=False)
    sdk.vm.get_instance.assert_not_called()


@pytest.mark.parametrize('flag', [None, 0, 1, 'false', {}, []])
def test_operator_availability_flag_must_be_an_explicit_bool(profile, imds, sdk, flag):
    with pytest.raises(RuntimeError, match='OCI read-only identity preflight failed'):
        probe.collect_operator_oci_identity(profile, imds, require_database_available=flag)
    assert_not_started(sdk)


def test_operator_readonly_status_can_observe_stopped_without_starting(profile, imds, sdk):
    database = sdk.db.get_autonomous_database.return_value.data
    database.db_name = 'JSNF2APEX'
    database.lifecycle_state = 'STOPPED'
    result = probe.collect_operator_oci_identity(profile, imds, require_database_available=False)
    assert result['database_lifecycle_state'] == 'STOPPED'
    with pytest.raises(RuntimeError, match='OCI read-only identity preflight failed'):
        probe.collect_operator_oci_identity(profile, imds, require_database_available=True)
    with pytest.raises(RuntimeError, match='OCI read-only identity preflight failed'):
        probe.collect_oci_identity(profile, imds)


@pytest.mark.parametrize('state', ['STOPPING', 'STARTING', 'TERMINATED', None, True, ''])
def test_operator_status_does_not_expand_allowed_database_states(profile, imds, sdk, state):
    database = sdk.db.get_autonomous_database.return_value.data
    database.db_name, database.lifecycle_state = 'JSNF2APEX', state
    with pytest.raises(RuntimeError, match='OCI read-only identity preflight failed'):
        probe.collect_operator_oci_identity(profile, imds, require_database_available=False)


def test_exact_instance_principal_fixed_endpoint_timeout_tls_and_no_retry(profile, imds, sdk):
    probe.collect_oci_identity(profile, imds)
    sdk.module.auth.signers.InstancePrincipalsSecurityTokenSigner.assert_called_once_with(
        federation_endpoint=probe.FEDERATION_ENDPOINT,
        federation_client_cert_bundle_verify=True,
        federation_client_retry_strategy=sdk.no_retry,
        retry_strategy=sdk.no_retry, log_requests=False)
    common = {'config':{'region':'us-ashburn-1','log_requests':False},
              'signer':sdk.signer,'retry_strategy':sdk.no_retry,'timeout':(3,15)}
    sdk.module.database.DatabaseClient.assert_called_once_with(
        service_endpoint=probe.DATABASE_ENDPOINT, **common)
    sdk.module.core.ComputeClient.assert_called_once_with(
        service_endpoint=probe.COMPUTE_ENDPOINT, **common)
    sdk.db.get_autonomous_database.assert_called_once_with(
        autonomous_database_id=profile['oci']['database_id'], retry_strategy=sdk.no_retry)
    sdk.vm.get_instance.assert_called_once_with(instance_id=profile['oci']['instance_id'],
                                               retry_strategy=sdk.no_retry)
    for client in (sdk.db, sdk.vm):
        assert client.base_client.session.verify is True
        assert client.base_client.session.trust_env is False
        client.base_client.session.close.assert_called_once_with()
    for session in sdk.sessions:
        session.requests_session.close.assert_called_once_with()


@pytest.mark.parametrize('path,value', [
    (('active',),False), (('schema_version',),True),
    (('oci','instance_id'),SECRET), (('oci','compartment_id'),SECRET),
    (('oci','database_id'),SECRET), (('oci','region'),'ap-singapore-1'),
    (('tested_versions','apex'),'999'), (('database','session_user'),'ADMIN'),
    (('scope','customer_deployment_authorized'),True),
    (('opaf','roles','mapper','model'),SECRET),
])
def test_entire_profile_guard_runs_before_sdk_import(profile, imds, sdk, path, value):
    cursor = profile
    for part in path[:-1]:
        cursor = cursor[part]
    cursor[path[-1]] = value
    failed(profile, imds)
    assert_not_started(sdk)


@pytest.mark.parametrize('profile_value', [None, [], 'secret', True, {}])
def test_malformed_profile_fails_before_sdk(profile_value, imds, sdk):
    failed(profile_value, imds)
    assert_not_started(sdk)


@pytest.mark.parametrize('field', ['instance_id','compartment_id','region'])
@pytest.mark.parametrize('value', [None,1,True,[],{},SECRET,'','iad',' us-ashburn-1'])
def test_imds_mismatch_or_wrong_type_before_sdk(profile, imds, sdk, field, value):
    imds[field] = value
    failed(profile, imds)
    assert_not_started(sdk)


@pytest.mark.parametrize('value', [None, [], '', True, {}])
def test_malformed_imds_before_sdk(profile, sdk, value):
    failed(profile, value)
    assert_not_started(sdk)


@pytest.mark.parametrize('field', ['instance_id','compartment_id','region'])
def test_imds_missing_field_before_sdk(profile, imds, sdk, field):
    del imds[field]
    failed(profile, imds)
    assert_not_started(sdk)


def test_imds_endpoint_or_other_extra_field_rejected(profile, imds, sdk):
    imds['endpoint'] = 'https://example.invalid/'+SECRET
    failed(profile, imds)
    assert_not_started(sdk)


@pytest.mark.parametrize('name', [
    'OCI_METADATA_BASE_URL', 'OCI_REGION_METADATA', 'OCI_REGION', 'OCI_CONFIG_FILE',
    'OCI_CONFIG_PROFILE', 'OCI_REALM_SPECIFIC_SERVICE_ENDPOINT_TEMPLATE_ENABLED',
    'OCI_DUAL_STACK_ENDPOINT_ENABLED', 'OCI_SDK_APPEND_USER_AGENT',
    'OCI_HEADER_PARSING_ERROR_MAX_RETRIES', 'OCI_PYSDK_PROPAGATION_REQUEST_ID_FILE',
    'OCI_SDK_FUTURE_ENDPOINT_OVERRIDE', 'oci_metadata_base_url',
    *sorted(probe._TRANSPORT_OVERRIDES), 'https_proxy', 'all_proxy',
])
@pytest.mark.parametrize('value', ['', SECRET])
def test_ambient_sdk_and_transport_overrides_rejected_before_import(profile, imds, sdk, monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    failed(profile, imds)
    assert_not_started(sdk)


def test_no_proxy_alone_is_not_an_override(profile, imds, sdk, monkeypatch):
    monkeypatch.setenv('NO_PROXY', '*')
    assert probe.collect_oci_identity(profile, imds)['region'] == 'us-ashburn-1'


@pytest.mark.parametrize('version', [None,'2.187.0','2.188.1','2.188.0.dev1',2.188,True])
def test_sdk_version_pin_before_signer(profile, imds, sdk, version):
    sdk.module.__version__ = version
    failed(profile, imds)
    sdk.module.auth.signers.InstancePrincipalsSecurityTokenSigner.assert_not_called()


@pytest.mark.parametrize('exception', [ModuleNotFoundError,ImportError,RuntimeError,PermissionError])
def test_sdk_unavailable_is_generic(profile, imds, sdk, exception):
    sdk.imported.side_effect = exception(SECRET)
    failed(profile, imds)


@pytest.mark.parametrize('where', ['signer','database_client','database_get','compute_client','compute_get'])
@pytest.mark.parametrize('exception', [PermissionError,TimeoutError,RuntimeError])
def test_provider_failure_is_bounded_and_not_printed(profile, imds, sdk, capsys, caplog, where, exception):
    calls = {'signer':sdk.module.auth.signers.InstancePrincipalsSecurityTokenSigner,
             'database_client':sdk.module.database.DatabaseClient,
             'database_get':sdk.db.get_autonomous_database,
             'compute_client':sdk.module.core.ComputeClient,
             'compute_get':sdk.vm.get_instance}
    calls[where].side_effect = exception(SECRET)
    failed(profile, imds)
    captured = capsys.readouterr()
    assert captured.out == captured.err == ''
    assert SECRET not in caplog.text
    assert calls[where].call_count == 1
    if where in ('signer','database_client','database_get'):
        sdk.vm.get_instance.assert_not_called()


@pytest.mark.parametrize('region', [None,True,'iad','ap-singapore-1',SECRET])
def test_signer_region_mismatch_fails_before_clients(profile, imds, sdk, region):
    sdk.signer.region = region
    failed(profile, imds)
    sdk.module.database.DatabaseClient.assert_not_called()
    sdk.module.core.ComputeClient.assert_not_called()


@pytest.mark.parametrize('which', ['db','vm'])
@pytest.mark.parametrize('attribute,value', [
    ('endpoint','https://example.invalid/'+SECRET), ('endpoint',probe.DATABASE_ENDPOINT),
    ('timeout',None), ('timeout',(3,None)), ('timeout',(3,999)),
    ('config',{'log_requests':True}), ('config',{}),
])
def test_client_safety_readback_precedes_resource_operation(profile, imds, sdk, which, attribute, value):
    client = getattr(sdk, which)
    setattr(client.base_client, attribute, value)
    failed(profile, imds)
    operation = client.get_autonomous_database if which == 'db' else client.get_instance
    operation.assert_not_called()


@pytest.mark.parametrize('which', ['db','vm'])
@pytest.mark.parametrize('field,value', [
    ('id',SECRET), ('id',None), ('id',True), ('compartment_id',SECRET),
    ('compartment_id',None), ('lifecycle_state','STOPPED'),
    ('lifecycle_state','STARTING'), ('lifecycle_state','AVAILABLE_WRONG'),
    ('lifecycle_state',None), ('lifecycle_state',True),
])
def test_response_wrong_identity_or_state_fails_closed(profile, imds, sdk, which, field, value):
    operation = sdk.db.get_autonomous_database if which == 'db' else sdk.vm.get_instance
    setattr(operation.return_value.data, field, value)
    failed(profile, imds)
    if which == 'db':
        sdk.module.core.ComputeClient.assert_not_called()


@pytest.mark.parametrize('which', ['db','vm'])
@pytest.mark.parametrize('status', [401,403,404,429,500,None,True,'200',200.0])
def test_unsuccessful_or_noninteger_response_status(profile, imds, sdk, which, status):
    operation = sdk.db.get_autonomous_database if which == 'db' else sdk.vm.get_instance
    operation.return_value.status = status
    failed(profile, imds)


@pytest.mark.parametrize('which', ['db','vm'])
@pytest.mark.parametrize('response', [None,{},SimpleNamespace(status=200,data=None)])
def test_malformed_sdk_response(profile, imds, sdk, which, response):
    operation = sdk.db.get_autonomous_database if which == 'db' else sdk.vm.get_instance
    operation.return_value = response
    failed(profile, imds)


def test_cleanup_failure_never_replaces_or_discloses_primary_error(profile, imds, sdk):
    sdk.db.get_autonomous_database.side_effect = RuntimeError(SECRET)
    sdk.db.base_client.session.close.side_effect = RuntimeError(SECRET)
    for session in sdk.sessions:
        session.requests_session.close.side_effect = RuntimeError(SECRET)
    failed(profile, imds)


def test_cleanup_failure_does_not_invalidate_successful_observation(profile, imds, sdk):
    sdk.db.base_client.session.close.side_effect = RuntimeError(SECRET)
    assert probe.collect_oci_identity(profile, imds)['instance_lifecycle_state'] == 'RUNNING'


@pytest.mark.parametrize('which', ['db','vm'])
def test_sdk_401_refresh_branch_cannot_replay_a_resource_read(profile, imds, sdk, which):
    original_refresh = sdk.signer.refresh_security_token
    replay = Mock()

    def sdk_401_branch(**kwargs):
        # Model the pinned SDK's independent 401 branch in BaseClient.call_api.
        sdk.signer.refresh_security_token()
        replay()
        return None

    operation = sdk.db.get_autonomous_database if which == 'db' else sdk.vm.get_instance
    operation.side_effect = sdk_401_branch
    failed(profile, imds)
    operation.assert_called_once()
    original_refresh.assert_not_called()
    replay.assert_not_called()


def test_replay_guard_changes_only_this_probe_signer(profile, imds, sdk):
    unrelated_signer = SimpleNamespace(refresh_security_token=Mock())
    unrelated_refresh = unrelated_signer.refresh_security_token
    probe.collect_oci_identity(profile, imds)
    assert sdk.signer.refresh_security_token is probe._deny_token_replay
    assert unrelated_signer.refresh_security_token is unrelated_refresh
