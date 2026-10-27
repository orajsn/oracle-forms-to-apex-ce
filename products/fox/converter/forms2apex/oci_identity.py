"""Read-only identity probe for the one approved JSN target.

Only SDK GetAutonomousDatabase and GetInstance operations are exposed here.
The caller supplies its independently collected, canonical IMDS identity.
Instance-principal authentication reads the VM's instance certificates from
link-local IMDS; it does not load an OCI user config, API signing key or DB
credential. There is deliberately no fallback authentication or endpoint.

Version scope: official OCI Python SDK 2.188.0. Its instance-principal metadata
and X509 federation requests use fixed (10, 60) connect/read timeouts; that
constructor has no supported timeout option. Resource clients use (3, 15).
These are per-request bounds, NOT a whole-probe wall-clock deadline. A caller
that requires a hard overall deadline must isolate this probe in a process.
See Oracle's signing/client documentation and the matching v2.188.0 SDK source.
"""
from __future__ import annotations

import importlib
import os

from .target_profile import validate_target_profile


SDK_VERSION = '2.188.0'
DATABASE_ENDPOINT = 'https://database.us-ashburn-1.oraclecloud.com'
COMPUTE_ENDPOINT = 'https://iaas.us-ashburn-1.oraclecloud.com'
FEDERATION_ENDPOINT = 'https://auth.us-ashburn-1.oraclecloud.com/v1/x509'
CLIENT_TIMEOUT = (3, 15)
_FAILURE = 'OCI read-only identity preflight failed'
_IMDS_FIELDS = frozenset({'instance_id', 'compartment_id', 'region'})
_TRANSPORT_OVERRIDES = frozenset({
    'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'REQUESTS_CA_BUNDLE',
    'CURL_CA_BUNDLE', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'PYTHONHTTPSVERIFY',
    'NETRC', 'PROPAGATION_ENABLED', 'OPC_INCOMING_REQUEST_ID',
})


def _check_environment() -> None:
    # Reject instead of mutating process-wide environment or allowing a proxy,
    # metadata override, custom region file, CA bundle, logging/config override
    # or SDK request-propagation file to affect this narrowly scoped probe.
    # NO_PROXY is not a redirect and is harmless without any proxy setting.
    for name in os.environ:
        upper = name.upper()
        if upper.startswith('OCI_') or upper in _TRANSPORT_OVERRIDES:
            raise RuntimeError(_FAILURE)


def _check_imds(profile: dict, imds: dict) -> None:
    expected = {key: profile['oci'][key] for key in _IMDS_FIELDS}
    if type(imds) is not dict or set(imds) != _IMDS_FIELDS:
        raise RuntimeError(_FAILURE)
    if any(type(imds[key]) is not str or imds[key] != expected[key]
           for key in _IMDS_FIELDS):
        raise RuntimeError(_FAILURE)


def _prepare_client(client, endpoint: str) -> None:
    # Check the actual generated client before either resource read. In this
    # pinned SDK both services append this API version to service_endpoint.
    base = client.base_client
    if base.endpoint != endpoint + '/20160918' or base.timeout != CLIENT_TIMEOUT:
        raise RuntimeError(_FAILURE)
    if base.config.get('log_requests') is not False:
        raise RuntimeError(_FAILURE)
    base.session.verify = True
    base.session.trust_env = False


def _resource(response, resource_id: str, compartment_id: str, state: str):
    if type(response.status) is not int or response.status != 200:
        raise RuntimeError(_FAILURE)
    resource = response.data
    expected = {'id': resource_id, 'compartment_id': compartment_id,
                'lifecycle_state': state}
    for name, value in expected.items():
        observed = getattr(resource, name, None)
        if type(observed) is not str or observed != value:
            raise RuntimeError(_FAILURE)
    return resource


def _close_session(owner, attribute: str) -> None:
    if owner is None:
        return
    try:
        session = getattr(owner, attribute, None)
        if session is not None:
            session.close()
    except Exception:
        # Cleanup must not replace a bounded failure with provider text.
        pass


def _deny_token_replay() -> None:
    # SDK BaseClient.call_api has a separate 401 refresh-and-replay branch even
    # with NoneRetryStrategy. This probe uses a fresh short-lived signer and
    # fails closed on 401 instead. Only this signer instance is changed; no SDK
    # class, global retry policy, or other worker's signer is modified.
    raise RuntimeError(_FAILURE)


def collect_oci_identity(profile: dict, imds: dict) -> dict:
    """Return the exact seven-key OCI observation, or a generic RuntimeError.

    ``imds`` must contain exactly ``instance_id``, ``compartment_id`` and the
    canonical ``region`` (us-ashburn-1, not the short IMDS region code iad).
    All local guards run before importing the SDK or authenticating. SDK and
    transport environment customizations are unsupported, even if they appear
    harmless; run this probe in a clean, controlled container environment.

    Success proves observed resource identity/state only. It grants no write
    authority, validates no DB credentials or schema, and creates no receipt.
    No provider exception or response body is returned or logged on failure.
    """
    return _collect_identity(profile, imds)


def collect_operator_oci_identity(profile: dict, imds: dict, *, require_database_available: bool) -> dict:
    """Operator projection adds the actual DB name, using the same two GETs.

    An explicit False also permits observed STOPPED for read-only status. No
    other state, resource, endpoint, authentication or start action is allowed.
    The original seven-key collector above remains strict and unchanged.
    """
    if type(require_database_available) is not bool:
        raise RuntimeError(_FAILURE)
    return _collect_identity(profile, imds, operator=True,
                             require_database_available=require_database_available)


def _collect_identity(profile, imds, *, operator=False, require_database_available=True):
    signer = None
    database_client = None
    compute_client = None
    try:
        profile = validate_target_profile(profile)
        _check_imds(profile, imds)
        _check_environment()
        sdk = importlib.import_module('oci')
        if getattr(sdk, '__version__', None) != SDK_VERSION:
            raise RuntimeError(_FAILURE)
        no_retry = sdk.retry.NoneRetryStrategy()
        signer = sdk.auth.signers.InstancePrincipalsSecurityTokenSigner(
            federation_endpoint=FEDERATION_ENDPOINT,
            federation_client_cert_bundle_verify=True,
            federation_client_retry_strategy=no_retry,
            retry_strategy=no_retry,
            log_requests=False,
        )
        target = profile['oci']
        if type(signer.region) is not str or signer.region != target['region']:
            raise RuntimeError(_FAILURE)
        signer.refresh_security_token = _deny_token_replay
        # This is an explicit in-memory config, never oci.config.from_file().
        config = {'region': target['region'], 'log_requests': False}
        options = {'signer': signer, 'retry_strategy': no_retry,
                   'timeout': CLIENT_TIMEOUT}
        database_client = sdk.database.DatabaseClient(
            config=dict(config), service_endpoint=DATABASE_ENDPOINT, **options)
        _prepare_client(database_client, DATABASE_ENDPOINT)
        database_response = database_client.get_autonomous_database(
            autonomous_database_id=target['database_id'], retry_strategy=no_retry)
        database_state = 'AVAILABLE'
        if operator and not require_database_available:
            database_state = getattr(database_response.data, 'lifecycle_state', None)
            if type(database_state) is not str or database_state not in ('AVAILABLE', 'STOPPED'):
                raise RuntimeError(_FAILURE)
        database = _resource(database_response, target['database_id'], target['compartment_id'], database_state)
        if operator and (type(getattr(database, 'db_name', None)) is not str or database.db_name != 'JSNF2APEX'):
            raise RuntimeError(_FAILURE)
        compute_client = sdk.core.ComputeClient(
            config=dict(config), service_endpoint=COMPUTE_ENDPOINT, **options)
        _prepare_client(compute_client, COMPUTE_ENDPOINT)
        instance = _resource(compute_client.get_instance(
            instance_id=target['instance_id'], retry_strategy=no_retry),
            target['instance_id'], target['compartment_id'], 'RUNNING')
        result = {
            'database_id': database.id,
            'database_compartment_id': database.compartment_id,
            'instance_id': instance.id,
            'instance_compartment_id': instance.compartment_id,
            'region': target['region'],
            'database_lifecycle_state': database.lifecycle_state,
            'instance_lifecycle_state': instance.lifecycle_state,
        }
        if operator:
            result['database_db_name'] = database.db_name
        return result
    except Exception:
        raise RuntimeError(_FAILURE) from None
    finally:
        for client in (database_client, compute_client):
            _close_session(getattr(client, 'base_client', None), 'session')
        _close_session(getattr(signer, 'federation_client', None), 'requests_session')
        for name in ('leaf_certificate_retriever', 'intermediate_certificate_retriever'):
            _close_session(getattr(signer, name, None), 'requests_session')
