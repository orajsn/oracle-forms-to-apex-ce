"""Modeled transport/count checks, not live provider or conversion evidence."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest

from fox.opaf import OpafClient, OpafError, canonical_hash, validate_model_environment
from fox.oci_genai import OciGenAiClient
from fox.provider_timing import ProviderTiming
from fox.design_provider import validate_environment
from test_oci_genai import target as direct_target, fake_sdk, InjectedService


ROOT = Path(__file__).resolve().parents[2]
PRIVATE = 'SYNTHETIC-PRIVATE-SOURCE-OR-CREDENTIAL'


class ModeledOpaf:
    """Inject a bounded HTTP contract below the real client request method."""
    def __init__(self, monkeypatch):
        self.target = json.loads((ROOT / 'deployment/target-profile.jsn.json').read_text())
        self.graph = json.loads((ROOT / 'deployment/native-opaf-mapper.json').read_text())['data']
        self.target['opaf']['certificate_sha256'] = hashlib.sha256(b'synthetic-certificate').hexdigest()
        self.role = self.target['opaf']['roles']['mapper']
        self.role['graph_sha256'] = canonical_hash(self.graph)
        selected = next(n['data']['template']['llmToUse']['value'] for n in self.graph['nodes']
                        if n['data']['type'] == 'llmStep')
        self.saved = {'name': selected, 'provider': 'oci', 'isActive': 'Y',
            'connectionDetails': {'model_id': self.role['model'], 'credentials_type': 'INSTANCE_PRINCIPAL',
                'compartment_id': self.target['oci']['compartment_id'],
                'service_endpoint': 'https://inference.generativeai.us-ashburn-1.oci.oraclecloud.com',
                'secret': PRIVATE}}
        self.identity = {'job_id': 'fox-' + 'a'*20, 'source_hash': 'b'*64}
        self.request = {'source': PRIVATE}
        self.connections, self.events = [], []
        self.server_close = False
        self.socket_close = False
        self.post_error = None
        self.oversize = False
        self.status = 200
        self.wrong_pin_connection = None
        self.reply = {'roomId': 'modeled-room', 'message': {'ok': True}}
        outer = self

        class Response:
            def __init__(self, value, connection):
                self.raw = json.dumps(value).encode()
                self.will_close = outer.server_close
                self.status = outer.status
                self.connection = connection
            def read(self, limit):
                assert limit == 8_000_001
                if outer.socket_close:
                    self.connection.sock = None
                return b' ' * limit if outer.oversize else self.raw[:limit]
            def getheaders(self):
                return [('Set-Cookie', 'agent_factory_session=synthetic-session')]

        class Connection:
            def __init__(self, *args, **kwargs):
                self.sock = None
                self.closed = False
                outer.connections.append(self)
                self.index = len(outer.connections)
            def connect(self):
                self.sock = self
            def getpeercert(self, **kwargs):
                assert kwargs == {'binary_form': True}
                outer.events.append(('PIN', self.index))
                return b'wrong' if self.index == outer.wrong_pin_connection else b'synthetic-certificate'
            def request(self, method, path, body, headers):
                outer.events.append((method, path))
                if method == 'POST' and outer.post_error:
                    raise outer.post_error
                if path.endswith('loginValidation'):
                    assert headers['Authorization'].startswith('Basic ')
                    self.value = {}
                elif path.endswith('/version'):
                    self.value = {'VERSION_STRING': '26.4.0.0.0', 'VERSION_NUMBER': 264000,
                                  'BUILD_ID': 1780444486153}
                elif '/agents/' in path:
                    self.value = {'data': {'published': 1, 'data': deepcopy(outer.graph)}}
                elif path.endswith('getSavedLLMConfigurations'):
                    self.value = {'data': {'savedConfiguration': [deepcopy(outer.saved)]}}
                else:
                    assert method == 'POST'
                    assert json.loads(json.loads(body)['message']) == outer.request
                    self.value = deepcopy(outer.reply)
            def getresponse(self):
                return Response(self.value, self)
            def close(self):
                self.sock = None
                self.closed = True

        monkeypatch.setattr('fox.opaf.http.client.HTTPSConnection', Connection)
        self.client = OpafClient(self.target['opaf']['base_url'], 'synthetic', PRIVATE,
                                 self.target['opaf']['certificate_sha256'])

    def prepared(self, callback=None):
        return self.client.invoke_prepared(self.role, self.request, self.identity, role_name='mapper',
            target_profile=self.target,
            before_invoke=callback or (lambda env: self.events.append(('INTENT', env['role']))))

    def counts(self):
        return {method: sum(e[0] == method for e in self.events) for method in ('GET', 'POST', 'PIN', 'INTENT')}


def test_prepared_observes_once_intent_before_post_and_preserves_sealed_schema(monkeypatch):
    case = ModeledOpaf(monkeypatch)
    output, invocation, environment, timing = case.prepared()
    assert output == {'ok': True}
    assert set(invocation) == {'workflow_id', 'room_id', 'model', 'graph_sha256', 'request_sha256',
                              'response_sha256', 'started_at_utc', 'completed_at_utc'}
    assert validate_model_environment(environment, case.target, 'mapper', case.identity, invocation) == environment
    assert case.counts() == {'GET': 4, 'POST': 1, 'PIN': 1, 'INTENT': 1}
    assert case.events[-2][0] == 'INTENT' and case.events[-1][0] == 'POST'
    assert len(case.connections) == 1 and all(c.closed for c in case.connections)
    assert timing['http_requests'] == 5 and timing['tls_connections'] == 1
    assert timing['request_body_bytes'] > 0 and timing['response_body_bytes'] > 0
    assert PRIVATE not in json.dumps((environment, timing, invocation))
    assert all(0 <= value <= 604800 for key, value in timing.items() if key.endswith('_seconds'))
    # A second role invocation must start a new authenticated, pinned observation.
    case.prepared()
    assert len(case.connections) == 2 and case.counts()['GET'] == 8
    assert not hasattr(case.client._transport_local, 'active')


def test_modeled_before_after_request_connection_count_benchmark(monkeypatch):
    case = ModeledOpaf(monkeypatch)
    case.client.observe_environment(case.role, case.identity, role_name='mapper', target_profile=case.target)
    case.client.invoke(case.role, case.request)
    before = case.counts()
    assert before == {'GET': 6, 'POST': 1, 'PIN': 7, 'INTENT': 0}
    assert len(case.connections) == 7 and all(c.closed for c in case.connections)
    case.events.clear()
    case.connections.clear()
    case.prepared()
    after = case.counts()
    assert after == {'GET': 4, 'POST': 1, 'PIN': 1, 'INTENT': 1}
    print('MODELED count benchmark: legacy=7 requests/7 TLS connections; prepared=5 requests/1 TLS connection; POST=1 in both')


@pytest.mark.parametrize('close_style', ['server_close', 'socket_close'])
def test_server_close_opens_and_repins_every_new_connection(monkeypatch, close_style):
    case = ModeledOpaf(monkeypatch)
    setattr(case, close_style, True)
    _, _, _, timing = case.prepared()
    assert case.counts() == {'GET': 4, 'POST': 1, 'PIN': 5, 'INTENT': 1}
    assert timing['tls_connections'] == 5 and all(c.closed for c in case.connections)


def test_changed_reopened_tls_pin_prevents_credentials_and_post(monkeypatch):
    case = ModeledOpaf(monkeypatch)
    case.server_close = True
    case.wrong_pin_connection = 2
    with pytest.raises(OpafError, match='TLS identity'):
        case.prepared()
    assert case.counts() == {'GET': 1, 'POST': 0, 'PIN': 2, 'INTENT': 0}
    assert all(c.closed for c in case.connections)


def test_callback_copy_cannot_rewrite_observed_opaf_evidence(monkeypatch):
    case = ModeledOpaf(monkeypatch)
    def callback(environment):
        environment['workflow']['model'] = 'unapproved-mutation'
    _, invocation, environment, _ = case.prepared(callback)
    assert environment['workflow']['model'] == case.role['model']
    assert validate_model_environment(environment, case.target, 'mapper', case.identity, invocation) == environment


def test_nested_prepared_role_is_rejected_before_post_and_closes_connection(monkeypatch):
    case = ModeledOpaf(monkeypatch)
    with pytest.raises(OpafError, match='intent callback'):
        case.prepared(lambda environment: case.prepared())
    assert case.counts()['POST'] == 0 and all(c.closed for c in case.connections)


@pytest.mark.parametrize('damage', ['graph', 'model'])
def test_observed_graph_or_saved_model_drift_blocks_intent_and_post(monkeypatch, damage):
    case = ModeledOpaf(monkeypatch)
    if damage == 'graph': case.graph['nodes'].append({'data': {'type': 'tool'}})
    else: case.saved['connectionDetails']['model_id'] = 'changed'
    with pytest.raises(OpafError): case.prepared()
    assert case.counts()['POST'] == case.counts()['INTENT'] == 0
    assert all(c.closed for c in case.connections)


@pytest.mark.parametrize('failure', [TimeoutError(PRIVATE), OSError(PRIVATE)])
def test_uncertain_post_is_once_only_redacted_and_connection_closed(monkeypatch, failure):
    case = ModeledOpaf(monkeypatch)
    case.post_error = failure
    with pytest.raises(OpafError, match='no automatic retry') as caught:
        case.prepared()
    assert PRIVATE not in str(caught.value)
    assert case.counts()['POST'] == case.counts()['INTENT'] == 1
    assert all(c.closed for c in case.connections)


@pytest.mark.parametrize('failure', ['callback', 'changed_request', 'changed_environment', 'expired'])
def test_callback_failure_mutation_and_expiry_never_post(monkeypatch, failure):
    case = ModeledOpaf(monkeypatch)
    def callback(env):
        if failure == 'callback': raise OSError(PRIVATE)
        if failure == 'changed_request': case.request['source'] = 'changed'
        if failure == 'changed_environment':
            # Callback gets a detached copy, so cannot rewrite observed evidence.
            env['workflow']['model'] = 'changed'
            raise RuntimeError('stop after mutating detached copy')
        if failure == 'expired':
            late = datetime.now(timezone.utc) + timedelta(seconds=121)
            monkeypatch.setattr('fox.opaf._utc_now', lambda: late)
    with pytest.raises((OpafError, RuntimeError)):
        case.prepared(callback)
    assert case.counts()['POST'] == 0
    assert all(c.closed for c in case.connections)


@pytest.mark.parametrize('damage', ['oversize_request', 'oversize_response', 'malformed', 'http_error'])
def test_request_and_response_bounds_no_retry(monkeypatch, damage):
    case = ModeledOpaf(monkeypatch)
    if damage == 'oversize_request': case.request['source'] = 'x' * 650001
    if damage == 'oversize_response': case.oversize = True
    if damage == 'malformed': case.reply['message'] = 'not json'
    if damage == 'http_error':
        case.status = 503
    with pytest.raises(OpafError): case.prepared()
    assert case.counts()['POST'] <= 1
    assert all(c.closed for c in case.connections)


def direct_case():
    target = direct_target()
    service = InjectedService()
    # Keep the synthetic test output independent of a real focus request shape.
    service.alter = lambda body: body['chat_response']['choices'][0]['message']['content'][0].update(text='{"ok":true}')
    client = OciGenAiClient(target, client=service, sdk=fake_sdk())
    identity = {'job_id': 'fox-' + 'a'*20, 'source_hash': 'b'*64}
    request = {'focus_id': 'synthetic', 'owned_objects': [], 'focus_binding': 'c'*64, 'source_binding': 'b'*64}
    return target, service, client, identity, request


def test_direct_prepared_callback_before_one_sdk_chat_and_original_evidence_schema():
    target, service, client, identity, request = direct_case()
    callbacks = []
    def callback(env):
        assert not service.calls
        callbacks.append(deepcopy(env))
        env['model'] = 'detached-copy-change'
    output, invocation, environment, timing = client.invoke_prepared(target['design_provider']['roles']['mapper'],
        request, identity, role_name='mapper', target_profile=target, before_invoke=callback)
    assert output == {'ok': True} and len(service.calls) == 1
    assert environment == callbacks[0]
    assert validate_environment(environment, target, 'mapper', identity, invocation) == environment
    assert set(timing) == {'schema_version', 'scope', 'provider', 'environment_seconds', 'setup_seconds',
                           'before_invoke_seconds', 'request_seconds', 'total_seconds'}
    assert service.calls[0][1]['retry_strategy'] == 'NO_RETRY'


@pytest.mark.parametrize('damage', ['target', 'callback', 'mutated', 'expired', 'uncertain'])
def test_direct_prepared_failure_order_and_no_retries(monkeypatch, damage):
    target, service, client, identity, request = direct_case()
    approved = deepcopy(target)
    if damage == 'target': approved['design_provider']['roles']['mapper']['model'] = 'changed'
    if damage == 'uncertain': service.failure = TimeoutError(PRIVATE)
    def callback(env):
        if damage == 'callback': raise OSError('intent write failed')
        if damage == 'mutated': request['changed'] = True
        if damage == 'expired':
            late = datetime.now(timezone.utc) + timedelta(seconds=121)
            monkeypatch.setattr('fox.oci_genai._now', lambda: late.isoformat())
    with pytest.raises((OpafError, OSError)) as caught:
        client.invoke_prepared(target['design_provider']['roles']['mapper'], request, identity,
            role_name='mapper', target_profile=approved, before_invoke=callback)
    assert PRIVATE not in str(caught.value)
    assert len(service.calls) == (1 if damage == 'uncertain' else 0)


@pytest.mark.parametrize('failure', ['auth', 'oversize_request'])
def test_direct_setup_failure_precedes_intent_and_sdk_chat(monkeypatch, failure):
    target, service, client, identity, request = direct_case()
    if failure == 'auth':
        def bad_client(): raise OSError(PRIVATE)
        monkeypatch.setattr(client, '_client', bad_client)
    else:
        request['source'] = 'x' * 650001
    with pytest.raises(OpafError, match='setup failed') as caught:
        client.invoke_prepared(target['design_provider']['roles']['mapper'], request, identity,
            role_name='mapper', target_profile=target,
            before_invoke=lambda environment: pytest.fail('Setup must succeed before intent'))
    assert not service.calls and PRIVATE not in str(caught.value)


def test_timing_rejects_free_form_fields_and_bounds_values(monkeypatch):
    clock = iter((0, 9999999, 99999999))
    monkeypatch.setattr('fox.provider_timing.monotonic', lambda: next(clock))
    timing = ProviderTiming('opaf')
    timing.mark('environment_seconds')
    timing.increment('response_body_bytes', 2**60)
    with pytest.raises(ValueError): timing.mark(PRIVATE)
    with pytest.raises(ValueError): timing.increment('headers')
    assert timing.finish()['total_seconds'] == timing.value['environment_seconds'] == 604800
    assert timing.value['response_body_bytes'] == 2**53 - 1
