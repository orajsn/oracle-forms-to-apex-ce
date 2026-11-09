"""Controlled HTTP response tests, not a live TLS/hosted callback claim."""
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from forms2apex import prototype_authority_client as client
from forms2apex.target_profile import select_target_profile


@pytest.fixture
def case(monkeypatch):
    profile = select_target_profile('jsn-native-project-2616-v1')
    monkeypatch.setattr(client.runtime_preflight, 'bound_target_profile', lambda settings: deepcopy(profile))
    request = {'job_id': 'fox-' + '1' * 20, 'project_id': 'synthetic-project', 'source_binding': 'a' * 64}
    response = {'schema_version': 1, 'scope': client.RESPONSE_SCOPE, 'request_sha256': client._hash(request),
                **request, 'target_profile_sha256': 'b' * 64,
                'execution_target_sha256': client._hash(client.execution_target(profile))}
    state = SimpleNamespace(status=200, body=response, calls=[], closed=0, profile=profile, fail_at=None,
                            settings=SimpleNamespace(bearer_token='synthetic-converter-test-token'))
    class Connection:
        def __init__(self, host, port, **kwargs):
            state.calls.append(('connect', host, port, kwargs))
        def request(self, *args, **kwargs):
            state.calls.append(('request', args, kwargs))
            if state.fail_at == 'request': raise TimeoutError('Authored request timeout')
        def getresponse(self):
            if state.fail_at == 'headers': raise TimeoutError('Authored response timeout')
            def read(bound):
                if state.fail_at == 'body': raise TimeoutError('Authored body timeout')
                return (state.body if isinstance(state.body, bytes) else json.dumps(state.body).encode())[:bound]
            return SimpleNamespace(status=state.status, read=read)
        def close(self): state.closed += 1
    monkeypatch.setattr(client.http.client, 'HTTPSConnection', Connection)
    callback = client.PrototypeAuthorityClient(state.settings,
        authority_url='https://fox.example.test' + client.AUTHORITY_PATH,
        authority_origin='https://fox.example.test')
    return state, callback, request


def test_exact_unchanged_request_and_secure_transport_configuration(case, monkeypatch):
    state, callback, request = case
    monkeypatch.setenv('HTTPS_PROXY', 'http://untrusted-proxy.test:8080')
    assert callback(request) is request
    connect, sent = state.calls
    assert connect[1:3] == ('fox.example.test', 443)
    context = connect[3]['context']
    assert context.check_hostname and context.verify_mode == 2
    assert connect[3]['timeout'] == callback.timeout == client.DEFAULT_AUTHORITY_TIMEOUT_SECONDS == 120
    assert client.MAX_AUTHORITY_TIMEOUT_SECONDS == 120
    assert sent[1] == ('POST', client.AUTHORITY_PATH)
    assert sent[2]['headers']['Authorization'] == 'Bearer synthetic-converter-test-token'
    assert sent[2]['headers']['Origin'] == 'https://fox.example.test'
    assert json.loads(sent[2]['body']) == request
    assert state.closed == 1


def test_preclaim_callback_binds_typed_consent_record_without_changing_original_request(case):
    state,callback,request=case
    record='c'*64
    state.body.update(scope=client.PRECLAIM_RESPONSE_SCOPE,record_sha256=record)
    assert callback.authorize_preclaim(request,record) is request
    sent=[row for row in state.calls if row[0]=='request']
    assert len(sent)==1 and sent[0][1]==('POST',client.PRECLAIM_AUTHORITY_PATH)
    assert json.loads(sent[0][2]['body'])=={'schema_version':1,
        'scope':'fox-prototype-preclaim-authorize-request-v1','request':request,'record_sha256':record}
    assert state.closed==1


@pytest.mark.parametrize('failure',['missing','forged','old-scope','unknown','response-loss'])
def test_preclaim_callback_refuses_missing_forged_or_old_record_and_never_retries(case,failure):
    state,callback,request=case
    state.body.update(scope=client.PRECLAIM_RESPONSE_SCOPE,record_sha256='c'*64)
    if failure=='missing': state.body.pop('record_sha256')
    elif failure=='forged': state.body['record_sha256']='d'*64
    elif failure=='old-scope': state.body['scope']=client.RESPONSE_SCOPE
    elif failure=='unknown': state.body['permission']=True
    else: state.fail_at='headers'
    with pytest.raises(RuntimeError,match='UNAVAILABLE_NO_RETRY'):
        callback.authorize_preclaim(request,'c'*64)
    assert len([row for row in state.calls if row[0]=='request'])==1 and state.closed==1


@pytest.mark.parametrize('record',[None,True,'z'*64,'a'*63,{},''])
def test_invalid_preclaim_record_refuses_before_any_http(case,record):
    state,callback,request=case
    with pytest.raises(RuntimeError,match='UNAVAILABLE_NO_RETRY'):
        callback.authorize_preclaim(request,record)
    assert state.calls==[] and state.closed==0


@pytest.mark.parametrize('failure', ['hash', 'destination', 'job', 'scope', 'extra', 'boolean_version',
                                    'nonhex', 'duplicate', 'oversized', 'nonfinite', 'redirect', 'denied'])
def test_callback_fail_closed_without_redirect_or_retry(case, failure):
    state, callback, request = case
    if failure == 'hash': state.body['request_sha256'] = '0' * 64
    elif failure == 'destination': state.body['execution_target_sha256'] = '0' * 64
    elif failure == 'job': state.body['job_id'] = 'fox-' + '0' * 20
    elif failure == 'scope': state.body['scope'] = 'untrusted'
    elif failure == 'extra': state.body['raw_source'] = 'must-not-return'
    elif failure == 'boolean_version': state.body['schema_version'] = True
    elif failure == 'nonhex': state.body['target_profile_sha256'] = 'z' * 64
    elif failure == 'duplicate': state.body = b'{"job_id":"x","job_id":"y"}'
    elif failure == 'oversized': state.body = b'x' * (client.MAX_RESPONSE_BYTES + 1)
    elif failure == 'nonfinite': state.body = b'{"value":NaN}'
    elif failure == 'redirect': state.status = 302
    else: state.status = 401
    with pytest.raises(RuntimeError, match='NO_RETRY'): callback(request)
    assert len([call for call in state.calls if call[0] == 'request']) == 1
    assert state.closed == 1


def test_network_failure_has_no_retry(case, monkeypatch):
    state, callback, request = case
    def fail(*args, **kwargs):
        state.calls.append(('failed',)); raise OSError('synthetic private detail')
    monkeypatch.setattr(client.http.client, 'HTTPSConnection', fail)
    with pytest.raises(RuntimeError, match='^PROTOTYPE_CURRENT_AUTHORITY_UNAVAILABLE_NO_RETRY$'):
        callback(request)
    assert state.calls == [('failed',)]


@pytest.mark.parametrize('timeout', [15, 30, 30.0, 0.1, 120, 120.0])
def test_explicit_bounded_timeout_remains_supported(case, timeout):
    state, _, _ = case
    callback = client.PrototypeAuthorityClient(state.settings,
        authority_url='https://fox.example.test' + client.AUTHORITY_PATH,
        authority_origin='https://fox.example.test', timeout=timeout)
    assert callback.timeout == timeout


@pytest.mark.parametrize('timeout', [0, 0.0, -1, 120.000001, 121, True, False, '120', None,
                                  float('inf'), float('-inf'), float('nan')])
def test_timeout_cap_and_type_checks_are_unchanged(case, timeout):
    state, _, _ = case
    with pytest.raises(ValueError):
        client.PrototypeAuthorityClient(state.settings,
            authority_url='https://fox.example.test' + client.AUTHORITY_PATH,
            authority_origin='https://fox.example.test', timeout=timeout)


@pytest.mark.parametrize('failure', ['request', 'headers', 'body', 'missing'])
def test_missing_or_timed_out_authority_stops_real_gateway_before_stage_without_retry(case, tmp_path_factory, failure):
    from test_prototype_gateway import case as gateway_fixture
    state, callback, _ = case
    item = gateway_fixture.__wrapped__(tmp_path_factory)
    item.adapter.authorize = callback
    if failure == 'missing': state.status = 503
    else: state.fail_at = failure
    with pytest.raises(RuntimeError, match='^PROTOTYPE_CURRENT_AUTHORITY_UNAVAILABLE_NO_RETRY$'):
        item.adapter.run_stage('validate', item.request)
    assert len([entry for entry in state.calls if entry[0] == 'request']) == 1
    assert state.closed == 1
    assert item.calls == []  # No validator, preflight, SQL runner or import.
    assert list(item.settings.jobs_root.iterdir()) == []  # No stage claim/receipt.


def test_registered_target_change_during_callback_revokes_authority(case, monkeypatch):
    state, callback, request = case
    observations = []
    def changing(settings):
        value = deepcopy(state.profile)
        if observations:
            value['apex']['workspace'] = 'DIFFERENT_TARGET'
        observations.append(value)
        return value
    monkeypatch.setattr(client.runtime_preflight, 'bound_target_profile', changing)
    with pytest.raises(RuntimeError, match='NO_RETRY'): callback(request)
    assert len(observations) == 2
    assert len([call for call in state.calls if call[0] == 'request']) == 1
    assert state.closed == 1


def test_payload_cannot_change_the_trusted_deadline(case):
    state,callback,request=case
    request['timeout']=0.1
    state.body['request_sha256']=client._hash(request)
    assert callback(request) is request
    assert state.calls[0][3]['timeout']==120
    assert len([call for call in state.calls if call[0]=='request'])==1 and state.closed==1


@pytest.mark.parametrize('failure',['request','headers','body'])
def test_default120_timeout_is_single_attempt_and_always_closes(case,failure):
    state,callback,request=case;state.fail_at=failure
    with pytest.raises(RuntimeError,match='^PROTOTYPE_CURRENT_AUTHORITY_UNAVAILABLE_NO_RETRY$'):
        callback(request)
    assert state.calls[0][3]['timeout']==120
    assert len([call for call in state.calls if call[0]=='connect'])==1
    assert len([call for call in state.calls if call[0]=='request'])==1 and state.closed==1


@pytest.mark.parametrize('url,origin', [
    ('http://fox.example.test' + client.AUTHORITY_PATH, 'http://fox.example.test'),
    ('https://fox.example.test/not-authority', 'https://fox.example.test'),
    ('https://fox.example.test' + client.AUTHORITY_PATH + '?url=other', 'https://fox.example.test'),
    ('https://user:pass@fox.example.test' + client.AUTHORITY_PATH, 'https://user:pass@fox.example.test'),
    ('https://fox.example.test:444' + client.AUTHORITY_PATH, 'https://fox.example.test:444'),
    ('https://fox.example.test' + client.AUTHORITY_PATH, 'https://other.test'),
])
def test_request_cannot_choose_authority_location(url, origin):
    with pytest.raises(ValueError):
        client.PrototypeAuthorityClient(SimpleNamespace(bearer_token='synthetic-test-token'),
                                        authority_url=url, authority_origin=origin)


def test_projection_matches_fox_and_excludes_only_nonexecution_identity():
    from fox.prototype_authority import execution_target as fox_projection
    profile = select_target_profile('jsn-native-project-2616-v1')
    assert client.execution_target(profile) == fox_projection(profile)
    changed = deepcopy(profile)
    changed['opaf']['roles']['mapper']['workflow_id'] = 'F' * 32
    changed['profile_id'] = 'focus-prototype'
    changed['scope']['conversion_profile'] = 'native-blueprint-prototype-v1'
    assert client.execution_target(profile) == client.execution_target(changed)
    for section in ('oci', 'database', 'apex', 'sqlcl'):
        changed = deepcopy(profile)
        key = next(iter(changed[section])); changed[section][key] += '-different'
        assert client.execution_target(profile) != client.execution_target(changed)
        del changed[section][key]
        with pytest.raises((ValueError, KeyError)): client.execution_target(changed)
        with pytest.raises((ValueError, KeyError)): fox_projection(changed)


def test_real_bound_registered_target_rejects_unbound_settings():
    # This check deliberately uses the real preflight loader, not the case fixture.
    callback = client.PrototypeAuthorityClient(SimpleNamespace(bearer_token='synthetic-test-token'),
        authority_url='https://fox.example.test' + client.AUTHORITY_PATH,
        authority_origin='https://fox.example.test')
    with pytest.raises(RuntimeError, match='NO_RETRY'): callback({})
