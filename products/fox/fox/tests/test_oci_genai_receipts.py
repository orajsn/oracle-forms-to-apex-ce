"""Synthetic receipt boundary only; no OCI SDK install, auth or external calls."""
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from fox.oci_genai import OciGenAiClient
from fox.opaf import OpafError, canonical_hash
from fox.provider_receipts import LocalProviderReceiptStore, MAX_RECEIPT_BYTES, ProviderReceiptError
from test_oci_genai import InjectedService, fake_sdk, target

PRIVATE = 'PRIVATE-CREDENTIAL-EXCEPTION-MARKER'


@pytest.fixture
def case(tmp_path):
    current, service = target(), InjectedService()
    service.alter = lambda body: body['chat_response']['choices'][0]['message']['content'][0].update(text='{"ok":true}')
    client = OciGenAiClient(current, client=service, sdk=fake_sdk())
    job = tmp_path / 'sealed-job'
    job.mkdir()
    store = LocalProviderReceiptStore(tmp_path / 'private-receipts', sealed_job_root=job)
    identity = {'job_id': 'fox-' + 'a' * 20, 'source_hash': 'b' * 64}
    request = {'focus_id': 'synthetic', 'owned_objects': [], 'focus_binding': 'c' * 64,
               'source_binding': 'b' * 64, 'original_code': "BEGIN x := 'sensitive literal'; END;"}
    return client, service, current, identity, request, store


def invoke(case, **kwargs):
    client, _, current, identity, request, store = case
    return client.invoke_prepared(current['design_provider']['roles']['mapper'], request, identity,
        role_name='mapper', target_profile=current, before_invoke=lambda env: None,
        receipt_store=store, **kwargs)


def recover(case):
    client, _, current, identity, request, store = case
    return client.recover_prepared(current['design_provider']['roles']['mapper'], request, identity,
        role_name='mapper', target_profile=current, receipt_store=store)


def records(store, kind):
    return list(store.root.glob('*.' + kind + '.json'))


def payload(store, kind):
    return json.loads(records(store, kind)[0].read_text(encoding='utf-8'))['payload']


def test_good_capture_precedes_post_and_parse_preserves_existing_contract(case, monkeypatch):
    client, service, current, identity, request, store = case
    originals = deepcopy((current, identity, request))
    original_chat = service.chat
    def chat(details, **options):
        intent = payload(store, 'intent')
        assert intent['client_request_id'] == options['opc_request_id']
        assert not records(store, 'response')
        return original_chat(details, **options)
    service.chat = chat
    original_parse = client._parse_response
    def parse(*args, **kwargs):
        assert payload(store, 'response')['body'] == kwargs['body']
        return original_parse(*args, **kwargs)
    monkeypatch.setattr(client, '_parse_response', parse)
    output, invocation, environment, timing = invoke(case)
    assert output == {'ok': True} and timing['provider'] == 'oci_genai'
    assert invocation['client_request_id'] == payload(store, 'intent')['client_request_id']
    assert invocation['request_id'] == payload(store, 'response')['request_id']
    assert set(invocation) == {'schema_version', 'provider', 'role', 'model', 'model_version',
        'prompt_version', 'prompt_sha256', 'request_id', 'client_request_id', 'request_sha256',
        'wire_request_sha256', 'response_sha256', 'started_at_utc', 'completed_at_utc'}
    assert recover(case) == (output, invocation, environment)
    assert len(service.calls) == 1 and originals == (current, identity, request)
    # Intent stores hashes only, never the request's source/code or SDK credentials.
    assert 'sensitive literal' not in records(store, 'intent')[0].read_text()
    with pytest.raises(OpafError, match='without replay'):
        invoke(case)
    assert len(service.calls) == 1


@pytest.mark.parametrize('damage', ['malformed', 'truncated', 'wrong_model', 'tool_call', 'http', 'missing_id'])
def test_invalid_received_output_retained_and_rejected_on_recovery(case, damage):
    _, service, _, _, _, store = case
    def alter(body):
        choice = body['chat_response']['choices'][0]
        if damage == 'malformed': choice['message']['content'][0]['text'] = PRIVATE
        if damage == 'truncated': choice['finish_reason'] = 'length'
        if damage == 'wrong_model': body['model_id'] = 'wrong-model'
        if damage == 'tool_call': choice['message']['tool_calls'] = [{'name': PRIVATE}]
    service.alter = alter
    original_chat = service.chat
    def chat(*args, **kwargs):
        response = original_chat(*args, **kwargs)
        response.headers['authorization'] = PRIVATE
        response.headers['set-cookie'] = PRIVATE
        if damage == 'http': response.status = 503
        if damage == 'missing_id': response.headers.pop('opc-request-id')
        return response
    service.chat = chat
    for action in (lambda: invoke(case), lambda: recover(case)):
        with pytest.raises(OpafError, match='Captured OCI response') as caught:
            action()
        assert PRIVATE not in str(caught.value)
    response = payload(store, 'response')
    assert response['outcome'] == 'captured'
    if damage == 'malformed':
        assert response['body']['chat_response']['choices'][0]['message']['content'][0]['text'] == PRIVATE
    else:
        assert 'authorization' not in records(store, 'response')[0].read_text()
        assert 'set-cookie' not in records(store, 'response')[0].read_text()
    assert len(service.calls) == 1


def test_crash_after_capture_recovers_on_fresh_client_without_auth_or_post(case, monkeypatch):
    client, service, current, _, _, store = case
    def crash(*args, **kwargs):
        raise SystemExit('simulated crash AFTER durable capture')
    monkeypatch.setattr(client, '_parse_response', crash)
    with pytest.raises(SystemExit): invoke(case)
    assert len(records(store, 'response')) == 1
    fresh = OciGenAiClient(current, sdk=fake_sdk())
    def forbidden(): pytest.fail('Recovery must not initialize auth/client')
    monkeypatch.setattr(fresh, '_client', forbidden)
    monkeypatch.setattr('fox.oci_genai._now', forbidden)
    recovered = recover((fresh, *case[1:]))
    assert recovered[0] == {'ok': True} and len(service.calls) == 1
    intent, response = payload(store, 'intent'), payload(store, 'response')
    assert recovered[1]['started_at_utc'] == intent['started_at_utc']
    assert recovered[1]['completed_at_utc'] == response['completed_at_utc']
    assert recovered[2] == intent['environment']


def test_transport_unknown_pending_intent_never_resubmits(case):
    _, service, _, _, _, store = case
    service.failure = TimeoutError(PRIVATE)
    with pytest.raises(OpafError, match='without replay') as caught: invoke(case)
    assert PRIVATE not in str(caught.value)
    assert records(store, 'intent') and not records(store, 'response')
    service.failure = None
    with pytest.raises(ProviderReceiptError, match='unknown'): recover(case)
    with pytest.raises(ProviderReceiptError, match='without replay'): invoke(case)
    assert len(service.calls) == 1


@pytest.mark.parametrize('damage', ['job', 'source', 'identity', 'profile', 'request', 'model', 'role', 'wire'])
def test_recovery_rejects_any_current_binding_change(case, damage):
    invoke(case)
    client, service, current, identity, request, _ = case
    if damage == 'job': identity['job_id'] += '-other'
    if damage == 'source': identity['source_hash'] = 'd' * 64
    if damage == 'identity': identity['owner'] = 'other-owner'
    if damage == 'profile': current['profile_id'] += '-other'
    if damage == 'request': request['original_code'] += ' --changed'
    if damage == 'model': current['design_provider']['roles']['mapper']['model'] = 'other'
    if damage == 'wire': client.sdk.generative_ai_inference.models.TextContent = lambda **kw: {'text': kw['text'] + 'changed'}
    with pytest.raises(OpafError):
        if damage == 'role':
            client.recover_prepared(current['design_provider']['roles']['reviewer'], request, identity,
                role_name='reviewer', target_profile=current, receipt_store=case[-1])
        else:
            recover(case)
    assert len(service.calls) == 1


@pytest.mark.parametrize('kind', ['intent', 'response'])
@pytest.mark.parametrize('damage', ['tampered', 'truncated', 'missing', 'oversized', 'hardlink', 'symlink'])
def test_unsafe_receipts_fail_closed_without_post(case, tmp_path, kind, damage):
    invoke(case)
    store = case[-1]
    path = records(store, kind)[0]
    if damage == 'tampered':
        value = json.loads(path.read_text())
        value['payload']['injected'] = PRIVATE
        path.write_text(json.dumps(value))
    if damage == 'truncated': path.write_bytes(b'{')
    if damage == 'missing': path.unlink()
    if damage == 'oversized': path.write_bytes(b'x' * (MAX_RECEIPT_BYTES + 1))
    if damage == 'hardlink': os.link(path, tmp_path / ('linked-' + kind))
    if damage == 'symlink':
        original = tmp_path / ('original-' + kind)
        path.rename(original)
        try: path.symlink_to(original)
        except OSError: pytest.skip('Windows symlink privilege unavailable; hardlink scenario still runs')
    with pytest.raises(OpafError) as caught: recover(case)
    assert PRIVATE not in str(caught.value) and len(case[1].calls) == 1
    with pytest.raises(OpafError): invoke(case)
    assert len(case[1].calls) == 1


def test_oversized_received_body_records_unavailable_without_truncation_or_replay(case):
    case[1].alter = lambda body: body.update(extra='x' * 2_000_001)
    with pytest.raises(ProviderReceiptError): invoke(case)
    response = payload(case[-1], 'response')
    assert response['outcome'] == 'body_unavailable' and response['body'] is None
    with pytest.raises(OpafError): recover(case)
    with pytest.raises(OpafError): invoke(case)
    assert len(case[1].calls) == 1


def test_intent_persistence_failure_prevents_post(case, monkeypatch):
    def fail(*args, **kwargs): raise OSError(PRIVATE)
    monkeypatch.setattr(case[-1], '_write', fail)
    with pytest.raises(ProviderReceiptError) as caught: invoke(case)
    assert PRIVATE not in str(caught.value) and not case[1].calls


def test_response_persistence_failure_leaves_unknown_and_never_replays(case, monkeypatch):
    store = case[-1]
    original_write = store._write
    def write(key, kind, data):
        if kind == 'response': raise OSError(PRIVATE)
        original_write(key, kind, data)
    monkeypatch.setattr(store, '_write', write)
    with pytest.raises(ProviderReceiptError) as caught: invoke(case)
    assert PRIVATE not in str(caught.value)
    with pytest.raises(OpafError): recover(case)
    with pytest.raises(OpafError): invoke(case)
    assert len(case[1].calls) == 1


def test_store_outside_sealed_tree_and_root_replacement_rejected(case):
    store = case[-1]
    with pytest.raises(ProviderReceiptError):
        LocalProviderReceiptStore(store.sealed_job_root / 'receipts', sealed_job_root=store.sealed_job_root)
    invoke(case)
    old = store.root.with_name('preserved-original-root')
    store.root.rename(old)
    store.root.mkdir(mode=0o700)
    with pytest.raises(OpafError): recover(case)
    with pytest.raises(OpafError): invoke(case)
    assert len(case[1].calls) == 1


def test_private_modes_and_root_symlink_are_rejected_when_supported(case, tmp_path):
    store = case[-1]
    alias = tmp_path / 'root-alias'
    try: alias.symlink_to(store.root, target_is_directory=True)
    except OSError: pytest.skip('Windows symlink privilege unavailable')
    with pytest.raises(ProviderReceiptError):
        LocalProviderReceiptStore(alias, sealed_job_root=store.sealed_job_root)
    if os.name != 'nt':
        store.root.chmod(0o755)
        with pytest.raises(OpafError): invoke(case)
        assert not case[1].calls


@pytest.mark.parametrize('damage', ['binding_extra', 'environment_extra', 'binding_bool', 'environment_bool'])
def test_fixed_metadata_schemas_reject_accidental_private_context_before_post(case, damage):
    client, service, current, identity, request, store = case
    environment = client.observe_environment(current['design_provider']['roles']['mapper'], identity,
        role_name='mapper', target_profile=current)
    binding = client._receipt_binding(current['design_provider']['roles']['mapper'], request, identity,
        'mapper', current, client._prepare_request(current['design_provider']['roles']['mapper'], request)[2])
    if damage == 'binding_extra': binding['authorization'] = PRIVATE
    if damage == 'environment_extra': environment['headers'] = {'cookie': PRIVATE}
    if damage == 'binding_bool': binding['schema_version'] = True
    if damage == 'environment_bool': environment['schema_version'] = True
    with pytest.raises(ProviderReceiptError) as caught:
        store.begin(binding, client_request_id='fox-' + 'd' * 32,
            started_at_utc=environment['observed_at_utc'], environment=environment)
    assert PRIVATE not in str(caught.value) and not service.calls and not list(store.root.iterdir())


@pytest.mark.parametrize('failure', ['auth', 'oversize_request'])
def test_setup_failure_with_receipts_still_precedes_all_intents_and_post(case, monkeypatch, failure):
    if failure == 'auth':
        def fail(): raise OSError(PRIVATE)
        monkeypatch.setattr(case[0], '_client', fail)
    else:
        case[4]['source'] = 'x' * 650_001
    with pytest.raises(OpafError, match='setup failed') as caught: invoke(case)
    assert PRIVATE not in str(caught.value)
    assert not case[1].calls and not list(case[-1].root.iterdir())


def test_concurrent_same_binding_can_submit_only_one_fake_post(case):
    def attempt():
        try:
            return invoke(case)[0]
        except ProviderReceiptError:
            return 'blocked'
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: attempt(), range(2)))
    assert results.count({'ok': True}) == results.count('blocked') == 1
    assert len(case[1].calls) == 1


def test_bool_envelope_schema_with_recomputed_payload_digest_fails_closed(case):
    invoke(case)
    path = records(case[-1], 'response')[0]
    record = json.loads(path.read_text())
    record['schema_version'] = True
    # Correct payload digest must not bypass the strict outer schema.
    record['payload_sha256'] = canonical_hash(record['payload'])
    path.write_text(json.dumps(record))
    with pytest.raises(OpafError): recover(case)
    with pytest.raises(OpafError): invoke(case)
    assert len(case[1].calls) == 1


@pytest.mark.parametrize('damage', ['profile', 'oversize_request', 'role'])
def test_recovery_failure_before_receipt_read_never_claims_captured_response(case, monkeypatch, damage):
    client, service, current, identity, request, store = case
    role = deepcopy(current['design_provider']['roles']['mapper'])
    selected = deepcopy(current)
    if damage == 'profile': selected['profile_id'] += '-changed'
    elif damage == 'oversize_request': request['oversize'] = 'x' * 650_001
    else: role['prompt_version'] = 'unapproved'
    def forbidden(*args, **kwargs): pytest.fail('Invalid inputs must stop before receipt read or auth')
    monkeypatch.setattr(store, 'read', forbidden)
    monkeypatch.setattr(client, '_client', forbidden)
    with pytest.raises(OpafError, match='recovery inputs are unavailable') as caught:
        client.recover_prepared(role, request, identity, role_name='mapper',
                               target_profile=selected, receipt_store=store)
    assert 'Captured' not in str(caught.value)
    assert not service.calls and not list(store.root.iterdir())


def test_root_parent_sync_precedes_receipt_namespace_sync(case, monkeypatch):
    from fox import provider_receipts as receipts
    events = []
    original = receipts._sync_directory
    def observed(path):
        events.append(path)
        return original(path)
    monkeypatch.setattr(receipts, '_sync_directory', observed)
    old = case[-1]
    store = LocalProviderReceiptStore(old.root.with_name('new-private-receipts'),
                                      sealed_job_root=old.sealed_job_root)
    assert events == [store.root.parent]
    invoke((*case[:-1], store))
    assert events == [store.root.parent, store.root, store.root]


def test_failed_root_parent_sync_refuses_store_before_any_provider_call(case, monkeypatch):
    from fox import provider_receipts as receipts
    def failed(_): raise OSError(PRIVATE)
    monkeypatch.setattr(receipts, '_sync_directory', failed)
    old = case[-1]
    with pytest.raises(ProviderReceiptError) as caught:
        LocalProviderReceiptStore(old.root.with_name('sync-failed-root'),
                                  sealed_job_root=old.sealed_job_root)
    assert PRIVATE not in str(caught.value) and not case[1].calls


@pytest.mark.parametrize('status,code', [(400, 'InvalidParameter'), (429, 'TooManyRequests'), (500, 'InternalServerError')])
def test_sdk_service_error_metadata_is_retained_without_message_headers_or_retry(case, status, code):
    client, service, _, _, _, store = case
    class SdkServiceError(Exception):
        pass
    client.sdk.exceptions = SimpleNamespace(ServiceError=SdkServiceError)
    failure = SdkServiceError(PRIVATE)
    failure.status, failure.code = status, code
    failure.message = PRIVATE
    failure.headers = {'opc-request-id': 'synthetic-service-error-id',
                       'authorization': PRIVATE, 'set-cookie': PRIVATE}
    service.failure = failure
    with pytest.raises(OpafError, match='service error metadata was captured') as caught:
        invoke(case)
    assert PRIVATE not in str(caught.value)
    response = payload(store, 'response')
    assert response['status'] == status
    assert response['request_id'] == 'synthetic-service-error-id'
    assert response['body'] == {'scope': 'fox-oci-service-error-v1', 'code': code}
    assert PRIVATE not in records(store, 'response')[0].read_text()
    with pytest.raises(OpafError): recover(case)
    with pytest.raises(OpafError): invoke(case)
    assert len(service.calls) == 1


def test_untyped_exception_status_does_not_fabricate_sdk_service_response(case):
    _, service, _, _, _, store = case
    failure = TimeoutError(PRIVATE)
    failure.status, failure.code = 429, 'TooManyRequests'
    failure.headers = {'opc-request-id': 'not-a-confirmed-sdk-response'}
    service.failure = failure
    with pytest.raises(OpafError) as caught: invoke(case)
    assert 'captured' not in str(caught.value).lower()
    assert not records(store, 'response') and len(service.calls) == 1
