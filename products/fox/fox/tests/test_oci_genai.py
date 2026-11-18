"""Injected OCI SDK/service contracts only; no model, Oracle or browser calls."""
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from fox.design_provider import roles, validate_environment
from fox.oci_genai import OciGenAiClient
from fox.opaf import OpafError, canonical_hash
from fox.prototype_pipeline import run_prototype_pipeline, authorize_prototype_request
from test_prototype_pipeline import documents, SyntheticConverter
from fox.forms_native_plan import POLICY_ID
from fox.forms_understanding_packet import local_packet


def target():
    source = Path(__file__).resolve().parents[2] / 'deployment' / 'target-profile.jsn-project-2616.json'
    value = json.loads(source.read_text())
    value.pop('opaf')
    value['tested_versions'].pop('opaf')
    value['profile_id'] = 'jsn-native-project-2616-oci-genai-v1'
    value['design_provider'] = {'schema_version': 1, 'provider': 'oci_genai',
        'endpoint': 'https://inference.generativeai.us-ashburn-1.oci.oraclecloud.com',
        'authentication': 'instance_principal',
        'roles': {n: {'model': 'xai.grok-4.3', 'prompt_version': 'fox-focus-' + n + '-v1'}
                  for n in ('mapper', 'reviewer')}}
    return value


def authored_output(request):
    if 'candidate' in request:
        return {'source_binding': request['request']['source_binding'],
            'focus_binding': request['request']['focus_binding'],
            'candidate_sha256': request['candidate_sha256'], 'verdict': 'APPROVED', 'findings': []}
    screens, rows = [], []
    screen_id = 'screen-' + request['focus_id']
    for obj in request['owned_objects']:
        row = {'source_object_id': obj['id'], 'disposition': 'unresolved',
            'reason': 'Authored offline structural proposal; business behavior remains unresolved.'}
        if obj['kind'] in ('Block', 'Item'):
            row.update(disposition='proposed', screen_id=screen_id)
            if obj['kind'] == 'Block': row['native_component'] = 'form'
            if not screens: screens.append({'id': screen_id, 'title': 'Authored offline screen'})
        rows.append(row)
    return {'focus_id': request['focus_id'], 'focus_binding': request['focus_binding'],
        'blueprint': {'schema_version': 1, 'scope': 'fox-forms-blueprint-v1',
            'source_binding': request['source_binding'], 'objects': rows, 'screens': screens,
            **{k: [] for k in ('claims', 'relationships', 'actions', 'questions', 'assumptions')}}}


def model(**kwargs):
    return kwargs


def fake_sdk():
    models = NS(**{n: model for n in ('ChatDetails', 'OnDemandServingMode', 'GenericChatRequest',
                                    'SystemMessage', 'TextContent', 'UserMessage')})
    return NS(__version__='2.188.0-injected-test', generative_ai_inference=NS(models=models),
              retry=NS(NoneRetryStrategy=lambda: 'NO_RETRY'), util=NS(to_dict=lambda x: x))


class InjectedService:
    def __init__(self):
        self.calls = []
        self.failure = None
        self.alter = lambda body: None

    def chat(self, details, **kwargs):
        self.calls.append((deepcopy(details), kwargs))
        if self.failure: raise self.failure
        request = json.loads(details['chat_request']['messages'][1]['content'][0]['text'])
        body = {'model_id': details['serving_mode']['model_id'], 'model_version': 'offline-fixture-v1',
            'chat_response': {'api_format': 'GENERIC', 'choices': [{'finish_reason': 'stop',
                'message': {'role': 'ASSISTANT', 'content': [{'type': 'TEXT',
                    'text': json.dumps(authored_output(request))}]}}]}}
        self.alter(body)
        return NS(status=200, headers={'opc-request-id': 'injected-response-' + str(len(self.calls))}, data=body)


@pytest.fixture
def direct_setup(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / 'converter'))
    service, current = InjectedService(), target()
    client = OciGenAiClient(current, client=service, sdk=fake_sdk())
    docs, approvals = documents(), []
    kwargs = {'project_id': 'offline-project', 'project_name': 'Offline direct test',
        'expected_source_binding': local_packet(docs)['source_binding'], 'approved_chunk_hashes': {},
        'approved_policy_id': POLICY_ID, 'opaf_client': client, 'profile': roles(current),
        'target_profile_loader': lambda: deepcopy(current),
        'processing_approval_check': lambda context: approvals.append(context) or True}
    return tmp_path / ('fox-' + '7' * 20), docs, client, service, current, approvals, kwargs


def test_direct_connected_design_review_render_and_historical_authority(direct_setup):
    job, docs, client, service, current, approvals, kwargs = direct_setup
    adapter = SyntheticConverter()
    result = run_prototype_pipeline(job, docs, converter_adapter=adapter, **kwargs)
    assert result['status'] == 'APEX_GENERATED'
    assert result['facts']['native_source_rendered'] is True
    assert result['facts']['business_behavior_accepted'] is False
    assert result['facts']['technically_verified'] is False
    assert len(approvals) == len(service.calls) * 2
    assert approvals[::2] == approvals[1::2]
    assert len(service.calls) == result['assessment']['focus_count'] * 2
    for path in (job / 'prototype-pipeline').glob('focus-*/mapper.json'):
        saved = json.loads(path.read_text())
        assert saved['invocation']['provider'] == 'oci_genai'
        assert saved['invocation']['model_version'] == 'offline-fixture-v1'
        assert not {'workflow_id', 'room_id', 'graph_sha256'} & saved['invocation'].keys()
        assert 'opaf' not in saved['model_environment']
    assert authorize_prototype_request(job, adapter.requests[0]) == adapter.requests[0]
    count = len(service.calls)
    service.failure = AssertionError('Completed calls must never replay')
    assert run_prototype_pipeline(job, docs, converter_adapter=adapter, **kwargs) == result
    assert len(service.calls) == count
    for index, (details, options) in enumerate(service.calls):
        request = details['chat_request']
        assert options['retry_strategy'] == 'NO_RETRY'
        assert request['is_stream'] is False and 'tools' not in request
        assert request['messages'][0]['content'][0]['text']
        if index % 2:
            prior = service.calls[index - 1][0]['chat_request']['messages'][0]['content'][0]['text']
            assert request['messages'][0]['content'][0]['text'] != prior


@pytest.mark.parametrize('damage', ['malformed', 'duplicate', 'truncated', 'wrong_model', 'tool_call', 'nonfinite'])
def test_malformed_output_retains_intent_and_restart_never_replays(direct_setup, damage):
    job, docs, client, service, current, approvals, kwargs = direct_setup
    def alter(body):
        choice = body['chat_response']['choices'][0]
        if damage == 'malformed': choice['message']['content'][0]['text'] = 'not-json'
        if damage == 'duplicate': choice['message']['content'][0]['text'] = '{"a":1,"a":2}'
        if damage == 'truncated': choice['finish_reason'] = 'length'
        if damage == 'wrong_model': body['model_id'] = 'unapproved-model'
        if damage == 'tool_call': choice['message']['tool_calls'] = [{'name': 'forbidden'}]
        if damage == 'nonfinite': choice['message']['content'][0]['text'] = '{"a":NaN}'
    service.alter = alter
    with pytest.raises(OpafError, match='reconcile without replay'):
        run_prototype_pipeline(job, docs, **kwargs)
    assert len(service.calls) == 1
    assert len(list((job / 'prototype-pipeline').glob('focus-*/mapper-intent.json'))) == 1
    assert not list((job / 'prototype-pipeline').glob('focus-*/mapper.json'))
    service.alter = lambda body: None
    with pytest.raises(OpafError, match='uncertain'):
        run_prototype_pipeline(job, docs, **kwargs)
    assert len(service.calls) == 1


def test_transient_transport_uncertain_result_is_not_retried(direct_setup):
    job, docs, client, service, current, approvals, kwargs = direct_setup
    service.failure = TimeoutError('PRIVATE SERVICE BODY')
    with pytest.raises(OpafError, match='reconcile without replay') as caught:
        run_prototype_pipeline(job, docs, **kwargs)
    assert 'PRIVATE' not in str(caught.value)
    service.failure = None
    with pytest.raises(OpafError, match='uncertain'):
        run_prototype_pipeline(job, docs, **kwargs)
    assert len(service.calls) == 1


def test_fresh_source_approval_precedes_inference(direct_setup):
    job, docs, client, service, current, approvals, kwargs = direct_setup
    kwargs['processing_approval_check'] = lambda context: False
    with pytest.raises(OpafError, match='approval'):
        run_prototype_pipeline(job, docs, **kwargs)
    assert not service.calls


def test_changed_profile_prevents_cached_reuse(direct_setup):
    job, docs, client, service, current, approvals, kwargs = direct_setup
    run_prototype_pipeline(job, docs, **kwargs)
    count = len(service.calls)
    current['design_provider']['roles']['mapper']['model'] = 'changed-model'
    with pytest.raises(OpafError, match='changed|differs'):
        run_prototype_pipeline(job, docs, **kwargs)
    assert len(service.calls) == count


def test_direct_configuration_accepts_no_opaf_secrets(direct_setup, monkeypatch, tmp_path):
    from fox.prototype_job import load_prototype_profile, _configuration
    job, docs, client, service, current, approvals, kwargs = direct_setup
    envelope = {'target_profile': current, 'target_profile_sha256': canonical_hash(current)}
    path = tmp_path / 'profile.json'
    path.write_text(json.dumps(envelope))
    credential = tmp_path / 'converter.json'
    credential.write_text(json.dumps({'converter_token': 'offline-test-token-only'}))
    monkeypatch.setenv('FOX_PROTOTYPE_PROFILE_FILE', str(path))
    monkeypatch.setenv('FOX_CONVERTER_CREDENTIAL_FILE', str(credential))
    monkeypatch.setenv('FOX_RUN_ADAPTER', 'oci-genai')
    monkeypatch.setenv('FOX_CONVERSION_PROFILE', 'native-project-v1')
    monkeypatch.setenv('FOX_DIRECT_LOOPBACK_AUTHORITY', '1')
    monkeypatch.setenv('FOX_CONVERTER_URL', 'http://127.0.0.1:18261')
    monkeypatch.delenv('FOX_OPAF_CREDENTIAL_FILE', raising=False)
    monkeypatch.setattr('fox.prototype_job.OpafClient', lambda *a, **k: pytest.fail('OPAF must be absent'))
    monkeypatch.setattr('fox.oci_genai.OciGenAiClient', lambda t: client)
    assert load_prototype_profile(path) == envelope
    configured = _configuration(envelope['target_profile_sha256'])
    assert configured['gateway']._port == 18261
    from fox.app import conversion_configuration
    readiness = conversion_configuration()
    assert readiness['conversion_configured'] is True
    assert readiness['design_provider'] == 'oci_genai'
    assert configured['opaf_client'] is client
    assert configured['profile'] == roles(current)
    assert not service.calls


def test_direct_execution_destination_parity_and_no_widening(direct_setup):
    from fox.prototype_authority import execution_target as fox_target
    from forms2apex.prototype_authority_client import execution_target as converter_target
    from forms2apex.target_profile import validate_target_profile, TargetProfileError
    current = target()
    assert validate_target_profile(current) == current
    assert fox_target(current) == converter_target(current)
    assert 'opaf' not in fox_target(current)['tested_versions']
    for field, key in [('oci', 'database_id'), ('database', 'parsing_schema'), ('apex', 'workspace')]:
        changed = deepcopy(current)
        changed[field][key] = 'changed'
        with pytest.raises(TargetProfileError): validate_target_profile(changed)
    changed = deepcopy(current)
    changed['design_provider']['roles']['mapper']['model'] = 'configurable-model'
    assert validate_target_profile(changed) == changed
    assert fox_target(changed) == fox_target(current)


def test_direct_historical_evidence_binding_rejects_tampering(direct_setup):
    job, docs, client, service, current, approvals, kwargs = direct_setup
    run_prototype_pipeline(job, docs, **kwargs)
    record = json.loads(next((job / 'prototype-pipeline').glob('focus-*/mapper.json')).read_text())
    identity = {'job_id': job.name, 'source_hash': kwargs['expected_source_binding']}
    for field in ('request_id', 'model', 'prompt_sha256', 'model_version'):
        invocation = deepcopy(record['invocation'])
        invocation[field] = ''
        with pytest.raises(OpafError):
            validate_environment(record['model_environment'], current, 'mapper', identity, invocation)


def test_loopback_authority_is_explicit_exact_and_direct_only(direct_setup):
    from forms2apex.prototype_authority_client import PrototypeAuthorityClient
    from fox.prototype_authority import _origin
    settings = NS(bearer_token='injected-nonsecret-test-token')
    url, origin = 'http://127.0.0.1:8196/api/internal/prototype/authorize', 'http://127.0.0.1:8196'
    with pytest.raises(ValueError):
        PrototypeAuthorityClient(settings, authority_url=url, authority_origin=origin)
    client = PrototypeAuthorityClient(settings, authority_url=url, authority_origin=origin, allow_loopback_http=True)
    assert client.loopback and client.url.port == 8196
    assert _origin(origin, allow_loopback_http=True) == origin
    for invalid in ('http://localhost:8196', 'http://192.0.2.1:8196', 'http://127.0.0.1',
                    'http://127.0.0.1:8196/path', 'http://user@127.0.0.1:8196'):
        with pytest.raises(ValueError): _origin(invalid, allow_loopback_http=True)
        with pytest.raises(ValueError):
            PrototypeAuthorityClient(settings, authority_url=invalid + '/api/internal/prototype/authorize',
                authority_origin=invalid, allow_loopback_http=True)


def test_direct_bound_target_settings_and_deterministic_preflight(direct_setup, tmp_path):
    from datetime import datetime, timezone
    from forms2apex.runtime_preflight import bound_target_profile
    from forms2apex.target_profile import verify_deterministic_target_preflight, TargetProfileError, TRUST_BOUNDARY
    current = target()
    path = tmp_path / 'target.json'
    path.write_text(json.dumps(current))
    settings = NS(target_profile_path=path, apex_workspace=current['apex']['workspace'],
        apex_parsing_schema=current['database']['parsing_schema'], sqlcl_connection_name='F2A_APEX',
        generator_model='xai.grok-4.3', reviewer_model='xai.grok-4.3',
        apex_base_url=current['apex']['ords_origin'] + current['apex']['ords_base_path'])
    assert bound_target_profile(settings) == current
    now = datetime.now(timezone.utc)
    oci, db, apex = (current[k] for k in ('oci', 'database', 'apex'))
    observation = {'schema_version': 1, 'trust_boundary': TRUST_BOUNDARY,
        'profile_sha256': canonical_hash(current), 'observed_at_utc': now.isoformat(),
        'oci': {'database_id': oci['database_id'], 'database_compartment_id': oci['compartment_id'],
            'instance_id': oci['instance_id'], 'instance_compartment_id': oci['compartment_id'],
            'region': oci['region'], 'database_lifecycle_state': 'AVAILABLE', 'instance_lifecycle_state': 'RUNNING'},
        'database': {'db_name': db['db_name'], 'session_user': db['session_user'],
            'current_schema': db['parsing_schema']},
        'apex': {**apex, 'parsing_schema': db['parsing_schema'],
            'workspace_schema_mapping_count': 1, 'https_reachable': True},
        'sqlcl': current['sqlcl'], 'versions': current['tested_versions']}
    assert verify_deterministic_target_preflight(current, observation, now=now)['passed'] is True
    observation['database']['current_schema'] = 'UNAPPROVED'
    with pytest.raises(TargetProfileError):
        verify_deterministic_target_preflight(current, observation, now=now)
    settings.generator_model = 'different-model'
    with pytest.raises(TargetProfileError): bound_target_profile(settings)


def test_configured_gateway_forwards_loopback_opt_in(direct_setup):
    from forms2apex.prototype_startup import configured_prototype_gateway
    settings = NS(bearer_token='injected-nonsecret-test-token')
    env = {'FOX_PROTOTYPE_AUTHORITY_ENABLED': '1', 'FOX_DIRECT_LOOPBACK_AUTHORITY': '1',
        'FOX_PROTOTYPE_AUTHORITY_URL': 'http://127.0.0.1:8196/api/internal/prototype/authorize',
        'FOX_PROTOTYPE_AUTHORITY_ORIGIN': 'http://127.0.0.1:8196'}
    gateway = configured_prototype_gateway(settings, environ=env)
    assert gateway.authorize.loopback is True
    env['FOX_DIRECT_LOOPBACK_AUTHORITY'] = 'true'
    with pytest.raises(ValueError): configured_prototype_gateway(settings, environ=env)
    env.pop('FOX_DIRECT_LOOPBACK_AUTHORITY')
    with pytest.raises(ValueError): configured_prototype_gateway(settings, environ=env)


def test_direct_preview_converter_requires_exact_explicit_separate_port():
    from fox.opaf import ConverterClient
    assert ConverterClient('http://127.0.0.1:18261', 'offline-token', direct_preview_port=18261)._port == 18261
    for url, port in [('http://127.0.0.1:8091', 8091), ('http://localhost:18261', 18261),
                      ('http://192.0.2.1:18261', 18261), ('http://127.0.0.1:18261/', 18261),
                      ('http://127.0.0.1:18261', True), ('http://127.0.0.1:18262', 18261)]:
        with pytest.raises(OpafError): ConverterClient(url, 'offline-token', direct_preview_port=port)
    with pytest.raises(OpafError): ConverterClient('http://127.0.0.1:18261', 'offline-token')
    assert ConverterClient('http://127.0.0.1:8091', 'offline-token')._port == 8091


from test_prototype_job import queued, saved_row


def test_direct_durable_worker_connects_without_legacy_execution(queued, monkeypatch):
    from fox import prototype_job, worker
    root, job, db, snapshot, legacy_client, converter, configurations = queued
    current, service = target(), InjectedService()
    direct = OciGenAiClient(current, client=service, sdk=fake_sdk())
    snapshot['prototype']['target_profile_sha256'] = canonical_hash(current)
    (job / 'source-snapshot.json').write_text(json.dumps(snapshot))
    monkeypatch.setenv('FOX_RUN_ADAPTER', 'oci-genai')
    def configuration(approved_hash, **kwargs):
        assert approved_hash == canonical_hash(current)
        return {'profile': roles(current), 'opaf_client': direct,
            'target_profile_loader': lambda: deepcopy(current), 'converter_adapter': converter}
    monkeypatch.setattr(prototype_job, '_configuration', configuration)
    worker.process_one(db, root)
    assert saved_row(db, job)['state'] == 'GENERATED'
    assert service.calls and converter.calls
    assert legacy_client.calls == []
    result = json.loads((job / 'prototype-result.json').read_text())
    assert result['facts']['business_behavior_accepted'] is False
    assert result['facts']['technically_verified'] is False


def test_legacy_invocation_identity_validation_is_preserved():
    from fox.design_provider import valid_invocation_identity
    assert valid_invocation_identity({'room_id': 'legacy-room:123'})
    for value in ('bad/room', ' ', 'a' * 129, ''):
        assert not valid_invocation_identity({'room_id': value})
