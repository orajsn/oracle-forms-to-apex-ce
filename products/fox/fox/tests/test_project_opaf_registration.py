"""Offline registration checks through the real OPAF HTTP serialization boundary.

Only the HTTPS connection is faked. The client, TLS-pin check, cookie/login code,
JSON serialization and GET-only environment observation execute normally. No
OCI, model, SSH, database, credential-file or external service is accessed.
"""
from copy import deepcopy
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from fox import opaf


ROOT = Path(__file__).resolve().parents[2]
DEPLOYMENT = ROOT / 'deployment'
SPEC = importlib.util.spec_from_file_location('project_opaf_registration', DEPLOYMENT / 'project_opaf_registration.py')
registration = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(registration)
SECRET = 'SYNTHETIC-SECRET-NEVER-PERSIST'
USER_ID = 'authenticated-user-id-123'
NEW_IDS = {'mapper': 'A' * 32, 'reviewer': 'B' * 32}


def inputs():
    return {
        'sources': {role: (DEPLOYMENT / f'project-opaf-{role}-v2.json').read_bytes()
                    for role in registration.ROLES},
        'legacy_target': json.loads((DEPLOYMENT / 'target-profile.jsn.json').read_bytes()),
        'candidate_contract': (DEPLOYMENT / 'project-opaf-v2-candidate-contract.json').read_bytes(),
    }


class MemoryStore:
    """Atomic/create-only test double; not a live durable-store implementation."""
    def __init__(self):
        self.records = {}
        self.events = []
        self.fail_suffix = None

    def read(self, key):
        return deepcopy(self.records.get(key))

    def create(self, key, value):
        if self.fail_suffix and key.endswith(self.fail_suffix):
            raise OSError(SECRET)
        if key in self.records:
            raise FileExistsError(key)
        self.records[key] = deepcopy(value)
        self.events.append(key)


class HTTPHarness:
    def __init__(self, monkeypatch):
        self.plan = registration.build_plan(**inputs())
        self.digest = registration.validate_plan(self.plan)
        self.store = MemoryStore()
        self.calls = []
        self.scope_calls = 0
        self.scope = deepcopy(registration.SCOPE)
        self.scope_hook = None
        self.after_write = None
        self.fail = None
        self.create_status = 200
        self.peer_cert = b'fake-peer-cert'
        self.extra_items = []
        self.list_metadata = {}
        self.new = {}
        # Retained real agent GET responses omit category. Keep submitted state
        # separately so optional-field tests can exercise a returned category.
        self.omit_category = True
        target = self.plan['legacy_target']
        self.old = {
            target['opaf']['roles'][role]['workflow_id']: {
                **json.loads((DEPLOYMENT / f'native-opaf-{role}.json').read_bytes()),
                'id': target['opaf']['roles'][role]['workflow_id'], 'published': True,
            }
            for role in registration.ROLES
        }
        self.original_old = deepcopy(self.old)
        self.version = {'VERSION_NUMBER': 264000, 'BUILD_ID': 1780444486153,
                        'VERSION_STRING': '26.4.0.0.0', 'secret': SECRET}
        self.login = {'data': {'USER_ID': USER_ID, 'secret': SECRET}}
        self.registered = [{'value': name} for name in registration.CONNECTIONS.values()]
        self.saved = [{
            'name': name, 'provider': 'oci', 'isActive': 'Y', 'private': SECRET,
            'connectionDetails': {
                'model_id': 'xai.grok-4.3', 'credentials_type': 'INSTANCE_PRINCIPAL',
                'compartment_id': registration.SCOPE['compartment_id'],
                'service_endpoint': 'https://inference.generativeai.us-ashburn-1.oci.oraclecloud.com',
                'api_key': SECRET,
            },
        } for name in registration.CONNECTIONS.values()]
        harness = self
        pin = target['opaf']['certificate_sha256']
        original_sha256 = hashlib.sha256

        def cert_hash(raw=b''):
            if raw == b'fake-peer-cert':
                return SimpleNamespace(hexdigest=lambda: pin)
            return original_sha256(raw)

        class FakeHTTPSConnection:
            def __init__(self, host, port, **kwargs):
                assert host == 'localhost' and port == 8080
                self.sock = self
                self.response = None

            def connect(self):
                pass

            def getpeercert(self, **kwargs):
                return harness.peer_cert

            def request(self, method, path, body, headers):
                assert path.startswith('/agentFactory/v1/')
                assert body is None or isinstance(body, str)
                route = path.removeprefix('/agentFactory')
                if route == '/v1/loginValidation':
                    assert headers['Authorization'].startswith('Basic ')
                else:
                    assert headers['Cookie'] == 'agent_factory_session=' + SECRET
                    assert headers['Origin'] == 'https://localhost:8080'
                call = {'method': method, 'path': route, 'body': body}
                harness.calls.append(call)
                self.response = harness.route(method, route, json.loads(body) if body is not None else None)

            def getresponse(self):
                status, value = self.response

                class Response:
                    def __init__(self):
                        self.status = status

                    def read(self, limit):
                        raw = value if isinstance(value, bytes) else json.dumps(value).encode()
                        return raw[:limit]

                    def getheaders(self):
                        return [('Set-Cookie', 'agent_factory_session=' + SECRET + '; HttpOnly')]

                return Response()

            def close(self):
                pass

        monkeypatch.setattr(opaf, 'hashlib', SimpleNamespace(sha256=cert_hash))
        monkeypatch.setattr(opaf.http.client, 'HTTPSConnection', FakeHTTPSConnection)
        self.client = opaf.OpafClient(target['opaf']['base_url'], 'synthetic-user', SECRET, pin)
        self.executor = registration.RegistrationExecutor(client=self.client, store=self.store, scope_check=self.check_scope)

    def check_scope(self):
        self.scope_calls += 1
        if self.scope_hook:
            self.scope_hook(self)
        return deepcopy(self.scope)

    def key(self, suffix):
        return self.digest + '-' + suffix + '.json'

    def writes(self):
        return [call for call in self.calls if call['method'] != 'GET']

    def seed(self, role, *, published=False):
        record = {**deepcopy(self.plan['roles'][role]['document']), 'id': NEW_IDS[role], 'published': published}
        self.new[NEW_IDS[role]] = record
        return record

    def apply(self):
        return self.executor.apply(self.plan, expected_plan_sha256=self.digest, explicit_apply=True)

    def route(self, method, path, body):
        if method == 'GET':
            if self.fail == 'read_after_create' and self.new:
                raise TimeoutError(SECRET)
            if path == '/v1/loginValidation':
                return 200, deepcopy(self.login)
            if path == '/v1/version':
                return 200, deepcopy(self.version)
            if path == '/v1/getSavedLLMConfigurations':
                return 200, {'data': {'savedConfiguration': deepcopy(self.saved)}}
            if path == '/v1/agentBuilderGetRegisteredLLMS':
                return 200, {'data': deepcopy(self.registered)}
            if path == '/v1/agents':
                items = [{'id': key, 'name': value['name']} for key, value in {**self.old, **self.new}.items()]
                return 200, {'data': {'items': items + deepcopy(self.extra_items), **self.list_metadata}}
            if path.startswith('/v1/agents/'):
                workflow_id = path.removeprefix('/v1/agents/')
                record = deepcopy({**self.old, **self.new}[workflow_id])
                if self.omit_category:
                    record.pop('category', None)
                return 200, {'data': record}
        if method == 'POST' and path == '/v1/agents':
            role = next(role for role in registration.ROLES if body['name'] == registration.NAMES[role])
            assert self.store.read(self.key('claim')) is not None
            intent = self.store.read(self.key(role + '-create-intent'))
            assert intent is not None and intent['method'] == 'POST' and intent['path'] == path
            assert body['user_id'] == USER_ID
            assert {key: value for key, value in body.items() if key != 'user_id'} == self.plan['roles'][role]['document']
            assert intent['document_sha256'] == registration.canonical_hash(self.plan['roles'][role]['document'])
            if self.fail == 'create_before':
                raise TimeoutError(SECRET)
            self.seed(role)
            if self.after_write:
                self.after_write(self, method, role)
            if self.fail == 'create_after':
                raise TimeoutError(SECRET)
            if self.fail == 'create_unknown':
                return 200, {'success': True, 'private': SECRET}
            if self.fail == 'create_invalid_json':
                return 200, b'not-json-' + SECRET.encode()
            if self.fail == 'create_wrong_id':
                return 200, {'data': {'id': 'C' * 32}}
            return self.create_status, {'data': {'id': NEW_IDS[role]}}
        if method == 'PUT' and path.endswith('/publish'):
            workflow_id = path.split('/')[3]
            role = next(role for role, value in NEW_IDS.items() if value == workflow_id)
            assert body == {}
            intent = self.store.read(self.key(role + '-publish-intent'))
            assert intent is not None and intent['method'] == 'PUT' and intent['path'] == path
            assert workflow_id not in self.old
            if self.fail == 'publish_before':
                raise TimeoutError(SECRET)
            self.new[workflow_id]['published'] = True
            if self.after_write:
                self.after_write(self, method, role)
            if self.fail == 'publish_after':
                raise TimeoutError(SECRET)
            return 200, {'success': True}
        pytest.fail(f'Unexpected external operation: {method} {path}')


@pytest.fixture
def case(monkeypatch):
    return HTTPHarness(monkeypatch)


def test_plan_is_pure_deterministic_and_preserves_exact_sources(monkeypatch):
    monkeypatch.setattr(opaf.OpafClient, '_request', lambda *_args, **_kwargs: pytest.fail('Planning must be pure'))
    source = inputs()
    before = deepcopy(source)
    plan = registration.build_plan(**source)
    assert registration.build_plan(**source) == plan and source == before
    assert registration.validate_plan(plan) == registration.canonical_hash(plan)
    assert plan['model_invocation'] is False and plan['profile_activation'] is False
    assert plan['legacy_target_sha256'] == registration.LEGACY_TARGET_SHA256
    for role in registration.ROLES:
        entry = plan['roles'][role]
        original = json.loads(source['sources'][role])
        assert base64.b64decode(entry['source_base64']) == source['sources'][role]
        assert entry['document']['data'] == original['data']
        assert entry['graph_sha256'] == registration.GRAPH_SHA256[role]
        assert entry['document']['name'] == registration.NAMES[role] != original['name']
        assert entry['source_header_sha256'] == registration.canonical_hash({k: original[k] for k in registration.HEADERS})


@pytest.mark.parametrize('change', [
    lambda value: value['sources'].__setitem__('mapper', value['sources']['mapper'] + b'\n'),
    lambda value: value['sources'].pop('reviewer'),
    lambda value: value.__setitem__('candidate_contract', value['candidate_contract'] + b'\n'),
    lambda value: value['legacy_target']['opaf'].__setitem__('build_id', 1),
])
def test_builder_rejects_source_contract_or_baseline_drift(change):
    value = inputs()
    change(value)
    with pytest.raises(registration.RegistrationError):
        registration.build_plan(**value)


@pytest.mark.parametrize('change', [
    lambda plan: plan['roles']['mapper']['document'].__setitem__('name', 'other'),
    lambda plan: plan['roles']['mapper']['document']['data']['nodes'].clear(),
    lambda plan: plan['roles']['mapper'].__setitem__('source_bytes_sha256', '0' * 64),
    lambda plan: plan['roles']['mapper'].__setitem__('source_base64', 'invalid base64'),
    lambda plan: plan['oci'].__setitem__('region', 'other'),
    lambda plan: plan['operations'].append('DELETE'),
    lambda plan: plan.__setitem__('profile_activation', True),
    lambda plan: plan.__setitem__('extra', 'unexpected'),
])
def test_even_rehashed_plan_tampering_fails_before_any_request(case, change):
    changed = deepcopy(case.plan)
    change(changed)
    with pytest.raises(registration.RegistrationError):
        case.executor.apply(changed, expected_plan_sha256=registration.canonical_hash(changed), explicit_apply=True)
    assert not case.calls and not case.store.records


@pytest.mark.parametrize('flag,digest', [(False, None), (1, None), (True, '0' * 64)])
def test_explicit_boolean_and_exact_reviewed_hash_required(case, flag, digest):
    with pytest.raises(registration.RegistrationError):
        case.executor.apply(case.plan, expected_plan_sha256=digest or case.digest, explicit_apply=flag)
    assert not case.calls and not case.store.records


def test_inspection_is_get_only_and_never_creates_journal_or_execution_claim(case):
    case.seed('mapper')
    observed = case.executor.inspect(case.plan, expected_plan_sha256=case.digest)
    assert observed['roles']['mapper']['workflow_id'] == NEW_IDS['mapper']
    assert observed['roles']['reviewer'] is None
    assert observed['execution_receipt'] is False and observed['automatic_replay_allowed'] is False
    assert not case.writes() and not case.store.records
    assert SECRET not in json.dumps(observed)


@pytest.mark.parametrize('status,expected', [
    (200, 'COMPLETE'), (201, 'COMPLETE_WITH_CREATE_READBACK_RECONCILIATION'),
])
def test_actual_http_serialization_registers_two_roles_and_preserves_legacy(case, status, expected):
    case.create_status = status
    receipt = case.apply()
    writes = case.writes()
    assert [(call['method'], call['path']) for call in writes] == [
        ('POST', '/v1/agents'), ('PUT', '/v1/agents/' + NEW_IDS['mapper'] + '/publish'),
        ('POST', '/v1/agents'), ('PUT', '/v1/agents/' + NEW_IDS['reviewer'] + '/publish'),
    ]
    assert all(isinstance(call['body'], str) for call in writes)
    assert receipt['status'] == expected and receipt['execution_receipt'] is True
    assert case.scope_calls == 6  # initial, immediately before each of four writes, final
    assert case.old == case.original_old
    assert {record['workflow_id'] for record in receipt['roles'].values()} == set(NEW_IDS.values())
    assert all(record['published'] for record in receipt['roles'].values())
    assert case.store.read(case.key('complete')) is not None
    assert SECRET not in json.dumps(case.store.records)
    assert USER_ID not in json.dumps(case.store.records)  # identity is hashed in intent
    assert not any('/run/' in call['path'] for call in case.calls)
    for role in registration.ROLES:
        outcome = case.store.read(case.key(role + '-create-outcome'))
        assert outcome['readback']['document']['data'] == case.plan['roles'][role]['document']['data']
        if status == 201:
            assert outcome['response_classification'] == 'http_201_acknowledged_exact_readback_required'


def test_successful_apply_is_never_replayed(case):
    case.apply()
    before = deepcopy(case.calls)
    with pytest.raises(registration.RegistrationError, match='already attempted'):
        case.apply()
    assert case.calls == before


def test_real_get_shape_without_category_succeeds_without_invented_readback_field(case):
    receipt = case.apply()
    for role in registration.ROLES:
        record = receipt['roles'][role]
        submitted = case.plan['roles'][role]
        assert record['category_observation'] == 'not_returned_submitted_only'
        assert 'category' not in record['document']
        assert record['header_fields_hashed'] == ['name', 'description', 'icon']
        assert record['header_sha256'] == submitted['readback_header_sha256']
        assert record['submitted_header_sha256'] == submitted['request_header_sha256']
        assert record['header_sha256'] != record['submitted_header_sha256']
        for phase in ('create', 'publish'):
            saved = case.store.read(case.key(role + '-' + phase + '-outcome'))['readback']
            assert saved['category_observation'] == 'not_returned_submitted_only'
            assert 'category' not in saved['document']
    for call in case.writes():
        if call['method'] == 'POST':
            payload = json.loads(call['body'])
            assert type(payload['category']) is int and payload['category'] == 1


def test_optional_returned_category_is_recorded_only_when_observed_and_matched(case):
    case.omit_category = False
    receipt = case.apply()
    for record in receipt['roles'].values():
        assert record['category_observation'] == 'returned_and_matched'
        assert type(record['document']['category']) is int and record['document']['category'] == 1


@pytest.mark.parametrize('conflict', ['duplicate', 'header', 'graph', 'preexisting_exact', 'partial_listing'])
def test_duplicate_conflict_existing_or_partial_listing_blocks_without_writes(case, conflict):
    if conflict == 'partial_listing':
        case.list_metadata['hasMore'] = True
    else:
        record = case.seed('mapper')
        if conflict == 'duplicate':
            case.extra_items.append({'name': registration.NAMES['mapper'], 'id': 'C' * 32})
        elif conflict == 'header':
            record['description'] = 'changed'
        elif conflict == 'graph':
            record['data']['edges'].clear()
    with pytest.raises(registration.RegistrationError):
        case.apply()
    assert not case.writes() and not case.store.records


@pytest.mark.parametrize('stage', ['existing', 'after_create'])
@pytest.mark.parametrize('change', [
    lambda record: record.update(category=True),
    lambda record: record.update(category=1.0),
    lambda record: next(node for node in record['data']['nodes']
                       if node['data']['type'] == 'llmStep')['data']['template']['temperature'].update(value=False),
])
def test_canonical_readback_rejects_boolean_integer_float_equivalence(case, stage, change):
    case.omit_category = False
    if stage == 'existing':
        change(case.seed('mapper'))
        with pytest.raises(registration.RegistrationError):
            case.executor.inspect(case.plan)
        assert not case.writes() and not case.store.records
    else:
        def mutate(value, method, role):
            if method == 'POST':
                change(value.new[NEW_IDS[role]])
        case.after_write = mutate
        with pytest.raises(registration.RegistrationError, match='incomplete'):
            case.apply()
        assert [call['method'] for call in case.writes()] == ['POST']
        assert case.store.read(case.key('mapper-publish-intent')) is None


@pytest.mark.parametrize('change', [
    lambda case: case.version.update(VERSION_NUMBER=264001),
    lambda case: case.version.update(BUILD_ID='1780444486153'),
    lambda case: case.version.update(VERSION_STRING='other'),
    lambda case: case.saved[0]['connectionDetails'].update(model_id='other'),
    lambda case: case.saved[0]['connectionDetails'].update(credentials_type='API_KEY'),
    lambda case: case.saved[0]['connectionDetails'].update(compartment_id='other'),
    lambda case: case.saved[0]['connectionDetails'].update(service_endpoint='https://other.invalid'),
    lambda case: case.saved[0].update(provider='other'),
    lambda case: case.saved[0].update(isActive='N'),
    lambda case: case.saved.append(deepcopy(case.saved[0])),
    lambda case: case.registered.clear(),
    lambda case: case.registered.append(deepcopy(case.registered[0])),
    lambda case: next(iter(case.old.values()))['data']['edges'].clear(),
    lambda case: next(iter(case.old.values())).update(published=False),
    lambda case: case.scope.update(region='other'),
    lambda case: case.scope.update(instance_id='other'),
    lambda case: case.scope.update(compartment_id='other'),
    lambda case: setattr(case.client, 'pin', '0' * 64),
    lambda case: setattr(case, 'peer_cert', b'changed-certificate'),
    lambda case: case.login['data'].pop('USER_ID'),
])
def test_environment_profile_identity_and_model_drift_fail_closed(case, change):
    change(case)
    with pytest.raises((registration.RegistrationError, opaf.OpafError)) as error:
        case.apply()
    assert SECRET not in str(error.value)
    assert not case.writes() and not case.store.records


@pytest.mark.parametrize('guard_number,write_count', [(2, 0), (3, 1), (4, 2), (5, 3), (6, 4)])
def test_fresh_scope_guard_precedes_every_write_and_final_completion(case, guard_number, write_count):
    def drift(value):
        if value.scope_calls == guard_number:
            value.scope['instance_id'] = 'changed'
    case.scope_hook = drift
    with pytest.raises(registration.RegistrationError):
        case.apply()
    assert len(case.writes()) == write_count
    assert case.store.read(case.key('complete')) is None
    assert case.store.read(case.key('attention')) is not None


def test_legacy_graph_is_revalidated_after_create_and_before_publish(case):
    def drift(value, method, role):
        if method == 'POST':
            next(iter(value.old.values()))['data']['edges'].clear()
    case.after_write = drift
    with pytest.raises(registration.RegistrationError):
        case.apply()
    assert [call['method'] for call in case.writes()] == ['POST']
    assert case.store.read(case.key('mapper-publish-intent')) is None


@pytest.mark.parametrize('failure,expected_writes,existing,published', [
    ('create_before', 1, False, False), ('create_after', 1, True, False),
    ('read_after_create', 1, True, False), ('create_unknown', 1, True, False),
    ('create_invalid_json', 1, True, False), ('create_wrong_id', 1, True, False),
    ('publish_before', 2, True, False), ('publish_after', 2, True, True),
])
def test_partial_or_unknown_create_publish_keeps_intent_and_never_replays(case, failure, expected_writes, existing, published):
    case.fail = failure
    with pytest.raises(registration.RegistrationError, match='incomplete') as error:
        case.apply()
    assert SECRET not in str(error.value)
    assert len(case.writes()) == expected_writes
    assert (NEW_IDS['mapper'] in case.new) is existing
    if existing:
        assert case.new[NEW_IDS['mapper']]['published'] is published
    assert case.store.read(case.key('mapper-create-intent')) is not None
    assert case.store.read(case.key('complete')) is None
    assert case.store.read(case.key('attention')) is not None
    case.fail = None
    before = deepcopy(case.calls)
    with pytest.raises(registration.RegistrationError, match='already attempted'):
        case.apply()
    assert case.calls == before
    observed = case.executor.inspect(case.plan)
    assert observed['journal']['attention'] is True
    assert len(case.writes()) == expected_writes
    assert SECRET not in json.dumps(case.store.records)


@pytest.mark.parametrize('suffix,expected', [('mapper-create-intent.json', 0), ('mapper-publish-intent.json', 1)])
def test_failed_durable_intent_blocks_corresponding_write(case, suffix, expected):
    case.store.fail_suffix = suffix
    with pytest.raises(registration.RegistrationError):
        case.apply()
    assert len(case.writes()) == expected
    assert case.store.read(case.key('complete')) is None


def test_reconciliation_is_explicit_get_only_and_not_a_clean_execution_receipt(case):
    for role in registration.ROLES:
        case.seed(role, published=True)
    with pytest.raises(registration.RegistrationError, match='Explicit'):
        case.executor.reconcile_completion(case.plan, expected_plan_sha256=case.digest)
    assert not case.calls
    receipt = case.executor.reconcile_completion(case.plan, expected_plan_sha256=case.digest, explicit_reconcile=True)
    assert receipt['execution_receipt'] is False
    assert receipt['prior_process_exit'] == 'not_inferred'
    assert receipt['prior_claim_present'] is False
    assert receipt['status'] == 'CONFIRMED_EXISTING_PUBLISHED_OBJECTS'
    assert not case.writes() and case.store.read(case.key('complete')) is None
    assert case.store.read(case.key('reconciled')) is not None
    with pytest.raises(registration.RegistrationError, match='already attempted'):
        case.apply()


def test_reconciliation_refuses_incomplete_objects_without_mutation(case):
    case.seed('mapper', published=False)
    with pytest.raises(registration.RegistrationError, match='remains incomplete'):
        case.executor.reconcile_completion(case.plan, expected_plan_sha256=case.digest, explicit_reconcile=True)
    assert not case.writes() and not case.store.records


def incomplete(case, failure):
    case.fail = failure
    with pytest.raises(registration.RegistrationError, match='incomplete'):
        case.apply()
    case.fail = None


def continue_once(case):
    return case.executor.continue_unattempted(
        case.plan, expected_plan_sha256=case.digest, explicit_continue=True)


@pytest.mark.parametrize('failure', ['create_after', 'read_after_create', 'create_unknown'])
def test_explicit_continuation_confirms_created_mapper_and_only_writes_unattempted_phases(case, failure):
    incomplete(case, failure)
    assert [call['method'] for call in case.writes()] == ['POST']
    assert case.store.read(case.key('mapper-create-outcome')) is None
    receipt = continue_once(case)
    assert [(call['method'], call['path']) for call in case.writes()] == [
        ('POST', '/v1/agents'), ('PUT', '/v1/agents/' + NEW_IDS['mapper'] + '/publish'),
        ('POST', '/v1/agents'), ('PUT', '/v1/agents/' + NEW_IDS['reviewer'] + '/publish'),
    ]
    assert receipt['status'] == 'COMPLETE_WITH_EXPLICIT_CONTINUATION'
    assert receipt['scope'] == 'fox-project-opaf-registration-continuation-v1'
    assert receipt['execution_receipt'] is False and receipt['prior_process_exit'] == 'not_inferred'
    assert case.store.read(case.key('mapper-create-outcome')) is None  # never backfill a clean response
    reconciled = case.store.read(case.key('mapper-create-reconciled'))
    assert reconciled['execution_receipt'] is False
    assert reconciled['readback']['workflow_id'] == NEW_IDS['mapper']
    assert case.store.read(case.key('continuation-claim')) is not None
    assert case.old == case.original_old
    assert SECRET not in json.dumps(case.store.records)


def test_explicit_continuation_after_applied_publish_timeout_skips_attempted_put(case):
    incomplete(case, 'publish_after')
    assert case.store.read(case.key('mapper-publish-outcome')) is None
    before = deepcopy(case.writes())
    receipt = continue_once(case)
    added = case.writes()[len(before):]
    assert [(call['method'], call['path']) for call in added] == [
        ('POST', '/v1/agents'), ('PUT', '/v1/agents/' + NEW_IDS['reviewer'] + '/publish'),
    ]
    assert len([call for call in case.writes() if call['path'].endswith(NEW_IDS['mapper'] + '/publish')]) == 1
    assert case.store.read(case.key('mapper-publish-outcome')) is None
    assert case.store.read(case.key('mapper-publish-reconciled'))['execution_receipt'] is False
    assert receipt['execution_receipt'] is False and receipt['prior_process_exit'] == 'not_inferred'


@pytest.mark.parametrize('failure', ['create_before', 'publish_before'])
def test_continuation_never_replays_absent_attempted_create_or_unpublished_attempted_put(case, failure):
    incomplete(case, failure)
    before = deepcopy(case.writes())
    with pytest.raises(registration.RegistrationError, match='incomplete'):
        continue_once(case)
    assert case.writes() == before
    assert case.store.read(case.key('complete')) is None
    assert case.store.read(case.key('continuation-attention')) is not None
    calls_before_second = deepcopy(case.calls)
    with pytest.raises(registration.RegistrationError, match='already continued'):
        continue_once(case)
    assert case.calls == calls_before_second


@pytest.mark.parametrize('flag', [False, None, 1])
def test_continuation_requires_literal_explicit_boolean_before_get(case, flag):
    incomplete(case, 'create_after')
    before = deepcopy(case.calls)
    with pytest.raises(registration.RegistrationError, match='Explicit'):
        case.executor.continue_unattempted(case.plan, expected_plan_sha256=case.digest, explicit_continue=flag)
    assert case.calls == before


@pytest.mark.parametrize('state', ['unattempted', 'attention_missing', 'complete', 'already_continued'])
def test_continuation_cannot_race_apply_or_repeat_complete_or_prior_continuation(case, state):
    if state == 'complete':
        case.apply()
    elif state != 'unattempted':
        incomplete(case, 'create_after')
        if state == 'attention_missing':
            case.store.records.pop(case.key('attention'))
        else:
            continue_once(case)
    before = deepcopy(case.calls)
    with pytest.raises(registration.RegistrationError):
        continue_once(case)
    assert case.calls == before


@pytest.mark.parametrize('prior_identity', ['create_outcome', 'publish_intent'])
def test_continuation_rejects_replaced_object_identity_from_durable_prior_record(case, prior_identity):
    incomplete(case, 'publish_before')
    replacement = case.new.pop(NEW_IDS['mapper'])
    replacement['id'] = 'C' * 32
    case.new[replacement['id']] = replacement
    if prior_identity == 'publish_intent':
        # Simulate missing earlier outcome to prove the durable publish ID also
        # independently prevents adopting a replacement exact-name graph.
        case.store.records.pop(case.key('mapper-create-outcome'))
    before = deepcopy(case.writes())
    with pytest.raises(registration.RegistrationError):
        continue_once(case)
    assert case.writes() == before
    assert case.store.read(case.key('complete')) is None


@pytest.mark.parametrize('guard_offset,added_writes', [(1, 0), (2, 0), (3, 0), (4, 1), (5, 2), (6, 3)])
def test_continuation_checks_fresh_scope_before_each_new_write_and_final_receipt(case, guard_offset, added_writes):
    incomplete(case, 'create_after')
    previous_guard_count = case.scope_calls
    prior_writes = len(case.writes())

    def drift(value):
        if value.scope_calls == previous_guard_count + guard_offset:
            value.scope['compartment_id'] = 'changed'

    case.scope_hook = drift
    with pytest.raises(registration.RegistrationError):
        continue_once(case)
    assert len(case.writes()) - prior_writes == added_writes
    assert case.store.read(case.key('complete')) is None


@pytest.mark.skipif(os.name == 'posix', reason='Non-POSIX fail-closed contract')
def test_file_store_refuses_platform_without_posix_private_file_guarantees(tmp_path):
    with pytest.raises(registration.RegistrationError, match='POSIX'):
        registration.FileStore(tmp_path)


@pytest.mark.skipif(os.name != 'posix', reason='Requires actual POSIX filesystem semantics')
def test_file_store_private_create_only_and_file_directory_fsync(tmp_path, monkeypatch):
    base = tmp_path / 'private'
    base.mkdir(mode=0o700)
    store = registration.FileStore(base)
    calls = []
    original = os.fsync
    monkeypatch.setattr(registration.os, 'fsync', lambda fd: (calls.append(fd), original(fd))[-1])
    try:
        store.create('entry.json', {'safe': True})
        assert store.read('entry.json') == {'safe': True}
        assert len(calls) == 2 and calls[1] == store.fd
        assert (base / 'entry.json').stat().st_mode & 0o777 == 0o600
        with pytest.raises(FileExistsError):
            store.create('entry.json', {'changed': True})
        with pytest.raises(registration.RegistrationError, match='key'):
            store.create('../other.json', {})
        (base / 'entry.json').chmod(0o644)
        with pytest.raises(registration.RegistrationError, match='permissions'):
            store.read('entry.json')
    finally:
        store.close()


@pytest.mark.skipif(os.name != 'posix', reason='Requires actual POSIX filesystem semantics')
def test_file_store_rejects_symlink_directory_or_record_and_insecure_mode(tmp_path):
    base = tmp_path / 'private'
    base.mkdir(mode=0o700)
    link = tmp_path / 'link'
    link.symlink_to(base, target_is_directory=True)
    with pytest.raises(registration.RegistrationError, match='symlink'):
        registration.FileStore(link)
    store = registration.FileStore(base)
    try:
        store.create('actual.json', {'safe': True})
        (base / 'link.json').symlink_to(base / 'actual.json')
        with pytest.raises(OSError):
            store.read('link.json')
        base.chmod(0o755)
        with pytest.raises(registration.RegistrationError, match='permissions'):
            store.read('actual.json')
    finally:
        store.close()
