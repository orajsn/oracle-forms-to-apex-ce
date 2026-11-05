"""Offline injected-client/store checks; no credentials, cloud, model or DB calls."""
from copy import deepcopy
import json
from pathlib import Path

import pytest

from deployment import forms_understanding_registration as registration


ROOT = Path(__file__).resolve().parents[2]
SECRET = 'SYNTHETIC-SECRET-DO-NOT-RETURN'
IDS = dict(zip(registration.ROLES, ('A' * 32, 'B' * 32, 'C' * 32)))


class Store:
    """Create-only test double, NOT a real durable journal implementation."""
    def __init__(self):
        self.records = {}
        self.fail = None

    def read(self, key):
        return deepcopy(self.records.get(key))

    def create(self, key, value):
        if self.fail and key.endswith(self.fail):
            raise OSError(SECRET)
        if key in self.records:
            raise FileExistsError(SECRET)
        self.records[key] = deepcopy(value)


class Harness:
    def __init__(self):
        self.profile = json.loads((ROOT / 'deployment/target-profile.jsn-project-v2.json').read_bytes())
        # Capability additions must not reject a current deployment profile.
        self.profile['scope']['capabilities'] = {'forms_understanding': False}
        self.plan = registration.build_registration_plan(registration.build_candidates(), self.profile)
        self.digest = registration.validate_plan(self.plan)
        self.origin = self.profile['opaf']['base_url'].removesuffix('/agentFactory')
        self.pin = self.profile['opaf']['certificate_sha256']
        self.store = Store()
        self.scope = deepcopy(registration.SCOPE)
        self.calls = []
        self.new = {}
        self.list_metadata = {}
        self.extra_items = []
        self.login = {'USER_ID': 'test-user', 'secret': SECRET}
        self.fail = None
        self.create201 = None
        self.after_write = None
        self.old = {}
        for role, expected in self.profile['opaf']['roles'].items():
            self.old[expected['workflow_id']] = {
                **json.loads((ROOT / f'deployment/project-opaf-{role}-v2.json').read_bytes()),
                'id': expected['workflow_id'], 'published': True}
        self.originals = deepcopy(self.old)
        self.saved = []
        for role, candidate in self.plan['candidates']['candidates'].items():
            self.saved.append({'name': candidate['connection_name'], 'provider': 'oci', 'isActive': 'Y',
                               'private': SECRET, 'connectionDetails': {
                                   'model_id': registration.MODELS[role], 'credentials_type': 'INSTANCE_PRINCIPAL',
                                   'compartment_id': registration.SCOPE['compartment_id'],
                                   'service_endpoint': registration.ENDPOINT, 'private': SECRET}})
        self.registered = [{'value': row['name']} for row in self.saved]
        self.executor = registration.RegistrationExecutor(client=self, store=self.store,
                                                         scope_check=lambda: deepcopy(self.scope))

    def writes(self):
        return [call for call in self.calls if call[0] != 'GET']

    def act(self, role='baseline43', operation='create', **kwargs):
        return self.executor.act(self.plan, role=role, operation=operation,
                                 expected_plan_sha256=self.digest, explicit_apply=True, **kwargs)

    def seed(self, role='baseline43', published=False):
        candidate = self.plan['candidates']['candidates'][role]
        self.new[IDS[role]] = {**deepcopy(candidate['header']), 'data': deepcopy(candidate['graph']),
                               'id': IDS[role], 'published': published}

    def _request(self, method, path, payload=None, **kwargs):
        self.calls.append((method, path, deepcopy(payload)))
        if method == 'GET':
            if self.fail == 'readback' and self.new:
                raise TimeoutError(SECRET)
            if path == '/v1/loginValidation':
                assert kwargs == {'login': True}
                return {'data': deepcopy(self.login)}
            if path == '/v1/getSavedLLMConfigurations':
                return {'data': {'savedConfiguration': deepcopy(self.saved)}}
            if path == '/v1/agentBuilderGetRegisteredLLMS':
                return {'data': deepcopy(self.registered)}
            if path == '/v1/agents':
                items = [{'id': key, 'name': value['name']} for key, value in {**self.old, **self.new}.items()]
                return {'data': {'items': items + deepcopy(self.extra_items), **self.list_metadata}}
            current = deepcopy({**self.old, **self.new}[path.removeprefix('/v1/agents/')])
            current.pop('category', None)  # Observed OPAF omits category on GET.
            return {'data': current}
        assert method in ('POST', 'PUT')
        role = next(role for role in registration.ROLES if
                    (payload.get('name') == self.plan['candidates']['candidates'][role]['header']['name']
                     if method == 'POST' else IDS[role] in path))
        operation = 'create' if method == 'POST' else 'publish'
        intent = self.store.read(self.executor._key(self.digest, role, operation, 'intent'))
        assert intent and intent['method'] == method and intent['path'] == path
        if self.fail == 'timeout':
            raise TimeoutError(SECRET)
        if method == 'POST':
            self.seed(role)
        else:
            self.new[IDS[role]]['published'] = True
        if self.after_write:
            self.after_write(self)
        if self.fail == 'timeout-after':
            raise TimeoutError(SECRET)
        if method == 'POST' and self.create201:
            if self.create201 == 'text':
                raise RuntimeError('OPAF request did not complete (HTTP 201). No automatic retry was attempted.')
            error = RuntimeError(SECRET)
            error.status_code = self.create201
            raise error
        return {'data': {'id': IDS[role]}} if method == 'POST' else {'data': {}}


def test_pure_plan_is_deterministic_and_secret_free():
    harness = Harness()
    original = deepcopy(harness.profile)
    harness.profile['password'] = SECRET
    harness.profile['opaf']['password'] = SECRET
    result = registration.build_registration_plan(registration.build_candidates(), harness.profile)
    assert result == harness.plan
    assert SECRET not in json.dumps(result)
    assert not harness.calls
    assert result['scope'] == 'fox-forms-understanding-registration-v1'
    assert result['existing_profile']['opaf']['roles'] == original['opaf']['roles']


def test_happy_three_distinct_roles_one_mutation_each_act():
    harness = Harness()
    for role in registration.ROLES:
        count = len(harness.writes())
        created = harness.act(role)
        assert len(harness.writes()) == count + 1
        assert created['readback']['workflow_id'] == IDS[role]
        assert not created['readback']['published']
        published = harness.act(role, 'publish')
        assert len(harness.writes()) == count + 2
        assert published['readback']['published']
        assert not published['model_invocation'] and not published['profile_activation']
    assert harness.old == harness.originals
    assert len({item['id'] for item in harness.new.values()}) == 3
    assert len(harness.store.records) == 12
    assert SECRET not in json.dumps(harness.store.records)


def test_inspect_get_only_no_journal_mutation():
    harness = Harness()
    harness.seed()
    result = harness.executor.inspect(harness.plan, expected_plan_sha256=harness.digest)
    assert result['remote_methods'] == ['GET']
    assert result['roles']['baseline43']['workflow_id'] == IDS['baseline43']
    assert not harness.store.records and not harness.writes()


@pytest.mark.parametrize('variant', ['text', 201])
def test_known_201_unique_exact_readback_only(variant):
    harness = Harness()
    harness.create201 = variant
    result = harness.act()
    assert result['response_classification'] == 'http_201_exact_readback'
    assert len(harness.writes()) == 1


@pytest.mark.parametrize('failure', ['timeout', 'timeout-after', 'readback'])
def test_unknown_create_outcome_retains_intent_and_never_retries(failure):
    harness = Harness()
    harness.fail = failure
    with pytest.raises(registration.RegistrationError) as caught:
        harness.act()
    assert SECRET not in str(caught.value)
    assert len(harness.writes()) == 1
    harness.fail = None
    with pytest.raises(registration.RegistrationError, match='already attempted'):
        harness.act()
    assert len(harness.writes()) == 1


@pytest.mark.parametrize('mutation', ['scope', 'graph', 'old-unpublished', 'model', 'compartment',
                                     'endpoint', 'provider', 'active', 'auth', 'duplicate-saved',
                                     'registered-missing', 'partial', 'partial-count', 'pin', 'origin'])
def test_changed_environment_blocks_before_write(mutation):
    harness = Harness()
    first = next(iter(harness.old.values()))
    detail = harness.saved[1]['connectionDetails']
    if mutation == 'scope':
        harness.scope['compartment_id'] = 'different'
    elif mutation == 'graph':
        first['data']['nodes'][0]['id'] = 'different'
    elif mutation == 'old-unpublished':
        first['published'] = False
    elif mutation == 'model':
        detail['model_id'] = 'xai.grok-4.3'
    elif mutation == 'compartment':
        detail['compartment_id'] = 'different'
    elif mutation == 'endpoint':
        detail['service_endpoint'] = 'https://example.invalid'
    elif mutation == 'provider':
        harness.saved[1]['provider'] = 'other'
    elif mutation == 'active':
        harness.saved[1]['isActive'] = 'N'
    elif mutation == 'auth':
        detail['credentials_type'] = 'API_KEY'
    elif mutation == 'duplicate-saved':
        harness.saved.append(deepcopy(harness.saved[1]))
    elif mutation == 'registered-missing':
        harness.registered.pop()
    elif mutation == 'partial':
        harness.list_metadata['hasMore'] = True
    elif mutation == 'partial-count':
        harness.list_metadata['totalCount'] = 99
    elif mutation == 'pin':
        harness.pin = '0' * 64
    elif mutation == 'origin':
        harness.origin = 'https://example.invalid'
    with pytest.raises(registration.RegistrationError):
        harness.act()
    assert not harness.writes() and not harness.store.records


def test_existing_name_never_overwritten():
    harness = Harness()
    harness.seed()
    with pytest.raises(registration.RegistrationError, match='already exists'):
        harness.act()
    assert not harness.writes()


@pytest.mark.parametrize('kind', ['duplicate-name', 'old-alias', 'new-alias', 'header', 'graph'])
def test_conflicting_readback_or_identity_blocks(kind):
    harness = Harness()
    harness.seed()
    item = harness.new[IDS['baseline43']]
    if kind == 'duplicate-name':
        harness.extra_items.append({'name': item['name'], 'id': 'D' * 32})
    elif kind == 'old-alias':
        harness.extra_items.append({'name': harness.plan['candidates']['candidates']['candidate47']['header']['name'],
                                    'id': next(iter(harness.old))})
    elif kind == 'new-alias':
        harness.extra_items.append({'name': harness.plan['candidates']['candidates']['candidate47']['header']['name'],
                                    'id': IDS['baseline43']})
    elif kind == 'header':
        item['icon'] = 'different'
    else:
        item['data']['nodes'][0]['id'] = 'different'
    with pytest.raises(registration.RegistrationError):
        harness.executor.inspect(harness.plan)
    assert not harness.writes()


@pytest.mark.parametrize('failure', ['intent.json', 'outcome.json'])
def test_journal_failure_never_replays_or_leaks(failure):
    harness = Harness()
    harness.store.fail = failure
    with pytest.raises(registration.RegistrationError) as caught:
        harness.act()
    assert SECRET not in str(caught.value)
    assert len(harness.writes()) == (0 if failure == 'intent.json' else 1)
    if failure == 'outcome.json':
        harness.store.fail = None
        with pytest.raises(registration.RegistrationError, match='already attempted'):
            harness.act()


def test_publish_requires_exact_recorded_unpublished_creation():
    harness = Harness()
    harness.seed()
    with pytest.raises(registration.RegistrationError, match='recorded unpublished'):
        harness.act(operation='publish')
    assert not harness.writes()


def test_changed_or_already_published_create_cannot_be_published():
    harness = Harness()
    harness.act()
    harness.new[IDS['baseline43']]['published'] = True
    with pytest.raises(registration.RegistrationError, match='recorded unpublished'):
        harness.act(operation='publish')
    assert len(harness.writes()) == 1


def test_publish_unknown_retains_intent_and_cannot_retry():
    harness = Harness()
    harness.act()
    harness.fail = 'timeout-after'
    with pytest.raises(registration.RegistrationError):
        harness.act(operation='publish')
    harness.fail = None
    with pytest.raises(registration.RegistrationError, match='already attempted'):
        harness.act(operation='publish')
    assert len(harness.writes()) == 2


def test_original_graph_rechecked_after_write_no_false_outcome():
    harness = Harness()
    harness.after_write = lambda h: next(iter(h.old.values()))['data']['nodes'].clear()
    with pytest.raises(registration.RegistrationError, match='Original workflow'):
        harness.act()
    assert len(harness.writes()) == 1
    assert not any(key.endswith('outcome.json') for key in harness.store.records)


@pytest.mark.parametrize('tamper', ['prompt', 'connection', 'header', 'scope', 'extra', 'boolean-number'])
def test_self_consistent_tampered_plan_cannot_authorize_write(tamper):
    harness = Harness()
    candidate = harness.plan['candidates']['candidates']['baseline43']
    if tamper == 'prompt':
        candidate['graph']['nodes'][1]['data']['template']['prompt']['value'] = SECRET
    elif tamper == 'connection':
        candidate['connection_name'] = 'another model'
    elif tamper == 'header':
        candidate['header']['name'] = 'another workflow'
    elif tamper == 'scope':
        harness.plan['oci']['region'] = 'other-region'
    elif tamper == 'boolean-number':
        candidate['graph']['nodes'][2]['data']['template']['temperature']['value'] = False
    else:
        harness.plan['extra'] = 'not allowed'
    candidate['header_sha256'] = registration.canonical_hash(candidate['header'])
    candidate['graph_sha256'] = registration.canonical_hash(candidate['graph'])
    harness.digest = registration.canonical_hash(harness.plan)
    with pytest.raises(registration.RegistrationError):
        harness.act()
    assert not harness.calls and not harness.store.records


@pytest.mark.parametrize('login', [{}, {'USER_ID': 'a', 'user_id': 'b'}, {'USER_ID': SECRET + '\n'}, {'USER_ID': 123}])
def test_invalid_login_blocks_create(login):
    harness = Harness()
    harness.login = login
    with pytest.raises(registration.RegistrationError, match='user identity'):
        harness.act()
    assert not harness.writes() and not harness.store.records


def test_authorization_and_reviewed_hash_required():
    harness = Harness()
    with pytest.raises(registration.RegistrationError, match='authorization'):
        harness.executor.act(harness.plan, role='baseline43', operation='create',
                             expected_plan_sha256=harness.digest)
    with pytest.raises(registration.RegistrationError, match='hash differs'):
        harness.executor.act(harness.plan, role='baseline43', operation='create',
                             expected_plan_sha256='0' * 64, explicit_apply=True)
    assert not harness.calls


def test_scope_changed_during_preflight_blocks_write_and_retains_intent():
    harness = Harness()
    observations = iter([deepcopy(registration.SCOPE), {**registration.SCOPE, 'region': 'other-region'}])
    harness.executor.scope_check = lambda: next(observations)
    with pytest.raises(registration.RegistrationError, match='immediately before write'):
        harness.act()
    assert not harness.writes()
    assert len(harness.store.records) == 1
    harness.executor.scope_check = lambda: deepcopy(registration.SCOPE)
    with pytest.raises(registration.RegistrationError, match='already attempted'):
        harness.act()


def test_readback_boolean_is_not_equal_to_reviewed_numeric_zero():
    harness = Harness()
    harness.seed()
    harness.new[IDS['baseline43']]['data']['nodes'][2]['data']['template']['temperature']['value'] = False
    with pytest.raises(registration.RegistrationError, match='readback header'):
        harness.executor.inspect(harness.plan)
