"""Bundled workflow and injected registration tests; no live OPAF operations."""
from copy import deepcopy
import json

import pytest

from deployment import forms_clause_analysis_profiles as profiles
from deployment import forms_clause_analysis_registration as registration
from deployment import forms_understanding_profiles as base_profiles
from deployment import forms_understanding_profiles_v2, forms_understanding_profiles_v3, forms_understanding_profiles_v4
from deployment import forms_understanding_registration as base
from deployment.tests import test_forms_understanding_registration as safety


class Harness(safety.Harness):
    """Reuse the legacy synthetic transport, never an actual remote client."""
    def __init__(self):
        super().__init__()
        self.plan = registration.build_registration_plan(profiles.build_candidates(), self.profile)
        self.digest = registration.validate_plan(self.plan)
        self.executor = registration.RegistrationExecutor(client=self, store=self.store,
                                                         scope_check=lambda: deepcopy(self.scope))


def test_one_fresh_tool_free_graph_exact_existing_model_and_zero_temperature():
    originals = [module.build_candidates() for module in
                 (base_profiles, forms_understanding_profiles_v2, forms_understanding_profiles_v3, forms_understanding_profiles_v4)]
    result = profiles.build_candidates()
    assert result == profiles.build_candidates()
    assert set(result['candidates']) == {'baseline43'}
    assert result['profile_activation'] is False and result['model_invocation'] is False
    candidate = result['candidates']['baseline43']
    assert candidate['header']['name'] == 'JSNFOXClauseAnalysisV1Grok43'
    assert candidate['connection_name'] == 'JSN Forms Converter 4.3'
    graph = candidate['graph']
    base_profiles._check_graph(graph)
    llm = graph['nodes'][2]['data']['template']
    assert set(llm) == {'llmToUse', 'prompt', 'temperature'}
    assert llm['llmToUse']['value'] == candidate['connection_name']
    assert type(llm['temperature']['value']) is int and llm['temperature']['value'] == 0
    assert registration.MODELS == {'baseline43': 'xai.grok-4.3'}
    for key in ('header', 'graph'):
        assert candidate[key + '_sha256'] == base.canonical_hash(candidate[key])
    prompt = graph['nodes'][1]['data']['template']['prompt']['value']
    assert candidate['prompt_sha256'] == base_profiles._sha(prompt.encode('utf-8'))
    assert prompt.count('{{request}}') == 1
    assert prompt.index('WhereClause') < prompt.index('{{request}}')
    assert prompt.index('UNTRUSTED DATA') < prompt.index('{{request}}')
    for text in ('OrderByClause', '512', '1000', 'unresolved', 'production data', 'inert evidence', 'Generic refusal'):
        assert text in prompt
    identities = {row['id'] for old in originals for candidate in old['candidates'].values()
                  for category in ('nodes', 'edges') for row in candidate['graph'][category]}
    assert all(row['id'] not in identities for category in ('nodes', 'edges') for row in graph[category])
    assert originals == [module.build_candidates() for module in
                         (base_profiles, forms_understanding_profiles_v2, forms_understanding_profiles_v3, forms_understanding_profiles_v4)]


def test_registration_is_one_role_create_publish_only_and_preserves_originals():
    harness = Harness()
    assert harness.executor._roles() == ('baseline43',)
    inspected = harness.executor.inspect(harness.plan, expected_plan_sha256=harness.digest)
    assert inspected['roles'] == {'baseline43': None}
    assert inspected['remote_methods'] == ['GET']
    assert not harness.writes() and not harness.store.records
    created = harness.act()
    assert created['readback']['published'] is False
    assert len(harness.writes()) == 1
    published = harness.act(operation='publish')
    assert published['readback']['published'] is True
    assert len(harness.writes()) == 2
    assert harness.old == harness.originals
    assert published['scope'] == registration.PLAN_SCOPE
    assert published['model_invocation'] is False and published['profile_activation'] is False
    assert len(harness.store.records) == 4
    assert safety.SECRET not in json.dumps(harness.store.records)
    for operation in ('create', 'publish'):
        with pytest.raises(registration.RegistrationError, match='no automatic replay'):
            harness.act(operation=operation)
    assert len(harness.writes()) == 2


@pytest.mark.parametrize('role', ['candidate47', 'reviewer43', 'other'])
def test_executor_never_exposes_other_roles(role):
    harness = Harness()
    with pytest.raises(registration.RegistrationError): harness.act(role)
    assert not harness.calls and not harness.store.records


@pytest.mark.parametrize('tamper', ['prompt', 'activation', 'invocation', 'model', 'role', 'scope', 'bool-version', 'extra-key'])
def test_even_self_consistent_tampered_plan_rejected_before_any_remote_call(tamper):
    harness = Harness()
    plan = harness.plan
    candidate = plan['candidates']['candidates']['baseline43']
    if tamper == 'prompt': candidate['graph']['nodes'][1]['data']['template']['prompt']['value'] += ' changed'
    elif tamper == 'activation': plan['profile_activation'] = True
    elif tamper == 'invocation': plan['model_invocation'] = True
    elif tamper == 'model': candidate['connection_name'] = 'Other model'
    elif tamper == 'role': plan['candidates']['candidates']['reviewer43'] = deepcopy(candidate)
    elif tamper == 'scope': plan['scope'] = base.PLAN_SCOPE
    elif tamper == 'bool-version': plan['schema_version'] = True
    else: plan['extra'] = 'untrusted'
    candidate['header_sha256'] = base.canonical_hash(candidate['header'])
    candidate['graph_sha256'] = base.canonical_hash(candidate['graph'])
    harness.digest = base.canonical_hash(plan)
    with pytest.raises(registration.RegistrationError): harness.act()
    assert not harness.calls and not harness.store.records


@pytest.mark.parametrize('prompt', ['', 'no slot', '{{request}} {{request}}'])
def test_missing_or_ambiguous_prompt_slot_fails(tmp_path, monkeypatch, prompt):
    (tmp_path / 'prompts').mkdir()
    (tmp_path / 'prompts/forms-clause-analysis-v1.txt').write_text(prompt, encoding='utf-8')
    monkeypatch.setattr(profiles, 'ROOT', tmp_path)
    with pytest.raises(ValueError): profiles.build_candidates()


def test_changed_bundled_prompt_invalidates_reviewed_plan(tmp_path, monkeypatch):
    harness = Harness()
    (tmp_path / 'prompts').mkdir()
    raw = (profiles.ROOT / 'prompts/forms-clause-analysis-v1.txt').read_bytes()
    (tmp_path / 'prompts/forms-clause-analysis-v1.txt').write_bytes(raw + b'\nChanged trusted contract.\n')
    monkeypatch.setattr(profiles, 'ROOT', tmp_path)
    with pytest.raises(registration.RegistrationError): harness.act()
    assert not harness.calls and not harness.store.records


@pytest.mark.parametrize('connection', ['JSN Forms Converter 4.3', 'JSN Forms Reviewer'])
@pytest.mark.parametrize('mutation', ['model', 'compartment', 'endpoint', 'provider', 'active', 'auth', 'duplicate-saved'])
def test_relevant_original_and_clause_model_connections_are_guarded(connection, mutation):
    harness = Harness()
    saved = next(row for row in harness.saved if row['name'] == connection)
    detail = saved['connectionDetails']
    if mutation == 'model': detail['model_id'] = 'xai.grok-4.7'
    elif mutation == 'compartment': detail['compartment_id'] = 'different'
    elif mutation == 'endpoint': detail['service_endpoint'] = 'https://example.invalid'
    elif mutation == 'provider': saved['provider'] = 'other'
    elif mutation == 'active': saved['isActive'] = 'N'
    elif mutation == 'auth': detail['credentials_type'] = 'API_KEY'
    else: harness.saved.append(deepcopy(saved))
    with pytest.raises(registration.RegistrationError): harness.act()
    assert not harness.writes() and not harness.store.records


SAFETY_CASES = [
    ('test_inspect_get_only_no_journal_mutation', ()),
    *(('test_known_201_unique_exact_readback_only', (value,)) for value in ('text', 201)),
    *(('test_unknown_create_outcome_retains_intent_and_never_retries', (value,))
      for value in ('timeout', 'timeout-after', 'readback')),
    *(('test_changed_environment_blocks_before_write', (value,)) for value in
      ('scope', 'graph', 'old-unpublished', 'registered-missing', 'partial', 'partial-count', 'pin', 'origin')),
    ('test_existing_name_never_overwritten', ()),
    *(('test_journal_failure_never_replays_or_leaks', (value,)) for value in ('intent.json', 'outcome.json')),
    ('test_publish_requires_exact_recorded_unpublished_creation', ()),
    ('test_changed_or_already_published_create_cannot_be_published', ()),
    ('test_publish_unknown_retains_intent_and_cannot_retry', ()),
    ('test_original_graph_rechecked_after_write_no_false_outcome', ()),
    ('test_authorization_and_reviewed_hash_required', ()),
    ('test_scope_changed_during_preflight_blocks_write_and_retains_intent', ()),
    ('test_readback_boolean_is_not_equal_to_reviewed_numeric_zero', ()),
]


@pytest.mark.parametrize('name,args', SAFETY_CASES)
def test_inherited_no_replay_scope_and_environment_guards(name, args, monkeypatch):
    monkeypatch.setattr(safety, 'Harness', Harness)
    getattr(safety, name)(*args)
