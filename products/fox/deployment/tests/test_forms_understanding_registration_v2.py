"""Offline v2 plan/executor acceptance and the shared v1 safety regression suite."""
from copy import deepcopy
import inspect
import json
from pathlib import Path

import pytest

from deployment import forms_understanding_profiles as profiles_v1
from deployment import forms_understanding_profiles_v2 as profiles_v2
from deployment import forms_understanding_registration as v1
from deployment import forms_understanding_registration_v2 as v2
from deployment.tests import test_forms_understanding_registration as safety


ROOT = Path(__file__).resolve().parents[1]
V1_PLAN_SHA256 = 'd0655abb6be7b2e6741ca7c4cb1182fbd4088c2ca87b60915def79cfe1ee15c8'


class Harness(safety.Harness):
    """Use the same injected client/journal double with the trusted v2 adapter."""
    def __init__(self):
        super().__init__()
        self.plan = v2.build_registration_plan(v2.build_candidates(), self.profile)
        self.digest = v2.validate_plan(self.plan)
        self.executor = v2.RegistrationExecutor(client=self, store=self.store,
                                               scope_check=lambda: deepcopy(self.scope))


def test_v1_default_plan_digest_and_result_labels_are_preserved():
    harness = safety.Harness()
    assert harness.digest == V1_PLAN_SHA256
    assert v1.canonical_hash(profiles_v1.build_candidates()) == '6cdc8f21e43ff27a6f7e02e1a424e9c8981d74efc9b01ba1dafb9d2503b68b55'
    assert harness.executor._receipt_scope() == v1.PLAN_SCOPE
    assert harness.executor._validated_plan(harness.plan, harness.digest) == harness.digest
    assert harness.executor.inspect(harness.plan)['scope'] == v1.PLAN_SCOPE + '-inspection'
    result = harness.act()
    assert result['scope'] == v1.PLAN_SCOPE
    assert all(record['scope'] == v1.PLAN_SCOPE for record in harness.store.records.values())
    assert v1.validate_plan(harness.plan) == V1_PLAN_SHA256


def test_v2_pure_plan_is_deterministic_inactive_and_secret_free():
    harness = Harness()
    harness.profile['password'] = safety.SECRET
    harness.profile['opaf']['password'] = safety.SECRET
    plan = v2.build_registration_plan(v2.build_candidates(), harness.profile)
    assert plan == harness.plan
    assert set(plan) == set(safety.Harness().plan)
    assert type(plan['schema_version']) is int and plan['schema_version'] == 1
    assert plan['scope'] == 'fox-forms-understanding-registration-v2'
    assert plan['candidates']['scope'] == 'fox-forms-understanding-candidates-v2'
    assert plan['model_invocation'] is False and plan['profile_activation'] is False
    assert plan['existing_profile'] == safety.Harness().plan['existing_profile']
    assert safety.SECRET not in json.dumps(plan)
    assert v2.validate_plan(plan, harness.digest) == harness.digest
    assert not harness.calls and not harness.store.records


def test_v2_three_roles_create_publish_and_scoped_receipts_are_additive():
    harness = Harness()
    # Already registered v1 graphs must not prevent additive v2 registration.
    old_plan = safety.Harness().plan
    retained_v1 = {}
    for index, (role, candidate) in enumerate(old_plan['candidates']['candidates'].items()):
        identity = str(index + 4) * 32
        retained_v1[identity] = {**deepcopy(candidate['header']), 'data': deepcopy(candidate['graph']),
                                 'id': identity, 'published': True}
    harness.new.update(deepcopy(retained_v1))
    for role in v2.ROLES:
        before = len(harness.writes())
        created = harness.act(role)
        assert created['scope'] == v2.PLAN_SCOPE
        assert len(harness.writes()) == before + 1
        assert created['readback']['workflow_id'] == safety.IDS[role]
        assert created['readback']['published'] is False
        published = harness.act(role, 'publish')
        assert published['scope'] == v2.PLAN_SCOPE
        assert len(harness.writes()) == before + 2
        assert published['readback']['published'] is True
        assert published['model_invocation'] is False and published['profile_activation'] is False
    assert harness.old == harness.originals
    assert {identity: harness.new[identity] for identity in retained_v1} == retained_v1
    assert len(harness.store.records) == 12
    assert all(record['scope'] == v2.PLAN_SCOPE for record in harness.store.records.values())
    result = harness.executor.inspect(harness.plan, expected_plan_sha256=harness.digest)
    assert result['scope'] == v2.PLAN_SCOPE + '-inspection'
    assert result['remote_methods'] == ['GET']
    assert safety.SECRET not in json.dumps(harness.store.records)


def test_adapter_only_overrides_validation_and_receipt_hooks():
    assert v2.RegistrationExecutor.__bases__ == (v1.RegistrationExecutor,)
    own_methods = {name for name, value in vars(v2.RegistrationExecutor).items() if callable(value)}
    assert own_methods == {'_validated_plan', '_receipt_scope'}
    assert v2.RegistrationExecutor.act is v1.RegistrationExecutor.act
    assert v2.RegistrationExecutor.inspect is v1.RegistrationExecutor.inspect
    assert v2.RegistrationExecutor._guard is v1.RegistrationExecutor._guard
    assert v2.RegistrationExecutor._candidates is v1.RegistrationExecutor._candidates
    assert inspect.signature(v2.build_registration_plan) == inspect.signature(v1.build_registration_plan)
    assert inspect.signature(v2.validate_plan) == inspect.signature(v1.validate_plan)


@pytest.mark.parametrize('executor_version,plan_version', [(1, 2), (2, 1)])
@pytest.mark.parametrize('operation', ['inspect', 'create'])
def test_cross_version_plan_rejected_before_remote_calls(executor_version, plan_version, operation):
    harness = safety.Harness() if executor_version == 1 else Harness()
    other = safety.Harness() if plan_version == 1 else Harness()
    with pytest.raises(v2.RegistrationError):
        if operation == 'inspect':
            harness.executor.inspect(other.plan, expected_plan_sha256=other.digest)
        else:
            harness.executor.act(other.plan, role='baseline43', operation='create',
                                 expected_plan_sha256=other.digest, explicit_apply=True)
    assert not harness.calls and not harness.store.records


@pytest.mark.parametrize('tamper', ['old-prompt', 'new-prompt', 'old-name', 'old-node-id', 'version',
                                  'candidate-version', 'candidate-scope', 'plan-scope', 'activation',
                                  'invocation', 'extra-candidate', 'extra-plan', 'false-temperature'])
def test_self_consistent_v2_tamper_is_rejected_before_remote_calls(tamper):
    harness = Harness()
    plan = harness.plan
    candidate = plan['candidates']['candidates']['baseline43']
    if tamper in ('old-prompt', 'new-prompt'):
        prompt = profiles_v1.build_candidates()['candidates']['baseline43']['graph']['nodes'][1]['data']['template']['prompt']['value']
        if tamper == 'new-prompt':
            prompt += '\nUnreviewed prompt change.'
        candidate['graph']['nodes'][1]['data']['template']['prompt']['value'] = prompt
    elif tamper == 'old-name':
        candidate['header']['name'] = 'JSNFOXG2Understandingv1Baseline43'
    elif tamper == 'old-node-id':
        candidate['graph']['nodes'][0]['id'] = 'g2-baseline43-input'
    elif tamper == 'version':
        plan['schema_version'] = 2
    elif tamper == 'candidate-version':
        plan['candidates']['schema_version'] = 2
    elif tamper == 'candidate-scope':
        plan['candidates']['scope'] = 'fox-forms-understanding-candidates-v1'
    elif tamper == 'plan-scope':
        plan['scope'] = v1.PLAN_SCOPE
    elif tamper == 'activation':
        plan['profile_activation'] = True
    elif tamper == 'invocation':
        plan['model_invocation'] = True
    elif tamper == 'extra-candidate':
        plan['candidates']['candidates']['new-role'] = deepcopy(candidate)
    elif tamper == 'extra-plan':
        plan['resource_builder'] = 'arbitrary.module.function'
    else:
        candidate['graph']['nodes'][2]['data']['template']['temperature']['value'] = False
    candidate['header_sha256'] = v2.canonical_hash(candidate['header'])
    candidate['graph_sha256'] = v2.canonical_hash(candidate['graph'])
    prompt = candidate['graph']['nodes'][1]['data']['template']['prompt']['value']
    candidate['prompt_sha256'] = profiles_v1._sha(prompt.encode('utf-8'))
    harness.digest = v2.canonical_hash(plan)
    with pytest.raises(v2.RegistrationError):
        harness.act()
    assert not harness.calls and not harness.store.records


@pytest.mark.parametrize('kind', ['understanding', 'review'])
def test_valid_but_changed_resource_invalidates_reviewed_plan(tmp_path, monkeypatch, kind):
    harness = Harness()
    prompt_dir = tmp_path / 'prompts'
    prompt_dir.mkdir()
    for name in ('forms-understanding-v2.txt', 'forms-understanding-review-v2.txt'):
        text = (ROOT / 'prompts' / name).read_text(encoding='utf-8')
        if ('review' in name) == (kind == 'review'):
            text += '\nNew local contract wording.'
        (prompt_dir / name).write_text(text, encoding='utf-8')
    monkeypatch.setattr(profiles_v2, '_ROOT', tmp_path)
    with pytest.raises(v2.RegistrationError, match='freshly rebuilt'):
        harness.act()
    assert not harness.calls and not harness.store.records


@pytest.mark.parametrize('kwargs', [{'builder': profiles_v1.build_candidates}, {'version': 1},
                                  {'scope': v1.PLAN_SCOPE}, {'prompt': '{{request}}'}])
def test_plan_builder_rejects_unrecognized_resource_selection(kwargs):
    harness = Harness()
    with pytest.raises(TypeError):
        v2.build_registration_plan(v2.build_candidates(), harness.profile, **kwargs)
    assert not harness.calls


@pytest.mark.parametrize('role,operation,apply', [('other', 'create', True), ('baseline43', 'overwrite', True),
                                              ('baseline43', 'create', 1), ('baseline43', 'create', 'true')])
def test_executor_rejects_invalid_operation_or_non_boolean_authorization(role, operation, apply):
    harness = Harness()
    with pytest.raises(v2.RegistrationError):
        harness.executor.act(harness.plan, role=role, operation=operation,
                             expected_plan_sha256=harness.digest, explicit_apply=apply)
    assert not harness.calls and not harness.store.records


@pytest.mark.parametrize('digest', ['', '0' * 64, 1, True, []])
def test_reviewed_hash_must_exactly_match(digest):
    harness = Harness()
    with pytest.raises(v2.RegistrationError, match='hash differs'):
        harness.executor.act(harness.plan, role='baseline43', operation='create',
                             expected_plan_sha256=digest, explicit_apply=True)
    assert not harness.calls and not harness.store.records


# Reuse the exact existing safety assertions against the subclass, rather than
# copying the executor or maintaining a subtly weaker v2-specific guard suite.
SAFETY_CASES = [
    ('test_happy_three_distinct_roles_one_mutation_each_act', ()),
    ('test_inspect_get_only_no_journal_mutation', ()),
    *(('test_known_201_unique_exact_readback_only', (value,)) for value in ('text', 201)),
    *(('test_unknown_create_outcome_retains_intent_and_never_retries', (value,))
      for value in ('timeout', 'timeout-after', 'readback')),
    *(('test_changed_environment_blocks_before_write', (value,))
      for value in ('scope', 'graph', 'old-unpublished', 'model', 'compartment', 'endpoint',
                    'provider', 'active', 'auth', 'duplicate-saved', 'registered-missing',
                    'partial', 'partial-count', 'pin', 'origin')),
    ('test_existing_name_never_overwritten', ()),
    *(('test_conflicting_readback_or_identity_blocks', (value,))
      for value in ('duplicate-name', 'old-alias', 'new-alias', 'header', 'graph')),
    *(('test_journal_failure_never_replays_or_leaks', (value,)) for value in ('intent.json', 'outcome.json')),
    ('test_publish_requires_exact_recorded_unpublished_creation', ()),
    ('test_changed_or_already_published_create_cannot_be_published', ()),
    ('test_publish_unknown_retains_intent_and_cannot_retry', ()),
    ('test_original_graph_rechecked_after_write_no_false_outcome', ()),
    *(('test_self_consistent_tampered_plan_cannot_authorize_write', (value,))
      for value in ('prompt', 'connection', 'header', 'scope', 'extra', 'boolean-number')),
    *(('test_invalid_login_blocks_create', (value,))
      for value in ({}, {'USER_ID': 'a', 'user_id': 'b'}, {'USER_ID': safety.SECRET + '\n'}, {'USER_ID': 123})),
    ('test_authorization_and_reviewed_hash_required', ()),
    ('test_scope_changed_during_preflight_blocks_write_and_retains_intent', ()),
    ('test_readback_boolean_is_not_equal_to_reviewed_numeric_zero', ()),
]


@pytest.mark.parametrize('name,args', SAFETY_CASES,
                         ids=[name.removeprefix('test_') + '-' + str(index)
                              for index, (name, _) in enumerate(SAFETY_CASES)])
def test_inherited_registration_safety(name, args, monkeypatch):
    monkeypatch.setattr(safety, 'Harness', Harness)
    getattr(safety, name)(*args)
