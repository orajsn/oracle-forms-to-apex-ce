"""Pure resources and injected registration tests; no model-quality claims."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from deployment import forms_understanding_profiles as p1
from deployment import forms_understanding_profiles_v2 as p2
from deployment import forms_understanding_profiles_v3 as p3
from deployment import forms_understanding_registration as r1
from deployment import forms_understanding_registration_v3 as r3
from deployment.tests import test_forms_understanding_registration as safety


class Harness(safety.Harness):
    def __init__(self):
        super().__init__()
        self.plan = r3.build_registration_plan(p3.build_candidates(), self.profile)
        self.digest = r3.validate_plan(self.plan)
        self.executor = r3.RegistrationExecutor(client=self, store=self.store,
                                                scope_check=lambda: deepcopy(self.scope))

    def _request(self, method, path, payload=None, **kwargs):
        if method == 'GET':
            return super()._request(method, path, payload, **kwargs)
        self.calls.append((method, path, deepcopy(payload)))
        role = next(role for role in r3.ROLES if
                    (payload.get('name') == self.plan['candidates']['candidates'][role]['header']['name']
                     if method == 'POST' else safety.IDS[role] in path))
        operation = 'create' if method == 'POST' else 'publish'
        intent = self.store.read(self.executor._key(self.digest, role, operation, 'intent'))
        assert intent and intent['method'] == method and intent['path'] == path
        if self.fail == 'timeout':
            raise TimeoutError(safety.SECRET)
        if method == 'POST': self.seed(role)
        else: self.new[safety.IDS[role]]['published'] = True
        return {'data': {'id': safety.IDS[role]}} if method == 'POST' else {'data': {}}


def test_two_tool_free_additive_roles_leave_old_resources_unchanged():
    old1, old2 = p1.build_candidates(), p2.build_candidates()
    result = p3.build_candidates()
    assert set(result['candidates']) == {'baseline43', 'reviewer43'}
    assert result['model_invocation'] is result['profile_activation'] is False
    old_names = {c['header']['name'] for old in (old1, old2) for c in old['candidates'].values()}
    old_ids = {n['id'] for old in (old1, old2) for c in old['candidates'].values() for n in c['graph']['nodes']}
    for role, item in result['candidates'].items():
        p1._check_graph(item['graph'])
        assert item['header']['name'] not in old_names
        assert not {n['id'] for n in item['graph']['nodes']} & old_ids
        assert item['graph_sha256'] == r3.canonical_hash(item['graph'])
        prompt = item['graph']['nodes'][1]['data']['template']['prompt']['value']
        assert prompt.count('{{request}}') == 1
        assert hashlib.sha256(prompt.encode()).hexdigest() == item['prompt_sha256']
        assert 'NOT analysis' in prompt or 'NOT design/analysis' in prompt
        assert 'Global ProgramUnits' in prompt or 'GLOBAL BEHAVIOR' in prompt
        if role == 'reviewer43':
            assert 'Claim/relationship/action/question/assumption IDs' in prompt
            assert 'Screen IDs retain screen-<exact Block ID>, not the counter format.' in prompt
            assert 'Candidate IDs unique' not in prompt
        assert item['graph']['nodes'][2]['data']['template']['temperature']['value'] == 0
    assert p1.build_candidates() == old1 and p2.build_candidates() == old2
    assert r1.RegistrationExecutor._roles(safety.Harness().executor) == r1.ROLES


def test_only_two_roles_create_and_publish_without_altering_originals():
    h = Harness()
    for role in r3.ROLES:
        assert h.act(role)['readback']['published'] is False
        assert h.act(role, 'publish')['readback']['published'] is True
    result = h.executor.inspect(h.plan, expected_plan_sha256=h.digest)
    assert set(result['roles']) == set(r3.ROLES)
    assert len(h.writes()) == 4 and len(h.store.records) == 8
    assert h.old == h.originals
    assert safety.SECRET not in json.dumps(h.store.records)
    assert all(row['scope'] == r3.PLAN_SCOPE for row in h.store.records.values())


def test_unused_model_role_is_rejected_before_any_remote_call():
    h = Harness()
    with pytest.raises(r3.RegistrationError): h.act('candidate47')
    assert not h.calls and not h.store.records


@pytest.mark.parametrize('change', ['prompt', 'scope', 'extra_role', 'destination'])
def test_changed_plan_is_rejected_even_if_caller_rehashes(change):
    h = Harness();p = deepcopy(h.plan)
    if change == 'prompt': p['candidates']['candidates']['baseline43']['graph']['nodes'][1]['data']['template']['prompt']['value'] += '\nchanged'
    elif change == 'scope': p['scope'] = r1.PLAN_SCOPE
    elif change == 'extra_role': p['candidates']['candidates']['candidate47'] = deepcopy(p['candidates']['candidates']['baseline43'])
    else: p['oci']['region'] = 'unapproved'
    with pytest.raises(r3.RegistrationError): h.executor.inspect(p, expected_plan_sha256=r3.canonical_hash(p))
    assert not h.calls and not h.store.records


def test_existing_create_is_not_replayed():
    h = Harness();h.act();writes = len(h.writes())
    with pytest.raises(r3.RegistrationError): h.act()
    assert len(h.writes()) == writes == 1


def test_unknown_create_keeps_intent_and_forbids_replay():
    h = Harness();h.fail = 'timeout'
    with pytest.raises(r3.RegistrationError): h.act()
    assert len(h.writes()) == 1 and len(h.store.records) == 1
    h.fail = None
    with pytest.raises(r3.RegistrationError): h.act()
    assert len(h.writes()) == 1 and not h.new
