"""Reviewer-only resources/protocol tests, no inference or remote writes."""
from copy import deepcopy
import pytest
from deployment import forms_understanding_profiles_v3 as p3
from deployment import forms_understanding_profiles_v4 as p4
from deployment import forms_understanding_registration_v4 as r4
from deployment.tests.test_forms_understanding_v3 import Harness as BaseHarness


class Harness(BaseHarness):
    def __init__(self, *, seed_mapper=True):
        super().__init__()
        self.plan = r4.build_registration_plan(p4.build_candidates(), self.profile)
        self.digest = r4.validate_plan(self.plan)
        self.executor = r4.RegistrationExecutor(client=self, store=self.store, scope_check=lambda: deepcopy(self.scope))
        if seed_mapper:self.seed('baseline43', published=True)


def test_mapper_exactly_unchanged_and_reviewer_is_additive():
    old=p3.build_candidates();new=p4.build_candidates()
    assert new['candidates']['baseline43']==old['candidates']['baseline43']
    assert p3.build_candidates()==old
    assert new['candidates']['reviewer43']['header']['name']!=old['candidates']['reviewer43']['header']['name']
    prompt=new['candidates']['reviewer43']['graph']['nodes'][1]['data']['template']['prompt']['value']
    assert 'No owned Block means zero declared screens is correct' in prompt
    assert 'may validly have ZERO proposed UI objects' in prompt
    assert 'does NOT excuse unsupported overrefusal for Items' in prompt
    assert 'Inspect' in prompt or 'inspect actual claims/actions' in prompt
    assert 'full merger' in prompt and prompt.count('{{request}}')==1


def test_only_reviewer_mutates_and_mapper_remains_exact():
    h=Harness();before=deepcopy(h.new)
    h.act('reviewer43');h.act('reviewer43','publish')
    assert len(h.writes())==2
    for key,value in before.items():assert h.new[key]==value
    assert h.executor.inspect(h.plan)['roles']['baseline43']['published'] is True
    with pytest.raises(r4.RegistrationError):h.act('baseline43')
    assert len(h.writes())==2


def test_missing_mapper_stops_before_any_write():
    h=Harness(seed_mapper=False)
    with pytest.raises(r4.RegistrationError):h.act('reviewer43')
    assert not h.writes() and not h.store.records


def test_uncertain_reviewer_create_is_never_replayed():
    h=Harness();h.fail='timeout'
    with pytest.raises(r4.RegistrationError):h.act('reviewer43')
    h.fail=None
    with pytest.raises(r4.RegistrationError):h.act('reviewer43')
    assert len(h.writes())==1
