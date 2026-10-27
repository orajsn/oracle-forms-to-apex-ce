"""Reviewed local configuration checks; no model, network or database writes."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from fox import native_pipeline as pipeline
from fox.native_project_pipeline import PROJECT_MAPPING_CAPABILITY, load_project_profile
from fox.opaf import OpafClient, OpafError, canonical_hash, load_native_profile
from test_native_pipeline import NativeHarness, read_json, write_json


ROOT = Path(__file__).resolve().parents[2]
DEPLOYMENT = ROOT/'deployment'
OLD_HASH = '7c7b73d43febc9befb1d43e47449a02cc7894b879dd4bc32904cec538e5f95e6'
NEW_HASH = '7170d60927b7e5b7aed5d56174f97efbeff3052be247b244911deff768701ed3'


def document(name):
    return json.loads((DEPLOYMENT/name).read_bytes())


def select_harness_profile(harness, target):
    """Use real reviewed tuple inputs with the existing offline fake providers."""
    harness.target_profile = deepcopy(target)
    harness.profile = {'schema_version': 1, 'profile_id': pipeline.PROFILE_ID,
        'opaf_base_url': target['opaf']['base_url'],
        'certificate_sha256': target['opaf']['certificate_sha256'],
        **deepcopy(target['opaf']['roles'])}
    write_json(harness.profile_path, harness.profile)


def test_registered_profile_pair_loads_offline_and_keeps_legacy_and_candidates(monkeypatch):
    monkeypatch.setattr(OpafClient, '_request', lambda *_a, **_k: pytest.fail('No network'))
    profile = load_project_profile(DEPLOYMENT/'project-opaf-profile-v2.json')
    target = document('target-profile.jsn-project-v2.json')
    old = document('target-profile.jsn.json')
    assert canonical_hash(target) == NEW_HASH
    assert canonical_hash(old) == OLD_HASH
    assert target['active'] is True and target['profile_id'] == 'jsn-native-project-v2'
    assert target['scope']['project_mapping'] == PROJECT_MAPPING_CAPABILITY
    assert {key: profile[key] for key in PROJECT_MAPPING_CAPABILITY} == PROJECT_MAPPING_CAPABILITY
    assert target['opaf']['roles'] == {role: profile[role] for role in ('mapper', 'reviewer')}
    assert profile['opaf_base_url'] == target['opaf']['base_url']
    assert profile['certificate_sha256'] == target['opaf']['certificate_sha256']
    assert target['scope']['customer_deployment_authorized'] is False
    assert target['scope']['existing_resources_only'] is True
    assert load_native_profile(DEPLOYMENT/'native-beta-profile.json')['mapper'] == old['opaf']['roles']['mapper']
    assert document('project-opaf-target-profile-v2.candidate.json')['active'] is False
    assert all(document('project-opaf-profile-v2.candidate.json')[role]['workflow_id'] is None
               for role in ('mapper', 'reviewer'))


def test_historical_hashes_append_both_snapshots_without_an_unknown_profile():
    assert pipeline.HISTORICAL_TARGET_PROFILE_HASHES == frozenset({OLD_HASH, NEW_HASH})
    unknown = document('target-profile.jsn-project-v2.json')
    unknown['profile_id'] = 'unknown-history'
    assert canonical_hash(unknown) not in pipeline.HISTORICAL_TARGET_PROFILE_HASHES


@pytest.mark.parametrize('selected,current', [
    ('target-profile.jsn.json', 'target-profile.jsn-project-v2.json'),
    ('target-profile.jsn-project-v2.json', 'target-profile.jsn.json'),
])
def test_mismatched_current_gateway_roles_block_before_model_dispatch(tmp_path,monkeypatch,selected,current):
    harness = NativeHarness(tmp_path, monkeypatch)
    select_harness_profile(harness, document(selected))
    observed = document(current)
    harness.responses['target-profile'] = {'target_profile': observed, 'target_profile_sha256': canonical_hash(observed)}
    with pytest.raises(OpafError, match='target profile differs'):
        harness.run()
    assert harness.model_calls == []
    assert not (harness.checkpoints/'mapper-intent.json').exists()


def test_cached_old_mapper_does_not_authorize_reviewer_after_profile_swap(tmp_path,monkeypatch):
    harness = NativeHarness(tmp_path, monkeypatch)
    old = document('target-profile.jsn.json')
    new = document('target-profile.jsn-project-v2.json')
    select_harness_profile(harness, old)
    original = harness.request
    def request(method, path, payload=None, binary=False):
        if path == '/fox/target-profile' and harness.target_profile_requests:
            harness.responses['target-profile'] = {'target_profile': new, 'target_profile_sha256': canonical_hash(new)}
        return original(method, path, payload, binary)
    monkeypatch.setattr(harness, 'request', request)
    with pytest.raises(OpafError, match='target profile differs'):
        harness.run()
    assert [name for name, _ in harness.model_calls] == ['mapper']
    saved = (harness.checkpoints/'mapper.json').read_bytes()
    assert read_json(harness.checkpoints/'target-profile.json')['target_profile'] == old
    assert not (harness.checkpoints/'reviewer-intent.json').exists()
    # Retained completed mapper evidence is not a fallback for the failed fresh gate.
    with pytest.raises(OpafError, match='target profile differs'):
        harness.run()
    assert [name for name, _ in harness.model_calls] == ['mapper']
    assert (harness.checkpoints/'mapper.json').read_bytes() == saved


@pytest.mark.parametrize('filename', ['target-profile.jsn.json', 'target-profile.jsn-project-v2.json'])
def test_both_registered_historical_packages_verify_without_current_profile_or_dispatch(tmp_path,monkeypatch,filename):
    from test_native_pipeline import package_bytes
    harness = NativeHarness(tmp_path, monkeypatch)
    target = document(filename)
    select_harness_profile(harness, target)
    harness.run()
    raw = package_bytes(harness.members())
    before = len(harness.model_calls)
    def forbidden(*_args, **_kwargs):
        pytest.fail('Historical verification cannot call a current target or model')
    monkeypatch.setattr(harness, 'request', forbidden)
    monkeypatch.setattr(harness, 'invoke', forbidden)
    assert pipeline.verify_package(raw, harness.evidence(), harness.snapshot['native_form']) == hashlib.sha256(raw).hexdigest()
    assert len(harness.model_calls) == before
