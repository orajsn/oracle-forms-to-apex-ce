"""Offline real preflight algorithms; external observations and SQL are modeled."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import socket
import subprocess
from types import SimpleNamespace

import pytest

from forms2apex import prototype_gateway as gateway
from forms2apex import runtime_preflight as runtime
from forms2apex.target_profile import TargetProfileError, load_target_profile
from test_prototype_gateway import case, advance
from test_runtime_preflight import PROFILE_PATH, install_full_probe_mocks


@pytest.fixture
def guarded(case, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Offline regression forbids real network or SQLcl processes")
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    advance(case, "validate")
    profile = load_target_profile(PROFILE_PATH)
    settings = case.settings
    settings.target_profile_path = PROFILE_PATH
    settings.generator_model = profile["opaf"]["roles"]["mapper"]["model"]
    settings.reviewer_model = profile["opaf"]["roles"]["reviewer"]["model"]
    settings.opaf_mapper_workflow_id = profile["opaf"]["roles"]["mapper"]["workflow_id"]
    settings.opaf_reviewer_workflow_id = profile["opaf"]["roles"]["reviewer"]["workflow_id"]
    settings.apex_base_url = profile["apex"]["ords_origin"] + "/ords"
    probes = install_full_probe_mocks(monkeypatch, profile)
    state = SimpleNamespace(now=datetime(2026, 11, 12, tzinfo=timezone.utc),
                            delay=0, authorizations=0, collections=[], checks=[],
                            hook=None, probes=probes, case=case)

    # Exercise real receipt collection/verification without waiting or executing
    # HTTP, SDK, SQLcl, or any model. Probe adapters above are entirely synthetic.
    monkeypatch.setattr(runtime, "_now", lambda: state.now)
    class Clock:
        @staticmethod
        def now(tz):
            assert tz == timezone.utc
            return state.now
    monkeypatch.setattr(gateway, "datetime", Clock)
    collect = runtime.collect_deterministic_preflight
    verify = runtime.verify_action_preflight
    def collecting(*args, **kwargs):
        value = collect(*args, **kwargs)
        state.collections.append((state.authorizations, deepcopy(value)))
        return value
    def verifying(value, *args, **kwargs):
        before = deepcopy(value)
        state.checks.append((state.authorizations, kwargs["now"]))
        result = verify(value, *args, **kwargs)
        assert value == before  # Checking must never extend the original TTL.
        return result
    monkeypatch.setattr(runtime, "collect_deterministic_preflight", collecting)
    monkeypatch.setattr(runtime, "verify_action_preflight", verifying)
    def authorize(request):
        state.authorizations += 1
        state.now += timedelta(seconds=state.delay)
        if state.hook:
            return state.hook(request)
        return deepcopy(request)
    case.adapter.authorize = authorize
    case.adapter.preflight = case.adapter._target_preflight
    state.root = settings.jobs_root / case.request["job_id"] / "prototype-converter"
    return state


def assert_no_ddl(state):
    assert not any("FOX_PROTO_CREATED=" in call for call in state.case.calls)
    assert not (state.root / "prepare_schema.json").exists()


@pytest.mark.parametrize("delay", [0, 100])
def test_each_composite_guard_collects_once_then_authorizes_once(guarded, delay):
    state = guarded
    state.delay = delay
    receipt = advance(state.case, "prepare_schema")
    assert receipt["ready_for_import"] is True
    assert receipt["business_behavior_accepted"] is False
    assert state.authorizations == 5  # entry + three guards + final binding check
    assert [count for count, _ in state.collections] == [1, 2, 3]
    assert [count for count, _ in state.checks] == [2, 3, 4]
    assert state.probes == ["imds", "tooling", "database", "oci", "ords"] * 3
    observed = []
    for _, proof in state.collections:
        start = datetime.fromisoformat(proof["observations"]["observed_at_utc"])
        end = datetime.fromisoformat(proof["valid_until_utc"])
        assert end - start == timedelta(seconds=300)
        assert proof["target_preflight"]["max_age_seconds"] == 300
        observed.append(start)
    assert observed == [observed[0] + timedelta(seconds=delay * n) for n in range(3)]
    sql_calls = [call for call in state.case.calls if "FOX_PROTO_" in call]
    assert len(sql_calls) == 2
    assert "FOX_PROTO_ABSENT=" in sql_calls[0]
    assert "raise_application_error(-20084" in sql_calls[1]
    assert (state.root / "schema-write-intent.json").is_file()


@pytest.mark.parametrize("guard", [1, 2, 3])
def test_one_authorization_longer_than_original_ttl_refuses_before_ddl(guarded, guard):
    state = guarded
    def slow(request):
        if state.authorizations == guard + 1:
            state.now += timedelta(seconds=301)
        return deepcopy(request)
    state.hook = slow
    with pytest.raises(TargetProfileError, match="stale"):
        state.case.adapter.run_stage("prepare_schema", state.case.request)
    assert state.authorizations == guard + 1
    assert len(state.collections) == len(state.checks) == guard
    if guard == 1:
        assert not (state.root / "synthetic-schema.sql").exists()
    assert (state.root / "schema-write-intent.json").exists() is (guard == 3)
    assert_no_ddl(state)
    # The exclusive stage intent remains: expiry is not permission to replay.
    with pytest.raises(RuntimeError, match="ALREADY_ATTEMPTED"):
        state.case.adapter.run_stage("prepare_schema", state.case.request)


@pytest.mark.parametrize("guard", [1, 2, 3])
@pytest.mark.parametrize("drift", ["source", "consent", "snapshot", "prior"])
def test_current_authority_and_immutable_inputs_still_gate_each_write(guarded, guard, drift):
    state = guarded
    def changed(request):
        if state.authorizations != guard + 1:
            return deepcopy(request)
        if drift == "source":
            return {**request, "source_binding": "f" * 64}
        if drift == "consent":
            raise RuntimeError("SYNTHETIC_CURRENT_CONSENT_REVOKED")
        if drift == "snapshot":
            (state.root / "candidate-apexlang.zip").write_bytes(b"changed")
        else:
            (state.root / "validate.json").write_text("{}", encoding="utf-8")
        return deepcopy(request)
    state.hook = changed
    code = {"source": "AUTHORIZATION_FAILED", "consent": "CONSENT_REVOKED",
            "snapshot": "SNAPSHOT_CHANGED", "prior": "PRIOR_RECEIPT_MISMATCH"}[drift]
    with pytest.raises(RuntimeError, match=code):
        state.case.adapter.run_stage("prepare_schema", state.case.request)
    assert len(state.collections) == guard
    assert len(state.checks) == guard - 1
    assert_no_ddl(state)
    if guard < 3:
        assert not (state.root / "schema-write-intent.json").exists()


@pytest.mark.parametrize("guard", [1, 2, 3])
def test_new_target_observation_drift_cannot_reuse_previous_pass(guarded, monkeypatch, guard):
    state = guarded
    original = runtime.collect_database_identity
    seen = 0
    def database(*args, **kwargs):
        nonlocal seen
        seen += 1
        value = original(*args, **kwargs)
        if seen == guard:
            value["database"]["current_schema"] = "OTHER"
        return value
    monkeypatch.setattr(runtime, "collect_database_identity", database)
    with pytest.raises(TargetProfileError):
        state.case.adapter.run_stage("prepare_schema", state.case.request)
    assert seen == guard
    assert_no_ddl(state)


def test_default_factory_has_no_eager_verification_or_authorization(guarded):
    state = guarded
    check = state.case.adapter._target_preflight(state.case.request, "prepare-schema", state.root)
    assert callable(check)
    assert len(state.collections) == 1
    assert state.authorizations == 0 and state.checks == []
    check()
    assert state.authorizations == 0
    assert len(state.collections) == len(state.checks) == 1


def test_noncallable_target_guard_cannot_write(guarded):
    state = guarded
    state.case.adapter.preflight = lambda *args: {"passed": True}
    with pytest.raises(RuntimeError, match="FRESH_TARGET_AUTHORITY_REQUIRED"):
        state.case.adapter.run_stage("prepare_schema", state.case.request)
    assert_no_ddl(state)


def test_read_only_completed_and_unknown_recovery_never_recollect(guarded):
    state = guarded
    original = deepcopy(state.case.request)
    receipt = advance(state.case, "prepare_schema")
    before = (len(state.collections), list(state.probes), list(state.case.calls))
    assert state.case.adapter.recover_stage("prepare_schema", original) == receipt
    assert state.case.adapter.recover_stage_for_job(original["job_id"], "prepare_schema") == receipt
    assert state.case.adapter.recover_stage("import", state.case.request) is None
    assert state.case.adapter.recover_stage_for_job(original["job_id"], "import") is None
    assert (len(state.collections), state.probes, state.case.calls) == before


def test_unknown_sql_outcome_retains_claim_and_read_only_recovery(guarded):
    state = guarded
    def uncertain(*args, **kwargs):
        raise TimeoutError("synthetic lost acknowledgement")
    state.case.adapter.runner = uncertain
    with pytest.raises(TimeoutError):
        state.case.adapter.run_stage("prepare_schema", state.case.request)
    assert (state.root / "prepare_schema-intent.json").is_file()
    before = (len(state.collections), list(state.probes), list(state.case.calls))
    assert state.case.adapter.recover_stage("prepare_schema", state.case.request) is None
    assert state.case.adapter.recover_stage_for_job(state.case.request["job_id"], "prepare_schema") is None
    with pytest.raises(RuntimeError, match="ALREADY_ATTEMPTED"):
        state.case.adapter.run_stage("prepare_schema", state.case.request)
    assert (len(state.collections), state.probes, state.case.calls) == before
    assert_no_ddl(state)
