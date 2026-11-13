"""Filesystem contract tests with explicitly synthetic browser command output."""
from copy import deepcopy

import pytest

from forms2apex.project_reviews import canonical, read_object
from forms2apex import native_blueprint, native_blueprint_required, blueprint_profiles
from forms2apex import prototype_runtime_bridge as bridge_module
from forms2apex.prototype_runtime_bridge import (
    REQUEST, RESULT, PrototypeRuntimeBridge, code_sha256, object_bytes,
)
from qa.operator import prototype_runtime_worker as worker
from qa.operator.tests.test_prototype_browser import runtime_case
from qa.operator.tests.test_prototype_runtime_worker import bridge_case


def verifier(case, *, execute=True, mutate=None):
    bridge = PrototypeRuntimeBridge(case.io.jobs_root, expected_worker_sha256=code_sha256(worker.__file__),
                                    timeout_seconds=60 if execute else 0.02, poll_seconds=0.001)
    original = bridge.io.create
    def create(job, name, raw):
        original(job, name, raw)
        if name == REQUEST and execute:
            worker.run_once(case.config, job)
            if mutate:
                mutate(case)
    bridge.io.create = create
    return bridge


def invoke(bridge, case, **overrides):
    kwargs = {"root": case.root, "imported": case.imported, "trace": case.packet["trace"],
              "artifact_binding": case.packet["artifact_binding"], "freshness_check": lambda: None}
    kwargs.update(overrides)
    return bridge(case.request, **kwargs)


def test_converter_validates_real_callback_return_and_rejects_duplicate_dispatch(bridge_case):
    case = bridge_case
    bridge = verifier(case)
    receipt = invoke(bridge, case)
    assert receipt["passed"] is True and len(case.calls) == 3
    with pytest.raises(FileExistsError):
        invoke(bridge, case)
    assert len(case.calls) == 3


def test_post_dispatch_timeout_retains_packet_and_cannot_redispatch(bridge_case, monkeypatch):
    case = bridge_case
    bridge = verifier(case, execute=False)
    bridge.timeout_seconds, bridge.poll_seconds = 60, 5
    clock = [0.0]
    monkeypatch.setattr(bridge_module.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(bridge_module.time, 'sleep', lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    with pytest.raises(RuntimeError, match="(?:TIMEOUT|EXPIRED)_UNKNOWN_NO_REPLAY"):
        invoke(bridge, case)
    assert (case.root / REQUEST).exists() and not case.calls
    with pytest.raises(FileExistsError):
        invoke(bridge, case)


@pytest.mark.parametrize("field", ["worker_sha256", "dispatch_sha256", "binding", "receipt_sha256"])
def test_tampered_result_never_passes(bridge_case, field):
    def mutate(case):
        result = read_object(case.root / RESULT)
        result[field] = "0"*64
        (case.root / RESULT).write_bytes(canonical(result))
    with pytest.raises(RuntimeError, match="RESULT_"):
        invoke(verifier(bridge_case, mutate=mutate), bridge_case)


def test_changed_artifact_is_not_a_runtime_pass(bridge_case):
    def mutate(case):
        (case.root / "runtime-evidence/browser-report.json").write_bytes(b"{}")
    with pytest.raises(RuntimeError, match="ARTIFACT_CHANGED"):
        invoke(verifier(bridge_case, mutate=mutate), bridge_case)


@pytest.mark.parametrize('raw', [b'{', b'{"schema_version":1,"schema_version":1}', b'[]'])
def test_malformed_published_result_is_not_a_pass(bridge_case, raw):
    def mutate(case):
        (case.root / RESULT).write_bytes(raw)
    with pytest.raises(RuntimeError, match='JSON_'):
        invoke(verifier(bridge_case, mutate=mutate), bridge_case)


@pytest.mark.parametrize("field", ["trace", "imported", "artifact_binding"])
def test_mismatched_callback_context_rejected_before_publication(bridge_case, field):
    case = bridge_case
    with pytest.raises((RuntimeError, ValueError), match="CHANGED"):
        invoke(verifier(case), case, **{field: {}})
    assert not (case.root / REQUEST).exists() and not case.calls


@pytest.mark.parametrize("field", ["trace", "template"])
def test_cross_profile_context_cannot_be_downgraded_before_runtime_dispatch(bridge_case, field):
    case = bridge_case
    selected = blueprint_profiles.select(case.request["rendering_spec"])
    other = native_blueprint_required if selected is native_blueprint else native_blueprint
    if field == "trace":
        overrides = {"trace": {**case.packet["trace"], "scope": other.PROFILE_ID + "-trace"}}
    else:
        overrides = {"artifact_binding": {**case.packet["artifact_binding"], "template": other.context()}}
    with pytest.raises(RuntimeError, match="TRACE_CHANGED|SNAPSHOT_CHANGED"):
        invoke(verifier(case), case, **overrides)
    assert not (case.root / REQUEST).exists() and not case.calls


def test_empty_wait_defers_producer_revocation_check_without_granting_execution(bridge_case, monkeypatch):
    # Pending polls no longer latch transient revocation. They publish nothing
    # further and never authorize a browser. Worker execution checks are separate.
    calls = []
    sleeps = []
    clock = [0.0]
    def fresh():
        calls.append(1)
        if len(calls) > 1:
            raise RuntimeError("SYNTHETIC_AUTHORITY_REVOKED")
    def sleep(seconds):
        sleeps.append(seconds)
        clock[0] += seconds
    monkeypatch.setattr(bridge_module.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(bridge_module.time, 'sleep', sleep)
    bridge = verifier(bridge_case, execute=False)
    bridge.timeout_seconds, bridge.poll_seconds = 60, 5
    with pytest.raises(RuntimeError, match="TIMEOUT_UNKNOWN_NO_REPLAY"):
        invoke(bridge, bridge_case, freshness_check=fresh)
    assert calls == [1] and len(sleeps) > 1
    assert all(0 < seconds <= bridge.poll_seconds for seconds in sleeps)
    assert (bridge_case.root / REQUEST).exists()
    assert not (bridge_case.root / RESULT).exists() and not bridge_case.calls
    with pytest.raises(FileExistsError):
        invoke(bridge, bridge_case)


@pytest.mark.parametrize('reject_at', [2, 3])
def test_revocation_on_result_arrival_or_final_acceptance_never_returns_receipt(bridge_case, reject_at):
    bridge = verifier(bridge_case)
    calls, result_reads = [], []
    read = bridge.io.read
    def observe_read(job, name, limit):
        if name in (RESULT, 'runtime-receipt.json'):
            result_reads.append(name)
        return read(job, name, limit)
    def fresh():
        calls.append(1)
        if len(calls) == reject_at:
            raise RuntimeError('SYNTHETIC_AUTHORITY_REVOKED')
    bridge.io.read = observe_read
    with pytest.raises(RuntimeError, match='AUTHORITY_REVOKED'):
        invoke(bridge, bridge_case, freshness_check=fresh)
    assert len(calls) == reject_at
    assert (bridge_case.root / RESULT).exists()  # Preserve actual worker evidence.
    assert not (bridge_case.root / 'verify_runtime.json').exists()
    if reject_at == 2:
        assert not result_reads
    else:
        assert result_reads


@pytest.mark.parametrize('expire_at', [1, 2, 3])
def test_slow_authorization_never_extends_dispatch_or_acceptance_deadline(bridge_case, monkeypatch, expire_at):
    bridge = verifier(bridge_case)
    clock, calls, result_reads = [0.0], [], []
    read = bridge.io.read
    def observe_read(job, name, limit):
        if name in (RESULT, 'runtime-receipt.json'):
            result_reads.append(name)
        return read(job, name, limit)
    def fresh():
        calls.append(1)
        if len(calls) == expire_at:
            clock[0] = bridge.timeout_seconds + 1
    bridge.io.read = observe_read
    monkeypatch.setattr(bridge_module.time, 'monotonic', lambda: clock[0])
    with pytest.raises(RuntimeError, match='TIMEOUT_UNKNOWN_NO_REPLAY'):
        invoke(bridge, bridge_case, freshness_check=fresh)
    assert len(calls) == expire_at
    assert (bridge_case.root / REQUEST).exists() is (expire_at != 1)
    if expire_at <= 2:
        assert not result_reads
    assert not (bridge_case.root / 'verify_runtime.json').exists()


def test_retained_input_change_during_empty_poll_fails_before_more_authority(bridge_case, monkeypatch):
    bridge = verifier(bridge_case, execute=False)
    bridge.timeout_seconds = 60
    calls = []
    def sleep(seconds):
        (bridge_case.root / 'import.json').write_bytes(b'{}')
    monkeypatch.setattr(bridge_module.time, 'sleep', sleep)
    with pytest.raises(RuntimeError, match='RETAINED_PRIOR_CHANGED'):
        invoke(bridge, bridge_case, freshness_check=lambda: calls.append(1))
    assert calls == [1]
    assert (bridge_case.root / REQUEST).exists() and not bridge_case.calls


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{', b'[]', b''])
def test_malformed_json_is_not_a_result(raw):
    with pytest.raises(RuntimeError, match="JSON_"):
        object_bytes(raw)


def test_deadline_and_worker_pin_are_mandatory(bridge_case):
    with pytest.raises(RuntimeError, match="WORKER_IDENTITY"):
        PrototypeRuntimeBridge(bridge_case.io.jobs_root, expected_worker_sha256="")
    for timeout in (600, float("nan"), float("inf"), -1):
        with pytest.raises(RuntimeError, match="DEADLINE"):
            PrototypeRuntimeBridge(bridge_case.io.jobs_root, expected_worker_sha256="a"*64, timeout_seconds=timeout)
