"""Pure local receipt tests; no OPAF, credentials, model or database calls."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from forms2apex.native import TEMPLATE_ID
from forms2apex.native_contract import validate_native_spec
from forms2apex.review_receipts import candidate_sha256, record_review, verify_review, review_proof_scope, verify_historical_model_environment


ROLES = ("mapper-workflow", "reviewer-workflow", "xai.grok-4.3", "xai.grok-4.3")


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False, allow_nan=False).encode()).hexdigest()


@pytest.fixture
def job(tmp_path):
    root = tmp_path / "fox-native-review"
    intake = root / "intake"
    intake.mkdir(parents=True)
    content = b'<FormModule Name="SYNTHETIC"><Block Name="ORDERS"/></FormModule>'
    (intake / "source.xml").write_bytes(content)
    native = {
        "profile_id": "native-table-form-v1", "data_mode": "synthetic_test_only",
        "table_name": "FOX_NATIVE_ORDERS", "columns": [
            {"name": "ORDER_ID", "data_type": "NUMBER", "nullable": False,
             "primary_key": True, "identity": True, "label": "Order ID"},
            {"name": "DESCRIPTION", "data_type": "VARCHAR2", "nullable": False,
             "length": 100, "label": "Description"},
        ],
    }
    manifest = {
        "job_id": root.name, "source_manifest_sha256": "1" * 64, "native_form": native,
        "files": [{"packaged_name": "source.xml", "sha256": hashlib.sha256(content).hexdigest()}],
    }
    (intake / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    candidate = {
        "job_id": root.name, "template_id": TEMPLATE_ID,
        "data_classification": "synthetic_or_stub_only", "generator": {"model": ROLES[2]},
        "native_form": native, "remediation_items": [],
        "mapping_summary": "Synthetic report and native table form; no customer behavior inferred.",
    }
    def invocation(workflow_id, room_id, start, complete):
        return {
            "workflow_id": workflow_id, "room_id": room_id, "model": ROLES[2],
            "graph_sha256": "2" * 64, "request_sha256": "3" * 64, "response_sha256": "4" * 64,
            "started_at_utc": start, "completed_at_utc": complete,
        }
    payload = {
        "job_id": root.name, "source_hash": manifest["source_manifest_sha256"], "candidate": candidate,
        "mapper_invocation": invocation(ROLES[0], "mapper-room", "2026-10-16T00:00:00Z", "2026-10-16T00:00:10Z"),
        "reviewer_invocation": invocation(ROLES[1], "reviewer-room", "2026-10-16T00:00:11Z", "2026-10-16T00:00:20Z"),
        "review": {"verdict": "approve", "candidate_sha256": candidate_sha256(candidate),
                   "notes": "Independent invocation approves the exact synthetic metadata.", "blocking_findings": []},
    }
    return root, payload


def record(job, payload=None):
    root, supplied = job
    return record_review(root, supplied if payload is None else payload, *ROLES)


def verify(job, candidate=None):
    root, payload = job
    return verify_review(root, payload["candidate"] if candidate is None else candidate, *ROLES)


def update_manifest(root, update):
    path = root / "intake/manifest.json"
    value = json.loads(path.read_text())
    update(value)
    path.write_text(json.dumps(value), encoding="utf-8")


def test_valid_receipt_roundtrip_seal_and_idempotence(job):
    root, payload = job
    original = deepcopy(payload)
    receipt = record(job)
    assert payload == original
    assert receipt["candidate_sha256"] == canonical_hash(payload["candidate"])
    content = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    assert receipt["receipt_sha256"] == canonical_hash(content)
    assert receipt["trust_boundary"] == "authenticated_fox_executor_not_vendor_attestation"
    assert "request" not in receipt["mapper_invocation"]
    assert "response" not in receipt["reviewer_invocation"]
    assert verify(job) == receipt
    path = root / "native-review.json"
    before = path.read_bytes()
    assert record(job) == receipt
    assert path.read_bytes() == before
    assert not list(root.glob(".native-review-*.tmp"))


def test_hash_is_key_order_independent_but_binds_exact_unormalized_values(job):
    _, payload = job
    candidate = payload["candidate"]
    assert candidate_sha256(dict(reversed(list(candidate.items())))) == candidate_sha256(candidate)
    normalized = deepcopy(candidate)
    normalized["native_form"] = validate_native_spec(candidate["native_form"])
    assert candidate_sha256(normalized) != candidate_sha256(candidate)


def test_normalized_manifest_schema_is_semantically_equal(job):
    root, _ = job
    update_manifest(root, lambda manifest: manifest.update(native_form=validate_native_spec(manifest["native_form"])))
    assert record(job)["review"]["verdict"] == "approve"


def test_missing_receipt_cannot_be_satisfied_by_submitted_approval(job):
    with pytest.raises(RuntimeError, match="missing or linked"):
        verify(job)
    _, payload = job
    payload["candidate"]["reviewer"] = {"model": ROLES[3], "verdict": "approve"}
    with pytest.raises(ValueError, match="no self-declared reviewer"):
        record(job)


@pytest.mark.parametrize("extra", ["reviewer", "prototype_html", "apexlang_files", "sql", "verdict", "materialized_files"])
def test_candidate_rejects_untrusted_envelope_extensions(job, extra):
    _, payload = job
    payload["candidate"][extra] = "not permitted"
    with pytest.raises(ValueError, match="exactly"):
        record(job)


@pytest.mark.parametrize("field", ["job_id", "template_id", "data_classification", "generator", "native_form", "remediation_items", "mapping_summary"])
def test_candidate_requires_complete_envelope(job, field):
    _, payload = job
    del payload["candidate"][field]
    with pytest.raises(ValueError):
        record(job)


@pytest.mark.parametrize("field,value", [
    ("template_id", "sqlcl-html-template"), ("data_classification", "production"),
    ("job_id", "../other"), ("job_id", 1), ("mapping_summary", ""),
    ("mapping_summary", ["text"]), ("mapping_summary", "x" * 8001),
    ("remediation_items", ["unknown"]), ("remediation_items", [{}] * 201),
    ("generator", {"model": ROLES[2], "verdict": "approve"}),
    ("generator", {"model": "other-model"}),
])
def test_candidate_metadata_fails_closed(job, field, value):
    _, payload = job
    payload["candidate"][field] = value
    with pytest.raises(ValueError):
        record(job)


def test_native_contract_is_not_bypassed_by_receipt(job):
    _, payload = job
    payload["candidate"]["native_form"]["columns"][0]["primary_key"] = False
    with pytest.raises(ValueError, match="primary key"):
        record(job)


@pytest.mark.parametrize("field", ["job_id", "source_hash", "candidate", "mapper_invocation", "reviewer_invocation", "review"])
def test_payload_requires_all_fields(job, field):
    _, payload = job
    del payload[field]
    with pytest.raises(ValueError, match="exactly"):
        record(job)


@pytest.mark.parametrize("role", ["mapper_invocation", "reviewer_invocation"])
@pytest.mark.parametrize("field", ["workflow_id", "room_id", "model", "graph_sha256", "request_sha256", "response_sha256", "started_at_utc", "completed_at_utc"])
def test_invocations_require_all_fields(job, role, field):
    _, payload = job
    del payload[role][field]
    with pytest.raises(ValueError, match="exactly"):
        record(job)


@pytest.mark.parametrize("role", ["mapper_invocation", "reviewer_invocation"])
@pytest.mark.parametrize("field,value", [
    ("workflow_id", "unexpected"), ("model", "unexpected"), ("room_id", ""),
    ("room_id", "room/unsafe"), ("room_id", "x" * 129),
    ("graph_sha256", "no-hash"), ("request_sha256", "A" * 64), ("response_sha256", None),
    ("started_at_utc", "2026-10-16T00:00:00"),
    ("started_at_utc", "2026-10-16T00:00:00+07:00"),
    ("started_at_utc", "2026-13-16T00:00:00Z"),
    ("completed_at_utc", "not-time"),
])
def test_invocation_metadata_is_validated(job, role, field, value):
    _, payload = job
    payload[role][field] = value
    with pytest.raises(ValueError):
        record(job)


def test_mapper_and_reviewer_must_have_distinct_workflows(job):
    root, payload = job
    with pytest.raises(ValueError, match="distinct configured workflows"):
        record_review(root, payload, ROLES[0], ROLES[0], ROLES[2], ROLES[3])


def test_mapper_and_reviewer_must_have_distinct_rooms(job):
    _, payload = job
    payload["reviewer_invocation"]["room_id"] = payload["mapper_invocation"]["room_id"]
    with pytest.raises(ValueError, match="distinct OPAF rooms"):
        record(job)


def test_same_model_different_invocations_are_supported(job):
    # Current approved configuration uses xai.grok-4.3 for both roles, but not
    # one invocation or one workflow masquerading as independent review.
    assert record(job)["mapper_invocation"]["model"] == ROLES[3]


def test_case_only_workflow_alias_is_not_independence(job):
    root, payload = job
    with pytest.raises(ValueError, match="distinct configured workflows"):
        record_review(root, payload, "A" * 32, "a" * 32, ROLES[2], ROLES[3])


def test_case_only_room_alias_is_not_independence(job):
    _, payload = job
    payload["mapper_invocation"]["room_id"] = "B" * 32
    payload["reviewer_invocation"]["room_id"] = "b" * 32
    with pytest.raises(ValueError, match="distinct OPAF rooms"):
        record(job)


@pytest.mark.parametrize("role", ["mapper_invocation", "reviewer_invocation"])
def test_completion_cannot_precede_start(job, role):
    _, payload = job
    payload[role]["completed_at_utc"] = "2026-10-15T23:59:59Z"
    with pytest.raises(ValueError, match="completed before"):
        record(job)


def test_reviewer_cannot_start_before_mapping_finished(job):
    _, payload = job
    payload["reviewer_invocation"]["started_at_utc"] = "2026-10-16T00:00:09Z"
    with pytest.raises(ValueError, match="after mapper completion"):
        record(job)


def test_utc_zero_offset_and_subsecond_timestamps_supported(job):
    _, payload = job
    payload["mapper_invocation"]["started_at_utc"] = "2026-10-16T00:00:00.001+00:00"
    assert record(job)


@pytest.mark.parametrize("verdict", ["APPROVE", "accepted", "maybe", "", None, {}])
def test_unknown_reviewer_verdict_is_not_approval(job, verdict):
    _, payload = job
    payload["review"]["verdict"] = verdict
    with pytest.raises(ValueError, match="verdict"):
        record(job)


@pytest.mark.parametrize("field,value", [
    ("candidate_sha256", "0" * 64), ("notes", {"text": "approved"}),
    ("notes", "x" * 8001), ("blocking_findings", "none"),
    ("blocking_findings", [""]), ("blocking_findings", ["Fix missing evidence"]),
])
def test_reviewer_must_approve_exact_candidate_without_blockers(job, field, value):
    _, payload = job
    payload["review"][field] = value
    with pytest.raises(ValueError):
        record(job)


@pytest.mark.parametrize("notes", ["", "Approved with explicit remediation", [], ["Independent review completed", "Synthetic schema unchanged"]])
def test_review_notes_preserve_string_or_array_response_shape(job, notes):
    _, payload = job
    payload["review"]["notes"] = notes
    assert record(job)["review"]["notes"] == notes
    assert verify(job)["review"]["notes"] == notes


@pytest.mark.parametrize("notes", [["x"] * 101, ["x" * 2001], [""], [None], [1], [{}], [["nested"]], None])
def test_review_notes_array_is_bounded_and_typed(job, notes):
    _, payload = job
    payload["review"]["notes"] = notes
    with pytest.raises(ValueError):
        record(job)


def test_rejection_is_recorded_but_never_authorizes_generation(job):
    root, payload = job
    payload["review"].update(verdict="reject", blocking_findings=["Key metadata needs owner review"])
    receipt = record(job)
    with pytest.raises(ValueError, match="reviewer approval"):
        verify(job)
    payload["review"].update(verdict="approve", blocking_findings=[])
    with pytest.raises(ValueError, match="already exists"):
        record(job)
    assert json.loads((root / "native-review.json").read_text()) == receipt


def test_mutated_candidate_is_not_approved(job):
    record(job)
    _, payload = job
    candidate = deepcopy(payload["candidate"])
    candidate["mapping_summary"] = "Different mapping"
    with pytest.raises(ValueError, match="exact candidate"):
        verify(job, candidate)


def test_mutated_source_bytes_cannot_reuse_receipt(job):
    record(job)
    root, _ = job
    (root / "intake/source.xml").write_text("<FormModule Name='CHANGED'/>")
    with pytest.raises(ValueError, match="Source file hash"):
        verify(job)


def test_mutated_source_and_file_hash_cannot_reuse_receipt(job):
    record(job)
    root, _ = job
    changed = b"<FormModule Name='CHANGED'/>"
    (root / "intake/source.xml").write_bytes(changed)
    update_manifest(root, lambda manifest: manifest["files"][0].update(sha256=hashlib.sha256(changed).hexdigest()))
    with pytest.raises(ValueError, match="frozen source"):
        verify(job)


def test_mutated_source_manifest_hash_cannot_reuse_receipt(job):
    record(job)
    root, _ = job
    update_manifest(root, lambda manifest: manifest.update(source_manifest_sha256="a" * 64))
    with pytest.raises(ValueError, match="source hash"):
        verify(job)


def test_mutated_native_schema_cannot_reuse_receipt(job):
    record(job)
    root, _ = job
    update_manifest(root, lambda manifest: manifest["native_form"]["columns"][1].update(length=101))
    with pytest.raises(ValueError, match="native specification"):
        verify(job)


def test_unlisted_added_source_file_invalidates_receipt(job):
    record(job)
    root, _ = job
    (root / "intake/extra.txt").write_text("Not in reviewed intake")
    with pytest.raises(ValueError, match="frozen source"):
        verify(job)


def test_unlisted_initial_file_is_not_treated_as_reviewed(job):
    root, _ = job
    (root / "intake/extra.txt").write_text("Never submitted for review")
    with pytest.raises(ValueError, match="manifest exactly"):
        record(job)


def test_large_unlisted_initial_file_is_rejected_before_hashing(job, monkeypatch):
    import forms2apex.review_receipts as receipts
    root, _ = job
    (root / "intake/extra.txt").write_bytes(b"x" * 300_001)
    monkeypatch.setattr(receipts, "tree_digest", lambda path: pytest.fail("Oversized source must not be hashed"))
    with pytest.raises(ValueError, match="bounded source size"):
        record(job)


@pytest.mark.parametrize("field,value", [
    ("job_id", "different-job"), ("source_manifest_sha256", "invalid"),
    ("native_form", {}), ("files", []), ("files", None),
])
def test_manifest_must_bind_complete_pinned_intake(job, field, value):
    root, _ = job
    update_manifest(root, lambda manifest: manifest.update({field: value}))
    with pytest.raises(ValueError):
        record(job)


@pytest.mark.parametrize("name", ["../outside.xml", "/outside.xml", "C:/outside.xml", "source.xml:stream", "./source.xml", "a/../source.xml", "a\\source.xml", "manifest.json"])
def test_manifest_paths_fail_closed(job, name):
    root, _ = job
    update_manifest(root, lambda manifest: manifest["files"][0].update(packaged_name=name))
    with pytest.raises(ValueError):
        record(job)


def test_duplicate_manifest_members_are_rejected(job):
    root, _ = job
    update_manifest(root, lambda manifest: manifest["files"].append(dict(manifest["files"][0])))
    with pytest.raises(ValueError, match="duplicate"):
        record(job)


def test_receipt_corruption_is_detected_even_if_candidate_unchanged(job):
    record(job)
    root, _ = job
    path = root / "native-review.json"
    receipt = json.loads(path.read_text())
    receipt["review"]["notes"] = "Edited after seal"
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="content hash"):
        verify(job)
    with pytest.raises(ValueError, match="content hash"):
        record(job)


@pytest.mark.parametrize("index,value", [(0, "other-mapper"), (1, "other-reviewer"), (2, "other-generator"), (3, "other-reviewer-model")])
def test_changed_configuration_does_not_authorize_old_receipt(job, index, value):
    record(job)
    root, payload = job
    roles = list(ROLES)
    roles[index] = value
    with pytest.raises(ValueError, match="configured"):
        verify_review(root, payload["candidate"], *roles)


def test_duplicate_persisted_json_keys_are_rejected(job):
    record(job)
    root, _ = job
    path = root / "native-review.json"
    raw = path.read_text()
    path.write_text(raw[:-2] + ',"schema_version":1}\n')
    with pytest.raises(ValueError, match="Duplicate JSON"):
        verify(job)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), {1: "non-string-key"}, ("tuple",)])
def test_non_json_candidate_values_are_rejected(job, value):
    _, payload = job
    payload["candidate"]["remediation_items"] = [{"value": value}]
    with pytest.raises(ValueError, match="JSON"):
        record(job)


def test_raw_response_not_accepted_as_unbounded_receipt_metadata(job):
    _, payload = job
    payload["reviewer_invocation"]["response"] = {"credentials": "not permitted"}
    with pytest.raises(ValueError, match="exactly"):
        record(job)


def test_bounded_payload_size(job):
    _, payload = job
    payload["candidate"]["remediation_items"] = [{"detail": "x" * 256_001}]
    with pytest.raises(ValueError, match="bounded payload"):
        record(job)


def test_maximum_size_canonical_receipt_can_be_reread(job):
    import forms2apex.review_receipts as receipts
    root, payload = job
    payload["candidate"]["remediation_items"] = [{"detail": ""}]
    payload["review"]["candidate_sha256"] = candidate_sha256(payload["candidate"])
    receipt = receipts._sealed_payload(root, payload, *ROLES)
    length = len(receipts._canonical(receipt))
    payload["candidate"]["remediation_items"][0]["detail"] = "x" * (receipts._MAX_BYTES - length)
    payload["review"]["candidate_sha256"] = candidate_sha256(payload["candidate"])
    record(job)
    assert (root / "native-review.json").stat().st_size == receipts._MAX_BYTES + 1
    assert verify(job)["review"]["verdict"] == "approve"


def test_failed_atomic_publish_leaves_no_receipt_or_partial_target(job, monkeypatch):
    import forms2apex.review_receipts as receipts
    root, _ = job
    def fail(*args):
        raise OSError("Simulated publish interruption")
    monkeypatch.setattr(receipts.os, "link", fail)
    with pytest.raises(OSError, match="interruption"):
        record(job)
    assert not (root / "native-review.json").exists()
    assert not list(root.glob(".native-review-*.tmp"))


def test_uncertain_directory_sync_is_reconciled_by_identical_retry(job, monkeypatch):
    import forms2apex.review_receipts as receipts
    root, _ = job
    calls = []
    def fail(directory):
        calls.append(directory)
        assert (directory / "native-review.json").is_file()
        raise OSError("Simulated directory sync interruption")
    monkeypatch.setattr(receipts, "_sync_directory", fail)
    with pytest.raises(OSError, match="sync interruption"):
        record(job)
    before = (root / "native-review.json").read_bytes()
    monkeypatch.setattr(receipts, "_sync_directory", lambda directory: calls.append(directory))
    assert record(job) == verify(job)
    assert (root / "native-review.json").read_bytes() == before
    assert calls == [root, root]


def test_source_change_during_publication_blocks_receipt(job, monkeypatch):
    import forms2apex.review_receipts as receipts
    root, _ = job
    original = receipts.tree_digest
    calls = 0
    def changed(path):
        nonlocal calls
        calls += 1
        if calls == 3:
            (root / "intake/source.xml").write_text("changed before publication")
        return original(path)
    monkeypatch.setattr(receipts, "tree_digest", changed)
    with pytest.raises(RuntimeError, match="before publishing"):
        record(job)
    assert not (root / "native-review.json").exists()


def test_concurrent_identical_records_are_idempotent(job):
    with ThreadPoolExecutor(max_workers=4) as pool:
        receipts = list(pool.map(lambda _: record(job), range(8)))
    assert all(receipt == receipts[0] for receipt in receipts)
    assert verify(job) == receipts[0]


def test_concurrent_different_records_never_overwrite_winner(job):
    _, payload = job
    alternate = deepcopy(payload)
    alternate["review"]["notes"] = "Different independent reviewer notes"
    def attempt(supplied):
        try:
            return record(job, supplied)
        except ValueError as exc:
            assert "already exists" in str(exc)
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, [payload, alternate]))
    assert sum(result is not None for result in results) == 1
    assert verify(job) == next(result for result in results if result is not None)


@pytest.fixture
def environment_job(job):
    """Use the checked-in secret-free profile; never collect a live observation."""
    from pathlib import Path
    from forms2apex.target_profile import load_target_profile, target_profile_sha256
    profile = load_target_profile(Path(__file__).resolve().parents[2] / "deployment/target-profile.jsn.json")
    root, payload = job
    roles = profile["opaf"]["roles"]
    for role in ("mapper", "reviewer"):
        payload[role + "_invocation"].update(roles[role])
    payload["candidate"]["generator"]["model"] = roles["mapper"]["model"]
    payload["review"]["candidate_sha256"] = candidate_sha256(payload["candidate"])
    payload["model_environment"] = {}
    for role in ("mapper", "reviewer"):
        payload["model_environment"][role] = {
            "schema_version": 1, "scope": "opaf-model-environment-v1",
            "trust_boundary": "authenticated_fox_executor_not_vendor_attestation",
            "job_id": root.name, "role": role, "source_manifest_sha256": payload["source_hash"],
            "target_profile_sha256": target_profile_sha256(profile),
            "observed_at_utc": payload[role + "_invocation"]["started_at_utc"],
            "opaf": {key: profile["opaf"][key] for key in ("base_url", "certificate_sha256", "model_authentication", "version_number", "build_id")},
            "workflow": {**roles[role], "published": True}, "opaf_version": profile["tested_versions"]["opaf"],
        }
    arguments = (roles["mapper"]["workflow_id"], roles["reviewer"]["workflow_id"], roles["mapper"]["model"], roles["reviewer"]["model"])
    return root, payload, profile, arguments


def record_environment(job):
    root, payload, profile, arguments = job
    return record_review(root, payload, *arguments, target_profile=profile)


def verify_environment(job, profile_override=None):
    root, payload, profile, arguments = job
    return verify_review(root, payload["candidate"], *arguments,
                         target_profile=profile if profile_override is None else profile_override)


def test_v2_environment_receipt_is_sealed_and_exactly_idempotent(environment_job):
    root, payload, _, _ = environment_job
    before_payload = deepcopy(payload)
    receipt = record_environment(environment_job)
    before_file = (root / "native-review.json").read_bytes()
    assert receipt["schema_version"] == 2
    assert receipt["model_environment"] == payload["model_environment"]
    assert receipt["historical_target_profile"] == environment_job[2]
    assert "historical_target_profile" not in payload
    assert receipt["receipt_sha256"] == canonical_hash({key: value for key, value in receipt.items() if key != "receipt_sha256"})
    assert verify_environment(environment_job) == receipt
    assert record_environment(environment_job) == receipt
    assert (root / "native-review.json").read_bytes() == before_file
    assert payload == before_payload
    assert review_proof_scope(receipt) == "historical_model_environment_and_invocation_candidate_source_binding"
    assert "proof_scope" not in receipt


def test_new_configured_job_requires_both_model_observations(environment_job):
    root, payload, _, _ = environment_job
    del payload["model_environment"]
    with pytest.raises(ValueError, match="required fields"):
        record_environment(environment_job)
    assert not (root / "native-review.json").exists()


@pytest.mark.parametrize("value", [None, [], {}, {"mapper": {}}, {"reviewer": {}}, {"mapper": {}, "reviewer": {}, "other": {}}])
def test_v2_environment_pair_is_exactly_typed(environment_job, value):
    _, payload, _, _ = environment_job
    payload["model_environment"] = value
    with pytest.raises(ValueError): record_environment(environment_job)


@pytest.mark.parametrize("role", ["mapper", "reviewer"])
@pytest.mark.parametrize("field,value", [
    ("schema_version", True), ("opaf_version", "26.5"), ("target_profile_sha256", "0" * 64),
    ("source_manifest_sha256", "0" * 64), ("job_id", "other-job"), ("role", "generator"),
    ("scope", "live-current-proof"), ("trust_boundary", "vendor_attestation"),
    ("observed_at_utc", "2026-10-15T23:50:00Z"),
    ("observed_at_utc", "2026-10-16T00:01:00Z"),
])
def test_v2_rejects_changed_or_stale_environment_binding(environment_job, role, field, value):
    _, payload, _, _ = environment_job
    payload["model_environment"][role][field] = value
    with pytest.raises(ValueError): record_environment(environment_job)


@pytest.mark.parametrize("role", ["mapper", "reviewer"])
@pytest.mark.parametrize("field,value", [
    ("base_url", "https://other.invalid/agentFactory"), ("certificate_sha256", "0" * 64),
    ("model_authentication", "api_key"), ("version_number", 264001), ("build_id", 1),
])
def test_v2_rejects_changed_measured_opaf_environment(environment_job, role, field, value):
    _, payload, _, _ = environment_job
    payload["model_environment"][role]["opaf"][field] = value
    with pytest.raises(ValueError): record_environment(environment_job)


@pytest.mark.parametrize("field,value", [("published", False), ("graph_sha256", "0" * 64), ("model", "other"), ("workflow_id", "A" * 32)])
def test_v2_rejects_changed_observed_workflow(environment_job, field, value):
    _, payload, _, _ = environment_job
    payload["model_environment"]["reviewer"]["workflow"][field] = value
    with pytest.raises(ValueError): record_environment(environment_job)


def test_v2_invocation_graph_cannot_differ_from_its_observation(environment_job):
    _, payload, _, _ = environment_job
    payload["reviewer_invocation"]["graph_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="role binding"): record_environment(environment_job)


def test_v2_verification_is_selfcontained_without_current_profile(environment_job):
    receipt = record_environment(environment_job)
    root, payload, _, arguments = environment_job
    assert verify_review(root, payload["candidate"], *arguments) == receipt
    assert json.loads((root / "native-review.json").read_text()) == receipt


@pytest.mark.parametrize("section,field,value", [("tested_versions", "opaf", "26.5"), ("opaf", "build_id", 1), ("apex", "workspace", "OTHER")])
def test_current_profile_is_not_substituted_for_historical_proof(environment_job, section, field, value):
    receipt = record_environment(environment_job)
    profile = deepcopy(environment_job[2]); profile[section][field] = value
    assert verify_environment(environment_job, profile) == receipt
    assert receipt["historical_target_profile"] == environment_job[2]


def test_v2_environment_tampering_fails_without_resealing(environment_job):
    record_environment(environment_job)
    root, _, _, _ = environment_job
    path = root / "native-review.json"
    receipt = json.loads(path.read_text())
    receipt["model_environment"]["mapper"]["opaf"]["build_id"] = 1
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="content hash"): verify_environment(environment_job)


def test_v2_resealed_environment_tampering_still_fails_profile_binding(environment_job):
    record_environment(environment_job)
    root, _, _, _ = environment_job
    path = root / "native-review.json"
    receipt = json.loads(path.read_text())
    receipt["model_environment"]["reviewer"]["workflow"]["graph_sha256"] = "0" * 64
    receipt["receipt_sha256"] = canonical_hash({key: value for key, value in receipt.items() if key != "receipt_sha256"})
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError): verify_environment(environment_job)


def test_historical_v2_proof_verifies_offline_without_current_time_or_collectors(environment_job, monkeypatch):
    import forms2apex.runtime_preflight as runtime
    from datetime import datetime as real_datetime, timedelta, timezone
    _, payload, _, _ = environment_job
    for role in ("mapper", "reviewer"):
        invocation = payload[role + "_invocation"]
        for field in ("started_at_utc", "completed_at_utc"):
            invocation[field] = (real_datetime.fromisoformat(invocation[field].replace("Z", "+00:00")) - timedelta(days=365)).isoformat()
        payload["model_environment"][role]["observed_at_utc"] = invocation["started_at_utc"]
    def no_external(*args, **kwargs):
        pytest.fail("Historical model proof must not call a clock, network, subprocess or collector")
    monkeypatch.setattr(runtime, "_now", no_external)
    monkeypatch.setattr(runtime.http.client, "HTTPSConnection", no_external)
    monkeypatch.setattr(runtime.http.client, "HTTPConnection", no_external)
    monkeypatch.setattr(runtime.subprocess, "run", no_external)
    monkeypatch.setattr(runtime, "collect_imds_identity", no_external)
    monkeypatch.setattr(runtime, "collect_database_identity", no_external)
    receipt = record_environment(environment_job)
    assert verify_environment(environment_job) == receipt


def test_model_observation_unknown_secret_fields_never_leak(environment_job):
    _, payload, _, _ = environment_job
    marker = "synthetic-sensitive-value-must-not-appear"
    payload["model_environment"]["mapper"]["provider_response"] = marker
    with pytest.raises(ValueError) as error: record_environment(environment_job)
    assert marker not in str(error.value)


def test_v1_exact_bytes_hash_scope_and_replay_stay_unchanged_with_profile(environment_job):
    root, payload, profile, arguments = environment_job
    legacy = {key: value for key, value in payload.items() if key != "model_environment"}
    receipt = record_review(root, legacy, *arguments)
    path = root / "native-review.json"; before = path.read_bytes()
    assert receipt["schema_version"] == 1 and "model_environment" not in receipt
    expected = {**deepcopy(legacy), "schema_version": 1,
                "trust_boundary": "authenticated_fox_executor_not_vendor_attestation",
                "candidate_sha256": canonical_hash(legacy["candidate"]), "intake_sha256": receipt["intake_sha256"]}
    expected["receipt_sha256"] = canonical_hash(expected)
    assert receipt == expected
    assert verify_review(root, legacy["candidate"], *arguments, target_profile=profile) == receipt
    assert record_review(root, legacy, *arguments, target_profile=profile) == receipt
    assert path.read_bytes() == before
    assert review_proof_scope(receipt) == "legacy_invocation_candidate_source_binding_no_model_environment"


def test_v1_receipt_cannot_be_upgraded_or_replaced_in_place(environment_job):
    root, payload, profile, arguments = environment_job
    legacy = {key: value for key, value in payload.items() if key != "model_environment"}
    record_review(root, legacy, *arguments)
    path = root / "native-review.json"; before = path.read_bytes()
    with pytest.raises(ValueError, match="already exists"):
        record_review(root, payload, *arguments, target_profile=profile)
    assert path.read_bytes() == before


def test_unconfigured_v1_library_does_not_accept_unverified_environment_fields(environment_job):
    root, payload, _, arguments = environment_job
    with pytest.raises(ValueError, match="required fields"):
        record_review(root, payload, *arguments)


@pytest.mark.parametrize("different_payload", [False, True])
def test_configured_legacy_replay_can_never_publish_after_retained_file_disappears(environment_job, monkeypatch, different_payload):
    import forms2apex.review_receipts as receipts
    from pathlib import Path
    root, payload, profile, arguments = environment_job
    legacy = {key: value for key, value in payload.items() if key != "model_environment"}
    record_review(root, legacy, *arguments)
    if different_payload:
        legacy["review"]["notes"] = ["Different evidence must never become a fresh legacy receipt"]
    target = root / "native-review.json"
    original_seal, original_exists = receipts._sealed_payload, Path.exists
    stale_exists_answer = [False]
    def seal_then_remove(*args, **kwargs):
        result = original_seal(*args, **kwargs)
        target.unlink()
        stale_exists_answer[0] = True
        return result
    def stale_first_exists(path):
        if path == target and stale_exists_answer[0]:
            stale_exists_answer[0] = False
            return True
        return original_exists(path)
    monkeypatch.setattr(receipts, "_sealed_payload", seal_then_remove)
    monkeypatch.setattr(Path, "exists", stale_first_exists)
    with pytest.raises(RuntimeError, match="missing or linked"):
        record_review(root, legacy, *arguments, target_profile=profile)
    assert not original_exists(target)
    assert not list(root.glob(".native-review-*.tmp"))


def test_profile_snapshot_cannot_be_supplied_or_overridden_in_caller_payload(environment_job):
    _, payload, profile, _ = environment_job
    payload["historical_target_profile"] = deepcopy(profile)
    with pytest.raises(ValueError, match="required fields"):
        record_environment(environment_job)


def test_unregistered_resealed_embedded_profile_fails_closed(environment_job):
    record_environment(environment_job)
    root, _, _, _ = environment_job
    path = root / "native-review.json"
    receipt = json.loads(path.read_text())
    receipt["historical_target_profile"]["opaf"]["build_id"] += 1
    receipt["receipt_sha256"] = canonical_hash({key: value for key, value in receipt.items() if key != "receipt_sha256"})
    path.write_text(json.dumps(receipt))
    with pytest.raises(ValueError, match="registered immutable snapshot"):
        verify_environment(environment_job)


def test_incomplete_v2_without_embedded_profile_is_never_backfilled(environment_job):
    record_environment(environment_job)
    root, _, _, _ = environment_job
    path = root / "native-review.json"
    receipt = json.loads(path.read_text())
    del receipt["historical_target_profile"]
    receipt["receipt_sha256"] = canonical_hash({key: value for key, value in receipt.items() if key != "receipt_sha256"})
    path.write_text(json.dumps(receipt)); before = path.read_bytes()
    with pytest.raises(ValueError, match="required fields"):
        verify_environment(environment_job)
    assert path.read_bytes() == before


def test_v2_uses_registered_historical_roles_not_current_caller_roles(environment_job):
    root, payload, profile, _ = environment_job
    receipt = record_environment(environment_job)
    assert verify_review(root, payload["candidate"], "new-mapper", "new-reviewer", "new-generator", "new-review-model",
                         target_profile={"not": "a historical input"}) == receipt
    assert verify_historical_model_environment(receipt) == profile
    assert "current_target_authorized" not in receipt


def test_known_historical_snapshot_survives_deployable_profile_rotation(environment_job, tmp_path, monkeypatch):
    import forms2apex.target_profile as profiles
    import shutil
    root, payload, old_profile, arguments = environment_job
    receipt = record_environment(environment_job)
    new_active = profiles.load_target_profile(Path(__file__).resolve().parents[2] /
                                              'deployment/target-profile.jsn-project-v2.json')
    new_digest = profiles.target_profile_sha256(new_active)
    monkeypatch.setattr(profiles, "_DEPLOYABLE_TARGET_PROFILES", {new_digest: new_active})
    assert verify_environment(environment_job, new_active) == receipt
    # Existing completed model work is replayed idempotently as historical
    # evidence, even after active settings rotate. No receipt is rewritten.
    assert record_review(root, payload, *arguments, target_profile=new_active) == receipt
    fresh = tmp_path / "fresh" / root.name
    fresh.mkdir(parents=True)
    shutil.copytree(root / "intake", fresh / "intake")
    with pytest.raises(ValueError):
        record_review(fresh, payload, *arguments, target_profile=old_profile)
    assert not (fresh / "native-review.json").exists()


def test_v1_forbids_invented_profile_and_observations(environment_job):
    root, payload, profile, arguments = environment_job
    legacy = {key: value for key, value in payload.items() if key != "model_environment"}
    receipt = record_review(root, legacy, *arguments)
    assert verify_historical_model_environment(receipt) is None
    receipt["historical_target_profile"] = profile
    receipt["receipt_sha256"] = canonical_hash({key: value for key, value in receipt.items() if key != "receipt_sha256"})
    with pytest.raises(ValueError): verify_historical_model_environment(receipt)


def test_v2_rejected_receipt_is_idempotent_evidence_but_never_approval(environment_job):
    root, payload, _, _ = environment_job
    payload["review"].update(verdict="reject", blocking_findings=["Synthetic candidate requires explicit correction"])
    receipt = record_environment(environment_job)
    path = root / "native-review.json"; before = path.read_bytes()
    assert record_environment(environment_job) == receipt
    assert path.read_bytes() == before
    with pytest.raises(ValueError, match="reviewer approval"):
        verify_environment(environment_job)
    payload["review"].update(verdict="approve", blocking_findings=[])
    with pytest.raises(ValueError, match="already exists"):
        record_environment(environment_job)
    assert path.read_bytes() == before
