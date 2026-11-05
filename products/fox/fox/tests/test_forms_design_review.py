"""Synthetic structured receipts, not actual reviewer invocation/Oracle proof."""
from copy import deepcopy
import hashlib
import json
import traceback

import pytest

from fox import forms_design_review as receipts
from fox.forms_focus import build_focus_plan
from fox.forms_focus_merge import merge_focus_blueprints
from fox.forms_understanding_packet import local_packet


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


def reseal(request):
    request["focus_binding"] = digest({key: value for key, value in request.items() if key != "focus_binding"})


@pytest.fixture
def sample():
    documents = [("synthetic.xml", b'<FormModule Name="A"><Block Name="B" DatabaseBlock="true">'
                  b'<Item Name="I"/><Trigger Name="T" TriggerText="BEGIN NULL; END;"/>'
                  b'</Block></FormModule>')]
    packet = local_packet(documents)
    plan = build_focus_plan(documents, expected_source_binding=packet["source_binding"], approved_chunk_hashes={})
    request = next(row for row in plan["requests"] if row["context_objects"])
    candidate = {"focus_id": request["focus_id"], "focus_binding": request["focus_binding"],
                 "blueprint": {"schema_version": 1, "scope": "fox-forms-blueprint-v1",
                               "source_binding": request["source_binding"],
                               "objects": [{"source_object_id": row["id"], "disposition": "unresolved",
                                            "reason": "Prototype needs source-owner review, not conversion."}
                                           for row in request["owned_objects"]],
                               **{key: [] for key in ("screens", "claims", "relationships", "actions", "questions", "assumptions")}}}
    review = {"source_binding": request["source_binding"], "focus_binding": request["focus_binding"],
              "candidate_sha256": digest(candidate), "verdict": "APPROVED", "findings": []}
    return request, candidate, review


def changes(request, candidate, *, owner=None):
    return {"source_binding": request["source_binding"], "focus_binding": request["focus_binding"],
            "candidate_sha256": digest(candidate), "verdict": "CHANGES_REQUIRED", "findings": [
                {"source_object_id": owner, "code": "MISSING_BODY", "detail": "Supply the complete body or retain unresolved behavior."}]}


def test_approved_receipt_summary_is_narrow_exact_and_does_not_mutate(sample):
    request, candidate, review = sample
    before = deepcopy(sample)
    result = receipts.validate_design_review(*sample)
    assert result == {"verdict": "APPROVED", "candidate_sha256": digest(candidate),
                      "source_binding": request["source_binding"], "focus_binding": request["focus_binding"],
                      "approved_structured_design": True, "generation_ready": False,
                      "native_apex_generated": False, "native_apex_validity_verified": False,
                      "import_verified": False, "business_behavior_accepted": False}
    assert sample == before
    assert "findings" not in result and "candidate" not in result


@pytest.mark.parametrize("global_finding", [False, True])
def test_missing_body_rejection_receipt_is_valid_but_not_approved(sample, global_finding):
    request, candidate, _ = sample
    trigger = next(row for row in request["owned_objects"] if row["kind"] == "Trigger")
    assert request["unselected_code_unit_ids"] and not request["chunks"]
    review = changes(request, candidate, owner=None if global_finding else trigger["id"])
    result = receipts.validate_design_review(request, candidate, review)
    assert result["verdict"] == "CHANGES_REQUIRED"
    assert result["approved_structured_design"] is False
    assert all(result[key] is False for key in ("generation_ready", "native_apex_generated", "import_verified", "business_behavior_accepted"))


def test_hash_is_sorted_compact_utf8_not_ascii_escaped_or_insertion_order(sample):
    request, candidate, review = sample
    candidate["blueprint"]["objects"][0]["reason"] = "évidence 日本語"
    review["candidate_sha256"] = digest(candidate)
    reversed_candidate = dict(reversed(list(candidate.items())))
    assert receipts.validate_design_review(request, reversed_candidate, review)["candidate_sha256"] == digest(candidate)
    escaped = json.dumps(candidate, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    review["candidate_sha256"] = hashlib.sha256(escaped).hexdigest()
    with pytest.raises(ValueError):
        receipts.validate_design_review(request, candidate, review)


@pytest.mark.parametrize("target,field", [("request", "source_binding"), ("request", "focus_binding"),
                                         ("candidate", "focus_binding"), ("candidate", "focus_id"),
                                         ("blueprint", "source_binding"), ("review", "source_binding"),
                                         ("review", "focus_binding"), ("review", "candidate_sha256")])
def test_stale_or_tampered_identity_is_rejected(sample, target, field):
    request, candidate, review = sample
    row = {"request": request, "candidate": candidate, "blueprint": candidate["blueprint"], "review": review}[target]
    row[field] = "0" * 64
    with pytest.raises(ValueError):
        receipts.validate_design_review(*sample)


def test_candidate_tampering_invalidates_retained_review_hash(sample):
    sample[1]["blueprint"]["objects"][0]["reason"] = "Changed after review."
    with pytest.raises(ValueError):
        receipts.validate_design_review(*sample)


@pytest.mark.parametrize("target", ["request", "candidate", "blueprint", "review", "finding"])
def test_envelopes_reject_extra_keys(sample, target):
    request, candidate, review = sample
    if target == "finding":
        review = changes(request, candidate)
    row = {"request": request, "candidate": candidate, "blueprint": candidate["blueprint"],
           "review": review, "finding": review.get("findings", [])}[target]
    if target == "finding":
        row = row[0]
    row["native_apex_generated"] = True
    if target == "request":
        reseal(request)
    with pytest.raises(ValueError):
        receipts.validate_design_review(request, candidate, review)


@pytest.mark.parametrize("field", ["source_binding", "focus_binding", "candidate_sha256", "verdict", "findings"])
def test_receipt_requires_every_field(sample, field):
    sample[2].pop(field)
    with pytest.raises(ValueError):
        receipts.validate_design_review(*sample)


@pytest.mark.parametrize("verdict,findings", [("APPROVED", True), ("CHANGES_REQUIRED", False), (True, False), ("OTHER", False)])
def test_verdict_and_findings_must_agree(sample, verdict, findings):
    request, candidate, review = sample
    if findings:
        review.update(changes(request, candidate))
    review["verdict"] = verdict
    with pytest.raises(ValueError):
        receipts.validate_design_review(*sample)


@pytest.mark.parametrize("bad_owner", ["unknown", "context", True, 1, [], {}])
def test_findings_only_reference_owned_source_objects_or_null(sample, bad_owner):
    request, candidate, _ = sample
    if bad_owner == "context":
        bad_owner = request["context_objects"][0]["id"]
    review = changes(request, candidate, owner=bad_owner)
    with pytest.raises(ValueError):
        receipts.validate_design_review(request, candidate, review)


@pytest.mark.parametrize("category", ["objects", "claims", "questions"])
def test_candidate_source_ownership_does_not_transfer_from_context(sample, category):
    request, candidate, review = sample
    ref = request["context_objects"][0]["id"]
    if category == "objects":
        candidate["blueprint"][category][0]["source_object_id"] = ref
    elif category == "claims":
        candidate["blueprint"][category] = [{"id": "claim-1", "source_object_id": ref, "kind": "meaning",
            "value": "proposal", "status": "proposal", "evidence_refs": [ref], "reason": "Prototype only."}]
    else:
        candidate["blueprint"][category] = [{"id": "question-1", "source_object_id": ref, "text": "Provide evidence."}]
    review["candidate_sha256"] = digest(candidate)
    with pytest.raises(ValueError):
        receipts.validate_design_review(*sample)


@pytest.mark.parametrize("operation", ["drop", "duplicate"])
def test_candidate_accounts_for_exact_owned_rows(sample, operation):
    rows = sample[1]["blueprint"]["objects"]
    if operation == "drop":
        rows.pop()
    else:
        rows.append(deepcopy(rows[0]))
    sample[2]["candidate_sha256"] = digest(sample[1])
    with pytest.raises(ValueError):
        receipts.validate_design_review(*sample)


@pytest.mark.parametrize("target", ["request", "blueprint"])
@pytest.mark.parametrize("field,value", [("schema_version", True), ("schema_version", 2), ("scope", "wrong")])
def test_schema_scope_and_boolean_integer_are_strict(sample, target, field, value):
    request, candidate, review = sample
    row = request if target == "request" else candidate["blueprint"]
    row[field] = value
    if target == "request":
        reseal(request)
        candidate["focus_binding"] = review["focus_binding"] = request["focus_binding"]
    review["candidate_sha256"] = digest(candidate)
    with pytest.raises(ValueError):
        receipts.validate_design_review(*sample)


@pytest.mark.parametrize("value", [{"sql": "BEGIN payload; END;"}, [["nested"]], 1.5, float("nan"), b"bytes", object()])
def test_arbitrary_nested_or_non_json_claim_payloads_fail_closed(sample, value):
    request, candidate, review = sample
    ref = request["owned_objects"][0]["id"]
    candidate["blueprint"]["claims"] = [{"id": "claim-1", "source_object_id": ref, "kind": "meaning", "value": value,
        "status": "proposal", "evidence_refs": [ref], "reason": "Prototype only."}]
    with pytest.raises(ValueError):
        receipts.validate_design_review(*sample)


@pytest.mark.parametrize("value", [None, True, 1, "proposal", [None, False, 2, "proposal"]])
def test_published_claim_scalar_types_are_supported(sample, value):
    request, candidate, review = sample
    ref = request["owned_objects"][0]["id"]
    candidate["blueprint"]["claims"] = [{"id": "claim-1", "source_object_id": ref, "kind": "meaning", "value": value,
        "status": "proposal", "evidence_refs": [ref], "reason": "Prototype only."}]
    review["candidate_sha256"] = digest(candidate)
    assert receipts.validate_design_review(*sample)["approved_structured_design"] is True


@pytest.mark.parametrize("category", ["objects", "screens", "claims", "relationships", "actions", "questions", "assumptions"])
def test_candidate_collections_must_be_arrays(sample, category):
    sample[1]["blueprint"][category] = {}
    sample[2]["candidate_sha256"] = digest(sample[1])
    with pytest.raises(ValueError):
        receipts.validate_design_review(*sample)


@pytest.mark.parametrize("category", ["objects", "screens", "claims", "relationships", "actions", "questions", "assumptions"])
def test_every_candidate_row_rejects_unpublished_executable_fields(sample, category):
    request, candidate, review = sample
    ref = request["owned_objects"][0]["id"]
    rows = {"objects": deepcopy(candidate["blueprint"]["objects"][0]),
            "screens": {"id": "screen-1", "title": "Prototype"},
            "claims": {"id": "claim-1", "source_object_id": ref, "kind": "meaning", "value": "proposal",
                       "status": "proposal", "evidence_refs": [ref], "reason": "Prototype only."},
            "relationships": {"id": "relationship-1", "claim_ids": ["claim-1"]},
            "actions": {"id": "action-1", "claim_ids": ["claim-1"]},
            "questions": {"id": "question-1", "source_object_id": ref, "text": "Provide evidence."},
            "assumptions": {"id": "assumption-1", "text": "Prototype only.", "scope": "prototype-only"}}
    row = rows[category]
    row["sql"] = "BEGIN DO_NOT_EXECUTE; END;"
    if category == "objects":
        candidate["blueprint"][category][0] = row
    else:
        candidate["blueprint"][category] = [row]
    review["candidate_sha256"] = digest(candidate)
    with pytest.raises(ValueError):
        receipts.validate_design_review(*sample)


@pytest.mark.parametrize("field,value", [("code", ""), ("code", "not a stable code"), ("code", "x" * 101),
                                        ("code", []), ("detail", ""), ("detail", "control\x00"), ("detail", {})])
def test_finding_code_and_detail_are_bounded_text(sample, field, value):
    request, candidate, _ = sample
    review = changes(request, candidate)
    review["findings"][0][field] = value
    with pytest.raises(ValueError):
        receipts.validate_design_review(request, candidate, review)


@pytest.mark.parametrize("mutation", ["stale-content", "empty-owned", "duplicate-owned", "context-overlap", "bool-safety"])
def test_request_binding_ownership_and_safety_are_strict(sample, mutation):
    request, candidate, review = sample
    if mutation == "stale-content":
        request["owned_objects"][0]["name"] = "Changed since request was sealed."
    elif mutation == "empty-owned":
        request["owned_objects"] = []
    elif mutation == "duplicate-owned":
        request["owned_objects"].append(deepcopy(request["owned_objects"][0]))
    elif mutation == "context-overlap":
        request["context_objects"].append(deepcopy(request["owned_objects"][0]))
    else:
        request["safety"]["native_generation_allowed"] = 0
    if mutation != "stale-content":
        reseal(request)
        candidate["focus_binding"] = review["focus_binding"] = request["focus_binding"]
        review["candidate_sha256"] = digest(candidate)
    with pytest.raises(ValueError):
        receipts.validate_design_review(*sample)


@pytest.mark.parametrize("where", ["request", "candidate", "review", "detail", "count", "depth", "cycle"])
def test_documents_findings_and_nesting_are_bounded(sample, where):
    request, candidate, review = sample
    if where == "request":
        request["owned_objects"][0]["name"] = "é" * receipts.MAX_REQUEST_BYTES
    elif where == "candidate":
        candidate["blueprint"]["objects"][0]["reason"] = "é" * receipts.MAX_CANDIDATE_BYTES
    elif where == "review":
        review["findings"] = [{"detail": "é" * receipts.MAX_REVIEW_BYTES}]
    elif where in ("detail", "count"):
        review.update(changes(request, candidate))
        if where == "detail":
            review["findings"][0]["detail"] = "x" * 2001
        else:
            review["findings"] *= receipts.MAX_FINDINGS + 1
    elif where == "depth":
        value = []
        for _ in range(22):
            value = [value]
        candidate["blueprint"]["claims"] = value
    else:
        candidate["blueprint"]["claims"].append(candidate)
    with pytest.raises(ValueError):
        receipts.validate_design_review(*sample)


def test_errors_do_not_reflect_source_receipt_or_encoding_failures(sample):
    secret = "synthetic-private-password-not-for-errors"
    sample[1]["blueprint"]["objects"][0]["reason"] = secret + "\ud800"
    with pytest.raises(ValueError) as raised:
        receipts.validate_design_review(*sample)
    assert str(raised.value) == "Invalid source-bound design review receipt."
    formatted = "".join(traceback.format_exception(raised.type, raised.value, raised.tb))
    assert secret not in formatted and "UnicodeEncodeError" not in formatted


def test_receipt_approval_cannot_bypass_complete_fresh_merge(sample):
    # Receipt validation is not the G1 semantic checklist: it cannot prove source
    # authenticity or judge missing code. Fresh complete merge remains the gate.
    request, candidate, review = sample
    trigger = next(row for row in request["owned_objects"] if row["kind"] == "Trigger")
    row = next(row for row in candidate["blueprint"]["objects"] if row["source_object_id"] == trigger["id"])
    row.update(disposition="proposed", screen_id="screen-placeholder")
    review["candidate_sha256"] = digest(candidate)
    assert receipts.validate_design_review(*sample)["approved_structured_design"] is True
    documents = [("synthetic.xml", b'<FormModule Name="DIFFERENT"/>')]
    packet = local_packet(documents)
    plan = build_focus_plan(documents, expected_source_binding=packet["source_binding"], approved_chunk_hashes={})
    with pytest.raises(ValueError):
        merge_focus_blueprints(documents, plan, [candidate])


def test_even_an_approved_receipt_does_not_bypass_unsupplied_body_merge_gate():
    documents = [("synthetic.xml", b'<FormModule Name="A"><Trigger Name="T" TriggerText="BEGIN NULL; END;"/></FormModule>')]
    packet = local_packet(documents)
    plan = build_focus_plan(documents, expected_source_binding=packet["source_binding"], approved_chunk_hashes={})
    request = plan["requests"][0]
    trigger = next(row for row in request["owned_objects"] if row["kind"] == "Trigger")
    candidate = {"focus_id": request["focus_id"], "focus_binding": request["focus_binding"],
                 "blueprint": {"schema_version": 1, "scope": "fox-forms-blueprint-v1",
                               "source_binding": request["source_binding"],
                               "objects": [{"source_object_id": row["id"], "disposition": "unresolved", "reason": "Needs review."}
                                           for row in request["owned_objects"]],
                               "screens": [{"id": "screen-1", "title": "Prototype"}],
                               **{key: [] for key in ("claims", "relationships", "actions", "questions", "assumptions")}}}
    next(row for row in candidate["blueprint"]["objects"] if row["source_object_id"] == trigger["id"]).update(
        disposition="proposed", screen_id="screen-1")
    review = {"source_binding": request["source_binding"], "focus_binding": request["focus_binding"],
              "candidate_sha256": digest(candidate), "verdict": "APPROVED", "findings": []}
    assert receipts.validate_design_review(request, candidate, review)["approved_structured_design"] is True
    with pytest.raises(ValueError, match="exact complete source code"):
        merge_focus_blueprints(documents, plan, [candidate])
