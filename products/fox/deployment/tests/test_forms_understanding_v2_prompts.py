"""Static prompt contract and authored examples, NOT model/inference evidence."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from fox.forms_design_review import validate_design_review
from fox.forms_focus import build_focus_plan
from fox.forms_focus_merge import merge_focus_blueprints
from fox.forms_understanding_packet import local_packet


PROMPTS = Path(__file__).resolve().parents[1] / "prompts"
ARRAYS = ("objects", "screens", "claims", "relationships", "actions", "questions", "assumptions")
FACT_KINDS = ("object.kind", "object.name", "object.module_id", "object.block_id", "object.parent_id",
              "block.classification", "item.database_item", "item.item_type", "code.sha256",
              "code.bytes", "code.lines", "code.source_attribute", "code.execution_status")


def prompt(review=False):
    return (PROMPTS / ("forms-understanding-review-v2.txt" if review else
                       "forms-understanding-v2.txt")).read_text(encoding="utf-8")


def json_line(text):
    return next(json.loads(line) for line in text.splitlines() if line.startswith('{"'))


@pytest.mark.parametrize("review,limit", [(False, 4500), (True, 3500)])
def test_prompt_is_short_single_slot_and_additive(review, limit):
    text = prompt(review)
    assert 1500 < len(text) <= limit
    assert text.count("{{request}}") == 1
    assert "{{" not in text.replace("{{request}}", "")
    previous = (PROMPTS / ("forms-understanding-review-v1.txt" if review else
                           "forms-understanding-v1.txt")).read_text(encoding="utf-8")
    assert len(text) < len(previous)
    assert "v1" in previous


def test_exact_response_wrapper_and_row_contracts():
    text = prompt()
    response = json_line(text)
    assert set(response) == {"focus_id", "focus_binding", "blueprint"}
    blueprint = response["blueprint"]
    assert set(blueprint) == {"schema_version", "scope", "source_binding", *ARRAYS}
    assert type(blueprint["schema_version"]) is int and blueprint["schema_version"] == 1
    assert blueprint["scope"] == "fox-forms-blueprint-v1"
    assert all(blueprint[key] == [] for key in ARRAYS)
    expected = {
        "objects": {"source_object_id", "disposition", "reason"},
        "screens": {"id", "title"},
        "claims": {"id", "source_object_id", "kind", "value", "status", "evidence_refs", "reason"},
        "relationships/actions": {"id", "claim_ids"},
        "questions": {"id", "source_object_id", "text"},
        "assumptions": {"id", "text", "scope"},
    }
    decoder = json.JSONDecoder()
    for category, keys in expected.items():
        line = next(line for line in text.splitlines() if line.startswith(category + ":"))
        row, _ = decoder.raw_decode(line.split(": ", 1)[1])
        assert set(row) == keys
    for kind in FACT_KINDS:
        assert kind in text and kind in prompt(True)


def test_exact_review_receipt_and_trusted_hash_copy():
    text = prompt(True)
    receipt = json_line(text)
    assert set(receipt) == {"source_binding", "focus_binding", "candidate_sha256", "verdict", "findings"}
    assert set(receipt["findings"][0]) == {"source_object_id", "code", "detail"}
    assert receipt["verdict"] == "APPROVED|CHANGES_REQUIRED"
    assert "trusted hash" in text and "never calculate/repair" in text
    assert "empty findings" in text and "CHANGES_REQUIRED" in text


@pytest.mark.parametrize("review", [False, True])
def test_observed_v1_failure_classes_have_explicit_guidance(review):
    text = prompt(review)
    for term in ("BEHAVIOR_NOT_ASSESSED", "CODE_REQUIRES_REVIEW", "native_generation_allowed:false",
                 "NOT design", "behavior.intent", "transaction", "actions", "FormModule", "container",
                 "local absence", "partition", "global missing-file", "context", "prototype-only",
                 "ffdep1-", "fflink1-", "source_fact", "ALL", "chunks"):
        assert term in text
    assert "metadata" in text and "unresolved" in text
    assert all(term in text for term in ("database", "control", "unknown", "screen-", "omitted"))
    assert "512" in text and "32" in text and "2000" in text


@pytest.mark.parametrize("review", [False, True])
def test_behavior_interpretation_exempts_identifier_only_source_names(review):
    text = prompt(review).lower()
    for term in ("behavioral", "trigger", "programunit", "query", "filter", "behavior.intent"):
        assert term in text
    # Test the exemption's meaning, not a fixed full sentence or punctuation.
    clause = next(part for part in text.split(".") if "querydatasourcename" in part)
    assert "identifier-only" in clause and "metadata" in clause
    assert "not" in clause and "action" in clause


@pytest.mark.parametrize("review", [False, True])
def test_withheld_markers_are_unknown_not_business_constants(review):
    clause = next(line.lower() for line in prompt(review).splitlines() if "FOX_REDACTED_*" in line)
    assert all(term in clause for term in ("withheld", "values", "code", "unknown", "business constants"))
    assert "never" in clause and "not reconstruct" in clause


def authored_design(*, classification="database", body="selected", split=False):
    """Illustrate the permitted contract without pretending a model produced it."""
    flag = {"database": ' DatabaseBlock="true"', "control": ' DatabaseBlock="false"', "unknown": ""}[classification]
    code = '' if body == "missing" else ' TriggerText="UPDATE ORDERS SET STATUS=\'READY\' WHERE ORDER_ID=:B.ID; COMMIT_FORM;"'
    source = f'<FormModule Name="M"><Block Name="B"{flag} QueryDataSourceName="ORDERS"><Item Name="ID"/><Trigger Name="SAVE"{code}/></Block></FormModule>'.encode()
    documents = [("synthetic.xml", source)]
    packet = local_packet(documents)
    selected = {chunk["id"]: chunk["sha256"] for chunk in packet["chunks"]} if body == "selected" else {}
    plan = build_focus_plan(documents, expected_source_binding=packet["source_binding"],
                            approved_chunk_hashes=selected, max_owned_objects=1 if split else 250)
    block = next(row for entry in packet["sources"] for row in entry["facts"]["objects"] if row["kind"] == "Block")
    responses = []
    for request in plan["requests"]:
        blueprint = {"schema_version": 1, "scope": "fox-forms-blueprint-v1", "source_binding": plan["source_binding"],
                     **{key: [] for key in ARRAYS}}
        for source in request["owned_objects"]:
            row = {"source_object_id": source["id"], "disposition": "unresolved", "reason": "Retained container or explicit behavior gap."}
            if classification != "unknown" and (source["kind"] in ("Block", "Item") or
                                                source["kind"] == "Trigger" and body == "selected"):
                row.update(disposition="proposed", screen_id="screen-" + block["id"])
            if row["disposition"] == "proposed" and source["kind"] == "Block":
                row["native_component"] = "form" if classification == "database" else "page-items"
                blueprint["screens"].append({"id": row["screen_id"], "title": "Proposed UI"})
            blueprint["objects"].append(row)
            if source["kind"] == "Trigger" and body == "selected":
                unit = next(unit for unit in request["code_units"] if unit["owner_id"] == source["id"])
                claim_id = request["focus_id"] + "-claim-1"
                blueprint["claims"].append({"id": claim_id, "source_object_id": source["id"], "kind": "behavior.intent",
                    "value": "Proposes setting matching order status to READY using the current item value, then committing the form; target schema and transaction handling need review.",
                    "status": "proposal", "evidence_refs": [unit["id"]], "reason": "Interpretation of selected code only, not implementation."})
                blueprint["actions"].append({"id": request["focus_id"] + "-action-1", "claim_ids": [claim_id]})
        responses.append({"focus_id": request["focus_id"], "focus_binding": request["focus_binding"], "blueprint": blueprint})
    return documents, plan, responses


def test_identifier_source_metadata_does_not_need_behavior_action():
    documents, plan, responses = authored_design()
    units = {unit["id"]: unit for request in plan["requests"] for unit in request["code_units"]}
    # The current extractor retains an identifier-only source as a dependency,
    # not code; the prompt exemption also handles prebuilt metadata selections.
    assert {unit["source_attribute"] for unit in units.values()} == {"TriggerText"}
    assert sum(len(request["chunks"]) for request in plan["requests"]) == 1
    assert any(row["evidence"] == "property:QueryDataSourceName" and row["name"] == "ORDERS"
               for request in plan["requests"] for row in request["dependencies"])
    actions = [row for response in responses for row in response["blueprint"]["actions"]]
    claims = {row["id"]: row for response in responses for row in response["blueprint"]["claims"]}
    assert len(actions) == 1
    behavior = claims[actions[0]["claim_ids"][0]]
    assert behavior["kind"] == "behavior.intent"
    assert {units[ref]["source_attribute"] for ref in behavior["evidence_refs"]} == {"TriggerText"}
    assert merge_focus_blueprints(documents, plan, responses)["validation"]["structured_blueprint_valid"] is True


@pytest.mark.parametrize("classification", ["database", "control", "unknown"])
@pytest.mark.parametrize("body", ["selected", "unselected", "missing"])
@pytest.mark.parametrize("split", [False, True])
def test_authored_examples_use_unchanged_merge_and_receipt_contract(classification, body, split):
    documents, plan, responses = authored_design(classification=classification, body=body, split=split)
    result = merge_focus_blueprints(documents, plan, responses)
    assert result["validation"]["structured_blueprint_valid"] is True
    assert result["validation"]["accounted_objects"] == 4
    assert result["validation"]["proposed_objects"] == (0 if classification == "unknown" else 2 + int(body == "selected"))
    for key in ("generation_ready", "native_apex_generated", "native_apex_validity_verified", "import_verified", "business_behavior_accepted"):
        assert result["validation"][key] is False
    for request, candidate in zip(plan["requests"], responses, strict=True):
        digest = hashlib.sha256(json.dumps(candidate, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
        receipt = {"source_binding": request["source_binding"], "focus_binding": request["focus_binding"],
                   "candidate_sha256": digest, "verdict": "APPROVED", "findings": []}
        assert validate_design_review(request, candidate, receipt)["approved_structured_design"] is True


@pytest.mark.parametrize("fault", ["incompatible_mapping", "missing_body", "invented_fact", "context_owner", "extra_key"])
def test_unchanged_validator_rejects_contract_violations(fault):
    documents, plan, responses = authored_design(body="unselected" if fault == "missing_body" else "selected")
    responses = deepcopy(responses)
    response = next(row for row in responses if row["blueprint"]["screens"])
    blueprint = response["blueprint"]
    if fault == "incompatible_mapping":
        blueprint["objects"][0]["native_component"] = "page-items"
    elif fault == "missing_body":
        trigger = blueprint["objects"][-1]
        trigger.update(disposition="proposed", screen_id=blueprint["screens"][0]["id"])
    elif fault == "invented_fact":
        blueprint["claims"][0].update(status="source_fact", kind="database.primary_key", value="ID")
    elif fault == "context_owner":
        request = next(row for row in plan["requests"] if row["focus_id"] == response["focus_id"])
        blueprint["claims"][0]["source_object_id"] = request["context_objects"][0]["id"]
    else:
        blueprint["actions"][0]["sql"] = "not allowed"
    with pytest.raises(ValueError):
        merge_focus_blueprints(documents, plan, responses)
