"""Deterministic authored outputs, never actual OPAF/model acceptance evidence."""
from copy import deepcopy
import importlib.util
from pathlib import Path

import pytest

from fox.forms_focus import build_focus_plan
from fox.forms_understanding_packet import local_packet

_SPEC = importlib.util.spec_from_file_location(
    "forms_understanding_benchmark", Path(__file__).resolve().parents[1] / "forms_understanding_benchmark.py")
benchmark = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(benchmark)


def setup(index=0, *, propose=True):
    case = benchmark.build_cases()[index]
    packet = local_packet(case["documents"])
    plan = build_focus_plan(case["documents"], expected_source_binding=packet["source_binding"],
                            approved_chunk_hashes={row["id"]: row["sha256"] for row in packet["chunks"]})
    responses = []
    for request in plan["requests"]:
        blueprint = {"schema_version": 1, "scope": "fox-forms-blueprint-v1",
                     "source_binding": plan["source_binding"], "objects": [],
                     **{key: [] for key in ("screens", "claims", "relationships", "actions", "questions", "assumptions")}}
        screen = 'screen-' + request["focus_id"]
        for row in request["owned_objects"]:
            disposition = {"source_object_id": row["id"], "disposition": "unresolved", "reason": "Authored synthetic review needed."}
            if propose and index != 2 and row["kind"] in {"Block", "Item"}:
                disposition.update(disposition="proposed", screen_id=screen)
                if row["kind"] == "Block":
                    disposition["native_component"] = "form" if index == 0 else "page-items"
            blueprint["objects"].append(disposition)
            blueprint["claims"].append({"id": "claim-" + row["id"], "source_object_id": row["id"],
                                        "kind": "object.name", "value": row["name"], "status": "source_fact",
                                        "evidence_refs": [row["id"]], "reason": "Exact authored source name."})
            if row["kind"] == "Trigger":
                blueprint["questions"].append({"id": "question-" + row["id"], "source_object_id": row["id"],
                                               "text": "Please provide the missing definition or confirm intended behavior."})
        if any(row["disposition"] == "proposed" for row in blueprint["objects"]):
            blueprint["screens"].append({"id": screen, "title": "Synthetic prototype proposal"})
        responses.append({"focus_id": request["focus_id"], "focus_binding": request["focus_binding"], "blueprint": blueprint})
    return case, plan, responses


@pytest.mark.parametrize("index", range(3))
def test_small_public_cases_and_exact_authored_outputs(index):
    case, plan, responses = setup(index)
    before = deepcopy((case, plan, responses))
    assert len(plan["requests"]) == 2
    assert 5 <= plan["total_source_objects"] <= 8
    assert sum(chunk["bytes"] for request in plan["requests"] for chunk in request["chunks"]) < 2000
    assert "expected_labels" not in str(plan)
    result = benchmark.evaluate_case(case, plan, list(reversed(responses)))
    assert result["structured_pass"] and result["pass"] and result["safety_case_pass"]
    assert result["accounted"] == plan["total_source_objects"]
    assert result["source_fact_counts"]["validated"] == plan["total_source_objects"]
    assert result["expected_candidate_names_retained"]
    assert result["useful_design"] is (index != 2)
    assert result["native_block_mapping_proposal_coverage"] == (0.0 if index == 2 else 1.0)
    assert result["missing_input_questions_count"] == 1
    assert not any(result[key] for key in ("native_apex_generated", "generation_ready",
                                          "native_apex_validity_verified", "business_behavior_accepted",
                                          "semantic_correctness_verified"))
    assert (case, plan, responses) == before


def test_all_unresolved_is_not_useful_design():
    case, plan, responses = setup(propose=False)
    result = benchmark.evaluate_case(case, plan, responses)
    assert result["structured_pass"] and result["safety_case_pass"]
    assert not result["pass"] and not result["useful_design"]
    assert result["native_block_mapping_proposal_coverage"] == 0
    assert result["unresolved"] == result["accounted"]


@pytest.mark.parametrize("failure", ["changed-source", "stale", "omitted-focus", "omitted-object", "invented-fact", "wrong-component"])
def test_invalid_outputs_fail_closed(failure):
    case, plan, responses = setup(1)
    if failure == "changed-source":
        name, raw = case["documents"][0]
        case["documents"][0] = (name, raw.replace(b'SYN_FILTER', b'SYN_OTHER'))
    elif failure == "stale":
        responses[0]["focus_binding"] = "0" * 64
    elif failure == "omitted-focus":
        responses.pop()
    elif failure == "omitted-object":
        responses[-1]["blueprint"]["objects"].pop()
    elif failure == "invented-fact":
        responses[-1]["blueprint"]["claims"][0]["value"] = "INVENTED"
    else:
        next(row for row in responses[-1]["blueprint"]["objects"] if "native_component" in row)["native_component"] = "form"
    result = benchmark.evaluate_case(case, plan, responses)
    assert not result["structured_pass"] and not result["pass"]
    assert result["safety_failure_issues"]
    assert result["source_fact_counts"]["validated"] == 0


@pytest.mark.parametrize("kind", ["Block", "Item", "Trigger"])
def test_unknown_block_or_missing_body_cannot_be_proposed(kind):
    case, plan, responses = setup(2)
    request = plan["requests"][-1]
    blueprint = responses[-1]["blueprint"]
    source = next(row for row in request["owned_objects"] if row["kind"] == kind)
    row = next(row for row in blueprint["objects"] if row["source_object_id"] == source["id"])
    blueprint["screens"] = [{"id": "invalid-screen", "title": "Invalid proposal"}]
    row.update(disposition="proposed", screen_id="invalid-screen")
    if kind == "Block":
        row["native_component"] = "form"
    result = benchmark.evaluate_case(case, plan, responses)
    assert not result["structured_pass"] and result["safety_failure_issues"]


def test_fresh_case_returns_do_not_share_mutable_labels():
    first = benchmark.build_cases()
    first[0]["expected_labels"]["candidate_dependency_names"].append("not-public-input")
    assert "not-public-input" not in str(benchmark.build_cases())


def test_explicit_unknown_omissions_are_safe_but_not_useful():
    case, plan, responses = setup(2)
    for response in responses:
        for row in response["blueprint"]["objects"]:
            row["disposition"] = "omitted"
    result = benchmark.evaluate_case(case, plan, responses)
    assert result["pass"] and result["safety_case_pass"]
    assert result["omitted"] == result["accounted"]
    assert not result["useful_design"]


def test_database_block_cannot_use_control_component():
    case, plan, responses = setup()
    next(row for row in responses[-1]["blueprint"]["objects"] if "native_component" in row)["native_component"] = "page-items"
    result = benchmark.evaluate_case(case, plan, responses)
    assert not result["structured_pass"] and result["safety_failure_issues"]
