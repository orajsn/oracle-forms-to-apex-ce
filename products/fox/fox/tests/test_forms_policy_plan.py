"""Synthetic complete-source policy acceptance; no Oracle/runtime claims."""
from copy import deepcopy
import xml.etree.ElementTree as ET

import pytest

from fox.forms_policy_plan import build_policy_plan
from fox.forms_understanding_packet import _build
from fox.forms_behavior_plan import _source_objects
from forms2apex.native_policy_rules import render_policy_code, _canonical, _sha


def source(text=None, procedure=None, module="EXAMPLE", kind="Char"):
    root = ET.Element("Module", xmlns="http://xmlns.oracle.com/Forms")
    form = ET.SubElement(root, "FormModule", Name=module)
    block = ET.SubElement(form, "Block", Name="ROWS", DatabaseBlock="true")
    for name in ("APPROVED", "ORIGIN", "DEST", "FLAG"):
        ET.SubElement(block, "Item", Name=name, DatabaseItem="true", DataType=kind, MaximumLength="40")
    if text is not None:
        ET.SubElement(block, "Trigger", Name="WHEN-NEW-RECORD-INSTANCE", TriggerText=text)
    if procedure is not None:
        ET.SubElement(form, "ProgramUnit", Name="APPLY_POLICY", ProgramUnitType="Procedure", ProgramUnitText=procedure)
    return ET.tostring(root)


def context(docs=None):
    docs = docs or [("example.xml", source("IF :ORIGIN=:DEST THEN :FLAG:='N'; END IF;"))]
    packet, _ = _build(docs)
    objects, metadata = _source_objects(docs, packet)
    trace = {"source_binding": packet["source_binding"], "blocks": []}
    for block in (obj for obj in objects.values() if obj["kind"] == "Block"):
        trace["blocks"].append({"source_block_id": block["id"], "source_module_id": block["module_id"],
            "name": block["name"], "classification": block["classification"], "items": [
            {"source_item_id": item["id"], "source_name": item["name"], "column": "C_" + item["name"],
             "data_type": {"Char": "VARCHAR2", "Number": "NUMBER", "Date": "DATE"}.get(metadata[item["id"]].get("DataType"), "VARCHAR2"),
             "database_bound": True, "value_computation_implemented": False}
            for item in objects.values() if item["kind"] == "Item" and item["block_id"] == block["id"]]})
    return docs, trace


def plan_for(text=None, procedure=None):
    return build_policy_plan(*context([("example.xml", source(text, procedure))]))


def seal(plan):
    plan["plan_sha256"] = _sha(_canonical({k: v for k, v in plan.items() if k != "plan_sha256"}))
    return plan


def test_whole_conditional_assignment_has_bound_types_and_no_conversion_claim():
    args = context()
    before = deepcopy(args)
    plan = build_policy_plan(*args)
    sql, receipt = render_policy_code(plan)
    assert args == before
    assert plan == build_policy_plan(*args)
    assert len(plan["operations"]) == len(plan["coverage"]) == 1
    op = plan["operations"][0]
    assert {field["data_type"] for field in op["fields"].values()} == {"VARCHAR2"}
    assert " ELSE" not in sql and "IN OUT VARCHAR2" in sql
    assert "text_value := p_f" in sql
    assert op["source_parent_id"] and op["source_module_id"]
    assert receipt["converted_code_unit_count"] == 0
    assert all(row["not_yet_converted"] and row["status"] == "unsupported" for row in plan["coverage"])
    assert all(not receipt[k] for k in ("native_generated", "event_activated", "oracle_compiled", "runtime_verified", "business_accepted"))


def test_complete_default_resets_conditional_override_and_local_wrapper():
    text = """PROCEDURE APPLY_POLICY IS BEGIN
    SET_BLOCK_PROPERTY('ROWS',INSERT_ALLOWED,PROPERTY_TRUE);
    SET_ITEM_PROPERTY('ROWS.FLAG',ENABLED,PROPERTY_TRUE);
    IF :APPROVED IS NOT NULL AND :APPROVED='Y' THEN
      SET_BLOCK_PROPERTY('ROWS',INSERT_ALLOWED,PROPERTY_FALSE);
      SET_ITEM_PROPERTY('FLAG',ENABLED,PROPERTY_FALSE);
    END IF; END APPLY_POLICY;"""
    plan = plan_for("APPLY_POLICY;", text)
    assert len(plan["operations"]) == 2
    caller, callee = plan["operations"]
    assert caller["body"][0]["kind"] == "local_call"
    assert caller["body"][0]["body"] == callee["body"]
    assert caller["local_calls"][0]["source_unit_id"] == callee["source_unit_id"]
    assert [row["value"] for row in callee["body"][:2]] == [True, True]
    assert [row["value"] for row in callee["body"][2]["body"]] == [False, False]
    sql, receipt = render_policy_code(plan)
    assert sql.count("boolean_value := TRUE;") == 4
    assert sql.count("boolean_value := FALSE;") == 4
    assert receipt["converted_code_unit_count"] == 0


def test_warning_only_status_input_and_failure_guard_stay_distinct():
    warning = "IF :ORIGIN IS NULL AND :SYSTEM.FORM_STATUS<>'QUERY' THEN MESSAGE('A warning'); MESSAGE('A warning'); END IF;"
    guard = "PROCEDURE APPLY_POLICY IS BEGIN IF NOT (FORM_SUCCESS) THEN RAISE FORM_TRIGGER_FAILURE; END IF; END;"
    plan = plan_for(warning, guard)
    sql, receipt = render_policy_code(plan)
    assert len(plan["operations"]) == 2
    assert plan["operations"][0]["fields"]["intrinsic:FORM_STATUS"]["provider"] == "required_source_form_status_snapshot"
    assert plan["operations"][1]["fields"]["intrinsic:FORM_SUCCESS"]["data_type"] == "BOOLEAN"
    assert sql.count("effect_kind := 'warning';") == 2
    assert sql.count("effect_kind := 'failure';") == 1
    assert sql.count("RETURN;") == 1
    assert "RAISE " not in sql and "FORM_TRIGGER_FAILURE" not in sql
    assert all(row["generation_status"] == "generated_unwired" for row in receipt["generated_operations"])


@pytest.mark.parametrize("tail", ["COMMIT;", "NULL;", "GO_BLOCK('ROWS');", "EXECUTE_QUERY;", "SELECT 1 INTO :FLAG FROM DUAL;",
    "UPDATE T SET C=1;", "RAISE OTHER_EXCEPTION;", "WHILE TRUE LOOP NULL; END LOOP;", "UNKNOWN;", "EXCEPTION WHEN OTHERS THEN NULL;"])
def test_supported_prefix_never_hides_additional_unsupported_behavior(tail):
    plan = plan_for("BEGIN IF :ORIGIN=:DEST THEN :FLAG:='N'; END IF; " + tail + " END;")
    assert plan["operations"] == []
    assert len(plan["coverage"]) == 1 and plan["coverage"][0]["reason"]


@pytest.mark.parametrize("change", ["name", "type", "module", "duplicate", "column", "computed", "formula", "source_type"])
def test_source_metadata_and_trace_tampering_block_encoding(change):
    docs, trace = context()
    if change == "formula" or change == "source_type":
        root = ET.fromstring(docs[0][1])
        item = next(node for node in root.iter() if node.get("Name") == "ORIGIN")
        item.set("Formula", "1+1") if change == "formula" else item.set("DataType", "Date")
        docs, trace = context([("example.xml", ET.tostring(root))])
    else:
        block, field = trace["blocks"][0], trace["blocks"][0]["items"][1]
        if change == "name": field["source_name"] = "OTHER"
        if change == "type": field["data_type"] = "NUMBER"
        if change == "module": block["source_module_id"] = "ff1-" + "0" * 24
        if change == "duplicate": block["items"].append(deepcopy(field))
        if change == "column": field["column"] = "X); COMMIT;"
        if change == "computed": field["value_computation_implemented"] = True
    assert build_policy_plan(docs, trace)["operations"] == []


def test_source_binding_mismatch_is_hard_error():
    docs, trace = context()
    trace["source_binding"] = "0" * 64
    with pytest.raises(ValueError, match="TRACE_BINDING"):
        build_policy_plan(docs, trace)


def test_document_reordering_preserves_plan_and_review_bytes_for_multiple_modules():
    docs = [("two.xml", source("MESSAGE('second');", module="SECOND")),
            ("one.xml", source("MESSAGE('first');", module="FIRST"))]
    documents, trace = context(docs)
    plan = build_policy_plan(documents, trace)
    reversed_plan = build_policy_plan(list(reversed(documents)), trace)
    assert plan == reversed_plan
    assert render_policy_code(plan) == render_policy_code(reversed_plan)


@pytest.mark.parametrize("procedure", [
    "PROCEDURE APPLY_POLICY IS BEGIN APPLY_POLICY; END;",
    "PROCEDURE OTHER IS BEGIN MESSAGE('warning'); END;",
    "PROCEDURE APPLY_POLICY IS BEGIN MESSAGE('warning'); GO_BLOCK('ROWS'); END;",
    "PROCEDURE APPLY_POLICY IS BEGIN REMOTE_PROC; END;",
])
def test_local_wrapper_requires_whole_name_bound_nonrecursive_pure_callee(procedure):
    plan = plan_for("APPLY_POLICY;", procedure)
    assert plan["operations"] == []
    assert len(plan["coverage"]) == 2


def test_identically_named_callee_from_another_module_cannot_resolve():
    docs = [("one.xml", source("APPLY_POLICY;", module="ONE")),
            ("two.xml", source(procedure="PROCEDURE APPLY_POLICY IS BEGIN MESSAGE('warning'); END;", module="TWO"))]
    plan = build_policy_plan(*context(docs))
    assert len(plan["operations"]) == 1
    assert plan["coverage"][0]["reason"] == "policy_same_module_local_call_body_not_proven"


def test_duplicates_and_wrong_owner_scope_do_not_create_implicit_field_bindings():
    root = ET.fromstring(source(procedure="PROCEDURE APPLY_POLICY IS BEGIN IF :ORIGIN=:DEST THEN :FLAG:='N'; END IF; END;"))
    form = next(node for node in root.iter() if node.tag.endswith("FormModule"))
    block = next(node for node in root.iter() if node.tag.endswith("Block"))
    other = deepcopy(block)
    other.set("Name", "OTHER_ROWS")
    form.append(other)
    plan = build_policy_plan(*context([("ambiguous.xml", ET.tostring(root))]))
    assert plan["operations"] == []


def test_unique_cross_block_inputs_are_explicit_source_buffer_dependencies():
    root = ET.fromstring(source("IF :ORIGIN=:REMOTE THEN :FLAG:='N'; END IF;"))
    ns = "{http://xmlns.oracle.com/Forms}"
    form = next(node for node in root.iter() if node.tag.endswith("FormModule"))
    other = ET.SubElement(form, ns + "Block", Name="OTHER_ROWS", DatabaseBlock="true")
    ET.SubElement(other, ns + "Item", Name="REMOTE", DataType="Char", DatabaseItem="true")
    plan = build_policy_plan(*context([("cross.xml", ET.tostring(root))]))
    assert len(plan["operations"]) == 1
    fields = list(plan["operations"][0]["fields"].values())
    assert len({row["source_block_id"] for row in fields}) == 2
    assert {row["provider"] for row in fields} == {"required_source_record_buffer_snapshot"}


def test_source_proven_button_property_is_encoded_with_missing_target_effect_binding():
    docs, trace = context([("button.xml", source("SET_ITEM_PROPERTY('FLAG',ENABLED,PROPERTY_FALSE);"))])
    trace["blocks"][0]["items"] = [row for row in trace["blocks"][0]["items"] if row["source_name"] != "FLAG"]
    plan = build_policy_plan(docs, trace)
    assert len(plan["operations"]) == 1
    target, = plan["operations"][0]["property_targets"].values()
    assert target["native_item"] is None
    assert target["target_effect_binding"] == "required_unimplemented"
    assert render_policy_code(plan)[1]["converted_code_unit_count"] == 0


@pytest.mark.parametrize("unit", ["MESSAGE('earlier'); IF NOT FORM_SUCCESS THEN RAISE FORM_TRIGGER_FAILURE; END IF;",
    "IF NOT FORM_SUCCESS THEN RAISE FORM_TRIGGER_FAILURE; END IF; MESSAGE('later');",
    "SET_BLOCK_PROPERTY('ROWS',INSERT_ALLOWED,PROPERTY_TRUE); IF NOT FORM_SUCCESS THEN RAISE FORM_TRIGGER_FAILURE; END IF;",
    "IF :SYSTEM.FORM_STATUS='QUERY' THEN :FLAG:='N'; END IF;"])
def test_intrinsic_snapshots_cannot_mask_status_changes_from_other_operations(unit):
    plan = plan_for(unit)
    assert plan["operations"] == []
    assert "requires" in plan["coverage"][0]["reason"]


def test_failure_from_inlined_wrapper_terminates_caller_preserving_prior_effects():
    guard = "PROCEDURE APPLY_POLICY IS BEGIN IF :APPROVED='Y' THEN MESSAGE('before'); RAISE FORM_TRIGGER_FAILURE; END IF; END;"
    plan = plan_for("MESSAGE('first'); APPLY_POLICY; MESSAGE('last');", guard)
    caller = plan["operations"][0]
    assert [node["kind"] for node in caller["body"]] == ["warning", "local_call", "warning"]
    sql, receipt = render_policy_code(plan)
    caller_sql = sql.split("CREATE OR REPLACE PACKAGE BODY", 1)[1].split("END " + receipt["generated_operations"][0]["procedure_name"])[0]
    assert caller_sql.index("'first'") < caller_sql.index("'before'") < caller_sql.index("RETURN;") < caller_sql.index("'last'")
    assert "RAISE " not in caller_sql


def test_mutual_local_call_cycle_is_blocked_for_every_caller():
    root = ET.fromstring(source("APPLY_POLICY;", "PROCEDURE APPLY_POLICY IS BEGIN OTHER_POLICY; END;"))
    ns = "{http://xmlns.oracle.com/Forms}"
    form = next(node for node in root.iter() if node.tag.endswith("FormModule"))
    ET.SubElement(form, ns + "ProgramUnit", Name="OTHER_POLICY", ProgramUnitType="Procedure",
                  ProgramUnitText="PROCEDURE OTHER_POLICY IS BEGIN APPLY_POLICY; END;")
    plan = build_policy_plan(*context([("cycle.xml", ET.tostring(root))]))
    assert plan["operations"] == []
    assert len(plan["coverage"]) == 3
    assert {row["reason"] for row in plan["coverage"]} == {"policy_recursive_local_call"}


@pytest.mark.parametrize("change", ["different_type", "literal_type", "intrinsic_target", "global", "missing_type"])
def test_scalar_type_or_context_mismatch_never_uses_implicit_coercion(change):
    text = {"different_type": "IF :ORIGIN=:DEST THEN :FLAG:='N'; END IF;", "literal_type": ":FLAG:=1;",
            "intrinsic_target": ":SYSTEM.FORM_STATUS:='QUERY';", "global": "IF :GLOBAL.X='Y' THEN :FLAG:='N'; END IF;",
            "missing_type": ":FLAG:='N';"}[change]
    root = ET.fromstring(source(text))
    if change == "different_type": next(node for node in root.iter() if node.get("Name") == "DEST").set("DataType", "Number")
    if change == "missing_type": next(node for node in root.iter() if node.get("Name") == "FLAG").attrib.pop("DataType")
    # The fixture target guesses VARCHAR2 if source DataType is absent; the
    # source-bound planner must still reject that guess.
    plan = build_policy_plan(*context([("types.xml", ET.tostring(root))]))
    assert plan["operations"] == []


def test_output_is_pure_synthetic_identifiers_and_escaped_literal_data():
    text = "MESSAGE('O''Brien; COMMIT; -- data');"
    plan = plan_for(text)
    sql, receipt = render_policy_code(plan)
    assert "O''Brien; COMMIT; -- data" in sql
    assert "WHEN-NEW-RECORD-INSTANCE" not in sql and "EXAMPLE" not in sql
    assert "SET_BLOCK_PROPERTY" not in sql and "FORM_SUCCESS" not in sql
    assert receipt["sql_sha256"] == _sha(sql.encode())


def test_no_operations_is_comment_only_and_plan_changes_are_detected():
    plan = plan_for("NULL;")
    sql, receipt = render_policy_code(plan)
    assert "CREATE " not in sql and receipt["generated_operations"] == []
    plan["coverage"][0]["reason"] = "tampered"
    with pytest.raises(ValueError, match="PLAN_CHANGED"):
        render_policy_code(plan)


@pytest.mark.parametrize("mutation", ["ast", "type", "target", "metadata", "extra_op", "coverage", "source_text", "parent_trace", "claims", "extra_root"])
def test_resealed_plan_must_still_match_reparsed_source_and_parent_trace(mutation):
    plan = plan_for("SET_BLOCK_PROPERTY('ROWS',INSERT_ALLOWED,PROPERTY_TRUE);")
    op = plan["operations"][0]
    if mutation == "ast": op["body"][0]["value"] = False
    if mutation == "type": op["body"][0]["value"] = 1
    if mutation == "target": op["body"][0]["target_id"] = "ff1-" + "0" * 24
    if mutation == "metadata": plan["source_catalog"]["objects"][-1]["metadata"]["Name"] = "OTHER"
    if mutation == "extra_op": op["raw_sql"] = "COMMIT;"
    if mutation == "coverage": plan["coverage"][0]["status"] = "converted"
    if mutation == "source_text": plan["source_catalog"]["units"][0]["text"] += " COMMIT;"
    if mutation == "parent_trace": plan["parent_trace"]["blocks"][0]["name"] = "OTHER"
    if mutation == "claims": plan["event_activated"] = True
    if mutation == "extra_root": plan["raw_sql"] = "COMMIT;"
    with pytest.raises(ValueError):
        render_policy_code(seal(plan))
