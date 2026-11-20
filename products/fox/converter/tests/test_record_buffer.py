"""Standalone whole-source IR and pure draft semantics, without Oracle calls."""
from copy import deepcopy

import pytest

from forms2apex import record_buffer as rb


def closed_plan(*, case_restriction=None, required=None, copy_from=None):
    """Synthetic source facts, never claimed as an XML or target runtime test."""
    def identity(value):
        return "ff1-" + rb._sha(value.encode())[:24]

    source_binding = rb._sha(b"synthetic-source")
    module = identity("MODULE")
    objects, units = [], []

    def obj(kind, name, *, parent=None, block=None, classification=None, database=None, **metadata):
        object_id = identity(kind + ":" + name)
        objects.append({"id": object_id, "kind": kind, "name": name, "module_id": module,
                        "block_id": block, "parent_id": parent, "classification": classification,
                        "database_item": database, "metadata": {"Name": name, **metadata}})
        return object_id

    objects.append({"id": module, "kind": "FormModule", "name": "MODULE", "module_id": module,
                    "block_id": None, "parent_id": None, "classification": None, "database_item": None,
                    "metadata": {"Name": "MODULE"}})
    parent = obj("Block", "HEADERS", parent=module, classification="database")
    child = obj("Block", "LINES", parent=module, classification="database")
    control_block = obj("Block", "CONTROL", parent=module, classification="control")
    key_fields = []
    for name, block in (("ORDER_NO", parent), ("ORDER_NO", child), ("LINE_NO", child)):
        # Distinct item IDs even when the exact source name repeats across blocks.
        item_id = identity(block + name)
        item = {"id": item_id, "kind": "Item", "name": name, "module_id": module, "block_id": block,
                "parent_id": block, "classification": None, "database_item": True,
                "metadata": {"Name": name, "DataType": "Char", "MaximumLength": "16", "DataLengthSemantics": "Null"}}
        if block == child and name == "ORDER_NO":
            if copy_from is not None:
                item["metadata"]["CopyValueFromItem"] = copy_from
            if case_restriction is not None:
                item["metadata"]["CaseRestriction"] = case_restriction
            if required is not None:
                item["metadata"]["Required"] = "true" if required else "false"
        objects.append(item)
        key_fields.append(item_id)
    formula = obj("Item", "MATCHED", parent=child, block=child, database=False, DataType="Number", CalculateMode="Formula",
                  Formula="MATCH_VALUE(:CONTROL.KEY_VALUE,:LINES.ORDER_NO||:LINES.LINE_NO)")
    control = obj("Item", "KEY_VALUE", parent=control_block, block=control_block, database=False,
                  DataType="Char", MaximumLength="50", DataLengthSemantics="BYTE")
    summary = obj("Item", "COUNT_MATCHED", parent=control_block, block=control_block, database=False, DataType="Number",
                  CalculateMode="Summary", SummaryFunction="Sum", SummaryBlockName="LINES", SummaryItemName="MATCHED")
    trigger_text = (":CONTROL.KEY_VALUE:=:LINES.ORDER_NO||:LINES.LINE_NO; IF :CONTROL.COUNT_MATCHED>1 THEN "
                    "MESSAGE('Duplicate'); MESSAGE('Duplicate'); RAISE FORM_TRIGGER_FAILURE; END IF;")
    trigger = obj("Trigger", "WHEN-VALIDATE-RECORD", parent=child, block=child, TriggerText=trigger_text)
    helper_text = ("FUNCTION MATCH_VALUE(A VARCHAR2,B VARCHAR2) RETURN NUMBER IS BEGIN "
                   "IF A=B THEN RETURN 1; ELSE RETURN 0; END IF; END;")
    helper = obj("ProgramUnit", "MATCH_VALUE", parent=module, ProgramUnitText=helper_text)
    relation = obj("Relation", "HEADER_LINES", parent=parent, block=parent, DetailBlock="LINES", RelationType="Join",
                   JoinCondition="HEADERS.ORDER_NO=LINES.ORDER_NO")
    for index, (owner, attribute, text) in enumerate(((formula, "Formula", ""),
                                                     (trigger, "TriggerText", trigger_text),
                                                     (helper, "ProgramUnitText", helper_text))):
        if attribute == "Formula":
            text = next(o for o in objects if o["id"] == owner)["metadata"][attribute]
        units.append({"id": identity("unit" + str(index)), "owner_id": owner, "source_attribute": attribute,
                      "sha256": rb._sha(text.encode()), "text": text, "chunk_id": "fup1-" + rb._sha(("chunk" + text).encode()),
                      "location": {"path": "/FormModule[1]/Code[" + str(index + 1) + "]", "line": 1, "column": 1, "byte_offset": 0}})
    def field(item_id, column, dtype, database=True, native=None):
        item = next(o for o in objects if o["id"] == item_id)
        return {"source_item_id": item_id, "source_name": item["name"], "column": column,
                "data_type": dtype, "database_bound": database, "value_computation_implemented": False,
                "native_item": native, "native_item_page_id": 7 if native else None}

    trace = {"source_binding": source_binding, "blocks": [
        {"source_block_id": parent, "source_module_id": module, "name": "HEADERS", "classification": "database",
         "table_name": "FOX_HEADERS", "report_file": "pages/headers.apx", "report_page_id": 2,
         "synthetic_key": {"column": "FOX_ROW_ID", "source_derived": False, "source_item_id": None},
         "items": [field(key_fields[0], "ORDER_NO", "VARCHAR2")]},
        {"source_block_id": child, "source_module_id": module, "name": "LINES", "classification": "database",
         "table_name": "FOX_LINES", "report_file": "pages/lines.apx", "report_page_id": 3,
         "synthetic_key": {"column": "FOX_ROW_ID", "source_derived": False, "source_item_id": None},
         "items": [field(key_fields[1], "ORDER_NO", "VARCHAR2"), field(key_fields[2], "LINE_NO", "VARCHAR2"),
                   field(formula, "MATCHED", "NUMBER")]},
        {"source_block_id": control_block, "source_module_id": module, "name": "CONTROL", "classification": "control",
         "page_id": 7, "page_file": "pages/control.apx", "items": [field(control, None, "VARCHAR2", False, "P7_KEY"),
                                                                    field(summary, None, "NUMBER", False, "P7_SUM")]}]}
    attrs = next(o for o in objects if o["id"] == relation)["metadata"]
    sources = [{"name": "synthetic.xml", "sha256": source_binding, "bytes": 100}]
    edge = {"relation_id": relation, "source_module_id": module, "parent_block_id": parent, "child_block_id": child,
            "source_attribute_sha256": rb._sha(rb._canonical(attrs)),
            "join_pairs": [{"parent_item_id": key_fields[0], "parent_column": "ORDER_NO", "child_item_id": key_fields[1],
                            "child_column": "ORDER_NO", "data_type": "VARCHAR2"}],
            "parent": {"table": "FOX_HEADERS", "report_file": "pages/headers.apx", "report_page_id": 2, "row_id_column": "FOX_ROW_ID"},
            "child": {"table": "FOX_LINES", "report_file": "pages/lines.apx", "report_page_id": 3, "row_id_column": "FOX_ROW_ID"},
            "source_flags": {k: None for k in rb.native_relations._FLAGS}}
    relation_plan = {"schema_version": 1, "scope": rb.native_relations.SCOPE, "source_binding": source_binding,
                     "parent_zip_sha256": source_binding, "source_manifest_sha256": source_binding,
                     "parent_trace_sha256": source_binding, "parent_trace_canonical_sha256": rb._sha(rb._canonical(trace)),
                     "sources": sources, "operations": [edge], "coverage": [], "native_generated": False,
                     "runtime_verified": False, "business_accepted": False}
    relation_plan["plan_sha256"] = rb._sha(rb._canonical(relation_plan))
    receipt = {"scope": rb.native_relations.RENDERER, "native_generated": True, "runtime_verified": False,
               "business_accepted": False, "write_lifecycle": False, "source_binding": source_binding,
               "plan_sha256": relation_plan["plan_sha256"], "plan_artifact_sha256": rb._sha(rb._canonical(relation_plan)),
               "generated_operations": [{"relation_id": relation, "generation_status": "read_navigation_generated",
                    "source_module_id": module, "parent_block_id": parent, "child_block_id": child,
                    "parent_report_file": "pages/headers.apx", "page_id": 4, "page_file": "pages/p00004-fox_relation_4.apx",
                    "parent_item": "P4_PARENT_ID", "write_lifecycle": False}]}
    catalog = {"objects": objects, "units": units}
    ops, coverage = rb.derive_buffer_operations(catalog, trace, source_binding, relation_plan, receipt)
    assert len(ops) == 1
    plan = {"schema_version": 1, "scope": rb.SCOPE, "source_binding": source_binding,
            "parent_zip_sha256": source_binding, "source_manifest_sha256": source_binding,
            "parent_trace_sha256": source_binding, "trace_sha256": rb._sha(rb._canonical(trace)),
            "relation_plan_sha256": rb._sha(rb._canonical(relation_plan)), "relation_receipt_sha256": rb._sha(rb._canonical(receipt)),
            "sources": sources, "source_catalog": catalog, "parent_trace": trace, "relation_plan": relation_plan,
            "relation_receipt": receipt, "operations": ops, "coverage": coverage, "code_unit_count": len(units),
            "native_generated": False, "event_activated": False, "runtime_verified": False, "business_accepted": False}
    return resign(plan)


def resign(plan):
    plan["plan_sha256"] = rb._sha(rb._canonical({k: v for k, v in plan.items() if k != "plan_sha256"}))
    return plan


def state(values, *, parent_id=1, collation="BINARY", case_restriction=None, required=None):
    plan = closed_plan(case_restriction=case_restriction, required=required)
    return rb.BufferState(plan, plan["operations"][0]["operation_id"], parent_id=parent_id,
                          rows=[{"row_id": i + 1, "values": {"ORDER_NO": a, "LINE_NO": b}}
                                for i, (a, b) in enumerate(values)], collation=collation)


def submit(buffer, changes, **kwargs):
    return buffer.submit(changes, revision=buffer.revision, parent_id=buffer.parent_id,
                         source_module_id=buffer.op["source_module_id"], **kwargs)


def test_whole_pipeline_rederived_supports_not_recounted():
    plan = closed_plan()
    assert rb.validate_buffer_plan(plan) == plan
    assert [r["status"] for r in plan["coverage"]].count("planned_wired_adapted") == 1
    assert [r["status"] for r in plan["coverage"]].count("supporting_unit_not_counted") == 2
    assert all(plan[k] is False for k in rb._FLAGS)


@pytest.mark.parametrize("source", [
    ":C.K:=:B.X; IF :C.N>1 THEN MESSAGE('x'); RAISE FORM_TRIGGER_FAILURE; END IF; COMMIT;",
    ":C.K:=:B.X; IF :C.N>0 THEN MESSAGE('x'); RAISE FORM_TRIGGER_FAILURE; END IF;",
    ":C.K:=:B.X; IF :C.N>1 THEN MESSAGE(:B.X); RAISE FORM_TRIGGER_FAILURE; END IF;",
    ":C.K:=UPPER(:B.X); IF :C.N>1 THEN MESSAGE('x'); RAISE FORM_TRIGGER_FAILURE; END IF;",
    ":C.K:=:B.X||'|'; IF :C.N>1 THEN MESSAGE('x'); RAISE FORM_TRIGGER_FAILURE; END IF;",
    ":C.K:=:B.X; IF :C.N>1 THEN RAISE FORM_TRIGGER_FAILURE; END IF;",
    ":C.K:=:B.X; IF :C.N>1 THEN MESSAGE('&#10;'); RAISE FORM_TRIGGER_FAILURE; END IF;",
    ":C.K:=:B.A||:B.B||:B.C||:B.D||:B.E; IF :C.N>1 THEN MESSAGE('x'); RAISE FORM_TRIGGER_FAILURE; END IF;",
])
def test_parser_rejects_partial_or_unbounded_bodies(source):
    with pytest.raises(rb.UnsupportedBuffer):
        rb.parse_duplicate_trigger(source)


def test_decode_and_message_order_preserved():
    body = "--x&#10;BEGIN :C.K:=:B.X; IF :C.N>1 THEN MESSAGE('first'); MESSAGE('second'); RAISE FORM_TRIGGER_FAILURE; END IF; END;"
    parsed, receipt = rb.parse_duplicate_trigger(body)
    assert parsed["warnings"] == ["first", "second"]
    assert receipt["raw_sha256"] == rb._sha(body.encode())
    assert receipt["substitutions"][0]["codepoint"] == 10


def test_current_row_counted_once_and_failure_retains_overlay_and_prior_fields():
    buffer = state([("AA", "1"), ("AA", "2")])
    assert submit(buffer, {})["summary"] == 1
    result = submit(buffer, {"LINE_NO": "2"}, action="next")
    assert result["summary"] == 2 and result["accepted"] is False
    assert result["warnings"] == ["Duplicate", "Duplicate"]
    assert buffer.current_row_id == 1 and buffer.rows[1] == {"ORDER_NO": "AA", "LINE_NO": "2"}
    assert buffer.rows[2] == {"ORDER_NO": "AA", "LINE_NO": "2"}
    assert buffer.revision == 2
    result = submit(buffer, {"LINE_NO": "3"}, action="next")
    assert result["accepted"] and result["advanced"] and buffer.current_row_id == 2


def test_multiple_edited_drafts_recalculated_in_same_buffer():
    buffer = state([("AA", "1"), ("AA", "2")])
    submit(buffer, {"LINE_NO": "9"}, action="next")
    result = submit(buffer, {"LINE_NO": "9"})
    assert result["summary"] == 2 and not result["accepted"]
    assert buffer.rows[1]["LINE_NO"] == buffer.rows[2]["LINE_NO"] == "9"


@pytest.mark.parametrize("rows,count,accepted", [
    ([(None, ""), ("", None)], 0, True),
    ([(None, "A"), ("", "A")], 2, False),
    ([("AB", "C"), ("A", "BC")], 2, False),
    ([("A", "B"), ("a", "B")], 1, True),
    ([("A ", "B"), ("A", "B")], 1, True),
])
def test_oracle_null_concat_collision_and_binary_nonpadded_model(rows, count, accepted):
    result = submit(state(rows), {})
    assert (result["summary"], result["accepted"]) == (count, accepted)


def test_parent_and_module_isolation_stale_revision_and_unknown_mutations():
    buffer = state([("A", "B")])
    before = buffer.snapshot()
    for kwargs in ({"revision": 1, "parent_id": 1, "source_module_id": buffer.op["source_module_id"]},
                   {"revision": 0, "parent_id": 2, "source_module_id": buffer.op["source_module_id"]},
                   {"revision": 0, "parent_id": 1, "source_module_id": "other"}):
        with pytest.raises(rb.BufferPlanError):
            buffer.submit({}, **kwargs)
        assert buffer.snapshot() == before
    for changes in ({"UNKNOWN": "X"}, {"ORDER_NO": 1}, {"ORDER_NO": "X" * 17}):
        with pytest.raises(rb.BufferPlanError):
            submit(buffer, changes)
        assert buffer.snapshot() == before
    other_parent = state([("A", "B")], parent_id=2)
    assert submit(other_parent, {})["summary"] == 1


def test_empty_buffer_new_and_boundary_navigation():
    buffer = state([])
    assert buffer.current_row_id == 1 and len(buffer.rows) == 1
    assert submit(buffer, {}, action="previous")["advanced"] is False
    result = submit(buffer, {"ORDER_NO": "A"}, action="new")
    assert result["accepted"] and buffer.current_row_id == 2 and buffer.rows[2] == {"ORDER_NO": None, "LINE_NO": None}
    assert submit(buffer, {}, action="next")["advanced"] is False


def test_only_current_control_assignment_has_50byte_limit():
    buffer = state([("A", "B"), ("\u4e00" * 16, "\u4e01" * 16)])
    assert submit(buffer, {})["accepted"]
    before = buffer.snapshot()
    with pytest.raises(rb.BufferPlanError, match="CONTROL_BYTE_LENGTH"):
        submit(buffer, {"ORDER_NO": "\u4e00" * 16, "LINE_NO": "\u4e01" * 16})
    assert buffer.snapshot() == before


def test_explicit_binary_prerequisite_required():
    with pytest.raises(rb.BufferPlanError, match="COLLATION"):
        state([("A", "B")], collation=None)


def test_new_capacity_guard_precedes_candidate_and_source_effects():
    buffer = state([(str(index), "A") for index in range(rb.MAX_ROWS)])
    before = buffer.snapshot()
    with pytest.raises(rb.BufferPlanError, match="ROW_CAPACITY"):
        submit(buffer, {"ORDER_NO": "new"}, action="new")
    assert buffer.snapshot() == before


def test_caller_plan_and_snapshot_mutation_do_not_change_internal_state():
    plan = closed_plan()
    buffer = rb.BufferState(plan, plan["operations"][0]["operation_id"], parent_id=1,
                            rows=[{"row_id": 1, "values": {"ORDER_NO": "A", "LINE_NO": "B"}}], collation="BINARY")
    plan["operations"][0]["warnings"] = ["changed"]
    snapshot = buffer.snapshot()
    snapshot["rows"][0]["values"]["ORDER_NO"] = "changed"
    assert buffer.rows[1]["ORDER_NO"] == "A" and buffer.op["warnings"] == ["Duplicate", "Duplicate"]


@pytest.mark.parametrize("restriction,typed,loaded", [("Upper", "ab", "AB"), ("Lower", "AB", "ab")])
def test_declared_ascii_case_restriction_precedes_comparison(restriction, typed, loaded):
    buffer = state([("X", "1"), (loaded, "1")], case_restriction=restriction)
    result = submit(buffer, {"ORDER_NO": typed})
    assert result["accepted"] is False and result["summary"] == 2
    assert buffer.rows[1]["ORDER_NO"] == loaded


def test_case_restriction_does_not_rewrite_other_query_loaded_drafts():
    buffer = state([("X", "1"), ("abc", "1")], case_restriction="Upper")
    result = submit(buffer, {"ORDER_NO": "abc"})
    assert result["accepted"] and buffer.rows[1]["ORDER_NO"] == "ABC"
    assert buffer.rows[2]["ORDER_NO"] == "abc"


def test_case_restriction_preserves_unchanged_queried_internal_value():
    buffer = state([("mixedCase", "1")], case_restriction="Upper")
    assert submit(buffer, {})["control_key"] == "mixedCase1"
    assert buffer.rows[1]["ORDER_NO"] == "mixedCase"
    assert submit(buffer, {"LINE_NO": "2"})["control_key"] == "mixedCase2"
    assert submit(buffer, {"ORDER_NO": "mixedCase"})["control_key"] == "MIXEDCASE2"
    buffer = state([("\u00e9", "1")], case_restriction="Upper")
    assert submit(buffer, {})["control_key"] == "\u00e91"


def test_required_input_guard_precedes_trigger_and_empty_new_draft_is_retained():
    buffer = state([], required=True)
    before = buffer.snapshot()
    with pytest.raises(rb.BufferPlanError, match="REQUIRED_INPUT"):
        submit(buffer, {}, action="next")
    assert buffer.snapshot() == before
    result = submit(buffer, {"ORDER_NO": "A"}, action="new")
    assert result["accepted"] and buffer.current_row_id == 2
    assert buffer.rows[2]["ORDER_NO"] is None
    before = buffer.snapshot()
    with pytest.raises(rb.BufferPlanError, match="REQUIRED_INPUT"):
        submit(buffer, {"ORDER_NO": ""})
    assert buffer.snapshot() == before


def test_non_ascii_case_model_requires_oracle_equivalence_but_uncased_characters_pass():
    buffer = state([("X", "1")], case_restriction="Upper")
    before = buffer.snapshot()
    with pytest.raises(rb.BufferPlanError, match="UNICODE_CASE_PREREQUISITE"):
        submit(buffer, {"ORDER_NO": "\u00e9"})
    assert buffer.snapshot() == before
    assert submit(buffer, {"ORDER_NO": "\u4e00"})["accepted"]


@pytest.mark.parametrize("mutation", ["sourcehash", "target", "warning", "support", "unknown", "claim"])
def test_closed_plan_rejects_self_rehashed_semantic_and_proof_mutations(mutation):
    plan = deepcopy(closed_plan())
    if mutation == "sourcehash": plan["source_catalog"]["units"][1]["sha256"] = "0" * 64
    elif mutation == "target": plan["operations"][0]["key_bindings"][0]["column"] = "OTHER"
    elif mutation == "warning": plan["operations"][0]["warnings"].reverse(); plan["operations"][0]["warnings"][0] = "changed"
    elif mutation == "support": plan["operations"][0]["helper"]["source_unit_text"] += " COMMIT;"
    elif mutation == "unknown": plan["operations"][0]["invented"] = True
    elif mutation == "claim": plan["runtime_verified"] = True
    with pytest.raises(ValueError):
        rb.validate_buffer_plan(resign(plan))


def inherited_state(rows=(), *, parent_values=None, parent_id=1, **kwargs):
    plan = closed_plan(copy_from="HEADERS.ORDER_NO", **kwargs)
    return rb.BufferState(plan, plan["operations"][0]["operation_id"], parent_id=parent_id,
                          parent_values=parent_values, rows=[{"row_id": i + 1,
                          "values": {"ORDER_NO": a, "LINE_NO": b}} for i, (a, b) in enumerate(rows)],
                          collation="BINARY")


def test_inherited_first_and_new_drafts_use_authoritative_parent_without_case_coercion():
    authoritative = {"ORDER_NO": "mixedCase"}
    buffer = inherited_state(parent_values=authoritative, case_restriction="Upper", required=True)
    authoritative["ORDER_NO"] = "changed"
    assert buffer.rows[1] == {"ORDER_NO": "mixedCase", "LINE_NO": None}
    assert submit(buffer, {"ORDER_NO": "mixedCase", "LINE_NO": "1"}, action="new")["accepted"]
    assert buffer.rows[2] == {"ORDER_NO": "mixedCase", "LINE_NO": None}


@pytest.mark.parametrize("parent_values,code", [
    (None, "PARENT_VALUES"), ({}, "PARENT_VALUES"), ({"ORDER_NO": "A", "OTHER": "B"}, "PARENT_VALUES"),
    ({"ORDER_NO": None}, "PARENT_COPY_NULL"), ({"ORDER_NO": ""}, "PARENT_COPY_NULL"),
    ({"ORDER_NO": "X" * 17}, "VALUE_LENGTH"), ({"ORDER_NO": 1}, "VALUE_TYPE"),
])
def test_authoritative_parent_values_must_be_explicit_nonnull_and_fit_child(parent_values, code):
    with pytest.raises(rb.BufferPlanError, match=code):
        inherited_state(parent_values=parent_values)


@pytest.mark.parametrize("value", [None, "", "other", "MIXEDCASE"])
def test_inherited_submit_mismatch_rejected_without_mutation(value):
    buffer = inherited_state(parent_values={"ORDER_NO": "mixedCase"}, case_restriction="Upper")
    before = buffer.snapshot()
    with pytest.raises(rb.BufferPlanError, match="PARENT_COPY_MISMATCH"):
        submit(buffer, {"ORDER_NO": value, "LINE_NO": "1"}, action="new")
    assert buffer.snapshot() == before


@pytest.mark.parametrize("value", [None, "", "other"])
def test_loaded_inherited_mismatch_rejected(value):
    with pytest.raises(rb.BufferPlanError, match="PARENT_COPY_MISMATCH"):
        inherited_state([(value, "1")], parent_values={"ORDER_NO": "A"})


def test_inherited_duplicate_failure_correction_and_sibling_parent_isolation():
    buffer = inherited_state([("A", "1"), ("A", "2")], parent_values={"ORDER_NO": "A"})
    failed = submit(buffer, {"LINE_NO": "2"}, action="next")
    assert not failed["accepted"] and failed["summary"] == 2
    assert buffer.current_row_id == 1 and buffer.rows[1] == {"ORDER_NO": "A", "LINE_NO": "2"}
    assert submit(buffer, {"LINE_NO": "3"}, action="new")["accepted"]
    assert buffer.rows[3] == {"ORDER_NO": "A", "LINE_NO": None}
    sibling = inherited_state(parent_values={"ORDER_NO": "B"}, parent_id=2)
    assert submit(sibling, {"LINE_NO": "2"})["summary"] == 1
    assert buffer.rows[1]["ORDER_NO"] == "A" and sibling.rows[1]["ORDER_NO"] == "B"


def test_parent_copy_receipt_cannot_be_self_rehashed_to_another_column_or_item():
    for key in ("parent_column", "parent_item_id"):
        plan = closed_plan(copy_from="HEADERS.ORDER_NO")
        plan["operations"][0]["key_bindings"][0]["parent_copy"][key] = "OTHER"
        with pytest.raises(rb.BufferPlanError, match="SOURCE_IR_MISMATCH"):
            rb.validate_buffer_plan(resign(plan))
