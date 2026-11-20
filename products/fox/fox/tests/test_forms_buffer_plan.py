"""Real deterministic source/native package boundaries; no Oracle runtime claims."""
from copy import deepcopy
import io
import json
from pathlib import Path
import zipfile

import pytest

from fox.forms_buffer_plan import build_buffer_plan
from fox.forms_behavior_plan import build_behavior_plan
from fox.forms_native_plan import POLICY_ID, build_native_prototype_plan
from fox.forms_relation_plan import build_relation_plan
from fox.forms_understanding_packet import _build
from fox.xml_mapping import _blueprint
from forms2apex import native_blueprint, native_behavior, native_relations
from forms2apex.record_buffer import validate_buffer_plan, _canonical, _sha

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "xml-mapping" / "record_buffer.xml"
PARENT_COPY_EXAMPLE = EXAMPLE.with_name("record_buffer_parent_copy.xml")


def documents(*, changes=(), module="SHIPMENT_DRAFT"):
    raw = EXAMPLE.read_bytes().replace(b"SHIPMENT_DRAFT", module.encode())
    for old, new in changes:
        assert old.encode() in raw
        raw = raw.replace(old.encode(), new.encode())
    return [(module.lower() + ".xml", raw)]


def pack(files):
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w") as archive:
        for name, data in sorted(files.items()):
            archive.writestr(name, data)
    return target.getvalue()


def members(raw):
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def parent_package(docs):
    """Run installed base/behavior/relation renderers, without assembler recursion."""
    packet, chunks = _build(docs)
    spec = build_native_prototype_plan(docs, _blueprint(packet), project_id="buffer-test",
        project_name="Draft test", approved_policy_id=POLICY_ID)["rendering_spec"]
    files = {name: text.encode() for name, text in native_blueprint.render_native_blueprint(spec).items()}
    trace = native_blueprint.prototype_trace(spec)
    objects = {obj["id"]: obj for entry in packet["sources"] for obj in entry["facts"]["objects"]}
    for block in trace["blocks"]:
        block["source_module_id"] = objects[block["source_block_id"]]["module_id"]
    manifest = {"source_binding": packet["source_binding"],
                "files": [{key: entry["source"][key] for key in ("name", "sha256", "bytes")} for entry in packet["sources"]],
                "selected_chunk_hashes": {chunk["id"]: chunk["sha256"] for chunk in chunks}}
    files["fox-package/source-manifest.json"] = _canonical(manifest)
    files["fox-package/source-to-page.json"] = _canonical(trace)
    files["fox-package/supporting-schema.sql"] = native_blueprint.render_prototype_schema(spec).encode()
    for name, source in docs:
        files["fox-package/sources/" + name] = source
    raw = pack(files)
    behavior = build_behavior_plan(docs, raw)
    if behavior["operations"]:
        raw, _ = native_behavior.render_behavior_package(raw, behavior)
    relations = build_relation_plan(docs, raw)
    if relations["operations"]:
        raw, _ = native_relations.render_relation_package(raw, relations)
    return raw


def test_complete_source_pipeline_binds_all_native_fields_and_preserves_bytes():
    docs = documents()
    parent = parent_package(docs)
    before = deepcopy(docs), parent
    plan = build_buffer_plan(docs, parent)
    assert plan == build_buffer_plan(docs, parent) == validate_buffer_plan(plan)
    assert (docs, parent) == before
    assert plan["code_unit_count"] == len(plan["coverage"]) == 3
    op, = plan["operations"]
    assert op["source_event"] == "WHEN-VALIDATE-RECORD"
    assert [b["source_item_name"] for b in op["key_bindings"]] == ["PREFIX", "CODE"]
    assert op["concat_max_bytes"] == 192
    assert op["control_key"]["max_length"] == 50 and op["control_key"]["source_length_semantics"] == "BYTE"
    assert op["summary_metadata"]["SummaryFunction"] == "Sum"
    assert op["relation"]["parent_item"].startswith("P")
    assert op["relation"]["row_identity_source_derived"] is False
    assert len(op["supporting_units"]) == 2
    assert sum(row["status"] == "planned_wired_adapted" for row in plan["coverage"]) == 1
    assert sum(row["status"] == "supporting_unit_not_counted" for row in plan["coverage"]) == 2
    assert all(plan[key] is False for key in ("native_generated", "event_activated", "runtime_verified", "business_accepted"))


def test_name_independence_and_distinct_module_isolation():
    docs = documents(module="OUTGOING") + documents(module="INCOMING")
    plan = build_buffer_plan(docs, parent_package(docs))
    assert len(plan["operations"]) == 2
    assert len({op["source_module_id"] for op in plan["operations"]}) == 2
    assert len({op["relation"]["page_id"] for op in plan["operations"]}) == 2
    for op in plan["operations"]:
        assert all(binding["source_module_id"] == op["source_module_id"] for binding in op["key_bindings"])


@pytest.mark.parametrize("old,new,reason", [
    ("RAISE FORM_TRIGGER_FAILURE; END IF; END;", "RAISE FORM_TRIGGER_FAILURE; END IF; COMMIT; END;", "complete_duplicate"),
    ("WHEN-VALIDATE-RECORD", "POST-QUERY", "outside_duplicate"),
    ("SummaryFunction=\"Sum\"", "SummaryFunction=\"Count\"", "exact_source_sum"),
    ("SummaryBlockName=\"PACKS\"", "SummaryBlockName=\"ORDERS\"", "exact_source_sum"),
    ("KEY_MATCH(:CONTROL.KEY_VALUE, :PACKS.PREFIX || :PACKS.CODE)",
     "KEY_MATCH(:PACKS.PREFIX || :PACKS.CODE, :CONTROL.KEY_VALUE)", "formula_argument_order"),
    ("KEY_MATCH(:CONTROL.KEY_VALUE, :PACKS.PREFIX || :PACKS.CODE)",
     "KEY_MATCH(:CONTROL.KEY_VALUE, :PACKS.CODE || :PACKS.PREFIX)", "formula_argument_order"),
    ("IF val1 = val2 THEN answer := 1;", "IF val1 = val2 THEN answer := 0;", "local_comparison"),
    ("answer := 1; END IF; RETURN(answer);", "answer := 1; END IF; EXECUTE_QUERY; RETURN(answer);", "local_comparison"),
    ("answer := 1; END IF; RETURN(answer);", "answer := 1; END IF; SELECT X INTO answer FROM Y; RETURN(answer);", "local_comparison"),
    ("answer := 1; END IF; RETURN(answer);", "answer := 1; END IF; LOOP answer := 0; END LOOP; RETURN(answer);", "local_comparison"),
    ("MaximumLength=\"16\"", "MaximumLength=\"4000\"", "character_length"),
    ("Name=\"PREFIX\" ItemType", "Name=\"PREFIX\" Collation=\"BINARY_CI\" ItemType", "source_collation"),
    ("Name=\"PREFIX\" ItemType", "Name=\"PREFIX\" CaseRestriction=\"Title\" ItemType", "source_input_property"),
    ("Name=\"PREFIX\" ItemType", "Name=\"PREFIX\" Required=\"maybe\" ItemType", "source_input_property"),
    (":CONTROL.KEY_VALUE := :PACKS.PREFIX || :PACKS.CODE;", ":CONTROL.KEY_VALUE := :PACKS.PREFIX || :PACKS.PREFIX;", "repeated_key_reference"),
])
def test_unsupported_whole_source_has_visible_coverage(old, new, reason):
    docs = documents(changes=[(old, new)])
    plan = build_buffer_plan(docs, parent_package(docs))
    assert plan["operations"] == []
    assert any(reason in row["reason"] for row in plan["coverage"])
    assert len(plan["coverage"]) == 3


def test_no_relation_and_no_buffer_old_forms_still_get_complete_coverage():
    docs = [("plain.xml", b'<FormModule Name="PLAIN"><Block Name="LINES" DatabaseBlock="true">'
             b'<Item Name="N" ItemType="Text Item" DatabaseItem="true" DataType="Number"/>'
             b'<Trigger Name="PRE-QUERY" TriggerText="NULL;"/></Block></FormModule>')]
    parent = parent_package(docs)
    assert "fox-package/relation-plan.json" not in members(parent)
    plan = build_buffer_plan(docs, parent)
    assert not plan["operations"] and plan["relation_receipt"] == {}
    assert len(plan["coverage"]) == 1


def test_exact_declared_required_and_case_input_properties_bound_before_event():
    docs = documents(changes=[("Name=\"PREFIX\" ItemType", "Name=\"PREFIX\" Required=\"true\" ItemType"),
                              ("Name=\"CODE\" ItemType", "Name=\"CODE\" CaseRestriction=\"Upper\" ItemType")])
    plan = build_buffer_plan(docs, parent_package(docs))
    first, second = plan["operations"][0]["key_bindings"]
    assert first["required"] is True and first["case_restriction"] == "NONE"
    assert second["required"] is False and second["case_restriction"] == "UPPER"
    assert first["source_length_semantics"] == ""
    assert "unresolved" in plan["operations"][0]["semantics"]["source_default_length_semantics"]


def test_missing_direct_incoming_context_is_unsupported_not_invented():
    docs = documents()
    name, raw = docs[0]
    import re
    docs = [(name, re.sub(rb"    <Relation .*?/>\n", b"", raw))]
    plan = build_buffer_plan(docs, parent_package(docs))
    assert not plan["operations"]
    assert any(row["reason"] == "direct_incoming_relation_required" for row in plan["coverage"])


@pytest.mark.parametrize("target", ["source", "trace", "receipt", "schema", "controlpage", "contextpage"])
def test_parent_tampering_rejected_at_fresh_plan_boundary(target):
    docs = documents()
    parent = parent_package(docs)
    files = members(parent)
    clean = build_buffer_plan(docs, parent)
    op = clean["operations"][0]
    if target == "source": files["fox-package/sources/" + docs[0][0]] += b" "
    elif target == "trace":
        trace = json.loads(files[native_relations.TRACE])
        child = next(b for b in trace["blocks"] if b["source_block_id"] == op["source_block_id"])
        child["items"][0]["source_name"] = "OTHER"
        files[native_relations.TRACE] = _canonical(trace)
    elif target == "receipt":
        receipt = json.loads(files["fox-package/relation-receipt.json"])
        receipt["generated_operations"][0]["parent_item"] = "P4_OTHER"
        files["fox-package/relation-receipt.json"] = _canonical(receipt)
    elif target == "schema":
        field = op["key_bindings"][0]
        files["fox-package/supporting-schema.sql"] = files["fox-package/supporting-schema.sql"].replace(
            (field["column"] + " VARCHAR2(16)").encode(), (field["column"] + " VARCHAR2(17)").encode())
    elif target == "controlpage": files[op["control_key"]["native_page_file"]] = b"page 9 (\n)"
    elif target == "contextpage": files[op["relation"]["page_file"]] = b"page 9 (\n)"
    with pytest.raises(ValueError):
        build_buffer_plan(docs, pack(files))


def test_four_direct_character_key_fields_supported_and_fifth_rejected():
    docs = documents()
    name, raw = docs[0]
    extra = (b'<Item Name="THIRD" ItemType="Text Item" DatabaseItem="true" DataType="Char" MaximumLength="2"/>'
             b'<Item Name="FOURTH" ItemType="Text Item" DatabaseItem="true" DataType="Char" MaximumLength="2"/>')
    raw = raw.replace(b'    <Item Name="MATCHES"', extra + b'    <Item Name="MATCHES"')
    raw = raw.replace(b":PACKS.PREFIX || :PACKS.CODE", b":PACKS.PREFIX || :PACKS.CODE || :PACKS.THIRD || :PACKS.FOURTH")
    docs = [(name, raw)]
    plan = build_buffer_plan(docs, parent_package(docs))
    assert len(plan["operations"][0]["key_bindings"]) == 4
    docs = [(name, raw.replace(b"|| :PACKS.FOURTH", b"|| :PACKS.FOURTH || :PACKS.CODE"))]
    plan = build_buffer_plan(docs, parent_package(docs))
    assert not plan["operations"] and any(row["reason"] == "key_field_capacity" for row in plan["coverage"])


def inherited_documents(*, changes=(), module="DISPATCH_DRAFT"):
    raw = PARENT_COPY_EXAMPLE.read_bytes().replace(b"DISPATCH_DRAFT", module.encode())
    for old, new in changes:
        assert old.encode() in raw
        raw = raw.replace(old.encode(), new.encode())
    return [(module.lower() + ".xml", raw)]


def test_renamed_second_form_explicitly_binds_inheritance_and_preserves_ordinary_fixture():
    docs = documents(module="OUTGOING") + inherited_documents(module="INCOMING")
    plan = build_buffer_plan(docs, parent_package(docs))
    assert plan == validate_buffer_plan(plan) and len(plan["operations"]) == 2
    ordinary = next(op for op in plan["operations"] if op["key_bindings"][0]["source_item_name"] == "PREFIX")
    copied = next(op for op in plan["operations"] if op["key_bindings"][0]["source_item_name"] == "LOAD_REFERENCE")
    assert all("parent_copy" not in binding for binding in ordinary["key_bindings"])
    key, editable = copied["key_bindings"]
    pair, = copied["relation"]["join_pairs"]
    assert key["parent_copy"] == {"parent_column": pair["parent_column"], "parent_item_id": pair["parent_item_id"]}
    assert key["source_item_id"] == pair["child_item_id"] and key["required"] is True
    assert "parent_copy" not in editable
    assert ordinary["source_module_id"] != copied["source_module_id"]
    assert ordinary["relation"]["page_id"] != copied["relation"]["page_id"]


@pytest.mark.parametrize("old,new", [
    ("LOADS.LOAD_REFERENCE\" Required", "LOADS.UNKNOWN\" Required"),
    ("LOADS.LOAD_REFERENCE\" Required", "PIECES.LOAD_REFERENCE\" Required"),
    ("LOADS.LOAD_REFERENCE\" Required", ":LOADS.LOAD_REFERENCE\" Required"),
    ("LOADS.LOAD_REFERENCE\" Required", "LOADS.LOAD_REFERENCE || 'X'\" Required"),
    ('Name="PIECE_CODE" ItemType', 'Name="PIECE_CODE" CopyValueFromItem="LOADS.LOAD_REFERENCE" ItemType'),
])
def test_unproven_key_copy_is_visible_unsupported_whole_pipeline(old, new):
    docs = inherited_documents(changes=[(old, new)])
    plan = build_buffer_plan(docs, parent_package(docs))
    assert not plan["operations"] and len(plan["coverage"]) == 3
    assert any(row["status"] == "unsupported" for row in plan["coverage"])


def test_parent_copy_uses_exact_source_size_and_safe_child_bounds_with_wider_parent():
    name, raw = inherited_documents()[0]
    docs = [(name, raw.replace(b'MaximumLength="16"', b'MaximumLength="20"', 1))]
    plan = build_buffer_plan(docs, parent_package(docs))
    key = plan["operations"][0]["key_bindings"][0]
    assert key["max_length"] == 16 and key["data_type"] == "VARCHAR2" and "parent_copy" in key
    from forms2apex.record_buffer import BufferPlanError, BufferState
    with pytest.raises(BufferPlanError, match="MODEL_VALUE_LENGTH"):
        BufferState(plan, plan["operations"][0]["operation_id"], parent_id=1, rows=[], collation="BINARY",
                    parent_values={key["parent_copy"]["parent_column"]: "X" * 17})


def test_copied_parent_source_size_must_match_actual_parent_schema():
    docs = inherited_documents()
    parent = parent_package(docs)
    plan = build_buffer_plan(docs, parent)
    op, = plan["operations"]
    table = op["relation"]["parent"]["table"]
    column = op["key_bindings"][0]["parent_copy"]["parent_column"]
    files = members(parent)
    schema = files["fox-package/supporting-schema.sql"]
    start = schema.index(("CREATE TABLE " + table + " (").encode())
    end = schema.index(b"\n);", start)
    changed = schema[start:end].replace((column + " VARCHAR2(16)").encode(), (column + " VARCHAR2(17)").encode())
    assert changed != schema[start:end]
    files["fox-package/supporting-schema.sql"] = schema[:start] + changed + schema[end:]
    with pytest.raises(ValueError, match="NATIVE_KEY_LENGTH_BINDING"):
        build_buffer_plan(docs, pack(files))


def test_parent_copy_cannot_resolve_a_parent_only_present_in_another_module():
    docs = inherited_documents(changes=[('CopyValueFromItem="LOADS.LOAD_REFERENCE"',
                                         'CopyValueFromItem="ORDERS.ORDER_ID"')]) + documents()
    plan = build_buffer_plan(docs, parent_package(docs))
    assert len(plan["operations"]) == 1
    assert all("parent_copy" not in key for key in plan["operations"][0]["key_bindings"])
    assert any(row["reason"] == "source_item_reference_not_unique" for row in plan["coverage"])
