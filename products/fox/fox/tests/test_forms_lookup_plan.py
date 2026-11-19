"""Real deterministic source/ZIP boundaries, no source database query or import."""
from copy import deepcopy
import io
import xml.etree.ElementTree as ET
import zipfile

import pytest

from fox.forms_behavior_plan import build_behavior_plan
from fox.forms_lookup_plan import build_lookup_plan
from fox.forms_native_plan import POLICY_ID, build_native_prototype_plan
from fox.forms_understanding_packet import _build
from fox.xml_mapping import _blueprint
from forms2apex import native_blueprint, native_behavior
from forms2apex.source_lookup import validate_lookup_plan, _canonical, _sha


def documents(*, module="DISPATCH", block="PACKS", body=None, input_props=None):
    root = ET.Element("FormModule", Name=module)
    node = ET.SubElement(root, "Block", Name=block, DatabaseBlock="true", InsertAllowed="true", UpdateAllowed="false")
    for name, dtype, length, db in [("ROUTE", "Char", "20", "true"), ("DEST", "Char", "10", "false"), ("LABEL", "Char", "40", "false"), ("COUNTED", "Number", None, "false")]:
        props = dict(Name=name, ItemType="Text Item", DataType=dtype, DatabaseItem=db)
        if length:
            props.update(MaximumLength=length, DataLengthSemantics="BYTE")
        if name == "ROUTE":
            props.update(Required="true", CaseRestriction="Upper", InsertAllowed="true", UpdateAllowed="false")
            props.update(input_props or {})
        item = ET.SubElement(node, "Item", **props)
        if name == "ROUTE":
            ET.SubElement(item, "Trigger", Name="POST-CHANGE", TriggerText=body or
                "BEGIN SELECT DESTINATION, CITY_NAME INTO :DEST, :LABEL FROM ROUTES, CITIES WHERE ROUTE_CODE = :ROUTE AND CITY_CODE = DESTINATION; EXCEPTION WHEN NO_DATA_FOUND THEN :LABEL := NULL; :DEST := NULL; END;")
    ET.SubElement(node, "Trigger", Name="POST-QUERY", TriggerText=
        "BEGIN SELECT QTY INTO :COUNTED FROM COUNTS WHERE CODE = :ROUTE; EXCEPTION WHEN OTHERS THEN :COUNTED := NULL; END;")
    return [(module.lower() + ".xml", ET.tostring(root))]


def pack(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, data in sorted(files.items()):
            archive.writestr(name, data)
    return output.getvalue()


def members(raw):
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def parent_package(docs):
    packet, chunks = _build(docs)
    spec = build_native_prototype_plan(docs, _blueprint(packet), project_id="lookup-test", project_name="Lookup test", approved_policy_id=POLICY_ID)["rendering_spec"]
    files = {n: t.encode() for n, t in native_blueprint.render_native_blueprint(spec).items()}
    trace = native_blueprint.prototype_trace(spec)
    objects = {o["id"]: o for entry in packet["sources"] for o in entry["facts"]["objects"]}
    for block in trace["blocks"]:
        block["source_module_id"] = objects[block["source_block_id"]]["module_id"]
    manifest = {"source_binding": packet["source_binding"], "files": [{k: e["source"][k] for k in ("name", "sha256", "bytes")} for e in packet["sources"]],
                "selected_chunk_hashes": {c["id"]: c["sha256"] for c in chunks}}
    files["fox-package/source-manifest.json"] = _canonical(manifest)
    files["fox-package/source-to-page.json"] = _canonical(trace)
    files["fox-package/supporting-schema.sql"] = native_blueprint.render_prototype_schema(spec).encode()
    for name, source in docs:
        files["fox-package/sources/" + name] = source
    raw = pack(files)
    behavior = build_behavior_plan(docs, raw)
    if behavior["operations"]:
        raw, _ = native_behavior.render_behavior_package(raw, behavior)
    return raw


def rehash(plan):
    plan["plan_sha256"] = _sha(_canonical({k: v for k, v in plan.items() if k != "plan_sha256"}))


def test_complete_whole_events_typed_bindings_and_original_bytes_preserved():
    docs = documents()
    parent = parent_package(docs)
    before = deepcopy(docs), parent
    plan = build_lookup_plan(docs, parent)
    assert plan == build_lookup_plan(docs, parent) == validate_lookup_plan(plan)
    assert (docs, parent) == before
    assert plan["code_unit_count"] == len(plan["coverage"]) == 2
    assert len(plan["operations"]) == 2
    change = next(op for op in plan["operations"] if op["source_event"] == "POST-CHANGE")
    assert change["exception_kind"] == "NO_DATA_FOUND"
    assert change["reset_order"] == [b["source_item_id"] for b in reversed(change["output_bindings"])]
    binding, = change["input_bindings"]
    assert binding["source_insert_allowed"] is True and binding["source_update_allowed"] is False
    assert binding["required"] is True and binding["case_restriction"] == "UPPER"
    assert binding["max_length"] == 20 and binding["source_length_semantics"] == "BYTE"
    assert change["output_bindings"][0]["database_bound"] is True
    assert change["output_bindings"][0]["source_database_item"] is False
    assert change["target"]["row_identity_source_derived"] is False
    assert change["target"]["source_update_allowed"] is False
    assert change["source_objects"][0]["verification"] == "unverified_original_read_interface"
    assert all(plan[k] is False for k in ("native_generated", "event_activated", "runtime_verified", "business_accepted"))


def test_renamed_examples_and_same_named_blocks_isolated_by_module():
    docs = documents(module="NORTH", block="ROWS") + documents(module="SOUTH", block="ROWS")
    plan = build_lookup_plan(docs, parent_package(docs))
    assert len(plan["operations"]) == 4
    assert len({op["source_module_id"] for op in plan["operations"]}) == 2
    for op in plan["operations"]:
        assert all(b["source_module_id"] == op["source_module_id"] and b["source_block_id"] == op["source_block_id"] for b in op["input_bindings"] + op["output_bindings"])


@pytest.mark.parametrize("old,new,reason", [
    (":DEST, :LABEL", ":DEST, :DEST", "distinct_outputs"),
    (":LABEL := NULL; :DEST", ":DEST := NULL; :DEST", "distinct_outputs"),
    ("INTO :DEST, :LABEL", "INTO :ROUTE, :LABEL", "distinct_outputs"),
    (":ROUTE AND", ":OTHER.ROUTE AND", "same_block"),
    (":ROUTE AND", ":MISSING AND", "not_unique"),
    (":ROUTE AND", ":DEST AND", "distinct_outputs"),
    (":ROUTE AND", ":COUNTED AND", "changed_item_must_be_query_input"),
    ("END;", "END; COMMIT;", "extra_active_source"),
])
def test_rejects_entire_unsupported_event_without_partial_generation(old, new, reason):
    docs = documents()
    root = ET.fromstring(docs[0][1]); trigger = next(root.iter("Trigger"))
    trigger.set("TriggerText", trigger.get("TriggerText").replace(old, new))
    docs = [(docs[0][0], ET.tostring(root))]
    plan = build_lookup_plan(docs, parent_package(docs))
    assert len(plan["coverage"]) == 2 and len(plan["operations"]) == 1
    assert any(reason in c["reason"] and c["status"] == "unsupported" for c in plan["coverage"])


@pytest.mark.parametrize("target", ["operation", "decode", "type", "coverage", "catalog", "trace", "claim", "unknown"])
def test_resigned_plan_tampering_rejected(target):
    docs = documents(); plan = build_lookup_plan(docs, parent_package(docs))
    if target == "operation": plan["operations"][0]["query"]["tables"][0]["parts"] = ["REPLACED"]
    elif target == "decode": plan["operations"][0]["decode_receipt"]["substitutions"] = [{"fake": True}]
    elif target == "type": plan["operations"][0]["input_bindings"][0]["data_type"] = "DATE"
    elif target == "coverage": plan["coverage"].pop()
    elif target == "catalog": plan["source_catalog"]["units"][0]["text"] += " "
    elif target == "trace": plan["parent_trace"]["blocks"][0]["table_name"] = "REPLACED"
    elif target == "claim": plan["runtime_verified"] = True
    else: plan["unknown"] = True
    rehash(plan)
    with pytest.raises(ValueError): validate_lookup_plan(plan)


@pytest.mark.parametrize("properties,reason", [
    ({"DataType": "Date"}, "native_source_type_binding"),
    ({"MaximumLength": "0"}, "explicit_character_length_required"),
    ({"CaseRestriction": "Title"}, "source_input_property_unsupported"),
    ({"Required": "maybe"}, "source_input_property_unsupported"),
    ({"InsertAllowed": "maybe"}, "source_mutability_property_unsupported"),
    ({"CalculateMode": "Summary", "SummaryFunction": "Sum"}, "direct_noncomputed_item_required"),
])
def test_unknown_source_types_computation_and_item_properties_not_guessed(properties, reason):
    docs = documents(input_props=properties)
    plan = build_lookup_plan(docs, parent_package(docs))
    assert not plan["operations"]
    assert len(plan["coverage"]) == 2
    assert all(reason in c["reason"] for c in plan["coverage"])


def test_nonlookup_units_remain_visible_and_duplicate_event_not_partially_planned():
    docs = documents()
    root = ET.fromstring(docs[0][1]); block = next(root.iter("Block"))
    ET.SubElement(block, "Trigger", Name="WHEN-NEW-RECORD-INSTANCE", TriggerText="BEGIN NULL; END;")
    item = next(root.iter("Item"))
    ET.SubElement(item, "Trigger", Name="POST-CHANGE", TriggerText=next(root.iter("Trigger")).get("TriggerText"))
    docs = [(docs[0][0], ET.tostring(root))]
    plan = build_lookup_plan(docs, parent_package(docs))
    assert len(plan["coverage"]) == 4
    assert len(plan["operations"]) == 1
    assert sum(c["reason"] == "direct_whole_event_owner_required" for c in plan["coverage"]) == 2
    assert sum(c["reason"] == "outside_source_lookup_event" for c in plan["coverage"]) == 1


@pytest.mark.parametrize("target", ["original", "schema", "type", "report", "chunk", "already", "path"])
def test_fresh_parent_tampering_rejected(target):
    docs = documents(); parent = parent_package(docs); files = members(parent)
    plan = build_lookup_plan(docs, parent); op = plan["operations"][0]
    if target == "original": files["fox-package/sources/" + docs[0][0]] += b" "
    elif target == "schema": files["fox-package/supporting-schema.sql"] = files["fox-package/supporting-schema.sql"].replace(b"VARCHAR2(20)", b"VARCHAR2(21)")
    elif target == "type": files["fox-package/supporting-schema.sql"] = files["fox-package/supporting-schema.sql"].replace(b"VARCHAR2(20)", b"NUMBER")
    elif target == "report": files[op["target"]["report_file"]] = b"page 1 (\n)"
    elif target == "chunk":
        import json
        manifest = json.loads(files["fox-package/source-manifest.json"])
        manifest["selected_chunk_hashes"] = {}
        files["fox-package/source-manifest.json"] = _canonical(manifest)
    elif target == "already": files["fox-package/lookup-plan.json"] = b"{}"
    else: files["../invalid"] = b"x"
    with pytest.raises(ValueError): build_lookup_plan(docs, pack(files))
