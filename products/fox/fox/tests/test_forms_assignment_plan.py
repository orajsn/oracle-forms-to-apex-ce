"""Synthetic source-bound assignment checks; no Oracle or live-flow assertions."""
from copy import deepcopy
import xml.etree.ElementTree as ET

import pytest

from fox.forms_assignment_plan import build_assignment_plan
from fox.forms_behavior_plan import _source_objects
from fox.forms_understanding_packet import _build
from forms2apex.native_assignments import _canonical, _sha, render_assignment_code


def seal(plan):
    plan["plan_sha256"] = _sha(_canonical({k: v for k, v in plan.items() if k != "plan_sha256"}))
    return plan


def test_sibling_reports_do_not_grant_a_parent_assignment_context():
    from fox.forms_native_plan import POLICY_ID
    from fox.xml_mapping import generate_xml_package
    from test_forms_relation_plan import sibling_documents

    docs = sibling_documents(count=2, child_extra=(
        '<Trigger Name="PRE-INSERT" TriggerText=":DETAIL_ID := :CUSTOMERS.CUST_ID;"/>'))
    _, result = generate_xml_package(docs, 'manual-relation', 'Related records', POLICY_ID)
    navigation = result['relation_receipt']['generated_operations']
    assert len(navigation) == 2
    assert all(not op['write_lifecycle'] for op in navigation)
    assert {row['reason'] for row in result['relation_plan']['coverage']} == {
        'manual_navigation_without_assignment_context'}
    assert not result['assignment_plan']['operations']
    assert not result['assignment_receipt']['generated_operations']


def source(module="SAMPLE", parent="HEADER", child="LINES", text=":COPIED := :ORIGIN;", kind="Char"):
    root = ET.Element("Module", xmlns="http://xmlns.oracle.com/Forms")
    form = ET.SubElement(root, "FormModule", Name=module)
    for name, field in ((parent, "ORIGIN"), (child, "COPIED")):
        block = ET.SubElement(form, "Block", Name=name, DatabaseBlock="true")
        ET.SubElement(block, "Item", Name="KEY_VALUE", DatabaseItem="true", DataType="Number")
        ET.SubElement(block, "Item", Name=field, DatabaseItem="true", DataType=kind, MaximumLength="40")
        if name == parent:
            ET.SubElement(block, "Relation", Name="DETAIL_EDGE", RelationType="Join", DetailBlock=child,
                          JoinCondition=f"{parent}.KEY_VALUE={child}.KEY_VALUE")
        else:
            ET.SubElement(block, "Trigger", Name="PRE-INSERT", TriggerText=text)
            ET.SubElement(block, "Trigger", Name="PRE-UPDATE", TriggerText=text)
            ET.SubElement(block, "Trigger", Name="WHEN-NEW-RECORD-INSTANCE", TriggerText="NULL;")
    return ET.tostring(root)


def context(docs=None):
    """Construct local synthetic native trace/edge proofs from actual XML facts."""
    from fox.forms_relation_plan import parse_join_condition, relation_attribute_sha256
    docs = docs or [("sample.xml", source())]
    packet, _ = _build(docs)
    objects, metadata = _source_objects(docs, packet)
    trace = {"source_binding": packet["source_binding"], "blocks": []}
    for index, block in enumerate(row for row in objects.values() if row["kind"] == "Block"):
        fields = []
        for item in objects.values():
            if item["kind"] == "Item" and item["block_id"] == block["id"]:
                fields.append({"source_item_id": item["id"], "source_name": item["name"],
                    "column": "C_" + item["name"], "database_bound": True,
                    "data_type": "NUMBER" if metadata[item["id"]].get("DataType") == "Number" else "VARCHAR2",
                    "value_computation_implemented": False})
        trace["blocks"].append({"source_block_id": block["id"], "source_module_id": block["module_id"],
            "classification": "database", "name": block["name"], "table_name": f"FOX_T{index}",
            "report_file": f"pages/p{index+1:05}.apx", "report_page_id": index + 1,
            "synthetic_key": {"column": "FOX_ROW_ID"}, "items": fields})
    relations, coverage = [], []
    for row in objects.values():
        if row["kind"] != "Relation":
            continue
        props = metadata[row["id"]]
        parent = objects[row["parent_id"]]
        children = [obj for obj in objects.values() if obj["kind"] == "Block"
            and obj["module_id"] == row["module_id"] and obj["name"] == props["DetailBlock"]]
        if len(children) != 1:
            continue
        child = children[0]
        def target(block):
            mapped = next(b for b in trace["blocks"] if b["source_block_id"] == block["id"])
            return {"table": mapped["table_name"], "report_file": mapped["report_file"],
                    "report_page_id": mapped["report_page_id"], "row_id_column": "FOX_ROW_ID"}
        def item(block, name):
            return next(obj for obj in objects.values() if obj["kind"] == "Item"
                        and obj["block_id"] == block["id"] and obj["name"] == name)
        pairs = [{"parent_item_id": item(parent, p)["id"], "child_item_id": item(child, c)["id"],
                  "parent_column": "C_" + p, "child_column": "C_" + c, "data_type": "NUMBER"}
                 for p, c in parse_join_condition(props["JoinCondition"], parent["name"], child["name"])]
        digest = relation_attribute_sha256(props)
        relations.append({"relation_id": row["id"], "source_module_id": row["module_id"],
            "parent_block_id": parent["id"], "child_block_id": child["id"],
            "source_attribute_sha256": digest, "join_pairs": pairs,
            "parent": target(parent), "child": target(child), "source_flags": {key: props.get(key) for key in
                ("AutoQuery", "Deferred", "DeleteRecord", "PreventMasterlessOperations")}})
        coverage.append({"relation_id": row["id"], "status": "read_navigation_planned",
                         "source_attribute_sha256": digest})
    plan = seal({"schema_version": 1, "scope": "fox-forms-relation-plan-v1",
        "source_binding": packet["source_binding"],
        "parent_trace_canonical_sha256": _sha(_canonical(trace)),
        "sources": [{k: e["source"][k] for k in ("name", "sha256", "bytes")} for e in packet["sources"]],
        "operations": relations, "coverage": coverage, "native_generated": False,
        "runtime_verified": False, "business_accepted": False})
    return docs, plan, trace


def test_both_events_are_separate_unwired_pure_null_preserving_copies():
    args = context()
    before = deepcopy(args)
    plan = build_assignment_plan(*args)
    sql, receipt = render_assignment_code(plan)
    assert args == before
    assert plan == build_assignment_plan(*args)
    assert [op["source_event"] for op in plan["operations"]] == ["PRE-INSERT", "PRE-UPDATE"]
    assert len({op["procedure_name"] for op in receipt["generated_operations"]}) == 2
    assert sql.count("p_copy := p_value;") == 2
    assert all(op["null_policy"] == "preserve" and op["event_activated"] is False
               and op["encoding_status"] == "generated_unwired" for op in receipt["generated_operations"])
    assert all(row["status"] == "unsupported" and row["not_yet_converted"] for row in plan["coverage"])
    assert receipt["converted_code_unit_count"] == 0
    assert len(plan["coverage"]) == 3
    assert plan["coverage"][-1]["reason"] == "not_a_supported_block_write_copy"
    assert all(plan[key] is False for key in ("native_generated", "write_lifecycle", "runtime_verified", "business_accepted"))
    assert "ORIGIN" not in sql and "HEADER" not in sql


@pytest.mark.parametrize("kind", ["Char", "Number"])
@pytest.mark.parametrize("text", [":COPIED := :ORIGIN;", ":LINES.COPIED := :HEADER.ORIGIN;",
    "BEGIN /* copy */ :COPIED := :ORIGIN; END;", "-- comment &#10; :COPIED := :ORIGIN; &#13;&#10;"])
def test_complete_forms_comments_qualified_refs_and_explicit_types(kind, text):
    plan = build_assignment_plan(*context([("one.xml", source(text=text, kind=kind))]))
    assert len(plan["operations"]) == 2


@pytest.mark.parametrize("text", [":COPIED:=:ORIGIN; COMMIT;", "NULL; :COPIED:=:ORIGIN;",
    "BEGIN :COPIED:=:ORIGIN; EXCEPTION WHEN OTHERS THEN NULL; END;", ":COPIED:=NVL(:ORIGIN,0);",
    ":COPIED:=:GLOBAL.ORIGIN;", ":COPIED:=:ORIGIN||'X';", "DECLARE x NUMBER; BEGIN :COPIED:=:ORIGIN; END;",
    ":COPIED:=:KEY_VALUE;", ":HEADER.ORIGIN:=:ORIGIN;", ":COPIED:=:ORIGIN; :COPIED:=:ORIGIN;",
    ":COPIED:=':ORIGIN';", ":COPIED:=:ORIGIN; /* unfinished"])
def test_extra_active_code_expressions_globals_and_ambiguous_refs_are_not_encoded(text):
    plan = build_assignment_plan(*context([("one.xml", source(text=text))]))
    assert plan["operations"] == []
    assert all(row["status"] == "unsupported" for row in plan["coverage"])


def test_same_names_in_other_modules_do_not_create_ambiguity():
    args = context([("a.xml", source(module="ALPHA")), ("b.xml", source(module="BETA"))])
    plan = build_assignment_plan(*args)
    assert len(plan["operations"]) == 4
    assert len({op["source_module_id"] for op in plan["operations"]}) == 2
    assert len({op["operation_id"] for op in plan["operations"]}) == 4


def test_renamed_blocks_and_fields_bind_without_hardcoded_source_names():
    raw = source(parent="BATCH", child="ENTRIES", text=":ENTRIES.DEST := :BATCH.SRC;")
    raw = raw.replace(b'Name="ORIGIN"', b'Name="SRC"').replace(b'Name="COPIED"', b'Name="DEST"')
    plan = build_assignment_plan(*context([("renamed.xml", raw)]))
    assert len(plan["operations"]) == 2
    assert plan["operations"][0]["source_ref"]["item_name"] == "SRC"


def test_missing_parent_context_never_guesses_a_relation():
    docs, relation, trace = context()
    relation["operations"] = []
    seal(relation)
    plan = build_assignment_plan(docs, relation, trace)
    assert plan["operations"] == []
    assert plan["coverage"][0]["reason"] == "direct_parent_context_unproven"


@pytest.mark.parametrize("change", ["source", "source_binding", "trace_binding", "column", "copy_column", "join", "duplicate"])
def test_source_relation_trace_target_tampering_rejects(change):
    docs, relation, trace = context()
    if change == "source":
        docs = [(docs[0][0], docs[0][1].replace(b':COPIED', b':MISSING'))]
    if change == "source_binding":
        relation["source_binding"] = "a" * 64
    if change == "trace_binding":
        trace["source_binding"] = "a" * 64
    if change == "column":
        trace["blocks"][0]["items"][0]["column"] = "ALTERED"
    if change == "copy_column":
        trace["blocks"][0]["items"][1]["column"] = "ALTERED"
    if change == "join":
        relation["operations"][0]["join_pairs"][0]["child_column"] = "ALTERED"
    if change == "duplicate":
        relation["operations"].append(deepcopy(relation["operations"][0]))
    seal(relation)
    with pytest.raises(ValueError):
        build_assignment_plan(docs, relation, trace)


@pytest.mark.parametrize("mutation", ["computed", "type", "non_database", "duplicate_event", "qualified_event"])
def test_unknown_computed_and_ambiguous_source_metadata_remain_unsupported(mutation):
    root = ET.fromstring(source())
    local = lambda tag: tag.rsplit("}", 1)[-1]
    blocks = [n for n in root.iter() if local(n.tag) == "Block"]
    items = [n for n in blocks[1] if local(n.tag) == "Item"]
    if mutation == "computed": items[1].set("Formula", "'X'")
    if mutation == "type": items[1].set("DataType", "Date")
    if mutation == "non_database": items[1].set("DatabaseItem", "false")
    if mutation == "duplicate_event":
        blocks[1].append(deepcopy(next(n for n in blocks[1] if local(n.tag) == "Trigger")))
    if mutation == "qualified_event":
        for trigger in blocks[1]:
            if local(trigger.tag) == "Trigger":
                trigger.set("Name", "UNKNOWN")
    plan = build_assignment_plan(*context([("one.xml", ET.tostring(root))]))
    if mutation == "duplicate_event":
        assert len(plan["operations"]) == 1
        assert sum(row["reason"] == "ambiguous_block_event" for row in plan["coverage"]) == 2
    else:
        assert plan["operations"] == []


def test_chain_composite_relation_copies_only_from_direct_parent():
    root = ET.fromstring(source())
    ns = "{http://xmlns.oracle.com/Forms}"
    form = next(n for n in root if n.tag == ns + "FormModule")
    header, lines = list(form)
    for block in (header, lines):
        ET.SubElement(block, ns + "Item", Name="SECOND_KEY", DataType="Number", DatabaseItem="true")
    next(n for n in header if n.tag == ns + "Relation").set("JoinCondition",
        "HEADER.KEY_VALUE=LINES.KEY_VALUE AND LINES.SECOND_KEY=HEADER.SECOND_KEY")
    ET.SubElement(lines, ns + "Relation", Name="NEXT_EDGE", RelationType="Join", DetailBlock="ENTRIES",
        JoinCondition="LINES.KEY_VALUE=ENTRIES.KEY_VALUE AND LINES.SECOND_KEY=ENTRIES.SECOND_KEY")
    entries = ET.SubElement(form, ns + "Block", Name="ENTRIES", DatabaseBlock="true")
    for name in ("KEY_VALUE", "SECOND_KEY"):
        ET.SubElement(entries, ns + "Item", Name=name, DataType="Number", DatabaseItem="true")
    ET.SubElement(entries, ns + "Item", Name="DEST", DataType="Char", DatabaseItem="true")
    ET.SubElement(entries, ns + "Trigger", Name="PRE-INSERT", TriggerText=":DEST:=:LINES.COPIED;")
    ET.SubElement(entries, ns + "Trigger", Name="PRE-UPDATE", TriggerText=":DEST:=:HEADER.ORIGIN;")
    plan = build_assignment_plan(*context([("chain.xml", ET.tostring(root))]))
    assert len(plan["operations"]) == 3
    assert plan["coverage"][-1]["reason"] == "reference_outside_required_block"


@pytest.mark.parametrize("subset", [False, True])
def test_cyclic_source_context_is_rejected_even_when_plan_hides_an_edge(subset):
    root = ET.fromstring(source())
    ns = "{http://xmlns.oracle.com/Forms}"
    form = next(n for n in root if n.tag == ns + "FormModule")
    _, lines = list(form)
    ET.SubElement(lines, ns + "Relation", Name="BACK_EDGE", RelationType="Join", DetailBlock="HEADER",
                  JoinCondition="LINES.KEY_VALUE=HEADER.KEY_VALUE")
    docs, relation, trace = context([("cyclic.xml", ET.tostring(root))])
    if subset:
        relation["operations"] = relation["operations"][:1]
        seal(relation)
    with pytest.raises(ValueError, match="CYCLE"):
        build_assignment_plan(docs, relation, trace)


def test_duplicate_source_relations_cannot_be_hidden_by_selecting_one():
    root = ET.fromstring(source())
    ns = "{http://xmlns.oracle.com/Forms}"
    parent = next(n for n in root.iter() if n.tag == ns + "Block")
    edge = deepcopy(next(n for n in parent if n.tag == ns + "Relation"))
    edge.set("Name", "ANOTHER_EDGE")
    parent.append(edge)
    docs, relation, trace = context([("duplicate.xml", ET.tostring(root))])
    relation["operations"] = relation["operations"][:1]
    seal(relation)
    with pytest.raises(ValueError, match="AMBIGUOUS"):
        build_assignment_plan(docs, relation, trace)


@pytest.mark.parametrize("owner", ["form", "item"])
def test_only_direct_block_owned_events_are_eligible(owner):
    root = ET.fromstring(source())
    ns = "{http://xmlns.oracle.com/Forms}"
    form = next(n for n in root if n.tag == ns + "FormModule")
    lines = list(form)[1]
    destination = form if owner == "form" else next(n for n in lines if n.tag == ns + "Item")
    for trigger in list(lines):
        if trigger.tag == ns + "Trigger":
            lines.remove(trigger)
            destination.append(trigger)
    plan = build_assignment_plan(*context([("scoped.xml", ET.tostring(root))]))
    assert plan["operations"] == []


def test_changed_dict_cannot_rebind_copy_field_even_when_relation_join_is_unchanged():
    docs, relation, trace = context()
    trace["blocks"][1]["items"][1]["column"] = "C_OTHER_FIELD"
    with pytest.raises(ValueError, match="TRACE_CHANGED"):
        build_assignment_plan(docs, relation, trace)
