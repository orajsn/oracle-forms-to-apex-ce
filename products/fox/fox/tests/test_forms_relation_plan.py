"""Fresh sanitized relation source tests; no Oracle runtime acceptance claims."""
from copy import deepcopy
from html import escape
import io
import json
import zipfile

import pytest

from fox.forms_relation_plan import build_relation_plan, parse_join_condition, UnsupportedRelation
from fox.forms_native_plan import POLICY_ID, build_native_prototype_plan
from fox.forms_behavior_plan import build_behavior_plan
from fox.forms_understanding_packet import _build
from fox.xml_mapping import _blueprint
from forms2apex import native_blueprint, native_behavior


def documents(module="SALES", parent="ORDERS", child="LINES", leaf="DETAILS", *,
              condition=None, extra_parent="", extra_child="", key_type="Number", key_extra=""):
    def item(name, dtype="Number", extra=""):
        return f'<Item Name="{name}" ItemType="Text Item" DatabaseItem="true" DataType="{dtype}" {extra}/>'
    def relation(name, detail, join):
        return (f'<Relation Name="{name}" RelationType="Join" DetailBlock="{detail}" '
                f'JoinCondition="{escape(join, quote=True)}" AutoQuery="false" Deferred="false" '
                'DeleteRecord="Cascading" PreventMasterlessOperations="false"/>')
    xml = (f'<FormModule Name="{module}"><Block Name="{parent}" DatabaseBlock="true">'
           + item("ORDER_ID", key_type, key_extra)
           + relation("ORDER_LINES", child, condition or f"{child}.ORDER_ID = {parent}.ORDER_ID")
           + extra_parent + f'</Block><Block Name="{child}" DatabaseBlock="true">'
           + item("ORDER_ID", key_type) + item("LINE_ID") + item("MASS")
           + item("STATE", "Char")
           + '<Item Name="ROUNDED" ItemType="Display Item" DatabaseItem="false" DataType="Number" Formula="CEIL(:MASS)"/>'
           + relation("LINE_DETAILS", leaf, f"{leaf}.ORDER_ID = {child}.ORDER_ID AND {child}.LINE_ID = {leaf}.LINE_ID")
           + extra_child + f'</Block><Block Name="{leaf}" DatabaseBlock="true">'
           + item("ORDER_ID", key_type) + item("LINE_ID") + '</Block></FormModule>')
    return [(module.lower() + ".xml", xml.encode())]


def package(docs):
    # Build exactly the pre-relation boundary, independent of future pipeline
    # integration. These are the installed native/behavior renderers, no doubles.
    packet, chunks = _build(docs)
    spec = build_native_prototype_plan(docs, _blueprint(packet), project_id="relation-test",
        project_name="Relation test", approved_policy_id=POLICY_ID)["rendering_spec"]
    files = {name: text.encode() for name, text in native_blueprint.render_native_blueprint(spec).items()}
    manifest = {"source_binding": packet["source_binding"],
                "files": [{key: entry["source"][key] for key in ("name", "sha256", "bytes")}
                          for entry in packet["sources"]],
                "selected_chunk_hashes": {chunk["id"]: chunk["sha256"] for chunk in chunks}}
    trace = native_blueprint.prototype_trace(spec)
    objects = {obj["id"]: obj for entry in packet["sources"] for obj in entry["facts"]["objects"]}
    for block in trace["blocks"]:
        block["source_module_id"] = objects[block["source_block_id"]]["module_id"]
    files["fox-package/source-manifest.json"] = json.dumps(manifest).encode()
    files["fox-package/source-to-page.json"] = json.dumps(trace).encode()
    files["fox-package/supporting-schema.sql"] = native_blueprint.render_prototype_schema(spec).encode()
    for name, source in docs:
        files["fox-package/sources/" + name] = source
    raw = pack(files)
    behavior = build_behavior_plan(docs, raw)
    if behavior["operations"]:
        raw, _ = native_behavior.render_behavior_package(raw, behavior)
    return raw


def members(raw):
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def pack(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.comment = b"original-comment"
        for name, raw in files.items():
            archive.writestr(name, raw)
    return output.getvalue()


@pytest.mark.parametrize("names", [("SALES", "ORDERS", "LINES", "DETAILS"),
                                  ("WAREHOUSE", "CRATES", "PACKAGES", "CONTENTS")])
def test_exact_source_relations_bind_renamed_chain_and_composite_keys(names):
    docs = documents(*names)
    raw = package(docs)
    before = deepcopy(docs), raw
    plan = build_relation_plan(docs, raw)
    assert plan == build_relation_plan(docs, raw)
    assert len(plan["operations"]) == 2
    assert sorted(len(op["join_pairs"]) for op in plan["operations"]) == [1, 2]
    assert all(row["status"] == "read_navigation_planned" for row in plan["coverage"])
    assert all(op["source_flags"]["DeleteRecord"] == "Cascading" for op in plan["operations"])
    assert all(len(row["unimplemented_lifecycle"]) == 4 for row in plan["coverage"])
    assert all(plan[key] is False for key in ("native_generated", "runtime_verified", "business_accepted"))
    assert (docs, raw) == before


def test_repeated_block_names_are_resolved_within_distinct_source_modules():
    docs = documents() + documents("EXPORT")
    plan = build_relation_plan(docs, package(docs))
    assert len(plan["operations"]) == 4
    assert len({op["source_module_id"] for op in plan["operations"]}) == 2
    trace = json.loads(members(package(docs))["fox-package/source-to-page.json"])
    blocks = {b["source_block_id"]: b for b in trace["blocks"]}
    assert all(blocks[op["parent_block_id"]]["source_module_id"] ==
               blocks[op["child_block_id"]]["source_module_id"] == op["source_module_id"] for op in plan["operations"])


@pytest.mark.parametrize("condition", [
    "LINES.ORDER_ID = ORDERS.ORDER_ID OR 1=1", "NVL(LINES.ORDER_ID,0) = ORDERS.ORDER_ID",
    "ORDER_ID = ORDERS.ORDER_ID", "LINES.ORDER_ID = OTHER.ORDER_ID",
    "LINES.ORDER_ID = ORDERS.ORDER_ID; DELETE FROM X", "LINES.ORDER_ID >= ORDERS.ORDER_ID",
    "LINES.ORDER_ID = ORDERS.ORDER_ID AND LINES.ORDER_ID = ORDERS.ORDER_ID",
    "(LINES.ORDER_ID = ORDERS.ORDER_ID)", "LINES.ORDER_ID = ORDERS.ORDER_ID -- suffix",
])
def test_whole_source_condition_only_no_partial_matching(condition):
    docs = documents(condition=condition)
    plan = build_relation_plan(docs, package(docs))
    assert len(plan["operations"]) == 1
    assert len(plan["coverage"]) == 2
    assert sum(row["status"] == "unsupported" for row in plan["coverage"]) == 1


def test_control_entities_and_both_orientations_belong_to_complete_grammar():
    assert parse_join_condition("b.x=a.y AND&#10;a.z=b.w", "A", "B") == [("Y", "X"), ("Z", "W")]
    with pytest.raises(UnsupportedRelation):
        parse_join_condition("b.x=a.y AND b.w=a.y", "A", "B")
    with pytest.raises(UnsupportedRelation):
        parse_join_condition(" AND ".join(f"a.X{i}=b.X{i}" for i in range(5)), "A", "B")


@pytest.mark.parametrize("old,new", [
    ('AutoQuery="false"', 'AutoQuery="sometimes"'),
    ('DeleteRecord="Cascading"', 'DeleteRecord="SQL"'),
    ('RelationType="Join"', 'RelationType="Ref"'),
    ('DetailBlock="LINES"', 'DetailBlock="MISSING"'),
    ('Name="ORDER_ID" ItemType="Text Item" DatabaseItem="true" DataType="Number"',
     'Name="ORDER_ID" ItemType="Text Item" DatabaseItem="true" DataType="Date"'),
    ('Name="ORDER_ID" ItemType="Text Item" DatabaseItem="true" DataType="Number"',
     'Name="ORDER_ID" ItemType="Text Item" DatabaseItem="false" DataType="Number"'),
])
def test_unsupported_source_metadata_has_visible_coverage(old, new):
    name, xml = documents()[0]
    docs = [(name, xml.replace(old.encode(), new.encode(), 1))]
    plan = build_relation_plan(docs, package(docs))
    assert len(plan["operations"]) == 1
    assert any(row["status"] == "unsupported" for row in plan["coverage"])


@pytest.mark.parametrize("extra", [
    '<Relation Name="SECOND" RelationType="Join" DetailBlock="LINES" JoinCondition="ORDERS.ORDER_ID=LINES.ORDER_ID"/>',
    '<Relation Name="BRANCH" RelationType="Join" DetailBlock="DETAILS" JoinCondition="ORDERS.ORDER_ID=DETAILS.ORDER_ID"/>',
])
def test_duplicate_or_branching_parent_never_silently_selects_one(extra):
    docs = documents(extra_parent=extra)
    plan = build_relation_plan(docs, package(docs))
    assert not any(len(op["join_pairs"]) == 1 for op in plan["operations"])
    assert sum(row["reason"] == "ambiguous_relation_branching" for row in plan["coverage"]) >= 2


def test_cycle_is_rejected_as_whole_graph():
    name, xml = documents()[0]
    xml = xml.replace(b'</Block></FormModule>',
        b'<Relation Name="CYCLE" RelationType="Join" DetailBlock="ORDERS" JoinCondition="DETAILS.ORDER_ID=ORDERS.ORDER_ID"/></Block></FormModule>')
    docs = [(name, xml)]
    plan = build_relation_plan(docs, package(docs))
    assert plan["operations"] == []
    assert {row["reason"] for row in plan["coverage"]} == {"cyclic_relation_context"}


def test_unsupported_second_source_edge_still_makes_the_parent_ambiguous():
    docs = documents(extra_parent='<Relation Name="INVALID_BRANCH" RelationType="Join" DetailBlock="DETAILS" JoinCondition="1=1"/>')
    plan = build_relation_plan(docs, package(docs))
    assert all(len(op["join_pairs"]) != 1 for op in plan["operations"])
    assert any(row["reason"] == "ambiguous_relation_branching" for row in plan["coverage"])


def test_computed_key_is_not_direct_relation_input_and_varchar2_is_supported():
    docs = documents(key_extra='Formula="CEIL(:ORDER_ID)"')
    assert len(build_relation_plan(docs, package(docs))["operations"]) == 1
    docs = documents(key_type="Char")
    plan = build_relation_plan(docs, package(docs))
    assert len(plan["operations"]) == 2
    assert {pair["data_type"] for op in plan["operations"] for pair in op["join_pairs"]} == {"NUMBER", "VARCHAR2"}


@pytest.mark.parametrize("member", ["fox-package/source-manifest.json", "fox-package/source-to-page.json",
                                    "fox-package/supporting-schema.sql", "fox-package/sources/sales.xml"])
def test_source_target_provenance_tampering_stops_before_planning(member):
    docs = documents()
    files = members(package(docs))
    if member.endswith("source-manifest.json"):
        data = json.loads(files[member]); data["source_binding"] = "0" * 64
        files[member] = json.dumps(data).encode()
    elif member.endswith("source-to-page.json"):
        data = json.loads(files[member]); data["blocks"][0]["source_module_id"] = "wrong"
        files[member] = json.dumps(data).encode()
    elif member.endswith("supporting-schema.sql"):
        files[member] = files[member].replace(b" NUMBER", b" DATE", 1)
    else:
        files[member] += b" "
    with pytest.raises(ValueError):
        build_relation_plan(docs, pack(files))
