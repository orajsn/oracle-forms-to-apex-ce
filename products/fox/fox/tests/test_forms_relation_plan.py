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
from forms2apex import native_blueprint, native_behavior, native_relations


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
    "LINES.ORDER_ID = OTHER.ORDER_ID", "ORDER_ID = ORDER_ID",
    "LINES.ORDER_ID = ORDER_ID", "ORDER_ID = LINES.ORDER_ID",
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


def test_duplicate_child_declarations_never_silently_select_one():
    extra = '<Relation Name="SECOND" RelationType="Join" DetailBlock="LINES" JoinCondition="ORDERS.ORDER_ID=LINES.ORDER_ID"/>'
    docs = documents(extra_parent=extra)
    plan = build_relation_plan(docs, package(docs))
    assert not any(len(op["join_pairs"]) == 1 for op in plan["operations"])
    assert sum(row["reason"] == "ambiguous_relation_branching" for row in plan["coverage"]) >= 2


def test_multiple_incoming_rejects_both_target_edges_but_keeps_independent_child():
    docs = documents(extra_parent='<Relation Name="BRANCH" RelationType="Join" DetailBlock="DETAILS" JoinCondition="ORDERS.ORDER_ID=DETAILS.ORDER_ID"/>')
    plan = build_relation_plan(docs, package(docs))
    assert len(plan["operations"]) == 1
    assert len(plan["operations"][0]["join_pairs"]) == 1
    assert sum(row["reason"] == "ambiguous_relation_branching" for row in plan["coverage"]) == 2


def test_cycle_is_rejected_as_whole_graph():
    name, xml = documents()[0]
    xml = xml.replace(b'</Block></FormModule>',
        b'<Relation Name="CYCLE" RelationType="Join" DetailBlock="ORDERS" JoinCondition="DETAILS.ORDER_ID=ORDERS.ORDER_ID"/></Block></FormModule>')
    docs = [(name, xml)]
    plan = build_relation_plan(docs, package(docs))
    assert plan["operations"] == []
    assert {row["reason"] for row in plan["coverage"]} == {"cyclic_relation_context"}


def test_unsupported_second_incoming_edge_still_makes_the_child_ambiguous():
    docs = documents(extra_parent='<Relation Name="INVALID_BRANCH" RelationType="Join" DetailBlock="DETAILS" JoinCondition="1=1"/>')
    plan = build_relation_plan(docs, package(docs))
    assert len(plan["operations"]) == 1
    assert len(plan["operations"][0]["join_pairs"]) == 1
    assert any(row["reason"] == "ambiguous_relation_branching" for row in plan["coverage"])


def sibling_documents(count=6, *, condition=None, parent_extra="", child_extra="", last_extra=""):
    """Synthetic customer/branch analogue; no original customer input or data."""
    item = lambda name: f'<Item Name="{name}" ItemType="Text Item" DatabaseItem="true" DataType="Char"/>'
    relation = lambda i: (f'<Relation Name="CUSTOMER_DETAIL_{i}" RelationType="Join" DetailBlock="DETAIL{i}" '
        f'JoinCondition="{escape(condition or "DETAIL_ID=CUSTOMERS.CUST_ID AND DETAIL_BRANCH=CUSTOMERS.CUST_BRANCH", quote=True)}" '
        'AutoQuery="false" Deferred="false" DeleteRecord="Non Isolated" PreventMasterlessOperations="false"/>')
    xml = ('<FormModule Name="COMPOSITE"><Block Name="CUSTOMERS" DatabaseBlock="true">'
           + item("CUST_ID") + item("CUST_BRANCH") + parent_extra
           + ''.join(relation(i) for i in range(count)) + '</Block>'
           + ''.join(f'<Block Name="DETAIL{i}" DatabaseBlock="true">' + item("DETAIL_ID")
                     + item("DETAIL_BRANCH") + child_extra + (last_extra if i == count - 1 else "")
                     + '</Block>' for i in range(count)) + '</FormModule>')
    return [("composite.xml", xml.encode())]


@pytest.mark.parametrize("condition", [
    "DETAIL_ID=CUSTOMERS.CUST_ID AND DETAIL_BRANCH=CUSTOMERS.CUST_BRANCH",
    "CUSTOMERS.CUST_ID=DETAIL_ID AND CUSTOMERS.CUST_BRANCH=DETAIL_BRANCH",
    "DETAIL_ID = CUSTOMERS.CUST_ID AND CUSTOMERS.CUST_BRANCH = DETAIL_BRANCH",
])
def test_six_independent_children_bind_both_keys_without_lifecycle_claims(condition):
    docs = sibling_documents(condition=condition)
    raw = package(docs)
    plan = build_relation_plan(docs, raw)
    assert plan == build_relation_plan(docs, raw)
    assert len(plan["operations"]) == 6
    assert len({op["child_block_id"] for op in plan["operations"]}) == 6
    assert len({op["parent_block_id"] for op in plan["operations"]}) == 1
    assert all(len(op["join_pairs"]) == 2 for op in plan["operations"])
    packet, _ = _build(docs)
    names = {obj["id"]: obj["name"] for entry in packet["sources"] for obj in entry["facts"]["objects"]}
    for op in plan["operations"]:
        assert [(names[p["parent_item_id"]], names[p["child_item_id"]]) for p in op["join_pairs"]] == [
            ("CUST_ID", "DETAIL_ID"), ("CUST_BRANCH", "DETAIL_BRANCH")]
        assert len({p["parent_item_id"] for p in op["join_pairs"]}) == 2
        assert len({p["child_item_id"] for p in op["join_pairs"]}) == 2
        assert {p["data_type"] for p in op["join_pairs"]} == {"VARCHAR2"}
        assert op["source_flags"] == {"AutoQuery": "false", "Deferred": "false",
            "DeleteRecord": "Non Isolated", "PreventMasterlessOperations": "false"}
    assert all(row["reason"] == "manual_navigation_without_assignment_context" for row in plan["coverage"])
    assert all(row["unimplemented_lifecycle"] == ["AutoQuery", "Deferred", "DeleteRecord", "PreventMasterlessOperations"]
               for row in plan["coverage"])
    assert all(plan[key] is False for key in ("native_generated", "runtime_verified", "business_accepted"))
    unsigned = {key: value for key, value in plan.items() if key != "plan_sha256"}
    assert plan["plan_sha256"] == native_relations._sha(native_relations._json(unsigned))


def test_composite_sibling_navigation_preserves_the_saved_rate_editor():
    from xml.etree import ElementTree as ET
    from fox.forms_native_plan import POLICY_ID
    from fox.xml_mapping import generate_xml_package
    from test_forms_rate_numbers import SOURCE as rate_source

    form = ET.fromstring(rate_source)
    parent = form.find("./Block[@Name='HEADER']")
    rates = form.find("./Block[@Name='LINES']")
    notes = ET.SubElement(form, 'Block', Name='NOTES', DatabaseBlock='true')
    for block, fields in ((parent, ['ACCOUNT', 'BRANCH']), (rates, ['BILL_TO', 'BILL_BRANCH']),
                          (notes, ['NOTE_ACCOUNT', 'NOTE_BRANCH'])):
        for name in fields:
            ET.SubElement(block, 'Item', Name=name, ColumnName=name, DatabaseItem='true',
                          ItemType='Text Item', DataType='Char', MaximumLength='20')
    for child, keys in [('LINES', ('BILL_TO', 'BILL_BRANCH')), ('NOTES', ('NOTE_ACCOUNT', 'NOTE_BRANCH'))]:
        ET.SubElement(parent, 'Relation', Name='HEADER_' + child, DetailBlock=child, RelationType='Join',
                      JoinCondition=f'{keys[0]}=HEADER.ACCOUNT AND {keys[1]}=HEADER.BRANCH', AutoQuery='false')
    _, generated = generate_xml_package([('shipping.xml', ET.tostring(form))],
                                         'rates-by-account', 'Rates by account', POLICY_ID)
    relations = generated['relation_receipt']['generated_operations']
    assert len(relations) == 2 and len({op['selector_page_id'] for op in relations}) == 1
    meta = generated['metadata']
    assert meta['row_lookup_summary'] == {'editors': 1, 'mapped_returns': 5}
    workspace, = meta['saved_lookup_workspaces']
    amount, = workspace['stored_number_fields']
    assert amount['name'] == 'AMOUNT' and amount['column'] == 'N001'


def test_bare_child_parser_requires_unique_declared_child_evidence():
    join = "DETAIL_ID=CUSTOMERS.CUST_ID AND CUSTOMERS.CUST_BRANCH=DETAIL_BRANCH"
    assert parse_join_condition(join, "CUSTOMERS", "DETAIL0",
        child_item_names=["detail_id", "detail_branch"]) == [("CUST_ID", "DETAIL_ID"), ("CUST_BRANCH", "DETAIL_BRANCH")]
    for names in (None, [], ["DETAIL_ID"], ["DETAIL_ID", "DETAIL_BRANCH", "detail_id"]):
        with pytest.raises(UnsupportedRelation):
            parse_join_condition(join, "CUSTOMERS", "DETAIL0", child_item_names=names)
    four = " AND ".join(f"K{i}=CUSTOMERS.P{i}" for i in range(4))
    assert len(parse_join_condition(four, "CUSTOMERS", "DETAIL0", child_item_names=[f"K{i}" for i in range(4)])) == 4


@pytest.mark.parametrize("condition", [
    "UNKNOWN=CUSTOMERS.CUST_ID", "DETAIL_ID=CUSTOMERS.UNKNOWN", "DETAIL_ID=OTHER.CUST_ID",
    "DETAIL0.DETAIL_ID=CUST_ID", "DETAIL_ID=CUST_ID", "DETAIL_ID=CUSTOMERS.CUST_ID OR 1=1",
    "DETAIL_ID=CUSTOMERS.CUST_ID AND DETAIL_BRANCH=CUSTOMERS.CUST_ID",
    "DETAIL_ID=CUSTOMERS.CUST_ID AND DETAIL_ID=CUSTOMERS.CUST_BRANCH",
    "DETAIL_ID=CUSTOMERS.CUST_ID /* suffix */", ":DETAIL_ID=CUSTOMERS.CUST_ID",
])
def test_unqualified_child_unsupported_shapes_fail_closed(condition):
    docs = sibling_documents(count=1, condition=condition)
    plan = build_relation_plan(docs, package(docs))
    assert plan["operations"] == []
    assert plan["coverage"][0]["status"] == "unsupported"


def test_unsupported_duplicate_child_edge_still_rejects_supported_sibling_edge():
    extra = '<Relation Name="INVALID_DUPLICATE" RelationType="Join" DetailBlock="DETAIL0" JoinCondition="1=1"/>'
    docs = sibling_documents(count=2, parent_extra=extra)
    plan = build_relation_plan(docs, package(docs))
    assert len(plan["operations"]) == 1
    assert sum(row["reason"] == "ambiguous_relation_branching" for row in plan["coverage"]) == 1


def test_branching_graph_cycle_is_detected_even_with_multiple_outgoing_edges():
    cycle = '<Relation Name="BACK" RelationType="Join" DetailBlock="CUSTOMERS" JoinCondition="CUSTOMERS.CUST_ID=DETAIL1.DETAIL_ID"/>'
    docs = sibling_documents(count=2, last_extra=cycle)
    plan = build_relation_plan(docs, package(docs))
    assert plan["operations"] == []
    assert {row["reason"] for row in plan["coverage"]} == {"cyclic_relation_context"}


def test_relation_capacity_remains_a_visible_limit(monkeypatch):
    docs = sibling_documents(count=2)
    raw = package(docs)
    monkeypatch.setattr(native_relations, "MAX_RELATIONS", 1)
    plan = build_relation_plan(docs, raw)
    assert len(plan["operations"]) == 1
    assert sum(row["reason"] == "relation_page_limit" for row in plan["coverage"]) == 1


@pytest.mark.parametrize("old,new", [
    ('<Block Name="DETAIL1"', '<Block Name="detail0"'),
    ('<Block Name="DETAIL1"', '<Block Name="customers"'),
    ('<Item Name="DETAIL_BRANCH"', '<Item Name="DETAIL_ID"'),
])
def test_case_insensitive_source_name_ambiguity_fails_before_relation_package(old, new):
    name, xml = sibling_documents(count=2)[0]
    docs = [(name, xml.replace(old.encode(), new.encode(), 1))]
    with pytest.raises(ValueError, match="Duplicate source block or item identity"):
        package(docs)


def test_unqualified_composite_key_requires_exact_compatible_target_types():
    name, xml = sibling_documents(count=1)[0]
    xml = xml.replace(b'Name="DETAIL_BRANCH" ItemType="Text Item" DatabaseItem="true" DataType="Char"',
                      b'Name="DETAIL_BRANCH" ItemType="Text Item" DatabaseItem="true" DataType="Number"')
    docs = [(name, xml)]
    plan = build_relation_plan(docs, package(docs))
    assert plan["operations"] == []
    assert plan["coverage"][0]["reason"] == "same_relation_key_types_required"


def test_unsupported_cycle_declaration_blocks_supported_context_navigation():
    cycle = '<Relation Name="BACK" RelationType="Join" DetailBlock="CUSTOMERS" JoinCondition="1=1"/>'
    docs = sibling_documents(count=2, last_extra=cycle)
    plan = build_relation_plan(docs, package(docs))
    assert plan["operations"] == []
    assert sum(row["reason"] == "cyclic_relation_context" for row in plan["coverage"]) == 2


def test_self_relation_is_never_a_manual_context():
    self_edge = '<Relation Name="SELF" RelationType="Join" DetailBlock="CUSTOMERS" JoinCondition="CUSTOMERS.CUST_ID=CUSTOMERS.CUST_ID"/>'
    docs = sibling_documents(count=1, parent_extra=self_edge)
    plan = build_relation_plan(docs, package(docs))
    assert plan["operations"] == []
    assert any(row["reason"] == "cyclic_relation_context" for row in plan["coverage"])


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
