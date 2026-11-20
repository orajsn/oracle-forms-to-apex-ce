"""Native renderer + SQLite semantic probes; no Oracle/runtime acceptance claim."""
from copy import deepcopy
from html import escape
import json
import sqlite3

import pytest

from forms2apex import native_blueprint, native_relations
from fox.forms_guarded_query import apply_guarded_queries, parse_guard
from fox.forms_native_plan import POLICY_ID, build_native_prototype_plan
from fox.forms_relation_plan import build_relation_plan
from fox.forms_understanding_packet import _build
from fox.prototype_export_only import _members, _zip
from fox.xml_mapping import _blueprint
from fox.xml_mapping import generate_xml_package


def source(module="DISPATCH", parent="HEADERS", child="PACKAGES", guard=None,
           extra="", parent_extra="", child_extra=""):
    guard = guard or f"IF :{parent}.CODE IS NOT NULL AND :{parent}.SEQ IS NOT NULL THEN EXECUTE_QUERY; ELSE NULL; END IF;"
    def field(name, extra=""):
        return f'<Item Name="{name}" DatabaseItem="true" DataType="Char" ItemType="Text Item">{extra}</Item>'
    trigger = f'<Trigger Name="KEY-EXEQRY" TriggerText="{escape(guard, quote=True)}"/>'
    return (f'<FormModule Name="{module}"><Block Name="{parent}" DatabaseBlock="true">'
        + field("CODE") + field("SEQ") + parent_extra
        + f'<Relation Name="CHILDREN" DetailBlock="{child}" RelationType="JOIN" '
          f'JoinCondition="{parent}.CODE = {child}.HEADER_CODE AND {parent}.SEQ = {child}.HEADER_SEQ"/>'
        + f'</Block><Block Name="{child}" DatabaseBlock="true">'
        + field("HEADER_CODE") + field("HEADER_SEQ") + field("VALUE", trigger)
        + extra + child_extra + '</Block></FormModule>').encode()


def prepare(documents):
    """Real structural and relation renderers, independent of assembler wiring."""
    packet, chunks = _build(documents)
    plan = build_native_prototype_plan(documents, _blueprint(packet), project_id="guard-test",
        project_name="Guarded query", approved_policy_id=POLICY_ID)
    spec = plan["rendering_spec"]
    files = _members(native_blueprint.deterministic_prototype_zip(spec))
    trace = native_blueprint.prototype_trace(spec)
    objects = {o["id"]: o for s in packet["sources"] for o in s["facts"]["objects"]}
    for block in trace["blocks"]:
        block["source_module_id"] = objects[block["source_block_id"]]["module_id"]
    manifest = {"schema_version": 1, "source_binding": packet["source_binding"],
        "files": [{k: s["source"][k] for k in ("name", "sha256", "bytes")} for s in packet["sources"]],
        "selected_chunk_hashes": {c["id"]: c["sha256"] for c in chunks}}
    for name, value in (("source-manifest.json", manifest), ("source-to-page.json", trace)):
        files["fox-package/" + name] = json.dumps(value).encode()
    files["fox-package/supporting-schema.sql"] = native_blueprint.render_prototype_schema(spec).encode()
    for name, raw in documents:
        files["fox-package/sources/" + name] = raw
    relation_plan = build_relation_plan(documents, _zip(files))
    if relation_plan["operations"]:
        rendered, _ = native_relations.render_relation_package(_zip(files), relation_plan)
        files = _members(rendered)
    else:
        files["fox-package/relation-plan.json"] = json.dumps(relation_plan).encode()
    return packet, chunks, trace, files


def apply(documents=None):
    documents = documents or [("dispatch.xml", source())]
    args = prepare(documents)
    files, receipt = apply_guarded_queries(documents, *args)
    return files, receipt, args


def test_whole_guard_native_action_preserves_query_parent_and_inputs():
    documents = [("dispatch.xml", source())]
    args = prepare(documents)
    original = deepcopy((documents, args))
    files, receipt = apply_guarded_queries(documents, *args)
    assert (documents, args) == original
    assert (files, receipt) == apply_guarded_queries(documents, *args)
    assert len(receipt["generated_operations"]) == 1 and not receipt["gaps"]
    op = receipt["generated_operations"][0]
    page = files[op["target"]["page_file"]].decode()
    assert "label: Execute query\n" in page and "type: rowsReturned\n" in page
    assert "action: redirectThisApp\n" in page
    button = page.split("    button guarded-execute-query (", 1)[1].split("    region guarded-query-scope", 1)[0]
    assert f"page: {op['target']['page_id']}\n" in button
    # False guard omits the action in APEX; no fallback/empty submit exists.
    assert all(s not in button for s in ("submitPage", "apex.submit", "javaScript", "request:", "items:", "clearCache:"))
    assert "storage: session\n" in page and "checksumRequiredSessionLevel\n" in page
    assert "argumentsMustHaveChecksum\n" in page
    assert all(not op[k] for k in ("runtime_verified", "business_accepted"))
    assert "automatic Forms coordination" in op["adaptation"]
    assert "    process " not in page and "    branch " not in page
    assert files["fox-package/sources/dispatch.xml"] == documents[0][1]
    unchanged = set(args[3]) - {op["target"]["page_file"]}
    assert all(files[name] == args[3][name] for name in unchanged)


def test_emitted_sql_enforces_every_guard_and_keeps_sibling_filter_without_writes():
    _, receipt, (_, _, trace, files) = apply()
    op = receipt["generated_operations"][0]
    relations = json.loads(files["fox-package/relation-plan.json"])["operations"]
    relation = next(r for r in relations if r["relation_id"] == op["relation_id"])
    parent = next(b for b in trace["blocks"] if b["source_block_id"] == relation["parent_block_id"])
    child = next(b for b in trace["blocks"] if b["source_block_id"] == relation["child_block_id"])
    connection = sqlite3.connect(":memory:")
    for block in (parent, child):
        cols = ",".join(["FOX_ROW_ID integer"] + [i["column"] + " text" for i in block["items"]])
        connection.execute(f"create table {block['table_name']} ({cols})")
    connection.executemany(f"insert into {parent['table_name']} values (?,?,?)",
                           [(1, "A", "1"), (2, "B", "1"), (3, None, "1"), (4, "A", None), (5, "C", "1")])
    connection.executemany(f"insert into {child['table_name']} values (?,?,?,?)",
                           [(11, "A", "1", "selected"), (12, "B", "1", "sibling"), (13, "A", "2", "wrong second key")])
    for selected, expected, enabled in ((None, [], False), (1, [11], True), (2, [12], True),
                                        (3, [], False), (4, [], False), (5, [], True), (999, [], False)):
        before = connection.total_changes
        binds = {op["target"]["parent_item"]: selected}
        assert [r[0] for r in connection.execute(op["guarded_query_sql"], binds)] == expected
        assert bool(connection.execute(op["button_condition_sql"], binds).fetchall()) == enabled
        assert connection.total_changes == before
    # Recheck on every refresh: formerly valid context cannot bypass a new NULL.
    connection.execute(f"update {parent['table_name']} set {op['guard_bindings'][1]['column']}=null where FOX_ROW_ID=1")
    binds = {op["target"]["parent_item"]: 1}
    assert not connection.execute(op["button_condition_sql"], binds).fetchall()
    assert not connection.execute(op["guarded_query_sql"], binds).fetchall()


def test_unqualified_unique_parent_reference_and_export_tabs():
    files, receipt, _ = apply([("renamed.xml", source(guard="IF :CODE IS NOT NULL THEN &#10;\\tEXECUTE_QUERY; ELSE &#10;\\tNULL; END IF;\\t"))])
    op = receipt["generated_operations"][0]
    assert len(op["guard_bindings"]) == 1
    assert op["decode_receipt"]["substitutions"] and op["decode_receipt"]["literal_export_tab_offsets"]
    assert files["fox-package/sources/renamed.xml"].endswith(b"</FormModule>")


def test_integrated_multiline_calculation_projection_and_native_actions_are_retained():
    raw = source(child_extra='<Item Name="WEIGHT" DatabaseItem="true" DataType="Number" ItemType="Text Item"/>'
                 '<Item Name="ROUNDED" DatabaseItem="false" DataType="Number" ItemType="Display Item" Formula="CEIL(:WEIGHT)"/>')
    candidate, report = generate_xml_package([("calculated.xml", raw)], "calc-guard", "Calculated query", POLICY_ID)
    files = _members(candidate)
    receipt = report["guarded_query_receipt"]
    assert len(receipt["generated_operations"]) == 1 and not receipt["gaps"]
    op = receipt["generated_operations"][0]
    query = op["guarded_query_sql"]
    assert "ceil(" in query and "\n                    " in query
    relation = next(r for r in report["relation_plan"]["operations"] if r["relation_id"] == op["relation_id"])
    for pair in relation["join_pairs"]:
        assert f"fox_parent.{pair['parent_column']} = fox_child.{pair['child_column']}" in query
    assert all(f"fox_parent.{b['column']} is not null" in query for b in op["guard_bindings"])
    assert "ceil(" in files[op["target"]["page_file"]].decode()
    assert files["fox-package/sources/calculated.xml"] == raw


@pytest.mark.parametrize("text", [
    "IF :CODE IS NOT NULL THEN EXECUTE_QUERY; END IF;",
    "IF :CODE IS NOT NULL OR :SEQ IS NOT NULL THEN EXECUTE_QUERY; ELSE NULL; END IF;",
    "IF :CODE IS NOT NULL THEN EXECUTE_QUERY; ELSE EXECUTE_QUERY; END IF;",
    "IF :CODE IS NOT NULL THEN EXECUTE_QUERY; ELSE NULL; END IF; COMMIT;",
    "IF :CODE IS NOT NULL THEN DELETE FROM X; EXECUTE_QUERY; ELSE NULL; END IF;",
    "IF :CODE IS NOT NULL AND :CODE IS NOT NULL THEN EXECUTE_QUERY; ELSE NULL; END IF;",
    "IF :CODE IS NOT NULL THEN EXECUTE_QUERY(); ELSE NULL; END IF;",
    "NULL;",
])
def test_partial_and_unknown_patterns_do_not_generate(text):
    with pytest.raises(ValueError):
        parse_guard(text)
    _, receipt, _ = apply([("unknown.xml", source(guard=text))])
    assert not receipt["generated_operations"] and len(receipt["gaps"]) == 1


def test_renamed_multiple_modules_bind_only_own_parent_and_detail():
    docs = [("one.xml", source(module="FREIGHT", parent="SHIPMENTS", child="CRATES")),
            ("two.xml", source(module="DELIVERY", parent="JOURNEYS", child="STOPS"))]
    _, receipt, _ = apply(docs)
    ops = receipt["generated_operations"]
    assert len(ops) == 2
    assert len({op["source_module_id"] for op in ops}) == 2
    assert len({op["target"]["page_file"] for op in ops}) == 2
    assert len({op["parent_block_id"] for op in ops}) == 2


@pytest.mark.parametrize("change", ["ambiguous_name", "child_reference", "partial_binding", "computed_parent", "conflicting_key", "multiple_guards", "ambiguous_relation"])
def test_ambiguous_partial_or_conflicting_bindings_stay_gaps(change):
    raw = source()
    if change == "ambiguous_name":
        raw = source(guard="IF :CODE IS NOT NULL THEN EXECUTE_QUERY; ELSE NULL; END IF;", child_extra='<Item Name="CODE" DatabaseItem="true" DataType="Char" ItemType="Text Item"/>')
    if change == "child_reference":
        raw = source(guard="IF :PACKAGES.HEADER_CODE IS NOT NULL THEN EXECUTE_QUERY; ELSE NULL; END IF;")
    if change == "partial_binding":
        raw = source(guard="IF :HEADERS.CODE IS NOT NULL AND :HEADERS.MISSING IS NOT NULL THEN EXECUTE_QUERY; ELSE NULL; END IF;")
    if change == "computed_parent":
        raw = raw.replace(b'Name="CODE" DatabaseItem', b'Name="CODE" Formula="SOMETHING()" DatabaseItem', 1)
    if change == "conflicting_key":
        raw = source(child_extra='<Trigger Name="KEY-EXEQRY" TriggerText="NULL;"/>')
    if change == "multiple_guards":
        guard = escape("IF :HEADERS.CODE IS NOT NULL THEN EXECUTE_QUERY; ELSE NULL; END IF;", quote=True)
        raw = source(child_extra=f'<Item Name="SECOND" DatabaseItem="true" DataType="Char" ItemType="Text Item"><Trigger Name="KEY-EXEQRY" TriggerText="{guard}"/></Item>')
    if change == "ambiguous_relation":
        raw = source(parent_extra='<Relation Name="EXTRA" DetailBlock="PACKAGES" RelationType="JOIN" JoinCondition="unsupported"/>')
    _, receipt, (_, _, _, originals) = apply([("bad.xml", raw)])
    assert not receipt["generated_operations"] and receipt["gaps"]


@pytest.mark.parametrize("change", ["unprotected", "session", "query", "join", "chunk", "trace", "original"])
def test_changed_security_context_source_or_filter_never_acquires_action(change):
    docs = [("dispatch.xml", source())]
    packet, chunks, trace, files = prepare(docs)
    op = json.loads(files["fox-package/relation-receipt.json"])["generated_operations"][0]
    path = op["page_file"]
    if change == "unprotected": files[path] = files[path].replace(b"checksumRequiredSessionLevel", b"unrestricted")
    if change == "session": files[path] = files[path].replace(b"storage: session", b"storage: request")
    if change == "query": files[path] = files[path].replace(b"fox_parent.FOX_ROW_ID = :", b"fox_parent.FOX_ROW_ID != :")
    if change == "join":
        plan = json.loads(files["fox-package/relation-plan.json"])
        plan["operations"][0]["join_pairs"].pop()
        files["fox-package/relation-plan.json"] = json.dumps(plan).encode()
    if change == "chunk": chunks[0]["text"] += " COMMIT;"
    if change == "trace": trace["blocks"][0]["table_name"] = "WRONG"
    if change == "original": files["fox-package/sources/dispatch.xml"] += b" "
    if change in ("trace", "original"):
        with pytest.raises(ValueError): apply_guarded_queries(docs, packet, chunks, trace, files)
    else:
        result, receipt = apply_guarded_queries(docs, packet, chunks, trace, files)
        assert not receipt["generated_operations"] and receipt["gaps"]
        assert result == files
