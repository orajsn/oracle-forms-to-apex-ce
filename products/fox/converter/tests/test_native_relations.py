"""Generated read-navigation artifacts and local SQL semantics, never live proof."""
from copy import deepcopy
import io
import json
import re
import sqlite3
import zipfile

import pytest

from forms2apex import native_relations as renderer
from forms2apex import native_blueprint
from test_native_blueprint import source_id, field


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


def fixture(block_count=3):
    # Standalone converter fixture: target-bound IR is synthetic, not presented
    # as proof of a source recognizer. Fresh-source grammar tests live in FOX.
    spec = {"schema_version": 1, "profile_id": native_blueprint.PROFILE_ID,
            "data_mode": "synthetic_test_only", "project_id": "relation-renderer",
            "project_name": "Relation renderer", "source_binding": "a" * 64, "blocks": []}
    for index in range(1, block_count + 1):
        block_id = source_id(index)
        table = "FOX_NATIVE_" + renderer._sha(renderer._json([spec["project_id"], spec["source_binding"], block_id]))[:19].upper()
        spec["blocks"].append({"source_block_id": block_id, "name": f"BLOCK_{index}", "sequence": index,
            "classification": "database", "native_component": "report", "table_name": table,
            "fields": [field(index * 1000 + j, kind="NUMBER", edit=False) for j in range(3)]})
    files = {name: text.encode() for name, text in native_blueprint.render_native_blueprint(spec).items()}
    trace = native_blueprint.prototype_trace(spec)
    for block in trace["blocks"]:
        block["source_module_id"] = source_id(99)
    original = b'<FormModule Name="SYNTHETIC"/>'
    sources = [{"name": "synthetic.xml", "sha256": renderer._sha(original), "bytes": len(original)}]
    manifest = {"source_binding": spec["source_binding"], "files": sources, "selected_chunk_hashes": {}}
    files[renderer.MANIFEST] = renderer._json(manifest)
    files[renderer.TRACE] = renderer._json(trace)
    files["fox-package/supporting-schema.sql"] = native_blueprint.render_prototype_schema(spec).encode()
    files["fox-package/sources/synthetic.xml"] = original
    # A preexisting generated numeric projection must survive the relation clone.
    block = trace["blocks"][1]
    text = files[block["report_file"]].decode()
    match, _ = renderer._report_source(text, block)
    computed = block["items"][-1]["column"]
    projection = ", ".join(["FOX_ROW_ID"] + [f"ceil({i['column']}) as {i['column']}" if i["column"] == computed
                                           else i["column"] for i in block["items"]])
    source = ("        source {\n            location: localDatabase\n            type: sqlQuery\n"
              "            sqlQuery:\n                ```sql\n"
              f"                select {projection}\n                from {block['table_name']}\n"
              "                ```\n        }")
    files[block["report_file"]] = (text[:match.start()] + source + text[match.end():]).encode()
    raw = pack(files)
    plan = {"schema_version": 1, "scope": renderer.SCOPE, "source_binding": spec["source_binding"],
            "parent_zip_sha256": renderer._sha(raw), "source_manifest_sha256": renderer._sha(files[renderer.MANIFEST]),
            "parent_trace_sha256": renderer._sha(files[renderer.TRACE]),
            "parent_trace_canonical_sha256": renderer._sha(renderer._json(trace)), "sources": sources,
            "operations": [], "coverage": [], "native_generated": False, "runtime_verified": False,
            "business_accepted": False}
    for index in range(2):
        parent, child = trace["blocks"][index:index + 2]
        relation_id = source_id(90 + index)
        op = {"relation_id": relation_id, "source_module_id": source_id(99),
              "parent_block_id": parent["source_block_id"], "child_block_id": child["source_block_id"],
              "source_attribute_sha256": str(index) * 64, "source_flags": {"AutoQuery": "false", "Deferred": "false",
              "DeleteRecord": "Cascading", "PreventMasterlessOperations": "false"}, "join_pairs": []}
        for role, target in (("parent", parent), ("child", child)):
            op[role] = {"table": target["table_name"], "report_file": target["report_file"],
                        "report_page_id": target["report_page_id"], "row_id_column": "FOX_ROW_ID"}
        for offset in range(index + 1):
            p, c = parent["items"][offset], child["items"][offset]
            op["join_pairs"].append({"parent_item_id": p["source_item_id"], "parent_column": p["column"],
                                    "child_item_id": c["source_item_id"], "child_column": c["column"], "data_type": "NUMBER"})
        plan["operations"].append(op)
        plan["coverage"].append({"relation_id": relation_id, "source_module_id": source_id(99),
            "source_attribute_sha256": op["source_attribute_sha256"], "status": "read_navigation_planned",
            "reason": "manual_read_navigation_only", "unimplemented_lifecycle":
            ["AutoQuery", "Deferred", "DeleteRecord", "PreventMasterlessOperations"],
            "runtime_verified": False, "business_accepted": False})
    return raw, reseal(plan)


def retarget(raw, operation, parent_index, child_index):
    """Rebind only synthetic target facts; never infer a source relation."""
    blocks = json.loads(members(raw)[renderer.TRACE])["blocks"]
    parent, child = blocks[parent_index], blocks[child_index]
    for role, block in (("parent", parent), ("child", child)):
        operation[role + "_block_id"] = block["source_block_id"]
        operation[role] = {"table": block["table_name"], "report_file": block["report_file"],
                           "report_page_id": block["report_page_id"], "row_id_column": "FOX_ROW_ID"}
    for offset, pair in enumerate(operation["join_pairs"]):
        for role, block in (("parent", parent), ("child", child)):
            pair[role + "_item_id"] = block["items"][offset]["source_item_id"]
            pair[role + "_column"] = block["items"][offset]["column"]


def fanout_fixture():
    raw, plan = fixture()
    # Both children use customer ID AND branch, including the later operation.
    plan["operations"][0]["join_pairs"].append(deepcopy(plan["operations"][1]["join_pairs"][1]))
    for index, operation in enumerate(plan["operations"], 1):
        retarget(raw, operation, 0, index)
    return raw, reseal(plan)


def reseal(plan):
    plan["plan_sha256"] = renderer._sha(renderer._json({k: v for k, v in plan.items() if k != "plan_sha256"}))
    return plan


def test_deterministic_one_application_originals_preserved_and_read_only_claims():
    raw, plan = fixture()
    before = deepcopy(plan), raw
    output, receipt = renderer.render_relation_package(raw, plan)
    assert renderer.render_relation_package(raw, plan) == (output, receipt)
    assert (plan, raw) == before
    originals, generated = members(raw), members(output)
    assert set(originals) <= set(generated)
    assert {name for name in originals if originals[name] != generated[name]} == set(receipt["changed_members"])
    assert len(receipt["added_pages"]) == 2
    assert sum(data.startswith(b"app ") for data in generated.values()) == 1
    assert receipt["runtime_verified"] is receipt["business_accepted"] is receipt["write_lifecycle"] is False
    assert receipt["source_parser_rebuild_required_at_gateway"] is True
    assert receipt["validation"] == {"status": "pending", "passed": False, "parent_validation_applies": False}
    assert {row["status"] for row in receipt["coverage"]} == {"read_navigation_generated"}
    for row in receipt["generated_operations"]:
        page = generated[row["page_file"]].decode()
        assert "pageAccessProtection: argumentsMustHaveChecksum" in page
        assert "sessionStateProtection: checksumRequiredSessionLevel" in page
        assert "storage: session" in page and "dataType: number" in page
        assert "pageItemsToSubmit" not in page
        assert "last selection" in page and "remain unconverted" in page
        assert not re.search(r"^    (?:button|process)\b", page, re.M)
        assert "automaticRowProcessing" not in page


def test_chain_clone_inherits_outgoing_column_link_and_preserves_calculation():
    raw, plan = fixture()
    output, receipt = renderer.render_relation_package(raw, plan)
    generated = members(output)
    by_id = {op["relation_id"]: op for op in plan["operations"]}
    chain = next(op for op in plan["operations"] if len(op["join_pairs"]) == 1)
    next_relation = next(op for op in plan["operations"] if len(op["join_pairs"]) == 2)
    row = next(row for row in receipt["generated_operations"] if row["relation_id"] == chain["relation_id"])
    next_row = next(row for row in receipt["generated_operations"] if row["relation_id"] == next_relation["relation_id"])
    page = generated[row["page_file"]].decode()
    assert "ceil(" in page
    assert f"P{next_row['page_id']}_PARENT_ID: \"#FOX_ROW_ID#\"" in page
    assert "            type: link\n" in page
    assert "            displayColumn FOX_ROW_ID (" in page
    for relation_id, op in by_id.items():
        base = generated[op["parent"]["report_file"]].decode()
        assert "linkText: View related records" in base
        assert not any(f'"#{pair["parent_column"]}#"' in base for pair in op["join_pairs"])


def test_existing_report_validation_link_is_preserved_on_base_and_clone():
    raw, plan = fixture()
    files = members(raw)
    child_report = next(op["child"]["report_file"] for op in plan["operations"] if len(op["join_pairs"]) == 1)
    original_link = b'''        link {
            linkColumn: customTarget
            target: {
                page: 800
                clearCache: 800
                items: {
                    P800_FOX_ROW_ID: "#FOX_ROW_ID#"
                }
            }
            linkIcon: Validate
        }
'''
    text = files[child_report]
    position = text.index(b"        column ")
    files[child_report] = text[:position] + original_link + text[position:]
    raw = pack(files)
    plan["parent_zip_sha256"] = renderer._sha(raw)
    reseal(plan)
    output, receipt = renderer.render_relation_package(raw, plan)
    after = members(output)
    assert original_link in after[child_report]
    clone = next(row for row in receipt["generated_operations"] if row["relation_id"] ==
                 next(op["relation_id"] for op in plan["operations"] if op["child"]["report_file"] == child_report))
    assert original_link in after[clone["page_file"]]
    assert b"linkText: View related records" in after[clone["page_file"]]


def test_generated_exists_sql_filters_composite_null_missing_and_deleted_parent_locally():
    raw, plan = fixture()
    output, receipt = renderer.render_relation_package(raw, plan)
    files = members(output)
    relation = next(op for op in plan["operations"] if len(op["join_pairs"]) == 2)
    generated = next(row for row in receipt["generated_operations"] if row["relation_id"] == relation["relation_id"])
    text = files[generated["page_file"]].decode()
    query = re.search(r"```sql\n(.*?)\n                ```", text, re.S)[1]
    query = "\n".join(line.removeprefix("                ") for line in query.splitlines())
    conn = sqlite3.connect(":memory:")
    parent, child = relation["parent"]["table"], relation["child"]["table"]
    pc = [p["parent_column"] for p in relation["join_pairs"]]
    cc = [p["child_column"] for p in relation["join_pairs"]]
    trace = json.loads(files[renderer.TRACE])
    child_columns = [item["column"] for block in trace["blocks"]
                     if block["source_block_id"] == relation["child_block_id"] for item in block["items"]]
    conn.execute(f"create table {parent}(FOX_ROW_ID number, {pc[0]} number, {pc[1]} number)")
    conn.execute(f"create table {child}(FOX_ROW_ID number, " + ", ".join(col + " number" for col in child_columns) + ")")
    conn.executemany(f"insert into {parent} values(?,?,?)", [(1, 10, 20), (2, 10, 30), (3, None, 20)])
    conn.executemany(f"insert into {child}(FOX_ROW_ID,{cc[0]},{cc[1]}) values(?,?,?)",
                     [(11, 10, 20), (12, 10, 30), (13, None, 20), (14, 90, 20)])
    def selected(context):
        return [row[0] for row in conn.execute(query, {generated["parent_item"]: context})]
    assert selected(1) == [11]
    assert selected(2) == [12]
    assert selected(None) == selected(999) == selected(3) == []
    conn.execute(f"delete from {parent} where FOX_ROW_ID=1")
    assert selected(1) == []
    conn.close()


@pytest.mark.parametrize("mutation", [
    lambda p: p.update(untrusted_sql="select * from secrets"),
    lambda p: p["operations"][0]["join_pairs"][0].update(parent_column="UNBOUND"),
    lambda p: p["operations"][0]["parent"].update(table="WRONG_TABLE"),
    lambda p: p["operations"][0].update(source_module_id="wrong-module"),
    lambda p: p["operations"][0]["join_pairs"][0].update(data_type="DATE"),
    lambda p: p["operations"][0]["source_flags"].update(AutoQuery="perhaps"),
    lambda p: p["coverage"][0].update(status="read_navigation_generated"),
    lambda p: p.update(runtime_verified=True),
    lambda p: p.update(parent_trace_canonical_sha256="0" * 64),
])
def test_closed_target_contract_rejects_resealed_tampering(mutation):
    raw, plan = fixture()
    mutation(plan)
    reseal(plan)
    with pytest.raises(ValueError):
        renderer.render_relation_package(raw, plan)


def test_original_parent_tampering_and_second_adaptation_are_rejected():
    raw, plan = fixture()
    with pytest.raises(ValueError):
        renderer.render_relation_package(raw + b"changed", plan)
    rendered, _ = renderer.render_relation_package(raw, plan)
    with pytest.raises(ValueError):
        renderer.render_relation_package(rendered, plan)


def test_generated_projection_preserves_inert_literals_and_checks_exact_slots():
    renderer._projection_columns("FOX_ROW_ID, case when 'FROM; -- , ''literal''' = 'select' then 1 else 0 end as OUTPUT",
                                 ["FOX_ROW_ID", "OUTPUT"])
    for projection in ("FOX_ROW_ID, OTHER", "FOX_ROW_ID, X as OTHER", "FOX_ROW_ID, (select 1 from X) as OUTPUT",
                       "FOX_ROW_ID, 1; COMMIT as OUTPUT", "FOX_ROW_ID, func(1 as OUTPUT"):
        with pytest.raises(ValueError):
            renderer._projection_columns(projection, ["FOX_ROW_ID", "OUTPUT"])


def test_single_successor_native_members_remain_exact_0572_bytes():
    raw, plan = fixture()
    output, receipt = renderer.render_relation_package(raw, plan)
    native = {name: renderer._sha(data) for name, data in members(output).items() if name.endswith(".apx")}
    # Captured from fox-v0.57.2's renderer with this unchanged synthetic fixture.
    assert renderer._sha(renderer._json(native)) == "e7bea275dc007b66b1d154c66846fa4218a1ad39b160acf0563584f8b4f7d628"
    assert all("selector_page_id" not in row for row in receipt["generated_operations"])


def test_fanout_has_one_secured_request_selector_and_each_distinct_child_action():
    raw, plan = fanout_fixture()
    output, receipt = renderer.render_relation_package(raw, plan)
    assert renderer.render_relation_package(raw, plan) == (output, receipt)
    files = members(output)
    rows = receipt["generated_operations"]
    assert len(receipt["added_pages"]) == 3
    assert len({row["page_id"] for row in rows}) == 2
    assert len({row["selector_page_id"] for row in rows}) == 1
    hub_id = rows[0]["selector_page_id"]
    hub = files[rows[0]["selector_page_file"]].decode()
    parent = files[plan["operations"][0]["parent"]["report_file"]].decode()
    assert parent.count("linkText: Choose related records") == 1
    assert f'P{hub_id}_PARENT_ID: "#FOX_ROW_ID#"' in parent
    assert "authentication: required" in hub
    assert "pageAccessProtection: argumentsMustHaveChecksum" in hub
    assert "storage: request" in hub and "storage: session" not in hub
    assert "sessionStateProtection: checksumRequiredSessionLevel" in hub
    assert len(re.findall(r"^    button ", hub, re.M)) == 2
    for row, operation in zip(rows, plan["operations"], strict=True):
        assert f'button {row["selector_button"]} (' in hub
        assert json.dumps(row["selector_label"]) in hub
        assert f'page: {row["page_id"]}' in hub
        assert f'{row["parent_item"]}: "&P{hub_id}_PARENT_ID."' in hub
        assert row["selection_storage"] == "request"
        child = files[row["page_file"]].decode()
        assert "authentication: required" in child and "storage: request" in child
        assert "storage: session" not in child
        assert "The report submits this tab's selected parent" in child
        assert f"pageItemsToSubmit: {row['parent_item']}" in child
        for pair in operation["join_pairs"]:
            assert f"fox_parent.{pair['parent_column']} = fox_child.{pair['child_column']}" in child
        assert not re.search(r"^    (?:process|button)\b", child, re.M)
    assert all(receipt[key] is False for key in ("write_lifecycle", "runtime_verified", "business_accepted"))


def test_every_sibling_query_separates_same_account_branches_null_and_missing_parent():
    raw, plan = fanout_fixture()
    output, receipt = renderer.render_relation_package(raw, plan)
    files = members(output)
    conn = sqlite3.connect(":memory:")
    trace = json.loads(files[renderer.TRACE])
    for block in trace["blocks"]:
        columns = ", ".join(item["column"] + " number" for item in block["items"])
        conn.execute(f"create table {block['table_name']}(FOX_ROW_ID number, {columns})")
    table = plan["operations"][0]["parent"]["table"]
    pc = [pair["parent_column"] for pair in plan["operations"][0]["join_pairs"]]
    conn.executemany(f"insert into {table}(FOX_ROW_ID,{','.join(pc)}) values(?,?,?)",
                     [(1, 10, 20), (2, 10, 30), (3, None, 20), (4, 10, None), (5, 10, 20)])
    for index, operation in enumerate(plan["operations"], 1):
        cc = [pair["child_column"] for pair in operation["join_pairs"]]
        conn.executemany(f"insert into {operation['child']['table']}(FOX_ROW_ID,{','.join(cc)}) values(?,?,?)",
                         [(index * 100 + n, a, b) for n, a, b in
                          [(1, 10, 20), (2, 10, 20), (3, 10, 30), (4, 90, 20), (5, None, 20), (6, 10, None)]])
    before = list(conn.iterdump())
    for index, row in enumerate(receipt["generated_operations"], 1):
        query = re.search(r"```sql\n(.*?)\n                ```", files[row["page_file"]].decode(), re.S)[1]
        def selected(parent_id):
            return [record[0] for record in conn.execute(query, {row["parent_item"]: parent_id})]
        assert selected(1) == selected(5) == [index * 100 + 1, index * 100 + 2]
        assert selected(2) == [index * 100 + 3]
        assert selected(1) == [index * 100 + 1, index * 100 + 2]  # Tab A after B.
        assert selected(None) == selected(999) == selected(3) == selected(4) == []
    assert list(conn.iterdump()) == before
    conn.execute(f"delete from {table} where FOX_ROW_ID=1")
    for row in receipt["generated_operations"]:
        query = re.search(r"```sql\n(.*?)\n                ```", files[row["page_file"]].decode(), re.S)[1]
        assert conn.execute(query, {row["parent_item"]: 1}).fetchall() == []
    conn.close()


def test_nested_fanout_clone_links_to_its_own_selector():
    raw, plan = fixture(block_count=5)
    template, coverage = deepcopy(plan["operations"][0]), deepcopy(plan["coverage"][0])
    plan["operations"], plan["coverage"] = [], []
    for index, (parent, child) in enumerate([(0, 1), (0, 2), (1, 3), (1, 4)]):
        operation, row = deepcopy(template), deepcopy(coverage)
        operation["relation_id"] = row["relation_id"] = source_id(90 + index)
        retarget(raw, operation, parent, child)
        plan["operations"].append(operation)
        plan["coverage"].append(row)
    output, receipt = renderer.render_relation_package(raw, reseal(plan))
    files = members(output)
    rows = receipt["generated_operations"]
    assert len(receipt["added_pages"]) == 6
    assert len({row["selector_page_id"] for row in rows}) == 2
    next_hub = rows[2]["selector_page_id"]
    intermediate = files[rows[0]["page_file"]].decode()
    assert f'P{next_hub}_PARENT_ID: "#FOX_ROW_ID#"' in intermediate
    assert "linkText: Choose related records" in intermediate
    assert rows[0]["selector_page_id"] != next_hub


@pytest.mark.parametrize("case", ["duplicate", "incoming", "cycle", "branch_cycle"])
def test_invalid_graphs_reject_every_edge_including_later_siblings(case):
    raw, plan = fanout_fixture()
    if case == "duplicate":
        retarget(raw, plan["operations"][1], 0, 1)
    elif case == "incoming":
        retarget(raw, plan["operations"][1], 2, 1)
    elif case == "cycle":
        retarget(raw, plan["operations"][1], 1, 0)
    else:
        operation, row = deepcopy(plan["operations"][1]), deepcopy(plan["coverage"][1])
        operation["relation_id"] = row["relation_id"] = source_id(92)
        retarget(raw, operation, 2, 0)
        plan["operations"].append(operation)
        plan["coverage"].append(row)
    with pytest.raises(renderer.RelationRenderError, match="GRAPH_"):
        renderer.render_relation_package(raw, reseal(plan))


@pytest.mark.parametrize("case", ["parent_public", "child_public", "duplicate_page", "wrong_page", "alias_collision"])
def test_fanout_rejects_unsafe_page_security_identity_and_labels(case):
    raw, plan = fanout_fixture()
    files = members(raw)
    if case in {"parent_public", "child_public"}:
        role = "parent" if case == "parent_public" else "child"
        report = plan["operations"][-1][role]["report_file"]
        files[report] = files[report].replace(b"authentication: required", b"authentication: public")
    elif case == "duplicate_page":
        files["pages/p00001-extra.apx"] = b"page 1 (\n)\n"
    elif case == "wrong_page":
        files["pages/p00002-extra.apx"] = b"page 4 (\n)\n"
    else:
        files["pages/p00007-extra.apx"] = b"page 7 (\n    alias: FOX_RELATION_SELECTOR_6\n)\n"
    raw = pack(files)
    plan["parent_zip_sha256"] = renderer._sha(raw)
    with pytest.raises(renderer.RelationRenderError):
        renderer.render_relation_package(raw, reseal(plan))


@pytest.mark.parametrize("name", ["Notes #2", "Terms & conditions", "&APP_USER.", "<detail>"])
def test_unusual_child_labels_get_safe_destination_fallback_without_losing_association(name):
    raw, plan = fanout_fixture()
    files = members(raw)
    trace = json.loads(files[renderer.TRACE])
    trace["blocks"][-1]["name"] = name
    files[renderer.TRACE] = renderer._json(trace)
    plan["parent_trace_sha256"] = renderer._sha(files[renderer.TRACE])
    plan["parent_trace_canonical_sha256"] = renderer._sha(renderer._json(trace))
    raw = pack(files)
    plan["parent_zip_sha256"] = renderer._sha(raw)
    output, receipt = renderer.render_relation_package(raw, reseal(plan))
    row = receipt["generated_operations"][-1]
    assert row["selector_label"] == f"View related report {row['page_id']}"
    assert row["child_block_id"] == trace["blocks"][-1]["source_block_id"]
    hub = members(output)[row["selector_page_file"]].decode()
    assert name not in hub
    assert json.dumps(row["selector_label"]) in hub


def test_selector_counts_toward_page_capacity_and_relations_remain_bounded(monkeypatch):
    raw, plan = fanout_fixture()
    monkeypatch.setattr(renderer, "MAX_PAGE_ID", 5)
    with pytest.raises(renderer.RelationRenderError, match="PAGE_CAPACITY_EXCEEDED"):
        renderer.render_relation_package(raw, plan)
    monkeypatch.setattr(renderer, "MAX_PAGE_ID", 8999)
    monkeypatch.setattr(renderer, "MAX_RELATIONS", 1)
    with pytest.raises(renderer.RelationRenderError, match="PLAN_LIMIT_INVALID"):
        renderer.render_relation_package(raw, plan)


def test_selector_pages_respect_existing_reserved_page_ids():
    raw, plan = fanout_fixture()
    files = members(raw)
    for number in (2, 4, 6):
        files[f"pages/p{number:05d}-existing.apx"] = f"page {number} (\n)\n".encode()
    raw = pack(files)
    plan["parent_zip_sha256"] = renderer._sha(raw)
    output, receipt = renderer.render_relation_package(raw, reseal(plan))
    rows = receipt["generated_operations"]
    assert [row["page_id"] for row in rows] == [7, 8]
    assert {row["selector_page_id"] for row in rows} == {9}
    assert all(members(output)[name] == data for name, data in files.items()
               if name not in receipt["changed_members"])
