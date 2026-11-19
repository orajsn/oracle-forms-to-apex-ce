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


def fixture():
    # Standalone converter fixture: target-bound IR is synthetic, not presented
    # as proof of a source recognizer. Fresh-source grammar tests live in FOX.
    spec = {"schema_version": 1, "profile_id": native_blueprint.PROFILE_ID,
            "data_mode": "synthetic_test_only", "project_id": "relation-renderer",
            "project_name": "Relation renderer", "source_binding": "a" * 64, "blocks": []}
    for index in range(1, 4):
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
