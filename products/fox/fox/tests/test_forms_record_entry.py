"""Real deterministic renderers and modeled SQL semantics; no Oracle claim."""
from copy import deepcopy
from html import escape
import json
import re
import sqlite3

import pytest

from forms2apex import native_blueprint, native_policy_rules, native_relations
from fox.forms_native_plan import POLICY_ID, build_native_prototype_plan
from fox.forms_policy_plan import build_policy_plan
from fox.forms_record_entry import apply_record_entries
from fox.forms_relation_plan import build_relation_plan
from fox.forms_understanding_packet import _build
from fox.prototype_export_only import _members, _zip
from fox.xml_mapping import _blueprint


def source(module="DISPATCH", header="JOURNEYS", middle="BAGS", detail="PARCELS",
           text=None, *, extra_relation="", extra_detail="", same_block=False):
    text = text or ("IF :ORIGIN=:VIA THEN :FLAG:='N'; END IF;" if same_block else
                    f"IF :{header}.ORIGIN=:{header}.VIA THEN :FLAG:='N'; END IF;")
    def item(name, size="10", dtype="Char"):
        return f'<Item Name="{name}" DatabaseItem="true" DataType="{dtype}" MaximumLength="{size}" ItemType="Text Item"/>'
    trigger = f'<Trigger Name="WHEN-NEW-RECORD-INSTANCE" TriggerText="{escape(text, quote=True)}"/>'
    if same_block:
        return (f'<FormModule Name="{module}"><Block Name="{detail}" DatabaseBlock="true">'
                + item("ORIGIN") + item("VIA") + item("FLAG", "1") + trigger + extra_detail + '</Block></FormModule>').encode()
    return (f'<FormModule Name="{module}"><Block Name="{header}" DatabaseBlock="true">'
            + item("KEY") + item("ORIGIN") + item("VIA")
            + f'<Relation Name="CHILDREN" DetailBlock="{middle}" RelationType="JOIN" JoinCondition="{header}.KEY={middle}.HKEY"/>'
            + extra_relation + f'</Block><Block Name="{middle}" DatabaseBlock="true">'
            + item("KEY") + item("HKEY")
            + f'<Relation Name="DETAILS" DetailBlock="{detail}" RelationType="JOIN" JoinCondition="{middle}.KEY={detail}.PKEY"/>'
            + f'</Block><Block Name="{detail}" DatabaseBlock="true">'
            + item("PKEY") + item("FLAG", "1") + trigger + extra_detail + '</Block></FormModule>').encode()


def prepare(documents):
    packet, chunks = _build(documents)
    plan = build_native_prototype_plan(documents, _blueprint(packet), project_id="entry-test",
        project_name="Record entry", approved_policy_id=POLICY_ID)
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
    relation = build_relation_plan(documents, _zip(files))
    if relation["operations"]:
        rendered, _ = native_relations.render_relation_package(_zip(files), relation)
        files = _members(rendered)
    else:
        files["fox-package/relation-plan.json"] = json.dumps(relation).encode()
    policy = build_policy_plan(documents, trace)
    sql, receipt = native_policy_rules.render_policy_code(policy)
    files["fox-package/policy-plan.json"] = json.dumps(policy).encode()
    files["fox-package/policy-receipt.json"] = json.dumps(receipt).encode()
    files[native_policy_rules.CODE_MEMBER] = sql.encode()
    return packet, chunks, trace, files


def apply(documents=None):
    docs = documents or [("dispatch.xml", source())]
    args = prepare(docs)
    files, receipt = apply_record_entries(docs, *args)
    return files, receipt, args


def test_complete_original_ast_has_explicit_context_and_atomic_file_changes():
    docs = [("dispatch.xml", source())]
    args = prepare(docs)
    before = deepcopy(args)
    files, receipt = apply_record_entries(docs, *args)
    assert args == before
    assert (files, receipt) == apply_record_entries(docs, *args)
    op, = receipt["generated_operations"]
    assert not receipt["gaps"] and len(op["path_block_ids"]) == 3 and len(op["relation_ids"]) == 2
    assert op["kind"] == "selected_record_entry_assignment" and op["phase"] == "entered_selected_record"
    assert op["generation_status"] == "generated_wired_adapted"
    assert "stored synthetic values only" in op["adaptation"]
    assert all(op[k] is False for k in ("customer_table_writes", "oracle_compiled", "runtime_verified", "business_accepted"))
    for name in args[-1]:
        if name != op["entry_report_file"]:
            assert files[name] == args[-1][name]
    assert files["fox-package/sources/dispatch.xml"] == docs[0][1]
    page = files[op["target"]["page_file"]].decode()
    assert "point: beforeHeader\n" in page and "lookup-page outputs and draft edits are not shared" in page
    assert page.count("checksumRequiredSessionLevel") == 3
    assert page.count("selected synthetic row identity") == 3
    assert "pageAccessProtection: argumentsMustHaveChecksum" in page
    assert "sessionStateProtection: restricted" in page
    assert "label {\n" in page and not re.search(r"^\s+label:.*\n\s+layout", page, re.M)


def database_for(op, trace):
    blocks = [next(b for b in trace["blocks"] if b["source_block_id"] == uid) for uid in op["path_block_ids"]]
    db = sqlite3.connect(":memory:")
    for b in blocks:
        db.execute(f"create table {b['table_name']} (FOX_ROW_ID integer primary key, "
                   + ",".join(f["column"] + " text" for f in b["items"]) + ")")
    # Both root rows have the same business key. A key-only ancestor inference
    # would produce two candidates with different source condition results.
    db.executemany(f"insert into {blocks[0]['table_name']} values (?,?,?,?)",
                   [(1, "DUP", "A", "A"), (2, "DUP", "A", "B"), (3, "OTHER", None, "B")])
    db.executemany(f"insert into {blocks[1]['table_name']} values (?,?,?)",
                   [(11, "BAG", "DUP"), (12, "SIBLING", "OTHER")])
    db.executemany(f"insert into {blocks[2]['table_name']} values (?,?,?)",
                   [(21, "BAG", "Y"), (22, "SIBLING", "X")])
    return db, blocks


def test_generated_sql_retains_exact_selected_grandparent_even_with_duplicate_business_keys():
    _, receipt, (_, _, trace, _) = apply()
    op, = receipt["generated_operations"]
    db, _ = database_for(op, trace)
    p = op["target"]["page_id"]
    before = db.total_changes
    first = db.execute(op["selected_record_sql"], {f"P{p}_ID0": 1, f"P{p}_ID1": 11, f"P{p}_ID2": 21}).fetchall()
    second = db.execute(op["selected_record_sql"], {f"P{p}_ID0": 2, f"P{p}_ID1": 11, f"P{p}_ID2": 21}).fetchall()
    assert first == [("A", "A", "Y")] and second == [("A", "B", "Y")]
    for ids in ((None, 11, 21), (1, None, 21), (1, 11, None), (1, 11, 22), (3, 11, 21), (999, 11, 21)):
        assert not db.execute(op["selected_record_sql"], {f"P{p}_ID{i}": value for i, value in enumerate(ids)}).fetchall()
    # Each chooser inherits protected row identities and rechecks every join.
    assert len(db.execute(op["chooser_sql"][0]).fetchall()) == 3
    middle_page, child_page = op["chooser_pages"][1:]
    assert [r[0] for r in db.execute(op["chooser_sql"][1], {f"P{middle_page}_ID0": 1})] == [11]
    assert [r[0] for r in db.execute(op["chooser_sql"][2], {f"P{child_page}_ID0": 1, f"P{child_page}_ID1": 11})] == [21]
    assert db.total_changes == before


def test_no_else_prior_value_survives_first_false_null_and_existing_session_paths():
    _, receipt, _ = apply()
    op, = receipt["generated_operations"]
    sql = op["process_plsql"]
    # Initial target is fetched before prior session target is restored. A
    # cursor's empty result cannot undefine SELECT INTO target variables.
    assert sql.index("\ninto l_f1, l_f2, l_f3\n") < sql.index("for saved in (") < sql.index("IF (l_f1 = l_f2) THEN")
    assert "l_f3 := saved.c002;\nend loop;\nIF (l_f1 = l_f2) THEN\nl_f3 := 'N';\nEND IF;" in sql
    assert "exception when no_data_found then null" not in sql
    assert "l_seq := apex_collection.add_member(" in sql
    assert "Selected record session result is ambiguous" in sql
    assert "ELSE" not in sql
    # Evaluate the actual emitted finite condition in SQL's three-valued logic.
    condition = re.search(r"\nIF (.*?) THEN\nl_f3 := 'N';", sql)[1]
    db = sqlite3.connect(":memory:")
    for a, b, prior, expected in (("A", "A", "Y", "N"), ("A", "B", "Y", "Y"),
                                  (None, "A", "Y", "Y"), ("A", None, "X", "X"),
                                  (None, None, None, None), ("A", "B", "N", "N")):
        truth = db.execute("select " + condition.replace("l_f1", ":a").replace("l_f2", ":b"), {"a": a, "b": b}).fetchone()[0]
        assert ("N" if truth else prior) == expected
    assert "to_char(:P" in sql and sql.count(",'TM9')") == 3


def test_same_block_numeric_and_character_assignments_have_native_targets():
    text = "IF :ORIGIN=:VIA THEN :FLAG:='N'; END IF; :COUNT:=2;"
    raw = source(text=text, same_block=True,
                 extra_detail='<Item Name="COUNT" DatabaseItem="true" DataType="Number" ItemType="Text Item"/>')
    _, receipt, _ = apply([("simple.xml", raw)])
    op, = receipt["generated_operations"]
    assert len(op["path_block_ids"]) == 1 and not op["relation_ids"]
    assert set(op["result_slots"].values()) == {"c002", "n001"}
    assert "NUMBER;" in op["process_plsql"] and " := 2;" in op["process_plsql"]


def test_renamed_multiple_modules_do_not_share_pages_collections_or_rows():
    docs = [("one.xml", source(module="ONE", header="H1", middle="M1", detail="D1")),
            ("two.xml", source(module="TWO", header="H2", middle="M2", detail="D2"))]
    _, receipt, _ = apply(docs)
    assert len(receipt["generated_operations"]) == 2
    for key in ("collection_name", "source_module_id", "source_unit_id"):
        assert len({op[key] for op in receipt["generated_operations"]}) == 2
    pages = [p for op in receipt["generated_operations"] for p in op["chooser_pages"] + [op["target"]["page_id"]]]
    assert len(pages) == len(set(pages)) == 8


@pytest.mark.parametrize("change", ["ambiguous", "wrong_ancestor", "missing_size", "other_event", "mixed_effects", "local_call", "cross_target"])
def test_partial_ambiguous_other_events_and_effects_never_generate(change):
    raw = source()
    if change == "ambiguous":
        raw = source(extra_relation='<Relation Name="EXTRA" DetailBlock="BAGS" RelationType="JOIN" JoinCondition="unsupported"/>')
    elif change == "wrong_ancestor":
        raw = source(text="IF :OTHER.ORIGIN=:OTHER.VIA THEN :FLAG:='N'; END IF;")
    elif change == "missing_size":
        raw = raw.replace(b'MaximumLength="1"', b'')
    elif change == "other_event":
        raw = raw.replace(b'WHEN-NEW-RECORD-INSTANCE', b'POST-QUERY')
    elif change == "mixed_effects":
        raw = source(text="IF :JOURNEYS.ORIGIN=:JOURNEYS.VIA THEN :FLAG:='N'; MESSAGE('extra'); END IF;")
    elif change == "local_call":
        raw = source(text="WRAPPER;").replace(b'</FormModule>', b'<ProgramUnit Name="WRAPPER" ProgramUnitType="Procedure" ProgramUnitText="PROCEDURE WRAPPER IS BEGIN :PARCELS.FLAG:=\'N\'; END;"/></FormModule>')
    elif change == "cross_target":
        raw = source(text="IF :JOURNEYS.ORIGIN=:JOURNEYS.VIA THEN :JOURNEYS.KEY:='N'; END IF;")
    files, receipt, args = apply([("unsupported.xml", raw)])
    assert not receipt["generated_operations"] and files == args[-1]


@pytest.mark.parametrize("change", ["chunk", "trace", "original", "manifest", "review", "ddl", "relation"])
def test_source_proof_metadata_and_schema_changes_do_not_wire(change):
    docs = [("dispatch.xml", source())]
    packet, chunks, trace, files = prepare(docs)
    if change == "chunk": chunks[0]["text"] += " "
    elif change == "trace": trace["blocks"][0]["table_name"] = "OTHER_TABLE"
    elif change == "original": files["fox-package/sources/dispatch.xml"] += b' '
    elif change == "manifest": files["fox-package/source-manifest.json"] = b'{}'
    elif change == "review": files[native_policy_rules.CODE_MEMBER] += b'-- changed'
    elif change == "ddl": files["fox-package/supporting-schema.sql"] = b'-- missing'
    elif change == "relation":
        p = json.loads(files["fox-package/relation-plan.json"])
        p["operations"][0]["join_pairs"][0]["child_column"] = "OTHER_COLUMN"
        files["fox-package/relation-plan.json"] = json.dumps(p).encode()
    try:
        result, receipt = apply_record_entries(docs, packet, chunks, trace, files)
    except ValueError as exc:
        assert str(exc).startswith("ENTRY_")
    else:
        assert not receipt["generated_operations"] and result == files


def test_assembler_ui_selection_status_is_not_source_authority():
    docs = [("dispatch.xml", source())]
    args = list(prepare(docs))
    args[0]["selection_status"] = "NOT_SELECTED"
    assert len(apply_record_entries(docs, *args)[1]["generated_operations"]) == 1


@pytest.mark.parametrize("separator", ["\u0085", "\u2028", "\u2029", "\u00a0"])
def test_source_literal_unicode_whitespace_is_not_reformatted(separator):
    docs = [("literal.xml", source(same_block=True, text=":FLAG:='" + separator + "';"))]
    files, receipt, args = apply(docs)
    assert not receipt["generated_operations"] and files == args[-1]
    assert receipt["gaps"][0]["reason"] == "ENTRY_LITERAL_CONTEXT"
