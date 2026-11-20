"""Actual deterministic rendering and SQL expression tests; no APEX runtime claim."""
from copy import deepcopy
import json
import re
import sqlite3
import xml.etree.ElementTree as ET

import pytest

from forms2apex import native_buffer, native_policy_rules
from fox.forms_buffer_plan import build_buffer_plan
from fox.forms_draft_policy import apply_draft_policies, _compact
from fox.forms_policy_plan import build_policy_plan
from fox.forms_understanding_packet import _build
from test_forms_buffer_plan import parent_package, members, pack, PARENT_COPY_EXAMPLE


def source(*, renamed=False, trigger="POLICY;", helper=None, extra=""):
    root = ET.fromstring(PARENT_COPY_EXAMPLE.read_bytes())
    parent = root.find("Block")
    ET.SubElement(parent, "Item", Name="APPROVED", ItemType="Text Item", DatabaseItem="true", DataType="Char", MaximumLength="1")
    ET.SubElement(root, "Trigger", Name="WHEN-NEW-RECORD-INSTANCE", TriggerText=trigger)
    helper = helper or ("PROCEDURE POLICY IS BEGIN "
        "SET_BLOCK_PROPERTY('PIECES',INSERT_ALLOWED,PROPERTY_TRUE); "
        "SET_BLOCK_PROPERTY('PIECES',UPDATE_ALLOWED,PROPERTY_TRUE); "
        "SET_BLOCK_PROPERTY('PIECES',DELETE_ALLOWED,PROPERTY_TRUE); "
        "IF :LOADS.APPROVED IS NOT NULL AND :LOADS.APPROVED='Y' THEN "
        "SET_BLOCK_PROPERTY('PIECES',INSERT_ALLOWED,PROPERTY_FALSE); "
        "SET_BLOCK_PROPERTY('PIECES',UPDATE_ALLOWED,PROPERTY_FALSE); END IF; END;")
    ET.SubElement(root, "ProgramUnit", Name="POLICY", ProgramUnitType="Procedure", ProgramUnitText=helper)
    if extra:
        root.append(ET.fromstring(extra))
    raw = ET.tostring(root)
    if renamed:
        for old, new in ((b"DISPATCH_DRAFT", b"WAREHOUSE"), (b"LOADS", b"SHIPMENTS"), (b"PIECES", b"CRATES"),
                         (b"LOAD_REFERENCE", b"SHIP_CODE"), (b"APPROVED", b"SEALED"), (b"POLICY", b"CHECK_SEAL")):
            raw = raw.replace(old, new)
    return [("warehouse.xml" if renamed else "dispatch.xml", raw)]


def prepare(docs):
    files = members(parent_package(docs))
    packet, chunks = _build(docs)
    trace = json.loads(files["fox-package/source-to-page.json"])
    plan = build_policy_plan(docs, trace)
    sql, review = native_policy_rules.render_policy_code(plan)
    files["fox-package/policy-plan.json"] = json.dumps(plan).encode()
    files["fox-package/policy-receipt.json"] = json.dumps(review).encode()
    files[native_policy_rules.CODE_MEMBER] = sql.encode()
    parent = pack(files)
    buffer = build_buffer_plan(docs, parent)
    raw, _ = native_buffer.render_buffer_package(parent, buffer)
    return packet, chunks, trace, members(raw)


def apply(docs=None):
    docs = docs or source()
    args = prepare(docs)
    out, receipt = apply_draft_policies(docs, *args)
    return out, receipt, args


@pytest.mark.parametrize("renamed", [False, True])
def test_deterministic_partial_projection_preserves_source_and_other_members(renamed):
    docs = source(renamed=renamed)
    args = prepare(docs)
    before = deepcopy(args)
    files, receipt = apply_draft_policies(docs, *args)
    assert args == before
    assert (files, receipt) == apply_draft_policies(docs, *args)
    assert receipt["converted_code_unit_count"] == 0 and receipt["generated_operations"] == []
    op, = receipt["adapted_operations"]
    assert not receipt["gaps"] and op["status"] == "adapted"
    assert {e["property"] for e in op["enforced_effects"]} == {"INSERT_ALLOWED", "UPDATE_ALLOWED"}
    assert {e["property"] for e in op["omitted_effects"]} == {"DELETE_ALLOWED"}
    assert len(op["supporting_units"]) == 1
    assert all(s["source_unit_id"] and s["source_unit_sha256"] for s in op["supporting_units"])
    assert all(op[k] is False for k in ("customer_table_writes", "oracle_compiled", "runtime_verified", "business_accepted"))
    for name in args[-1]:
        if name != op["page_file"]:
            assert files[name] == args[-1][name]
    assert files["fox-package/sources/" + docs[0][0]] == docs[0][1]


@pytest.mark.parametrize("approved,expected", [(None, 1), ("", 1), ("N", 1), ("Y", 0), ("y", 1), ("Y ", 1)])
def test_policy_uses_current_selected_parent_and_binary_null_semantics(approved, expected):
    _, receipt, args = apply()
    op, = receipt["adapted_operations"]
    parent = next(b for b in args[2]["blocks"] if b["source_block_id"] == op["parent_block_id"])
    column = next(f["column"] for f in parent["items"] if f["source_name"] == "APPROVED")
    with sqlite3.connect(":memory:") as db:
        db.execute(f"create table parents(FOX_ROW_ID integer primary key,{column} text)")
        db.executemany("insert into parents values (?,?)", [(1, approved), (2, "Y")])
        query = "select " + op["policy_expression_sql"] + " from parents where FOX_ROW_ID=?"
        assert db.execute(query, (1,)).fetchone() == (expected,)
        assert db.execute(query, (2,)).fetchone() == (0,)
        # A previously rendered editable screen grants no continuing permission.
        db.execute(f"update parents set {column}='Y' where FOX_ROW_ID=1")
        assert db.execute(query, (1,)).fetchone() == (0,)


def test_all_four_contexts_and_initialization_lock_then_recheck_before_mutating():
    files, receipt, _ = apply()
    op, = receipt["adapted_operations"]
    page = files[op["page_file"]].decode()
    contexts = re.findall(r"function context_ok return boolean.*?end context_ok;", page)
    assert len(contexts) == 4
    for code in contexts:
        assert code.index("for update nowait;") < code.index("select CASE WHEN") < code.index("return false;", code.index("select CASE WHEN"))
        assert "POLICY_STATUS" not in code
    for name, code in re.findall(r"(validation [\w-]+|process [\w-]+) \(.*?```plsql\n(.*?)\n\s*```", page, re.S):
        if name.startswith("validation"):
            assert len(code.strip().encode()) <= 3950
        if "apex_collection." in code:
            assert code.index("for update nowait;") < code.index("select CASE WHEN") < code.index("apex_collection.")
        if "source-record-check" in name:
            assert "update_member_attribute" in code and "if not context_ok" in code
        if "keep-draft-and-move" in name:
            assert "if not context_ok then raise_application_error" in code
    assert page.count("item: P" + str(op["page_id"]) + "_POLICY_STATUS") == 5
    assert "sessionStateProtection: restricted" in page
    assert "to view records. No draft changes were retained." in page
    assert "does not save or approve business records" in page


@pytest.mark.parametrize("change", ["unknown_call", "extra_action", "duplicate_helper", "missing_update", "conditional_only", "child_override", "nonstored_input"])
def test_ambiguous_policy_fails_closed_with_read_only_explanation(change):
    docs = source(trigger="UNAVAILABLE;" if change == "unknown_call" else "POLICY;")
    root = ET.fromstring(docs[0][1])
    helper = next(n for n in root.iter("ProgramUnit") if n.get("Name") == "POLICY")
    if change == "extra_action":
        helper.set("ProgramUnitText", helper.get("ProgramUnitText").replace("END;", "COMMIT; END;"))
    if change == "duplicate_helper":
        root.append(deepcopy(helper))
    if change == "missing_update":
        helper.set("ProgramUnitText", re.sub(r"SET_BLOCK_PROPERTY\('PIECES',UPDATE_ALLOWED,PROPERTY_(?:TRUE|FALSE)\);", "", helper.get("ProgramUnitText")))
    if change == "conditional_only":
        helper.set("ProgramUnitText", "PROCEDURE POLICY IS BEGIN IF :LOADS.APPROVED='Y' THEN SET_BLOCK_PROPERTY('PIECES',INSERT_ALLOWED,PROPERTY_FALSE); SET_BLOCK_PROPERTY('PIECES',UPDATE_ALLOWED,PROPERTY_FALSE); END IF; END;")
    if change == "child_override":
        child = next(b for b in root.iter("Block") if b.get("Name") == "PIECES")
        ET.SubElement(child, "Trigger", Name="WHEN-NEW-RECORD-INSTANCE", TriggerText="MESSAGE('Other event');")
    if change == "nonstored_input":
        next(i for i in root.iter("Item") if i.get("Name") == "APPROVED").set("DatabaseItem", "false")
    docs = [(docs[0][0], ET.tostring(root))]
    files, receipt, _ = apply(docs)
    if change == "conditional_only":
        # Unknown default stays NULL, so even unapproved parents cannot edit.
        op, = receipt["adapted_operations"]
        assert "ELSE NULL" in op["policy_expression_sql"]
    else:
        assert receipt["adapted_operations"] == []
        op, = receipt["gaps"]
        assert op["status"] == "read_only_unresolved" and op["policy_expression_sql"] == "0"
        assert "cannot be safely evaluated" in files[op["page_file"]].decode()
    assert receipt["converted_code_unit_count"] == 0


@pytest.mark.parametrize("part", ["original", "trace", "policy", "page", "manifest"])
def test_mutated_source_or_trusted_template_is_rejected_atomically(part):
    docs = source()
    args = list(prepare(docs))
    files = dict(args[-1])
    path = {"original": "fox-package/sources/dispatch.xml", "trace": "fox-package/source-to-page.json",
            "policy": "fox-package/policy-plan.json", "manifest": "fox-package/source-manifest.json"}.get(part)
    if part == "page":
        path = json.loads(files["fox-package/buffer-receipt.json"])["generated_operations"][0]["page_file"]
        files[path] = files[path].replace(b"if not context_ok", b"if false")
    elif part == "original":
        files[path] += b" "
    else:
        value = json.loads(files[path]);value["source_binding"] = "f" * 64
        files[path] = json.dumps(value).encode()
    args[-1] = files
    before = deepcopy(files)
    with pytest.raises(ValueError, match="DRAFT_POLICY_"):
        apply_draft_policies(docs, *args)
    assert files == before


def test_literal_compaction_preserves_message_bytes_and_encoded_quote():
    assert _compact(" IF x = 'a ; ( b '' c' THEN\n  y := 1; END IF; ") == "IF x = 'a ; ( b '' c' THEN y := 1;END IF;"


def test_empty_buffer_plan_without_receipt_is_a_noop():
    docs = source()
    docs = [(docs[0][0], docs[0][1].replace(b"WHEN-VALIDATE-RECORD", b"POST-QUERY"))]
    args = list(prepare(docs))
    args[-1].pop("fox-package/buffer-receipt.json")
    files, receipt = apply_draft_policies(docs, *args)
    assert files == args[-1] and not receipt["adapted_operations"] and not receipt["gaps"]


def test_unrelated_helper_is_not_attributed_to_the_draft_projection():
    extra = '<ProgramUnit Name="OTHER" ProgramUnitType="Procedure" ProgramUnitText="PROCEDURE OTHER IS BEGIN SET_BLOCK_PROPERTY(\'LOADS\',DELETE_ALLOWED,PROPERTY_FALSE); END;"/>'
    docs = source(trigger="POLICY; OTHER;", extra=extra)
    _, receipt, args = apply(docs)
    op, = receipt["adapted_operations"]
    catalog = json.loads(args[-1]["fox-package/policy-plan.json"])["source_catalog"]
    other = next(o["id"] for o in catalog["objects"] if o["name"] == "OTHER")
    assert len(op["supporting_units"]) == 1
    assert all(o["source_owner_id"] != other for o in op["supporting_units"])


def test_capacity_failure_replaces_the_mutating_context_with_unconditional_deny():
    # A valid finite policy can still exceed APEX's bounded validation field.
    # Repeat complete nested conditions, without mocks or changing the limit.
    condition = " AND ".join(":LOADS.APPROVED='Y'" for _ in range(12))
    helper = ("PROCEDURE POLICY IS BEGIN SET_BLOCK_PROPERTY('PIECES',INSERT_ALLOWED,PROPERTY_TRUE); "
              "SET_BLOCK_PROPERTY('PIECES',UPDATE_ALLOWED,PROPERTY_TRUE); IF " + condition
              + " THEN SET_BLOCK_PROPERTY('PIECES',INSERT_ALLOWED,PROPERTY_FALSE); "
                "SET_BLOCK_PROPERTY('PIECES',UPDATE_ALLOWED,PROPERTY_FALSE); END IF; END;")
    files, receipt, _ = apply(source(helper=helper))
    assert not receipt["adapted_operations"]
    gap, = receipt["gaps"]
    assert gap["reason"] == "DRAFT_POLICY_VALIDATION_CAPACITY" and gap["authority"] == "unconditional_deny"
    page = files[gap["page_file"]].decode()
    assert page.count("function context_ok return boolean is begin return false;end context_ok;") == 4
    for code in re.findall(r"validation [\w-]+ \(.*?```plsql\n(.*?)\n\s*```", page, re.S):
        assert len(code.strip().encode()) <= 3950


def test_module_with_no_entry_policy_does_not_change_unrelated_drafts():
    docs = source()
    root = ET.fromstring(docs[0][1])
    root.remove(next(n for n in root if n.tag == "Trigger"))
    docs = [(docs[0][0], ET.tostring(root))]
    files, receipt, args = apply(docs)
    assert files == args[-1] and not receipt["adapted_operations"] and not receipt["gaps"]


def test_independent_module_policies_stay_bound_to_their_own_parent_columns():
    docs = source() + source(renamed=True)
    files, receipt, args = apply(docs)
    assert len(receipt["adapted_operations"]) == 2 and not receipt["gaps"]
    assert len({op["source_module_id"] for op in receipt["adapted_operations"]}) == 2
    for op in receipt["adapted_operations"]:
        parent = next(b for b in args[2]["blocks"] if b["source_block_id"] == op["parent_block_id"])
        column = next(f["column"] for f in parent["items"] if f["source_name"] in ("APPROVED", "SEALED"))
        assert column in op["policy_expression_sql"]
        assert column in files[op["page_file"]].decode()


@pytest.mark.parametrize("target,prop", [("PIECES", "DELETE_ALLOWED"), ("LOADS", "UPDATE_ALLOWED")])
def test_proven_unrelated_property_policy_preserves_independent_draft(target, prop):
    docs = source(helper=f"PROCEDURE POLICY IS BEGIN SET_BLOCK_PROPERTY('{target}',{prop},PROPERTY_FALSE); END;")
    files, receipt, args = apply(docs)
    assert files == args[-1] and not receipt["adapted_operations"] and not receipt["gaps"]
    assert receipt["unchanged_drafts"][0]["reason"] == "proven_property_effects_outside_draft_provider"


def test_mixed_create_update_permissions_explicitly_use_conservative_whole_screen_gate():
    helper = ("PROCEDURE POLICY IS BEGIN SET_BLOCK_PROPERTY('PIECES',INSERT_ALLOWED,PROPERTY_TRUE); "
              "SET_BLOCK_PROPERTY('PIECES',UPDATE_ALLOWED,PROPERTY_FALSE); END;")
    files, receipt, _ = apply(source(helper=helper))
    op, = receipt["adapted_operations"]
    assert op["permission_strategy"] == "conservative_all_draft_mutations_require_create_and_update"
    with sqlite3.connect(":memory:") as db:
        assert db.execute("select " + op["policy_expression_sql"]).fetchone() == (0,)
    assert "mixed permissions make all draft actions read only" in files[op["page_file"]].decode()


@pytest.mark.parametrize("property_name", ["InsertAllowed", "UpdateAllowed", "Enabled"])
def test_explicit_item_restriction_is_not_overridden_by_a_block_grant(property_name):
    docs = source()
    root = ET.fromstring(docs[0][1])
    next(i for i in root.iter("Item") if i.get("Name") == "PIECE_CODE").set(property_name, "false")
    docs = [(docs[0][0], ET.tostring(root))]
    _, receipt, _ = apply(docs)
    op, = receipt["adapted_operations"]
    with sqlite3.connect(":memory:") as db:
        assert db.execute("select " + op["policy_expression_sql"]).fetchone() == (0,)


def test_explicit_static_true_property_does_not_expand_identical_dynamic_gate():
    docs = source()
    _, before, _ = apply(docs)
    root = ET.fromstring(docs[0][1])
    next(i for i in root.iter("Item") if i.get("Name") == "PIECE_CODE").set("UpdateAllowed", "true")
    _, after, _ = apply([(docs[0][0], ET.tostring(root))])
    # Hashed columns change with source bytes; compare SQL syntax/shape.
    normalize = lambda value: re.sub(r"F_[A-Z0-9]+", "SOURCE_COLUMN", value)
    assert normalize(before["adapted_operations"][0]["policy_expression_sql"]) == normalize(after["adapted_operations"][0]["policy_expression_sql"])
