"""Synthetic register acceptance. No private source, Oracle or model calls."""
from copy import deepcopy
import csv
import io
import json
from xml.etree import ElementTree as ET

import pytest

from fox.forms_understanding_packet import _build
from fox.forms_discrepancies import build_dependency_evidence
from fox.forms_interface_inventory import (
    build_interface_inventory, interface_inventory_csv, validate_interface_inventory)


def document(text, module="EXAMPLE", helper=None):
    form = ET.Element("FormModule", Name=module)
    block = ET.SubElement(form, "Block", Name="LINES", DatabaseBlock="true", QueryDataSourceName="APP.LINE_ROWS")
    ET.SubElement(block, "Item", Name="CODE", DataType="Char", ItemType="Text Item", DatabaseItem="true", MaximumLength="20")
    ET.SubElement(block, "Item", Name="WEIGHT", DataType="Number", ItemType="Text Item", DatabaseItem="true", MaximumLength="8")
    item = ET.SubElement(block, "Item", Name="ACTION", DataType="Char", ItemType="Push Button")
    ET.SubElement(item, "Trigger", Name="WHEN-BUTTON-PRESSED", TriggerText=text)
    if helper:
        for name, body in helper:
            ET.SubElement(form, "ProgramUnit", Name=name, ProgramUnitText=body)
    ET.SubElement(form, "Report", Name="SLIP", Filename="slip.rdf")
    return ET.tostring(form)


def context(text=None, documents=None, **kwargs):
    documents = documents or [("example.xml", document(text or "BEGIN NULL; END;"))]
    packet, chunks = _build(documents)
    ledger = {"source_binding": packet["source_binding"], "code_units": [
        {"source_unit_id": unit["id"], "source_unit_sha256": unit["sha256"], "source_owner_id": unit["owner_id"],
         "source_location": unit["location"]} for source in packet["sources"] for unit in source["facts"]["code_units"]],
        "dependencies_and_links": [
            {"kind": collection, "evidence": row} for source in packet["sources"] for collection in ("dependencies", "links")
            for row in source["facts"][collection]]}
    register = build_interface_inventory(packet, chunks, ledger, documents=documents, **kwargs)
    return packet, chunks, ledger, documents, register


def calls(register, name):
    return [row for row in register["records"] if (row["name"] or "").upper() == name.upper() and row["role"] == "routine_invocation"]


def test_call_sites_arity_named_notation_nested_commas_binds_and_no_literals():
    text = """BEGIN
        APP.API.APPROVE(:LINES.CODE, p_weight => CEIL(:LINES.WEIGHT), p_note => 'private,note',
                        p_user => :GLOBAL.USER_ID, p_state => :SYSTEM.MODE);
        APP.API.APPROVE(q'[private,(note),''x]', nested(1, 2)); -- APP.API.GHOST(9)
        /* APP.API.GHOST(8) */ GET_SEQUENCE(:LINES.CODE);
    END;"""
    packet, chunks, ledger, documents, result = context(text)
    approve = calls(result, "APP.API.APPROVE")
    assert len(approve) == 2
    assert [r["argument_count"] for r in approve] == [5, 2]
    assert [a["named_parameter"] for a in approve[0]["arguments"]] == [None, "p_weight", "p_note", "p_user", "p_state"]
    assert approve[0]["arguments"][0]["source_declared_type"] == "Char"
    assert approve[0]["arguments"][1]["binds"][0]["source_declared_type"] == "Number"
    assert approve[0]["arguments"][3]["binds"][0]["kind"] == "global_bind"
    assert approve[0]["arguments"][4]["binds"][0]["kind"] == "system_bind"
    assert all(a["formal_parameter_direction"] == "unknown" for a in approve[0]["arguments"])
    assert len(calls(result, "nested")) == 1 and len(calls(result, "CEIL")) == 1
    assert calls(result, "GET_SEQUENCE")[0]["classification"] == "unresolved_routine_candidate"
    assert calls(result, "APP.API.GHOST") == []
    assert "private" not in json.dumps(result)
    first = approve[0]
    assert first["position"]["character_offset"] == text.index("APP.API.APPROVE")
    assert first["position"]["line"] == 2
    assert first["source"]["owner_kind"] == "Trigger"
    assert [x["kind"] for x in first["source"]["owner_path"]] == ["FormModule", "Block", "Item", "Trigger"]
    assert first["source"]["xml_element_line"] == 1
    assert validate_interface_inventory(result, packet, chunks, ledger, documents=documents) == result


def test_database_roles_exact_qualified_targets_and_platform_names():
    *_, result = context("""BEGIN
        SELECT LPAD(:LINES.CODE, 4, '0') INTO x FROM APP.HEAD A, APP.DETAIL B JOIN APP.EXTRA C ON A.ID=B.ID;
        SELECT 1 INTO x FROM DUAL;
        INSERT INTO APP.HEAD(ID) VALUES (1);
        UPDATE APP.HEAD SET ID=2;
        DELETE FROM APP.DETAIL WHERE ID=2;
        MERGE INTO APP.EXTRA E USING APP.HEAD H ON (E.ID=H.ID) WHEN MATCHED THEN UPDATE SET E.ID=H.ID;
        SELECT ID INTO x FROM APP.HEAD FOR UPDATE;
    END;""")
    assert {(r["name"], r["role"]) for r in result["records"] if r["classification"] == "database_object_to_verify"} >= {
        ("APP.HEAD", "read"), ("APP.DETAIL", "read"), ("APP.EXTRA", "read"), ("APP.HEAD", "insert"),
        ("APP.HEAD", "update"), ("APP.DETAIL", "delete"), ("APP.EXTRA", "merge")}
    assert not any(r["name"] in {"SET", "ID", "E.ID"} and r["role"] == "update" for r in result["records"])
    assert next(r for r in result["records"] if r["name"] == "DUAL")["classification"] == "oracle_platform_object"
    assert calls(result, "LPAD")[0]["classification"] == "oracle_platform_routine"
    assert calls(result, "APP.HEAD") == []
    assert next(r for r in result["records"] if r["role"] == "report_registration")["name"] == "slip"


def test_delete_without_from_records_the_target_at_its_own_call_site():
    text = """IF :LINES.CODE IS NOT NULL THEN
        DELETE app.stage_rows WHERE code=:LINES.CODE;
        INSERT INTO app.stage_rows(code) SELECT code FROM app.source_rows;
        keys.DELETE(1);
        -- DELETE app.obsolete;
    END IF;"""
    *_, result = context(text)
    deletes = [r for r in result["records"] if r["role"] == "delete"]
    assert [r["name"] for r in deletes] == ["app.stage_rows"]
    span = deletes[0]["position"]
    assert text[span["character_offset"]:span["end_character_offset"]] == "app.stage_rows"
    assert span["line"] == 2
    assert any(r["role"] == "insert" and r["name"] == "app.stage_rows" for r in result["records"])


def test_bare_delete_alone_identifies_the_affected_database_object_in_discrepancies():
    packet, chunks, ledger, _, result = context("BEGIN DELETE app.expired_rows WHERE code=:LINES.CODE; END;")
    deletion, = [r for r in result["records"] if r["role"] == "delete"]
    assert deletion["affected_actions"]
    evidence = build_dependency_evidence(packet, chunks, ledger)
    assert any(r["evidence"].get("name") == deletion["name"] for r in evidence["references"])


def test_forms_ddl_exposes_exact_transaction_command_without_exporting_other_literals():
    *_, register = context("""BEGIN
        FORMS_DDL(' commit '); FORMS_DDL('rollback'); FORMS_DDL('ROLLBACK TO private_name');
        FORMS_DDL(:GLOBAL.CMD); FORMS_DDL('COM' || 'MIT'); END;""")
    records = calls(register, "FORMS_DDL")
    assert [r["transaction_effect"] for r in records] == [
        "requests_database_commit", "requests_database_rollback", *["unresolved_dynamic_command"] * 3]
    csv_rows = list(csv.DictReader(io.StringIO(interface_inventory_csv(register))))
    assert [r["transaction_effect"] for r in csv_rows if r["name"] == "FORMS_DDL"] == [
        r["transaction_effect"] for r in records]
    assert "private_name" not in json.dumps(register) and "private_name" not in interface_inventory_csv(register)
    raw = document("BEGIN FORMS_DDL('COMMIT'); END;",
                   helper=[("FORMS_DDL", "PROCEDURE FORMS_DDL(x varchar2) IS BEGIN NULL; END;")])
    *_, shadowed = context(documents=[("x.xml", raw)])
    assert all("transaction_effect" not in r for r in calls(shadowed, "FORMS_DDL"))


def test_pre_delete_dependency_is_linked_to_posting_sites_in_the_same_block():
    root = ET.fromstring(document("NULL;"))
    block = root.find("Block")
    ET.SubElement(block, "Trigger", Name="KEY-DELREC", TriggerText="DELETE_RECORD; COMMIT_FORM;")
    ET.SubElement(block, "Trigger", Name="PRE-DELETE", TriggerText="BEGIN APP.AUDIT_ROW(:LINES.CODE); END;")
    packet, chunks, ledger, docs, initial = context(documents=[("posting.xml", ET.tostring(root))])
    mark, = calls(initial, "DELETE_RECORD")
    commit, = calls(initial, "COMMIT_FORM")
    audit, = calls(initial, "APP.AUDIT_ROW")
    pair = {role + "_source_unit_" + key: record["source"]["source_unit_" + key]
            for role, record in (("key", mark), ("pre_delete", audit)) for key in ("id", "sha256")}
    ledger["delete_posting_pairs"] = [pair]
    register = build_interface_inventory(packet, chunks, ledger, documents=docs)
    audit, = calls(register, "APP.AUDIT_ROW")
    direct, posted = audit["affected_actions"]
    assert direct["relationship"] == "direct_source_reference"
    assert posted["relationship"] == "conditional_pre_delete_during_post"
    assert posted["via_call_site_ids"] == [mark["id"], commit["id"]]
    assert posted["unit_path"] == [mark["source"]["source_unit_id"], audit["source"]["source_unit_id"]]
    pair["key_source_unit_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="posting link"):
        build_interface_inventory(packet, chunks, ledger, documents=docs)


def test_static_local_paths_module_isolation_cycles_and_nested_effects():
    helpers = [("HELPER", "PROCEDURE HELPER IS BEGIN APP.API.DELETE_ROW(:LINES.CODE); OTHER; END HELPER;"),
               ("OTHER", "PROCEDURE OTHER IS BEGIN HELPER; END OTHER;")]
    first = document("BEGIN HELPER; END;", module="FIRST", helper=helpers)
    second = document("BEGIN HELPER; END;", module="SECOND")
    *_, result = context(documents=[("a.xml", first), ("b.xml", second)])
    deletion, = calls(result, "APP.API.DELETE_ROW")
    assert len(deletion["affected_actions"]) == 3  # direct, trigger, OTHER; cycle never repeats
    assert any(a["action"]["owner_kind"] == "Trigger" for a in deletion["affected_actions"])
    assert all(a["action"]["file"] == "a.xml" for a in deletion["affected_actions"])
    assert all(len(a["unit_path"]) == len(set(a["unit_path"])) for a in deletion["affected_actions"])
    assert {r["classification"] for r in calls(result, "HELPER")} == {"source_program_unit", "unresolved_routine_candidate"}


def test_nested_bodies_are_supplied_and_never_inherit_unproved_parent_callers():
    helper = """PROCEDURE HELPER IS
        PROCEDURE INNER_HELPER IS BEGIN APP.API.HIDDEN(1); END INNER_HELPER;
        BEGIN INNER_HELPER; END HELPER;"""
    *_, result = context(documents=[("a.xml", document("BEGIN HELPER; END;", helper=[("HELPER", helper)]))])
    assert calls(result, "INNER_HELPER")[0]["classification"] == "source_nested_routine"
    hidden, = calls(result, "APP.API.HIDDEN")
    assert hidden["lexical_enclosing_routine"] == "INNER_HELPER"
    assert len(hidden["affected_actions"]) == 1


@pytest.mark.parametrize("newline", ["\n", "\r", "\r\n", "&#10;", "&#13;"])
def test_semantic_positions_after_newline_decoding(newline):
    *_, result = context("BEGIN -- hidden" + newline + "APP.API.CHECK_ROW(:LINES.CODE); END;")
    row, = calls(result, "APP.API.CHECK_ROW")
    assert row["position"]["line"] == 2 and row["position"]["column"] == 1


def test_ambiguous_decoding_and_malformed_calls_are_explicit():
    *_, ambiguous = context("BEGIN MESSAGE('&#10;'); APP.CHECK_ROW(1); END;")
    assert any(r["role"] == "unresolved_source_unit" for r in ambiguous["records"])
    retained = [r for r in ambiguous["records"] if r["name"] == "APP.CHECK_ROW"]
    assert retained and all(r["position"] is None for r in retained)
    *_, malformed = context("BEGIN APP.API.CHECK_ROW(:LINES.CODE; END;")
    row, = calls(malformed, "APP.API.CHECK_ROW")
    assert row["argument_count"] is None and "unclosed_argument_list" in row["limitation"]
    *_, dynamic = context("BEGIN EXECUTE IMMEDIATE 'select private from private_rows'; END;")
    assert any(r["role"] == "dynamic_sql" for r in dynamic["records"])
    assert "private" not in json.dumps(dynamic)


def test_quoted_object_and_bare_qualified_call_preserve_uncertainty():
    *_, result = context('BEGIN SELECT 1 INTO x FROM "CaseSchema"."CaseTable"@REMOTE; APP . API . VALIDATE_ROW; END;')
    row = next(r for r in result["records"] if r["role"] == "read")
    assert row["name"] == '"CaseSchema"."CaseTable"@REMOTE' and "Quoted" in row["limitation"]
    assert calls(result, "APP.API.VALIDATE_ROW")[0]["argument_count"] == 0


def test_fresh_evidence_tampering_does_not_change_source_and_csv_is_formula_safe():
    packet, chunks, ledger, documents, register = context("BEGIN APP.API.RUN(:LINES.CODE); END;")
    original = deepcopy((packet, chunks, ledger, documents, register))
    evidence = build_dependency_evidence(packet, chunks, ledger)
    evidence["references"].pop()
    with pytest.raises(ValueError):
        build_interface_inventory(packet, chunks, ledger, dependency_evidence=evidence)
    broken = deepcopy(register)
    broken["records"].pop()
    with pytest.raises(ValueError):
        validate_interface_inventory(broken, packet, chunks, ledger, documents=documents)
    changed = deepcopy(chunks)
    changed[0]["text"] += " NULL;"
    with pytest.raises(ValueError):
        build_interface_inventory(packet, changed, ledger)
    assert original == (packet, chunks, ledger, documents, register)
    register["records"][0]["source"]["file"] = " \t=HYPERLINK(1)"
    csv_rows = list(csv.DictReader(io.StringIO(interface_inventory_csv(register))))
    assert csv_rows[0]["file"].startswith("'")
    assert not any("private" in value for row in csv_rows for value in row.values())


def test_non_source_enrichment_is_allowed_and_missing_type_remains_unknown():
    packet, chunks, ledger, documents, register = context("BEGIN APP.API.RUN(:LINES.CODE); END;")
    packet["extra_design"] = {"unrelated": True}
    assert build_interface_inventory(packet, chunks, ledger, documents=documents) == register
    unknown = build_interface_inventory(packet, chunks, ledger)
    assert calls(unknown, "APP.API.RUN")[0]["arguments"][0]["source_declared_type"] is None
    with pytest.raises(ValueError):
        build_interface_inventory(packet, chunks, ledger, documents=[("renamed.xml", documents[0][1])])


def test_bind_expressions_are_not_labelled_as_direct_bind():
    *_, result = context("BEGIN APP.API.RUN(:LINES.CODE || 'hidden', :LINES.WEIGHT+1, :CODE+1, :CODE); EXIT; END;")
    row, = calls(result, "APP.API.RUN")
    assert [arg["actual_kind"] for arg in row["arguments"]] == ["expression", "expression", "expression", "direct_bind"]
    # The Trigger is inside an Item, so the block identity resolves :CODE.
    assert row["arguments"][-1]["source_declared_type"] == "Char"
    assert not calls(result, "EXIT")


def test_visible_detail_and_csv_limits_keep_complete_reference_index(monkeypatch):
    import fox.forms_interface_inventory as inventory
    monkeypatch.setattr(inventory, "MAX_RECORDS", 3)
    *_, result = context("BEGIN APP.API.ONE(1); APP.API.TWO(2); APP.API.THREE(3); APP.API.FOUR(4); END;")
    assert len(result["records"]) <= 3
    assert result["detail_coverage"]["complete"] is False
    assert result["complete_reference_index"] == "fox-package/discrepancy-evidence.json"
    monkeypatch.setattr(inventory, "MAX_CSV_ROWS", 2)
    csv_rows = list(csv.DictReader(io.StringIO(interface_inventory_csv(result))))
    assert csv_rows[-1]["role"] == "csv_detail_omitted"
    monkeypatch.setattr(inventory, "MAX_SCAN_CHARACTERS", 5)
    *_, limited = context("BEGIN APP.API.ONE(1); END;")
    assert limited["detail_coverage"]["limits_reached"]["units_without_detail"]
    assert any(r["name"] == "API.ONE" or r["name"] == "APP.API.ONE" for r in limited["records"])


def test_argument_mapping_limits_are_explicit(monkeypatch):
    import fox.forms_interface_inventory as inventory
    monkeypatch.setattr(inventory, "MAX_ARGUMENT_TOKENS", 8)
    *_, result = context("BEGIN APP.API.ONE(nested(nested(nested(nested(1))))); END;")
    row, = calls(result, "APP.API.ONE")
    assert row["argument_count"] is None and "call_span_limit" in row["limitation"]
    assert result["detail_coverage"]["complete"] is False


def test_unique_local_scalar_type_evidence_does_not_infer_formal_direction():
    *_, result = context("DECLARE local_weight NUMBER(8); label_value VARCHAR2(30); BEGIN APP.API.RUN(local_weight, p_label => label_value); END;")
    row, = calls(result, "APP.API.RUN")
    assert [a["actual_kind"] for a in row["arguments"]] == ["local_identifier", "local_identifier"]
    assert [a["source_declared_type"] for a in row["arguments"]] == ["NUMBER", "VARCHAR2"]
    assert all(a["source_type_evidence"]["declaration_position"] for a in row["arguments"])
    assert all(a["formal_parameter_direction"] == "unknown" for a in row["arguments"])


def test_nested_scope_scalar_types_are_not_leaked_into_outer_invocation():
    *_, result = context("DECLARE PROCEDURE inner_helper IS local_weight NUMBER; BEGIN NULL; END inner_helper; BEGIN APP.API.RUN(local_weight); END;")
    assert calls(result, "APP.API.RUN")[0]["arguments"][0]["source_declared_type"] is None


def test_csv_rows_flatten_argument_bind_and_action_coordinates():
    *_, result = context("BEGIN APP.API.RUN(:LINES.WEIGHT + :LINES.WEIGHT); END;")
    rows = [r for r in csv.DictReader(io.StringIO(interface_inventory_csv(result))) if r["name"] == "APP.API.RUN"]
    assert len(rows) == 2
    assert all(r["argument_ordinal"] == "1" and r["bind_name"] == "LINES.WEIGHT" for r in rows)
    assert rows[0]["bind_character_offset"] != rows[1]["bind_character_offset"]
    assert all(r["bind_source_declared_type"] == "Number" and r["bind_data_flow"] == "unknown" for r in rows)


def test_repeated_call_sites_stop_with_visible_metadata_limits():
    *_, result = context("BEGIN " + "APP.API.RUN(:LINES.CODE); " * 1200 + " END;")
    assert result["detail_coverage"]["complete"] is False
    assert len(result["records"]) <= result["detail_coverage"]["maximum_records"]
    assert result["complete_reference_index"] == "fox-package/discrepancy-evidence.json"
    assert len(interface_inventory_csv(result).encode()) <= 2_000_000
