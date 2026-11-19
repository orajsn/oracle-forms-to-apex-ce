"""Synthetic source-bound report acceptance; no Oracle/runtime/business proof."""
from copy import deepcopy
from xml.etree import ElementTree as ET

import pytest

from fox.forms_discrepancies import build_discrepancies, build_dependency_evidence, validate_discrepancies
from fox.forms_native_plan import POLICY_ID
from fox.forms_understanding_packet import _build
from fox.xml_mapping import generate_xml_package, mapping_catalog


def source(module="EXAMPLE", helper="HELPER", body=True):
    form = ET.Element("FormModule", Name=module)
    block = ET.SubElement(form, "Block", Name="LINES", DatabaseBlock="true", QueryDataSourceName="SOURCE_ROWS")
    ET.SubElement(block, "Item", Name="PRICE", ItemType="Text Item", DataType="Number", DatabaseItem="true")
    ET.SubElement(block, "Item", Name="TOTAL", ItemType="Display Item", DataType="Number", DatabaseItem="false", Formula="CEIL(:PRICE)")
    for name in ("ORIGIN", "DEST", "FLAG"):
        ET.SubElement(block, "Item", Name=name, ItemType="Text Item", DataType="Char", DatabaseItem="true", MaximumLength="40")
    ET.SubElement(block, "Trigger", Name="WHEN-NEW-RECORD-INSTANCE", TriggerText="IF :ORIGIN=:DEST THEN :FLAG:='N'; END IF;")
    ET.SubElement(block, "Trigger", Name="CHECK", TriggerText=f"BEGIN GO_ITEM('LINES.PRICE'); {helper}(1); MYSTERY(1); END;")
    ET.SubElement(block, "Trigger", Name="CHECK_AGAIN", TriggerText="BEGIN go_item('LINES.PRICE'); END;")
    ET.SubElement(form, "ProgramUnit", Name=helper, ProgramUnitText=(
        f"PROCEDURE {helper}(X NUMBER) IS BEGIN NULL; END;" if body else f"PROCEDURE {helper}(X NUMBER);"))
    ET.SubElement(form, "RecordGroup", Name="CHOICES", RecordGroupQuery="SELECT 1 FROM DUAL")
    ET.SubElement(form, "Report", Name="PRINT_LAYOUT", Filename="print_layout.rdf")
    return ET.tostring(form)


def context(documents=None):
    documents = documents or [("example.xml", source())]
    packet, chunks = _build(documents)
    _, result = generate_xml_package(documents, "discrepancy-test", "Discrepancy test", POLICY_ID)
    ledger, gaps, catalog = result["mapping_ledger"], result["gap_report"], mapping_catalog()
    report = build_discrepancies(packet, ledger, gaps, catalog, chunks=chunks)
    return packet, chunks, ledger, gaps, catalog, report


@pytest.fixture(scope="module")
def example():
    return context()


def test_exact_partition_catalog_adaptations_and_defensive_result(example):
    packet, chunks, ledger, gaps, catalog, report = deepcopy(example)
    original = deepcopy((packet, chunks, ledger, gaps, catalog))
    assert report["summary"] == {"total_units": 6, "generated_units": 1, "encoded_unwired_units": 1,
        "unimplemented_units": 4, "dependency_groups": 7, "dependency_references": 8}
    assert len({u["source_unit_id"] for u in report["units"]}) == 6
    rules = {r["id"]: r for r in catalog["rules"]}
    coverage = {r["source_unit_id"]: r for r in ledger["code_units"]}
    for unit in report["units"]:
        assert unit["source_file"] == "example.xml" and unit["source_line"] > 0
        if unit["status"] != "unimplemented":
            assert rules[coverage[unit["source_unit_id"]]["rule_id"]]["adaptations"] in unit["message"]
    checked = validate_discrepancies(report, ledger, gaps, catalog, packet=packet, chunks=chunks)
    assert checked == validate_discrepancies(report, ledger, gaps, catalog)
    checked["units"][0]["message"] = "changed copy"
    assert checked != report
    assert original == (packet, chunks, ledger, gaps, catalog)
    assert report["runtime_verified"] is report["business_behavior_accepted"] is False


def test_candidates_are_grouped_and_known_source_apis_are_not_external_missing_files(example):
    *_, report = example
    groups = {(g["name"].upper(), g["kind"]): g for g in report["dependencies"]}
    assert len(groups[("GO_ITEM", "forms_api")]["occurrences"]) == 2
    assert groups[("HELPER", "local_routine")]["status"] == "source_definition_present"
    assert groups[("MYSTERY", "routine_reference")]["status"] == "unverified"
    assert groups[("CEIL", "routine_reference")]["status"] == "unverified"
    assert "platform SQL" in groups[("DUAL", "database_object")]["message"]
    assert "registration" in groups[("PRINT_LAYOUT", "report")]["message"]
    assert all(g["status"] == "unverified" for g in report["dependencies"] if g["kind"] != "local_routine")
    assert all(g["message"] and g["next_action"] for g in report["dependencies"])
    assert all("missing customer" not in g["message"] for g in report["dependencies"] if g["name"] != "DUAL")


def test_renamed_sources_and_modules_do_not_resolve_across_modules():
    a = source("FIRST", helper="UNIQUE_HELPER")
    other = ET.fromstring(source("SECOND", helper="SECOND_HELPER"))
    for trigger in other.iter("Trigger"):
        trigger.set("TriggerText", "BEGIN UNIQUE_HELPER(1); GO_ITEM(1); END;")
    packet, chunks, ledger, gaps, catalog, report = context([("renamed-a.xml", a), ("renamed-b.xml", ET.tostring(other))])
    assert report["summary"]["total_units"] == 12
    matches = [g for g in report["dependencies"] if g["name"].upper() == "UNIQUE_HELPER"]
    assert {g["kind"] for g in matches} == {"local_routine", "routine_reference"}
    assert len([g for g in report["dependencies"] if g["kind"] == "forms_api" and g["name"].upper() == "GO_ITEM"]) == 2
    assert all(len({o["source_file"] for o in g["occurrences"]}) == 1 for g in report["dependencies"])
    validate_discrepancies(report, ledger, gaps, catalog, packet=packet, chunks=chunks)


def test_declaration_only_or_unavailable_chunks_do_not_prove_body(example):
    packet, _, ledger, gaps, catalog, _ = example
    report = build_discrepancies(packet, ledger, gaps, catalog)
    assert next(g for g in report["dependencies"] if g["kind"] == "local_routine")["status"] == "unverified"
    *_, report = context([("declaration.xml", source(body=False))])
    assert next(g for g in report["dependencies"] if g["kind"] == "local_routine")["status"] == "unverified"


def test_multiple_modules_in_one_file_keep_reference_groups_separate():
    root = ET.Element("Module")
    root.extend([ET.fromstring(source("FIRST")), ET.fromstring(source("SECOND"))])
    packet, chunks, ledger, gaps, catalog, report = context([("modules.xml", ET.tostring(root))])
    assert report["summary"]["total_units"] == 12
    assert len([g for g in report["dependencies"] if g["kind"] == "local_routine"]) == 2
    assert len([g for g in report["dependencies"] if g["name"].upper() == "GO_ITEM"]) == 2
    validate_discrepancies(report, ledger, gaps, catalog, packet=packet, chunks=chunks)
    broken = deepcopy(report)
    groups = [g for g in broken["dependencies"] if g["name"].upper() == "GO_ITEM"]
    groups[0]["occurrences"].extend(groups[1]["occurrences"])
    broken["dependencies"].remove(groups[1])
    with pytest.raises(ValueError):
        validate_discrepancies(broken, ledger, gaps, catalog)


@pytest.mark.parametrize("mutation", ["binding", "sha", "name", "file", "line", "drop_unit", "duplicate_unit",
    "promote_unit", "summary", "bool_summary", "extra_field", "drop_field", "runtime", "business",
    "drop_reference", "duplicate_reference", "reference_name", "reference_line", "reference_unit", "dependency_status", "group_id"])
def test_rehashed_report_tampering_is_rejected_without_trusting_report_hash(example, mutation):
    packet, chunks, ledger, gaps, catalog, report = deepcopy(example)
    if mutation == "binding": report["source_binding"] = "0" * 64
    elif mutation == "sha": report["units"][0]["source_unit_sha256"] = "0" * 64
    elif mutation in {"name", "file", "line"}:
        report["units"][0]["source_" + mutation] = 999 if mutation == "line" else "invented"
    elif mutation == "drop_unit": report["units"].pop()
    elif mutation == "duplicate_unit": report["units"][-1] = deepcopy(report["units"][0])
    elif mutation == "promote_unit": report["units"][-1]["status"] = "generated"
    elif mutation == "summary": report["summary"]["generated_units"] += 1
    elif mutation == "bool_summary": report["summary"]["generated_units"] = True
    elif mutation == "extra_field": report["invented"] = True
    elif mutation == "drop_field": report["units"][0].pop("next_action")
    elif mutation == "runtime": report["runtime_verified"] = True
    elif mutation == "business": report["business_behavior_accepted"] = True
    elif mutation == "drop_reference": report["dependencies"].pop()
    elif mutation == "duplicate_reference": report["dependencies"][0]["occurrences"] *= 2
    elif mutation == "reference_name": report["dependencies"][0]["name"] = "INVENTED"
    elif mutation == "reference_line": report["dependencies"][0]["occurrences"][0]["source_line"] += 1
    elif mutation == "reference_unit": report["dependencies"][0]["occurrences"][0]["source_unit_ids"] = ["unknown"]
    elif mutation == "dependency_status": report["dependencies"][0]["status"] = "runtime_verified"
    elif mutation == "group_id": report["dependencies"][0]["id"] = "fd1-" + "0" * 24
    # These are content gates; a caller computing a new JSON hash grants nothing.
    for kwargs in ({}, {"packet": packet, "chunks": chunks}):
        with pytest.raises(ValueError):
            validate_discrepancies(report, ledger, gaps, catalog, **kwargs)


@pytest.mark.parametrize("mutation", ["dropped_ledger", "duplicate_ledger", "unit_sha", "unit_line", "source_file_sha",
    "drop_candidate", "duplicate_candidate", "candidate_line", "catalog_sha", "gap_binding", "gap_name", "gap_drop", "chunk_text"])
def test_fresh_source_evidence_tampering_is_rejected(example, mutation):
    packet, chunks, ledger, gaps, catalog, _ = deepcopy(example)
    if mutation == "dropped_ledger": ledger["code_units"].pop()
    elif mutation == "duplicate_ledger": ledger["code_units"][-1] = deepcopy(ledger["code_units"][0])
    elif mutation == "unit_sha": ledger["code_units"][0]["source_unit_sha256"] = "0" * 64
    elif mutation == "unit_line": ledger["code_units"][0]["source_location"]["line"] += 1
    elif mutation == "source_file_sha": ledger["code_units"][0]["source_file"]["sha256"] = "0" * 64
    elif mutation == "drop_candidate": ledger["dependencies_and_links"].pop()
    elif mutation == "duplicate_candidate": ledger["dependencies_and_links"].append(deepcopy(ledger["dependencies_and_links"][0]))
    elif mutation == "candidate_line": ledger["dependencies_and_links"][0]["evidence"]["location"]["line"] += 1
    elif mutation == "catalog_sha": catalog["catalog_sha256"] = "0" * 64
    elif mutation == "gap_binding": gaps["source_binding"] = "0" * 64
    elif mutation == "gap_name": gaps["gaps"][0]["source_name"] = "INVENTED"
    elif mutation == "gap_drop": gaps["gaps"].pop()
    elif mutation == "chunk_text": chunks[0]["text"] += " NULL;"
    with pytest.raises(ValueError):
        build_discrepancies(packet, ledger, gaps, catalog, chunks=chunks)


def test_retained_validation_preserves_old_explanation_and_registry_without_rebuilding(example, monkeypatch):
    _, _, ledger, gaps, catalog, report = deepcopy(example)
    generated = next(u for u in report["units"] if u["status"] == "generated")
    generated["message"] = "Historical explanation. " + generated["message"]
    monkeypatch.setattr("fox.forms_discrepancies.build_discrepancies", lambda *a, **k: pytest.fail("must not rebuild historical artifact"))
    assert validate_discrepancies(report, ledger, gaps, catalog) == report


def semantic_context(text):
    root = ET.fromstring(source())
    next(t for t in root.iter("Trigger") if t.get("Name") == "CHECK").set("TriggerText", text)
    return context([("encoded.xml", ET.tostring(root))])


@pytest.mark.parametrize("newline", ["&#10;", "&#13;", "&#13;&#10;", "\n", "\r", "\r\n"])
def test_additive_semantic_inventory_unhides_calls_after_encoded_or_native_newlines(newline):
    packet, chunks, ledger, gaps, catalog, old_report = semantic_context(
        "BEGIN -- comment" + newline + " REMOTE_API.RUN(1); SELECT 1 FROM HIDDEN_ROWS; END;")
    original = deepcopy((packet, chunks, ledger, gaps, catalog, old_report))
    evidence = build_dependency_evidence(packet, chunks, ledger)
    report = build_discrepancies(packet, ledger, gaps, catalog, chunks=chunks, dependency_evidence=evidence)
    assert {g["name"] for g in report["dependencies"]} >= {"REMOTE_API.RUN", "HIDDEN_ROWS"}
    assert report["source_binding"] == old_report["source_binding"]
    assert {k: v for k, v in report["summary"].items() if k.endswith("units")} == {
        k: v for k, v in old_report["summary"].items() if k.endswith("units")}
    assert all(g["status"] == "unverified" for g in report["dependencies"] if g["name"] in {"REMOTE_API.RUN", "HIDDEN_ROWS"})
    validate_discrepancies(report, ledger, gaps, catalog, packet=packet, chunks=chunks, dependency_evidence=evidence)
    validate_discrepancies(report, ledger, gaps, catalog, dependency_evidence=evidence)
    assert original == (packet, chunks, ledger, gaps, catalog, old_report)


@pytest.mark.parametrize("literal", ["'REMOTE_API.FAKE(1) FROM FAKE_ROWS'", "q'[REMOTE_API.FAKE(1) FROM FAKE_ROWS]'",
    "'&#10; REMOTE_API.FAKE(1)'", "q'[&#10; REMOTE_API.FAKE(1)]'"])
def test_literal_business_text_never_becomes_dependency_and_ambiguous_decoding_is_explicit(literal):
    packet, chunks, ledger, gaps, catalog, _ = semantic_context("BEGIN MESSAGE(" + literal + "); END;")
    evidence = build_dependency_evidence(packet, chunks, ledger)
    report = build_discrepancies(packet, ledger, gaps, catalog, chunks=chunks, dependency_evidence=evidence)
    assert not any("FAKE" in g["name"] for g in report["dependencies"])
    check = next(r for r in report["units"] if r["source_name"] == "CHECK")
    unit = next(u for u in evidence["units"] if u["source_unit_id"] == check["source_unit_id"])
    assert (unit["decoding"] == "original_fallback") == ("&#10;" in literal)
    assert bool(unit["limitation"]) == ("&#10;" in literal)
    validate_discrepancies(report, ledger, gaps, catalog, dependency_evidence=evidence)


def test_semantic_inventory_captures_simple_comma_from_lists_and_excludes_datatype_syntax():
    packet, chunks, ledger, gaps, catalog, _ = semantic_context(
        "DECLARE X VARCHAR2(30); Y NUMBER(5); BEGIN -- hidden&#10; "
        "SELECT A FROM FIRST_ROWS A, SECOND_ROWS AS B, THIRD_ROWS C WHERE NOT (1=2); "
        "MESSAGE('FROM FAKE_ROWS, OTHER_FAKE'); /* SELECT 1 FROM COMMENTED, ALSO_COMMENTED */ END;")
    evidence = build_dependency_evidence(packet, chunks, ledger)
    report = build_discrepancies(packet, ledger, gaps, catalog, chunks=chunks, dependency_evidence=evidence)
    names = {g["name"] for g in report["dependencies"]}
    assert names >= {"FIRST_ROWS", "SECOND_ROWS", "THIRD_ROWS"}
    assert names.isdisjoint({"VARCHAR2", "NUMBER", "NOT", "FAKE_ROWS", "OTHER_FAKE", "COMMENTED", "ALSO_COMMENTED"})


@pytest.mark.parametrize("mutation", ["binding", "unit_sha", "semantic_sha", "unit_drop", "reference_drop",
    "reference_duplicate", "reference_name", "reference_line", "extra_field", "chunk_text"])
def test_additive_evidence_is_closed_and_exactly_rebuilt_from_fresh_source(mutation):
    packet, chunks, ledger, gaps, catalog, _ = semantic_context("BEGIN -- hidden&#10; REMOTE_API.RUN(1); END;")
    evidence = build_dependency_evidence(packet, chunks, ledger)
    if mutation == "binding": evidence["source_binding"] = "0" * 64
    elif mutation == "unit_sha": evidence["units"][0]["source_unit_sha256"] = "0" * 64
    elif mutation == "semantic_sha": evidence["units"][0]["semantic_sha256"] = "0" * 64
    elif mutation == "unit_drop": evidence["units"].pop()
    elif mutation == "reference_drop": evidence["references"].pop()
    elif mutation == "reference_duplicate": evidence["references"].append(deepcopy(evidence["references"][0]))
    elif mutation == "reference_name": evidence["references"][0]["evidence"]["name"] = "INVENTED"
    elif mutation == "reference_line": evidence["references"][0]["evidence"]["location"]["line"] += 1
    elif mutation == "extra_field": evidence["invented"] = True
    elif mutation == "chunk_text": chunks[0]["text"] += " NULL;"
    with pytest.raises(ValueError):
        build_discrepancies(packet, ledger, gaps, catalog, chunks=chunks, dependency_evidence=evidence)


@pytest.mark.parametrize("mutation", ["binding", "unit_sha", "semantic_sha", "unit_drop", "extra_field", "duplicate_reference", "non_code_reference_drop"])
def test_authenticated_retained_evidence_still_requires_closed_schema_and_crosslinks(mutation):
    packet, chunks, ledger, gaps, catalog, _ = semantic_context("BEGIN -- hidden&#10; REMOTE_API.RUN(1); END;")
    evidence = build_dependency_evidence(packet, chunks, ledger)
    report = build_discrepancies(packet, ledger, gaps, catalog, chunks=chunks, dependency_evidence=evidence)
    if mutation == "binding": evidence["source_binding"] = "0" * 64
    elif mutation == "unit_sha": evidence["units"][0]["source_unit_sha256"] = "0" * 64
    elif mutation == "semantic_sha": evidence["units"][0]["semantic_sha256"] = "not-a-sha"
    elif mutation == "unit_drop": evidence["units"].pop()
    elif mutation == "extra_field": evidence["references"][0]["evidence"]["invented"] = True
    elif mutation == "duplicate_reference": evidence["references"].append(deepcopy(evidence["references"][0]))
    elif mutation == "non_code_reference_drop": evidence["references"].pop(0)
    with pytest.raises(ValueError):
        validate_discrepancies(report, ledger, gaps, catalog, dependency_evidence=evidence)


def test_ambiguous_unit_retains_original_candidates_and_retained_path_never_rescans(monkeypatch):
    packet, chunks, ledger, gaps, catalog, _ = semantic_context("BEGIN MESSAGE('&#10;'); REMOTE_API.RUN(1); END;")
    evidence = build_dependency_evidence(packet, chunks, ledger)
    report = build_discrepancies(packet, ledger, gaps, catalog, chunks=chunks, dependency_evidence=evidence)
    assert any(u["decoding"] == "original_fallback" for u in evidence["units"])
    monkeypatch.setattr("fox.forms_discrepancies.build_dependency_evidence", lambda *a: pytest.fail("historical read must not rescan"))
    assert validate_discrepancies(report, ledger, gaps, catalog, dependency_evidence=evidence) == report
    evidence["references"] = [row for row in evidence["references"] if row["evidence"].get("name") != "REMOTE_API.RUN"]
    report["dependencies"] = [g for g in report["dependencies"] if g["name"] != "REMOTE_API.RUN"]
    report["summary"]["dependency_groups"] -= 1
    report["summary"]["dependency_references"] -= 1
    with pytest.raises(ValueError):
        validate_discrepancies(report, ledger, gaps, catalog, dependency_evidence=evidence)
