"""Synthetic local planning only; no provider, Oracle or customer XML proof."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from fox.forms_native_plan import POLICY_ID, build_native_prototype_plan
from fox.forms_understanding_packet import local_packet


def source(items=None, *, database=True, block_name="BUSINESS", extras=""):
    items = items or ['<Item Name="VALUE" ItemType="Text Item" DataType="Char" MaximumLength="90" DatabaseItem="true" Prompt="Value"/>']
    return (f'<FormModule Name="SYNTHETIC"><Block Name="{block_name}" DatabaseBlock="{str(database).lower()}">'
            + "".join(items) + f'</Block>{extras}</FormModule>').encode()


def design(documents, *, propose=True):
    packet = local_packet(documents)
    rows = []
    for entry in packet["sources"]:
        for obj in entry["facts"]["objects"]:
            row = {"source_object_id": obj["id"], "disposition": "unresolved", "reason": "Source behavior still needs review."}
            if propose and obj["kind"] in {"Block", "Item"}:
                row.update(disposition="proposed", reason="Explicit prototype proposal.", screen_id="screen")
                if obj["kind"] == "Block":
                    row["native_component"] = "form" if obj["classification"] == "database" else "page-items"
            rows.append(row)
    return {"schema_version": 1, "scope": "fox-forms-blueprint-v1", "source_binding": packet["source_binding"],
            "objects": rows, "screens": [{"id": "screen", "title": "Synthetic prototype"}] if propose else [],
            "claims": [], "relationships": [], "actions": [], "questions": [], "assumptions": []}


def build(documents, blueprint=None, **kwargs):
    return build_native_prototype_plan(documents, blueprint or design(documents), project_id="project-1",
                                       project_name="Synthetic prototype", approved_policy_id=kwargs.pop("policy", POLICY_ID), **kwargs)


def item(name, dtype="Char", kind="Text Item", length="100", flag="true", prompt="Label"):
    return (f'<Item Name="{name}" ItemType="{kind}" DataType="{dtype}" MaximumLength="{length}" '
            f'DatabaseItem="{flag}" Prompt="{prompt}" ColumnName="CUSTOMER_COLUMN"/>')


def test_multi_database_and_control_bound_to_fresh_bytes_without_mutation():
    documents = [("a.xml", source([item("NAME"), item("AMOUNT", "Number"), item("DAY", "Date")], extras='<Trigger Name="SAVE" TriggerText="BEGIN BUSINESS_API.SAVE; END;"/>')),
                 ("b.xml", source([item("SEARCH", flag="false")], database=False, block_name="CONTROL"))]
    blueprint = design(documents)
    before = deepcopy((documents, blueprint))
    result = build(documents, blueprint)
    spec = result["rendering_spec"]
    database, control = spec["blocks"]
    assert database["classification"] == "database"
    assert len(database["table_name"]) == 30 and database["table_name"].startswith("FOX_NATIVE_")
    assert [f["data_type"] for f in database["fields"]] == ["VARCHAR2", "NUMBER", "DATE"]
    assert control["table_name"] is None and control["classification"] == "control"
    assert database["native_component"] == "form" and control["native_component"] == "page-items"
    assert all(f["nullable"] is True for b in spec["blocks"] for f in b["fields"])
    assert all(f["name"].startswith("F_") and f["name"].isupper() for b in spec["blocks"] for f in b["fields"])
    assert "CUSTOMER_COLUMN" not in json.dumps(spec)
    assert "BUSINESS_API.SAVE" not in json.dumps(result)
    assert any(r["code"] == "code_unit_not_translated" for r in result["remediation"])
    assert result["coverage"]["accounted_objects"] == result["coverage"]["source_objects"]
    assert all(result["coverage"][key] is False for key in ("native_apex_generated", "import_verified", "business_behavior_accepted"))
    assert (documents, blueprint) == before


def test_real_scale_synthetic_109_main_items_and_complete_9_block_222_item_accounting():
    kinds = ["Text Item"] * 58 + ["List Item"] * 12 + ["Check Box"] * 26 + ["Display Item"] * 13
    parts = ['<FormModule Name="SYNTHETIC">']
    for b in range(9):
        parts.append(f'<Block Name="B{b}" DatabaseBlock="true">')
        count = 109 if b == 0 else 15 if b < 2 else 14
        for i in range(count):
            parts.append(item(f"I{i}", "Datetime" if i == 0 else "Char", kinds[i] if b == 0 else "Text Item"))
        parts.append('</Block>')
    parts.append('<LOV Name="LOOKUP"/><Relation Name="DETAIL"/><AttachedLibrary Name="LIB"/><ProgramUnit Name="CALL" ProgramUnitText="BEGIN NULL; END;"/></FormModule>')
    documents = [("scale.xml", "".join(parts).encode())]
    result = build(documents)
    assert len(result["rendering_spec"]["blocks"]) == 9
    assert len(result["rendering_spec"]["blocks"][0]["fields"]) == 109
    assert sum(len(b["fields"]) for b in result["rendering_spec"]["blocks"]) == 222
    rows = result["coverage"]["objects"]
    assert len([r for r in rows if r["kind"] == "Item"]) == 222
    assert len({r["source_object_id"] for r in rows}) == result["coverage"]["source_objects"]
    assert sum(a["code"] == "interaction_not_ported" for a in result["assumptions"]) == 38
    first = result["rendering_spec"]["blocks"][0]["fields"][0]
    assert (first["data_type"], first["length"], first["widget"]) == ("VARCHAR2", 64, "text")
    assert all(r["disposition"] == "unresolved" for r in rows if r["kind"] in {"LOV", "Relation", "AttachedLibrary", "ProgramUnit"})


@pytest.mark.parametrize("mutation", ["stale", "invented", "missing"])
def test_rejects_stale_invented_or_incomplete_blueprint(mutation):
    documents = [("a.xml", source())]
    blueprint = design(documents)
    if mutation == "stale":
        documents = [("a.xml", source([item("CHANGED")]))]
    elif mutation == "invented":
        blueprint["objects"][0]["source_object_id"] = "invented"
    else:
        blueprint["objects"].pop()
    with pytest.raises(ValueError):
        build(documents, blueprint)


@pytest.mark.parametrize("policy", [None, "", "automatic", True, "fox-demo-synthetic-schema-v2"])
def test_explicit_exact_policy_required(policy):
    with pytest.raises(ValueError, match="policy"):
        build([("a.xml", source())], policy=policy)


def test_source_metadata_missing_types_lengths_and_labels_are_never_guessed_silently():
    originals = [item("MISSING", ""), item("BINARY", "Image"), item("HUGE", length="4001"),
                 item("ZERO", length="0", prompt=""), item("BAD_LABEL", prompt="&lt;script&gt;"),
                 item("LONG_LABEL", prompt="L" * 100), item("NO_LENGTH").replace(' MaximumLength="100"', ""),
                 item("INVALID_LENGTH", length="-1"), item("DATE_TIME", "Datetime"),
                 item("BUTTON", kind="Push Button"), item("DISPLAY", kind="Display Item")]
    result = build([("a.xml", source(originals))])
    fields = {f["source_name"]: f for f in result["rendering_spec"]["blocks"][0]["fields"]}
    assert set(fields) == {"ZERO", "BAD_LABEL", "LONG_LABEL", "NO_LENGTH", "DATE_TIME", "DISPLAY"}
    assert fields["ZERO"]["length"] == fields["NO_LENGTH"]["length"] == 255
    assert fields["BAD_LABEL"]["label"] == "Bad Label"
    assert fields["DISPLAY"]["widget"] == "display" and fields["DISPLAY"]["in_edit_form"] is False
    metadata = {r["source_metadata"].get("Name"): r["source_metadata"] for r in result["coverage"]["objects"]}
    assert metadata["BAD_LABEL"]["Prompt"] == "<script>"
    assert metadata["LONG_LABEL"]["Prompt"] == "L" * 100
    assert metadata["ZERO"]["MaximumLength"] == "0"
    assert len([a for a in result["assumptions"] if a["code"] == "source_name_label_fallback"]) == 3
    assert any(r["code"] == "button_not_implemented" for r in result["remediation"])


def test_control_never_acquires_data_table_and_non_database_item_is_not_editable_storage():
    documents = [("a.xml", source([item("COMPUTED", flag="false"), item("UNKNOWN", flag="")], block_name="DATA")),
                 ("b.xml", source([item("SEARCH", flag="false"), item("INCONSISTENT", flag="true"),
                                   item("CONTROL_DISPLAY", flag="false", kind="Display Item")], database=False))]
    result = build(documents)
    data, control = result["rendering_spec"]["blocks"]
    assert all(f["widget"] == "display" and f["in_edit_form"] is False for f in data["fields"])
    assert control["table_name"] is None
    assert [f["source_name"] for f in control["fields"]] == ["SEARCH", "CONTROL_DISPLAY"]
    assert control["fields"][1]["widget"] == "display" and control["fields"][1]["in_edit_form"] is False
    assert any(r["code"] == "inconsistent_database_item" for r in result["remediation"])
    assert not any(r["code"] == "control_display_not_implemented" for r in result["remediation"])
    assert any(r["code"] == "control_display_no_computation" for r in result["assumptions"])


def test_only_proposed_objects_enter_plan_and_empty_known_database_block_is_retained():
    documents = [("a.xml", source([item("BAD", "Image"), item("OMITTED")]))]
    blueprint = design(documents)
    target = next(row for row in blueprint["objects"] if row["source_object_id"] == local_packet(documents)["sources"][0]["facts"]["items"][1]["id"])
    target.update(disposition="omitted", reason="Explicitly outside this draft.")
    target.pop("screen_id")
    result = build(documents, blueprint)
    assert result["rendering_spec"]["blocks"][0]["fields"] == []
    assert result["coverage"]["omitted_objects"] == 1
    assert any(row["code"] == "no_native_items" for row in result["remediation"])
    unresolved = build(documents, design(documents, propose=False))
    assert unresolved["rendering_spec"]["blocks"] == []


@pytest.mark.parametrize("component", ["report", "interactive-grid"])
def test_source_report_intent_is_preserved_and_grid_fallback_is_explicitly_read_only(component, monkeypatch):
    documents = [("a.xml", source([item("NAME"), item("AMOUNT", "Number")]))]
    blueprint = design(documents)
    block_row = next(row for row in blueprint["objects"] if "native_component" in row)
    block_row["native_component"] = component
    result = build(documents, blueprint)
    block = result["rendering_spec"]["blocks"][0]
    assert block["native_component"] == "report"
    assert all(field["in_edit_form"] is False for field in block["fields"])
    coverage = next(row for row in result["coverage"]["objects"] if row["kind"] == "Block")
    assert coverage["source_native_component"] == component
    assert coverage["planned_native_component"] == "report"
    assert result["coverage"]["accounted_objects"] == result["coverage"]["source_objects"]
    grid_remediation = [row for row in result["remediation"] if row["code"] == "grid_editing_not_implemented"]
    grid_assumptions = [row for row in result["assumptions"] if row["code"] == "grid_editing_not_implemented"]
    assert bool(grid_remediation) is (component == "interactive-grid")
    assert bool(grid_assumptions) is (component == "interactive-grid")
    if grid_remediation:
        assert "read-only" in grid_remediation[0]["reason"]
        assert "without a form" in grid_remediation[0]["reason"]
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "converter"))
    from forms2apex.native_blueprint import render_native_blueprint, validate_prototype_spec
    assert validate_prototype_spec(result["rendering_spec"]) == result["rendering_spec"]
    files = render_native_blueprint(result["rendering_spec"])
    assert "pages/p00002-edit_1.apx" not in files
    report = files["pages/p00001-block_1.apx"]
    assert "type: interactiveReport" in report and "type: tableView" in report
    assert "button " not in report and "linkColumn:" not in report and "formAutoRowProcessing" not in report


def test_9_block_216_field_control_display_plan_matches_renderer_without_business_claims(monkeypatch):
    parts = ['<FormModule Name="SYNTHETIC">']
    for block_index, count in enumerate((109, 62)):
        parts.append(f'<Block Name="DATA_{block_index}" DatabaseBlock="true">')
        parts.extend(item(f"I{i}") for i in range(count))
        parts.append('</Block>')
    for block_index, count in enumerate((7, 7, 7, 6, 6, 6, 6)):
        parts.append(f'<Block Name="CONTROL_{block_index}" DatabaseBlock="false">')
        parts.extend(item(f"DISPLAY_{i}", kind="Display Item", flag="false") for i in range(count))
        if block_index < 6:
            parts.append(item("ACTION", kind="Push Button", flag="false"))
        parts.append('</Block>')
    parts.append('</FormModule>')
    documents = [("control-display-scale.xml", "".join(parts).encode())]
    result = build(documents)
    spec = result["rendering_spec"]
    assert len(spec["blocks"]) == 9
    assert len(spec["blocks"][0]["fields"]) == 109
    assert sum(len(block["fields"]) for block in spec["blocks"]) == 216
    control_fields = [field for block in spec["blocks"] if block["classification"] == "control" for field in block["fields"]]
    assert len(control_fields) == 45
    assert all(field["widget"] == "display" and field["in_edit_form"] is False for field in control_fields)
    assert sum(row["code"] == "button_not_implemented" for row in result["remediation"]) == 6
    assert not any(row["code"] in {"control_display_not_implemented", "no_native_items"} for row in result["remediation"])
    assert sum(row["code"] == "control_display_no_computation" for row in result["assumptions"]) == 45
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "converter"))
    from forms2apex.native_blueprint import (deterministic_prototype_zip, prototype_trace,
                                           render_native_blueprint, render_prototype_schema,
                                           validate_prototype_spec)
    assert validate_prototype_spec(spec) == spec
    files = render_native_blueprint(spec)
    trace = prototype_trace(spec)
    assert sum(content.count("type: displayOnly") for content in files.values()) == 45
    for block in trace["blocks"]:
        if block["classification"] == "control":
            page = files[block["page_file"]]
            assert "pageItem " in page
            assert "tableName:" not in page and "source {" not in page and "process " not in page
            assert all(item["native_item"] is not None and item["database_bound"] is False
                       and item["value_computation_implemented"] is False for item in block["items"])
    assert render_prototype_schema(spec).count("CREATE TABLE ") == 2
    assert deterministic_prototype_zip(spec) == deterministic_prototype_zip(spec)
    assert all(trace[flag] is False for flag in ("sqlcl_validated", "imported", "runtime_verified", "business_behavior_verified"))
    assert result == build(documents)


def test_control_display_database_item_flag_retained_without_binding_or_editable_exception(monkeypatch):
    documents = [("flagged-display.xml", source([
        item("DISPLAY_FLAGGED", kind="Display Item", flag="true"),
        item("EDITABLE_FLAGGED", kind="Text Item", flag="true"),
        item("ACTION", kind="Push Button", flag="true"),
    ], database=False, block_name="CONTROL"))]
    result = build(documents)
    spec = result["rendering_spec"]
    block = spec["blocks"][0]
    assert block["table_name"] is None and block["native_component"] == "page-items"
    assert [field["source_name"] for field in block["fields"]] == ["DISPLAY_FLAGGED"]
    field = block["fields"][0]
    assert field["widget"] == "display" and field["in_edit_form"] is False
    row = next(row for row in result["coverage"]["objects"]
               if row["source_object_id"] == field["source_item_id"])
    assert row["disposition"] == "planned" and row["source_metadata"]["DatabaseItem"] == "true"
    assumptions = [row for row in result["assumptions"]
                   if row["code"] == "control_display_database_flag_not_binding"]
    assert len(assumptions) == 1 and assumptions[0]["source_object_id"] == field["source_item_id"]
    assert "does not establish a database binding" in assumptions[0]["reason"]
    assert sum(row["code"] == "inconsistent_database_item" for row in result["remediation"]) == 1
    assert sum(row["code"] == "button_not_implemented" for row in result["remediation"]) == 1
    assert result["coverage"]["accounted_objects"] == result["coverage"]["source_objects"]
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "converter"))
    from forms2apex.native_blueprint import prototype_trace, render_native_blueprint, render_prototype_schema, validate_prototype_spec
    assert validate_prototype_spec(spec) == spec
    trace = prototype_trace(spec)
    page = render_native_blueprint(spec)[trace["blocks"][0]["page_file"]]
    assert "type: displayOnly" in page
    for forbidden in ("source {", "tableName:", "formRegion:", "process ", "button ", "validation {"):
        assert forbidden not in page
    assert "CREATE TABLE" not in render_prototype_schema(spec)
    assert trace["blocks"][0]["items"][0]["database_bound"] is False
    assert trace["business_behavior_verified"] is False


def test_metadata_matches_full_exact_object_path_not_duplicate_name_or_substring():
    documents = [("a.xml", source([item("DUP", "Number"), item("DUP", "Date"), item("DUP", "Char", length="7")]))]
    result = build(documents)
    fields = result["rendering_spec"]["blocks"][0]["fields"]
    assert [f["data_type"] for f in fields] == ["NUMBER", "DATE", "VARCHAR2"]
    assert fields[2]["length"] == 7
    assert len({f["source_item_id"] for f in fields}) == len({f["name"] for f in fields}) == 3


def test_qualified_inherited_property_is_not_silently_an_effective_source_type():
    raw = source([item("QUALIFIED").replace('DataType="Char"', 'xmlns:p="urn:unresolved" p:DataType="Char"')])
    result = build([("a.xml", raw)])
    assert result["rendering_spec"]["blocks"][0]["fields"] == []
    row = next(r for r in result["coverage"]["objects"] if r["kind"] == "Item")
    assert row["source_metadata"]["{urn:unresolved}DataType"] == "Char"
    assert row["disposition"] == "unresolved"


def test_apex_substitutions_are_not_renderable_labels_or_project_names():
    documents = [("a.xml", source([item("SAFE_NAME", prompt="&amp;APP_USER.")]))]
    result = build(documents)
    assert result["rendering_spec"]["blocks"][0]["fields"][0]["label"] == "Safe Name"
    assert any(a["code"] == "source_name_label_fallback" for a in result["assumptions"])
    with pytest.raises(ValueError, match="Project name"):
        build_native_prototype_plan(documents, design(documents), project_id="project-1",
                                    project_name="&APP_USER.", approved_policy_id=POLICY_ID)


def test_maximum_limits_create_explicit_remediations_not_project_rejection():
    parts = ['<FormModule Name="SYNTHETIC">']
    for b in range(51):
        parts.append(f'<Block Name="B{b}" DatabaseBlock="true">')
        parts.extend(item(f"I{i}") for i in range(256 if b == 0 else 1))
        parts.append('</Block>')
    parts.append('</FormModule>')
    result = build([("limits.xml", "".join(parts).encode())])
    assert len(result["rendering_spec"]["blocks"]) == 50
    assert len(result["rendering_spec"]["blocks"][0]["fields"]) == 255
    codes = [r["code"] for r in result["remediation"]]
    assert "field_limit" in codes and "block_limit" in codes and "source_block_not_planned" in codes
    assert result["coverage"]["source_objects"] == result["coverage"]["accounted_objects"]


def test_canonical_complete_plan_hash_and_project_source_identifier_binding():
    documents = [("a.xml", source())]
    result = build(documents)
    assert result == build(documents)
    digest = result.pop("plan_sha256")
    assert digest == hashlib.sha256(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    other = build_native_prototype_plan(documents, design(documents), project_id="project-2", project_name="Synthetic prototype", approved_policy_id=POLICY_ID)
    assert other["rendering_spec"]["blocks"][0]["table_name"] != result["rendering_spec"]["blocks"][0]["table_name"]
    assert other["source_binding"] == result["source_binding"]


def test_proposed_code_and_relations_remain_unimplemented_even_when_model_proposes():
    documents = [("a.xml", source(extras='<Relation Name="DETAIL"/><LOV Name="CHOICE"/><ProgramUnit Name="UTIL" ProgramUnitText="BEGIN NULL; END;"/>'))]
    blueprint = design(documents)
    for row in blueprint["objects"]:
        if row["disposition"] == "unresolved":
            row.update(disposition="proposed", screen_id="screen")
    result = build(documents, blueprint)
    rows = result["coverage"]["objects"]
    assert all(r["disposition"] == "unresolved" for r in rows if r["kind"] not in {"Block", "Item"})
    assert "BEGIN NULL" not in json.dumps(result)
