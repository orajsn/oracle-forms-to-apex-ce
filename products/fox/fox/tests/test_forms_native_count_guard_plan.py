"""Synthetic source-to-plan checks; no model, database or live-source fixtures."""
from copy import deepcopy
import hashlib
import xml.etree.ElementTree as ET

import pytest

from fox.forms_native_plan import POLICY_ID, _canonical
from fox.forms_native_required_plan import build_native_required_prototype_plan
from fox.forms_native_count_guard_plan import build_native_count_guard_prototype_plan
from test_forms_native_plan import design


def source():
    root = ET.Element("Module", xmlns="http://xmlns.oracle.com/Forms")
    form = ET.SubElement(root, "FormModule", Name="SYNTHETIC")
    master = ET.SubElement(form, "Block", Name="HEADER", DatabaseBlock="true",
                           QueryDataSourceType="Table", QueryDataSourceName="DEMO_HEADER")
    ET.SubElement(master, "Item", Name="GROUP_NO", ItemType="Text Item", DataType="Char",
                  MaximumLength="30", DatabaseItem="true", ColumnName="GROUP_NO")
    button = ET.SubElement(master, "Item", Name="CHECK_RECORDS", ItemType="Push Button")
    ET.SubElement(button, "Trigger", Name="WHEN-BUTTON-PRESSED", TriggerText="""DECLARE
        found_rows NUMBER;
        BEGIN
          SELECT COUNT(0) INTO found_rows FROM DEMO_DETAIL
          WHERE NVL(QUANTITY,0)=0 AND GROUP_NO=:GROUP_NO;
          IF found_rows > 0 THEN MESSAGE('Check required'); RAISE FORM_TRIGGER_FAILURE; END IF;
          unimplemented_followup;
        EXCEPTION WHEN OTHERS THEN NULL;
        END;""")
    detail = ET.SubElement(form, "Block", Name="DETAIL", DatabaseBlock="true",
                           QueryDataSourceType="Table", QueryDataSourceName="DEMO_DETAIL")
    ET.SubElement(detail, "Item", Name="DETAIL_GROUP", ItemType="Text Item", DataType="Char",
                  MaximumLength="30", DatabaseItem="true", ColumnName="GROUP_NO")
    ET.SubElement(detail, "Item", Name="QUANTITY", ItemType="Text Item", DataType="Number",
                  DatabaseItem="true", ColumnName="QUANTITY")
    return ET.tostring(root)


def inputs():
    raw = source()
    docs = [("synthetic.xml", raw)]
    return docs, design(docs), {"source_name": docs[0][0],
        "source_sha256": hashlib.sha256(raw).hexdigest(), "module": "SYNTHETIC",
        "block": "HEADER", "item": "CHECK_RECORDS"}


def build(docs, blueprint, selected, consent=True):
    return build_native_count_guard_prototype_plan(docs, blueprint,
        project_id="project-count-check", project_name="Synthetic count check",
        approved_policy_id=POLICY_ID, count_guard_selection=selected,
        partial_scope_consent=consent)


def test_exact_source_plan_preserves_omissions_and_requires_real_runtime():
    docs, blueprint, selected = inputs()
    before = deepcopy((docs, blueprint, selected))
    result = build(docs, blueprint, selected)
    assert result == build(docs, blueprint, selected)
    assert (docs, blueprint, selected) == before
    assert result["rendering_spec"]["schema_version"] == 3
    assert result["count_guard_plan"]["status"] == "planned_not_runtime_verified"
    assert result["count_guard_plan"]["full_button_converted"] is False
    assert result["count_guard_plan"]["business_behavior_accepted"] is False
    assert all(result["coverage"][key] is False for key in (
        "native_apex_generated", "import_verified", "business_behavior_accepted"))
    marked = [row for row in result["coverage"]["objects"] if "isolated_count_check" in row]
    assert {row["kind"] for row in marked} == {"Item", "Trigger"}
    assert all(row["isolated_count_check"]["full_object_converted"] is False for row in marked)
    assert any(row["code"] == "code_unit_not_translated" for row in result["remediation"])
    assert any(row["code"] == "count_check_remainder_not_converted" for row in result["remediation"])
    unsigned = {k: v for k, v in result.items() if k != "plan_sha256"}
    assert hashlib.sha256(_canonical(unsigned)).hexdigest() == result["plan_sha256"]


def test_existing_required_plan_schema_and_files_are_unchanged():
    from forms2apex import native_blueprint_count_guard as new
    from forms2apex import native_blueprint_required as old
    docs, blueprint, selected = inputs()
    base = build_native_required_prototype_plan(docs, blueprint,
        project_id="project-count-check", project_name="Synthetic count check", approved_policy_id=POLICY_ID)
    result = build(docs, blueprint, selected)
    assert result["rendering_spec"]["blocks"] == base["rendering_spec"]["blocks"]
    assert new.render_prototype_schema(result["rendering_spec"]) == old.render_prototype_schema(base["rendering_spec"])
    assert base["rendering_spec"]["schema_version"] == 2
    assert "count_guard" not in base["rendering_spec"]
    assert result["coverage"]["accounted_objects"] == base["coverage"]["accounted_objects"]


@pytest.mark.parametrize("consent", [False, None, 1, "true"])
def test_explicit_boolean_partial_consent_required(consent):
    with pytest.raises(ValueError, match="consent"):
        build(*inputs(), consent=consent)


@pytest.mark.parametrize("mutation", ["hash", "file", "button", "extra", "missing"])
def test_stale_unknown_or_ambiguous_source_selection_rejected(mutation):
    docs, blueprint, selected = inputs()
    if mutation == "hash": selected["source_sha256"] = "0" * 64
    if mutation == "file": selected["source_name"] = "absent.xml"
    if mutation == "button": selected["item"] = "UNKNOWN"
    if mutation == "extra": selected["sql"] = "select 1 from dual"
    if mutation == "missing": selected.pop("module")
    with pytest.raises(ValueError):
        build(docs, blueprint, selected)


@pytest.mark.parametrize("kind", ["Item", "Trigger"])
def test_explicitly_omitted_action_is_not_silently_partly_added(kind):
    from fox.forms_understanding_packet import local_packet
    docs, blueprint, selected = inputs()
    objects = local_packet(docs)["sources"][0]["facts"]["objects"]
    wanted = "CHECK_RECORDS" if kind == "Item" else "WHEN-BUTTON-PRESSED"
    object_id = next(row["id"] for row in objects if row["kind"] == kind and row["name"] == wanted)
    proposal = next(row for row in blueprint["objects"] if row["source_object_id"] == object_id)
    proposal.update(disposition="omitted", reason="Explicitly excluded from this prototype.")
    proposal.pop("screen_id", None)
    with pytest.raises(ValueError, match="omitted"):
        build(docs, blueprint, selected)


def test_missing_detail_field_is_not_invented_to_force_rule_conversion():
    from fox.forms_understanding_packet import local_packet
    docs, blueprint, selected = inputs()
    objects = local_packet(docs)["sources"][0]["facts"]["items"]
    object_id = next(row["id"] for row in objects if row["name"] == "QUANTITY")
    row = next(row for row in blueprint["objects"] if row["source_object_id"] == object_id)
    row.update(disposition="omitted", reason="Unavailable in this selected mapping.")
    row.pop("screen_id", None)
    with pytest.raises(ValueError, match="SOURCE_FIELD_NOT_MAPPED"):
        build(docs, blueprint, selected)
