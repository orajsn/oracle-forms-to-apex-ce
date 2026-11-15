"""Sanitized source fixtures only; no customer code or Oracle/model operations."""
from copy import deepcopy
from decimal import Decimal
import hashlib
import xml.etree.ElementTree as ET

import pytest

from forms2apex.forms_count_guard import (
    blocks_matching_numeric_rows, extract_count_guard, validate_count_guard,
)


CODE = """/* FOX_ANALYSIS_ONLY_NON_EXECUTABLE */
DECLARE
  unused_counter NUMBER:=0;
  unused_text VARCHAR2(FOX_REDACTED_NUMBER_1):=NULL;
  found_rows NUMBER;
BEGIN
  SELECT COUNT(0) INTO found_rows FROM DEMO_DETAIL
  WHERE NVL(QUANTITY,0)=0 /* masked comment */ AND GROUP_NO=:GROUP_NO;
  IF found_rows >0 THEN
    MESSAGE(FOX_REDACTED_LITERAL_1);
    MESSAGE(FOX_REDACTED_LITERAL_2);
    RAISE FORM_TRIGGER_FAILURE;
  END IF;
  unsupported_followup;
EXCEPTION WHEN OTHERS THEN NULL;
END;"""


def fixture(code=CODE):
    root = ET.Element("Module", xmlns="http://xmlns.oracle.com/Forms")
    form = ET.SubElement(root, "FormModule", Name="DEMO_FORM")
    master = ET.SubElement(form, "Block", Name="DEMO_MASTER")
    ET.SubElement(master, "Item", Name="GROUP_NO", DatabaseItem="true",
                  ColumnName="GROUP_NO", DataType="Char")
    button = ET.SubElement(master, "Item", Name="CHECK_RECORDS", ItemType="Push Button")
    ET.SubElement(button, "Trigger", Name="WHEN-BUTTON-PRESSED", TriggerText=code)
    detail = ET.SubElement(form, "Block", Name="DEMO_DETAIL", DatabaseBlock="true",
                           QueryDataSourceType="Table", QueryDataSourceName="DEMO_DETAIL")
    ET.SubElement(detail, "Item", Name="DETAIL_QUANTITY", DatabaseItem="true",
                  ColumnName="QUANTITY", DataType="Number")
    ET.SubElement(detail, "Item", Name="DETAIL_GROUP", DatabaseItem="true",
                  ColumnName="GROUP_NO", DataType="Char")
    return ET.tostring(root)


def extract(raw):
    return extract_count_guard(raw, source_sha256=hashlib.sha256(raw).hexdigest(),
                               module="DEMO_FORM", block="DEMO_MASTER", item="CHECK_RECORDS")


def test_exact_prefix_source_bindings_and_visible_remainder():
    raw = fixture()
    spec = extract(raw)
    assert validate_count_guard(spec, raw) == spec
    assert extract(raw) == spec
    assert spec["bindings"]["value"] == {
        "block": "DEMO_DETAIL", "item": "DETAIL_QUANTITY", "column": "QUANTITY", "data_type": "Number"}
    assert spec["bindings"]["bind"]["block"] == "DEMO_MASTER"
    path = "/Module[1]/FormModule[1]/Block[2]/Item[1]"
    expected_id = "ff1-" + hashlib.sha256((hashlib.sha256(raw).hexdigest() + "\n" + path + "\n").encode()).hexdigest()[:24]
    assert spec["source_objects"]["value_item"] == {"path": path, "id": expected_id}
    assert spec["source"]["trigger_sha256"] == hashlib.sha256(CODE.encode()).hexdigest()
    end = spec["source"]["prefix_end_character"]
    assert CODE[:end].rstrip().endswith("END IF;")
    assert spec["source"]["prefix_sha256"] == hashlib.sha256(CODE[:end].encode()).hexdigest()
    assert spec["unsupported_remainder"]["sha256"] == hashlib.sha256(CODE[end:].encode()).hexdigest()
    assert spec["unsupported_remainder"]["converted"] is False
    assert spec["unsupported_remainder"]["exception_keyword_present"] is True
    assert spec["unsupported_remainder"]["exception_handlers_converted"] is False
    assert spec["diagnostics"] == {"message_count": 2, "message_text_available": False,
                                    "unused_declaration_length_redacted": True}
    assert "EXCEPTION" in CODE[end:]
    assert any("exception handlers" in line for line in spec["limitations"])


@pytest.mark.parametrize("values,blocked", [([], False), ([1, 2], False), ([-1], False),
    ([Decimal("-0.01"), 2], False), ([None], True), ([0], True),
    ([Decimal("0.00")], True), ([4, None, -1], True)])
def test_exact_null_or_zero_predicate_model_not_positive_only(values, blocked):
    assert blocks_matching_numeric_rows(values) is blocked


@pytest.mark.parametrize("old,new", [
    ("COUNT(0)", "COUNT(QUANTITY)"), ("NVL(QUANTITY,0)", "NVL(QUANTITY,1)"),
    ("NVL(QUANTITY,0)", "NVL(QUANTITY,FOX_REDACTED_NUMBER_2)"),
    ("=0 /* masked", "<0 /* masked"), ("found_rows >0", "found_rows >=0"),
    ("GROUP_NO=:GROUP_NO", "GROUP_NO=:GROUP_NO OR 1=1"),
    ("SELECT COUNT", "COMMIT; SELECT COUNT"),
    ("IF found_rows", "found_rows:=0; IF found_rows"),
    ("RAISE FORM_TRIGGER_FAILURE", "COMMIT; RAISE FORM_TRIGGER_FAILURE"),
    ("MESSAGE(FOX_REDACTED_LITERAL_1)", "MESSAGE(unknown_function())"),
    ("MESSAGE(FOX_REDACTED_LITERAL_1)", "MESSAGE(FOX_REDACTED_LITERAL_1||GROUP_NO)"),
    ("unused_counter NUMBER:=0", "unused_counter NUMBER:=side_effect()"),
    ("unused_counter NUMBER:=0", "unused_counter NUMBER:=FOX_REDACTED_NUMBER_2"),
    ("found_rows NUMBER", "found_rows VARCHAR2(30)"),
    ("FROM DEMO_DETAIL", "FROM FOX_REDACTED_TABLE_1"),
    ("QUANTITY,0", "FOX_REDACTED_COLUMN_1,0"),
    ("BEGIN\n  SELECT", "BEGIN\n  IF 1=1 THEN SELECT"),
])
def test_unknown_predicate_or_prefix_side_effects_fail_closed(old, new):
    assert old in CODE
    with pytest.raises(ValueError):
        extract(fixture(CODE.replace(old, new, 1)))


def test_real_quoted_diagnostics_and_comments_are_not_executed():
    raw = fixture(CODE.replace("FOX_REDACTED_LITERAL_1", "'/* not a comment */ can''t proceed'"))
    assert extract(raw)["diagnostics"]["message_count"] == 2


@pytest.mark.parametrize("mutation", ["bind", "table", "column", "datatype", "disabled", "trigger"])
def test_ambiguous_or_unproven_source_binding_rejected(mutation):
    root = ET.fromstring(fixture())
    ns = "{http://xmlns.oracle.com/Forms}"
    form = root[0]
    master, detail = form
    if mutation == "bind":
        ET.SubElement(detail, ns + "Item", Name="GROUP_NO", DatabaseItem="true",
                      ColumnName="OTHER", DataType="Char")
    elif mutation == "table":
        form.append(deepcopy(detail))
    elif mutation == "column":
        detail.append(deepcopy(detail[0]))
    elif mutation == "datatype":
        detail[0].set("DataType", "Char")
    elif mutation == "disabled":
        master[1].set("Enabled", "false")
    elif mutation == "trigger":
        master[1].append(deepcopy(master[1][0]))
    with pytest.raises(ValueError):
        extract(ET.tostring(root))


@pytest.mark.parametrize("part", ["predicate", "source", "bindings", "unsupported_remainder", "extra"])
def test_spec_changes_cannot_authorize_another_rule(part):
    raw = fixture()
    spec = extract(raw)
    if part == "extra":
        spec["full_approval_converted"] = True
    elif part == "predicate":
        spec[part]["equals"] = 1
    elif part == "source":
        spec[part]["trigger_sha256"] = "0" * 64
    elif part == "bindings":
        spec[part]["value"]["column"] = "OTHER"
    else:
        spec[part]["converted"] = True
    with pytest.raises(ValueError):
        validate_count_guard(spec, raw)


def test_changed_original_and_dtd_are_rejected():
    raw = fixture()
    with pytest.raises(ValueError, match="SOURCE_HASH_MISMATCH"):
        validate_count_guard(extract(raw), raw + b" ")
    with pytest.raises(ValueError, match="DECLARATION_FORBIDDEN"):
        extract(b'<!DOCTYPE Module [<!ENTITY x "bad">]>' + raw)


def test_boolean_integer_substitution_is_not_equal_source_evidence():
    raw = fixture()
    spec = extract(raw)
    spec["predicate"]["equals"] = False
    with pytest.raises(ValueError, match="SPEC_SOURCE_MISMATCH"):
        validate_count_guard(spec, raw)


@pytest.mark.parametrize("values", [[True], ["0"], [0.0], [Decimal("NaN")], [Decimal("Infinity")]])
def test_local_predicate_model_rejects_unproven_numeric_conversion(values):
    with pytest.raises(ValueError):
        blocks_matching_numeric_rows(values)
