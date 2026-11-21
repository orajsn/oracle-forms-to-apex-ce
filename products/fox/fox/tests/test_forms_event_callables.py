import hashlib
from xml.etree import ElementTree as ET

import pytest

from fox.forms_event_callables import build_event_callables
from fox.forms_understanding_packet import _build


AUDIT = ":UPDATED_BY := :GLOBAL.CLERK; :UPDATED_ON := SYSDATE;"
LIMIT = "IF :ORDERS.RATE > 75.5 THEN MESSAGE('Rate''s limit'); RAISE FORM_TRIGGER_FAILURE; END IF;"


def compile_event(body, *, project="pilot", event="POST-CHANGE", discount_type="Number", skip=False):
    form = ET.Element("FormModule", Name="SALES")
    block = ET.SubElement(form, "Block", Name="ORDERS", DatabaseBlock="true")
    value = ET.SubElement(block, "Item", Name="RATE", ItemType="Text Item", DataType=discount_type)
    ET.SubElement(block, "Item", Name="UPDATED_BY", ItemType="Display Item", DataType="Char")
    ET.SubElement(block, "Item", Name="UPDATED_ON", ItemType="Display Item", DataType="Datetime")
    ET.SubElement(value if event == "POST-CHANGE" else block, "Trigger", Name=event, TriggerText=body)
    docs = [("rules.xml",ET.tostring(form))]
    packet, chunks = _build(docs)
    unit, = packet["sources"][0]["facts"]["code_units"]
    coverage = [dict(source_unit_id=unit["id"], source_owner_id=unit["owner_id"], source_unit_sha256=unit["sha256"],
                     status="generated_wired_adapted" if skip else "unimplemented")]
    return build_event_callables(docs, packet, chunks, coverage, project)


def test_limit_and_audit_generate_ordered_parameterized_plsql():
    body = f"BEGIN {LIMIT} -- audit after successful validation&#10; {AUDIT} END;"
    operations, code = compile_event(body)
    op, = operations.values()
    assert op["source_unit_sha256"] == hashlib.sha256(body.encode()).hexdigest()
    assert op["guard"] == dict(kind="numeric_limit", parameter="p_1", operator=">", value="75.5", message="Rate's limit")
    assert [p["kind"] for p in op["parameters"]] == ["current_value","forms_global","current_row_output","current_row_output"]
    assert op["parameters"][1]["reference"] == "GLOBAL.CLERK"
    expected = ("IF p_1 > 75.5 THEN\n      raise_application_error(-20001, 'Rate''s limit');\n"
                "    END IF;\n    p_3 := p_2;\n    p_4 := SYSDATE;")
    assert expected in code.decode() and ":GLOBAL" not in code.decode()
    assert not op["native_event_wired"] and not op["oracle_compiled"]
    assert compile_event(body) == (operations,code)
    second, _ = compile_event(body,project="other")
    assert next(iter(second.values()))["package_name"] != op["package_name"]


def test_record_status_preserves_values_and_unconditional_create_is_distinct():
    ops, sql = compile_event(f"BEGIN IF :SYSTEM.RECORD_STATUS = 'CHANGED' THEN {AUDIT} END IF; END;")
    op, = ops.values()
    assert op["guard"]["kind"] == "record_status"
    assert [p["mode"] for p in op["parameters"] if p["kind"]=="current_row_output"] == ["IN OUT","IN OUT"]
    assert b"IF p_1 = 'CHANGED' THEN\n      p_3 := p_2;\n      p_4 := SYSDATE;\n    END IF;" in sql
    create, _ = compile_event(f"BEGIN {AUDIT} END;",event="WHEN-CREATE-RECORD")
    assert next(iter(create.values()))["guard"] is None


@pytest.mark.parametrize("body", [
    f"BEGIN {LIMIT} {AUDIT} COMMIT; END;",
    f"BEGIN :OTHER.UPDATED_BY := :GLOBAL.CLERK; END;",
    "BEGIN :UPDATED_BY := SYSDATE; END;",
    "BEGIN :UPDATED_ON := :GLOBAL.CLERK; END;",
    f"BEGIN {LIMIT.replace('> 75.5','> >= 75.5')} {AUDIT} END;",
    f"BEGIN {LIMIT.replace('ORDERS.RATE','ORDERS.UNKNOWN')} {AUDIT} END;",
    f"BEGIN {LIMIT.replace('FORM_TRIGGER_FAILURE','SOME_FAILURE')} {AUDIT} END;",
    f"BEGIN {LIMIT.replace('limit','&REFERENCE')} {AUDIT} END;",
    f"BEGIN {AUDIT} IF :RATE>9 THEN NULL; END IF; END;",
    f"BEGIN IF :SYSTEM.RECORD_STATUS = 'CHANGED' THEN {AUDIT} ELSE NULL; END IF; END;",
    f"BEGIN {AUDIT} END; ignored;",
])
def test_incomplete_shape_is_left_unchanged(body):
    assert compile_event(body) == ({},None)


def test_never_replaces_already_wired_code_or_guesses_numeric_input():
    body = f"BEGIN {LIMIT} {AUDIT} END;"
    assert compile_event(body,skip=True) == ({},None)
    assert compile_event(body,discount_type="Char") == ({},None)
