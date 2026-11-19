"""Pure local artifact tests, without Oracle compilation or runtime claims."""
from copy import deepcopy
import re

import pytest

from forms2apex.native_assignments import (
    SCOPE, _canonical, _sha, operation_id, parse_assignment_text, render_assignment_code,
)


def seal(plan):
    plan["plan_sha256"] = _sha(_canonical({k: v for k, v in plan.items() if k != "plan_sha256"}))
    return plan


def fixture(datatype="VARCHAR2"):
    plan = {"schema_version": 1, "scope": SCOPE, "source_binding": "a" * 64,
        "relation_plan_sha256": "b" * 64, "trace_sha256": "c" * 64,
        "sources": [{"name": "sanitized.xml", "sha256": "d" * 64, "bytes": 512}],
        "operations": [], "coverage": [], "code_unit_count": 2,
        "native_generated": False, "write_lifecycle": False,
        "runtime_verified": False, "business_accepted": False}
    def identity(number):
        return "ff1-" + f"{number:024x}"
    for index, event in enumerate(("PRE-INSERT", "PRE-UPDATE"), 1):
        text = "BEGIN :DEST.COPY_VALUE := :ORIGIN.SOURCE_VALUE; END;"
        _, _, decode = parse_assignment_text(text)
        op = {"operation_id": operation_id(plan["source_binding"], identity(index)),
            "source_unit_id": identity(index), "source_unit_sha256": _sha(text.encode()),
            "source_chunk_id": "fup1-" + str(index) * 64,
            "source_owner_id": identity(index + 2), "source_module_id": identity(5),
            "source_event": event, "source_unit_text": text, "relation_id": identity(6),
            "decode_receipt": decode,
            "source_ref": {"block_id": identity(7), "item_id": identity(9),
                "block_name": "ORIGIN", "item_name": "SOURCE_VALUE", "column": "C_SOURCE", "data_type": datatype},
            "target_ref": {"block_id": identity(8), "item_id": identity(10),
                "block_name": "DEST", "item_name": "COPY_VALUE", "column": "C_COPY", "data_type": datatype}}
        plan["operations"].append(op)
        plan["coverage"].append({key: deepcopy(op[key]) for key in ("operation_id", "source_unit_id",
            "source_unit_sha256", "source_chunk_id", "source_owner_id")})
        plan["coverage"][-1].update(source_location={"path": f"/FormModule[1]/Block[2]/Trigger[{index}]",
            "line": 1, "column": 1, "byte_offset": 0},
            status="unsupported", not_yet_converted=True, reason="write_lifecycle_unimplemented",
            encoding_status="generated_unwired", runtime_verified=False, business_accepted=False)
    return seal(plan)


@pytest.mark.parametrize("datatype", ["NUMBER", "VARCHAR2"])
def test_bounded_oracle_package_contains_only_null_preserving_value_copies(datatype):
    plan = fixture(datatype)
    before = deepcopy(plan)
    sql, receipt = render_assignment_code(plan)
    assert plan == before
    assert (sql, receipt) == render_assignment_code(plan)
    assert sql.count("p_copy := p_value;") == 2
    assert f"p_value IN {datatype}, p_copy OUT {datatype}" in sql
    assert re.search(r"CREATE OR REPLACE PACKAGE FOX_ASG_[A-F0-9]{20} AUTHID CURRENT_USER", sql)
    assert not re.search(r"\b(SELECT|INSERT|UPDATE|DELETE|COMMIT|ROLLBACK|TRIGGER|EXECUTE|NVL)\b", sql, re.I)
    assert "ORIGIN" not in sql and "SOURCE_VALUE" not in sql and "PRE-INSERT" not in sql
    assert receipt["converted_code_unit_count"] == 0
    assert receipt["code_member"] == "fox-package/assignment-review.sql"
    assert receipt["sql_sha256"] == _sha(sql.encode())
    for op in receipt["generated_operations"]:
        assert op["encoding_status"] == op["generation_status"] == "generated_unwired"
        assert op["null_policy"] == "preserve"
        assert op["activation_requirements"]
        assert all(op[k] is False for k in ("write_lifecycle", "event_activated", "oracle_compiled",
                                            "runtime_verified", "business_accepted"))
    assert all(row["status"] == "unsupported" for row in receipt["coverage"])


def test_no_operations_produce_comment_only_review_artifact():
    plan = fixture()
    plan.update(operations=[], coverage=[], code_unit_count=0)
    sql, receipt = render_assignment_code(seal(plan))
    assert "CREATE" not in sql
    assert receipt["generated_operations"] == []


@pytest.mark.parametrize("mutation", ["source_text", "source_hash", "source_ref", "target_ref", "event", "type",
    "extra_root", "extra_op", "extra_ref", "claims", "write_lifecycle", "coverage_claim",
    "coverage_hash", "coverage_orphan", "duplicate_event", "duplicate_op", "raw_identifier", "decode"])
def test_even_resealed_inconsistent_or_unsafe_plan_rejected(mutation):
    plan = fixture()
    op = plan["operations"][0]
    if mutation == "source_text": op["source_unit_text"] += " COMMIT;"
    if mutation == "source_hash": op["source_unit_sha256"] = "0" * 64
    if mutation == "source_ref": op["source_ref"]["item_name"] = "OTHER"
    if mutation == "target_ref": op["target_ref"]["item_name"] = "OTHER"
    if mutation == "event": op["source_event"] = "WHEN-BUTTON-PRESSED"
    if mutation == "type": op["target_ref"]["data_type"] = "NUMBER"
    if mutation == "extra_root": plan["sql"] = "select 1 from dual"
    if mutation == "extra_op": op["sql"] = "select 1 from dual"
    if mutation == "extra_ref": op["source_ref"]["sql"] = "select 1 from dual"
    if mutation == "claims": plan["native_generated"] = True
    if mutation == "write_lifecycle": plan["write_lifecycle"] = True
    if mutation == "coverage_claim": plan["coverage"][0]["status"] = "converted"
    if mutation == "coverage_hash": plan["coverage"][0]["source_unit_sha256"] = "0" * 64
    if mutation == "coverage_orphan": plan["coverage"][1]["operation_id"] = "unknown"
    if mutation == "duplicate_event": plan["operations"][1]["source_event"] = "PRE-INSERT"
    if mutation == "duplicate_op": plan["operations"][1] = deepcopy(op)
    if mutation == "raw_identifier": op["source_ref"]["column"] = "X); COMMIT; --"
    if mutation == "decode": op["decode_receipt"]["semantic_sha256"] = "0" * 64
    seal(plan)
    with pytest.raises(ValueError):
        render_assignment_code(plan)


def test_checksum_detects_unsealed_tampering():
    plan = fixture()
    plan["operations"][0]["source_event"] = "PRE-UPDATE"
    with pytest.raises(ValueError, match="PLAN_CHANGED"):
        render_assignment_code(plan)


@pytest.mark.parametrize("text", ["BEGIN :B := :A; END; COMMIT;", ":B := :A + 1;",
    "BEGIN :B := :A; NULL; END;", "BEGIN :B := :A; END other;", ":B := NULL;",
    ":B := :A; /* nested /* bad */", "-- all commented :B := :A;", ":B := :A; &#65;",
    ":B := ':A';", ":B := :A; '/*';"])
def test_parser_rejects_incomplete_or_extended_source(text):
    with pytest.raises(ValueError):
        parse_assignment_text(text)


def test_comment_control_entity_receipt_and_entire_statement_are_bound():
    target, source, receipt = parse_assignment_text("-- escaped newline &#10; BEGIN :CHILD.B := :PARENT.A; END;&#13;")
    assert target == ["CHILD", "B"] and source == ["PARENT", "A"]
    assert [row["codepoint"] for row in receipt["substitutions"]] == [10, 13]


@pytest.mark.parametrize("text", ["x" * 16_385, "", None])
def test_source_capacity_is_bounded(text):
    with pytest.raises(ValueError):
        parse_assignment_text(text)
