"""Synthetic modeled SQL protocol; tests never open an Oracle connection."""
from copy import deepcopy
import hashlib
import re

import pytest

from forms2apex import count_guard_fixture as fixture
from test_count_guard_integration import request_and_import


def request():
    return request_and_import()[0]


def receipt(value):
    plan = fixture.plan(value)
    return {"plan": plan, "plan_sha256": fixture.digest(plan), "request_sha256": fixture.digest(value),
            "fixture_sql_sha256": hashlib.sha256(fixture.insert_sql(value).encode()).hexdigest(),
            "prepared": True, "rows": [{"case": row["case"], "primary_key": str(index + 1)}
                                      for index, row in enumerate(plan["cases"])]}


def observed():
    return "\n".join(["FOX_CG_CASE=" + name + "|1" for name, _ in fixture.CASES] + ["FOX_CG_TOTAL=4"])


def test_only_four_source_bound_labelled_synthetic_rows_and_insert_only():
    value = request()
    original = deepcopy(value)
    planned = fixture.plan(value)
    assert fixture.plan(value) == planned
    assert [row["value"] for row in planned["cases"]] == [None, 0, 2, -1]
    assert [row["expected_blocked"] for row in planned["cases"]] == [True, True, False, False]
    assert all(re.fullmatch(r"FCG[A-F0-9]{12}[0-3]", row["key"]) for row in planned["cases"])
    sql = fixture.insert_sql(value)
    assert sql.lower().count("insert into ") == 4
    assert not re.search(r"\b(update|delete|merge|truncate|drop|alter|execute immediate)\b", sql, re.I)
    assert sql.index("if n<>0") < sql.index("insert into")
    assert sql.count("sql%rowcount<>1") == 4
    assert "exception when others then rollback; raise;" in sql
    assert "DEMO_DETAIL" not in sql and "DETAIL_QUANTITY" not in sql
    assert value == original


def test_distinct_job_generates_distinct_markers():
    a = request()
    b = {**a, "job_id": "different-count-check"}
    assert {row["key"] for row in fixture.plan(a)["cases"]}.isdisjoint(
        row["key"] for row in fixture.plan(b)["cases"])


def test_short_grouping_column_rejects_instead_of_truncating_markers():
    value = request()
    ids = value["rendering_spec"]["count_guard"]["source_objects"]
    for block in value["rendering_spec"]["blocks"]:
        for field in block["fields"]:
            if field["source_item_id"] == ids["key_item"]:
                field["length"] = 8
    with pytest.raises(RuntimeError, match="KEY_TOO_SHORT"):
        fixture.plan(value)


@pytest.mark.parametrize("key", ["project_id", "source_binding"])
def test_request_binding_cannot_name_another_project(key):
    value = request()
    value[key] = "different"
    with pytest.raises(RuntimeError, match="SOURCE_BINDING_INVALID"):
        fixture.plan(value)


def test_receipt_requires_exact_plan_sql_and_independent_row_ids():
    value = request()
    evidence = receipt(value)
    assert fixture.validate_receipt(value, evidence, prepare_request_sha256=fixture.digest(value)) == evidence["plan"]
    for key in ("plan_sha256", "fixture_sql_sha256", "request_sha256"):
        changed = {**evidence, key: "f" * 64}
        with pytest.raises(RuntimeError):
            fixture.validate_receipt(value, changed, prepare_request_sha256=fixture.digest(value))
    evidence["rows"][1]["primary_key"] = evidence["rows"][0]["primary_key"]
    with pytest.raises(RuntimeError, match="DUPLICATE_ROW_IDENTITY"):
        fixture.validate_receipt(value, evidence)


def test_readback_is_readonly_and_checks_all_fixture_rows():
    value = request()
    commands = []
    def run(sql):
        commands.extend(sql)
        return observed()
    assert fixture.observe(value, receipt(value), execute_sql=run)["observed"] is True
    assert len(commands) == 5 and all(sql.startswith("select ") for sql in commands)
    assert all("FOX_ROW_ID=" in sql for sql in commands[:4])
    with pytest.raises(RuntimeError, match="PERSISTED_ROWS_CHANGED"):
        fixture.observe(value, receipt(value), execute_sql=lambda _: observed().replace("FOX_CG_TOTAL=4", "FOX_CG_TOTAL=5"))


def test_prepare_records_intent_before_only_write_and_never_replays(tmp_path):
    value = request()
    expected = receipt(value)
    calls = []
    def run(commands):
        calls.append(commands)
        if len(calls) == 1:
            return "FOX_CG_ABSENT=0"
        if len(calls) == 2:
            assert (tmp_path / "count-guard-fixture-intent.json").is_file()
            assert not (tmp_path / "count-guard-fixture.json").exists()
            return "\n".join(["FOX_CG_FIXTURE=" + expected["plan_sha256"]]
                             + ["FOX_CG_ROW=" + row["case"] + "|" + row["primary_key"] for row in expected["rows"]])
        return observed()
    checks = []
    result = fixture.prepare(tmp_path, value, execute_sql=run, fresh_check=lambda: checks.append(True))
    assert result == expected and len(calls) == 3 and len(checks) == 3
    with pytest.raises(RuntimeError, match="ALREADY_ATTEMPTED_NO_REPLAY"):
        fixture.prepare(tmp_path, value, execute_sql=run, fresh_check=lambda: checks.append(True))
    assert len(calls) == 3


def test_existing_markers_never_adopted_or_written(tmp_path):
    calls = []
    with pytest.raises(RuntimeError, match="EXISTING_ROWS_PRESERVED"):
        fixture.prepare(tmp_path, request(), execute_sql=lambda sql: calls.append(sql) or "FOX_CG_ABSENT=4", fresh_check=lambda: None)
    assert len(calls) == 1 and not list(tmp_path.iterdir())


def test_unknown_write_outcome_preserves_intent_and_no_success_receipt(tmp_path):
    calls = []
    with pytest.raises(RuntimeError, match="OUTCOME_UNCONFIRMED_NO_REPLAY"):
        fixture.prepare(tmp_path, request(), execute_sql=lambda sql: calls.append(sql) or (
            "FOX_CG_ABSENT=0" if len(calls) == 1 else ""), fresh_check=lambda: None)
    assert len(calls) == 2
    assert (tmp_path / "count-guard-fixture-intent.json").exists()
    assert not (tmp_path / "count-guard-fixture.json").exists()
