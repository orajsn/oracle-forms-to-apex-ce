"""Mock-only target verification tests: never connect to a database."""

from copy import deepcopy
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from forms2apex.native_target import verify_native_schema


GOOD_OUTPUT = """FOX_NATIVE_BEGIN=1
FOX_NATIVE_TABLE_COUNT=1
FOX_NATIVE_COLUMN=ORDER_ID|NUMBER|N|0|YES
FOX_NATIVE_COLUMN=DESCRIPTION|VARCHAR2|N|100|NO
FOX_NATIVE_COLUMN=ORDER_DATE|DATE|Y|0|NO
FOX_NATIVE_PK_COUNT=1
FOX_NATIVE_PK=ORDER_ID|1|ENABLED|VALIDATED
FOX_NATIVE_ENABLED_TRIGGER_COUNT=0
FOX_NATIVE_OK=1
"""


@pytest.fixture
def spec():
    return {"profile_id": "native-table-form-v1", "data_mode": "synthetic_test_only",
            "table_name": "FOX_NATIVE_ORDERS", "columns": [
                {"name": "ORDER_ID", "data_type": "NUMBER", "nullable": False,
                 "label": "Order ID", "primary_key": True, "identity": True},
                {"name": "DESCRIPTION", "data_type": "VARCHAR2", "nullable": False,
                 "label": "Description", "length": 100},
                {"name": "ORDER_DATE", "data_type": "DATE", "nullable": True, "label": "Order date"},
            ]}


@pytest.fixture
def settings():
    return SimpleNamespace(sqlcl_path=Path("/not-a-real-sqlcl"),
                           sqlcl_connection_name="F2A_APEX", apex_workspace="FORMS2APEX_POC")


@pytest.fixture
def runner(monkeypatch):
    state = {"output": GOOD_OUTPUT, "stderr": "", "code": 0, "calls": []}

    def run(*args, **kwargs):
        state["calls"].append((args, kwargs))
        return subprocess.CompletedProcess([], state["code"], state["output"], state["stderr"])

    monkeypatch.setattr("forms2apex.native_target._run_script", run)
    return state


def test_verified_schema_receipt_is_safe_and_read_only(spec, settings, runner, tmp_path):
    original = deepcopy(spec)
    result = verify_native_schema(settings, spec, tmp_path)
    assert result["passed"] is True
    assert result["table_name"] == "FOX_NATIVE_ORDERS"
    assert result["workspace"] == "FORMS2APEX_POC"
    assert result["primary_key"] == {"columns": ["ORDER_ID"], "status": "ENABLED", "validated": "VALIDATED"}
    assert result["columns"][1]["char_length"] == 100
    assert result["enabled_trigger_count"] == 0
    assert result["business_behavior_verified"] is False
    assert len(result["spec_sha256"]) == 64
    assert result["verified_at_utc"].endswith("+00:00")
    assert spec == original
    assert list(tmp_path.iterdir()) == []
    assert len(runner["calls"]) == 1
    args, kwargs = runner["calls"][0]
    assert args[0] == settings.sqlcl_path
    assert args[1] == ["-S", "-L", "-name", "F2A_APEX"]
    assert args[3] == tmp_path
    assert kwargs["timeout"] == 120
    commands = args[2]
    joined = "\n".join(commands)
    assert "ASZ8EQWFM8UNCA2_JSNF2APEX" in joined
    assert "or user <> 'FORMS2APEX_POC'" in joined
    assert "target identity mismatch" in joined
    assert joined.index("target identity mismatch") < joined.index("from user_tables")
    for dictionary in ("user_tables", "user_tab_columns", "user_constraints", "user_cons_columns", "user_triggers"):
        assert dictionary in joined
    for command in commands:
        assert not command.lower().startswith(("create ", "alter ", "drop ", "insert ", "update ", "delete ", "apex import"))
    assert "from FOX_NATIVE_ORDERS" not in joined


@pytest.mark.parametrize("old,new", [
    ("TABLE_COUNT=1", "TABLE_COUNT=0"), ("TABLE_COUNT=1", "TABLE_COUNT=2"),
    ("PK_COUNT=1", "PK_COUNT=0"), ("PK_COUNT=1", "PK_COUNT=2"),
    ("ENABLED_TRIGGER_COUNT=0", "ENABLED_TRIGGER_COUNT=1"),
    ("ORDER_ID|NUMBER|N|0|YES", "ORDER_ID|NUMBER|Y|0|YES"),
    ("ORDER_ID|NUMBER|N|0|YES", "ORDER_ID|NUMBER|N|0|NO"),
    ("DESCRIPTION|VARCHAR2|N|100|NO", "DESCRIPTION|VARCHAR2|N|99|NO"),
    ("DESCRIPTION|VARCHAR2|N|100|NO", "DESCRIPTION|VARCHAR2|Y|100|NO"),
    ("DESCRIPTION|VARCHAR2|N|100|NO", "DESCRIPTION|NUMBER|N|0|NO"),
    ("ORDER_DATE|DATE|Y|0|NO", "OTHER_DATE|DATE|Y|0|NO"),
    ("ORDER_DATE|DATE|Y|0|NO", "ORDER_DATE|DATE|Y|1|NO"),
    ("PK=ORDER_ID|1|ENABLED|VALIDATED", "PK=DESCRIPTION|1|ENABLED|VALIDATED"),
    ("PK=ORDER_ID|1|ENABLED|VALIDATED", "PK=ORDER_ID|1|DISABLED|VALIDATED"),
    ("PK=ORDER_ID|1|ENABLED|VALIDATED", "PK=ORDER_ID|1|ENABLED|NOT VALIDATED"),
    ("PK=ORDER_ID|1|ENABLED|VALIDATED", "PK=ORDER_ID|2|ENABLED|VALIDATED"),
])
def test_any_schema_mismatch_blocks_import(spec, settings, runner, tmp_path, old, new):
    runner["output"] = GOOD_OUTPUT.replace(old, new)
    with pytest.raises(RuntimeError):
        verify_native_schema(settings, spec, tmp_path)


@pytest.mark.parametrize("line", GOOD_OUTPUT.strip().splitlines())
def test_every_expected_row_is_required(spec, settings, runner, tmp_path, line):
    runner["output"] = GOOD_OUTPUT.replace(line + "\n", "")
    with pytest.raises(RuntimeError):
        verify_native_schema(settings, spec, tmp_path)


@pytest.mark.parametrize("line", GOOD_OUTPUT.strip().splitlines())
def test_duplicate_protocol_rows_are_rejected(spec, settings, runner, tmp_path, line):
    runner["output"] = GOOD_OUTPUT.replace(line + "\n", line + "\n" + line + "\n")
    with pytest.raises(RuntimeError):
        verify_native_schema(settings, spec, tmp_path)


@pytest.mark.parametrize("extra", [
    "FOX_NATIVE_COLUMN=OTHER|NUMBER|Y|0|NO", "FOX_NATIVE_PK=OTHER|1|ENABLED|VALIDATED",
    "FOX_NATIVE_UNKNOWN=0", "ORA-00942: table or view does not exist",
    "SP2-0734: unknown command", "SQLcl incomplete result", "FOX_NATIVE_COLUMN=malformed",
    "FOX_NATIVE_COLUMN=UNKNOWN|CLOB|Y|0|NO", "FOX_NATIVE_COLUMN=UNKNOWN|NUMBER|MAYBE|0|NO",
    "FOX_NATIVE_COLUMN=UNKNOWN|NUMBER|Y|0|UNKNOWN", "FOX_NATIVE_COLUMN=UNKNOWN|NUMBER|Y|-1|NO",
])
def test_extra_or_unknown_output_is_rejected(spec, settings, runner, tmp_path, extra):
    runner["output"] = GOOD_OUTPUT.replace("FOX_NATIVE_OK=1", extra + "\nFOX_NATIVE_OK=1")
    with pytest.raises(RuntimeError):
        verify_native_schema(settings, spec, tmp_path)


@pytest.mark.parametrize("output", ["", "FOX_NATIVE_OK=1", None, "x" * 100_001,
                                       "FOX_NATIVE_BEGIN=1\nFOX_NATIVE_TABLE_COUNT=1.0\nFOX_NATIVE_OK=1"],
                         ids=["empty", "missing_begin", "nonstring", "oversized", "bad_count"])
def test_incomplete_or_malformed_output_is_rejected(spec, settings, runner, tmp_path, output):
    runner["output"] = output
    with pytest.raises(RuntimeError):
        verify_native_schema(settings, spec, tmp_path)


def test_column_order_must_match(spec, settings, runner, tmp_path):
    runner["output"] = GOOD_OUTPUT.replace("DESCRIPTION|VARCHAR2|N|100|NO", "TEMP|DATE|Y|0|NO").replace(
        "ORDER_DATE|DATE|Y|0|NO", "DESCRIPTION|VARCHAR2|N|100|NO").replace("TEMP|DATE|Y|0|NO", "ORDER_DATE|DATE|Y|0|NO")
    with pytest.raises(RuntimeError, match="columns do not exactly match"):
        verify_native_schema(settings, spec, tmp_path)


@pytest.mark.parametrize("code,stderr", [(1, ""), (-1, ""), (0, "ORA-20081: target identity mismatch"), (0, None)])
def test_execution_failure_never_uses_plausible_success_output(spec, settings, runner, tmp_path, code, stderr):
    runner.update(code=code, stderr=stderr)
    with pytest.raises(RuntimeError, match="execution failed"):
        verify_native_schema(settings, spec, tmp_path)


@pytest.mark.parametrize("workspace", ["ADMIN", "OTHER_WORKSPACE", "FORMS2APEX_POC';--", None])
def test_other_or_unsafe_schema_never_connects(spec, settings, runner, tmp_path, workspace):
    settings.apex_workspace = workspace
    with pytest.raises(ValueError, match="restricted"):
        verify_native_schema(settings, spec, tmp_path)
    assert runner["calls"] == []


@pytest.mark.parametrize("connection", ["", None, "USER/PASSWORD@DB", "F2A_APEX\nconnect OTHER", "A" * 81])
def test_only_safe_named_connections_are_used(spec, settings, runner, tmp_path, connection):
    settings.sqlcl_connection_name = connection
    with pytest.raises(ValueError, match="saved SQLcl connection"):
        verify_native_schema(settings, spec, tmp_path)
    assert runner["calls"] == []


def test_invalid_contract_never_connects(spec, settings, runner, tmp_path):
    spec["table_name"] = "FOX_NATIVE_ORDERS'; DROP TABLE X;--"
    with pytest.raises(ValueError):
        verify_native_schema(settings, spec, tmp_path)
    assert runner["calls"] == []


def test_missing_job_directory_never_connects(spec, settings, runner, tmp_path):
    with pytest.raises(ValueError, match="job directory"):
        verify_native_schema(settings, spec, tmp_path / "not-created")
    assert runner["calls"] == []


def test_spec_hash_binds_reviewed_labels_as_well_as_schema(spec, settings, runner, tmp_path):
    first = verify_native_schema(settings, spec, tmp_path)
    spec["columns"][1]["label"] = "Order description"
    second = verify_native_schema(settings, spec, tmp_path)
    assert first["spec_sha256"] != second["spec_sha256"]


def test_sql_errors_do_not_leak_raw_output(spec, settings, runner, tmp_path):
    runner["output"] = "sensitive unexpected text ORA-20081"
    with pytest.raises(RuntimeError) as error:
        verify_native_schema(settings, spec, tmp_path)
    assert "sensitive" not in str(error.value)
