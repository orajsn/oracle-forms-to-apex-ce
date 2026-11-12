"""Synthetic runner protocol checks only; no Oracle calls or speedup claim."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import pytest

from forms2apex import blueprint_profiles, native_blueprint, native_target
from forms2apex import prototype_gateway as gateway
from test_native_blueprint import field, source_id, spec
from test_native_blueprint_required import spec as required_spec


def _spec(count=7, *, required=False, fields=3):
    value = (required_spec if required else spec)(fields)
    template = value["blocks"][0]
    value["blocks"] = []
    for index in range(1, count + 1):
        block = deepcopy(template)
        block.update(source_block_id=source_id(index), name=f"BLOCK_{index}", sequence=index)
        block["table_name"] = native_blueprint._table(
            value["project_id"], value["source_binding"], block["source_block_id"])
        block["fields"] = [field(1000 * index + offset,
            kind=("VARCHAR2", "NUMBER", "DATE")[offset % 3], nullable=offset % 2 == 0)
            for offset in range(fields)]
        if required:
            for item in block["fields"]:
                item["value_required"] = False
        value["blocks"].append(block)
    return value


def _prefix(block):
    return f"FOX_SCHEMA_METADATA={block['source_block_id']}|{block['table_name']}|"


def _native_rows(renderer, block):
    rows = ["FOX_NATIVE_BEGIN=1", "FOX_NATIVE_TABLE_COUNT=1"]
    for column in renderer._columns(block):
        rows.append("FOX_NATIVE_COLUMN=" + "|".join([
            column["name"], column["data_type"], "Y" if column["nullable"] else "N",
            str(column.get("length", 0)), "YES" if column["identity"] else "NO"]))
    return [*rows, "FOX_NATIVE_PK_COUNT=1", "FOX_NATIVE_PK=FOX_ROW_ID|1|ENABLED|VALIDATED",
            "FOX_NATIVE_ENABLED_TRIGGER_COUNT=0", "FOX_NATIVE_OK=1"]


def _rows(value):
    renderer = blueprint_profiles.select(value)
    return [_prefix(block) + row for block in value["blocks"]
            if block["classification"] == "database" for row in _native_rows(renderer, block)]


def _sqlcl_output(rows):
    # SQLcl default/pagesize0 shape: blank lines separate SELECT results,
    # padded rows, and CRLF on Windows. No headings/feedback with _run_script.
    output, previous_column_prefix = "\r\n \t\r\n", None
    for row in rows:
        column_prefix = row.split("FOX_NATIVE_COLUMN=", 1)[0] if "FOX_NATIVE_COLUMN=" in row else None
        # Multiple rows of ONE column SELECT have no intervening blank line.
        output += ("\r\n" if column_prefix is not None and column_prefix == previous_column_prefix
                   else "\r\n\r\n") + "  " + row + "  "
        previous_column_prefix = column_prefix
    return output + "\r\n\r\n"


def _adapter(value, *, rows=None, output=None, returncode=0, stderr=""):
    calls = []
    settings = SimpleNamespace(sqlcl_path=Path("sql"), sqlcl_connection_name="F2A_APEX",
        apex_workspace="FORMS2APEX_POC", apex_parsing_schema="FORMS2APEX_POC")
    def run(sql, args, commands, root, timeout):
        calls.append((sql, args, commands, root, timeout))
        return SimpleNamespace(returncode=returncode, stderr=stderr,
            stdout=output if output is not None else _sqlcl_output(_rows(value) if rows is None else rows))
    return gateway.PrototypeGateway(settings, runner=run), calls


@pytest.mark.parametrize("required", [False, True])
def test_seven_blocks_use_one_guarded_call_and_identical_per_table_metadata(required, monkeypatch):
    value = _spec(required=required)
    original = deepcopy(value)
    adapter, calls = _adapter(value)
    parsed = []
    parse = native_target._parse_output
    def observe_parse(output):
        result = parse(output)
        parsed.append(result)
        return result
    monkeypatch.setattr(native_target, "_parse_output", observe_parse)
    assert adapter._observe(Path("."), value) is None
    assert value == original
    assert len(calls) == 1  # Former loop made seven separate SQLcl calls.
    sql, args, commands, root, timeout = calls[0]
    assert sql == Path("sql") and root == Path(".") and timeout == 120
    assert args == ["-S", "-L", "-name", "F2A_APEX"]
    assert commands.count(gateway.sqlcl._target_guard("FORMS2APEX_POC")) == 1
    assert commands[:6] == ["set sqlformat default", "set pagesize 0", "set linesize 32767",
                           "set trimout on", "set define off", "whenever oserror exit failure rollback"]
    renderer = blueprint_profiles.select(value)
    assert parsed == [parse("\n".join(_native_rows(renderer, block))) for block in value["blocks"]]
    assert len(parsed) == 7
    for block in value["blocks"]:
        queries = [command for command in commands if command.startswith("select '")
                   and _prefix(block) in command]
        assert len(queries) == 7
        assert queries[0] == f"select '{_prefix(block)}FOX_NATIVE_BEGIN=1' from dual;"
        assert queries[-1] == f"select '{_prefix(block)}FOX_NATIVE_OK=1' from dual;"
        assert all(f"table_name='{block['table_name']}'" in query for query in queries[1:-1])
        assert "order by column_id" in queries[2]
        assert "order by cc.position" in queries[4]
        assert "c.status||'|'||c.validated" in queries[4]
        assert "status='ENABLED'" in queries[5]
    # No cache: the next observation executes a new guarded session.
    adapter._observe(Path("."), value)
    assert len(calls) == 2


@pytest.mark.parametrize("count,fields", [(1, 0), (1, 255), (50, 0)])
def test_single_block_and_contract_bounds(count, fields):
    value = _spec(count, fields=fields)
    adapter, calls = _adapter(value)
    adapter._observe(Path("."), value)
    assert len(calls) == 1


def test_control_blocks_require_no_sql():
    value = spec()
    value["blocks"] = [value["blocks"][-1]]
    adapter, calls = _adapter(value)
    adapter._observe(Path("."), value)
    assert calls == []


@pytest.mark.parametrize("bad", ["ff1-' from dual;--", "ff1-" + "a" * 23 + "|",
                                 "ff1-" + "a" * 23 + "\n", "ff1-" + "A" * 24])
def test_unsafe_block_id_rejected_before_sql(bad):
    value = _spec()
    value["blocks"][0]["source_block_id"] = bad
    adapter, calls = _adapter(value)
    with pytest.raises(ValueError, match="BLOCK_ID_INVALID"):
        adapter._observe(Path("."), value)
    assert not calls


@pytest.mark.parametrize("bad", ["UNREVIEWED_TABLE", "T' OR 1=1--", None])
def test_unbound_table_rejected_before_sql(bad):
    value = _spec()
    value["blocks"][0]["table_name"] = bad
    adapter, calls = _adapter(value)
    with pytest.raises(ValueError, match="TABLE_BINDING_INVALID"):
        adapter._observe(Path("."), value)
    assert not calls


@pytest.mark.parametrize("setting,bad", [("sqlcl_connection_name", "OTHER"),
    ("apex_workspace", "OTHER"), ("apex_parsing_schema", "OTHER")])
def test_exact_saved_target_still_required(setting, bad):
    value = _spec()
    adapter, calls = _adapter(value)
    setattr(adapter.settings, setting, bad)
    with pytest.raises(RuntimeError, match="EXACT_SAVED_JSN_TARGET_REQUIRED"):
        adapter._observe(Path("."), value)
    assert not calls


@pytest.mark.parametrize("mutation", [
    "missing-table", "duplicate-table", "reordered-tables", "wrong-table", "wrong-block",
    "cross-bound-row", "missing-row", "duplicate-row", "reordered-columns", "reordered-scalars",
    "missing-begin", "missing-ok", "truncated", "extra-output", "unknown-marker", "unbound-legacy",
    "oracle-error", "sqlplus-error", "sqlcl-error", "prefixed-error", "extra-native-ok",
])
def test_wrong_incomplete_crossbound_and_error_protocols_fail(mutation):
    value = _spec()
    rows = _rows(value)
    width = len(_native_rows(blueprint_profiles.select(value), value["blocks"][0]))
    if mutation == "missing-table":
        del rows[:width]
    elif mutation == "duplicate-table":
        rows[width:2 * width] = rows[:width]
    elif mutation == "reordered-tables":
        rows[:2 * width] = rows[width:2 * width] + rows[:width]
    elif mutation == "wrong-table":
        rows[0] = rows[0].replace(value["blocks"][0]["table_name"], "FOX_NATIVE_" + "0" * 19)
    elif mutation == "wrong-block":
        rows[0] = rows[0].replace(source_id(1), source_id(2))
    elif mutation == "cross-bound-row":
        rows[2] = rows[width + 2]
    elif mutation == "missing-row":
        del rows[2]
    elif mutation == "duplicate-row":
        rows.insert(2, rows[2])
    elif mutation == "reordered-columns":
        rows[2], rows[3] = rows[3], rows[2]
    elif mutation == "reordered-scalars":
        rows[1], rows[-2] = rows[-2], rows[1]
    elif mutation == "missing-begin":
        del rows[0]
    elif mutation == "missing-ok":
        del rows[-1]
    elif mutation == "truncated":
        rows[-1] = rows[-1][:-1]
    elif mutation == "unknown-marker":
        rows[1] = rows[1].replace("TABLE_COUNT", "UNEXPECTED")
    elif mutation == "unbound-legacy":
        rows = [row.split("|", 2)[2] for row in rows]
    else:
        rows.insert(width, {"extra-output": "unexpected output", "oracle-error": "ORA-00942: missing table",
            "sqlplus-error": "SP2-0734: unknown command", "sqlcl-error": "Error starting at line : 1",
            "prefixed-error": _prefix(value["blocks"][0]) + "ORA-00942: missing table",
            "extra-native-ok": "FOX_NATIVE_OK=1"}[mutation])
    adapter, calls = _adapter(value, rows=rows)
    with pytest.raises(RuntimeError):
        adapter._observe(Path("."), value)
    assert len(calls) == 1


@pytest.mark.parametrize("old,new", [
    ("TABLE_COUNT=1", "TABLE_COUNT=0"), ("TABLE_COUNT=1", "TABLE_COUNT=2"),
    ("PK_COUNT=1", "PK_COUNT=0"), ("PK_COUNT=1", "PK_COUNT=2"),
    ("ENABLED_TRIGGER_COUNT=0", "ENABLED_TRIGGER_COUNT=1"),
    ("FOX_ROW_ID|NUMBER|N|0|YES", "FOX_ROW_ID|NUMBER|N|0|NO"),
    ("FOX_ROW_ID|NUMBER|N|0|YES", "FOX_ROW_ID|NUMBER|Y|0|YES"),
    ("|VARCHAR2|Y|120|NO", "|VARCHAR2|Y|121|NO"),
    ("|VARCHAR2|Y|120|NO", "|NUMBER|Y|120|NO"),
    ("PK=FOX_ROW_ID|1|ENABLED|VALIDATED", "PK=FOX_ROW_ID|1|DISABLED|VALIDATED"),
    ("PK=FOX_ROW_ID|1|ENABLED|VALIDATED", "PK=FOX_ROW_ID|1|ENABLED|NOT VALIDATED"),
    ("PK=FOX_ROW_ID|1|ENABLED|VALIDATED", "PK=FOX_ROW_ID|2|ENABLED|VALIDATED"),
    ("BEGIN=1", "BEGIN=0"), ("OK=1", "OK=0"),
])
def test_every_existing_per_table_metadata_gate_remains(old, new):
    value = _spec()
    output = _sqlcl_output(_rows(value))
    assert old in output
    adapter, calls = _adapter(value, output=output.replace(old, new, 1))
    with pytest.raises(RuntimeError):
        adapter._observe(Path("."), value)
    assert len(calls) == 1


@pytest.mark.parametrize("output", [None, b"bytes", 42, "", "x" * 700_001],
                         ids=["none", "bytes", "integer", "empty", "oversized"])
def test_invalid_or_oversized_output_is_not_accepted(output):
    value = _spec()
    adapter, calls = _adapter(value)
    adapter.runner = lambda *args, **kwargs: SimpleNamespace(returncode=0, stderr="", stdout=output)
    with pytest.raises(RuntimeError, match="METADATA_PROTOCOL_INVALID"):
        adapter._observe(Path("."), value)


@pytest.mark.parametrize("returncode,stderr", [(1, ""), (0, "ORA-00942"), (0, None), (0, b"")])
def test_sqlcl_failure_gate_is_unchanged(returncode, stderr):
    value = _spec()
    adapter, calls = _adapter(value, returncode=returncode, stderr=stderr)
    with pytest.raises(RuntimeError, match="SCHEMA_SQLCL_FAILED_NO_REPLAY"):
        adapter._observe(Path("."), value)
    assert len(calls) == 1


def test_sqlcl_timeout_propagates_without_replay():
    value = _spec()
    adapter, calls = _adapter(value)
    def timeout(*args, **kwargs):
        calls.append("timeout")
        raise TimeoutError("controlled runner timeout")
    adapter.runner = timeout
    with pytest.raises(TimeoutError):
        adapter._observe(Path("."), value)
    assert calls == ["timeout"]


def test_whitespace_only_stderr_is_still_accepted():
    value = _spec()
    adapter, calls = _adapter(value, stderr="\r\n \t")
    adapter._observe(Path("."), value)
    assert len(calls) == 1
