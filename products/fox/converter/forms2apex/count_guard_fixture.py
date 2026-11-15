"""Four labelled synthetic rows for one check-only prototype's runtime proof.

No connection is opened here. The gateway supplies its existing exact-JSN SQL
executor and fresh authorization callback. No update/delete, replacement or
automatic retry occurs. Existing profiles never invoke this module.
"""
from __future__ import annotations

import hashlib
import re

from . import native_blueprint_count_guard as renderer


CASES = (("null", None), ("zero", 0), ("positive", 2), ("negative", -1))
canonical = renderer.legacy._canonical


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _need(condition, code):
    if not condition:
        raise RuntimeError("COUNT_GUARD_FIXTURE_" + code)


def plan(request):
    spec = renderer.validate_prototype_spec(request["rendering_spec"])
    _need(request.get("project_id") == spec["project_id"]
          and request.get("source_binding") == spec["source_binding"], "SOURCE_BINDING_INVALID")
    job = request["job_id"]
    _need(type(job) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{2,47}", job), "JOB_INVALID")
    target = renderer._targets(spec)
    fields = {field["source_item_id"]: field for block in spec["blocks"] for field in block["fields"]}
    key_field = fields[spec["count_guard"]["source_objects"]["key_item"]]
    seed = digest([job, spec["project_id"], spec["source_binding"], spec["count_guard"]])
    if target["key_type"] == "VARCHAR2":
        _need(min(target["key_length"], key_field["length"]) >= 16, "LABELLED_KEY_TOO_SHORT")
        keys = ["FCG" + seed[:12].upper() + str(index) for index in range(4)]
    else:
        # Exact, bounded integer strings survive Oracle NUMBER and browser input.
        base = 100_000_000_000_000 + int(seed[:11], 16) * 10
        keys = [str(base + index) for index in range(4)]
    return {"schema_version": 1, "scope": "fox-count-guard-synthetic-fixture-v1",
        "job_id": job, "project_id": spec["project_id"], "source_binding": spec["source_binding"],
        "rendering_spec_sha256": digest(spec), "source_rule_sha256": spec["count_guard"]["source_rule_sha256"],
        "table_name": target["table_name"], "source_block_id": target["detail_block"]["source_block_id"],
        "key_column": target["key_column"], "value_column": target["value_column"],
        "key_type": target["key_type"], "page_id": target["page_id"], "key_item": target["key_item"],
        "request": renderer.REQUEST,
        "other_columns": [field["name"] for field in target["detail_block"]["fields"]
                          if field["name"] not in (target["key_column"], target["value_column"])],
        "cases": [{"case": name, "key": key, "value": value, "expected_blocked": value in (None, 0)}
                  for (name, value), key in zip(CASES, keys, strict=True)],
        "data_mode": "synthetic_qa_only", "rows_retained": True}


def _key(value, kind):
    if kind == "VARCHAR2":
        _need(type(value) is str and re.fullmatch(r"FCG[A-F0-9]{12}[0-3]", value), "KEY_INVALID")
        return "'" + value + "'"
    _need(kind == "NUMBER" and type(value) is str and re.fullmatch(r"[1-9][0-9]{14,15}", value), "KEY_INVALID")
    return value


def _predicate(recipe):
    return recipe["key_column"] + " in (" + ",".join(_key(row["key"], recipe["key_type"])
                                                   for row in recipe["cases"]) + ")"


def insert_sql(request):
    """Fixed four-row insert; identifiers/values are derived, never caller SQL."""
    recipe = plan(request)
    statements = []
    for index, row in enumerate(recipe["cases"]):
        value = "null" if row["value"] is None else str(row["value"])
        statements.extend([
            f"insert into {recipe['table_name']} ({recipe['key_column']}, {recipe['value_column']}) "
            f"values ({_key(row['key'], recipe['key_type'])}, {value}) returning FOX_ROW_ID into l_id_{index + 1};",
            "if sql%rowcount<>1 then raise_application_error(-20086,'FOX fixture row count differs'); end if;",
        ])
    output = [f"dbms_output.put_line('FOX_CG_ROW={row['case']}|'||to_char(l_id_{index + 1},'TM9'));"
              for index, row in enumerate(recipe["cases"])]
    return "\n".join([
        "declare", "  n number;", *[f"  l_id_{index + 1} number;" for index in range(4)], "begin",
        f"  select count(*) into n from {recipe['table_name']} where {_predicate(recipe)};",
        "  if n<>0 then raise_application_error(-20085,'FOX existing fixture preserved'); end if;",
        *statements, "commit;", f"dbms_output.put_line('FOX_CG_FIXTURE={digest(recipe)}');", *output,
        "exception when others then rollback; raise;", "end;", "/",
    ])


def validate_receipt(request, receipt, *, prepare_request_sha256=None):
    recipe = plan(request)
    _need(type(receipt) is dict and set(receipt) == {"plan", "plan_sha256", "request_sha256",
          "fixture_sql_sha256", "prepared", "rows"}, "RECEIPT_FIELDS_INVALID")
    _need(canonical(receipt["plan"]) == canonical(recipe) and receipt["plan_sha256"] == digest(recipe)
          and receipt["fixture_sql_sha256"] == hashlib.sha256(insert_sql(request).encode()).hexdigest()
          and receipt["prepared"] is True, "RECEIPT_BINDING_INVALID")
    _need(type(receipt["request_sha256"]) is str
          and re.fullmatch(r"[a-f0-9]{64}", receipt["request_sha256"])
          and (prepare_request_sha256 is None or receipt["request_sha256"] == prepare_request_sha256),
          "PREPARE_REQUEST_BINDING_INVALID")
    rows = receipt["rows"]
    _need(type(rows) is list and len(rows) == 4, "ROW_LEDGER_INVALID")
    for expected, actual in zip(recipe["cases"], rows, strict=True):
        _need(type(actual) is dict and set(actual) == {"case", "primary_key"}
              and actual["case"] == expected["case"] and type(actual["primary_key"]) is str
              and re.fullmatch(r"[1-9][0-9]{0,37}", actual["primary_key"]), "ROW_LEDGER_INVALID")
    _need(len({row["primary_key"] for row in rows}) == 4, "DUPLICATE_ROW_IDENTITY")
    return recipe


def observe(request, receipt, *, execute_sql):
    """Read all fixture values and otherwise-null columns without changing rows."""
    recipe = validate_receipt(request, receipt)
    commands = []
    for case, row in zip(recipe["cases"], receipt["rows"], strict=True):
        predicate = (f"FOX_ROW_ID={row['primary_key']} and {recipe['key_column']}="
                     f"{_key(case['key'], recipe['key_type'])} and {recipe['value_column']} "
                     + ("is null" if case["value"] is None else "=" + str(case["value"])))
        predicate += "".join(" and " + col + " is null" for col in recipe["other_columns"])
        commands.append(f"select 'FOX_CG_CASE={case['case']}|'||to_char(count(*),'TM9') "
                        f"from {recipe['table_name']} where {predicate};")
    commands.append(f"select 'FOX_CG_TOTAL='||to_char(count(*),'TM9') from {recipe['table_name']} where {_predicate(recipe)};")
    expected = ["FOX_CG_CASE=" + name + "|1" for name, _ in CASES] + ["FOX_CG_TOTAL=4"]
    output = execute_sql(commands)
    _need(type(output) is str and [line.strip() for line in output.splitlines() if line.strip()] == expected,
          "PERSISTED_ROWS_CHANGED")
    return {"observed": True, "plan_sha256": digest(recipe), "row_count": 4}


def prepare(root, request, *, execute_sql, fresh_check):
    """Once-only insertion into the already-created, observed synthetic table."""
    from .project_reviews import publish
    _need(all(not (root / name).exists() and not (root / name).is_symlink()
              for name in ("count-guard-fixture-intent.json", "count-guard-fixture.json")),
          "ALREADY_ATTEMPTED_NO_REPLAY")
    recipe, sql = plan(request), insert_sql(request)
    fresh_check()
    absent = execute_sql([f"select 'FOX_CG_ABSENT='||to_char(count(*),'TM9') from {recipe['table_name']} where {_predicate(recipe)};"])
    _need(type(absent) is str and absent.strip() == "FOX_CG_ABSENT=0", "EXISTING_ROWS_PRESERVED")
    intent = {"plan": recipe, "plan_sha256": digest(recipe), "request_sha256": digest(request),
              "fixture_sql_sha256": hashlib.sha256(sql.encode()).hexdigest()}
    publish(root / "count-guard-fixture-intent.json", intent)
    fresh_check()
    output = execute_sql(["set serveroutput on size 100000", sql])
    _need(type(output) is str and len(output) < 10_000, "OUTCOME_UNCONFIRMED_NO_REPLAY")
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    _need(len(lines) == 5 and lines[0] == "FOX_CG_FIXTURE=" + digest(recipe), "OUTCOME_UNCONFIRMED_NO_REPLAY")
    rows = []
    for line, (name, _) in zip(lines[1:], CASES, strict=True):
        prefix = "FOX_CG_ROW=" + name + "|"
        _need(line.startswith(prefix), "OUTCOME_UNCONFIRMED_NO_REPLAY")
        rows.append({"case": name, "primary_key": line[len(prefix):]})
    receipt = {**intent, "prepared": True, "rows": rows}
    validate_receipt(request, receipt)
    fresh_check()
    observe(request, receipt, execute_sql=execute_sql)
    publish(root / "count-guard-fixture.json", receipt)
    return receipt
