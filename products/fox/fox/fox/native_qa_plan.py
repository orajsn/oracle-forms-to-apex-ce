"""Independent, pure verification of native QA applicability and field coverage.

This is the Python reader for ``fox-native-qa-plan-v2``. It does not import the
browser runner, execute SQL, access a target, or record human acceptance. The
caller must hash the exact packaged native-spec bytes, parse them without
duplicate keys, and supply that hash; hashing a reserialized spec is not an
equivalent byte binding. Receipt provenance and runtime assertions remain
separate requirements of the release gate.

Plan derivation is structural, not producer authorization. Labels are retained
exactly for selectors; the canonical source/converter validators own label
safety and Unicode policy. A derivable plan does not authorize its package.
"""
from __future__ import annotations

import hashlib
import json
import re


PROFILE_ID = "native-table-form-v1"
CASE_NAMES = (
    "login", "create", "search_positive", "search_negative", "reread",
    "edit_save", "cancel_edit", "cancel_create", "required_fields",
    "invalid_number", "invalid_date", "maximum_length", "concurrent_edit",
    "browser_runtime_errors",
)
_ALL_EDITABLE_CASES = frozenset({
    "create", "reread", "edit_save", "cancel_edit", "cancel_create",
})
_ADDITIONAL_CHECKS = frozenset({"database_constraints", "database_sql_readback"})
_IDENTIFIER = re.compile(r"[A-Z][A-Z0-9_]{0,29}\Z")
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_EXCLUDED_IDENTIFIERS = frozenset(
    "ACCESS ADD ALL ALTER AND ANY AS ASC AUDIT BETWEEN BY CHAR CHECK CLUSTER "
    "COLUMN COMMENT COMPRESS CONNECT CREATE CURRENT DATE DECIMAL DEFAULT DELETE "
    "DESC DISTINCT DROP ELSE EXCLUSIVE EXISTS FILE FLOAT FOR FROM GRANT GROUP "
    "HAVING IDENTIFIED IMMEDIATE IN INCREMENT INDEX INITIAL INSERT INTEGER "
    "INTERSECT INTO IS LEVEL LIKE LOCK LONG MAXEXTENTS MINUS MLSLABEL MODE "
    "MODIFY NOAUDIT NOCOMPRESS NOT NOWAIT NULL NUMBER OF OFFLINE ON ONLINE "
    "OPTION OR ORDER PCTFREE PRIOR PRIVILEGES PUBLIC RAW RENAME RESOURCE REVOKE "
    "ROW ROWID ROWNUM ROWS SELECT SESSION SET SHARE SIZE SMALLINT START "
    "SUCCESSFUL SYNONYM SYSDATE TABLE THEN TO TRIGGER UID UNION UNIQUE UPDATE "
    "USER VALIDATE VALUES VARCHAR VARCHAR2 VIEW WHENEVER WHERE WITH "
    "PRIMARY KEY IDENTITY CONSTRAINT".split()
)


class NativeQaPlanError(ValueError):
    """A bounded metadata/coverage failure, without source or credential text."""


def _require(condition, message):
    if not condition:
        raise NativeQaPlanError(message)


def _fields(value, required, optional=frozenset()):
    _require(isinstance(value, dict) and required <= value.keys()
             and value.keys() <= required | optional,
             "Native QA metadata has missing or unsupported fields.")


def _identifier(value):
    _require(isinstance(value, str) and _IDENTIFIER.fullmatch(value)
             and value not in _EXCLUDED_IDENTIFIERS,
             "Native QA metadata contains an unsupported identifier.")


def _validate_native_spec(spec):
    # Kept independent of the converter and browser implementations so the
    # release reader cannot inherit the runner's own applicability mistake.
    _fields(spec, {"profile_id", "data_mode", "table_name", "columns"},
            {"supported_operations"})
    _require(spec["profile_id"] == PROFILE_ID
             and spec["data_mode"] == "synthetic_test_only",
             "Native QA requires the explicit synthetic native profile.")
    _identifier(spec["table_name"])
    _require(spec["table_name"].startswith("FOX_NATIVE_"),
             "Native QA table is outside the synthetic profile.")
    _require("supported_operations" not in spec or (
        isinstance(spec["supported_operations"], list)
        and spec["supported_operations"] == ["query", "insert", "update"]),
        "Native QA operations differ from the supported profile.")
    columns = spec["columns"]
    _require(isinstance(columns, list) and 2 <= len(columns) <= 20,
             "Native QA requires between two and twenty columns.")
    names, keys = set(), []
    for column in columns:
        _fields(column, {"name", "label", "data_type", "nullable"},
                {"primary_key", "identity", "length"})
        _identifier(column["name"])
        _require(column["name"] not in names, "Native QA column names are duplicated.")
        names.add(column["name"])
        _require(isinstance(column["data_type"], str)
                 and column["data_type"] in ("NUMBER", "VARCHAR2", "DATE")
                 and type(column["nullable"]) is bool,
                 "Native QA column type or nullability is unsupported.")
        primary, identity = column.get("primary_key", False), column.get("identity", False)
        _require(type(primary) is bool and type(identity) is bool
                 and primary is identity
                 and (not primary or (column["data_type"] == "NUMBER"
                                      and column["nullable"] is False)),
                 "Native QA requires an explicit non-null NUMBER identity key.")
        if primary:
            keys.append(column)
        label = column["label"]
        _require(isinstance(label, str) and 1 <= len(label) <= 80
                 and not any(0xD800 <= ord(char) <= 0xDFFF for char in label),
                 "Native QA column label is invalid.")
        if column["data_type"] == "VARCHAR2":
            _require(type(column.get("length")) is int and 1 <= column["length"] <= 4000,
                     "Native QA VARCHAR2 length is unsupported.")
        else:
            _require("length" not in column, "Only native VARCHAR2 fields have a length.")
    _require(len(keys) == 1, "Native QA requires exactly one identity primary key.")
    return keys[0], [column for column in columns if column.get("primary_key") is not True]


def derive_native_qa_plan(spec: dict, native_spec_sha256: str) -> dict:
    """Derive ordered cases from strict metadata and the exact spec-byte hash.

    Neither the input spec nor its column order is normalized or mutated.
    The first non-key column is the deterministic edit/concurrency field.
    Absence of an editable type makes only its own conditional case N/A.
    """
    primary, editable = _validate_native_spec(spec)
    _require(isinstance(native_spec_sha256, str) and _SHA256.fullmatch(native_spec_sha256),
             "The exact native-spec byte SHA-256 is required.")
    names = [column["name"] for column in editable]
    conditional = {
        "required_fields": ([column["name"] for column in editable if not column["nullable"]],
                            "REQUIRED_EDITABLE_FIELDS", "NO_REQUIRED_EDITABLE_FIELDS"),
        "invalid_number": ([column["name"] for column in editable if column["data_type"] == "NUMBER"],
                           "EDITABLE_NUMBER_FIELDS", "NO_EDITABLE_NUMBER_FIELDS"),
        "invalid_date": ([column["name"] for column in editable if column["data_type"] == "DATE"],
                         "EDITABLE_DATE_FIELDS", "NO_EDITABLE_DATE_FIELDS"),
        "maximum_length": ([column["name"] for column in editable if column["data_type"] == "VARCHAR2"],
                           "BOUNDED_VARCHAR2_FIELDS", "NO_EDITABLE_VARCHAR2_FIELDS"),
    }
    cases = []
    for name in CASE_NAMES:
        if name in conditional:
            fields, present, absent = conditional[name]
            applicable, reason = bool(fields), present if fields else absent
        else:
            fields = list(names) if name in _ALL_EDITABLE_CASES else [names[0]] if name == "concurrent_edit" else []
            applicable, reason = True, "UNIVERSAL_NATIVE_FLOW"
        cases.append({"name": name, "applicable": applicable,
                      "field_names": fields, "reason_code": reason})
    return {
        "schema_version": 1, "scope": "fox-native-qa-plan-v2", "profile_id": PROFILE_ID,
        "native_spec_sha256": native_spec_sha256,
        "primary_key": {"name": primary["name"], "item_name": "P2_" + primary["name"],
                        "representation": "decimal_string"},
        "row_tracking": {"mode": "clean_empty_then_observed_pk", "initial_row_count": 0},
        "edit_field": names[0], "cases": cases,
    }


def derive_native_qa_profile(spec: dict) -> dict:
    """Derive all synthetic QA input values without marker/edit overrides."""
    primary, editable = _validate_native_spec(spec)
    values = {"VARCHAR2": "A", "NUMBER": "1", "DATE": "2026-01-01"}
    return {
        "schema_version": 2, "profile_id": PROFILE_ID,
        "data_mode": "synthetic_test_only", "table_name": spec["table_name"],
        "primary_key": primary["name"],
        "fields": [
            {"name": column["name"], "label": column["label"],
             "data_type": column["data_type"], "required": not column["nullable"],
             **({"max_length": column["length"]} if column["data_type"] == "VARCHAR2" else {}),
             "valid_value": values[column["data_type"]]}
            for column in editable
        ],
        "database_constraints": [],
    }


def _canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise NativeQaPlanError("The native QA plan is not canonical JSON metadata.") from None


def qa_plan_sha256(plan: dict) -> str:
    """Hash UTF-8 recursively key-sorted compact JSON, without a newline."""
    _require(isinstance(plan, dict), "The native QA plan must be an object.")
    return hashlib.sha256(_canonical(plan)).hexdigest()


def validate_native_qa_result_cases(result: dict, plan: dict) -> dict:
    """Return the fourteen indexed passed/N/A cases or raise NativeQaPlanError.

    ``plan`` must be independently derived from the exact packaged native spec;
    never pass ``result['test_plan']`` as the expected plan. Required flags are
    checked against that derivation, not used to decide which tests matter.
    The caller separately verifies login identity, clean row state, concurrency
    evidence, receipt ownership, target binding, timestamps and other gates.
    """
    _require(isinstance(result, dict) and result.get("status") == "PASSED",
             "Native QA result did not pass.")
    _require(isinstance(plan, dict) and type(plan.get("schema_version")) is int
             and plan["schema_version"] == 1 and plan.get("scope") == "fox-native-qa-plan-v2"
             and plan.get("profile_id") == PROFILE_ID
             and isinstance(plan.get("cases"), list)
             and [case.get("name") if isinstance(case, dict) else None
                  for case in plan["cases"]] == list(CASE_NAMES),
             "An independently derived native QA v2 plan is required.")
    _require(_canonical(result.get("test_plan")) == _canonical(plan)
             and result.get("test_plan_sha256") == qa_plan_sha256(plan),
             "Reported native QA plan differs from the independently derived plan.")
    tests = result.get("tests")
    _require(isinstance(tests, list) and len(tests) == len(CASE_NAMES)
             and all(isinstance(test, dict) for test in tests),
             "Native QA requires exactly fourteen case results.")
    names = [test.get("name") for test in tests]
    _require(all(isinstance(name, str) for name in names)
             and len(set(names)) == len(names) and set(names) == set(CASE_NAMES),
             "Native QA cases are missing, duplicated or unexpected.")
    indexed = dict(zip(names, tests))
    for case in plan["cases"]:
        test, applicable = indexed[case["name"]], case.get("applicable")
        _require(type(applicable) is bool
                 and test.get("applicable") is applicable
                 and test.get("required") is applicable
                 and test.get("reason_code") == case.get("reason_code")
                 and _canonical(test.get("field_names")) == _canonical(case.get("field_names")),
                 "Native QA applicability or ordered field coverage differs from the plan.")
        _require(test.get("status") == ("PASSED" if applicable else "NOT_APPLICABLE"),
                 "An applicable native QA case did not pass or a N/A case was misstated.")
        expected = [{"field_name": name, "status": "PASSED"} for name in case["field_names"]]
        _require(_canonical(test.get("field_results")) == _canonical(expected),
                 "Native QA lacks a passed runtime result for every applicable field.")
    additional = result.get("additional_checks")
    _require(isinstance(additional, list) and len(additional) == len(_ADDITIONAL_CHECKS)
             and all(isinstance(check, dict) for check in additional),
             "Optional database checks must be separately and explicitly recorded.")
    names = [check.get("name") for check in additional]
    _require(all(isinstance(name, str) for name in names)
             and len(set(names)) == len(names) and set(names) == _ADDITIONAL_CHECKS,
             "Optional database check names are missing, duplicated or unexpected.")
    for check in additional:
        _require(check.get("required") is False and check.get("status") == "NOT_RUN"
                 and isinstance(check.get("reason"), str) and 0 < len(check["reason"].strip()) <= 1000,
                 "Optional database checks cannot claim unproven or failed execution.")
    return indexed
