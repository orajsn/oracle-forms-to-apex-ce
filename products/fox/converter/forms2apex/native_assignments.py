"""Finite parent-value copy review artifacts, never installed or event-wired.

The caller must freshly rebuild the source plan before rendering. Digests detect
changed plans; they are not signatures authenticating caller-supplied source.
No source identifier or source text is interpolated into executable PL/SQL.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re

SCOPE = "fox-forms-assignment-plan-v1"
RENDERER = "fox-native-assignment-review-v1"
CODE_MEMBER = "fox-package/assignment-review.sql"
MAX_OPERATIONS = 100
MAX_UNIT_CHARACTERS = 16_384
MAX_SQL_CHARACTERS = 131_072
ACTIVATION_REQUIREMENTS = [
    "Implement native write-event lifecycle and explicit parent-row context.",
    "Implement authorization, validation, transaction and missing-parent guards.",
    "Compile and verify in an approved Oracle target; accept business behavior separately.",
]
_IDENT = r"[A-Za-z][A-Za-z0-9_$#]{0,127}"
_REF = rf":\s*({_IDENT})(?:\s*\.\s*({_IDENT}))?"
_ASSIGN = re.compile(rf"\s*{_REF}\s*:=\s*{_REF}\s*;\s*", re.I)
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"ff1-[0-9a-f]{24}\Z")
_ROOT = {"schema_version", "scope", "source_binding", "relation_plan_sha256", "trace_sha256",
         "sources", "operations", "coverage", "code_unit_count", "native_generated",
         "write_lifecycle", "runtime_verified", "business_accepted", "plan_sha256"}
_OP = {"operation_id", "source_unit_id", "source_unit_sha256", "source_chunk_id",
       "source_owner_id", "source_module_id", "source_event", "source_unit_text",
       "relation_id", "source_ref", "target_ref", "decode_receipt"}
_BINDING = {"block_id", "item_id", "block_name", "item_name", "column", "data_type"}
_COVERAGE = {"source_unit_id", "source_unit_sha256", "source_chunk_id", "source_owner_id",
             "source_location", "status", "not_yet_converted", "reason",
             "runtime_verified", "business_accepted"}


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _need(condition, code):
    if not condition:
        raise ValueError("ASSIGNMENT_" + code)


def parse_assignment_text(raw):
    """Recognize one complete copy, optional BEGIN/END, comments/control escapes.

    Quotes, expressions, declarations, exception handlers and additional active
    statements cannot enter this grammar. Null values are copied unchanged.
    """
    _need(type(raw) is str and 0 < len(raw) <= MAX_UNIT_CHARACTERS, "UNIT_SIZE")
    out, substitutions, offset = [], [], 0
    for match in re.finditer(r"&#(?:([0-9]+)|[xX]([0-9a-fA-F]+));", raw):
        out.append(raw[offset:match.start()])
        cp = int(match[1], 10) if match[1] else int(match[2], 16)
        _need(cp in (9, 10, 13), "CONTROL_ENTITY")
        substitutions.append({"raw_character_offset": match.start(),
            "semantic_character_offset": sum(map(len, out)),
            "encoded": match[0], "codepoint": cp})
        out.append(chr(cp))
        offset = match.end()
    out.append(raw[offset:])
    semantic = "".join(out)
    receipt = {"rule": "numeric-tab-lf-cr-outside-literals-v1",
        "raw_sha256": _sha(raw.encode()), "semantic_sha256": _sha(semantic.encode()),
        "offset_unit": "unicode_character", "substitutions": substitutions}
    clean, pos = [], 0
    while pos < len(semantic):
        if semantic.startswith("--", pos):
            end = re.search(r"[\r\n]", semantic[pos + 2:])
            pos = len(semantic) if end is None else pos + 2 + end.start()
            clean.append(" ")
        elif semantic.startswith("/*", pos):
            end = semantic.find("*/", pos + 2)
            _need(end >= 0 and "/*" not in semantic[pos + 2:end], "COMMENT")
            pos = end + 2
            clean.append(" ")
        else:
            clean.append(semantic[pos])
            pos += 1
    text = "".join(clean).strip()
    wrapper = re.fullmatch(r"BEGIN\b(.*)\bEND\s*;", text, re.I | re.S)
    if wrapper:
        text = wrapper[1]
    match = _ASSIGN.fullmatch(text)
    _need(match is not None, "COMPLETE_COPY_REQUIRED")
    target = [value.upper() for value in match.group(1, 2) if value is not None]
    source = [value.upper() for value in match.group(3, 4) if value is not None]
    return target, source, receipt


def operation_id(source_binding, unit_id):
    return "fa1-" + _sha(_canonical([source_binding, unit_id]))[:24]


def _reference(parts, ref):
    return parts == [ref["item_name"].upper()] or parts == [
        ref["block_name"].upper(), ref["item_name"].upper()]


def _validate(plan):
    _need(type(plan) is dict and set(plan) == _ROOT, "PLAN_FIELDS")
    _need(type(plan["schema_version"]) is int and plan["schema_version"] == 1
          and plan["scope"] == SCOPE, "PLAN_VERSION")
    for key in ("source_binding", "relation_plan_sha256", "trace_sha256", "plan_sha256"):
        _need(type(plan[key]) is str and _SHA.fullmatch(plan[key]), "DIGEST")
    _need(plan["plan_sha256"] == _sha(_canonical({k: v for k, v in plan.items()
                                                 if k != "plan_sha256"})), "PLAN_CHANGED")
    _need(all(plan[key] is False for key in ("native_generated", "write_lifecycle",
          "runtime_verified", "business_accepted")), "FALSE_CLAIMS")
    sources = plan["sources"]
    _need(type(sources) is list and 1 <= len(sources) <= 4, "SOURCES")
    names = set()
    for row in sources:
        _need(type(row) is dict and set(row) == {"name", "sha256", "bytes"}, "SOURCE_FIELDS")
        _need(type(row["name"]) is str and 0 < len(row["name"]) <= 180
              and "/" not in row["name"] and "\\" not in row["name"]
              and row["name"].casefold() not in names, "SOURCE_NAME")
        names.add(row["name"].casefold())
        _need(type(row["sha256"]) is str and _SHA.fullmatch(row["sha256"])
              and type(row["bytes"]) is int and 0 < row["bytes"] <= 5 * 1024 * 1024, "SOURCE_IDENTITY")
    operations, coverage = plan["operations"], plan["coverage"]
    _need(type(operations) is list and len(operations) <= MAX_OPERATIONS
          and type(coverage) is list and len(coverage) <= 20_000
          and type(plan["code_unit_count"]) is int and plan["code_unit_count"] == len(coverage), "CAPACITY")
    indexed, occupied = {}, set()
    for row in coverage:
        _need(type(row) is dict and _COVERAGE <= set(row)
              and set(row) <= _COVERAGE | {"operation_id", "encoding_status"}, "COVERAGE_FIELDS")
        _need(type(row["source_unit_id"]) is str and _ID.fullmatch(row["source_unit_id"])
              and row["source_unit_id"] not in indexed, "COVERAGE_IDENTITY")
        _need(type(row["source_owner_id"]) is str and _ID.fullmatch(row["source_owner_id"])
              and type(row["source_unit_sha256"]) is str and _SHA.fullmatch(row["source_unit_sha256"])
              and type(row["source_chunk_id"]) is str
              and re.fullmatch(r"fup1-[0-9a-f]{64}", row["source_chunk_id"])
              and type(row["reason"]) is str and 0 < len(row["reason"]) <= 200, "COVERAGE_UNIT")
        location = row["source_location"]
        _need(type(location) is dict and set(location) == {"path", "line", "column", "byte_offset"}
              and type(location["path"]) is str and 0 < len(location["path"]) <= 8192
              and location["path"].startswith("/")
              and all(type(location[key]) is int and location[key] >= minimum for key, minimum in
                      (("line", 1), ("column", 1), ("byte_offset", 0))), "SOURCE_LOCATION")
        _need(row["status"] == "unsupported" and row["not_yet_converted"] is True
              and row["runtime_verified"] is False and row["business_accepted"] is False,
              "COVERAGE_CLAIMS")
        indexed[row["source_unit_id"]] = row
    seen, owners, relation_bindings, item_bindings = set(), set(), {}, {}
    for op in operations:
        _need(type(op) is dict and set(op) == _OP, "OPERATION_FIELDS")
        for key in ("source_unit_id", "source_owner_id", "source_module_id", "relation_id"):
            _need(type(op[key]) is str and _ID.fullmatch(op[key]), "OPERATION_IDENTITY")
        _need(op["source_event"] in ("PRE-INSERT", "PRE-UPDATE"), "EVENT")
        _need(type(op["source_unit_sha256"]) is str and _SHA.fullmatch(op["source_unit_sha256"])
              and type(op["source_chunk_id"]) is str
              and re.fullmatch(r"fup1-[0-9a-f]{64}", op["source_chunk_id"]), "UNIT_IDENTITY")
        _need(op["operation_id"] == operation_id(plan["source_binding"], op["source_unit_id"])
              and op["operation_id"] not in seen, "DUPLICATE_OPERATION")
        _need(op["source_owner_id"] not in owners, "AMBIGUOUS_OWNER")
        owners.add(op["source_owner_id"])
        seen.add(op["operation_id"])
        target, source, receipt = parse_assignment_text(op["source_unit_text"])
        _need(receipt == op["decode_receipt"] and receipt["raw_sha256"] == op["source_unit_sha256"],
              "SOURCE_CHANGED")
        for key in ("source_ref", "target_ref"):
            ref = op[key]
            _need(type(ref) is dict and set(ref) == _BINDING, "BINDING_FIELDS")
            _need(all(type(ref[name]) is str and _ID.fullmatch(ref[name])
                      for name in ("block_id", "item_id")), "BINDING_IDENTITY")
            _need(all(type(ref[name]) is str and re.fullmatch(_IDENT, ref[name])
                      for name in ("block_name", "item_name", "column"))
                  and ref["data_type"] in ("NUMBER", "VARCHAR2"), "BINDING_TYPE")
            _need(ref["item_id"] not in item_bindings or item_bindings[ref["item_id"]] == ref,
                  "ITEM_BINDING_CONFLICT")
            item_bindings[ref["item_id"]] = ref
        _need(_reference(target, op["target_ref"]) and _reference(source, op["source_ref"])
              and op["source_ref"]["block_id"] != op["target_ref"]["block_id"]
              and op["source_ref"]["data_type"] == op["target_ref"]["data_type"], "BINDING_CHANGED")
        edge = (op["source_module_id"], op["source_ref"]["block_id"], op["target_ref"]["block_id"])
        _need(op["relation_id"] not in relation_bindings or relation_bindings[op["relation_id"]] == edge,
              "RELATION_BINDING_CONFLICT")
        relation_bindings[op["relation_id"]] = edge
        collision = (op["source_module_id"], op["source_event"], op["target_ref"]["item_id"])
        _need(collision not in occupied, "AMBIGUOUS_EVENT_FIELD")
        occupied.add(collision)
        row = indexed.get(op["source_unit_id"])
        _need(row is not None and all(row[key] == op[key] for key in
              ("source_unit_id", "source_unit_sha256", "source_chunk_id", "source_owner_id", "operation_id"))
              and row.get("encoding_status") == "generated_unwired", "COVERAGE_BINDING")
    _need({row.get("operation_id") for row in coverage if "operation_id" in row} == seen,
          "COVERAGE_OPERATIONS")
    _need(all(("encoding_status" in row) == ("operation_id" in row) for row in coverage),
          "COVERAGE_ENCODING")


def render_assignment_code(plan):
    """Return review-only SQL and a separate, explicitly unwired binding manifest."""
    _validate(plan)
    package = "FOX_ASG_" + plan["plan_sha256"][:20].upper()
    header = ["-- FOX generated assignment review artifact: GENERATED_UNWIRED.",
              "-- Not installed, Oracle-compiled, event-wired or runtime-verified by FOX.",
              "-- Pure value copies only; the caller must provide and guard parent context."]
    spec, body, generated = [], [], []
    for op in plan["operations"]:
        name = "COPY_" + op["operation_id"][4:].upper()
        datatype = op["source_ref"]["data_type"]
        signature = f"  PROCEDURE {name}(p_value IN {datatype}, p_copy OUT {datatype})"
        spec.append(signature + ";")
        body.append(signature + " IS\n  BEGIN\n    p_copy := p_value;\n  END " + name + ";")
        generated.append({**deepcopy(op), "encoding_status": "generated_unwired",
            "generation_status": "generated_unwired", "code_member": CODE_MEMBER,
            "package_name": package, "procedure_name": name, "null_policy": "preserve",
            "write_lifecycle": False, "event_activated": False, "oracle_compiled": False,
            "runtime_verified": False, "business_accepted": False,
            "activation_requirements": list(ACTIVATION_REQUIREMENTS)})
    if generated:
        sql = "\n".join(header) + f"\nCREATE OR REPLACE PACKAGE {package} AUTHID CURRENT_USER AS\n"
        sql += "\n".join(spec) + f"\nEND {package};\n/\n"
        sql += f"CREATE OR REPLACE PACKAGE BODY {package} AS\n"
        sql += "\n".join(body) + f"\nEND {package};\n/\n"
    else:
        sql = "\n".join(header) + "\n-- No complete eligible assignment was encoded.\n"
    _need(len(sql) <= MAX_SQL_CHARACTERS, "SQL_CAPACITY")
    return sql, {"schema_version": 1, "scope": RENDERER, "plan_sha256": plan["plan_sha256"],
        "source_binding": plan["source_binding"], "relation_plan_sha256": plan["relation_plan_sha256"],
        "trace_sha256": plan["trace_sha256"], "code_member": CODE_MEMBER,
        "sql_sha256": _sha(sql.encode()), "generated_operations": generated,
        "coverage": deepcopy(plan["coverage"]), "code_unit_count": plan["code_unit_count"],
        "converted_code_unit_count": 0, "native_generated": False, "write_lifecycle": False,
        "event_activated": False, "oracle_compiled": False, "runtime_verified": False,
        "business_accepted": False}
