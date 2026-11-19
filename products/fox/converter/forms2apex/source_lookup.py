"""Closed source SELECT-INTO event IR. No source query is executed here.

Integrity digests are not authority: rebuild from retained source before emitting,
bind the exact parent ZIP, and separately verify/activate original read interfaces.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import re

from .native_assignments import _canonical, _sha
from .native_policy_rules import _validate_catalog

SCOPE = "fox-forms-source-lookup-plan-v1"
MAX_OPERATIONS = 50
MAX_TEXT = 16_384
_IDENT = r"[A-Z][A-Z0-9_$#]{0,127}"
_TARGET = r"[A-Z][A-Z0-9_]{0,127}"
_RESERVED = set("BEGIN END SELECT INTO FROM WHERE AND EXCEPTION WHEN THEN NO_DATA_FOUND OTHERS NULL AS OR UNION JOIN ON FOR UPDATE DELETE INSERT MERGE EXECUTE DISTINCT GROUP ORDER HAVING CONNECT START WITH ROWNUM ROWID SYSDATE CURRENT_DATE LEVEL".split())
FLAGS = ("native_generated", "event_activated", "runtime_verified", "business_accepted")
ACTIVATION_REQUIREMENTS = [
    "A trusted operator must verify the exact original source objects, columns, types, privileges and cardinality in the approved target parsing schema.",
    "Keep the server-only restricted application readiness item unset until that verification; browser state cannot activate original reads.",
    "Verify Oracle character length, case, numeric and SELECT INTO exception semantics on the target; accept business behavior separately.",
]
SEMANTICS = {
    "source_interface": "original_read_query_default_disabled",
    "cardinality": "exactly_one_no_row_limit_or_aggregation",
    "null_predicates": "oracle_three_valued_equality",
    "record_context": "same_block_synthetic_FOX_ROW_ID_not_source_key",
    "initialization": "post_query_after_synthetic_row_initialization",
    "input_case": "declared_case_only_on_changed_inputs_preserve_other_values_and_whitespace",
    "gate_outside_source_exception": True,
    "business_save": False,
}


class LookupPlanError(ValueError):
    """Bounded diagnostic without source data."""


class UnsupportedLookup(ValueError):
    """Whole event is outside the recognized finite grammar."""


def _need(value, code):
    if not value:
        raise LookupPlanError("LOOKUP_" + code)


def _unsupported(reason):
    raise UnsupportedLookup(reason)


def _one(rows, reason):
    if len(rows) != 1:
        _unsupported(reason)
    return rows[0]


def decode_source(raw):
    """Reuse the numeric-controls decoder; unknown backslash escapes stay invalid."""
    from .record_buffer import decode_source as decode, UnsupportedBuffer
    try:
        return decode(raw)
    except UnsupportedBuffer as exc:
        raise UnsupportedLookup(str(exc)) from None


def parse_lookup_trigger(raw):
    """Consume the entire BEGIN/SELECT/exception/reset/END event, never a slice."""
    text, receipt = decode_source(raw)
    pattern = re.compile(r"\s+|--[^\r\n]*|/\*.*?\*/|'(?:''|[^'])*'|:=|" + _IDENT + r"|[0-9]+(?:\.[0-9]+)?|[:.,;=+-]", re.I | re.S)
    tokens, pos = [], 0
    while pos < len(text):
        match = pattern.match(text, pos)
        if match is None:
            _unsupported("unsupported_active_token")
        value, pos = match[0], match.end()
        if value.isspace() or value.startswith(("--", "/*")):
            continue
        kind = "string" if value.startswith("'") else "number" if value[0].isdigit() else "token"
        tokens.append((kind, value[1:-1].replace("''", "'") if kind == "string" else value.upper()))
        if len(tokens) > 1024:
            _unsupported("token_capacity")
    index = 0

    def peek(value):
        return index < len(tokens) and tokens[index] == ("token", value)

    def take(value=None, kind="token"):
        nonlocal index
        if index >= len(tokens) or tokens[index][0] != kind or value is not None and tokens[index][1] != value:
            _unsupported("complete_lookup_body_required")
        result = tokens[index][1]
        index += 1
        return result

    def identifier():
        result = take()
        if not re.fullmatch(_IDENT, result) or result in _RESERVED:
            _unsupported("unsafe_or_reserved_identifier")
        return result

    def parts(maximum):
        result = [identifier()]
        while peek("."):
            take(".")
            result.append(identifier())
            if len(result) > maximum:
                _unsupported("qualified_identifier_capacity")
        return result

    def reference():
        take(":")
        return parts(2)

    def column():
        return {"kind": "column", "parts": parts(3)}

    def sequence(parser, maximum):
        values = [parser()]
        while peek(","):
            take(",")
            values.append(parser())
            if len(values) > maximum:
                _unsupported("query_list_capacity")
        return values

    take("BEGIN")
    take("SELECT")
    projections = sequence(column, 8)
    take("INTO")
    outputs = sequence(reference, 8)
    if len(projections) != len(outputs):
        _unsupported("projection_output_count")
    take("FROM")
    tables = sequence(lambda: {"parts": parts(2)}, 4)
    if len({tuple(t["parts"]) for t in tables}) != len(tables):
        _unsupported("duplicate_source_table")
    take("WHERE")
    predicates, inputs = [], []
    while True:
        left = column()
        take("=")
        if peek(":"):
            ref = reference()
            if ref not in inputs:
                inputs.append(ref)
            right = {"kind": "bind", "ref": ref}
        elif index < len(tokens) and tokens[index][0] == "string":
            value = take(kind="string")
            if len(value.encode()) > 2000 or any(ord(c) < 32 for c in value):
                _unsupported("literal_capacity")
            right = {"kind": "string", "value": value}
        elif peek("+") or peek("-") or index < len(tokens) and tokens[index][0] == "number":
            sign = take() if peek("+") or peek("-") else ""
            value = sign + take(kind="number")
            if len(value) > 40:
                _unsupported("literal_capacity")
            right = {"kind": "number", "value": value}
        else:
            right = column()
        predicates.append({"left": left, "right": right})
        if len(predicates) > 16:
            _unsupported("predicate_capacity")
        if not peek("AND"):
            break
        take("AND")
    take(";")
    for token in ("EXCEPTION", "WHEN"):
        take(token)
    exception = take()
    if exception not in ("NO_DATA_FOUND", "OTHERS"):
        _unsupported("source_exception_kind")
    take("THEN")
    resets = []
    while peek(":"):
        resets.append(reference())
        for token in (":=", "NULL", ";"):
            take(token)
        if len(resets) > 8:
            _unsupported("reset_capacity")
    take("END")
    take(";")
    if index != len(tokens):
        _unsupported("extra_active_source")
    if not inputs:
        _unsupported("query_input_required")
    for node in projections + [n for p in predicates for n in (p["left"], p["right"]) if n["kind"] == "column"]:
        qualifier = node["parts"][:-1]
        if qualifier and len([t for t in tables if t["parts"][-len(qualifier):] == qualifier]) != 1:
            _unsupported("source_column_qualifier")
    return {"query": {"projections": projections, "tables": tables, "predicates": predicates},
            "input_refs": inputs, "output_refs": outputs, "exception_kind": exception, "reset_refs": resets}, receipt


def operation_id(source_binding, unit_id):
    return "fl1-" + _sha(_canonical([source_binding, unit_id]))[:24]


def derive_lookup_operations(catalog, trace, source_binding):
    """Derive only complete same-block events over proven native fields."""
    objects = _validate_catalog(catalog, trace)
    counts = Counter((obj["module_id"], obj["parent_id"], (obj["name"] or "").upper())
                     for obj in objects.values() if obj["kind"] == "Trigger")
    by_owner = Counter(unit["owner_id"] for unit in catalog["units"])

    def resolve(ref, block):
        if len(ref) == 2 and ref[0] != (block["name"] or "").upper():
            _unsupported("same_block_reference_required")
        return _one([obj for obj in objects.values() if obj["kind"] == "Item" and obj["block_id"] == block["id"]
                     and obj["module_id"] == block["module_id"] and (obj["name"] or "").upper() == ref[-1]], "source_item_reference_not_unique")

    def allowed(props, key):
        value = props.get(key)
        if value is None:
            return None
        if value.strip().lower() not in ("true", "false"):
            _unsupported("source_mutability_property_unsupported")
        return value.strip().lower() == "true"

    def binding(item, block, mapped):
        props = item["metadata"]
        source_type = props.get("DataType", "").strip().upper()
        dtype = {"CHAR": "VARCHAR2", "VARCHAR2": "VARCHAR2", "NUMBER": "NUMBER"}.get(source_type)
        field = _one([f for f in mapped["items"] if f["source_item_id"] == item["id"]], "native_item_not_unique")
        if (dtype is None or field.get("data_type") != dtype or field.get("source_name") != item["name"]
                or not re.fullmatch(_TARGET, field.get("column") or "")
                or type(item["database_item"]) is not bool or field.get("database_bound") is not True):
            _unsupported("native_source_type_binding")
        if (props.get("Formula", "").strip() or field.get("value_computation_implemented") is True
                or any(props.get(k, "").strip().upper() not in ("", "NONE") for k in ("CalculateMode", "CalculationMode", "SummaryFunction"))):
            _unsupported("direct_noncomputed_item_required")
        maximum = None
        if dtype == "VARCHAR2":
            length = props.get("MaximumLength", "")
            if not re.fullmatch(r"[0-9]{1,4}", length) or not 0 < int(length) <= 4000:
                _unsupported("explicit_character_length_required")
            maximum = int(length)
        semantics = props.get("DataLengthSemantics", "").strip().upper()
        case = {"": "NONE", "NONE": "NONE", "MIXED": "NONE", "UPPER": "UPPER", "LOWER": "LOWER"}.get(props.get("CaseRestriction", "").strip().upper())
        required = props.get("Required", "false").strip().lower()
        if semantics not in ("", "NULL", "BYTE", "CHAR") or case is None or required not in ("true", "false"):
            _unsupported("source_input_property_unsupported")
        return {"source_item_id": item["id"], "source_block_id": block["id"], "source_module_id": block["module_id"],
                "source_item_name": item["name"], "source_block_name": block["name"], "source_data_type": source_type,
                "data_type": dtype, "max_length": maximum, "max_bytes": maximum * 6 if maximum else None,
                "source_length_semantics": semantics, "case_restriction": case, "required": required == "true",
                "column": field["column"], "database_bound": True, "source_database_item": item["database_item"],
                "source_insert_allowed": allowed(props, "InsertAllowed"), "source_update_allowed": allowed(props, "UpdateAllowed")}

    operations, coverage = [], []
    for unit in catalog["units"]:
        owner = objects[unit["owner_id"]]
        row = {"source_unit_id": unit["id"], "source_unit_sha256": unit["sha256"], "source_chunk_id": unit["chunk_id"],
               "source_owner_id": owner["id"], "source_location": deepcopy(unit["location"]), "status": "unsupported",
               "reason": "outside_source_lookup_event", "native_generated": False, "runtime_verified": False, "business_accepted": False}
        coverage.append(row)
        try:
            event = (owner["name"] or "").upper()
            if owner["kind"] != "Trigger" or event not in ("POST-QUERY", "POST-CHANGE"):
                continue
            parent = objects.get(owner["parent_id"])
            block = objects.get(owner["block_id"])
            if (block is None or block["kind"] != "Block" or block["classification"] != "database"
                    or owner["module_id"] != block["module_id"] or unit["source_attribute"] != "TriggerText"
                    or by_owner[owner["id"]] != 1 or counts[(owner["module_id"], owner["parent_id"], event)] != 1
                    or parent is None or parent["kind"] != ("Block" if event == "POST-QUERY" else "Item")
                    or event == "POST-QUERY" and parent["id"] != block["id"]):
                _unsupported("direct_whole_event_owner_required")
            parsed, receipt = parse_lookup_trigger(unit["text"])
            mapped = _one([b for b in trace["blocks"] if b["source_block_id"] == block["id"]], "native_block_not_unique")
            key = mapped.get("synthetic_key", {})
            if (mapped.get("source_module_id") != block["module_id"] or mapped.get("name") != block["name"]
                    or mapped.get("classification") != "database" or not re.fullmatch(_TARGET, mapped.get("table_name") or "")
                    or key.get("column") != "FOX_ROW_ID" or key.get("source_derived") is not False or key.get("source_item_id") is not None
                    or type(mapped.get("report_page_id")) is not int or not 0 < mapped["report_page_id"] < 9000
                    or type(mapped.get("report_file")) is not str):
                _unsupported("native_block_binding")
            input_items = [resolve(ref, block) for ref in parsed["input_refs"]]
            input_items = list({item["id"]: item for item in input_items}.values())
            output_items = [resolve(ref, block) for ref in parsed["output_refs"]]
            resets = [resolve(ref, block)["id"] for ref in parsed["reset_refs"]]
            out_ids = [item["id"] for item in output_items]
            if (len(set(out_ids)) != len(out_ids) or len(resets) != len(out_ids) or set(resets) != set(out_ids)
                    or {item["id"] for item in input_items} & set(out_ids)):
                _unsupported("distinct_outputs_exact_resets_no_input_overlap_required")
            if event == "POST-CHANGE" and parent["id"] not in {item["id"] for item in input_items}:
                _unsupported("changed_item_must_be_query_input")
            query = deepcopy(parsed["query"])
            for projection, output in zip(query["projections"], output_items, strict=True):
                projection["output_item_id"] = output["id"]
            for predicate in query["predicates"]:
                if predicate["right"]["kind"] == "bind":
                    predicate["right"] = {"kind": "bind", "source_item_id": resolve(predicate["right"]["ref"], block)["id"]}
            if len(operations) >= MAX_OPERATIONS:
                _unsupported("operation_capacity")
            operation = {"operation_id": operation_id(source_binding, unit["id"]), "kind": "source_select_into_lookup",
                "source_binding": source_binding, "source_module_id": block["module_id"], "source_block_id": block["id"],
                "source_event": event, "event_item_id": parent["id"] if event == "POST-CHANGE" else None,
                "source_unit_id": unit["id"], "source_unit_sha256": unit["sha256"], "source_chunk_id": unit["chunk_id"],
                "source_owner_id": owner["id"], "source_attribute": unit["source_attribute"], "source_location": deepcopy(unit["location"]),
                "source_unit_text": unit["text"], "decode_receipt": receipt, "query": query,
                "input_bindings": [binding(item, block, mapped) for item in input_items],
                "output_bindings": [binding(item, block, mapped) for item in output_items],
                "exception_kind": parsed["exception_kind"], "reset_order": resets,
                "target": {"table": mapped["table_name"], "report_file": mapped["report_file"], "report_page_id": mapped["report_page_id"],
                           "row_id_column": "FOX_ROW_ID", "row_identity_source_derived": False,
                           "source_insert_allowed": allowed(block["metadata"], "InsertAllowed"),
                           "source_update_allowed": allowed(block["metadata"], "UpdateAllowed")},
                "source_objects": [{"parts": deepcopy(t["parts"]), "verification": "unverified_original_read_interface"} for t in query["tables"]],
                "activation_requirements": deepcopy(ACTIVATION_REQUIREMENTS), "semantics": deepcopy(SEMANTICS)}
            operations.append(operation)
            row.update(status="planned_wired_adapted", reason="whole_source_lookup_planned_not_rendered", operation_id=operation["operation_id"])
        except UnsupportedLookup as exc:
            row["reason"] = str(exc)
    return operations, coverage


_ROOT = {"schema_version", "scope", "source_binding", "parent_zip_sha256", "source_manifest_sha256", "parent_trace_sha256",
         "trace_sha256", "source_catalog_sha256", "sources", "source_catalog", "parent_trace", "operations", "coverage",
         "code_unit_count", "plan_sha256", *FLAGS}


def validate_lookup_plan(plan):
    """Validate a closed plan and rederive all IR from its source proof catalog."""
    _need(type(plan) is dict and set(plan) == _ROOT, "PLAN_FIELDS")
    _need(type(plan["schema_version"]) is int and plan["schema_version"] == 1 and plan["scope"] == SCOPE, "PLAN_VERSION")
    _need(len(_canonical(plan)) <= 16_000_000, "PLAN_CAPACITY")
    for key in ("source_binding", "parent_zip_sha256", "source_manifest_sha256", "parent_trace_sha256", "trace_sha256", "source_catalog_sha256", "plan_sha256"):
        _need(type(plan[key]) is str and re.fullmatch(r"[0-9a-f]{64}", plan[key]), "DIGEST")
    _need(all(plan[k] is False for k in FLAGS), "FALSE_CLAIMS")
    _need(plan["plan_sha256"] == _sha(_canonical({k: v for k, v in plan.items() if k != "plan_sha256"})), "PLAN_CHANGED")
    _need(type(plan["sources"]) is list and 1 <= len(plan["sources"]) <= 4, "SOURCES")
    names = set()
    for source in plan["sources"]:
        _need(type(source) is dict and set(source) == {"name", "sha256", "bytes"}, "SOURCE_FIELDS")
        name = source["name"]
        _need(type(name) is str and 0 < len(name) <= 180 and name.lower().endswith(".xml")
              and not any(c in name for c in "/\\:") and ".." not in name and not any(ord(c) < 32 for c in name)
              and name.casefold() not in names and type(source["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", source["sha256"])
              and type(source["bytes"]) is int and 0 < source["bytes"] <= 5 * 1024 * 1024, "SOURCE_IDENTITY")
        names.add(name.casefold())
    _need(type(plan["parent_trace"]) is dict and plan["parent_trace"].get("source_binding") == plan["source_binding"]
          and _sha(_canonical(plan["parent_trace"])) == plan["trace_sha256"]
          and _sha(_canonical(plan["source_catalog"])) == plan["source_catalog_sha256"], "SOURCE_PROOF_CHANGED")
    try:
        operations, coverage = derive_lookup_operations(plan["source_catalog"], plan["parent_trace"], plan["source_binding"])
    except (KeyError, TypeError, IndexError):
        raise LookupPlanError("LOOKUP_SOURCE_PROOF_INVALID") from None
    _need(type(plan["code_unit_count"]) is int and plan["code_unit_count"] == len(coverage), "UNIT_COUNT")
    _need(_canonical(operations) == _canonical(plan["operations"]) and _canonical(coverage) == _canonical(plan["coverage"]), "SOURCE_IR_MISMATCH")
    return deepcopy(plan)


def model_lookup_result(operation, rows, *, error=None):
    """Pure cardinality/exception model; rows are projected, not a query engine.

    No execution, implicit conversion or NLS equivalence is claimed. Readiness
    and record-context checks belong outside the original exception handler.
    """
    _need(type(rows) is list and len(rows) <= 1000, "MODEL_ROWS")
    outputs = operation["output_bindings"]
    if error is None:
        error = "NO_DATA_FOUND" if not rows else "TOO_MANY_ROWS" if len(rows) > 1 else None
    if error:
        _need(error in ("NO_DATA_FOUND", "TOO_MANY_ROWS", "VALUE_ERROR", "OTHER"), "MODEL_ERROR")
        if operation["exception_kind"] != "OTHERS" and error != "NO_DATA_FOUND":
            return {"raised": error, "assignments": [], "runtime_verified": False}
        return {"raised": None, "assignments": [{"source_item_id": identity, "value": None}
                for identity in operation["reset_order"]], "runtime_verified": False}
    _need(len(rows) == 1 and type(rows[0]) in (list, tuple) and len(rows[0]) == len(outputs), "MODEL_PROJECTION")
    return {"raised": None, "assignments": [{"source_item_id": b["source_item_id"], "value": None if value == "" else value}
            for b, value in zip(outputs, rows[0], strict=True)], "runtime_verified": False}


def model_equality(left, right):
    """Oracle NULL/empty-string equality model; no collation/coercion proof."""
    if left is None or right is None or left == "" or right == "":
        return None
    return left == right
