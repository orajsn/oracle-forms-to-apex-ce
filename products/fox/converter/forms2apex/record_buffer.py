"""Closed duplicate-record plans and a pure session-draft reference model.

No Oracle/APEX runtime is executed here. Hashes check integrity, not authority:
the assembler must rebuild from retained XML and the renderer must bind the exact
parent ZIP. The model requires an explicit binary VARCHAR2 collation assumption.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import re

from . import local_comparison
from .native_assignments import _canonical, _sha
from .native_policy_rules import _validate_catalog
from . import native_relations

SCOPE = "fox-forms-record-buffer-plan-v1"
MAX_OPERATIONS = 20
MAX_ROWS = 1000
MAX_TEXT = 16_384
_IDENT = r"[A-Z][A-Z0-9_$#]{0,127}"
_TARGET = r"[A-Z][A-Z0-9_]{0,127}"
_FLAGS = ("native_generated", "event_activated", "runtime_verified", "business_accepted")
SEMANTICS = {
    "scope": "loaded_session_drafts_only", "include_current_row_once": True,
    "concatenation": "oracle_null_empty_no_delimiter", "comparison": "varchar2_binary_nonpadded",
    "null_equals_null": False, "summary": "sum_equality_indicators_before_validation",
    "failure": "retain_candidate_draft_and_prior_other_fields_block_advance",
    "source_key": False, "row_identity": "synthetic_FOX_ROW_ID_adapter",
    "target_prerequisite": "Verify binary VARCHAR2 equality and character encoding on Oracle target.",
    "source_default_length_semantics": "Unspecified or NULL remains unresolved; adapter bounds characters and 4000 bytes without coercion.",
    "typed_input_case": "Apply declared UPPER/LOWER only to edited noninherited fields before required checks and the trigger; retain queried/internal and copied parent values. Oracle Unicode case equivalence requires target verification.",
    "business_save": False,
}


class BufferPlanError(ValueError):
    """Bounded diagnostic without customer source text."""


class UnsupportedBuffer(ValueError):
    """A whole source pipeline is outside the finite grammar."""


def _need(condition, code):
    if not condition:
        raise BufferPlanError("BUFFER_" + code)


def _unsupported(reason):
    raise UnsupportedBuffer(reason)


def _one(rows, reason):
    if len(rows) != 1:
        _unsupported(reason)
    return rows[0]


def decode_source(raw):
    """Decode numeric TAB/LF/CR outside literals, with a lossless offset receipt."""
    if type(raw) is not str or not 0 < len(raw) <= MAX_TEXT:
        _unsupported("source_size")
    out, substitutions, i, state = [], [], 0, "code"
    while i < len(raw):
        entity = re.match(r"&#(?:([0-9]+)|[xX]([0-9a-fA-F]+));", raw[i:])
        if entity:
            cp = int(entity[1], 10) if entity[1] else int(entity[2], 16)
            if state == "string" or cp not in (9, 10, 13):
                _unsupported("ambiguous_entity")
            substitutions.append({"raw_character_offset": i, "semantic_character_offset": len(out),
                                  "encoded": entity[0], "codepoint": cp})
            out.append(chr(cp))
            i += len(entity[0])
            if state == "line" and cp in (10, 13):
                state = "code"
            continue
        pair, char = raw[i:i + 2], raw[i]
        if state == "string" and pair == "''":
            out.extend(pair)
            i += 2
            continue
        if state == "string" and char == "'":
            state = "code"
        elif state == "line" and char in "\r\n":
            state = "code"
        elif state == "block" and pair == "/*":
            _unsupported("nested_comment")
        elif state == "block" and pair == "*/":
            out.extend(pair)
            i += 2
            state = "code"
            continue
        elif state == "code" and pair in ("--", "/*"):
            state = "line" if pair == "--" else "block"
            out.extend(pair)
            i += 2
            continue
        elif state == "code" and char == "'":
            state = "string"
        out.append(char)
        i += 1
    if state in ("string", "block"):
        _unsupported("unterminated_literal_or_comment")
    text = "".join(out)
    return text, {"rule": "numeric-tab-lf-cr-outside-literals-v1", "raw_sha256": _sha(raw.encode()),
                  "semantic_sha256": _sha(text.encode()), "offset_unit": "unicode_character",
                  "substitutions": substitutions}


def parse_duplicate_trigger(raw):
    """Consume only assignment, exact SUM > 1 test, literal messages and failure."""
    semantic, receipt = decode_source(raw)
    pattern = re.compile(r"\s+|--[^\r\n]*|/\*.*?\*/|'(?:''|[^'])*'|:=|\|\||" +
                         _IDENT + r"|[0-9]+|[:.,();>]", re.I | re.S)
    tokens, pos = [], 0
    while pos < len(semantic):
        match = pattern.match(semantic, pos)
        if not match:
            _unsupported("unsupported_active_token")
        token = match[0]
        pos = match.end()
        if token.isspace() or token.startswith(("--", "/*")):
            continue
        tokens.append(("string", token[1:-1].replace("''", "'")) if token.startswith("'")
                      else ("token", token.upper()))
        if len(tokens) > 512:
            _unsupported("token_capacity")
    index = 0

    def peek(value):
        return index < len(tokens) and tokens[index] == ("token", value)

    def take(value=None, kind="token"):
        nonlocal index
        if index >= len(tokens) or tokens[index][0] != kind or value is not None and tokens[index][1] != value:
            _unsupported("complete_duplicate_body_required")
        result = tokens[index][1]
        index += 1
        return result

    def reference():
        take(":")
        parts = [take()]
        if peek("."):
            take(".")
            parts.append(take())
        if any(not re.fullmatch(_IDENT, part) for part in parts):
            _unsupported("reference_identifier")
        return parts

    wrapped = peek("BEGIN")
    if wrapped:
        take("BEGIN")
    control = reference()
    take(":=")
    keys = [reference()]
    while peek("||"):
        take("||")
        keys.append(reference())
        if len(keys) > 4:
            _unsupported("key_field_capacity")
    take(";")
    take("IF")
    summary = reference()
    for value in (">", "1", "THEN"):
        take(value)
    messages = []
    while peek("MESSAGE"):
        take("MESSAGE")
        take("(")
        message = take(kind="string")
        if len(message.encode()) > 2000 or any(ord(c) < 32 for c in message):
            _unsupported("message_capacity")
        messages.append(message)
        if len(messages) > 4:
            _unsupported("message_capacity")
        take(")")
        take(";")
    if not messages:
        _unsupported("literal_warning_required")
    for value in ("RAISE", "FORM_TRIGGER_FAILURE", ";", "END", "IF", ";"):
        take(value)
    if wrapped:
        take("END")
        take(";")
    if index != len(tokens):
        _unsupported("extra_active_source")
    return {"control_ref": control, "key_refs": keys, "summary_ref": summary,
            "warnings": messages}, receipt


def operation_id(source_binding, unit_id):
    return "fb1-" + _sha(_canonical([source_binding, unit_id]))[:24]


def _relation_context(block, objects, trace, relation_plan, receipt, source_binding):
    """Recheck direct incoming source edge, native joins and rendered page receipt."""
    _need(type(relation_plan) is dict and set(relation_plan) == native_relations._ROOT,
          "RELATION_PLAN_FIELDS")
    _need(relation_plan["scope"] == native_relations.SCOPE and type(relation_plan["schema_version"]) is int
          and relation_plan["schema_version"] == 1 and relation_plan["source_binding"] == source_binding
          and all(relation_plan[k] is False for k in ("native_generated", "runtime_verified", "business_accepted"))
          and relation_plan["plan_sha256"] == _sha(_canonical({k: v for k, v in relation_plan.items() if k != "plan_sha256"}))
          and relation_plan["parent_trace_canonical_sha256"] == _sha(_canonical(trace)), "RELATION_PLAN_BINDING")
    operation = _one([op for op in relation_plan["operations"] if op["child_block_id"] == block["id"]
                      and op["source_module_id"] == block["module_id"]], "direct_incoming_relation_required")
    _need(set(operation) == native_relations._OP, "RELATION_OPERATION_FIELDS")
    _need(type(receipt) is dict and receipt.get("scope") == native_relations.RENDERER
          and receipt.get("native_generated") is True and receipt.get("runtime_verified") is False
          and receipt.get("business_accepted") is False and receipt.get("write_lifecycle") is False
          and receipt.get("source_binding") == source_binding
          and receipt.get("plan_sha256") == relation_plan["plan_sha256"]
          and receipt.get("plan_artifact_sha256") == _sha(_canonical(relation_plan)), "RELATION_RECEIPT_BINDING")
    parent = objects[operation["parent_block_id"]]
    relation = objects[operation["relation_id"]]
    attrs = relation["metadata"]
    if (relation["kind"] != "Relation" or relation["parent_id"] != parent["id"]
            or relation["block_id"] != parent["id"] or parent["classification"] != "database"
            or relation["module_id"] != parent["module_id"] or parent["module_id"] != block["module_id"]
            or attrs.get("DetailBlock", "").upper() != block["name"].upper()
            or attrs.get("RelationType", "").upper() != "JOIN"
            or operation["source_attribute_sha256"] != _sha(_canonical(attrs))):
        _unsupported("relation_source_mismatch")
    # Other source declarations make context ambiguous even if absent in the plan.
    competing = [obj for obj in objects.values() if obj["kind"] == "Relation"
                 and obj["module_id"] == block["module_id"] and (obj["parent_id"] == parent["id"]
                 or obj["metadata"].get("DetailBlock", "").upper() == block["name"].upper())]
    if len(competing) != 1:
        _unsupported("ambiguous_source_relation")
    if operation["source_flags"] != {k: attrs.get(k) for k in native_relations._FLAGS}:
        _unsupported("relation_flags_mismatch")
    join_text, _ = decode_source(attrs.get("JoinCondition", ""))
    terms = re.split(r"\bAND\b", join_text, flags=re.I)
    expected = []
    if not 1 <= len(terms) <= 4:
        _unsupported("relation_join_unsupported")
    for term in terms:
        match = re.fullmatch(rf"\s*({_IDENT})\s*\.\s*({_IDENT})\s*=\s*({_IDENT})\s*\.\s*({_IDENT})\s*", term, re.I)
        if not match:
            _unsupported("relation_join_unsupported")
        a, x, b, y = (value.upper() for value in match.groups())
        if (a, b) == (block["name"].upper(), parent["name"].upper()):
            x, y = y, x
        elif (a, b) != (parent["name"].upper(), block["name"].upper()):
            _unsupported("relation_join_scope")
        fields = []
        for source_block, name in ((parent, x), (block, y)):
            item = _one([obj for obj in objects.values() if obj["kind"] == "Item"
                         and obj["block_id"] == source_block["id"] and (obj["name"] or "").upper() == name],
                        "relation_item_not_unique")
            props = item["metadata"]
            dtype = {"CHAR": "VARCHAR2", "VARCHAR2": "VARCHAR2", "NUMBER": "NUMBER"}.get(props.get("DataType", "").upper())
            if (item["database_item"] is not True or dtype is None or props.get("Formula", "").strip()
                    or any(props.get(k, "").upper() not in ("", "NONE") for k in
                           ("CalculateMode", "CalculationMode", "SummaryFunction"))):
                _unsupported("relation_direct_field_required")
            mapped = _one([row for row in trace["blocks"] if row["source_block_id"] == source_block["id"]], "relation_trace_block")
            field = _one([row for row in mapped["items"] if row["source_item_id"] == item["id"]], "relation_trace_field")
            if field["data_type"] != dtype or field["source_name"] != item["name"]:
                _unsupported("relation_trace_type")
            fields.append((item["id"], field["column"], dtype))
        if fields[0][2] != fields[1][2]:
            _unsupported("relation_join_type")
        expected.append({"parent_item_id": fields[0][0], "parent_column": fields[0][1],
                         "child_item_id": fields[1][0], "child_column": fields[1][1], "data_type": fields[0][2]})
    if operation["join_pairs"] != expected:
        _unsupported("relation_join_binding")
    for label, source_block in (("parent", parent), ("child", block)):
        mapped = _one([row for row in trace["blocks"] if row["source_block_id"] == source_block["id"]], "relation_native_block")
        expected_target = {"table": mapped["table_name"], "report_file": mapped["report_file"],
                           "report_page_id": mapped["report_page_id"], "row_id_column": "FOX_ROW_ID"}
        if (operation[label] != expected_target or mapped["source_module_id"] != block["module_id"]
                or mapped["name"] != source_block["name"] or mapped["synthetic_key"].get("source_derived") is not False
                or mapped["synthetic_key"].get("source_item_id") is not None
                or mapped["synthetic_key"].get("column") != "FOX_ROW_ID"):
            _unsupported("relation_native_target")
    generated_rows = [row for row in receipt["generated_operations"] if row["relation_id"] == relation["id"]]
    _need(len(generated_rows) == 1, "RELATION_NATIVE_PAGE_REQUIRED")
    generated = generated_rows[0]
    page = generated.get("page_id")
    if (type(page) is not int or not 0 < page < 9000 or generated.get("generation_status") != "read_navigation_generated"
            or generated.get("source_module_id") != block["module_id"] or generated.get("parent_block_id") != parent["id"]
            or generated.get("child_block_id") != block["id"] or generated.get("write_lifecycle") is not False
            or generated.get("parent_report_file") != operation["parent"]["report_file"]
            or generated.get("page_file") != f"pages/p{page:05d}-fox_relation_{page}.apx"
            or generated.get("parent_item") != f"P{page}_PARENT_ID"):
        raise BufferPlanError("BUFFER_RELATION_NATIVE_PAGE_BINDING")
    return {**deepcopy(operation), "page_file": generated["page_file"], "page_id": page,
            "parent_item": generated["parent_item"], "row_identity_source_derived": False}


def derive_buffer_operations(catalog, trace, source_binding, relation_plan, relation_receipt):
    """Re-derive whole pipelines; supporting units add no conversion claims.

    Existing behavior coverage owns any previous formula/helper status. This
    plan accounts for each source unit once and claims only the new whole event.
    """
    objects = _validate_catalog(catalog, trace)
    units = catalog["units"]
    by_owner = {}
    for unit in units:
        by_owner.setdefault(unit["owner_id"], []).append(unit)
    counts = Counter((obj["module_id"], obj["parent_id"], (obj["name"] or "").upper())
                     for obj in objects.values() if obj["kind"] == "Trigger")

    def resolve(parts, owner):
        found = [obj for obj in objects.values() if obj["kind"] == "Item" and obj["module_id"] == owner["module_id"]
                 and (obj["name"] or "").upper() == parts[-1]]
        if len(parts) == 2:
            found = [obj for obj in found if (objects[obj["block_id"]]["name"] or "").upper() == parts[0]]
        else:
            local = [obj for obj in found if obj["block_id"] == owner["block_id"]]
            if local:
                found = local
        return _one(found, "source_item_reference_not_unique")

    def bind(item, kind):
        block = objects[item["block_id"]]
        props = item["metadata"]
        # Undeclared collation is a target prerequisite, never evidence it holds.
        for obj in (objects[item["module_id"]], block, item):
            if any(("COLLATION" in k.upper() or k.upper() in ("NLS_COMP", "NLS_SORT"))
                   and v.strip().upper() not in ("", "BINARY") for k, v in obj["metadata"].items()):
                _unsupported("source_collation_unsupported")
        source_type = props.get("DataType", "").upper()
        dtype = {"CHAR": "VARCHAR2", "VARCHAR2": "VARCHAR2", "NUMBER": "NUMBER"}.get(source_type)
        mapped = _one([row for row in trace["blocks"] if row["source_block_id"] == block["id"]], "trace_block_not_unique")
        field = _one([row for row in mapped["items"] if row["source_item_id"] == item["id"]], "trace_item_not_unique")
        if (dtype is None or mapped["source_module_id"] != block["module_id"] or mapped["name"] != block["name"]
                or mapped["classification"] != block["classification"] or field["source_name"] != item["name"]
                or field["data_type"] != dtype):
            _unsupported("native_source_type_binding")
        if kind == "key":
            if (block["classification"] != "database" or item["database_item"] is not True
                    or field["database_bound"] is not True or not re.fullmatch(_TARGET, field.get("column") or "")
                    or field.get("value_computation_implemented") is True):
                _unsupported("direct_native_database_key_required")
        elif kind in ("control", "summary"):
            page = mapped.get("page_id")
            if (block["classification"] != "control" or item["database_item"] is not False
                    or field["database_bound"] is not False or field.get("column") is not None
                    or type(page) is not int or not 0 < page < 9000
                    or field.get("native_item_page_id") != page
                    or not re.fullmatch(rf"P{page}_[A-Z0-9_]+", field.get("native_item") or "")):
                _unsupported("native_control_binding_required")
        elif kind == "formula" and (block["classification"] != "database" or item["database_item"] is not False):
            _unsupported("formula_same_database_block_required")
        maximum, semantics = None, props.get("DataLengthSemantics", "").strip().upper()
        case_restriction = {"": "NONE", "NONE": "NONE", "MIXED": "NONE", "UPPER": "UPPER", "LOWER": "LOWER"}.get(
            props.get("CaseRestriction", "").strip().upper())
        required_text = props.get("Required", "false").strip().lower()
        if case_restriction is None or required_text not in ("true", "false"):
            _unsupported("source_input_property_unsupported")
        if semantics not in ("", "NULL", "BYTE", "CHAR"):
            _unsupported("source_length_semantics_unsupported")
        if dtype == "VARCHAR2":
            value = props.get("MaximumLength", "")
            if not re.fullmatch(r"[0-9]{1,4}", value) or not 0 < int(value) <= 666:
                _unsupported("character_length_required_or_too_large")
            maximum = int(value)
            if props.get("Formula", "").strip() or any(props.get(k, "").upper() not in ("", "NONE")
                    for k in ("CalculateMode", "CalculationMode", "SummaryFunction")):
                _unsupported("direct_character_field_required")
        return {"source_item_id": item["id"], "source_block_id": block["id"], "source_module_id": block["module_id"],
                "source_item_name": item["name"], "source_block_name": block["name"], "source_data_type": source_type,
                "data_type": dtype, "max_length": maximum, "source_length_semantics": semantics,
                "case_restriction": case_restriction, "required": required_text == "true",
                "max_bytes": maximum * 6 if maximum is not None else None,
                "column": field.get("column"), "native_item": field.get("native_item"),
                "native_page_id": mapped.get("page_id"), "native_page_file": mapped.get("page_file")}

    def proof(unit):
        _, decode = decode_source(unit["text"])
        return {"source_unit_id": unit["id"], "source_unit_sha256": unit["sha256"],
                "source_chunk_id": unit["chunk_id"], "source_owner_id": unit["owner_id"],
                "source_attribute": unit["source_attribute"], "source_location": deepcopy(unit["location"]),
                "source_unit_text": unit["text"], "decode_receipt": decode}

    operations, coverage = [], []
    for unit in units:
        owner = objects[unit["owner_id"]]
        row = {"source_unit_id": unit["id"], "source_unit_sha256": unit["sha256"],
               "source_chunk_id": unit["chunk_id"], "source_owner_id": owner["id"],
               "source_location": deepcopy(unit["location"]), "status": "unsupported",
               "reason": "outside_duplicate_record_pipeline", "native_generated": False,
               "runtime_verified": False, "business_accepted": False}
        coverage.append(row)
        try:
            if owner["kind"] != "Trigger" or (owner["name"] or "").upper() != "WHEN-VALIDATE-RECORD":
                continue
            block = objects.get(owner["parent_id"])
            if (block is None or block["kind"] != "Block" or block["classification"] != "database"
                    or owner["block_id"] != block["id"] or unit["source_attribute"] != "TriggerText"
                    or len(by_owner[owner["id"]]) != 1
                    or counts[(owner["module_id"], block["id"], "WHEN-VALIDATE-RECORD")] != 1):
                _unsupported("one_direct_block_validation_trigger_required")
            parsed, decode = parse_duplicate_trigger(unit["text"])
            key_items = [resolve(parts, owner) for parts in parsed["key_refs"]]
            if len({item["id"] for item in key_items}) != len(key_items):
                _unsupported("repeated_key_reference_unsupported")
            if any(item["block_id"] != block["id"] for item in key_items):
                _unsupported("same_block_key_required")
            key_bindings = [bind(item, "key") for item in key_items]
            if any(binding["data_type"] != "VARCHAR2" for binding in key_bindings):
                _unsupported("varchar2_key_required")
            if sum(binding["max_bytes"] for binding in key_bindings) > 4000:
                _unsupported("concatenation_exceeds_4000_bytes")
            control_item, summary_item = [resolve(parsed[key], owner) for key in ("control_ref", "summary_ref")]
            control, summary = bind(control_item, "control"), bind(summary_item, "summary")
            if control["data_type"] != "VARCHAR2" or summary["data_type"] != "NUMBER":
                _unsupported("typed_control_key_and_numeric_summary_required")
            if sum(binding["max_length"] for binding in key_bindings) > control["max_length"]:
                _unsupported("source_control_key_capacity")
            summary_props = summary_item["metadata"]
            if (summary_props.get("CalculateMode", "").upper() != "SUMMARY"
                    or summary_props.get("SummaryFunction", "").upper() != "SUM"
                    or summary_props.get("SummaryBlockName", "").upper() != block["name"].upper()
                    or summary_props.get("Formula", "").strip()
                    or summary_props.get("CalculationMode", "").upper() not in ("", "SUMMARY")):
                _unsupported("exact_source_sum_metadata_required")
            formula_item = resolve([block["name"].upper(), summary_props.get("SummaryItemName", "").upper()], owner)
            formula_binding = bind(formula_item, "formula")
            props = formula_item["metadata"]
            if (formula_binding["data_type"] != "NUMBER" or props.get("CalculateMode", "").upper() != "FORMULA"
                    or props.get("CalculationMode", "").upper() not in ("", "FORMULA")
                    or props.get("SummaryFunction", "").upper() not in ("", "NONE")):
                _unsupported("exact_source_formula_metadata_required")
            formula_unit = _one([u for u in by_owner.get(formula_item["id"], []) if u["source_attribute"] == "Formula"],
                                "whole_formula_unit_required")
            semantic, _ = decode_source(formula_unit["text"])
            call = local_comparison.parse_call(semantic)
            expected_args = [[control_item["id"]], [item["id"] for item in key_items]]
            actual_args = []
            for arg in call["args"]:
                if any(part["kind"] != "reference" for part in arg["parts"]):
                    _unsupported("formula_exact_direct_arguments_required")
                actual_args.append([resolve(part["parts"], formula_item)["id"] for part in arg["parts"]])
            if actual_args != expected_args:
                _unsupported("formula_argument_order_or_key_mismatch")
            helper = _one([obj for obj in objects.values() if obj["kind"] == "ProgramUnit"
                           and obj["module_id"] == owner["module_id"] and (obj["name"] or "").upper() == call["function"]],
                          "one_module_local_helper_required")
            helper_unit = _one(by_owner.get(helper["id"], []), "whole_helper_unit_required")
            if helper_unit["source_attribute"] != "ProgramUnitText":
                _unsupported("whole_helper_body_required")
            semantic, _ = decode_source(helper_unit["text"])
            definition = local_comparison.parse_function(semantic)
            if definition["function_name"] != call["function"]:
                _unsupported("helper_identity_mismatch")
            relation = _relation_context(block, objects, trace, relation_plan, relation_receipt, source_binding)
            for item, binding in zip(key_items, key_bindings):
                copy_from = item["metadata"].get("CopyValueFromItem", "").strip()
                if not copy_from:
                    continue
                match = re.fullmatch(rf"({_IDENT})\.({_IDENT})", copy_from, re.I)
                if not match:
                    _unsupported("parent_copy_direct_reference_required")
                parent_item = resolve([part.upper() for part in match.groups()], item)
                pair = _one([pair for pair in relation["join_pairs"]
                             if pair["child_item_id"] == item["id"]
                             and pair["parent_item_id"] == parent_item["id"]],
                            "parent_copy_direct_join_pair_required")
                parent_binding = bind(parent_item, "key")
                if (parent_item["block_id"] != relation["parent_block_id"]
                        or parent_item["module_id"] != item["module_id"]
                        or parent_binding["data_type"] != binding["data_type"]
                        or pair["parent_column"] != parent_binding["column"]
                        or pair["child_column"] != binding["column"]
                        or not re.fullmatch(_TARGET, pair["parent_column"])):
                    _unsupported("parent_copy_native_binding_mismatch")
                # Parent values are checked against the child's declared bounds at
                # draft creation. A wider parent is never silently truncated.
                binding["parent_copy"] = {"parent_column": pair["parent_column"],
                                          "parent_item_id": parent_item["id"]}
            if len(operations) >= MAX_OPERATIONS:
                _unsupported("operation_capacity")
            operation = {"operation_id": operation_id(source_binding, unit["id"]), "source_binding": source_binding,
                         "kind": "loaded_draft_duplicate_record", "source_module_id": owner["module_id"],
                         "source_block_id": block["id"], "source_event": "WHEN-VALIDATE-RECORD",
                         **proof(unit), "key_bindings": key_bindings, "control_key": control, "summary": summary,
                         "formula": {"binding": formula_binding, "expression": call, **proof(formula_unit)},
                         "helper": {"function_name": call["function"], "definition": definition, **proof(helper_unit)},
                         "supporting_units": [formula_unit["id"], helper_unit["id"]],
                         "warnings": parsed["warnings"], "relation": relation,
                         "summary_metadata": {key: props_value for key, props_value in summary_props.items()
                                              if key.startswith("Summary") or key in ("CalculateMode", "CalculationMode", "DataType")},
                         "concat_max_bytes": sum(binding["max_bytes"] for binding in key_bindings),
                         "semantics": deepcopy(SEMANTICS)}
            operations.append(operation)
            row.update(status="planned_wired_adapted", reason="whole_validation_pipeline_planned_not_rendered",
                       operation_id=operation["operation_id"])
        except (UnsupportedBuffer, local_comparison.ComparisonError) as exc:
            row["reason"] = str(exc)
    supports = {identity for op in operations for identity in op["supporting_units"]}
    for row in coverage:
        if row["source_unit_id"] in supports and row["status"] == "unsupported":
            row.update(status="supporting_unit_not_counted", reason="support_only_not_additional_conversion")
    return operations, coverage


_ROOT = {"schema_version", "scope", "source_binding", "parent_zip_sha256", "source_manifest_sha256",
         "parent_trace_sha256", "trace_sha256", "relation_plan_sha256", "relation_receipt_sha256",
         "sources", "source_catalog", "parent_trace", "relation_plan", "relation_receipt", "operations",
         "coverage", "code_unit_count", "native_generated", "event_activated", "runtime_verified",
         "business_accepted", "plan_sha256"}


def validate_buffer_plan(plan):
    """Validate closed fields, source hashes and freshly re-derived full-body IR."""
    _need(type(plan) is dict and set(plan) == _ROOT, "PLAN_FIELDS")
    _need(type(plan["schema_version"]) is int and plan["schema_version"] == 1 and plan["scope"] == SCOPE, "PLAN_VERSION")
    _need(len(_canonical(plan)) <= 16_000_000, "PLAN_CAPACITY")
    for key in ("source_binding", "parent_zip_sha256", "source_manifest_sha256", "parent_trace_sha256",
                "trace_sha256", "relation_plan_sha256", "relation_receipt_sha256", "plan_sha256"):
        _need(type(plan[key]) is str and re.fullmatch(r"[0-9a-f]{64}", plan[key]), "DIGEST")
    _need(all(plan[key] is False for key in _FLAGS), "FALSE_CLAIMS")
    _need(plan["plan_sha256"] == _sha(_canonical({k: v for k, v in plan.items() if k != "plan_sha256"})), "PLAN_CHANGED")
    _need(type(plan["sources"]) is list and 1 <= len(plan["sources"]) <= 4, "SOURCES")
    names = set()
    for source in plan["sources"]:
        _need(type(source) is dict and set(source) == {"name", "sha256", "bytes"}, "SOURCE_FIELDS")
        name = source["name"]
        _need(type(name) is str and 0 < len(name) <= 180 and name.lower().endswith(".xml")
              and not any(c in name for c in "/\\:") and ".." not in name
              and not any(ord(c) < 32 for c in name) and name.casefold() not in names
              and type(source["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", source["sha256"])
              and type(source["bytes"]) is int and 0 < source["bytes"] <= 5 * 1024 * 1024, "SOURCE_IDENTITY")
        names.add(name.casefold())
    for key, digest in (("parent_trace", "trace_sha256"), ("relation_plan", "relation_plan_sha256"),
                        ("relation_receipt", "relation_receipt_sha256")):
        _need(type(plan[key]) is dict and _sha(_canonical(plan[key])) == plan[digest], "PARENT_PROOF_CHANGED")
    _need(plan["parent_trace"].get("source_binding") == plan["source_binding"]
          and plan["relation_plan"].get("sources") == plan["sources"], "PARENT_SOURCE_BINDING")
    try:
        operations, coverage = derive_buffer_operations(plan["source_catalog"], plan["parent_trace"], plan["source_binding"],
                                                       plan["relation_plan"], plan["relation_receipt"])
    except (KeyError, TypeError, IndexError):
        raise BufferPlanError("BUFFER_SOURCE_PROOF_INVALID") from None
    _need(type(plan["code_unit_count"]) is int and plan["code_unit_count"] == len(coverage), "UNIT_COUNT")
    _need(_canonical(operations) == _canonical(plan["operations"])
          and _canonical(coverage) == _canonical(plan["coverage"]), "SOURCE_IR_MISMATCH")
    return deepcopy(plan)


class BufferState:
    """Pure draft model, with explicit context/revision and no customer-table save.

    Rows are closed records {row_id, values}; values use exact native columns.
    Inherited join keys require separate authoritative nonnull parent_values,
    keyed by parent columns, and must fit the child's declared value bounds.
    Failed validation retains the candidate overlay and other fields, increments
    revision, and keeps current_row_id. Unsupported/stale requests change nothing.
    """

    def __init__(self, plan, operation, *, parent_id, rows, current_row_id=None, collation=None,
                 parent_values=None):
        self.plan = validate_buffer_plan(plan)
        matches = [op for op in self.plan["operations"] if op["operation_id"] == operation]
        _need(len(matches) == 1, "MODEL_OPERATION")
        _need(collation == "BINARY", "MODEL_COLLATION_PREREQUISITE")
        _need(type(parent_id) is int and parent_id > 0, "MODEL_PARENT_ID")
        self.op, self.parent_id, self.revision = matches[0], parent_id, 0
        inherited = [binding for binding in self.op["key_bindings"] if "parent_copy" in binding]
        columns = {binding["parent_copy"]["parent_column"] for binding in inherited}
        if parent_values is None and not inherited:
            parent_values = {}
        _need(type(parent_values) is dict and set(parent_values) == columns, "MODEL_PARENT_VALUES")
        self._parent_values = self._values({binding["column"]: parent_values[binding["parent_copy"]["parent_column"]]
                                            for binding in inherited}, partial=True)
        _need(all(value is not None for value in self._parent_values.values()), "MODEL_PARENT_COPY_NULL")
        self.rows = {}
        _need(type(rows) is list and len(rows) <= MAX_ROWS, "MODEL_ROWS")
        for row in rows:
            _need(type(row) is dict and set(row) == {"row_id", "values"}
                  and type(row["row_id"]) is int and row["row_id"] > 0 and row["row_id"] not in self.rows,
                  "MODEL_ROW_ID")
            self.rows[row["row_id"]] = self._values(row["values"])
            self._check_parent_copy(self.rows[row["row_id"]])
        if not self.rows:
            self.rows[1] = self._new_values()
        self.current_row_id = next(iter(self.rows), None) if current_row_id is None else current_row_id
        _need(self.current_row_id is None and not self.rows or type(self.current_row_id) is int
              and self.current_row_id in self.rows, "MODEL_CURRENT_ROW")

    def _values(self, values, *, partial=False, typed_input=False):
        bindings = {row["column"]: row for row in self.op["key_bindings"]}
        _need(type(values) is dict and set(values) <= set(bindings)
              and (partial or set(values) == set(bindings)), "MODEL_UNSUPPORTED_MUTATION")
        result = {}
        for column, value in values.items():
            binding = bindings[column]
            _need(value is None or type(value) is str, "MODEL_VALUE_TYPE")
            if (value is not None and typed_input and "parent_copy" not in binding
                    and binding["case_restriction"] != "NONE"):
                # Python Unicode casing is not proof of Oracle NLS behavior.
                # Only ASCII is normalized; uncased non-ASCII is unchanged.
                _need(not any(ord(c) > 127 and c.upper() != c.lower() for c in value),
                      "MODEL_UNICODE_CASE_PREREQUISITE")
                value = value.translate(str.maketrans("abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
                                        if binding["case_restriction"] == "UPPER" else
                                        str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"))
            if value is not None:
                _need(len(value) <= binding["max_length"] and len(value.encode()) <= binding["max_bytes"], "MODEL_VALUE_LENGTH")
                if binding["source_length_semantics"] == "BYTE":
                    _need(len(value.encode()) <= binding["max_length"], "MODEL_VALUE_BYTE_LENGTH")
            result[column] = None if value == "" else value
        return result

    def _new_values(self):
        return {binding["column"]: self._parent_values.get(binding["column"])
                for binding in self.op["key_bindings"]}

    def _check_parent_copy(self, values):
        _need(all(values[column] == value for column, value in self._parent_values.items()),
              "MODEL_PARENT_COPY_MISMATCH")

    def snapshot(self):
        return {"source_binding": self.plan["source_binding"], "operation_id": self.op["operation_id"],
                "source_module_id": self.op["source_module_id"], "parent_id": self.parent_id,
                "revision": self.revision, "current_row_id": self.current_row_id,
                "rows": [{"row_id": row_id, "values": deepcopy(values)} for row_id, values in self.rows.items()]}

    def _key(self, values, *, assigned_control=False):
        value = "".join(values[binding["column"]] or "" for binding in self.op["key_bindings"])
        _need(len(value.encode()) <= 4000, "MODEL_CONCAT_LENGTH")
        if assigned_control:
            control = self.op["control_key"]
            _need(len(value) <= control["max_length"], "MODEL_CONTROL_LENGTH")
            if control["source_length_semantics"] == "BYTE":
                _need(len(value.encode()) <= control["max_length"], "MODEL_CONTROL_BYTE_LENGTH")
        return value or None

    def submit(self, changes, *, revision, parent_id, source_module_id, action="keep"):
        """Overlay current draft, recalculate all loaded rows, block movement on >1."""
        _need(type(revision) is int and revision == self.revision, "MODEL_STALE_REVISION")
        _need(type(parent_id) is int and parent_id == self.parent_id
              and source_module_id == self.op["source_module_id"], "MODEL_CONTEXT")
        _need(action in ("keep", "previous", "next", "new"), "MODEL_ACTION")
        _need(self.current_row_id is not None, "MODEL_CURRENT_ROW")
        if action == "new":
            _need(len(self.rows) < MAX_ROWS, "MODEL_ROW_CAPACITY")
        overlay = self._values(changes, partial=True, typed_input=True)
        candidate = {**self.rows[self.current_row_id], **overlay}
        self._check_parent_copy(candidate)
        for values in self.rows.values():
            self._check_parent_copy(values)
        _need(all(not binding["required"] or candidate[binding["column"]] is not None
                  for binding in self.op["key_bindings"]), "MODEL_REQUIRED_INPUT")
        candidate_key = self._key(candidate, assigned_control=True)
        # Recalculation sees edited drafts and includes current row exactly once.
        draft_rows = {**self.rows, self.current_row_id: candidate}
        indicators = {row_id: int(candidate_key is not None and self._key(values) == candidate_key)
                      for row_id, values in draft_rows.items()}
        count = sum(indicators.values())
        accepted = count <= 1
        previous_row_id = self.current_row_id
        self.rows[self.current_row_id] = candidate
        self.revision += 1
        if accepted:
            row_ids = list(self.rows)
            index = row_ids.index(self.current_row_id)
            if action == "previous" and index:
                self.current_row_id = row_ids[index - 1]
            elif action == "next" and index + 1 < len(row_ids):
                self.current_row_id = row_ids[index + 1]
            elif action == "new":
                self.current_row_id = max(self.rows, default=0) + 1
                self.rows[self.current_row_id] = self._new_values()
        return {"accepted": accepted, "advanced": self.current_row_id != previous_row_id,
                "warnings": [] if accepted else deepcopy(self.op["warnings"]), "summary": count,
                "indicators": indicators, "control_key": candidate_key, "state": self.snapshot(),
                "runtime_verified": False, "business_accepted": False}
