"""Closed, source-bound behavior planning; no SQL execution or runtime claims.

Only finite whole-source grammars are supported. Original XML/chunks are immutable;
control-entity decoding has a separate receipt. The parent ZIP is bound by digest,
not authenticated: its trusted baseline remains the integration caller's gate.
"""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import PurePosixPath
import re
import stat
import zipfile

from . import forms_facts
from .forms_understanding_packet import _build
from forms2apex import numeric_expression
from forms2apex.native_behavior import MAX_OPERATIONS

SCOPE = "fox-forms-behavior-plan-v1"
_IDENT = re.compile(r"[A-Za-z][A-Za-z0-9_$#]{0,127}\Z")
_ENTITY = re.compile(r"&#(?:([0-9]+)|[xX]([0-9a-fA-F]+));")
_NUMBER = re.compile(r"[+-]?[0-9]+(?:\.[0-9]+)?\Z")


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


class UnsupportedBehavior(ValueError):
    """A complete source unit does not belong to the finite supported grammar."""


def decode_control_entities(raw):
    """Decode only numeric TAB/LF/CR outside literals, including inside comments.

    Quote/comment state follows the decoded stream, so an encoded LF terminates
    a line comment. Offsets refer to Python characters, not XML byte positions.
    Numeric entities inside literals are ambiguous and never interpreted.
    """
    out, substitutions, i, state = [], [], 0, "code"
    while i < len(raw):
        entity = _ENTITY.match(raw, i)
        if entity:
            if state == "string":
                raise UnsupportedBehavior("numeric_entity_inside_literal")
            cp = int(entity.group(1), 10) if entity.group(1) else int(entity.group(2), 16)
            if cp not in (9, 10, 13):
                raise UnsupportedBehavior("unsupported_numeric_entity")
            char = chr(cp)
            substitutions.append({"raw_character_offset": i,
                                  "semantic_character_offset": len(out),
                                  "encoded": entity.group(), "codepoint": cp})
            out.append(char)
            i = entity.end()
            if state == "line" and char in "\r\n":
                state = "code"
            continue
        char = raw[i]
        pair = raw[i:i + 2]
        if state == "string":
            if pair == "''":
                out.extend(pair)
                i += 2
                continue
            if char == "'":
                state = "code"
        elif state == "line":
            if char in "\r\n":
                state = "code"
        elif state == "block":
            if pair == "*/":
                out.extend(pair)
                i += 2
                state = "code"
                continue
        elif pair in ("--", "/*"):
            state = "line" if pair == "--" else "block"
            out.extend(pair)
            i += 2
            continue
        elif char == "'":
            state = "string"
        out.append(char)
        i += 1
    if state in ("string", "block"):
        raise UnsupportedBehavior("unterminated_literal_or_comment")
    text = "".join(out)
    return text, {"rule": "numeric-tab-lf-cr-outside-literals-v1",
                  "raw_sha256": _hash(raw.encode()),
                  "semantic_sha256": _hash(text.encode()),
                  "offset_unit": "unicode_character", "substitutions": substitutions}


def _tokens(text):
    tokens, i = [], 0
    while i < len(text):
        if text[i].isspace():
            i += 1
        elif text.startswith("--", i):
            i += 2
            while i < len(text) and text[i] not in "\r\n":
                i += 1
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0 or "/*" in text[i + 2:end]:
                raise UnsupportedBehavior("ambiguous_block_comment")
            i = end + 2
        elif text[i] == "'":
            i += 1
            value = []
            while i < len(text):
                if text.startswith("''", i):
                    value.append("'")
                    i += 2
                elif text[i] == "'":
                    i += 1
                    break
                else:
                    value.append(text[i])
                    i += 1
            else:
                raise UnsupportedBehavior("unterminated_literal")
            tokens.append(("string", "".join(value)))
        elif text[i].isascii() and (text[i].isalpha() or text[i] in "_$#"):
            match = re.match(r"[A-Za-z_$#][A-Za-z0-9_$#]*", text[i:])
            tokens.append(("word", match.group().upper()))
            i += len(match.group())
        elif text[i] in ":.,();=":
            tokens.append(("symbol", text[i]))
            i += 1
        elif text[i].isascii() and text[i].isdigit():
            match = re.match(r"[0-9]+", text[i:])
            tokens.append(("number", match.group()))
            i += len(match.group())
        else:
            raise UnsupportedBehavior("unsupported_active_token")
    return tokens


class _Parser:
    def __init__(self, tokens):
        self.tokens, self.pos = tokens, 0

    def peek(self, value):
        return self.pos < len(self.tokens) and self.tokens[self.pos][1] == value

    def take(self, value=None, kind=None):
        if self.pos >= len(self.tokens):
            raise UnsupportedBehavior("incomplete_source_pattern")
        token = self.tokens[self.pos]
        if value is not None and kind is None:
            kind = "number" if value.isdigit() else "word" if _IDENT.fullmatch(value) else "symbol"
        if (value is not None and token[1] != value) or (kind is not None and token[0] != kind):
            raise UnsupportedBehavior("unsupported_complete_source_pattern")
        self.pos += 1
        return token[1]

    def reference(self):
        self.take(":")
        parts = [self.take(kind="word")]
        if self.peek("."):
            self.take(".")
            parts.append(self.take(kind="word"))
        return parts

    def end(self):
        if self.pos != len(self.tokens):
            raise UnsupportedBehavior("extra_active_source")


def _recognize(unit, owner, text):
    if unit["source_attribute"] == "Formula" and owner["kind"] == "Item":
        try:
            expression = numeric_expression.parse_expression(text)
        except numeric_expression.NumericExpressionError as exc:
            raise UnsupportedBehavior(str(exc)) from None
        root = expression["root"]
        if (root["kind"] == "call" and root["function"] == "CEIL"
                and root["args"][0]["kind"] == "reference"):
            return {"kind": "ceil_report_column", "reference": root["args"][0]["parts"]}
        return {"kind": "numeric_expression_report_column", "expression": expression}
    parser = _Parser(_tokens(text))
    if (owner["kind"] != "Trigger" or owner["name"] is None
            or owner["name"].upper() != "KEY-NEXT-ITEM"
            or unit["source_attribute"] != "TriggerText"):
        raise UnsupportedBehavior("unsupported_unit_kind")
    declared = parser.peek("DECLARE")
    if declared:
        parser.take("DECLARE")
        variable = parser.take(kind="word")
        if (not _IDENT.fullmatch(variable) or variable in {
                "DECLARE", "BEGIN", "END", "IF", "THEN", "ELSE", "ELSIF", "NUMBER",
                "LOOP", "EXCEPTION", "WHEN", "NULL", "SELECT", "FROM", "WHERE", "INSERT",
                "INTO", "UPDATE", "DELETE", "TABLE", "COMMIT", "ROLLBACK", "RETURN",
                "CREATE", "TRIGGER", "PROCEDURE", "FUNCTION", "AS", "IS", "OR", "AND", "NOT"}):
            raise UnsupportedBehavior("unsupported_declaration_identifier")
        parser.take("NUMBER")
        parser.take(";")
    wrapped = parser.peek("BEGIN")
    if wrapped:
        parser.take("BEGIN")
    elif declared:
        raise UnsupportedBehavior("declaration_requires_begin")
    for value in ("IF", "NVL", "("):
        parser.take(value)
    reference = parser.reference()
    for value in (",", "0", ")", "=", "0", "THEN"):
        parser.take(value)
    messages = []
    while parser.peek("MESSAGE") and len(messages) < 2:
        parser.take("MESSAGE")
        parser.take("(")
        messages.append(parser.take(kind="string"))
        parser.take(")")
        parser.take(";")
    if not messages or len(set(messages)) != 1:
        raise UnsupportedBehavior("message_calls_must_match")
    for value in ("RAISE", "FORM_TRIGGER_FAILURE", ";", "END", "IF", ";", "GO_ITEM", "("):
        parser.take(value)
    focus = parser.take(kind="string")
    parser.take(")")
    parser.take(";")
    if wrapped:
        parser.take("END")
        parser.take(";")
    parser.end()
    message = messages[0]
    if (not 0 < len(message) <= 1000 or any(ord(c) < 32 for c in message)
            or any(c in message for c in "`&<>")
            or re.search(r"&[A-Za-z0-9_$#]+\.", message)):
        raise UnsupportedBehavior("message_is_not_inert_plain_text")
    parts = focus.split(".")
    if not 1 <= len(parts) <= 2 or not all(_IDENT.fullmatch(part) for part in parts):
        raise UnsupportedBehavior("focus_is_not_item_reference")
    return {"kind": "numeric_nonzero_then_focus", "reference": reference,
            "focus_reference": [part.upper() for part in parts],
            "message": message, "message_call_count": len(messages)}


def _json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate parent JSON key.")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def _parent(raw, packet, chunks):
    if type(raw) is not bytes or not 0 < len(raw) <= 50_000_000:
        raise ValueError("Parent ZIP must be bounded original bytes.")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if (len(infos) > 4096 or len(set(names)) != len(names)
                or len({name.casefold() for name in names}) != len(names)
                or sum(info.file_size for info in infos) > 100_000_000):
            raise ValueError("Unsafe or duplicate parent ZIP members.")
        for info in infos:
            path = PurePosixPath(info.filename)
            if (path.is_absolute() or ".." in path.parts or "\\" in info.filename
                    or ":" in info.filename or stat.S_ISLNK(info.external_attr >> 16)):
                raise ValueError("Unsafe parent ZIP member path.")
        members = {info.filename: archive.read(info) for info in infos}
    try:
        manifest_raw = members["fox-package/source-manifest.json"]
        trace_raw = members["fox-package/source-to-page.json"]
        manifest, trace = _json(manifest_raw), _json(trace_raw)
        schema = members["fox-package/supporting-schema.sql"].decode("utf-8")
    except (KeyError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Parent package provenance is incomplete.") from exc
    files = [{key: entry["source"][key] for key in ("name", "sha256", "bytes")}
             for entry in packet["sources"]]
    if (manifest.get("source_binding") != packet["source_binding"]
            or trace.get("source_binding") != packet["source_binding"]
            or manifest.get("files") != files):
        raise ValueError("Parent manifest does not match fresh original sources.")
    available = {chunk["id"]: chunk["sha256"] for chunk in chunks}
    selected = manifest.get("selected_chunk_hashes")
    if type(selected) is not dict or any(key not in available or available[key] != value
                                         for key, value in selected.items()):
        raise ValueError("Parent selected chunk hash mismatch.")
    objects = {obj["id"]: obj for entry in packet["sources"] for obj in entry["facts"]["objects"]}
    targets, seen_blocks, seen_tables, seen_reports = {}, set(), set(), set()
    blocks = trace.get("blocks")
    if type(blocks) is not list:
        raise ValueError("Parent block trace is missing.")
    for block in blocks:
        block_id = block.get("source_block_id")
        source = objects.get(block_id)
        if (source is None or source["kind"] != "Block" or source["name"] != block.get("name")
                or block_id in seen_blocks):
            raise ValueError("Parent block identity collision or mismatch.")
        seen_blocks.add(block_id)
        if block.get("classification") != "database":
            continue
        table, report = block.get("table_name"), block.get("report_file")
        page = block.get("report_page_id")
        if (type(table) is not str or not _IDENT.fullmatch(table) or table in seen_tables
                or type(report) is not str or report not in members or report in seen_reports
                or type(page) is not int or not 0 < page < 9999):
            raise ValueError("Parent database target collision or invalid binding.")
        seen_tables.add(table)
        seen_reports.add(report)
        declarations = re.findall(r"\bCREATE TABLE " + re.escape(table) + r" \(\s*(.*?)\n\);", schema, re.S)
        if len(declarations) != 1:
            raise ValueError("Parent target table must have one synthetic DDL declaration.")
        columns = re.findall(r"^\s*([A-Z][A-Z0-9_$#]*)\s+(NUMBER|VARCHAR2|DATE)\b", declarations[0], re.M)
        if len(dict(columns)) != len(columns):
            raise ValueError("Parent DDL has colliding columns.")
        ddl = dict(columns)
        row_key = block.get("synthetic_key")
        if (type(row_key) is not dict or row_key.get("source_derived") is not False
                or row_key.get("source_item_id") is not None or ddl.get(row_key.get("column")) != "NUMBER"):
            raise ValueError("Parent synthetic row identity is not proven.")
        report_text = members[report].decode("utf-8")
        if (len(re.findall(r"\bpage\s+" + str(page) + r"\s*\(", report_text)) != 1
                or re.findall(r"\btableName:\s*([A-Z][A-Z0-9_$#]*)", report_text) != [table]
                or len(re.findall(r"\btype:\s*interactiveReport\b", report_text)) != 1):
            raise ValueError("Parent report does not uniquely bind its traced table.")
        seen_columns = {row_key["column"]}
        for field in block.get("items", []):
            item_id, column = field.get("source_item_id"), field.get("column")
            item = objects.get(item_id)
            if (item is None or item["kind"] != "Item" or item["block_id"] != block_id
                    or item["name"] != field.get("source_name") or item_id in targets):
                raise ValueError("Parent item identity collision or mismatch.")
            if (type(column) is not str or not _IDENT.fullmatch(column) or column in seen_columns
                    or field.get("data_type") not in ("NUMBER", "VARCHAR2", "DATE")
                    or ddl.get(column) != field["data_type"] or field.get("report_page_id") != page
                    or len(re.findall(r"\bcolumn\s+" + re.escape(column) + r"\s*\(", report_text)) != 1):
                raise ValueError("Parent column type, report identity or uniqueness mismatch.")
            seen_columns.add(column)
            targets[item_id] = (block, field)
    return members, targets, selected, _hash(manifest_raw), _hash(trace_raw)


def _source_objects(documents, packet):
    metadata, objects = {}, {}
    entries = {entry["source"]["name"]: entry for entry in packet["sources"]}
    for name, raw in documents:
        root, locations = forms_facts._safe_input(name, raw)
        nodes = {loc["path"]: node for node, loc in zip(root.iter(), locations, strict=True)}
        for obj in entries[name]["facts"]["objects"]:
            objects[obj["id"]] = obj
            metadata[obj["id"]] = dict(nodes[obj["location"]["path"]].attrib)
    return objects, metadata


def _resolve(parts, owner, objects):
    block = objects.get(owner["block_id"])
    if block is None or (len(parts) == 2 and parts[0] != (block["name"] or "").upper()):
        raise UnsupportedBehavior("cross_block_reference")
    found = [obj for obj in objects.values() if obj["kind"] == "Item"
             and obj["block_id"] == block["id"] and (obj["name"] or "").upper() == parts[-1]]
    if len(found) != 1:
        raise UnsupportedBehavior("item_reference_is_not_unique")
    return found[0]


def _bind(recognized, owner, objects, metadata, targets):
    if recognized["kind"] == "numeric_expression_report_column":
        if metadata[owner["id"]].get("DataType", "").strip().upper() != "NUMBER":
            raise UnsupportedBehavior("direct_source_number_type_required")
        if owner["id"] not in targets:
            raise LookupError("source_item_has_no_parent_report_column")
        block, output_field = targets[owner["id"]]
        if output_field["data_type"] != "NUMBER":
            raise ValueError("Numeric expression output must bind a NUMBER column.")
        bindings = {}
        for parts in numeric_expression.validate_expression(recognized["expression"]):
            item = _resolve(parts, owner, objects)
            if item["id"] == owner["id"]:
                raise UnsupportedBehavior("self_referencing_formula")
            props = metadata[item["id"]]
            if props.get("DataType", "").strip().upper() != "NUMBER":
                raise UnsupportedBehavior("direct_source_number_type_required")
            if (props.get("Formula", "").strip()
                    or props.get("CalculateMode", "").strip().upper() in ("FORMULA", "SUMMARY")):
                raise UnsupportedBehavior("input_computation_or_summary_not_implemented")
            if item["id"] not in targets:
                raise LookupError("source_item_has_no_parent_report_column")
            input_block, field = targets[item["id"]]
            if input_block is not block or field["data_type"] != "NUMBER":
                raise ValueError("Source NUMBER or same-block parent target mismatch.")
            bindings[item["id"]] = {"source_item_id": item["id"], "column": field["column"]}
        return {"kind": recognized["kind"], "source_block_id": block["source_block_id"],
                "source_item_id": owner["id"], "expression": recognized["expression"],
                "input_bindings": [bindings[key] for key in sorted(bindings)],
                "target": {"table": block["table_name"], "report_file": block["report_file"],
                           "report_page_id": block["report_page_id"], "output_column": output_field["column"]}}
    if recognized["kind"] == "ceil_report_column":
        output = owner
        value = _resolve(recognized["reference"], owner, objects)
        if value["id"] == output["id"]:
            raise UnsupportedBehavior("self_referencing_formula")
    else:
        value = objects.get(owner["parent_id"])
        if value is None or value["kind"] != "Item":
            raise UnsupportedBehavior("trigger_requires_direct_item_owner")
        if _resolve(recognized["reference"], owner, objects)["id"] != value["id"]:
            raise UnsupportedBehavior("validation_reference_not_owner")
        output = _resolve(recognized["focus_reference"], owner, objects)
        if output["id"] == value["id"]:
            raise UnsupportedBehavior("focus_must_be_distinct_item")
    for item in (value, output) if recognized["kind"] == "ceil_report_column" else (value,):
        if metadata[item["id"]].get("DataType", "").strip().upper() != "NUMBER":
            raise UnsupportedBehavior("direct_source_number_type_required")
    value_metadata = metadata[value["id"]]
    if (value_metadata.get("Formula", "").strip()
            or value_metadata.get("CalculateMode", "").strip().upper() in ("FORMULA", "SUMMARY")):
        raise UnsupportedBehavior("input_computation_or_summary_not_implemented")
    if value["id"] not in targets or output["id"] not in targets:
        raise LookupError("source_item_has_no_parent_report_column")
    block, value_field = targets[value["id"]]
    output_block, output_field = targets[output["id"]]
    if block is not output_block or value_field["data_type"] != "NUMBER":
        raise ValueError("Source NUMBER or same-block parent target mismatch.")
    common = {"table": block["table_name"], "report_file": block["report_file"],
              "report_page_id": block["report_page_id"]}
    operation = {"kind": recognized["kind"], "source_block_id": block["source_block_id"],
                 "source_item_id": owner["id"] if owner["kind"] == "Item" else value["id"]}
    if recognized["kind"] == "ceil_report_column":
        if output_field["data_type"] != "NUMBER":
            raise ValueError("CEIL output must bind a NUMBER column.")
        operation.update(input_source_item_id=value["id"], target={**common,
                         "input_column": value_field["column"], "output_column": output_field["column"]})
    else:
        minimum = metadata[value["id"]].get("LowestAllowedValue", "").strip() or None
        if minimum is not None and (len(minimum) > 80 or not _NUMBER.fullmatch(minimum)
                                    or sum(c.isdigit() for c in minimum) > 38):
            raise UnsupportedBehavior("minimum_is_not_finite_decimal_literal")
        operation.update(focus_source_item_id=output["id"], message=recognized["message"],
                         message_call_count=recognized["message_call_count"], minimum=minimum,
                         target={**common, "row_id_column": block["synthetic_key"]["column"],
                                 "value_column": value_field["column"], "focus_column": output_field["column"],
                                 "value_data_type": value_field["data_type"],
                                 "focus_data_type": output_field["data_type"]})
    return operation


def build_behavior_plan(documents, parent_zip, selected_unit_ids=None):
    """Return a deterministic finite IR bound to exact originals and parent bytes.

    Selection chooses complete source units only. Unsupported units always remain
    individually visible. A planned operation establishes neither APEX generation
    nor verification. No free SQL/expression strings are accepted or emitted.
    """
    packet, chunks = _build(documents)
    units = [unit for entry in packet["sources"] for unit in entry["facts"]["code_units"]]
    available_ids = {unit["id"] for unit in units}
    if selected_unit_ids is None:
        selected_ids = available_ids
    else:
        if (type(selected_unit_ids) not in (list, tuple, set, frozenset)
                or any(type(value) is not str for value in selected_unit_ids)
                or len(set(selected_unit_ids)) != len(selected_unit_ids)
                or not set(selected_unit_ids) <= available_ids):
            raise ValueError("Selection must contain unique complete source-unit identities.")
        selected_ids = set(selected_unit_ids)
    _, targets, parent_selected, manifest_sha, trace_sha = _parent(parent_zip, packet, chunks)
    objects, metadata = _source_objects(documents, packet)
    chunk_by_unit = {chunk["code_unit_id"]: chunk for chunk in chunks}
    operations, coverage, occupied = [], [], set()
    validation_reports = set()
    for unit in units:
        row = {"source_unit_id": unit["id"], "source_unit_sha256": unit["sha256"],
               "source_chunk_id": chunk_by_unit[unit["id"]]["id"],
               "source_owner_id": unit["owner_id"], "source_location": unit["location"],
               "status": "unsupported", "reason": "not_selected",
               "runtime_verified": False, "business_accepted": False}
        coverage.append(row)
        if unit["id"] not in selected_ids:
            continue
        chunk = chunk_by_unit[unit["id"]]
        try:
            semantic, receipt = decode_control_entities(chunk["text"])
            if receipt["raw_sha256"] != unit["sha256"]:
                raise ValueError("Raw unit hash mismatch after source reconstruction.")
            row["decode_receipt"] = receipt
            owner = objects[unit["owner_id"]]
            recognized = _recognize(unit, owner, semantic)
            if chunk["id"] not in parent_selected:
                raise LookupError("source_unit_not_selected_in_parent")
            operation = _bind(recognized, owner, objects, metadata, targets)
            collision = ("report_formula" if operation["kind"] in
                         {"ceil_report_column", "numeric_expression_report_column"}
                         else operation["kind"], operation["source_item_id"])
            if collision in occupied:
                raise ValueError("Multiple source units would overwrite one native behavior target.")
            # Capacity is a mapping limitation, not a reason to lose the whole
            # source set. Preserve every deferred unit with its exact identity.
            if len(operations) >= MAX_OPERATIONS:
                raise UnsupportedBehavior("behavior_operation_capacity_exceeded")
            if operation["kind"] == "numeric_nonzero_then_focus":
                report = operation["target"]["report_file"]
                if report in validation_reports:
                    raise UnsupportedBehavior("report_validation_link_capacity_exceeded")
                validation_reports.add(report)
            occupied.add(collision)
            operation.update(operation_id="fb1-" + _hash(_canonical([packet["source_binding"], unit["id"]]))[:24],
                             source_unit_id=unit["id"], source_unit_sha256=unit["sha256"],
                             source_chunk_id=chunk["id"],
                             decode_receipt=receipt)
            operations.append(operation)
            row.update(status="planned_wired_adapted", reason="complete_supported_source_pattern",
                       operation_id=operation["operation_id"])
        except UnsupportedBehavior as exc:
            row["reason"] = str(exc)
        except LookupError as exc:
            row.update(status="missing_input", reason=str(exc))
    plan = {"schema_version": 1, "scope": SCOPE, "source_binding": packet["source_binding"],
            "parent_zip_sha256": _hash(parent_zip), "source_manifest_sha256": manifest_sha,
            "parent_trace_sha256": trace_sha,
            "sources": [{key: entry["source"][key] for key in ("name", "sha256", "bytes")}
                        for entry in packet["sources"]],
            "code_unit_count": len(units), "operations": operations, "coverage": coverage,
            "native_generated": False, "runtime_verified": False, "business_accepted": False,
            "adaptations": (["Explicit Continue button replaces Forms keyboard event.",
                             "One native validation notification replaces repeated Forms MESSAGE calls.",
                             "Validation-only row view performs no save, DML or commit.",
                             "Original item minimum is independent of the NVL-zero trigger predicate."]
                            if any(op["kind"] == "numeric_nonzero_then_focus" for op in operations) else [])
                           + (["Report formulas use persisted synthetic rows, not the unsaved Forms record buffer."]
                              if any(op["kind"] in {"ceil_report_column", "numeric_expression_report_column"}
                                     for op in operations) else [])
                           + ["Parent synthetic tables are not authoritative customer database objects."],
            "remaining_scope": "Untranslated code units, record lifecycle, dependencies and full business workflows remain unresolved."}
    plan["plan_sha256"] = _hash(_canonical(plan))
    return plan
