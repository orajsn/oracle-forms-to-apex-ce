"""Closed, source-bound policy IR and pure PL/SQL review output.

No Forms API, authorization, event, record provider or transaction is activated.
The integration caller MUST rebuild from original XML and its current native trace
before rendering. Hashes detect changes; they do not authenticate supplied source.
The converter deliberately has no dependency on the FOX application package.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import re

from .native_assignments import _canonical, _sha

SCOPE = "fox-forms-policy-plan-v1"
RENDERER = "fox-native-policy-review-v1"
CODE_MEMBER = "fox-package/policy-review.sql"
MAX_UNIT_CHARACTERS = 16_384
MAX_OPERATIONS = 100
MAX_NODES = 256
MAX_DEPTH = 16
MAX_FIELDS = 64
_IDENT = r"[A-Za-z][A-Za-z0-9_$#]{0,127}"
_ID = r"ff1-[0-9a-f]{24}"
_SHA = r"[0-9a-f]{64}"
_PROPERTIES = {"block": {"INSERT_ALLOWED", "UPDATE_ALLOWED", "DELETE_ALLOWED"},
               "item": {"ENABLED", "INSERT_ALLOWED", "UPDATE_ALLOWED"}}
_RESERVED = {"SELECT", "INSERT", "UPDATE", "DELETE", "MERGE", "COMMIT", "ROLLBACK",
             "EXECUTE", "LOOP", "FOR", "WHILE", "RETURN", "DECLARE", "EXCEPTION",
             "NULL", "ELSE", "ELSIF", "END", "GO_ITEM", "GO_BLOCK", "NEXT_RECORD",
             "PREVIOUS_RECORD", "FIRST_RECORD", "LAST_RECORD", "DO_KEY", "SYNCHRONIZE",
             "EXECUTE_QUERY", "CLEAR_BLOCK", "CREATE_RECORD", "DELETE_RECORD"}
ACTIVATION_REQUIREMENTS = [
    "Bind the exact source event, record buffers, current block and typed input providers.",
    "Implement and verify ordered property, warning and failure effects in the target lifecycle.",
    "Verify source null, datatype, length and collation semantics against the approved target.",
    "Compile and test on an approved Oracle target; obtain business acceptance separately.",
]


def _need(condition, code):
    if not condition:
        raise ValueError("POLICY_" + code)


class UnsupportedPolicy(ValueError):
    """The complete source body is outside the bounded rule grammar or bindings."""


def _unsupported(reason):
    raise UnsupportedPolicy(reason)


def _lex(raw):
    """Decode only control entities outside literals; tokenize the whole source."""
    if type(raw) is not str or not 0 < len(raw) <= MAX_UNIT_CHARACTERS:
        _unsupported("policy_source_size")
    out, substitutions, state, i = [], [], "code", 0
    while i < len(raw):
        entity = re.match(r"&#(?:([0-9]+)|[xX]([0-9a-fA-F]+));", raw[i:])
        if entity:
            cp = int(entity[1], 10) if entity[1] else int(entity[2], 16)
            if state == "string" or cp not in (9, 10, 13):
                _unsupported("policy_ambiguous_entity")
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
            _unsupported("policy_nested_comment")
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
        _unsupported("policy_unterminated_literal_or_comment")
    semantic = "".join(out)
    pattern = re.compile(r"\s+|--[^\r\n]*|/\*.*?\*/|'(?:''|[^'])*'|:=|<>|!=|" +
                         _IDENT + r"|[0-9]+(?:\.[0-9]+)?|[:.,();=+-]", re.S)
    tokens, pos = [], 0
    while pos < len(semantic):
        match = pattern.match(semantic, pos)
        if not match:
            _unsupported("policy_unsupported_active_token")
        value = match[0]
        pos = match.end()
        if value.isspace() or value.startswith(("--", "/*")):
            continue
        kind = "string" if value.startswith("'") else "number" if value[0].isdigit() else "token"
        tokens.append((kind, value[1:-1].replace("''", "'") if kind == "string" else value.upper()))
        if len(tokens) > 4096:
            _unsupported("policy_token_capacity")
    receipt = {"rule": "numeric-tab-lf-cr-outside-literals-v1", "raw_sha256": _sha(raw.encode()),
        "semantic_sha256": _sha(semantic.encode()), "offset_unit": "unicode_character",
        "substitutions": substitutions}
    return tokens, receipt


class _Parser:
    def __init__(self, tokens):
        self.tokens, self.pos, self.nodes = tokens, 0, 0

    def peek(self, value):
        return self.pos < len(self.tokens) and self.tokens[self.pos] == ("token", value)

    def take(self, value=None, kind=None):
        if self.pos >= len(self.tokens):
            _unsupported("policy_incomplete_body")
        token = self.tokens[self.pos]
        if value is not None and token != ("token", value) or kind is not None and token[0] != kind:
            _unsupported("policy_complete_body_not_supported")
        self.pos += 1
        return token[1]

    def ident(self):
        value = self.take(kind="token")
        if not re.fullmatch(_IDENT, value):
            _unsupported("policy_identifier_required")
        return value

    def node(self, kind, depth, **values):
        self.nodes += 1
        if depth > MAX_DEPTH or self.nodes > MAX_NODES:
            _unsupported("policy_ast_capacity")
        return {"kind": kind, **values}

    def scalar(self, depth):
        if self.peek(":"):
            self.take(":")
            parts = [self.ident()]
            if self.peek("."):
                self.take(".")
                parts.append(self.ident())
            return self.node("field", depth, parts=parts)
        if self.peek("NULL"):
            self.take("NULL")
            return self.node("literal", depth, data_type="NULL", value=None)
        if self.pos < len(self.tokens) and self.tokens[self.pos][0] == "string":
            value = self.take(kind="string")
            if len(value.encode("utf-8")) > 2000:
                _unsupported("policy_literal_capacity")
            return self.node("literal", depth, data_type="VARCHAR2", value=value)
        sign = self.take() if self.peek("-") or self.peek("+") else ""
        value = self.take(kind="number")
        if len(value) > 38:
            _unsupported("policy_numeric_literal_capacity")
        return self.node("literal", depth, data_type="NUMBER", value=sign + value)

    def expression(self, depth=0, level=0):
        if depth > MAX_DEPTH:
            _unsupported("policy_ast_capacity")
        if level < 2:
            left = self.expression(depth + 1, level + 1)
            operator = "OR" if level == 0 else "AND"
            while self.peek(operator):
                self.take(operator)
                left = self.node(operator.lower(), depth, left=left,
                                 right=self.expression(depth + 1, level + 1))
            return left
        if self.peek("NOT"):
            self.take("NOT")
            return self.node("not", depth, value=self.expression(depth + 1, 2))
        if self.peek("("):
            self.take("(")
            result = self.expression(depth + 1)
            self.take(")")
            return result
        if self.peek("FORM_SUCCESS"):
            self.take("FORM_SUCCESS")
            return self.node("intrinsic", depth, name="FORM_SUCCESS", data_type="BOOLEAN")
        left = self.scalar(depth + 1)
        if self.peek("IS"):
            self.take("IS")
            negated = self.peek("NOT")
            if negated:
                self.take("NOT")
            self.take("NULL")
            return self.node("is_not_null" if negated else "is_null", depth, value=left)
        operator = self.take()
        if operator not in ("=", "<>", "!="):
            _unsupported("policy_comparison_not_supported")
        return self.node("eq" if operator == "=" else "ne", depth, left=left,
                         right=self.scalar(depth + 1))

    def statements(self, depth=0):
        if depth > MAX_DEPTH:
            _unsupported("policy_ast_capacity")
        result = []
        while self.pos < len(self.tokens) and not self.peek("END"):
            if self.peek("IF"):
                self.take("IF")
                condition = self.expression()
                self.take("THEN")
                body = self.statements(depth + 1)
                self.take("END")
                self.take("IF")
                node = self.node("if", depth, condition=condition, body=body)
            elif self.peek("SET_BLOCK_PROPERTY") or self.peek("SET_ITEM_PROPERTY"):
                target_kind = "block" if self.take() == "SET_BLOCK_PROPERTY" else "item"
                self.take("(")
                target = self.take(kind="string").upper()
                target_pattern = _IDENT + (r"(?:\." + _IDENT + ")?" if target_kind == "item" else "")
                if not re.fullmatch(target_pattern, target):
                    _unsupported("policy_property_target_not_static")
                self.take(",")
                prop = self.ident()
                self.take(",")
                value = self.ident()
                if prop not in _PROPERTIES[target_kind] or value not in ("PROPERTY_TRUE", "PROPERTY_FALSE"):
                    _unsupported("policy_property_not_supported")
                self.take(")")
                node = self.node("property", depth, target_kind=target_kind,
                    parts=target.split("."), property=prop, value=value == "PROPERTY_TRUE")
            elif self.peek(":"):
                target = self.scalar(depth + 1)
                self.take(":=")
                value = self.scalar(depth + 1)
                if value["kind"] != "literal":
                    _unsupported("policy_literal_assignment_required")
                node = self.node("assign", depth, target=target, value=value)
            elif self.peek("MESSAGE"):
                self.take("MESSAGE")
                self.take("(")
                value = self.scalar(depth + 1)
                if value["kind"] != "literal" or value["data_type"] != "VARCHAR2":
                    _unsupported("policy_literal_warning_required")
                self.take(")")
                node = self.node("warning", depth, message=value["value"])
            elif self.peek("RAISE"):
                self.take("RAISE")
                self.take("FORM_TRIGGER_FAILURE")
                node = self.node("failure", depth)
            else:
                name = self.ident()
                if name in _RESERVED:
                    _unsupported("policy_statement_or_side_effect_not_supported")
                # A complete parameterless supplied local procedure only.
                if self.peek("("):
                    self.take("(")
                    self.take(")")
                node = self.node("call", depth, name=name)
            self.take(";")
            result.append(node)
        if not result:
            _unsupported("policy_empty_body")
        return result


def parse_policy_text(raw):
    """Return a closed AST for an entire parameterless procedure or trigger body."""
    tokens, receipt = _lex(raw)
    parser = _Parser(tokens)
    name = None
    if parser.peek("PROCEDURE"):
        parser.take("PROCEDURE")
        name = parser.ident()
        if parser.peek("("):
            parser.take("(")
            parser.take(")")
        if parser.peek("IS"):
            parser.take("IS")
        else:
            parser.take("AS")
        parser.take("BEGIN")
        wrapped = True
    else:
        wrapped = parser.peek("BEGIN")
        if wrapped:
            parser.take("BEGIN")
    body = parser.statements()
    if wrapped:
        parser.take("END")
        if name is not None and parser.peek(name):
            parser.take(name)
        parser.take(";")
    if parser.pos != len(tokens):
        _unsupported("policy_extra_active_statement")
    def bounded(value, depth=0):
        if depth > MAX_DEPTH:
            _unsupported("policy_ast_capacity")
        if type(value) is dict:
            for nested in value.values():
                bounded(nested, depth + 1)
        elif type(value) is list:
            for nested in value:
                bounded(nested, depth)
    bounded(body)
    return {"procedure_name": name, "body": body}, receipt


def operation_id(source_binding, unit_id):
    return "fp1-" + _sha(_canonical([source_binding, unit_id]))[:24]


def _one(rows, reason):
    if len(rows) != 1:
        _unsupported(reason)
    return rows[0]


def _validate_catalog(catalog, trace):
    _need(type(catalog) is dict and set(catalog) == {"objects", "units"}, "CATALOG_FIELDS")
    _need(type(catalog["objects"]) is list and len(catalog["objects"]) <= 20_000
          and type(catalog["units"]) is list and len(catalog["units"]) <= 20_000, "CATALOG_CAPACITY")
    objects, seen = {}, set()
    fields = {"id", "kind", "name", "module_id", "block_id", "parent_id", "classification",
              "database_item", "metadata"}
    for obj in catalog["objects"]:
        _need(type(obj) is dict and set(obj) == fields, "OBJECT_FIELDS")
        _need(type(obj["id"]) is str and re.fullmatch(_ID, obj["id"]) and obj["id"] not in objects,
              "OBJECT_IDENTITY")
        _need(type(obj["kind"]) is str and type(obj["metadata"]) is dict
              and all(type(k) is type(v) is str for k, v in obj["metadata"].items()), "OBJECT_METADATA")
        _need(obj["name"] is None or type(obj["name"]) is str and len(obj["name"]) <= 512, "OBJECT_NAME")
        _need("Name" not in obj["metadata"] or obj["metadata"]["Name"] == obj["name"], "OBJECT_METADATA_NAME")
        for key in ("module_id", "block_id", "parent_id"):
            _need(obj[key] is None or type(obj[key]) is str and re.fullmatch(_ID, obj[key]), "OBJECT_PARENT")
        objects[obj["id"]] = obj
    for obj in objects.values():
        for key in ("module_id", "block_id", "parent_id"):
            _need(obj[key] is None or obj[key] in objects, "OBJECT_DANGLING_PARENT")
        if obj["block_id"] is not None:
            block = objects[obj["block_id"]]
            _need(block["kind"] == "Block" and block["module_id"] == obj["module_id"], "OBJECT_BLOCK_MODULE")
        if obj["parent_id"] is not None and obj["module_id"] is not None:
            parent = objects[obj["parent_id"]]
            _need(parent["module_id"] == obj["module_id"] or parent["id"] == obj["module_id"],
                  "OBJECT_PARENT_MODULE")
    unit_fields = {"id", "owner_id", "source_attribute", "sha256", "location", "chunk_id", "text"}
    for unit in catalog["units"]:
        _need(type(unit) is dict and set(unit) == unit_fields, "UNIT_FIELDS")
        _need(type(unit["id"]) is str and re.fullmatch(_ID, unit["id"]) and unit["id"] not in seen
              and unit["owner_id"] in objects, "UNIT_IDENTITY")
        seen.add(unit["id"])
        _need(type(unit["text"]) is str and len(unit["text"]) <= 1_000_000
              and unit["sha256"] == _sha(unit["text"].encode())
              and type(unit["chunk_id"]) is str and re.fullmatch(r"fup1-[0-9a-f]{64}", unit["chunk_id"]),
              "UNIT_SOURCE_BINDING")
        owner = objects[unit["owner_id"]]
        _need(type(unit["source_attribute"]) is str, "UNIT_SOURCE_ATTRIBUTE")
        if unit["source_attribute"] in owner["metadata"]:
            _need(owner["metadata"][unit["source_attribute"]] == unit["text"], "UNIT_METADATA_BODY")
        loc = unit["location"]
        _need(type(loc) is dict and set(loc) == {"path", "line", "column", "byte_offset"}
              and type(loc["path"]) is str and loc["path"].startswith("/")
              and all(type(loc[k]) is int and loc[k] >= n for k, n in
                      (("line", 1), ("column", 1), ("byte_offset", 0))), "UNIT_LOCATION")
    _need(type(trace) is dict and type(trace.get("blocks")) is list
          and len(trace["blocks"]) <= 20_000, "TRACE_FIELDS")
    for block in trace["blocks"]:
        _need(type(block) is dict and type(block.get("items")) is list
              and all(type(field) is dict for field in block["items"]), "TRACE_BLOCK_FIELDS")
    return objects


def derive_policy_operations(catalog, trace, source_binding):
    """Rebuild all IR from bounded source and metadata, including same-module calls."""
    objects = _validate_catalog(catalog, trace)
    units = catalog["units"]
    by_owner = {}
    for unit in units:
        by_owner.setdefault(unit["owner_id"], []).append(unit)
    operations, coverage = [], []
    event_counts = Counter((obj["module_id"], obj["parent_id"], (obj["name"] or "").upper())
                           for obj in objects.values() if obj["kind"] == "Trigger")

    def resolve(parts, owner, kind):
        candidates = [obj for obj in objects.values() if obj["kind"] == kind
                      and obj["module_id"] == owner["module_id"]
                      and (obj["name"] or "").upper() == parts[-1]]
        if kind == "Item":
            if len(parts) == 2:
                candidates = [obj for obj in candidates if
                    (objects[obj["block_id"]]["name"] or "").upper() == parts[0]]
            elif owner["block_id"] is not None:
                local = [obj for obj in candidates if obj["block_id"] == owner["block_id"]]
                # A cross-block snapshot is explicit only when the module-wide
                # source item identity is unique; no current-record provider is
                # inferred from this name resolution.
                if local:
                    candidates = local
        return _one(candidates, "policy_source_reference_not_unique")

    def block_trace(block):
        mapped = _one([row for row in trace["blocks"] if row.get("source_block_id") == block["id"]],
                      "policy_trace_block_not_unique")
        if (mapped.get("name") != block["name"] or mapped.get("classification") != block["classification"]
                or mapped.get("source_module_id", block["module_id"]) != block["module_id"]):
            _unsupported("policy_trace_block_source_mismatch")
        return mapped

    def bind_field(parts, owner, fields):
        if parts == ["SYSTEM", "FORM_STATUS"]:
            key = "intrinsic:FORM_STATUS"
            fields[key] = {"binding_kind": "intrinsic", "name": "FORM_STATUS", "data_type": "VARCHAR2",
                           "provider": "required_source_form_status_snapshot"}
            return {"kind": "field", "ref": key, "data_type": "VARCHAR2"}
        if parts[0] in ("SYSTEM", "GLOBAL", "PARAMETER"):
            _unsupported("policy_external_session_input_not_supported")
        item = resolve(parts, owner, "Item")
        block = objects[item["block_id"]]
        props = item["metadata"]
        source_type = props.get("DataType", "").upper()
        datatype = {"CHAR": "VARCHAR2", "VARCHAR2": "VARCHAR2", "NUMBER": "NUMBER"}.get(source_type)
        if (datatype is None or props.get("Formula", "").strip()
                or any(props.get(k, "").strip().upper() not in ("", "NONE") for k in
                       ("CalculateMode", "CalculationMode", "SummaryFunction"))):
            _unsupported("policy_explicit_noncomputed_scalar_type_required")
        mapped = block_trace(block)
        field = _one([row for row in mapped.get("items", []) if row.get("source_item_id") == item["id"]],
                     "policy_trace_item_not_unique")
        if (field.get("source_name") != item["name"] or field.get("data_type") != datatype
                or field.get("database_bound") is not (block["classification"] == "database")
                or field.get("value_computation_implemented") is True):
            _unsupported("policy_trace_item_source_mismatch")
        column = field.get("column")
        if column is not None and (type(column) is not str or not re.fullmatch(_IDENT, column)):
            _unsupported("policy_trace_column_invalid")
        if column is not None and sum(row.get("column") == column for row in mapped.get("items", [])) != 1:
            _unsupported("policy_trace_column_not_unique")
        key = item["id"]
        fields[key] = {"binding_kind": "source_item", "source_item_id": key,
            "source_block_id": block["id"], "source_module_id": owner["module_id"],
            "source_item_name": item["name"], "source_block_name": block["name"],
            "source_data_type": source_type, "data_type": datatype,
            "source_maximum_length": props.get("MaximumLength"), "source_database_item": item["database_item"],
            "column": column, "native_item": field.get("native_item"),
            "provider": "required_source_record_buffer_snapshot"}
        if len(fields) > MAX_FIELDS:
            _unsupported("policy_field_capacity")
        return {"kind": "field", "ref": key, "data_type": datatype}

    def expression(node, owner, fields):
        kind = node["kind"]
        if kind == "field":
            return bind_field(node["parts"], owner, fields)
        if kind == "literal":
            return deepcopy(node)
        if kind == "intrinsic":
            fields["intrinsic:FORM_SUCCESS"] = {"binding_kind": "intrinsic", "name": "FORM_SUCCESS",
                "data_type": "BOOLEAN", "provider": "required_preceding_forms_operation_success_snapshot"}
            return {"kind": "field", "ref": "intrinsic:FORM_SUCCESS", "data_type": "BOOLEAN"}
        if kind in ("not", "is_null", "is_not_null"):
            value = expression(node["value"], owner, fields)
            if kind == "not" and value.get("data_type") != "BOOLEAN":
                _unsupported("policy_boolean_condition_required")
            return {"kind": kind, "value": value, "data_type": "BOOLEAN"}
        left, right = expression(node["left"], owner, fields), expression(node["right"], owner, fields)
        types = {left["data_type"], right["data_type"]} - {"NULL"}
        if kind in ("and", "or") and types != {"BOOLEAN"} or len(types) > 1:
            _unsupported("policy_implicit_type_conversion_not_supported")
        return {"kind": kind, "left": left, "right": right, "data_type": "BOOLEAN"}

    def bind_unit(unit, stack, fields, targets, callees, budget):
        owner = objects[unit["owner_id"]]
        if unit["id"] in stack or len(stack) >= MAX_DEPTH:
            _unsupported("policy_recursive_local_call")
        if owner["kind"] not in ("ProgramUnit", "Trigger") or len(by_owner[owner["id"]]) != 1:
            _unsupported("policy_complete_procedure_or_trigger_required")
        expected_attrs = ("ProgramUnitText", "#text", "ProgramUnitText.text") if owner["kind"] == "ProgramUnit" else (
            "TriggerText", "#text", "TriggerText.text")
        if unit["source_attribute"] not in expected_attrs:
            _unsupported("policy_owner_source_attribute_mismatch")
        parsed, decode = parse_policy_text(unit["text"])
        if owner["kind"] == "ProgramUnit":
            if parsed["procedure_name"] != (owner["name"] or "").upper():
                _unsupported("policy_procedure_owner_name_mismatch")
            if owner["metadata"].get("ProgramUnitType", "Procedure").upper() != "PROCEDURE":
                _unsupported("policy_procedure_type_required")
        elif parsed["procedure_name"] is not None:
            _unsupported("policy_trigger_cannot_declare_procedure")
        elif event_counts[(owner["module_id"], owner["parent_id"], (owner["name"] or "").upper())] != 1:
            _unsupported("policy_ambiguous_source_event")

        def statements(body):
            result = []
            for node in body:
                budget[0] += 1
                if budget[0] > MAX_NODES:
                    _unsupported("policy_expanded_ast_capacity")
                kind = node["kind"]
                if kind == "if":
                    condition = expression(node["condition"], owner, fields)
                    if condition["data_type"] != "BOOLEAN":
                        _unsupported("policy_boolean_condition_required")
                    result.append({"kind": "if", "condition": condition, "body": statements(node["body"])})
                elif kind == "assign":
                    target = bind_field(node["target"]["parts"], owner, fields)
                    if target["ref"].startswith("intrinsic:"):
                        _unsupported("policy_intrinsic_assignment_forbidden")
                    if node["value"]["data_type"] not in (target["data_type"], "NULL"):
                        _unsupported("policy_assignment_type_mismatch")
                    result.append({"kind": "assign", "target": target, "value": deepcopy(node["value"])})
                elif kind == "property":
                    target = resolve(node["parts"], owner, "Block" if node["target_kind"] == "block" else "Item")
                    block = target if target["kind"] == "Block" else objects[target["block_id"]]
                    mapped = block_trace(block)
                    native_binding = None
                    if target["kind"] == "Item":
                        matches = [row for row in mapped.get("items", []) if row.get("source_item_id") == target["id"]]
                        if matches:
                            field = _one(matches, "policy_trace_item_not_unique")
                            if field.get("source_name") != target["name"]:
                                _unsupported("policy_trace_item_source_mismatch")
                            native_binding = field.get("native_item")
                    targets[target["id"]] = {"source_id": target["id"], "source_kind": target["kind"],
                        "source_name": target["name"], "source_block_id": block["id"],
                        "source_module_id": owner["module_id"], "native_item": native_binding,
                        "target_effect_binding": "required_unimplemented"}
                    result.append({"kind": "property", "target_id": target["id"],
                        "property": node["property"], "value": node["value"]})
                elif kind == "call":
                    callee = _one([obj for obj in objects.values() if obj["kind"] == "ProgramUnit"
                        and obj["module_id"] == owner["module_id"] and (obj["name"] or "").upper() == node["name"]],
                        "policy_same_module_local_call_body_not_proven")
                    callee_unit = _one(by_owner.get(callee["id"], []), "policy_local_call_complete_source_required")
                    nested, nested_decode = bind_unit(callee_unit, stack + [unit["id"]], fields, targets, callees, budget)
                    callees[callee_unit["id"]] = {"source_unit_id": callee_unit["id"],
                        "source_owner_id": callee["id"], "source_module_id": callee["module_id"],
                        "source_unit_sha256": callee_unit["sha256"], "decode_receipt": nested_decode}
                    result.append({"kind": "local_call", "source_unit_id": callee_unit["id"], "body": nested})
                else:
                    result.append(deepcopy(node))
            return result
        return statements(parsed["body"]), decode

    for unit in units:
        owner = objects[unit["owner_id"]]
        row = {"source_unit_id": unit["id"], "source_unit_sha256": unit["sha256"],
            "source_chunk_id": unit["chunk_id"], "source_owner_id": owner["id"],
            "source_location": deepcopy(unit["location"]), "status": "unsupported", "not_yet_converted": True,
            "reason": "policy_complete_procedure_or_trigger_required", "runtime_verified": False, "business_accepted": False}
        coverage.append(row)
        try:
            fields, targets, callees = {}, {}, {}
            body, decode = bind_unit(unit, [], fields, targets, callees, [0])
            if "intrinsic:FORM_SUCCESS" in fields:
                guard = body
                while len(guard) == 1 and guard[0]["kind"] == "local_call":
                    guard = guard[0]["body"]
                pure = len(guard) == 1 and guard[0]["kind"] == "if"
                if pure:
                    condition = guard[0]["condition"]
                    pure = (condition["kind"] == "not" and condition["value"].get("ref") == "intrinsic:FORM_SUCCESS"
                            and guard[0]["body"] == [{"kind": "failure"}])
                if not pure:
                    _unsupported("policy_form_success_requires_pure_snapshot_guard")
            if "intrinsic:FORM_STATUS" in fields:
                def warnings_only(nodes):
                    return all(node["kind"] == "warning" or node["kind"] in ("if", "local_call")
                               and warnings_only(node["body"]) for node in nodes)
                if not warnings_only(body):
                    _unsupported("policy_form_status_requires_nonmutating_warning_rule")
            if len(operations) >= MAX_OPERATIONS:
                _unsupported("policy_operation_capacity")
            op = {"operation_id": operation_id(source_binding, unit["id"]),
                "source_unit_id": unit["id"], "source_unit_sha256": unit["sha256"],
                "source_chunk_id": unit["chunk_id"], "source_owner_id": owner["id"],
                "source_module_id": owner["module_id"], "source_parent_id": owner["parent_id"],
                "source_event": owner["name"] if owner["kind"] == "Trigger" else None,
                "source_unit_text": unit["text"], "decode_receipt": decode, "body": body,
                "fields": fields, "property_targets": targets, "local_calls": list(callees.values()),
                "encoding_status": "generated_unwired"}
            operations.append(op)
            row.update(operation_id=op["operation_id"], encoding_status="generated_unwired",
                       reason="policy_rule_encoded_event_and_context_wiring_required")
        except UnsupportedPolicy as exc:
            row["reason"] = str(exc)
    return operations, coverage


def _validate(plan):
    keys = {"schema_version", "scope", "source_binding", "trace_sha256", "sources", "source_catalog", "parent_trace",
            "operations", "coverage", "code_unit_count", "native_generated", "event_activated",
            "runtime_verified", "business_accepted", "plan_sha256"}
    _need(type(plan) is dict and set(plan) == keys, "PLAN_FIELDS")
    _need(type(plan["schema_version"]) is int and plan["schema_version"] == 1 and plan["scope"] == SCOPE, "VERSION")
    _need(len(_canonical(plan)) <= 8_000_000, "PLAN_CAPACITY")
    for key in ("source_binding", "trace_sha256", "plan_sha256"):
        _need(type(plan[key]) is str and re.fullmatch(_SHA, plan[key]), "DIGEST")
    _need(plan["plan_sha256"] == _sha(_canonical({k: v for k, v in plan.items() if k != "plan_sha256"})), "PLAN_CHANGED")
    _need(all(plan[k] is False for k in ("native_generated", "event_activated", "runtime_verified", "business_accepted")),
          "FALSE_CLAIMS")
    sources = plan["sources"]
    _need(type(sources) is list and 1 <= len(sources) <= 4, "SOURCES")
    names = set()
    for source in sources:
        _need(type(source) is dict and set(source) == {"name", "sha256", "bytes"}, "SOURCE_FIELDS")
        name = source["name"]
        _need(type(name) is str and 0 < len(name) <= 180 and "/" not in name and "\\" not in name
              and name.casefold() not in names and type(source["sha256"]) is str
              and re.fullmatch(_SHA, source["sha256"]) and type(source["bytes"]) is int
              and 0 < source["bytes"] <= 5 * 1024 * 1024, "SOURCE_IDENTITY")
        names.add(name.casefold())
    _need(type(plan["parent_trace"]) is dict and plan["parent_trace"].get("source_binding") == plan["source_binding"]
          and _sha(_canonical(plan["parent_trace"])) == plan["trace_sha256"], "TRACE_BINDING")
    operations, coverage = derive_policy_operations(plan["source_catalog"], plan["parent_trace"], plan["source_binding"])
    _need(type(plan["code_unit_count"]) is int and plan["code_unit_count"] == len(coverage), "UNIT_COUNT")
    # Canonical bytes distinguish bool from int, unlike ordinary Python equality.
    _need(_canonical(operations) == _canonical(plan["operations"])
          and _canonical(coverage) == _canonical(plan["coverage"]), "SOURCE_IR_MISMATCH")


def render_policy_code(plan):
    """Render pure typed review procedures, with ordered effects and no API stubs.

    Failure is a terminating effect returned for review, never an invented Oracle
    exception. The consumer must implement lifecycle propagation before activation.
    Field parameters are IN OUT to preserve prior values on false/NULL no-ELSE paths.
    """
    _validate(plan)
    package = "FOX_POL_" + plan["plan_sha256"][:20].upper()
    header = ["-- FOX policy review: GENERATED_UNWIRED.",
              "-- Not installed, event-wired, Oracle-compiled or runtime-verified.",
              "-- Effects describe source order; no target authorization is activated."]
    spec, bodies, generated = [], [], []
    for op in plan["operations"]:
        name = "RULE_" + op["operation_id"][4:].upper()
        params = {key: "p_f" + str(i + 1) for i, key in enumerate(op["fields"])}
        arguments = [f"{params[key]} IN {'BOOLEAN' if binding['data_type'] == 'BOOLEAN' else 'OUT ' + binding['data_type']}"
                     for key, binding in op["fields"].items()]
        arguments.append("p_effects OUT t_effects")
        signature = "  PROCEDURE " + name + "(" + ", ".join(arguments) + ")"
        spec.append(signature + ";")

        def literal(node):
            if node["data_type"] == "NULL":
                return "NULL"
            if node["data_type"] == "NUMBER":
                return node["value"]
            return "'" + node["value"].replace("'", "''") + "'"

        def expr(node):
            kind = node["kind"]
            if kind == "field": return params[node["ref"]]
            if kind == "literal": return literal(node)
            if kind == "not": return "(NOT " + expr(node["value"]) + ")"
            if kind in ("is_null", "is_not_null"):
                return "(" + expr(node["value"]) + (" IS NULL)" if kind == "is_null" else " IS NOT NULL)")
            operator = {"eq": "=", "ne": "<>", "and": "AND", "or": "OR"}[kind]
            return "(" + expr(node["left"]) + " " + operator + " " + expr(node["right"]) + ")"

        def emit(nodes, indent="    "):
            lines = []
            for node in nodes:
                kind = node["kind"]
                if kind == "if":
                    lines.append(indent + "IF " + expr(node["condition"]) + " THEN")
                    lines.extend(emit(node["body"], indent + "  "))
                    lines.append(indent + "END IF;")
                elif kind == "local_call":
                    lines.extend(emit(node["body"], indent))
                elif kind == "assign":
                    lines.append(indent + params[node["target"]["ref"]] + " := " + literal(node["value"]) + ";")
                    lines.extend(effect("assignment", node["target"]["ref"], None, None, indent))
                    value_field = "number_value" if node["target"]["data_type"] == "NUMBER" else "text_value"
                    lines.append(indent + f"p_effects(n).{value_field} := " + params[node["target"]["ref"]] + ";")
                elif kind == "property":
                    lines.extend(effect("property", node["target_id"], node["property"],
                                        "TRUE" if node["value"] else "FALSE", indent))
                elif kind == "warning":
                    lines.extend(effect("warning", None, node["message"], None, indent))
                elif kind == "failure":
                    lines.extend(effect("failure", None, None, None, indent))
                    lines.append(indent + "RETURN;")
            return lines

        def effect(kind, target, text, boolean, indent):
            result = [indent + "n := n + 1;"]
            for field, value in (("effect_kind", kind), ("source_target", target), ("effect_text", text)):
                rendered = "NULL" if value is None else literal({"data_type": "VARCHAR2", "value": value})
                result.append(indent + f"p_effects(n).{field} := {rendered};")
            result.append(indent + "p_effects(n).boolean_value := " + (boolean or "NULL") + ";")
            return result

        bodies.append(signature + " IS\n    n PLS_INTEGER := 0;\n  BEGIN\n    p_effects.DELETE;\n" +
                      "\n".join(emit(op["body"])) + "\n  END " + name + ";")
        generated.append({**deepcopy(op), "code_member": CODE_MEMBER, "package_name": package,
            "procedure_name": name, "parameter_bindings": {params[k]: deepcopy(v) for k, v in op["fields"].items()},
            "encoding_status": "generated_unwired", "generation_status": "generated_unwired",
            "null_policy": "oracle_three_valued_conditions_preserve_no_else_values",
            "effect_contract": "ordered_records_failure_terminates_remaining_source_statements",
            "activation_requirements": list(ACTIVATION_REQUIREMENTS), "event_activated": False,
            "oracle_compiled": False, "runtime_verified": False, "business_accepted": False})
    sql = "\n".join(header) + "\n"
    if generated:
        sql += f"CREATE OR REPLACE PACKAGE {package} AUTHID CURRENT_USER AS\n"
        sql += "  TYPE t_effect IS RECORD (effect_kind VARCHAR2(20), source_target VARCHAR2(128),\n"
        sql += "    effect_text VARCHAR2(4000), boolean_value BOOLEAN, number_value NUMBER, text_value VARCHAR2(32767));\n"
        sql += "  TYPE t_effects IS TABLE OF t_effect INDEX BY PLS_INTEGER;\n"
        sql += "\n".join(spec) + f"\nEND {package};\n/\n"
        sql += f"CREATE OR REPLACE PACKAGE BODY {package} AS\n"
        sql += "\n".join(bodies) + f"\nEND {package};\n/\n"
    else:
        sql += "-- No complete supported policy body.\n"
    _need(len(sql) <= 1_000_000, "SQL_CAPACITY")
    return sql, {"schema_version": 1, "scope": RENDERER, "plan_sha256": plan["plan_sha256"],
        "source_binding": plan["source_binding"], "trace_sha256": plan["trace_sha256"], "code_member": CODE_MEMBER,
        "sql_sha256": _sha(sql.encode()), "generated_operations": generated, "coverage": deepcopy(plan["coverage"]),
        "code_unit_count": plan["code_unit_count"], "converted_code_unit_count": 0,
        "native_generated": False, "event_activated": False, "oracle_compiled": False,
        "runtime_verified": False, "business_accepted": False}
