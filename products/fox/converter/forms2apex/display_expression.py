"""Finite same-row display expressions; no source SQL or source events execute.

Only concatenation, bound character items, year formatting of bound DATE items,
and printable ASCII literals are supported. Callers must resolve bindings from
fresh source/storage evidence. Digests detect changes, not authentic source proof.
Rendering does not establish Oracle compilation or business acceptance.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re
from collections.abc import Mapping

SCOPE = "fox-display-expression-v1"
MAX_EXPRESSION_CHARACTERS = 4096
MAX_OPERANDS = 32
MAX_LITERAL_BYTES = 256
MAX_RESULT_BYTES = 4000
MAX_CHAR_BYTES = 2000
_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_$#]{0,127}\Z")
_COLUMN = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")
_TOKEN = re.compile(r"[A-Za-z][A-Za-z0-9_$#]{0,127}|\|\||[:.,()]")
_BIND_KEYS = {"column", "data_type", "maximum_length", "maximum_bytes", "nullable"}


def _need(condition, code):
    if not condition:
        raise ValueError("DISPLAY_EXPRESSION_" + code)


def _name(value):
    _need(type(value) is str and _NAME.fullmatch(value), "IDENTIFIER")
    return value.upper()


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()


def _literal(value):
    _need(type(value) is str and len(value) <= MAX_LITERAL_BYTES and
          all(32 <= ord(ch) <= 126 for ch in value), "LITERAL")
    return "'" + value.replace("'", "''") + "'"


def _tokens(text):
    _need(type(text) is str and 0 < len(text) <= MAX_EXPRESSION_CHARACTERS, "SIZE")
    result, pos = [], 0
    while pos < len(text):
        if text[pos] in " \t\r\n":
            pos += 1
        elif text[pos] == "'":
            pos += 1
            chars, closed = [], False
            while pos < len(text):
                ch = text[pos]
                pos += 1
                if ch == "'":
                    if pos < len(text) and text[pos] == "'":
                        chars.append("'")
                        pos += 1
                    else:
                        closed = True
                        break
                else:
                    chars.append(ch)
            _need(closed, "UNTERMINATED_LITERAL")
            value = "".join(chars)
            _literal(value)
            result.append(("literal", value))
        else:
            match = _TOKEN.match(text, pos)
            _need(match is not None, "TOKEN")
            value = match.group().upper()
            result.append(("token", value))
            pos = match.end()
        _need(len(result) <= MAX_OPERANDS * 12, "TOKEN_LIMIT")
    return result


def parse_display_expression(expression: str, *, block: str) -> dict:
    """Parse a whole expression, never an assignment or arbitrary SQL fragment.

    Qualified and unqualified colon item references resolve to the given block.
    GLOBAL/SYSTEM/PARAMETER and cross-block references are rejected. No implicit
    conversion, nested expression, comment or general function grammar exists.
    """
    block = _name(block)
    _need(block not in {"GLOBAL", "SYSTEM", "PARAMETER"}, "BLOCK")
    tokens, pos = _tokens(expression), 0

    def take(value):
        nonlocal pos
        _need(pos < len(tokens) and tokens[pos] == ("token", value), "GRAMMAR")
        pos += 1

    def reference():
        nonlocal pos
        take(":")
        _need(pos < len(tokens) and tokens[pos][0] == "token", "REFERENCE")
        first = _name(tokens[pos][1])
        pos += 1
        if pos < len(tokens) and tokens[pos] == ("token", "."):
            pos += 1
            _need(first == block, "CROSS_BLOCK")
            _need(pos < len(tokens) and tokens[pos][0] == "token", "REFERENCE")
            item = _name(tokens[pos][1])
            pos += 1
        else:
            item = first
        return block + "." + item

    operands = []
    while pos < len(tokens):
        kind, value = tokens[pos]
        if kind == "literal":
            operand = {"kind": "literal", "value": value}
            pos += 1
        elif value == ":":
            operand = {"kind": "item", "ref": reference()}
        elif value == "TO_CHAR":
            pos += 1
            take("(")
            ref = reference()
            take(",")
            _need(pos < len(tokens) and tokens[pos][0] == "literal" and
                  tokens[pos][1].upper() in {"RR", "YYYY"}, "YEAR_FORMAT")
            operand = {"kind": "date_year", "ref": ref, "format": tokens[pos][1].upper()}
            pos += 1
            take(")")
        else:
            raise ValueError("DISPLAY_EXPRESSION_OPERAND")
        operands.append(operand)
        _need(len(operands) <= MAX_OPERANDS, "OPERAND_LIMIT")
        if pos == len(tokens):
            break
        take("||")
        _need(pos < len(tokens), "TRAILING_CONCAT")
    _need(len(operands) >= 2 and any("ref" in op for op in operands), "CONCAT_REQUIRED")
    # Canonical qualification must remain bounded as well as the original text.
    _need(sum(len(op.get("ref", "")) + len(op.get("value", "").replace("'", "''")) +
              (24 if op["kind"] == "date_year" else 3) for op in operands) +
          4 * (len(operands) - 1) <= MAX_EXPRESSION_CHARACTERS, "CANONICAL_SIZE")
    result = {"scope": SCOPE, "block": block,
        "ast": {"kind": "concat", "operands": operands},
        "refs": sorted({op["ref"] for op in operands if "ref" in op})}
    result["expression_id"] = _digest(result)
    return result


def _validate_parsed(parsed):
    _need(isinstance(parsed, Mapping) and set(parsed) ==
          {"scope", "block", "ast", "refs", "expression_id"}, "PARSED_SHAPE")
    _need(parsed["scope"] == SCOPE, "SCOPE")
    _need(type(parsed["refs"]) is list and len(parsed["refs"]) <= MAX_OPERANDS and
          all(type(ref) is str and len(ref) <= 257 for ref in parsed["refs"]) and
          type(parsed["expression_id"]) is str and
          re.fullmatch(r"[0-9a-f]{64}", parsed["expression_id"]), "PARSED_METADATA")
    block, ast = _name(parsed["block"]), parsed["ast"]
    _need(type(ast) is dict and set(ast) == {"kind", "operands"} and
          ast["kind"] == "concat" and type(ast["operands"]) is list and
          2 <= len(ast["operands"]) <= MAX_OPERANDS, "AST")
    source = []
    for op in ast["operands"]:
        _need(type(op) is dict and type(op.get("kind")) is str, "AST_OPERAND")
        if op.get("kind") == "literal":
            _need(set(op) == {"kind", "value"}, "AST_LITERAL")
            source.append(_literal(op["value"]))
        else:
            _need(set(op) == ({"kind", "ref"} if op.get("kind") == "item" else
                  {"kind", "ref", "format"}) and op.get("kind") in {"item", "date_year"}, "AST_REF")
            ref = op["ref"]
            _need(type(ref) is str and len(ref) <= 257, "AST_REF")
            parts = ref.split(".")
            _need(len(parts) == 2 and _name(parts[0]) == block, "AST_REF")
            _name(parts[1])
            source.append(":" + ref if op["kind"] == "item" else
                          "TO_CHAR(:" + ref + "," + _literal(op["format"]) + ")")
    rebuilt = parse_display_expression(" || ".join(source), block=block)
    _need(dict(parsed) == rebuilt, "PARSED_MISMATCH")
    return rebuilt


def bind_display_expression(parsed: Mapping, bindings: Mapping[str, Mapping]) -> dict:
    """Bind exact resolved storage columns, with explicit conservative byte caps.

    Each binding has exactly column/data_type/maximum_length/maximum_bytes/nullable.
    Character maximum_length preserves the source fact (or None when unknown),
    while maximum_bytes is a separately proven storage/value upper bound. DATE
    lengths must be None. Precision is never inferred from display formatting.
    Extra bindings, aliases of one column, implicit numbers and missing caps fail.
    """
    parsed = _validate_parsed(parsed)
    _need(isinstance(bindings, Mapping) and set(bindings) == set(parsed["refs"]), "BINDINGS")
    normalized, columns = {}, set()
    for ref in parsed["refs"]:
        binding = bindings[ref]
        _need(isinstance(binding, Mapping) and set(binding) == _BIND_KEYS, "BINDING_SHAPE")
        col, dtype = binding["column"], binding["data_type"]
        _need(type(col) is str and _COLUMN.fullmatch(col) and col not in columns, "COLUMN")
        _need(type(dtype) is str and dtype in {"CHAR", "VARCHAR2", "DATE"}, "TYPE")
        _need(type(binding["nullable"]) is bool, "NULLABLE")
        length, size = binding["maximum_length"], binding["maximum_bytes"]
        if dtype == "DATE":
            _need(length is None and size is None, "DATE_LENGTH")
        else:
            _need(type(size) is int and 1 <= size <= MAX_RESULT_BYTES, "BYTE_BOUND")
            _need(dtype != "CHAR" or size <= MAX_CHAR_BYTES, "CHAR_BYTE_BOUND")
            _need(length is None or (type(length) is int and 1 <= length <= size), "LENGTH")
        columns.add(col)
        normalized[ref] = dict(binding)
    size, nullable, char_prefix = 0, True, True
    for op in parsed["ast"]["operands"]:
        if op["kind"] == "literal":
            size += len(op["value"])
            nullable = nullable and op["value"] == ""
        else:
            binding = normalized[op["ref"]]
            _need(binding["data_type"] in ({"DATE"} if op["kind"] == "date_year" else
                  {"CHAR", "VARCHAR2"}), "OPERAND_TYPE")
            size += len(op["format"]) if op["kind"] == "date_year" else binding["maximum_bytes"]
            nullable = nullable and binding["nullable"]
            char_prefix = char_prefix and binding["data_type"] == "CHAR"
        # A prefix containing only CHAR columns/literals must fit Oracle CHAR's
        # smaller limit before a DATE TO_CHAR/VARCHAR2 operand promotes it.
        _need(size <= (MAX_CHAR_BYTES if char_prefix else MAX_RESULT_BYTES), "RESULT_BYTE_BOUND")
    _need(size <= MAX_RESULT_BYTES, "RESULT_BYTE_BOUND")
    result = {"scope": SCOPE, "expression": deepcopy(parsed), "bindings": normalized,
        "maximum_bytes": size, "nullable": nullable, "null_semantics": "oracle_concat",
        "precision": None, "runtime_verified": False, "business_accepted": False}
    result["contract_id"] = _digest(result)
    return result


def validate_display_expression(contract: Mapping) -> dict:
    """Rebuild every derived fact before use, including AST, refs and bindings."""
    _need(isinstance(contract, Mapping) and set(contract) == {"scope", "expression", "bindings",
        "maximum_bytes", "nullable", "null_semantics", "precision", "runtime_verified",
        "business_accepted", "contract_id"}, "CONTRACT_SHAPE")
    _need(type(contract["maximum_bytes"]) is int and type(contract["nullable"]) is bool and
          contract["precision"] is None and contract["runtime_verified"] is False and
          contract["business_accepted"] is False, "CONTRACT_FACTS")
    rebuilt = bind_display_expression(contract["expression"], contract["bindings"])
    _need(dict(contract) == rebuilt, "CONTRACT_MISMATCH")
    return rebuilt


def render_display_expression(contract: Mapping, *, row_alias: str = "r") -> str:
    """Return one parenthesized SQL expression; identifiers come only from bindings.

    Plain character columns retain leading zeroes and CHAR trailing blanks.
    Native || preserves Oracle NULL behavior, including an all-NULL result.
    """
    contract = validate_display_expression(contract)
    _need(type(row_alias) is str and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,29}", row_alias), "ROW_ALIAS")
    pieces = []
    for op in contract["expression"]["ast"]["operands"]:
        if op["kind"] == "literal":
            pieces.append(_literal(op["value"]))
        else:
            col = row_alias + '."' + contract["bindings"][op["ref"]]["column"] + '"'
            pieces.append(col if op["kind"] == "item" else "TO_CHAR(" + col + ", '" + op["format"] + "')")
    return "(" + " || ".join(pieces) + ")"
