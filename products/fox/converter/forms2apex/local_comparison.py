"""Closed pure module-local character equality grammar and SQL rendering.

This module never executes source or compares values in Python. Oracle performs
VARCHAR2 equality, NULL/empty handling and concatenation in the emitted CASE.
"""
from __future__ import annotations

import re

MAX_TEXT = 4096
MAX_PARTS = 64
_IDENT = re.compile(r"[A-Z][A-Z0-9_$#]{0,127}\Z")
_TARGET = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")
_RESERVED = set("FUNCTION RETURN NUMBER VARCHAR2 IS AS BEGIN END IF THEN ELSE IN OUT NULL SELECT INSERT UPDATE DELETE COMMIT ROLLBACK EXCEPTION PRAGMA".split())


class ComparisonError(ValueError):
    """Bounded diagnostic without customer source text."""


def _need(condition, reason):
    if not condition:
        raise ComparisonError("local_comparison_" + reason)


def _name(value):
    _need(type(value) is str and _IDENT.fullmatch(value) and value not in _RESERVED,
          "identifier_invalid")
    return value


def _tokens(text):
    _need(type(text) is str and 0 < len(text) <= MAX_TEXT, "text_size_invalid")
    result, pos = [], 0
    while pos < len(text):
        if text[pos].isspace():
            pos += 1
            continue
        if text.startswith("--", pos):
            end = re.search(r"[\r\n]", text[pos + 2:])
            pos = len(text) if end is None else pos + 2 + end.start() + 1
            continue
        if text.startswith("/*", pos):
            end = text.find("*/", pos + 2)
            _need(end >= 0 and "/*" not in text[pos + 2:end], "comment_invalid")
            pos = end + 2
            continue
        if text[pos] == "'":
            pos += 1
            value = []
            while pos < len(text):
                if text.startswith("''", pos):
                    value.append("'")
                    pos += 2
                elif text[pos] == "'":
                    pos += 1
                    break
                else:
                    value.append(text[pos])
                    pos += 1
            else:
                raise ComparisonError("local_comparison_literal_unterminated")
            result.append(("string", "".join(value)))
        else:
            match = re.match(r"[A-Za-z][A-Za-z0-9_$#]*", text[pos:])
            if match:
                word = match.group().upper()
                _need(_IDENT.fullmatch(word), "identifier_invalid")
                result.append(("word", word))
                pos += len(match.group())
            elif text.startswith((":=", "||"), pos):
                result.append(("symbol", text[pos:pos + 2]))
                pos += 2
            else:
                _need(text[pos] in ":.,();=01", "token_unsupported")
                result.append(("number" if text[pos].isdigit() else "symbol", text[pos]))
                pos += 1
        _need(len(result) <= 512, "token_limit")
    return result


class _Parser:
    def __init__(self, text):
        self.tokens, self.pos = _tokens(text), 0

    def peek(self, value):
        return self.pos < len(self.tokens) and self.tokens[self.pos][1] == value

    def take(self, value=None, kind=None):
        _need(self.pos < len(self.tokens), "incomplete")
        token = self.tokens[self.pos]
        if value is not None and kind is None:
            kind = "word" if _IDENT.fullmatch(value) else "number" if value.isdigit() else "symbol"
        _need((value is None or token[1] == value) and (kind is None or token[0] == kind), "syntax_invalid")
        self.pos += 1
        return token[1]

    def name(self):
        return _name(self.take(kind="word"))

    def end(self):
        _need(self.pos == len(self.tokens), "extra_active_source")

    def returns(self, value):
        self.take("RETURN")
        wrapped = self.peek("(")
        if wrapped:
            self.take("(")
        self.take(value)
        if wrapped:
            self.take(")")
        self.take(";")


def parse_function(text):
    """Consume a complete function, with no inactive suffix or extra statement."""
    p = _Parser(text)
    p.take("FUNCTION")
    name = p.name()
    p.take("(")
    args = []
    for index in range(2):
        if index:
            p.take(",")
        args.append(p.name())
        if p.peek("IN"):
            p.take("IN")
        p.take("VARCHAR2")
    _need(len(set([name, *args])) == 3, "ambiguous_identifier")
    p.take(")")
    p.take("RETURN")
    p.take("NUMBER")
    p.take("AS" if p.peek("AS") else "IS")
    variable = None
    if not p.peek("BEGIN"):
        variable = p.name()
        _need(variable not in [name, *args], "ambiguous_identifier")
        for token in ("NUMBER", ":=", "0", ";"):
            p.take(token)
    p.take("BEGIN")
    p.take("IF")
    p.take(args[0])
    p.take("=")
    p.take(args[1])
    p.take("THEN")
    if variable:
        for token in (variable, ":=", "1", ";", "END", "IF", ";"):
            p.take(token)
        p.returns(variable)
    else:
        p.returns("1")
        if p.peek("ELSE"):
            p.take("ELSE")
            p.returns("0")
            for token in ("END", "IF", ";"):
                p.take(token)
        else:
            for token in ("END", "IF", ";"):
                p.take(token)
            p.returns("0")
    p.take("END")
    if p.peek(name):
        p.take(name)
    p.take(";")
    p.end()
    return {"schema_version": 1, "function_name": name, "argument_names": args,
            "semantic_kind": "varchar2_equality_number"}


def parse_call(text):
    p = _Parser(text)
    name = p.name()
    p.take("(")
    args = []
    for index in range(2):
        if index:
            p.take(",")
        parts = []
        while True:
            if p.peek(":"):
                p.take(":")
                names = [p.name()]
                if p.peek("."):
                    p.take(".")
                    names.append(p.name())
                parts.append({"kind": "reference", "parts": names})
            elif p.peek("NULL"):
                p.take("NULL")
                parts.append({"kind": "null"})
            else:
                parts.append({"kind": "literal", "value": p.take(kind="string")})
            _need(len(parts) <= MAX_PARTS, "part_limit")
            if not p.peek("||"):
                break
            p.take("||")
        args.append({"kind": "concat", "parts": parts})
    p.take(")")
    p.end()
    value = {"schema_version": 1, "function": name, "args": args}
    validate_expression(value)
    return value


def validate_expression(value):
    _need(type(value) is dict and set(value) == {"schema_version", "function", "args"}
          and type(value["schema_version"]) is int and value["schema_version"] == 1,
          "expression_invalid")
    _name(value["function"])
    _need(type(value["args"]) is list and len(value["args"]) == 2, "arity_invalid")
    refs, size = [], 0
    for arg in value["args"]:
        _need(type(arg) is dict and set(arg) == {"kind", "parts"} and arg["kind"] == "concat"
              and type(arg["parts"]) is list and 1 <= len(arg["parts"]) <= MAX_PARTS, "argument_invalid")
        for part in arg["parts"]:
            _need(type(part) is dict, "part_invalid")
            kind = part.get("kind")
            if kind == "literal":
                _need(set(part) == {"kind", "value"} and type(part["value"]) is str
                      and not any(ord(c) < 32 or c in "`&" for c in part["value"]), "literal_invalid")
                size += len(part["value"])
                _need(size <= MAX_TEXT, "literal_limit")
            elif kind == "null":
                _need(set(part) == {"kind"}, "part_invalid")
            else:
                _need(kind == "reference" and set(part) == {"kind", "parts"}
                      and type(part["parts"]) is list and 1 <= len(part["parts"]) <= 2, "reference_invalid")
                for name in part["parts"]:
                    _name(name)
                ref = tuple(part["parts"])
                if ref not in refs:
                    refs.append(ref)
    return refs


def render_sql(expression, bindings):
    refs = validate_expression(expression)
    _need(type(bindings) is dict and set(bindings) == set(refs), "binding_mismatch")
    for value in bindings.values():
        _need(type(value) is str and _TARGET.fullmatch(value.lstrip(":"))
              and value.count(":") <= 1 and (":" not in value or value.startswith(":")), "target_invalid")
    def part_sql(part):
        if part["kind"] == "reference":
            return bindings[tuple(part["parts"])]
        if part["kind"] == "null":
            return "null"
        return "'" + part["value"].replace("'", "''") + "'"
    args = ["(" + " || ".join(part_sql(part) for part in arg["parts"]) + ")" for arg in expression["args"]]
    # Formal parameters were VARCHAR2, whereas SQL character literals are CHAR.
    # Cast both evaluated arguments so Oracle never applies blank-padded CHAR
    # comparison semantics to a source VARCHAR2 function call.
    return f"case when cast({args[0]} as varchar2(4000)) = cast({args[1]} as varchar2(4000)) then 1 else 0 end"
