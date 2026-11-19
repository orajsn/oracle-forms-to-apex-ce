"""Bounded numeric Forms expressions, represented without executable SQL strings.

Decimal literals deliberately exclude exponent/float notation. Rendering retains
native NUMBER arithmetic, NULLs and errors; it never evaluates or repairs them.
References retain source names until an independent exact binding check supplies
target columns. The JSON AST is a closed, versioned data contract.
"""
from __future__ import annotations

import re

MAX_TEXT = 4096
MAX_NODES = 256
MAX_DEPTH = 32
_IDENT = re.compile(r"[A-Z][A-Z0-9_$#]{0,127}\Z")
_COLUMN = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")
_DECIMAL = re.compile(r"(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)\Z")
_ARITY = {"CEIL": (1,), "FLOOR": (1,), "ABS": (1,),
          "ROUND": (1, 2), "TRUNC": (1, 2), "NVL": (2,)}


class NumericExpressionError(ValueError):
    """Stable diagnostics with no source content."""


def _need(condition, reason):
    if not condition:
        raise NumericExpressionError("numeric_expression_" + reason)


def _literal(value):
    _need(type(value) is str and len(value) <= 80 and _DECIMAL.fullmatch(value)
          and sum(c.isdigit() for c in value) <= 38, "literal_invalid")


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
        match = re.match(r"(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)", text[pos:])
        if match:
            value = match.group()
            _literal(value)
            result.append(("number", value))
            pos += len(value)
        else:
            match = re.match(r"[A-Za-z][A-Za-z0-9_$#]*", text[pos:])
            if match:
                value = match.group().upper()
                _need(_IDENT.fullmatch(value), "identifier_invalid")
                result.append(("word", value))
                pos += len(value)
            else:
                _need(text[pos] in ":.,()+-*/", "active_token_unsupported")
                result.append(("symbol", text[pos]))
                pos += 1
        _need(len(result) <= MAX_NODES * 4, "token_limit")
    return result


class _Parser:
    def __init__(self, tokens):
        self.tokens, self.pos, self.nodes = tokens, 0, 0

    def peek(self, *values):
        return self.pos < len(self.tokens) and self.tokens[self.pos][1] in values

    def take(self, value=None, kind=None):
        _need(self.pos < len(self.tokens), "incomplete")
        token = self.tokens[self.pos]
        _need((value is None or token[1] == value) and (kind is None or token[0] == kind), "syntax_invalid")
        self.pos += 1
        return token[1]

    def node(self, kind, **kwargs):
        self.nodes += 1
        _need(self.nodes <= MAX_NODES, "node_limit")
        return {"kind": kind, **kwargs}

    def expression(self, depth=1, minimum=0):
        _need(depth <= MAX_DEPTH, "depth_limit")
        if self.peek("+", "-"):
            left = self.node("unary", operator=self.take(), operand=self.expression(depth + 1, 3))
        elif self.peek("("):
            self.take("(")
            left = self.expression(depth + 1)
            self.take(")")
        elif self.peek(":"):
            self.take(":")
            parts = [self.take(kind="word")]
            if self.peek("."):
                self.take(".")
                parts.append(self.take(kind="word"))
            left = self.node("reference", parts=parts)
        elif self.pos < len(self.tokens) and self.tokens[self.pos][0] == "number":
            left = self.node("number", value=self.take(kind="number"))
        elif self.peek("NULL"):
            self.take("NULL", "word")
            left = self.node("null")
        else:
            function = self.take(kind="word")
            _need(function in _ARITY, "function_unsupported")
            self.take("(")
            args = [self.expression(depth + 1)]
            if self.peek(","):
                self.take(",")
                args.append(self.expression(depth + 1))
            self.take(")")
            _need(len(args) in _ARITY[function], "arity_invalid")
            left = self.node("call", function=function, args=args)
        while self.peek("+", "-", "*", "/"):
            operator = self.tokens[self.pos][1]
            precedence = 1 if operator in ("+", "-") else 2
            if precedence < minimum:
                break
            self.take()
            right = self.expression(depth + 1, precedence + 1)
            left = self.node("binary", operator=operator, left=left, right=right)
        return left


def validate_expression(expression):
    """Validate every field and bound; return ordered unique source references."""
    _need(type(expression) is dict and set(expression) == {"schema_version", "root"}
          and type(expression["schema_version"]) is int and expression["schema_version"] == 1,
          "version_invalid")
    refs, count = [], 0

    def visit(node, depth):
        nonlocal count
        count += 1
        _need(depth <= MAX_DEPTH and count <= MAX_NODES, "ast_limit")
        _need(type(node) is dict and type(node.get("kind")) is str, "node_invalid")
        kind = node["kind"]
        fields = {"number": {"value"}, "null": set(), "reference": {"parts"},
                  "unary": {"operator", "operand"}, "binary": {"operator", "left", "right"},
                  "call": {"function", "args"}}
        _need(kind in fields and set(node) == {"kind"} | fields[kind], "node_fields_invalid")
        if kind == "number":
            _literal(node["value"])
        elif kind == "reference":
            parts = node["parts"]
            _need(type(parts) is list and 1 <= len(parts) <= 2
                  and all(type(p) is str and _IDENT.fullmatch(p) for p in parts), "reference_invalid")
            ref = tuple(parts)
            if ref not in refs:
                refs.append(ref)
        elif kind in ("unary", "binary"):
            _need(type(node["operator"]) is str and node["operator"] in
                  (("+", "-") if kind == "unary" else ("+", "-", "*", "/")), "operator_invalid")
            for key in (("operand",) if kind == "unary" else ("left", "right")):
                visit(node[key], depth + 1)
        elif kind == "call":
            function, args = node["function"], node["args"]
            _need(type(function) is str and function in _ARITY and type(args) is list
                  and len(args) in _ARITY[function], "function_or_arity_invalid")
            for arg in args:
                visit(arg, depth + 1)
    visit(expression["root"], 1)
    return refs


def parse_expression(text):
    """Parse one complete expression, never a statement or raw SQL fragment."""
    parser = _Parser(_tokens(text))
    result = {"schema_version": 1, "root": parser.expression()}
    _need(parser.pos == len(parser.tokens), "trailing_tokens")
    validate_expression(result)
    return result


def render_sql(expression, bindings):
    """Render only validated nodes and an exact mapping of reference tuples."""
    refs = validate_expression(expression)
    _need(type(bindings) is dict and set(bindings) == set(refs)
          and all(type(v) is str and _COLUMN.fullmatch(v) for v in bindings.values()), "bindings_invalid")

    def render(node):
        kind = node["kind"]
        if kind == "number":
            return node["value"]
        if kind == "null":
            return "null"
        if kind == "reference":
            return bindings[tuple(node["parts"])]
        if kind == "unary":
            return "(" + node["operator"] + render(node["operand"]) + ")"
        if kind == "binary":
            return "(" + render(node["left"]) + " " + node["operator"] + " " + render(node["right"]) + ")"
        return node["function"].lower() + "(" + ", ".join(render(arg) for arg in node["args"]) + ")"
    return render(expression["root"])
