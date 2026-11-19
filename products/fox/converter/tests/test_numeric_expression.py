"""Closed grammar and SQL emission checks, with no Oracle execution claim."""
from copy import deepcopy

import pytest

from forms2apex.numeric_expression import (
    NumericExpressionError, parse_expression, render_sql, validate_expression,
)


@pytest.mark.parametrize("text,sql", [
    ("1 + 2 * 3", "(1 + (2 * 3))"),
    ("(1 + 2) * 3", "((1 + 2) * 3)"),
    ("8 / 4 / 2", "((8 / 4) / 2)"),
    ("8 - (4 - 2)", "(8 - (4 - 2))"),
    ("-:MASS * +2", "((-C_MASS) * (+2))"),
    ("NVL(NULL, .5) + 1.", "(nvl(null, .5) + 1.)"),
    ("round(trunc(abs(-:MASS), 2), -1)", "round(trunc(abs((-C_MASS)), 2), (-1))"),
    ("ceil(:MASS) + floor(:PARCEL.MASS)", "(ceil(C_MASS) + floor(C_MASS))"),
    ("1 / 0", "(1 / 0)"),
    ("NULL / :MASS", "(null / C_MASS)"),
    ("/* inert */ TRUNC(:MASS) -- trailing comment", "trunc(C_MASS)"),
    ("ROUND(:MASS)", "round(C_MASS)"),
])
def test_exact_expression_structure_preserves_native_arithmetic(text, sql):
    expression = parse_expression(text)
    bindings = {ref: "C_MASS" for ref in validate_expression(expression)}
    assert render_sql(expression, bindings) == sql
    assert parse_expression(text) == expression


@pytest.mark.parametrize("text", [
    "", " ", "CEILING(:MASS)", "POWER(2, 3)", "DBMS_X.RUN(1)",
    "CEIL()", "FLOOR(1, 2)", "ABS(1, 2)", "ROUND(1, 2, 3)", "NVL(1)",
    "1; COMMIT;", "CEIL(:MASS) FROM X", "SELECT 1 FROM DUAL", "(SELECT 1 FROM DUAL)",
    "'1'", '"MASS"', "MASS", ":A.B.C", ":1", ":", ":MASS || 1", "1 = 1",
    "1e3", "1f", "1d", "NaN", "Infinity", "1,2", "1..2", "1 2", "1 +", "* 2",
    "/* no end", "/* /* nested */ 1 */", "(1", "1)", "'CEIL'(1)", "NULL(1)",
    "9" * 39, "0." + "0" * 39, "(" * 40 + "1" + ")" * 40,
    "-" * 40 + "1", "1+" * 200 + "1", "1" + " " * 4096,
])
def test_unsupported_oversized_or_partial_source_rejected(text):
    with pytest.raises(NumericExpressionError):
        parse_expression(text)


@pytest.mark.parametrize("mutate", [
    lambda e: e.update(schema_version=True),
    lambda e: e.update(sql="select 1"),
    lambda e: e["root"].update(raw_sql="1"),
    lambda e: e["root"].update(function="DELETE"),
    lambda e: e["root"].update(args=[]),
    lambda e: e["root"]["args"][0].update(parts=["MASS;COMMIT"]),
    lambda e: e["root"]["args"][0].update(parts=["mass"]),
    lambda e: e["root"]["args"][0].update(parts="MASS"),
    lambda e: e["root"]["args"][1].update(value=1),
    lambda e: e["root"]["args"][1].update(value="1e3"),
])
def test_ast_is_independently_validated_not_trusted(mutate):
    expression = parse_expression("NVL(:MASS, 1)")
    mutate(expression)
    with pytest.raises(NumericExpressionError):
        render_sql(expression, {("MASS",): "C_MASS"})


def test_cyclic_ast_is_bounded_without_recursion_error():
    node = {"kind": "unary", "operator": "-"}
    node["operand"] = node
    with pytest.raises(NumericExpressionError, match="ast_limit"):
        validate_expression({"schema_version": 1, "root": node})


@pytest.mark.parametrize("bindings", [
    {}, {("OTHER",): "C_MASS"}, {("MASS",): "C_MASS", ("OTHER",): "C_OTHER"},
    {("MASS",): "C_MASS from X"}, {("MASS",): "1"}, {("MASS",): None},
])
def test_exact_closed_target_bindings_required(bindings):
    with pytest.raises(NumericExpressionError):
        render_sql(parse_expression(":MASS"), bindings)


def test_reference_identity_deduplicates_only_identical_source_paths():
    expression = parse_expression(":MASS + :MASS + :PARCEL.MASS")
    before = deepcopy(expression)
    assert validate_expression(expression) == [("MASS",), ("PARCEL", "MASS")]
    assert render_sql(expression, {("MASS",): "C_MASS", ("PARCEL", "MASS"): "C_MASS"}) == "((C_MASS + C_MASS) + C_MASS)"
    assert expression == before
