"""Finite grammar and pure semantic models, not Oracle runtime evidence."""
from copy import deepcopy

import pytest

from forms2apex.source_lookup import (
    UnsupportedLookup, parse_lookup_trigger, model_lookup_result, model_equality,
)

BODY = """BEGIN
 SELECT R.DEST, C.LABEL INTO :DESTINATION, :CITY
 FROM APP.ROUTES, APP.CITIES
 WHERE R.CODE = :ROUTE AND C.CODE = R.DEST;
 EXCEPTION WHEN NO_DATA_FOUND THEN :CITY := NULL; :DESTINATION := NULL; END;"""
# The finite grammar preserves exact table names, without inventing aliases.
BODY = BODY.replace("R.", "ROUTES.").replace("C.", "CITIES.")


def test_complete_query_and_reset_order_with_case_and_comments():
    parsed, proof = parse_lookup_trigger("-- source&#10;" + BODY.lower() + " /* end */")
    assert parsed["query"]["tables"] == [{"parts": ["APP", "ROUTES"]}, {"parts": ["APP", "CITIES"]}]
    assert parsed["query"]["projections"][0] == {"kind": "column", "parts": ["ROUTES", "DEST"]}
    assert parsed["input_refs"] == [["ROUTE"]]
    assert parsed["reset_refs"] == [["CITY"], ["DESTINATION"]]
    assert parsed["exception_kind"] == "NO_DATA_FOUND"
    assert proof["substitutions"][0]["codepoint"] == 10
    assert proof["raw_sha256"] != proof["semantic_sha256"]


@pytest.mark.parametrize("old,new", [
    ("BEGIN", "DECLARE v NUMBER; BEGIN"),
    ("SELECT ROUTES.DEST", "SELECT MAX(ROUTES.DEST)"),
    ("SELECT ROUTES.DEST", "SELECT DISTINCT ROUTES.DEST"),
    ("ROUTES.CODE = :ROUTE", "ROUTES.CODE IN (SELECT CODE FROM OTHER)"),
    (" AND ", " OR "),
    (" = :ROUTE", " != :ROUTE"),
    ("FROM APP.ROUTES, APP.CITIES", "FROM APP.ROUTES R, APP.CITIES C"),
    ("ROUTES.CODE", '"ROUTES".CODE'),
    (";\n EXCEPTION", "; COMMIT; EXCEPTION"),
    (";\n EXCEPTION", " FOR UPDATE; EXCEPTION"),
    ("NO_DATA_FOUND", "TOO_MANY_ROWS"),
    ("END;", "END; DELETE FROM SECRET;"),
    ("ROUTES.CODE = :ROUTE", "ROUTES.CODE = :ROUTE AND ROWNUM = 1"),
    ("ROUTES.CODE = :ROUTE", "MISSING.CODE = :ROUTE"),
    ("BEGIN", "/* /* nested */ */ BEGIN"),
    ("BEGIN", r"BEGIN\t"),
])
def test_whole_event_rejects_unknown_active_grammar(old, new):
    assert old in BODY
    with pytest.raises(UnsupportedLookup):
        parse_lookup_trigger(BODY.replace(old, new))


def test_literals_comments_and_encoded_line_terminators_cannot_hide_source():
    body = BODY.replace("ROUTES.CODE = :ROUTE", "ROUTES.CODE = :ROUTE AND CITIES.STATUS = 'A'';--B'")
    parsed, _ = parse_lookup_trigger(body)
    assert parsed["query"]["predicates"][1]["right"] == {"kind": "string", "value": "A';--B"}
    with pytest.raises(UnsupportedLookup, match="ambiguous_entity"):
        parse_lookup_trigger(body.replace("A'';--B", "A&#10;B"))
    with pytest.raises(UnsupportedLookup):
        parse_lookup_trigger(BODY + " -- comment&#10;COMMIT;")
    with pytest.raises(UnsupportedLookup):
        parse_lookup_trigger(BODY + " /* unfinished")


def test_bounded_signed_numeric_and_schema_qualified_columns():
    parsed, _ = parse_lookup_trigger(BODY.replace("ROUTES.CODE = :ROUTE", "APP.ROUTES.CODE = :ROUTE AND CITIES.FLAG = -12.50"))
    assert parsed["query"]["predicates"][1]["right"] == {"kind": "number", "value": "-12.50"}


def test_model_cardinality_errors_and_reset_order_are_distinct():
    op = {"exception_kind": "NO_DATA_FOUND", "output_bindings": [{"source_item_id": "a"}, {"source_item_id": "b"}], "reset_order": ["b", "a"]}
    before = deepcopy(op)
    result = model_lookup_result(op, [])
    assert result["assignments"] == [{"source_item_id": "b", "value": None}, {"source_item_id": "a", "value": None}]
    assert model_lookup_result(op, [[" x ", 3]])["assignments"] == [{"source_item_id": "a", "value": " x "}, {"source_item_id": "b", "value": 3}]
    assert model_lookup_result(op, [[1, 2], [3, 4]])["raised"] == "TOO_MANY_ROWS"
    assert model_lookup_result(op, [], error="VALUE_ERROR")["raised"] == "VALUE_ERROR"
    assert op == before
    op["exception_kind"] = "OTHERS"
    for rows, error in [([], None), ([[1, 2], [3, 4]], None), ([], "VALUE_ERROR"), ([], "OTHER")]:
        result = model_lookup_result(op, rows, error=error)
        assert result["raised"] is None and result["assignments"][0]["source_item_id"] == "b"
        assert result["runtime_verified"] is False


def test_null_query_equality_is_unknown_not_false_or_match():
    for left, right in [(None, "x"), ("x", None), (None, None), ("", "")]:
        assert model_equality(left, right) is None
    assert model_equality(" x ", "x") is False
    assert model_equality(" x ", " x ") is True
