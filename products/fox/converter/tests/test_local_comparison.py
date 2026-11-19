"""Pure synthetic grammar checks; Oracle semantics are retained as native SQL."""
import pytest

from forms2apex import local_comparison as comparison


def function(name="SAME_TEXT", left="FIRST_VALUE", right="SECOND_VALUE"):
    return (f"FUNCTION {name}({left} VARCHAR2, {right} IN VARCHAR2) RETURN NUMBER IS "
            f"result NUMBER := 0; BEGIN IF {left} = {right} THEN result := 1; "
            "END IF; RETURN(result); END;")


@pytest.mark.parametrize("name,left,right", [("SAME_TEXT", "FIRST_VALUE", "SECOND_VALUE"),
                                               ("MATCH_VALUE", "INPUT_A", "INPUT_B")])
def test_renamed_whole_functions_and_native_expression(name, left, right):
    definition = comparison.parse_function(function(name, left, right))
    assert definition["function_name"] == name
    assert definition["argument_names"] == [left, right]
    expression = comparison.parse_call(f"{name}(:PANEL.KEY_VALUE, :ROWS.PREFIX || :ROWS.CODE)")
    assert comparison.render_sql(expression, {("PANEL", "KEY_VALUE"): ":P7_KEY_VALUE",
           ("ROWS", "PREFIX"): "F_PREFIX", ("ROWS", "CODE"): "F_CODE"}) == (
               "case when cast((:P7_KEY_VALUE) as varchar2(4000)) = cast((F_PREFIX || F_CODE) as varchar2(4000)) then 1 else 0 end")


@pytest.mark.parametrize("left,right", [("'equal'", "'equal'"), ("'equal'", "'other'"),
                                         ("NULL", "NULL"), ("''", "''"),
                                         ("NULL || 'x'", "'x'"), ("'x' || ''", "'x'"),
                                         ("'a''b'", "'a''b'"), ("'X'", "'X '"),
                                         ("'X ' || ''", "'X'"), ("' ' || NULL", "' '")])
def test_exact_native_case_preserves_null_empty_concat_and_literal_values(left, right):
    expression = comparison.parse_call(f"MATCH_VALUE({left}, {right})")
    assert comparison.render_sql(expression, {}) == (
        f"case when cast(({left.replace('NULL', 'null')}) as varchar2(4000)) = "
        f"cast(({right.replace('NULL', 'null')}) as varchar2(4000)) then 1 else 0 end")


@pytest.mark.parametrize("change", [
    lambda s: s + " COMMIT;", lambda s: "COMMIT; " + s,
    lambda s: s.replace("END IF;", "DELETE FROM T; END IF;"),
    lambda s: s.replace("RETURN(result);", "result := GLOBAL_VALUE; RETURN(result);"),
    lambda s: s.replace("THEN result := 1", "THEN result := SAME_TEXT(FIRST_VALUE, SECOND_VALUE)"),
    lambda s: s.replace("IN VARCHAR2", "OUT VARCHAR2"),
    lambda s: s.replace("RETURN NUMBER", "RETURN VARCHAR2"),
    lambda s: s.replace("FIRST_VALUE = SECOND_VALUE", "UPPER(FIRST_VALUE) = SECOND_VALUE"),
    lambda s: s.replace("result NUMBER := 0;", "result NUMBER;"),
    lambda s: s.replace("RETURN(result)", "RETURN(1)"),
    lambda s: s.replace("END;", "EXCEPTION WHEN OTHERS THEN RETURN 0; END;"),
    lambda s: s.replace("THEN", "'THEN'"),
])
def test_no_partial_function_or_side_effects(change):
    with pytest.raises(comparison.ComparisonError):
        comparison.parse_function(change(function()))


def test_comments_and_direct_return_are_complete_and_bounded():
    text = "FUNCTION CHECK_TEXT(A VARCHAR2,B VARCHAR2) RETURN NUMBER AS BEGIN /* COMMIT; */ IF A=B THEN RETURN 1; ELSE RETURN(0); END IF; END CHECK_TEXT;"
    assert comparison.parse_function(text)["function_name"] == "CHECK_TEXT"
    with pytest.raises(comparison.ComparisonError):
        comparison.parse_function(text + "/* unterminated")


@pytest.mark.parametrize("text", ["F('a','b'); COMMIT;", "PKG.F('a','b')", "F(:A, :B, :C)",
                                    "F(UPPER(:A),:B)", "F(1,2)", "F(:A + :B,:C)",
                                    "F(" + "'x'||" * 65 + "'x','b')", "F('`sql','b')"])
def test_unsupported_call_syntax_fails_closed(text):
    with pytest.raises(comparison.ComparisonError):
        comparison.parse_call(text)


def test_untrusted_ast_and_binding_are_revalidated():
    value = comparison.parse_call("F(:A,'x')")
    for binding in ("C_A); COMMIT; --", "A:B", "::P7_A", "P7_A\n"):
        with pytest.raises(comparison.ComparisonError):
            comparison.render_sql(value, {("A",): binding})
    value["args"][0]["parts"][0]["sql"] = "select 1"
    with pytest.raises(comparison.ComparisonError):
        comparison.validate_expression(value)
