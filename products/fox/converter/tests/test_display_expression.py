"""Synthetic parser/render boundary checks, not an Oracle runtime substitute."""
from copy import deepcopy
import unittest

from forms2apex.display_expression import (
    MAX_EXPRESSION_CHARACTERS, MAX_OPERANDS, _digest, bind_display_expression,
    parse_display_expression, render_display_expression, validate_display_expression,
)


def bindings():
    return {
        "SAMPLE.CODE": {"column": "F001", "data_type": "VARCHAR2", "maximum_length": 8,
                        "maximum_bytes": 8, "nullable": False},
        "SAMPLE.OTHER": {"column": "F002", "data_type": "CHAR", "maximum_length": 6,
                         "maximum_bytes": 24, "nullable": True},
        "SAMPLE.STAMP": {"column": "F003", "data_type": "DATE", "maximum_length": None,
                         "maximum_bytes": None, "nullable": True},
    }


def compile_expression(text=":sample.code || TO_CHAR(:sample.stamp,'RR')", **changes):
    parsed = parse_display_expression(text, block="SAMPLE")
    bound = {ref: bindings()[ref] for ref in parsed["refs"]}
    for ref, values in changes.items():
        bound[ref].update(values)
    return bind_display_expression(parsed, bound)


def reseal_expression(parsed):
    parsed["expression_id"] = _digest({k: v for k, v in parsed.items() if k != "expression_id"})


def reseal_contract(contract):
    contract["contract_id"] = _digest({k: v for k, v in contract.items() if k != "contract_id"})


class DisplayExpressionTests(unittest.TestCase):
    def test_canonical_refs_ast_and_case_whitespace_equivalence(self):
        parsed = parse_display_expression(" :code||to_char( :sample . stamp , 'rr' ) ", block="sample")
        expected = parse_display_expression(":SAMPLE.CODE || TO_CHAR(:SAMPLE.STAMP, 'RR')", block="SAMPLE")
        self.assertEqual(parsed, expected)
        self.assertEqual(parsed["refs"], ["SAMPLE.CODE", "SAMPLE.STAMP"])
        self.assertEqual(parsed["ast"], {"kind": "concat", "operands": [
            {"kind": "item", "ref": "SAMPLE.CODE"},
            {"kind": "date_year", "ref": "SAMPLE.STAMP", "format": "RR"}]})

    def test_exact_sql_uses_only_resolved_columns_and_explicit_date_format(self):
        contract = compile_expression()
        before = deepcopy(contract)
        sql = render_display_expression(contract)
        self.assertEqual(sql, '(r."F001" || TO_CHAR(r."F003", \'RR\'))')
        self.assertEqual(sql, render_display_expression(contract))
        self.assertEqual(before, contract)
        self.assertNotIn("SAMPLE", sql)
        self.assertNotIn(":", sql)
        self.assertEqual(contract["maximum_bytes"], 10)
        self.assertIsNone(contract["precision"])
        self.assertFalse(contract["runtime_verified"])
        self.assertFalse(contract["business_accepted"])

    def test_both_year_formats_and_repeated_refs(self):
        contract = compile_expression("TO_CHAR(:STAMP,'YYYY') || :CODE || TO_CHAR(:STAMP,'RR')")
        self.assertEqual(contract["maximum_bytes"], 14)
        self.assertEqual(len(contract["bindings"]), 2)
        self.assertEqual(render_display_expression(contract, row_alias="q"),
            '(TO_CHAR(q."F003", \'YYYY\') || q."F001" || TO_CHAR(q."F003", \'RR\'))')

    def test_character_columns_keep_leading_zeroes_and_char_trailing_blanks(self):
        # Direct columns preserve values such as '0012' and CHAR padded blanks;
        # no numeric conversion, trimming, padding or NULL replacement is emitted.
        contract = compile_expression(":CODE || :OTHER")
        self.assertEqual(render_display_expression(contract), '(r."F001" || r."F002")')
        self.assertEqual(contract["maximum_bytes"], 32)
        self.assertEqual(contract["bindings"]["SAMPLE.OTHER"]["maximum_length"], 6)
        self.assertEqual(contract["bindings"]["SAMPLE.OTHER"]["maximum_bytes"], 24)

    def test_optional_date_and_all_null_concat_remain_nullable(self):
        contract = compile_expression(**{"SAMPLE.CODE": {"nullable": True}})
        self.assertTrue(contract["nullable"])
        self.assertEqual(contract["null_semantics"], "oracle_concat")
        self.assertNotIn("NVL", render_display_expression(contract))
        self.assertFalse(compile_expression()["nullable"])

    def test_empty_literal_is_null_and_nonempty_literal_makes_result_nonnull(self):
        for literal, nullable in [("''", True), ("'x'", False)]:
            contract = compile_expression(literal + " || TO_CHAR(:STAMP,'YYYY')")
            self.assertIs(contract["nullable"], nullable)

    def test_quoted_ascii_literal_is_escaped_as_data(self):
        contract = compile_expression("'x''); DROP TABLE SAMPLE; --' || :CODE")
        self.assertEqual(render_display_expression(contract),
                         "('x''); DROP TABLE SAMPLE; --' || r.\"F001\")")
        self.assertEqual(contract["expression"]["ast"]["operands"][0]["value"],
                         "x'); DROP TABLE SAMPLE; --")

    def test_rejects_nonfinite_grammar_and_context(self):
        bad = ["", ":CODE", "'x' || 'y'", ":CODE ||", "|| :CODE", ":CODE + :OTHER",
            ":CODE || :OTHER;", "BEGIN :CODE || :OTHER END;", ":TARGET := :CODE || :OTHER",
            ":CODE || :GLOBAL.USERNAME", ":CODE || :OTHERBLOCK.CODE", ":CODE || :SYSTEM.X",
            "CODE || :OTHER", '"CODE" || :OTHER', ":CODE || 123", ":CODE || NULL",
            ":CODE || upper(:OTHER)", ":CODE || NVL(:OTHER,'x')", ":CODE || SYSDATE",
            ":CODE || (SELECT CODE FROM SAMPLE)", ":CODE || (:OTHER)",
            ":CODE /*comment*/ || :OTHER", ":CODE --comment\n || :OTHER",
            ":CODE || TO_CHAR(:STAMP)", ":CODE || TO_CHAR(:STAMP,'YY')",
            ":CODE || TO_CHAR(:STAMP,'YYYY-MM-DD')", ":CODE || TO_CHAR(SYSDATE,'YYYY')",
            ":CODE || TO_CHAR(:STAMP,'RR','NLS_DATE_LANGUAGE=ENGLISH')",
            ":CODE || TO_CHAR(TO_DATE(:OTHER),'YYYY')", ":CODE || :SAMPLE.CODE.EXTRA",
            ":CODE || 'unfinished", ":CODE || q'[quoted]'", ":CODE || N'x'",
            ":CODE || 'unicode\u2603'", ":CODE || 'line\nbreak'", ":CODE || '\x00'",
            ":CODE || '" + "x" * 257 + "'", " " * (MAX_EXPRESSION_CHARACTERS + 1),
            " || ".join([":CODE"] * (MAX_OPERANDS + 1))]
        for expression in bad:
            with self.subTest(expression=expression[:80]), self.assertRaises(ValueError):
                parse_display_expression(expression, block="SAMPLE")
        for block in ("GLOBAL", "SYSTEM", "PARAMETER", "SAMPLE;DROP", ""):
            with self.subTest(block=block), self.assertRaises(ValueError):
                parse_display_expression(":CODE || :OTHER", block=block)

    def test_rejects_bindings_missing_extra_aliases_and_sql_identifiers(self):
        parsed = parse_display_expression(":CODE || :OTHER", block="SAMPLE")
        good = {ref: bindings()[ref] for ref in parsed["refs"]}
        cases = []
        missing = deepcopy(good)
        missing.pop("SAMPLE.OTHER")
        cases.append(missing)
        extra = deepcopy(good)
        extra["SAMPLE.STAMP"] = bindings()["SAMPLE.STAMP"]
        cases.append(extra)
        for column in ["F002", "r.F001", "F001 || 1", 'F001"', "F001--", "f001", "F001$X", ""]:
            changed = deepcopy(good)
            changed["SAMPLE.CODE"]["column"] = column
            cases.append(changed)
        for candidate in cases:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                bind_display_expression(parsed, candidate)
        for alias in ("r.x", "r--", 'r"', "1r", "r" * 31):
            with self.subTest(alias=alias), self.assertRaises(ValueError):
                render_display_expression(compile_expression(), row_alias=alias)

    def test_rejects_unknown_or_implicit_type_length_null_facts(self):
        for values in [{"data_type": "NUMBER"}, {"data_type": "DATE"},
            {"data_type": "NVARCHAR2"}, {"nullable": None}, {"nullable": 1},
            {"maximum_bytes": None}, {"maximum_bytes": 0}, {"maximum_bytes": True},
            {"maximum_bytes": 4001}, {"maximum_length": True}, {"maximum_length": 9},
            {"maximum_length": 0}, {"precision": 8}, {"source_sql": "SELECT 1"}]:
            with self.subTest(values=values), self.assertRaises(ValueError):
                compile_expression(**{"SAMPLE.CODE": values})
        for values in [{"data_type": "VARCHAR2", "maximum_length": 10, "maximum_bytes": 10},
                       {"maximum_length": 10}, {"maximum_bytes": 10}]:
            with self.subTest(values=values), self.assertRaises(ValueError):
                compile_expression(**{"SAMPLE.STAMP": values})

    def test_unknown_source_char_length_is_preserved_with_explicit_byte_bound(self):
        contract = compile_expression(**{"SAMPLE.CODE": {"maximum_length": None}})
        self.assertIsNone(contract["bindings"]["SAMPLE.CODE"]["maximum_length"])
        self.assertEqual(contract["maximum_bytes"], 10)

    def test_exact_byte_cap_includes_repetitions_literals_and_date(self):
        contract = compile_expression(**{"SAMPLE.CODE": {"maximum_bytes": 3998}})
        self.assertEqual(contract["maximum_bytes"], 4000)
        with self.assertRaisesRegex(ValueError, "RESULT_BYTE_BOUND"):
            compile_expression(**{"SAMPLE.CODE": {"maximum_bytes": 3999}})
        with self.assertRaisesRegex(ValueError, "RESULT_BYTE_BOUND"):
            compile_expression(":CODE || :CODE", **{"SAMPLE.CODE": {"maximum_bytes": 2001}})
        with self.assertRaisesRegex(ValueError, "RESULT_BYTE_BOUND"):
            compile_expression(":CODE || 'xx'", **{"SAMPLE.CODE": {"maximum_bytes": 3999}})

    def test_char_only_prefix_has_smaller_byte_cap_without_trimming_or_casting(self):
        contract = compile_expression(":OTHER || :OTHER", **{
            "SAMPLE.OTHER": {"maximum_bytes": 1000}})
        self.assertEqual(contract["maximum_bytes"], 2000)
        self.assertEqual(render_display_expression(contract), '(r."F002" || r."F002")')
        with self.assertRaisesRegex(ValueError, "RESULT_BYTE_BOUND"):
            compile_expression(":OTHER || :OTHER", **{
                "SAMPLE.OTHER": {"maximum_bytes": 1001}})
        with self.assertRaisesRegex(ValueError, "RESULT_BYTE_BOUND"):
            compile_expression(":OTHER || :OTHER || :CODE", **{
                "SAMPLE.OTHER": {"maximum_bytes": 1001}})
        with self.assertRaisesRegex(ValueError, "CHAR_BYTE_BOUND"):
            compile_expression(":OTHER || :CODE", **{
                "SAMPLE.OTHER": {"maximum_bytes": 2001}})
        promoted = compile_expression(":CODE || :OTHER || :OTHER", **{
            "SAMPLE.OTHER": {"maximum_bytes": 1001}})
        self.assertEqual(promoted["maximum_bytes"], 2010)

    def test_ast_metadata_and_extra_nodes_are_checked_even_if_resealed(self):
        good = compile_expression()["expression"]
        for field, value in [("refs", []), ("block", "DIFFERENT"), ("scope", "different")]:
            bad = deepcopy(good)
            bad[field] = value
            reseal_expression(bad)
            with self.subTest(field=field), self.assertRaises(ValueError):
                bind_display_expression(bad, {ref: bindings()[ref] for ref in good["refs"]})
        for change in [{"kind": "raw_sql", "value": "DROP"},
                       {"kind": "item", "ref": "OTHER.CODE"},
                       {"kind": "item", "ref": "SAMPLE.CODE", "sql": "DROP"},
                       {"kind": ["item"], "ref": "SAMPLE.CODE"},
                       {"kind": "date_year", "ref": "SAMPLE.STAMP", "format": "YY"}]:
            bad = deepcopy(good)
            bad["ast"]["operands"][0] = change
            reseal_expression(bad)
            with self.subTest(change=change), self.assertRaises(ValueError):
                bind_display_expression(bad, {ref: bindings()[ref] for ref in good["refs"]})

    def test_derived_contract_metadata_and_claims_rebuilt_even_if_resealed(self):
        for key, value in [("maximum_bytes", 99), ("nullable", True),
            ("nullable", 0), ("runtime_verified", True), ("runtime_verified", 0),
            ("business_accepted", True), ("precision", 2), ("null_semantics", "coalesce"),
            ("scope", "other")]:
            contract = compile_expression()
            contract[key] = value
            reseal_contract(contract)
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                render_display_expression(contract)
        contract = compile_expression()
        contract["bindings"]["SAMPLE.CODE"]["column"] = "F099"
        with self.assertRaisesRegex(ValueError, "CONTRACT_MISMATCH"):
            render_display_expression(contract)

    def test_validation_returns_fresh_contract(self):
        contract = compile_expression()
        result = validate_display_expression(contract)
        self.assertEqual(result, contract)
        result["bindings"]["SAMPLE.CODE"]["column"] = "F099"
        self.assertEqual(contract["bindings"]["SAMPLE.CODE"]["column"], "F001")


if __name__ == "__main__":
    unittest.main()
