"""Pure v2 applicability/coverage tests; not claims of actual browser testing."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from fox.native_qa_plan import (
    CASE_NAMES, NativeQaPlanError, derive_native_qa_plan,
    derive_native_qa_profile, qa_plan_sha256, validate_native_qa_result_cases,
)


_PARITY_FIXTURE = json.loads((Path(__file__).parent / "fixtures" /
                            "native-qa-plan-v2-vectors.json").read_text(encoding="utf-8"))


def column(name, data_type, *, nullable=True, **extra):
    return {"name": name, "label": name.title(), "data_type": data_type,
            "nullable": nullable, **({"length": 1} if data_type == "VARCHAR2" else {}), **extra}


def spec_for(*columns, key_index=0):
    columns = list(columns)
    columns.insert(key_index, column("RECORD_NO", "NUMBER", nullable=False,
                                     primary_key=True, identity=True))
    return {"profile_id": "native-table-form-v1", "data_mode": "synthetic_test_only",
            "table_name": "FOX_NATIVE_MATRIX", "columns": columns}


def encoded(spec):
    return json.dumps(spec, ensure_ascii=False, indent=2).encode("utf-8")


def plan_for(spec):
    return derive_native_qa_plan(spec, hashlib.sha256(encoded(spec)).hexdigest())


def passed_result(plan):
    return {
        "status": "PASSED", "test_plan": deepcopy(plan), "test_plan_sha256": qa_plan_sha256(plan),
        "tests": [{**deepcopy(case), "required": case["applicable"],
                   "status": "PASSED" if case["applicable"] else "NOT_APPLICABLE",
                   "field_results": [{"field_name": name, "status": "PASSED"}
                                     for name in case["field_names"]]}
                  for case in plan["cases"]],
        "additional_checks": [
            {"name": "database_constraints", "required": False, "status": "NOT_RUN",
             "reason": "The supported contract has no CHECK constraints."},
            {"name": "database_sql_readback", "required": False, "status": "NOT_RUN",
             "reason": "Requires a separate operator SQL proof."},
        ],
    }


@pytest.mark.parametrize("data_type", ["NUMBER", "DATE", "VARCHAR2"])
@pytest.mark.parametrize("nullable", [True, False])
@pytest.mark.parametrize("key_index", [0, 1])
def test_single_editable_field_has_exact_applicability(data_type, nullable, key_index):
    spec = spec_for(column("VALUE_ONE", data_type, nullable=nullable), key_index=key_index)
    original = deepcopy(spec)
    plan = plan_for(spec)
    assert spec == original
    assert [case["name"] for case in plan["cases"]] == list(CASE_NAMES)
    assert plan["primary_key"] == {"name": "RECORD_NO", "item_name": "P2_RECORD_NO",
                                   "representation": "decimal_string"}
    assert plan["row_tracking"] == {"mode": "clean_empty_then_observed_pk", "initial_row_count": 0}
    assert plan["edit_field"] == "VALUE_ONE"
    cases = {case["name"]: case for case in plan["cases"]}
    expected = {"required_fields": not nullable, "invalid_number": data_type == "NUMBER",
                "invalid_date": data_type == "DATE", "maximum_length": data_type == "VARCHAR2"}
    for name, applies in expected.items():
        assert cases[name]["applicable"] is applies
        assert cases[name]["field_names"] == (["VALUE_ONE"] if applies else [])
        assert cases[name]["reason_code"].startswith("NO_") is (not applies)
    for name in set(CASE_NAMES) - expected.keys():
        assert cases[name]["applicable"] is True
        assert cases[name]["reason_code"] == "UNIVERSAL_NATIVE_FLOW"
    assert set(validate_native_qa_result_cases(passed_result(plan), plan)) == set(CASE_NAMES)


def test_type_cases_cover_every_matching_field_in_source_order():
    spec = spec_for(column("Z_TEXT", "VARCHAR2", nullable=False, length=4000),
                    column("Z_NUMBER", "NUMBER", nullable=False), column("Z_DATE", "DATE"),
                    column("A_TEXT", "VARCHAR2"), column("A_NUMBER", "NUMBER"),
                    column("A_DATE", "DATE", nullable=False), key_index=3)
    plan = plan_for(spec)
    cases = {case["name"]: case for case in plan["cases"]}
    assert cases["required_fields"]["field_names"] == ["Z_TEXT", "Z_NUMBER", "A_DATE"]
    assert cases["invalid_number"]["field_names"] == ["Z_NUMBER", "A_NUMBER"]
    assert cases["invalid_date"]["field_names"] == ["Z_DATE", "A_DATE"]
    assert cases["maximum_length"]["field_names"] == ["Z_TEXT", "A_TEXT"]
    assert cases["concurrent_edit"]["field_names"] == ["Z_TEXT"]
    for name in ("create", "reread", "edit_save", "cancel_edit", "cancel_create"):
        assert cases[name]["field_names"] == ["Z_TEXT", "Z_NUMBER", "Z_DATE", "A_TEXT", "A_NUMBER", "A_DATE"]
    for name in ("login", "search_positive", "search_negative", "browser_runtime_errors"):
        assert cases[name]["field_names"] == []


def test_non_nullable_primary_key_alone_does_not_make_required_case_applicable():
    plan = plan_for(spec_for(column("OPTIONAL_VALUE", "VARCHAR2")))
    required = next(case for case in plan["cases"] if case["name"] == "required_fields")
    assert required == {"name": "required_fields", "applicable": False,
                        "field_names": [], "reason_code": "NO_REQUIRED_EDITABLE_FIELDS"}


def test_profile_values_are_derived_and_exact_labels_retained_without_rejecting_duplicates():
    spec = spec_for(column("TEXT_VALUE", "VARCHAR2", nullable=False, label=" Same "),
                    column("NUMBER_VALUE", "NUMBER", label="Same"),
                    column("DATE_VALUE", "DATE", label="明細"), key_index=1)
    original = deepcopy(spec)
    assert derive_native_qa_profile(spec) == {
        "schema_version": 2, "profile_id": "native-table-form-v1",
        "data_mode": "synthetic_test_only", "table_name": "FOX_NATIVE_MATRIX",
        "primary_key": "RECORD_NO", "database_constraints": [],
        "fields": [
            {"name": "TEXT_VALUE", "label": " Same ", "data_type": "VARCHAR2", "required": True,
             "max_length": 1, "valid_value": "A"},
            {"name": "NUMBER_VALUE", "label": "Same", "data_type": "NUMBER", "required": False,
             "valid_value": "1"},
            {"name": "DATE_VALUE", "label": "明細", "data_type": "DATE", "required": False,
             "valid_value": "2026-01-01"},
        ],
    }
    assert spec == original


@pytest.mark.parametrize("bad_hash", [None, 1, True, "", "a" * 63, "a" * 65, "A" * 64, "x" * 64, "a" * 64 + "\n"])
def test_raw_spec_hash_must_be_lowercase_exact_sha256(bad_hash):
    with pytest.raises(NativeQaPlanError):
        derive_native_qa_plan(spec_for(column("VALUE_ONE", "NUMBER")), bad_hash)


@pytest.mark.parametrize("part,key,bad", [
    ("root", "profile_id", "unknown"), ("root", "data_mode", "customer"),
    ("root", "table_name", "CUSTOMER_TABLE"), ("root", "table_name", "FOX_NATIVE_a"),
    ("root", "table_name", "FOX_NATIVE_" + "A" * 20),
    ("root", "supported_operations", ["query", "update", "insert"]),
    ("root", "supported_operations", "query,insert,update"),
    ("root", "supported_operations", None), ("root", "sql", "SELECT secret"),
    ("field", "nullable", 1), ("field", "nullable", None),
    ("field", "primary_key", None), ("field", "identity", None),
    ("field", "primary_key", 0), ("field", "identity", "false"),
    ("field", "identity", True), ("field", "name", "SELECT"),
    ("field", "name", "bad lower case"), ("field", "name", None),
    ("field", "data_type", "CLOB"), ("field", "data_type", []),
    ("field", "length", 1), ("field", "default", "0"),
    ("field", "label", None), ("field", "label", ""),
    ("field", "label", "A" * 81),
    ("key", "nullable", True), ("key", "identity", False), ("key", "primary_key", False),
    ("key", "data_type", "DATE"), ("key", "primary_key", 1),
])
def test_unsupported_or_ambiguous_native_metadata_rejected(part, key, bad):
    spec = spec_for(column("VALUE_ONE", "NUMBER"))
    target = spec if part == "root" else spec["columns"][0 if part == "key" else 1]
    target[key] = bad
    with pytest.raises(NativeQaPlanError):
        plan_for(spec)
    with pytest.raises(NativeQaPlanError):
        derive_native_qa_profile(spec)


@pytest.mark.parametrize('label', ['   ', 'hidden\u200bcontrol', 'line\u2028break',
                                  '<b>markup</b>', 'SELECT secret FROM source', 'semi;colon',
                                  '\U0001FAE9', '\U0001FAEA', '  Same  '])
def test_derivable_plan_does_not_authorize_producer_labels(label):
    # QA planning has no Unicode-assignment or SQL-looking-label policy. A
    # separate producer contract must authorize the exact package beforehand.
    spec = spec_for(column('VALUE_ONE', 'VARCHAR2', label=label))
    plan = plan_for(spec)
    profile = derive_native_qa_profile(spec)
    assert plan['native_spec_sha256'] == hashlib.sha256(encoded(spec)).hexdigest()
    assert profile['fields'][0]['label'] == label
    assert spec['columns'][1]['label'] == label


@pytest.mark.parametrize('label', ['\ud800', '\udfff', 'unpaired\ud800text'])
def test_structural_label_requires_serializable_unicode_scalars(label):
    spec = spec_for(column('VALUE_ONE', 'VARCHAR2', label=label))
    raw = json.dumps(spec, ensure_ascii=True).encode('ascii')
    with pytest.raises(NativeQaPlanError):
        derive_native_qa_plan(spec, hashlib.sha256(raw).hexdigest())
    with pytest.raises(NativeQaPlanError):
        derive_native_qa_profile(spec)


@pytest.mark.parametrize("bad_length", [None, True, 0, -1, 4001, 2.5, "10"])
def test_varchar2_requires_bounded_integer_length(bad_length):
    with pytest.raises(NativeQaPlanError):
        plan_for(spec_for(column("VALUE_ONE", "VARCHAR2", length=bad_length)))


@pytest.mark.parametrize("mutation", ["empty", "one", "too_many", "duplicate", "two_keys", "missing_key", "not_list", "missing_label"])
def test_invalid_column_set_rejected(mutation):
    spec = spec_for(column("VALUE_ONE", "NUMBER"))
    if mutation == "empty": spec["columns"] = []
    elif mutation == "one": spec["columns"].pop()
    elif mutation == "too_many": spec = spec_for(*(column("COL_" + str(i), "NUMBER") for i in range(20)))
    elif mutation == "duplicate": spec["columns"][1]["name"] = "RECORD_NO"
    elif mutation == "two_keys": spec["columns"][1].update(primary_key=True, identity=True, nullable=False)
    elif mutation == "missing_key": spec["columns"][0].update(primary_key=False, identity=False)
    elif mutation == "not_list": spec["columns"] = {}
    elif mutation == "missing_label": del spec["columns"][1]["label"]
    with pytest.raises(NativeQaPlanError): plan_for(spec)


def test_maximum_native_column_count_and_optional_false_key_flags():
    spec = spec_for(*(column("COL_" + str(i), "NUMBER", primary_key=False, identity=False) for i in range(19)))
    assert len(plan_for(spec)["cases"][1]["field_names"]) == 19


def test_hash_canonicalizes_recursive_object_order_not_arrays_or_source_bytes():
    plan = plan_for(spec_for(column("Z_VALUE", "NUMBER"), column("A_VALUE", "DATE")))
    reordered = {key: value for key, value in reversed(list(plan.items()))}
    reordered["primary_key"] = dict(reversed(list(plan["primary_key"].items())))
    assert qa_plan_sha256(plan) == qa_plan_sha256(reordered)
    changed = deepcopy(plan)
    changed["cases"][1]["field_names"].reverse()
    assert qa_plan_sha256(plan) != qa_plan_sha256(changed)
    changed = deepcopy(plan)
    changed["native_spec_sha256"] = "0" * 64
    assert qa_plan_sha256(plan) != qa_plan_sha256(changed)
    canonical = json.dumps(plan, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    assert qa_plan_sha256(plan) == hashlib.sha256(canonical).hexdigest()
    assert qa_plan_sha256(plan) != hashlib.sha256(canonical + b"\n").hexdigest()


@pytest.mark.parametrize("data_type,nullable,expected", [
    ("NUMBER", True, "889e16fcf576a17f9034f11e6b479ba679ea18c779e6e1193bdbe40ae0fcd530"),
    ("NUMBER", False, "8b5ceaa0b27566903b996c5bb48fc15a0271ca5c1c7aacba84245ba950268423"),
    ("DATE", True, "aa32f15d02184b4f7d3accfffbc768a3eebf8ee1720ea5f38be752aef5b0f548"),
    ("DATE", False, "6c3c791a540f41bc20fe41d0282a1e3bc761b8c47b21aa2aa92b2a6b5131b888"),
    ("VARCHAR2", True, "33f14067a5e30a4a523f1e67a97af80f259625c8e905e885c85bf617755b9eb5"),
    ("VARCHAR2", False, "3f50fa9d1a6f0e05905b356a4368628f19b631a85c7765a20a5406dad7b558ae"),
])
@pytest.mark.parametrize("key_index", [0, 1])
def test_frozen_hash_vectors_independently_obtained_from_js(data_type, nullable, expected, key_index):
    # Obtained by running qa/lib/contracts.mjs deriveNativeQaPlan and its
    # canonicalQaPlan/sha256, not by asking this Python implementation to bless
    # its own output. The all-a digest is synthetic test input, not real proof.
    spec = spec_for(column("VALUE_ONE", data_type, nullable=nullable), key_index=key_index)
    plan = derive_native_qa_plan(spec, "a" * 64)
    assert qa_plan_sha256(plan) == expected


@pytest.mark.parametrize("bad", [None, [], {"bad": float("nan")}, {"bad": {1, 2}}, {"bad": "\ud800"}])
def test_non_json_hash_input_rejected(bad):
    with pytest.raises(NativeQaPlanError): qa_plan_sha256(bad)


@pytest.fixture
def evidence():
    plan = plan_for(spec_for(column("Z_VALUE", "NUMBER", nullable=False),
                             column("A_VALUE", "NUMBER", nullable=False)))
    return plan, passed_result(plan)


def test_receipt_case_order_may_vary_but_required_fields_remain_ordered(evidence):
    plan, result = evidence
    result["tests"].reverse()
    assert len(validate_native_qa_result_cases(result, plan)) == 14


@pytest.mark.parametrize("mutation", [
    "missing_test", "duplicate_test", "extra_test", "not_list", "bad_test", "bad_name",
    "plan_changed", "plan_hash_changed", "plan_bool_schema", "result_failed", "result_incomplete",
    "missing_field", "reordered_fields", "duplicate_field", "missing_field_result", "reordered_field_results",
    "extra_field_result_key", "field_failed", "field_not_run", "missing_required", "required_false",
    "required_numeric", "applicable_false", "applicable_numeric", "wrong_reason", "not_run", "failed",
    "optional_required", "optional_fake_pass", "optional_failed", "optional_missing", "optional_extra",
    "optional_duplicate", "optional_empty_reason", "optional_wrong_name",
])
def test_report_cannot_omit_or_weaken_derived_runtime_coverage(evidence, mutation):
    plan, result = evidence
    test = next(item for item in result["tests"] if item["name"] == "required_fields")
    if mutation == "missing_test": result["tests"].pop()
    elif mutation == "duplicate_test": result["tests"][-1] = deepcopy(result["tests"][0])
    elif mutation == "extra_test": result["tests"].append({"name": "extra", "status": "PASSED"})
    elif mutation == "not_list": result["tests"] = {}
    elif mutation == "bad_test": result["tests"][0] = None
    elif mutation == "bad_name": test["name"] = []
    elif mutation == "plan_changed": result["test_plan"]["edit_field"] = "A_VALUE"
    elif mutation == "plan_hash_changed": result["test_plan_sha256"] = "0" * 64
    elif mutation == "plan_bool_schema": result["test_plan"]["schema_version"] = True
    elif mutation == "result_failed": result["status"] = "FAILED"
    elif mutation == "result_incomplete": result["status"] = "INCOMPLETE"
    elif mutation == "missing_field": test["field_names"].pop()
    elif mutation == "reordered_fields": test["field_names"].reverse()
    elif mutation == "duplicate_field": test["field_names"][1] = test["field_names"][0]
    elif mutation == "missing_field_result": test["field_results"].pop()
    elif mutation == "reordered_field_results": test["field_results"].reverse()
    elif mutation == "extra_field_result_key": test["field_results"][0]["runtime_asserted"] = True
    elif mutation == "field_failed": test["field_results"][0]["status"] = "FAILED"
    elif mutation == "field_not_run": test["field_results"][0]["status"] = "NOT_RUN"
    elif mutation == "missing_required": del test["required"]
    elif mutation == "required_false": test["required"] = False
    elif mutation == "required_numeric": test["required"] = 1
    elif mutation == "applicable_false": test["applicable"] = False
    elif mutation == "applicable_numeric": test["applicable"] = 1
    elif mutation == "wrong_reason": test["reason_code"] = "UNIVERSAL_NATIVE_FLOW"
    elif mutation == "not_run": test["status"] = "NOT_RUN"
    elif mutation == "failed": test["status"] = "FAILED"
    elif mutation == "optional_required": result["additional_checks"][0]["required"] = True
    elif mutation == "optional_fake_pass": result["additional_checks"][0]["status"] = "PASSED"
    elif mutation == "optional_failed": result["additional_checks"][0]["status"] = "FAILED"
    elif mutation == "optional_missing": del result["additional_checks"]
    elif mutation == "optional_extra": result["additional_checks"].append({"name": "hidden_failure", "status": "FAILED"})
    elif mutation == "optional_duplicate": result["additional_checks"][1] = deepcopy(result["additional_checks"][0])
    elif mutation == "optional_empty_reason": result["additional_checks"][0]["reason"] = " "
    elif mutation == "optional_wrong_name": result["additional_checks"][0]["name"] = "unknown"
    with pytest.raises(NativeQaPlanError): validate_native_qa_result_cases(result, plan)


@pytest.mark.parametrize("key,bad", [
    ("status", "PASSED"), ("status", "NOT_RUN"), ("status", "FAILED"),
    ("applicable", True), ("required", True), ("required", 0),
    ("field_names", ["Z_VALUE"]), ("field_results", [{"field_name": "Z_VALUE", "status": "PASSED"}]),
    ("reason_code", "NO_EDITABLE_NUMBER_FIELDS"),
])
def test_not_applicable_is_explicit_and_not_a_fake_pass(evidence, key, bad):
    plan, result = evidence
    test = next(item for item in result["tests"] if item["name"] == "invalid_date")
    test[key] = bad
    with pytest.raises(NativeQaPlanError): validate_native_qa_result_cases(result, plan)


def test_result_validation_does_not_mutate_input(evidence):
    plan, result = evidence
    original = deepcopy((plan, result))
    validate_native_qa_result_cases(result, plan)
    assert (plan, result) == original


@pytest.mark.parametrize("vector", _PARITY_FIXTURE["vectors"], ids=lambda vector: vector["name"])
def test_shared_raw_spec_boundary_vectors_match_js_expected_hashes(vector):
    assert _PARITY_FIXTURE["schema_version"] == 1
    assert _PARITY_FIXTURE["scope"] == "fox-native-qa-plan-v2-parity-vectors"
    raw = vector["spec_json"].encode("utf-8")
    native_hash = hashlib.sha256(raw).hexdigest()
    assert native_hash == vector["native_spec_sha256"]
    spec = json.loads(raw)
    original = deepcopy(spec)
    if vector["derivable"]:
        plan = derive_native_qa_plan(spec, native_hash)
        profile = derive_native_qa_profile(spec)
        assert plan["native_spec_sha256"] == native_hash
        assert qa_plan_sha256(plan) == vector["plan_sha256"]
        profile_bytes = json.dumps(profile, sort_keys=True, ensure_ascii=False,
                                  separators=(",", ":")).encode("utf-8")
        assert hashlib.sha256(profile_bytes).hexdigest() == vector["profile_sha256"]
    else:
        with pytest.raises(NativeQaPlanError): derive_native_qa_plan(spec, native_hash)
        with pytest.raises(NativeQaPlanError): derive_native_qa_profile(spec)
        assert "plan_sha256" not in vector and "profile_sha256" not in vector
    assert spec == original
    assert hashlib.sha256(vector["spec_json"].encode("utf-8")).hexdigest() == native_hash


def test_raw_byte_variants_do_not_normalize_to_one_native_hash_or_plan():
    indexed = {vector["name"]: vector for vector in _PARITY_FIXTURE["vectors"]}
    compact = indexed["omitted_optional_compact"]
    pretty = indexed["omitted_optional_pretty_same_metadata"]
    assert json.loads(compact["spec_json"]) == json.loads(pretty["spec_json"])
    assert compact["native_spec_sha256"] != pretty["native_spec_sha256"]
    assert compact["plan_sha256"] != pretty["plan_sha256"]
    assert compact["profile_sha256"] == pretty["profile_sha256"]


def test_unicode_label_boundary_is_codepoints_not_utf16_units_or_graphemes():
    indexed = {vector["name"]: vector for vector in _PARITY_FIXTURE["vectors"]}
    for name, codepoints, utf16_units, accepted in (
        ("nonbmp_label_79", 79, 158, True), ("nonbmp_label_80", 80, 160, True),
        ("nonbmp_label_81", 81, 162, False),
        ("mixed_label_80_codepoints_81_utf16_units", 80, 81, True),
        ("combining_label_80_codepoints", 80, 80, True),
        ("combining_label_82_codepoints", 82, 82, False),
    ):
        vector = indexed[name]
        label = json.loads(vector["spec_json"])["columns"][1]["label"]
        assert len(label) == codepoints
        assert len(label.encode("utf-16-le")) // 2 == utf16_units
        assert vector["derivable"] is accepted


def test_shared_fixture_covers_column_count_and_optional_metadata_boundaries():
    indexed = {vector["name"]: vector for vector in _PARITY_FIXTURE["vectors"]}
    maximum = json.loads(indexed["20_columns_key_in_middle"]["spec_json"])
    excess = json.loads(indexed["21_columns_key_in_middle"]["spec_json"])
    assert len(maximum["columns"]) == 20 and len(excess["columns"]) == 21
    assert maximum["columns"][9]["primary_key"] is True
    omitted = json.loads(indexed["omitted_optional_compact"]["spec_json"])
    assert "supported_operations" not in omitted
    assert "primary_key" not in omitted["columns"][1]
    assert "identity" not in omitted["columns"][1]
