"""Contract-only tests; no database or customer source is used."""

from copy import deepcopy

import pytest

from forms2apex.native_contract import validate_native_spec


@pytest.fixture
def spec():
    return {
        "profile_id": "native-table-form-v1",
        "data_mode": "synthetic_test_only",
        "table_name": "FOX_NATIVE_ORDERS",
        "columns": [
            {"name": "ORDER_ID", "data_type": "NUMBER", "nullable": False,
             "label": "Order ID", "primary_key": True, "identity": True},
            {"name": "DESCRIPTION", "data_type": "VARCHAR2", "nullable": False,
             "label": "Description", "length": 100},
            {"name": "ORDER_DATE", "data_type": "DATE", "nullable": True,
             "label": "Order date"},
        ],
    }


def test_normalizes_supported_metadata_without_mutation(spec):
    original = deepcopy(spec)
    result = validate_native_spec(spec)
    assert result["supported_operations"] == ["query", "insert", "update"]
    assert result["columns"][1]["primary_key"] is False
    assert result["columns"][1]["identity"] is False
    assert result["columns"][1]["length"] == 100
    assert spec == original
    assert validate_native_spec(result) == result
    result["columns"][1]["length"] = 2
    assert spec["columns"][1]["length"] == 100


@pytest.mark.parametrize("field", ["profile_id", "data_mode", "table_name", "columns"])
def test_missing_root_metadata_is_blocked(spec, field):
    del spec[field]
    with pytest.raises(ValueError, match="missing required metadata"):
        validate_native_spec(spec)


@pytest.mark.parametrize("field", ["name", "data_type", "nullable", "label", "length"])
def test_missing_column_metadata_is_blocked(spec, field):
    del spec["columns"][1][field]
    with pytest.raises(ValueError):
        validate_native_spec(spec)


def test_absent_primary_key_is_not_inferred_from_id_name(spec):
    del spec["columns"][0]["primary_key"]
    del spec["columns"][0]["identity"]
    with pytest.raises(ValueError, match="exactly one"):
        validate_native_spec(spec)


def test_two_primary_keys_are_blocked(spec):
    spec["columns"].append({"name": "OTHER_ID", "data_type": "NUMBER", "nullable": False,
                            "label": "Other ID", "primary_key": True, "identity": True})
    with pytest.raises(ValueError, match="exactly one"):
        validate_native_spec(spec)


@pytest.mark.parametrize("change", [
    {"nullable": True}, {"data_type": "DATE"}, {"identity": False}, {"primary_key": False},
])
def test_unsupported_primary_key_metadata_is_blocked(spec, change):
    spec["columns"][0].update(change)
    with pytest.raises(ValueError, match="primary key"):
        validate_native_spec(spec)


def test_duplicate_columns_are_blocked(spec):
    spec["columns"][1]["name"] = "ORDER_ID"
    with pytest.raises(ValueError, match="unique"):
        validate_native_spec(spec)


@pytest.mark.parametrize("name", [
    "FOX_NATIVE_ORDERS;DROP TABLE X", "FOX_NATIVE_ORDERS--", '"FOX_NATIVE_ORDERS"',
    "FOX_NATIVE_A.B", "fox_native_orders", "FOX_NATIVE_" + "A" * 20,
    "OTHER_ORDERS", "FOX_NATIVE_ORDERS\n", "SELECT * FROM ORDERS",
])
def test_unsafe_or_out_of_scope_table_identifiers_are_blocked(spec, name):
    spec["table_name"] = name
    with pytest.raises(ValueError):
        validate_native_spec(spec)


@pytest.mark.parametrize("name", [
    "ID);DROP TABLE X", "SCHEMA.ID", '"ID"', "id", "A" * 31,
    "SELECT", "DATE", "ROWID", "ORDER", "COMMENT",
])
def test_unsafe_column_identifiers_are_blocked(spec, name):
    spec["columns"][1]["name"] = name
    with pytest.raises(ValueError):
        validate_native_spec(spec)


@pytest.mark.parametrize("data_type", ["CLOB", "TIMESTAMP", "VARCHAR2(80)", "number", None, {}])
def test_unsupported_data_types_are_blocked(spec, data_type):
    spec["columns"][1]["data_type"] = data_type
    with pytest.raises(ValueError, match="support only"):
        validate_native_spec(spec)


@pytest.mark.parametrize("field", ["nullable", "primary_key", "identity"])
@pytest.mark.parametrize("value", [0, 1, "true", "false", None, [], {}])
def test_booleans_do_not_accept_truthy_coercion(spec, field, value):
    spec["columns"][1][field] = value
    with pytest.raises(ValueError, match="JSON boolean"):
        validate_native_spec(spec)


@pytest.mark.parametrize("length", [0, 4001, True, False, "100", 1.5, None])
def test_varchar_length_requires_bounded_integer(spec, length):
    spec["columns"][1]["length"] = length
    with pytest.raises(ValueError, match="integer length"):
        validate_native_spec(spec)


@pytest.mark.parametrize("length", [1, 4000])
def test_varchar_length_boundaries_are_supported(spec, length):
    spec["columns"][1]["length"] = length
    assert validate_native_spec(spec)["columns"][1]["length"] == length


def test_length_is_not_silently_used_as_numeric_precision(spec):
    spec["columns"][0]["length"] = 10
    with pytest.raises(ValueError, match="only for VARCHAR2"):
        validate_native_spec(spec)


@pytest.mark.parametrize("label", [
    "", " " * 10, "A" * 81, "Description\nDROP TABLE X", "Field\tname", "Field\x00name",
    "Field\u202ename", "Field\u2028name", "Field\u2029name",
    "<script>alert(1)</script>", "<b>Name</b>", "Name; DROP TABLE X",
    "SELECT * FROM ORDERS", "EXECUTE IMMEDIATE 'x'", "Name -- comment", "Name/*x*/",
    "```html", "${value}", None, 5,
])
def test_non_plain_labels_are_blocked(spec, label):
    spec["columns"][1]["label"] = label
    with pytest.raises(ValueError):
        validate_native_spec(spec)


def test_plain_labels_are_trimmed_without_losing_business_punctuation(spec):
    spec["columns"][1]["label"] = "  Customer's name / 名称 & code  "
    assert validate_native_spec(spec)["columns"][1]["label"] == "Customer's name / 名称 & code"


@pytest.mark.parametrize("field", ["sql", "plsql", "html", "default", "schema", "connection", "verified_ddl"])
def test_unknown_root_metadata_is_blocked(spec, field):
    spec[field] = "not accepted"
    with pytest.raises(ValueError, match="unsupported metadata"):
        validate_native_spec(spec)


@pytest.mark.parametrize("field", ["sql", "expression", "default", "check", "foreign_key", "precision", "html"])
def test_unknown_column_metadata_is_blocked(spec, field):
    spec["columns"][1][field] = "not accepted"
    with pytest.raises(ValueError, match="unsupported metadata"):
        validate_native_spec(spec)


@pytest.mark.parametrize("operations", [
    ["query", "insert", "update", "delete"], ["query"], ["update", "insert", "query"],
    "query,insert,update", None,
])
def test_operations_cannot_enable_delete_or_change_profile(spec, operations):
    spec["supported_operations"] = operations
    with pytest.raises(ValueError, match="supports only"):
        validate_native_spec(spec)


@pytest.mark.parametrize("field,value", [
    ("profile_id", "native-table-form-v2"), ("profile_id", None),
    ("data_mode", "customer_data"), ("data_mode", None),
])
def test_profile_and_synthetic_mode_are_pinned(spec, field, value):
    spec[field] = value
    with pytest.raises(ValueError):
        validate_native_spec(spec)


@pytest.mark.parametrize("value", [None, [], "SELECT * FROM ORDERS", 1])
def test_non_object_spec_is_blocked(value):
    with pytest.raises(ValueError, match="JSON object"):
        validate_native_spec(value)


@pytest.mark.parametrize("count", [0, 1, 21])
def test_column_count_limits_are_enforced(spec, count):
    spec["columns"] = [{"name": f"COL_{index}", "data_type": "NUMBER", "nullable": False,
                        "label": f"Column {index}", "primary_key": index == 0,
                        "identity": index == 0} for index in range(count)]
    with pytest.raises(ValueError, match="between 2 and 20"):
        validate_native_spec(spec)


def test_twenty_columns_are_supported(spec):
    spec["columns"] = [{"name": f"COL_{index}", "data_type": "NUMBER", "nullable": False,
                        "label": f"Column {index}", "primary_key": index == 0,
                        "identity": index == 0} for index in range(20)]
    assert len(validate_native_spec(spec)["columns"]) == 20


@pytest.mark.parametrize("columns", [None, {}, "columns", [None, {}]])
def test_malformed_column_containers_are_blocked(spec, columns):
    spec["columns"] = columns
    with pytest.raises(ValueError):
        validate_native_spec(spec)
