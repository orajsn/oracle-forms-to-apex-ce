"""Sanitized check-only profile preparation; not Oracle/runtime acceptance."""
from copy import deepcopy
import hashlib
import io
import re
import zipfile

import pytest

from forms2apex import forms_count_guard, native_blueprint as legacy
from forms2apex import native_blueprint_required as required
from forms2apex import native_blueprint_count_guard as renderer
from test_forms_count_guard import fixture


def source_base(raw=None):
    raw = fixture() if raw is None else raw
    rule = forms_count_guard.extract_count_guard(raw, source_sha256=hashlib.sha256(raw).hexdigest(),
        module="DEMO_FORM", block="DEMO_MASTER", item="CHECK_RECORDS")
    ids = {role: entry["id"] for role, entry in rule["source_objects"].items()}
    base = {"schema_version": 2, "profile_id": required.PROFILE_ID,
        "input_validation_policy": required.INPUT_VALIDATION_POLICY,
        "data_mode": required.DATA_MODE, "project_id": "sanitized-check-project",
        "project_name": "Sanitized check-only prototype", "source_binding": "a" * 64, "blocks": []}
    for sequence, role, name in ((1, "owner_block", "DEMO_MASTER"), (2, "detail_block", "DEMO_DETAIL")):
        block_id = ids[role]
        base["blocks"].append({"source_block_id": block_id, "name": name, "sequence": sequence,
            "classification": "database", "native_component": "form",
            "table_name": legacy._table(base["project_id"], base["source_binding"], block_id), "fields": []})
    for block_index, role, name, kind in ((0, "bind_item", "GROUP_NO", "VARCHAR2"),
        (1, "value_item", "DETAIL_QUANTITY", "NUMBER"), (1, "key_item", "DETAIL_GROUP", "VARCHAR2")):
        field = {"source_item_id": ids[role], "source_name": name, "name": legacy._field_name(ids[role]),
            "label": name.replace("_", " "), "data_type": kind,
            "widget": "text" if kind == "VARCHAR2" else "number", "nullable": True,
            "in_edit_form": True, "value_required": False}
        if kind == "VARCHAR2":
            field["length"] = 80
        base["blocks"][block_index]["fields"].append(field)
    return raw, base


def spec():
    raw, base = source_base()
    return renderer.with_count_guard(base, raw, source_sha256=hashlib.sha256(raw).hexdigest(),
        module="DEMO_FORM", block="DEMO_MASTER", item="CHECK_RECORDS", partial_scope_consent=True)


def test_exact_source_id_bound_wrapper_is_normalized_and_does_not_mutate_inputs():
    raw, base = source_base()
    before = deepcopy(base)
    value = renderer.with_count_guard(base, raw, source_sha256=hashlib.sha256(raw).hexdigest(),
        module="DEMO_FORM", block="DEMO_MASTER", item="CHECK_RECORDS", partial_scope_consent=True)
    assert base == before
    assert renderer.validate_prototype_spec(value) == value
    assert renderer.validate_source_binding(value, raw) == value
    assert value["schema_version"] == 3
    assert value["count_guard"]["source_objects"]["owner_block"] == base["blocks"][0]["source_block_id"]


def test_only_owner_report_changes_existing_save_forms_and_schema_unchanged():
    value = spec()
    baseline = required.render_native_blueprint(renderer._required_projection(value))
    files = renderer.render_native_blueprint(value)
    target = renderer._targets(value)
    assert set(files) == set(baseline)
    assert [name for name in files if files[name] != baseline[name]] == [target["page_file"]]
    assert files["pages/p00002-edit_1.apx"] == baseline["pages/p00002-edit_1.apx"]
    assert files["pages/p00004-edit_2.apx"] == baseline["pages/p00004-edit_2.apx"]
    assert renderer.render_prototype_schema(value) == required.render_prototype_schema(renderer._required_projection(value))
    assert sum(bool(re.match(r"app ", text)) for text in files.values()) == 1


def test_separate_request_queries_only_exact_synthetic_columns_and_defends_success():
    value = spec()
    target = renderer._targets(value)
    page = renderer.render_native_blueprint(value)[target["page_file"]]
    assert "buttonName: FOX_COUNT_GUARD_CHECK" in page
    assert "action: submitPage" in page and "executeValidations: true" in page
    assert "type: functionBodyReturningBoolean" in page
    assert page.count("if :REQUEST = 'FOX_COUNT_GUARD_CHECK' then") == 2
    assert "whenButtonPressed: @count-guard-check" in page
    assert "raise_application_error(-20001" in page
    assert "raise_application_error(-20002" in page
    assert f"from {target['table_name']}" in page
    assert f"where nvl({target['value_column']}, 0) = 0" in page
    assert f"and {target['key_column']} = :{target['key_item']}" in page
    assert "No approval was performed." in page
    assert "return l_count = 0" in page
    fragment = renderer._check_fragment(target)
    assert not re.search(r"\b(?:insert|update|delete|merge|commit|rollback|webhook)\b", fragment, re.I)
    assert "databaseAction:" not in fragment
    assert "DETAIL_QUANTITY" not in fragment and "DEMO_DETAIL" not in fragment
    assert "< 0" not in fragment and ">= 0" not in fragment
    assert "valueRequired: false" in fragment
    assert "Empty keys or no matching rows pass" in fragment
    assert "Negative nonzero values pass" in fragment
    assert 'label: "GROUP NO"' in fragment


def test_trace_preserves_source_proof_and_reports_all_unverified_limits():
    value = spec()
    trace = renderer.prototype_trace(value)
    check = trace["count_guard"]
    assert check["request"] == renderer.REQUEST
    assert check["source_rule_sha256"] == value["count_guard"]["source_rule_sha256"]
    for key in ("source_authority_verified", "partial_consent_verified", "original_button_action_converted",
                "approval_performed", "schema_changed", "dml_performed_by_check", "runtime_verified",
                "unsupported_remainder_converted", "exception_handler_parity_verified"):
        assert check[key] is False
    assert trace["business_behavior_verified"] is False
    assert any("Null keys or no matching rows" in item for item in trace["assumptions"])


def test_stable_zip_context_and_input_order():
    value = spec()
    before = deepcopy(value)
    first = renderer.deterministic_prototype_zip(value)
    value["blocks"].reverse()
    assert first == renderer.deterministic_prototype_zip(value)
    assert renderer.context() == renderer.context()
    assert renderer.context()["profile_id"] == renderer.PROFILE_ID
    assert renderer.context() != required.context()
    with zipfile.ZipFile(io.BytesIO(first)) as archive:
        assert len(archive.namelist()) == len(set(archive.namelist()))
        assert archive.namelist() == sorted(archive.namelist())
    assert before["count_guard"] == value["count_guard"]


@pytest.mark.parametrize("consent", [False, None, 0, 1, "true"])
def test_binding_requires_explicit_partial_scope_assertion(consent):
    raw, base = source_base()
    with pytest.raises(ValueError, match="EXPLICIT_PARTIAL_CONSENT_REQUIRED"):
        renderer.with_count_guard(base, raw, source_sha256=hashlib.sha256(raw).hexdigest(),
            module="DEMO_FORM", block="DEMO_MASTER", item="CHECK_RECORDS", partial_scope_consent=consent)


@pytest.mark.parametrize("mutation", ["root_extra", "guard_extra", "raw_sql", "unknown_profile", "bool_version",
    "no_consent", "bad_hash", "bad_object_id", "different_owner", "wrong_type", "missing_field", "control_owner"])
def test_unknown_or_unbound_metadata_fail_closed(mutation):
    value = spec()
    guard = value["count_guard"]
    if mutation == "root_extra": value["sql"] = "select 1 from dual"
    elif mutation == "guard_extra": guard["fully_converted"] = True
    elif mutation == "raw_sql": guard["sql"] = "begin null; end;"
    elif mutation == "unknown_profile": value["profile_id"] = required.PROFILE_ID
    elif mutation == "bool_version": value["schema_version"] = True
    elif mutation == "no_consent": guard["partial_scope_consent"] = False
    elif mutation == "bad_hash": guard["source_prefix_sha256"] = "not-a-hash"
    elif mutation == "bad_object_id": guard["source_objects"]["value_item"] = "unsafe"
    elif mutation == "different_owner": guard["source_objects"]["bind_block"] = guard["source_objects"]["detail_block"]
    elif mutation == "wrong_type": value["blocks"][1]["fields"][0].update(data_type="DATE", widget="date")
    elif mutation == "missing_field": value["blocks"][1]["fields"].pop(0)
    elif mutation == "control_owner": value["blocks"][0].update(classification="control", native_component="page-items", table_name=None)
    with pytest.raises(ValueError):
        renderer.validate_prototype_spec(value)


@pytest.mark.parametrize("mutation", ["hash", "selector", "mapped_name", "mapped_type", "rebound_item", "source_changed"])
def test_source_authority_recomputed_not_granted_by_pure_rendering(mutation):
    raw, _ = source_base()
    value = spec()
    if mutation == "hash": value["count_guard"]["source_rule_sha256"] = "b" * 64
    elif mutation == "selector": value["count_guard"]["source_selector"]["item"] = "OTHER_BUTTON"
    elif mutation == "mapped_name": value["blocks"][1]["fields"][0]["source_name"] = "OTHER"
    elif mutation == "mapped_type":
        for field in (value["blocks"][0]["fields"][0], value["blocks"][1]["fields"][1]):
            field.update(data_type="NUMBER", widget="number")
            field.pop("length")
    elif mutation == "rebound_item":
        value["count_guard"]["source_objects"]["value_item"] = "ff1-" + "f" * 24
    else: raw += b" "
    with pytest.raises(ValueError):
        renderer.validate_source_binding(value, raw)


def test_ff1_ids_equal_existing_forms_facts_identity_when_available():
    # This is an integration identity check against the existing real parser,
    # not a replacement fixture/parser claiming source authority.
    from fox.forms_facts import assess_forms_xml
    raw, _ = source_base()
    facts = assess_forms_xml("sanitized.xml", raw)
    by_path = {row["location"]["path"]: row["id"] for row in facts["objects"]}
    rule = forms_count_guard.extract_count_guard(raw, source_sha256=hashlib.sha256(raw).hexdigest(),
        module="DEMO_FORM", block="DEMO_MASTER", item="CHECK_RECORDS")
    assert all(by_path[row["path"]] == row["id"] for row in rule["source_objects"].values())
