"""Synthetic pure-module acceptance; never Oracle, customer source or model proof."""
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import zipfile

import pytest

from forms2apex import blueprint_profiles, native_blueprint as legacy, native_project
from forms2apex import native_blueprint_required as renderer
from test_native_blueprint import spec as legacy_spec


def spec(count=4):
    value = legacy_spec(count)
    value.update(schema_version=2, profile_id=renderer.PROFILE_ID,
                 input_validation_policy=renderer.INPUT_VALIDATION_POLICY)
    for block in value["blocks"]:
        for field in block["fields"]:
            field.update(value_required=False, nullable=True)
    for block in value["blocks"][:2]:
        if block["fields"]:
            block["fields"][0]["value_required"] = True
    return value


def project(value):
    value = deepcopy(value)
    value.pop("input_validation_policy")
    value.update(schema_version=1, profile_id=legacy.PROFILE_ID)
    for block in value["blocks"]:
        for field in block["fields"]:
            field.pop("value_required")
    return value


def test_closed_registry_preserves_original_legacy_module_and_public_api():
    assert blueprint_profiles.select(legacy_spec()) is legacy
    assert blueprint_profiles.select(spec()) is renderer
    for name in ("validate_prototype_spec", "render_native_blueprint", "render_prototype_schema",
                 "context", "prototype_trace", "deterministic_prototype_zip"):
        assert callable(getattr(renderer, name))


@pytest.mark.parametrize("value", [None, [], {}, {"schema_version": True},
    {"schema_version": 1, "profile_id": renderer.PROFILE_ID},
    {"schema_version": 2, "profile_id": legacy.PROFILE_ID},
    {"schema_version": 2, "profile_id": "os.system"},
    {"schema_version": 2, "profile_id": []},
    {"schema_version": 3, "profile_id": renderer.PROFILE_ID}])
def test_registry_rejects_unknown_or_crossed_profile_versions(value):
    with pytest.raises(ValueError, match="PROTOTYPE_PROFILE_UNSUPPORTED"):
        blueprint_profiles.select(value)


def test_normalization_is_independent_idempotent_and_preserves_policy_after_sort():
    value = spec()
    value["blocks"].reverse()
    before = deepcopy(value)
    normalized = renderer.validate_prototype_spec(value)
    assert value == before
    assert renderer.validate_prototype_spec(normalized) == normalized
    assert [block["sequence"] for block in normalized["blocks"]] == [1, 2, 3]
    assert normalized["blocks"][0]["fields"][0]["value_required"] is True
    assert normalized["blocks"][2]["fields"][0]["value_required"] is False
    normalized["blocks"][0]["fields"][0]["label"] = "Changed"
    assert value == before


@pytest.mark.parametrize("bad", [None, 0, 1, "true", "false", [], {}, 1.0])
def test_value_required_must_be_actual_boolean(bad):
    value = spec()
    value["blocks"][0]["fields"][0]["value_required"] = bad
    with pytest.raises(ValueError, match="VALUE_REQUIRED_BOOLEAN_INVALID"):
        renderer.validate_prototype_spec(value)


def test_value_required_must_be_present_on_every_field():
    value = spec()
    value["blocks"][2]["fields"][1].pop("value_required")
    with pytest.raises(ValueError, match="FIELD_FIELDS_INVALID"):
        renderer.validate_prototype_spec(value)


@pytest.mark.parametrize("target", ["report", "report_only", "display", "control"])
@pytest.mark.parametrize("required", [False, True])
def test_only_editable_database_form_items_may_be_ui_required(target, required):
    value = spec()
    block = value["blocks"][2 if target == "control" else 0]
    field = block["fields"][0]
    field["value_required"] = required
    if target == "report":
        block["native_component"] = "report"
        for item in block["fields"]:
            item["in_edit_form"] = False
    elif target in {"report_only", "display"}:
        field["in_edit_form"] = False
        if target == "display":
            field["widget"] = "display"
    if required:
        with pytest.raises(ValueError, match="VALUE_REQUIRED_TARGET_INVALID"):
            renderer.validate_prototype_spec(value)
    else:
        assert renderer.validate_prototype_spec(value)
        assert renderer.render_native_blueprint(value)


@pytest.mark.parametrize("nullable", [False, True])
@pytest.mark.parametrize("required", [False, True])
@pytest.mark.parametrize("kind", ["VARCHAR2", "NUMBER", "DATE"])
def test_ui_required_is_independent_of_db_nullability_and_preserves_ddl(nullable, required, kind):
    value = spec()
    index = ("VARCHAR2", "NUMBER", "DATE").index(kind)
    field = value["blocks"][0]["fields"][index]
    field.update(nullable=nullable, value_required=required)
    baseline = project(value)
    files = renderer.render_native_blueprint(value)
    column = legacy._columns(baseline["blocks"][0])[index + 1]
    effective_required = not nullable or required
    item = native_project._item({**column, "nullable": not effective_required}, (index + 2) * 10, 2)
    assert files["pages/p00002-edit_1.apx"].count(item) == 1
    assert f"valueRequired: {str(effective_required).lower()}" in item
    assert f"template: @/{'required' if effective_required else 'optional'}-floating" in item
    assert renderer.render_prototype_schema(value).encode() == legacy.render_prototype_schema(baseline).encode()
    assert field["nullable"] is nullable


def test_only_exact_selected_editable_items_change_all_other_pages_and_items_stay_identical():
    value = spec(12)
    for block in value["blocks"]:
        block["fields"][3].update(widget="display", in_edit_form=False)
    baseline = project(value)
    expected = legacy.render_native_blueprint(baseline)
    actual = renderer.render_native_blueprint(value)
    for block in value["blocks"][:2]:
        pages = legacy._pages(block)
        column = legacy._columns(block)[1]
        old = native_project._item(column, 20, pages["form_page_id"])
        new = native_project._item({**column, "nullable": False}, 20, pages["form_page_id"])
        assert expected[pages["form_file"]].count(old) == 1
        expected[pages["form_file"]] = expected[pages["form_file"]].replace(old, new, 1)
    assert actual == expected
    assert "executeValidations: true" in actual["pages/p00002-edit_1.apx"]
    assert actual["pages/p00002-edit_1.apx"].count("executeValidations: true") == 2


@pytest.mark.parametrize("change", ["missing", "duplicate"])
def test_missing_or_duplicate_exact_item_anchor_fails_closed(monkeypatch, change):
    value = spec()
    baseline = project(value)
    files = legacy.render_native_blueprint(baseline)
    column = legacy._columns(baseline["blocks"][0])[1]
    anchor = native_project._item(column, 20, 2)
    files["pages/p00002-edit_1.apx"] = files["pages/p00002-edit_1.apx"].replace(
        anchor, "" if change == "missing" else anchor + "\n" + anchor, 1)
    monkeypatch.setattr(legacy, "render_native_blueprint", lambda _: files)
    with pytest.raises(ValueError, match="REQUIRED_ITEM_ANCHOR_CHANGED"):
        renderer.render_native_blueprint(value)


@pytest.mark.parametrize("location,key", [("root", "approved"), ("root", "sql"),
    ("block", "query"), ("field", "expression"), ("field", "primary_key"),
    ("block", "value_required"), ("field", "input_validation_policy")])
def test_projection_never_discards_arbitrary_extra_keys(location, key):
    value = spec()
    obj = value if location == "root" else value["blocks"][0] if location == "block" else value["blocks"][0]["fields"][0]
    obj[key] = "untrusted"
    with pytest.raises(ValueError, match="FIELDS_INVALID"):
        renderer.validate_prototype_spec(value)


@pytest.mark.parametrize("key,bad", [("schema_version", True), ("schema_version", 1),
    ("profile_id", legacy.PROFILE_ID), ("input_validation_policy", "arbitrary"),
    ("input_validation_policy", None), ("data_mode", "customer"),
    ("source_binding", "A" * 64), ("project_id", "../bad")])
def test_new_profile_and_all_legacy_root_constraints_apply(key, bad):
    value = spec()
    value[key] = bad
    with pytest.raises(ValueError):
        renderer.validate_prototype_spec(value)


@pytest.mark.parametrize("key,bad", [("name", "ARBITRARY_COLUMN"), ("source_item_id", "unbound"),
    ("source_name", "a;drop table x"), ("nullable", 1), ("in_edit_form", "true"),
    ("data_type", "CLOB"), ("widget", "checkbox"), ("length", True), ("length", 4001)])
def test_source_derived_field_names_and_legacy_field_constraints_still_apply(key, bad):
    value = spec()
    value["blocks"][0]["fields"][0][key] = bad
    with pytest.raises(ValueError):
        renderer.validate_prototype_spec(value)


@pytest.mark.parametrize("duplicate", ["block", "item", "sequence", "block_item"])
def test_duplicate_and_colliding_ids_are_rejected(duplicate):
    value = spec()
    if duplicate == "block":
        value["blocks"][1]["source_block_id"] = value["blocks"][0]["source_block_id"]
    elif duplicate == "item":
        value["blocks"][1]["fields"][0] = deepcopy(value["blocks"][0]["fields"][0])
    elif duplicate == "sequence":
        value["blocks"][1]["sequence"] = value["blocks"][0]["sequence"]
    else:
        value["blocks"][1]["source_block_id"] = value["blocks"][0]["fields"][0]["source_item_id"]
    with pytest.raises(ValueError):
        renderer.validate_prototype_spec(value)


@pytest.mark.parametrize("bad", ["&APP_USER.", "<script>alert(1)</script>", "BEGIN NULL; END;",
    "select password from users", "x\nprocess code", "x\u202ey", "", "x" * 81])
def test_xss_injection_and_unbounded_labels_remain_rejected(bad):
    value = spec()
    value["blocks"][0]["fields"][0]["label"] = bad
    with pytest.raises(ValueError):
        renderer.render_native_blueprint(value)


def test_structure_like_labels_are_escaped_not_rewritten_by_required_adaptation():
    value = spec()
    field = value["blocks"][0]["fields"][0]
    field["label"] = 'valueRequired: false @/optional-floating P2_ID $TABLE "quote" \\ path'
    files = renderer.render_native_blueprint(value)
    escaped = json.dumps(field["label"], ensure_ascii=False)
    assert escaped in files["pages/p00002-edit_1.apx"]
    assert escaped in files["pages/p00001-block_1.apx"]


def test_repeat_zip_bytes_sorted_members_and_unchanged_false_policy_legacy_zip():
    value = spec()
    before = deepcopy(value)
    raw = renderer.deterministic_prototype_zip(value)
    assert raw == renderer.deterministic_prototype_zip(value)
    assert value == before
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        assert archive.namelist() == sorted(archive.namelist())
        assert {name: archive.read(name).decode() for name in archive.namelist()} == renderer.render_native_blueprint(value)
        assert all(row.date_time == (1980, 1, 1, 0, 0, 0) for row in archive.infolist())
    for block in value["blocks"]:
        for field in block["fields"]:
            field["value_required"] = False
    assert renderer.deterministic_prototype_zip(value) == legacy.deterministic_prototype_zip(project(value))


def test_historical_context_source_and_zip_remain_unchanged_after_new_profile_use():
    original = legacy_spec()
    before_context = legacy.context()
    before_zip = legacy.deterministic_prototype_zip(original)
    files = [Path(module.__file__) for module in (legacy, native_project, legacy.native, legacy.native_contract)]
    before_sources = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in files}
    renderer.render_native_blueprint(spec())
    renderer.prototype_trace(spec())
    renderer.deterministic_prototype_zip(spec())
    assert legacy.context() == before_context
    assert legacy.deterministic_prototype_zip(original) == before_zip
    assert {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in files} == before_sources


def test_false_additional_policy_preserves_old_nonnull_ui_and_readonly_reports_byte_for_byte():
    original = legacy_spec()
    original["blocks"][1]["native_component"] = "report"
    for field in original["blocks"][1]["fields"]:
        field["in_edit_form"] = False
    value = deepcopy(original)
    value.update(schema_version=2, profile_id=renderer.PROFILE_ID,
                 input_validation_policy=renderer.INPUT_VALIDATION_POLICY)
    for block in value["blocks"]:
        for field in block["fields"]:
            field["value_required"] = False
    assert renderer.render_native_blueprint(value) == legacy.render_native_blueprint(original)
    assert renderer.deterministic_prototype_zip(value) == legacy.deterministic_prototype_zip(original)
    assert renderer.render_prototype_schema(value) == legacy.render_prototype_schema(original)


@pytest.mark.parametrize("bad", [None, [], {"blocks": []}])
def test_malformed_root_fails_closed(bad):
    with pytest.raises(ValueError, match="ROOT_FIELDS_INVALID"):
        renderer.validate_prototype_spec(bad)


@pytest.mark.parametrize("location", ["blocks", "block", "fields", "field"])
def test_malformed_collections_fail_closed(location):
    value = spec()
    if location == "blocks":
        value["blocks"] = None
    elif location == "block":
        value["blocks"][0] = None
    elif location == "fields":
        value["blocks"][0]["fields"] = None
    else:
        value["blocks"][0]["fields"][0] = None
    with pytest.raises(ValueError):
        renderer.validate_prototype_spec(value)


def test_context_binds_own_physical_source_and_legacy_context(monkeypatch):
    baseline = renderer.context()
    old_context = legacy.context()
    original = Path.read_text
    def changed(path, *args, **kwargs):
        value = original(path, *args, **kwargs)
        return value + "\n# changed" if path == Path(renderer.__file__) else value
    with monkeypatch.context() as patch:
        patch.setattr(Path, "read_text", changed)
        assert renderer.context()["sha256"] != baseline["sha256"]
        assert legacy.context() == old_context
    monkeypatch.setattr(legacy, "context", lambda: {**old_context, "sha256": "b" * 64})
    assert renderer.context()["sha256"] != baseline["sha256"]


def test_trace_discloses_ui_only_adaptation_and_retains_every_unverified_gate():
    value = spec()
    trace = renderer.prototype_trace(value)
    assert trace["schema_version"] == 2
    assert trace["scope"] == renderer.PROFILE_ID + "-trace"
    assert trace["input_validation_policy"] == renderer.INPUT_VALIDATION_POLICY
    assert trace["template"] == renderer.context()
    assert trace["application_count"] == 1
    assert trace["rendering_spec_sha256"] == legacy._sha(legacy._canonical(renderer.validate_prototype_spec(value)))
    assert any("submit-time UI validation" in text and "nullability" in text for text in trace["assumptions"])
    for key in ("input_validation_source_verified", "source_completeness_verified", "reviewer_approval_verified",
                "execution_authority_verified", "sqlcl_validated", "imported", "runtime_verified",
                "business_behavior_verified", "human_acceptance_recorded"):
        assert trace[key] is False
    for block, traced in zip(value["blocks"], trace["blocks"]):
        for field, item in zip(block["fields"], traced["items"]):
            assert item["value_required"] is field["value_required"]
            assert item["ui_validation_adaptation"] == ("submit_time_required_input" if field["value_required"] else None)
            assert item["legacy_behavior_implemented"] is False
            assert item["nullable"] is field["nullable"]


@pytest.mark.parametrize("count", [0, 1, 109, 255])
def test_existing_large_and_empty_field_bounds_remain_supported(count):
    value = spec(count)
    assert len(renderer.prototype_trace(value)["blocks"][0]["items"]) == count
    assert renderer.render_native_blueprint(value)
