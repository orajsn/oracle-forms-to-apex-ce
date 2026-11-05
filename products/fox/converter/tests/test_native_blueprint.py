"""Pure synthetic prototype contract/render checks; no Oracle/provider calls."""
from copy import deepcopy
import hashlib
import io
import json
import re
import zipfile

import pytest

from forms2apex import native, native_contract, native_project
from forms2apex import native_blueprint as renderer


def source_id(index):
    return "ff1-" + f"{index:024x}"


def field(index, *, kind="VARCHAR2", widget=None, edit=True, nullable=True):
    identity = source_id(index)
    result = {"source_item_id": identity, "source_name": f"ITEM_{index}",
              "name": "F_" + hashlib.sha256(identity.encode()).hexdigest()[:24].upper(),
              "label": f"Field {index}", "data_type": kind,
              "widget": widget or {"VARCHAR2": "text", "NUMBER": "number", "DATE": "date"}[kind],
              "nullable": nullable, "in_edit_form": edit}
    if kind == "VARCHAR2":
        result["length"] = 120
    return result


def spec(count=4):
    result = {"schema_version": 1, "profile_id": renderer.PROFILE_ID,
              "data_mode": "synthetic_test_only", "project_id": "synthetic-project:1",
              "project_name": "Synthetic multi-block prototype", "source_binding": "a" * 64,
              "blocks": []}
    for index, classification in enumerate(("database", "database", "control"), start=1):
        block_id = source_id(index)
        table = ("FOX_NATIVE_" + hashlib.sha256(json.dumps(
            [result["project_id"], result["source_binding"], block_id],
            ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:19].upper()
                 if classification == "database" else None)
        fields = [field(1000 * index + offset, kind=("VARCHAR2", "NUMBER", "DATE")[offset % 3],
                        edit=classification == "database", nullable=offset % 2 == 0)
                  for offset in range(count)]
        result["blocks"].append({"source_block_id": block_id, "name": f"BLOCK_{index}",
                                 "sequence": index, "classification": classification,
                                 "native_component": "form" if classification == "database" else "page-items",
                                 "table_name": table, "fields": fields})
    return result


def test_independent_profile_copy_idempotence_order_and_stable_ids():
    value = spec()
    value["blocks"].reverse()
    before = deepcopy(value)
    normalized = renderer.validate_prototype_spec(value)
    assert value == before
    assert renderer.validate_prototype_spec(normalized) == normalized
    assert [block["sequence"] for block in normalized["blocks"]] == [1, 2, 3]
    assert renderer.render_native_blueprint(value) == renderer.render_native_blueprint(normalized)
    normalized["blocks"][0]["fields"][0]["label"] = "Changed copy"
    assert value == before


def test_two_database_blocks_and_control_are_one_native_application():
    value = spec()
    files = renderer.render_native_blueprint(value)
    trace = renderer.prototype_trace(value)
    assert sum(bool(re.search(r"^app ", text, re.M)) for text in files.values()) == 1
    assert "app FOX_BLUEPRINT_PROTOTYPE (" in files["application.apx"]
    assert len([path for path in files if path.startswith("pages/")]) == 7
    assert trace["application_count"] == 1
    for block in trace["blocks"][:2]:
        report, detail = files[block["report_file"]], files[block["form_file"]]
        assert "type: interactiveReport" in report
        assert "includeSearchBar: true" in report
        assert "type: form" in detail and "type: formAutoRowProcessing" in detail
        assert "preventLostUpdates: true" in detail and "lockRow: true" in detail
        assert "lostUpdateType: rowValues" in detail
        assert "type: hidden" in detail
        assert f"tableName: {block['table_name']}" in report
        assert f"tableName: {block['table_name']}" in detail
        assert f"P{block['form_page_id']}_FOX_ROW_ID" in detail
        assert "Synthetic row identity" not in detail
        assert len(block["items"]) == 4
    control = trace["blocks"][2]
    page = files[control["page_file"]]
    assert "type: staticContent" in page
    for kind in ("textField", "numberField", "datePicker"):
        assert "type: " + kind in page
    for forbidden in ("tableName:", "formRegion:", "formAutoRowProcessing", "button ", "plsqlCode:"):
        assert forbidden not in page
    assert control["table_name"] is None and control["synthetic_key"] is None
    assert not any(path.startswith("_fragments/") for path in files)


def test_explicit_report_component_has_only_readonly_native_query_page():
    value = spec(109)
    block = value["blocks"][1]
    block["native_component"] = "report"
    block["name"] = "Create Record P2_ID HOME"
    for field_ in block["fields"]:
        field_["in_edit_form"] = False
    files = renderer.render_native_blueprint(value)
    trace = renderer.prototype_trace(value)
    report_block = trace["blocks"][1]
    report = files[report_block["report_file"]]
    assert "type: interactiveReport" in report
    assert "type: tableView" in report and f"tableName: {block['table_name']}" in report
    assert "includeSearchBar: true" in report
    assert report.count("        column ") == 110
    assert report.count("            displayColumn ") == 8
    for forbidden in ("linkColumn:", "linkIcon:", "target:", "button ", "pageItem ",
                      "formAutoRowProcessing", "formInitialization", "databaseAction:",
                      "submitPage", "P4_FOX_ROW_ID", "clearCache:"):
        assert forbidden not in report
    assert "pages/p00004-edit_2.apx" not in files
    assert len([path for path in files if path.startswith("pages/")]) == 6
    assert report_block["native_component"] == "report" and report_block["read_only"] is True
    assert "form_page_id" not in report_block and "form_file" not in report_block
    assert report_block["synthetic_key"]["hidden_item"] is None
    assert all(item["native_item"] is None and item["native_item_page_id"] is None
               and item["in_edit_form"] is False and item["disposition"] == "report_only"
               for item in report_block["items"])
    assert not any("Create may fail" in limit for limit in report_block["limitations"])
    assert trace["blocks"][0]["read_only"] is False
    assert trace["blocks"][0]["form_page_id"] == 2
    assert f"CREATE TABLE {block['table_name']}" in renderer.render_prototype_schema(value)
    assert renderer.deterministic_prototype_zip(value) == renderer.deterministic_prototype_zip(value)


@pytest.mark.parametrize("classification,component", [("database", "grid"), ("database", "page-items"),
                                                     ("control", "form"), ("control", "report"),
                                                     ("database", None), ("database", [])])
def test_native_component_must_match_explicit_supported_classification(classification, component):
    value = spec()
    block = value["blocks"][0 if classification == "database" else 2]
    block["native_component"] = component
    with pytest.raises(ValueError, match="COMPONENT_INVALID"):
        renderer.validate_prototype_spec(value)


def test_component_is_required_and_report_cannot_accept_editable_fields():
    value = spec()
    value["blocks"][0].pop("native_component")
    with pytest.raises(ValueError, match="BLOCK_FIELDS_INVALID"):
        renderer.validate_prototype_spec(value)
    value = spec()
    value["blocks"][0]["native_component"] = "report"
    with pytest.raises(ValueError, match="REPORT_EDIT_INVALID"):
        renderer.validate_prototype_spec(value)


@pytest.mark.parametrize("anchor", ["linkIcon: Edit", "label: Create Record"])
def test_readonly_interaction_removal_fails_closed_when_trusted_template_changes(monkeypatch, anchor):
    original = native._template_files
    files = original()
    files["_fragments/report.apx.tmpl"] = files["_fragments/report.apx.tmpl"].replace(anchor, anchor + " Changed")
    monkeypatch.setattr(native, "_template_files", lambda: files)
    value = spec()
    value["blocks"] = [value["blocks"][0]]
    value["blocks"][0]["native_component"] = "report"
    for field_ in value["blocks"][0]["fields"]:
        field_["in_edit_form"] = False
    with pytest.raises(ValueError, match="READONLY_ANCHOR_CHANGED"):
        renderer.render_native_blueprint(value)


def test_109_fields_do_not_invoke_legacy_column_cap(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Historical renderer/validator must not be invoked")
    for module, name in ((native_contract, "validate_native_spec"), (native, "render_native_form"),
                         (native_project, "validate_project_spec"), (native_project, "render_native_project")):
        monkeypatch.setattr(module, name, forbidden)
    value = spec(109)
    files = renderer.render_native_blueprint(value)
    trace = renderer.prototype_trace(value)
    report = files[trace["blocks"][0]["report_file"]]
    detail = files[trace["blocks"][0]["form_file"]]
    assert report.count("        column ") == 110
    assert report.count("            displayColumn ") == 8
    assert detail.count("    pageItem ") == 110
    assert len(trace["blocks"][0]["items"]) == 109
    assert renderer.render_prototype_schema(value).count("CREATE TABLE ") == 2
    assert renderer.deterministic_prototype_zip(value)


@pytest.mark.parametrize("count", [0, 1, 20, 255])
def test_field_bounds_include_empty_database_key_only(count):
    value = spec(count)
    files = renderer.render_native_blueprint(value)
    assert files["pages/p00002-edit_1.apx"].count("    pageItem ") == count + 1


def test_field_overflow_and_block_overflow_fail_without_partial_output():
    value = spec(256)
    with pytest.raises(ValueError, match="FIELD_COUNT"):
        renderer.render_native_blueprint(value)
    value = spec()
    value["blocks"] *= 17
    with pytest.raises(ValueError, match="BLOCK_COUNT"):
        renderer.render_native_blueprint(value)
    value["blocks"] = []
    with pytest.raises(ValueError, match="BLOCK_COUNT"):
        renderer.render_native_blueprint(value)


def test_50_block_boundary_preserves_all_native_pages_and_source_ids():
    value = spec(1)
    seed = value["blocks"][0]
    value["blocks"] = []
    for sequence in range(1, 51):
        block = deepcopy(seed)
        block.update(source_block_id=source_id(sequence), name=f"BLOCK_{sequence}", sequence=sequence)
        block["fields"] = [field(1000 + sequence)]
        block["table_name"] = renderer._table(value["project_id"], value["source_binding"], block["source_block_id"])
        value["blocks"].append(block)
    files = renderer.render_native_blueprint(value)
    trace = renderer.prototype_trace(value)
    assert len(trace["blocks"]) == 50
    assert len([path for path in files if path.startswith("pages/")]) == 102
    assert files["pages/p00100-edit_50.apx"].startswith("page 100 (")
    assert len({block["source_block_id"] for block in trace["blocks"]}) == 50


def test_sequence_gaps_bind_pages_home_navigation_and_items():
    value = spec()
    value["blocks"] = value["blocks"][1:]
    files = renderer.render_native_blueprint(value)
    assert "homeUrl: {\n            page: 3" in files["application.apx"]
    assert files["pages/p00003-block_2.apx"].startswith("page 3 (")
    assert files["pages/p00005-block_3.apx"].startswith("page 5 (")
    assert "page: 3" in files["shared-components/lists.apx"]
    assert "page: 5" in files["shared-components/lists.apx"]
    assert "entry block-1" not in files["shared-components/lists.apx"]
    assert "pageNumber: 3" in files["shared-components/breadcrumbs.apx"]


def test_report_only_display_fields_never_become_fake_editable_items():
    value = spec()
    for block in value["blocks"]:
        block["fields"][0].update(widget="display", in_edit_form=False)
    trace = renderer.prototype_trace(value)
    files = renderer.render_native_blueprint(value)
    for block in trace["blocks"]:
        item = block["items"][0]
        if block["classification"] == "database":
            assert item["native_item"] is None
            assert "column " + item["column"] in files[block["report_file"]]
            assert item["column"] not in files[block["form_file"]]
            assert item["disposition"] == "report_only"
        else:
            assert item["native_item"] == "P5_" + value["blocks"][2]["fields"][0]["name"]
            assert "pageItem " + item["native_item"] in files[block["page_file"]]
            assert "type: displayOnly" in files[block["page_file"]]
            assert item["disposition"] == "native_item_candidate"
            assert item["database_bound"] is False
            assert item["legacy_behavior_implemented"] is False
            assert item["value_computation_implemented"] is False


@pytest.mark.parametrize("kind", ["VARCHAR2", "NUMBER", "DATE"])
def test_control_display_only_items_use_proven_source_free_native_shape_without_fake_values(kind):
    value = spec(1)
    value["blocks"] = [value["blocks"][2]]
    field_ = field(3000, kind=kind, edit=False)
    value["blocks"][0]["fields"] = [field_]
    field_.update(widget="display", in_edit_form=False, nullable=False)
    field_["label"] = 'Display "quoted" label'
    trace = renderer.prototype_trace(value)
    block = trace["blocks"][0]
    page = renderer.render_native_blueprint(value)[block["page_file"]]
    assert f"pageItem P5_{field_['name']} (" in page
    assert page.count("type: displayOnly") == 1
    assert "label: " + json.dumps(field_["label"]) in page
    assert "region: @controls" in page and "slot: regionBody" in page
    assert "template: @/optional-floating" in page
    for forbidden in ("source {", "validation {", "valueRequired:", "maxLength:", "tableName:",
                      "formRegion:", "process ", "button ", "default", "computation", "plsql", "value:"):
        assert forbidden not in page
    assert block["table_name"] is None and block["synthetic_key"] is None
    assert any("no inferred value source" in limitation for limitation in block["limitations"])
    assert "CREATE TABLE" not in renderer.render_prototype_schema(value)
    assert trace["sqlcl_validated"] is trace["imported"] is trace["runtime_verified"] is trace["business_behavior_verified"] is False


def test_report_only_required_columns_keep_nullability_and_expose_create_limit():
    value = spec()
    value["blocks"][0]["fields"][0].update(widget="display", in_edit_form=False, nullable=False)
    trace = renderer.prototype_trace(value)
    assert any("Create may fail" in limitation for limitation in trace["blocks"][0]["limitations"])
    column = value["blocks"][0]["fields"][0]
    assert column["name"] + " VARCHAR2(120) NOT NULL" in renderer.render_prototype_schema(value)


def test_create_only_schema_exact_types_nullability_and_synthetic_keys():
    value = spec()
    schema = renderer.render_prototype_schema(value)
    assert schema.count("CREATE TABLE ") == 2
    assert schema.count("FOX_ROW_ID NUMBER GENERATED BY DEFAULT ON NULL AS IDENTITY PRIMARY KEY") == 2
    executable = "\n".join(line for line in schema.splitlines() if not line.startswith("--"))
    assert not re.search(r"\b(DROP|ALTER|TRUNCATE|DELETE|UPDATE|INSERT|GRANT|USER|REPLACE)\b", executable)
    for block in value["blocks"][:2]:
        assert len(block["table_name"]) <= 30
        for field_ in block["fields"]:
            sql_type = field_["data_type"] + (f"({field_['length']})" if "length" in field_ else "")
            assert (field_["name"] + " " + sql_type + ("" if field_["nullable"] else " NOT NULL")) in schema
            assert field_["source_name"] not in schema
    assert value["blocks"][2]["fields"][0]["name"] not in schema


def test_zip_is_sorted_utf8_deterministic_and_canonical():
    value = spec()
    value["project_name"] = "Synthetic café prototype"
    before = deepcopy(value)
    first = renderer.deterministic_prototype_zip(value)
    assert first == renderer.deterministic_prototype_zip(value)
    assert value == before
    with zipfile.ZipFile(io.BytesIO(first)) as archive:
        assert archive.namelist() == sorted(archive.namelist())
        assert {member.filename: archive.read(member).decode("utf-8") for member in archive.infolist()} == renderer.render_native_blueprint(value)
        assert all(member.date_time == (1980, 1, 1, 0, 0, 0) for member in archive.infolist())
        assert all(not member.filename.startswith(("/", "..")) for member in archive.infolist())


def test_labels_are_escaped_and_never_rewritten_as_structure():
    value = spec()
    field_ = value["blocks"][0]["fields"][0]
    field_["label"] = 'P2_ID page: 2 HOME @record "quote" \\ path $TABLE'
    files = renderer.render_native_blueprint(value)
    escaped = json.dumps(field_["label"], ensure_ascii=False)
    assert escaped in files["pages/p00001-block_1.apx"]
    assert escaped in files["pages/p00002-edit_1.apx"]


@pytest.mark.parametrize("bad", ["&APP_USER.", "<script>alert(1)</script>", "BEGIN NULL; END;",
                                  "select password from users", "x\nprocess code", "x\u202ey", "", "x" * 81])
def test_malicious_or_unbounded_labels_are_refused(bad):
    value = spec()
    value["blocks"][0]["fields"][0]["label"] = bad
    with pytest.raises(ValueError):
        renderer.render_native_blueprint(value)


@pytest.mark.parametrize("location,key", [("root", "sql"), ("block", "query"), ("field", "expression"),
                                          ("root", "approved"), ("field", "primary_key")])
def test_unknown_fields_rejected_at_every_level(location, key):
    value = spec()
    obj = value if location == "root" else value["blocks"][0] if location == "block" else value["blocks"][0]["fields"][0]
    obj[key] = "untrusted"
    with pytest.raises(ValueError):
        renderer.validate_prototype_spec(value)


@pytest.mark.parametrize("key,bad", [("schema_version", True), ("profile_id", "native-table-form-v1"),
                                    ("data_mode", "customer"), ("source_binding", "A" * 64),
                                    ("source_binding", {"hash": "a" * 64}), ("project_id", "../x")])
def test_invalid_root_contract(key, bad):
    value = spec()
    value[key] = bad
    with pytest.raises(ValueError):
        renderer.validate_prototype_spec(value)


@pytest.mark.parametrize("key,bad", [("source_block_id", "unbound"), ("sequence", True),
                                    ("sequence", 0), ("sequence", 51), ("name", "x&APP_USER."),
                                    ("classification", "view"), ("table_name", "FOX_NATIVE_ARBITRARY")])
def test_invalid_block_contract(key, bad):
    value = spec()
    value["blocks"][0][key] = bad
    with pytest.raises(ValueError):
        renderer.validate_prototype_spec(value)


@pytest.mark.parametrize("key,bad", [("source_item_id", "unbound"), ("source_name", "a;drop table x"),
                                    ("name", "ROWID"), ("data_type", "CLOB"), ("widget", "checkbox"),
                                    ("widget", "number"), ("nullable", 1), ("in_edit_form", "false"),
                                    ("length", True), ("length", 4001), ("length", 0)])
def test_invalid_field_contract(key, bad):
    value = spec()
    value["blocks"][0]["fields"][0][key] = bad
    with pytest.raises(ValueError):
        renderer.validate_prototype_spec(value)


def test_duplicate_source_id_sequence_and_wrong_storage_binding_rejected():
    for change in ("item", "block", "sequence", "control_table", "source_binding", "project_id", "length_number", "display_edit", "control_edit"):
        value = spec()
        if change == "item":
            value["blocks"][1]["fields"][0] = deepcopy(value["blocks"][0]["fields"][0])
        elif change == "block":
            value["blocks"][1]["source_block_id"] = value["blocks"][0]["source_block_id"]
        elif change == "sequence":
            value["blocks"][1]["sequence"] = 1
        elif change == "control_table":
            value["blocks"][2]["table_name"] = "FOX_NATIVE_X"
        elif change == "source_binding":
            value["source_binding"] = "b" * 64
        elif change == "project_id":
            value["project_id"] = "other"
        elif change == "length_number":
            value["blocks"][0]["fields"][1]["length"] = 10
        elif change == "display_edit":
            value["blocks"][0]["fields"][0]["widget"] = "display"
        else:
            value["blocks"][2]["fields"][0]["in_edit_form"] = True
        with pytest.raises(ValueError):
            renderer.validate_prototype_spec(value)


def test_source_names_256_are_preserved_not_truncated():
    value = spec()
    value["blocks"][0]["name"] = "B" * 256
    value["blocks"][0]["fields"][0]["source_name"] = "I" * 256
    normalized = renderer.validate_prototype_spec(value)
    assert normalized["blocks"][0]["name"] == "B" * 256
    assert normalized["blocks"][0]["fields"][0]["source_name"] == "I" * 256


def test_trace_covers_every_source_item_and_does_not_assert_proof():
    value = spec(109)
    trace = renderer.prototype_trace(value)
    assert trace["status"] == "CANDIDATE"
    assert trace["source_binding"] == value["source_binding"]
    assert len(trace["blocks"]) == 3
    assert {item["source_item_id"] for block in trace["blocks"] for item in block["items"]} == {
        item["source_item_id"] for block in value["blocks"] for item in block["fields"]}
    for flag in ("source_completeness_verified", "reviewer_approval_verified", "execution_authority_verified",
                 "sqlcl_validated", "imported", "runtime_verified", "business_behavior_verified", "human_acceptance_recorded"):
        assert trace[flag] is False
    assert all(block["synthetic_key"]["source_derived"] is False for block in trace["blocks"][:2])
    assert all(block["synthetic_key"]["source_item_id"] is None for block in trace["blocks"][:2])
    assert trace["template"] == renderer.context()
    assert len(trace["template"]["sha256"]) == 64


def test_context_changes_with_renderer_dependencies_and_templates(monkeypatch):
    before = renderer.context()
    original = renderer._templates
    monkeypatch.setattr(renderer, "_templates", lambda: {**original(), "control.apx.tmpl": "changed"})
    assert renderer.context()["sha256"] != before["sha256"]


def test_changed_trusted_structural_anchors_fail_closed(monkeypatch):
    original = native._template_files
    files = original()
    files["_fragments/report.apx.tmpl"] = files["_fragments/report.apx.tmpl"].replace("page 1 (", "page 9 (")
    monkeypatch.setattr(native, "_template_files", lambda: files)
    with pytest.raises(ValueError, match="TEMPLATE_ANCHOR_CHANGED"):
        renderer.render_native_blueprint(spec())


def test_historical_validator_still_rejects_21_columns():
    columns = [{"name": "ID", "label": "Identity", "data_type": "NUMBER", "nullable": False,
                "primary_key": True, "identity": True}] + [
        {"name": f"COL_{index}", "label": "Value", "data_type": "NUMBER", "nullable": True}
        for index in range(20)]
    with pytest.raises(ValueError, match="2 and 20"):
        native_contract.validate_native_spec({"profile_id": "native-table-form-v1",
            "data_mode": "synthetic_test_only", "table_name": "FOX_NATIVE_OLD", "columns": columns})
