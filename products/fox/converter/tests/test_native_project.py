"""Pure multi-form composition tests: no Oracle, model or network execution."""
from copy import deepcopy
import hashlib
import io
import json
import re
import zipfile

import pytest

from forms2apex import native, native_project as project


def native_spec(table="FOX_NATIVE_ORDERS", *, key="ID", label="Title", mixed=False):
    columns = [
        {"name": key, "data_type": "NUMBER", "nullable": False, "label": "Identity",
         "primary_key": True, "identity": True},
        {"name": "TITLE", "data_type": "VARCHAR2", "nullable": False, "label": label, "length": 100},
    ]
    if mixed:
        columns += [{"name": "AMOUNT", "data_type": "NUMBER", "nullable": False, "label": "Amount"},
                    {"name": "DUE_DATE", "data_type": "DATE", "nullable": True, "label": "Due date"}]
    return {"profile_id": "native-table-form-v1", "data_mode": "synthetic_test_only",
            "table_name": table, "columns": columns}


def form(index, *, table=None, **kwargs):
    return {"module_id": "form-" + f"{index:020x}", "form_name": f"FORM_{index}",
            "source_name": f"form-{index}.xml", "source_sha256": hashlib.sha256(str(index).encode()).hexdigest(),
            "native_form": native_spec(table or f"FOX_NATIVE_TABLE_{index}", **kwargs)}


def spec(count=2):
    return {"schema_version": 1, "profile_id": "native-project-v1", "data_mode": "synthetic_test_only",
            "project_name": "Synthetic multi-form project", "source_manifest_sha256": "a" * 64,
            "forms": [form(index + 1, mixed=index % 2 == 1) for index in range(count)]}


def test_normalization_is_deterministic_idempotent_and_does_not_mutate():
    value = spec(3)
    value["forms"].reverse()
    before = deepcopy(value)
    normalized = project.validate_project_spec(value)
    assert value == before
    assert [item["module_id"] for item in normalized["forms"]] == sorted(item["module_id"] for item in value["forms"])
    assert project.validate_project_spec(normalized) == normalized
    normalized["forms"][0]["native_form"]["columns"][1]["label"] = "Changed returned copy"
    assert value == before


@pytest.mark.parametrize("count", [1, 2, 3, 50])
def test_one_application_shell_and_all_selected_forms(count):
    value = spec(count)
    before = deepcopy(value)
    base = native._template_files()
    files = project.render_native_project(value)
    assert value == before
    assert len([name for name in files if name.startswith("pages/")]) == 2 * count + 2
    assert sum(bool(re.search(r"^app ", text, re.M)) for text in files.values()) == 1
    assert "app FOX_PROJECT_DRAFT (" in files["application.apx"]
    assert "    name: " + json.dumps(value["project_name"]) in files["application.apx"]
    assert "homeUrl: {\n            page: 1" in files["application.apx"]
    assert not any(name.startswith("_fragments/") for name in files)
    for name in ("pages/p00000-global-page.apx", "pages/p09999-login.apx",
                 "shared-components/authentications.apx", "shared-components/authorizations.apx",
                 "shared-components/component-settings.apx", ".apex/apexlang.json", "deployments/default.json"):
        assert files[name] == base[name]
    assert files["shared-components/lists.apx"].count("list navigation-bar (") == 1
    assert files["shared-components/lists.apx"].count("list navigation-menu (") == 1
    assert files["pages/p09999-login.apx"].count("page 9999 (") == 1
    assert "P9999_USERNAME" in files["pages/p09999-login.apx"]


def test_every_page_link_item_alias_and_native_behavior_is_module_scoped():
    value = spec(3)
    value["forms"][1]["native_form"]["columns"][0]["name"] = "TICKET_NUMBER"
    files = project.render_native_project(value)
    items, aliases = [], []
    trace = project.project_trace(value)
    for index, module in enumerate(trace["forms"]):
        report_id, form_id = 2 * index + 1, 2 * index + 2
        report, detail = files[module["report_file"]], files[module["form_file"]]
        columns = value["forms"][index]["native_form"]["columns"]
        key = columns[0]["name"]
        assert report.startswith(f"page {report_id} (")
        assert detail.startswith(f"page {form_id} (")
        for kind, page_id, content in (("report", report_id, report), ("form", form_id, detail)):
            alias = re.findall(r"^    alias: ([A-Z0-9_]+)$", content, re.M)
            assert alias == [module[kind + "_alias"]]
            assert module[kind + "_file"] == f"pages/p{page_id:05d}-{alias[0].lower()}.apx"
        assert re.findall(r"^\s+page: (\d+)$", report, re.M) == [str(form_id)] * 2
        assert re.findall(r"^\s+clearCache: (\d+)$", report, re.M) == [str(form_id)] * 2
        assert re.findall(r"^\s+page: (\d+)$", detail, re.M) == [str(report_id)] * 2
        assert re.findall(r"^\s+clearCache: (\d+)$", detail, re.M) == [str(form_id)] * 2
        assert f'P{form_id}_{key}: "#{key}#"' in report
        assert detail.count(f"item: P{form_id}_{key}") == 2
        assert report.count("        column ") == report.count("            displayColumn ") == len(columns)
        assert detail.count("    pageItem ") == len(columns)
        found = re.findall(r"^    pageItem (P[0-9]+_[A-Z0-9_]+) \($", detail, re.M)
        assert found == [f"P{form_id}_{column['name']}" for column in columns]
        items += found
        aliases += re.findall(r"^    alias: ([A-Z0-9_]+)$", report + detail, re.M)
        for marker in ("type: formInitialization", "type: formAutoRowProcessing", "preventLostUpdates: true",
                       "lostUpdateType: rowValues", "lockRow: true", "databaseAction: insert",
                       "databaseAction: update", "queryOnly: true", "sessionStateProtection: checksumRequiredSessionLevel"):
            assert marker in detail
        assert "authentication: required" in report
        assert "pageAccessProtection: argumentsMustHaveChecksum" in report and "pageAccessProtection: argumentsMustHaveChecksum" in detail
        assert "databaseAction: delete" not in detail
        assert "htmlCode:" not in report + detail and "javaScriptCode:" not in report + detail
    assert len(items) == len(set(items)) and len(aliases) == len(set(aliases)) == 6
    nav = files["shared-components/lists.apx"].split("list navigation-menu (")[1]
    assert re.findall(r"^\s+page: (\d+)$", nav, re.M) == ["1", "3", "5"]
    crumbs = files["shared-components/breadcrumbs.apx"]
    assert re.findall(r"^\s+pageNumber: (\d+)$", crumbs, re.M) == ["1", "3", "5"]
    assert re.findall(r"^\s+page: (\d+)$", crumbs, re.M) == ["1", "3", "5"]


def test_shared_table_deduplicates_schema_but_preserves_each_form_and_label():
    value = spec(2)
    value["forms"] = [form(1, table="FOX_NATIVE_SHARED", label="Order title"),
                      form(2, table="FOX_NATIVE_SHARED", label="Ticket title")]
    files = project.render_native_project(value)
    schema = project.render_project_schema(value)
    trace = project.project_trace(value)
    assert schema.count("CREATE TABLE FOX_NATIVE_SHARED (") == 1
    assert len(trace["tables"]) == 1 and len(trace["tables"][0]["module_ids"]) == 2
    assert trace["forms"][0]["schema_contract_sha256"] == trace["forms"][1]["schema_contract_sha256"]
    assert trace["tables"][0]["schema_sql_sha256"] == hashlib.sha256(schema.encode()).hexdigest()
    assert trace["forms"][0]["native_spec_sha256"] != trace["forms"][1]["native_spec_sha256"]
    assert 'label: "Order title"' in files["pages/p00002-edit_1.apx"]
    assert 'label: "Ticket title"' in files["pages/p00004-edit_2.apx"]


@pytest.mark.parametrize("change", ["length", "nullable", "type", "order", "key"])
def test_shared_schema_conflicts_stop_entire_project_before_template_read(monkeypatch, change):
    value = spec(2)
    value["forms"][1]["native_form"] = deepcopy(value["forms"][0]["native_form"])
    other = value["forms"][1]["native_form"]["columns"]
    if change == "length": other[1]["length"] = 80
    elif change == "nullable": other[1]["nullable"] = True
    elif change == "type": other[1].update(data_type="DATE"); other[1].pop("length")
    elif change == "order": other.reverse()
    elif change == "key": other[0]["name"] = "OTHER_ID"
    monkeypatch.setattr(native, "_template_files", lambda: pytest.fail("Templates read before all form metadata passed"))
    with pytest.raises(project.ProjectRenderError, match="PROJECT_SHARED_TABLE_CONFLICT") as error:
        project.render_native_project(value)
    assert error.value.module_id == value["forms"][1]["module_id"]


def test_multiple_modules_in_one_xml_keep_the_same_source_identity():
    value = spec(2)
    value["forms"][1]["source_name"] = value["forms"][0]["source_name"]
    value["forms"][1]["source_sha256"] = value["forms"][0]["source_sha256"]
    assert len(project.project_trace(value)["forms"]) == 2
    assert len(project.render_native_project(value)) > 0


def test_canonically_identical_form_names_are_ambiguous():
    value = spec(2)
    value["forms"][0]["form_name"] = "CAF\u00c9"
    value["forms"][1]["form_name"] = "cafe\u0301"
    with pytest.raises(project.ProjectRenderError, match="PROJECT_DUPLICATE_FORM_NAME"):
        project.render_native_project(value)


@pytest.mark.parametrize("change,code", [
    ("id", "PROJECT_DUPLICATE_MODULE_ID"), ("name", "PROJECT_DUPLICATE_FORM_NAME"),
    ("hash", "PROJECT_SOURCE_IDENTITY_CONFLICT"), ("case", "PROJECT_SOURCE_IDENTITY_CONFLICT"),
])
def test_identity_conflicts_are_not_renamed_or_dropped(change, code):
    value = spec(2)
    first, second = value["forms"]
    if change == "id": second["module_id"] = first["module_id"]
    elif change == "name": second["form_name"] = first["form_name"].lower()
    elif change == "hash": second["source_name"] = first["source_name"]
    else:
        second["source_name"] = first["source_name"].upper()
        second["source_sha256"] = first["source_sha256"]
    with pytest.raises(project.ProjectRenderError, match=code):
        project.render_native_project(value)


@pytest.mark.parametrize("label", ['P2_ID page: 2 HOME @record $TABLE', 'Customer "name" \\ path', '客户名称'])
def test_metadata_is_quoted_and_never_structurally_rewritten(label):
    value = spec(2)
    value["project_name"] = label
    value["forms"][1]["form_name"] = label
    value["forms"][1]["native_form"]["columns"][1]["label"] = label
    encoded = json.dumps(label, ensure_ascii=False)
    files = project.render_native_project(value)
    assert "    name: " + encoded in files["application.apx"]
    assert "heading: " + encoded in files["pages/p00003-form_2.apx"]
    assert "label: " + encoded in files["pages/p00004-edit_2.apx"]
    assert "label: " + encoded in files["shared-components/lists.apx"]
    assert "name: " + encoded in files["shared-components/breadcrumbs.apx"]
    assert "pageItem P4_TITLE (" in files["pages/p00004-edit_2.apx"]


@pytest.mark.parametrize("label", ["&APP_USER.", "<script>", "A\nB", "select password from secret", "", 42])
@pytest.mark.parametrize("location", ["project", "form", "field", "key"])
def test_unsafe_display_metadata_is_blocked(label, location):
    value = spec()
    if location == "project": value["project_name"] = label
    elif location == "form": value["forms"][1]["form_name"] = label
    else: value["forms"][1]["native_form"]["columns"][0 if location == "key" else 1]["label"] = label
    with pytest.raises(project.ProjectRenderError):
        project.render_native_project(value)


@pytest.mark.parametrize("mutate", [
    lambda v: v.update(sql="select * from dual"),
    lambda v: v.update(state="READY"),
    lambda v: v.update(schema_version=True),
    lambda v: v.update(schema_version=2),
    lambda v: v.update(profile_id="native-table-form-v1"),
    lambda v: v.update(data_mode="production"),
    lambda v: v.update(source_manifest_sha256="A" * 64),
    lambda v: v.update(forms=[]),
    lambda v: v.update(forms=[form(i + 1) for i in range(51)]),
    lambda v: v["forms"][0].update(selected=False),
    lambda v: v["forms"][0].update(module_id="form-../../bad"),
    lambda v: v["forms"][0].update(source_sha256="z" * 64),
    lambda v: v["forms"][0].update(source_name="../form.xml"),
    lambda v: v["forms"][0].update(source_name="raw.fmb"),
    lambda v: v["forms"][0].update(source_name="a:b.xml"),
    lambda v: v["forms"][0].update(source_name="a\\b.xml"),
])
def test_unknown_or_invalid_project_metadata_fails_closed(mutate):
    value = spec()
    mutate(value)
    with pytest.raises(project.ProjectRenderError):
        project.render_native_project(value)


def test_one_invalid_form_blocks_all_output_without_silently_dropping_it(monkeypatch):
    value = spec(3)
    value["forms"][1]["native_form"]["columns"][0].pop("identity")
    monkeypatch.setattr(native, "_template_files", lambda: pytest.fail("Must validate the entire project first"))
    for function in (project.render_native_project, project.render_project_schema,
                     project.project_trace, project.deterministic_project_zip):
        with pytest.raises(project.ProjectRenderError, match="PROJECT_NATIVE_FORM_INVALID") as error:
            function(value)
        assert error.value.module_id == value["forms"][1]["module_id"]


@pytest.mark.parametrize("kind", ["report", "form", "navigation", "breadcrumb", "extra_page"])
def test_unexpected_trusted_template_structure_is_not_silently_accepted(monkeypatch, kind):
    files = native._template_files()
    if kind == "report": files["_fragments/report.apx.tmpl"] = files["_fragments/report.apx.tmpl"].replace("page 1 (", "page 10 (")
    elif kind == "form": files["_fragments/form.apx.tmpl"] = files["_fragments/form.apx.tmpl"].replace("    alias: RECORD", "    alias: MODIFIED")
    elif kind == "navigation": files["shared-components/lists.apx"] += files["shared-components/lists.apx"]
    elif kind == "breadcrumb": files["shared-components/breadcrumbs.apx"] = files["shared-components/breadcrumbs.apx"].replace("pageNumber: 1", "pageNumber: 7")
    else: files["pages/p00003-unreviewed.apx"] = "page 3 ()"
    monkeypatch.setattr(native, "_template_files", lambda: deepcopy(files))
    with pytest.raises(project.ProjectRenderError, match="TEMPLATE"):
        project.render_native_project(spec())


def test_deterministic_archive_and_trace_are_not_validation_or_acceptance_claims():
    value = spec(3)
    first = project.deterministic_project_zip(value)
    reversed_value = deepcopy(value)
    reversed_value["forms"].reverse()
    assert first == project.deterministic_project_zip(reversed_value)
    files = project.render_native_project(value)
    with zipfile.ZipFile(io.BytesIO(first)) as archive:
        assert archive.testzip() is None
        assert archive.namelist() == sorted(files)
        assert len(archive.namelist()) == len(set(archive.namelist()))
        for info in archive.infolist():
            assert info.date_time == (1980, 1, 1, 0, 0, 0)
            assert info.create_system == 3 and info.external_attr >> 16 == 0o100644
            assert archive.read(info.filename) == files[info.filename].encode("utf-8")
    trace = project.project_trace(value)
    assert trace["application_count"] == 1 and trace["form_count"] == 3
    assert trace["source_manifest_sha256"] == value["source_manifest_sha256"]
    assert all(trace[key] is False for key in ("source_completeness_verified", "reviewer_approval_verified",
        "sqlcl_validated", "imported", "runtime_verified", "human_acceptance_recorded"))
    assert len(trace["forms"]) == len(value["forms"])
    changed = deepcopy(value)
    changed["forms"][0]["native_form"]["columns"][1]["label"] = "A different supplied label"
    assert project.deterministic_project_zip(changed) != first
    assert project.project_trace(changed)["rendering_spec_sha256"] != trace["rendering_spec_sha256"]


def test_native_single_form_api_and_shared_templates_remain_unchanged():
    original = native_spec()
    before = native.render_native_form(original)
    template_before = native.context()
    project.render_native_project(spec(3))
    assert native.render_native_form(original) == before
    assert native.context() == template_before
    assert "pages/p00001-home.apx" in before and "pages/p00002-record.apx" in before


def test_project_context_binds_base_context_and_new_code(monkeypatch):
    original = project.context()
    assert original["profile_id"] == "native-project-v1"
    assert original["template_id"] == "sqlcl-26.1.2-fox-project-v1"
    assert original["navigation_policy"] == "stable_module_id_order_not_inferred_business_flow"
    base = native.context()
    monkeypatch.setattr(native, "context", lambda: {**base, "sha256": "b" * 64})
    assert project.context()["sha256"] != original["sha256"]


def mapped_spec(*, project_id="mapped-project", shared=False):
    from fox_source_contract.project_conversion import derive_storage_mapping
    value = project.validate_project_spec(spec(2))
    value.update(schema_version=2, project_id=project_id)
    for index, row in enumerate(value["forms"]):
        source = project.native_contract.validate_native_spec(native_spec(label=f"Label {index + 1}"))
        source["table_name"] = "CUSTOMERS" if shared or index == 0 else "ORDERS"
        row["storage_mapping"] = derive_storage_mapping(project_id, source)
        row["native_form"] = {**source, "table_name": row["storage_mapping"]["target_table_name"]}
        row["ddl_sources"] = [{"name": "schema.sql", "sha256": "d" * 64}]
    return value


def test_v2_maps_only_structural_table_references_and_keeps_original_evidence():
    value = mapped_spec()
    label = "CUSTOMERS P2_ID page: 2 HOME @record $TABLE"
    value["forms"][1]["form_name"] = label
    value["forms"][1]["native_form"]["columns"][1]["label"] = label
    before = deepcopy(value)
    normalized = project.validate_project_spec(value)
    files, trace = project.render_native_project(value), project.project_trace(value)
    assert value == before and project.validate_project_spec(normalized) == normalized
    assert trace["schema_version"] == 2 and trace["scope"] == "fox-native-project-render-trace-v2"
    assert trace["project_id"] == value["project_id"]
    assert trace["source_manifest_sha256"] == value["source_manifest_sha256"]
    for row, mapped in zip(value["forms"], trace["forms"]):
        assert mapped["source_sha256"] == row["source_sha256"]
        assert mapped["ddl_sources"] == row["ddl_sources"]
        assert mapped["storage_mapping"] == row["storage_mapping"]
        for filename in (mapped["report_file"], mapped["form_file"]):
            assert re.findall(r"^\s*tableName: (\w+)$", files[filename], re.M) == [row["native_form"]["table_name"]]
        assert f"CREATE TABLE {row['native_form']['table_name']} (" in project.render_project_schema(value)
    assert json.dumps(label) in files["pages/p00004-edit_2.apx"]
    normalized["forms"][0]["ddl_sources"][0]["sha256"] = "b" * 64
    normalized["forms"][0]["storage_mapping"]["source_table_name"] = "CHANGED"
    assert value == before


def test_v2_shared_storage_preserves_form_labels_and_deduplicates_ddl():
    value = mapped_spec(shared=True)
    trace = project.project_trace(value)
    assert len(trace["tables"]) == 1
    assert trace["tables"][0]["ddl_sources"] == value["forms"][0]["ddl_sources"]
    assert trace["tables"][0]["storage_mapping"] == value["forms"][0]["storage_mapping"]
    assert project.render_project_schema(value).count("CREATE TABLE ") == 1
    assert trace["forms"][0]["native_spec_sha256"] != trace["forms"][1]["native_spec_sha256"]


@pytest.mark.parametrize("change", ["target", "source", "schema", "identity", "project", "version",
                                    "ddl_hash", "ddl_order", "no_mapping", "source_as_target", "extra"])
def test_v2_tampered_or_partial_mapping_fails_before_template_read(monkeypatch, change):
    value = mapped_spec()
    row = value["forms"][0]
    if change == "target": row["storage_mapping"]["target_table_name"] = "FOX_NATIVE_OTHER"
    elif change == "source": row["storage_mapping"]["source_table_name"] = "OTHER"
    elif change == "schema": row["native_form"]["columns"][1]["length"] += 1
    elif change == "identity": row["storage_mapping"]["identity_sha256"] = "f" * 64
    elif change == "project": value["project_id"] = "other-project"
    elif change == "version": row["storage_mapping"]["schema_version"] = True
    elif change == "ddl_hash": value["forms"][1]["ddl_sources"][0]["sha256"] = "f" * 64
    elif change == "ddl_order": row["ddl_sources"] = [{"name": n, "sha256": "d" * 64} for n in ("z.sql", "a.sql")]
    elif change == "no_mapping": row.pop("storage_mapping")
    elif change == "source_as_target": row["native_form"]["table_name"] = "CUSTOMERS"
    else: row["storage_mapping"]["approved"] = True
    monkeypatch.setattr(native, "_template_files", lambda: pytest.fail("Unvalidated mapping read templates"))
    with pytest.raises(project.ProjectRenderError):
        project.render_native_project(value)


def test_v1_envelope_is_not_reinterpreted_as_optional_mapping_metadata():
    legacy = spec()
    normalized = project.validate_project_spec(legacy)
    assert set(normalized) == project._ROOT_FIELDS
    assert all(set(row) == project._FORM_FIELDS for row in normalized["forms"])
    assert project.project_trace(legacy)["scope"] == "fox-native-project-render-trace-v1"
    for key, item in (("project_id", "mapped-project"), ("schema_version", 2)):
        changed = deepcopy(legacy)
        changed[key] = item
        with pytest.raises(project.ProjectRenderError):
            project.validate_project_spec(changed)
    mapped = mapped_spec()
    mapped["schema_version"] = 1
    with pytest.raises(project.ProjectRenderError):
        project.validate_project_spec(mapped)
