import copy
import hashlib
import json
from pathlib import Path

import pytest

from forms2apex import native


def spec(five=False):
    columns = [
        {"name": "ID", "data_type": "NUMBER", "nullable": False, "label": "ID", "primary_key": True, "identity": True},
        {"name": "TITLE", "data_type": "VARCHAR2", "nullable": False, "label": "Title", "length": 100},
    ]
    if five:
        columns += [
            {"name": "STATUS", "data_type": "VARCHAR2", "nullable": False, "label": "Status", "length": 20},
            {"name": "AMOUNT", "data_type": "NUMBER", "nullable": False, "label": "Amount"},
            {"name": "DUE_DATE", "data_type": "DATE", "nullable": True, "label": "Due Date"},
        ]
    return {"profile_id": "native-table-form-v1", "data_mode": "synthetic_test_only", "table_name": "FOX_NATIVE_261016", "columns": columns}


@pytest.mark.parametrize("five,count", [(False, 2), (True, 5)])
def test_native_pages_and_authentication(five, count):
    input_spec = spec(five)
    before = copy.deepcopy(input_spec)
    files = native.render_native_form(input_spec)
    assert input_spec == before
    report = files["pages/p00001-home.apx"]
    form = files["pages/p00002-record.apx"]
    assert "type: interactiveReport" in report
    assert "type: form\n" in form
    assert report.count("        column ") == count
    assert report.count("            displayColumn ") == count
    assert form.count("    pageItem ") == count
    assert "dataType: STRING" in report
    assert "dataType: NUMBER" in report
    assert "dataType: varchar2" in form
    assert "type: formInitialization" in form
    assert "type: formAutoRowProcessing" in form
    assert "preventLostUpdates: true" in form
    region=form.split('    region record (',1)[1].split('    pageItem ',1)[0]
    assert 'lostUpdateType: rowValues' in region
    assert 'enabled: true' in region
    assert 'allowedOperations: [\n                    add\n                    update\n                ]' in region
    assert 'delete' not in region
    assert "databaseAction: insert" in form
    assert "databaseAction: update" in form
    assert "databaseAction: delete" not in form
    assert report.count("warnOnUnsavedChanges: doNotCheck") == 1
    assert form.count("warnOnUnsavedChanges: doNotCheck") == 3
    assert "warnOnUnsavedChanges: false" not in report + form
    assert "type: selectList" not in form
    assert "        default {" not in form
    assert "htmlCode:" not in report + form
    assert "javaScriptCode:" not in report + form
    assert "plsqlCode:" not in report + form
    assert all(not key.startswith("_fragments/") for key in files)
    assert "type: oracleApexAccounts" in files["shared-components/authentications.apx"]
    starter = Path(native.__file__).parent / "templates" / "starter"
    for path in ("shared-components/authentications.apx", "pages/p09999-login.apx", ".apex/apexlang.json"):
        assert files[path].rstrip() == (starter / path).read_text(encoding="utf-8").rstrip()
    if five:
        assert "type: datePicker" in form
        assert "type: numberField" in form
        assert "dataType: DATE" in report
        assert "maxLength: 20" in form


def test_renamed_primary_key_and_metadata_consistently_render():
    value = spec()
    value["table_name"] = "FOX_NATIVE_CASES"
    value["columns"][0]["name"] = "CASE_ID"
    value["columns"][1]["name"] = "SUBJECT"
    files = native.render_native_form(value)
    report = files["pages/p00001-home.apx"]
    form = files["pages/p00002-record.apx"]
    assert 'P2_CASE_ID: "#CASE_ID#"' in report
    assert "pageItem P2_CASE_ID (" in form
    assert form.count("item: P2_CASE_ID") == 2
    assert "P2_ID" not in report + form
    assert "FOX_NATIVE_261016" not in report + form
    assert "FOX_NATIVE_CASES" in report and "FOX_NATIVE_CASES" in form
    assert "pageItem P2_SUBJECT (" in form


def test_labels_are_quoted_and_escaped_not_interpolated():
    value = spec()
    value["columns"][1]["label"] = 'Customer "title" \\ path'
    encoded = json.dumps(value["columns"][1]["label"], ensure_ascii=False)
    files = native.render_native_form(value)
    assert "heading: " + encoded in files["pages/p00001-home.apx"]
    assert "label: " + encoded in files["pages/p00002-record.apx"]


@pytest.mark.parametrize("bad", ["<script>alert(1)</script>", "Title\nprocess evil (", "&APP_USER.", "```html", "select password from secret"])
def test_unsafe_labels_rejected(bad):
    value = spec()
    value["columns"][1]["label"] = bad
    with pytest.raises(ValueError):
        native.render_native_form(value)


@pytest.mark.parametrize("key,value", [("table_name", "OTHER_TABLE"), ("table_name", "FOX_NATIVE_X; DROP TABLE X"), ("data_mode", "production"), ("sql", "select * from dual")])
def test_unsafe_spec_rejected(key, value):
    candidate = spec()
    candidate[key] = value
    with pytest.raises(ValueError):
        native.render_native_form(candidate)


def test_context_fingerprint_covers_templates_and_renderer():
    first = native.context()
    assert first == native.context()
    assert first["template_id"] == "sqlcl-26.1.2-fox-native-v1"
    assert len(first["sha256"]) == 64
    digest = hashlib.sha256()
    files = native._template_files()
    files["@renderer/native.py"] = Path(native.__file__).read_text(encoding="utf-8")
    for path, content in sorted(files.items()):
        for value in (path, content):
            encoded = value.encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
    assert first["sha256"] == digest.hexdigest()


def test_deterministic_output_has_no_unexpanded_template_tokens():
    first = native.render_native_form(spec(True))
    assert first == native.render_native_form(spec(True))
    assert "$TABLE" not in "".join(first.values())
    assert "$KEY" not in "".join(first.values())


def test_context_digest_changes_when_trusted_templates_change(monkeypatch):
    original = native.context()["sha256"]
    changed = native._template_files()
    changed["application.apx"] += "\n// changed trusted template\n"
    monkeypatch.setattr(native, "_template_files", lambda: changed.copy())
    assert native.context()["sha256"] != original
