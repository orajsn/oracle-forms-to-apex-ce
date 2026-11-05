"""Candidate-only native pages for a source-bound, synthetic blueprint prototype.

This independent versioned contract does not widen the historical native profile.
Metadata validation is not evidence of source completeness, review, authority,
SQLcl compatibility, import, runtime correctness or business acceptance.
"""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import re
from string import Template
import zipfile

from . import native, native_contract, native_project


PROFILE_ID = "native-blueprint-prototype-v1"
DATA_MODE = "synthetic_test_only"
TEMPLATE_ID = "sqlcl-26.1.2-fox-blueprint-prototype-v1"
MAX_BLOCKS = 50
MAX_FIELDS = 255
KEY = "FOX_ROW_ID"
ROOT = Path(__file__).parent / "templates" / "blueprint-prototype-v1"
_ROOT = {"schema_version", "profile_id", "data_mode", "project_id", "project_name",
         "source_binding", "blocks"}
_BLOCK = {"source_block_id", "name", "sequence", "classification", "native_component", "table_name", "fields"}
_FIELD = {"source_item_id", "source_name", "name", "label", "data_type", "widget",
          "nullable", "in_edit_form"}
_SOURCE_ID = re.compile(r"ff1-[a-f0-9]{24}\Z")
_SOURCE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_$# .-]{0,255}\Z")
_PROJECT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,179}\Z")
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_TYPES = {"VARCHAR2": "text", "NUMBER": "number", "DATE": "date"}
_SHARED_PAGES = {"pages/p00000-global-page.apx", "pages/p09999-login.apx"}


def _require(condition, code):
    if not condition:
        raise ValueError(code)


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _matches(value, pattern):
    return type(value) is str and pattern.fullmatch(value) is not None


def _label(value):
    try:
        result = native_contract._label(value)
        native._label(result)
    except (TypeError, ValueError):
        raise ValueError("PROTOTYPE_LABEL_INVALID") from None
    return result


def _source_name(value):
    _require(_matches(value, _SOURCE_NAME), "PROTOTYPE_SOURCE_NAME_INVALID")
    # Names are inert identity metadata, but also become escaped page labels.
    native._label(value)
    return value


def _table(project_id, binding, block_id):
    return "FOX_NATIVE_" + _sha(_canonical([project_id, binding, block_id]))[:19].upper()


def _field_name(source_id):
    return "F_" + _sha(source_id.encode("utf-8"))[:24].upper()


def validate_prototype_spec(value):
    """Return an independent normalized copy of strictly bounded inert metadata."""
    _require(type(value) is dict and set(value) == _ROOT, "PROTOTYPE_ROOT_FIELDS_INVALID")
    _require(type(value["schema_version"]) is int and value["schema_version"] == 1
             and value["profile_id"] == PROFILE_ID and value["data_mode"] == DATA_MODE,
             "PROTOTYPE_PROFILE_INVALID")
    _require(_matches(value["project_id"], _PROJECT_ID), "PROTOTYPE_PROJECT_ID_INVALID")
    _require(_matches(value["source_binding"], _SHA), "PROTOTYPE_BINDING_INVALID")
    project_name = _label(value["project_name"])
    _require(type(value["blocks"]) is list and 1 <= len(value["blocks"]) <= MAX_BLOCKS,
             "PROTOTYPE_BLOCK_COUNT_INVALID")
    ids, sequences, tables, items, blocks = set(), set(), set(), set(), []
    for block in value["blocks"]:
        _require(type(block) is dict and set(block) == _BLOCK, "PROTOTYPE_BLOCK_FIELDS_INVALID")
        block_id = block["source_block_id"]
        _require(_matches(block_id, _SOURCE_ID) and block_id not in ids,
                 "PROTOTYPE_BLOCK_ID_INVALID")
        ids.add(block_id)
        sequence = block["sequence"]
        _require(type(sequence) is int and 1 <= sequence <= MAX_BLOCKS and sequence not in sequences,
                 "PROTOTYPE_SEQUENCE_INVALID")
        sequences.add(sequence)
        name = _source_name(block["name"])
        classification = block["classification"]
        _require(type(classification) is str and classification in {"database", "control"},
                 "PROTOTYPE_CLASSIFICATION_INVALID")
        component = block["native_component"]
        _require(type(component) is str and component in
                 ({"form", "report"} if classification == "database" else {"page-items"}),
                 "PROTOTYPE_COMPONENT_INVALID")
        table = block["table_name"]
        if classification == "database":
            _require(table == _table(value["project_id"], value["source_binding"], block_id),
                     "PROTOTYPE_TABLE_BINDING_INVALID")
            native_contract._identifier(table, "Prototype table")
            _require(table not in tables, "PROTOTYPE_TABLE_COLLISION")
            tables.add(table)
        else:
            _require(table is None, "PROTOTYPE_CONTROL_TABLE_INVALID")
        _require(type(block["fields"]) is list and len(block["fields"]) <= MAX_FIELDS,
                 "PROTOTYPE_FIELD_COUNT_INVALID")
        fields, names = [], set()
        for field in block["fields"]:
            _require(type(field) is dict and _FIELD <= set(field) <= _FIELD | {"length"},
                     "PROTOTYPE_FIELD_FIELDS_INVALID")
            item_id = field["source_item_id"]
            _require(_matches(item_id, _SOURCE_ID) and item_id not in items and item_id not in ids,
                     "PROTOTYPE_ITEM_ID_INVALID")
            items.add(item_id)
            source_name = _source_name(field["source_name"])
            field_name = field["name"]
            _require(field_name == _field_name(item_id) and field_name not in names,
                     "PROTOTYPE_FIELD_NAME_INVALID")
            native_contract._identifier(field_name, "Prototype column")
            names.add(field_name)
            data_type, widget = field["data_type"], field["widget"]
            _require(type(data_type) is str and data_type in _TYPES, "PROTOTYPE_TYPE_INVALID")
            _require(type(widget) is str and widget in {_TYPES[data_type], "display"},
                     "PROTOTYPE_WIDGET_INVALID")
            _require(type(field["nullable"]) is bool and type(field["in_edit_form"]) is bool,
                     "PROTOTYPE_BOOLEAN_INVALID")
            _require(widget != "display" or not field["in_edit_form"],
                     "PROTOTYPE_DISPLAY_EDIT_INVALID")
            if classification == "control":
                _require(not field["in_edit_form"], "PROTOTYPE_CONTROL_EDIT_INVALID")
            if component == "report":
                _require(not field["in_edit_form"], "PROTOTYPE_REPORT_EDIT_INVALID")
            result = {key: field[key] for key in _FIELD}
            result.update(source_name=source_name, label=_label(field["label"]))
            if data_type == "VARCHAR2":
                _require(type(field.get("length")) is int and 1 <= field["length"] <= 4000,
                         "PROTOTYPE_LENGTH_INVALID")
                result["length"] = field["length"]
            else:
                _require("length" not in field, "PROTOTYPE_LENGTH_INVALID")
            fields.append(result)
        blocks.append({"source_block_id": block_id, "name": name, "sequence": sequence,
                       "classification": classification, "native_component": component,
                       "table_name": table, "fields": fields})
    _require(not ids.intersection(items), "PROTOTYPE_SOURCE_ID_COLLISION")
    return {"schema_version": 1, "profile_id": PROFILE_ID, "data_mode": DATA_MODE,
            "project_id": value["project_id"], "project_name": project_name,
            "source_binding": value["source_binding"],
            "blocks": sorted(blocks, key=lambda block: block["sequence"])}


def _columns(block):
    return [{"name": KEY, "label": "Synthetic row identity", "data_type": "NUMBER",
             "primary_key": True, "identity": True, "nullable": False}] + [
        {**{key: field[key] for key in ("name", "label", "data_type", "nullable")},
         **({"length": field["length"]} if "length" in field else {}),
         "primary_key": False, "identity": False} for field in block["fields"]]


def _pages(block):
    report = 2 * block["sequence"] - 1
    result = {"page_id": report, "page_alias": f"BLOCK_{block['sequence']}",
              "page_file": f"pages/p{report:05d}-block_{block['sequence']}.apx"}
    if block["classification"] == "database":
        result.update(report_page_id=report, report_alias=result["page_alias"],
                      report_file=result["page_file"])
        if block["native_component"] == "form":
            result.update(form_page_id=report + 1, form_alias=f"EDIT_{block['sequence']}",
                          form_file=f"pages/p{report + 1:05d}-edit_{block['sequence']}.apx")
    return result


def _templates():
    return {path.relative_to(ROOT).as_posix(): path.read_text(encoding="utf-8")
            for path in sorted(ROOT.rglob("*")) if path.is_file()}


def _database_pages(templates, block):
    pages = _pages(block)
    if block["native_component"] == "report":
        return _readonly_report(templates, block, pages)
    # Reuse proven structural parameterization without calling the old validator.
    form = {"form_name": block["name"], "native_form": {"table_name": block["table_name"],
            "columns": _columns(block)}}
    outputs = native_project._module_pages(templates, form, pages)
    columns = _columns(block)
    detail = outputs[pages["form_file"]]
    for index, (field, column) in enumerate(zip(block["fields"], columns[1:]), start=2):
        if not field["in_edit_form"]:
            item = native_project._item(column, index * 10, pages["form_page_id"])
            _require(detail.count(item) == 1, "PROTOTYPE_FORM_ITEM_ANCHOR_CHANGED")
            detail = detail.replace(item, "", 1)
    outputs[pages["form_file"]] = detail
    report = outputs[pages["report_file"]]
    # The key remains defined for edit links, but defaults show ordinary fields.
    for index, column in enumerate(columns, start=1):
        if index == 1 or index > 9:
            display = (f"            displayColumn {column['name']} (\n"
                       f"                sequence: {index * 10}\n            )")
            _require(report.count(display) == 1, "PROTOTYPE_REPORT_COLUMN_ANCHOR_CHANGED")
            report = report.replace(display, "", 1)
    outputs[pages["report_file"]] = report
    return outputs


def _readonly_report(templates, block, pages):
    # Remove complete, exact trusted interaction blocks BEFORE inserting any
    # source labels. A changed template fails closed rather than leaving an
    # accidental edit target or create action in a purported read-only page.
    report = templates["_fragments/report.apx.tmpl"]
    link = """        link {
            linkColumn: customTarget
            target: {
                page: 2
                clearCache: 2
                items: {
                    $KEY_ITEM: "#$KEY#"
                }
            }
            linkIcon: Edit
        }
"""
    create = """    button create (
        buttonName: CREATE
        label: Create Record
        layout {
            sequence: 10
            region: @records
            slot: rightOfInteractiveReportSearchBar
        }
        appearance {
            buttonTemplate: @/text
            hot: true
        }
        behavior {
            action: redirectThisApp
            warnOnUnsavedChanges: doNotCheck
            target: {
                page: 2
                clearCache: 2
            }
        }
    )
"""
    for trusted_block in (link, create):
        _require(report.count(trusted_block) == 1, "PROTOTYPE_READONLY_ANCHOR_CHANGED")
        report = report.replace(trusted_block, "", 1)
    report = native_project._lines(report, {
        "page 1 (": ("page $REPORT_PAGE (", 1),
        "    name: Native Records": ("    name: $DISPLAY_NAME", 1),
        "    alias: HOME": ("    alias: $REPORT_ALIAS", 1),
        "    title: Native Records": ("    title: $DISPLAY_NAME", 1),
        "        name: Native Records": ("        name: $DISPLAY_NAME", 1)})
    columns = _columns(block)
    replacements = {"TABLE": block["table_name"], "REPORT_PAGE": pages["report_page_id"],
                    "REPORT_ALIAS": pages["report_alias"], "DISPLAY_NAME": native._label(block["name"]),
                    "REPORT_COLUMNS": "\n".join(native._report_column(column, (index + 1) * 10)
                                                for index, column in enumerate(columns)),
                    "DISPLAY_COLUMNS": "\n".join(
                        f"            displayColumn {column['name']} (\n                sequence: {(index + 2) * 10}\n            )"
                        for index, column in enumerate(columns[1:9]))}
    return {pages["report_file"]: Template(report).substitute(replacements)}


def _control_item(field, sequence, page):
    # Same typed native primitives as trusted form items, but no table source,
    # automatic DML, submit actions, inferred defaults or executable expressions.
    if field["widget"] == "display":
        # SQLcl 26.1.2 complete-project validation established this narrow
        # source-free native component shape. No source, default, computation,
        # DB binding or validation is invented to populate the display value.
        return (f"    pageItem P{page}_{field['name']} (\n"
                "        type: displayOnly\n"
                "        label {\n"
                f"            label: {native._label(field['label'])}\n"
                "        }\n"
                "        layout {\n"
                f"            sequence: {sequence}\n"
                "            region: @controls\n"
                "            slot: regionBody\n"
                "        }\n"
                "        appearance {\n"
                "            template: @/optional-floating\n"
                "        }\n"
                "    )")
    column = {**field, "primary_key": False}
    item = native_project._item(column, sequence, page)
    source = ("        source {\n            formRegion: @record\n"
              f"            column: {field['name']}\n"
              f"            dataType: {field['data_type'].lower()}\n"
              "            primaryKey: false\n            queryOnly: false\n        }")
    _require(item.count(source) == 1, "PROTOTYPE_CONTROL_SOURCE_ANCHOR_CHANGED")
    item = item.replace(source, "", 1)
    return native_project._lines(item, {"            region: @record": ("            region: @controls", 1)})


def _control_page(templates, block):
    pages = _pages(block)
    items = "\n".join(_control_item(field, (index + 1) * 10, pages["page_id"])
                      for index, field in enumerate(block["fields"]))
    return {pages["page_file"]: Template(templates["control.apx.tmpl"]).substitute(
        PAGE=pages["page_id"], ALIAS=pages["page_alias"], NAME=native._label(block["name"]), ITEMS=items)}


def _navigation(source, blocks, *, breadcrumb=False):
    # Parameterization is over trusted structure only, before inserting labels.
    matches = list(re.finditer(r"^    entry home \(\n.*?^    \)", source, re.M | re.S))
    _require(len(matches) == 1, "PROTOTYPE_NAVIGATION_ANCHOR_CHANGED")
    match = matches[0]
    entries = []
    for block in blocks:
        sequence, pages = block["sequence"], _pages(block)
        rules = {"    entry home (": (f"    entry block-{sequence} (", 1),
                 "            sequence: 10": (f"            sequence: {sequence * 10}", 1),
                 "                page: 1": (f"                page: {pages['page_id']}", 1)}
        if breadcrumb:
            rules.update({"        name: Home": ("        name: $NAME", 1),
                          "        pageNumber: 1": (f"        pageNumber: {pages['page_id']}", 1)})
        else:
            rules["        label: Home"] = ("        label: $NAME", 1)
        entries.append(Template(native_project._lines(match.group(), rules)).substitute(NAME=native._label(block["name"])))
    return source[:match.start()] + "\n\n".join(entries) + source[match.end():]


def render_native_blueprint(value):
    """Render one complete CANDIDATE APEXlang app; validation/import required."""
    spec = validate_prototype_spec(value)
    templates = native._template_files()
    _require({name for name in templates if name.startswith("pages/")} == _SHARED_PAGES,
             "PROTOTYPE_SHARED_TEMPLATE_CHANGED")
    files = {name: content for name, content in templates.items() if not name.startswith("_fragments/")}
    app = native_project._lines(files["application.apx"], {
        "app FOX_NATIVE_DRAFT (": ("app FOX_BLUEPRINT_PROTOTYPE (", 1),
        "    name: FOX Native Forms Draft": ("    name: $PROJECT_NAME", 1),
        "            page: 1": (f"            page: {_pages(spec['blocks'][0])['page_id']}", 1)})
    files["application.apx"] = Template(app).substitute(PROJECT_NAME=native._label(spec["project_name"]))
    files["shared-components/lists.apx"] = _navigation(files["shared-components/lists.apx"], spec["blocks"])
    files["shared-components/breadcrumbs.apx"] = _navigation(files["shared-components/breadcrumbs.apx"], spec["blocks"], breadcrumb=True)
    control_templates = _templates()
    _require(set(control_templates) == {"control.apx.tmpl"}, "PROTOTYPE_CONTROL_TEMPLATE_CHANGED")
    for block in spec["blocks"]:
        pages = (_database_pages(templates, block) if block["classification"] == "database"
                 else _control_page(control_templates, block))
        _require(not set(files).intersection(pages), "PROTOTYPE_OUTPUT_COLLISION")
        files.update(pages)
    return dict(sorted(files.items()))


def render_prototype_schema(value):
    """Return only CREATE TABLE statements, never inferred customer DDL/data."""
    spec = validate_prototype_spec(value)
    statements = ["-- Synthetic test schema only; not supplied or inferred customer DDL.\n"
                  "-- Execute only with separate explicit target authority.\n"]
    for block in spec["blocks"]:
        if block["classification"] != "database":
            continue
        columns = [f"  {KEY} NUMBER GENERATED BY DEFAULT ON NULL AS IDENTITY PRIMARY KEY"]
        for field in block["fields"]:
            kind = field["data_type"] + (f"({field['length']})" if field["data_type"] == "VARCHAR2" else "")
            columns.append(f"  {field['name']} {kind}" + ("" if field["nullable"] else " NOT NULL"))
        statements.append(f"CREATE TABLE {block['table_name']} (\n" + ",\n".join(columns) + "\n);\n")
    return "\n".join(statements)


def context():
    """Bind the new renderer, reused trusted primitives and every template."""
    members = {"@native-context": native.context(), "@control-templates": _templates(),
               "@renderer": Path(__file__).read_text(encoding="utf-8"),
               "@project-primitives": Path(native_project.__file__).read_text(encoding="utf-8"),
               "@metadata-primitives": Path(native_contract.__file__).read_text(encoding="utf-8")}
    return {"template_id": TEMPLATE_ID, "sha256": _sha(_canonical(members)),
            "profile_id": PROFILE_ID, "data_mode": DATA_MODE,
            "max_blocks": MAX_BLOCKS, "max_fields_per_block": MAX_FIELDS,
            "status": "CANDIDATE", "requires_actual_sqlcl_validation": True}


def prototype_trace(value):
    """Return complete item mappings and explicit unverified/prototype limits."""
    spec = validate_prototype_spec(value)
    blocks = []
    for block in spec["blocks"]:
        pages = _pages(block)
        database = block["classification"] == "database"
        editable = block["native_component"] == "form"
        mappings = []
        for index, field in enumerate(block["fields"]):
            rendered = (editable and field["in_edit_form"]) if database else True
            page = pages.get("form_page_id", pages["page_id"])
            mappings.append({"source_item_id": field["source_item_id"], "source_name": field["source_name"],
                             "column": field["name"] if database else None,
                             "report_page_id": pages["page_id"] if database else None,
                             "default_report_visible": database and index < 8,
                             "native_item": f"P{page}_{field['name']}" if rendered else None,
                             "native_item_page_id": page if rendered else None,
                             "widget": field["widget"], "data_type": field["data_type"],
                             "nullable": field["nullable"], "in_edit_form": field["in_edit_form"],
                             "database_bound": database, "legacy_behavior_implemented": False,
                             "value_computation_implemented": False,
                             "disposition": "native_item_candidate" if rendered else
                                 "report_only"})
        limitations = []
        if not block["fields"]:
            limitations.append("No source fields mapped; this block is only a structural prototype candidate.")
        if editable and any(not field["nullable"] and not field["in_edit_form"] for field in block["fields"]):
            limitations.append("Required report-only columns have no inferred defaults; Create may fail until their input policy is reviewed.")
        if not database and any(field["widget"] == "display" for field in block["fields"]):
            limitations.append("Native control display-only items have no inferred value source or translated computation.")
        blocks.append({"source_block_id": block["source_block_id"], "name": block["name"],
                       "sequence": block["sequence"], "classification": block["classification"],
                       "native_component": block["native_component"], "read_only": database and not editable,
                       "table_name": block["table_name"], **pages,
                       "synthetic_key": {"column": KEY, "source_item_id": None,
                                         "source_derived": False,
                                         "hidden_item": f"P{pages['form_page_id']}_{KEY}" if editable else None}
                           if database else None,
                       "items": mappings, "limitations": limitations})
    return {"schema_version": 1, "scope": PROFILE_ID + "-trace", "status": "CANDIDATE",
            "data_mode": DATA_MODE, "project_id": spec["project_id"], "source_binding": spec["source_binding"],
            "rendering_spec_sha256": _sha(_canonical(spec)), "template": context(),
            "application_count": 1, "block_count": len(blocks), "blocks": blocks,
            "assumptions": ["Tables and FOX_ROW_ID are synthetic test objects, not customer-schema facts.",
                            "Only form components receive independent CRUD prototype pages; report components are read-only. No cross-block transaction or relationship is inferred.",
                            "Legacy triggers, buttons, packages, queries, defaults, LOVs and business logic are not executed or converted.",
                            "Display-only database fields are report-only; control display fields use source-free native display-only items, with no inferred value or translated computation.",
                            "Control items are native session-state candidates without persistence or legacy behavior.",
                            "Only the first eight ordinary fields appear in the default report; all report columns are defined."],
            "source_completeness_verified": False, "reviewer_approval_verified": False,
            "execution_authority_verified": False, "sqlcl_validated": False, "imported": False,
            "runtime_verified": False, "business_behavior_verified": False, "human_acceptance_recorded": False}


def deterministic_prototype_zip(value):
    """Return stable UTF-8 APEXlang project bytes without filesystem writes."""
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        for name, content in render_native_blueprint(value).items():
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system, info.external_attr, info.compress_type = 3, 0o100644 << 16, zipfile.ZIP_STORED
            archive.writestr(info, content.encode("utf-8"))
    return stream.getvalue()
