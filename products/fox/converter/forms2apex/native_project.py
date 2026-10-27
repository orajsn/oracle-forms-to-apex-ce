"""Deterministic composition of supported Forms metadata into one APEXlang app.

The caller must bind this rendering spec to the complete READY source plan and
independent review. This module validates every listed form, but a supplied hash
alone cannot establish source completeness, reviewer approval or execution.
Rendered files still require SQLcl validation, target import and runtime tests.
No database, model, filesystem write or user-authored code is executed here.
"""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
from string import Template
import unicodedata
import zipfile

from fox_source_contract import project_conversion as source_contract

from . import native, native_contract, native_schema


PROFILE_ID = "native-project-v1"
TEMPLATE_ID = "sqlcl-26.1.2-fox-project-v1"
MAX_FORMS = 50
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_MODULE = re.compile(r"form-[a-f0-9]{20}\Z")
_ROOT_FIELDS = {"schema_version", "profile_id", "data_mode", "project_name",
                "source_manifest_sha256", "forms"}
_FORM_FIELDS = {"module_id", "form_name", "source_name", "source_sha256", "native_form"}
_ROOT_FIELDS_V2 = _ROOT_FIELDS | {"project_id"}
_FORM_FIELDS_V2 = _FORM_FIELDS | {"ddl_sources", "storage_mapping"}
_SHARED_PAGES = {"pages/p00000-global-page.apx", "pages/p09999-login.apx"}


class ProjectRenderError(ValueError):
    """Stable diagnostic with an optional already-validated form identity."""

    def __init__(self, code: str, module_id: str | None = None):
        super().__init__(code)
        self.code = code
        self.module_id = module_id


def _require(condition, code, module_id=None):
    if not condition:
        raise ProjectRenderError(code, module_id)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _display(value, code, module_id=None):
    try:
        # Reuse the same conservative display-text contract as native fields.
        result = native_contract._label(value)
        native._label(result)  # Also excludes APEX substitution expressions.
    except (TypeError, ValueError):
        raise ProjectRenderError(code, module_id) from None
    return result


def schema_contract(spec):
    """Return the shared native table contract without per-form display labels."""
    normalized = native_contract.validate_native_spec(spec)
    return {"profile_id": normalized["profile_id"], "data_mode": normalized["data_mode"],
            "table_name": normalized["table_name"], "supported_operations": normalized["supported_operations"],
            "columns": [{key: value for key, value in column.items() if key != "label"}
                        for column in normalized["columns"]]}


def validate_project_spec(value):
    """Normalize a complete render input without changing the caller's value.

    A file may contain multiple distinct FormModules. Such forms must carry the
    same source digest for that filename. Input order cannot change page IDs:
    modules are allocated in stable module-ID order, not inferred business order.
    """
    _require(type(value) is dict, "PROJECT_METADATA_FIELDS_INVALID")
    version = value.get("schema_version")
    _require(type(version) is int and version in {1, 2}, "PROJECT_PROFILE_INVALID")
    _require(set(value) == (_ROOT_FIELDS if version == 1 else _ROOT_FIELDS_V2),
             "PROJECT_METADATA_FIELDS_INVALID")
    _require(value["profile_id"] == PROFILE_ID
             and value["data_mode"] == "synthetic_test_only",
             "PROJECT_PROFILE_INVALID")
    _require(type(value["source_manifest_sha256"]) is str
             and _SHA.fullmatch(value["source_manifest_sha256"]), "PROJECT_SOURCE_HASH_INVALID")
    project_name = _display(value["project_name"], "PROJECT_NAME_INVALID")
    forms = value["forms"]
    _require(type(forms) is list and 1 <= len(forms) <= MAX_FORMS, "PROJECT_FORM_COUNT_INVALID")
    ids, names, sources, schemas, normalized = set(), set(), {}, {}, []
    for form in forms:
        _require(type(form) is dict and set(form) == (_FORM_FIELDS if version == 1 else _FORM_FIELDS_V2),
                 "PROJECT_FORM_FIELDS_INVALID")
        module = form["module_id"]
        _require(type(module) is str and _MODULE.fullmatch(module), "PROJECT_MODULE_ID_INVALID")
        _require(module not in ids, "PROJECT_DUPLICATE_MODULE_ID", module)
        ids.add(module)
        name = _display(form["form_name"], "PROJECT_FORM_NAME_INVALID", module)
        name_key = unicodedata.normalize("NFC", name).casefold()
        _require(name_key not in names, "PROJECT_DUPLICATE_FORM_NAME", module)
        names.add(name_key)
        source, source_hash = form["source_name"], form["source_sha256"]
        _require(type(source) is str and 1 <= len(source) <= 180
                 and not any(token in source for token in ("/", "\\", ":", ".."))
                 and not any(ord(char) < 32 for char in source)
                 and PurePosixPath(source).suffix.lower() == ".xml", "PROJECT_SOURCE_NAME_INVALID", module)
        _require(type(source_hash) is str and _SHA.fullmatch(source_hash), "PROJECT_FORM_SOURCE_HASH_INVALID", module)
        source_key = source.casefold()
        _require(source_key not in sources or sources[source_key] == (source, source_hash),
                 "PROJECT_SOURCE_IDENTITY_CONFLICT", module)
        sources[source_key] = (source, source_hash)
        try:
            spec = native_contract.validate_native_spec(form["native_form"])
            for column in spec["columns"]:
                native._label(column["label"])
            contract = schema_contract(spec)
        except (TypeError, ValueError):
            raise ProjectRenderError("PROJECT_NATIVE_FORM_INVALID", module) from None
        table = spec["table_name"]
        _require(table not in schemas or schemas[table] == contract, "PROJECT_SHARED_TABLE_CONFLICT", module)
        schemas[table] = contract
        normalized.append({"module_id": module, "form_name": name, "source_name": source,
                           "source_sha256": source_hash, "native_form": spec})
        if version == 2:
            # Deep, recomputed validation is performed for the complete set
            # below, including full/truncated identity and shared-table clashes.
            normalized[-1].update(ddl_sources=form["ddl_sources"], storage_mapping=form["storage_mapping"])
    if version == 2:
        try:
            mappings = source_contract.validate_project_storage_mappings(normalized, project_id=value["project_id"])
        except (TypeError, ValueError):
            raise ProjectRenderError("PROJECT_STORAGE_MAPPING_INVALID") from None
        for form, mapping in zip(normalized, mappings):
            form["storage_mapping"] = mapping
            form["ddl_sources"] = [dict(reference) for reference in form["ddl_sources"]]
            for reference in form["ddl_sources"]:
                key = reference["name"].casefold()
                identity = (reference["name"], reference["sha256"])
                _require(key not in sources or sources[key] == identity,
                         "PROJECT_DDL_SOURCE_IDENTITY_CONFLICT", form["module_id"])
                sources[key] = identity
    result = {"schema_version": version, "profile_id": PROFILE_ID, "data_mode": "synthetic_test_only",
            "project_name": project_name, "source_manifest_sha256": value["source_manifest_sha256"],
            "forms": sorted(normalized, key=lambda form: form["module_id"])}
    if version == 2:
        result["project_id"] = value["project_id"]
    return result


def _pages(index):
    report, form = 2 * index + 1, 2 * index + 2
    _require(report > 0 and form < 9999, "PROJECT_PAGE_ALLOCATION_INVALID")
    report_alias, form_alias = f"FORM_{index + 1}", f"EDIT_{index + 1}"
    return {"report_page_id": report, "form_page_id": form,
            "report_alias": report_alias, "form_alias": form_alias,
            "report_file": f"pages/p{report:05d}-{report_alias.lower()}.apx",
            "form_file": f"pages/p{form:05d}-{form_alias.lower()}.apx"}


def _lines(source, rules):
    """Change exact trusted structural lines before inserting any metadata."""
    lines = source.splitlines()
    for old, (new, expected_count) in rules.items():
        _require(lines.count(old) == expected_count, "PROJECT_TEMPLATE_ANCHOR_CHANGED")
        lines = [new if line == old else line for line in lines]
    return "\n".join(lines) + ("\n" if source.endswith("\n") else "")


def _item(column, sequence, page):
    lines = native._form_item(column, sequence).splitlines()
    _require(lines[0] == f"    pageItem P2_{column['name']} (", "PROJECT_ITEM_TEMPLATE_CHANGED")
    lines[0] = f"    pageItem P{page}_{column['name']} ("
    return "\n".join(lines)


def _module_pages(templates, form, pages):
    # Fragment parameterization precedes Template substitution. Labels such as
    # 'P2_ID', 'page: 2', HOME or @record are consequently never rewritten.
    report = _lines(templates["_fragments/report.apx.tmpl"], {
        "page 1 (": ("page $REPORT_PAGE (", 1),
        "    name: Native Records": ("    name: $DISPLAY_NAME", 1),
        "    alias: HOME": ("    alias: $REPORT_ALIAS", 1),
        "    title: Native Records": ("    title: $DISPLAY_NAME", 1),
        "        name: Native Records": ("        name: $DISPLAY_NAME", 1),
        "                page: 2": ("                page: $FORM_PAGE", 2),
        "                clearCache: 2": ("                clearCache: $FORM_PAGE", 2),
    })
    detail = _lines(templates["_fragments/form.apx.tmpl"], {
        "page 2 (": ("page $FORM_PAGE (", 1),
        "    name: Native Record": ("    name: $DISPLAY_NAME", 1),
        "    alias: RECORD": ("    alias: $FORM_ALIAS", 1),
        "    title: Native Record": ("    title: $DISPLAY_NAME", 1),
        "                page: 1": ("                page: $REPORT_PAGE", 2),
        "                clearCache: 2": ("                clearCache: $FORM_PAGE", 2),
    })
    spec = form["native_form"]
    columns = spec["columns"]
    key = next(column["name"] for column in columns if column["primary_key"])
    replacements = {"TABLE": spec["table_name"], "KEY": key,
        "KEY_ITEM": f"P{pages['form_page_id']}_{key}",
        "REPORT_PAGE": pages["report_page_id"], "FORM_PAGE": pages["form_page_id"],
        "REPORT_ALIAS": pages["report_alias"], "FORM_ALIAS": pages["form_alias"],
        "DISPLAY_NAME": native._label(form["form_name"]),
        "REPORT_COLUMNS": "\n".join(native._report_column(column, (i + 1) * 10)
                                     for i, column in enumerate(columns)),
        "DISPLAY_COLUMNS": "\n".join(
            f"            displayColumn {column['name']} (\n                sequence: {(i + 1) * 10}\n            )"
            for i, column in enumerate(columns)),
        "FORM_ITEMS": "\n".join(_item(column, (i + 1) * 10, pages["form_page_id"])
                                  for i, column in enumerate(columns)),
    }
    return {pages["report_file"]: Template(report).substitute(replacements),
            pages["form_file"]: Template(detail).substitute(replacements)}


def _entries(source, forms, *, breadcrumb=False):
    matches = list(re.finditer(r"^    entry home \(\n.*?^    \)", source, re.M | re.S))
    _require(len(matches) == 1, "PROJECT_NAVIGATION_TEMPLATE_CHANGED")
    match = matches[0]
    original = match.group()
    generated = []
    for index, form in enumerate(forms):
        page = _pages(index)["report_page_id"]
        rules = {
            "    entry home (": (f"    entry form-{index + 1} (", 1),
            "            sequence: 10": (f"            sequence: {(index + 1) * 10}", 1),
            "                page: 1": (f"                page: {page}", 1),
        }
        if breadcrumb:
            rules.update({"        name: Home": ("        name: $DISPLAY_NAME", 1),
                          "        pageNumber: 1": (f"        pageNumber: {page}", 1)})
        else:
            rules["        label: Home"] = ("        label: $DISPLAY_NAME", 1)
        generated.append(Template(_lines(original, rules)).substitute(DISPLAY_NAME=native._label(form["form_name"])))
    return source[:match.start()] + "\n\n".join(generated) + source[match.end():]


def render_native_project(value):
    """Return ONE complete application file map; no partial output on failure."""
    project = validate_project_spec(value)
    templates = native._template_files()
    _require({name for name in templates if name.startswith("pages/")} == _SHARED_PAGES,
             "PROJECT_SHARED_PAGE_TEMPLATE_CHANGED")
    files = {name: content for name, content in templates.items() if not name.startswith("_fragments/")}
    app = _lines(files["application.apx"], {
        "app FOX_NATIVE_DRAFT (": ("app FOX_PROJECT_DRAFT (", 1),
        "    name: FOX Native Forms Draft": ("    name: $PROJECT_NAME", 1),
    })
    files["application.apx"] = Template(app).substitute(PROJECT_NAME=native._label(project["project_name"]))
    files["shared-components/lists.apx"] = _entries(files["shared-components/lists.apx"], project["forms"])
    files["shared-components/breadcrumbs.apx"] = _entries(
        files["shared-components/breadcrumbs.apx"], project["forms"], breadcrumb=True)
    for index, form in enumerate(project["forms"]):
        pages = _module_pages(templates, form, _pages(index))
        _require(not set(files).intersection(pages), "PROJECT_OUTPUT_COLLISION")
        files.update(pages)
    return dict(sorted(files.items()))


def render_project_schema(value):
    """Render one create-only synthetic DDL script, deduplicating shared tables."""
    project = validate_project_spec(value)
    tables = {form["native_form"]["table_name"]: form["native_form"] for form in project["forms"]}
    return "\n".join(native_schema.render_native_schema(tables[name]) for name in sorted(tables))


def context():
    """Bind project rendering and metadata/schema rules to the trusted template."""
    members = {"@native-context": native.context(),
               "@renderer/native_project.py": Path(__file__).read_text(encoding="utf-8"),
               "@contract/native_contract.py": Path(native_contract.__file__).read_text(encoding="utf-8"),
               "@schema/native_schema.py": Path(native_schema.__file__).read_text(encoding="utf-8")}
    return {"template_id": TEMPLATE_ID, "sha256": _sha(_canonical(members)),
            "profile_id": PROFILE_ID, "data_mode": "synthetic_test_only", "max_forms": MAX_FORMS,
            "navigation_policy": "stable_module_id_order_not_inferred_business_flow",
            "home_policy": "first_report_not_a_business_start_claim"}


def project_trace(value):
    """Describe the exact supplied form/page/item mapping, not an execution proof."""
    project = validate_project_spec(value)
    forms, tables = [], {}
    for index, form in enumerate(project["forms"]):
        spec, pages = form["native_form"], _pages(index)
        contract = schema_contract(spec)
        contract_hash = _sha(_canonical(contract))
        tables.setdefault(spec["table_name"], {"table_name": spec["table_name"],
            "schema_contract_sha256": contract_hash,
            "schema_sql_sha256": _sha(native_schema.render_native_schema(spec).encode("utf-8")),
            "module_ids": []})["module_ids"].append(form["module_id"])
        forms.append({key: form[key] for key in ("module_id", "form_name", "source_name", "source_sha256")} | {
            **pages, "table_name": spec["table_name"], "schema_contract_sha256": contract_hash,
            "native_spec_sha256": _sha(_canonical(spec)),
            "items": [{"column": column["name"], "item": f"P{pages['form_page_id']}_{column['name']}"}
                      for column in spec["columns"]]})
        if project["schema_version"] == 2:
            forms[-1].update(storage_mapping=form["storage_mapping"], ddl_sources=form["ddl_sources"])
            table = tables[spec["table_name"]]
            table["storage_mapping"] = form["storage_mapping"]
            references = {reference["name"]: reference for reference in table.get("ddl_sources", [])}
            references.update({reference["name"]: reference for reference in form["ddl_sources"]})
            table["ddl_sources"] = [references[name] for name in sorted(references)]
    version = project["schema_version"]
    result = {"schema_version": version, "scope": f"fox-native-project-render-trace-v{version}",
            "project_name": project["project_name"], "source_manifest_sha256": project["source_manifest_sha256"],
            "rendering_spec_sha256": _sha(_canonical(project)), "template": context(),
            "application_count": 1, "form_count": len(forms), "forms": forms,
            "tables": [tables[name] for name in sorted(tables)],
            "source_completeness_verified": False, "reviewer_approval_verified": False,
            "sqlcl_validated": False, "imported": False, "runtime_verified": False,
            "human_acceptance_recorded": False}
    if version == 2:
        result["project_id"] = project["project_id"]
    return result


def deterministic_project_zip(value):
    """Return a stable APEXlang archive; no clocks, paths or permission inputs."""
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        for name, content in render_native_project(value).items():
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, content.encode("utf-8"))
    return stream.getvalue()
