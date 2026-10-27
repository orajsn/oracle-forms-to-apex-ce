"""Deterministic native APEX table forms from the narrow synthetic contract.

No model-authored HTML, JavaScript, SQL, PL/SQL, or APEXlang is accepted here.
The rendering result still requires SQLcl validation and an actual compatible
APEX import/runtime test; this function does not prove database compatibility.
"""

import hashlib
import json
import re
from pathlib import Path
from string import Template

from .native_contract import validate_native_spec


ROOT = Path(__file__).parent / "templates" / "native-table-v1"
TEMPLATE_ID = "sqlcl-26.1.2-fox-native-v1"
_ITEM_TYPES = {"VARCHAR2": "textField", "NUMBER": "numberField", "DATE": "datePicker"}
# IR dataType is free text passed to the worksheet constraint, not the item enum.
_REPORT_TYPES = {"VARCHAR2": "STRING", "NUMBER": "NUMBER", "DATE": "DATE"}
_APEX_SUBSTITUTION = re.compile(r"&(?:[A-Za-z0-9_$#]+)\.")


def _label(value):
    if _APEX_SUBSTITUTION.search(value):
        raise ValueError("Native labels must not contain APEX substitution strings")
    return json.dumps(value, ensure_ascii=False)


def _template_files():
    return {
        path.relative_to(ROOT).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(ROOT.rglob("*")) if path.is_file()
    }


def context():
    """Return a digest bound to every trusted template and this renderer source."""
    digest = hashlib.sha256()
    files = _template_files()
    files["@renderer/native.py"] = Path(__file__).read_text(encoding="utf-8")
    for path, content in sorted(files.items()):
        for value in (path, content):
            encoded = value.encode("utf-8")
            digest.update(len(encoded).to_bytes(8, "big"))
            digest.update(encoded)
    return {
        "template_id": TEMPLATE_ID,
        "sha256": digest.hexdigest(),
        "profile_id": "native-table-form-v1",
        "data_mode": "synthetic_test_only",
        "supported_operations": ["query", "insert", "update"],
        "policy": "Return reviewed field metadata only. Native report/form pages are rendered deterministically; SQLcl validation, import and runtime verification remain required. No custom code, inferred LOVs, defaults or business logic are supported.",
    }


def _report_column(column, sequence):
    lines = [
        f"        column {column['name']} (",
        "            type: plainText",
        "            heading {",
        f"                heading: {_label(column['label'])}",
        "            }",
        "            layout {",
        f"                sequence: {sequence}",
        "            }",
        "            source {",
        f"                dataType: {_REPORT_TYPES[column['data_type']]}",
        "            }",
        "            security {",
        "                escapeSpecialChars: true",
        "            }",
    ]
    if column["data_type"] == "DATE":
        lines.extend(["            appearance {", "                formatMask: YYYY-MM-DD", "            }"])
    return "\n".join(lines + ["        )"])


def _form_item(column, sequence):
    key = column["primary_key"]
    required = not column["nullable"]
    item_type = "hidden" if key else _ITEM_TYPES[column["data_type"]]
    lines = [f"    pageItem P2_{column['name']} (", f"        type: {item_type}"]
    if not key:
        lines.extend(["        label {", f"            label: {_label(column['label'])}", "        }"])
    lines.extend([
        "        layout {",
        f"            sequence: {sequence}",
        "            region: @record",
        "            slot: regionBody",
        "        }",
    ])
    if not key:
        lines.extend([
            "        appearance {",
            f"            template: @/{'required' if required else 'optional'}-floating",
        ])
        if column["data_type"] == "DATE":
            lines.append("            formatMask: YYYY-MM-DD")
        lines.extend(["        }", "        validation {", f"            valueRequired: {str(required).lower()}"])
        if column["data_type"] == "VARCHAR2":
            lines.append(f"            maxLength: {column['length']}")
        lines.append("        }")
    lines.extend([
        "        source {",
        "            formRegion: @record",
        f"            column: {column['name']}",
        f"            dataType: {column['data_type'].lower()}",
        f"            primaryKey: {str(key).lower()}",
        f"            queryOnly: {str(key).lower()}",
        "        }",
    ])
    if key:
        lines.extend(["        security {", "            sessionStateProtection: checksumRequiredSessionLevel", "        }"])
    return "\n".join(lines + ["    )"])


def render_native_form(spec):
    """Return complete trusted APEXlang project files for validated metadata."""
    normalized = validate_native_spec(spec)
    columns = normalized["columns"]
    # Validate every label before rendering, including the hidden key label.
    for column in columns:
        _label(column["label"])
    key = next(column["name"] for column in columns if column["primary_key"])
    templates = _template_files()
    replacements = {
        "TABLE": normalized["table_name"],
        "KEY": key,
        "KEY_ITEM": f"P2_{key}",
        "REPORT_COLUMNS": "\n".join(_report_column(column, (index + 1) * 10) for index, column in enumerate(columns)),
        "DISPLAY_COLUMNS": "\n".join(
            f"            displayColumn {column['name']} (\n                sequence: {(index + 1) * 10}\n            )"
            for index, column in enumerate(columns)
        ),
        "FORM_ITEMS": "\n".join(_form_item(column, (index + 1) * 10) for index, column in enumerate(columns)),
    }
    files = {path: content for path, content in templates.items() if not path.startswith("_fragments/")}
    files["pages/p00001-home.apx"] = Template(templates["_fragments/report.apx.tmpl"]).substitute(replacements)
    files["pages/p00002-record.apx"] = Template(templates["_fragments/form.apx.tmpl"]).substitute(replacements)
    return dict(sorted(files.items()))
