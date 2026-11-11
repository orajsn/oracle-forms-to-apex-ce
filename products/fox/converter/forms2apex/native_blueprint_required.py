"""Versioned submit-time required-input adaptation for native prototypes.

The caller must independently authorize each flag against retained Forms source.
This pure renderer neither establishes that authority nor translates Forms
triggers/lifecycle behavior. Database nullability is an independent unchanged fact.
Historical blueprint files and their context hashes remain untouched.
"""
from __future__ import annotations

from copy import deepcopy
import io
from pathlib import Path
import zipfile

from . import native_blueprint as legacy
from . import native_project


PROFILE_ID = "native-blueprint-prototype-required-v1"
SCHEMA_VERSION = 2
INPUT_VALIDATION_POLICY = "forms-required-inputs-v1"
TEMPLATE_ID = "sqlcl-26.1.2-fox-blueprint-prototype-required-v1"
DATA_MODE = legacy.DATA_MODE
MAX_BLOCKS = legacy.MAX_BLOCKS
MAX_FIELDS = legacy.MAX_FIELDS
KEY = legacy.KEY
_pages = legacy._pages
_columns = legacy._columns


def _legacy_projection(spec):
    """Strip only the two known additions, never silently filter unknown keys."""
    result = deepcopy(spec)
    result.pop("input_validation_policy")
    result.update(schema_version=1, profile_id=legacy.PROFILE_ID)
    for block in result["blocks"]:
        for field in block["fields"]:
            field.pop("value_required")
    return result


def validate_prototype_spec(value):
    """Normalize v2 metadata with every historical v1 constraint still applied."""
    legacy._require(type(value) is dict
                    and set(value) == legacy._ROOT | {"input_validation_policy"},
                    "PROTOTYPE_ROOT_FIELDS_INVALID")
    legacy._require(type(value["schema_version"]) is int
                    and value["schema_version"] == SCHEMA_VERSION
                    and value["profile_id"] == PROFILE_ID
                    and value["input_validation_policy"] == INPUT_VALIDATION_POLICY,
                    "PROTOTYPE_PROFILE_INVALID")
    legacy._require(type(value["blocks"]) is list, "PROTOTYPE_BLOCK_COUNT_INVALID")
    for block in value["blocks"]:
        legacy._require(type(block) is dict and set(block) == legacy._BLOCK,
                        "PROTOTYPE_BLOCK_FIELDS_INVALID")
        legacy._require(type(block["fields"]) is list, "PROTOTYPE_FIELD_COUNT_INVALID")
        for field in block["fields"]:
            legacy._require(type(field) is dict and "value_required" in field,
                            "PROTOTYPE_FIELD_FIELDS_INVALID")
            legacy._require(type(field["value_required"]) is bool,
                            "PROTOTYPE_VALUE_REQUIRED_BOOLEAN_INVALID")
    # Deliberately retain every unknown root/block/field key in the projection;
    # the legacy validator must reject it rather than accepting a reduced view.
    normalized = legacy.validate_prototype_spec(_legacy_projection(value))
    flags = {field["source_item_id"]: field["value_required"]
             for block in value["blocks"] for field in block["fields"]}
    for block in normalized["blocks"]:
        for field in block["fields"]:
            required = flags[field["source_item_id"]]
            legacy._require(not required or (
                block["classification"] == "database"
                and block["native_component"] == "form"
                and field["in_edit_form"] and field["widget"] != "display"),
                "PROTOTYPE_VALUE_REQUIRED_TARGET_INVALID")
            field["value_required"] = required
    normalized.update(schema_version=SCHEMA_VERSION, profile_id=PROFILE_ID,
                      input_validation_policy=INPUT_VALIDATION_POLICY)
    return normalized


def render_native_blueprint(value):
    """Wrap v1 output, changing only exact editable-item validation fragments."""
    spec = validate_prototype_spec(value)
    files = legacy.render_native_blueprint(_legacy_projection(spec))
    for block in spec["blocks"]:
        if block["classification"] != "database" or block["native_component"] != "form":
            continue
        pages = _pages(block)
        detail = files[pages["form_file"]]
        for index, (field, column) in enumerate(zip(block["fields"], _columns(block)[1:]), start=2):
            if not field["in_edit_form"]:
                continue
            original = native_project._item(column, index * 10, pages["form_page_id"])
            legacy._require(detail.count(original) == 1,
                            "PROTOTYPE_REQUIRED_ITEM_ANCHOR_CHANGED")
            # Change exactly two complete trusted lines, never labels or other
            # item behavior. False never weakens historical NOT NULL checks.
            adapted = original
            if field["value_required"] and column["nullable"]:
                adapted = native_project._lines(original, {
                    "            template: @/optional-floating": (
                        "            template: @/required-floating", 1),
                    "            valueRequired: false": (
                        "            valueRequired: true", 1)})
            detail = detail.replace(original, adapted, 1)
        files[pages["form_file"]] = detail
    return files


def render_prototype_schema(value):
    """Byte-identical v1 DDL; UI Required never invents database NOT NULL."""
    return legacy.render_prototype_schema(_legacy_projection(validate_prototype_spec(value)))


def context():
    """Bind this physical renderer and the complete unchanged legacy closure."""
    members = {"@legacy-context": legacy.context(),
               "@renderer": Path(__file__).read_text(encoding="utf-8")}
    return {"template_id": TEMPLATE_ID, "sha256": legacy._sha(legacy._canonical(members)),
            "profile_id": PROFILE_ID, "schema_version": SCHEMA_VERSION,
            "input_validation_policy": INPUT_VALIDATION_POLICY, "data_mode": DATA_MODE,
            "max_blocks": MAX_BLOCKS, "max_fields_per_block": MAX_FIELDS,
            "status": "CANDIDATE", "requires_actual_sqlcl_validation": True}


def prototype_trace(value):
    """Expose submit-time UI adaptation separately from all unverified behavior."""
    spec = validate_prototype_spec(value)
    trace = legacy.prototype_trace(_legacy_projection(spec))
    trace.update(schema_version=SCHEMA_VERSION, scope=PROFILE_ID + "-trace",
                 input_validation_policy=INPUT_VALIDATION_POLICY,
                 rendering_spec_sha256=legacy._sha(legacy._canonical(spec)), template=context(),
                 input_validation_source_verified=False)
    for block, traced in zip(spec["blocks"], trace["blocks"]):
        for field, item in zip(block["fields"], traced["items"]):
            item.update(value_required=field["value_required"],
                        ui_validation_adaptation=("submit_time_required_input"
                                                  if field["value_required"] else None))
    trace["assumptions"].append(
        "Required-input flags adapt only native APEX submit-time UI validation on editable database form items; "
        "they never weaken existing required checks or alter database nullability, reproduce Forms trigger/lifecycle behavior, or prove source authority.")
    return trace


def deterministic_prototype_zip(value):
    """Return sorted deterministic UTF-8 project bytes without filesystem writes."""
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        for name, content in render_native_blueprint(value).items():
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system, info.external_attr, info.compress_type = 3, 0o100644 << 16, zipfile.ZIP_STORED
            archive.writestr(info, content.encode("utf-8"))
    return stream.getvalue()
