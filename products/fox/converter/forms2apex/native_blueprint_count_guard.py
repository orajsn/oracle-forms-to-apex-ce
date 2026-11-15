"""Opt-in isolated check action over persisted synthetic rows, never approval.

This versioned wrapper leaves prior profiles and their output unchanged. Source
authority must be recomputed with validate_source_binding at the gateway; pure
rendering alone establishes neither source provenance nor consent nor SQLcl,
import, runtime or business acceptance. No source SQL/PLSQL is interpolated.
"""
from __future__ import annotations

from copy import deepcopy
import io
from pathlib import Path
import re
import zipfile

from . import forms_count_guard as source_guard
from . import native_blueprint as legacy
from . import native_blueprint_required as required


PROFILE_ID = "native-blueprint-prototype-count-guard-v1"
SCHEMA_VERSION = 3
TEMPLATE_ID = "sqlcl-26.1.2-fox-count-guard-v1"
POLICY_ID = source_guard.PROFILE_ID
SCOPE = "isolated_pre_action_validation_only"
DATA_MODE = required.DATA_MODE
INPUT_VALIDATION_POLICY = required.INPUT_VALIDATION_POLICY
KEY = required.KEY
MAX_BLOCKS, MAX_FIELDS = required.MAX_BLOCKS, required.MAX_FIELDS
REQUEST = "FOX_COUNT_GUARD_CHECK"
_pages, _columns = required._pages, required._columns
_HASHES = {"source_xml_sha256", "source_trigger_sha256", "source_prefix_sha256",
           "source_remainder_sha256", "source_rule_sha256"}
_ROLES = {"module", "owner_block", "button", "trigger", "detail_block", "value_item",
          "key_item", "bind_block", "bind_item"}
_GUARD = _HASHES | {"policy_id", "scope", "source_selector", "source_objects", "partial_scope_consent"}
_SELECTOR = {"module", "block", "item", "event"}
_SOURCE_ID = re.compile(r"ff1-[a-f0-9]{24}\Z")
_SHA = re.compile(r"[a-f0-9]{64}\Z")
# Oracle-owned real APEX 26.1 exports, pinned rather than floating examples.
SPECIMEN_COMMIT = "0779f030fdee393ee418a3a76f6a4b09bf1408db"
SPECIMENS = {
    "boolean_validation": "https://github.com/oracle/skills/blob/" + SPECIMEN_COMMIT +
        "/apex/apexlang/26.1/apexlang-example-applications/assets/example-1/pages/p10042-user-access.apx#L305-L336",
    "scoped_success_process": "https://github.com/oracle/skills/blob/" + SPECIMEN_COMMIT +
        "/apex/apexlang/26.1/apexlang-example-applications/assets/example-1/pages/p10050-feedback.apx#L252-L279",
}
FAILURE = "Check blocked: a matching persisted row has a null or zero value. No approval was performed."
SUCCESS = "Null/zero check passed for persisted matching rows only. No approval was performed."


def _need(condition, code):
    legacy._require(condition, "COUNT_GUARD_NATIVE_" + code)


def _required_projection(spec):
    result = deepcopy(spec)
    result.pop("count_guard")
    result.update(schema_version=required.SCHEMA_VERSION, profile_id=required.PROFILE_ID)
    return result


def _guard_metadata(rule):
    return {"policy_id": POLICY_ID, "scope": SCOPE, "partial_scope_consent": True,
            "source_xml_sha256": rule["source"]["xml_sha256"],
            "source_trigger_sha256": rule["source"]["trigger_sha256"],
            "source_prefix_sha256": rule["source"]["prefix_sha256"],
            "source_remainder_sha256": rule["unsupported_remainder"]["sha256"],
            "source_rule_sha256": legacy._sha(legacy._canonical(rule)),
            "source_selector": {key: rule["source"][key] for key in _SELECTOR},
            "source_objects": {key: rule["source_objects"][key]["id"] for key in _ROLES}}


def with_count_guard(base_spec, source_bytes, *, source_sha256, module, block, item,
                     partial_scope_consent):
    """Bind an already source-authorized v2 plan to one freshly extracted guard.

    The boolean is a required creation-time assertion, not proof that human
    consent was obtained. The owning gateway must bind actual approval and the
    complete project source_binding independently, as with existing profiles.
    """
    _need(partial_scope_consent is True, "EXPLICIT_PARTIAL_CONSENT_REQUIRED")
    base = required.validate_prototype_spec(base_spec)
    rule = source_guard.extract_count_guard(source_bytes, source_sha256=source_sha256,
                                            module=module, block=block, item=item)
    base.update(schema_version=SCHEMA_VERSION, profile_id=PROFILE_ID, count_guard=_guard_metadata(rule))
    return validate_source_binding(base, source_bytes)


def _targets(spec):
    ids = spec["count_guard"]["source_objects"]
    blocks = {block["source_block_id"]: block for block in spec["blocks"]}
    _need(all(ids[role] in blocks for role in ("owner_block", "detail_block", "bind_block")),
          "SOURCE_BLOCK_NOT_MAPPED")
    owner, detail, bind = (blocks[ids[role]] for role in ("owner_block", "detail_block", "bind_block"))
    _need(owner["source_block_id"] == bind["source_block_id"], "CROSS_BLOCK_BIND_UNSUPPORTED")
    _need(owner["source_block_id"] != detail["source_block_id"], "DISTINCT_DETAIL_BLOCK_REQUIRED")
    _need(owner["classification"] == detail["classification"] == "database", "DATABASE_BLOCK_REQUIRED")
    fields = {}
    for role, block in (("value_item", detail), ("key_item", detail), ("bind_item", bind)):
        matches = [field for field in block["fields"] if field["source_item_id"] == ids[role]]
        _need(len(matches) == 1, "SOURCE_FIELD_NOT_MAPPED")
        fields[role] = matches[0]
    _need(fields["value_item"]["data_type"] == "NUMBER", "NUMERIC_VALUE_REQUIRED")
    key, binding = fields["key_item"], fields["bind_item"]
    _need(key["data_type"] == binding["data_type"] and key["data_type"] in {"VARCHAR2", "NUMBER"},
          "KEY_TYPE_MISMATCH")
    _need(key["source_item_id"] != fields["value_item"]["source_item_id"], "DISTINCT_COLUMNS_REQUIRED")
    page = _pages(owner)["report_page_id"]
    return {"page_id": page, "page_file": _pages(owner)["report_file"],
            "key_item": f"P{page}_FOX_COUNT_GUARD_KEY", "key_type": binding["data_type"],
            "key_length": binding.get("length"), "key_label": binding["label"],
            "owner_block": owner, "detail_block": detail,
            "value_column": fields["value_item"]["name"], "key_column": key["name"],
            "table_name": detail["table_name"]}


def validate_prototype_spec(value):
    """Closed inert v3 contract; source authenticity is a separate exact check."""
    _need(type(value) is dict and set(value) == legacy._ROOT | {"input_validation_policy", "count_guard"},
          "ROOT_FIELDS_INVALID")
    _need(type(value["schema_version"]) is int and value["schema_version"] == SCHEMA_VERSION
          and value["profile_id"] == PROFILE_ID, "PROFILE_INVALID")
    guard = value["count_guard"]
    _need(type(guard) is dict and set(guard) == _GUARD, "GUARD_FIELDS_INVALID")
    _need(guard["policy_id"] == POLICY_ID and guard["scope"] == SCOPE
          and guard["partial_scope_consent"] is True, "ISOLATED_SCOPE_CONSENT_REQUIRED")
    _need(all(type(guard[key]) is str and _SHA.fullmatch(guard[key]) for key in _HASHES),
          "SOURCE_HASH_INVALID")
    selector = guard["source_selector"]
    _need(type(selector) is dict and set(selector) == _SELECTOR
          and selector["event"] == "WHEN-BUTTON-PRESSED", "SOURCE_SELECTOR_INVALID")
    for key in ("module", "block", "item"):
        source_guard._identifier(selector[key])
    objects = guard["source_objects"]
    _need(type(objects) is dict and set(objects) == _ROLES
          and all(type(v) is str and _SOURCE_ID.fullmatch(v) for v in objects.values()),
          "SOURCE_OBJECTS_INVALID")
    _need(len(set(objects[role] for role in ("module", "owner_block", "button", "trigger",
                                           "detail_block", "value_item", "key_item", "bind_item"))) == 8,
          "SOURCE_OBJECT_COLLISION")
    result = required.validate_prototype_spec(_required_projection(value))
    result.update(schema_version=SCHEMA_VERSION, profile_id=PROFILE_ID, count_guard=deepcopy(guard))
    _targets(result)
    return result


def validate_source_binding(spec, source_bytes):
    """Recompute the source proof and source->existing-target IDs from exact XML."""
    normalized = validate_prototype_spec(spec)
    guard = normalized["count_guard"]
    selector = guard["source_selector"]
    rule = source_guard.extract_count_guard(source_bytes, source_sha256=guard["source_xml_sha256"],
                                            **selector)
    _need(legacy._canonical(guard) == legacy._canonical(_guard_metadata(rule)), "SOURCE_RULE_MISMATCH")
    target = _targets(normalized)
    by_id = {field["source_item_id"]: field for block in normalized["blocks"] for field in block["fields"]}
    for role, source_role in (("value", "value_item"), ("key", "key_item"), ("bind", "bind_item")):
        field = by_id[guard["source_objects"][source_role]]
        _need(field["source_name"].upper() == rule["bindings"][role]["item"], "SOURCE_NAME_MISMATCH")
        expected_type = {"Char": "VARCHAR2", "Number": "NUMBER"}.get(rule["bindings"][role]["data_type"])
        _need(field["data_type"] == expected_type, "SOURCE_TYPE_MISMATCH")
    _need(target["owner_block"]["name"].upper() == selector["block"]
          and target["detail_block"]["name"].upper() == rule["bindings"]["value"]["block"],
          "SOURCE_BLOCK_NAME_MISMATCH")
    return normalized


def _check_fragment(target):
    page, key = target["page_id"], target["key_item"]
    key_field = {"name": "FOX_COUNT_GUARD_KEY", "label": target["key_label"],
                 "data_type": target["key_type"], "widget": "number" if target["key_type"] == "NUMBER" else "text",
                 "nullable": True, "in_edit_form": False}
    if target["key_type"] == "VARCHAR2":
        key_field["length"] = target["key_length"]
    item = legacy._control_item(key_field, 10, page).replace("region: @controls", "region: @count-guard-check")
    # Component shapes are taken from the pinned official real exports above.
    # PL/SQL is a fixed template; only validated synthetic identifiers enter it.
    return f'''    region count-guard-check (
        name: Null or zero pre-check only - persisted rows - not approval
        type: staticContent
        source {{
            htmlCode:
                ```html
                <p>This is only the first null/zero check, using saved synthetic rows. Empty keys or no matching rows pass this isolated predicate. Negative nonzero values pass. Approval, later rules and original exception handling are not performed.</p>
                ```
        }}
        layout {{
            sequence: 20
            slot: body
        }}
        appearance {{
            template: @/standard
            templateOptions: #DEFAULT#
        }}
    )
{item}
    button count-guard-check (
        buttonName: {REQUEST}
        label: Check null or zero values only
        layout {{
            sequence: 20
            region: @count-guard-check
            slot: create
        }}
        appearance {{
            buttonTemplate: @/text
        }}
        behavior {{
            action: submitPage
            executeValidations: true
            warnOnUnsavedChanges: doNotCheck
        }}
    )
    validation count-guard-check (
        name: Isolated null or zero persisted-row check
        execution {{
            sequence: 10
        }}
        validation {{
            type: functionBodyReturningBoolean
            plsqlFunctionBody:
                ```plsql
                if :REQUEST = '{REQUEST}' then
                    declare
                        l_count number;
                    begin
                        select count(0) into l_count
                        from {target['table_name']}
                        where nvl({target['value_column']}, 0) = 0
                          and {target['key_column']} = :{key};
                        return l_count = 0;
                    end;
                else
                    return true;
                end if;
                ```
        }}
        error {{
            errorMessage: {FAILURE}
            displayLocation: inlineInNotification
        }}
    )
    process count-guard-check-passed (
        name: Report isolated check passed only
        type: executeCode
        source {{
            plsqlCode:
                ```plsql
                declare
                    l_count number;
                begin
                    if :REQUEST = '{REQUEST}' then
                        select count(0) into l_count
                        from {target['table_name']}
                        where nvl({target['value_column']}, 0) = 0
                          and {target['key_column']} = :{key};
                        if l_count > 0 then
                            raise_application_error(-20001, '{FAILURE}');
                        end if;
                    else
                        raise_application_error(-20002, 'This request does not run the isolated check.');
                    end if;
                end;
                ```
        }}
        execution {{
            sequence: 10
        }}
        successMessage {{
            successMessage: {SUCCESS}
        }}
        serverSideCondition {{
            whenButtonPressed: @count-guard-check
        }}
    )
'''


def render_native_blueprint(value):
    """One complete candidate app; only selected owner report gets check action."""
    spec = validate_prototype_spec(value)
    files = required.render_native_blueprint(_required_projection(spec))
    target = _targets(spec)
    original = files[target["page_file"]]
    _need(original.endswith(")\n"), "PAGE_ANCHOR_CHANGED")
    files[target["page_file"]] = original[:-2] + _check_fragment(target) + ")\n"
    return files


def render_prototype_schema(value):
    return required.render_prototype_schema(_required_projection(validate_prototype_spec(value)))


def context():
    members = {"@required-context": required.context(),
               "@renderer": Path(__file__).read_text(encoding="utf-8"),
               "@source-extractor": Path(source_guard.__file__).read_text(encoding="utf-8")}
    return {"template_id": TEMPLATE_ID, "sha256": legacy._sha(legacy._canonical(members)),
            "profile_id": PROFILE_ID, "schema_version": SCHEMA_VERSION,
            "input_validation_policy": INPUT_VALIDATION_POLICY, "count_guard_policy": POLICY_ID,
            "data_mode": DATA_MODE, "status": "CANDIDATE", "requires_actual_sqlcl_validation": True,
            "max_blocks": MAX_BLOCKS, "max_fields_per_block": MAX_FIELDS}


def prototype_trace(value):
    spec = validate_prototype_spec(value)
    target = _targets(spec)
    trace = required.prototype_trace(_required_projection(spec))
    trace.update(schema_version=SCHEMA_VERSION, scope=PROFILE_ID + "-trace", template=context(),
                 rendering_spec_sha256=legacy._sha(legacy._canonical(spec)))
    trace["count_guard"] = {**deepcopy(spec["count_guard"]),
        **{key: target[key] for key in ("page_id", "page_file", "key_item", "table_name", "value_column", "key_column")},
        "request": REQUEST, "source_authority_verified": False, "partial_consent_verified": False,
        "original_button_action_converted": False, "approval_performed": False,
        "schema_changed": False, "dml_performed_by_check": False,
        "runtime_verified": False, "unsupported_remainder_converted": False,
        "exception_handler_parity_verified": False, "specimen_provenance": SPECIMENS}
    trace["assumptions"].extend([
        "Only the isolated source count predicate is adapted to a separate native check request; the original button action remains unconverted.",
        "The check reads persisted synthetic rows only, not unsaved Forms buffers; it performs no approval, DML, webhook or inferred relationship.",
        "Null keys or no matching rows produce count zero, as in the isolated SQL predicate; later original no-row checks are unconverted.",
        "Messages are generated explanations, not recovered masked original text. Negative nonzero values do not block.",
        "Original exception handlers, failure propagation and transaction semantics are not reproduced.",
        "Validation and the success process independently repeat the same read-only count; concurrent changes can alter either result. This is not an atomic approval or original transaction-parity claim.",
    ])
    trace["assumptions"] = [
        "Except for the separately traced isolated count predicate, legacy triggers, buttons, packages, queries, defaults, LOVs and business logic remain unconverted."
        if row == "Legacy triggers, buttons, packages, queries, defaults, LOVs and business logic are not executed or converted."
        else row for row in trace["assumptions"]]
    return trace


def deterministic_prototype_zip(value):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        for name, content in sorted(render_native_blueprint(value).items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system, info.external_attr, info.compress_type = 3, 0o100644 << 16, zipfile.ZIP_STORED
            archive.writestr(info, content.encode("utf-8"))
    return stream.getvalue()
