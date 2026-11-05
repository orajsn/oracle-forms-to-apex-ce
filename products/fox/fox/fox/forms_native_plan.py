"""Pure source-bound synthetic prototype planning, never execution permission.

Fresh original bytes establish facts; the blueprint only selects proposed
objects. This plan proves no translation, database identity, independent review,
import or business acceptance. The execution caller must check those gates.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import json
import re

from . import forms_facts
from .forms_blueprint import validate_blueprint
from .forms_understanding_packet import local_packet
from .native_source import _humanize, _label, _LABEL_SQL

POLICY_ID = "fox-demo-synthetic-schema-v1"
PROFILE_ID = "native-blueprint-prototype-v1"
MAX_BLOCKS = 50
MAX_FIELDS = 255
_PROJECT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,179}\Z")
_APEX_SUBSTITUTION = re.compile(r"&[A-Za-z0-9_$#]+\.")
_PROPERTIES = frozenset({"Name", "DSCName", "ItemType", "DataType", "MaximumLength", "Prompt",
                         "ColumnName", "DatabaseItem", "PrimaryKey", "DatabaseBlock"})


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _hash(value):
    return hashlib.sha256(value).hexdigest()


def _safe_label(value):
    # Same inert-label boundary as the native renderer, without importing the
    # converter into the application. APEX substitutions are not plain labels.
    return type(value) is str and _label(value) and not _APEX_SUBSTITUTION.search(value)


def _safe_name(value):
    # Source identity is not a rewritten label. Unsafe identities stay in the
    # coverage report, not in the executable rendering contract.
    return (type(value) is str and forms_facts._identifier(value) is not None
            and not any(token in value for token in ("--", "${", "&"))
            and not _LABEL_SQL.search(value))


def _metadata(documents, packet):
    sources = {entry["source"]["name"]: entry for entry in packet["sources"]}
    indexed = {}
    for name, raw in documents:
        root, locations = forms_facts._safe_input(name, raw)
        nodes = {location["path"]: (node, location)
                 for node, location in zip(root.iter(), locations, strict=True)}
        for source in sources[name]["facts"]["objects"]:
            node, location = nodes[source["location"]["path"]]
            if location != source["location"] or forms_facts._local(node.tag) != source["kind"]:
                raise ValueError("Source object does not match its fresh exact XML path.")
            # Full values, not truncated snippets, of relevant properties only.
            # Qualified/inherited metadata is retained but never guessed into a
            # plain effective property. Executable attributes/bodies stay out.
            indexed[source["id"]] = {
                key: value for key, value in node.attrib.items()
                if forms_facts._local(key) in _PROPERTIES}
    return indexed


def build_native_prototype_plan(documents: list[tuple[str, bytes]], blueprint: dict, *,
                                project_id, project_name, approved_policy_id) -> dict:
    """Return a deterministic non-executing plan and complete source coverage.

    Policy selection permits only explicit synthetic mapping assumptions here;
    it is not user permission, reviewer provenance or a provider/Oracle receipt.
    Original/source metadata and caller-owned blueprint are never changed.
    Unsupported items are individually unresolved, not silently coerced.
    """
    if type(approved_policy_id) is not str or approved_policy_id != POLICY_ID:
        raise ValueError("The explicit synthetic-schema policy is required.")
    if type(project_id) is not str or not _PROJECT_ID.fullmatch(project_id):
        raise ValueError("Project identity must be a bounded safe token.")
    if not _safe_label(project_name):
        raise ValueError("Project name must be safe plain text of 1 to 80 characters.")
    packet = local_packet(documents)
    validate_blueprint(packet, blueprint)
    metadata = _metadata(documents, packet)
    objects = [row for entry in packet["sources"] for row in entry["facts"]["objects"]]
    dispositions = {row["source_object_id"]: row for row in blueprint["objects"]}
    coverage, remediation, assumptions, blocks = [], [], [], []
    indexed_coverage = {}

    def problem(source, code, reason, next_action="Supply an explicit reviewed mapping before claiming this behavior."):
        remediation.append({"source_object_id": source["id"], "kind": source["kind"],
                            "code": code, "reason": reason, "next_action": next_action})

    def adaptation(source, code, reason):
        assumptions.append({"source_object_id": source["id"], "code": code,
                            "reason": reason, "policy_id": POLICY_ID,
                            "scope": "synthetic-prototype-only"})

    for source in objects:
        proposal = dispositions[source["id"]]
        disposition = proposal["disposition"]
        row = {"source_object_id": source["id"], "kind": source["kind"],
               "blueprint_disposition": disposition,
               "disposition": "unresolved" if disposition == "proposed" else disposition,
               "reason": proposal["reason"], "location": deepcopy(source["location"]),
               "source_metadata": deepcopy(metadata[source["id"]])}
        if source["kind"] == "Block" and "native_component" in proposal:
            row["source_native_component"] = proposal["native_component"]
        indexed_coverage[source["id"]] = row
        coverage.append(row)
        if disposition != "proposed":
            problem(source, "blueprint_" + disposition,
                    "Explicit blueprint disposition retained; this source object is not rendered.")
        elif source["kind"] not in {"Block", "Item"}:
            row["reason"] = "This profile does not translate or execute this source object."
            problem(source, "source_behavior_not_implemented", row["reason"])

    selected = {}
    for source in objects:
        if source["kind"] != "Block" or dispositions[source["id"]]["disposition"] != "proposed":
            continue
        row = indexed_coverage[source["id"]]
        if not _safe_name(source["name"]):
            row["reason"] = "The exact source block name is unavailable or unsafe for native rendering."
            problem(source, "unsafe_source_name", row["reason"])
            continue
        if len(blocks) >= MAX_BLOCKS:
            row["reason"] = "This block exceeds the bounded 50-block prototype profile."
            problem(source, "block_limit", row["reason"], "Split the prototype scope explicitly or extend and verify the renderer profile.")
            continue
        # validate_blueprint already prevents unknown blocks becoming data.
        classification = source["classification"]
        source_component = dispositions[source["id"]]["native_component"]
        native_component = "report" if source_component == "interactive-grid" else source_component
        if source_component == "interactive-grid":
            reason = "Interactive-grid editing is not implemented; this explicit native report fallback is read-only, without a form, Create action or automatic DML."
            adaptation(source, "grid_editing_not_implemented", reason)
            problem(source, "grid_editing_not_implemented", reason,
                    "Review the read-only prototype or implement and verify native grid editing separately.")
        block = {"source_block_id": source["id"], "name": source["name"],
                 "sequence": len(blocks) + 1, "classification": classification,
                 "native_component": native_component,
                 "table_name": ("FOX_NATIVE_" + _hash(_canonical(
                     [project_id, packet["source_binding"], source["id"]]))[:19].upper()
                     if classification == "database" else None), "fields": []}
        blocks.append(block)
        selected[source["id"]] = block
        row["planned_native_component"] = native_component
        row.update(disposition="planned", reason="Native synthetic prototype structure is planned; not rendered or verified.")

    used_fields = set()
    for source in objects:
        if source["kind"] != "Item" or dispositions[source["id"]]["disposition"] != "proposed":
            continue
        row = indexed_coverage[source["id"]]
        block = selected.get(source["block_id"])

        def unresolved(code, reason):
            row["reason"] = reason
            problem(source, code, reason)

        if block is None:
            unresolved("source_block_not_planned", "The item's exact source block has no native prototype plan.")
            continue
        if not _safe_name(source["name"]):
            unresolved("unsafe_source_name", "The exact source item name is unavailable or unsafe for native rendering.")
            continue
        if len(block["fields"]) >= MAX_FIELDS:
            unresolved("field_limit", "This item exceeds the bounded 255-field block profile.")
            continue
        props = metadata[source["id"]]
        item_type = (props.get("ItemType") or "").strip().casefold()
        if item_type == "push button":
            unresolved("button_not_implemented", "Button interaction and legacy calls are not implemented or executed.")
            continue
        if item_type not in {"text item", "display item", "check box", "list item"}:
            unresolved("unsupported_item_type", "The source item type is missing or unsupported; no widget was guessed.")
            continue
        if block["classification"] == "control" and source["database_item"] is True:
            if item_type != "display item":
                unresolved("inconsistent_database_item", "A database item in a control block needs an explicit mapping; no table is inferred.")
                continue
            adaptation(source, "control_display_database_flag_not_binding", "The original DatabaseItem=true flag is retained in source metadata but does not establish a database binding. This control Display Item is source-free and has no database table, source, persistence or translated computation.")
        dtype = (props.get("DataType") or "").strip().casefold()
        if dtype not in {"char", "varchar2", "number", "integer", "date", "datetime"}:
            unresolved("unsupported_data_type", "The effective source data type is missing or unsupported; no type was guessed.")
            continue
        length = None
        if dtype in {"char", "varchar2"}:
            maximum = props.get("MaximumLength")
            if maximum is not None and re.fullmatch(r"[0-9]{1,7}", maximum) is None:
                unresolved("unsupported_length", "The effective source character length is invalid; no length was guessed.")
                continue
            length = int(maximum) if maximum is not None else 0
            if length > 4000:
                unresolved("unsupported_length", "The source character length exceeds VARCHAR2(4000); no truncation was applied.")
                continue
            if length == 0:
                length = 255
                adaptation(source, "synthetic_default_length_255", "Absent or zero source character length uses explicit synthetic VARCHAR2(255), not a customer schema claim.")
            data_type, widget = "VARCHAR2", "text"
        elif dtype in {"number", "integer"}:
            data_type, widget = "NUMBER", "number"
        elif dtype == "date":
            data_type, widget = "DATE", "date"
        else:
            data_type, widget, length = "VARCHAR2", "text", 64
            adaptation(source, "datetime_as_text", "Datetime uses synthetic VARCHAR2(64) text; time is not silently truncated to a date-only widget.")
        if item_type in {"check box", "list item"}:
            if data_type != "VARCHAR2":
                length = 64
            data_type, widget = "VARCHAR2", "text"
            adaptation(source, "interaction_not_ported", "Checkbox/list interaction, values, validation and lookup behavior are not ported; this is a native TEXT fallback only.")
            problem(source, "interaction_not_ported", "Native text fallback does not implement the original checkbox/list behavior.")
        in_edit_form = item_type != "display item"
        if item_type == "display item":
            widget = "display"
            if block["classification"] == "database":
                adaptation(source, "display_report_only", "Display items are report-only in database blocks; original computation and display behavior are not translated.")
            else:
                adaptation(source, "control_display_no_computation", "A native display-only control page item is planned without a value source; legacy computations and display behavior are not implemented.")
        if block["classification"] == "database" and source["database_item"] is not True:
            widget, in_edit_form = "display", False
            adaptation(source, "non_database_item_report_only", "Non-database or unknown-binding source item is synthetic report-only, not customer-table persistence or a translated computation.")
        if block["classification"] == "control":
            in_edit_form = False
            adaptation(source, "control_no_persistence", "Control items are native page items only; no database table or legacy action is inferred.")
        if block["native_component"] == "report":
            in_edit_form = False
        prompt = props.get("Prompt")
        if _safe_label(prompt):
            label = prompt.strip()
        else:
            label = _humanize(source["name"])
            if not _safe_label(label):
                label = label[:80].strip()
            if not _safe_label(label):
                label = "Source item"
            adaptation(source, "source_name_label_fallback", "Empty, unsafe or overlong source Prompt uses a bounded humanized source-name label; original metadata is retained unchanged.")
        name = "F_" + _hash(source["id"].encode("utf-8"))[:24].upper()
        if name in used_fields:
            raise ValueError("Synthetic item identifiers collided; no plan was returned.")
        used_fields.add(name)
        field = {"source_item_id": source["id"], "source_name": source["name"],
                 "name": name, "label": label, "data_type": data_type,
                 "widget": widget, "nullable": True, "in_edit_form": in_edit_form}
        if length is not None:
            field["length"] = length
        block["fields"].append(field)
        row.update(disposition="planned", reason="Native synthetic item is planned with explicit adaptations; original behavior is not accepted.")

    for source in objects:
        if source["id"] in selected and not selected[source["id"]]["fields"]:
            problem(source, "no_native_items", "No source items are natively planned; a database block has only the new synthetic FOX_ROW_ID, never an invented customer field.")
    for entry in packet["sources"]:
        for unit in entry["facts"]["code_units"]:
            remediation.append({"source_object_id": unit["owner_id"], "kind": unit["kind"],
                                "code": "code_unit_not_translated", "code_unit_id": unit["id"],
                                "sha256": unit["sha256"], "bytes": unit["bytes"],
                                "reason": "Exact source code is not executed or claimed translated by this prototype plan.",
                                "next_action": "Implement and independently verify a separate behavior mapping."})
        for collection in ("dependencies", "links"):
            for evidence in entry["facts"][collection]:
                remediation.append({"source_object_id": evidence["source_id"],
                                    "kind": collection, "code": "dependency_not_implemented",
                                    "evidence": deepcopy(evidence),
                                    "reason": "Source dependency/link evidence is not executed or claimed resolved by the native prototype.",
                                    "next_action": "Review and implement the dependency separately; source presence is not conversion."})
    counts = Counter(row["disposition"] for row in coverage)
    result = {
        "rendering_spec": {"schema_version": 1, "profile_id": PROFILE_ID,
                           "data_mode": "synthetic_test_only", "project_id": project_id,
                           "project_name": project_name, "source_binding": packet["source_binding"],
                           "blocks": blocks},
        "coverage": {"objects": coverage, "source_objects": len(objects),
                     "accounted_objects": len(coverage),
                     **{key + "_objects": counts[key] for key in ("planned", "omitted", "unresolved")},
                     "native_apex_generated": False, "import_verified": False,
                     "business_behavior_accepted": False},
        "remediation": remediation,
        "assumptions": [{"policy_id": POLICY_ID, "scope": "synthetic-prototype-only",
                         "code": "synthetic_schema_only",
                         "reason": "New synthetic FOX_ROW_ID keys and nullable fields only. No customer DDL, PK, constraints, routines, approval or review provenance is inferred."}, *assumptions],
        "source_binding": packet["source_binding"],
    }
    result["plan_sha256"] = _hash(_canonical(result))
    return result
