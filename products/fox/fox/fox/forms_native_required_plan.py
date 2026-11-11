"""Opt-in source Required -> native submit-time UI validation, never DDL.

The legacy planner remains the structural authority. Only a directly written,
unqualified Required=true on an eligible source item enables the new UI flag.
Unknown/inherited properties, arbitrary PL/SQL and event timing are not inferred.
"""
from __future__ import annotations

from copy import deepcopy

from . import forms_facts, forms_native_plan
from .forms_understanding_packet import local_packet

INPUT_POLICY_ID = "forms-required-inputs-v1"
PROFILE_ID = "native-blueprint-prototype-required-v1"


def bound_native_input_policy(binding):
    """Absent means legacy; an explicitly present null/unknown value is invalid."""
    if "native_input_policy" not in binding:
        return None
    policy = binding["native_input_policy"]
    if type(policy) is not str or policy != INPUT_POLICY_ID:
        raise ValueError("Unknown immutable native input policy.")
    return policy


def build_native_plan(documents, blueprint, *, native_input_policy=None, **kwargs):
    """Closed dispatch. The default returns the unmodified legacy plan."""
    if native_input_policy is None:
        return forms_native_plan.build_native_prototype_plan(documents, blueprint, **kwargs)
    bound_native_input_policy({"native_input_policy": native_input_policy})
    return build_native_required_prototype_plan(documents, blueprint, **kwargs)


def _source_items(documents, packet):
    entries = {entry["source"]["name"]: entry for entry in packet["sources"]}
    indexed = {}
    for name, raw in documents:
        entry = entries[name]
        root, locations = forms_facts._safe_input(name, raw)
        nodes = {location["path"]: (node, location)
                 for node, location in zip(root.iter(), locations, strict=True)}
        for source in entry["facts"]["items"]:
            node, location = nodes[source["location"]["path"]]
            if (location != source["location"] or forms_facts._local(node.tag) != "Item"
                    or forms_facts._identifier(node.get("Name")) != source["name"]):
                raise ValueError("Required property does not match its fresh source item identity.")
            attributes = {key: value for key, value in node.attrib.items()
                          if forms_facts._local(key) == "Required"}
            direct = attributes.get("Required")
            normalized = direct.strip().casefold() if direct is not None else None
            explicit = {"true": True, "false": False}.get(normalized)
            indexed[source["id"]] = (source, {
                "source_object_id": source["id"], "source_name": source["name"],
                "source_file": name, "source_sha256": entry["source"]["sha256"],
                "location": deepcopy(location), "attributes": attributes,
                "direct_required": explicit,
                "interpretation": "direct-unqualified-boolean" if explicit is not None else "unknown",
            })
    return indexed


def build_native_required_prototype_plan(documents, blueprint, *, project_id,
                                         project_name, approved_policy_id):
    """Add source-proven required UI flags without changing nullable storage."""
    result = forms_native_plan.build_native_prototype_plan(documents, blueprint,
        project_id=project_id, project_name=project_name, approved_policy_id=approved_policy_id)
    packet = local_packet(documents)
    items = _source_items(documents, packet)
    fields = {}
    for block in result["rendering_spec"]["blocks"]:
        for field in block["fields"]:
            source, _ = items[field["source_item_id"]]
            if (source["name"] != field["source_name"] or source["block_id"] != block["source_block_id"]
                    or source["id"] in fields):
                raise ValueError("Required field does not match its exact source identity and block.")
            eligible = (block["classification"] == "database" and block["native_component"] == "form"
                        and source["database_item"] is True and field["in_edit_form"] is True
                        and field["widget"] != "display")
            field["value_required"] = bool(eligible and items[source["id"]][1]["direct_required"] is True)
            fields[source["id"]] = field
    for row in result["coverage"]["objects"]:
        if row["kind"] != "Item":
            continue
        source, proof = items[row["source_object_id"]]
        row["source_metadata"].update(proof["attributes"])
        field = fields.get(source["id"])
        enabled = field is not None and field["value_required"] is True
        row["input_validation"] = {
            "policy_id": INPUT_POLICY_ID, "source_proof": proof,
            "native_required_ui": enabled,
            "scope": "native-submit-time-only" if enabled else "no-additional-proven-rule",
            "original_event_timing_preserved": False,
            "database_constraint_inferred": False,
        }
        if any(key != "Required" for key in proof["attributes"]):
            result["remediation"].append({
                "source_object_id": source["id"], "kind": "Item",
                "code": "qualified_required_not_interpreted",
                "reason": "Qualified Required metadata is preserved as evidence only; it is not coerced into an effective Forms property or native validation.",
                "next_action": "Establish the effective direct source property and review its provenance before mapping this metadata.",
            })
        if proof["direct_required"] is True and not enabled:
            result["remediation"].append({
                "source_object_id": source["id"], "kind": "Item",
                "code": "required_input_not_implemented",
                "reason": "Source Required=true is not enforced on this omitted, unsupported, display-only, report-only, control or non-database item.",
                "next_action": "Supply an explicit editable mapping and verify validation separately; do not claim this required behavior converted.",
            })
        elif proof["direct_required"] is None:
            result["remediation"].append({
                "source_object_id": source["id"], "kind": "Item",
                "code": "required_input_unknown",
                "reason": "No direct unqualified Required=true/false is established; absent, qualified, inherited or default properties are not guessed.",
                "next_action": "Confirm the effective source property before claiming original required-input behavior.",
            })
        if enabled:
            result["assumptions"].append({
                "source_object_id": source["id"], "policy_id": INPUT_POLICY_ID,
                "scope": "synthetic-prototype-only", "code": "native_required_ui_submit_time",
                "reason": "Direct source Required=true is adapted to native APEX submit-time required UI validation only. Original Forms validation/event timing is not preserved; storage remains nullable and no database constraint is inferred.",
            })
    result["rendering_spec"].update(schema_version=2, profile_id=PROFILE_ID,
                                    input_validation_policy=INPUT_POLICY_ID)
    result.pop("plan_sha256")
    result["plan_sha256"] = forms_native_plan._hash(forms_native_plan._canonical(result))
    return result
