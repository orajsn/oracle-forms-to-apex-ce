"""Plan one explicitly selected source-derived check, not a complete button action.

Existing required-input plans stay unchanged. The caller must bind this selection
and partial-scope approval at run creation, and reconstruct them for every stage.
This module grants no model, SQL, import or execution authority.
"""
from __future__ import annotations

from copy import deepcopy
import re

from . import forms_native_plan
from .forms_native_required_plan import build_native_required_prototype_plan
from .forms_understanding_packet import local_packet


POLICY_ID = "forms-isolated-count-check-v1"
_SELECTION = {"source_name", "source_sha256", "module", "block", "item"}


def build_native_count_guard_prototype_plan(documents, blueprint, *, project_id,
                                          project_name, approved_policy_id,
                                          count_guard_selection,
                                          partial_scope_consent):
    """Rebuild the exact selected guard from retained XML and the approved design.

    A boolean here is only a prerequisite, not evidence of approval. The pipeline
    must independently validate its immutable creation-time approval binding.
    """
    if partial_scope_consent is not True:
        raise ValueError("Count-check planning requires explicit partial-scope consent.")
    selected = count_guard_selection
    if (type(selected) is not dict or set(selected) != _SELECTION
            or any(type(value) is not str or not value for value in selected.values())
            or re.fullmatch(r"[a-f0-9]{64}", selected["source_sha256"]) is None):
        raise ValueError("Count-check selection requires an exact retained source and button.")
    # Validate the whole project first; never replace its source binding with a
    # single-file hash or trust model-authored table/column names as authority.
    result = build_native_required_prototype_plan(documents, blueprint,
        project_id=project_id, project_name=project_name,
        approved_policy_id=approved_policy_id)
    matching = [raw for name, raw in documents if name == selected["source_name"]]
    if len(matching) != 1 or forms_native_plan._hash(matching[0]) != selected["source_sha256"]:
        raise ValueError("Count-check source is missing, ambiguous or changed.")
    raw = matching[0]
    from forms2apex import native_blueprint_count_guard as renderer
    rendered = renderer.with_count_guard(result["rendering_spec"], raw,
        source_sha256=selected["source_sha256"], module=selected["module"],
        block=selected["block"], item=selected["item"], partial_scope_consent=True)
    rendered = renderer.validate_source_binding(rendered, raw)
    guard = rendered["count_guard"]

    packet = local_packet(documents)
    source = next(row for row in packet["sources"] if row["source"]["name"] == selected["source_name"])
    objects = {row["id"]: row for row in source["facts"]["objects"]}
    ids = guard["source_objects"]
    kinds = {"module": "FormModule", "owner_block": "Block", "button": "Item",
             "trigger": "Trigger", "detail_block": "Block", "value_item": "Item",
             "key_item": "Item", "bind_block": "Block", "bind_item": "Item"}
    if any(object_id not in objects or objects[object_id]["kind"] != kinds[role]
           for role, object_id in ids.items()):
        raise ValueError("Count-check objects differ from fresh project source identities.")
    trigger = objects[ids["trigger"]]
    if (trigger["parent_id"] != ids["button"]
            or objects[ids["button"]]["parent_id"] != ids["owner_block"]
            or any(objects[value]["module_id"] != ids["module"] for value in ids.values())):
        raise ValueError("Count-check source ownership differs from the selected module.")
    # A full omission is not permission to silently add part of that action.
    proposed = {row["source_object_id"]: row for row in blueprint["objects"]}
    if any(proposed[ids[role]]["disposition"] == "omitted" for role in ("button", "trigger")):
        raise ValueError("An explicitly omitted button or trigger cannot acquire a count check.")
    units = [unit for unit in source["facts"]["code_units"]
             if unit["owner_id"] == ids["trigger"] and unit["source_attribute"] == "TriggerText"]
    if len(units) != 1 or units[0]["sha256"] != guard["source_trigger_sha256"]:
        raise ValueError("Count-check trigger does not match the retained source code unit.")

    result["rendering_spec"] = rendered
    result["count_guard_plan"] = {
        "policy_id": POLICY_ID, "selection": deepcopy(selected),
        "partial_scope_consent": True, "source_proof": deepcopy(guard),
        "status": "planned_not_runtime_verified",
        "full_button_converted": False, "business_behavior_accepted": False,
    }
    for row in result["coverage"]["objects"]:
        if row["source_object_id"] in {ids["button"], ids["trigger"]}:
            row["isolated_count_check"] = {
                "policy_id": POLICY_ID, "status": "planned_not_runtime_verified",
                "source_prefix_sha256": guard["source_prefix_sha256"],
                "full_object_converted": False,
            }
    result["remediation"].append({
        "source_object_id": ids["trigger"], "kind": "Trigger",
        "code": "count_check_remainder_not_converted",
        "sha256": guard["source_remainder_sha256"],
        "reason": "Only the initial null-or-zero count check is planned as a separate APEX action. Later statements, approval, transaction handling and exception handlers remain unconverted.",
        "next_action": "Review the remaining original action and its dependencies separately; this check does not approve or save a business record.",
    })
    result["assumptions"].append({
        "source_object_id": ids["trigger"], "policy_id": POLICY_ID,
        "scope": "synthetic-prototype-only", "code": "isolated_persisted_count_check",
        "reason": "A separate check queries saved synthetic detail rows using a supplied grouping value. It does not reproduce unsaved Forms buffers, reject negative nonzero values or prove the original button's complete behavior.",
    })
    result.pop("plan_sha256")
    result["plan_sha256"] = forms_native_plan._hash(forms_native_plan._canonical(result))
    return result
