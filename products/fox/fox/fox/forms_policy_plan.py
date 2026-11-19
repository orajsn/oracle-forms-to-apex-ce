"""Fresh complete-source policy plans; review artifacts never count as converted."""
from __future__ import annotations

from copy import deepcopy

from .forms_understanding_packet import _build
from .forms_behavior_plan import _source_objects
from forms2apex.native_policy_rules import SCOPE, derive_policy_operations, _canonical, _sha


def build_policy_plan(documents, trace):
    """Bind bounded policy IR to original XML bytes and the exact parent trace.

    No source event or context provider is inferred. Rebuild immediately before
    rendering; a plan digest is an integrity check, not source authentication.
    """
    packet, chunks = _build(documents)
    objects, metadata = _source_objects(documents, packet)
    if type(trace) is not dict or trace.get("source_binding") != packet["source_binding"]:
        raise ValueError("POLICY_TRACE_BINDING")
    chunks = {row["code_unit_id"]: row for row in chunks}
    catalog = {"objects": [], "units": []}
    # _source_objects follows caller document order; the source packet and
    # generated package are canonical regardless of that order.
    for obj in sorted(objects.values(), key=lambda row: row["id"]):
        row = {key: deepcopy(obj.get(key)) for key in ("id", "kind", "name", "module_id", "block_id", "parent_id",
                                                      "classification", "database_item")}
        row["metadata"] = deepcopy(metadata[obj["id"]])
        catalog["objects"].append(row)
    for entry in packet["sources"]:
        for unit in entry["facts"]["code_units"]:
            catalog["units"].append({**{key: deepcopy(unit[key]) for key in
                ("id", "owner_id", "source_attribute", "sha256", "location")},
                "chunk_id": chunks[unit["id"]]["id"], "text": chunks[unit["id"]]["text"]})
    operations, coverage = derive_policy_operations(catalog, trace, packet["source_binding"])
    plan = {"schema_version": 1, "scope": SCOPE, "source_binding": packet["source_binding"],
        "trace_sha256": _sha(_canonical(trace)), "parent_trace": deepcopy(trace), "source_catalog": catalog,
        "sources": [{key: entry["source"][key] for key in ("name", "sha256", "bytes")} for entry in packet["sources"]],
        "operations": operations, "coverage": coverage, "code_unit_count": len(coverage),
        "native_generated": False, "event_activated": False, "runtime_verified": False, "business_accepted": False}
    plan["plan_sha256"] = _sha(_canonical(plan))
    return plan
