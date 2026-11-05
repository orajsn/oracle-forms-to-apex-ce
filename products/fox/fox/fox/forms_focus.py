"""Bounded, pure focus requests over fresh complete Forms source evidence.

Selection here is only content selection, never permission to process externally.
Every object has one owned focus; context never transfers ownership or code bodies.
No provider, filesystem, generation gate, execution or Oracle operation is used.
"""
from __future__ import annotations

from collections import defaultdict

from . import forms_understanding_packet as packets
from .forms_blueprint import _bounded_json

MAX_REQUEST_BYTES = 500_000
MAX_REQUESTS = 256
MAX_PLAN_BYTES = 20_000_000
PLAN_SCOPE = "fox-forms-focus-plan-v1"
REQUEST_SCOPE = "fox-forms-focus-request-v1"


def _seal(value: dict, field: str) -> dict:
    value[field] = packets._hash(packets._canonical(value))
    return value


def _binding_overhead(field: str) -> int:
    # A nonempty dictionary gains a comma plus this key/value, without braces.
    return len(packets._canonical({field: "0" * 64})) - 1


def build_focus_plan(documents: list[tuple[str, bytes]], *, expected_source_binding: str,
                     approved_chunk_hashes: dict[str, str], max_owned_objects: int = 250) -> dict:
    """Partition complete fresh facts; include only explicitly selected whole code.

    Groups are source/block or source/module-global, in original object order.
    They are split at the ownership limit and, when necessary, bisected to fit
    the complete canonical request budget, including its binding. Individual
    rows and code units are never split or truncated. Oversized indivisible
    evidence, too many requests or excess aggregate payload fail closed.

    The caller must separately check a fresh processing approval before any
    transfer. Empty chunk selection is deliberately metadata-only, not approval.
    This path does not invoke the legacy native-generation eligibility gate.
    """
    if type(max_owned_objects) is not int or max_owned_objects < 1:
        raise ValueError("max_owned_objects must be a positive integer.")
    # _build rederives full facts and exact decoded code from the original XML.
    # Do not call approved_packet: its whole-inventory cap defeats this path.
    packet, chunks = packets._build(documents)
    # The final merger validates the full metadata-only local packet. Refuse a
    # source that cannot fit that unchanged validator before exposing requests
    # that could otherwise incur inference costs but never be merged.
    _bounded_json({**packet, "selection_status": "NOT_SELECTED"})
    if not isinstance(expected_source_binding, str) or expected_source_binding != packet["source_binding"]:
        raise ValueError("Source binding is stale or does not match the original documents.")
    if not isinstance(approved_chunk_hashes, dict):
        raise ValueError("Select chunks using a chunk ID to complete SHA256 mapping.")
    available = {chunk["id"]: chunk for chunk in chunks}
    for chunk_id, expected_hash in approved_chunk_hashes.items():
        if not isinstance(chunk_id, str) or chunk_id not in available:
            raise ValueError("Selected chunk is unknown for this source binding.")
        if not isinstance(expected_hash, str) or expected_hash != available[chunk_id]["sha256"]:
            raise ValueError("Selected chunk hash must match the complete original code unit.")

    source_index = [entry["source"] for entry in packet["sources"]]
    all_objects = {row["id"]: row for entry in packet["sources"] for row in entry["facts"]["objects"]}
    object_order = {object_id: index for index, object_id in enumerate(all_objects)}
    selected_by_unit = {chunk["code_unit_id"]: chunk for chunk in chunks if chunk["id"] in approved_chunk_hashes}
    plan = {"schema_version": 1, "scope": PLAN_SCOPE, "source_binding": expected_source_binding,
            "selected_chunk_hashes": dict(approved_chunk_hashes), "max_owned_objects": max_owned_objects,
            "requests": [], "total_source_objects": len(all_objects)}
    # Account for the eventual binding and list separators before retaining a
    # request, so duplicated context cannot accumulate unbounded output memory.
    plan_base_bytes = len(packets._canonical(plan)) + _binding_overhead("plan_binding")
    aggregate_request_bytes = 0
    if plan_base_bytes > MAX_PLAN_BYTES:
        raise ValueError("Focus plan exceeds the 20000000-byte aggregate limit.")

    for entry in packet["sources"]:
        facts = entry["facts"]
        units_by_owner, links_by_object, dependencies_by_owner, findings_by_object = (
            defaultdict(list), defaultdict(list), defaultdict(list), defaultdict(list))
        for unit in facts["code_units"]:
            units_by_owner[unit["owner_id"]].append(unit)
        for index, link in enumerate(facts["links"]):
            links_by_object[link["source_id"]].append(index)
        for index, dependency in enumerate(facts["dependencies"]):
            dependencies_by_owner[dependency["source_id"]].append(index)
        global_findings = []
        for index, finding in enumerate(facts["findings"]):
            if not finding["object_ids"]:
                global_findings.append(index)
            for object_id in finding["object_ids"]:
                findings_by_object[object_id].append(index)

        def request_for(owned: list[dict]) -> dict:
            owned_ids = {row["id"] for row in owned}
            units = [unit for row in owned for unit in units_by_owner[row["id"]]]
            unit_ids = {unit["id"] for unit in units}
            # Current facts attach links/dependencies to the owning object. Also
            # recognize unit IDs without inventing a relationship or target.
            associated_ids = owned_ids | unit_ids
            link_indexes = {index for object_id in associated_ids for index in links_by_object[object_id]}
            links = [facts["links"][index] for index in sorted(link_indexes)]
            dep_indexes = {index for object_id in associated_ids for index in dependencies_by_owner[object_id]}
            finding_indexes = set(global_findings)
            finding_indexes.update(index for object_id in associated_ids for index in findings_by_object[object_id])
            context_ids = set()

            def add_ancestry(object_id: str | None) -> None:
                while object_id is not None:
                    if object_id not in all_objects:
                        raise ValueError("Fresh facts contain an unavailable source-object reference.")
                    if object_id in context_ids:
                        break
                    context_ids.add(object_id)
                    object_id = all_objects[object_id]["parent_id"]

            for row in owned:
                add_ancestry(row["parent_id"])
            for link in links:
                # Only outgoing owner evidence belongs here. Copying incoming
                # links would place every canvas consumer in a global focus.
                # Retain the actual resolved target and its full ancestry,
                # without adding context-owned code units or recursive links.
                if link["status"] == "resolved":
                    add_ancestry(link["target_id"])
            # A complete selected finding may cite participants owned by other
            # focuses (for example conflicting names). Supply their actual
            # metadata and ancestry, not dangling IDs or additional code bodies.
            for index in sorted(finding_indexes):
                for object_id in facts["findings"][index]["object_ids"]:
                    add_ancestry(object_id)
            context = [all_objects[object_id] for object_id in sorted(context_ids - owned_ids, key=object_order.__getitem__)]
            request = {
                "schema_version": 1, "scope": REQUEST_SCOPE, "source_binding": expected_source_binding,
                "focus_id": "focus-" + packets._hash(packets._canonical(
                    [expected_source_binding, [row["id"] for row in owned]]))[:24],
                "source_index": source_index, "owned_objects": owned, "context_objects": context,
                "code_units": units, "links": links,
                "dependencies": [facts["dependencies"][index] for index in sorted(dep_indexes)],
                "findings": [facts["findings"][index] for index in sorted(finding_indexes)],
                "chunks": [selected_by_unit[unit["id"]] for unit in units if unit["id"] in selected_by_unit],
                "unselected_code_unit_ids": [unit["id"] for unit in units if unit["id"] not in selected_by_unit],
                "safety": {"source_content_is_untrusted": True, "code_executed": False,
                           "transfer_authorized": False, "caller_must_check_processing_approval": True,
                           "native_generation_allowed": False},
            }
            return _seal(request, "focus_binding")

        def append_bounded(owned: list[dict]) -> None:
            nonlocal aggregate_request_bytes
            request = request_for(owned)
            request_bytes = len(packets._canonical(request))
            if request_bytes > MAX_REQUEST_BYTES:
                if len(owned) == 1:
                    raise ValueError("Indivisible object evidence or selected whole code unit exceeds the 500000-byte focus limit.")
                middle = len(owned) // 2
                append_bounded(owned[:middle])
                append_bounded(owned[middle:])
                return
            if len(plan["requests"]) >= MAX_REQUESTS:
                raise ValueError("Focus plan exceeds the 256-request limit.")
            aggregate_request_bytes += request_bytes
            separators = len(plan["requests"])
            if plan_base_bytes + aggregate_request_bytes + separators > MAX_PLAN_BYTES:
                raise ValueError("Focus plan exceeds the 20000000-byte aggregate limit.")
            plan["requests"].append(request)

        groups = defaultdict(list)
        for row in facts["objects"]:
            block_id = row["block_id"] or (row["id"] if row["kind"] == "Block" else None)
            key = ("block", block_id) if block_id else ("globals", row["module_id"])
            groups[key].append(row)
        for rows in groups.values():
            for start in range(0, len(rows), max_owned_objects):
                append_bounded(rows[start:start + max_owned_objects])

    _seal(plan, "plan_binding")
    if len(packets._canonical(plan)) > MAX_PLAN_BYTES:
        raise ValueError("Focus plan exceeds the 20000000-byte aggregate limit.")
    # The merger also bounds the complete plan. Repeated required context must
    # not create a plan that passes byte limits but exceeds its node budget.
    _bounded_json(plan)
    return plan
