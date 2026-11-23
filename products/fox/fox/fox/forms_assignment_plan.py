"""Source-bound PRE-INSERT/PRE-UPDATE copies for unwired review artifacts only."""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import re

from .forms_understanding_packet import _build
from .forms_behavior_plan import _source_objects
from forms2apex.native_assignments import (
    SCOPE, MAX_OPERATIONS, _canonical, _sha, parse_assignment_text, operation_id,
)


class UnsupportedAssignment(ValueError):
    """A complete source unit cannot be safely encoded in the bounded scope."""


def _one(rows, reason):
    if len(rows) != 1:
        raise UnsupportedAssignment(reason)
    return rows[0]


def _item(parts, block, objects):
    if len(parts) == 2 and parts[0] != (block["name"] or "").upper():
        raise UnsupportedAssignment("reference_outside_required_block")
    return _one([row for row in objects.values() if row["kind"] == "Item"
                 and row["block_id"] == block["id"]
                 and (row["name"] or "").upper() == parts[-1]], "item_reference_not_unique")


def _field(item, block, objects, metadata, trace):
    props = metadata[item["id"]]
    source_type = props.get("DataType", "").strip().upper()
    datatype = {"NUMBER": "NUMBER", "CHAR": "VARCHAR2", "VARCHAR2": "VARCHAR2"}.get(source_type)
    if (block["classification"] != "database" or item["database_item"] is not True
            or datatype is None or props.get("Formula", "").strip()
            or props.get("CalculateMode", "").strip().upper() not in ("", "NONE")
            or props.get("CalculationMode", "").strip().upper() not in ("", "NONE")
            or props.get("SummaryFunction", "").strip().upper() not in ("", "NONE")
            or any(row["kind"] == "Item" and row["id"] != item["id"]
                   and row["block_id"] == block["id"] and (row["name"] or "").upper() ==
                   (item["name"] or "").upper() for row in objects.values())):
        raise UnsupportedAssignment("direct_noncomputed_database_item_required")
    mapped = _one([row for row in trace.get("blocks", [])
                   if row.get("source_block_id") == block["id"]], "trace_block_not_unique")
    field = _one([row for row in mapped.get("items", [])
                  if row.get("source_item_id") == item["id"]], "trace_item_not_unique")
    if (mapped.get("source_module_id") != block["module_id"]
            or mapped.get("classification") != "database" or mapped.get("name") != block["name"]
            or field.get("source_name") != item["name"] or field.get("data_type") != datatype
            or field.get("database_bound") is not True
            or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", field.get("column") or "")
            or field.get("value_computation_implemented") is True):
        raise UnsupportedAssignment("trace_item_source_binding_mismatch")
    if sum(candidate.get("column") == field["column"] for candidate in mapped.get("items", [])) != 1:
        raise UnsupportedAssignment("trace_column_not_unique")
    return {"block_id": block["id"], "item_id": item["id"], "block_name": block["name"],
            "item_name": item["name"], "column": field["column"], "data_type": datatype}


def _proven_relations(relation_plan, packet, objects, metadata, trace):
    """Recheck declared direct edges against fresh XML; trust no caller-made edge.

    The relation planner owns exact DDL/package validation. This API receives its
    plan and the original native trace, not a ZIP; the integration caller must
    freshly rebuild that plan from the source package immediately before use.
    """
    from .forms_relation_plan import _flags, parse_join_condition, relation_attribute_sha256
    from forms2apex.native_relations import MANUAL_SELECTION_ONLY
    if (type(relation_plan) is not dict or relation_plan.get("scope") != "fox-forms-relation-plan-v1"
            or relation_plan.get("schema_version") != 1
            or relation_plan.get("source_binding") != packet["source_binding"]
            or relation_plan.get("sources") != [{key: entry["source"][key]
                  for key in ("name", "sha256", "bytes")} for entry in packet["sources"]]
            or relation_plan.get("plan_sha256") != _sha(_canonical({k: v for k, v in
                  relation_plan.items() if k != "plan_sha256"}))
            or any(relation_plan.get(key) is not False for key in
                   ("native_generated", "runtime_verified", "business_accepted"))):
        raise ValueError("ASSIGNMENT_RELATION_PLAN_BINDING")
    if type(trace) is not dict or trace.get("source_binding") != packet["source_binding"]:
        raise ValueError("ASSIGNMENT_TRACE_BINDING")
    if relation_plan.get("parent_trace_canonical_sha256") != _sha(_canonical(trace)):
        raise ValueError("ASSIGNMENT_TRACE_CHANGED")
    operations = relation_plan.get("operations")
    if type(operations) is not list or len(operations) > 100:
        raise ValueError("ASSIGNMENT_RELATION_OPERATIONS")
    graph, incoming, relation_ids = {}, {}, set()
    assignment_contexts = []
    for op in operations:
        try:
            relation = objects[op["relation_id"]]
            parent, child = objects[op["parent_block_id"]], objects[op["child_block_id"]]
            props = metadata[relation["id"]]
            valid = (relation["kind"] == "Relation" and parent["kind"] == child["kind"] == "Block"
                and relation["parent_id"] == parent["id"] and relation["block_id"] == parent["id"]
                and relation["module_id"] == parent["module_id"] == child["module_id"] == op["source_module_id"]
                and parent["id"] != child["id"] and parent["classification"] == child["classification"] == "database"
                and props.get("RelationType", "").strip().upper() == "JOIN"
                and (child["name"] or "").upper() == props.get("DetailBlock", "").strip().upper()
                and op["source_attribute_sha256"] == relation_attribute_sha256(props))
            if not valid:
                raise ValueError("ASSIGNMENT_RELATION_SOURCE_MISMATCH")
            if op.get("source_flags") != _flags(props):
                raise ValueError("ASSIGNMENT_RELATION_FLAGS_CHANGED")
            # Reject duplicate block identities by name as well as duplicate edges.
            for block in (parent, child):
                _one([row for row in objects.values() if row["kind"] == "Block"
                      and row["module_id"] == block["module_id"]
                      and (row["name"] or "").upper() == (block["name"] or "").upper()],
                     "relation_block_not_unique")
            coverage = [row for row in relation_plan["coverage"] if row.get("relation_id") == relation["id"]]
            if (len(coverage) != 1 or coverage[0].get("status") != "read_navigation_planned"
                    or coverage[0].get("source_attribute_sha256") != op["source_attribute_sha256"]):
                raise ValueError("ASSIGNMENT_RELATION_COVERAGE")
            navigation_only = coverage[0].get("reason") == MANUAL_SELECTION_ONLY
            child_names = ([item["name"] or "" for item in objects.values()
                            if item["kind"] == "Item" and item["block_id"] == child["id"]]
                           if navigation_only else None)
            pairs = parse_join_condition(props.get("JoinCondition", ""), parent["name"], child["name"],
                                         child_item_names=child_names)
            expected = []
            for parent_name, child_name in pairs:
                p = _item([parent_name], parent, objects)
                c = _item([child_name], child, objects)
                pb, cb = _field(p, parent, objects, metadata, trace), _field(c, child, objects, metadata, trace)
                if pb["data_type"] != cb["data_type"]:
                    raise ValueError("ASSIGNMENT_RELATION_TYPE")
                expected.append({"parent_item_id": p["id"], "parent_column": pb["column"],
                    "child_item_id": c["id"], "child_column": cb["column"], "data_type": pb["data_type"]})
            if expected != op["join_pairs"]:
                raise ValueError("ASSIGNMENT_RELATION_JOIN_CHANGED")
            for label, block in (("parent", parent), ("child", child)):
                mapped = _one([row for row in trace["blocks"] if row.get("source_block_id") == block["id"]],
                              "trace_block_not_unique")
                expected_target = {"table": mapped["table_name"], "report_file": mapped["report_file"],
                    "report_page_id": mapped["report_page_id"], "row_id_column": mapped["synthetic_key"]["column"]}
                if op[label] != expected_target:
                    raise ValueError("ASSIGNMENT_RELATION_TARGET_CHANGED")
            if relation["id"] in relation_ids:
                raise ValueError("ASSIGNMENT_RELATION_AMBIGUOUS")
            relation_ids.add(relation["id"])
            if navigation_only:
                continue
            if parent["id"] in graph or child["id"] in incoming:
                raise ValueError("ASSIGNMENT_RELATION_AMBIGUOUS")
            graph[parent["id"]], incoming[child["id"]] = child["id"], parent["id"]
            assignment_contexts.append(op)
        except (KeyError, TypeError, UnsupportedAssignment):
            raise ValueError("ASSIGNMENT_RELATION_PROOF_INVALID") from None
    operations = assignment_contexts
    for start in graph:
        visited, node = set(), start
        while node in graph:
            if node in visited:
                raise ValueError("ASSIGNMENT_RELATION_CYCLE")
            visited.add(node)
            node = graph[node]
    # A forged subset of an ambiguous source graph must not create context.
    for op in operations:
        competing = []
        for row in objects.values():
            if row["kind"] != "Relation" or row["module_id"] != op["source_module_id"]:
                continue
            detail = metadata[row["id"]].get("DetailBlock", "").strip().upper()
            if row["parent_id"] == op["parent_block_id"] or detail == (objects[op["child_block_id"]]["name"] or "").upper():
                competing.append(row)
        if len(competing) != 1:
            raise ValueError("ASSIGNMENT_RELATION_SOURCE_AMBIGUOUS")
    if operations:
        # Recheck the entire declared graph, including edges omitted from a
        # caller-provided plan, so a rehashed subset cannot hide a source cycle.
        declared, incoming_counts, outgoing_counts = {}, Counter(), Counter()
        for row in objects.values():
            if row["kind"] != "Relation":
                continue
            parent = objects.get(row["parent_id"])
            if parent is None or parent["kind"] != "Block":
                continue
            children = [block for block in objects.values() if block["kind"] == "Block"
                and block["module_id"] == row["module_id"] and (block["name"] or "").upper() ==
                metadata[row["id"]].get("DetailBlock", "").strip().upper()]
            if len(children) != 1:
                continue
            child = children[0]
            outgoing_counts[parent["id"]] += 1
            incoming_counts[child["id"]] += 1
            declared[parent["id"]] = child["id"]
        for op in operations:
            if outgoing_counts[op["parent_block_id"]] != 1 or incoming_counts[op["child_block_id"]] != 1:
                raise ValueError("ASSIGNMENT_RELATION_SOURCE_AMBIGUOUS")
        cyclic = set()
        for start in declared:
            path, node = [], start
            while node in declared and node not in path:
                path.append(node)
                node = declared[node]
            if node in path:
                cyclic.update(path[path.index(node):])
        if any(op["parent_block_id"] in cyclic or op["child_block_id"] in cyclic for op in operations):
            raise ValueError("ASSIGNMENT_RELATION_SOURCE_CYCLE")
    return operations


def build_assignment_plan(documents, relation_plan, trace):
    """Build fresh whole-unit IR, preserving unsupported coverage for every unit."""
    packet, chunks = _build(documents)
    objects, metadata = _source_objects(documents, packet)
    relations = _proven_relations(relation_plan, packet, objects, metadata, trace)
    chunks = {row["code_unit_id"]: row for row in chunks}
    units = [unit for entry in packet["sources"] for unit in entry["facts"]["code_units"]]
    event_owners = Counter((row["module_id"], row["block_id"], (row["name"] or "").upper())
        for row in objects.values() if row["kind"] == "Trigger"
        and objects.get(row["parent_id"], {}).get("kind") == "Block")
    owner_units = Counter(unit["owner_id"] for unit in units)
    operations, coverage = [], []
    for unit in units:
        owner = objects[unit["owner_id"]]
        chunk = chunks[unit["id"]]
        row = {"source_unit_id": unit["id"], "source_unit_sha256": unit["sha256"],
            "source_chunk_id": chunk["id"], "source_owner_id": owner["id"],
            "source_location": deepcopy(unit["location"]), "status": "unsupported",
            "not_yet_converted": True, "reason": "not_a_supported_block_write_copy",
            "runtime_verified": False, "business_accepted": False}
        coverage.append(row)
        try:
            event = (owner["name"] or "").upper()
            block = objects.get(owner["parent_id"])
            if (owner["kind"] != "Trigger" or event not in ("PRE-INSERT", "PRE-UPDATE")
                    or block is None or block["kind"] != "Block"
                    or unit["source_attribute"] not in ("TriggerText", "#text", "TriggerText.text")):
                continue
            if event_owners[(owner["module_id"], block["id"], event)] != 1 or owner_units[owner["id"]] != 1:
                raise UnsupportedAssignment("ambiguous_block_event")
            try:
                target_parts, source_parts, decode = parse_assignment_text(chunk["text"])
            except ValueError:
                raise UnsupportedAssignment("complete_parent_value_copy_required") from None
            target = _item(target_parts, block, objects)
            relation = _one([edge for edge in relations if edge["child_block_id"] == block["id"]
                             and edge["source_module_id"] == owner["module_id"]], "direct_parent_context_unproven")
            parent = objects[relation["parent_block_id"]]
            if len(source_parts) == 1:
                source = _one([item for item in objects.values() if item["kind"] == "Item"
                    and item["module_id"] == owner["module_id"]
                    and (item["name"] or "").upper() == source_parts[0]], "parent_reference_not_unique")
                if source["block_id"] != parent["id"]:
                    raise UnsupportedAssignment("direct_parent_context_unproven")
            else:
                source = _item(source_parts, parent, objects)
            source_ref = _field(source, parent, objects, metadata, trace)
            target_ref = _field(target, block, objects, metadata, trace)
            if source_ref["data_type"] != target_ref["data_type"]:
                raise UnsupportedAssignment("explicit_types_incompatible")
            if len(operations) >= MAX_OPERATIONS:
                raise UnsupportedAssignment("assignment_capacity_exceeded")
            op = {"operation_id": operation_id(packet["source_binding"], unit["id"]),
                "source_unit_id": unit["id"], "source_unit_sha256": unit["sha256"],
                "source_chunk_id": chunk["id"], "source_owner_id": owner["id"],
                "source_module_id": owner["module_id"], "source_event": event,
                "source_unit_text": chunk["text"], "relation_id": relation["relation_id"],
                "source_ref": source_ref, "target_ref": target_ref, "decode_receipt": decode}
            operations.append(op)
            row.update(reason="parent_value_copy_encoded_write_lifecycle_unimplemented",
                       operation_id=op["operation_id"], encoding_status="generated_unwired")
        except UnsupportedAssignment as exc:
            row["reason"] = str(exc)
    plan = {"schema_version": 1, "scope": SCOPE, "source_binding": packet["source_binding"],
        "relation_plan_sha256": relation_plan["plan_sha256"], "trace_sha256": _sha(_canonical(trace)),
        "sources": [{key: entry["source"][key] for key in ("name", "sha256", "bytes")}
                    for entry in packet["sources"]],
        "operations": operations, "coverage": coverage, "code_unit_count": len(units),
        "native_generated": False, "write_lifecycle": False, "runtime_verified": False,
        "business_accepted": False}
    plan["plan_sha256"] = _sha(_canonical(plan))
    return plan
