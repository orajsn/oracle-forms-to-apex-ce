"""Finite source-defined relation navigation, without Forms write lifecycle claims."""
from __future__ import annotations

from collections import Counter
import re

from .forms_behavior_plan import _source_objects, decode_control_entities
from .forms_understanding_packet import _build
from forms2apex import native_relations as native

SCOPE = native.SCOPE
FLAGS = ("AutoQuery", "Deferred", "DeleteRecord", "PreventMasterlessOperations")
_IDENT = r"[A-Za-z][A-Za-z0-9_$#]{0,127}"
_OPERAND = rf"(?:({_IDENT})\s*\.\s*)?({_IDENT})"
_PAIR = re.compile(rf"\s*{_OPERAND}\s*=\s*{_OPERAND}\s*", re.I)


class UnsupportedRelation(ValueError):
    """Complete source relation is outside the bounded navigation grammar."""


def relation_attribute_sha256(attributes):
    return native._sha(native._json(attributes))


def parse_join_condition(text, parent_name, child_name, *, child_item_names=None):
    """Bind whole AND equalities; only uniquely owned child items may be bare.

    The optional names must come from the declared child's source items. Without
    that ownership evidence the original fully qualified grammar is required.
    Exact source/target identity and database types are checked by the planner.
    """
    if (type(text) is not str or len(text) > 8192 or type(parent_name) is not str
            or type(child_name) is not str or parent_name.upper() == child_name.upper()):
        raise UnsupportedRelation("join_condition_invalid")
    try:
        text, _ = decode_control_entities(text)
    except ValueError:
        raise UnsupportedRelation("join_condition_control_encoding_invalid") from None
    terms = re.split(r"\bAND\b", text, flags=re.I)
    if not 1 <= len(terms) <= 4:
        raise UnsupportedRelation("join_pair_count_unsupported")
    child_names = Counter(name.upper() for name in child_item_names) if child_item_names is not None else None
    pairs = []
    for term in terms:
        match = _PAIR.fullmatch(term)
        if not match:
            raise UnsupportedRelation("whole_qualified_equality_required")
        a, left, b, right = (v.upper() if v is not None else None for v in match.groups())
        if (a, b) == (parent_name.upper(), child_name.upper()):
            pair = (left, right)
        elif (a, b) == (child_name.upper(), parent_name.upper()):
            pair = (right, left)
        elif (a, b) in {(None, parent_name.upper()), (parent_name.upper(), None)}:
            pair = (right, left) if a is None else (left, right)
            if child_names is None:
                raise UnsupportedRelation("whole_qualified_equality_required")
            if child_names[pair[1]] != 1:
                raise UnsupportedRelation("unqualified_child_item_not_unique")
        else:
            raise UnsupportedRelation("join_must_bind_exact_parent_and_child")
        if pair in pairs:
            raise UnsupportedRelation("duplicate_join_pair")
        pairs.append(pair)
    if len({a for a, _ in pairs}) != len(pairs) or len({b for _, b in pairs}) != len(pairs):
        raise UnsupportedRelation("ambiguous_join_item_reuse")
    return pairs


def _flags(attrs):
    flags = {key: attrs.get(key) for key in FLAGS}
    for key in ("AutoQuery", "Deferred", "PreventMasterlessOperations"):
        if flags[key] is not None and flags[key].strip().lower() not in {"true", "false"}:
            raise UnsupportedRelation("invalid_relation_lifecycle_flags")
    if flags["DeleteRecord"] is not None and flags["DeleteRecord"].strip().lower() not in {
            "cascading", "isolated", "non isolated"}:
        raise UnsupportedRelation("invalid_relation_lifecycle_flags")
    return flags


def _target(block):
    return {"table": block["table_name"], "report_file": block["report_file"],
            "report_page_id": block["report_page_id"], "row_id_column": block["synthetic_key"]["column"]}


def build_relation_plan(documents, parent_zip):
    """Rebuild source authority and bind read-only manual relation navigation.

    Unsupported declarations remain coverage rows. Graph ambiguity rejects every
    involved edge; it never picks a convenient first relation. Original lifecycle
    metadata is retained without claiming automatic query, write or delete wiring.
    """
    packet, chunks = _build(documents)
    objects, metadata = _source_objects(documents, packet)
    raw, _, files, _ = native._archive(parent_zip)
    manifest, trace, blocks, targets = native._targets(files)
    sources = [{key: entry["source"][key] for key in ("name", "sha256", "bytes")}
               for entry in packet["sources"]]
    if (manifest.get("source_binding") != packet["source_binding"] or manifest.get("files") != sources
            or trace.get("source_binding") != packet["source_binding"]):
        raise ValueError("Relation parent source manifest does not match original documents.")
    native._originals(files, sources)
    selected = manifest.get("selected_chunk_hashes")
    available = {chunk["id"]: chunk["sha256"] for chunk in chunks}
    if type(selected) is not dict or any(available.get(key) != value for key, value in selected.items()):
        raise ValueError("Relation parent selected source chunks do not match original documents.")
    # Validate every traced identity, including unrelated reports, before using it.
    for block_id, block in blocks.items():
        source = objects.get(block_id)
        if (source is None or source["kind"] != "Block" or source["name"] != block.get("name")
                or source["module_id"] != block.get("source_module_id")):
            raise ValueError("Relation parent block source identity mismatch.")
        for field in block["items"]:
            item = objects.get(field["source_item_id"])
            if (item is None or item["kind"] != "Item" or item["block_id"] != block_id
                    or item["name"] != field["source_name"]):
                raise ValueError("Relation parent field source identity mismatch.")
    coverage, candidates, declared_edges = [], [], []
    for relation in sorted((obj for obj in objects.values() if obj["kind"] == "Relation"), key=lambda o: o["id"]):
        attrs = metadata[relation["id"]]
        row = {"relation_id": relation["id"], "source_module_id": relation["module_id"],
               "source_attribute_sha256": relation_attribute_sha256(attrs), "status": "unsupported",
               "reason": "", "unimplemented_lifecycle": list(FLAGS),
               "runtime_verified": False, "business_accepted": False}
        coverage.append(row)
        try:
            parent = objects.get(relation["block_id"])
            if parent is None or relation["parent_id"] != parent["id"] or parent["kind"] != "Block":
                raise UnsupportedRelation("relation_must_be_directly_block_owned")
            parents = [obj for obj in objects.values() if obj["kind"] == "Block"
                       and obj["module_id"] == parent["module_id"]
                       and (obj["name"] or "").upper() == (parent["name"] or "").upper()]
            if len(parents) != 1:
                raise UnsupportedRelation("same_module_parent_block_not_unique")
            detail = attrs.get("DetailBlock", "").upper()
            children = [obj for obj in objects.values() if obj["kind"] == "Block"
                        and obj["module_id"] == parent["module_id"] and (obj["name"] or "").upper() == detail]
            if len(children) != 1:
                raise UnsupportedRelation("same_module_detail_block_not_unique")
            child = children[0]
            # Count even unsupported declarations: a second edge to the same
            # child or another incoming parent must never select a first winner.
            declared_edges.append((parent["id"], child["id"]))
            if attrs.get("RelationType", "").strip().upper() != "JOIN":
                raise UnsupportedRelation("explicit_join_relation_required")
            flags = _flags(attrs)
            pairs = parse_join_condition(attrs.get("JoinCondition"), parent["name"], child["name"],
                child_item_names=[obj["name"] or "" for obj in objects.values()
                                  if obj["kind"] == "Item" and obj["block_id"] == child["id"]])
            if any(obj["classification"] != "database" or obj["id"] not in blocks for obj in (parent, child)):
                raise UnsupportedRelation("both_database_reports_required")
            joins = []
            for p_name, c_name in pairs:
                bound = []
                for block, name in ((parent, p_name), (child, c_name)):
                    matches = [obj for obj in objects.values() if obj["kind"] == "Item"
                               and obj["block_id"] == block["id"] and (obj["name"] or "").upper() == name]
                    if len(matches) != 1:
                        raise UnsupportedRelation("relation_item_not_unique")
                    item = matches[0]
                    props = metadata[item["id"]]
                    dtype = {"CHAR": "VARCHAR2", "VARCHAR2": "VARCHAR2", "NUMBER": "NUMBER"}.get(
                        props.get("DataType", "").strip().upper())
                    if (props.get("DatabaseItem", "").strip().lower() != "true" or dtype is None
                            or props.get("Formula", "").strip()
                            or props.get("CalculateMode", "").strip().upper() not in {"", "NONE"}
                            or props.get("CalculationMode", "").strip().upper() not in {"", "NONE"}
                            or props.get("SummaryFunction", "").strip().upper() not in {"", "NONE"}):
                        raise UnsupportedRelation("direct_noncomputed_database_key_required")
                    target = targets.get(item["id"])
                    if target is None or target[0]["source_block_id"] != block["id"] or target[1]["data_type"] != dtype:
                        raise UnsupportedRelation("exact_relation_target_type_required")
                    bound.append((item, target[1], dtype))
                if bound[0][2] != bound[1][2]:
                    raise UnsupportedRelation("same_relation_key_types_required")
                joins.append({"parent_item_id": bound[0][0]["id"], "parent_column": bound[0][1]["column"],
                              "child_item_id": bound[1][0]["id"], "child_column": bound[1][1]["column"],
                              "data_type": bound[0][2]})
            operation = {"relation_id": relation["id"], "source_module_id": parent["module_id"],
                         "parent_block_id": parent["id"], "child_block_id": child["id"],
                         "source_attribute_sha256": row["source_attribute_sha256"], "join_pairs": joins,
                         "parent": _target(blocks[parent["id"]]), "child": _target(blocks[child["id"]]),
                         "source_flags": flags}
            _, projection = native._report_source(files[blocks[child["id"]]["report_file"]].decode("utf-8"), blocks[child["id"]])
            try:
                native._relation_query(operation, blocks[child["id"]], 8999, projection)
            except native.RelationRenderError:
                raise UnsupportedRelation("relation_query_length_limit") from None
            candidates.append((operation, row))
        except UnsupportedRelation as exc:
            row["reason"] = str(exc)
    incoming = Counter(child for _, child in declared_edges)
    outgoing = Counter(parent for parent, _ in declared_edges)
    graph = {}
    for parent, child in declared_edges:
        graph.setdefault(parent, set()).add(child)
    cyclic = set()
    # Every outgoing edge participates, including unsupported declarations and
    # fan-out. An iterative walk stays bounded by the source graph, not Python's
    # recursion limit; only vertices actually on a cycle are marked.
    for start in graph:
        pending, seen = list(graph[start]), set()
        while pending:
            current = pending.pop()
            if current == start:
                cyclic.add(start)
                break
            if current not in seen:
                seen.add(current)
                pending.extend(graph.get(current, ()))
    operations = []
    for operation, row in candidates:
        parent, child = operation["parent_block_id"], operation["child_block_id"]
        if incoming[child] != 1:
            row["reason"] = "ambiguous_relation_branching"
        elif parent in cyclic or child in cyclic:
            row["reason"] = "cyclic_relation_context"
        elif len(operations) >= native.MAX_RELATIONS:
            row["reason"] = "relation_page_limit"
        else:
            # Previously proven linear, fully qualified relations may also
            # establish assignment context. Wider read navigation never grants it.
            read_only = outgoing[parent] != 1
            if not read_only:
                try:
                    parse_join_condition(metadata[operation["relation_id"]]["JoinCondition"],
                                         objects[parent]["name"], objects[child]["name"])
                except UnsupportedRelation:
                    read_only = True
            row.update(status="read_navigation_planned",
                       reason=native.MANUAL_SELECTION_ONLY if read_only else "manual_read_navigation_only")
            operations.append(operation)
    plan = {"schema_version": 1, "scope": SCOPE, "source_binding": packet["source_binding"],
            "parent_zip_sha256": native._sha(raw), "source_manifest_sha256": native._sha(files[native.MANIFEST]),
            "parent_trace_sha256": native._sha(files[native.TRACE]),
            "parent_trace_canonical_sha256": native._sha(native._json(trace)), "sources": sources,
            "operations": operations, "coverage": coverage, "native_generated": False,
            "runtime_verified": False, "business_accepted": False}
    plan["plan_sha256"] = native._sha(native._json(plan))
    return plan
