"""Adapt whole item query guards to manual, parent-filtered report refreshes.

The selected persisted synthetic parent replaces the Forms record buffer. This
does not implement automatic coordination, other key overrides or write events.
The assembler supplies freshly generated native relation pages; unknown or
ambiguous source/bindings remain explicit gaps. No source SQL is executed.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import json
import re

from forms2apex import native_relations
from .forms_behavior_plan import (_Parser, _tokens, _source_objects,
                                  decode_control_entities)
from .forms_relation_plan import parse_join_condition, relation_attribute_sha256
from .forms_understanding_packet import _build

RULE_ID = "fox.query.guarded-related-query"
_IDENT = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")
_SOURCE = re.compile(r"^        source \{\n            location: localDatabase\n.*?^        \}", re.M | re.S)


def _need(condition, reason):
    if not condition:
        raise ValueError(reason)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode()


def parse_guard(text):
    """Consume the entire finite IF/AND/non-null/query/ELSE NULL grammar.

    Forms XML may retain literal backslash-t export whitespace. With no string
    expressions in this grammar, decoding those tabs cannot reinterpret a
    source literal; any literal/unknown executable remainder is still rejected.
    """
    _need(type(text) is str and len(text) <= 8192, "query_guard_capacity")
    semantic, receipt = decode_control_entities(text)
    tabs = [m.start() for m in re.finditer(r"\\t", semantic)]
    semantic = semantic.replace("\\t", "\t")
    parser = _Parser(_tokens(semantic))
    parser.take("IF")
    refs = []
    while True:
        parts = parser.reference()
        parser.take("IS")
        parser.take("NOT")
        parser.take("NULL")
        refs.append(parts)
        _need(len(refs) <= 4 and parts not in refs[:-1], "query_guard_duplicate_or_capacity")
        if not parser.peek("AND"):
            break
        parser.take("AND")
    for value in ("THEN", "EXECUTE_QUERY", ";", "ELSE", "NULL", ";", "END", "IF", ";"):
        parser.take(value)
    _need(parser.pos == len(parser.tokens), "query_guard_whole_source_required")
    receipt = {**receipt, "literal_export_tab_offsets": tabs,
               "tab_rule": "literal-backslash-t-in-closed-guard-v1",
               "guard_semantic_sha256": hashlib.sha256(semantic.encode()).hexdigest()}
    return refs, receipt


def _field(item, block, props):
    p = props[item["id"]]
    dtype = {"CHAR": "VARCHAR2", "VARCHAR2": "VARCHAR2", "NUMBER": "NUMBER"}.get(
        p.get("DataType", "").strip().upper())
    _need(p.get("DatabaseItem", "").strip().lower() == "true" and dtype is not None
          and not p.get("Formula", "").strip()
          and all(p.get(k, "").strip().upper() in ("", "NONE")
                  for k in ("CalculateMode", "CalculationMode", "SummaryFunction")),
          "query_guard_direct_parent_field_required")
    fields = [f for f in block["items"] if f["source_item_id"] == item["id"]]
    _need(len(fields) == 1 and fields[0].get("database_bound") is True
          and fields[0].get("data_type") == dtype
          and _IDENT.fullmatch(fields[0].get("column", ""))
          and fields[0].get("source_name") == item["name"], "query_guard_field_target_mismatch")
    return fields[0]


def _source(text):
    matches = list(_SOURCE.finditer(text))
    _need(len(matches) == 1, "query_guard_report_source_not_unique")
    return matches[0]


def _query(match):
    found = re.fullmatch(r"        source \{\n            location: localDatabase\n"
        r"            type: sqlQuery\n            sqlQuery:\n                ```sql\n"
        r"(.*?)\n                ```\n        \}", match.group(), re.S)
    _need(found is not None, "query_guard_filtered_report_required")
    lines = found[1].splitlines()
    _need(all(line.startswith("                ") for line in lines), "query_guard_sql_shape")
    return "\n".join(line[16:] for line in lines)


def _projection(text, child):
    match = _source(text)
    cols = ["FOX_ROW_ID"] + [f["column"] for f in child["items"]]
    table = ("        source {\n            location: localDatabase\n"
             f"            type: tableView\n            tableName: {child['table_name']}\n        }}")
    if match.group() == table:
        return ", ".join(cols)
    query = _query(match)
    prefix, suffix = "select ", "\nfrom " + child["table_name"]
    _need(query.startswith(prefix) and query.endswith(suffix), "query_guard_projection_shape")
    projection = query[len(prefix):-len(suffix)]
    native_relations._projection_columns(projection, cols)
    # The native relation renderer retains projection continuation indentation
    # from the APEXlang source, then indents the complete cloned query again.
    # Reconstruct that exact representation rather than normalizing SQL text.
    return projection.replace("\n", "\n" + " " * 16)


def _incoming(child, module, objects, props):
    # Every declaration participates in ambiguity checks, even an unsupported
    # declaration. Do not select a convenient supported edge from a branch.
    relations = [o for o in objects.values() if o["kind"] == "Relation"
                 and o["module_id"] == module
                 and props[o["id"]].get("DetailBlock", "").upper() == child["name"].upper()]
    _need(len(relations) == 1, "query_guard_incoming_relation_not_unique")
    relation = relations[0]
    parent = objects.get(relation["block_id"])
    _need(parent is not None and relation["parent_id"] == parent["id"]
          and parent["kind"] == "Block" and parent["module_id"] == module,
          "query_guard_direct_parent_required")
    outgoing = [o for o in objects.values() if o["kind"] == "Relation"
                and o["block_id"] == parent["id"]]
    _need(len(outgoing) == 1, "query_guard_parent_relation_ambiguous")
    return relation, parent


def _bind(owner, refs, objects, props, trace, files):
    child = objects.get(owner["block_id"])
    _need(owner["kind"] == "Trigger" and child is not None, "query_guard_item_trigger_required")
    item = objects.get(owner["parent_id"])
    _need(item is not None and item["kind"] == "Item" and item["block_id"] == child["id"]
          and item["module_id"] == owner["module_id"], "query_guard_item_trigger_required")
    overrides = [o for o in objects.values() if o["kind"] == "Trigger"
                 and o["module_id"] == owner["module_id"] and o["id"] != owner["id"]
                 and (o["name"] or "").upper() == "KEY-EXEQRY"
                 and o["parent_id"] in (item["id"], child["id"]) ]
    _need(not overrides, "query_guard_conflicting_key_override")
    relation, parent = _incoming(child, owner["module_id"], objects, props)
    blocks = {}
    for obj in (parent, child):
        found = [b for b in trace["blocks"] if b["source_block_id"] == obj["id"]]
        _need(len(found) == 1 and found[0].get("classification") == "database"
              and found[0].get("source_module_id") == owner["module_id"]
              and found[0].get("name") == obj["name"]
              and _IDENT.fullmatch(found[0].get("table_name", "")), "query_guard_native_block_mismatch")
        blocks[obj["id"]] = found[0]
    plan = json.loads(files["fox-package/relation-plan.json"])
    receipt = json.loads(files["fox-package/relation-receipt.json"])
    _need(plan.get("source_binding") == receipt.get("source_binding") == trace["source_binding"],
          "query_guard_relation_source_mismatch")
    ops = [o for o in native_relations.context_operations(plan) if o["relation_id"] == relation["id"]]
    rendered = [o for o in receipt["generated_operations"] if o["relation_id"] == relation["id"]]
    _need(len(ops) == len(rendered) == 1, "query_guard_generated_relation_required")
    op, rendered = ops[0], rendered[0]
    _need(all(o.get("parent_block_id") == parent["id"] and o.get("child_block_id") == child["id"]
              and o.get("source_module_id") == owner["module_id"] for o in (op, rendered))
          and op.get("source_attribute_sha256") == relation_attribute_sha256(props[relation["id"]]),
          "query_guard_relation_identity_mismatch")
    attrs = props[relation["id"]]
    _need(attrs.get("RelationType", "").upper() == "JOIN", "query_guard_explicit_join_required")
    pairs = parse_join_condition(attrs.get("JoinCondition"), parent["name"], child["name"])
    joins = []
    for p_name, c_name in pairs:
        bound = []
        for obj, name in ((parent, p_name), (child, c_name)):
            found = [i for i in objects.values() if i["kind"] == "Item"
                     and i["block_id"] == obj["id"] and (i["name"] or "").upper() == name]
            _need(len(found) == 1, "query_guard_join_item_not_unique")
            bound.append((found[0], _field(found[0], blocks[obj["id"]], props)))
        (p, pf), (c, cf) = bound
        _need(pf["data_type"] == cf["data_type"], "query_guard_join_type_mismatch")
        joins.append({"parent_item_id": p["id"], "parent_column": pf["column"],
                      "child_item_id": c["id"], "child_column": cf["column"], "data_type": pf["data_type"]})
    _need(op["join_pairs"] == joins, "query_guard_exact_relation_pairs_required")
    for role, obj in (("parent", parent), ("child", child)):
        b = blocks[obj["id"]]
        _need(op[role] == {"table": b["table_name"], "report_file": b["report_file"],
              "report_page_id": b["report_page_id"], "row_id_column": "FOX_ROW_ID"},
              "query_guard_relation_target_mismatch")
    bindings = []
    for parts in refs:
        found = [i for i in objects.values() if i["kind"] == "Item"
                 and i["module_id"] == owner["module_id"] and (i["name"] or "").upper() == parts[-1]
                 and (len(parts) == 1 or (objects[i["block_id"]]["name"] or "").upper() == parts[0])]
        _need(len(found) == 1 and found[0]["block_id"] == parent["id"],
              "query_guard_exact_direct_parent_reference_required")
        field = _field(found[0], blocks[parent["id"]], props)
        bindings.append({"source_reference": parts, "source_item_id": found[0]["id"], "column": field["column"]})
    _need(len({b["source_item_id"] for b in bindings}) == len(bindings), "query_guard_duplicate_field")
    page = rendered["page_id"]
    _need(type(page) is int and 0 < page < 9000 and rendered["parent_item"] == f"P{page}_PARENT_ID",
          "query_guard_parent_identity_mismatch")
    text = files[rendered["page_file"]].decode().replace("\r\n", "\n")
    _need(text.startswith(f"page {page} (\n") and text.endswith(")\n")
          and "        pageAccessProtection: argumentsMustHaveChecksum\n" in text,
          "query_guard_page_security_mismatch")
    parent_item = f'''    pageItem P{page}_PARENT_ID (
        type: hidden
        layout {{
            sequence: 10
            region: @records
            slot: regionBody
        }}
        sessionState {{
            storage: session
            dataType: number
        }}
        security {{
            sessionStateProtection: checksumRequiredSessionLevel
        }}
    )'''
    _need(text.count(f"    pageItem P{page}_PARENT_ID (\n") == 1 and parent_item in text,
          "query_guard_persistent_protected_parent_required")
    projection = _projection(files[blocks[child["id"]]["report_file"]].decode().replace("\r\n", "\n"), blocks[child["id"]])
    match = _source(text)
    expected = native_relations._relation_query(op, blocks[child["id"]], page, projection)
    _need(_query(match) == expected, "query_guard_filtered_query_changed")
    return parent, op, rendered, bindings, text, match, expected


def _render(bound):
    parent, relation, rendered, bindings, text, match, query = bound
    page = rendered["page_id"]
    guards = [f"fox_parent.{b['column']} is not null" for b in bindings]
    # Strengthen the same EXISTS; do not replace any join, projection or bind.
    guarded = query[:-1] + "\nand " + "\nand ".join(guards) + ")"
    source = match.group().replace("\n".join("                " + line for line in query.splitlines()),
                                   "\n".join("                " + line for line in guarded.splitlines()))
    text = text[:match.start()] + source + text[match.end():]
    condition = (f"select 1 from {relation['parent']['table']} fox_parent\n"
                 f"where fox_parent.FOX_ROW_ID = :P{page}_PARENT_ID\nand " + "\nand ".join(guards))
    _need(len(guarded.encode()) <= 32767 and len(condition.encode()) <= 4000,
          "query_guard_native_sql_capacity")
    button = f'''    button guarded-execute-query (
        buttonName: FOX_EXECUTE_QUERY
        label: Execute query
        layout {{
            sequence: 130
            region: @records
            slot: rightOfInteractiveReportSearchBar
        }}
        appearance {{
            buttonTemplate: @/text
        }}
        behavior {{
            action: redirectThisApp
            target: {{
                page: {page}
            }}
        }}
        serverSideCondition {{
            type: rowsReturned
            sqlQuery:
                ```sql
{chr(10).join('                ' + line for line in condition.splitlines())}
                ```
        }}
    )
    region guarded-query-scope (
        name: Execute query scope
        type: staticContent
        source {{
            htmlCode: "Execute query refreshes related saved rows only when every original parent-field guard is satisfied. Open from the parent row first. The selected parent stays in this session; reopen its link to change it. Other key overrides, unsaved Forms buffers and automatic coordination remain unconverted."
        }}
        layout {{
            sequence: 6
            slot: body
        }}
        appearance {{
            template: @/standard
            templateOptions: #DEFAULT#
        }}
    )
'''
    _need("    button guarded-execute-query (" not in text, "query_guard_already_applied")
    return (text[:-2] + button + ")\n").encode(), condition, guarded


def apply_guarded_queries(documents, packet, chunks, trace, files):
    """Return copied members and an honest generated/gap receipt; never mutate inputs."""
    fresh, original_chunks = _build(documents)
    _need(packet.get("source_binding") == fresh["source_binding"] == trace.get("source_binding"),
          "QUERY_GUARD_SOURCE_BINDING_MISMATCH")
    _need(json.loads(files["fox-package/source-to-page.json"]) == trace, "QUERY_GUARD_TRACE_MISMATCH")
    for name, raw in documents:
        _need(files.get("fox-package/sources/" + name) == raw, "QUERY_GUARD_ORIGINAL_CHANGED")
    objects, props = _source_objects(documents, fresh)
    available = {c["code_unit_id"]: c for c in chunks}
    originals = {c["code_unit_id"]: c for c in original_chunks}
    result, operations, gaps, candidates = dict(files), [], [], []
    for source in fresh["sources"]:
        for unit in source["facts"]["code_units"]:
            owner = objects[unit["owner_id"]]
            if (unit["source_attribute"] != "TriggerText" or owner["kind"] != "Trigger"
                    or (owner["name"] or "").upper() != "KEY-EXEQRY"):
                continue
            try:
                _need(available.get(unit["id"]) == originals.get(unit["id"]), "query_guard_chunk_mismatch")
                refs, decode = parse_guard(originals[unit["id"]]["text"])
                bound = _bind(owner, refs, objects, props, trace, files)
                candidates.append((unit, owner, decode, bound))
            except (ValueError, KeyError, TypeError, UnicodeError) as exc:
                reason = str(exc) if isinstance(exc, ValueError) else "query_guard_context_missing"
                gaps.append({"source_unit_id": unit["id"], "reason": reason})
    pages = Counter(c[3][2]["page_file"] for c in candidates)
    for unit, owner, decode, bound in candidates:
        if pages[bound[2]["page_file"]] != 1:
            gaps.append({"source_unit_id": unit["id"], "reason": "query_guard_multiple_item_actions_for_one_report"})
            continue
        try:
            rendered, condition, query = _render(bound)
        except ValueError as exc:
            gaps.append({"source_unit_id": unit["id"], "reason": str(exc)})
            continue
        parent, relation, target, bindings, *_ = bound
        result[target["page_file"]] = rendered
        operations.append({"source_unit_id": unit["id"], "source_unit_sha256": unit["sha256"],
            "source_owner_id": owner["id"], "source_module_id": owner["module_id"],
            "operation_id": "guarded-query-" + hashlib.sha256(_canonical([unit["id"], target["page_id"]])).hexdigest()[:20],
            "kind": "guarded_related_query", "rule_id": RULE_ID, "decode_receipt": decode,
            "relation_id": relation["relation_id"], "parent_block_id": parent["id"],
            "guard_bindings": bindings, "target": deepcopy(target),
            "button_condition_sql": condition, "guarded_query_sql": query,
            "generation_status": "generated_wired_adapted",
            "adaptation": "Manual refresh of the existing related report over a persisted selected synthetic parent. All source non-null guard fields are checked on the server. Initial related navigation may also query; automatic Forms coordination, other key overrides and unsaved record buffers are not implemented. No submit, request override, cache clear or session assignment is generated.",
            "runtime_verified": False, "business_accepted": False})
    receipt = {"schema_version": 1, "scope": "fox-guarded-related-query-v1",
               "source_binding": fresh["source_binding"], "generated_operations": operations,
               "gaps": gaps, "runtime_verified": False, "business_accepted": False}
    receipt["receipt_sha256"] = hashlib.sha256(_canonical(receipt)).hexdigest()
    return result, receipt
