"""Finite record-entry assignments over explicitly selected synthetic records.

This adapter has its own session result provider. It reads stored synthetic
values, not the live Forms buffer, lookup-page outputs or the draft editor.
Only a complete block-owned entry assignment AST is wired here. No customer
table is written and no other event or local program unit is claimed.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re

from forms2apex import native_policy_rules
from forms2apex.native_buffer import _expand_groups
from .forms_behavior_plan import _source_objects
from .forms_policy_plan import build_policy_plan
from .forms_relation_plan import parse_join_condition, relation_attribute_sha256, _flags
from .forms_understanding_packet import _build

RULE_ID = "fox.policy.selected-record-entry"
_IDENT = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")


def _need(value, reason):
    if not value:
        raise ValueError("ENTRY_" + reason)


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _lit(value):
    _need(type(value) is str and not any(c in value for c in "&`")
          and all(c.isprintable() and (not c.isspace() or c == " ") for c in value), "LITERAL_CONTEXT")
    return "'" + value.replace("'", "''") + "'"


def _one(rows, reason):
    _need(len(rows) == 1, reason)
    return rows[0]


def _body(nodes, variables, targets):
    """Render only the already source-bound policy expression/assignment AST."""
    def expr(node):
        kind = node["kind"]
        if kind == "field":
            return variables[node["ref"]]
        if kind == "literal":
            if node["data_type"] == "NULL":
                return "NULL"
            if node["data_type"] == "NUMBER":
                _need(re.fullmatch(r"[+-]?[0-9]+(?:\.[0-9]+)?", node["value"]), "NUMBER_LITERAL")
                return node["value"]
            return _lit(node["value"])
        if kind == "not":
            return "(NOT " + expr(node["value"]) + ")"
        if kind in ("is_null", "is_not_null"):
            return "(" + expr(node["value"]) + (" IS NULL)" if kind == "is_null" else " IS NOT NULL)")
        _need(kind in ("eq", "ne", "and", "or"), "EXPRESSION_KIND")
        return "(" + expr(node["left"]) + " " + {"eq": "=", "ne": "<>", "and": "AND", "or": "OR"}[kind] + " " + expr(node["right"]) + ")"

    lines = []
    for node in nodes:
        if node["kind"] == "if":
            lines += ["IF " + expr(node["condition"]) + " THEN", _body(node["body"], variables, targets), "END IF;"]
        elif node["kind"] == "assign":
            targets.add(node["target"]["ref"])
            lines.append(variables[node["target"]["ref"]] + " := " + expr(node["value"]) + ";")
        else:
            # Inlining a caller would overclaim the callee and other effects.
            raise ValueError("ENTRY_ASSIGNMENTS_ONLY")
    return "\n".join(lines)


def _block(block_id, objects, trace, files):
    source = objects[block_id]
    b = _one([b for b in trace["blocks"] if b["source_block_id"] == block_id], "BLOCK_NOT_UNIQUE")
    _need(source["kind"] == "Block" and source["classification"] == b.get("classification") == "database"
          and b.get("name") == source["name"] and b.get("source_module_id") == source["module_id"]
          and _IDENT.fullmatch(b.get("table_name", "")) and b.get("report_file") in files
          and type(b.get("report_page_id")) is int
          and b.get("synthetic_key", {}).get("column") == "FOX_ROW_ID"
          and b["synthetic_key"].get("source_derived") is False
          and b["synthetic_key"].get("source_item_id") is None,
          "BLOCK_TARGET")
    schema = files["fox-package/supporting-schema.sql"].decode()
    ddl = _one(re.findall(r"\bCREATE TABLE " + re.escape(b["table_name"]) + r" \(\s*(.*?)\n\);", schema, re.S), "DDL_TABLE")
    columns = re.findall(r"^\s*([A-Z][A-Z0-9_]*)\s+(NUMBER|VARCHAR2|DATE)\b", ddl, re.M)
    _need(len(dict(columns)) == len(columns) and dict(columns).get("FOX_ROW_ID") == "NUMBER", "DDL_COLUMNS")
    for field in b["items"]:
        _need(_IDENT.fullmatch(field.get("column", ""))
              and dict(columns).get(field["column"]) == field["data_type"], "DDL_FIELD")
    return b


def _chain(op, objects, props, trace, files):
    """Prove one incoming chain without inferring row identity from its keys."""
    owner = objects[op["source_owner_id"]]
    _need(owner["kind"] == "Trigger" and owner["parent_id"] == owner["block_id"]
          and op["source_parent_id"] == owner["block_id"], "BLOCK_OWNED_TRIGGER_REQUIRED")
    path, edges = [owner["block_id"]], []
    _need(op["fields"] and all(f["binding_kind"] == "source_item" for f in op["fields"].values()), "STORED_SOURCE_FIELDS_REQUIRED")
    required = {f["source_block_id"] for f in op["fields"].values()}
    plan = json.loads(files.get("fox-package/relation-plan.json", b"{}"))
    receipt = json.loads(files.get("fox-package/relation-receipt.json", b"{}"))
    while not required.issubset(path):
        _need(len(path) < 8, "ANCESTOR_CAPACITY")
        child = objects[path[-1]]
        declarations = [o for o in objects.values() if o["kind"] == "Relation" and o["module_id"] == owner["module_id"]
                        and props[o["id"]].get("DetailBlock", "").upper() == child["name"].upper()]
        rel = _one(declarations, "INCOMING_RELATION_NOT_UNIQUE")
        parent = objects.get(rel["block_id"])
        _need(parent is not None and parent["kind"] == "Block" and rel["parent_id"] == parent["id"]
              and parent["module_id"] == owner["module_id"] and parent["id"] not in path, "ANCESTOR_GRAPH")
        _need(len([r for r in objects.values() if r["kind"] == "Relation" and r["block_id"] == parent["id"]]) == 1,
              "OUTGOING_RELATION_NOT_UNIQUE")
        _need(plan.get("source_binding") == receipt.get("source_binding") == trace["source_binding"], "RELATION_BINDING")
        edge = _one([e for e in plan.get("operations", []) if e["relation_id"] == rel["id"]], "RELATION_NOT_PROVED")
        rendered = _one([e for e in receipt.get("generated_operations", []) if e["relation_id"] == rel["id"]], "RELATION_NOT_RENDERED")
        attrs = props[rel["id"]]
        _need(attrs.get("RelationType", "").upper() == "JOIN", "JOIN_REQUIRED")
        _flags(attrs)
        pairs = parse_join_condition(attrs.get("JoinCondition"), parent["name"], child["name"])
        joins = []
        for p_name, c_name in pairs:
            bound = []
            for source, name in ((parent, p_name), (child, c_name)):
                item = _one([o for o in objects.values() if o["kind"] == "Item" and o["block_id"] == source["id"]
                             and (o["name"] or "").upper() == name], "JOIN_ITEM_NOT_UNIQUE")
                attr = props[item["id"]]
                dtype = {"CHAR": "VARCHAR2", "VARCHAR2": "VARCHAR2", "NUMBER": "NUMBER"}.get(attr.get("DataType", "").upper())
                _need(attr.get("DatabaseItem", "").lower() == "true" and dtype is not None
                      and not attr.get("Formula", "").strip()
                      and all(attr.get(k, "").strip().upper() in ("", "NONE") for k in
                              ("CalculateMode", "CalculationMode", "SummaryFunction")), "DIRECT_JOIN_FIELD_REQUIRED")
                block = _block(source["id"], objects, trace, files)
                field = _one([f for f in block["items"] if f["source_item_id"] == item["id"]], "JOIN_TARGET_NOT_UNIQUE")
                _need(field["source_name"] == item["name"] and field["data_type"] == dtype, "JOIN_TARGET_TYPE")
                bound.append((item["id"], field["column"], dtype))
            p, c = bound
            _need(p[2] == c[2], "JOIN_TYPE")
            joins.append(dict(parent_item_id=p[0], parent_column=p[1], child_item_id=c[0], child_column=c[1], data_type=p[2]))
        _need(edge.get("join_pairs") == joins and edge.get("source_attribute_sha256") == relation_attribute_sha256(attrs), "EXACT_RELATION_REQUIRED")
        for value in (edge, rendered):
            _need(value.get("parent_block_id") == parent["id"] and value.get("child_block_id") == child["id"]
                  and value.get("source_module_id") == owner["module_id"], "RELATION_IDENTITY")
        path.append(parent["id"])
        edges.append(edge)
    path.reverse()
    edges.reverse()
    return [_block(b, objects, trace, files) for b in path], edges


def _selection(blocks, edges, page, *, complete=False, fields=None):
    """No aggregate/first-row selection: every chosen ancestor is an exact ID."""
    index = {b["source_block_id"]: i for i, b in enumerate(blocks)}
    current = len(blocks) - 1
    if fields is not None:
        projections = [f"r{index[f['source_block_id']]}.{f['column']}" for f in fields]
    else:
        projections = [f"r{current}.FOX_ROW_ID"]
        projections += [f"r{current}.{f['column']}" for f in blocks[-1]["items"]]
        projections += [f"r{i}.FOX_ROW_ID as FOX_CONTEXT_{i}" for i in range(current)]
    query = "select " + ", ".join(projections) + "\nfrom " + ", ".join(f"{b['table_name']} r{i}" for i, b in enumerate(blocks))
    conditions = [f"r{i}.FOX_ROW_ID = :P{page}_ID{i}" for i in range(len(blocks) if complete else current)]
    for i, edge in enumerate(edges):
        conditions += [f"r{i}.{p['parent_column']} = r{i+1}.{p['child_column']}" for p in edge["join_pairs"]]
    if conditions:
        query += "\nwhere " + "\nand ".join(conditions)
    _need(len(query) <= 32767, "QUERY_CAPACITY")
    return query


def _hidden(page, index):
    return f"""    pageItem P{page}_ID{index} (
        type: hidden
        layout {{ sequence: {index+1}
            region: @records
            slot: regionBody }}
        sessionState {{ storage: session
            dataType: number }}
        security {{ sessionStateProtection: checksumRequiredSessionLevel }}
    )
"""


def _shell(page, title, body):
    return _expand_groups(f"""page {page} (
    name: {json.dumps(title)}
    alias: FOX_ENTRY_{page}
    title: {json.dumps(title)}
    appearance {{ pageTemplate: @/standard
        templateOptions: #DEFAULT# }}
    security {{ authentication: required
        pageAccessProtection: argumentsMustHaveChecksum }}
{body})
""")


def _chooser(page, next_page, blocks, edges):
    query = _selection(blocks, edges, page)
    current = len(blocks)-1
    names = [("FOX_ROW_ID", "NUMBER", "Select record")]
    names += [(f["column"], f["data_type"], f["source_name"]) for f in blocks[-1]["items"]]
    names += [(f"FOX_CONTEXT_{i}", "NUMBER", "Selected ancestor identity") for i in range(current)]
    # Source names are JSON quoted in APEXlang, never inserted as executable text.
    columns = ""
    for n, (name, datatype, label) in enumerate(names, 1):
        link = ""
        if name == "FOX_ROW_ID":
            values = [f'                        P{next_page}_ID{i}: "#FOX_CONTEXT_{i}#"' for i in range(current)]
            values.append(f'                        P{next_page}_ID{current}: "#FOX_ROW_ID#"')
            link = f"""            link {{
                target: {{
                    page: {next_page}
                    clearCache: {next_page}
                    items: {{
{chr(10).join(values)}
                    }}
                }}
                linkText: Select record
            }}
"""
        columns += f"""        column {name} (
            type: {"link" if link else "plainText"}
            heading {{ heading: {json.dumps(label)} }}
            layout {{ sequence: {n*10} }}
            source {{ dataType: {"NUMBER" if datatype == "NUMBER" else "DATE" if datatype == "DATE" else "STRING"} }}
            security {{ escapeSpecialChars: true }}
{link}        )
"""
    display = "".join(f"            displayColumn {n} (\n                sequence: {i*10}\n            )\n" for i, (n, _, _) in enumerate(names[:9], 1))
    body = f"""    region records (
        name: Select record entry context
        type: interactiveReport
        source {{
            location: localDatabase
            type: sqlQuery
            sqlQuery:
                ```sql
{chr(10).join('                '+s for s in query.splitlines())}
                ```
        }}
        layout {{ sequence: 10
            slot: body }}
        appearance {{ template: @/interactive-report
            templateOptions: #DEFAULT# }}
        searchBar {{ includeSearchBar: true
            searchField: true }}
{columns}        savedReport primary (
            visibility: primaryDefault
            view {{ default: report
                rowsPerPage: 15 }}
{display}        )
    )
""" + "".join(_hidden(page, i) for i in range(current))
    return _shell(page, "Select record entry context", body), query


def _result(page, op, blocks, edges, variables, targets, code):
    fields = list(op["fields"].values())
    selected_sql = _selection(blocks, edges, page, complete=True, fields=fields)
    select_into = selected_sql.replace("\nfrom ", "\ninto " + ", ".join(variables[f["source_item_id"]] for f in fields) + "\nfrom ", 1) + ";"
    collection = "FOX_ENT_" + hashlib.sha256(op["operation_id"].encode()).hexdigest()[:20].upper()
    declarations = []
    for key, field in op["fields"].items():
        dtype = "NUMBER"
        if field["data_type"] == "VARCHAR2":
            length = field.get("source_maximum_length")
            _need(type(length) is str and length.isdigit() and 1 <= int(length) <= 4000, "EXPLICIT_FIELD_SIZE_REQUIRED")
            dtype = f"VARCHAR2({int(length)} CHAR)"
        declarations.append(variables[key] + " " + dtype + ";")
    target_keys = sorted(targets)
    chars = [k for k in target_keys if op["fields"][k]["data_type"] == "VARCHAR2"]
    numbers = [k for k in target_keys if op["fields"][k]["data_type"] == "NUMBER"]
    _need(len(chars) <= 48 and len(numbers) <= 5, "TARGET_CAPACITY")
    slots = {key: f"c{i:03}" for i, key in enumerate(chars, 2)}
    slots.update({key: f"n{i:03}" for i, key in enumerate(numbers, 1)})
    columns = ["seq_id"] + [slots[k] for k in target_keys]
    args = [f"p_{slots[k]} => {variables[k]}" for k in target_keys]
    key = " || '/' || ".join(f"to_char(:P{page}_ID{i},'TM9')" for i in range(len(blocks)))
    sql = ("declare\n" + "\n".join(declarations) + "\nl_seq number;\nl_key varchar2(4000);\nbegin\n"
           + select_into + "\nl_key := " + key + ";\n"
           + "l_seq := null;\nfor saved in (select " + ", ".join(columns)
           + f"\nfrom apex_collections where collection_name = '{collection}' and c001 = l_key) loop\n"
           + "if l_seq is not null then raise_application_error(-20002,'Selected record session result is ambiguous.'); end if;\n"
           + "l_seq := saved.seq_id;\n" + "\n".join(variables[k] + " := saved." + slots[k] + ";" for k in target_keys)
           + "\nend loop;\n" + code + "\n"
           + "\n".join(f"if lengthb({variables[k]}) > 4000 then raise_application_error(-20003,'Selected record result exceeds session capacity.'); end if;" for k in chars) + "\n"
           + f"if not apex_collection.collection_exists('{collection}') then\napex_collection.create_collection('{collection}');\nend if;\n"
           + f"if l_seq is null then\nl_seq := apex_collection.add_member(p_collection_name => '{collection}', p_c001 => l_key, " + ", ".join(args) + ");\n"
           + f"else\napex_collection.update_member(p_collection_name => '{collection}', p_seq => l_seq, p_c001 => l_key, " + ", ".join(args) + ");\nend if;\n"
           + "\n".join(f":P{page}_VALUE{i} := {variables[k]};" for i, k in enumerate(target_keys, 1))
           + "\n" + "\n".join(f":P{page}_SELECTED{i} := :P{page}_ID{i};" for i in range(len(blocks)))
           + "\nexception when no_data_found then\nraise_application_error(-20001,'Selected record context is missing or no longer matches.');\nend;")
    items = "".join(_hidden(page, i) for i in range(len(blocks)))
    for i, block in enumerate(blocks):
        items += f"""    pageItem P{page}_SELECTED{i} (
        type: displayOnly
        label {{ label: {json.dumps(block['name'] + ' - selected synthetic row identity')} }}
        layout {{ sequence: {50+i}
            region: @records
            slot: regionBody }}
        sessionState {{ storage: session
            dataType: number }}
        security {{ sessionStateProtection: restricted }}
    )
"""
    for i, key in enumerate(target_keys, 1):
        items += f"""    pageItem P{page}_VALUE{i} (
        type: displayOnly
        label {{ label: {json.dumps(op['fields'][key]['source_item_name'] + ' - selected record session result')} }}
        layout {{ sequence: {100+i}
            region: @records
            slot: regionBody }}
        sessionState {{ storage: session
            dataType: {"number" if key in numbers else "varchar2"} }}
        security {{ sessionStateProtection: restricted }}
    )
"""
    body = f"""    region records (
        name: Selected record session result
        type: staticContent
        source {{
            htmlCode:
                ```html
                <p>Explicit entry into the selected synthetic record. Inputs are stored synthetic values; lookup-page outputs and draft edits are not shared. Results remain in this session for this exact record and ancestor selection. False or NULL conditions preserve the previous value. No customer record is saved. Other Forms actions do not invoke this adapter.</p>
                ```
        }}
        layout {{ sequence: 10
            slot: body }}
        appearance {{ template: @/standard
            templateOptions: #DEFAULT# }}
    )
{items}    process selected-record-entry (
        name: Apply selected record entry assignments
        type: executeCode
        source {{
            plsqlCode:
                ```plsql
{chr(10).join('                '+s for s in sql.splitlines())}
                ```
        }}
        execution {{ sequence: 10
            point: beforeHeader }}
    )
"""
    return _shell(page, "Selected record session result", body), selected_sql, sql, collection, slots


def apply_record_entries(documents, packet, chunks, trace, members):
    """Return new files/receipt; the assembler owns ledger and technical gates."""
    actual, actual_chunks = _build(documents)
    # The assembler annotates selection_status for the UI. Source authority is
    # the canonical source binding/content, never that presentation state.
    _need(actual["source_binding"] == packet.get("source_binding") and actual["sources"] == packet.get("sources")
          and actual_chunks == chunks and trace.get("source_binding") == packet["source_binding"], "SOURCE_BINDING")
    manifest = json.loads(members["fox-package/source-manifest.json"])
    _need(manifest.get("source_binding") == packet["source_binding"]
          and manifest.get("files") == [{k: s["source"][k] for k in ("name", "sha256", "bytes")} for s in actual["sources"]]
          and manifest.get("selected_chunk_hashes") == {c["id"]: c["sha256"] for c in actual_chunks}, "MANIFEST_BINDING")
    _need(json.loads(members["fox-package/source-to-page.json"]) == trace, "STORED_TRACE")
    for name, raw in documents:
        _need(members.get("fox-package/sources/" + name) == raw, "ORIGINAL_SOURCE")
    policy = build_policy_plan(documents, trace)
    sql, review = native_policy_rules.render_policy_code(policy)
    _need(json.loads(members["fox-package/policy-plan.json"]) == policy
          and json.loads(members["fox-package/policy-receipt.json"]) == review
          and members[native_policy_rules.CODE_MEMBER] == sql.encode(), "POLICY_PROOF")
    objects, props = _source_objects(documents, packet)
    files, generated, gaps = dict(members), [], []
    occupied = {int(m[1]) for path in files if (m := re.fullmatch(r"pages/p(\d+)-[^/]+\.apx", path))}
    candidates = [o for o in policy["operations"] if (o.get("source_event") or "").upper() == "WHEN-NEW-RECORD-INSTANCE"]
    for op in candidates:
        try:
            variables = {key: f"l_f{i}" for i, key in enumerate(op["fields"], 1)}
            targets = set()
            code = _body(op["body"], variables, targets)
            _need(targets and not op["local_calls"] and not op["property_targets"], "COMPLETE_ASSIGNMENT_EVENT_REQUIRED")
            owner = objects[op["source_owner_id"]]
            _need(all(op["fields"][k]["source_block_id"] == owner["block_id"] for k in targets), "SAME_BLOCK_TARGET_REQUIRED")
            blocks, edges = _chain(op, objects, props, trace, files)
            pages = []
            for _ in range(len(blocks)+1):
                page = next((p for p in range(8200, 8900) if p not in occupied and p not in pages), None)
                _need(page is not None, "PAGE_CAPACITY")
                pages.append(page)
            additions, chooser_sql = {}, []
            for i, block in enumerate(blocks):
                text, query = _chooser(pages[i], pages[i+1], blocks[:i+1], edges[:i])
                additions[f"pages/p{pages[i]:05d}-fox_entry_{pages[i]}.apx"] = text.encode()
                chooser_sql.append(query)
            text, selected_sql, process, collection, slots = _result(pages[-1], op, blocks, edges, variables, targets, code)
            result_path = f"pages/p{pages[-1]:05d}-fox_entry_{pages[-1]}.apx"
            additions[result_path] = text.encode()
            report = blocks[-1]["report_file"]
            original = files[report].decode()
            _need(original.endswith(")\n") and "    region records (\n" in original, "ENTRY_REPORT_SHAPE")
            button = _expand_groups(f"""    button record-entry-{pages[0]} (
        buttonName: FOX_ENTRY_{pages[0]}
        label: Select record entry context
        layout {{ sequence: {pages[0]}
            region: @records
            slot: rightOfInteractiveReportSearchBar }}
        appearance {{ buttonTemplate: @/text }}
        behavior {{
            action: redirectThisApp
            target: {{ page: {pages[0]}
                clearCache: {pages[0]} }}
        }}
    )
""")
            files[report] = (original[:-2] + button + ")\n").encode()
            files.update(additions)
            occupied.update(pages)
            generated.append({"kind": "selected_record_entry_assignment", "rule_id": RULE_ID,
                **{k: deepcopy(op[k]) for k in ("operation_id", "source_unit_id", "source_unit_sha256", "source_module_id", "source_owner_id", "decode_receipt", "body", "fields")},
                "policy_plan_sha256": policy["plan_sha256"], "phase": "entered_selected_record",
                "generation_status": "generated_wired_adapted", "target": {"page_id": pages[-1], "page_file": result_path},
                "entry_report_file": report, "chooser_pages": pages[:-1], "chooser_sql": chooser_sql,
                "selected_record_sql": selected_sql, "process_plsql": process,
                "path_block_ids": [b["source_block_id"] for b in blocks], "relation_ids": [e["relation_id"] for e in edges],
                "collection_name": collection, "result_slots": slots, "target_field_ids": sorted(targets),
                "adaptation": "Explicit selected-record session adaptation; stored synthetic values only. Lookup outputs and draft buffers are not shared. Other Forms actions do not invoke this adapter.",
                "null_policy": "oracle_three_valued_conditions_preserve_prior_no_else_values",
                "customer_table_writes": False, "oracle_compiled": False, "runtime_verified": False, "business_accepted": False})
        except ValueError as exc:
            gaps.append({"source_unit_id": op["source_unit_id"], "reason": str(exc), "generation_status": "unsupported"})
    return files, {"scope": "fox-selected-record-entry-v1", "source_binding": packet["source_binding"],
                   "generated_operations": generated, "gaps": gaps, "runtime_verified": False, "business_accepted": False}
