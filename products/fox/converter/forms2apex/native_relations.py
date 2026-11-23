"""Standalone closed-plan native read navigation over immutable synthetic reports.

The gateway must rebuild source semantics from original documents. This renderer
checks the closed plan and exact parent/trace/DDL/original bindings; its hashes do
not authenticate a caller-authored plan. No database or external calls occur.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

SCOPE = "fox-forms-relation-plan-v1"
RENDERER = "fox-native-relations-v1"
MAX_RELATIONS = 50
MANUAL_SELECTION_ONLY = "manual_navigation_without_assignment_context"


def context_operations(plan):
    """Only pre-existing relation shapes may authorize other Forms event adapters."""
    manual = {row["relation_id"] for row in plan.get("coverage", ())
              if row.get("reason") == MANUAL_SELECTION_ONLY}
    return [op for op in plan.get("operations", ()) if op["relation_id"] not in manual]
MAX_PAGE_ID = 8999
MANIFEST = "fox-package/source-manifest.json"
TRACE = "fox-package/source-to-page.json"
_PREFIX = "fox-package/relation-"
_IDENT = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_FLAGS = {"AutoQuery", "Deferred", "DeleteRecord", "PreventMasterlessOperations"}
_ROOT = {"schema_version", "scope", "source_binding", "parent_zip_sha256", "source_manifest_sha256",
         "parent_trace_sha256", "parent_trace_canonical_sha256", "sources", "operations", "coverage", "native_generated",
         "runtime_verified", "business_accepted", "plan_sha256"}
_OP = {"relation_id", "source_module_id", "parent_block_id", "child_block_id", "source_attribute_sha256",
       "join_pairs", "parent", "child", "source_flags"}
_TARGET = {"table", "report_file", "report_page_id", "row_id_column"}
_PAIR = {"parent_item_id", "parent_column", "child_item_id", "child_column", "data_type"}
_COVERAGE = {"relation_id", "source_module_id", "source_attribute_sha256", "status", "reason",
             "unimplemented_lifecycle", "runtime_verified", "business_accepted"}


class RelationRenderError(ValueError):
    """Bounded contract diagnostic without executable source values."""


def _need(condition, code):
    if not condition:
        raise RelationRenderError("RELATION_" + code)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _read_json(raw):
    def unique(pairs):
        value = {}
        for key, entry in pairs:
            _need(key not in value, "DUPLICATE_JSON_KEY")
            value[key] = entry
        return value
    return json.loads(raw, object_pairs_hook=unique)


def _identifier(value):
    _need(type(value) is str and _IDENT.fullmatch(value), "IDENTIFIER_INVALID")
    return value


def _archive(parent):
    raw = parent if type(parent) is bytes else Path(parent).read_bytes()
    _need(0 < len(raw) <= 32 * 1024 * 1024, "PARENT_SIZE_INVALID")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            _need(len(infos) <= 4096 and len(names) == len({name.casefold() for name in names}), "DUPLICATE_MEMBER")
            _need(sum(i.file_size for i in infos) <= 64 * 1024 * 1024, "PARENT_EXPANSION_TOO_LARGE")
            for info in infos:
                path = PurePosixPath(info.filename)
                _need(not path.is_absolute() and ".." not in path.parts and "\\" not in info.filename
                      and ":" not in info.filename and not stat.S_ISLNK(info.external_attr >> 16), "MEMBER_PATH_INVALID")
                _need(not info.filename.startswith(_PREFIX), "ALREADY_ADAPTED")
            files = {info.filename: archive.read(info) for info in infos}
            return raw, infos, files, archive.comment
    except (zipfile.BadZipFile, OSError, RuntimeError):
        raise RelationRenderError("RELATION_PARENT_INVALID") from None


def _originals(files, sources):
    _need(type(sources) is list and 1 <= len(sources) <= 4, "SOURCES_INVALID")
    digests = {_sha(data): len(data) for name, data in files.items() if name.lower().endswith(".xml")}
    seen = set()
    for row in sources:
        _need(type(row) is dict and set(row) == {"name", "sha256", "bytes"}, "SOURCE_FIELDS_INVALID")
        name = row["name"]
        _need(type(name) is str and 0 < len(name) <= 180 and name.lower().endswith(".xml")
              and not any(c in name for c in "/\\:") and ".." not in name
              and not any(ord(c) < 32 for c in name) and name.casefold() not in seen, "SOURCE_NAME_INVALID")
        seen.add(name.casefold())
        _need(type(row["sha256"]) is str and _SHA.fullmatch(row["sha256"])
              and type(row["bytes"]) is int and row["bytes"] > 0
              and digests.get(row["sha256"]) == row["bytes"], "ORIGINAL_SOURCE_MISSING_OR_CHANGED")


def _projection_columns(projection, columns, *, row_alias=None):
    """Check generated projection slots without treating literal text as SQL."""
    code = re.sub(r"'(?:[^']|'')*'", " ", projection)
    _need("'" not in code and not any(token in code for token in (";", "--", "/*", "*/"))
          and not re.search(r"\b(select|from|where|union|insert|update|delete|merge|commit)\b", code, re.I),
          "REPORT_QUERY_SHAPE_UNSUPPORTED")
    pieces, depth, quoted, start, index = [], 0, False, 0, 0
    while index < len(projection):
        char = projection[index]
        if char == "'":
            if quoted and projection[index:index + 2] == "''":
                index += 2
                continue
            quoted = not quoted
        elif not quoted:
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                _need(depth >= 0, "REPORT_PROJECTION_INVALID")
            elif char == "," and depth == 0:
                pieces.append(projection[start:index].strip())
                start = index + 1
        index += 1
    _need(not quoted and depth == 0, "REPORT_PROJECTION_INVALID")
    pieces.append(projection[start:].strip())
    _need(len(pieces) == len(columns), "REPORT_PROJECTION_COLUMNS_MISMATCH")
    for piece, column in zip(pieces, columns, strict=True):
        _need(piece == column or (row_alias is not None and piece == f"{row_alias}.{column}") or re.fullmatch(r".+\s+as\s+" + re.escape(column), piece, re.I | re.S),
              "REPORT_PROJECTION_COLUMNS_MISMATCH")
    return pieces


def _report_source(text, block):
    """Locate one bounded generated report source, retaining its SQL projection."""
    _need(text.startswith(f"page {block['report_page_id']} (\n")
          and text.count("    region records (\n") == 1
          and text.count("        type: interactiveReport\n") == 1, "REPORT_SHAPE_INVALID")
    _need(not re.search(r"^    (?:process|button|pageItem)\b", text, re.M)
          and "type: form\n" not in text, "REPORT_NOT_READ_ONLY")
    matches = list(re.finditer(r"^        source \{\n.*?^        \}", text, re.M | re.S))
    _need(len(matches) == 1, "REPORT_SOURCE_NOT_UNIQUE")
    match = matches[0]
    table_source = ("        source {\n            location: localDatabase\n            type: tableView\n"
                    f"            tableName: {block['table_name']}\n        }}")
    columns = [block["synthetic_key"]["column"]] + [item["column"] for item in block["items"]]
    if match.group() == table_source:
        projection = ", ".join(columns)
    else:
        query = re.fullmatch(r"        source \{\n            location: localDatabase\n            type: sqlQuery\n"
                             r"            sqlQuery:\n                ```sql\n                select (.*?)\n"
                             r"                from " + re.escape(block["table_name"]) + r"\n                ```\n        \}",
                             match.group(), re.S)
        _need(query is not None, "REPORT_QUERY_SHAPE_UNSUPPORTED")
        projection = query[1]
        _need(len(projection) <= 32767 and "```" not in projection,
              "REPORT_QUERY_SHAPE_UNSUPPORTED")
        _projection_columns(projection, columns)
    _need(len(columns) == len(set(columns)) and all(text.count(f"        column {c} (\n") == 1 for c in columns),
          "REPORT_COLUMNS_MISMATCH")
    return match, projection


def _targets(files):
    try:
        manifest, trace = _read_json(files[MANIFEST]), _read_json(files[TRACE])
        schema = files["fox-package/supporting-schema.sql"].decode("utf-8")
        _need(type(trace.get("blocks")) is list, "BLOCK_TRACE_MISSING")
        blocks, fields, tables, reports, pages = {}, {}, set(), set(), set()
        for block in trace["blocks"]:
            if block.get("classification") != "database":
                continue
            block_id = block.get("source_block_id")
            table, report, page = block.get("table_name"), block.get("report_file"), block.get("report_page_id")
            _identifier(table)
            _need(type(block_id) is str and block_id not in blocks and table not in tables
                  and type(report) is str and report in files and report not in reports
                  and type(page) is int and 0 < page <= MAX_PAGE_ID and page not in pages
                  and block.get("native_component", "report") == "report", "BLOCK_TARGET_INVALID")
            declarations = re.findall(r"\bCREATE TABLE " + re.escape(table) + r" \(\s*(.*?)\n\);", schema, re.S)
            _need(len(declarations) == 1, "DDL_TABLE_MISMATCH")
            columns = re.findall(r"^\s*([A-Z][A-Z0-9_]*)\s+(NUMBER|VARCHAR2|DATE)\b", declarations[0], re.M)
            ddl = dict(columns)
            _need(len(columns) == len(ddl), "DDL_COLUMN_COLLISION")
            key = block.get("synthetic_key")
            _need(type(key) is dict and key.get("column") == "FOX_ROW_ID" and key.get("source_derived") is False
                  and key.get("source_item_id") is None and ddl.get("FOX_ROW_ID") == "NUMBER", "SYNTHETIC_IDENTITY_MISSING")
            text = files[report].decode("utf-8")
            _report_source(text, block)
            seen_columns = {"FOX_ROW_ID"}
            for item in block["items"]:
                column, item_id = item.get("column"), item.get("source_item_id")
                _identifier(column)
                _need(type(item_id) is str and item_id not in fields and column not in seen_columns
                      and ddl.get(column) == item.get("data_type") and item.get("data_type") in {"NUMBER", "VARCHAR2", "DATE"}
                      and item.get("report_page_id") == page, "FIELD_TARGET_INVALID")
                seen_columns.add(column)
                fields[item_id] = (block, item)
            blocks[block_id] = block
            tables.add(table)
            reports.add(report)
            pages.add(page)
        return manifest, trace, blocks, fields
    except (KeyError, TypeError, UnicodeError, json.JSONDecodeError):
        raise RelationRenderError("RELATION_PARENT_PROVENANCE_INVALID") from None


def _validate(raw, files, plan):
    _need(type(plan) is dict and set(plan) == _ROOT, "PLAN_FIELDS_INVALID")
    _need(type(plan["schema_version"]) is int and plan["schema_version"] == 1 and plan["scope"] == SCOPE,
          "PLAN_SCOPE_INVALID")
    for key in ("native_generated", "runtime_verified", "business_accepted"):
        _need(plan[key] is False, "PLAN_CLAIMS_INVALID")
    _need(plan["plan_sha256"] == _sha(_json({k: v for k, v in plan.items() if k != "plan_sha256"})), "PLAN_HASH_MISMATCH")
    _need(plan["parent_zip_sha256"] == _sha(raw)
          and plan["source_manifest_sha256"] == _sha(files[MANIFEST])
          and plan["parent_trace_sha256"] == _sha(files[TRACE]), "PARENT_BINDING_MISMATCH")
    manifest, trace, blocks, fields = _targets(files)
    _need(plan["parent_trace_canonical_sha256"] == _sha(_json(trace)), "CANONICAL_TRACE_BINDING_MISMATCH")
    _need(plan["source_binding"] == manifest.get("source_binding") == trace.get("source_binding")
          and plan["sources"] == manifest.get("files"), "SOURCE_BINDING_MISMATCH")
    _originals(files, plan["sources"])
    _need(type(plan["operations"]) is list and len(plan["operations"]) <= MAX_RELATIONS
          and type(plan["coverage"]) is list and len(plan["coverage"]) <= 4096, "PLAN_LIMIT_INVALID")
    coverage = {}
    for row in plan["coverage"]:
        _need(type(row) is dict and set(row) == _COVERAGE and type(row["relation_id"]) is str
              and row["relation_id"] not in coverage and row["runtime_verified"] is False
              and row["business_accepted"] is False and row["unimplemented_lifecycle"] ==
              ["AutoQuery", "Deferred", "DeleteRecord", "PreventMasterlessOperations"]
              and row["status"] in {"read_navigation_planned", "unsupported"}
              and type(row["reason"]) is str and 0 < len(row["reason"]) <= 128, "COVERAGE_INVALID")
        coverage[row["relation_id"]] = row
    edges, children, ids, bound = set(), set(), set(), []
    for op in plan["operations"]:
        _need(type(op) is dict and set(op) == _OP, "OPERATION_FIELDS_INVALID")
        relation = op["relation_id"]
        _need(type(relation) is str and relation not in ids and relation in coverage, "RELATION_IDENTITY_INVALID")
        ids.add(relation)
        row = coverage[relation]
        _need(row["status"] == "read_navigation_planned" and row["source_module_id"] == op["source_module_id"]
              and row["source_attribute_sha256"] == op["source_attribute_sha256"]
              and type(op["source_attribute_sha256"]) is str and _SHA.fullmatch(op["source_attribute_sha256"]), "SOURCE_PROOF_MISMATCH")
        p, c = op["parent_block_id"], op["child_block_id"]
        _need(p in blocks and c in blocks and p != c and (p, c) not in edges and c not in children, "GRAPH_AMBIGUOUS")
        edges.add((p, c))
        children.add(c)
        for role, block_id in (("parent", p), ("child", c)):
            target, block = op[role], blocks[block_id]
            _need(type(target) is dict and set(target) == _TARGET and target == {
                "table": block["table_name"], "report_file": block["report_file"],
                "report_page_id": block["report_page_id"], "row_id_column": block["synthetic_key"]["column"]}
                and block.get("source_module_id") == op["source_module_id"], "TARGET_BINDING_MISMATCH")
        _need(type(op["source_flags"]) is dict and set(op["source_flags"]) == _FLAGS, "FLAGS_INVALID")
        for key, value in op["source_flags"].items():
            valid = {"cascading", "isolated", "non isolated"} if key == "DeleteRecord" else {"true", "false"}
            _need(value is None or type(value) is str and value.strip().lower() in valid, "FLAGS_INVALID")
        _need(type(op["join_pairs"]) is list and 1 <= len(op["join_pairs"]) <= 4, "JOIN_LIMIT_INVALID")
        ps, cs = set(), set()
        for pair in op["join_pairs"]:
            _need(type(pair) is dict and set(pair) == _PAIR and pair["data_type"] in {"NUMBER", "VARCHAR2"}, "JOIN_FIELDS_INVALID")
            for role, block_id, seen in (("parent", p, ps), ("child", c, cs)):
                item_id, column = pair[role + "_item_id"], pair[role + "_column"]
                _need(type(item_id) is str and item_id in fields and item_id not in seen, "JOIN_ITEM_INVALID")
                seen.add(item_id)
                block, item = fields[item_id]
                _need(block["source_block_id"] == block_id and item["column"] == column
                      and item["data_type"] == pair["data_type"], "JOIN_BINDING_MISMATCH")
        bound.append((op, blocks[p], blocks[c]))
    _need(ids == {key for key, row in coverage.items() if row["status"] == "read_navigation_planned"}, "COVERAGE_OPERATION_MISMATCH")
    graph = {}
    for p, c in edges:
        graph.setdefault(p, []).append(c)
    visited, active = set(), set()
    def visit(node):
        _need(node not in active, "GRAPH_CYCLE")
        if node in visited:
            return
        active.add(node)
        for child in graph.get(node, []):
            visit(child)
        active.remove(node)
        visited.add(node)
    for start in graph:
        visit(start)
    return bound


def _link(text, target_page, label="View related records"):
    pattern = r"^        column FOX_ROW_ID \(\n.*?^        \)"
    matches = list(re.finditer(pattern, text, re.M | re.S))
    _need(len(matches) == 1, "ROW_LINK_COLUMN_MISSING")
    match = matches[0]
    column = match.group()
    _need(column.count("            type: plainText\n") == 1 and "            link {\n" not in column,
          "ROW_LINK_COLUMN_UNSUPPORTED")
    column = column.replace("            type: plainText\n", "            type: link\n", 1)
    link = f'''            link {{
                target: {{
                    page: {target_page}
                    clearCache: {target_page}
                    items: {{
                        P{target_page}_PARENT_ID: "#FOX_ROW_ID#"
                    }}
                }}
                linkText: {label}
            }}
'''
    column = column[:-len("        )")] + link + "        )"
    text = text[:match.start()] + column + text[match.end():]
    anchor = "        savedReport primary (\n"
    _need(text.count(anchor) == 1, "SAVED_REPORT_UNSUPPORTED")
    start = text.index(anchor)
    end = text.index("\n        )", start)
    if "            displayColumn FOX_ROW_ID (\n" not in text[start:end]:
        fragment = "\n            displayColumn FOX_ROW_ID (\n                sequence: 1\n            )"
        text = text[:end] + fragment + text[end:]
    return text


def _child_label(child, target):
    name = child.get("name")
    if (type(name) is not str or not 0 < len(name) <= 128
            or any(ord(c) < 32 or c in "&#<>" for c in name)):
        return f"View related report {target}"
    return f"View {name} (page {target})"


def _selector(outgoing, destinations, page):
    """One signed row context, with an explicit action for every child report.

    Labels are trace metadata, never APEX substitutions or HTML. Buttons use
    native redirect targets so APEX signs both the selector and child links.
    """
    buttons = []
    for sequence, (op, _, child) in enumerate(outgoing, 1):
        target = destinations[op["relation_id"]]
        label = json.dumps(_child_label(child, target), ensure_ascii=False)
        buttons.append(f'''    button child-{sequence} (
        buttonName: FOX_RELATED_{sequence}
        label: {label}
        layout {{
            sequence: {sequence * 10}
            region: @related-actions
            slot: regionBody
        }}
        appearance {{
            buttonTemplate: @/text
        }}
        behavior {{
            action: redirectThisApp
            target: {{
                page: {target}
                clearCache: {target}
                items: {{
                    P{target}_PARENT_ID: "&P{page}_PARENT_ID."
                }}
            }}
        }}
    )
''')
    return f'''page {page} (
    name: Choose related records
    alias: FOX_RELATION_SELECTOR_{page}
    title: Choose related records
    appearance {{
        pageTemplate: @/standard
        templateOptions: #DEFAULT#
    }}
    security {{
        authentication: required
        pageAccessProtection: argumentsMustHaveChecksum
    }}
    region related-actions (
        name: Choose a detail report
        type: staticContent
        source {{
            htmlCode: <p>Choose a detail report for the selected parent row. Each report checks every join key against that stored parent. Without a matching parent no related rows are selected. This is manual read-only navigation; automatic query, copying, saving and delete lifecycle remain unconverted.</p>
        }}
        layout {{
            sequence: 10
            slot: body
        }}
        appearance {{
            template: @/standard
            templateOptions: #DEFAULT#
        }}
    )
    pageItem P{page}_PARENT_ID (
        type: hidden
        layout {{
            sequence: 10
            region: @related-actions
            slot: regionBody
        }}
        sessionState {{
            storage: request
            dataType: number
        }}
        security {{
            sessionStateProtection: checksumRequiredSessionLevel
        }}
    )
{''.join(buttons)})
'''.encode("utf-8")


def _relation_query(operation, child, page, projection):
    predicates = [f"fox_parent.{pair['parent_column']} = fox_child.{pair['child_column']}" for pair in operation["join_pairs"]]
    # The inner report projection is retained byte for byte: calculated columns
    # and binds keep their existing meaning. Ordinary outer columns are qualified
    # for unambiguous parent/child table names, including equal item names.
    columns = [child["synthetic_key"]["column"]] + [item["column"] for item in child["items"]]
    query = ("select " + ", ".join("fox_child." + col for col in columns)
             + f"\nfrom (select {projection}\nfrom {child['table_name']}) fox_child"
             + f"\nwhere exists (select 1 from {operation['parent']['table']} fox_parent"
             + f"\nwhere fox_parent.FOX_ROW_ID = :P{page}_PARENT_ID"
             + "\nand " + "\nand ".join(predicates) + ")")
    _need(len(query) <= 32767, "QUERY_TOO_LARGE")
    return query


def _clone(text, operation, child, page, *, request_context=False):
    match, projection = _report_source(text, child)
    query = _relation_query(operation, child, page, projection)
    source = ("        source {\n            location: localDatabase\n            type: sqlQuery\n"
              "            sqlQuery:\n                ```sql\n"
              + "\n".join("                " + line for line in query.splitlines())
              + "\n                ```\n"
              + (f"            pageItemsToSubmit: P{page}_PARENT_ID\n" if request_context else "")
              + "        }")
    text = text[:match.start()] + source + text[match.end():]
    text = text.replace(f"page {child['report_page_id']} (\n", f"page {page} (\n", 1)
    text, count = re.subn(r"^    alias: .*?$", f"    alias: FOX_RELATION_{page}", text, count=1, flags=re.M)
    _need(count == 1 and "        pageAccessProtection: argumentsMustHaveChecksum\n" in text, "PAGE_SECURITY_UNSUPPORTED")
    _need(text.endswith(")\n"), "PAGE_END_UNSUPPORTED")
    item = f'''    pageItem P{page}_PARENT_ID (
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
    )
    region relation-scope (
        name: Related records scope
        type: staticContent
        source {{
            htmlCode:
                ```html
                <p>Read-only related records. Open this page from a parent row. Without established parent context no rows are selected. A selected parent is retained for this session, including report refreshes; revisiting without a new link may retain the last selection. Manual navigation adapts the source join. Automatic query, record buffers, save rules and delete lifecycle remain unconverted.</p>
                ```
        }}
        layout {{
            sequence: 5
            slot: body
        }}
        appearance {{
            template: @/standard
            templateOptions: #DEFAULT#
        }}
    )
'''
    if request_context:
        item = item.replace("            storage: session\n", "            storage: request\n", 1)
        item = item.replace("A selected parent is retained for this session, including report refreshes; revisiting without a new link may retain the last selection.",
                            "The report submits this tab's selected parent when it refreshes. Select a parent row to switch context.")
    return text[:-2] + item + ")\n"


def render_relation_package(parent_zip, plan):
    """Return deterministic ZIP and generation receipt, requiring fresh gates."""
    raw, infos, files, comment = _archive(parent_zip)
    bound = _validate(raw, files, plan)
    occupied, aliases = set(), set()
    for name, data in files.items():
        if match := re.fullmatch(r"pages/p(\d+)-[^/]+\.apx", name):
            number = int(match[1])
            _need(number not in occupied and data.startswith(f"page {number} (\n".encode()), "PAGE_IDENTITY_INVALID")
            occupied.add(number)
            aliases.update(match[1].strip('"').upper() for match in
                           re.finditer(r"^    alias: (.+)$", data.decode("utf-8"), re.M))
    additions, changes, destinations = {}, {}, {}
    page = 1
    def allocate():
        nonlocal page
        while page in occupied and page <= MAX_PAGE_ID:
            page += 1
        _need(page <= MAX_PAGE_ID, "PAGE_CAPACITY_EXCEEDED")
        occupied.add(page)
        return page
    outgoing = {}
    for entry in bound:
        outgoing.setdefault(entry[0]["parent_block_id"], []).append(entry)
    for op, _, _ in sorted(bound, key=lambda row: row[0]["relation_id"]):
        destinations[op["relation_id"]] = allocate()
    selectors = {}
    for block_id, entries in sorted(outgoing.items()):
        if len(entries) > 1:
            selector_page = allocate()
            _need(f"FOX_RELATION_SELECTOR_{selector_page}" not in aliases, "PAGE_ALIAS_COLLISION")
            selectors[block_id] = selector_page
            filename = f"pages/p{selector_page:05d}-fox_relation_selector_{selector_page}.apx"
            additions[filename] = _selector(sorted(entries, key=lambda row: row[0]["relation_id"]),
                                            destinations, selector_page)

    def link_outgoing(text, block_id):
        entries = outgoing.get(block_id, [])
        if not entries:
            return text
        if block_id in selectors:
            return _link(text, selectors[block_id], "Choose related records")
        return _link(text, destinations[entries[0][0]["relation_id"]])
    # Add outgoing links to base reports before cloning: every intermediate
    # context clone inherits its own outgoing relation link and validation link.
    for block_id, entries in outgoing.items():
        parent = entries[0][1]
        report = parent["report_file"]
        text = files[report].decode("utf-8")
        _need("        authentication: required\n" in text
              and "        pageAccessProtection: argumentsMustHaveChecksum\n" in text, "PAGE_SECURITY_UNSUPPORTED")
        changes[report] = link_outgoing(text, block_id).encode("utf-8")
    generated = []
    for op, _, child in bound:
        page = destinations[op["relation_id"]]
        _need(f"FOX_RELATION_{page}" not in aliases, "PAGE_ALIAS_COLLISION")
        report = child["report_file"]
        text = files[report].decode("utf-8")
        cloned = _clone(text, op, child, page, request_context=op["parent_block_id"] in selectors)
        _need("        authentication: required\n" in cloned, "PAGE_SECURITY_UNSUPPORTED")
        cloned = link_outgoing(cloned, op["child_block_id"])
        filename = f"pages/p{page:05d}-fox_relation_{page}.apx"
        _need(filename not in files, "PAGE_COLLISION")
        additions[filename] = cloned.encode("utf-8")
        generated.append({"relation_id": op["relation_id"], "generation_status": "read_navigation_generated",
                          "source_module_id": op["source_module_id"], "parent_block_id": op["parent_block_id"],
                          "child_block_id": op["child_block_id"], "parent_report_file": op["parent"]["report_file"],
                          "page_file": filename, "page_id": page, "parent_item": f"P{page}_PARENT_ID",
                          "write_lifecycle": False})
        if op["parent_block_id"] in selectors:
            selector_page = selectors[op["parent_block_id"]]
            siblings = sorted(outgoing[op["parent_block_id"]], key=lambda row: row[0]["relation_id"])
            sequence = next(i for i, entry in enumerate(siblings, 1) if entry[0]["relation_id"] == op["relation_id"])
            generated[-1].update(selector_page_id=selector_page,
                                 selector_page_file=f"pages/p{selector_page:05d}-fox_relation_selector_{selector_page}.apx",
                                 selector_button=f"child-{sequence}", selector_label=_child_label(child, page),
                                 selection_storage="request")
    coverage = deepcopy(plan["coverage"])
    for row in coverage:
        if row["status"] == "read_navigation_planned":
            row["status"] = "read_navigation_generated"
    receipt = {"schema_version": 1, "scope": RENDERER, "source_binding": plan["source_binding"],
               "parent_zip_sha256": _sha(raw), "plan_sha256": plan["plan_sha256"],
               "plan_artifact_sha256": _sha(_json(plan)), "renderer_sha256": _sha(Path(__file__).read_bytes()),
               "generated_operations": generated, "coverage": coverage, "native_generated": True,
               "changed_members": sorted(changes), "added_pages": sorted(additions),
               "validation": {"status": "pending", "passed": False, "parent_validation_applies": False},
               "source_parser_rebuild_required_at_gateway": True, "write_lifecycle": False,
               "runtime_verified": False, "business_accepted": False}
    additions[_PREFIX + "plan.json"] = _json(plan)
    additions[_PREFIX + "receipt.json"] = _json(receipt)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.comment = comment
        for info in infos:
            archive.writestr(info, changes.get(info.filename, files[info.filename]))
        for name, data in sorted(additions.items()):
            info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, data)
    result = output.getvalue()
    return result, {**receipt, "output_zip_sha256": _sha(result), "output_bytes": len(result)}
