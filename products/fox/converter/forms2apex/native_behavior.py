"""Finite, source-bound behavior adaptations over an immutable native package.

The caller must rebuild the plan from the original documents before rendering.
This renderer checks parent/target bindings; it does not authenticate source text
absent from that package. Output is a candidate requiring fresh SQLcl validation,
import/runtime verification and business acceptance. No external operations occur.
"""
from __future__ import annotations

from copy import deepcopy
from decimal import Decimal, InvalidOperation
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import zipfile

from . import native, native_project, numeric_expression, local_comparison

SCOPE = "fox-forms-behavior-plan-v1"
RENDERER = "fox-native-behavior-v1"
MAX_OPERATIONS = 100
_IDENT = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_PREFIX = "fox-package/behavior-"
_CALCULATIONS = {"ceil_report_column", "numeric_expression_report_column", "local_comparison_report_column"}
_BASE = {"operation_id", "kind", "source_unit_id", "source_unit_sha256", "source_chunk_id",
         "source_block_id", "source_item_id", "decode_receipt", "target"}
_ROOT = {"schema_version", "scope", "source_binding", "parent_zip_sha256",
         "source_manifest_sha256", "parent_trace_sha256", "sources", "operations",
         "coverage", "native_generated", "plan_sha256", "runtime_verified", "business_accepted",
         "code_unit_count", "adaptations", "remaining_scope"}


class BehaviorRenderError(ValueError):
    """Closed-contract diagnostic; no executable source in error messages."""


def _need(condition, code):
    if not condition:
        raise BehaviorRenderError("BEHAVIOR_" + code)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _identifier(value):
    _need(type(value) is str and _IDENT.fullmatch(value), "IDENTIFIER_INVALID")
    return value


def _archive(parent):
    raw = bytes(parent) if isinstance(parent, (bytes, bytearray)) else Path(parent).read_bytes()
    _need(len(raw) <= 32 * 1024 * 1024, "PARENT_TOO_LARGE")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = archive.infolist()
            names = [item.filename for item in infos]
            _need(len(names) == len(set(n.casefold() for n in names)), "DUPLICATE_MEMBER")
            _need(sum(i.file_size for i in infos) <= 64 * 1024 * 1024, "PARENT_EXPANSION_TOO_LARGE")
            for name in names:
                _need(not PurePosixPath(name).is_absolute() and ".." not in PurePosixPath(name).parts
                      and "\\" not in name and ":" not in name, "MEMBER_PATH_INVALID")
                _need(not name.startswith(_PREFIX), "ALREADY_ADAPTED")
            files = {item.filename: archive.read(item) for item in infos}
            comment = archive.comment
    except (zipfile.BadZipFile, RuntimeError, OSError):
        raise BehaviorRenderError("BEHAVIOR_PARENT_INVALID") from None
    _need(all(name in files for name in ("application.apx", "fox-package/source-manifest.json",
                                         "fox-package/source-to-page.json")), "PARENT_MEMBERS_MISSING")
    return raw, infos, files, comment


def _one(entries, key, value):
    matches = [entry for entry in entries if entry.get(key) == value]
    _need(len(matches) == 1, "TARGET_NOT_UNIQUE")
    return matches[0]


def _minimum(value):
    if value is None:
        return None
    _need(type(value) is str and len(value) <= 80
          and re.fullmatch(r"[+-]?[0-9]+(?:\.[0-9]+)?", value)
          and sum(c.isdigit() for c in value) <= 38,
          "MINIMUM_INVALID")
    try:
        _need(Decimal(value).is_finite(), "MINIMUM_INVALID")
    except InvalidOperation:
        raise BehaviorRenderError("BEHAVIOR_MINIMUM_INVALID") from None
    return value


def _expression_sql(operation, block, field):
    """Recheck source names, types and the exact reference-to-column relation."""
    try:
        refs = numeric_expression.validate_expression(operation["expression"])
    except numeric_expression.NumericExpressionError:
        raise BehaviorRenderError("BEHAVIOR_EXPRESSION_INVALID") from None
    _need(field["data_type"] == "NUMBER" and field["column"] == operation["target"]["output_column"],
          "EXPRESSION_OUTPUT_MISMATCH")
    expected, columns = {}, {}
    for parts in refs:
        _need(len(parts) == 1 or (type(block.get("name")) is str and parts[0] == block["name"].upper()),
              "EXPRESSION_CROSS_BLOCK")
        matches = [item for item in block["items"]
                   if type(item.get("source_name")) is str and item["source_name"].upper() == parts[-1]]
        _need(len(matches) == 1, "EXPRESSION_REFERENCE_NOT_UNIQUE")
        item = matches[0]
        _need(item["data_type"] == "NUMBER" and item["source_item_id"] != field["source_item_id"]
              and item["column"] != field["column"], "EXPRESSION_INPUT_MISMATCH")
        # An item identity must itself identify exactly one target column.
        _one(block["items"], "source_item_id", item["source_item_id"])
        _identifier(item["column"])
        expected[item["source_item_id"]] = {"source_item_id": item["source_item_id"], "column": item["column"]}
        columns[parts] = item["column"]
    _need(type(operation["input_bindings"]) is list and operation["input_bindings"] ==
          [expected[key] for key in sorted(expected)], "EXPRESSION_BINDING_MISMATCH")
    try:
        return numeric_expression.render_sql(operation["expression"], columns)
    except numeric_expression.NumericExpressionError:
        raise BehaviorRenderError("BEHAVIOR_EXPRESSION_INVALID") from None


def control_binding(files, trace, item_id):
    """Prove one source-free visible text page item against exact native trace."""
    matches = [(block, item) for block in trace["blocks"] for item in block.get("items", [])
               if item.get("source_item_id") == item_id]
    _need(len(matches) == 1, "CONTROL_TARGET_NOT_UNIQUE")
    block, item = matches[0]
    page, filename, name = block.get("page_id"), block.get("page_file"), item.get("native_item")
    _need(block.get("classification") == "control" and item.get("data_type") == "VARCHAR2"
          and item.get("widget") == "text" and item.get("database_bound") is False
          and item.get("native_item_page_id") == page and type(page) is int and 0 < page < 9999
          and type(filename) is str and filename in files, "CONTROL_TARGET_INVALID")
    _identifier(name)
    _need(name.startswith(f"P{page}_"), "CONTROL_PAGE_MISMATCH")
    _need(sum(candidate.get("native_item") == name for entry in trace["blocks"]
              for candidate in entry.get("items", [])) == 1, "CONTROL_ITEM_NOT_UNIQUE")
    text = files[filename].decode("utf-8")
    _need(text.startswith(f"page {page} (\n"), "CONTROL_PAGE_MISMATCH")
    fragments = re.findall(r"^    pageItem " + re.escape(name) + r" \(\n(.*?)^    \)", text, re.M | re.S)
    _need(len(fragments) == 1 and len(re.findall(r"\bpageItem\s+" + re.escape(name) + r"\s*\(", text)) == 1,
          "CONTROL_ITEM_NOT_UNIQUE")
    fragment = fragments[0]
    _need(fragment.count("        type: textField\n") == 1
          and not re.search(r"\b(?:source|default|computation|security|serverSideCondition|authorization)\s*\{", fragment)
          and "sessionState" not in fragment, "CONTROL_ITEM_NOT_SOURCE_FREE")
    return {"source_item_id": item_id, "source_block_id": block["source_block_id"],
            "page_item": name, "page_id": page, "page_file": filename}


def _comparison_sql(operation, block, field, files, trace):
    try:
        refs = local_comparison.validate_expression(operation["expression"])
    except local_comparison.ComparisonError:
        raise BehaviorRenderError("BEHAVIOR_COMPARISON_INVALID") from None
    _need(field["data_type"] == "NUMBER" and field["column"] == operation["target"]["output_column"],
          "COMPARISON_OUTPUT_MISMATCH")
    module = block.get("source_module_id")
    _need(type(module) is str and module, "COMPARISON_MODULE_SCOPE_MISSING")
    expected, columns = {}, {}
    for parts in refs:
        same_row = len(parts) == 1 or parts[0] == (block.get("name") or "").upper()
        if same_row:
            matches = [item for item in block["items"]
                       if (item.get("source_name") or "").upper() == parts[-1]]
            _need(len(matches) == 1, "COMPARISON_REFERENCE_NOT_UNIQUE")
            item = matches[0]
            _one(block["items"], "source_item_id", item["source_item_id"])
            _need(item["data_type"] == "VARCHAR2" and item["source_item_id"] != field["source_item_id"],
                  "COMPARISON_INPUT_MISMATCH")
            _identifier(item["column"])
            binding = {"source_item_id": item["source_item_id"], "column": item["column"]}
            target = item["column"]
        else:
            matches = [item for candidate in trace["blocks"]
                       if candidate.get("source_module_id") == module
                       and (candidate.get("name") or "").upper() == parts[0]
                       for item in candidate.get("items", []) if (item.get("source_name") or "").upper() == parts[-1]]
            _need(len(matches) == 1, "CONTROL_REFERENCE_NOT_UNIQUE")
            item = matches[0]
            binding = control_binding(files, trace, item["source_item_id"])
            target = ":" + binding["page_item"]
        expected[item["source_item_id"]] = binding
        columns[parts] = target
    _need(operation["input_bindings"] == [expected[key] for key in sorted(expected)], "COMPARISON_BINDING_MISMATCH")
    supports = operation["supporting_units"]
    _need(type(supports) is list and len(supports) == 1, "COMPARISON_HELPER_INVALID")
    support = supports[0]
    _need(type(support) is dict and set(support) == {"source_unit_id", "source_unit_sha256", "source_chunk_id",
          "source_owner_id", "module_id", "function_name", "semantic_kind", "decode_receipt"}
          and support["function_name"] == operation["expression"]["function"]
          and support["module_id"] == module
          and support["semantic_kind"] == "equality-indicator-v1"
          and all(type(support[key]) is str and support[key] for key in
                  ("source_unit_id", "source_chunk_id", "source_owner_id", "module_id"))
          and type(support["source_unit_sha256"]) is str and _SHA.fullmatch(support["source_unit_sha256"])
          and type(support["decode_receipt"]) is dict, "COMPARISON_HELPER_INVALID")
    try:
        return local_comparison.render_sql(operation["expression"], columns)
    except local_comparison.ComparisonError:
        raise BehaviorRenderError("BEHAVIOR_COMPARISON_INVALID") from None


def _validate(files, raw, value):
    _need(type(value) is dict and set(value) == _ROOT, "PLAN_FIELDS_INVALID")
    # Bound untrusted expression trees before deepcopy/canonical JSON recursion.
    _need(type(value["operations"]) is list and 1 <= len(value["operations"]) <= MAX_OPERATIONS,
          "OPERATION_COUNT_INVALID")
    for operation in value["operations"]:
        if type(operation) is dict and operation.get("kind") == "local_comparison_report_column":
            try:
                local_comparison.validate_expression(operation.get("expression"))
            except local_comparison.ComparisonError:
                raise BehaviorRenderError("BEHAVIOR_COMPARISON_INVALID") from None
        if type(operation) is dict and operation.get("kind") == "numeric_expression_report_column":
            try:
                numeric_expression.validate_expression(operation.get("expression"))
            except numeric_expression.NumericExpressionError:
                raise BehaviorRenderError("BEHAVIOR_EXPRESSION_INVALID") from None
    plan = deepcopy(value)
    _need(type(plan["schema_version"]) is int and plan["schema_version"] == 1
          and plan["scope"] == SCOPE, "PLAN_VERSION_INVALID")
    _need(plan["plan_sha256"] == _sha(_json({k: v for k, v in plan.items() if k != "plan_sha256"})),
          "PLAN_HASH_MISMATCH")
    _need(plan["runtime_verified"] is False and plan["business_accepted"] is False,
          "UNVERIFIED_SCOPE_REQUIRED")
    _need(plan["native_generated"] is False, "PLAN_ALREADY_GENERATED")
    _need(plan["parent_zip_sha256"] == _sha(raw), "PARENT_HASH_MISMATCH")
    manifest_raw, trace_raw = (files["fox-package/" + name] for name in
                               ("source-manifest.json", "source-to-page.json"))
    _need(plan["source_manifest_sha256"] == _sha(manifest_raw)
          and plan["parent_trace_sha256"] == _sha(trace_raw), "PARENT_BINDING_MISMATCH")
    manifest, trace = json.loads(manifest_raw), json.loads(trace_raw)
    _need(plan["source_binding"] == manifest["source_binding"] == trace["source_binding"],
          "SOURCE_BINDING_MISMATCH")
    _need(plan["sources"] == manifest["files"], "SOURCE_MANIFEST_MISMATCH")
    operations = plan["operations"]
    _need(type(operations) is list and 1 <= len(operations) <= MAX_OPERATIONS, "OPERATION_COUNT_INVALID")
    coverage = plan["coverage"]
    _need(type(coverage) is list, "COVERAGE_INVALID")
    _need(type(plan["code_unit_count"]) is int and plan["code_unit_count"] == len(coverage)
          and len(coverage) <= 10000, "COVERAGE_COUNT_MISMATCH")
    _need(type(plan["adaptations"]) is list
          and all(type(item) is str and len(item) <= 2000 for item in plan["adaptations"])
          and type(plan["remaining_scope"]) is str and len(plan["remaining_scope"]) <= 2000,
          "SCOPE_METADATA_INVALID")
    hashes = manifest["selected_chunk_hashes"]
    units, chunks = {}, set()
    for row in coverage:
        _need(type(row) is dict and type(row.get("source_unit_id")) is str
              and row["source_unit_id"] not in units, "COVERAGE_UNIT_INVALID")
        chunk = row.get("source_chunk_id")
        _need(type(chunk) is str and chunk not in chunks
              and type(row.get("source_unit_sha256")) is str
              and _SHA.fullmatch(row["source_unit_sha256"]), "COVERAGE_CHUNK_MISMATCH")
        _need((chunk in hashes and row["source_unit_sha256"] == hashes[chunk])
              or (chunk not in hashes and row.get("status") in {"unsupported", "missing_input"}),
              "COVERAGE_CHUNK_MISMATCH")
        _need(row.get("status") in {"planned_wired_adapted", "unsupported", "missing_input"}
              and row.get("runtime_verified") is False and row.get("business_accepted") is False,
              "COVERAGE_STATUS_INVALID")
        chunks.add(chunk)
        units[row["source_unit_id"]] = row
    _need(set(hashes) <= chunks, "COVERAGE_INCOMPLETE")
    seen_ops, seen_units, seen_targets = set(), set(), set()
    bound = []
    for operation in operations:
        _need(type(operation) is dict, "OPERATION_INVALID")
        kind = operation.get("kind")
        extras = ({"input_source_item_id"} if kind == "ceil_report_column" else
                  {"expression", "input_bindings"} if kind == "numeric_expression_report_column" else
                  {"expression", "input_bindings", "supporting_units"} if kind == "local_comparison_report_column" else
                  {"focus_source_item_id", "message", "message_call_count", "minimum"}
                  if kind == "numeric_nonzero_then_focus" else None)
        _need(extras is not None and set(operation) == _BASE | extras, "OPERATION_FIELDS_INVALID")
        oid, unit = operation["operation_id"], operation["source_unit_id"]
        _need(type(oid) is str and 1 <= len(oid) <= 100 and oid not in seen_ops
              and type(unit) is str and unit not in seen_units, "OPERATION_COLLISION")
        seen_ops.add(oid)
        seen_units.add(unit)
        _need(unit in units and units[unit]["source_chunk_id"] == operation["source_chunk_id"]
              and operation["source_chunk_id"] in hashes
              and units[unit]["source_unit_sha256"] == operation["source_unit_sha256"]
              and units[unit]["status"] == "planned_wired_adapted"
              and units[unit].get("operation_id") == oid, "SOURCE_UNIT_HASH_MISMATCH")
        _need(type(operation["decode_receipt"]) is dict, "DECODE_RECEIPT_INVALID")
        block = _one(trace["blocks"], "source_block_id", operation["source_block_id"])
        _need(block.get("classification") == "database", "DATABASE_BLOCK_REQUIRED")
        field = _one(block["items"], "source_item_id", operation["source_item_id"])
        target = operation["target"]
        base_fields = {"table", "report_file", "report_page_id"}
        expected = base_fields | ({"input_column", "output_column"} if kind == "ceil_report_column" else
                                 {"output_column"} if kind in {"numeric_expression_report_column", "local_comparison_report_column"} else
                                 {"row_id_column", "value_column", "focus_column", "value_data_type", "focus_data_type"})
        _need(type(target) is dict and set(target) == expected, "TARGET_FIELDS_INVALID")
        _need(target["table"] == block["table_name"] and target["report_file"] == block["report_file"]
              and type(target["report_page_id"]) is int
              and target["report_page_id"] == block["report_page_id"], "TARGET_BINDING_MISMATCH")
        _identifier(target["table"])
        _need(target["report_file"] in files, "TARGET_REPORT_MISSING")
        if kind == "ceil_report_column":
            source = _one(block["items"], "source_item_id", operation["input_source_item_id"])
            _need(source["data_type"] == field["data_type"] == "NUMBER"
                  and source["column"] == target["input_column"]
                  and field["column"] == target["output_column"]
                  and source["column"] != field["column"], "CEIL_BINDING_MISMATCH")
            slot = (target["report_file"], field["column"])
        elif kind == "numeric_expression_report_column":
            _expression_sql(operation, block, field)
            source = None
            slot = (target["report_file"], field["column"])
        elif kind == "local_comparison_report_column":
            _comparison_sql(operation, block, field, files, trace)
            source = None
            slot = (target["report_file"], field["column"])
        else:
            source = _one(block["items"], "source_item_id", operation["focus_source_item_id"])
            _need(field["data_type"] == target["value_data_type"] == "NUMBER"
                  and source["data_type"] == target["focus_data_type"]
                  and source["data_type"] in {"NUMBER", "VARCHAR2"}
                  and field["column"] == target["value_column"] and source["column"] == target["focus_column"]
                  and field["column"] != source["column"]
                  and block.get("synthetic_key", {}).get("column") == target["row_id_column"],
                  "NUMERIC_BINDING_MISMATCH")
            _need(type(operation["message_call_count"]) is int and operation["message_call_count"] in (1, 2),
                  "MESSAGE_COUNT_INVALID")
            message = operation["message"]
            _need(type(message) is str and 1 <= len(message) <= 1000
                  and not any(ord(c) < 32 for c in message)
                  and not any(c in message for c in "`&<>"), "MESSAGE_INVALID")
            _minimum(operation["minimum"])
            slot = (target["report_file"], "link")
        _need(slot not in seen_targets, "TARGET_COLLISION")
        seen_targets.add(slot)
        for key in expected - base_fields - {"value_data_type", "focus_data_type"}:
            _identifier(target[key])
        bound.append((operation, block, field, source))
    outputs = {op["source_item_id"] for op in operations if op["kind"] in _CALCULATIONS}
    for op in operations:
        inputs = ([op["input_source_item_id"]] if op["kind"] == "ceil_report_column" else
                  [entry["source_item_id"] for entry in op["input_bindings"]]
                  if op["kind"] in {"numeric_expression_report_column", "local_comparison_report_column"} else [])
        _need(not outputs.intersection(inputs), "COMPUTED_INPUT_UNSUPPORTED")
    supporting = {}
    for op in operations:
        for support in op.get("supporting_units", []):
            unit = support["source_unit_id"]
            _need(unit not in seen_units and unit in units and support["source_chunk_id"] in hashes
                  and hashes[support["source_chunk_id"]] == support["source_unit_sha256"]
                  and units[unit]["source_chunk_id"] == support["source_chunk_id"]
                  and units[unit]["source_unit_sha256"] == support["source_unit_sha256"]
                  and units[unit].get("source_owner_id") == support["source_owner_id"], "SUPPORTING_UNIT_MISMATCH")
            if unit in supporting:
                _need(supporting[unit][0] == support, "SUPPORTING_UNIT_MISMATCH")
            supporting.setdefault(unit, (support, []))[1].append(op["operation_id"])
    for unit, (_, callers) in supporting.items():
        _need(units[unit].get("operation_ids") == sorted(callers)
              and units[unit].get("operation_id") == sorted(callers)[0]
              and units[unit].get("reason") == "pure_local_function_inlined", "SUPPORTING_CALLER_MISMATCH")
    _need({unit for unit, row in units.items() if row["status"] == "planned_wired_adapted"} == seen_units | set(supporting),
          "COVERAGE_OPERATION_MISMATCH")
    return plan, bound


def _report(text, block):
    _need(text.startswith(f"page {block['report_page_id']} (\n"), "REPORT_PAGE_MISMATCH")
    _need(text.count("        type: interactiveReport\n") == 1
          and text.count("    region records (\n") == 1, "REPORT_REGION_UNSUPPORTED")
    source = ("        source {\n            location: localDatabase\n            type: tableView\n"
              f"            tableName: {block['table_name']}\n        }}")
    _need(text.count(source) == 1, "REPORT_SOURCE_UNSUPPORTED")
    return source


def _ceil(text, operations, block, files, trace):
    old = _report(text, block)
    replacements = {}
    for operation in operations:
        target = operation["target"]
        expression = (f"ceil({target['input_column']})" if operation["kind"] == "ceil_report_column" else
                      _comparison_sql(operation, block, _one(block["items"], "source_item_id", operation["source_item_id"]), files, trace)
                      if operation["kind"] == "local_comparison_report_column" else
                      _expression_sql(operation, block,
                                      _one(block["items"], "source_item_id", operation["source_item_id"])))
        replacements[target["output_column"]] = expression
    columns = [block["synthetic_key"]["column"]] + [i["column"] for i in block["items"] if i.get("column")]
    _need(len(columns) == len(set(columns)), "REPORT_COLUMN_COLLISION")
    for column in columns:
        _identifier(column)
        _need(text.count(f"        column {column} (\n") == 1, "REPORT_COLUMNS_MISMATCH")
    projection = [f"{replacements[column]} as {column}" if column in replacements
                  else column for column in columns]
    query = ",\n                    ".join(projection)
    _need(len(f"select {query}\nfrom {block['table_name']}") <= 32767, "REPORT_QUERY_TOO_LARGE")
    new = ("        source {\n            location: localDatabase\n            type: sqlQuery\n"
           "            sqlQuery:\n                ```sql\n"
           f"                select {query}\n                from {block['table_name']}\n"
           "                ```\n        }")
    text = text.replace(old, new, 1)
    for column in replacements:
        if f"            displayColumn {column} (\n" in text:
            continue
        anchor = "        savedReport primary (\n"
        _need(text.count(anchor) == 1, "SAVED_REPORT_UNSUPPORTED")
        position = text.index("\n        )", text.index(anchor))
        sequences = [int(v) for v in re.findall(r"^                sequence: (\d+)$", text[text.index(anchor):position], re.M)]
        fragment = f"\n            displayColumn {column} (\n                sequence: {max(sequences, default=0) + 10}\n            )"
        text = text[:position] + fragment + text[position:]
    return text


def _link(text, operation, block, page):
    _report(text, block)
    _need("        link {\n" not in text, "REPORT_LINK_EXISTS")
    key = operation["target"]["row_id_column"]
    anchor = "        column "
    position = text.index(anchor)
    fragment = f'''        link {{
            linkColumn: customTarget
            target: {{
                page: {page}
                clearCache: {page}
                items: {{
                    P{page}_{key}: "#{key}#"
                }}
            }}
            linkIcon: Validate
        }}
'''
    return text[:position] + fragment + text[position:]


def _validation(slug, sequence, expression, message):
    # Message is an inert quoted APX property, never inserted into PL/SQL.
    return f'''    validation {slug} (
        name: {slug}
        execution {{
            sequence: {sequence}
        }}
        validation {{
            type: functionBodyReturningBoolean
            plsqlFunctionBody:
                ```plsql
                if :REQUEST = 'FOX_BEHAVIOR_CONTINUE' then
                    return {expression};
                else
                    return true;
                end if;
                ```
        }}
        error {{
            errorMessage: {json.dumps(message, ensure_ascii=False)}
            displayLocation: inlineInNotification
        }}
    )
'''


def _page(operation, block, field, focus, page):
    target = operation["target"]
    key, value, destination = (target[k] for k in ("row_id_column", "value_column", "focus_column"))
    columns = [(key, "NUMBER", "Synthetic row identity", True),
               (value, "NUMBER", native_project._display(field["source_name"], "BEHAVIOR_SOURCE_LABEL_INVALID"), False),
               (destination, focus["data_type"], native_project._display(focus["source_name"], "BEHAVIOR_SOURCE_LABEL_INVALID"), False)]
    items = []
    for index, (column, dtype, label, pk) in enumerate(columns, 1):
        spec = {"name": column, "data_type": dtype, "label": label, "primary_key": pk,
                "nullable": True, "length": 4000}
        items.append(native_project._item(spec, index * 10, page))
    validations = _validation("nonzero", 10, f"nvl(:P{page}_{value}, 0) <> 0", operation["message"])
    minimum = operation["minimum"]
    if minimum is not None:
        # Null/zero belongs to the trigger-derived main validation. The separate
        # source item minimum rejects only nonzero values below the bound, so a
        # zero submit produces one notification rather than two overlapping ones.
        validations += _validation("source-minimum", 20,
            f"nvl(:P{page}_{value}, 0) = 0 or :P{page}_{value} >= {minimum}",
            f"Value must be at least {minimum} (independent source item minimum).")
    # APEX executes after-submit processes only after validations pass. The
    # fixed request condition further prevents unrelated submits causing focus.
    return f'''page {page} (
    name: Value validation only
    alias: FOX_BEHAVIOR_{page}
    title: Value validation only
    appearance {{
        pageTemplate: @/standard
        templateOptions: #DEFAULT#
    }}
    security {{
        authentication: required
        pageAccessProtection: argumentsMustHaveChecksum
    }}
    region scope (
        name: Validation scope
        type: staticContent
        source {{
            htmlCode:
                ```html
                <p>Validate this value with Continue. Values are not saved. Keyboard navigation is adapted to an explicit button; repeated Forms messages become one notification. This page does not implement the complete source workflow.</p>
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
    region record (
        name: Existing synthetic row values
        type: form
        source {{
            location: localDatabase
            type: tableView
            tableName: {target['table']}
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
{chr(10).join(items)}
    button continue (
        buttonName: FOX_BEHAVIOR_CONTINUE
        label: Continue
        layout {{
            sequence: 10
            region: @record
            slot: create
        }}
        appearance {{
            buttonTemplate: @/text
        }}
        behavior {{
            action: submitPage
            executeValidations: true
            warnOnUnsavedChanges: doNotCheck
        }}
    )
    process initialize-record (
        name: Initialize existing row
        type: formInitialization
        formRegion: @record
        execution {{
            sequence: 10
            point: beforeHeader
        }}
    )
{validations}    process focus-next-field (
        name: Focus next field after successful validation
        type: executeCode
        source {{
            plsqlCode:
                ```plsql
                apex_javascript.add_onload_code(p_code => 'apex.item("P{page}_{destination}").setFocus();');
                ```
        }}
        execution {{
            sequence: 10
            point: processing
        }}
        serverSideCondition {{
            whenButtonPressed: @continue
        }}
        successMessage {{
            successMessage: Validation passed. Values have not been saved.
        }}
    )
)
'''


def render_behavior_package(parent_zip, plan):
    """Return deterministic candidate ZIP bytes and an honest generation receipt.

    Original members retain their bytes unless an operation explicitly changes
    its bound report. Old reviews/validation are historical parent evidence and
    are never promoted to validation of the new package.
    """
    raw, infos, files, comment = _archive(parent_zip)
    normalized, bound = _validate(files, raw, plan)
    trace = json.loads(files["fox-package/source-to-page.json"])
    changes, additions, generated = {}, {}, []
    occupied = {int(m.group(1)) for name in files
                if (m := re.fullmatch(r"pages/p(\d+)-[^/]+\.apx", name))}
    # Stable free-page allocation excludes the login/system page ranges.
    candidate = 1
    for operation, block, field, focus in sorted(bound, key=lambda v: v[0]["operation_id"]):
        report = operation["target"]["report_file"]
        text = changes.get(report, files[report]).decode("utf-8")
        if operation["kind"] in _CALCULATIONS:
            result = {"report_file": report, "output_column": operation["target"]["output_column"]}
        else:
            while candidate in occupied and candidate < 9000:
                candidate += 1
            _need(candidate < 9000, "PAGE_CAPACITY_EXCEEDED")
            occupied.add(candidate)
            page = candidate
            filename = f"pages/p{page:05d}-fox_behavior_{page}.apx"
            _need(filename not in files and filename not in additions, "PAGE_COLLISION")
            text = _link(text, operation, block, page)
            additions[filename] = _page(operation, block, field, focus, page).encode("utf-8")
            result = {"report_file": report, "page_file": filename, "page_id": page,
                      "value_item": f"P{page}_{operation['target']['value_column']}",
                      "focus_item": f"P{page}_{operation['target']['focus_column']}"}
        changes[report] = text.encode("utf-8")
        generated.append({"operation_id": operation["operation_id"], "kind": operation["kind"],
                          "source_unit_id": operation["source_unit_id"],
                          "generation_status": "generated_wired_adapted", **result})
    controls = {}
    for operation, _, _, _ in bound:
        for binding in operation.get("input_bindings", []):
            if "page_item" in binding:
                controls.setdefault(binding["page_file"], {})[binding["page_item"]] = binding
    for filename, bindings in controls.items():
        text = files[filename].decode("utf-8")
        _need("button apply-control-values (" not in text and text.endswith(")\n"), "CONTROL_SUBMIT_COLLISION")
        for name in sorted(bindings):
            anchor = f"    pageItem {name} (\n"
            _need(text.count(anchor) == 1, "CONTROL_ITEM_NOT_UNIQUE")
            text = text.replace(anchor, anchor + "        sessionState {\n            storage: session\n            dataType: varchar2\n        }\n", 1)
        text = text[:-2] + '''    button apply-control-values (
        buttonName: FOX_APPLY_CONTROL_VALUES
        label: Apply control values
        layout {
            sequence: 900
            region: @controls
            slot: regionBody
        }
        appearance {
            buttonTemplate: @/text
        }
        behavior {
            action: submitPage
            executeValidations: true
            warnOnUnsavedChanges: doNotCheck
        }
    )
)
'''
        changes[filename] = text.encode("utf-8")
    # Compose all same-report calculations once; retain any validation-page link
    # already added above. Each expression reads the original input column, so
    # no unrequested chained computation or evaluation order is inferred.
    calculations = {}
    for operation, block, _, _ in bound:
        if operation["kind"] in _CALCULATIONS:
            calculations.setdefault(operation["target"]["report_file"], (block, []))[1].append(operation)
    for report, (block, operations) in calculations.items():
        changes[report] = _ceil(changes[report].decode("utf-8"), operations, block, files, trace).encode("utf-8")
    support_callers = {}
    for operation, _, _, _ in bound:
        for support in operation.get("supporting_units", []):
            support_callers.setdefault(support["source_unit_id"], (support, []))[1].append(operation["operation_id"])
    for unit, (support, callers) in sorted(support_callers.items()):
        generated.append({"kind": "local_comparison_function_inlined", "source_unit_id": unit,
                          "source_unit_sha256": support["source_unit_sha256"],
                          "source_chunk_id": support["source_chunk_id"], "caller_operation_ids": sorted(callers),
                          "generation_status": "generated_wired_adapted"})
    coverage = deepcopy(normalized["coverage"])
    for row in coverage:
        if row["status"] == "planned_wired_adapted":
            row["status"] = "generated_wired_adapted"
    receipt = {"schema_version": 1, "scope": RENDERER, "parent_zip_sha256": _sha(raw),
               "renderer_sources": {name: _sha(Path(__file__).with_name(name).read_bytes()) for name in
                                    ("native_behavior.py", "numeric_expression.py", "local_comparison.py", "native.py", "native_project.py")},
               "plan_sha256": normalized["plan_sha256"],
               "plan_artifact_sha256": _sha(_json(normalized)), "source_binding": normalized["source_binding"],
               "generated_operations": generated, "coverage": coverage, "native_generated": True,
               "changed_members": sorted(changes), "added_pages": sorted(additions),
               "validation": {"status": "pending", "passed": False,
                              "parent_validation_applies": False},
               "runtime_verified": False, "business_accepted": False,
               "source_parser_rebuild_required_at_gateway": True}
    additions[_PREFIX + "plan.json"] = _json(normalized)
    additions[_PREFIX + "receipt.json"] = _json(receipt)
    additions[_PREFIX + "README.md"] = (
        "# Generated behavior candidate\n\n"
        "Only the operations in behavior-plan.json are generated and wired with explicit web adaptations. "
        "Other coverage remains unsupported or missing input. Original package reviews and validation "
        "are preserved historical parent evidence; they do not validate these new bytes. "
        "Fresh whole-package SQLcl validation, database import/runtime tests and business acceptance "
        "remain required. The linked validation page reads existing synthetic rows and does not save "
        "values or implement the complete source workflow.\n"
    ).encode("utf-8")
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
