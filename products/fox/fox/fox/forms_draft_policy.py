"""Enforce finite module property policies on the native session draft provider.

This is a partial effect adapter, never a whole Forms event conversion. Current
stored synthetic parent values are read again after locking its row. Submitted
items, cached approval flags and other session collections grant no permission.
"""
from __future__ import annotations

from copy import deepcopy
import json
import re

from forms2apex import native_buffer, native_policy_rules
from forms2apex.record_buffer import validate_buffer_plan
from .forms_policy_plan import build_policy_plan
from .forms_understanding_packet import _build

SCOPE = "fox-parent-draft-policy-v1"
_IDENT = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")
_MESSAGE = ("Read only: the selected parent's current source policy does not allow "
            "draft creation or changes. Return to the parent or related records report "
            "to view records. No draft changes were retained.")
_UNRESOLVED = ("Read only: this source policy cannot be safely evaluated for the selected "
               "parent. Return to the parent or related records report to view records. "
               "No draft changes were retained.")


def _need(value, reason):
    if not value:
        raise ValueError("DRAFT_POLICY_" + reason)


def _literal(value):
    _need(type(value) is str and len(value) <= 4000 and not any(c in value for c in "&`")
          and all(c.isprintable() and (not c.isspace() or c == " ") for c in value), "LITERAL")
    return "'" + value.replace("'", "''") + "'"


def _expression(node, fields):
    kind = node["kind"]
    if kind == "field":
        return fields[node["ref"]]["column"]
    if kind == "literal":
        if node["data_type"] == "NULL":
            return "NULL"
        if node["data_type"] == "NUMBER":
            _need(re.fullmatch(r"[+-]?[0-9]+(?:\.[0-9]+)?", node["value"]), "NUMBER")
            return node["value"]
        return _literal(node["value"])
    if kind == "not":
        return "(NOT " + _expression(node["value"], fields) + ")"
    if kind in ("is_null", "is_not_null"):
        return "(" + _expression(node["value"], fields) + (" IS NULL)" if kind == "is_null" else " IS NOT NULL)")
    _need(kind in ("eq", "ne", "and", "or"), "EXPRESSION")
    left, right = _expression(node["left"], fields), _expression(node["right"], fields)
    # Match the existing draft provider's explicit binary VARCHAR2 contract.
    if kind in ("eq", "ne") and "VARCHAR2" in (node["left"]["data_type"], node["right"]["data_type"]):
        left = "(" + left + " COLLATE BINARY)"
    return "(" + left + " " + {"eq": "=", "ne": "<>", "and": "AND", "or": "OR"}[kind] + " " + right + ")"


def _derive(op, buffer, trace, catalog):
    """Symbolically execute complete property/IF/local-call AST, in source order."""
    parent_id, child_id = buffer["relation"]["parent_block_id"], buffer["relation"]["child_block_id"]
    parent = next(b for b in trace["blocks"] if b["source_block_id"] == parent_id)
    _need(parent.get("table_name") == buffer["relation"]["parent"]["table"]
          and _IDENT.fullmatch(parent["table_name"]), "PARENT_TARGET")
    editable = {f["source_item_id"] for f in buffer["key_bindings"] if not f.get("parent_copy")}

    def relevant(node):
        target = op["property_targets"][node["target_id"]]
        return ((target["source_kind"] == "Block" and target["source_id"] == child_id
                 and node["property"] in ("INSERT_ALLOWED", "UPDATE_ALLOWED"))
                or (target["source_kind"] == "Item" and target["source_id"] in editable
                    and node["property"] in ("ENABLED", "INSERT_ALLOWED", "UPDATE_ALLOWED")))

    def flatten(nodes):
        result = []
        for node in nodes:
            _need(node["kind"] in ("if", "local_call", "property"), "COMPLETE_PROPERTY_BODY_REQUIRED")
            result.extend(flatten(node["body"]) if node["kind"] in ("if", "local_call") else [node])
        return result

    properties = flatten(op["body"])
    if not any(relevant(node) for node in properties):
        return None, [], [], set()
    for key, field in op["fields"].items():
        matches = [f for f in parent["items"] if f["source_item_id"] == key]
        _need(field["binding_kind"] == "source_item" and field["source_block_id"] == parent_id
              and field["source_database_item"] is True and len(matches) == 1
              and field["column"] == matches[0].get("column")
              and field["data_type"] == matches[0].get("data_type")
              and _IDENT.fullmatch(field["column"] or ""), "CURRENT_STORED_PARENT_FIELD_REQUIRED")
    states, enforced, omitted, contributing = {}, {}, {}, set()
    # Explicit static restrictions survive a block-level grant unless the
    # corresponding item property is itself changed by this source event.
    for item_id in {child_id} | editable:
        props = catalog[item_id]["metadata"]
        for name, prop in (("InsertAllowed", "INSERT_ALLOWED"), ("UpdateAllowed", "UPDATE_ALLOWED"), ("Enabled", "ENABLED")):
            if name == "Enabled" and item_id == child_id:
                continue
            value = props.get(name, "").strip().lower()
            _need(value in ("", "true", "false"), "STATIC_PROPERTY_UNRESOLVED")
            if value:
                states[(item_id, prop)] = "1" if value == "true" else "0"

    def walk(nodes, inherited=None, calls=()):
        for node in nodes:
            kind = node["kind"]
            if kind == "local_call":
                walk(node["body"], inherited, calls + (node["source_unit_id"],))
            elif kind == "if":
                condition = _expression(node["condition"], op["fields"])
                walk(node["body"], condition if inherited is None else "(" + inherited + " AND " + condition + ")", calls)
            elif kind == "property":
                target = op["property_targets"][node["target_id"]]
                key = (node["target_id"], node["property"])
                effect = {"target_id": key[0], "property": key[1], "source_name": target["source_name"]}
                if relevant(node):
                    contributing.update(calls)
                    enforced[key] = effect
                    value = "1" if node["value"] else "0"
                    # Unknown initial state stays NULL, which denies permission.
                    states[key] = value if inherited is None else f"CASE WHEN {inherited} THEN {value} ELSE {states.get(key, 'NULL')} END"
                else:
                    omitted[key] = {**effect, "reason": "outside_session_draft_create_update_provider"}
            else:
                raise ValueError("DRAFT_POLICY_COMPLETE_PROPERTY_BODY_REQUIRED")
    walk(op["body"])
    _need(all((child_id, prop) in states for prop in ("INSERT_ALLOWED", "UPDATE_ALLOWED")),
          "COMPLETE_CHILD_CREATE_UPDATE_POLICY_REQUIRED")
    # Constant TRUE restrictions add no condition; retaining them would waste
    # the finite APEX source field and obscure an otherwise identical gate.
    conditions = sorted(set(states.values()) - {"1"})
    # CASE ELSE denies NULL as well as FALSE, without inventing property defaults.
    allowed = " AND ".join("(" + state + ")=1" for state in conditions)
    sql = ("0" if "0" in conditions else "1" if not conditions else conditions[0]
           if len(conditions) == 1 else "CASE WHEN " + allowed + " THEN 1 ELSE 0 END")
    _need(len(sql.encode()) <= 2048, "EXPRESSION_CAPACITY")
    return sql, list(enforced.values()), list(omitted.values()), contributing


def _compact(code):
    """Compact trusted generated code only; quoted literals remain byte-identical.

    This does not relax SQLcl's validation limit. It avoids charging APEX's 3950
    byte source field for presentation whitespace introduced by the renderer.
    """
    tokens = re.split(r"('(?:''|[^'])*')", code)
    for i in range(0, len(tokens), 2):
        _need("--" not in tokens[i] and "/*" not in tokens[i], "GENERATED_COMMENT")
        tokens[i] = re.sub(r"\s+", " ", tokens[i])
        tokens[i] = re.sub(r"\s*([,;()])\s*", r"\1", tokens[i])
    return "".join(tokens).strip()


def _render(buffer, page, expression, message):
    """Adapt exact trusted templates; every mutating path gets lock then recheck."""
    table = buffer["relation"]["parent"]["table"]
    _need(_IDENT.fullmatch(table), "PARENT_TABLE")
    check = f"select {expression} into l_exists from {table} where FOX_ROW_ID=l_parent;\nif nvl(l_exists,0)<>1 then return false; end if;"
    old = native_buffer._read_parent(buffer, "l_exists", lock=True)
    new = old + "\n" + check
    text = native_buffer._raw_page(buffer, page)
    _need(text.count(old) == 4, "ALL_CONTEXT_CHECKS_REQUIRED")
    text = text.replace(old, new)
    # Initial loading also creates META/ROW members (including a first blank row).
    initial = native_buffer._read_parent(buffer, "l_stored_parent", lock=bool(native_buffer._parent_copies(buffer)))
    locked = native_buffer._read_parent(buffer, "l_stored_parent", lock=True)
    init_guard = (locked + "\n" + check.replace("l_exists", "l_stored_parent").replace(
        "return false;", f":P{page}_POLICY_STATUS := {_literal(message)}; return;"))
    _need(text.count(initial) == 1, "INITIALIZER_REQUIRED")
    text = text.replace(initial, f":P{page}_POLICY_STATUS := NULL;\n  " + init_guard)
    text = text.replace("if not context_ok then raise_application_error(-20006,'Draft changed in another request. Reopen it before editing.'); end if;",
                        "if not context_ok then raise_application_error(-20006," + _literal(message) + "); end if;")
    text = text.replace("This draft changed, its parent is unavailable, or its record limit was reached. Reopen the draft before continuing.",
                        "The parent policy may now be read only, or the draft changed. Reopen it; use the parent or related records report for viewing.")
    status = f'''    pageItem P{page}_POLICY_STATUS (
        type: displayOnly
        label {{ label: Draft policy status }}
        layout {{ sequence: 10
            region: @scope
            slot: regionBody }}
        appearance {{ template: @/optional-floating }}
        sessionState {{ storage: request
            dataType: varchar2 }}
        security {{ sessionStateProtection: restricted }}
    )
'''
    text = text[:-2] + status + ")\n"
    # UI flags only hide editing affordances. PL/SQL never uses them as authority.
    condition = f"        serverSideCondition {{ type: itemIsNull\n            item: P{page}_POLICY_STATUS\n        }}\n"
    for slug, request, label, seq in zip(("keep", "previous", "next", "new"), native_buffer.REQUESTS,
                                       ("Keep draft", "Previous record", "Next record", "New draft record"), (10, 20, 30, 40)):
        button = native_buffer._button(slug, request, label, seq)
        _need(text.count(button) == 1, "BUTTON_TEMPLATE")
        text = text.replace(button, button[:-6] + condition + "    )\n")
    text = text.replace("    region editor (\n        name:", "    region editor (\n" + condition + "        name:")
    text = text.replace("<p>Edit the current record,", "<p>This session draft follows the selected parent's current create/update policy. "
                        "Approval can make this screen read only. This adaptation does not save or approve business records. "
                        "This conservative screen requires both creation and changes to be allowed; mixed permissions make all draft actions read only. "
                        "Use the parent or related records report for viewing.</p><p>Edit the current record,")
    if expression == "0":
        # Even a nearly full original validator must remain publishable in the
        # deny-only fallback. No collection mutation can pass this function.
        text, count = re.subn(r"function context_ok return boolean is\n.*?end context_ok;",
                              "function context_ok return boolean is begin return false; end context_ok;", text, flags=re.S)
        _need(count == 4, "DENY_CONTEXTS_REQUIRED")

    def compact_validation(match):
        code = _compact(match[1])
        return "```plsql\n                " + code + "\n                ```"
    # Compact all closed generated fences consistently, and gate validations.
    text = re.sub(r"```plsql\n(.*?)\n\s*```", compact_validation, text, flags=re.S)
    for code in re.findall(r"validation [\w-]+ \(.*?```plsql\n(.*?)\n\s*```", text, re.S):
        if len(code.strip().encode()) > 3950:
            raise native_buffer.BufferValidationCapacity("DRAFT_POLICY_VALIDATION_CAPACITY")
    return native_buffer._expand_groups(text).encode()


def apply_draft_policies(documents, packet, chunks, trace, files):
    """Return copied members and an honest partial-effect receipt; no ledger edits."""
    actual, actual_chunks = _build(documents)
    _need(actual["source_binding"] == packet.get("source_binding") and actual["sources"] == packet.get("sources")
          and actual_chunks == chunks and trace.get("source_binding") == packet["source_binding"], "SOURCE_BINDING")
    manifest = json.loads(files["fox-package/source-manifest.json"])
    _need(manifest.get("source_binding") == packet["source_binding"]
          and manifest.get("files") == [{k: s["source"][k] for k in ("name", "sha256", "bytes")} for s in actual["sources"]]
          and manifest.get("selected_chunk_hashes") == {c["id"]: c["sha256"] for c in actual_chunks}
          and json.loads(files["fox-package/source-to-page.json"]) == trace, "MANIFEST_TRACE")
    for name, raw in documents:
        _need(files.get("fox-package/sources/" + name) == raw, "ORIGINAL_SOURCE")
    policy = build_policy_plan(documents, trace)
    sql, review = native_policy_rules.render_policy_code(policy)
    _need(json.loads(files["fox-package/policy-plan.json"]) == policy
          and json.loads(files["fox-package/policy-receipt.json"]) == review
          and files[native_policy_rules.CODE_MEMBER] == sql.encode(), "FRESH_POLICY_PROOF")
    output = dict(files)
    receipt = {"scope": SCOPE, "source_binding": actual["source_binding"], "policy_plan_sha256": policy["plan_sha256"],
               "generated_operations": [], "adapted_operations": [], "gaps": [], "unchanged_drafts": [], "converted_code_unit_count": 0,
               "oracle_compiled": False, "runtime_verified": False, "business_accepted": False}
    if "fox-package/buffer-plan.json" not in files:
        return output, receipt
    plan = validate_buffer_plan(json.loads(files["fox-package/buffer-plan.json"]))
    _need(plan["source_binding"] == actual["source_binding"] and plan["source_catalog"] == policy["source_catalog"]
          and plan["parent_trace"] == trace, "BUFFER_SOURCE_PROOF")
    if not plan["operations"]:
        return output, receipt
    rendered = json.loads(files["fox-package/buffer-receipt.json"])
    _need(plan["source_binding"] == rendered.get("source_binding") == actual["source_binding"]
          and plan["source_catalog"] == policy["source_catalog"] and plan["parent_trace"] == trace
          and rendered.get("plan_sha256") == plan["plan_sha256"], "BUFFER_SOURCE_PROOF")
    catalog = {o["id"]: o for o in policy["source_catalog"]["objects"]}
    operations = {o["operation_id"]: o for o in plan["operations"]}
    seen = set()
    for target in rendered.get("generated_operations", []):
        buffer = operations.get(target["operation_id"])
        _need(buffer is not None and target["operation_id"] not in seen, "BUFFER_OPERATION")
        seen.add(target["operation_id"])
        page, path = target["page_id"], target["page_file"]
        _need(type(page) is int and 1 <= page < 9000
              and path == f"pages/p{page:05d}-fox_buffer_{page}.apx"
              and files.get(path) == native_buffer._page(buffer, page).encode(), "EXACT_BUFFER_PAGE_REQUIRED")
        module = buffer["source_module_id"]
        events = [o for o in catalog.values() if o["kind"] == "Trigger" and o["module_id"] == module
                  and (o["name"] or "").upper() == "WHEN-NEW-RECORD-INSTANCE" and o["parent_id"] == module]
        if not events:
            continue
        op, expression, enforced, omitted, reason, contributing = None, "0", [], [], None, set()
        try:
            _need(len(events) == 1, "MODULE_EVENT_NOT_UNIQUE")
            candidates = [o for o in policy["operations"] if o["source_owner_id"] == events[0]["id"]]
            _need(len(candidates) == 1, "COMPLETE_MODULE_EVENT_UNPROVEN")
            op = candidates[0]
            expression, enforced, omitted, contributing = _derive(op, buffer, trace, catalog)
            # Child/parent entry triggers can override module event inheritance.
            relevant_blocks = {buffer["relation"]["parent_block_id"], buffer["relation"]["child_block_id"]}
            _need(expression is None or not any(o["kind"] == "Trigger" and o["id"] != events[0]["id"] and o["block_id"] in relevant_blocks
                          and (o["name"] or "").upper() == "WHEN-NEW-RECORD-INSTANCE" for o in catalog.values()),
                  "ENTRY_EVENT_INHERITANCE_UNRESOLVED")
        except ValueError as exc:
            reason = str(exc)
            expression = "0"
        if expression is None:
            receipt["unchanged_drafts"].append({"source_unit_id": op["source_unit_id"],
                "buffer_operation_id": buffer["operation_id"], "reason": "proven_property_effects_outside_draft_provider"})
            continue
        message = _UNRESOLVED if reason else _MESSAGE
        # Capacity failure is not permission to leave the original mutator open.
        try:
            output[path] = _render(buffer, page, expression, message)
        except native_buffer.BufferValidationCapacity:
            reason, expression, message = "DRAFT_POLICY_VALIDATION_CAPACITY", "0", _UNRESOLVED
            output[path] = _render(buffer, page, expression, message)
        row = {"buffer_operation_id": buffer["operation_id"], "page_id": page, "page_file": path,
               "parent_block_id": buffer["relation"]["parent_block_id"], "child_block_id": buffer["relation"]["child_block_id"],
               "source_module_id": module, "source_event": "WHEN-NEW-RECORD-INSTANCE",
               "policy_expression_sql": expression, "enforced_effects": enforced, "omitted_effects": omitted,
               "status": "read_only_unresolved" if reason else "adapted",
               "generation_status": "generated_wired_adapted_partial", "reason": reason,
               "mutation_paths": ["initial_collection_and_first_row", "duplicate_failure_retention", "keep_previous_next_new"],
               "authority": "unconditional_deny" if reason else "locked_current_synthetic_parent_then_fresh_policy_read",
               "permission_strategy": "conservative_all_draft_mutations_require_create_and_update",
               "customer_table_writes": False, "oracle_compiled": False, "runtime_verified": False, "business_accepted": False}
        if op:
            row.update({k: deepcopy(op[k]) for k in ("operation_id", "source_unit_id", "source_unit_sha256", "decode_receipt")})
            row["supporting_units"] = deepcopy([call for call in op["local_calls"] if call["source_unit_id"] in contributing])
        if reason:
            row["enforced_effects"] = []
            receipt["gaps"].append(row)
        else:
            receipt["adapted_operations"].append(row)
    return output, receipt
