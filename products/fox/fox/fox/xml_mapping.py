"""Deterministic original XML -> one synthetic APEXlang project, without AI.

Generation, offline format validation and business acceptance are separate facts.
No source SQL is executed and no customer schema or editable workflow is inferred.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from forms2apex import native_blueprint, native_behavior, numeric_expression, local_comparison, native_relations, native_assignments, native_policy_rules, native_buffer, record_buffer, native_lookups, source_lookup, native_record_groups
from forms2apex.native_behavior import render_behavior_package

from .forms_blueprint import validate_blueprint
from .forms_mapping_gaps import classify_gaps
from .forms_discrepancies import build_discrepancies, validate_discrepancies, build_dependency_evidence
from .forms_relation_plan import build_relation_plan
from .forms_assignment_plan import build_assignment_plan
from .forms_policy_plan import build_policy_plan
from .forms_order_rules import apply_order_rules
from .forms_buffer_plan import build_buffer_plan
from .forms_lookup_plan import build_lookup_plan
from .forms_guarded_query import apply_guarded_queries
from .forms_manifest_filter import apply_manifest_filters
from .forms_session_defaults import apply_session_defaults
from .forms_record_entry import apply_record_entries
from .forms_draft_policy import apply_draft_policies
from .forms_synthetic_save import apply_synthetic_saves
from .forms_behavior_plan import build_behavior_plan
from .forms_native_plan import POLICY_ID, build_native_prototype_plan
from .forms_understanding_packet import _build
from .prototype_export_only import (_compatibility, _members, _validated_log,
                                    _zip, validate_offline)

SCOPE = "fox-xml-mapping-package-v1"
CATALOG_ID = "fox-xml-mapping-catalog-v1"
_FALSE = ("schema_prepared", "import_verified", "runtime_verified",
          "clean_schema_install_passed", "package_reimport_passed",
          "technically_verified", "business_behavior_accepted")
_BEHAVIOR_RULES = {
    "synthetic_parent_copy_write": "fox.assignment.synthetic-record-save",
    "selected_record_entry_assignment": "fox.policy.selected-record-entry",
    "source_filtered_block_query": "fox.query.source-block-filter",
    "source_session_default": "fox.session.source-default",
    "guarded_related_query": "fox.query.guarded-related-query",
    "record_group_reference_report": "fox.query.record-group-report",
    "source_select_into_lookup": "fox.lookup.source-read-event",
    "loaded_draft_duplicate_record": "fox.buffer.duplicate-record-validation",
    "local_comparison_report_column": "fox.behavior.local-comparison-report-column",
    "local_comparison_function_inlined": "fox.behavior.local-comparison-function-inlined",
    "initial_report_order": "fox.query.initial-report-order",
    "ceil_report_column": "fox.behavior.ceil-report-column",
    "numeric_expression_report_column": "fox.behavior.numeric-expression-report-column",
    "numeric_nonzero_then_focus": "fox.behavior.numeric-nonzero-then-focus",
}


def _bytes(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def mapping_catalog():
    """Return a defensive, versioned description of actually dispatched rules."""
    rules = [
        ("fox.xml.database-readonly-report", "Proven database block; safe exact name; native bounds.",
         "Synthetic table and read-only native report.", "New synthetic row key; no inferred CRUD or source transactions."),
        ("fox.xml.control-page-items", "Proven control block; safe exact name; native bounds.",
         "Native control page and supported page items.", "Session state only; no persistence or source lifecycle."),
        ("fox.xml.typed-item", "Exact source block selected; supported explicit item/type metadata.",
         "Source-linked native typed field or page item.", "Nullable synthetic fields; planner records type/widget/label fallbacks individually."),
        ("fox.xml.unresolved-object", "Object is outside the finite rendered structure.",
         "Complete unresolved source ledger and remediation.", "Preserved source is not counted as business conversion."),
        ("fox.behavior.ceil-report-column", "Complete Item Formula CEIL of one same-block direct NUMBER input; within the 100-operation package bound.",
         "Bound native report calculation.", "Persisted synthetic rows replace the unsaved Forms record buffer."),
        ("fox.behavior.numeric-expression-report-column", "Complete bounded numeric AST; exact same-block direct NUMBER bindings; within the 100-operation package bound.",
         "Bound native report calculation.", "Oracle NULL/error semantics retained; no implicit casts or divide-by-zero guards."),
        ("fox.behavior.numeric-nonzero-then-focus", "Complete supported KEY-NEXT-ITEM guard; distinct same-block focus item; first supported guard per report; within the 100-operation package bound.",
         "Linked native validation-only page with Continue action and focus request.",
         "Existing synthetic row only; no save/DML/commit; repeated MESSAGE becomes one notification."),
        ("fox.behavior.local-comparison-report-column", "Complete local equality helper call; same-row VARCHAR2 and proven control-session bindings.",
         "Numeric report CASE expression with native VARCHAR2 comparison and concatenation.", "Persisted rows/submitted control values; compatible USING_NLS_COMP collation/session settings required and unverified; original lifecycle separate."),
        ("fox.behavior.local-comparison-function-inlined", "Complete side-effect-free same-module VARCHAR2 equality function with at least one emitted caller.",
         "Function semantics inlined into supported formula callers, counted once per original body.", "Unsupported callers and duplicate-record workflows remain explicit; no standalone database function is installed."),
        ("fox.relation.read-context", "Explicit same-module bounded AND equality relation with exact native database fields and unambiguous acyclic context.",
         "Protected parent-row navigation and filtered read-only detail pages.", "Persisted synthetic rows and manual session selection only; no automatic query, cascading delete or write lifecycle."),
        ("fox.assignment.parent-copy-review", "Complete block-owned PRE-INSERT/PRE-UPDATE value copy under a proven direct source relation.",
         "Namespaced pure IN/OUT PL/SQL review procedures and exact source/event bindings.", "Generated but not Oracle-compiled, installed or event-wired; remains in not-yet-converted coverage."),
        ("fox.assignment.synthetic-record-save", "Complete before-write parent-value copy on a supported related draft with a checked parent and mapped child fields.",
         "Save the current synthetic row and copy the selected parent's value immediately before its insert or update.", "Only the mapped synthetic fields participate in this save. Other Forms validations, the full commit sequence and customer database writes require separate implementation."),
        ("fox.query.initial-report-order", "Complete ORDER BY of 1..6 direct mapped database columns, direction and NULL placement.",
         "Initial native saved-report sort, also retained by related report pages.", "Persisted synthetic rows; users may change report sorting. Equal-key order is unspecified; compatible database collation is required."),
        ("fox.policy.finite-review", "Complete finite IF/scalar/property/warning/failure rules, with proven same-module local calls.",
         "Typed PL/SQL review procedures and ordered effects with exact source/context bindings.", "Generated but not installed, Oracle-compiled or event-wired. No permissions or writes are activated."),
        ("fox.policy.parent-draft-guard", "A source record-entry policy sets edit permissions for a related draft block using fields on the selected parent.",
         "The draft editor rechecks the selected parent's current policy on the server.", "This connects the rule to session drafts. The full rule still needs its other item, block and event bindings."),
        ("fox.buffer.duplicate-record-validation", "Complete source duplicate trigger, local helper/formula and control SUM with proven parent relation and bounded direct character fields.",
         "Native session-draft editor validates the current record against loaded same-parent drafts before keeping or moving records.", "No customer-table save. Explicit draft lifecycle, 1000-row cap, source size limits and matching binary comparison/encoding prerequisites; target runtime remains unverified."),
        ("fox.lookup.source-read-event", "Complete same-block SELECT INTO lookup with exact source exception/null-reset behavior and typed native fields.",
         "Native selected-record POST-QUERY handlers or explicit Apply lookup POST-CHANGE adapters, linked from source reports.", "Original read interfaces are embedded but disabled by default behind restricted server-only readiness items. Existing field edit restrictions are retained; no customer save. Verify original objects, types, privileges and authorization before activation; runtime remains unverified."),
        ("fox.query.record-group-report", "Complete query record group with matching projected columns, verified row context and bounded SELECT grammar.",
         "Native reference choices report linked from the synthetic source row chooser.", "Original database and session inputs require trusted configuration. Read-only selection view. LOV return to the calling field remains pending."),
        ("fox.query.guarded-related-query", "Complete item KEY-EXEQRY guard using non-null keys on the selected parent in a proven incoming relation.",
         "Manual Execute query action refreshes the related synthetic report after checking its parent keys.", "Uses the selected persisted row. The related view can also query on initial entry. Automatic coordination and dirty record buffers remain separate."),
        ("fox.session.source-default", "Complete form initialization loads one global from a single-row NVL lookup and preserves it on error.",
         "Runs on the first mapped module page visited in an enabled application session.", "Trusted source context and a verified original interface are required. A new APEX session adapts Forms launch timing. Subsequent visits retain the initialized value."),
        ("fox.query.source-block-filter", "Whole block filter consists of direct source column equalities with literals and trusted globals.",
         "A dedicated original-source query page applies the declared filter to its verified database source.", "Source reads require a trusted session context and an enabled interface. The other prototype screens continue to use synthetic tables. This read adapter covers the source query only."),
        ("fox.policy.selected-record-entry", "Complete conditional scalar assignment on record entry with an explicitly selected record and proven parent chain.",
         "Native page applies the assignment to session state for the selected synthetic record.", "Inputs come from the selected synthetic rows. False and NULL conditions preserve the previous flag. Other lookup pages and drafts have independent state. This adapter applies when the selected record-entry page is opened."),
        ("fox.behavior.unresolved-unit", "Complete source unit does not satisfy a supported mapping and all bindings.",
         "Unsupported or missing-input coverage with exact unit hash.", "No partial execution or invented business logic."),
    ]
    catalog = {"schema_version": 1, "catalog_id": CATALOG_ID, "revision": 10,
               "origin": "deterministic_rules", "policy_id": POLICY_ID,
               "implementation_sources": {name: _sha(Path(__file__).with_name(name).read_bytes())
                   for name in ("xml_mapping.py", "forms_native_plan.py", "forms_behavior_plan.py",
                                "forms_facts.py", "forms_understanding_packet.py", "forms_blueprint.py", "forms_mapping_gaps.py", "forms_relation_plan.py", "forms_assignment_plan.py", "forms_policy_plan.py", "forms_order_rules.py", "forms_buffer_plan.py", "forms_discrepancies.py", "forms_lookup_plan.py", "forms_guarded_query.py", "forms_session_defaults.py", "forms_manifest_filter.py", "forms_record_entry.py", "forms_draft_policy.py", "forms_synthetic_save.py")}
                   | {"forms2apex/native_behavior.py": _sha(Path(native_behavior.__file__).read_bytes()),
                      "forms2apex/numeric_expression.py": _sha(Path(numeric_expression.__file__).read_bytes()),
                      "forms2apex/local_comparison.py": _sha(Path(local_comparison.__file__).read_bytes()),
                      "forms2apex/native_relations.py": _sha(Path(native_relations.__file__).read_bytes()),
                      "forms2apex/native_assignments.py": _sha(Path(native_assignments.__file__).read_bytes()),
                      "forms2apex/native_policy_rules.py": _sha(Path(native_policy_rules.__file__).read_bytes()),
                      "forms2apex/native_buffer.py": _sha(Path(native_buffer.__file__).read_bytes()),
                      "forms2apex/record_buffer.py": _sha(Path(record_buffer.__file__).read_bytes()),
                      "forms2apex/native_record_groups.py": _sha(Path(native_record_groups.__file__).read_bytes()),
                      "forms2apex/native_lookups.py": _sha(Path(native_lookups.__file__).read_bytes()),
                      "forms2apex/source_lookup.py": _sha(Path(source_lookup.__file__).read_bytes())},
               "rules": [{"id": key, "revision": 1, "guards": guard,
                          "outputs": output, "adaptations": adaptation}
                         for key, guard, output, adaptation in rules]}
    return {**catalog, "catalog_sha256": _sha(_bytes(catalog))}


def _blueprint(packet):
    objects = [obj for entry in packet["sources"] for obj in entry["facts"]["objects"]]
    blocks = {obj["id"]: obj for obj in objects if obj["kind"] == "Block"
              and obj["classification"] in {"database", "control"}}
    screens = [{"id": "xml-screen-" + key, "title": "Source block prototype"} for key in blocks]
    rows, identities = [], set()
    for obj in objects:
        if obj["kind"] in {"Block", "Item"} and obj["name"] is not None:
            identity = (obj["kind"], obj["module_id"] if obj["kind"] == "Block" else obj["block_id"],
                        obj["name"].casefold())
            if identity in identities:
                raise ValueError("Duplicate source block or item identity in one source scope.")
            identities.add(identity)
        row = {"source_object_id": obj["id"], "disposition": "unresolved",
               "reason": "Outside finite structural mapping; source remains unresolved."}
        block_id = obj["id"] if obj["kind"] == "Block" else obj["block_id"]
        if obj["kind"] in {"Block", "Item"} and block_id in blocks:
            row.update(disposition="proposed", screen_id="xml-screen-" + block_id,
                       reason="Deterministic synthetic structure under explicit policy.")
            if obj["kind"] == "Block":
                row["native_component"] = ("report" if obj["classification"] == "database"
                                           else "page-items")
        rows.append(row)
    return {"schema_version": 1, "scope": "fox-forms-blueprint-v1",
            "source_binding": packet["source_binding"], "objects": rows, "screens": screens,
            "claims": [], "relationships": [], "actions": [], "questions": [], "assumptions": []}


def _apex_members(files):
    return {name: _sha(raw) for name, raw in sorted(files.items())
            if name.endswith(".apx") or name.startswith(".apex/")}


def generate_xml_package(documents, project_id, project_name, approved_policy_id):
    """Return (candidate bytes, report) from fresh originals, with no parent job.

    The explicit policy selects synthetic adaptations only. It does not record
    user business acceptance, AI review, external transfer or database authority.
    Existing packet, native planner and renderer bounds remain in force.
    """
    packet, chunks = _build(documents)
    # Same metadata-only inventory state as local_packet(); this records no
    # external content selection or processing approval.
    packet["selection_status"] = "NOT_SELECTED"
    blueprint = _blueprint(packet)
    blueprint_validation = validate_blueprint(packet, blueprint)
    native_plan = build_native_prototype_plan(documents, blueprint, project_id=project_id,
        project_name=project_name, approved_policy_id=approved_policy_id)
    spec = native_plan["rendering_spec"]
    if not spec["blocks"]:
        raise ValueError("No renderable source block is available for this XML prototype.")
    # Use the existing renderer, templates, trace and synthetic schema verbatim.
    files = _members(native_blueprint.deterministic_prototype_zip(spec))
    trace = native_blueprint.prototype_trace(spec)
    source_objects = {obj["id"]: obj for entry in packet["sources"] for obj in entry["facts"]["objects"]}
    for block in trace["blocks"]:
        block["source_module_id"] = source_objects[block["source_block_id"]]["module_id"]
    manifest = {"schema_version": 1, "source_binding": packet["source_binding"],
        "origin": "deterministic_local_xml", "code_scope": "all_original_units_locally_assessed",
        "files": [{key: entry["source"][key] for key in ("name", "sha256", "bytes")}
                  for entry in packet["sources"]],
        "selected_chunk_hashes": {chunk["id"]: chunk["sha256"] for chunk in chunks}}
    for name, value in (("source-manifest.json", manifest), ("source-to-page.json", trace)):
        files["fox-package/" + name] = _bytes(value)
    files["fox-package/supporting-schema.sql"] = native_blueprint.render_prototype_schema(spec).encode("utf-8")
    originals = dict(documents)
    for source in manifest["files"]:
        files["fox-package/sources/" + source["name"]] = originals[source["name"]]
    structural_parent = _zip(files)
    behavior_plan = build_behavior_plan(documents, structural_parent)
    behavior_receipt = None
    if behavior_plan["operations"]:
        rendered, behavior_receipt = render_behavior_package(structural_parent, behavior_plan)
        if (behavior_receipt["plan_sha256"] != behavior_plan["plan_sha256"]
                or behavior_receipt["source_binding"] != packet["source_binding"]):
            raise ValueError("Behavior rendering differs from the fresh source-bound plan.")
        files = _members(rendered)
        # The renderer's generic parent-review wording is inapplicable here.
        files["fox-package/behavior-README.md"] = (
            "# Deterministic XML behavior candidate\n\n"
            "No AI reviews exist for this XML-only package. Only the complete supported "
            "operations in behavior-plan.json were generated. Whole-package format validation, "
            "target import/runtime checks and business acceptance remain separate.\n"
        ).encode("utf-8")
        coverage = behavior_receipt["coverage"]
    else:
        coverage = behavior_plan["coverage"]
        files["fox-package/behavior-plan.json"] = _bytes(behavior_plan)
    # Relation and assignment knowledge is rebuilt from the same originals.
    # Read navigation and unwired review code are distinct from converted units.
    files, order_receipt = apply_order_rules(documents, packet, chunks, trace, files)
    files["fox-package/order-receipt.json"] = _bytes(order_receipt)
    relation_parent = _zip(files)
    relation_plan = build_relation_plan(documents, relation_parent)
    assignment_plan = build_assignment_plan(documents, relation_plan, trace)
    relation_receipt = None
    if relation_plan["operations"]:
        related, relation_receipt = native_relations.render_relation_package(relation_parent, relation_plan)
        files = _members(related)
    else:
        files["fox-package/relation-plan.json"] = _bytes(relation_plan)
    assignment_sql, assignment_receipt = native_assignments.render_assignment_code(assignment_plan)
    files[native_assignments.CODE_MEMBER] = assignment_sql.encode("utf-8")
    files["fox-package/assignment-plan.json"] = _bytes(assignment_plan)
    files["fox-package/assignment-receipt.json"] = _bytes(assignment_receipt)
    encoded = {op["source_unit_id"]: op for op in assignment_receipt["generated_operations"]}
    policy_plan = build_policy_plan(documents, trace)
    policy_sql, policy_receipt = native_policy_rules.render_policy_code(policy_plan)
    files[native_policy_rules.CODE_MEMBER] = policy_sql.encode("utf-8")
    files["fox-package/policy-plan.json"] = _bytes(policy_plan)
    files["fox-package/policy-receipt.json"] = _bytes(policy_receipt)
    policy_encoded = {op["source_unit_id"]: op for op in policy_receipt["generated_operations"]}
    if set(policy_encoded) & set(encoded):
        raise ValueError("A source unit cannot have two review-code owners.")
    buffer_parent = _zip(files)
    buffer_plan = build_buffer_plan(documents, buffer_parent)
    buffer_receipt = None
    if buffer_plan["operations"]:
        if buffer_plan != build_buffer_plan(documents, buffer_parent):
            raise ValueError("Record-buffer plan differs from fresh original-source rebuilding.")
        buffered_package, buffer_receipt = native_buffer.render_buffer_package(buffer_parent, buffer_plan)
        files = _members(buffered_package)
    else:
        files["fox-package/buffer-plan.json"] = _bytes(buffer_plan)
    buffered = {op["source_unit_id"]: op for op in buffer_receipt["generated_operations"]} if buffer_receipt else {}
    buffer_gaps = {op["source_unit_id"]: op["reason"] for op in buffer_receipt["unrendered_operations"]} if buffer_receipt else {}
    if set(buffered) & (set(encoded) | set(policy_encoded)):
        raise ValueError("A record event cannot also be counted as unwired review code.")
    lookup_parent = _zip(files)
    lookup_plan = build_lookup_plan(documents, lookup_parent)
    lookup_receipt = None
    if lookup_plan["operations"]:
        if lookup_plan != build_lookup_plan(documents, lookup_parent):
            raise ValueError("Lookup plan differs from fresh original-source rebuilding.")
        looked_package, lookup_receipt = native_lookups.render_lookup_package(lookup_parent, lookup_plan)
        files = _members(looked_package)
    else:
        files["fox-package/lookup-plan.json"] = _bytes(lookup_plan)
    looked = {op["source_unit_id"]: op for op in lookup_receipt["generated_operations"]} if lookup_receipt else {}
    lookup_gaps = {op["source_unit_id"]: op["reason"] for op in lookup_receipt["unrendered_operations"]} if lookup_receipt else {}
    if set(looked) & (set(encoded) | set(policy_encoded) | set(buffered)):
        raise ValueError("A source event cannot have two native/review owners.")
    files, group_receipt = native_record_groups.apply_record_groups(documents, packet, chunks, trace, files)
    files["fox-package/record-group-receipt.json"] = _bytes(group_receipt)
    files, query_receipt = apply_guarded_queries(documents, packet, chunks, trace, files)
    files["fox-package/guarded-query-receipt.json"] = _bytes(query_receipt)
    files, filter_receipt = apply_manifest_filters(documents, packet, chunks, trace, files)
    files["fox-package/block-filter-receipt.json"] = _bytes(filter_receipt)
    files, defaults_receipt = apply_session_defaults(packet, chunks, trace, files)
    files["fox-package/session-defaults.json"] = _bytes(defaults_receipt)
    files, entry_receipt = apply_record_entries(documents, packet, chunks, trace, files)
    files["fox-package/record-entry-receipt.json"] = _bytes(entry_receipt)
    files, draft_policy = apply_draft_policies(documents, packet, chunks, trace, files)
    files["fox-package/draft-policy-receipt.json"] = _bytes(draft_policy)
    files, save_receipt = apply_synthetic_saves(documents, packet, chunks, trace, files)
    files["fox-package/synthetic-save-receipt.json"] = _bytes(save_receipt)
    for save in save_receipt["generated_operations"]:
        uid = save["source_unit_id"]
        review = encoded.pop(uid, None)
        if (review is None or review["source_unit_sha256"] != save["source_unit_sha256"]
                or review["operation_id"] != save["assignment_operation_id"]
                or save["source_event"] != review["source_event"]
                or save["synthetic_table_writes"] is not True or save["customer_table_writes"] is not False):
            raise ValueError("Synthetic write event differs from the original before-write assignment.")
    # A permanently read-only fallback has no reachable draft validator.
    # The earlier buffer-renderer receipt records what that stage produced.
    buffer_ids = {op["operation_id"]: uid for uid, op in buffered.items()}
    for gap in draft_policy["gaps"]:
        uid = buffer_ids[gap["buffer_operation_id"]]
        buffered.pop(uid)
        buffer_gaps[uid] = "draft_policy_context_unresolved"
    partial_policies = set()
    for guard in draft_policy["adapted_operations"]:
        uid = guard["source_unit_id"]
        if (uid not in policy_encoded or policy_encoded[uid]["source_unit_sha256"] != guard["source_unit_sha256"]
                or guard["generation_status"] != "generated_wired_adapted_partial"):
            raise ValueError("Draft policy does not match its source review rule.")
        partial_policies.add(uid)
        for helper in guard["supporting_units"]:
            hid = helper["source_unit_id"]
            if hid in policy_encoded:
                if policy_encoded[hid]["source_unit_sha256"] != helper["source_unit_sha256"]:
                    raise ValueError("Draft policy helper differs from its source.")
                partial_policies.add(hid)
    for operation in entry_receipt["generated_operations"]:
        uid = operation["source_unit_id"]
        review = policy_encoded.pop(uid, None)
        if review is None or review["source_unit_sha256"] != operation["source_unit_sha256"]:
            raise ValueError("Record entry requires the exact encoded source policy.")
    source_adapters = {}
    for receipt, reason in (
        (save_receipt, "parent_copy_wired_to_synthetic_write"),
        (entry_receipt, "selected_record_entry_generated"),
        (query_receipt, "related_query_action_generated"),
        (group_receipt, "record_group_query_generated_interface_pending"),
        (filter_receipt, "source_block_filter_read_adapter"),
        (defaults_receipt, "source_session_default_generated"),
    ):
        for operation in receipt["generated_operations"]:
            uid = operation["source_unit_id"]
            if uid in source_adapters or uid in looked or uid in buffered or uid in encoded or uid in policy_encoded:
                raise ValueError("Two mappings claim the same source unit.")
            source_adapters[uid] = (operation, reason)
    ordered = {op["source_unit_id"]: op for op in order_receipt["generated_operations"]}
    coverage = deepcopy(coverage)
    for row in coverage:
        uid = row["source_unit_id"]
        if uid in source_adapters:
            if row["status"] == "generated_wired_adapted" or uid in ordered:
                raise ValueError("A source adapter cannot replace generated behavior.")
            operation, reason = source_adapters[uid]
            if operation["source_unit_sha256"] != row["source_unit_sha256"]:
                raise ValueError("Adapter receipt differs from its source unit.")
            row.update(status="generated_wired_adapted", reason=reason, operation_id=operation["operation_id"])
        if uid in looked:
            if row["status"] == "generated_wired_adapted":
                raise ValueError("A lookup cannot replace existing generated behavior.")
            row.update(status="generated_wired_adapted", reason="source_lookup_generated_read_interface_pending",
                       operation_id=looked[uid]["operation_id"])
        if uid in lookup_gaps:
            row.update(reason=lookup_gaps[uid])
        if uid in buffer_gaps:
            row.update(reason=buffer_gaps[uid])
        if uid in buffered:
            if row["status"] == "generated_wired_adapted":
                raise ValueError("A buffer event cannot replace an existing operation.")
            row.update(status="generated_wired_adapted", reason="duplicate_record_draft_event_generated",
                       operation_id=buffered[uid]["operation_id"])
        if uid in policy_encoded:
            if row["status"] == "generated_wired_adapted":
                raise ValueError("Policy review code cannot replace wired behavior.")
            row.update(encoding_status="generated_unwired", reason="policy_rule_encoded_event_context_unimplemented",
                       policy_operation_id=policy_encoded[uid]["operation_id"])
            if uid in partial_policies:
                row["reason"] = "policy_rule_partial_draft_guard"
        if uid in ordered:
            row.update(status="generated_wired_adapted", reason="initial_report_order_generated",
                       operation_id=ordered[uid]["operation_id"])
    for row in coverage:
        if row["source_unit_id"] in encoded:
            if row["status"] == "generated_wired_adapted":
                raise ValueError("An assignment review artifact cannot replace an already generated behavior.")
            row.update(encoding_status="generated_unwired",
                reason="parent_value_copy_encoded_write_lifecycle_unimplemented",
                assignment_operation_id=encoded[row["source_unit_id"]]["operation_id"])
    relation_coverage = relation_receipt["coverage"] if relation_receipt else relation_plan["coverage"]
    context_summary = {"relations_generated": len(relation_receipt["generated_operations"]) if relation_receipt else 0,
        "relations_not_converted": sum(row["status"] != "read_navigation_generated" for row in relation_coverage),
        "assignments_generated_unwired": len(encoded)}
    generated = {row["source_unit_id"]: row for row in
                 behavior_receipt["generated_operations"]} if behavior_receipt else {}
    generated.update(ordered)
    generated.update(buffered)
    generated.update(looked)
    generated.update((uid, operation) for uid, (operation, _) in source_adapters.items())
    remediation = deepcopy(native_plan["remediation"])
    for row in remediation:
        if row.get("code") == "code_unit_not_translated" and row.get("code_unit_id") in generated:
            row.update(code="behavior_generated_runtime_pending", generation_status="generated_wired_adapted",
                reason="Supported complete source behavior generated with explicit adaptations; runtime and business checks pending.",
                next_action="Review the generated operation and verify it in an authorized synthetic target.")
    for row in remediation:
        if row.get("code_unit_id") in encoded and row.get("code") == "code_unit_not_translated":
            row.update(code="assignment_generated_unwired", encoding_status="generated_unwired",
                reason="Value-copy review code is generated; insert/update event wiring and required guards remain pending.",
                next_action="Review assignment-review.sql and activate only after the native write lifecycle is implemented.")
    for row in remediation:
        if row.get("code_unit_id") in policy_encoded and row.get("code") == "code_unit_not_translated":
            row.update(code="policy_generated_unwired", encoding_status="generated_unwired",
                reason="Complete policy review code generated; original event and state providers remain unwired.",
                next_action="Review policy-review.sql and its ordered effects; implement event/context adapters and server-side enforcement before activation.")
            if row["code_unit_id"] in partial_policies:
                row.update(reason="The selected parent controls edits in the related session draft.",
                           next_action="Connect the remaining field, block and record-entry effects.")
    trace_blocks = {block["source_block_id"]: block for block in trace["blocks"]}
    source_files = {obj["id"]: {key: entry["source"][key] for key in ("name", "sha256", "bytes")}
                    for entry in packet["sources"] for obj in entry["facts"]["objects"]}
    trace_items = {item["source_item_id"]: {"source_block_id": block["source_block_id"], **item}
                   for block in trace["blocks"] for item in block["items"]}
    operations = {op["source_unit_id"]: op for op in behavior_plan["operations"]}
    generated_by_item = {}
    for op in operations.values():
        generated_by_item.setdefault(op["source_item_id"], []).append(op)
    ledger_objects = []
    for row in native_plan["coverage"]["objects"]:
        target = trace_blocks.get(row["source_object_id"]) if row["kind"] == "Block" else trace_items.get(row["source_object_id"])
        rule_id = ("fox.xml.database-readonly-report" if target and row["kind"] == "Block" and target["classification"] == "database"
                   else "fox.xml.control-page-items" if target and row["kind"] == "Block"
                   else "fox.xml.typed-item" if target else "fox.xml.unresolved-object")
        target = deepcopy(target)
        if target and row["kind"] == "Item":
            item_ops = generated_by_item.get(row["source_object_id"], [])
            target["value_computation_implemented"] = any(op["kind"] in {
                "ceil_report_column", "numeric_expression_report_column", "local_comparison_report_column"} for op in item_ops)
            target["generated_behavior_operation_ids"] = [op["operation_id"] for op in item_ops]
        ledger_objects.append({**deepcopy(row), "rule_id": rule_id, "rule_revision": 1,
            "source_file": source_files[row["source_object_id"]],
            "disposition": "generated_structural" if target else row["disposition"],
            "reason": "Native synthetic structure generated; behavior coverage is recorded separately." if target else row["reason"],
            "target": target, "business_behavior_accepted": False})
    ledger_units = []
    for row in coverage:
        op = operations.get(row["source_unit_id"]) or generated.get(row["source_unit_id"])
        ledger_units.append({**deepcopy(row), "rule_id": _BEHAVIOR_RULES[op["kind"]] if op else "fox.behavior.unresolved-unit",
            "source_file": source_files[row["source_owner_id"]],
            "rule_revision": 1, "target": deepcopy(generated.get(row["source_unit_id"]))})
    for row in ledger_units:
        if row["source_unit_id"] in encoded:
            row.update(rule_id="fox.assignment.parent-copy-review", target=deepcopy(encoded[row["source_unit_id"]]))
        if row["source_unit_id"] in policy_encoded:
            rule = "fox.policy.parent-draft-guard" if row["source_unit_id"] in partial_policies else "fox.policy.finite-review"
            row.update(rule_id=rule, target=deepcopy(policy_encoded[row["source_unit_id"]]))
    gap_report = classify_gaps(packet, chunks, coverage)
    catalog = mapping_catalog()
    catalog_rules = {row["id"]: row for row in catalog["rules"]}
    ledger = {"schema_version": 1, "scope": "fox-xml-source-to-target-v1",
        "source_binding": packet["source_binding"], "catalog_sha256": catalog["catalog_sha256"],
        "objects": ledger_objects, "code_units": ledger_units,
        "relations": relation_coverage, "assignment_review": list(encoded.values()),
        "synthetic_write_events": save_receipt["generated_operations"],
        "policy_review": list(policy_encoded.values()),
        "draft_policy_guards": draft_policy["adapted_operations"],
        "draft_policy_gaps": draft_policy["gaps"],
        "selected_record_entries": entry_receipt["generated_operations"],
        "buffer_flows": list(buffered.values()),
        "source_lookups": list(looked.values()),
        "record_group_reports": group_receipt["generated_operations"],
        "source_block_filters": filter_receipt["generated_operations"],
        "session_defaults": defaults_receipt["generated_operations"],
        "guarded_queries": query_receipt["generated_operations"],
        "dependencies_and_links": [deepcopy(row) for row in remediation if row["code"] == "dependency_not_implemented"],
        "structural_objects_are_business_conversion": False,
        "runtime_verified": False, "business_behavior_accepted": False}
    dependency_evidence = build_dependency_evidence(packet, chunks, ledger)
    discrepancies = build_discrepancies(packet, ledger, gap_report, catalog, chunks=chunks,
        dependency_evidence=dependency_evidence)
    validate_discrepancies(discrepancies, ledger, gap_report, catalog, packet=packet, chunks=chunks,
        dependency_evidence=dependency_evidence)
    files["fox-package/discrepancy-evidence.json"] = _bytes(dependency_evidence)
    files["fox-package/discrepancies.json"] = _bytes(discrepancies)
    applied = sorted({row["rule_id"] for row in ledger_objects + ledger_units})
    if context_summary["relations_generated"]:
        applied = sorted(set(applied) | {"fox.relation.read-context"})
    counts = dict(sorted(Counter(row["status"] for row in coverage).items()))
    compatibility = _compatibility(files, trace)
    if behavior_receipt:
        compatibility["behavior_renderer"] = {"scope": behavior_receipt["scope"],
                                               "sources": behavior_receipt["renderer_sources"]}
    original_reads = any(receipt["generated_operations"] for receipt in (group_receipt, defaults_receipt, filter_receipt)) or bool(looked)
    metadata = {"schema_version": 1, "scope": SCOPE,
        "status": "GENERATED_FORMAT_VALIDATION_PENDING", "origin": "deterministic_local_xml",
        "project_id": project_id, "project_name": project_name, "application_count": 1,
        "source_binding": packet["source_binding"], "approved_policy_id": approved_policy_id,
        "catalog_id": CATALOG_ID, "catalog_sha256": catalog["catalog_sha256"],
        "implementation_sources": catalog["implementation_sources"],
        "applied_rule_ids": applied, "source_parser_rebuilt": True,
        "ai_review": {"performed": False, "approval_recorded": False, "origin": "none"},
        "format_validated": False, "validation": None, "native_apex_generated": True,
        "data_mode": "synthetic_test_only", "structural_only": not bool(generated or context_summary["relations_generated"]),
        "structural_coverage": deepcopy(native_plan["coverage"]),
        "behavior_coverage": {"total": len(coverage), "counts": counts},
        "context_summary": context_summary,
        "policy_summary": {"rules_generated_unwired": len(policy_encoded)},
        "synthetic_save_summary": {"screens": len({op["page_file"] for op in save_receipt["generated_operations"]}),
                                   "before_write_events": len(save_receipt["generated_operations"])},
        "buffer_summary": {"record_validation_flows": len(buffered)},
        "lookup_summary": {"generated_lookup_handlers": len(looked), "original_reads_enabled": False},
        "original_read_adapters": {"embedded": original_reads, "enabled_by_default": False,
            "queries_executed_during_generation": False, "activation_changes_runtime_data_scope": original_reads},
        "gap_summary": gap_report["summary"], "gap_report_path": "fox-package/mapping-gaps.json",
        "discrepancy_report_path": "fox-package/discrepancies.json",
        "discrepancy_report_sha256": _sha(files["fox-package/discrepancies.json"]),
        "discrepancy_evidence_path": "fox-package/discrepancy-evidence.json",
        "discrepancy_evidence_sha256": _sha(files["fox-package/discrepancy-evidence.json"]),
        "generated_operations": list(generated.values()),
        "structural_trace_path": "fox-package/source-to-page.json",
        "current_mapping_ledger_path": "fox-package/mapping-ledger.json",
        "relation_plan_sha256": relation_plan["plan_sha256"],
        "assignment_plan_sha256": assignment_plan["plan_sha256"],
        "policy_plan_sha256": policy_plan["plan_sha256"],
        "buffer_plan_sha256": buffer_plan["plan_sha256"],
        "lookup_plan_sha256": lookup_plan["plan_sha256"], "order_receipt_sha256": order_receipt["receipt_sha256"],
        "native_plan_sha256": native_plan["plan_sha256"], "behavior_plan_sha256": behavior_plan["plan_sha256"],
        "adaptations": native_plan["assumptions"] + [{"scope": "generated_behavior",
            "rule_id": _BEHAVIOR_RULES[op["kind"]], "source_unit_id": op["source_unit_id"],
            "reason": catalog_rules[_BEHAVIOR_RULES[op["kind"]]]["adaptations"]}
            for op in operations.values()],
        "compatibility": compatibility, "omissions": remediation,
        "prerequisites": ["Matching APEXlang-capable SQLcl/Java for offline format validation.",
            "Separate authority and compatible isolated APEX workspace/schema before any import.",
            "Review synthetic supporting-schema.sql, unresolved behavior and lifecycle adaptations."]
            + (["Comparison inputs require target VARCHAR2 collation compatible with USING_NLS_COMP and matching source comparison session settings; format validation does not establish this."]
               if any(op["kind"] == "local_comparison_report_column" for op in behavior_plan["operations"]) else []),
        "provider_calls": 0, "database_imports": 0, **{name: False for name in _FALSE}}
    files.update({"fox-package/" + name: _bytes(value) for name, value in (
        ("mapping-catalog.json", catalog), ("mapping-ledger.json", ledger),
        ("mapping-gaps.json", gap_report),
        ("native-plan.json", native_plan), ("blueprint.json", blueprint),
        ("blueprint-validation.json", blueprint_validation), ("behavior-coverage.json", coverage),
        ("remediation.json", remediation))})
    files["fox-package/README.md"] = (
        "# Deterministic XML synthetic prototype\n\n"
        "One project / multiple Forms XML modules / one native APEXlang application. "
        "Original XML is retained byte-for-byte under sources/. No AI was invoked or approved this mapping.\n\n"
        "CURRENT format status is in metadata.json. Generated, format validated, imported, runtime "
        "verified and business accepted are separate states. This package has no target import or runtime proof.\n\n"
        "Read discrepancies.json for all source-unit statuses, generated adaptations and reference candidates to verify. Findings do not imply missing files or prevent generation of supported parts. "
        "Read mapping-ledger.json, behavior-coverage.json, remediation.json and supporting-schema.sql. "
        "Database blocks default to read-only reports; control values use APEX session state, not customer-table writes. "
        "Supported report formulas use persisted synthetic rows, not the unsaved Forms buffer. "
        "Referenced control values can be submitted explicitly; original Forms events that populate them remain separate. "
        "Pure local comparison functions are inlined only into supported callers. Complete supported duplicate-record pipelines receive a separate session-draft adapter, described in buffer-plan.json and buffer-receipt.json. "
        "Comparison collation/session compatibility requires target verification; casts preserve VARCHAR2 nonpadding, not an unconditional environment equivalence. "
        "Any linked Continue page validates an existing synthetic row without saving it. "
        "Source-supported related-record links are manual, read-only adaptations; retained session selection is explicit. "
        "assignment-review.sql contains generated value-copy procedures only: not installed, Oracle-compiled or event-wired. "
        "synthetic-save-receipt.json and the mapping ledger identify before-write events connected to a synthetic save. Other assignment procedures remain available for review. "
        "policy-review.sql preserves complete supported scalar, permission, warning and failure rules as ordered effects; it is not installed, Oracle-compiled or event-wired. "
        "Initial source report ordering is generated when every sort column is directly mapped; users may change the saved-report sort. "
        "Draft edits use a source-bound parent context and current-record validation before navigation; no customer-table save, source transaction or full Forms lifecycle is implied. "
        "lookup-activation.md lists native source SELECT-INTO handlers and restricted readiness items. Original reads are disabled by default and require verified target interfaces and separate activation authority. POST-CHANGE is adapted to Apply lookup; POST-QUERY runs after selecting a record. These pages do not save records. "
        "Other dependencies, relationship lifecycle, source transactions and behavior remain unresolved.\n\n"
        "Extract the entire project including .apex. Fresh SQLcl /nolog validation is required "
        "before a format-validated handoff. Import/schema changes require separate authorization.\n"
    ).encode("utf-8")
    metadata["apex_members"] = _apex_members(files)
    files["fox-package/metadata.json"] = _bytes(metadata)
    candidate = _zip(files)
    _members(candidate)  # Retain existing package size and safe-member limits.
    return candidate, {"schema_version": 1, "scope": SCOPE,
        "candidate_sha256": _sha(candidate), "candidate_bytes": len(candidate),
        "source_binding": packet["source_binding"], "metadata": metadata,
        "blueprint_validation": blueprint_validation, "native_plan": native_plan,
        "behavior_plan": behavior_plan, "renderer_receipt": behavior_receipt,
        "mapping_ledger": ledger, "gap_report": gap_report, "discrepancies": discrepancies, "dependency_evidence": dependency_evidence, "relation_plan": relation_plan,
        "relation_receipt": relation_receipt, "assignment_plan": assignment_plan, "assignment_receipt": assignment_receipt, "policy_plan": policy_plan, "policy_receipt": policy_receipt, "order_receipt": order_receipt, "buffer_plan": buffer_plan, "buffer_receipt": buffer_receipt, "lookup_plan": lookup_plan, "lookup_receipt": lookup_receipt, "record_group_receipt": group_receipt, "guarded_query_receipt": query_receipt, "apex_members": metadata["apex_members"],
        "format_validated": False, "runtime_verified": False, "business_behavior_accepted": False}


def _check_candidate(candidate):
    """Reconstruct deterministic authority, including originals, before sealing."""
    files = _members(candidate)
    try:
        metadata = json.loads(files["fox-package/metadata.json"])
        manifest = json.loads(files["fox-package/source-manifest.json"])
        docs = [(row["name"], files["fox-package/sources/" + row["name"]]) for row in manifest["files"]]
        expected, _ = generate_xml_package(docs, metadata["project_id"], metadata["project_name"],
                                           metadata["approved_policy_id"])
    except (KeyError, TypeError, json.JSONDecodeError, UnicodeError):
        raise ValueError("XML candidate provenance is incomplete or invalid.") from None
    if candidate != expected:
        raise ValueError("XML candidate differs from fresh deterministic source-bound generation.")
    return files, metadata


def _seal_validated_xml_package(candidate, bound_validation, validation_directory):
    if bound_validation.get("candidate_sha256") != _sha(candidate):
        raise ValueError("Compiler evidence belongs to another candidate.")
    files, metadata = _check_candidate(candidate)
    checked = _validated_log(validation_directory, bound_validation["validation"])
    evidence = {"schema_version": 1, "scope": "fox-xml-format-validation-v1",
        "candidate_sha256": _sha(candidate), "apex_members": _apex_members(files),
        "validation": checked, "runtime_verified": False, "business_behavior_accepted": False}
    metadata.update(status="GENERATED_FORMAT_VALIDATED_RUNTIME_UNVERIFIED", format_validated=True, validation=checked)
    files["fox-package/metadata.json"] = _bytes(metadata)
    files["fox-package/xml-validation.json"] = _bytes(evidence)
    output = _zip(files)
    if _apex_members(_members(output)) != evidence["apex_members"]:
        raise ValueError("Generated APEX bytes changed while attaching format validation.")
    return output, {**evidence, "package_sha256": _sha(output), "package_bytes": len(output)}


def validate_xml_package(candidate, validation_directory, *, validator=None):
    """Fresh SQLcl /nolog validation of exact bytes; override only for synthetic tests."""
    if type(candidate) is not bytes:
        raise ValueError("The exact generated candidate bytes are required.")
    _check_candidate(candidate)
    validation = (validator or validate_offline)(candidate, validation_directory)
    return _seal_validated_xml_package(candidate,
        {"candidate_sha256": _sha(candidate), "validation": validation}, validation_directory)
