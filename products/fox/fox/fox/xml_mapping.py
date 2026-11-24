"""Deterministic original XML -> one synthetic APEXlang project, without AI.

Generation, offline format validation and business acceptance are separate facts.
No source SQL is executed and no customer schema or editable workflow is inferred.
"""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
from html import escape
import json
from pathlib import Path
import re

from forms2apex import native_blueprint, native_behavior, numeric_expression, local_comparison, native_relations, native_assignments, native_policy_rules, native_buffer, record_buffer, native_lookups, source_lookup, native_record_groups
from forms2apex.native_behavior import render_behavior_package
from forms2apex import display_expression, native_display_projection
from .forms_display_projection import build_display_projections

from .forms_blueprint import validate_blueprint
from .forms_mapping_gaps import classify_gaps
from .forms_discrepancies import build_discrepancies, validate_discrepancies, build_dependency_evidence
from .forms_relation_plan import build_relation_plan
from .forms_assignment_plan import build_assignment_plan
from .forms_policy_plan import build_policy_plan
from .forms_order_rules import apply_order_rules
from .forms_module_navigation import apply_module_navigation, block_labels, source_modules
from .forms_buffer_plan import build_buffer_plan
from .forms_lookup_plan import build_lookup_plan
from .forms_guarded_query import apply_guarded_queries
from .forms_manifest_filter import apply_manifest_filters
from .forms_session_defaults import apply_session_defaults
from .forms_record_entry import apply_record_entries
from .forms_draft_policy import apply_draft_policies
from .forms_synthetic_save import apply_synthetic_saves
from .forms_item_validation import apply_item_validations
from .forms_interface_inventory import build_interface_inventory, interface_inventory_csv
from .forms_gap_requirements import add_gap_requirements
from .forms_event_callables import CODE_MEMBER as SCALAR_EVENT_CODE, build_event_callables
from .forms_lov_return import apply_lov_returns
from .forms_master_detail import apply_master_details
from .forms_detail_clear import apply_detail_clear
from .forms_approval_action import apply_approval_actions
from .forms_staged_query import apply_staged_queries
from .forms_behavior_plan import build_behavior_plan
from .forms_native_plan import POLICY_ID, build_native_prototype_plan
from . import xml_supporting_inputs
from .forms_understanding_packet import _build, generation_sources
from .prototype_export_only import (MAX_ZIP, _compatibility, _members, _validated_log,
                                    _zip, validate_offline)

SCOPE = "fox-xml-mapping-package-v1"
CATALOG_ID = "fox-xml-mapping-catalog-v1"
_FALSE = ("schema_prepared", "import_verified", "runtime_verified",
          "clean_schema_install_passed", "package_reimport_passed",
          "technically_verified", "business_behavior_accepted")
_BEHAVIOR_RULES = {
    "typed_draft_lookup": "fox.validation.typed-row-lookup",
    "literal_item_focus": "fox.item.literal-focus-command",
    "item_null_query_override": "fox.item.null-query-command",
    "cross_block_item_lookup_validation": "fox.validation.draft-item-lookup",
    "record_group_with_caller_returns": "fox.query.record-group-caller-returns",
    "record_group_with_draft_catalog": "fox.query.row-lookup-draft",
    "synthetic_parent_copy_write": "fox.assignment.synthetic-record-save",
    "selected_record_entry_assignment": "fox.policy.selected-record-entry",
    "source_filtered_block_query": "fox.query.source-block-filter",
    "source_session_default": "fox.session.source-default",
    "rate_new_draft_default": "fox.rate.create-record-default",
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
         "Continue validates the value on an existing synthetic record and moves focus. Repeated source messages appear as one notification."),
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
         "Typed PL/SQL review procedures and ordered effects with exact source/context bindings.", "The complete rule is available as review code. The source-unit note identifies any connected APEX effects and remaining event bindings."),
        ("fox.policy.parent-draft-guard", "A source record-entry policy sets edit permissions for a related draft block using fields on the selected parent.",
         "The draft editor rechecks the selected parent's current policy on the server.", "This connects the rule to session drafts. The full rule still needs its other item, block and event bindings."),
        ("fox.buffer.duplicate-record-validation", "Complete source duplicate trigger, local helper/formula and control SUM with proven parent relation and bounded direct character fields.",
         "Native session-draft editor validates the current record against loaded same-parent drafts before keeping or moving records.", "No customer-table save. Explicit draft lifecycle, 1000-row cap, source size limits and matching binary comparison/encoding prerequisites; target runtime remains unverified."),
        ("fox.lookup.source-read-event", "Complete same-block SELECT INTO lookup with exact source exception/null-reset behavior and typed native fields.",
         "Native selected-record POST-QUERY handlers or explicit Apply lookup POST-CHANGE adapters, linked from source reports.", "Original read interfaces are embedded but disabled by default behind restricted server-only readiness items. Existing field edit restrictions are retained; no customer save. Verify original objects, types, privileges and authorization before activation; runtime remains unverified."),
        ("fox.query.record-group-report", "Complete query record group with matching projected columns, verified row context and bounded SELECT grammar.",
         "Native reference choices report linked from the synthetic source row chooser.", "Original database and session inputs require trusted configuration. Read-only selection view. LOV return to the calling field remains pending."),
        ("fox.query.record-group-caller-returns", "The query has an explicit source calling item and complete typed return bindings on a supported record.",
         "Choose a reference row and apply its values to the calling field and its declared companion fields.", "The caller editor uses the selected synthetic row and its session draft. Applying a choice requires a verified source interface and a permitted current row."),
        ("fox.query.row-lookup-draft", "An optional list on an otherwise omitted caller block has an eligible source query and complete typed return mappings within that block.",
         "Select a synthetic choice and apply every mapped value to one identified draft row.",
         "The generated editor uses private test tables for the reference catalog and session-owned drafts. Other original events and business persistence remain separate."),
        ("fox.query.guarded-related-query", "Complete item KEY-EXEQRY guard using non-null keys on the selected parent in a proven incoming relation.",
         "Manual Execute query action refreshes the related synthetic report after checking its parent keys.", "Uses the selected persisted row. The related view can also query on initial entry. Automatic coordination and dirty record buffers remain separate."),
        ("fox.rate.create-record-default", "A complete block-level WHEN-CREATE-RECORD initializes projected fields with typed literals.",
         "Initialize a new synthetic rate draft once, with the fields bound to its own module and block.",
         "Reopening a saved rate preserves its stored values. Original business posting and other source events retain their own coverage."),
        ("fox.session.source-default", "Complete form initialization loads one global from a single-row NVL lookup and preserves it on error.",
         "Runs on the first mapped module page visited in an enabled application session.", "Trusted source context and a verified original interface are required. A new APEX session adapts Forms launch timing. Subsequent visits retain the initialized value."),
        ("fox.query.source-block-filter", "Whole block filter consists of direct source column equalities with literals and trusted globals.",
         "A dedicated original-source query page applies the declared filter to its verified database source.", "Source reads require a trusted session context and an enabled interface. The other prototype screens continue to use synthetic tables. This read adapter covers the source query only."),
        ("fox.policy.selected-record-entry", "Complete conditional scalar assignment on record entry with an explicitly selected record and proven parent chain.",
         "Native page applies the assignment to session state for the selected synthetic record.", "Inputs come from the selected synthetic rows. False and NULL conditions preserve the previous flag. Other lookup pages and drafts have independent state. This adapter applies when the selected record-entry page is opened."),
        ("fox.validation.draft-item-lookup", "A complete changed-item rule binds its parent fields, row state, single-row lookup and ordered effects to the current guarded draft.",
         "Validate a changed draft item against the mapped test table and retain the source field effects in the current record.", "The lookup uses synthetic rows across all parents. The subsequent Forms navigation and transaction have their own source-unit status."),
        ("fox.validation.item-lookup-review", "Complete item-validation logic is parsed, but one or more required state or data bindings are unavailable.",
         "Review the ordered field effects and query in the item-validation receipt.", "The event remains disconnected until the missing bindings are established."),
        ("fox.relation.selected-master-population", "Source population trigger and local helpers match a proven relation, key guard and selected record.",
         "Show selected master context and refresh the related records for supported states.", "Other Forms buffer, message-level and cursor effects are tracked separately."),
        ("fox.relation.selected-master-clear", "The source clear caller and recursive helper have a bound descendant session provider on a master selection.",
         "Check related drafts when the selected master changes.", "The native clear gate covers its recorded session buffers. Other blocks and the original form-wide commit remain open."),
        ("fox.relation.partial-unit", "An incomplete source unit has exact native effect bindings in its coordination receipt.",
         "Source-linked records identify the generated pages and the effect of this unit on each page.", "Whole-unit coverage remains unfinished until the remaining event and state behavior is connected."),
        ("fox.approval.staged-review", "The complete button procedure is parsed, including separate commits, failure branches and external call sites.",
         "Retain ordered workflow stages and identify each stage's required provider.", "Actual form state, commit outcomes and external calls require separate bindings."),
        ("fox.approval.saved-readiness", "A source-bound approval button and its current permission are linked to a selected synthetic master and two proved related blocks.",
         "Check the saved master and its related rows for the conditions in the source.", "Later checks describe currently saved rows. The action leaves approval, source commit segments and external calls pending."),
        ("fox.validation.saved-number-correction", "The readiness check identifies a numeric field with a source validation and a permitted, identified synthetic row.",
         "Open the blocking record, correct its numeric value, save and recheck the selected master.",
         "Explicit Save updates the selected synthetic record and applies its source before-update assignment. The approval transaction remains pending."),
        ("fox.query.staged-refresh", "A guarded query trigger deletes and repopulates rows for one key before executing the block query.",
         "Record the ordered source statements and link any generated session refresh page.", "Database staging visibility and the caller's transaction require target verification."),
        ("fox.delete.source-workflow", "A complete block-owned delete trigger is linked to its source fields, relation and posting stages.",
         "Record the source checks, calls and transaction order; attach the selected-record check when its inputs are proved.",
         "The source unit keeps its remaining deletion, transaction or external-provider requirements."),
        ("fox.item.literal-focus-command", "The complete item-owned Next trigger names a uniquely bound focus destination.",
         "Next moves focus to the XML target field in the selected record context.",
         "Field commands use explicitly selected saved synthetic records. Validation, record creation and form-wide commits have separate bindings."),
        ("fox.item.null-query-command", "The complete item-owned Enter Query or Execute Query handler contains only NULL.",
         "Consume that query command on its owning field and retain the current record.",
         "FOX supplies explicit query commands and browser shortcuts on the saved-record navigation screen."),
        ("fox.workflow.xml-item-entry", "A complete local entry event or navigation-and-assignment routine has been parsed and bound to its fields.",
         "Preserve ordered navigation, conditions, assignments and applicable commit boundaries in a reusable callable.",
         "Current record state, navigation side effects and whole-form commits require the recorded providers where applicable."),
        ("fox.behavior.unresolved-unit", "Complete source unit does not satisfy a supported mapping and all bindings.",
         "Unsupported or missing-input coverage with exact unit hash.", "No partial execution or invented business logic."),
        ("fox.query.saved-row-workspace", "A source-bound row editor and validated companion lists belong to the same block.",
         "Choose values on one row, save its mapped fields and reopen a durable synthetic record in a later session.",
         "Saved records belong to an application and user. Source business-table writes and unrelated source events require separate mappings."),
        ("fox.row.stored-number", "An editable stored number on the same rendered block has a supported decimal picture and a verified input binding.",
         "Edit the numeric field on the selected synthetic row and retain it through Save and Reopen.",
         "The source picture and explicit bounds constrain the prototype field. The original database precision and posting logic require independent verification."),
        ("fox.row.parent-copy", "Every component of a proved parent relation has a matching child item source copy declaration.",
         "Create an owned synthetic draft for the selected parent and retain its verified keys across Save and Reopen.",
         "An explicit action copies keys from the synthetic parent. Original record-event timing, business permissions and posting remain separate."),
        ("fox.event.scalar-procedure", "A complete scalar trigger assigns global or clock values, optionally guarded by record status or a numeric validation.",
         "Generate a PL/SQL procedure with explicit typed inputs and current-row outputs.",
         "The event host must supply the correct row, trusted Forms context and target field constraints. The procedure is available in scalar-events.sql."),
        ("fox.validation.typed-row-lookup", "A complete field change reads companion values by the typed key and defines its missing-row behavior.",
         "Recalculate the selected draft's companion fields when keeping a changed input.",
         "The generated editor uses the private synthetic lookup table. It validates a typed value on explicit submission."),
    ]
    rules.append(("fox.navigation.module-button", "One complete push-button event opens a uniquely named project module.",
                  "Open the module overview and its generated block pages.",
                  "Original startup, window, return, shared state and transaction behavior require separate bindings."))
    rules.append(("fox.display.saved-row-label", "A source display item has a complete concatenation assignment bound to the same stored row.",
                  "Calculate the display column in its synthetic reports.", "Other statements, Forms event timing and unsaved buffer behavior require separate bindings."))
    rules.append(("fox.checkbox.session-draft", "A complete changed-checkbox event and exact stored checkbox values are proved from fresh source.",
                  "Open a separate selected-row synthetic session draft from the existing report.",
                  "Only exact checked/unchecked values are admitted. Record entry, original permissions, source NULL/other display behavior and database Save remain separate; no whole source unit is counted as converted."))
    catalog = {"schema_version": 1, "catalog_id": CATALOG_ID, "revision": 30,
               "origin": "deterministic_rules", "policy_id": POLICY_ID,
               "implementation_sources": {name: _sha(Path(__file__).with_name(name).read_bytes())
                   for name in ("xml_mapping.py", "forms_native_plan.py", "forms_behavior_plan.py", "forms_module_navigation.py",
                                "forms_route_lookup_plan.py", "forms_route_lookup_native.py", "forms_route_lookup_typed.py", "forms_event_callables.py",
                                "forms_rate_choices.py", "forms_rate_workspace.py", "forms_rate_numbers.py",
                                "forms_rate_create_defaults.py", "forms_rate_parent.py", "forms_rate_parent_page.py", "forms_rate_field_coverage.py", "forms_display_projection.py",
                                "forms_checkbox_group.py", "forms_checkbox_workspace.py",
                                "xml_supporting_inputs.py", "intake.py",
                                "forms_facts.py", "forms_understanding_packet.py", "forms_blueprint.py", "forms_mapping_gaps.py", "forms_relation_plan.py", "forms_assignment_plan.py", "forms_policy_plan.py", "forms_order_rules.py", "forms_buffer_plan.py", "forms_discrepancies.py", "forms_lookup_plan.py", "forms_guarded_query.py", "forms_session_defaults.py", "forms_manifest_filter.py", "forms_record_entry.py", "forms_draft_policy.py", "forms_synthetic_save.py", "forms_lov_return.py", "forms_master_detail.py", "forms_detail_clear.py", "forms_item_validation.py", "forms_draft_providers.py", "forms_interface_inventory.py", "forms_approval_plan.py", "forms_approval_action.py",
                                "forms_staged_query_plan.py", "forms_staged_query.py",
                                "forms_numeric_correction.py", "forms_numeric_correction_page.py",
                                "forms_delete_plan.py", "forms_delete_action.py", "forms_item_commands.py",
                                "forms_item_entry_workflow.py", "forms_gap_requirements.py",
                                "forms_bag_entry_wiring.py", "forms_note_entry_wiring.py")}
                   | {"forms2apex/native_behavior.py": _sha(Path(native_behavior.__file__).read_bytes()),
                      "forms2apex/numeric_expression.py": _sha(Path(numeric_expression.__file__).read_bytes()),
                      "forms2apex/display_expression.py": _sha(Path(display_expression.__file__).read_bytes()),
                      "forms2apex/native_display_projection.py": _sha(Path(native_display_projection.__file__).read_bytes()),
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


def _attach_rate_field_coverage(files, metadata, report):
    """Keep counts complete if only part of the supplementary detail fits."""
    member = 'fox-package/rate-field-coverage.json'
    meta_path = 'fox-package/metadata.json'
    if len(files) + 2 > 4096:
        return
    base_size = len(_zip(files)) - len(files[meta_path])
    reserve = len(_bytes(metadata['apex_members'])) + 2048
    for limit in (None, 100, 20, 0):
        workspaces = []
        for w in report['workspaces']:
            items = w['items']
            if limit is not None and len(items) > limit:
                items = sorted(items, key=lambda f: f['status'] != 'pending')[:limit]
            workspaces.append({**w, 'items': items, 'limited': len(items) < w['counts']['total']})
        payload = _bytes({**report, 'workspaces': workspaces})
        descriptor = {'member': member, 'sha256': _sha(payload), 'source_binding': report['source_binding']}
        updated = _bytes({**metadata, 'rate_field_coverage': descriptor})
        if base_size + len(updated) + len(payload) + 76 + 2 * len(member) + reserve <= MAX_ZIP:
            metadata['rate_field_coverage'] = descriptor
            files[member] = payload
            files[meta_path] = updated
            return


def _attach_interface_inventory(files, metadata, inventory):
    """Fit supplementary review files alongside the mandatory source and compiler proof."""
    artifacts = {
        'json': ('fox-package/interface-register.json', _bytes(inventory)),
        'csv': ('fox-package/interface-register.csv', interface_inventory_csv(inventory).encode('utf-8-sig')),
    }
    meta_path = 'fox-package/metadata.json'
    base_size = len(_zip(files)) - len(files[meta_path])
    # Sealing adds the APEX member map, compiler descriptors and their archive
    # header. Keep room for those mandatory fields before choosing any extras.
    reserve = len(_bytes(metadata['apex_members'])) + 2048
    for choice in (('json','csv'), ('csv',), ('json',), ()):
        names = {kind: {'path': artifacts[kind][0], 'sha256': _sha(artifacts[kind][1])} for kind in choice}
        descriptor = {'scope': inventory['scope'], 'source_binding': inventory['source_binding'],
                      'record_count': len(inventory['records']), 'artifacts': names,
                      'core_reference_path': 'fox-package/discrepancy-evidence.json',
                      'detail_limited': not inventory['detail_coverage']['complete'],
                      'size_limited': len(choice) < len(artifacts)}
        updated = _bytes({**metadata, 'interface_register': descriptor})
        extra = sum(len(artifacts[k][1]) + 76 + 2*len(artifacts[k][0].encode()) for k in choice)
        if len(files) + len(choice) + 1 <= 4096 and base_size + len(updated) + extra + reserve <= MAX_ZIP:
            metadata['interface_register'] = descriptor
            files[meta_path] = updated
            for kind in choice:
                path, data = artifacts[kind]
                files[path] = data
            return
    # Even the supplementary descriptor must not displace an otherwise valid
    # package. The stable README points to the mandatory reference evidence.


def _coordination_effects(population, clearing, chunks, files):
    """Attribute only emitted effects to source units, without whole-unit promotion."""
    hashes = {c["code_unit_id"]: c["sha256"] for c in chunks}
    result = {}

    def record(uid, digest, reason, operation, rule, owner):
        if hashes.get(uid) != digest or operation["page_file"] not in files:
            raise ValueError("Coordination effect differs from its source or generated page.")
        row = result.setdefault(uid, {"source_unit_id": uid, "source_unit_sha256": digest,
                                     "reason": reason, "effects": []})
        row["effects"].append({"rule_id": rule, "operation_id": owner,
                               "page_id": operation["page_id"], "page_file": operation["page_file"]})

    for op in population["adapted_operations"]:
        if op["generation_status"] != "partial_effects_wired":
            raise ValueError("Missing selected-master effect status.")
        rule = "fox.relation.selected-master-population"
        record(op["source_unit_id"], op["source_unit_sha256"], "master_population_partly_connected", op, rule, op["operation_id"])
        for helper in op["source_helper_units"]:
            record(helper["source_unit_id"], helper["source_unit_sha256"], "master_query_helper_partly_connected", op, rule, op["operation_id"])
    for op in clearing["adapted_operations"]:
        if op["generation_status"] != "partial_effects_wired" or not op["native_event_wired"]:
            raise ValueError("Missing master-switch clear effect status.")
        for uid, digest in ((op["source_unit_id"], op["source_unit_sha256"]),
                            (op["caller_source_unit_id"], op["caller_source_unit_sha256"])):
            record(uid, digest, "master_clear_partly_connected", op, "fox.relation.selected-master-clear", op["population_operation_id"])
    return result


def _approval_bindings(plan, receipt, chunks, files):
    hashes = {c["code_unit_id"]: c["sha256"] for c in chunks}
    parsed = {}
    for op in plan["operations"]:
        uid = op["source_unit_id"]
        if uid in parsed or hashes.get(uid) != op["source_unit_sha256"]:
            raise ValueError("Approval plan differs from its source action.")
        parsed[uid] = op
    connected = {}
    for op in receipt["adapted_operations"]:
        uid = op["source_unit_id"]
        if (uid not in parsed or uid in connected or op["source_unit_sha256"] != hashes[uid]
                or op["page_file"] not in files or op["entry_file"] not in files
                or op["source_transaction_stages"] != parsed[uid]["stages"]
                or op["whole_source_unit_converted"] is not False or op["approval_flag_written"] is not False):
            raise ValueError("Approval-readiness evidence differs from its bound source stages.")
        connected[uid] = op
    return parsed, connected


def _connect_entry_drafts(entry_targets, receipt, files, scope):
    """Attach a proved session action to its existing unit, without counting it twice."""
    for action in receipt['adapted_operations']:
        uid = action['source_unit_id']
        target = entry_targets.get(uid)
        if (target is None or 'draft_wiring' in target
                or any(action[key] != target[key] for key in ('source_unit_sha256', 'source_event', 'operation_id'))
                or receipt['customer_table_writes'] is not False
                or action['page_file'] not in files or not action['connected_effects']):
            raise ValueError("Draft entry wiring differs from its source unit or target page.")
        routine = target['source_event'] == 'ProgramUnit'
        if routine and action.get('source_caller_installed') is not False:
            raise ValueError("A callable entry procedure cannot acquire an implicit source caller.")
        target.update(draft_wiring='routine' if routine else scope, page_file=action['page_file'],
                      connected_effects=list(action['connected_effects']),
                      required_boundaries=list(action['remaining_boundaries']))
        target.pop('binding_gap', None)
        if routine:
            if action['callable_argument'] != target['operation_id']:
                raise ValueError("Draft procedure argument differs from its source operation.")
            target['native_callable'] = dict(page_file=action['page_file'], callable=action['callable'],
                                             operation_id_argument=action['callable_argument'],
                                             scope=receipt['scope'], source_caller_installed=False)
        else:
            target['connection'] = 'adapted_operations'


def _numeric_correction_links(receipt, approval_pages, behavior_plan, files):
    rules = {op["source_unit_id"]: op for op in behavior_plan["operations"]
             if op["kind"] == "numeric_nonzero_then_focus"}
    links = []
    seen = set()
    for action in receipt["adapted_operations"]:
        uid = action["source_unit_id"]
        rule = rules.get(uid)
        approval = approval_pages.get(action["approval_source_unit_id"])
        identity = (uid, action["approval_source_unit_id"])
        if (identity in seen or rule is None or approval is None
                or action["source_unit_sha256"] != rule["source_unit_sha256"]
                or rule["source_item_id"] != approval["contract"]["fields"]["weight"]["source_item_id"]
                or action["entry_file"] != approval["page_file"] or action["entry_file"] not in files
                or action["readiness_final_page_sha256"] != _sha(files[action["entry_file"]])
                or action["readiness_query_sha256"] != _sha(approval["readiness_query_sql"].encode())
                or action["chooser_page_file"] not in files or action["page_file"] not in files
                or action["synthetic_table_writes"] is not True
                or action["customer_table_writes"] is not False or action["approval_flag_written"] is not False):
            raise ValueError("Numeric correction does not match the source field and readiness page.")
        seen.add(identity)
        links.append({k: action[k] for k in ("operation_id", "source_unit_id", "source_unit_sha256",
                     "approval_source_unit_id", "entry_file", "chooser_page_file", "page_file", "synthetic_table_writes",
                     "customer_table_writes", "approval_flag_written")})
    return links


def _delete_targets(plan, receipt, chunks, files):
    sources = {chunk["code_unit_id"]: chunk["sha256"] for chunk in chunks}
    targets, pairs = {}, []
    for op in plan["operations"]:
        uid = op["source_unit_id"]
        if uid in targets or sources.get(uid) != op["source_unit_sha256"]:
            raise ValueError("Delete workflow differs from its original source unit.")
        targets[uid] = {k: op[k] for k in ("source_unit_id", "source_unit_sha256", "source_event",
                                            "source_block_id", "kind", "operation_id")}
        parsed = op["parsed"]
        targets[uid]["interfaces"] = [parsed[k]["callee"] for k in ("permission_call", "audit_call") if k in parsed]
        targets[uid]["delete_tables"] = [parsed[k]["table"] for k in ("flag_delete", "cascade_delete") if parsed.get(k)]
        targets[uid]["requests_database_commit"] = parsed.get("forms_ddl_commit") is True
        targets[uid].update(plan_member="fox-package/delete-plan.json", native_page=None,
                            whole_source_unit_converted=False)
    for op in plan["operations"]:
        paired = op.get("paired_pre_delete_unit_id")
        if paired:
            pre = targets.get(paired)
            if (op["source_event"] != "KEY-DELREC" or pre is None or pre["source_event"] != "PRE-DELETE"
                    or pre["source_block_id"] != op["source_block_id"]
                    or pre["source_unit_sha256"] != op["paired_pre_delete_sha256"]):
                raise ValueError("Delete key and posting trigger belong to different source workflows.")
            pairs.append({"key_source_unit_id": op["source_unit_id"], "key_source_unit_sha256": op["source_unit_sha256"],
                          "pre_delete_source_unit_id": paired, "pre_delete_source_unit_sha256": pre["source_unit_sha256"]})
            targets[op["source_unit_id"]]["posting_interfaces"] = list(pre["interfaces"])
    for action in receipt["adapted_operations"]:
        target = targets.get(action["source_unit_id"])
        if (not target or target["native_page"] or target["source_unit_sha256"] != action["source_unit_sha256"]
                or action["page_file"] not in files or action["entry_file"] not in files
                or action["whole_source_unit_converted"] is not False or receipt["customer_table_writes"] is not False
                or receipt["synthetic_table_writes"] is not False):
            raise ValueError("Delete preflight differs from its bound source and read-only page.")
        target.update(native_page=action["page_file"], entry_file=action["entry_file"])
    return targets, pairs


def _staged_query_targets(plan, receipt, chunks, files):
    sources = {chunk["code_unit_id"]: chunk["sha256"] for chunk in chunks}
    targets = {}
    for op in plan["operations"]:
        uid = op["source_unit_id"]
        if uid in targets or sources.get(uid) != op["source_unit_sha256"]:
            raise ValueError("Staged query plan differs from its source action.")
        targets[uid] = {"source_unit_id": uid, "source_unit_sha256": op["source_unit_sha256"],
                        "operation_id": op["operation_id"], "plan_member": "fox-package/staged-query-plan.json",
                        "native_page": None, "whole_source_unit_converted": False}
    for action in receipt["generated_operations"]:
        target = targets.get(action["source_unit_id"])
        if (not target or target["native_page"] is not None or action["page_file"] not in files
                or action["plan_operation_id"] != target["operation_id"]
                or action["source_unit_sha256"] != target["source_unit_sha256"]
                or action["native_event_wired"] is not True or action["customer_table_writes"] is not False
                or action["whole_source_unit_converted"] is not False):
            raise ValueError("Staged query page differs from its source plan.")
        target["native_page"] = action["page_file"]
    return targets


def _delete_interface_links(plan, register):
    sites = {(r["source"]["source_unit_id"], r["position"]["character_offset"]): r
             for r in register["records"] if r["role"] == "routine_invocation" and r["position"]}
    links = []
    for op in plan["operations"]:
        for role in ("permission_call", "audit_call"):
            call = op["parsed"].get(role)
            if not call:
                continue
            position = call["position"]
            site = sites.get((op["source_unit_id"], position["character_offset"]))
            matched = (site is not None and site["name"].upper() == call["callee"].upper()
                       and site["position"]["end_character_offset"] == position["end_character_offset"]
                       and site["argument_count"] == call["arity"])
            links.append({"source_unit_id": op["source_unit_id"], "role": role, "callee": call["callee"],
                          "call_site_id": call["call_site_id"], "supplied_argument_count": call["arity"],
                          "position": position, "interface_record_id": site["id"] if matched else None,
                          "binding": "same_source_span" if matched else "see_delete_plan",
                          "target_interface_verified": False})
    return links


def _staged_query_interfaces(plan, register):
    """Link each table access to its own source position, including DELETE without FROM."""
    sites = {}
    for record in register["records"]:
        if record["role"] in {"delete", "insert", "read"} and record["position"]:
            key = (record["source"]["source_unit_id"], record["role"], record["name"].upper())
            sites.setdefault(key, []).append(record)
    links = []
    for op in plan["operations"]:
        for role, table in (("delete", op["staging_table"]), ("insert", op["staging_table"]), ("read", op["source_table"])):
            matches = sites.get((op["source_unit_id"], role, table.upper()), [])
            site = matches[0] if len(matches) == 1 else None
            links.append({"source_unit_id": op["source_unit_id"], "role": role, "source_table": table,
                          "position": site["position"] if site else None,
                          "interface_record_id": site["id"] if site else None,
                          "target_interface_verified": False})
    return links


def _approval_interface_links(plans, inventory):
    sites = {(r["source"]["source_unit_id"], r["position"]["character_offset"], (r["name"] or "").upper()): r
             for r in inventory["records"] if r["role"] == "routine_invocation" and r["position"]}
    links = []
    for uid, op in plans.items():
        for call in op["parsed"]["external_calls"]:
            site = sites.get((uid, call["position"]["character_offset"], call["callee"].upper()))
            matched = site is not None and site["position"] == call["position"] and site["argument_count"] == len(call["arguments"])
            links.append({"source_unit_id": uid, "call_site_id": call["call_site_id"], "stage_id": call["stage_id"],
                          "callee": call["callee"], "supplied_argument_count": len(call["arguments"]),
                          "interface_record_id": site["id"] if matched else None,
                          "binding": "same_source_span" if matched else "see_source_call_site",
                          "external_outcome_verified": False})
    return links


def _attach_row_lookups(documents, packet, chunks, trace, files, groups, returns, *, create_policies=None):
    from .forms_rate_create_defaults import bind_rate_create_defaults
    from .forms_rate_choices import compile_rate_choices
    from .forms_rate_numbers import compile_rate_numbers
    from .forms_rate_parent import compile_rate_parent
    from .forms_rate_parent_page import render_parent_page
    from .forms_rate_workspace import render_rate_workspace
    from .forms_route_lookup_native import render_row_lookup
    from .forms_route_lookup_plan import OPTIONAL_CALLER_GAPS, compile_row_lookups

    if not any(gap['reason'] in OPTIONAL_CALLER_GAPS for gap in returns['gaps']):
        return []
    contracts = compile_row_lookups(documents, packet, chunks, trace, files, groups, returns)
    lookup_pages = []
    if not contracts:
        return lookup_pages
    # Plan against the original receipts before decorating pages or extending
    # the schema. Every chooser for this block must share the same editor.
    anchors = Counter((c['source_module_id'], c['source_block_id']) for c in contracts)
    bundles = {c['contract_id']: compile_rate_choices(documents, packet, chunks, trace, files, groups, returns, c)
               for c in contracts if anchors[(c['source_module_id'], c['source_block_id'])] == 1}
    number_plans = {c['contract_id']: compile_rate_numbers(documents, packet, chunks, trace, files, groups, returns, c)
                    for c in contracts if bundles.get(c['contract_id'], {}).get('choices')}
    parent_plans = {c['contract_id']: compile_rate_parent(documents, packet, chunks, trace, files, groups, returns, c)
                    for c in contracts if c['contract_id'] in number_plans}
    relation_receipt = json.loads(files.get('fox-package/relation-receipt.json', b'{}'))
    relation_actions = {r['relation_id']: r for r in relation_receipt.get('generated_operations', [])}
    queries = {op['operation_id']: op for op in groups['generated_operations']}
    occupied = {int(m[1]) for name in files if (m := re.fullmatch(r'pages/p(\d+)-[^/]+\.apx', name))}
    label_blocks = {block['source_block_id']: block for block in trace['blocks']}
    # An eligible editor can also come from a transient block with no structural page.
    for contract in contracts:
        bid = contract['source_block_id']
        label_blocks.setdefault(bid, {'source_block_id': bid, 'source_module_id': contract['source_module_id'],
                                      'name': contract['source_block_name']})
    labels = block_labels(label_blocks.values(), source_modules(packet))
    init_properties = None
    if create_policies and any(op['source_event'] == 'WHEN-CREATE-RECORD' for op in create_policies[0]['operations']):
        from .forms_behavior_plan import _source_objects
        _, init_properties = _source_objects(documents, packet)
    page = 8900
    for contract in contracts:
        bundle = bundles.get(contract['contract_id'])
        choices = bundle['choices'] if bundle else []
        group = queries[contract['record_group_operation_id']]
        uid, lid = contract['source_unit_id'], contract['source_lov_id']
        matches = [g for g in returns['gaps'] if (g['source_unit_id'], g['source_lov_id']) == (uid, lid)]
        if (len(matches) != 1 or matches[0]['reason'] not in OPTIONAL_CALLER_GAPS
                or group['source_unit_sha256'] != contract['source_unit_sha256']
                or contract['source_binding'] != packet['source_binding']):
            raise ValueError('Row lookup no longer matches the unresolved caller and source query.')
        parent_plan = parent_plans.get(contract['contract_id'])
        parent_binding = parent_plan['binding'] if parent_plan else None
        span = 2 + len(choices) + int(parent_binding is not None)
        while occupied.intersection(range(page, page + span)):
            page += 1
        if page + span > 9900:
            raise ValueError('No native page range is available for the lookup editor.')
        numbers = number_plans.get(contract['contract_id'])
        initializer = None
        if choices:
            numbers = numbers if numbers['fields'] else None
            if init_properties is not None:
                parent_keys = {x['child_item_id'] for x in parent_binding['join_pairs']} if parent_binding else set()
                initializer = bind_rate_create_defaults(packet, *create_policies, contract, bundle,
                                                        properties=init_properties, parent_keys=parent_keys)
        relation = None
        if parent_binding is not None:
            relation = relation_actions.get(parent_binding['relation_id'])
            if (not relation or relation['child_block_id'] != contract['source_block_id']
                    or relation['source_module_id'] != contract['source_module_id']
                    or relation['page_file'] not in files):
                raise ValueError('The parent copy must be reached from its own generated relation.')

        def render_editor(init):
            if not choices:
                return render_row_lookup(contract, page), None
            workspace = render_rate_workspace(contract, bundle, page, numbers=numbers,
                block_label=labels[contract['source_block_id']], initializer=init,
                parent=parent_plan if relation else None)
            launcher = (render_parent_page(contract, bundle, parent_plan, page, page + span - 1,
                        relation, numbers=numbers, initializer=init) if relation else None)
            return workspace, launcher

        try:
            rendered, launcher = render_editor(initializer)
        except ValueError as error:
            if not initializer or not str(error).endswith('CAPACITY'):
                raise
            # Keep an existing supported workspace; retain the source-event gap.
            initializer = None
            rendered, launcher = render_editor(None)
        target = rendered['metadata']
        if initializer:
            target['new_record_initializer'] = initializer
        if launcher:
            rendered['pages'].extend(launcher['pages'])
            child_page = relation['page_file']
            files[child_page] = native_record_groups._append(files[child_page].decode(), launcher['entry_fragment']).encode()
            target['parent_launcher'] = launcher['metadata']
        for component in rendered['pages']:
            if component['page_file'] in files or component['page_id'] in occupied:
                raise ValueError('Lookup page conflicts with an existing source screen.')
            files[component['page_file']] = component['text']
            occupied.add(component['page_id'])
        files['fox-package/supporting-schema.sql'] += b'\n' + rendered['supporting_sql']
        # Retain the complete underlying reference report. The entry button also
        # appears on its normal source report, so a user can open the editor
        # while the original database interface remains disabled.
        entry_files = list(dict.fromkeys(group['report_files'] + [group['chooser_file'], group['page_file']]))
        label = ('Edit ' + contract['source_block_name'] + ' rows' if choices else
                 'Edit ' + contract['source_caller_name'] + ' choices')
        button = native_record_groups._button(page, page, label)
        for path in entry_files:
            text = files[path].decode()
            if '    region records (\n' not in text:
                raise ValueError('The declared lookup entry point has no report region.')
            files[path] = native_record_groups._append(text, button).encode()
        op = {'kind': 'source_optional_row_lookup', 'operation_id': contract['contract_id'],
              'source_group_unit_id': uid, 'source_unit_id': uid, 'source_unit_sha256': group['source_unit_sha256'],
              'source_group_unit_sha256': group['source_unit_sha256'], 'record_group_operation_id': group['operation_id'],
              'source_lov_id': lid, 'source_caller_name': contract['source_caller_name'],
              'source_caller_item_id': contract['source_caller_item_id'], 'source_caller_id': contract['source_caller_item_id'],
              'source_block_id': contract['source_block_id'], 'return_mappings': contract['returns'],
              'page_id': page, 'page_file': target['entry_page_file'], 'chooser_file': target['chooser_page_file'],
              'lov_return_implemented': True, 'native_event_wired': True, 'query_already_counted': True,
              'entry_files': entry_files, 'contract': contract, 'native_target': target,
              'customer_table_writes': False, 'original_reads_enabled': False, 'session_draft_table_writes': True,
              'runtime_verified': False, 'business_accepted': False}
        if choices:
            op['durable_synthetic_save'] = True
            tables = sorted({contract['caller_source_table'], contract['source_table'],
                             *(choice['source_table'] for choice in choices)})
            op['original_tables_to_verify'] = tables
            html = ('<p>For a customer database connection, check the table or view definitions (DDL) '
                    'for these source objects and provide any missing definitions to the project.</p><ul>'
                    + ''.join(f'<li>{escape(name)}</li>' for name in tables)
                    + '</ul><p>Save and Reopen here use private synthetic tables.</p>')
            region = native_buffer._expand_groups(f'''    region source-definitions (
        name: Supporting files for original data
        type: staticContent
        source {{ htmlCode: {json.dumps(html)} }}
        layout {{ sequence: 95
            slot: body }}
        appearance {{ template: @/standard }}
    )
''')
            editor = target['entry_page_file']
            files[editor] = native_record_groups._append(files[editor].decode(), region).encode()
        returns['gaps'].remove(matches[0])
        returns['generated_operations'].append(op)
        lookup_pages.append(op)
        if choices:
            links = {c['source_lov_id']: c for c in target['companion_choices']}
            if len(links) != len(choices):
                raise ValueError('Companion choice page bindings are incomplete.')
            attached = set(entry_files)
            for choice in choices:
                cg = queries[choice['record_group_operation_id']]
                cuid, clid = choice['source_unit_id'], choice['source_lov_id']
                gaps = [g for g in returns['gaps'] if (g['source_unit_id'], g['source_lov_id']) == (cuid, clid)]
                existing = [g for g in returns['generated_operations']
                            if (g['source_group_unit_id'], g['source_lov_id']) == (cuid, clid)]
                pending = len(gaps) == 1 and gaps[0]['reason'] == 'LOV_RETURN_CALLER_BLOCK' and not existing
                also_connected = (not gaps and len(existing) == 1 and existing[0]['kind'] == 'source_caller_lov_return'
                                  and existing[0]['source_caller_item_id'] == choice['source_caller_item_id']
                                  and existing[0]['source_group_unit_sha256'] == choice['source_unit_sha256']
                                  and [(f['source_item_id'], f['source_column']) for f in existing[0]['return_mappings']]
                                  == [(f['source_item_id'], f['source_column']) for f in choice['returns']])
                link = links[clid]
                if (not (pending or also_connected)
                        or cg['source_unit_sha256'] != choice['source_unit_sha256']
                        or choice['source_block_id'] != contract['source_block_id']
                        or link['chooser_page_file'] not in files):
                    raise ValueError('Companion list differs from its source unit or native editor.')
                entries = list(dict.fromkeys(cg['report_files'] + [cg['chooser_file'], cg['page_file']]))
                for path in entries:
                    if path not in attached:
                        files[path] = native_record_groups._append(files[path].decode(), button).encode()
                        attached.add(path)
                companion = {**op, 'kind': 'source_companion_row_lookup',
                    'operation_id': choice['contract_id'], 'source_group_unit_id': cuid, 'source_unit_id': cuid,
                    'source_unit_sha256': cg['source_unit_sha256'], 'source_group_unit_sha256': cg['source_unit_sha256'],
                    'record_group_operation_id': cg['operation_id'], 'source_lov_id': clid,
                    'source_caller_name': choice['source_caller_name'], 'source_caller_id': choice['source_caller_item_id'],
                    'source_caller_item_id': choice['source_caller_item_id'], 'return_mappings': choice['returns'],
                    'entry_files': entries, 'chooser_file': link['chooser_page_file'], 'contract': choice, 'native_target': link}
                if pending:
                    returns['gaps'].remove(gaps[0])
                    returns['generated_operations'].append(companion)
                else:
                    existing[0]['shared_editor'] = {'page_file': op['page_file'], 'chooser_file': companion['chooser_file'],
                                                    'operation_id': companion['operation_id']}
                lookup_pages.append(companion)
            number_report = number_plans[contract['contract_id']]
            if number_report['fields'] or number_report['gaps']:
                op['stored_numbers'] = number_report
            if parent_binding or parent_plan['gaps']:
                op['parent_copy'] = parent_plan
        page += span
    returns['session_draft_table_writes'] = True
    return lookup_pages


def _final_record_groups(groups, returns):
    """Keep query and return evidence together and count the query unit once."""
    by_lov = {}
    for op in returns["generated_operations"]:
        key = (op["source_group_unit_id"], op["source_lov_id"])
        if key in by_lov:
            raise ValueError("Duplicate LOV caller binding.")
        by_lov[key] = op
    unresolved = {(g["source_unit_id"], g["source_lov_id"]): g for g in returns["gaps"]}
    result = deepcopy(groups["generated_operations"])
    for group in result:
        connected = 0
        for lov in group["associated_lovs"]:
            key = (group["source_unit_id"], lov["source_lov_id"])
            op = by_lov.pop(key, None)
            if op is None:
                gap = unresolved.pop(key)
                if gap["declared_return_mappings"] != lov["return_mappings"]:
                    raise ValueError("Unresolved LOV returns differ from their source.")
                lov["return_gap"] = gap["reason"]
                continue
            if (op["record_group_operation_id"] != group["operation_id"]
                    or op["source_group_unit_sha256"] != group["source_unit_sha256"]
                    or len(op["return_mappings"]) != len(lov["return_mappings"])):
                raise ValueError("LOV caller returns differ from their source query.")
            connected += len(op["return_mappings"])
            lov.update(lov_return_implemented=True, caller=op["source_caller_name"],
                       caller_item_id=op["source_caller_item_id"], return_operation_id=op["operation_id"])
            if op.get("kind") in {"source_optional_row_lookup", "source_companion_row_lookup"}:
                lov.update(row_editor_page=op["page_file"], choice_catalog="synthetic",
                           return_scope="selected_session_draft")
                if op.get("durable_synthetic_save"):
                    lov["durable_synthetic_save"] = True
            elif op.get("shared_editor"):
                lov.update(row_editor_page=op["shared_editor"]["page_file"], choice_catalog="synthetic",
                           return_scope="selected_session_draft", durable_synthetic_save=True)
        if connected:
            pending = group["unimplemented_lov_return_mapping_count"] - connected
            group.update(kind="record_group_with_caller_returns", connected_return_count=connected,
                         unimplemented_lov_return_mapping_count=pending, lov_return_implemented=pending == 0,
                         warnings=["explicit_source_lov_return_mappings_unimplemented"] if pending else [],
                         adaptation="The query supports selection and return to a source-linked session draft for the recorded caller.")
    if by_lov or unresolved:
        raise ValueError("LOV disposition does not match a generated record group.")
    return result


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


def _attach_checkbox_drafts(documents, packet, chunks, trace, files):
    """Add independently proved, partial drafts without promoting source events."""
    # Use the already rebuilt object inventory, not another parse for every form.
    if not any(obj['kind'] == 'Trigger' and (obj.get('name') or '').upper() == 'WHEN-CHECKBOX-CHANGED'
               for entry in packet['sources'] for obj in entry['facts']['objects']):
        return None
    from .forms_checkbox_group import build_checkbox_groups
    from .forms_checkbox_workspace import attach_report_action, render_checkbox_workspace

    receipt = build_checkbox_groups(documents, packet, chunks, trace)
    occupied = {int(m[1]) for name in files if (m := re.fullmatch(r'pages/p(\d+)-[^/]+\.apx', name))}
    for name, raw in files.items():
        if name.endswith('.apx'):
            occupied.update(int(m) for m in re.findall(r'(?m)^page\s+(\d+)\s*\(', raw.decode()))
    schema_member = 'fox-package/supporting-schema.sql'
    schema = files[schema_member]
    tables = set(re.findall(rb'\bcreate\s+table\s+([A-Z][A-Z0-9_$#]*)', schema, re.I))
    tables = {name.decode().upper() for name in tables}
    generated, summaries = [], []
    for group in receipt['groups']:
        page = next((p for p in range(8100, 10000) if p not in occupied), None)
        proof = {key: group[key] for key in ('source_unit_id', 'source_unit_sha256', 'source_block_id')}
        if page is None:
            receipt['gaps'].append({**proof, 'reason': 'CHECKBOX_PACKAGE_PAGE_CAPACITY'})
            continue
        try:
            rendered = render_checkbox_workspace(group, page)
        except ValueError as error:
            # A renderer capacity/admission limit leaves the original event visible.
            receipt['gaps'].append({**proof, 'reason': str(error)})
            continue
        target = rendered['metadata']
        source = group['report_file']
        if (source not in files or target['source_page_file'] != source
                or target['source_page_id'] != group['report_page_id']
                or target['source_unit_sha256'] != group['source_unit_sha256']
                or target['source_binding'] != packet['source_binding']):
            raise ValueError('Checkbox draft no longer matches its source report.')
        source_text = files[source].decode()
        if not re.search(r'(?m)^page\s+' + str(group['report_page_id']) + r'\s*\(', source_text):
            raise ValueError('Checkbox source report has a different page identity.')
        pages = rendered['pages']
        if (len(pages) != 1 or pages[0]['page_id'] != page or pages[0]['page_file'] in files
                or target['page_id'] != page or target['page_file'] != pages[0]['page_file']
                or target['draft_table'].upper() in tables
                or any(re.search(r'(?m)^\s*alias:\s*' + re.escape(target['page_alias']) + r'\s*$', raw.decode())
                       for name, raw in files.items() if name.endswith('.apx'))):
            raise ValueError('Checkbox draft conflicts with an existing page or table.')
        # Validate every identity before changing the package; entry links are additive.
        block = next(b for b in trace['blocks'] if b['source_block_id'] == group['source_block_id'])
        try:
            files[source] = attach_report_action(source_text, block, group, page).encode()
        except ValueError as error:
            if str(error) != 'CHECKBOX_WORKSPACE_RECORD_QUERY_CAPACITY':
                receipt['gaps'].append({**proof, 'reason': str(error)})
                continue
            # Preserve access to a previously eligible workspace when an extra
            # report projection would exceed Oracle's generated SQL limit.
            title = 'All saved rows for checkbox drafts (separate from the report filter)'
            fragment = rendered['entry_fragment'].replace('Account checkbox session drafts', title, 1)
            files[source] = native_record_groups._append(source_text, fragment).encode()
            target['entry_mode'] = 'all_rows_selector_at_query_limit'
        else:
            target['entry_mode'] = 'source_report_row'
        files[pages[0]['page_file']] = pages[0]['text']
        schema += b'\n' + rendered['supporting_sql']
        occupied.add(page)
        tables.add(target['draft_table'].upper())
        generated.append({**group, 'native_target': target})
        summaries.append({**proof, 'source_block_name': group['source_block_name'],
                          'controller': group['controller']['source_name'],
                          'dependents': [field['source_name'] for field in group['dependents']],
                          'page_id': page, 'page_file': target['page_file'], 'reset_on_manual_off': True})
    files[schema_member] = schema
    receipt['groups'] = generated
    member = 'fox-package/checkbox-drafts.json'
    if member in files:
        raise ValueError('Checkbox draft receipt already exists.')
    files[member] = _bytes(receipt)
    return {'member': member, 'sha256': _sha(files[member]),
            'scope': 'synthetic_session_draft_only', 'groups': summaries,
            'gaps': [{key: gap[key] for key in ('source_unit_id', 'reason')} for gap in receipt['gaps']],
            'generated_group_count': len(generated), 'gap_count': len(receipt['gaps']),
            'converted_code_unit_count': 0, 'exact_checked_unchecked_only': True,
            'null_other_values_accepted': False, 'original_access_rights_proven': False,
            'record_entry_initialization_implemented': False, 'durable_synthetic_save': False,
            'customer_table_writes': False, 'runtime_verified': False, 'business_accepted': False}


def generate_xml_package(documents, project_id, project_name, approved_policy_id):
    """Return (candidate bytes, report) from fresh originals, with no parent job.

    The explicit policy selects synthetic adaptations only. It does not record
    user business acceptance, AI review, external transfer or database authority.
    Existing packet, native planner and renderer bounds remain in force.
    """
    xml, supporting = xml_supporting_inputs.split_inputs(documents)
    with generation_sources(xml):
        return _generate_xml_package(xml, project_id, project_name, approved_policy_id, supporting=supporting)


def _generate_xml_package(documents, project_id, project_name, approved_policy_id, *, supporting=()):
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
    files, item_validation = apply_item_validations(documents, packet, chunks, trace, files)
    files["fox-package/item-validation-receipt.json"] = _bytes(item_validation)
    item_review = {u["source_unit_id"]: u for u in item_validation["encoded_operations"]}
    partial_item_events = {u["source_unit_id"] for u in item_validation.get("adapted_operations", [])}
    for op in item_validation["generated_operations"]:
        raw = item_review.pop(op["source_unit_id"], None)
        if (raw is None or raw["source_unit_sha256"] != op["source_unit_sha256"]
                or op["source_event"] != "WHEN-VALIDATE-ITEM" or op["native_event_wired"] is not True
                or op["page_file"] not in files):
            raise ValueError("Generated item validation lacks its source-bound field event.")
    files, lov_receipt = apply_lov_returns(documents, packet, chunks, trace, files)
    files["fox-package/lov-return-receipt.json"] = _bytes(lov_receipt)
    files, population = apply_master_details(documents, packet, chunks, trace, files)
    files["fox-package/master-detail-receipt.json"] = _bytes(population)
    files, clearing = apply_detail_clear(documents, packet, chunks, trace, files)
    files["fox-package/detail-clear-receipt.json"] = _bytes(clearing)
    coordination = _coordination_effects(population, clearing, chunks, files)
    files, approval = apply_approval_actions(documents, packet, chunks, trace, files)
    files["fox-package/approval-action-receipt.json"] = _bytes(approval)
    approval_plan = json.loads(files["fox-package/approval-plan.json"])
    approval_units, approval_pages = _approval_bindings(approval_plan, approval, chunks, files)
    files, stage_receipt = apply_staged_queries(documents, packet, chunks, trace, files)
    files["fox-package/staged-query-receipt.json"] = _bytes(stage_receipt)
    stage_plan = json.loads(files["fox-package/staged-query-plan.json"])
    staged_units = _staged_query_targets(stage_plan, stage_receipt, chunks, files)
    from .forms_numeric_correction_page import apply_numeric_corrections
    files, correction_receipt = apply_numeric_corrections(documents, packet, chunks, trace, files)
    files["fox-package/numeric-correction-receipt.json"] = _bytes(correction_receipt)
    numeric_corrections = _numeric_correction_links(correction_receipt, approval_pages, behavior_plan, files)
    from .forms_delete_action import apply_delete_actions
    files, delete_receipt = apply_delete_actions(documents, packet, chunks, trace, files)
    files["fox-package/delete-action-receipt.json"] = _bytes(delete_receipt)
    delete_plan = json.loads(files["fox-package/delete-plan.json"])
    delete_targets, delete_pairs = _delete_targets(delete_plan, delete_receipt, chunks, files)
    from .forms_item_commands import apply_item_commands
    from .forms_item_entry_workflow import apply_item_entry_workflows
    files, commands = apply_item_commands(documents, packet, chunks, trace, files)
    files["fox-package/item-command-receipt.json"] = _bytes(commands)
    for command in commands['generated_operations']:
        if command['page_file'] not in files or command.get('source_event') not in ('KEY-NEXT-ITEM','KEY-ENTQRY','KEY-EXEQRY'):
            raise ValueError('Item command lacks its source event or target page.')
    files, entry_work = apply_item_entry_workflows(documents, packet, chunks, trace, files)
    files["fox-package/item-entry-receipt.json"] = _bytes(entry_work)
    entry_targets = {}
    for status in ('encoded_operations', 'adapted_operations'):
        for op in entry_work[status]:
            uid = op['source_unit_id']
            if uid in entry_targets:
                raise ValueError('Item-entry workflow was counted twice.')
            target = op['target']
            if target['runtime_file'] not in files or target['plan_file'] not in files:
                raise ValueError('Item-entry workflow lacks its packaged callable or source plan.')
            if status == 'adapted_operations' and op.get('page_file') not in files:
                raise ValueError('Connected item-entry workflow lacks its native page.')
            entry_targets[uid] = {k: op[k] for k in ('source_unit_id','source_unit_sha256','source_event','operation_id')}
            entry_targets[uid].update(plan_file=target['plan_file'], runtime_file=target['runtime_file'],
                                      callable=target['callable'], connection=status, page_file=op.get('page_file'),
                                      connected_effects=op.get('connected_effects',[]),
                                      required_boundaries=op.get('remaining_boundaries',op.get('required_boundaries',[])),
                                      caller_evidence=op.get('caller_evidence'))
            callable_target = op.get('native_callable_target')
            if callable_target:
                if callable_target['page_file'] not in files:
                    raise ValueError('Item-entry routine lacks its native callable page.')
                entry_targets[uid]['native_callable'] = {k: callable_target[k] for k in
                    ('page_file','callable','operation_id_argument','scope','source_caller_installed')}
            if op.get('integration_boundary_evidence'):
                entry_targets[uid]['binding_gap'] = op['integration_boundary_evidence'].get('reason')
    from .forms_bag_entry_wiring import apply_bag_entry_wiring
    from .forms_note_entry_wiring import apply_note_entry_wiring
    for scope, apply_wiring in (('bag',apply_bag_entry_wiring), ('note',apply_note_entry_wiring)):
        files, wiring = apply_wiring(documents, packet, chunks, trace, files)
        if wiring['source_binding'] != packet['source_binding']:
            raise ValueError("Entry wiring receipt is for a different source.")
        files[f'fox-package/{scope}-entry-wiring-receipt.json'] = _bytes(wiring)
        _connect_entry_drafts(entry_targets, wiring, files, scope)
    row_lookups = _attach_row_lookups(documents, packet, chunks, trace, files, group_receipt, lov_receipt,
                                      create_policies=(policy_plan, policy_receipt))
    files["fox-package/lov-return-receipt.json"] = _bytes(lov_receipt)
    final_groups = _final_record_groups(group_receipt, lov_receipt)
    for group in final_groups:
        projected = [lov for lov in group['associated_lovs'] if lov.get('row_editor_page')]
        if projected:
            group['kind'] = 'record_group_with_draft_catalog'
            for path in (group['page_file'], group['chooser_file']):
                text = files[path].decode()
                text = text.replace('LOV field selection and return remain unimplemented.',
                                    'Open the linked row editor to use a supported synthetic lookup.')
                text = re.sub(r'\d+ explicit source LOV return mappings remain unimplemented\.',
                              f"{group['connected_return_count']} field returns connected; "
                              f"{group['unimplemented_lov_return_mapping_count']} pending.", text)
                files[path] = text.encode()
    if row_lookups:
        trace["lookup_draft_pages"] = [
            {k: op[k] for k in ('source_block_id', 'source_caller_item_id', 'page_file', 'chooser_file')}
            for op in row_lookups]
        files['fox-package/source-to-page.json'] = _bytes(trace)
    files, module_navigation = apply_module_navigation(documents, packet, chunks, trace, files)
    navigation_member = "fox-package/module-navigation.json"
    files[navigation_member] = _bytes(module_navigation)
    navigation_actions = {op["source_unit_id"]: op for op in module_navigation["operations"]}
    navigation_gaps = {gap["source_unit_id"]: gap for gap in module_navigation["gaps"]}
    display_plan = build_display_projections(documents, packet, chunks, trace)
    files, display_receipt = native_display_projection.apply_display_projections(files, trace, display_plan, relation_receipt)
    display_member = "fox-package/saved-display-fields.json"
    display_units = {}
    display_items = {op['source_item_id']: op for op in display_receipt['applied']}
    if display_receipt["applied"] or display_receipt["gaps"]:
        files[display_member] = _bytes(display_receipt)
    for projection in display_receipt["applied"]:
        for proof in projection["whole_source_units"]:
            uid = proof["source_unit_id"]
            if uid in display_units:
                raise ValueError("More than one display field claims the same source assignment.")
            display_units[uid] = (proof, projection)
    checkbox_drafts = _attach_checkbox_drafts(documents, packet, chunks, trace, files)
    correctable_approvals = {link["approval_source_unit_id"] for link in numeric_corrections}
    correction_gaps = {gap.get("approval_source_unit_id", gap["source_unit_id"]): gap["reason"]
                       for gap in correction_receipt["gaps"]}
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
    typed_lookups = []
    for op in row_lookups:
        for typed in op["native_target"].get("typed_lookup_receipts", []):
            if (typed["source_binding"] != packet["source_binding"]
                    or typed["source_caller_item_id"] != op["source_caller_id"]
                    or source_objects[typed["source_owner_id"]]["parent_id"] != op["source_caller_id"]
                    or typed["source_event"] != "POST-CHANGE" or not typed["native_event_wired"]
                    or {p["page_file"] for p in typed["page_bindings"]} != {op["page_file"],op["chooser_file"]}
                    or any(p["page_file"] not in files for p in typed["page_bindings"])):
                raise ValueError("Typed lookup does not match its caller and native pages.")
            typed_lookups.append(dict(typed, kind="typed_draft_lookup",
                                      operation_id="typed-lookup-" + typed["source_unit_id"], page_file=op["page_file"]))
    create_rules = []
    for op in row_lookups:
        init = op['native_target'].get('new_record_initializer')
        if init is None or op['kind'] != 'source_optional_row_lookup':
            continue
        uid = init['source_unit_id']
        prior = policy_encoded.pop(uid, None)
        if prior is None or prior['source_unit_sha256'] != init['source_unit_sha256'] or uid in partial_policies:
            raise ValueError('Create default differs from its unique source policy')
        create_rules.append(dict(init, kind='rate_new_draft_default', page_file=op['page_file'], page_id=op['page_id']))
    source_adapters = {}
    for receipt, reason in (
        ({"generated_operations": create_rules}, "source_literal_new_draft_default"),
        ({"generated_operations": typed_lookups}, "typed_lookup_draft_generated"),
        (commands, "item_command_generated"),
        (item_validation, "item_lookup_validation_wired_to_draft"),
        (save_receipt, "parent_copy_wired_to_synthetic_write"),
        (entry_receipt, "selected_record_entry_generated"),
        (query_receipt, "related_query_action_generated"),
        ({"generated_operations": final_groups}, "record_group_query_generated_interface_pending"),
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
        if uid in lookup_gaps and uid not in source_adapters:
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
        if row["source_unit_id"] in item_review:
            if row["status"] == "generated_wired_adapted" or row.get("encoding_status") == "generated_unwired":
                raise ValueError("Two adapters claim the same parsed item rule.")
            row.update(encoding_status="generated_unwired", reason=(
                "item_lookup_partly_connected" if row["source_unit_id"] in partial_item_events
                else "item_lookup_validation_binding_pending"))
    relation_coverage = relation_receipt["coverage"] if relation_receipt else relation_plan["coverage"]
    for row in coverage:
        effect = coordination.get(row["source_unit_id"])
        if effect and row["status"] != "generated_wired_adapted":
            row["reason"] = effect["reason"]
        uid = row["source_unit_id"]
        if uid in staged_units:
            if row["status"] == "generated_wired_adapted" or row.get("encoding_status") == "generated_unwired":
                raise ValueError("Two mappings claim the same staging trigger.")
            row.update(encoding_status="generated_unwired", reason=(
                "staged_query_partly_connected" if staged_units[uid]["native_page"] else "staged_query_binding_pending"))
        if uid in approval_units:
            if row["status"] == "generated_wired_adapted" or row.get("encoding_status") == "generated_unwired":
                raise ValueError("Two adapters claim the same approval trigger.")
            row.update(encoding_status="generated_unwired", reason=(
                "approval_readiness_partly_connected" if uid in approval_pages else "approval_source_binding_pending"))
            if uid in correctable_approvals:
                row["saved_weight_correction"] = "connected"
            elif uid in correction_gaps:
                row["saved_weight_correction"] = "unavailable"
                row["saved_weight_correction_reason"] = correction_gaps[uid]
        if uid in delete_targets:
            if row["status"] == "generated_wired_adapted" or row.get("encoding_status") == "generated_unwired":
                raise ValueError("Two mappings claim the same delete trigger.")
            target = delete_targets[uid]
            row.update(encoding_status="generated_unwired", delete_event=target["source_event"],
                       reason="delete_check_partly_connected" if target["native_page"] else "delete_posting_binding_pending")
            row["delete_requirements"] = {k: target[k] for k in ("interfaces", "delete_tables", "requests_database_commit")}
            row["delete_requirements"]["posting_interfaces"] = target.get("posting_interfaces", [])
        if uid in entry_targets:
            op = entry_targets[uid]
            if (op['source_unit_sha256'] != row['source_unit_sha256'] or row["status"] == "generated_wired_adapted"
                    or row.get("encoding_status") == "generated_unwired"):
                raise ValueError("Item-entry workflow overlaps another source rule or has a different source hash.")
            row.update(encoding_status="generated_unwired", item_entry_boundaries=op["required_boundaries"],
                       item_entry_draft_wiring=op.get('draft_wiring'),
                       item_entry_caller_absent=bool(op["caller_evidence"] and not op["caller_evidence"]["original_caller_proven"]),
                       item_entry_native_callable=bool(op.get('native_callable')),
                       item_entry_binding_gap=op.get('binding_gap'),
                       reason="item_entry_partly_connected" if op["connection"]=="adapted_operations" else "item_entry_provider_pending")
            if op.get('draft_wiring'):
                row['reason'] = ('item_entry_draft_callable' if op['draft_wiring']=='routine'
                                 else 'item_entry_draft_connected')
        if uid in navigation_actions or uid in navigation_gaps:
            binding = navigation_actions.get(uid) or navigation_gaps[uid]
            if (binding["source_unit_sha256"] != row["source_unit_sha256"]
                    or binding["source_owner_id"] != row["source_owner_id"]):
                raise ValueError("Module navigation differs from the source event.")
            claimed = row["status"] == "generated_wired_adapted" or row.get("encoding_status") == "generated_unwired"
            if uid in navigation_actions:
                if claimed:
                    raise ValueError("Module navigation overlaps another generated mapping.")
                row.update(reason="module_navigation_partly_connected", module_target=binding["literal_target"])
            elif not claimed:
                row.update(reason="module_navigation_pending", module_target=binding["literal_target"],
                           module_gap=binding["reason"])
        if uid in display_units:
            proof, projection = display_units[uid]
            if (proof['source_unit_sha256'] != row['source_unit_sha256'] or proof['source_owner_id'] != row['source_owner_id']
                    or row['status'] == 'generated_wired_adapted' or row.get('encoding_status') == 'generated_unwired'):
                raise ValueError("Saved display projection conflicts with a source operation.")
            row.update(reason="saved_display_partly_connected", display_target=projection['qualified_target'])
    scalar_events, scalar_sql = build_event_callables(documents, packet, chunks, coverage, project_id)
    if scalar_sql:
        files[SCALAR_EVENT_CODE] = scalar_sql
        for row in coverage:
            if row["source_unit_id"] in scalar_events:
                row.update(encoding_status="generated_unwired", reason="scalar_event_host_pending")
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
        if row.get("code") == "code_unit_not_translated" and row.get("code_unit_id") in scalar_events:
            row.update(code="scalar_event_host_pending", reason="The complete scalar procedure is generated.",
                       next_action="Bind its typed parameters to a verified row and event before installation.")
        if row.get("code_unit_id") in policy_encoded and row.get("code") == "code_unit_not_translated":
            row.update(code="policy_generated_unwired", encoding_status="generated_unwired",
                reason="Complete policy review code generated; original event and state providers remain unwired.",
                next_action="Review policy-review.sql and its ordered effects; implement event/context adapters and server-side enforcement before activation.")
            if row["code_unit_id"] in partial_policies:
                row.update(reason="The selected parent controls edits in the related session draft.",
                           next_action="Connect the remaining field, block and record-entry effects.")
    trace_blocks = {block["source_block_id"]: block for block in trace["blocks"]}
    for row in remediation:
        partial = coordination.get(row.get("code_unit_id"))
        if partial and row.get("code") in {"code_unit_not_translated", "policy_generated_unwired"}:
            row.update(code="partial_coordination_effects", generation_status="partial_effects_wired",
                       reason="The generated master-detail flow implements the recorded effects of this source unit.",
                       next_action="Review the remaining lifecycle gaps for this unit in the discrepancy report.")
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
            if row["source_object_id"] in display_items:
                display = display_items[row["source_object_id"]]
                target.update(value_computation_implemented=True, computation_scope="synthetic_saved_report",
                              computation_pages=display['page_files'], computation_member=display_member,
                              native_event_wired=False)
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
        uid = row["source_unit_id"]
        if uid in display_units:
            proof, projection = display_units[uid]
            row.update(rule_id="fox.display.saved-row-label", target={
                **proof, "source_item_id": projection["source_item_id"], "member": display_member,
                "page_files": projection["page_files"], "source_event_timing_preserved": False})
        if uid in navigation_actions:
            row.update(rule_id="fox.navigation.module-button", target=deepcopy(navigation_actions[uid]))
        if uid in scalar_events:
            row.update(rule_id="fox.event.scalar-procedure", target=scalar_events[uid])
        if uid in entry_targets:
            row.update(rule_id='fox.workflow.xml-item-entry',target=entry_targets[uid])
        if uid in delete_targets:
            row.update(rule_id="fox.delete.source-workflow", target=delete_targets[uid])
        if uid in staged_units:
            row.update(rule_id="fox.query.staged-refresh", target=staged_units[uid])
        if uid in approval_units:
            plan_op = approval_units[uid]
            row.update(rule_id="fox.approval.saved-readiness" if uid in approval_pages else "fox.approval.staged-review",
                       target={"source_unit_id": uid, "source_unit_sha256": plan_op["source_unit_sha256"],
                               "operation_id": plan_op["operation_id"], "operation_sha256": plan_op["operation_sha256"],
                               "plan_member": "fox-package/approval-plan.json", "whole_source_unit_converted": False,
                               "native_page": approval_pages[uid]["page_file"] if uid in approval_pages else None})
        if row["source_unit_id"] in item_review:
            row.update(rule_id="fox.validation.item-lookup-review", target=deepcopy(item_review[row["source_unit_id"]]))
        if row["source_unit_id"] in encoded:
            row.update(rule_id="fox.assignment.parent-copy-review", target=deepcopy(encoded[row["source_unit_id"]]))
        if row["source_unit_id"] in policy_encoded:
            rule = "fox.policy.parent-draft-guard" if row["source_unit_id"] in partial_policies else "fox.policy.finite-review"
            row.update(rule_id=rule, target=deepcopy(policy_encoded[row["source_unit_id"]]))
        elif row["source_unit_id"] in coordination and row["status"] != "generated_wired_adapted":
            row.update(rule_id="fox.relation.partial-unit", target=deepcopy(coordination[row["source_unit_id"]]))
    gap_report = classify_gaps(packet, chunks, coverage)
    catalog = mapping_catalog()
    catalog_rules = {row["id"]: row for row in catalog["rules"]}
    ledger = {"schema_version": 1, "scope": "fox-xml-source-to-target-v1",
        "source_binding": packet["source_binding"], "catalog_sha256": catalog["catalog_sha256"],
        "objects": ledger_objects, "code_units": ledger_units,
        "relations": relation_coverage, "assignment_review": list(encoded.values()),
        "synthetic_write_events": save_receipt["generated_operations"],
        "item_validations": item_validation["generated_operations"],
        "partial_item_validations": item_validation.get("adapted_operations", []),
        "item_validation_review": list(item_review.values()),
        "policy_review": list(policy_encoded.values()),
        "draft_policy_guards": draft_policy["adapted_operations"],
        "draft_policy_gaps": draft_policy["gaps"],
        "selected_record_entries": entry_receipt["generated_operations"],
        "buffer_flows": list(buffered.values()),
        "source_lookups": list(looked.values()),
        "record_group_reports": final_groups,
        "lov_returns": lov_receipt["generated_operations"],
        "scalar_event_procedures": list(scalar_events.values()),
        "typed_draft_lookups": typed_lookups,
        "lov_return_gaps": lov_receipt["gaps"],
        "coordination_partial_units": list(coordination.values()),
        "approval_readiness": [{"source_unit_id": uid, "source_unit_sha256": op["source_unit_sha256"],
                                "page_file": op["page_file"], "entry_file": op["entry_file"],
                                "operation_id": op["operation_id"], "entry_kind": op["entry_kind"],
                                "approval_flag_written": False} for uid, op in approval_pages.items()],
        "source_block_filters": filter_receipt["generated_operations"],
        "session_defaults": defaults_receipt["generated_operations"],
        "guarded_queries": query_receipt["generated_operations"],
        "staged_queries": list(staged_units.values()),
        "numeric_corrections": numeric_corrections,
        "delete_workflows": list(delete_targets.values()),
        "item_commands": [{k: op[k] for k in ('source_unit_id','operation_id','page_file','source_event','kind')}
                          for op in commands['generated_operations']],
        "item_entry_workflows": list(entry_targets.values()),
        "delete_posting_pairs": delete_pairs,
        "dependencies_and_links": [deepcopy(row) for row in remediation if row["code"] == "dependency_not_implemented"],
        "structural_objects_are_business_conversion": False,
        "runtime_verified": False, "business_behavior_accepted": False}
    dependency_evidence = build_dependency_evidence(packet, chunks, ledger)
    discrepancies = build_discrepancies(packet, ledger, gap_report, catalog, chunks=chunks,
        dependency_evidence=dependency_evidence)
    validate_discrepancies(discrepancies, ledger, gap_report, catalog, packet=packet, chunks=chunks,
        dependency_evidence=dependency_evidence)
    interface_register = build_interface_inventory(packet, chunks, ledger, dependency_evidence=dependency_evidence,
                                                   discrepancies=discrepancies, documents=documents)
    add_gap_requirements(gap_report, packet, chunks, interface_register)
    ledger["approval_interface_links"] = _approval_interface_links(approval_units, interface_register)
    ledger["staged_query_interfaces"] = _staged_query_interfaces(stage_plan, interface_register)
    ledger["delete_interface_links"] = _delete_interface_links(delete_plan, interface_register)
    files["fox-package/discrepancy-evidence.json"] = _bytes(dependency_evidence)
    files["fox-package/discrepancies.json"] = _bytes(discrepancies)
    applied = sorted({row["rule_id"] for row in ledger_objects + ledger_units})
    if context_summary["relations_generated"]:
        applied = sorted(set(applied) | {"fox.relation.read-context"})
    applied = sorted(set(applied) | {e["rule_id"] for r in coordination.values() for e in r["effects"]})
    if numeric_corrections:
        applied = sorted(set(applied) | {"fox.validation.saved-number-correction"})
    if row_lookups:
        applied = sorted(set(applied) | {"fox.query.row-lookup-draft"})
    if checkbox_drafts and checkbox_drafts['groups']:
        applied = sorted(set(applied) | {'fox.checkbox.session-draft'})
    if any(op.get("durable_synthetic_save") for op in row_lookups):
        applied = sorted(set(applied) | {"fox.query.saved-row-workspace"})
    if any(op.get("stored_numbers", {}).get("fields") for op in row_lookups):
        applied = sorted(set(applied) | {"fox.row.stored-number"})
    if any(op.get("parent_copy", {}).get("binding") for op in row_lookups):
        applied = sorted(set(applied) | {"fox.row.parent-copy"})
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
        **({'checkbox_drafts': checkbox_drafts} if checkbox_drafts else {}),
        "data_mode": "synthetic_test_only", "structural_only": not bool(generated or context_summary["relations_generated"] or navigation_actions or display_units or (checkbox_drafts and checkbox_drafts['groups'])),
        **({"saved_display_fields": {"member": display_member, "sha256": _sha(files[display_member]),
                                     "count": len(display_receipt["applied"]), "pending": len(display_receipt["gaps"])}}
           if display_member in files else {}),
        "module_navigation": {"member": navigation_member, "sha256": _sha(files[navigation_member]),
                              "links": len(navigation_actions), "gaps": len(module_navigation["gaps"])},
        "structural_coverage": deepcopy(native_plan["coverage"]),
        "behavior_coverage": {"total": len(coverage), "counts": counts},
        "context_summary": context_summary,
        "policy_summary": {"rules_generated_unwired": len(policy_encoded)},
        "synthetic_save_summary": {"screens": len({op["page_file"] for op in save_receipt["generated_operations"]}),
                                   "before_write_events": len(save_receipt["generated_operations"])},
        "buffer_summary": {"record_validation_flows": len(buffered)},
        "item_validation_summary": {"wired": len(item_validation["generated_operations"]),
                                    "partial": len(partial_item_events),
                                    "encoded_only": len(item_review) - len(partial_item_events)},
        "lookup_summary": {"generated_lookup_handlers": len(looked), "original_reads_enabled": False},
        "row_lookup_summary": {"editors": len({op["page_file"] for op in row_lookups}), "mapped_returns": sum(len(op["return_mappings"]) for op in row_lookups)},
        "saved_lookup_workspaces": [
            {"page_file": op["page_file"], "source_block_id": op["source_block_id"],
             "choices": 1 + len(op["native_target"]["companion_choices"]),
             "saved_table": op["native_target"]["saved_table"], "customer_table_writes": False,
             **({"parent_launcher_page": op["native_target"]["parent_launcher"]["page_file"],
                 "copied_parent_keys": [{"parent_item_id": field["parent_item_id"], "child_item_id": field["child_item_id"],
                                         "column": field["column"]} for field in op["native_target"]["parent_copy_fields"]]}
                if "parent_launcher" in op["native_target"] else {}),
             **({"parent_copy_gaps": [g['reason'] for g in op["parent_copy"]["gaps"]]}
                if op.get("parent_copy", {}).get("gaps") else {}),
             **({"stored_number_fields": [{"id": field["source_item_id"], "name": field["source_name"],
                                           "column": field["column"]} for field in op["stored_numbers"]["fields"]],
                 "stored_number_gaps": op["stored_numbers"]["gaps"]} if "stored_numbers" in op else {})}
            for op in row_lookups if op["kind"] == "source_optional_row_lookup" and op.get("durable_synthetic_save")],
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
            + (["Install the private draft and empty lookup catalog tables from supporting-schema.sql in the test schema. Load synthetic choices into the catalog for the row editor; original business tables and Forms events have separate requirements."] if row_lookups else [])
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
        "When scalar_event_procedures is populated in the ledger, scalar-events.sql contains those complete "
        "trigger procedures and the ledger identifies their parameters. An event host supplies the current row and trusted globals. "
        "The interface register lists source call sites, supplied argument forms and affected actions. "
        "See metadata.json for included JSON or CSV exports. The mandatory reference inventory is in discrepancy-evidence.json. "
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
        "item-validation-receipt.json identifies changed-field events, the selected parent inputs and any additional synthetic write fields they bind. "
        "bag-entry-wiring-receipt.json and note-entry-wiring-receipt.json describe subsequent session-draft actions and the remaining whole-form and caller boundaries. "
        "The current row's validation state is maintained separately from its loaded baseline. Later navigation and whole-form commits remain separate events. "
        "approval-plan.json retains each proved approval stage and commit in source order. approval-action-receipt.json identifies connected readiness checks and pending target operations. "
        "lookup-activation.md lists native source SELECT-INTO handlers and restricted readiness items. Original reads are disabled by default and require verified target interfaces and separate activation authority. POST-CHANGE is adapted to Apply lookup; POST-QUERY runs after selecting a record. These pages do not save records. "
        "Other dependencies, relationship lifecycle, source transactions and behavior remain unresolved.\n\n"
        "Extract the entire project including .apex. Fresh SQLcl /nolog validation is required "
        "before a format-validated handoff. Import/schema changes require separate authorization.\n"
    ).encode("utf-8")
    if checkbox_drafts:
        files['fox-package/README.md'] += (
            b'\n## Checkbox session drafts\n\ncheckbox-drafts.json lists separately generated checkbox session drafts and rejected events. '
            b'The existing source reports and sources are preserved. Only exact checked and unchecked values are accepted; '
            b'NULL and other stored values are rejected. Manual switch-off clears dependents to their source unchecked values. '
            b'Record-entry initialization, original permissions, database Save and whole Forms events remain separate. '
            b'No source unit is counted as converted by this partial adapter. Oracle compilation, installed APEX behavior '
            b'and business acceptance remain unverified.\n')
    metadata["apex_members"] = _apex_members(files)
    extra = xml_supporting_inputs.attach(files, metadata, documents, supporting)
    if extra:
        files['fox-package/README.md'] += (
            b'\n## Supporting inputs\n\nsupporting-inputs.json lists the accompanying source files, their hashes '
            b'and declaration changes compared with the Forms XML alone. The supporting-inputs directory '
            b'preserves their original bytes as text evidence. No supporting script is installed or executed.\n')
    files["fox-package/metadata.json"] = _bytes(metadata)
    _attach_interface_inventory(files, metadata, interface_register)
    if any(op.get('durable_synthetic_save') for op in row_lookups):
        from .forms_rate_field_coverage import build_rate_field_coverage
        report = build_rate_field_coverage(documents, packet, row_lookups, scalar_events)
        if report['workspaces']:
            _attach_rate_field_coverage(files, metadata, report)
    candidate = _zip(files)
    _members(candidate)  # Retain existing package size and safe-member limits.
    return candidate, {"schema_version": 1, "scope": SCOPE,
        "candidate_sha256": _sha(candidate), "candidate_bytes": len(candidate),
        "source_binding": packet["source_binding"], "metadata": metadata,
        "blueprint_validation": blueprint_validation, "native_plan": native_plan,
        "behavior_plan": behavior_plan, "renderer_receipt": behavior_receipt,
        "mapping_ledger": ledger, "gap_report": gap_report, "discrepancies": discrepancies, "dependency_evidence": dependency_evidence, "relation_plan": relation_plan,
        "relation_receipt": relation_receipt, "assignment_plan": assignment_plan, "assignment_receipt": assignment_receipt, "policy_plan": policy_plan, "policy_receipt": policy_receipt, "order_receipt": order_receipt, "buffer_plan": buffer_plan, "buffer_receipt": buffer_receipt, "lookup_plan": lookup_plan, "lookup_receipt": lookup_receipt, "record_group_receipt": group_receipt, "guarded_query_receipt": query_receipt, "apex_members": metadata["apex_members"],
        **({'checkbox_drafts': deepcopy(checkbox_drafts)} if checkbox_drafts else {}),
        "format_validated": False, "runtime_verified": False, "business_behavior_accepted": False}


def _check_candidate(candidate):
    """Reconstruct deterministic authority, including originals, before sealing."""
    files = _members(candidate)
    try:
        metadata = json.loads(files["fox-package/metadata.json"])
        manifest = json.loads(files["fox-package/source-manifest.json"])
        docs = [(row["name"], files["fox-package/sources/" + row["name"]]) for row in manifest["files"]]
        if xml_supporting_inputs.MEMBER in files:
            supporting = json.loads(files[xml_supporting_inputs.MEMBER])
            docs.extend((row["name"],files[row["member"]]) for row in supporting["files"])
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
