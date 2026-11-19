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

from forms2apex import native_blueprint, native_behavior, numeric_expression
from forms2apex.native_behavior import render_behavior_package

from .forms_blueprint import validate_blueprint
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
        ("fox.behavior.unresolved-unit", "Complete source unit does not satisfy a supported mapping and all bindings.",
         "Unsupported or missing-input coverage with exact unit hash.", "No partial execution or invented business logic."),
    ]
    catalog = {"schema_version": 1, "catalog_id": CATALOG_ID, "revision": 1,
               "origin": "deterministic_rules", "policy_id": POLICY_ID,
               "implementation_sources": {name: _sha(Path(__file__).with_name(name).read_bytes())
                   for name in ("xml_mapping.py", "forms_native_plan.py", "forms_behavior_plan.py",
                                "forms_facts.py", "forms_understanding_packet.py", "forms_blueprint.py")}
                   | {"forms2apex/native_behavior.py": _sha(Path(native_behavior.__file__).read_bytes()),
                      "forms2apex/numeric_expression.py": _sha(Path(numeric_expression.__file__).read_bytes())},
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
    generated = {row["source_unit_id"]: row for row in
                 behavior_receipt["generated_operations"]} if behavior_receipt else {}
    remediation = deepcopy(native_plan["remediation"])
    for row in remediation:
        if row.get("code") == "code_unit_not_translated" and row.get("code_unit_id") in generated:
            row.update(code="behavior_generated_runtime_pending", generation_status="generated_wired_adapted",
                reason="Supported complete source behavior generated with explicit adaptations; runtime and business checks pending.",
                next_action="Review the generated operation and verify it in an authorized synthetic target.")
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
                "ceil_report_column", "numeric_expression_report_column"} for op in item_ops)
            target["generated_behavior_operation_ids"] = [op["operation_id"] for op in item_ops]
        ledger_objects.append({**deepcopy(row), "rule_id": rule_id, "rule_revision": 1,
            "source_file": source_files[row["source_object_id"]],
            "disposition": "generated_structural" if target else row["disposition"],
            "reason": "Native synthetic structure generated; behavior coverage is recorded separately." if target else row["reason"],
            "target": target, "business_behavior_accepted": False})
    ledger_units = []
    for row in coverage:
        op = operations.get(row["source_unit_id"])
        ledger_units.append({**deepcopy(row), "rule_id": _BEHAVIOR_RULES[op["kind"]] if op else "fox.behavior.unresolved-unit",
            "source_file": source_files[row["source_owner_id"]],
            "rule_revision": 1, "target": deepcopy(generated.get(row["source_unit_id"]))})
    catalog = mapping_catalog()
    catalog_rules = {row["id"]: row for row in catalog["rules"]}
    ledger = {"schema_version": 1, "scope": "fox-xml-source-to-target-v1",
        "source_binding": packet["source_binding"], "catalog_sha256": catalog["catalog_sha256"],
        "objects": ledger_objects, "code_units": ledger_units,
        "dependencies_and_links": [deepcopy(row) for row in remediation if row["code"] == "dependency_not_implemented"],
        "structural_objects_are_business_conversion": False,
        "runtime_verified": False, "business_behavior_accepted": False}
    applied = sorted({row["rule_id"] for row in ledger_objects + ledger_units})
    counts = dict(sorted(Counter(row["status"] for row in coverage).items()))
    compatibility = _compatibility(files, trace)
    if behavior_receipt:
        compatibility["behavior_renderer"] = {"scope": behavior_receipt["scope"],
                                               "sources": behavior_receipt["renderer_sources"]}
    metadata = {"schema_version": 1, "scope": SCOPE,
        "status": "GENERATED_FORMAT_VALIDATION_PENDING", "origin": "deterministic_local_xml",
        "project_id": project_id, "project_name": project_name, "application_count": 1,
        "source_binding": packet["source_binding"], "approved_policy_id": approved_policy_id,
        "catalog_id": CATALOG_ID, "catalog_sha256": catalog["catalog_sha256"],
        "implementation_sources": catalog["implementation_sources"],
        "applied_rule_ids": applied, "source_parser_rebuilt": True,
        "ai_review": {"performed": False, "approval_recorded": False, "origin": "none"},
        "format_validated": False, "validation": None, "native_apex_generated": True,
        "data_mode": "synthetic_test_only", "structural_only": not bool(generated),
        "structural_coverage": deepcopy(native_plan["coverage"]),
        "behavior_coverage": {"total": len(coverage), "counts": counts},
        "generated_operations": list(generated.values()),
        "structural_trace_path": "fox-package/source-to-page.json",
        "current_mapping_ledger_path": "fox-package/mapping-ledger.json",
        "native_plan_sha256": native_plan["plan_sha256"], "behavior_plan_sha256": behavior_plan["plan_sha256"],
        "adaptations": native_plan["assumptions"] + [{"scope": "generated_behavior",
            "rule_id": _BEHAVIOR_RULES[op["kind"]], "source_unit_id": op["source_unit_id"],
            "reason": catalog_rules[_BEHAVIOR_RULES[op["kind"]]]["adaptations"]}
            for op in operations.values()],
        "compatibility": compatibility, "omissions": remediation,
        "prerequisites": ["Matching APEXlang-capable SQLcl/Java for offline format validation.",
            "Separate authority and compatible isolated APEX workspace/schema before any import.",
            "Review synthetic supporting-schema.sql, unresolved behavior and lifecycle adaptations."],
        "provider_calls": 0, "database_imports": 0, **{name: False for name in _FALSE}}
    files.update({"fox-package/" + name: _bytes(value) for name, value in (
        ("mapping-catalog.json", catalog), ("mapping-ledger.json", ledger),
        ("native-plan.json", native_plan), ("blueprint.json", blueprint),
        ("blueprint-validation.json", blueprint_validation), ("behavior-coverage.json", coverage),
        ("remediation.json", remediation))})
    files["fox-package/README.md"] = (
        "# Deterministic XML synthetic prototype\n\n"
        "One project / multiple Forms XML modules / one native APEXlang application. "
        "Original XML is retained byte-for-byte under sources/. No AI was invoked or approved this mapping.\n\n"
        "CURRENT format status is in metadata.json. Generated, format validated, imported, runtime "
        "verified and business accepted are separate states. This package has no target import or runtime proof.\n\n"
        "Read mapping-ledger.json, behavior-coverage.json, remediation.json and supporting-schema.sql. "
        "Database blocks default to read-only reports; control items have no persistence. "
        "Supported report formulas use persisted synthetic rows, not the unsaved Forms buffer. "
        "Any linked Continue page validates an existing synthetic row without saving it. "
        "Dependencies, relationships, source transactions and unsupported behavior remain unresolved.\n\n"
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
        "mapping_ledger": ledger, "apex_members": metadata["apex_members"],
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
