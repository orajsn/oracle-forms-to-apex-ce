"""One-app project export/package publication with explicit historical evidence.

Single-form releases remain owned by ``release``. This module never upgrades an
old receipt, runs model SQL, deletes an application or certifies business parity.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
import uuid
import zipfile

from . import native_project, release, review_receipts, schema_probe
from .native_contract import validate_native_spec
from .security import alias_for_job
from .sqlcl import _IMPORT_LOCK, _candidate_application_ids, _run_script, _sqlcl_input_path, _target_guard, validate_apexlang


def _bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _require(condition, message):
    if not condition:
        raise RuntimeError(message)


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON member")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def _storage_manifest(project):
    """Visible, deterministic source-to-synthetic storage records for v2 only."""
    trace = native_project.project_trace(project)
    return {"schema_version": 1, "scope": "fox-project-storage-package-v1",
        "project_id": project["project_id"], "data_mode": "synthetic_test_only",
        "source_manifest_sha256": project["source_manifest_sha256"],
        "data_migration_included": False,
        "mappings": [{key: table[key] for key in ("storage_mapping", "ddl_sources", "module_ids")}
                     for table in trace["tables"]]}


def _storage_readme(project):
    rows = _storage_manifest(project)["mappings"]
    lines = ["\nProject-isolated synthetic storage (rendering specification v2)",
        "Original source filenames and byte hashes are preserved. Only generated table references use the synthetic namespace.",
        "This is not a data migration: no customer rows are copied, no source table is renamed, and no existing table is altered.",
        "Import requirements: use the exact mapped names below in an explicitly approved empty test parsing schema; do not substitute customer table names.",
        "A changed structural schema or project identity produces a new synthetic table. Review schema/storage-mapping.json and source-to-apex.json before installation.",
        "Remediation: the source owner and DBA must separately design and approve any real-data migration, relationships, business rules and production integration."]
    for row in rows:
        mapping = row["storage_mapping"]
        lines.append(mapping["source_table_name"] + " -> " + mapping["target_table_name"])
        lines.extend("  Original DDL: " + reference["name"] + " (SHA-256 " + reference["sha256"] + ")"
                     for reference in row["ddl_sources"])
    return "\n".join(lines) + "\n"


def _package_readme(project):
    text = ("FOX native APEX project package\n\nOne application contains every approved form as native report/form pages. "
        "It uses synthetic test schemas and supports query/insert/update only. This is not a complete conversion of customer transaction logic.\n\n"
        "In an explicitly selected empty test parsing schema, review and run schema/01_synthetic_schema.sql before importing the one sql/fNNN.sql file. "
        "DDL creates only the reviewed tables, contains no data or business APIs, and fails on existing names. Select a NEW application ID and alias; never replace an app. "
        "Confirm actual target compatibility and authentication.\n\n"
        "source-to-apex.json is a deterministic mapping, not execution proof. evidence/ contains separate SQLcl/import, source, per-form review and remediation records. "
        "The recorded runtime check reaches the login page only. Authenticated per-form tests, clean-schema installation and business-owner acceptance require separate receipts "
        "bound to this exact package hash. Review all remediation before acceptance. No passwords, wallets or API keys are included.\n")
    return text + (_storage_readme(project) if project["schema_version"] == 2 else "")


def _mapped_project_requests(members, project, aggregate, source_manifest, binding):
    """Recompute v2 authority from the package's original byte-proven sources.

    These are consistency checks, not provider/vendor attestations. No package
    mapping or compact model projection is accepted as its own source evidence.
    """
    from . import project_reviews, project_source
    inventory = _json(members["evidence/normalized-forms-inventory.json"])
    shared = inventory["shared_inventory"]
    records = [{"name": module["file"], "text": module["readable_source"],
                "sha256": module["sha256"], "bytes": module["bytes"]}
               for module in shared["modules"]]
    source_hashes = {source["packaged_name"]: source["sha256"] for source in source_manifest["files"]}
    _require(len(records) == len(source_hashes)
             and {record["name"]: record["sha256"] for record in records} == source_hashes,
             "Project original source inventory is incomplete")
    plan = project_source.validate_project_sources(project, records, project_id=project["project_id"],
                                                   plan_sha256=aggregate["plan_sha256"])
    rows = project_reviews.project_inventory_rows(plan, aggregate["job_id"], shared)
    _require(inventory.get("job_id") == aggregate["job_id"]
             and inventory.get("source_hash") == project["source_manifest_sha256"]
             and inventory.get("conversion_profile") == native_project.PROFILE_ID
             and inventory.get("native_project") == project
             and inventory.get("native_project_profile") == native_project.context()
             and inventory.get("shared_inventory_sha256") == _sha(_bytes(shared))
             and inventory.get("forms") == rows
             and binding.get("inventory_sha256") == _sha(members["evidence/normalized-forms-inventory.json"])
             and binding.get("remediation_sha256") == _sha(members["evidence/migration-and-exception-report.json"]),
             "Project original-source model projection differs")

    def intake_digest(manifest_bytes):
        tree = {**source_hashes, "manifest.json": _sha(manifest_bytes)}
        return _sha(json.dumps(tree, sort_keys=True, separators=(",", ":")).encode())

    _require(binding.get("intake_sha256") == aggregate.get("intake_sha256")
             == intake_digest(members["evidence/source-manifest.json"]),
             "Project original source bytes differ from their intake binding")
    requests = {}
    for row, form in zip(rows, project["forms"]):
        child_manifest = {"job_id": row["child_job_id"], "source_manifest_sha256": project["source_manifest_sha256"],
            "conversion_profile": "native-table-form-v1", "native_form": form["native_form"],
            "files": source_manifest["files"], "storage_mapping": form["storage_mapping"],
            "ddl_sources": form["ddl_sources"], "module_execution_binding": row["binding"]}
        requests[form["module_id"]] = (project_reviews.project_model_request(None, row, shared_inventory=shared),
                                      intake_digest(_bytes(child_manifest) + b"\n"))
    return requests


def _read_members(package):
    source = io.BytesIO(package) if isinstance(package, bytes) else package
    with zipfile.ZipFile(source) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        _require(len(names) == len(set(names)) and len(names) <= 500
                 and sum(entry.file_size for entry in entries) <= 20_000_000,
                 "Invalid project package member set")
        for entry in entries:
            name = entry.filename
            path = PurePosixPath(name)
            mode = (entry.external_attr >> 16) & 0o170000
            _require(not path.is_absolute() and bool(path.parts) and name == path.as_posix()
                     and not any(part in {".", ".."} for part in path.parts)
                     and not any(token in name for token in ("\\", ":"))
                     and not any(ord(char) < 32 for char in name)
                     and not entry.is_dir() and mode in {0, 0o100000} and not entry.flag_bits & 1,
                     "Unsafe project package member")
        members = {name: archive.read(name) for name in names}
    manifest = _json(members["manifest.json"])
    _require(isinstance(manifest, dict) and set(members) == set(manifest) | {"manifest.json"},
             "Incomplete project package manifest")
    _require(all(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value)
                 and _sha(members[name]) == value for name, value in manifest.items()),
             "Project package member hash mismatch")
    return members, manifest


def _check_export_coverage(members, project):
    """Require all allocated pages/items; SQLcl still supplies syntax proof."""
    apx = {name: raw.decode("utf-8") for name, raw in members.items()
           if name.startswith("apexlang/") and name.endswith(".apx")}
    _require("apexlang/application.apx" in apx, "Project package has no application")
    _require(sum(len(re.findall(r"^app\s+[^\s(]+\s*\(", text, re.M)) for text in apx.values()) == 1,
             "Project package must contain one APEX application")
    pages = {}
    for text in apx.values():
        for match in re.finditer(r"^page\s+(\d+)\s*\(", text, re.M):
            number = int(match.group(1))
            _require(number not in pages, "Project export contains duplicate page identities")
            pages[number] = text
    trace = native_project.project_trace(project)
    required = {0, 9999} | {form[key] for form in trace["forms"]
                            for key in ("report_page_id", "form_page_id")}
    _require(set(pages) == required, "Project export omitted or added a page")
    for form in trace["forms"]:
        report, detail = pages[form["report_page_id"]], pages[form["form_page_id"]]
        _require("type: interactiveReport" in report and "type: formAutoRowProcessing" in detail,
                 "Project export lacks native report/form components")
        if project["schema_version"] == 2:
            # Independently bind the two generated region sources to the
            # reviewed synthetic target, even if ZIP/export hashes are rebuilt.
            for page in (report, detail):
                names = re.findall(r"^[ \t]*tableName[ \t]*:[ \t]*([^\r\n]*)", page, re.M)
                names = [name.strip() for name in names]
                _require(names == [form["table_name"]], "Project export storage target differs")
        for item in form["items"]:
            _require(re.search(r"\bpageItem\s+" + re.escape(item["item"]) + r"\s*\(", detail),
                     "Project export omitted a reviewed form item")


def validate_project_package(package, *, expected_project=None, expected_evidence=None):
    """Validate a new-profile ZIP offline; never reinterpret a legacy package.

    ``package`` is bytes or a Path. Metadata equality can additionally bind the
    caller's independently recovered project and release evidence. This proves
    consistency, not source provenance or that an external service executed.
    """
    try:
        members, manifest = _read_members(package)
        project = native_project.validate_project_spec(_json(members["native-project-spec.json"]))
        evidence = _json(members["evidence/release-evidence.json"])
        trace = _json(members["source-to-apex.json"])
        aggregate = _json(members["evidence/project-review.json"])
        spec = _json(members["evidence/migration-spec.json"])
        source_manifest = _json(members["evidence/source-manifest.json"])
        schema_preparation = _json(members["evidence/schema-preparation.json"])
        from .target_profile import validate_historical_target_profile
        historical_profile = validate_historical_target_profile(_json(members["evidence/target-profile.json"]))
        if project["schema_version"] == 2:
            from .workflow_router import project_mapping_profile_supported
            _require(project_mapping_profile_supported(historical_profile),
                     "Project storage mapping requires its registered mapping-aware review profile")
        _require(evidence.get("conversion_profile") == native_project.PROFILE_ID
                 and evidence.get("template_id") == native_project.TEMPLATE_ID
                 and type(evidence.get("application_count")) is int and evidence["application_count"] == 1
                 and type(evidence.get("form_count")) is int and evidence["form_count"] == len(project["forms"]),
                 "Project package profile mismatch")
        _require(expected_project is None or project == native_project.validate_project_spec(expected_project),
                 "Project package differs from the approved project")
        _require(expected_evidence is None or evidence == expected_evidence,
                 "Project package differs from release evidence")
        _require(trace == native_project.project_trace(project), "Project source-to-APEX trace mismatch")
        if project["schema_version"] == 2:
            _require(evidence.get("forms") == trace["forms"], "Project release source-to-target mappings differ")
        _require(members["schema/01_synthetic_schema.sql"] == native_project.render_project_schema(project).encode(),
                 "Project package schema differs from the reviewed metadata")
        _require(spec.get("template_id") == native_project.TEMPLATE_ID
                 and native_project.validate_project_spec(spec.get("native_project")) == project
                 and aggregate.get("candidate") == spec
                 and aggregate.get("candidate_sha256") == _sha(_bytes(spec))
                 and aggregate.get("scope") == f"fox-native-project-review-v{project['schema_version']}"
                 and (project["schema_version"] == 1 or type(aggregate.get("schema_version")) is int
                      and aggregate["schema_version"] == 2)
                 and aggregate.get("trust_boundary") == "authenticated_fox_executor_not_vendor_attestation"
                 and aggregate.get("verdict") == "approve"
                 and aggregate.get("job_id") == spec.get("job_id") == evidence.get("job_id"),
                 "Project package candidate mismatch")
        _require(source_manifest.get("source_manifest_sha256") == project["source_manifest_sha256"]
                 == evidence.get("source_manifest_sha256") == aggregate.get("source_hash"),
                 "Project package source identity mismatch")
        source_files = source_manifest.get("files", [])
        source_hashes = {row["packaged_name"]: row["sha256"] for row in source_files}
        _require(len(source_hashes) == len(source_files)
                 and _sha("\n".join(name + ":" + source_hashes[name] for name in sorted(source_hashes)).encode())
                     == project["source_manifest_sha256"]
                 and all(source_hashes.get(form["source_name"]) == form["source_sha256"] for form in project["forms"]),
                 "Project form source membership mismatch")
        if project["schema_version"] == 2:
            _require(source_manifest.get("project_id") == aggregate.get("project_id") == project["project_id"]
                     and source_manifest.get("native_project") == project
                     and type(aggregate.get("plan_sha256")) is str
                     and re.fullmatch(r"[a-f0-9]{64}", aggregate["plan_sha256"])
                     and source_manifest.get("plan_sha256") == aggregate["plan_sha256"],
                     "Project mapped source plan binding mismatch")
            _require(all(source_hashes.get(reference["name"]) == reference["sha256"]
                         for form in project["forms"] for reference in form["ddl_sources"]),
                     "Project original DDL membership mismatch")
            storage = members["schema/storage-mapping.json"]
            _require(_json(storage) == _storage_manifest(project)
                     and evidence.get("storage_mapping_sha256") == _sha(storage)
                     and evidence.get("project_id") == project["project_id"],
                     "Project package storage mapping mismatch")
            _require(_package_readme(project).encode() == members["README.txt"],
                     "Project package storage import requirements are missing")
        _require(evidence.get("review_receipt_sha256") == aggregate.get("receipt_sha256")
                 and aggregate.get("receipt_sha256") == _sha(_bytes({k: v for k, v in aggregate.items()
                                                                      if k != "receipt_sha256"})),
                 "Project aggregate review seal mismatch")
        _require(evidence.get("schema_preparation_sha256") == _sha(members["evidence/schema-preparation.json"]),
                 "Project schema preparation evidence mismatch")
        _require(schema_preparation.get("scope") == "fox-native-schema-preparation-v1"
                 and schema_preparation.get("all_ready") is True
                 and schema_preparation.get("business_behavior_verified") is False
                 and schema_preparation.get("automatic_replay_permitted") is False
                 and {row["table_name"] for row in schema_preparation.get("tables", [])}
                     == {form["native_form"]["table_name"] for form in project["forms"]},
                 "Project schemas were not prepared")
        summaries = aggregate.get("form_reviews")
        _require(isinstance(summaries, list) and len(summaries) == len(project["forms"]),
                 "Project review coverage is incomplete")
        _require(evidence.get("form_reviews") == summaries, "Project release review references differ")
        binding = evidence.get("artifact_binding", {})
        _require(binding.get("reviewed_spec_sha256") == manifest["evidence/migration-spec.json"]
                 and binding.get("project_review_sha256") == manifest["evidence/project-review.json"]
                 and binding.get("project_trace_sha256") == manifest["source-to-apex.json"],
                 "Project package bytes differ from their original artifact binding")
        mapped_requests = (_mapped_project_requests(members, project, aggregate, source_manifest, binding)
                           if project["schema_version"] == 2 else {})
        _require(schema_preparation.get("record_sha256") == _sha(_bytes({key: value for key, value in schema_preparation.items()
                                                                         if key != "record_sha256"})),
                 "Project schema preparation record seal mismatch")
        _require(schema_preparation.get("binding") == {"job_id": evidence["job_id"],
            "source_manifest_sha256": project["source_manifest_sha256"],
            "artifact_binding_sha256": _sha(_bytes(binding)), "review_receipts_sha256": _sha(_bytes(summaries)),
            "validated_draft_sha256": binding.get("draft_sha256")}, "Project schema receipt is not bound to this draft")
        tables = schema_preparation["tables"]
        by_table = {row["table_name"]: row for row in tables}
        _require(len(by_table) == len(tables) and all(
            by_table[form["native_form"]["table_name"]].get("bootstrap_schema_sha256") == schema_probe.schema_sha256(form["native_form"])
            and by_table[form["native_form"]["table_name"]].get("state") in {"CREATED", "REUSED"}
            for form in project["forms"]), "Project schema contract coverage differs")
        by_id = {row["module_id"]: row for row in summaries}
        _require(len(by_id) == len(summaries) and set(by_id) == {form["module_id"] for form in project["forms"]},
                 "Project review module identities differ")
        expected_receipts = {f"evidence/form-reviews/{form['module_id']}.json" for form in project["forms"]}
        _require({name for name in members if name.startswith("evidence/form-reviews/")} == expected_receipts,
                 "Project package omitted or added a form review")
        receipts = []
        for form in project["forms"]:
            receipt = _json(members[f"evidence/form-reviews/{form['module_id']}.json"])
            review_receipts._verify_seal(receipt)
            _require(receipt.get("schema_version") == 2, "New project packages require historical v2 model proof")
            historical = review_receipts.verify_historical_model_environment(receipt)
            _require(historical == historical_profile, "Project forms disagree on their historical target profile")
            roles = historical["opaf"]["roles"]
            _, completed = review_receipts._invocation(receipt["mapper_invocation"], roles["mapper"]["workflow_id"],
                                                       roles["mapper"]["model"], "Mapper invocation")
            started, _ = review_receipts._invocation(receipt["reviewer_invocation"], roles["reviewer"]["workflow_id"],
                                                     roles["reviewer"]["model"], "Reviewer invocation")
            summary = by_id[form["module_id"]]
            if project["schema_version"] == 2:
                execution_identity = {"scope": "fox-project-module-execution-v2",
                    "parent_job_id": evidence["job_id"], "source_hash": project["source_manifest_sha256"],
                    "module_id": form["module_id"], "native_form": form["native_form"],
                    "project_id": project["project_id"], "plan_sha256": aggregate["plan_sha256"],
                    "storage_mapping": form["storage_mapping"], "ddl_sources": form["ddl_sources"]}
                expected_binding = {"schema_version": 2, "scope": execution_identity["scope"],
                    "parent_job_id": evidence["job_id"], "child_job_id": "fox-" + _sha(_bytes(execution_identity))[:20],
                    "project_id": project["project_id"], "module_id": form["module_id"],
                    "source_hash": project["source_manifest_sha256"], "plan_sha256": aggregate["plan_sha256"],
                    "source_name": form["source_name"], "source_sha256": form["source_sha256"],
                    "native_form_sha256": _sha(_bytes(form["native_form"])),
                    "storage_mapping": form["storage_mapping"], "ddl_sources": form["ddl_sources"]}
                _require(summary.get("execution_binding") == expected_binding
                         and summary.get("child_job_id") == expected_binding["child_job_id"],
                         "Project storage mapping per-form execution binding mismatch")
                from .project_reviews import _verify_mapping_request
                request, child_intake = mapped_requests[form["module_id"]]
                _verify_mapping_request(receipt, request)
                _require(receipt.get("intake_sha256") == child_intake,
                         "Project mapped review does not bind its original child intake")
            _require(isinstance(summary.get("child_job_id"), str)
                     and re.fullmatch(r"fox-[a-f0-9]{20}", summary["child_job_id"]),
                     "Project child job identity invalid")
            _require(receipt.get("receipt_sha256") == summary.get("receipt_sha256")
                     and receipt.get("candidate_sha256") == summary.get("candidate_sha256")
                     and receipt.get("job_id") == summary.get("child_job_id")
                     and receipt.get("review", {}).get("verdict") == "approve"
                     and receipt["review"].get("blocking_findings") == []
                     and receipt["review"].get("candidate_sha256") == receipt["candidate_sha256"]
                     and receipt.get("source_hash") == project["source_manifest_sha256"]
                     and receipt["candidate"].get("job_id") == receipt["job_id"]
                     and receipt["candidate"]["generator"]["model"] == roles["mapper"]["model"]
                     and receipt["mapper_invocation"]["room_id"].casefold() != receipt["reviewer_invocation"]["room_id"].casefold()
                     and started >= completed
                     and validate_native_spec(receipt["candidate"]["native_form"]) == form["native_form"]
                     and review_receipts.candidate_sha256(receipt["candidate"]) == receipt["candidate_sha256"],
                     "Project per-form review binding mismatch")
            receipts.append(receipt)
        app_id = evidence.get("application_id")
        _require(type(app_id) is int and app_id > 0
                 and {name for name in members if name.startswith("sql/")} == {f"sql/f{app_id}.sql"},
                 "Project package must contain one conventional SQL export")
        reimport = _json(members["evidence/package-reimport.json"])
        _require(reimport == evidence.get("package_reimport") and reimport.get("passed") is True
                 and reimport.get("sql_sha256") == manifest[f"sql/f{app_id}.sql"]
                 and type(reimport.get("application_id")) is int and reimport["application_id"] > 0
                 and reimport["application_id"] != app_id
                 and reimport.get("application_alias") == alias_for_job(evidence["job_id"] + "-sqlcheck"),
                 "Project SQL reimport proof mismatch")
        imported = _json(members["evidence/imported-application.json"])
        _require(imported.get("application_id") == app_id
                 and imported.get("application_alias") == evidence.get("application_alias") == alias_for_job(evidence["job_id"])
                 and imported.get("artifact_binding") == binding
                 and evidence.get("imported_application_sha256") == manifest["evidence/imported-application.json"],
                 "Project imported identity mismatch")
        complete = _json(members["evidence/export-completion.json"])
        actual_export = {name[len("apexlang/"):]: digest for name, digest in manifest.items() if name.startswith("apexlang/")}
        expected_export = {name[len(evidence["application_alias"].lower()) + 1:]: digest
                           for name, digest in complete.get("files", {}).items()
                           if name.startswith(evidence["application_alias"].lower() + "/")}
        _require(complete.get("artifact_binding") == binding and complete.get("application_id") == app_id
                 and evidence.get("export_completion_sha256") == manifest["evidence/export-completion.json"]
                 and complete.get("application_alias") == evidence["application_alias"]
                 and complete.get("apexlang_validation_passed") is True
                 and complete.get("imported_application_sha256") == manifest["evidence/imported-application.json"]
                 and complete.get("files", {}).get(f"f{app_id}.sql") == manifest[f"sql/f{app_id}.sql"]
                 and complete.get("files", {}).get("apexlang-validation.log") == manifest["evidence/export-validation.log"]
                 and actual_export == expected_export
                 and _sha(json.dumps(actual_export, sort_keys=True, separators=(",", ":")).encode())
                     == imported.get("compiled_metadata_sha256"), "Project export completion coverage differs")
        preflights = evidence.get("target_preflights")
        _require(isinstance(preflights, dict) and set(preflights) == {"validate", "import", "export", "reimport"}
                 and preflights["import"] == imported.get("target_preflight")
                 and preflights["export"] == complete.get("target_preflight")
                 and preflights["reimport"] == reimport.get("target_preflight"),
                 "Project target preflight references are incomplete")
        for role, reference in preflights.items():
            name = reference.get("file", "")
            expected_action = {"validate": {"validate"}, "import": {"import", "reconcile"},
                               "export": {"release"}, "reimport": {"release"}}[role]
            _require(isinstance(name, str) and re.fullmatch(r"target-check-(?:validate|import|reconcile|release)-[a-f0-9]{16}\.json", name)
                     and reference.get("action") in expected_action
                     and manifest.get("evidence/" + name) == reference.get("sha256")
                     and _json(members["evidence/" + name]).get("artifact_binding") == binding,
                     "Project target preflight evidence is missing or unbound")
        _require(all(evidence.get(flag) is False for flag in ("authenticated_runtime_passed", "clean_schema_install_passed", "human_acceptance_recorded"))
                 and evidence.get("runtime_smoke_scope") == "login_page_reachability_only",
                 "Project package overstates runtime or business acceptance")
        _check_export_coverage(members, project)
        return {"manifest": manifest, "project": project, "trace": trace,
                "evidence": evidence, "form_reviews": receipts}
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, UnicodeError, OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise RuntimeError("Project package integrity verification failed") from exc


def verify_project_cached_release(root, job_id, binding):
    """Read only; project validation does not modify retained legacy evidence."""
    evidence = release._verify_cached_release(root, job_id, binding)
    spec = release._read_object(root / "migration-spec.json")
    checked = validate_project_package(root / "apex-package.zip", expected_project=spec.get("native_project"),
                                       expected_evidence=evidence)
    _require(checked["manifest"]["evidence/project-review.json"] == release._file_digest(root / "project-review.json"),
             "Project review changed after package publication")
    _require(checked["manifest"]["evidence/schema-preparation.json"] == release._file_digest(root / "schema-preparation.json"),
             "Schema preparation changed after package publication")
    return evidence


def _recover_project_publication(root, job_id, binding):
    journal = release._read_object(root / "release-publication.json")
    stage_name = journal.get("stage_directory", "")
    _require(isinstance(stage_name, str) and re.fullmatch(r"\.release-publication-[a-zA-Z0-9_-]+", stage_name),
             "Invalid project publication directory")
    stage = root / stage_name
    _require(not stage.is_symlink(), "Linked project publication directory")
    package = root / "apex-package.zip"
    if not package.exists():
        package = stage / package.name
    validate_project_package(package, expected_project=release._read_object(root / "migration-spec.json")["native_project"])
    release._recover_publication(root, job_id, binding)
    return verify_project_cached_release(root, job_id, binding)


def _ensure_project_export(workflow, root, job_id, binding, app_id, alias, args, guard):
    export = root / "export"
    if (export / release._EXPORT_MANIFEST).exists():
        release._verify_completed_export(root, job_id, binding, app_id, alias)
        return export
    _require(not (root / "package-reimport-intent.json").exists()
             and not (root / "package-reimport.json").exists(),
             "Previous SQL reimport requires operator reconciliation; no automatic retry")
    preflight = workflow.native_target_preflight(job_id, "release")
    original_import = release._file_digest(root / "imported-application.json")
    if export.exists() or export.is_symlink():
        _require(not export.is_symlink() and export.is_dir(), "Unsafe existing project export")
        export.rename(root / (".export-preserved-" + uuid.uuid4().hex))
        release._sync_directory(root)
    attempt = Path(tempfile.mkdtemp(prefix=".export-attempt-", dir=root))
    workflow.assert_native_preflight_fresh(job_id, preflight, "release")
    result = _run_script(workflow.settings.sqlcl_path, args, [guard,
        f"select 'FOX_EXPORT_MATCH='||count(*) from apex_applications where workspace='{workflow.settings.apex_workspace}' and application_id={app_id} and upper(alias)='{alias}';",
        f"apex export -applicationid {app_id} -exptype SQL",
        f"apex export -applicationid {app_id} -exptype APEXLANG"], attempt)
    release._write_bytes(attempt / "export.log", (result.stdout + "\n" + result.stderr).encode())
    _require(result.returncode == 0 and not result.stderr.strip()
             and re.findall(r"(?m)^\s*FOX_EXPORT_MATCH=(\d+)\s*$", result.stdout) == ["1"],
             "Project export did not confirm the expected application")
    sql, app = attempt / f"f{app_id}.sql", attempt / alias.lower()
    _require(sql.is_file() and sql.stat().st_size >= 1000 and (app / "application.apx").is_file(),
             "Project SQL and APEXlang export is incomplete")
    before, sql_hash = release._tree_hashes(app), release._file_digest(sql)
    imported = release._read_object(root / "imported-application.json")
    _require(_sha(json.dumps(before, sort_keys=True, separators=(",", ":")).encode())
             == imported.get("compiled_metadata_sha256"),
             "Exported project differs from the confirmed complete imported metadata")
    validation = validate_apexlang(workflow.settings.sqlcl_path, app, attempt / "apexlang-validation.log")
    _require(validation.get("passed") is True, "Actual project APEXlang export failed SQLcl validation")
    _require(release._tree_hashes(app) == before and release._file_digest(sql) == sql_hash,
             "Project export changed during validation")
    _require(workflow.assert_artifact_binding(job_id) == binding
             and release._file_digest(root / "imported-application.json") == original_import,
             "Project artifact or imported identity changed during export")
    project = release._read_object(root / "migration-spec.json")["native_project"]
    _check_export_coverage({"apexlang/" + name: (app / name).read_bytes() for name in before}, project)
    completion = {"schema_version": 1, "job_id": job_id, "artifact_binding": binding,
        "application_id": app_id, "application_alias": alias, "imported_application_sha256": original_import,
        "apexlang_validation_passed": True, "files": release._tree_hashes(attempt), "target_preflight": preflight}
    for path in attempt.rglob("*"):
        if path.is_file():
            with path.open("r+b") as handle:
                os.fsync(handle.fileno())
    release._atomic_json(attempt / release._EXPORT_MANIFEST, completion)
    attempt.rename(export)
    release._sync_directory(root)
    release._verify_completed_export(root, job_id, binding, app_id, alias)
    return export


def _ensure_reimport(workflow, root, job_id, binding, app_id, alias, sql, args, guard):
    receipt, intent = root / "package-reimport.json", root / "package-reimport-intent.json"
    test_job, test_alias = job_id + "-sqlcheck", alias_for_job(job_id + "-sqlcheck")
    with _IMPORT_LOCK:
        if receipt.exists():
            return release._verify_reimport_receipt(sql, receipt, test_alias)
        _require(not intent.exists(), "Previous SQL reimport needs operator reconciliation; no automatic retry")
        workflow._schema_ready(job_id)
        preflight = workflow.native_target_preflight(job_id, "release")
        candidates = _candidate_application_ids(test_job)
        settings = workflow.settings
        pre = _run_script(settings.sqlcl_path, args, [guard,
            f"select 'FOX_ALIAS_COUNT='||count(*) from apex_applications where workspace='{settings.apex_workspace}' and upper(alias)='{test_alias}';",
            "select 'FOX_USED_ID='||application_id from apex_applications where application_id in (" + ",".join(map(str, candidates)) + ");"], root)
        _require(not pre.returncode and not pre.stderr.strip()
                 and re.findall(r"(?m)^\s*FOX_ALIAS_COUNT=(\d+)\s*$", pre.stdout) == ["0"],
                 "Reimport alias is not proven absent; existing applications are preserved")
        used = set(map(int, re.findall(r"(?m)^\s*FOX_USED_ID=(\d+)\s*$", pre.stdout)))
        test_id = next((value for value in candidates if value not in used), None)
        _require(test_id is not None, "No free project reimport application ID")
        release._verify_completed_export(root, job_id, binding, app_id, alias)
        sql_hash = release._file_digest(sql)
        workflow.assert_native_preflight_fresh(job_id, preflight, "release")
        release._write_bytes(intent, _bytes({"job_id": job_id, "application_id": test_id, "alias": test_alias,
            "artifact_binding": binding, "sql_sha256": sql_hash, "target_preflight": preflight}))
        release._sync_directory(root)
        schema = workflow._schema_ready(job_id)
        workflow.assert_native_preflight_fresh(job_id, preflight, "release")
        # Recheck in the same SQLcl script immediately before the conventional
        # import. A saved ambiguous result is never replayed automatically.
        absent = ("declare n number; begin select count(*) into n from apex_applications "
                  f"where application_id={test_id} or (workspace='{settings.apex_workspace}' and upper(alias)='{test_alias}'); "
                  "if n<>0 then raise_application_error(-20082,'FOX create-only application collision'); end if; end;\n/")
        result = _run_script(settings.sqlcl_path, args, [guard, absent,
            f"begin apex_application_install.set_workspace('{settings.apex_workspace}'); apex_application_install.set_schema('{settings.apex_parsing_schema}'); apex_application_install.set_application_id({test_id}); apex_application_install.generate_offset; apex_application_install.set_application_alias('{test_alias}'); end;\n/",
            '@"' + _sqlcl_input_path(sql) + '"',
            f"select 'FOX_REIMPORT_MATCH='||count(*) from apex_applications where workspace='{settings.apex_workspace}' and application_id={test_id} and upper(alias)='{test_alias}';"], root, timeout=1200)
        release._write_bytes(root / "package-reimport.log", (result.stdout + "\n" + result.stderr).encode())
        _require(not result.returncode and not result.stderr.strip()
                 and re.findall(r"(?m)^\s*FOX_REIMPORT_MATCH=(\d+)\s*$", result.stdout) == ["1"],
                 "Project conventional SQL export did not pass reimport verification")
        _require(release._file_digest(sql) == sql_hash and workflow.assert_artifact_binding(job_id) == binding,
                 "Project artifact or SQL export changed during reimport")
        checked = {"passed": True, "application_id": test_id, "application_alias": test_alias,
                   "sql_sha256": sql_hash, "target_preflight": preflight,
                   "project_schema_verification": schema}
        release._atomic_json(receipt, checked)
        return checked


def finalize_project_release(workflow, job_id):
    """Export the one imported project app and publish one recoverable package."""
    root = workflow.store.require(job_id)
    binding = workflow.assert_artifact_binding(job_id)
    status = workflow.status(job_id)
    _require(status["state"] == "IMPORTED" and status.get("validation", {}).get("passed") is True,
             "A reviewed, validated and imported project is required before export")
    if (root / "release-publication.json").exists():
        evidence = _recover_project_publication(root, job_id, binding)
        _require(workflow.assert_artifact_binding(job_id) == binding, "Project artifact changed during release")
        return evidence
    if (root / "apex-package.zip").exists() or (root / "release-integrity.json").exists():
        evidence = verify_project_cached_release(root, job_id, binding)
        _require(workflow.assert_artifact_binding(job_id) == binding, "Project artifact changed during release")
        return evidence
    _require(not (root / "release-evidence.json").exists(), "Unbound project release evidence requires reconciliation")
    spec = release._read_object(root / "migration-spec.json")
    _require(spec.get("template_id") == native_project.TEMPLATE_ID, "Project release requires the project template")
    project = native_project.validate_project_spec(spec.get("native_project"))
    review = workflow.verify_project_review(root, spec)
    app = release._read_object(root / "imported-application.json")
    app_id, alias = app.get("application_id"), alias_for_job(job_id)
    settings = workflow.settings
    _require(type(app_id) is int and app_id > 0 and app.get("application_alias") == alias
             and app.get("workspace") == settings.apex_workspace, "Imported project application identity mismatch")
    args = ["-S", "-L", "-name", settings.sqlcl_connection_name]
    guard = _target_guard(settings.apex_workspace)
    export = _ensure_project_export(workflow, root, job_id, binding, app_id, alias, args, guard)
    sql, exported_app = export / f"f{app_id}.sql", export / alias.lower()
    receipt = _ensure_reimport(workflow, root, job_id, binding, app_id, alias, sql, args, guard)
    smoke = release.runtime_login_check(app["application_url"])
    release._atomic_json(root / "smoke-test-report.json", smoke)
    _require(smoke.get("passed") is True, "The project APEX login page is not reachable")
    trace = native_project.project_trace(project)
    preparation = root / "schema-preparation.json"
    _require(release._read_object(preparation).get("all_ready") is True, "Project schema preparation evidence is required")
    evidence = {"job_id": job_id, "source_manifest_sha256": project["source_manifest_sha256"],
        "artifact_binding": binding, "conversion_profile": native_project.PROFILE_ID,
        "template_id": native_project.TEMPLATE_ID, "application_count": 1, "form_count": len(project["forms"]),
        "forms": trace["forms"], "form_reviews": review["form_reviews"], "review_receipt_sha256": review["receipt_sha256"],
        "remediation_items": spec.get("remediation_items", []), "mapping_summary": spec.get("mapping_summary"),
        "reviewer_approved": True, "reviewer_execution_verified": True, "model_environment_verified": True,
        "review_proof_scope": "authenticated_executor_per_form_v2_environment_and_candidate_binding_not_vendor_attestation",
        "sqlcl_valid": True, "import_passed": True, "runtime_smoke_passed": True,
        "runtime_smoke_scope": "login_page_reachability_only", "business_acceptance_required": True,
        "package_reimport_passed": True, "package_reimport": receipt,
        "application_id": app_id, "application_alias": alias, "application_url": app["application_url"],
        "imported_application_sha256": release._file_digest(root / "imported-application.json"),
        "export_completion_sha256": release._file_digest(export / release._EXPORT_MANIFEST),
        "authenticated_runtime_passed": False, "clean_schema_install_passed": False,
        "human_acceptance_recorded": False, "schema_preparation_sha256": release._file_digest(preparation),
        "project_schema_verification": app.get("project_schema_verification"),
        "prototype_scope": "One native APEX app containing every approved form; synthetic tables; query/insert/update only; customer transaction logic not converted"}
    readme = _package_readme(project)
    members = {f"sql/{sql.name}": sql.read_bytes(), "README.txt": readme.encode(),
        "native-project-spec.json": _bytes(project), "source-to-apex.json": (root / "source-to-apex.json").read_bytes(),
        "schema/01_synthetic_schema.sql": native_project.render_project_schema(project).encode(),
        "evidence/project-review.json": (root / "project-review.json").read_bytes(),
        "evidence/source-manifest.json": (root / "intake/manifest.json").read_bytes(),
        "evidence/schema-preparation.json": preparation.read_bytes(), "evidence/release-evidence.json": _bytes(evidence)}
    if project["schema_version"] == 2:
        members["schema/storage-mapping.json"] = _bytes(_storage_manifest(project))
        evidence.update(project_id=project["project_id"],
                        storage_mapping_sha256=_sha(members["schema/storage-mapping.json"]))
    review_rows = {row["module_id"]: row for row in review["form_reviews"]}
    historical_profile = None
    for form in project["forms"]:
        child_id = review_rows[form["module_id"]]["child_job_id"]
        _require(isinstance(child_id, str) and re.fullmatch(r"fox-[a-f0-9]{20}", child_id), "Project child identity invalid")
        path = root / "form-reviews" / child_id / "native-review.json"
        release._file_digest(path)
        raw = path.read_bytes()
        members[f"evidence/form-reviews/{form['module_id']}.json"] = raw
        historical = review_receipts.verify_historical_model_environment(_json(raw))
        _require(historical is not None and (historical_profile is None or historical_profile == historical),
                 "Project forms disagree on their historical target profile")
        historical_profile = historical
    members["evidence/target-profile.json"] = _bytes(historical_profile)
    for path in exported_app.rglob("*"):
        if path.is_file():
            members["apexlang/" + path.relative_to(exported_app).as_posix()] = path.read_bytes()
    for name in ("normalized-forms-inventory.json", "migration-and-exception-report.json", "migration-spec.json",
                 "validation-results.log", "imported-application.json", "package-reimport.json", "smoke-test-report.json"):
        members["evidence/" + name] = (root / name).read_bytes()
    members["evidence/export-completion.json"] = (export / release._EXPORT_MANIFEST).read_bytes()
    members["evidence/export-validation.log"] = (export / "apexlang-validation.log").read_bytes()
    references = {"validate": status.get("validation", {}).get("target_preflight"), "import": app.get("target_preflight"),
                  "export": release._read_object(export / release._EXPORT_MANIFEST).get("target_preflight"), "reimport": receipt.get("target_preflight")}
    evidence["target_preflights"] = references
    members["evidence/release-evidence.json"] = _bytes(evidence)
    for reference in references.values():
        _require(isinstance(reference, dict), "Project release requires every target preflight reference")
        name = reference.get("file", "")
        _require(isinstance(name, str) and re.fullmatch(r"target-check-(?:validate|import|reconcile|release)-[a-f0-9]{16}\.json", name)
                 and release._file_digest(root / name) == reference.get("sha256"), "Project target preflight evidence changed")
        members["evidence/" + name] = (root / name).read_bytes()
    _require(workflow.assert_artifact_binding(job_id) == binding, "Project artifact changed during release")
    stage = Path(tempfile.mkdtemp(prefix=".release-publication-", dir=root))
    release._write_bytes(stage / "release-evidence.json", _bytes(evidence))
    members["manifest.json"] = _bytes({name: _sha(raw) for name, raw in members.items()})
    package = stage / "apex-package.zip"
    with zipfile.ZipFile(package, "x", zipfile.ZIP_DEFLATED) as archive:
        for name, raw in sorted(members.items()):
            archive.writestr(name, raw)
    with package.open("r+b") as handle:
        os.fsync(handle.fileno())
    validate_project_package(package, expected_project=project, expected_evidence=evidence)
    release._verify_package_members(package, stage / "release-evidence.json", sql, root / "package-reimport.json", exported_app)
    _require(workflow.assert_artifact_binding(job_id) == binding, "Project artifact changed during release")
    integrity = {"schema_version": 1, "job_id": job_id, "artifact_binding": binding,
        "package_sha256": release._file_digest(package), "evidence_sha256": release._file_digest(stage / "release-evidence.json"),
        "sql_sha256": release._file_digest(sql), "export_completion_sha256": release._file_digest(export / release._EXPORT_MANIFEST)}
    release._atomic_json(stage / "release-integrity.json", integrity)
    release._sync_directory(stage)
    release._verify_completed_export(root, job_id, binding, app_id, alias)
    release._atomic_json(root / "release-publication.json", {"schema_version": 1, "job_id": job_id,
        "artifact_binding": binding, "stage_directory": stage.name,
        "components": {name: release._file_digest(stage / name) for name in release._PUBLICATION_FILES},
        "reimport_receipt_sha256": release._file_digest(root / "package-reimport.json")})
    result = _recover_project_publication(root, job_id, binding)
    _require(workflow.assert_artifact_binding(job_id) == binding, "Project artifact changed during release")
    return result
