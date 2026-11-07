"""New-profile browser proof and immutable SQLcl export, not legacy QA proof.

An injected trusted browser executor must run the exact independently derived
page checks and retain actual bytes. Neither HTTP/login reachability nor old
native-project proof is accepted. This module never imports/reimports an app,
executes source SQL, reads credentials or records human business acceptance.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
import zipfile

from . import native_blueprint, runtime_preflight, sqlcl
from .project_reviews import canonical, digest, publish, read_object
from .provenance import file_digest, tree_digest
from .release import _tree_hashes
from .review_receipts import _unique_keys
from .prototype_package import (RUNTIME_SCOPE, PACKAGE_SCOPE, expected_runtime_pages,
                                runtime_binding, _package_zip, _package_members,
                                validate_prototype_package)


_SHA = re.compile(r"[a-f0-9]{64}\Z")
_ARTIFACT = re.compile(r"runtime-evidence/[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\.(?:json|png)\Z")


def _need(condition, code):
    if not condition:
        raise RuntimeError(code)


def _bytes(path, raw):
    _need(not path.exists() and not path.is_symlink(), "PROTOTYPE_RELEASE_FILE_ALREADY_EXISTS")
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _timestamp(value):
    _need(type(value) is str and len(value) <= 40, "PROTOTYPE_RUNTIME_TIME_INVALID")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise RuntimeError("PROTOTYPE_RUNTIME_TIME_INVALID") from None
    _need(result.tzinfo is not None and result.utcoffset().total_seconds() == 0,
          "PROTOTYPE_RUNTIME_TIME_INVALID")
    return result


def validate_runtime_receipt(root, request, imported, artifact_binding, value):
    """Check NEW scope + every page + actual browser report/artifact hashes."""
    expected = runtime_binding(request, imported, artifact_binding)
    keys = set(expected) | {"passed", "authenticated", "business_pages_tested", "business_behavior_accepted",
                            "started_at_utc", "completed_at_utc", "runner", "pages", "artifacts", "data_retention", "retained_rows"}
    _need(type(value) is dict and set(value) == keys
          and all(value.get(key) == item for key, item in expected.items()),
          "PROTOTYPE_RUNTIME_BINDING_INVALID")
    _need(all(value[key] is True for key in ("passed", "authenticated", "business_pages_tested"))
          and value["business_behavior_accepted"] is False, "PROTOTYPE_AUTHENTICATED_RUNTIME_REQUIRED")
    forms = [block for block in request["rendering_spec"]["blocks"] if block["native_component"] == "form"]
    _need(value["data_retention"] == "synthetic_test_rows_retained" and type(value["retained_rows"]) is list
          and len(value["retained_rows"]) == len(forms), "PROTOTYPE_RUNTIME_RETENTION_LEDGER_REQUIRED")
    for row, block in zip(value["retained_rows"], forms):
        _need(type(row) is dict and set(row) == {"source_block_id", "table_name", "primary_key", "marker", "created", "updated", "deleted"}
              and row["source_block_id"] == block["source_block_id"] and row["table_name"] == block["table_name"]
              and type(row["primary_key"]) is str and re.fullmatch(r"[1-9][0-9]{0,37}", row["primary_key"])
              and type(row["marker"]) is str and re.fullmatch(r"FPQ-[a-f0-9]{12,28}", row["marker"])
              and row["created"] is True and row["updated"] is True and row["deleted"] is False,
              "PROTOTYPE_RUNTIME_RETENTION_LEDGER_REQUIRED")
    started, completed = _timestamp(value["started_at_utc"]), _timestamp(value["completed_at_utc"])
    _need(0 <= (completed - started).total_seconds() <= 3600
          and (completed - datetime.now(timezone.utc)).total_seconds() <= 5,
          "PROTOTYPE_RUNTIME_TIME_INVALID")
    runner = value["runner"]
    _need(type(runner) is dict and set(runner) == {"kind", "tool", "code_sha256", "image_id"}
          and runner["kind"] == "authenticated_browser" and runner["tool"] == "playwright"
          and type(runner["code_sha256"]) is str and _SHA.fullmatch(runner["code_sha256"])
          and type(runner["image_id"]) is str and re.fullmatch(r"sha256:[a-f0-9]{64}", runner["image_id"]),
          "PROTOTYPE_RUNTIME_EXECUTOR_IDENTITY_REQUIRED")
    pages = expected_runtime_pages(request["rendering_spec"])
    _need(type(value["pages"]) is list and len(value["pages"]) == len(pages),
          "PROTOTYPE_RUNTIME_PAGE_COVERAGE_INVALID")
    for actual, page in zip(value["pages"], pages):
        _need(type(actual) is dict and set(actual) == {"page_id", "source_block_id", "passed", "authenticated", "checks"}
              and type(actual["page_id"]) is int and actual["page_id"] == page["page_id"]
              and actual["source_block_id"] == page["source_block_id"] and actual["passed"] is True
              and actual["authenticated"] is True and type(actual["checks"]) is dict
              and set(actual["checks"]) == set(page["checks"])
              and all(item is True for item in actual["checks"].values()),
              "PROTOTYPE_RUNTIME_PAGE_COVERAGE_INVALID")
    artifacts = value["artifacts"]
    _need(type(artifacts) is list and 1 <= len(artifacts) <= 100, "PROTOTYPE_RUNTIME_ARTIFACTS_REQUIRED")
    names, total = set(), 0
    root = Path(root)
    _need(not (root / "runtime-evidence").is_symlink(), "PROTOTYPE_RUNTIME_ARTIFACT_UNSAFE")
    for row in artifacts:
        _need(type(row) is dict and set(row) == {"path", "sha256", "bytes"}
              and type(row["path"]) is str and _ARTIFACT.fullmatch(row["path"])
              and row["path"] not in names and type(row["bytes"]) is int and 0 < row["bytes"] <= 5_000_000
              and type(row["sha256"]) is str and _SHA.fullmatch(row["sha256"]),
              "PROTOTYPE_RUNTIME_ARTIFACT_UNSAFE")
        names.add(row["path"])
        path = root / row["path"]
        _need(file_digest(path) == row["sha256"] and path.stat().st_size == row["bytes"],
              "PROTOTYPE_RUNTIME_ARTIFACT_CHANGED")
        total += row["bytes"]
    _need(total <= 20_000_000 and "runtime-evidence/browser-report.json" in names,
          "PROTOTYPE_RUNTIME_BROWSER_REPORT_REQUIRED")
    report = json.loads((root / "runtime-evidence/browser-report.json").read_bytes(), object_pairs_hook=_unique_keys)
    _need(report == {key: item for key, item in value.items() if key != "artifacts"},
          "PROTOTYPE_RUNTIME_BROWSER_REPORT_MISMATCH")
    return value


def verify_runtime(settings, root, request, *, imported, artifact_binding, verifier, freshness_check):
    _need(callable(verifier), "PROTOTYPE_RUNTIME_VERIFIER_UNAVAILABLE")
    freshness_check()
    receipt = verifier(request, root=Path(root), imported=imported,
        trace=native_blueprint.prototype_trace(request["rendering_spec"]), artifact_binding=artifact_binding,
        freshness_check=freshness_check)
    freshness_check()
    validate_runtime_receipt(root, request, imported, artifact_binding, receipt)
    return {"passed": True, "authenticated": True, "business_pages_tested": True,
            "application_id": imported["application_id"], "runtime_receipt": receipt,
            "runtime_receipt_sha256": digest(receipt)}


def export_prototype(settings, root, request, *, imported, artifact_binding, runtime_receipt,
                     freshness_check, runner=None, validator=None, target_profile_loader=None):
    """Actual guarded SQLcl export of the existing app; no allocation/import."""
    runner, validator = runner or sqlcl._run_script, validator or sqlcl.validate_apexlang
    root = Path(root)
    validate_runtime_receipt(root, request, imported, artifact_binding, runtime_receipt)
    identity = runtime_binding(request, imported, artifact_binding)
    _need(settings.sqlcl_connection_name == "F2A_APEX" and settings.apex_workspace == "FORMS2APEX_POC",
          "PROTOTYPE_EXPORT_EXACT_SAVED_TARGET_REQUIRED")
    profile = (target_profile_loader or runtime_preflight.bound_target_profile)(settings)
    _need(not (root / "prototype-package.zip").exists(), "PROTOTYPE_EXPORT_ALREADY_PUBLISHED")
    app_id, alias = imported["application_id"], imported["application_alias"]
    # Keep SQLcl output below Windows path limits; retain the attempt on any
    # uncertainty. The parent stage's exclusive durable intent prevents replay.
    attempt = Path(tempfile.mkdtemp(prefix=".px-", dir=Path(settings.jobs_root).parent))
    publish(root / "export-attempt.json", {"directory": str(attempt), "binding": identity})
    freshness_check()
    match = f"workspace='FORMS2APEX_POC' and application_id={app_id} and upper(alias)='{alias}'"
    result = runner(settings.sqlcl_path, ["-S", "-L", "-name", "F2A_APEX"], [
        sqlcl._target_guard("FORMS2APEX_POC"),
        f"select 'FOX_PROTO_EXPORT_BEFORE='||count(*) from apex_applications where {match};",
        f"apex export -applicationid {app_id} -exptype SQL",
        f"apex export -applicationid {app_id} -exptype APEXLANG",
        f"select 'FOX_PROTO_EXPORT_AFTER='||count(*) from apex_applications where {match};"], attempt, timeout=600)
    _bytes(attempt / "export.log", (result.stdout + "\n" + result.stderr).encode())
    _need(result.returncode == 0 and not result.stderr.strip()
          and all(re.findall(r"(?m)^\s*" + marker + r"=(\d+)\s*$", result.stdout) == ["1"]
                  for marker in ("FOX_PROTO_EXPORT_BEFORE", "FOX_PROTO_EXPORT_AFTER")),
          "PROTOTYPE_EXPORT_IDENTITY_UNCONFIRMED")
    sql, app = attempt / f"f{app_id}.sql", attempt / alias.lower()
    _need(file_digest(sql) and 1000 <= sql.stat().st_size <= 20_000_000
          and (app / "application.apx").is_file(), "PROTOTYPE_EXPORT_FILES_INCOMPLETE")
    before, sql_hash = _tree_hashes(app), file_digest(sql)
    _need(tree_digest(app) == imported["compiled_metadata_sha256"], "PROTOTYPE_EXPORT_IMPORTED_METADATA_MISMATCH")
    validation = validator(settings.sqlcl_path, app, attempt / "validation.log")
    _need(validation.get("passed") is True and validation.get("return_code") == 0,
          "PROTOTYPE_EXPORT_VALIDATION_FAILED")
    _need(_tree_hashes(app) == before and file_digest(sql) == sql_hash, "PROTOTYPE_EXPORT_BYTES_CHANGED")
    freshness_check()
    validate_runtime_receipt(root, request, imported, artifact_binding, runtime_receipt)
    authority = root.parent / "prototype-pipeline"
    source_manifest = read_object(authority / "sources-manifest.json")
    plan_path = authority / "native-plan.json"
    _need(file_digest(plan_path), "PROTOTYPE_EXPORT_SOURCE_PLAN_REQUIRED")
    plan = json.loads(plan_path.read_bytes(), object_pairs_hook=_unique_keys)
    _need(plan.get("plan_sha256") == request["plan_sha256"]
          and plan.get("rendering_spec") == request["rendering_spec"]
          and type(plan.get("coverage")) is dict and type(plan.get("remediation")) is list
          and source_manifest.get("source_binding") == request["source_binding"]
          and type(source_manifest.get("files")) is list and 1 <= len(source_manifest["files"]) <= 4,
          "PROTOTYPE_EXPORT_SOURCE_PLAN_CHANGED")
    summary = {"source_binding": request["source_binding"], "source_count": len(source_manifest["files"]),
               "block_count": len(request["rendering_spec"]["blocks"]),
               "item_count": sum(len(block["fields"]) for block in request["rendering_spec"]["blocks"]),
               "files": source_manifest["files"], "coverage": plan["coverage"], "remediation": plan["remediation"]}
    requirements = {"profile_id": native_blueprint.PROFILE_ID, "tested_versions": profile["tested_versions"],
                    "workspace": profile["apex"]["workspace"], "parsing_schema": profile["database"]["parsing_schema"],
                    "synthetic_schema_only": True, "new_application_id_and_alias_required": True,
                    "other_target_import_guaranteed": False}
    evidence = {**identity, "sql_sha256": sql_hash, "compiled_metadata_sha256": imported["compiled_metadata_sha256"],
                "runtime_receipt_sha256": digest(runtime_receipt), "authenticated_runtime_passed": True,
                "sqlcl_export_validated": True, "package_reimport_passed": False,
                "clean_schema_install_passed": False, "business_behavior_accepted": False,
                "technical_scope": "original_app_authenticated_browser_and_exact_SQLcl_export_not_clean_SQL_reimport"}
    readme = ("FOX synthetic native blueprint prototype\n\n"
        "One project, one APEX application. Legacy business behavior is not converted or accepted.\n"
        "Import sql/fNNN.sql into a compatible reviewed test target using a NEW application ID and alias. "
        "Never replace an existing app. Review evidence/target-requirements.json, synthetic schema and all omissions first.\n"
        "The APEXlang files are actual validated SQLcl exports. Authentication and applicable pages were tested "
        "on the original imported app. Conventional SQL reimport and clean-schema install are NOT proven by this package.\n")
    members = {f"sql/{sql.name}": sql.read_bytes(), "README.txt": readme.encode(),
               "native-blueprint-spec.json": canonical(request["rendering_spec"]),
               "source-to-apex.json": canonical(native_blueprint.prototype_trace(request["rendering_spec"])),
               "schema/01_synthetic_schema.sql": native_blueprint.render_prototype_schema(request["rendering_spec"]).encode(),
               "evidence/runtime-receipt.json": canonical(runtime_receipt),
               "evidence/release-evidence.json": canonical(evidence), "evidence/source-summary.json": canonical(summary),
               "evidence/target-requirements.json": canonical(requirements)}
    for name in before:
        members["apexlang/" + name] = (app / name).read_bytes()
    for artifact in runtime_receipt["artifacts"]:
        members["evidence/" + artifact["path"]] = (root / artifact["path"]).read_bytes()
    members["manifest.json"] = canonical({"schema_version": 1, "scope": PACKAGE_SCOPE, "binding": identity,
        "files": {name: hashlib.sha256(value).hexdigest() for name, value in sorted(members.items())}})
    raw = _package_zip(members)
    validate_prototype_package(raw, request=request, runtime_receipt=runtime_receipt,
                               imported=imported, artifact_binding=artifact_binding)
    freshness_check()
    _need(file_digest(sql) == sql_hash and _tree_hashes(app) == before, "PROTOTYPE_EXPORT_BYTES_CHANGED")
    package = root / "prototype-package.zip"
    _bytes(package, raw)
    return {"exported": True, "package_path": str(package), "package_sha256": hashlib.sha256(raw).hexdigest(),
            "native_sql_path": str(sql), "native_sql_sha256": sql_hash, "native_sql_bytes": sql.stat().st_size,
            "application_id": app_id, "application_alias": alias, "runtime_receipt_sha256": digest(runtime_receipt),
            "package_reimport_passed": False, "clean_schema_install_passed": False,
            "business_behavior_accepted": False, "target_requirements": requirements, "source_summary": summary}
