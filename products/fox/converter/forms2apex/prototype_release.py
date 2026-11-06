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
from .security import alias_for_job


RUNTIME_SCOPE = "fox-native-blueprint-runtime-v1"
PACKAGE_SCOPE = "fox-native-blueprint-package-v1"
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


def expected_runtime_pages(spec):
    """Each actual report/form/control page; no inferred business logic checks."""
    spec = native_blueprint.validate_prototype_spec(spec)
    result = []
    for block in spec["blocks"]:
        pages = native_blueprint._pages(block)
        checks = ["render", "native_items"]
        if block["classification"] == "database":
            checks = ["render", "report_columns", "search"]
            if block["native_component"] == "form":
                checks.append("detail_navigation")
        result.append({"page_id": pages["page_id"], "source_block_id": block["source_block_id"],
                       "checks": checks})
        if block["native_component"] == "form":
            result.append({"page_id": pages["form_page_id"], "source_block_id": block["source_block_id"],
                           "checks": ["render", "native_items", "create", "update", "synthetic_records_accounted"]})
    return result


def runtime_binding(request, imported, artifact_binding):
    """Original durable import identity, not a URL/app ID supplied by a caller."""
    app_id, alias = imported.get("application_id"), imported.get("application_alias")
    _need(imported.get("imported") is True and type(app_id) is int and app_id > 0
          and alias == alias_for_job(request["job_id"])
          and imported.get("workspace") == "FORMS2APEX_POC"
          and all(type(imported.get(key)) is str and _SHA.fullmatch(imported[key])
                  for key in ("import_intent_sha256", "compiled_metadata_sha256")),
          "PROTOTYPE_RUNTIME_EXACT_IMPORT_REQUIRED")
    return {"schema_version": 1, "scope": RUNTIME_SCOPE, "profile_id": native_blueprint.PROFILE_ID,
            "job_id": request["job_id"], "project_id": request["project_id"],
            "source_binding": request["source_binding"], "plan_sha256": request["plan_sha256"],
            "rendered_zip_sha256": request["rendered_zip_sha256"],
            "artifact_binding_sha256": digest(artifact_binding), "import_receipt_sha256": digest(imported),
            "application_id": app_id, "application_alias": alias, "workspace": "FORMS2APEX_POC"}


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


def _package_zip(members):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, raw in sorted(members.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, raw)
    return stream.getvalue()


def _package_members(raw):
    _need(type(raw) is bytes and len(raw) <= 64_000_000, "PROTOTYPE_PACKAGE_SIZE_INVALID")
    members, total = {}, 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        _need(1 <= len(archive.infolist()) <= 700, "PROTOTYPE_PACKAGE_MEMBERS_INVALID")
        for row in archive.infolist():
            path = PurePosixPath(row.filename)
            _need(not path.is_absolute() and ".." not in path.parts and "\\" not in row.filename
                  and ":" not in row.filename and row.filename not in members and not row.is_dir()
                  and not row.flag_bits & 1 and (row.external_attr >> 16) & 0o170000 != 0o120000
                  and row.file_size <= 20_000_000,
                  "PROTOTYPE_PACKAGE_MEMBER_UNSAFE")
            total += row.file_size
            _need(total <= 64_000_000, "PROTOTYPE_PACKAGE_SIZE_INVALID")
            members[row.filename] = archive.read(row)
    return members


def validate_prototype_package(raw, *, request, runtime_receipt, imported, artifact_binding, export_receipt=None):
    """Pure package integrity; explicitly NOT conventional-SQL reimport proof."""
    members = _package_members(raw)
    manifest_raw = members.get("manifest.json", b"{}")
    manifest = json.loads(manifest_raw, object_pairs_hook=_unique_keys)
    expected = {name: hashlib.sha256(value).hexdigest() for name, value in members.items() if name != "manifest.json"}
    _need(type(manifest) is dict and set(manifest) == {"schema_version", "scope", "binding", "files"}
          and type(manifest["schema_version"]) is int and manifest["schema_version"] == 1 and manifest["scope"] == PACKAGE_SCOPE
          and manifest["files"] == expected
          and manifest["binding"] == runtime_binding(request, imported, artifact_binding),
          "PROTOTYPE_PACKAGE_MANIFEST_MISMATCH")
    required = {f"sql/f{imported['application_id']}.sql", "apexlang/application.apx", "README.txt",
                "native-blueprint-spec.json", "source-to-apex.json", "schema/01_synthetic_schema.sql",
                "evidence/runtime-receipt.json", "evidence/runtime-evidence/browser-report.json",
                "evidence/release-evidence.json", "evidence/source-summary.json", "evidence/target-requirements.json"}
    _need(required <= set(members), "PROTOTYPE_PACKAGE_INCOMPLETE")
    _need(members["native-blueprint-spec.json"] == canonical(request["rendering_spec"])
          and members["source-to-apex.json"] == canonical(native_blueprint.prototype_trace(request["rendering_spec"]))
          and members["schema/01_synthetic_schema.sql"] == native_blueprint.render_prototype_schema(request["rendering_spec"]).encode()
          and members["evidence/runtime-receipt.json"] == canonical(runtime_receipt),
          "PROTOTYPE_PACKAGE_EVIDENCE_MISMATCH")
    metadata = {name[len("apexlang/"):]: hashlib.sha256(value).hexdigest() for name, value in members.items()
                if name.startswith("apexlang/")}
    allowed = required | {"apexlang/" + name for name in metadata} | {
        "evidence/" + row["path"] for row in runtime_receipt["artifacts"]} | {"manifest.json"}
    _need(set(members) == allowed, "PROTOTYPE_PACKAGE_EXTRA_MEMBERS")
    _need(hashlib.sha256(json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
          == imported["compiled_metadata_sha256"], "PROTOTYPE_PACKAGE_COMPILED_METADATA_MISMATCH")
    for artifact in runtime_receipt["artifacts"]:
        name = "evidence/" + artifact["path"]
        _need(name in members and hashlib.sha256(members[name]).hexdigest() == artifact["sha256"]
              and len(members[name]) == artifact["bytes"], "PROTOTYPE_PACKAGE_RUNTIME_ARTIFACT_MISMATCH")
    evidence = json.loads(members["evidence/release-evidence.json"], object_pairs_hook=_unique_keys)
    _need(all(evidence.get(key) == value for key, value in runtime_binding(request, imported, artifact_binding).items())
          and evidence.get("sql_sha256") == hashlib.sha256(members[f"sql/f{imported['application_id']}.sql"]).hexdigest()
          and evidence.get("compiled_metadata_sha256") == imported["compiled_metadata_sha256"]
          and evidence.get("runtime_receipt_sha256") == digest(runtime_receipt)
          and evidence.get("authenticated_runtime_passed") is True and evidence.get("sqlcl_export_validated") is True
          and evidence.get("business_behavior_accepted") is False
          and evidence.get("package_reimport_passed") is False
          and evidence.get("clean_schema_install_passed") is False,
          "PROTOTYPE_PACKAGE_UNPROVEN_CLAIM")
    if export_receipt is not None:
        _need(hashlib.sha256(raw).hexdigest() == export_receipt.get("package_sha256")
              and evidence["sql_sha256"] == export_receipt.get("native_sql_sha256")
              and members["evidence/source-summary.json"] == canonical(export_receipt.get("source_summary"))
              and members["evidence/target-requirements.json"] == canonical(export_receipt.get("target_requirements")),
              "PROTOTYPE_PACKAGE_EXPORT_RECEIPT_MISMATCH")
    return {"manifest": manifest, "members": members, "evidence": evidence}


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
