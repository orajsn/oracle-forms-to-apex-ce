"""Pure exact prototype package validation; no execution or filesystem writes.

This module is shared with the limited FOX renderer payload. It must import
only the standard library and the existing pure native blueprint closure.
It proves package integrity, not execution, clean reimport or business acceptance.
"""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import PurePosixPath
import re
import zipfile

from . import native_blueprint


RUNTIME_SCOPE = "fox-native-blueprint-runtime-v1"
PACKAGE_SCOPE = "fox-native-blueprint-package-v1"
_SHA = re.compile(r"[a-f0-9]{64}\Z")


def _need(condition, code):
    if not condition:
        raise RuntimeError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON fields are not permitted in review evidence")
        result[key] = value
    return result


def alias_for_job(job_id):
    # Preserve security.alias_for_job's exact generic job/alias contract without
    # importing converter execution dependencies into the FOX app payload.
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{2,47}", job_id):
        raise ValueError("job_id must be 3-48 characters using letters, digits, underscore, or hyphen")
    alias = ("F2A_" + re.sub(r"[^A-Za-z0-9_]", "_", job_id).upper())[:52]
    if not re.fullmatch(r"F2A_[A-Z0-9_]{3,48}", alias):
        raise ValueError("job_id cannot be converted to a safe APEX alias")
    return alias


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
