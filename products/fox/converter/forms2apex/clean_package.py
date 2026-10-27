"""Offline verification of an explicitly approved native ZIP.

The caller must supply the SHA-256 from an independently approved artifact,
not calculate its trust anchor from an untrusted upload. Hash seals establish
content consistency inside that approved package; they are NOT Oracle/OPAF
signatures or vendor attestations. No SQL, model, network or database operation
is executed. Passing this check does not establish customer compatibility,
functional acceptance, or a successful clean installation.

Only the original packaged schema and application SQL bytes are returned. The
schema is compared byte-for-byte with the deterministic synthetic contract; it
is never substituted with newly generated DDL. There is deliberately no generic
extraction function: an authorized installer must write the returned bytes only
in its new, private, OS-guarded directory and perform target checks separately.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import zipfile

from .native import TEMPLATE_ID
from .native_contract import validate_native_spec
from .native_schema import render_native_schema
from .review_receipts import candidate_sha256, _verify_seal, _invocation, verify_historical_model_environment, review_proof_scope
from .security import alias_for_job, validate_job_id


MAX_ZIP_BYTES = 8_000_000
MAX_MEMBER_BYTES = 8_000_000
MAX_EXPANDED_BYTES = 20_000_000
MAX_MEMBERS = 500
MAX_RATIO = 200
SCHEMA_MEMBER = "schema/01_synthetic_schema.sql"
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_NAME = re.compile(r"[A-Za-z0-9_./-]{1,240}\Z")
_DEVICE = re.compile(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?\Z", re.I)
_CANDIDATE_KEYS = {"job_id", "template_id", "data_classification", "generator", "native_form", "remediation_items", "mapping_summary"}


class PackageValidationError(ValueError):
    """The supplied package has not passed offline clean-install prerequisites."""


def _require(condition, message):
    if not condition:
        raise PackageValidationError(message)


def _sha(value):
    _require(isinstance(value, str) and _SHA.fullmatch(value), "A lowercase SHA-256 digest is required")
    return value


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "Duplicate JSON keys are not permitted")
        result[key] = value
    return result


def _object(raw):
    _require(len(raw) <= 1_000_000, "JSON evidence exceeds the package bound")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                       parse_constant=lambda value: (_ for _ in ()).throw(PackageValidationError("Non-finite JSON is not permitted")))
    _require(isinstance(value, dict), "Package evidence must be a JSON object")
    return value


def _safe_name(name):
    _require(isinstance(name, str) and _NAME.fullmatch(name), "Unsafe package member path")
    parts = name.split("/")
    _require(len(parts) <= 12 and all(part not in ("", ".", "..") and not part.endswith(".")
                                    and not _DEVICE.fullmatch(part) for part in parts), "Unsafe package member path")
    return name


def _read_package(package):
    if isinstance(package, bytes):
        raw = package
    elif isinstance(package, (str, os.PathLike)):
        path = Path(package)
        _require(not path.is_symlink() and path.is_file(), "Package must be an unlinked regular file")
        _require(path.stat().st_size <= MAX_ZIP_BYTES, "Package exceeds the compressed size bound")
        with path.open("rb") as stream:
            raw = stream.read(MAX_ZIP_BYTES + 1)
    else:
        raise PackageValidationError("Package must be exact bytes or a local file path")
    _require(0 < len(raw) <= MAX_ZIP_BYTES, "Package exceeds the compressed size bound")
    return raw


def _members(raw):
    # This intentionally narrow ZIP profile forbids SFX, ZIP64, trailing blobs,
    # comments and all extension fields, including nonstandard link metadata.
    _require(raw.startswith(b"PK\x03\x04") and raw[-22:-18] == b"PK\x05\x06"
             and raw[-2:] == b"\x00\x00", "Unsupported ZIP envelope or trailing content")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        _require(0 < len(entries) <= MAX_MEMBERS and not archive.comment, "Invalid package member count or comment")
        _require(sum(entry.file_size for entry in entries) <= MAX_EXPANDED_BYTES, "Package exceeds the expanded size bound")
        names, offsets = set(), set()
        for entry in entries:
            name = _safe_name(entry.orig_filename)
            _require(name == entry.filename, "Normalized ZIP member paths are not accepted")
            _require(name.casefold() not in names and entry.header_offset not in offsets, "Duplicate or aliased package member")
            names.add(name.casefold()); offsets.add(entry.header_offset)
            kind = stat.S_IFMT(entry.external_attr >> 16)
            _require(kind in (0, stat.S_IFREG) and not entry.is_dir() and not entry.external_attr & 0x10,
                     "Linked or non-regular package member")
            _require(not entry.extra and not entry.comment and not entry.flag_bits & ~0x800,
                     "Encrypted or extended package members are not accepted")
            _require(entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), "Unsupported ZIP compression")
            _require(0 <= entry.file_size <= MAX_MEMBER_BYTES and entry.compress_size >= 0,
                     "Package member exceeds the size bound")
            _require(entry.file_size == 0 or (entry.compress_size > 0 and entry.file_size <= entry.compress_size * MAX_RATIO),
                     "Package member exceeds the compression ratio bound")
        for name in names:
            _require(not any("/".join(name.split("/")[:n]) in names for n in range(1, len(name.split("/")))),
                     "Package member collides with a directory path")
        result = {}
        for entry in entries:
            with archive.open(entry) as source:
                data = source.read(MAX_MEMBER_BYTES + 1)
            _require(len(data) == entry.file_size, "Package member length or CRC is invalid")
            result[entry.filename] = data
        manifest = _object(result["manifest.json"])
        _require(set(result) == set(manifest) | {"manifest.json"} and "manifest.json" not in manifest,
                 "Package manifest membership is not exact")
        for name, digest in manifest.items():
            _require(_digest(result[name]) == _sha(digest), "Package member hash differs from manifest")
        return result, manifest


def _source_identity(inventory):
    modules = inventory.get("modules")
    _require(isinstance(modules, list) and 1 <= len(modules) <= 50, "Source inventory must contain bounded modules")
    names, identities, total = set(), [], 0
    for module in modules:
        _require(isinstance(module, dict), "Invalid source module")
        name = _safe_name(module.get("file"))
        _require("/" not in name and name.casefold() not in names, "Invalid or duplicate source filename")
        names.add(name.casefold())
        text = module.get("readable_source")
        _require(isinstance(text, str), "Readable source evidence is required")
        raw = text.encode("utf-8")
        digest = _sha(module.get("sha256"))
        # Intake decodes UTF-8-sig after hashing original bytes. Reconstruct only
        # its two exact encodings; never normalize CRLF, Unicode or whitespace.
        if _digest(raw) != digest:
            raw = b"\xef\xbb\xbf" + raw
        _require(_digest(raw) == digest, "Source content differs from inventory hash")
        if "bytes" in module:
            _require(type(module["bytes"]) is int and module["bytes"] >= 0 and module["bytes"] == len(raw),
                     "Source byte count differs from original inventory bytes")
        # Older retained inventories omit bytes; the matching SHA still binds
        # exact original bytes and supplies the length for the aggregate bound.
        total += len(raw)
        _require(total <= 300_000, "Source evidence exceeds the native intake bound")
        identities.append((name, digest))
    return _digest("\n".join(name + ":" + digest for name, digest in sorted(identities)).encode())


def _validate(members, manifest, package_hash):
    release = _object(members["evidence/release-evidence.json"])
    spec = _object(members["native-form-spec.json"])
    normalized = validate_native_spec(spec)
    _require(spec == normalized, "Packaged native metadata is not the normalized synthetic contract")
    _require(members[SCHEMA_MEMBER] == render_native_schema(spec).encode("utf-8"),
             "Packaged schema SQL differs from the exact deterministic synthetic contract")
    _require(release.get("conversion_profile") == "native-table-form-v1", "Native conversion profile is required")
    for flag in ("reviewer_approved", "reviewer_execution_verified", "sqlcl_valid", "import_passed", "package_reimport_passed"):
        _require(release.get(flag) is True, "Required technical release evidence has not passed")
    job_id = release.get("job_id")
    _require(isinstance(job_id, str), "Job identity is required")
    validate_job_id(job_id)
    source_hash = _sha(release.get("source_manifest_sha256"))
    app_id, alias = release.get("application_id"), release.get("application_alias")
    _require(type(app_id) is int and 0 < app_id < 2**31 and alias == alias_for_job(job_id), "Invalid original application identity")
    sql_member = "sql/f" + str(app_id) + ".sql"
    _require(len(members[sql_member]) >= 1000 and {name for name in members if name.startswith("sql/")} == {sql_member},
             "Package must contain exactly the original application SQL export")
    binding = release.get("artifact_binding")
    _require(isinstance(binding, dict) and binding.get("schema_version") == 1
             and binding.get("job_id") == job_id and binding.get("template_id") == TEMPLATE_ID, "Invalid artifact binding")
    for key in ("draft_sha256", "draft_zip_sha256", "intake_sha256", "template_sha256"):
        _sha(binding.get(key))
    for key, member in {
        "native_review_sha256": "evidence/native-review.json",
        "inventory_sha256": "evidence/normalized-forms-inventory.json",
        "remediation_sha256": "evidence/migration-and-exception-report.json",
        "reviewed_spec_sha256": "evidence/migration-spec.json",
    }.items():
        _require(binding.get(key) == manifest[member], "Packaged evidence differs from artifact binding")

    inventory = _object(members["evidence/normalized-forms-inventory.json"])
    _require(inventory.get("job_id") == job_id and inventory.get("approved_native_form") == spec
             and _source_identity(inventory) == source_hash, "Inventory differs from approved source/native metadata")
    review = _object(members["evidence/native-review.json"])
    _verify_seal(review)
    historical_profile = verify_historical_model_environment(review)
    if review["schema_version"] == 2:
        from .target_profile import _canonical_bytes
        _require(members["evidence/target-profile.json"] == _canonical_bytes(historical_profile),
                 "Bundled target profile differs from the canonical sealed historical profile")
        profile_hash = _digest(members["evidence/target-profile.json"])
        _require(all(review["model_environment"][role]["target_profile_sha256"] == profile_hash for role in ("mapper", "reviewer")),
                 "Historical model observations do not bind the bundled profile bytes")
    else:
        _require("evidence/target-profile.json" not in members,
                 "Legacy v1 packages must not invent a historical target profile")
    candidate = review["candidate"]
    _require(review["job_id"] == job_id and review["source_hash"] == source_hash
             and review["intake_sha256"] == binding["intake_sha256"]
             and review["receipt_sha256"] == release.get("review_receipt_sha256")
             and review["candidate_sha256"] == candidate_sha256(candidate)
             and candidate["job_id"] == job_id and candidate["native_form"] == spec,
             "Native review does not bind this exact candidate/source")
    verdict = review["review"]
    _require(isinstance(verdict, dict) and verdict.get("verdict") == "approve"
             and verdict.get("blocking_findings") == [] and verdict.get("candidate_sha256") == review["candidate_sha256"],
             "Separate review has not approved the exact candidate")
    mapper, reviewer = review["mapper_invocation"], review["reviewer_invocation"]
    _, mapped_at = _invocation(mapper, mapper["workflow_id"], candidate["generator"]["model"], "Mapper")
    reviewed_at, _ = _invocation(reviewer, reviewer["workflow_id"], release["reviewer"]["model"], "Reviewer")
    _require(mapper["workflow_id"].casefold() != reviewer["workflow_id"].casefold()
             and mapper["room_id"].casefold() != reviewer["room_id"].casefold() and reviewed_at >= mapped_at,
             "Mapper and reviewer invocation independence/order is invalid")
    _require(release["reviewer"].get("receipt_sha256") == review["receipt_sha256"]
             and release["reviewer"].get("room_id") == reviewer["room_id"]
             and release["reviewer"].get("verdict") == "approve", "Release reviewer differs from sealed receipt")
    migration = _object(members["evidence/migration-spec.json"])
    _require({key: migration.get(key) for key in _CANDIDATE_KEYS} == candidate, "Materialized migration spec differs from reviewed candidate")

    imported = _object(members["evidence/imported-application.json"])
    _require(imported.get("job_id") == job_id and all(imported.get(key) == release.get(key)
             for key in ("application_id", "application_alias", "application_url", "artifact_binding")),
             "Release differs from original imported application")
    reimport = _object(members["evidence/package-reimport.json"])
    _require(reimport == release.get("package_reimport") and reimport.get("passed") is True
             and reimport.get("sql_sha256") == manifest[sql_member]
             and type(reimport.get("application_id")) is int and 0 < reimport["application_id"] < 2**31
             and reimport["application_id"] != app_id and reimport.get("application_alias") != alias,
             "Original SQL export is not bound to successful separate reimport evidence")
    completion = _object(members["evidence/export-completion.json"])
    _require(completion.get("schema_version") == 1 and completion.get("apexlang_validation_passed") is True
             and all(completion.get(key) == release.get(key) for key in ("job_id", "application_id", "application_alias", "artifact_binding"))
             and completion.get("imported_application_sha256") == manifest["evidence/imported-application.json"],
             "Export completion is not bound to original import")
    files = completion.get("files")
    _require(isinstance(files, dict) and 1 <= len(files) <= MAX_MEMBERS, "Export completion file set is invalid")
    for name, digest in files.items():
        _safe_name(name); _sha(digest)
    prefix = alias.lower() + "/"
    expected_apex = {"apexlang/" + name[len(prefix):]: digest for name, digest in files.items() if name.startswith(prefix)}
    actual_apex = {name: digest for name, digest in manifest.items() if name.startswith("apexlang/")}
    _require("apexlang/application.apx" in actual_apex and expected_apex == actual_apex
             and files.get("f" + str(app_id) + ".sql") == manifest[sql_member]
             and files.get("apexlang-validation.log") == manifest["evidence/export-validation.log"],
             "Packaged SQL/APEXlang/validation bytes differ from completed export")
    return {"package_sha256": package_hash, "job_id": job_id, "source_manifest_sha256": source_hash,
            "application_id": app_id, "application_alias": alias, "native_form": spec, "release_evidence": release,
            "schema_member": SCHEMA_MEMBER, "application_member": sql_member,
            "schema_sql": members[SCHEMA_MEMBER], "application_sql": members[sql_member],
            "selected_member_sha256": {SCHEMA_MEMBER: manifest[SCHEMA_MEMBER], sql_member: manifest[sql_member]},
            "validation_scope": "package_integrity_and_synthetic_schema_only",
            "review_proof_scope": review_proof_scope(review),
            "historical_model_environment_verified": review["schema_version"] == 2,
            "historical_target_profile": historical_profile,
            "current_target_authorized": False,
            "customer_compatibility_verified": False}


def validate_native_package(package, expected_sha256):
    """Validate approved ZIP bytes and return metadata plus original SQL bytes.

    ``expected_sha256`` is mandatory and must come from the approved artifact
    record. This function never executes, modifies, or regenerates an artifact.
    """
    try:
        expected = _sha(expected_sha256)
        raw = _read_package(package)
        digest = _digest(raw)
        _require(digest == expected, "Package SHA-256 does not match the approved artifact")
        members, manifest = _members(raw)
        return _validate(members, manifest, digest)
    except PackageValidationError:
        raise
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError, RecursionError, zipfile.BadZipFile, NotImplementedError):
        raise PackageValidationError("Native package evidence is malformed or inconsistent; installation is not authorized") from None

