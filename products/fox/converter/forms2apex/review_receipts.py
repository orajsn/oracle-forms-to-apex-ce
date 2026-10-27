"""Fail-closed review evidence for the native conversion path.

Only the authenticated FOX executor may submit these receipts. It must derive
the mapper/reviewer invocation metadata from two actual OPAF responses and pass
the review from the second response.message object, never from mapper output.
The hashes are bounded audit metadata, not a vendor signature or a cryptographic
attestation that OPAF ran. A caller with executor credentials or write access to
the job directory remains inside the trust boundary.

Candidates contain metadata only and cannot declare their own reviewer. Their
exact canonical JSON is hashed (normalization is used only to compare schemas).
The frozen source tree is also bound, so changing bytes, manifest, or native
specification invalidates a receipt. A rejected job needs a new job/receipt;
different evidence never replaces an existing receipt. No network or database
access is performed here.

Version 1 proves invocation/candidate/source binding only. Version 2 additionally
seals the authenticated executor's historical environment observation for each
model invocation and its server-supplied registered target-profile snapshot.
Historical verification
does not contact OPAF or expire by the current wall clock. Existing version 1
receipts are never upgraded, rewritten, or described as environment proof.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile

from .native import TEMPLATE_ID
from .native_contract import validate_native_spec
from .provenance import tree_digest
from .security import validate_job_id


_MAX_BYTES = 256_000
_CANDIDATE_FIELDS = {
    "job_id", "template_id", "data_classification", "generator", "native_form",
    "remediation_items", "mapping_summary",
}
_PAYLOAD_FIELDS = {
    "job_id", "source_hash", "candidate", "mapper_invocation", "reviewer_invocation", "review",
}
_ENVIRONMENT_FIELDS = {"model_environment"}
_INVOCATION_FIELDS = {
    "workflow_id", "room_id", "model", "graph_sha256", "request_sha256",
    "response_sha256", "started_at_utc", "completed_at_utc",
}
_REVIEW_FIELDS = {"verdict", "candidate_sha256", "notes", "blocking_findings"}
_SEAL_FIELDS = {"schema_version", "trust_boundary", "candidate_sha256", "intake_sha256", "receipt_sha256"}
_HISTORICAL_PROFILE_FIELDS = {"historical_target_profile"}
_TRUST_BOUNDARY = "authenticated_fox_executor_not_vendor_attestation"
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)\Z")


def _fields(value, expected, location):
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{location} must contain exactly its required fields")


def _text(value, location, maximum=8000, allow_empty=False):
    if not isinstance(value, str) or len(value) > maximum or (not allow_empty and not value.strip()):
        raise ValueError(f"{location} must be bounded text")
    if any(ord(char) < 32 and char not in "\n\r\t" for char in value):
        raise ValueError(f"{location} must not contain control characters")
    return value


def _identity(value, location):
    if not isinstance(value, str) or not _IDENTITY.fullmatch(value):
        raise ValueError(f"{location} must be a bounded identifier")
    return value


def _sha256(value, location):
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{location} must be a lowercase SHA-256 digest")
    return value


def _json_types(value, depth=0):
    if depth > 16:
        raise ValueError("Review evidence exceeds the JSON nesting limit")
    if value is None or type(value) in (str, int, float, bool):
        return
    if type(value) is list:
        for entry in value:
            _json_types(entry, depth + 1)
        return
    if type(value) is dict and all(type(key) is str for key in value):
        for entry in value.values():
            _json_types(entry, depth + 1)
        return
    raise ValueError("Review evidence must contain JSON values only")


def _canonical(value):
    _json_types(value)
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                         allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise ValueError("Review evidence is not canonical JSON") from exc
    if len(raw) > _MAX_BYTES:
        raise ValueError("Review evidence exceeds the bounded payload size")
    return raw


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _candidate(candidate):
    _fields(candidate, _CANDIDATE_FIELDS, "Native candidate (no self-declared reviewer)")
    if not isinstance(candidate["job_id"], str):
        raise ValueError("Native candidate job_id must be text")
    validate_job_id(candidate["job_id"])
    if candidate["template_id"] != TEMPLATE_ID:
        raise ValueError("Native candidate must use the canonical native template")
    if candidate["data_classification"] != "synthetic_or_stub_only":
        raise ValueError("Native candidate requires synthetic_or_stub_only data")
    _fields(candidate["generator"], {"model"}, "Native generator")
    _identity(candidate["generator"]["model"], "Generator model")
    validate_native_spec(candidate["native_form"])
    _text(candidate["mapping_summary"], "Mapping summary")
    items = candidate["remediation_items"]
    if not isinstance(items, list) or len(items) > 200 or any(not isinstance(item, dict) for item in items):
        raise ValueError("Remediation items must be a bounded array of objects")
    _canonical(candidate)
    return candidate


def candidate_sha256(candidate):
    """Hash exact, strict native metadata JSON; never accept a reviewer field."""
    return _digest(_candidate(candidate))


def _utc(value, location):
    if not isinstance(value, str) or not _UTC.fullmatch(value):
        raise ValueError(f"{location} must be an ISO 8601 UTC timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{location} is not a valid UTC timestamp") from exc
    if result.utcoffset() != timezone.utc.utcoffset(result):
        raise ValueError(f"{location} must use UTC")
    return result


def _invocation(value, workflow_id, model, location):
    _fields(value, _INVOCATION_FIELDS, location)
    for key in ("workflow_id", "room_id", "model"):
        _identity(value[key], f"{location}.{key}")
    if value["workflow_id"] != workflow_id or value["model"] != model:
        raise ValueError(f"{location} does not match the configured workflow/model")
    for key in ("graph_sha256", "request_sha256", "response_sha256"):
        _sha256(value[key], f"{location}.{key}")
    start = _utc(value["started_at_utc"], f"{location}.started_at_utc")
    complete = _utc(value["completed_at_utc"], f"{location}.completed_at_utc")
    if complete < start:
        raise ValueError(f"{location} completed before it started")
    return start, complete


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON fields are not permitted in review evidence")
        result[key] = value
    return result


def _read_object(path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("Required review evidence file is missing or linked")
    # Permit the optional UTF-8 BOM/newline; canonical JSON remains bounded.
    if path.stat().st_size > _MAX_BYTES + 4:
        raise ValueError("Review evidence file exceeds the bounded size")
    raw = path.read_bytes()
    if len(raw) > _MAX_BYTES + 4:
        raise ValueError("Review evidence file exceeds the bounded size")
    value = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_keys)
    if not isinstance(value, dict):
        raise ValueError("Review evidence must be a JSON object")
    _canonical(value)
    return value


def _source_binding(job_root, job_id, source_hash, native_form):
    root = Path(job_root)
    if root.is_symlink() or not root.is_dir() or root.name != job_id:
        raise ValueError("Review job directory must match the exact job_id")
    intake = root / "intake"
    before = _intake_digest(intake)
    manifest = _read_object(intake / "manifest.json")
    if manifest.get("job_id") != job_id:
        raise ValueError("Intake manifest job_id does not match the review")
    if _sha256(manifest.get("source_manifest_sha256"), "Intake source hash") != source_hash:
        raise ValueError("Intake source hash does not match the review")
    if validate_native_spec(manifest.get("native_form")) != validate_native_spec(native_form):
        raise ValueError("Intake native specification does not match the reviewed candidate")
    files = manifest.get("files")
    if not isinstance(files, list) or not 1 <= len(files) <= 50:
        raise ValueError("Review requires a nonempty bounded source manifest")
    names = set()
    total = 0
    for entry in files:
        if not isinstance(entry, dict):
            raise ValueError("Invalid source manifest entry")
        name = entry.get("packaged_name")
        if not isinstance(name, str) or not name or "\\" in name or ":" in name:
            raise ValueError("Invalid source manifest path")
        path = PurePosixPath(name)
        if (path.is_absolute() or ".." in path.parts or name != path.as_posix()
                or name == "manifest.json" or name in names):
            raise ValueError("Invalid or duplicate source manifest path")
        names.add(name)
        source = intake.joinpath(*path.parts)
        if source.is_symlink() or not source.is_file() or intake.resolve() not in source.resolve().parents:
            raise ValueError("Source manifest entry is missing or linked")
        raw = source.read_bytes()
        total += len(raw)
        if total > 300_000 or not raw:
            raise ValueError("Review source exceeds the bounded source size")
        if hashlib.sha256(raw).hexdigest() != _sha256(entry.get("sha256"), "Source file hash"):
            raise ValueError("Source file hash does not match the frozen manifest")
    actual = {path.relative_to(intake).as_posix() for path in intake.rglob("*") if path.is_file()}
    if actual != names | {"manifest.json"}:
        raise ValueError("Source files do not match the frozen source manifest exactly")
    if _intake_digest(intake) != before:
        raise RuntimeError("Source changed while binding the native review")
    return before


def _intake_digest(intake):
    """Bound the local tree before hashing; staging remains a separate control."""
    if intake.is_symlink() or not intake.is_dir():
        raise RuntimeError("Required source directory is missing or linked")
    count = total = 0
    for path in intake.rglob("*"):
        count += 1
        if count > 250 or path.is_symlink():
            raise ValueError("Source tree exceeds entry limits or contains links")
        if path.is_file():
            if path == intake / "manifest.json":
                if path.stat().st_size > _MAX_BYTES + 4:
                    raise ValueError("Source manifest exceeds the bounded size")
            else:
                total += path.stat().st_size
                if total > 300_000:
                    raise ValueError("Review source exceeds the bounded source size")
        elif not path.is_dir():
            raise ValueError("Unsupported source filesystem entry")
    return tree_digest(intake)


def _sealed_payload(job_root, payload, expected_mapper_id, expected_reviewer_id, generator_model, reviewer_model,
                    *, target_profile=None, _historical_verification=False):
    version = 2 if target_profile is not None else 1
    payload_fields = _PAYLOAD_FIELDS | (_ENVIRONMENT_FIELDS if version == 2 else set())
    _fields(payload, payload_fields, "Review payload")
    if version == 2:
        from .target_profile import validate_target_profile, validate_historical_target_profile
        # Only server-approved ACTIVE configuration can create new evidence.
        # Reverification explicitly selects its already sealed known snapshot.
        target_profile = (validate_historical_target_profile(target_profile) if _historical_verification
                          else validate_target_profile(target_profile))
    _identity(expected_mapper_id, "Configured mapper workflow")
    _identity(expected_reviewer_id, "Configured reviewer workflow")
    _identity(generator_model, "Configured generator model")
    _identity(reviewer_model, "Configured reviewer model")
    # Conservative beta policy: case-only aliases do not establish independence,
    # even for deployments whose opaque identifiers may be case-sensitive.
    if expected_mapper_id.casefold() == expected_reviewer_id.casefold():
        raise ValueError("Mapper and reviewer must use distinct configured workflows")
    # Round-trip detaches all submitted containers; caller mutations cannot alter
    # the evidence between validation and the atomic publish.
    payload = json.loads(_canonical(payload))
    candidate = _candidate(payload["candidate"])
    if payload["job_id"] != candidate["job_id"]:
        raise ValueError("Review job_id does not match its candidate")
    if candidate["generator"]["model"] != generator_model:
        raise ValueError("Candidate generator model does not match the configured model")
    source_hash = _sha256(payload["source_hash"], "Review source hash")
    mapper = payload["mapper_invocation"]
    reviewer = payload["reviewer_invocation"]
    _, mapper_complete = _invocation(mapper, expected_mapper_id, generator_model, "Mapper invocation")
    reviewer_start, _ = _invocation(reviewer, expected_reviewer_id, reviewer_model, "Reviewer invocation")
    if mapper["room_id"].casefold() == reviewer["room_id"].casefold():
        raise ValueError("Mapper and reviewer must use distinct OPAF rooms")
    if reviewer_start < mapper_complete:
        raise ValueError("Reviewer must start after mapper completion")
    if version == 2:
        _fields(payload["model_environment"], {"mapper", "reviewer"}, "Historical model environment")
        # This function is pure: it checks historical values against the actual
        # invocation window, never invoking a live environment collector.
        from .runtime_preflight import validate_model_environment_observation
        for role, invocation in (("mapper", mapper), ("reviewer", reviewer)):
            validate_model_environment_observation(
                target_profile, payload["model_environment"][role], job_id=payload["job_id"],
                source_manifest_sha256=source_hash, role=role, invocation=invocation,
            )
    review = payload["review"]
    _fields(review, _REVIEW_FIELDS, "Separate reviewer response")
    if review["verdict"] not in ("approve", "reject"):
        raise ValueError("Reviewer verdict must be approve or reject")
    digest = candidate_sha256(candidate)
    if _sha256(review["candidate_sha256"], "Reviewed candidate hash") != digest:
        raise ValueError("Reviewer candidate hash does not match the exact candidate")
    notes = review["notes"]
    if isinstance(notes, list):
        if len(notes) > 100:
            raise ValueError("Review notes must be a bounded text array")
        for note in notes:
            _text(note, "Review note", maximum=2000)
    else:
        _text(notes, "Review notes", allow_empty=True)
    findings = review["blocking_findings"]
    if not isinstance(findings, list) or len(findings) > 100:
        raise ValueError("Review blocking findings must be a bounded text array")
    for finding in findings:
        _text(finding, "Blocking finding", maximum=2000)
    if review["verdict"] == "approve" and findings:
        raise ValueError("Approval cannot contain blocking findings")
    intake_digest = _source_binding(job_root, payload["job_id"], source_hash, candidate["native_form"])
    receipt = {
        **payload, "schema_version": version, "trust_boundary": _TRUST_BOUNDARY,
        "candidate_sha256": digest, "intake_sha256": intake_digest,
    }
    if version == 2:
        # This field is server-supplied and never accepted from caller payload.
        receipt["historical_target_profile"] = target_profile
    return {**receipt, "receipt_sha256": _digest(receipt)}


def _verify_seal(receipt):
    if not isinstance(receipt, dict) or type(receipt.get("schema_version")) is not int or receipt["schema_version"] not in (1, 2):
        raise ValueError("Unsupported review receipt version")
    _fields(receipt, _PAYLOAD_FIELDS | _SEAL_FIELDS | ((_ENVIRONMENT_FIELDS | _HISTORICAL_PROFILE_FIELDS) if receipt["schema_version"] == 2 else set()),
            "Sealed review receipt")
    if receipt["schema_version"] == 2:
        _fields(receipt["model_environment"], {"mapper", "reviewer"}, "Historical model environment")
        if not isinstance(receipt["historical_target_profile"], dict):
            raise ValueError("Version 2 review requires its sealed historical target profile")
    if receipt["trust_boundary"] != _TRUST_BOUNDARY:
        raise ValueError("Unknown review receipt trust boundary")
    digest = _sha256(receipt["receipt_sha256"], "Receipt hash")
    content = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    if not hmac.compare_digest(digest, _digest(content)):
        raise ValueError("Review receipt content hash mismatch")


def _sync_directory(root):
    # Linux deployment durability: fsync the directory entry after publication.
    # Python has no portable Windows directory fsync; local Windows tests prove
    # atomic create-only behavior, not durability across a host power loss.
    if os.name == "posix":
        descriptor = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def review_proof_scope(receipt):
    """Describe a receipt's evidence tier; call after full verify_review.

    This helper checks the content seal only. It does not itself validate the
    source directory or target profile and does not modify the sealed receipt.
    """
    _verify_seal(receipt)
    return ("legacy_invocation_candidate_source_binding_no_model_environment" if receipt["schema_version"] == 1
            else "historical_model_environment_and_invocation_candidate_source_binding")


def verify_historical_model_environment(receipt):
    """Verify v2's self-contained known profile/observations without live probes.

    Return the validated historical snapshot, or None for legacy v1. This does
    NOT authorize the current target or verify the source directory; callers
    must enforce those separate gates. No current configuration is substituted.
    """
    _verify_seal(receipt)
    if receipt["schema_version"] == 1:
        return None
    from .target_profile import validate_historical_target_profile
    from .runtime_preflight import validate_model_environment_observation
    profile = validate_historical_target_profile(receipt["historical_target_profile"])
    for role in ("mapper", "reviewer"):
        validate_model_environment_observation(
            profile, receipt["model_environment"][role], job_id=receipt["job_id"],
            source_manifest_sha256=receipt["source_hash"], role=role,
            invocation=receipt[role + "_invocation"],
        )
    return profile


def record_review(job_root, payload, expected_mapper_id, expected_reviewer_id, generator_model, reviewer_model,
                  *, target_profile=None):
    """Record trusted executor evidence once; identical retries are idempotent.

    A rejection is preserved as evidence, not treated as approval. Verification
    must still be called at generation/import boundaries. Published receipt
    files are never replaced, including after an uncertain previous response.

    With a configured target_profile, NEW receipts require both historical
    model_environment observations and use version 2. An exact replay of an
    already stored version 1 payload may return that same legacy receipt; no
    missing observations are invented. With no profile, NEW receipts preserve
    legacy version 1 library behavior and cannot accept environment fields.
    An existing v2 receipt may be replayed from its registered historical proof,
    without substituting current settings or rewriting the retained receipt.
    """
    root = Path(job_root)
    target = root / "native-review.json"
    legacy_replay = False
    if target.exists() or target.is_symlink():
        existing = _read_object(target)
        _verify_seal(existing)
        if existing["schema_version"] == 2:
            _fields(payload, _PAYLOAD_FIELDS | _ENVIRONMENT_FIELDS, "Review payload")
            existing = _verify_recorded_receipt(root, payload["candidate"], expected_mapper_id, expected_reviewer_id,
                                               generator_model, reviewer_model)
            if _canonical(payload) != _canonical({key: existing[key] for key in _PAYLOAD_FIELDS | _ENVIRONMENT_FIELDS}):
                raise ValueError("Different native review evidence already exists; use a new job")
            _sync_directory(root)
            return existing
        legacy_replay = target_profile is not None and isinstance(payload, dict) and set(payload) == _PAYLOAD_FIELDS
    receipt = _sealed_payload(job_root, payload, expected_mapper_id, expected_reviewer_id,
                              generator_model, reviewer_model,
                              target_profile=None if legacy_replay else target_profile)
    if legacy_replay:
        # Never enter the publish path for configured legacy replay, even if the
        # old file disappears or changes between the initial read and now.
        existing = _read_object(target)
        _verify_seal(existing)
        if _canonical(existing) != _canonical(receipt):
            raise ValueError("Different native review evidence already exists; use a new job")
        _sync_directory(root)
        return existing
    if target.exists() or target.is_symlink():
        existing = _read_object(target)
        _verify_seal(existing)
        if _canonical(existing) != _canonical(receipt):
            raise ValueError("Different native review evidence already exists; use a new job")
        _sync_directory(root)
        return existing
    descriptor, temporary_name = tempfile.mkstemp(prefix=".native-review-", suffix=".tmp", dir=root)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_canonical(receipt) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        if _intake_digest(root / "intake") != receipt["intake_sha256"]:
            raise RuntimeError("Source changed before publishing native review")
        # link() atomically publishes a complete file and fails if target exists;
        # replace() would permit concurrent callers to overwrite first evidence.
        try:
            os.link(temporary, target)
        except FileExistsError:
            existing = _read_object(target)
            _verify_seal(existing)
            if _canonical(existing) != _canonical(receipt):
                raise ValueError("Different native review evidence already exists; use a new job")
            _sync_directory(root)
            return existing
        _sync_directory(root)
        return receipt
    finally:
        temporary.unlink(missing_ok=True)


def _verify_recorded_receipt(job_root, candidate, expected_mapper_id, expected_reviewer_id, generator_model, reviewer_model,
                             *, target_profile=None):
    """Verify retained evidence, including rejection, without authorizing work.

    Version 2 derives expected model/workflow identities and environment checks
    from its sealed registered historical snapshot, NOT current arguments or
    target_profile. Current target authorization is a separate fresh gate.
    Version 1 remains legacy invocation/source proof, even if a profile is now
    configured. Return the original sealed dictionary unchanged in both cases.
    """
    receipt = _read_object(Path(job_root) / "native-review.json")
    _verify_seal(receipt)
    if receipt["candidate_sha256"] != candidate_sha256(candidate):
        raise ValueError("Review receipt does not approve the exact candidate")
    version = receipt["schema_version"]
    historical_profile = verify_historical_model_environment(receipt) if version == 2 else None
    if version == 2:
        roles = historical_profile["opaf"]["roles"]
        expected_mapper_id, expected_reviewer_id = roles["mapper"]["workflow_id"], roles["reviewer"]["workflow_id"]
        generator_model, reviewer_model = roles["mapper"]["model"], roles["reviewer"]["model"]
    fields = _PAYLOAD_FIELDS | (_ENVIRONMENT_FIELDS if version == 2 else set())
    payload = {key: receipt[key] for key in fields}
    expected = _sealed_payload(job_root, payload, expected_mapper_id, expected_reviewer_id,
                               generator_model, reviewer_model,
                               target_profile=historical_profile, _historical_verification=version == 2)
    if _canonical(receipt) != _canonical(expected):
        raise ValueError("Review receipt no longer matches the frozen source or specification")
    return receipt


def verify_review(job_root, candidate, expected_mapper_id, expected_reviewer_id, generator_model, reviewer_model,
                  *, target_profile=None):
    """Require approval after exact source/candidate/historical proof checks.

    V2 uses its registered sealed historical profile, never current arguments to
    substitute the old model environment. Fresh target authorization is separate.
    V1 preserves its original explicit role checks and legacy evidence scope.
    """
    receipt = _verify_recorded_receipt(job_root, candidate, expected_mapper_id, expected_reviewer_id,
                                      generator_model, reviewer_model, target_profile=target_profile)
    if receipt["review"]["verdict"] != "approve":
        raise ValueError("Separate OPAF reviewer approval is required")
    return receipt
