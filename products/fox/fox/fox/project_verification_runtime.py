"""Local durable project QA decisions; no APEX/OCI calls or human acceptance.

Reuses native owner-private receipt I/O and the existing SQLite proof/event
schema. New decisions require current complete selected sources; historical
reads verify retained exact evidence at the original decision time without
reopening today's version allowlist or requiring current source selection.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3

from . import native_verification as native_io
from .intake import inventory
from .native_verification_policy import BoundVerificationPolicy, VerificationPolicyError, validate_allocation_receipt
from .opaf import canonical_hash, OpafError
from .project_qa_plan import PROFILE_ID
from .project_verification import (PROOF_SCOPE, RECEIPT_NAMES, ProjectVerificationError,
                                  _verify, verify_project_detached_proof)
from .source_history import selected_sources, SourceHistoryError


ATTEMPT_SCOPE = "fox-project-technical-attempt-v1"
_PACKAGE_LIMIT = 8_000_000
_RETAINED = "project-technical-verification"
_PIPELINE = "native-project-pipeline"
_TABLE_DDL = ("CREATE TABLE IF NOT EXISTS technical_verifications("
    "run TEXT PRIMARY KEY REFERENCES runs(id),source_hash TEXT NOT NULL,"
    "artifact_sha256 TEXT NOT NULL,proof_sha256 TEXT NOT NULL,proof_json TEXT NOT NULL,created REAL NOT NULL)")


def _require(condition, message):
    if not condition:
        raise ProjectVerificationError(message)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _raw(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def _one(connection, sql, parameters=()):
    cursor = connection.execute(sql, parameters)
    row = cursor.fetchone()
    return dict(zip((column[0] for column in cursor.description), row)) if row is not None else None


def _stored(connection, run_id):
    exists = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='technical_verifications'").fetchone()
    return _one(connection, "SELECT * FROM technical_verifications WHERE run=?", (run_id,)) if exists else None


def _run_id(value):
    _require(isinstance(value, str) and re.fullmatch(r"fox-[a-f0-9]{20}", value), "Invalid project run identity.")
    return value


def _material(root, run_id):
    job = native_io._safe_path(root / "jobs" / _run_id(run_id))
    paths = {"source_snapshot": job / "source-snapshot.json", "release_evidence": job / "release-evidence.json",
             "download": job / _PIPELINE / "download.json", "target_profile": job / _PIPELINE / "target-profile.json"}
    raws = {key: native_io._read(path) for key, path in paths.items()}
    objects = {key: native_io._json(value) for key, value in raws.items()}
    package_path = job / "apex-package.zip"
    package = native_io._read(package_path, _PACKAGE_LIMIT)
    snapshot, release = objects["source_snapshot"], objects["release_evidence"]
    envelope = objects["target_profile"]
    _require(snapshot.get("conversion_profile") == PROFILE_ID and release.get("conversion_profile") == PROFILE_ID
             and release.get("job_id") == run_id
             and objects["download"] == {"package_sha256": _sha(package), "source_hash": snapshot.get("source_hash")},
             "Frozen project download, source or release identity differs.")
    _require(set(envelope) == {"target_profile", "target_profile_sha256"}
             and isinstance(envelope["target_profile"], dict)
             and envelope["target_profile_sha256"] == canonical_hash(envelope["target_profile"]),
             "The immutable project target-profile cache is invalid.")
    return {"job": job, "paths": paths, "raws": raws, "objects": objects,
            "package_path": package_path, "package": package, "target_profile": envelope["target_profile"]}


def _row_binding(row, material, root):
    snapshot = material["objects"]["source_snapshot"]
    _require(row is not None and row.get("source_hash") == snapshot.get("source_hash")
             and row.get("project") == snapshot.get("project") == snapshot.get("project_id")
             and row.get("artifact") == str(material["package_path"].relative_to(root)),
             "The project run does not bind its complete source version and exact package.")


def _selection(connection, row, snapshot):
    try:
        sources = selected_sources(connection, row["project"])
        _require(inventory(sources)["source_hash"] == snapshot["source_hash"],
                 "Selected project sources changed; prior proof cannot promote this version.")
    except SourceHistoryError:
        raise ProjectVerificationError("Selected complete source history is unavailable or inconsistent.") from None


def _attempt_identity(run_id, material, policy, allocation_raw, receipt_raws, run_created):
    return {"schema_version": 1, "scope": ATTEMPT_SCOPE, "job_id": run_id,
        "run_created": run_created,
        "source_manifest_sha256": material["objects"]["source_snapshot"]["source_hash"],
        "package_sha256": _sha(material["package"]), "verification_profile_sha256": policy.sha256,
        "allocation_receipt_sha256": _sha(allocation_raw),
        "receipt_sha256": dict(zip(RECEIPT_NAMES, map(_sha, receipt_raws))),
        "frozen_file_sha256": {key: _sha(raw) for key, raw in material["raws"].items()}}


def _arguments(material, receipts, policy, allocation_raw, decision_time, created):
    return {"package": material["package"], "snapshot": material["objects"]["source_snapshot"],
        "release": material["objects"]["release_evidence"], "clean_install_raw": receipts[0],
        "qa_result_raw": receipts[1], "qa_target_raw": receipts[2], "qa_profile_raw": receipts[3],
        "policy": policy, "allocation_receipt_raw": allocation_raw, "now": decision_time,
        "run_created": created, "target_profile": material["target_profile"]}


def _recorded_proof(base, attempt_raw):
    return {**base, "operator_attempt_sha256": _sha(attempt_raw)}


def _same_material(material):
    _require(all(native_io._read(path) == material["raws"][key] for key, path in material["paths"].items())
             and native_io._read(material["package_path"], _PACKAGE_LIMIT) == material["package"],
             "Project source, target or package changed before technical commit.")


def _checked(connection, root, run):
    run_id = _run_id(run.get("id"))
    stored = _stored(connection, run_id)
    _require(stored is not None and run.get("state") in {"VERIFIED", "ACCEPTED"},
             "Project technical verification is required before acceptance or download.")
    material = _material(root, run_id)
    _row_binding(run, material, root)
    retained = native_io._safe_path(material["job"] / _RETAINED)
    proof_raw = native_io._read(retained / "verification.json")
    _require(isinstance(stored.get("proof_json"), str) and stored["proof_json"].encode() == proof_raw
             and _sha(proof_raw) == stored.get("proof_sha256")
             and stored.get("source_hash") == run["source_hash"]
             and stored.get("artifact_sha256") == _sha(material["package"]),
             "Stored project proof or package bytes changed.")
    proof = native_io._json(proof_raw)
    _require(type(proof.get("schema_version")) is int and proof["schema_version"] == 1
             and proof.get("scope") == PROOF_SCOPE and proof.get("conversion_profile") == PROFILE_ID,
             "Retained proof is not the project verification contract.")
    policy = BoundVerificationPolicy(native_io._read(retained / "verification-profile.json", 16_384), historical=True)
    allocation_raw = native_io._read(retained / "allocation-receipt.json", 16_384)
    validate_allocation_receipt(allocation_raw, policy)
    receipt_raws = [native_io._read(retained / name) for name in RECEIPT_NAMES]
    attempt_raw = native_io._read(retained / "attempt.json")
    attempt = native_io._json(attempt_raw)
    identity = _attempt_identity(run_id, material, policy, allocation_raw, receipt_raws, run["created"])
    _require(set(attempt) == set(identity) | {"verified_at_utc"}
             and _raw({key: attempt[key] for key in identity}) == _raw(identity),
             "Project retained attempt differs from its exact original inputs.")
    decision_time = datetime.fromtimestamp(native_io._time(attempt["verified_at_utc"]), timezone.utc)
    _require(type(stored.get("created")) in (int, float) and stored["created"] == decision_time.timestamp(),
             "Original project decision timestamp changed.")
    base = _verify(**_arguments(material, receipt_raws, policy, allocation_raw, decision_time, run["created"]), _historical=True)
    expected = _recorded_proof(base, attempt_raw)
    _require(_raw(expected) == proof_raw, "Retained whole-project runtime proof no longer validates.")
    # No current source-selection or current-version check here: accepted
    # historical source versions retain their exact valid package identity.
    return {"proof": proof, "package": material["package"]}


def checked_project_release(connection: sqlite3.Connection, root: Path, run: dict):
    """Return {'proof': dict, 'package': bytes}; never None or change state.

    The shared dispatcher calls this for every project marker. It must not be
    used as a permissive profile detector or fall back to legacy on failure.
    Existing accepted historical runs need no current operator input directory.
    """
    try:
        return _checked(connection, native_io._safe_path(Path(root)), dict(run))
    except ProjectVerificationError:
        raise
    except (native_io.VerificationError, VerificationPolicyError, OpafError, OSError, sqlite3.Error,
            ValueError, KeyError, TypeError, AttributeError, RecursionError):
        raise ProjectVerificationError("Retained project verification evidence is unavailable or malformed.") from None


def _promote(*, root, run_id, operator_receipt_dir, policy, now):
    run_id = _run_id(run_id)
    _require(type(policy) is BoundVerificationPolicy, "An exact project verification policy is required.")
    requested_historical = policy.historical
    root = native_io._safe_path(Path(root))
    operator = native_io._private(Path(operator_receipt_dir), directory=True)
    _require(operator != root and root not in operator.parents, "Operator evidence must be outside FOX data.")
    policy_raw = native_io._read(native_io._private(operator / "verification-profile.json"), 16_384)
    _require(policy_raw == policy.raw, "Private operator policy differs from the supplied policy.")
    retained_policy = BoundVerificationPolicy(policy_raw, historical=True)
    allocation_raw = native_io._read(native_io._private(operator / "allocation-receipt.json"), 16_384)
    validate_allocation_receipt(allocation_raw, retained_policy)
    receipt_raws = [native_io._read(native_io._private(operator / name)) for name in RECEIPT_NAMES]
    material = _material(root, run_id)
    database = native_io._safe_path(root / "fox.sqlite3")
    current_time = now or datetime.now(timezone.utc)
    _require(isinstance(current_time, datetime) and current_time.tzinfo is not None,
             "Project decision time must be timezone-aware.")
    with sqlite3.connect(database, timeout=30) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        row = _one(connection, "SELECT * FROM runs WHERE id=?", (run_id,))
        _require(row is not None and row["state"] in {"QA_REQUIRED", "VERIFIED", "ACCEPTED"},
                 "Project run is not eligible for technical verification.")
        _row_binding(row, material, root)
        prior = _stored(connection, run_id)
        identity = _attempt_identity(run_id, material, retained_policy, allocation_raw, receipt_raws, row["created"])
        if prior:
            checked = checked_project_release(connection, root, row)
            proof = checked["proof"]
            _require(proof["receipt_sha256"] == identity["receipt_sha256"]
                     and proof["verification_profile_sha256"] == retained_policy.sha256
                     and proof["allocation_receipt_sha256"] == _sha(allocation_raw),
                     "A different operator input cannot replace the recorded project proof.")
            return {"id": run_id, "state": row["state"], "idempotent": True, "proof_sha256": prior["proof_sha256"]}
        _require(row["state"] == "QA_REQUIRED", "A project state without its proof requires reconciliation.")
        _selection(connection, row, material["objects"]["source_snapshot"])
        retained = material["job"] / _RETAINED
        attempt_path = retained / "attempt.json"
        if attempt_path.exists() or attempt_path.is_symlink():
            native_io._private(retained, directory=True)
            _require(native_io._read(native_io._private(retained / "verification-profile.json"), 16_384) == policy_raw
                     and native_io._read(native_io._private(retained / "allocation-receipt.json"), 16_384) == allocation_raw,
                     "Retained project attempt has a different policy or allocation.")
            attempt_raw = native_io._read(native_io._private(attempt_path))
            attempt = native_io._json(attempt_raw)
            _require(set(attempt) == set(identity) | {"verified_at_utc"}
                     and _raw({key: attempt[key] for key in identity}) == _raw(identity),
                     "Existing project attempt differs; no overwrite or automatic replay.")
            decision_time = datetime.fromtimestamp(native_io._time(attempt["verified_at_utc"]), timezone.utc)
            _require(decision_time.timestamp() <= current_time.timestamp() + 300, "Retained project attempt is future-dated.")
            proof = _verify(**_arguments(material, receipt_raws, retained_policy, allocation_raw, decision_time, row["created"]), _historical=True)
        else:
            _require(not requested_historical, "Historical policy cannot authorize a new project decision.")
            active_policy = BoundVerificationPolicy(policy_raw)
            decision_time = current_time
            attempt_raw = _raw({**identity, "verified_at_utc": decision_time.astimezone(timezone.utc).isoformat()})
            proof = verify_project_detached_proof(**_arguments(material, receipt_raws, active_policy, allocation_raw, decision_time, row["created"]))
        proof_raw = _raw(_recorded_proof(proof, attempt_raw))
        retained.mkdir(mode=0o700, exist_ok=True)
        native_io._private(retained, directory=True)
        native_io._save_once(retained / "verification-profile.json", policy_raw)
        native_io._save_once(retained / "allocation-receipt.json", allocation_raw)
        native_io._save_once(attempt_path, attempt_raw)
        for name, raw in zip(RECEIPT_NAMES, receipt_raws):
            native_io._save_once(retained / name, raw)
        native_io._save_once(retained / "verification.json", proof_raw)
        # File evidence is durable before a SQLite state can refer to it.
        connection.execute("BEGIN IMMEDIATE")
        current = _one(connection, "SELECT * FROM runs WHERE id=?", (run_id,))
        _row_binding(current, material, root)
        _require(current["created"] == row["created"], "Project run creation time changed before commit.")
        _same_material(material)
        _require(all(native_io._read(native_io._private(operator / name)) == raw
                     for name, raw in zip(RECEIPT_NAMES, receipt_raws))
                 and native_io._read(native_io._private(operator / "verification-profile.json"), 16_384) == policy_raw
                 and native_io._read(native_io._private(operator / "allocation-receipt.json"), 16_384) == allocation_raw,
                 "Private operator inputs changed before project commit.")
        _require(all(native_io._read(retained / name) == raw for name, raw in zip(RECEIPT_NAMES, receipt_raws))
                 and native_io._read(retained / "verification-profile.json", 16_384) == policy_raw
                 and native_io._read(retained / "allocation-receipt.json", 16_384) == allocation_raw
                 and native_io._read(attempt_path) == attempt_raw
                 and native_io._read(retained / "verification.json") == proof_raw,
                 "Retained project receipts changed before commit.")
        connection.execute(_TABLE_DDL)
        concurrent = _stored(connection, run_id)
        if concurrent:
            _require(current["state"] in {"VERIFIED", "ACCEPTED"}
                     and concurrent["proof_json"] == proof_raw.decode()
                     and concurrent["proof_sha256"] == _sha(proof_raw)
                     and concurrent["source_hash"] == current["source_hash"]
                     and concurrent["artifact_sha256"] == _sha(material["package"]),
                     "A different project decision was committed concurrently.")
            return {"id": run_id, "state": current["state"], "idempotent": True, "proof_sha256": _sha(proof_raw)}
        _require(current["state"] == "QA_REQUIRED", "Project state changed before technical commit.")
        _selection(connection, current, material["objects"]["source_snapshot"])
        connection.execute("INSERT INTO technical_verifications VALUES(?,?,?,?,?,?)",
            (run_id, current["source_hash"], _sha(material["package"]), _sha(proof_raw), proof_raw.decode(), decision_time.timestamp()))
        changed = connection.execute("UPDATE runs SET state='VERIFIED',message=?,updated=? WHERE id=? AND state='QA_REQUIRED'",
            ("Complete project package passed clean import and every form's runtime checks. Human review is still required.", current_time.timestamp(), run_id))
        _require(changed.rowcount == 1, "Project state changed during technical commit.")
        connection.execute("INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)",
            ("developer-operator", "project_technical_verified", run_id, current_time.timestamp()))
    return {"id": run_id, "state": "VERIFIED", "idempotent": False, "proof_sha256": _sha(proof_raw)}


def promote_project_run(*, root: Path, run_id: str, operator_receipt_dir: Path,
                        policy: BoundVerificationPolicy, now: datetime | None = None):
    """Private-operator-only QA_REQUIRED -> VERIFIED; never ACCEPTED.

    Same inputs retry idempotently. Uncertain APEX/browser work is not replayed:
    this function only verifies supplied existing exact-byte local receipts.
    """
    try:
        return _promote(root=root, run_id=run_id, operator_receipt_dir=operator_receipt_dir, policy=policy, now=now)
    except ProjectVerificationError:
        raise
    except (native_io.VerificationError, VerificationPolicyError, OpafError, OSError, sqlite3.Error,
            ValueError, KeyError, TypeError, AttributeError, RecursionError):
        raise ProjectVerificationError("Project promotion is blocked; existing evidence and state are preserved.") from None


def verify_existing_project_run(*, root: Path, run_id: str):
    """Read-only retained-proof recheck without current policy or source writes."""
    try:
        root = native_io._safe_path(Path(root))
        database = native_io._safe_path(root / "fox.sqlite3")
        with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=30) as connection:
            row = _one(connection, "SELECT * FROM runs WHERE id=?", (_run_id(run_id),))
            _require(row is not None, "Project run was not found.")
            checked_project_release(connection, root, row)
            proof = _stored(connection, run_id)
            return {"id": run_id, "state": row["state"], "idempotent": True, "read_only": True,
                    "proof_sha256": proof["proof_sha256"], "active_policy_applied": False}
    except ProjectVerificationError:
        raise
    except (native_io.VerificationError, OSError, sqlite3.Error, ValueError, KeyError, TypeError):
        raise ProjectVerificationError("Historical project proof is unavailable or malformed.") from None
