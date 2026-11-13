"""Private, create-only runtime handoff. No commands, credentials or listeners.

The host worker is a separately configured trusted executor, not a capability
inferred from a request hash. A claimed or timed-out attempt is never replayed.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile
import time
from typing import Protocol

from . import blueprint_profiles
from .project_reviews import canonical, digest
from .prototype_gateway import PrototypeGateway
from .prototype_release import runtime_binding, validate_runtime_receipt
from .review_receipts import _unique_keys
from .security import validate_job_id


REQUEST = "runtime-request.json"
CLAIM = "runtime-claim.json"
RESULT = "runtime-result.json"
RECEIPT = "runtime-receipt.json"
MAX_JSON = 4_000_000
MAX_ARTIFACT = 5_000_000
MAX_PENDING = 100
MAX_PENDING_ENTRIES = 4096
MAX_PENDING_RESPONSE = 4096
FOX_JOB = re.compile(r"fox-[a-f0-9]{20}\Z")
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_ARTIFACT = re.compile(r"runtime-evidence/[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\.(?:json|png)\Z")
_CONTEXT = {REQUEST, CLAIM, RESULT, RECEIPT, "snapshot.json", "candidate-apexlang.zip",
            "validate.json", "prepare_schema.json", "import.json", "verify_runtime-request.json",
            "verify_runtime-intent.json"}


def need(value, code):
    if not value:
        raise RuntimeError(code)


def code_sha256(path=__file__):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def object_bytes(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_JSON, "PROTOTYPE_BRIDGE_JSON_SIZE_INVALID")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_keys)
    except (ValueError, UnicodeError):
        raise RuntimeError("PROTOTYPE_BRIDGE_JSON_INVALID") from None
    need(type(value) is dict, "PROTOTYPE_BRIDGE_JSON_INVALID")
    return value


class JobIO(Protocol):
    """Trusted namespace adapter. create MUST be atomic, durable, no-overwrite.

    Implementations enforce the configured root and these exact logical names;
    callers cannot supply shell fragments or absolute filesystem paths.
    """
    def read(self, job_id: str, name: str, limit: int) -> bytes: ...
    def exists(self, job_id: str, name: str) -> bool: ...
    def create(self, job_id: str, name: str, raw: bytes) -> None: ...
    def pending(self, *, limit: int = 1) -> list[str]: ...


def checked_path(root, job_id, name):
    validate_job_id(job_id)
    need(name in _CONTEXT or bool(_ARTIFACT.fullmatch(name)), "PROTOTYPE_BRIDGE_PATH_INVALID")
    root = Path(root).absolute()
    path = root / job_id / "prototype-converter" / name
    for parent in (*reversed(path.parents), path):
        need(not parent.is_symlink(), "PROTOTYPE_BRIDGE_LINKED_PATH")
    need(root.is_dir() and (root / job_id / "prototype-converter").is_dir(),
         "PROTOTYPE_BRIDGE_JOB_ROOT_MISSING")
    return path


def create_bytes(path, raw, *, owner=None):
    """Publish complete bytes atomically; retain a winner without replacement."""
    path = Path(path)
    need(type(raw) is bytes, "PROTOTYPE_BRIDGE_BYTES_REQUIRED")
    fd, name = tempfile.mkstemp(prefix=".runtime-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            if owner is not None:
                os.fchown(stream.fileno(), *owner)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
        temporary.unlink()
        if os.name == "posix":
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


class LocalJobIO:
    """Same-namespace implementation; cross-UID deployments inject JobIO."""
    def __init__(self, jobs_root, *, publication_owner=None):
        self.jobs_root = Path(jobs_root).absolute()
        self.publication_owner = publication_owner

    def read(self, job_id, name, limit):
        path = checked_path(self.jobs_root, job_id, name)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        with os.fdopen(os.open(path, flags), "rb") as stream:
            info = os.fstat(stream.fileno())
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= limit,
                 "PROTOTYPE_BRIDGE_FILE_INVALID")
            raw = stream.read(limit + 1)
        need(0 < len(raw) <= limit, "PROTOTYPE_BRIDGE_FILE_INVALID")
        return raw

    def exists(self, job_id, name):
        return checked_path(self.jobs_root, job_id, name).exists()

    def create(self, job_id, name, raw):
        path = checked_path(self.jobs_root, job_id, name)
        if name.startswith("runtime-evidence/"):
            created = False
            try:
                path.parent.mkdir(mode=0o700)
                created = True
            except FileExistsError:
                pass
            need(not path.parent.is_symlink(), "PROTOTYPE_BRIDGE_LINKED_PATH")
            if self.publication_owner is not None:
                if created:
                    os.chown(path.parent, *self.publication_owner, follow_symlinks=False)
                else:
                    info = path.parent.stat()
                    need((info.st_uid, info.st_gid) == self.publication_owner,
                         "PROTOTYPE_BRIDGE_EVIDENCE_OWNER_CHANGED")
        create_bytes(path, raw, owner=self.publication_owner)

    def pending(self, *, limit=1):
        """Bounded direct-child metadata discovery, never execution/recovery.

        All claimed, completed or ambiguous retained results are excluded.
        run_once still exclusively claims and rechecks everything after discovery.
        """
        need(type(limit) is int and 1 <= limit <= MAX_PENDING, "PROTOTYPE_BRIDGE_PENDING_LIMIT_INVALID")
        root = self.jobs_root
        for parent in (*reversed(root.parents), root):
            need(not parent.is_symlink() and not getattr(parent, 'is_junction', lambda: False)(),
                 "PROTOTYPE_BRIDGE_LINKED_PATH")
        need(root.is_dir(), "PROTOTYPE_BRIDGE_JOB_ROOT_MISSING")
        names = []
        with os.scandir(root) as entries:
            for index, entry in enumerate(entries):
                need(index < MAX_PENDING_ENTRIES, "PROTOTYPE_BRIDGE_PENDING_SCAN_LIMIT")
                if FOX_JOB.fullmatch(entry.name) and not entry.is_symlink() and entry.is_dir(follow_symlinks=False):
                    names.append(entry.name)
        jobs = []
        for name in sorted(names):
            job, context = root / name, root / name / 'prototype-converter'
            try:
                # lstat never follows a linked job/context/request. Windows
                # junctions/reparse directories are links too, not job roots.
                directories = [path.lstat() for path in (job, context)]
                if any(not stat.S_ISDIR(info.st_mode) or getattr(info, 'st_file_attributes', 0)
                       & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0) for info in directories):
                    continue
                request = (context / REQUEST).lstat()
                if not (stat.S_ISREG(request.st_mode) and request.st_nlink == 1 and 0 < request.st_size <= MAX_JSON):
                    continue
                retained = False
                for marker in (CLAIM, RESULT, RECEIPT, 'runtime-evidence'):
                    try:
                        (context / marker).lstat()
                        retained = True  # Includes dangling links, not just files.
                        break
                    except FileNotFoundError:
                        pass
                if not retained:
                    jobs.append(name)
                    if len(jobs) == limit:
                        break
            except (FileNotFoundError, NotADirectoryError):
                continue
        return jobs


def validate_context(request, imported, trace, artifact_binding):
    # Reuse the gateway's strict deterministic request/prior-shape validator.
    # This identity callback is NOT authority; both endpoints separately invoke
    # their real current authorizers before publication or any browser write.
    spec, _ = PrototypeGateway(None, authorize=lambda value: value)._request("verify_runtime", request)
    renderer = blueprint_profiles.select(spec)
    need(imported == request["prior_receipts"]["import"], "PROTOTYPE_BRIDGE_IMPORT_CHANGED")
    for stage, value in request["prior_receipts"].items():
        original = {**request, "prior_receipts": {key: request["prior_receipts"][key]
                    for key in ("validate", "prepare_schema", "import")[:("validate", "prepare_schema", "import").index(stage)]}}
        need(value.get("status") == "COMPLETE", "PROTOTYPE_BRIDGE_PRIOR_INCOMPLETE")
        PrototypeGateway._check_receipt(stage, original, value)
    need(trace == renderer.prototype_trace(spec), "PROTOTYPE_BRIDGE_TRACE_CHANGED")
    expected = {"schema_version": 1, "job_id": request["job_id"], "project_id": request["project_id"],
                "source_binding": request["source_binding"], "plan_sha256": request["plan_sha256"],
                "rendering_spec_sha256": digest(spec), "source_authority": request["source_authority"],
                "draft_zip_sha256": request["rendered_zip_sha256"], "template": renderer.context()}
    need(artifact_binding == expected, "PROTOTYPE_BRIDGE_SNAPSHOT_CHANGED")
    return runtime_binding(request, imported, artifact_binding)


def packet_for(request, imported, trace, artifact_binding, *, timeout_seconds=480, issued_at=None, deadline_at=None):
    identity = validate_context(request, imported, trace, artifact_binding)
    issued = datetime.now(timezone.utc)
    issued_at = issued.isoformat() if issued_at is None else issued_at
    deadline_at = (issued + timedelta(seconds=timeout_seconds)).isoformat() if deadline_at is None else deadline_at
    return {"schema_version": 1, "scope": "fox-prototype-runtime-dispatch-v1", "request": request,
            "imported": imported, "trace": trace, "artifact_binding": artifact_binding, "binding": identity,
            "issued_at_utc": issued_at, "deadline_at_utc": deadline_at,
            "target": {"workspace": "FORMS2APEX_POC", "db_name": "ASZ8EQWFM8UNCA2_JSNF2APEX",
                       "ords_origin": "https://asz8eqwfm8unca2-jsnf2apex.adb.us-ashburn-1.oraclecloudapps.com"},
            "producer": {"component": "fox-prototype-runtime-bridge", "code_sha256": code_sha256()}}


def remaining_seconds(packet):
    try:
        values = [packet[key] for key in ("issued_at_utc", "deadline_at_utc")]
        need(all(type(value) is str and len(value) <= 40 for value in values), "PROTOTYPE_BRIDGE_TIME_INVALID")
        issued, deadline = (datetime.fromisoformat(value) for value in values)
        need(all(value.tzinfo is not None and value.utcoffset().total_seconds() == 0 for value in (issued, deadline)),
             "PROTOTYPE_BRIDGE_TIME_INVALID")
        now = datetime.now(timezone.utc)
        need(0 < (deadline - issued).total_seconds() <= 540 and (issued - now).total_seconds() <= 5,
             "PROTOTYPE_BRIDGE_TIME_INVALID")
        remaining = (deadline - now).total_seconds()
    except (KeyError, ValueError, TypeError):
        raise RuntimeError("PROTOTYPE_BRIDGE_TIME_INVALID") from None
    need(remaining > 0, "PROTOTYPE_BRIDGE_EXPIRED_UNKNOWN_NO_REPLAY")
    return remaining


def validate_packet(packet):
    need(type(packet) is dict and set(packet) == {"schema_version", "scope", "request", "imported", "trace",
         "artifact_binding", "binding", "producer", "issued_at_utc", "deadline_at_utc", "target"}, "PROTOTYPE_BRIDGE_PACKET_INVALID")
    remaining_seconds(packet)
    expected = packet_for(packet["request"], packet["imported"], packet["trace"], packet["artifact_binding"],
                          issued_at=packet["issued_at_utc"], deadline_at=packet["deadline_at_utc"])
    need(packet == expected and type(packet["schema_version"]) is int, "PROTOTYPE_BRIDGE_PACKET_CHANGED")
    return packet


def check_retained(io, packet):
    request, job = packet["request"], packet["request"]["job_id"]
    for stage, receipt in request["prior_receipts"].items():
        need(object_bytes(io.read(job, stage + ".json", MAX_JSON)) == receipt,
             "PROTOTYPE_BRIDGE_RETAINED_PRIOR_CHANGED")
    need(object_bytes(io.read(job, "snapshot.json", MAX_JSON)) == packet["artifact_binding"],
         "PROTOTYPE_BRIDGE_RETAINED_SNAPSHOT_CHANGED")
    need(object_bytes(io.read(job, "verify_runtime-request.json", MAX_JSON)) == request
         and object_bytes(io.read(job, "verify_runtime-intent.json", MAX_JSON)) == {"request_sha256": digest(request)},
         "PROTOTYPE_BRIDGE_RETAINED_INTENT_CHANGED")
    need(hashlib.sha256(io.read(job, "candidate-apexlang.zip", 64 * 1024 * 1024)).hexdigest()
         == request["rendered_zip_sha256"], "PROTOTYPE_BRIDGE_RETAINED_ARCHIVE_CHANGED")


def check_artifacts(receipt):
    rows = receipt.get("artifacts") if type(receipt) is dict else None
    need(type(rows) is list and 1 <= len(rows) <= 100, "PROTOTYPE_BRIDGE_ARTIFACTS_INVALID")
    names, total = set(), 0
    for row in rows:
        need(type(row) is dict and set(row) == {"path", "bytes", "sha256"}
             and type(row["path"]) is str and bool(_ARTIFACT.fullmatch(row["path"]))
             and row["path"] not in names and type(row["bytes"]) is int and 0 < row["bytes"] <= MAX_ARTIFACT
             and type(row["sha256"]) is str and bool(_SHA.fullmatch(row["sha256"])),
             "PROTOTYPE_BRIDGE_ARTIFACTS_INVALID")
        names.add(row["path"])
        total += row["bytes"]
    need(total <= 20_000_000, "PROTOTYPE_BRIDGE_ARTIFACTS_TOO_LARGE")
    return rows


class PrototypeRuntimeBridge:
    def __init__(self, jobs_root, *, expected_worker_sha256, timeout_seconds=480, poll_seconds=0.25):
        need(type(expected_worker_sha256) is str and bool(_SHA.fullmatch(expected_worker_sha256)),
             "PROTOTYPE_BRIDGE_WORKER_IDENTITY_REQUIRED")
        need(type(timeout_seconds) in (int, float) and math.isfinite(timeout_seconds) and 0 < timeout_seconds <= 540
             and type(poll_seconds) in (int, float) and math.isfinite(poll_seconds) and 0 < poll_seconds <= 5,
             "PROTOTYPE_BRIDGE_DEADLINE_INVALID")
        self.io = LocalJobIO(jobs_root)
        self.expected_worker_sha256 = expected_worker_sha256
        self.timeout_seconds, self.poll_seconds = timeout_seconds, poll_seconds

    def __call__(self, request, *, root, imported, trace, artifact_binding, freshness_check):
        deadline = time.monotonic() + self.timeout_seconds
        packet = deepcopy(packet_for(request, imported, trace, artifact_binding, timeout_seconds=self.timeout_seconds))
        job = request["job_id"]
        expected_root = self.io.jobs_root / job / "prototype-converter"
        need(Path(root).absolute() == expected_root, "PROTOTYPE_BRIDGE_EXACT_JOB_REQUIRED")
        freshness_check()
        check_retained(self.io, packet)
        def remaining():
            utc_remaining = remaining_seconds(packet)
            monotonic_remaining = deadline - time.monotonic()
            need(monotonic_remaining > 0, "PROTOTYPE_BRIDGE_TIMEOUT_UNKNOWN_NO_REPLAY")
            return min(utc_remaining, monotonic_remaining)
        # Identical redispatch is forbidden too, even following a timeout/crash.
        raw = canonical(packet)
        need(len(raw) <= MAX_JSON, "PROTOTYPE_BRIDGE_JSON_SIZE_INVALID")
        remaining()  # A slow prepublication check never renews this attempt.
        self.io.create(job, REQUEST, raw)
        while True:
            remaining()
            check_retained(self.io, packet)
            if self.io.exists(job, RESULT):
                # Empty polls neither execute work nor release result data.
                # Current authority is mandatory before reading a result and
                # again before returning it; worker execution gates are separate.
                freshness_check()
                remaining()
                check_retained(self.io, packet)
                result = object_bytes(self.io.read(job, RESULT, MAX_JSON))
                expected = {"schema_version": 1, "scope": "fox-prototype-runtime-result-v1",
                            "dispatch_sha256": digest(packet), "binding": packet["binding"],
                            "worker_sha256": self.expected_worker_sha256, "receipt_sha256": result.get("receipt_sha256")}
                need(result == expected and type(result.get("schema_version")) is int,
                     "PROTOTYPE_BRIDGE_RESULT_BINDING_CHANGED")
                receipt = object_bytes(self.io.read(job, RECEIPT, MAX_JSON))
                need(digest(receipt) == result["receipt_sha256"], "PROTOTYPE_BRIDGE_RESULT_RECEIPT_CHANGED")
                check_artifacts(receipt)
                validate_runtime_receipt(expected_root, request, imported, artifact_binding, receipt)
                freshness_check()
                remaining()
                return receipt
            time.sleep(min(self.poll_seconds, remaining()))
