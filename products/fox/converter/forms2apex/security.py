from __future__ import annotations

from pathlib import Path, PurePosixPath
import re


JOB_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{2,47}$")
ALIAS_RE = re.compile(r"^F2A_[A-Z0-9_]{3,48}$")
ALLOWED_DRAFT_SUFFIXES = {".apx", ".json", ".sql", ".js", ".css", ".txt"}

SECRET_PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.I),
    "password_assignment": re.compile(
        r"\b[A-Za-z0-9_]*(?:password|passwd|pwd)[A-Za-z0-9_]*\b"
        r"[^\r\n;]{0,120}(?::=|=)\s*[^\s<>{}]{4,}",
        re.I,
    ),
    "bearer_token": re.compile(r"\bbearer\s+[A-Za-z0-9._~+/-]{16,}", re.I),
    "cloud_secret": re.compile(
        r"\b(?:api[_-]?key|client[_-]?secret|auth[_-]?token|secret[_-]?key)"
        r"\s*[:=]\s*[^\s<>{}]{8,}",
        re.I,
    ),
    "oracle_connect": re.compile(r"\b(?:jdbc:oracle:|connect\s+\S+/\S+@)", re.I),
}

UNSAFE_GENERATED_PATTERNS = {
    "database_link": re.compile(r"\bCREATE\s+(?:SHARED\s+)?DATABASE\s+LINK\b", re.I),
    "external_network_call": re.compile(r"\b(?:UTL_HTTP|HTTPURITYPE|DBMS_CLOUD|UTL_TCP|UTL_SMTP)\b", re.I),
    "scheduler_job": re.compile(r"\bDBMS_SCHEDULER\b", re.I),
    "system_or_identity_change": re.compile(
        r"\b(?:ALTER\s+SYSTEM|CREATE\s+USER|ALTER\s+USER|DROP\s+USER|GRANT\s+|REVOKE\s+)", re.I
    ),
    "host_or_file_access": re.compile(r"\b(?:HOST\s*\(|UTL_FILE|CREATE\s+DIRECTORY|BFILE\s*\()", re.I),
}


def validate_job_id(job_id: str) -> str:
    if not JOB_ID_RE.fullmatch(job_id):
        raise ValueError("job_id must be 3-48 characters using letters, digits, underscore, or hyphen")
    return job_id


def job_path(jobs_root: Path, job_id: str) -> Path:
    validate_job_id(job_id)
    root = jobs_root.resolve()
    candidate = (root / job_id).resolve()
    if candidate.parent != root:
        raise ValueError("job path escaped the configured jobs root")
    return candidate


def safe_relative_path(value: str) -> PurePosixPath:
    if "\\" in value:
        raise ValueError(f"draft path must use forward slashes: {value}")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or ".." in path.parts or "." in path.parts:
        raise ValueError(f"unsafe draft path: {value}")
    if any(part.startswith("~") for part in path.parts):
        raise ValueError(f"unsafe draft path: {value}")
    if path.suffix.lower() not in ALLOWED_DRAFT_SUFFIXES:
        raise ValueError(f"unsupported draft file type: {value}")
    return path


def assert_no_secrets(text: str, source: str) -> None:
    for label, pattern in SECRET_PATTERNS.items():
        if pattern.search(text):
            raise ValueError(f"blocked likely secret ({label}) in {source}")


def assert_safe_generated_content(text: str, source: str) -> None:
    assert_no_secrets(text, source)
    for label, pattern in UNSAFE_GENERATED_PATTERNS.items():
        if pattern.search(text):
            raise ValueError(f"blocked unsafe generated construct ({label}) in {source}")
    if source.lower().endswith(".sql") and re.search(r"\b(?:INSERT|UPDATE|DELETE|MERGE)\b", text, re.I):
        if "-- F2A_SYNTHETIC_DATA_ONLY" not in text:
            raise ValueError(f"DML in {source} requires the F2A_SYNTHETIC_DATA_ONLY marker")


def alias_for_job(job_id: str) -> str:
    raw = re.sub(r"[^A-Za-z0-9_]", "_", validate_job_id(job_id)).upper()
    alias = f"F2A_{raw}"[:52]
    if not ALIAS_RE.fullmatch(alias):
        raise ValueError("job_id cannot be converted to a safe APEX alias")
    return alias
