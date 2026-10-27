from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import json
import os
import tempfile

from .security import job_path


STATE_FILE = "job-status.json"
ALLOWED_TRANSITIONS = {
    "INTAKE_READY": {"INSPECTED", "FAILED"},
    "INSPECTED": {"DRAFTED", "FAILED"},
    "DRAFTED": {"VALID", "INVALID", "FAILED"},
    "INVALID": {"DRAFTED", "FAILED"},
    "VALID": {"IMPORTED", "DRAFTED", "FAILED"},
    "IMPORTED": set(),
    "FAILED": {"INSPECTED", "DRAFTED"},
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class JobStore:
    def __init__(self, jobs_root: Path):
        self.jobs_root = jobs_root.resolve()
        self.jobs_root.mkdir(parents=True, exist_ok=True)

    def root(self, job_id: str) -> Path:
        return job_path(self.jobs_root, job_id)

    def require(self, job_id: str) -> Path:
        root = self.root(job_id)
        if not root.is_dir():
            raise FileNotFoundError(f"job does not exist: {job_id}")
        return root

    def read(self, job_id: str) -> dict:
        root = self.require(job_id)
        status_path = root / STATE_FILE
        if not status_path.exists():
            return {
                "job_id": job_id,
                "state": "INTAKE_READY",
                "created_at_utc": utc_now(),
                "updated_at_utc": utc_now(),
                "history": [],
            }
        return json.loads(status_path.read_text(encoding="utf-8-sig"))

    def write(self, job_id: str, value: dict) -> dict:
        root = self.require(job_id)
        value = dict(value)
        value["job_id"] = job_id
        value["updated_at_utc"] = utc_now()
        target = root / STATE_FILE
        fd, temp_name = tempfile.mkstemp(prefix=".job-status-", suffix=".json", dir=root)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                json.dump(value, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, target)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
        return value

    def transition(self, job_id: str, new_state: str, details: dict | None = None) -> dict:
        status = self.read(job_id)
        current = status["state"]
        recovery=(details or {}).get('import_recovery',{})
        verified_recovery=(current=='FAILED' and new_state=='IMPORTED' and recovery.get('reconciled') is True
            and recovery.get('target_writes') is False
            and recovery.get('reconciliation_scope')=='exact_identity_and_complete_compiled_metadata'
            and recovery.get('artifact_binding')==status.get('artifact_binding')
            and bool(status.get('artifact_binding')))
        if new_state != current and new_state not in ALLOWED_TRANSITIONS.get(current, set()) and not verified_recovery:
            raise RuntimeError(f"invalid job transition: {current} -> {new_state}")
        event = {"at_utc": utc_now(), "from": current, "to": new_state}
        if details:
            event["details"] = details
            status.update(details)
        status.setdefault("history", []).append(event)
        status["state"] = new_state
        return self.write(job_id, status)

