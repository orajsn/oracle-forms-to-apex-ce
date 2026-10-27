"""Recompute project source authority inside the installed converter.

The pure contract is mirrored byte-for-byte at build time. No development-tree
path is imported, and client rendering specs/readiness flags are not authority.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re

from fox_source_contract import intake as contract_intake
from fox_source_contract import project_conversion as contract

from .native_project import validate_project_spec


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _source_records(files):
    _require(type(files) is list and len(files) <= contract.MAX_SOURCE_FILES,
             "A complete bounded project source set is required")
    result = []
    for value in files:
        _require(type(value) is dict and set(value) in (
            {"name", "text", "sha256"}, {"name", "text", "sha256", "bytes"}),
            "Project source fields are invalid")
        _require(type(value["name"]) is str and type(value["text"]) is str
                 and type(value["sha256"]) is str
                 and re.fullmatch(r"[a-f0-9]{64}", value["sha256"]),
                 "Project source metadata is invalid")
        try:
            raw = value["text"].encode("utf-8")
        except UnicodeError:
            raise ValueError("Project sources must be valid UTF-8") from None
        # FOX's checked source records keep the original byte hash but may
        # remove one UTF-8 BOM from the decoded text. Reconstruct only the exact
        # digest-proven bytes; never normalize line endings or guess encoding.
        if hashlib.sha256(raw).hexdigest() != value["sha256"]:
            raw = b"\xef\xbb\xbf" + raw
        _require(hashlib.sha256(raw).hexdigest() == value["sha256"],
                 "Project source bytes changed")
        if "bytes" in value:
            _require(type(value["bytes"]) is int and value["bytes"] == len(raw),
                     "Project source byte count changed")
        result.append(contract_intake.checked_source(value["name"], raw))
    return result


def validate_project_sources(project, files, *, project_id, plan_sha256):
    """Return the complete authoritative READY plan, or stop before effects."""
    expected = Path(__file__).resolve().parents[1] / "fox_source_contract"
    _require(Path(contract.__file__).resolve() == expected / "project_conversion.py"
             and Path(contract_intake.__file__).resolve() == expected / "intake.py",
             "The installed project source contract is unavailable")
    _require(type(plan_sha256) is str and re.fullmatch(r"[a-f0-9]{64}", plan_sha256),
             "An exact project plan hash is required")
    checked = validate_project_spec(project)
    _require(checked["schema_version"] == 1 or checked["project_id"] == project_id,
             "The project storage mapping belongs to a different project")
    sources = _source_records(files)
    plan = contract.assess_project_conversion(sources, project_id=project_id,
        project_name=checked["project_name"], source_hash=checked["source_manifest_sha256"])
    _require(plan["state"] == "READY" and plan["can_generate"] is True
             and plan["assessment_complete"] is True,
             "The complete project has blocking findings; no forms may be silently omitted")
    _require(plan["plan_sha256"] == plan_sha256,
             "The project plan changed; reassess the complete source version")
    _require(plan["rendering_spec"] == checked,
             "The project specification differs from its supplied sources")
    return plan


# One hash domain shared with FOX; callers must first recompute the source plan.
module_execution_binding = contract.module_execution_binding
