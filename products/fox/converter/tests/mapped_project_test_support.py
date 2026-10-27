"""Synthetic registered profile INPUT for offline mapped-project integration.

Only test-scoped registry data is injected. All target, source, review, package,
and schema validators remain real. This is not live Oracle or OPAF evidence.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path


def register_mapped_test_profile(tmp_path, monkeypatch):
    from forms2apex import target_profile
    import test_project_workflow

    root = Path(__file__).resolve().parents[2]
    profile = json.loads((root / "deployment/project-opaf-target-profile-v2.candidate.json").read_bytes())
    profile["active"] = True
    profile["profile_id"] = "synthetic-offline-project-v2-fixture"
    profile["opaf"]["roles"]["mapper"]["workflow_id"] = "D" * 32
    profile["opaf"]["roles"]["reviewer"]["workflow_id"] = "E" * 32
    raw = json.dumps(profile, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    digest = hashlib.sha256(raw).hexdigest()
    registered = {**target_profile._KNOWN_HISTORICAL_PROFILES, digest: deepcopy(profile)}
    monkeypatch.setattr(target_profile, "_KNOWN_HISTORICAL_PROFILES", registered)
    monkeypatch.setattr(target_profile, "_DEPLOYABLE_TARGET_PROFILES", {
        **target_profile._DEPLOYABLE_TARGET_PROFILES, digest: deepcopy(profile)})
    path = tmp_path / "synthetic-offline-project-v2-profile.json"
    path.write_bytes(raw)
    monkeypatch.setattr(test_project_workflow, "PROFILE_PATH", path)
    assert target_profile.load_target_profile(path) == profile
    assert target_profile.validate_historical_target_profile(profile) == profile
    return path, profile
