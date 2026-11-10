"""Real persistent export storage; SQLcl/browser replies are authored fixtures.

No live SQLcl, model, Oracle or runtime acceptance is claimed. The readonly
parent permission assertion is POSIX-only; path selection is guarded everywhere.
"""
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from forms2apex import prototype_release as release
from forms2apex.project_reviews import read_object
from forms2apex.prototype_runtime_bridge import LocalJobIO
from forms2apex.security import validate_job_id
from qa.operator import snapshot
from test_prototype_gateway import case, advance
from test_prototype_release import imported_case


def hashes(root):
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob("*") if p.is_file()}


@pytest.fixture
def export_case(imported_case, monkeypatch):
    case = imported_case
    advance(case, "verify_runtime")
    jobs = case.settings.jobs_root
    parent = jobs.parent
    original_mode = stat.S_IMODE(parent.stat().st_mode)
    jobs.chmod(0o700)
    parent.chmod(0o555)
    real_mkdtemp = release.tempfile.mkdtemp
    created = []
    case.export_before = hashes(case.root)
    case.export_candidate = (case.root / "candidate-apexlang.zip").read_bytes()
    case.export_request = deepcopy(case.request)
    case.export_created = created

    def mkdtemp(*args, **kwargs):
        # This guard is portable; actual creation and persistence are not mocked.
        assert not args and kwargs == {"prefix": ".px-", "dir": Path(jobs)}
        path = Path(real_mkdtemp(**kwargs))
        assert path.parent == jobs and path.name.startswith(".px-")
        if os.name == "posix":
            assert stat.S_IMODE(path.stat().st_mode) == 0o700
        created.append(path)
        return str(path)

    def forbidden(*args, **kwargs):
        raise AssertionError("Export must not import another application")

    try:
        if os.name == "posix" and os.geteuid() != 0:
            assert not os.access(parent, os.W_OK)
        monkeypatch.setattr(release.tempfile, "mkdtemp", mkdtemp)
        case.adapter.importer = forbidden
        yield case
    finally:
        parent.chmod(original_mode)


def retained(case):
    assert len(case.export_created) == 1
    attempt = case.export_created[0]
    assert attempt.is_dir()  # No TemporaryDirectory/finally cleanup, even on failure.
    record = read_object(case.root / "export-attempt.json")
    assert Path(record["directory"]) == attempt
    assert record["binding"] == release.runtime_binding(case.export_request,
        case.export_request["prior_receipts"]["import"], read_object(case.root / "snapshot.json"))
    after = hashes(case.root)
    assert all(after[name] == value for name, value in case.export_before.items())
    assert (case.root / "candidate-apexlang.zip").read_bytes() == case.export_candidate
    assert case.request == case.export_request
    assert sorted(p.name for p in case.settings.jobs_root.parent.iterdir()) == ["jobs"]
    assert (case.root / "export-intent.json").is_file()
    with pytest.raises(ValueError):
        validate_job_id(attempt.name)
    assert LocalJobIO(case.settings.jobs_root).pending() == []
    # The real backup member/inventory contract accepts and includes dot scratch.
    roles = {"converter-jobs": case.settings.jobs_root}
    inventory = snapshot._inventory(roles)
    snapshot._validate_inventory(inventory, roles)
    prefix = "converter-jobs/" + attempt.name
    assert inventory[prefix]["kind"] == "directory"
    assert any(name.startswith(prefix + "/") and row["kind"] == "file" for name, row in inventory.items())
    return attempt


def no_replay(case):
    before = hashes(case.settings.jobs_root)
    assert not (case.root / "export.json").exists()
    assert not (case.root / "prototype-package.zip").exists()
    assert case.adapter.recover_stage("export", case.export_request) is None
    with pytest.raises(RuntimeError, match="ALREADY_ATTEMPTED"):
        case.adapter.run_stage("export", case.export_request)
    assert len(case.export_created) == 1 and hashes(case.settings.jobs_root) == before


def test_private_persistent_export_preserves_exact_package_and_snapshot_members(export_case, record_property):
    case = export_case
    result = case.adapter.run_stage("export", case.export_request)
    attempt = retained(case)
    raw = Path(result["package_path"]).read_bytes()
    imported = case.export_request["prior_receipts"]["import"]
    runtime = case.export_request["prior_receipts"]["verify_runtime"]["runtime_receipt"]
    checked = release.validate_prototype_package(raw, request=case.export_request,
        runtime_receipt=runtime, imported=imported, artifact_binding=read_object(case.root / "snapshot.json"))
    sql = attempt / f"f{imported['application_id']}.sql"
    app = attempt / imported["application_alias"].lower()
    assert checked["members"]["sql/" + sql.name] == sql.read_bytes()
    assert all(checked["members"]["apexlang/" + name] == (app / name).read_bytes() for name in hashes(app))
    assert hashlib.sha256(raw).hexdigest() == result["package_sha256"]
    assert hashlib.sha256(sql.read_bytes()).hexdigest() == result["native_sql_sha256"]
    assert result["application_id"] == imported["application_id"]
    assert result["application_alias"] == imported["application_alias"]
    assert result["business_behavior_accepted"] is result["package_reimport_passed"] is result["clean_schema_install_passed"] is False
    assert (attempt / "export.log").is_file() and (attempt / "validation.log").is_file()
    assert case.adapter.recover_stage("export", case.export_request) == result
    longest = max(len(str(path.absolute())) for path in attempt.rglob("*") if path.is_file())
    record_property("longest_actual_fixture_export_path", longest)
    if os.name == "nt":
        assert longest < 260  # Actual full renderer/export fixture, not all possible SQLcl themes.


def test_failed_export_validation_retains_attempt_sql_and_logs(export_case):
    case = export_case
    def invalid(sql, app, log):
        log.write_text("Synthetic failed export validation", encoding="utf-8")
        return {"passed": False, "return_code": 1, "log": str(log)}
    case.adapter.validator = invalid
    with pytest.raises(RuntimeError, match="EXPORT_VALIDATION_FAILED"):
        case.adapter.run_stage("export", case.export_request)
    attempt = retained(case)
    assert (attempt / "export.log").is_file() and (attempt / "validation.log").is_file()
    assert (attempt / "f12345.sql").is_file()
    no_replay(case)


def test_unconfirmed_export_identity_retains_actual_output_without_publication(export_case):
    case = export_case
    original = case.adapter.runner
    def wrong_identity(sql, args, commands, directory, **kwargs):
        result = original(sql, args, commands, directory, **kwargs)
        if any("apex export" in command for command in commands):
            return SimpleNamespace(returncode=0, stdout="FOX_PROTO_EXPORT_BEFORE=0\nFOX_PROTO_EXPORT_AFTER=1\n", stderr="")
        return result
    case.adapter.runner = wrong_identity
    with pytest.raises(RuntimeError, match="EXPORT_IDENTITY_UNCONFIRMED"):
        case.adapter.run_stage("export", case.export_request)
    attempt = retained(case)
    assert "FOX_PROTO_EXPORT_BEFORE=0" in (attempt / "export.log").read_text()
    assert not (attempt / "validation.log").exists()
    no_replay(case)


def test_unknown_export_keeps_partial_output_and_original_claim(export_case):
    case = export_case
    original = case.adapter.runner
    def unknown(sql, args, commands, directory, **kwargs):
        if any("apex export" in command for command in commands):
            (directory / "partial-export.txt").write_bytes(b"Synthetic retained partial export")
            raise TimeoutError("Synthetic unknown export outcome")
        return original(sql, args, commands, directory, **kwargs)
    case.adapter.runner = unknown
    with pytest.raises(TimeoutError):
        case.adapter.run_stage("export", case.export_request)
    attempt = retained(case)
    assert (attempt / "partial-export.txt").read_bytes() == b"Synthetic retained partial export"
    assert not (attempt / "export.log").exists()  # No fabricated terminal output.
    no_replay(case)


@pytest.mark.parametrize("mutate", ["sql", "apexlang"])
def test_export_byte_mutation_still_fails_closed_with_persistent_evidence(export_case, mutate):
    case = export_case
    def corrupt(sql, app, log):
        path = app.parent / "f12345.sql" if mutate == "sql" else app / "application.apx"
        path.write_bytes(b"Synthetic changed exported bytes")
        log.write_text("Synthetic validator response", encoding="utf-8")
        return {"passed": True, "return_code": 0}
    case.adapter.validator = corrupt
    with pytest.raises(RuntimeError, match="EXPORT_BYTES_CHANGED"):
        case.adapter.run_stage("export", case.export_request)
    retained(case)
    no_replay(case)
