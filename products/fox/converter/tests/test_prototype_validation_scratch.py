"""Real scratch/extraction checks; validator replies are local boundary fixtures.

No SQLcl, database, model or importer is executed. POSIX non-root runs also
enforce the parent permission; the path-selection guard applies on Windows.
"""
from copy import deepcopy
import hashlib
import io
import os
from pathlib import Path
import stat
import tempfile
import zipfile

import pytest

from forms2apex import native_blueprint as renderer
from forms2apex import prototype_gateway as gateway
from forms2apex.project_reviews import digest, read_object
from forms2apex.provenance import tree_digest
from test_prototype_gateway import case


@pytest.fixture
def scratch_case(case, monkeypatch):
    parent = case.settings.jobs_root.parent
    original_mode = stat.S_IMODE(parent.stat().st_mode)
    case.settings.jobs_root.chmod(0o700)
    parent.chmod(0o555)
    real_temporary = tempfile.TemporaryDirectory
    default_root = Path(tempfile.gettempdir()).resolve()
    created = []
    external_calls = []

    def temporary(*args, **kwargs):
        # Do not mock creation or extraction: require the system-temp boundary,
        # then create a real private directory with the standard-library helper.
        assert not args and kwargs == {"prefix": ".p-"}
        result = real_temporary(**kwargs)
        path = Path(result.name).resolve()
        assert path.parent == default_root
        assert not path.is_relative_to(parent.resolve())
        if os.name == "posix":
            assert stat.S_IMODE(path.stat().st_mode) == 0o700
        created.append(path)
        return result

    def forbidden(*args, **kwargs):
        external_calls.append(True)
        raise AssertionError("Validation must not run SQL, preflight or import")

    try:
        if os.name == "posix" and os.geteuid() != 0:
            assert not os.access(parent, os.W_OK)
            with pytest.raises(PermissionError):
                with real_temporary(dir=parent):
                    pass
        monkeypatch.setattr(gateway.tempfile, "TemporaryDirectory", temporary)
        case.adapter.importer = forbidden
        case.adapter.runner = forbidden
        case.adapter.preflight = forbidden
        yield case, parent, created, external_calls
    finally:
        parent.chmod(original_mode)


def test_system_scratch_preserves_exact_zip_tree_log_and_receipt(scratch_case):
    case, parent, created, external_calls = scratch_case
    request = deepcopy(case.request)
    raw = renderer.deterministic_prototype_zip(request["rendering_spec"])
    root = case.settings.jobs_root / request["job_id"] / "prototype-converter"
    observed = []

    def validate(sql, app, log):
        assert sql == case.settings.sqlcl_path
        assert app == created[0] / "apexlang"
        assert app.is_dir() and (app / "application.apx").is_file()
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            expected = {name: archive.read(name) for name in archive.namelist()}
        assert {p.relative_to(app).as_posix(): p.read_bytes()
                for p in app.rglob("*") if p.is_file()} == expected
        assert (root / "candidate-apexlang.zip").read_bytes() == raw
        assert log == root / "validation.log"
        log.write_text("Synthetic boundary validation only", encoding="utf-8")
        observed.append(tree_digest(app))
        return {"passed": True, "return_code": 0, "log": str(log)}

    case.adapter.validator = validate
    receipt = case.adapter.run_stage("validate", request)
    assert len(created) == len(observed) == 1 and not created[0].exists()
    assert receipt["status"] == "COMPLETE" and receipt["passed"] is True
    assert receipt["draft_sha256"] == observed[0]
    assert receipt["request_sha256"] == digest(request)
    assert receipt["artifact_binding"]["draft_zip_sha256"] == hashlib.sha256(raw).hexdigest()
    assert receipt["artifact_binding"]["draft_zip_sha256"] == request["rendered_zip_sha256"]
    assert read_object(root / "validate.json") == receipt
    assert read_object(root / "snapshot.json") == receipt["artifact_binding"]
    assert (root / "candidate-apexlang.zip").read_bytes() == raw
    assert (root / "validation.log").read_text() == "Synthetic boundary validation only"
    assert receipt["business_behavior_accepted"] is False
    assert case.request == request
    assert sorted(p.name for p in parent.iterdir()) == ["jobs"]
    assert not external_calls


def test_system_scratch_still_rejects_validator_input_mutation(scratch_case):
    case, parent, created, external_calls = scratch_case
    raw = renderer.deterministic_prototype_zip(case.request["rendering_spec"])
    root = case.settings.jobs_root / case.request["job_id"] / "prototype-converter"

    def corrupt(sql, app, log):
        assert app == created[0] / "apexlang"
        (app / "application.apx").write_bytes(b"changed validation input")
        return {"passed": True, "return_code": 0}

    case.adapter.validator = corrupt
    with pytest.raises(RuntimeError, match="PROTOTYPE_VALIDATION_INPUT_CHANGED"):
        case.adapter.run_stage("validate", case.request)
    assert len(created) == 1 and not created[0].exists()
    assert (root / "candidate-apexlang.zip").read_bytes() == raw
    assert (root / "validate-intent.json").is_file()
    assert not (root / "validate.json").exists()
    with pytest.raises(RuntimeError, match="ALREADY_ATTEMPTED"):
        case.adapter.run_stage("validate", case.request)
    assert len(created) == 1
    assert sorted(p.name for p in parent.iterdir()) == ["jobs"]
    assert not external_calls


def test_changed_zip_hash_rejected_before_scratch_or_validator(scratch_case):
    case, parent, created, external_calls = scratch_case
    case.request["rendered_zip_sha256"] = "f" * 64
    with pytest.raises(RuntimeError, match="RENDERED_ZIP"):
        case.adapter.run_stage("validate", case.request)
    assert not created and not case.calls and not external_calls
    assert sorted(p.name for p in parent.iterdir()) == ["jobs"]
