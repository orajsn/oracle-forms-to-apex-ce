"""Local synthetic product-fixture checks, not Oracle or human acceptance.

Only the Windows-specific ownership/fsync shims are patched during promotion;
the production package, verification, SQLite, and worker contracts stay real.
"""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "qa/prepare-product-download-fixture.py"
UI = ROOT / "work/product-ui-build-20261017b"
spec = importlib.util.spec_from_file_location("product_download_fixture", HELPER)
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


def snapshot(directory):
    return {path.relative_to(directory).as_posix(): path.read_bytes()
            for path in directory.rglob("*") if path.is_file()}


def save_manifest(directory, manifest):
    (directory / "manifest.json").write_bytes(fixtures.raw(manifest))


@pytest.fixture(autouse=True)
def isolated_process(monkeypatch, tmp_path):
    """Never inherit live integration configuration or retain synthetic env."""
    for key in tuple(os.environ):
        if key.startswith(("FOX_OPAF", "FOX_CONVERTER", "FOX_NATIVE_PROFILE", "FOX_RUN_ADAPTER")):
            monkeypatch.delenv(key)
    for key in ("FOX_DATA_DIR", "FOX_PUBLIC_ORIGIN", "FOX_ADMIN_USERNAME",
                "FOX_PASSWORD_HASH", "FOX_CONVERSION_PROFILE"):
        monkeypatch.setenv(key, str(tmp_path / "unused-import-data") if key == "FOX_DATA_DIR" else "")

    def forbidden(*args, **kwargs):
        pytest.fail("External network/process activity is forbidden in local fixture tests")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)


@pytest.fixture
def prepared(tmp_path):
    directory = tmp_path / "fixture"
    manifest = fixtures.prepare(directory, UI)
    return directory, manifest


def test_export_has_exact_hashes_and_explicitly_synthetic_identity(prepared):
    directory, manifest = prepared
    loaded, credentials = fixtures.load_fixture(directory)
    assert loaded == manifest
    assert manifest["simulated_fixtures"] is True
    assert manifest["live_acceptance_recorded"] is False
    assert manifest["owner"].startswith("synthetic-product-")
    assert manifest["owner"] != "jason"
    assert credentials["username"] == manifest["owner"]
    assert len(credentials["password"]) >= 40
    assert manifest["origin"] == "http://127.0.0.1:8100"
    assert manifest["notes"] == fixtures.NOTES
    assert set(manifest["files"]) == set(fixtures.INPUTS)
    assert set(snapshot(directory)) == set(fixtures.INPUTS) | {"manifest.json"}
    for name, expected in manifest["files"].items():
        assert hashlib.sha256((directory / name).read_bytes()).hexdigest() == expected
    package = (directory / "apex-package.zip").read_bytes()
    assert len(package) == manifest["package_bytes"]
    assert hashlib.sha256(package).hexdigest() == manifest["package_sha256"]
    from fox.app import check_password
    assert check_password(credentials["password"], credentials["password_hash"])


def test_preparations_use_fresh_synthetic_credentials_and_preserve_source(prepared, tmp_path):
    first, original = prepared
    frozen = snapshot(first)
    second = tmp_path / "another"
    following = fixtures.prepare(second, UI)
    _, first_credentials = fixtures.load_fixture(first)
    _, second_credentials = fixtures.load_fixture(second)
    assert original["owner"] != following["owner"]
    assert original["project_id"] != following["project_id"]
    assert first_credentials["password"] != second_credentials["password"]
    assert original["source_hash"] == following["source_hash"]
    assert original["package_sha256"] == following["package_sha256"]
    assert snapshot(first) == frozen


def test_existing_output_is_never_overwritten(prepared, tmp_path):
    complete, _ = prepared
    empty = tmp_path / "empty"
    empty.mkdir()
    file = tmp_path / "existing-file"
    file.write_bytes(b"retain this unrelated file")
    for output in (complete, empty, file):
        before = output.read_bytes() if output.is_file() else snapshot(output)
        with pytest.raises(ValueError, match="already exists"):
            fixtures.prepare(output, UI)
        assert (output.read_bytes() if output.is_file() else snapshot(output)) == before


@pytest.mark.parametrize("field,value", [("owner", "jason"), ("origin", "http://localhost:8100")])
def test_manifest_cannot_target_real_owner_or_other_origin(prepared, field, value):
    directory, manifest = prepared
    manifest[field] = value
    save_manifest(directory, manifest)
    with pytest.raises(ValueError, match="synthetic owner|release binding"):
        fixtures.load_fixture(directory)


def test_changed_package_bytes_are_rejected(prepared):
    directory, _ = prepared
    package = directory / "apex-package.zip"
    package.write_bytes(package.read_bytes() + b"tampered synthetic package")
    with pytest.raises(ValueError, match="Fixture bytes differ"):
        fixtures.load_fixture(directory)


def test_changed_candidate_ui_is_rejected_before_data_creation(prepared, tmp_path):
    directory, _ = prepared
    changed_ui = tmp_path / "changed-ui"
    shutil.copytree(UI, changed_ui)
    script = next(changed_ui.glob("assets/*.js"))
    script.write_bytes(script.read_bytes() + b"\n/* altered candidate */")
    data = tmp_path / "data"
    with pytest.raises(ValueError, match="Candidate UI bytes differ"):
        fixtures.seed(directory, data, changed_ui)
    assert not data.exists()


def test_seed_uses_real_gate_and_keeps_acceptance_empty(prepared, tmp_path, monkeypatch):
    directory, manifest = prepared
    frozen = snapshot(directory)
    data = tmp_path / "data"
    from fox import native_verification as gate
    if os.name == "nt":
        # Windows tests cover content/transaction behavior, never POSIX provenance.
        monkeypatch.setattr(gate, "_private", lambda path, directory=False: gate._safe_path(path))
        monkeypatch.setattr(gate, "_sync_dir", lambda path: None)
    app = fixtures.seed(directory, data, UI)
    worker = app.state.worker_monitor.snapshot(thread_alive=False)
    assert worker["enabled"] is False
    assert worker["state"] == "disabled"
    assert worker["healthy"] is True
    with sqlite3.connect(data / "fox.sqlite3") as connection:
        assert connection.execute("SELECT owner FROM projects").fetchall() == [(manifest["owner"],)]
        assert connection.execute("SELECT id,state FROM runs").fetchall() == [(manifest["run_id"], "VERIFIED")]
        assert connection.execute("SELECT COUNT(*) FROM sources").fetchone()[0] == 2
        assert connection.execute("SELECT COUNT(*) FROM acceptances").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM events WHERE action='human_accepted'").fetchone()[0] == 0
    checked = gate.verify_existing_native_run(root=data, run_id=manifest["run_id"])
    assert checked["state"] == "VERIFIED"
    assert checked["read_only"] is True
    bootstrap = json.loads((data / "synthetic-bootstrap.json").read_bytes())
    assert bootstrap["worker_enabled"] is False
    assert bootstrap["simulated_fixtures"] is True
    assert bootstrap["live_acceptance_recorded"] is False
    assert bootstrap["proof_sha256"] == checked["proof_sha256"]
    assert (data / "jobs" / manifest["run_id"] / "apex-package.zip").read_bytes() == (directory / "apex-package.zip").read_bytes()
    assert snapshot(directory) == frozen


def test_seed_refuses_existing_data_without_changing_it(prepared, tmp_path):
    directory, _ = prepared
    data = tmp_path / "existing-data"
    data.mkdir()
    (data / "keep.txt").write_bytes(b"unrelated data must stay untouched")
    before = snapshot(data)
    with pytest.raises(ValueError, match="never reuse"):
        fixtures.seed(directory, data, UI)
    assert snapshot(data) == before


def test_runtime_imports_do_not_require_test_only_dependencies():
    tree = ast.parse(HELPER.read_text(encoding="utf-8"))
    runtime = ast.Module(body=[node for node in tree.body
                              if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or node.name != "prepare"],
                         type_ignores=[])
    names = []
    for node in ast.walk(runtime):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.append(node.module or "")
    assert all(not name.startswith(("pytest", "test_")) for name in names)
    assert "uvicorn" in names
