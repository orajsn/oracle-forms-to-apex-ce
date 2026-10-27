"""Local synthetic fixture checks; no Oracle, browser, network, model or DB."""
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath

import pytest


HELPER_PATH = Path(__file__).resolve().parents[1] / "prepare-fox-journey.py"
spec = importlib.util.spec_from_file_location("fox_journey_fixtures", HELPER_PATH)
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)

from fox.extractor import ExtractionError, verify  # noqa: E402
from fox.intake import checked_source, inventory  # noqa: E402
from fox.native_source import assess_native_source  # noqa: E402
from fox.prepared_source import (  # noqa: E402
    UPLOAD_MANIFEST_NAME,
    encode_upload_manifest,
    verify_upload_manifest,
)


def _snapshot(root):
    return {p.relative_to(root).as_posix(): p.read_bytes()
            for p in root.rglob("*") if p.is_file()}


@pytest.fixture
def prepared(tmp_path):
    output = tmp_path / "fixtures"
    receipt = fixtures.prepare_fixtures(output)
    return output, receipt


def test_receipt_is_exact_portable_public_metadata(prepared):
    output, receipt = prepared
    raw_receipt = (output / "journey-fixtures.json").read_bytes()
    assert json.loads(raw_receipt) == receipt
    assert set(receipt) == {"schema_version", "scope", "table_name", "happy", "blocked"}
    assert type(receipt["schema_version"]) is int and receipt["schema_version"] == 1
    assert receipt["scope"] == "fox-prepared-journey-fixtures-v1"
    assert receipt["table_name"] == "FOX_NATIVE_MINI"
    for case, stem in (("happy", "mini"), ("blocked", "blocked")):
        details = receipt[case]
        assert set(details) == {"job_id", "ready_directory", "readable_source_hash", "manifest_sha256", "files"}
        assert details["job_id"] == f"journey-{case}-v1"
        path = PurePosixPath(details["ready_directory"])
        assert not path.is_absolute() and ".." not in path.parts and "\\" not in str(path)
        assert str(path) == f"{case}/extraction/journey-{case}-v1/ready"
        ready = output / path
        assert {p.name for p in ready.iterdir()} == {f"{stem}.xml", f"{stem}.sql", UPLOAD_MANIFEST_NAME}
        accepted = [checked_source(item["name"], (ready / item["name"]).read_bytes())
                    for item in details["files"]]
        assert {item["name"] for item in details["files"]} == {f"{stem}.xml", f"{stem}.sql"}
        for item in details["files"]:
            assert set(item) == {"name", "sha256", "bytes"}
            raw = (ready / item["name"]).read_bytes()
            assert item["sha256"] == hashlib.sha256(raw).hexdigest()
            assert type(item["bytes"]) is int and item["bytes"] == len(raw)
        public_raw = (ready / UPLOAD_MANIFEST_NAME).read_bytes()
        public = verify_upload_manifest(public_raw, accepted)
        assert details["files"] == public["files"]
        assert details["readable_source_hash"] == public["readable_source_hash"] == inventory(accepted)["source_hash"]
        assert details["manifest_sha256"] == hashlib.sha256(public_raw).hexdigest()
        assert public_raw == encode_upload_manifest(public)
    for private in (str(output).encode(), b"manifest.json", b"input", b"approval", b"approved",
                    b"backend", b"source_manifest_hash", b"<Module", b"CREATE TABLE"):
        assert private not in raw_receipt


@pytest.mark.parametrize("case,stem,state", [("happy", "mini", "READY"), ("blocked", "blocked", "BLOCKED")])
def test_real_extractor_and_native_assessment_preserve_source(prepared, case, stem, state):
    output, receipt = prepared
    frozen = _snapshot(output)
    ready = output / receipt[case]["ready_directory"]
    verification = verify(ready.parent)
    assert verification["status"] == "VERIFIED_REVIEW_REQUIRED"
    assert verification["files"] == 2
    assert verification["approved_for_upload"] is False
    accepted = []
    for name in (f"{stem}.xml", f"{stem}.sql"):
        raw = (ready / name).read_bytes()
        assert raw == (output / case / "input" / name).read_bytes()
        accepted.append(checked_source(name, raw))
    assessment = assess_native_source(accepted)
    assert assessment["state"] == state
    assert assessment["native_form"] == fixtures.EXPECTED_NATIVE_FORM
    if case == "happy":
        assert not assessment["blockers"] and not assessment["unsupported"]
    else:
        assert len(assessment["blockers"]) == len(assessment["unsupported"]) == 1
        assert assessment["blockers"][0]["code"] == "BUSINESS_CODE_REVIEW_REQUIRED"
        assert assessment["blockers"][0]["source"] == "blocked.xml"
        assert assessment["blockers"][0]["evidence"] == "trigger:WHEN-NEW-FORM-INSTANCE"
        assert assessment["unsupported"][0]["status"] == "UNCONVERTED_REVIEW_REQUIRED"
    assert _snapshot(output) == frozen


def test_trigger_is_the_only_source_difference(prepared):
    output, receipt = prepared
    happy = output / receipt["happy"]["ready_directory"]
    blocked = output / receipt["blocked"]["ready_directory"]
    assert (happy / "mini.sql").read_bytes() == (blocked / "blocked.sql").read_bytes()
    happy_xml = (happy / "mini.xml").read_bytes()
    blocked_xml = (blocked / "blocked.xml").read_bytes()
    assert blocked_xml.replace(fixtures.TRIGGER.encode("utf-8"), b"") == happy_xml
    assert receipt["happy"]["readable_source_hash"] != receipt["blocked"]["readable_source_hash"]


def test_exact_synthetic_source_bytes_are_pinned(prepared):
    _, receipt = prepared
    expected = {
        "mini.sql": (132, "8e66edefe2dfd5b6fb3614dfba179b997e4151b962dd9761bd7909abf87adc7e"),
        "mini.xml": (283, "4e9416890275043aac6061330d44c5bef713ea13d3d01e8251679ac941231197"),
        "blocked.sql": (132, "8e66edefe2dfd5b6fb3614dfba179b997e4151b962dd9761bd7909abf87adc7e"),
        "blocked.xml": (359, "a687cff597ce10257d410a34529c32cf8f65a80a00be126fd99a630d414974a0"),
    }
    assert {item["name"]: (item["bytes"], item["sha256"])
            for case in ("happy", "blocked") for item in receipt[case]["files"]} == expected


@pytest.mark.parametrize("kind", ["empty-directory", "file", "populated-directory"])
def test_existing_output_is_never_reused(tmp_path, kind):
    output = tmp_path / "existing"
    if kind == "file":
        output.write_bytes(b"keep this file")
        before = output.read_bytes()
    else:
        output.mkdir()
        if kind == "populated-directory":
            (output / "keep.txt").write_bytes(b"keep this source")
        before = _snapshot(output)
    with pytest.raises(fixtures.FixtureError, match="already exists"):
        fixtures.prepare_fixtures(output)
    assert (output.read_bytes() if output.is_file() else _snapshot(output)) == before


def test_completed_fixture_cannot_be_overwritten(prepared):
    output, _ = prepared
    frozen = _snapshot(output)
    with pytest.raises(fixtures.FixtureError, match="already exists"):
        fixtures.prepare_fixtures(output)
    assert _snapshot(output) == frozen


def test_different_fresh_roots_produce_identical_fixtures(tmp_path):
    first, second = tmp_path / "one", tmp_path / "two"
    assert fixtures.prepare_fixtures(first) == fixtures.prepare_fixtures(second)
    assert _snapshot(first) == _snapshot(second)


@pytest.mark.parametrize("failure", ["verification", "native-state", "blocked-state", "source-mutation"])
def test_failed_preparation_does_not_publish_receipt(tmp_path, monkeypatch, failure):
    output = tmp_path / "failed"
    if failure == "verification":
        monkeypatch.setattr(fixtures, "verify", lambda _: {
            "status": "INVALID", "files": 2, "approved_for_upload": False})
    elif failure in {"native-state", "blocked-state"}:
        original = fixtures.assess_native_source

        def wrong_state(files):
            result = original(files)
            if failure == "native-state":
                result["state"] = "BLOCKED"
            elif any(item["name"] == "blocked.xml" for item in files):
                result["state"] = "READY"
            return result

        monkeypatch.setattr(fixtures, "assess_native_source", wrong_state)
    else:
        original = fixtures.prepare

        def changed_source(source, *args, **kwargs):
            job = original(source, *args, **kwargs)
            (source / "mini.sql").write_bytes(b"changed source")
            return job

        monkeypatch.setattr(fixtures, "prepare", changed_source)
    with pytest.raises(fixtures.FixtureError):
        fixtures.prepare_fixtures(output)
    assert not (output / "journey-fixtures.json").exists()
    assert output.is_dir()  # Failed evidence remains local; no cleanup/deletion.
    if failure == "blocked-state":
        assert verify(output / "happy/extraction/journey-happy-v1")["files"] == 2


def test_corrupt_public_sidecar_never_publishes_receipt(tmp_path, monkeypatch):
    output = tmp_path / "corrupt"
    original = fixtures.prepare

    def corrupt_sidecar(*args, **kwargs):
        job = original(*args, **kwargs)
        (job / "ready" / UPLOAD_MANIFEST_NAME).write_bytes(b'{"invalid":true}')
        return job

    monkeypatch.setattr(fixtures, "prepare", corrupt_sidecar)
    with pytest.raises(ExtractionError, match="manifest changed"):
        fixtures.prepare_fixtures(output)
    assert not (output / "journey-fixtures.json").exists()


def test_cli_returns_receipt_and_safe_repeat_error(tmp_path, capsys):
    output = tmp_path / "cli-fixtures"
    assert fixtures.main(["--output", str(output)]) == 0
    captured = capsys.readouterr()
    assert not captured.err
    assert json.loads(captured.out) == json.loads((output / "journey-fixtures.json").read_bytes())
    frozen = _snapshot(output)
    assert fixtures.main(["--output", str(output)]) == 1
    captured = capsys.readouterr()
    assert not captured.out
    assert "already exists" in captured.err
    assert str(output) not in captured.err
    assert _snapshot(output) == frozen
