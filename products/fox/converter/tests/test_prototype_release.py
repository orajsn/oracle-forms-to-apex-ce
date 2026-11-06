"""Modelled browser/SQLcl transports; no live runtime or export claim."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from forms2apex import native_blueprint, prototype_release as release
from forms2apex.project_reviews import canonical, digest, read_object
from forms2apex.security import alias_for_job
from forms2apex.target_profile import load_target_profile
from test_prototype_gateway import case, advance


def browser_receipt(request, *, root, imported, trace, artifact_binding, freshness_check):
    freshness_check()
    now = datetime.now(timezone.utc).isoformat()
    result = {**release.runtime_binding(request, imported, artifact_binding), "passed": True,
        "authenticated": True, "business_pages_tested": True, "business_behavior_accepted": False,
        "started_at_utc": now, "completed_at_utc": now,
        "data_retention": "synthetic_test_rows_retained",
        "retained_rows": [{"source_block_id": block["source_block_id"], "table_name": block["table_name"],
                           "primary_key": str(index + 1), "marker": "FPQ-" + "a" * 12,
                           "created": True, "updated": True, "deleted": False}
                          for index, block in enumerate(request["rendering_spec"]["blocks"]) if block["native_component"] == "form"],
        "runner": {"kind": "authenticated_browser", "tool": "playwright", "code_sha256": "a" * 64,
                   "image_id": "sha256:" + "b" * 64},
        "pages": [{"page_id": row["page_id"], "source_block_id": row["source_block_id"], "passed": True,
                   "authenticated": True, "checks": {name: True for name in row["checks"]}}
                  for row in release.expected_runtime_pages(request["rendering_spec"])]}
    folder = root / "runtime-evidence"
    folder.mkdir()
    raw = canonical(result)
    (folder / "browser-report.json").write_bytes(raw)
    result["artifacts"] = [{"path": "runtime-evidence/browser-report.json", "bytes": len(raw),
                            "sha256": hashlib.sha256(raw).hexdigest()}]
    return result


@pytest.fixture
def imported_case(case):
    files = native_blueprint.render_native_blueprint(case.request["rendering_spec"])
    compiled = digest({name: hashlib.sha256(text.encode()).hexdigest() for name, text in files.items()})
    original = case.adapter.importer
    def imported(*args, **kwargs):
        return {**original(*args, **kwargs), "application_alias": alias_for_job(case.request["job_id"]),
                "workspace": "FORMS2APEX_POC", "compiled_metadata_sha256": compiled}
    case.adapter.importer = imported
    advance(case, "validate")
    advance(case, "prepare_schema")
    advance(case, "import")
    root = case.settings.jobs_root / case.request["job_id"] / "prototype-converter"
    authority = root.parent / "prototype-pipeline"
    authority.mkdir()
    (authority / "sources-manifest.json").write_bytes(canonical({"source_binding": case.request["source_binding"],
        "files": [{"name": "synthetic.xml", "sha256": "a" * 64, "bytes": 20}]}))
    (authority / "native-plan.json").write_bytes(canonical({"plan_sha256": case.request["plan_sha256"],
        "rendering_spec": case.request["rendering_spec"], "coverage": {"source_objects": 9},
        "remediation": [{"reason": "Legacy behavior not converted", "source_object_id": "synthetic"}]}))
    case.adapter.runtime_verifier = browser_receipt
    profile = load_target_profile(Path(__file__).resolve().parents[2] / "deployment/target-profile.jsn.json")
    case.adapter.target_profile_loader = lambda settings: profile
    original_runner = case.adapter.runner
    def run(sql, args, commands, directory, **kwargs):
        if not any("apex export" in line for line in commands):
            return original_runner(sql, args, commands, directory, **kwargs)
        assert args == ["-S", "-L", "-name", "F2A_APEX"]
        assert release.sqlcl._target_guard("FORMS2APEX_POC") in commands
        assert not any("apex import" in line for line in commands)
        app_id = case.request["prior_receipts"]["import"]["application_id"]
        (directory / f"f{app_id}.sql").write_bytes(b"-- controlled SQLcl export bytes, not live import proof\n" * 100)
        app = directory / alias_for_job(case.request["job_id"]).lower()
        for name, text in files.items():
            path = app / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="\n")
        case.calls.append("export")
        return SimpleNamespace(returncode=0, stdout="FOX_PROTO_EXPORT_BEFORE=1\nFOX_PROTO_EXPORT_AFTER=1\n", stderr="")
    case.adapter.runner = run
    case.root = root
    return case


def test_authenticated_new_profile_runtime_and_actual_package_bytes(imported_case):
    case = imported_case
    request = deepcopy(case.request)
    runtime = advance(case, "verify_runtime")
    assert runtime["authenticated"] is runtime["business_pages_tested"] is True
    before = list(case.calls)
    assert case.adapter.recover_stage_for_job(request["job_id"], "verify_runtime") == runtime
    assert before == case.calls
    exported_request = deepcopy(case.request)
    exported = advance(case, "export")
    raw = Path(exported["package_path"]).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == exported["package_sha256"]
    assert exported["native_sql_bytes"] > 1000
    assert exported["package_reimport_passed"] is exported["clean_schema_install_passed"] is False
    checked = release.validate_prototype_package(raw, request=exported_request,
        runtime_receipt=runtime["runtime_receipt"], imported=request["prior_receipts"]["import"],
        artifact_binding=read_object(case.root / "snapshot.json"))
    assert checked["evidence"]["business_behavior_accepted"] is False
    assert exported["source_summary"]["source_count"] == 1
    assert exported["source_summary"]["remediation"]
    assert exported["target_requirements"]["tested_versions"]["apex"]
    assert "sql/f12345.sql" in checked["members"]
    assert sum(name.startswith("apexlang/application.apx") for name in checked["members"]) == 1
    assert case.adapter.recover_stage_for_job(request["job_id"], "export") == exported
    assert case.calls.count("import") == 1
    with pytest.raises(RuntimeError, match="ALREADY_ATTEMPTED"):
        case.adapter.run_stage("export", exported_request)
    assert case.calls.count("import") == 1


@pytest.mark.parametrize("mutation,code", [
    (lambda value: value.update(authenticated=False), "AUTHENTICATED_RUNTIME"),
    (lambda value: value.update(scope="fox-project-qa-result-v1"), "RUNTIME_BINDING"),
    (lambda value: value.update(application_id=999), "RUNTIME_BINDING"),
    (lambda value: value.update(source_binding="c" * 64), "RUNTIME_BINDING"),
    (lambda value: value.update(business_behavior_accepted=True), "AUTHENTICATED_RUNTIME"),
    (lambda value: value["pages"].pop(), "PAGE_COVERAGE"),
    (lambda value: value["pages"][0]["checks"].update(search=False), "PAGE_COVERAGE"),
    (lambda value: value.update(artifacts=[]), "ARTIFACTS_REQUIRED"),
])
def test_unauthenticated_stale_or_incomplete_browser_proof_is_denied(imported_case, mutation, code):
    case = imported_case
    def invalid(*args, **kwargs):
        result = browser_receipt(*args, **kwargs)
        mutation(result)
        return result
    case.adapter.runtime_verifier = invalid
    with pytest.raises(RuntimeError, match=code):
        case.adapter.run_stage("verify_runtime", case.request)
    assert case.adapter.recover_stage_for_job(case.request["job_id"], "verify_runtime") is None
    assert case.calls.count("import") == 1


def test_absent_runtime_executor_is_unavailable_not_a_pass(imported_case):
    case = imported_case
    case.adapter.runtime_verifier = None
    assert not case.adapter.supports("verify_runtime")
    receipt = case.adapter.run_stage("verify_runtime", case.request)
    assert receipt["status"] == "UNAVAILABLE" and "passed" not in receipt
    assert not (case.root / "verify_runtime-intent.json").exists()


def test_runtime_artifact_tamper_blocks_export_and_cached_recovery(imported_case):
    case = imported_case
    advance(case, "verify_runtime")
    (case.root / "runtime-evidence/browser-report.json").write_bytes(b"changed")
    with pytest.raises(RuntimeError, match="ARTIFACT_CHANGED"):
        case.adapter.run_stage("export", case.request)
    with pytest.raises(RuntimeError, match="ARTIFACT_CHANGED"):
        case.adapter.recover_stage_for_job(case.request["job_id"], "verify_runtime")
    assert "export" not in case.calls


def test_export_validation_failure_cannot_publish_or_replay(imported_case):
    case = imported_case
    advance(case, "verify_runtime")
    case.adapter.validator = lambda *args: {"passed": False, "return_code": 1}
    with pytest.raises(RuntimeError, match="EXPORT_VALIDATION_FAILED"):
        case.adapter.run_stage("export", case.request)
    assert not (case.root / "prototype-package.zip").exists()
    assert case.adapter.recover_stage_for_job(case.request["job_id"], "export") is None
    with pytest.raises(RuntimeError, match="ALREADY_ATTEMPTED"):
        case.adapter.run_stage("export", case.request)
    assert case.calls.count("import") == 1


def test_export_wrong_live_compiled_metadata_fails_closed(imported_case):
    case = imported_case
    advance(case, "verify_runtime")
    original = case.adapter.runner
    def changed(*args, **kwargs):
        result = original(*args, **kwargs)
        if any("apex export" in command for command in args[2]):
            directory = args[3]
            (directory / alias_for_job(case.request["job_id"]).lower() / "application.apx").write_text("changed")
        return result
    case.adapter.runner = changed
    with pytest.raises(RuntimeError, match="IMPORTED_METADATA_MISMATCH"):
        case.adapter.run_stage("export", case.request)
    assert not (case.root / "prototype-package.zip").exists()


def test_package_tamper_and_rehashed_wrong_source_binding_are_rejected(imported_case):
    case = imported_case
    advance(case, "verify_runtime")
    request = deepcopy(case.request)
    exported = advance(case, "export")
    path = Path(exported["package_path"])
    members = release._package_members(path.read_bytes())
    members["native-blueprint-spec.json"] = b"{}"
    raw = release._package_zip(members)
    with pytest.raises(RuntimeError, match="MANIFEST_MISMATCH"):
        release.validate_prototype_package(raw, request=request,
            runtime_receipt=request["prior_receipts"]["verify_runtime"]["runtime_receipt"],
            imported=request["prior_receipts"]["import"], artifact_binding=read_object(case.root / "snapshot.json"))
    path.write_bytes(raw)
    with pytest.raises(RuntimeError, match="PACKAGE_CHANGED"):
        case.adapter.recover_stage_for_job(case.request["job_id"], "export")


def test_rehashed_package_cannot_change_sql_source_or_claims(imported_case):
    case = imported_case
    advance(case, "verify_runtime")
    request = deepcopy(case.request)
    exported = advance(case, "export")
    original = Path(exported["package_path"]).read_bytes()
    def checked(members):
        manifest = json.loads(members["manifest.json"])
        manifest["files"] = {name: hashlib.sha256(raw).hexdigest() for name, raw in members.items() if name != "manifest.json"}
        members["manifest.json"] = canonical(manifest)
        return release.validate_prototype_package(release._package_zip(members), request=request,
            runtime_receipt=request["prior_receipts"]["verify_runtime"]["runtime_receipt"],
            imported=request["prior_receipts"]["import"], artifact_binding=read_object(case.root / "snapshot.json"))
    members = release._package_members(original)
    members["native-blueprint-spec.json"] = b"{}"
    with pytest.raises(RuntimeError, match="EVIDENCE_MISMATCH"):
        checked(members)
    members = release._package_members(original)
    members["sql/f12345.sql"] = b"tampered SQL"
    with pytest.raises(RuntimeError, match="UNPROVEN_CLAIM"):
        checked(members)
    members = release._package_members(original)
    members["sql/unexpected.sql"] = b"extra SQL must not ship"
    with pytest.raises(RuntimeError, match="EXTRA_MEMBERS"):
        checked(members)


def test_default_export_and_validation_helpers_use_saved_sqlcl_transport(imported_case, monkeypatch):
    case = imported_case
    advance(case, "verify_runtime")
    original = case.adapter.runner
    calls = []
    def transport(sql, args, commands, directory, **kwargs):
        calls.append(args)
        if args == ["-S", "/nolog"]:
            return SimpleNamespace(returncode=0, stdout="Validation successful", stderr="")
        return original(sql, args, commands, directory, **kwargs)
    monkeypatch.setattr(release.sqlcl, "_run_script", transport)
    monkeypatch.setattr(release.runtime_preflight, "bound_target_profile", case.adapter.target_profile_loader)
    result = release.export_prototype(case.settings, case.root, case.request,
        imported=case.request["prior_receipts"]["import"], artifact_binding=read_object(case.root / "snapshot.json"),
        runtime_receipt=case.request["prior_receipts"]["verify_runtime"]["runtime_receipt"], freshness_check=lambda: None)
    assert result["exported"] is True
    assert calls == [["-S", "-L", "-name", "F2A_APEX"], ["-S", "/nolog"]]
