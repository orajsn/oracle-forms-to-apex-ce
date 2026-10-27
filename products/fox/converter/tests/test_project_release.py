"""Project releases use real render/receipt/package components and fake I/O."""
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace
import zipfile

import pytest

from forms2apex import native, native_project, project_release, release, review_receipts, schema_probe
from forms2apex.security import alias_for_job
from forms2apex.target_profile import load_target_profile, target_profile_sha256


JOB = "fox-" + "c" * 20
FIXTURE = Path(__file__).parent / "fixtures/project_v1/two-forms-final"


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(project_release._bytes(value))


@pytest.fixture
def project_job(tmp_path_factory, monkeypatch):
    root = tmp_path_factory.mktemp("pr") / JOB
    root.mkdir()
    project = native_project.validate_project_spec(json.loads((FIXTURE / "native-project-spec.json").read_text()))
    files = []
    for path in sorted((FIXTURE / "sources").iterdir()):
        raw = path.read_bytes()
        (root / "intake").mkdir(exist_ok=True)
        (root / "intake" / path.name).write_bytes(raw)
        files.append({"packaged_name": path.name, "sha256": hashlib.sha256(raw).hexdigest()})
    put(root / "intake/manifest.json", {"job_id": JOB, "source_manifest_sha256": project["source_manifest_sha256"],
        "native_project": project, "files": files})
    profile = load_target_profile(Path(__file__).resolve().parents[2] / "deployment/target-profile.jsn.json")
    roles = profile["opaf"]["roles"]
    identities = tuple(roles[role][field] for field in ("workflow_id", "model") for role in ("mapper", "reviewer"))
    rows = []
    for form in project["forms"]:
        child_id = "fox-" + project_release._sha(project_release._bytes({"scope": "fox-project-module-execution-v1",
            "parent_job_id": JOB, "source_hash": project["source_manifest_sha256"],
            "module_id": form["module_id"], "native_form": form["native_form"]}))[:20]
        child = root / "form-reviews" / child_id
        (child / "intake").mkdir(parents=True)
        for path in (root / "intake").iterdir():
            if path.name != "manifest.json":
                (child / "intake" / path.name).write_bytes(path.read_bytes())
        put(child / "intake/manifest.json", {"job_id": child.name, "source_manifest_sha256": project["source_manifest_sha256"],
            "native_form": form["native_form"], "files": files})
        candidate = {"job_id": child.name, "template_id": native.TEMPLATE_ID,
            "data_classification": "synthetic_or_stub_only", "generator": {"model": roles["mapper"]["model"]},
            "native_form": deepcopy(form["native_form"]), "remediation_items": [], "mapping_summary": "Synthetic component fixture only"}
        # Review receipts hash exact metadata, but approved optional defaults
        # are normalized when comparing to the deterministic project spec.
        candidate["native_form"].pop("supported_operations")
        for column in candidate["native_form"]["columns"]:
            for key in ("primary_key", "identity"):
                if column.get(key) is False:
                    column.pop(key)
        payload = {"job_id": child.name, "source_hash": project["source_manifest_sha256"], "candidate": candidate,
            "review": {"verdict": "approve", "candidate_sha256": review_receipts.candidate_sha256(candidate),
                       "notes": "Independent fixture review", "blocking_findings": []}, "model_environment": {}}
        for i, role in enumerate(("mapper", "reviewer")):
            invocation = {**roles[role], "room_id": role + "-room", "request_sha256": "a" * 64,
                "response_sha256": "b" * 64, "started_at_utc": f"2026-10-24T00:00:0{i * 2}Z",
                "completed_at_utc": f"2026-10-24T00:00:0{i * 2 + 1}Z"}
            payload[role + "_invocation"] = invocation
            payload["model_environment"][role] = {"schema_version": 1, "scope": "opaf-model-environment-v1",
                "trust_boundary": "authenticated_fox_executor_not_vendor_attestation", "job_id": child.name,
                "role": role, "source_manifest_sha256": payload["source_hash"],
                "target_profile_sha256": target_profile_sha256(profile), "observed_at_utc": invocation["started_at_utc"],
                "opaf": {key: profile["opaf"][key] for key in ("base_url", "certificate_sha256", "model_authentication", "version_number", "build_id")},
                "workflow": {**roles[role], "published": True}, "opaf_version": profile["tested_versions"]["opaf"]}
        receipt = review_receipts.record_review(child, payload, *identities, target_profile=profile)
        rows.append({"module_id": form["module_id"], "child_job_id": child.name,
                     "candidate_sha256": receipt["candidate_sha256"], "receipt_sha256": receipt["receipt_sha256"]})
    spec = {"job_id": JOB, "template_id": native_project.TEMPLATE_ID, "data_classification": "synthetic_or_stub_only",
        "generator": {"model": roles["mapper"]["model"]}, "native_project": project,
        "remediation_items": [], "mapping_summary": "One synthetic application; no business equivalence claim"}
    aggregate = {"schema_version": 1, "scope": "fox-native-project-review-v1", "job_id": JOB,
        "trust_boundary": "authenticated_fox_executor_not_vendor_attestation",
        "source_hash": project["source_manifest_sha256"], "candidate": spec,
        "candidate_sha256": project_release._sha(project_release._bytes(spec)), "form_reviews": rows, "verdict": "approve"}
    aggregate["receipt_sha256"] = project_release._sha(project_release._bytes(aggregate))
    put(root / "migration-spec.json", spec)
    put(root / "project-review.json", aggregate)
    put(root / "source-to-apex.json", native_project.project_trace(project))
    binding = {"schema_version": 1, "job_id": JOB, "template_id": native_project.TEMPLATE_ID, "draft_sha256": "d" * 64,
        "reviewed_spec_sha256": release._file_digest(root / "migration-spec.json"),
        "project_review_sha256": release._file_digest(root / "project-review.json"),
        "project_trace_sha256": release._file_digest(root / "source-to-apex.json")}
    alias = alias_for_job(JOB)
    calls, preflights = [], []

    def preflight(job_id, action):
        name = f"target-check-{action}-{len(preflights):016x}.json"
        raw = project_release._bytes({"artifact_binding": binding, "test_boundary": action})
        (root / name).write_bytes(raw)
        ref = {"file": name, "sha256": hashlib.sha256(raw).hexdigest(), "action": action}
        preflights.append(ref)
        return ref

    validation_ref, import_ref = preflight(JOB, "validate"), preflight(JOB, "import")
    exported_hashes = {name: hashlib.sha256(content.encode()).hexdigest()
                       for name, content in native_project.render_native_project(project).items()}
    put(root / "imported-application.json", {"job_id": JOB, "application_id": 123,
        "application_alias": alias, "workspace": "FORMS2APEX_POC", "artifact_binding": binding,
        "compiled_metadata_sha256": hashlib.sha256(json.dumps(exported_hashes, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        "target_preflight": import_ref, "application_url": "https://example.invalid/ords/project/"})
    preparation = {"scope": "fox-native-schema-preparation-v1", "all_ready": True,
        "business_behavior_verified": False, "automatic_replay_permitted": False,
        "binding": {"job_id": JOB, "source_manifest_sha256": project["source_manifest_sha256"],
            "artifact_binding_sha256": project_release._sha(project_release._bytes(binding)),
            "review_receipts_sha256": project_release._sha(project_release._bytes(rows)),
            "validated_draft_sha256": binding["draft_sha256"]},
        "tables": [{"table_name": form["native_form"]["table_name"], "state": "CREATED",
                    "ownership_sha256": "e" * 64, "object_identity": {"object_id": "123"},
                    "bootstrap_schema_sha256": schema_probe.schema_sha256(form["native_form"])} for form in project["forms"]]}
    preparation["record_sha256"] = project_release._sha(project_release._bytes(preparation))
    put(root / "schema-preparation.json", preparation)
    for name in ("normalized-forms-inventory.json", "migration-and-exception-report.json", "validation-results.log"):
        put(root / name, {})
    workflow = SimpleNamespace(store=SimpleNamespace(require=lambda job_id: root),
        settings=SimpleNamespace(apex_workspace="FORMS2APEX_POC", apex_parsing_schema="FORMS2APEX_POC",
            sqlcl_connection_name="F2A_APEX", sqlcl_path=root / "sql"),
        assert_artifact_binding=lambda job_id: deepcopy(binding),
        status=lambda job_id: {"state": "IMPORTED", "validation": {"passed": True, "target_preflight": validation_ref}},
        verify_project_review=lambda path, value: deepcopy(aggregate), native_target_preflight=preflight,
        _schema_ready=lambda job_id: {"state": "READY", "ready_for_import": True, "database_writes": False},
        assert_native_preflight_fresh=lambda job_id, ref, action: calls.append("fresh_" + action))

    def sqlcl(path, args, commands, cwd, **kwargs):
        script = "\n".join(commands)
        if "apex export " in script:
            calls.append("export")
            (cwd / "f123.sql").write_text("-- synthetic export\n" + "x" * 1200)
            for name, content in native_project.render_native_project(project).items():
                target = cwd / alias.lower() / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content.encode())
            output = "FOX_EXPORT_MATCH=1"
        elif "apex validate " in script:
            calls.append("validate_export")
            app = Path(re.search(r'apex validate -input "([^"]+)"', script).group(1))
            assert app.is_dir() and len(list((app / "pages").glob("*.apx"))) == 6
            output = "Validation successful"
        elif "FOX_ALIAS_COUNT=" in script:
            calls.append("allocation")
            output = "FOX_ALIAS_COUNT=0"
        elif "apex_application_install" in script:
            calls.append("reimport")
            assert "FOX create-only application collision" in script
            assert "FOX target identity mismatch" in script
            assert (root / "package-reimport-intent.json").exists()
            output = "FOX_REIMPORT_MATCH=1"
        else:
            pytest.fail("Unexpected SQLcl invocation")
        return subprocess.CompletedProcess(args, 0, output, "")
    monkeypatch.setattr(project_release, "_run_script", sqlcl)
    monkeypatch.setattr("forms2apex.sqlcl._run_script", sqlcl)
    monkeypatch.setattr(release, "runtime_login_check", lambda url: {"passed": True, "scope": "login_page_reachability"})
    return SimpleNamespace(root=root, workflow=workflow, project=project, binding=binding, sqlcl=sqlcl, calls=calls)


def finish(job):
    return project_release.finalize_project_release(job.workflow, JOB)


def forbidden(*args, **kwargs):
    pytest.fail("No external boundary may run")


def test_project_export_is_complete_one_app_and_cached_read_only(project_job, monkeypatch):
    job = project_job
    evidence = finish(job)
    assert evidence["form_count"] == 2 and evidence["application_count"] == 1
    assert evidence["clean_schema_install_passed"] is False
    checked = project_release.validate_project_package((job.root / "apex-package.zip").read_bytes(),
        expected_project=job.project, expected_evidence=evidence)
    assert len(checked["form_reviews"]) == 2
    assert checked["trace"]["human_acceptance_recorded"] is False
    assert [call for call in job.calls if not call.startswith("fresh_")] == ["export", "validate_export", "allocation", "reimport"]
    before = {p.relative_to(job.root): p.read_bytes() for p in job.root.rglob("*") if p.is_file()}
    monkeypatch.setattr(project_release, "_run_script", forbidden)
    monkeypatch.setattr("forms2apex.sqlcl._run_script", forbidden)
    monkeypatch.setattr(release, "runtime_login_check", forbidden)
    assert finish(job) == evidence
    assert before == {p.relative_to(job.root): p.read_bytes() for p in job.root.rglob("*") if p.is_file()}


@pytest.mark.parametrize("change", ["schema", "trace", "missing_review", "missing_page", "extra_sql", "bad_receipt", "partial_preparation", "missing_preflight", "changed_table"])
def test_manifest_rehash_does_not_bless_incomplete_project(project_job, change):
    job = project_job
    finish(job)
    with zipfile.ZipFile(job.root / "apex-package.zip") as archive:
        members = {name: archive.read(name) for name in archive.namelist() if name != "manifest.json"}
    if change == "schema":
        members["schema/01_synthetic_schema.sql"] += b"\n-- changed"
    elif change == "trace":
        value = json.loads(members["source-to-apex.json"])
        value["forms"].pop()
        members["source-to-apex.json"] = project_release._bytes(value)
    elif change == "missing_review":
        del members[next(name for name in members if name.startswith("evidence/form-reviews/"))]
    elif change == "missing_page":
        del members["apexlang/pages/p00004-edit_2.apx"]
    elif change == "extra_sql":
        members["sql/f456.sql"] = b"-- extra application"
    elif change == "bad_receipt":
        name = next(name for name in members if name.startswith("evidence/form-reviews/"))
        value = json.loads(members[name])
        value["candidate"]["native_form"]["columns"][0]["label"] = "Changed"
        members[name] = project_release._bytes(value)
    elif change == "partial_preparation":
        value = json.loads(members["evidence/schema-preparation.json"])
        value["tables"].pop()
        members["evidence/schema-preparation.json"] = project_release._bytes(value)
    elif change == "missing_preflight":
        for name in list(members):
            if name.startswith("evidence/target-check-"):
                del members[name]
    else:
        name = "apexlang/pages/p00001-form_1.apx"
        members[name] = members[name].replace(b"FOX_NATIVE_CUSTOMERS", b"OTHER_TABLE")
        complete = json.loads(members["evidence/export-completion.json"])
        complete["files"][alias_for_job(JOB).lower() + "/pages/p00001-form_1.apx"] = hashlib.sha256(members[name]).hexdigest()
        members["evidence/export-completion.json"] = project_release._bytes(complete)
    members["manifest.json"] = project_release._bytes({name: hashlib.sha256(raw).hexdigest() for name, raw in members.items()})
    target = job.root / "tampered.zip"
    with zipfile.ZipFile(target, "w") as archive:
        for name, raw in members.items():
            archive.writestr(name, raw)
    with pytest.raises(RuntimeError, match="Project package integrity"):
        project_release.validate_project_package(target)


def test_missing_second_form_export_stops_before_reimport(project_job, monkeypatch):
    job = project_job
    def incomplete(*args, **kwargs):
        result = job.sqlcl(*args, **kwargs)
        if "apex export " in "\n".join(args[2]):
            (args[3] / alias_for_job(JOB).lower() / "pages/p00004-edit_2.apx").unlink()
        return result
    monkeypatch.setattr(project_release, "_run_script", incomplete)
    # SQLcl boundary is successful to prove the independent coverage guard acts.
    monkeypatch.setattr(project_release, "validate_apexlang", lambda *args: {"passed": True})
    with pytest.raises(RuntimeError, match="differs from the confirmed complete imported metadata"):
        finish(job)
    assert "reimport" not in job.calls
    assert not (job.root / "package-reimport-intent.json").exists()


def test_uncertain_project_reimport_is_not_replayed(project_job, monkeypatch):
    job = project_job
    def timeout(*args, **kwargs):
        result = job.sqlcl(*args, **kwargs)
        if "apex_application_install" in "\n".join(args[2]):
            raise subprocess.TimeoutExpired("fake", 1)
        return result
    monkeypatch.setattr(project_release, "_run_script", timeout)
    with pytest.raises(subprocess.TimeoutExpired):
        finish(job)
    assert (job.root / "package-reimport-intent.json").exists()
    monkeypatch.setattr(project_release, "_run_script", forbidden)
    with pytest.raises(RuntimeError, match="operator reconciliation"):
        finish(job)
    assert job.calls.count("reimport") == 1


@pytest.mark.parametrize("index", [1, 2, 3])
def test_project_publication_recovers_every_partial_rename_without_io(project_job, monkeypatch, index):
    job = project_job
    original = Path.replace
    count = []
    def interrupt(path, target):
        target = Path(target)
        if target.parent == job.root and target.name in release._PUBLICATION_FILES:
            count.append(target.name)
            if len(count) == index:
                raise OSError("publication interruption")
        return original(path, target)
    monkeypatch.setattr(Path, "replace", interrupt)
    with pytest.raises(OSError, match="publication interruption"):
        finish(job)
    monkeypatch.setattr(Path, "replace", original)
    monkeypatch.setattr(project_release, "_run_script", forbidden)
    monkeypatch.setattr("forms2apex.sqlcl._run_script", forbidden)
    monkeypatch.setattr(release, "runtime_login_check", forbidden)
    assert finish(job)["form_count"] == 2


def test_current_target_gate_failure_preserves_review_and_blocks_export(project_job):
    job = project_job
    before = (job.root / "project-review.json").read_bytes()
    def reject(*args):
        raise RuntimeError("active target mismatch")
    job.workflow.native_target_preflight = reject
    with pytest.raises(RuntimeError, match="active target mismatch"):
        finish(job)
    assert not job.calls
    assert (job.root / "project-review.json").read_bytes() == before


def test_live_schema_drift_blocks_sql_reimport_before_intent(project_job):
    job = project_job
    def reject(*args):
        raise RuntimeError("managed table changed")
    job.workflow._schema_ready = reject
    with pytest.raises(RuntimeError, match="managed table changed"):
        finish(job)
    assert "reimport" not in job.calls
    assert not (job.root / "package-reimport-intent.json").exists()


@pytest.mark.parametrize("changed", ["table", "process"])
def test_post_import_compiled_app_change_blocks_export_publication(project_job, monkeypatch, changed):
    job = project_job
    def drift(*args, **kwargs):
        result = job.sqlcl(*args, **kwargs)
        if "apex export " in "\n".join(args[2]):
            page = args[3] / alias_for_job(JOB).lower() / "pages/p00001-form_1.apx"
            raw = page.read_bytes()
            raw = raw.replace(b"FOX_NATIVE_CUSTOMERS", b"OTHER_TABLE") if changed == "table" else raw + b"\n-- changed process\n"
            page.write_bytes(raw)
        return result
    monkeypatch.setattr(project_release, "_run_script", drift)
    with pytest.raises(RuntimeError, match="confirmed complete imported metadata"):
        finish(job)
    assert "reimport" not in job.calls
    assert not (job.root / "export/.export-complete.json").exists()


def build_actual_project_release(tmp_path_factory, monkeypatch, *, source_snapshot=None):
    """Use actual source planner, reviews, workflow, bootstrap and durable import.

    Only target preflight observations, SQLcl transport, schema database adapter
    and HTTP are isolated. No model/network/database call is made by this helper.
    Returns exact package bytes and source/profile metadata for cross-layer tests.
    """
    from test_project_workflow import make_project, snapshot
    if source_snapshot is not None:
        if source_snapshot[0]["native_project"]["schema_version"] == 2:
            from mapped_project_test_support import register_mapped_test_profile
            register_mapped_test_profile(tmp_path_factory.mktemp("profile"), monkeypatch)
        snapshot = lambda **kwargs: deepcopy(source_snapshot)
        monkeypatch.setattr("test_project_workflow.snapshot", snapshot)
    from test_schema_bootstrap import Database
    from forms2apex import sqlcl
    w, root, _, _, aggregate, plan = make_project(tmp_path_factory.mktemp("i"))
    project, jid = aggregate["candidate"]["native_project"], root.name
    table_count = len({form["native_form"]["table_name"] for form in project["forms"]})
    w.generate(jid, json.dumps(aggregate["candidate"]))
    sequence, calls, app_ids = [], [], []
    alias = alias_for_job(jid)

    def preflight(job_id, action):
        binding = w.assert_artifact_binding(job_id)
        name = f"target-check-{action}-{len(sequence):016x}.json"
        sequence.append(name)
        raw = project_release._bytes({"artifact_binding": binding, "test_boundary": action})
        (root / name).write_bytes(raw)
        return {"file": name, "sha256": hashlib.sha256(raw).hexdigest(), "action": action}
    monkeypatch.setattr(w, "native_target_preflight", preflight)
    monkeypatch.setattr(w, "assert_native_preflight_fresh", lambda *args: None)

    def transport(path, args, commands, cwd, **kwargs):
        script = "\n".join(commands)
        if "apex validate " in script:
            calls.append("compile")
            output = "Validation successful"
        elif "F2A_ALIAS_COUNT=" in script:
            calls.append("allocate_import")
            output = "F2A_ALIAS_COUNT=0"
        elif "apex import -input" in script:
            calls.append("import")
            assert len(database.ddl) == table_count
            app_ids.append(int(re.search(r" -id (\d+)", script).group(1)))
            output = "Import successful"
        elif "apex export " in script:
            calls.append("capture" if "F2A_CAPTURE_IDENTITY=" in script else "export")
            for name, content in native_project.render_native_project(project).items():
                target = cwd / alias.lower() / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content.encode())
            if "-exptype SQL" in script:
                (cwd / f"f{app_ids[0]}.sql").write_text("-- synthetic SQLcl boundary\n" + "x" * 1200)
                output = "FOX_EXPORT_MATCH=1"
            else:
                output = "F2A_CAPTURE_IDENTITY=1\nF2A_CAPTURE_ALIAS=1\nF2A_CAPTURE_IDENTITY_AFTER=1"
        elif "FOX_ALIAS_COUNT=" in script:
            calls.append("allocate_reimport")
            output = "FOX_ALIAS_COUNT=0"
        elif "apex_application_install" in script:
            calls.append("reimport")
            assert "FOX create-only application collision" in script
            output = "FOX_REIMPORT_MATCH=1"
        else:
            pytest.fail("Unexpected SQLcl boundary")
        return subprocess.CompletedProcess(args, 0, output, "")
    monkeypatch.setattr(sqlcl, "_run_script", transport)
    monkeypatch.setattr(project_release, "_run_script", transport)
    database = Database()
    monkeypatch.setattr("forms2apex.schema_bootstrap.SqlclSchemaExecutor", lambda: database)
    monkeypatch.setattr("forms2apex.project_workflow.runtime_login_check", lambda url: {"passed": True})
    monkeypatch.setattr(release, "runtime_login_check", lambda url: {"passed": True})
    assert w.validate(jid)["passed"] is True
    assert w.prepare_schema(jid)["state"] == "READY"
    imported = w.import_draft(jid)
    assert imported["project_schema_verification"]["ready_for_import"] is True
    evidence = project_release.finalize_project_release(w, jid)
    package = (root / "apex-package.zip").read_bytes()
    checked = project_release.validate_project_package(package, expected_project=project, expected_evidence=evidence)
    assert checked["trace"] == json.loads((root / "source-to-apex.json").read_bytes())
    assert evidence["project_schema_verification"] == imported["project_schema_verification"]
    assert calls.count("import") == 1 and calls.count("reimport") == 1 and len(database.ddl) == table_count
    # The independent FOX-side reader consumes the exact package bytes emitted
    # by the real converter path, not a separate hand-built ZIP fixture.
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "fox"))
    from fox.native_project_pipeline import verify_project_package
    assert verify_project_package(package, evidence, project, w.target_profile()) == hashlib.sha256(package).hexdigest()
    source_snapshot, _ = snapshot()
    assert source_snapshot["native_project"] == project
    return SimpleNamespace(package=package, evidence=evidence, project=project,
                           snapshot=source_snapshot, profile=w.target_profile(), root=root)


def test_actual_project_workflow_schema_import_export_and_both_package_verifiers(tmp_path_factory, monkeypatch):
    built = build_actual_project_release(tmp_path_factory, monkeypatch)
    assert built.snapshot["project_id"] == "test-project"
    assert built.evidence["application_count"] == 1 and built.evidence["form_count"] == 2


def test_actual_ordinary_source_project_release_retains_mapping_and_original_bytes(tmp_path_factory, monkeypatch):
    from test_project_source import mapped_snapshot
    source = mapped_snapshot()
    built = build_actual_project_release(tmp_path_factory, monkeypatch, source_snapshot=source)
    checked = project_release.validate_project_package(built.package, expected_project=source[0]["native_project"])
    assert checked["trace"]["schema_version"] == 2
    assert built.evidence["project_id"] == source[0]["project_id"]
    with zipfile.ZipFile(io.BytesIO(built.package)) as archive:
        storage = json.loads(archive.read("schema/storage-mapping.json"))
        readme = archive.read("README.txt").decode()
        assert storage == project_release._storage_manifest(built.project)
        assert "This is not a data migration" in readme
        assert "no source table is renamed" in readme
        assert "Remediation:" in readme
        assert all(form["storage_mapping"][key] in readme for form in built.project["forms"]
                   for key in ("source_table_name", "target_table_name"))
    for record in source[0]["files"]:
        assert hashlib.sha256((built.root / "intake" / record["name"]).read_bytes()).hexdigest() == record["sha256"]


@pytest.mark.parametrize("change", ["target", "quoted_extra", "empty_extra"])
def test_v2_export_coverage_independently_checks_every_table_reference(change):
    from test_native_project import mapped_spec
    project = native_project.validate_project_spec(mapped_spec())
    members = {"apexlang/" + name: content.encode() for name, content in native_project.render_native_project(project).items()}
    name = "apexlang/pages/p00001-form_1.apx"
    if change == "target":
        members[name] = members[name].replace(project["forms"][0]["native_form"]["table_name"].encode(), b"CUSTOMERS")
    elif change == "quoted_extra":
        members[name] += b'\n            tableName: "CUSTOMERS"\n'
    else:
        members[name] += b"\n            tableName: \n"
    with pytest.raises(RuntimeError, match="storage target differs"):
        project_release._check_export_coverage(members, project)


@pytest.mark.parametrize("change", ["mapping_manifest", "ddl_ref", "project", "trace", "release_forms",
                                    "execution_binding", "original_bytes", "request_hash", "table_target", "extra_quoted_table", "readme"])
def test_rehashed_ordinary_package_cannot_change_source_target_or_import_contract(tmp_path_factory, monkeypatch, change):
    from test_project_source import mapped_snapshot
    built = build_actual_project_release(tmp_path_factory, monkeypatch, source_snapshot=mapped_snapshot())
    with zipfile.ZipFile(io.BytesIO(built.package)) as archive:
        members = {name: archive.read(name) for name in archive.namelist() if name != "manifest.json"}
    if change in {"mapping_manifest", "ddl_ref", "project"}:
        name = "schema/storage-mapping.json" if change == "mapping_manifest" else "native-project-spec.json"
        value = json.loads(members[name])
        if change == "mapping_manifest": value["mappings"][0]["storage_mapping"]["source_table_name"] = "FAKE"
        elif change == "ddl_ref": value["forms"][0]["ddl_sources"][0]["sha256"] = "f" * 64
        else: value["project_id"] = "other-project"
    elif change == "trace":
        name = "source-to-apex.json"
        value = json.loads(members[name])
        value["forms"][0]["storage_mapping"]["target_table_name"] = "FOX_NATIVE_FAKE"
    elif change == "release_forms":
        name = "evidence/release-evidence.json"
        value = json.loads(members[name])
        value["forms"][0]["storage_mapping"]["source_table_name"] = "FAKE"
    elif change == "execution_binding":
        name = "evidence/project-review.json"
        value = json.loads(members[name])
        value["form_reviews"][0]["execution_binding"]["storage_mapping"]["source_table_name"] = "FAKE"
    elif change == "original_bytes":
        name = "evidence/normalized-forms-inventory.json"
        value = json.loads(members[name])
        value["shared_inventory"]["modules"][0]["readable_source"] += " "
    elif change == "request_hash":
        name = next(name for name in members if name.startswith("evidence/form-reviews/"))
        value = json.loads(members[name])
        value["mapper_invocation"]["request_sha256"] = "f" * 64
        value["receipt_sha256"] = project_release._sha(project_release._bytes({key: item for key, item in value.items()
                                                                               if key != "receipt_sha256"}))
    elif change == "readme":
        name, value = "README.txt", None
        members[name] = b"Import into customer schema."
    else:
        name, value = "apexlang/pages/p00001-form_1.apx", None
        if change == "table_target":
            original = built.project["forms"][0]["native_form"]["table_name"].encode()
            members[name] = members[name].replace(original, b"CUSTOMERS")
        else:
            members[name] += b'\n            tableName: "CUSTOMERS"\n'
    if value is not None:
        members[name] = project_release._bytes(value)
    members["manifest.json"] = project_release._bytes({name: hashlib.sha256(raw).hexdigest() for name, raw in members.items()})
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, raw in members.items():
            archive.writestr(name, raw)
    with pytest.raises(RuntimeError, match="Project package integrity"):
        project_release.validate_project_package(stream.getvalue())
