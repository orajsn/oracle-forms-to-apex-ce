"""Controlled external adapters only; these tests make no live-flow claim."""
from copy import deepcopy
import base64
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from forms2apex import blueprint_profiles
from forms2apex import prototype_gateway as gateway
from forms2apex.project_reviews import digest, read_object
from test_native_blueprint import spec
from test_native_blueprint_required import spec as required_spec


def _case(tmp_path_factory, profile="v1"):
    tmp_path = tmp_path_factory.mktemp("p")
    jobs = tmp_path / "jobs"
    jobs.mkdir()
    make_spec = spec if profile == "v1" else required_spec
    value = make_spec(2)
    renderer = blueprint_profiles.select(value)
    request = {"schema_version": 1, "scope": "fox-prototype-converter-request-v1",
               "job_id": "fox-0123456789abcdefabcd", "project_id": value["project_id"],
               "source_binding": value["source_binding"], "plan_sha256": "b" * 64,
               "rendering_spec": value,
               "rendered_zip_sha256": hashlib.sha256(renderer.deterministic_prototype_zip(value)).hexdigest(),
               "prior_receipts": {}, "source_authority": {"schema_version": 1,
               "scope": "fox-prototype-source-authority-v1", "binding_sha256": "c" * 64,
               "sources_manifest_sha256": "d" * 64, "review_index_sha256": "e" * 64}}
    settings = SimpleNamespace(jobs_root=jobs, sqlcl_path=tmp_path / "sql", sqlcl_connection_name="F2A_APEX",
                               apex_workspace="FORMS2APEX_POC", apex_parsing_schema="FORMS2APEX_POC")
    calls = []
    def validate(sql, app, log):
        assert (app / "application.apx").is_file()
        assert {p.relative_to(app).as_posix(): p.read_text(encoding="utf-8")
                for p in app.rglob("*") if p.is_file()} == renderer.render_native_blueprint(value)
        calls.append("validate")
        log.write_text("Validation successful", encoding="utf-8")
        return {"passed": True, "return_code": 0, "log": str(log)}
    def fresh(req, action, root):
        calls.append("preflight:" + action)
        return lambda: calls.append("fresh:" + action)
    def run(sql, args, commands, root, timeout):
        assert args == ["-S", "-L", "-name", "F2A_APEX"]
        assert gateway.sqlcl._target_guard("FORMS2APEX_POC") in commands
        text = "\n".join(commands)
        calls.append(text)
        if "FOX_PROTO_ABSENT=" in text:
            output = "FOX_PROTO_ABSENT=0\n"
        elif "FOX_PROTO_CREATED=" in text:
            assert renderer.render_prototype_schema(value) in commands
            output = "FOX_PROTO_CREATED=1\n"
        else:
            block = next(block for block in value["blocks"]
                         if block["table_name"] and block["table_name"] in text)
            rows = ["FOX_NATIVE_BEGIN=1", "FOX_NATIVE_TABLE_COUNT=1"]
            for col in renderer._columns(block):
                rows.append("FOX_NATIVE_COLUMN=" + "|".join([col["name"], col["data_type"],
                    "Y" if col["nullable"] else "N", str(col.get("length", 0)), "YES" if col["identity"] else "NO"]))
            rows += ["FOX_NATIVE_PK_COUNT=1", "FOX_NATIVE_PK=FOX_ROW_ID|1|ENABLED|VALIDATED",
                     "FOX_NATIVE_ENABLED_TRIGGER_COUNT=0", "FOX_NATIVE_OK=1"]
            output = "\n".join(rows)
        return SimpleNamespace(returncode=0, stdout=output, stderr="")
    def imported(sql, connection, workspace, job_id, archive, log, **kwargs):
        assert archive.is_file() and archive.suffix == ".zip"
        assert kwargs["expected_draft_sha256"] == request["rendered_zip_sha256"]
        assert kwargs["artifact_binding"]["job_id"] == request["job_id"]
        kwargs["pre_write_check"]()
        calls.append("import")
        return {"application_id": 12345, "application_alias": "F2A_FOX_0123456789ABCDEFABCD",
                "import_intent_sha256": "1" * 64, "compiled_metadata_sha256": "2" * 64}
    adapter = gateway.PrototypeGateway(settings, authorize=lambda request: deepcopy(request),
        validator=validate, importer=imported, runner=run, preflight=fresh)
    return SimpleNamespace(adapter=adapter, request=request, calls=calls, settings=settings, run=run,
                           renderer=renderer, make_spec=make_spec)


@pytest.fixture
def case(tmp_path_factory):
    """Preserve direct legacy fixture callers outside this test module."""
    return _case(tmp_path_factory)


@pytest.fixture(params=["v1", "required-v1"])
def profile_case(tmp_path_factory, request):
    return _case(tmp_path_factory, request.param)


def advance(case, stage):
    receipt = case.adapter.run_stage(stage, case.request)
    assert receipt["request_sha256"] == digest(case.request)
    assert receipt["business_behavior_accepted"] is False
    case.request["prior_receipts"][stage] = receipt
    return receipt


def test_actual_directory_validation_and_exact_read_only_recovery(case):
    request = deepcopy(case.request)
    assert case.adapter.recover_stage("validate", request) is None
    receipt = advance(case, "validate")
    assert receipt["passed"] is True
    before = list(case.calls)
    assert case.adapter.recover_stage("validate", request) == receipt
    assert case.adapter.recover_stage_for_job(request["job_id"], "validate") == receipt
    assert case.calls == before
    with pytest.raises(RuntimeError, match="ALREADY_ATTEMPTED"):
        case.adapter.run_stage("validate", request)


def test_three_real_adapters_bind_snapshot_schema_and_durable_import(case):
    advance(case, "validate")
    schema = advance(case, "prepare_schema")
    assert schema["ready_for_import"] is True and len(schema["tables"]) == 2
    imported = advance(case, "import")
    assert imported["imported"] is True and imported["application_id"] == 12345
    assert "preflight:prepare-schema" in case.calls and "fresh:import" in case.calls
    root = case.settings.jobs_root / case.request["job_id"] / "prototype-converter"
    assert read_object(root / "snapshot.json")["source_authority"] == case.request["source_authority"]
    assert (root / "synthetic-schema.sql").read_text() == case.renderer.render_prototype_schema(case.request["rendering_spec"])
    assert read_object(root / "snapshot.json")["template"] == case.renderer.context()
    assert not case.adapter.supports("verify_runtime") and not case.adapter.supports("export")
    unavailable = case.adapter.run_stage("verify_runtime", case.request)
    assert unavailable["status"] == "UNAVAILABLE" and "passed" not in unavailable


def test_no_source_authority_callback_cannot_even_validate(case):
    case.adapter.authorize = None
    with pytest.raises(RuntimeError, match="SOURCE_REVIEW_AUTHORIZATION_UNAVAILABLE"):
        case.adapter.run_stage("validate", case.request)
    assert not case.calls


@pytest.mark.parametrize("change,code", [
    (lambda req: req.update(source_binding="f" * 64), "SOURCE_BINDING"),
    (lambda req: req.update(rendered_zip_sha256="f" * 64), "RENDERED_ZIP"),
    (lambda req: req.update(unknown=True), "REQUEST_FIELDS"),
    (lambda req: req["rendering_spec"].update(profile_id="native-project-v1"), "PROFILE"),
    (lambda req: req["source_authority"].update(approved=True), "AUTHORITY_FIELDS"),
])
def test_strict_source_hash_metadata_and_unknown_fields_rejected(case, change, code):
    change(case.request)
    with pytest.raises((ValueError, RuntimeError), match=code):
        case.adapter.run_stage("validate", case.request)
    assert not case.calls


def test_reviewer_authority_change_stops_before_sql(case):
    advance(case, "validate")
    case.adapter.authorize = lambda req: {**req, "source_binding": "f" * 64}
    with pytest.raises(RuntimeError, match="AUTHORIZATION_FAILED"):
        case.adapter.run_stage("prepare_schema", case.request)
    assert case.calls == ["validate"]


def test_failed_validation_never_allows_schema(case):
    case.adapter.validator = lambda *args: {"passed": False, "return_code": 1}
    advance(case, "validate")
    with pytest.raises(RuntimeError, match="PRIOR_STAGE_NOT_PASSED"):
        case.adapter.run_stage("prepare_schema", case.request)
    assert not case.calls


def test_validator_mutation_is_not_a_pass(case):
    def corrupt(sql, app, log):
        (app / "application.apx").write_text("tampered", encoding="utf-8")
        return {"passed": True}
    case.adapter.validator = corrupt
    with pytest.raises(RuntimeError, match="VALIDATION_INPUT_CHANGED"):
        case.adapter.run_stage("validate", case.request)
    with pytest.raises(RuntimeError, match="ALREADY_ATTEMPTED"):
        case.adapter.run_stage("validate", case.request)


def test_snapshot_and_prior_receipt_tamper_are_rejected(case):
    advance(case, "validate")
    root = case.settings.jobs_root / case.request["job_id"] / "prototype-converter"
    (root / "candidate-apexlang.zip").write_bytes(b"changed")
    with pytest.raises(RuntimeError, match="SNAPSHOT_CHANGED"):
        case.adapter.run_stage("prepare_schema", case.request)


def test_supplied_success_boolean_is_not_a_saved_receipt(case):
    advance(case, "validate")
    case.request["prior_receipts"]["validate"]["request_sha256"] = "f" * 64
    with pytest.raises(RuntimeError, match="PRIOR_RECEIPT_MISMATCH"):
        case.adapter.run_stage("prepare_schema", case.request)


def test_unknown_schema_outcome_never_replayed(case):
    advance(case, "validate")
    def uncertain(*args, **kwargs):
        raise TimeoutError("do not surface provider output")
    case.adapter.runner = uncertain
    with pytest.raises(TimeoutError):
        case.adapter.run_stage("prepare_schema", case.request)
    assert case.adapter.recover_stage("prepare_schema", case.request) is None
    with pytest.raises(RuntimeError, match="ALREADY_ATTEMPTED"):
        case.adapter.run_stage("prepare_schema", case.request)


def test_existing_objects_never_adopted_or_overwritten(case):
    advance(case, "validate")
    case.adapter.runner = lambda *args, **kwargs: SimpleNamespace(returncode=0, stderr="", stdout="FOX_PROTO_ABSENT=1\n")
    with pytest.raises(RuntimeError, match="EXISTING_OBJECT_PRESERVED"):
        case.adapter.run_stage("prepare_schema", case.request)
    root = case.settings.jobs_root / case.request["job_id"] / "prototype-converter"
    assert not (root / "schema-write-intent.json").exists()


def test_fresh_target_failure_stops_write(case):
    advance(case, "validate")
    def denied(*args):
        def expired():
            raise RuntimeError("EXPIRED_TARGET")
        return expired
    case.adapter.preflight = denied
    with pytest.raises(RuntimeError, match="EXPIRED_TARGET"):
        case.adapter.run_stage("prepare_schema", case.request)
    assert case.calls == ["validate"]


def test_wrong_saved_connection_cannot_write(case):
    advance(case, "validate")
    case.settings.sqlcl_connection_name = "ADMIN"
    with pytest.raises(RuntimeError, match="EXACT_SAVED_JSN"):
        case.adapter.run_stage("prepare_schema", case.request)
    assert case.calls == ["validate"]


def test_default_sqlcl_validation_is_called_without_database(case, monkeypatch):
    observed = []
    def sqlcl_validate(sql, app, log):
        observed.append(app.name)
        assert (app / "application.apx").is_file()
        return {"passed": True, "return_code": 0}
    monkeypatch.setattr(gateway.sqlcl, "validate_apexlang", sqlcl_validate)
    adapter = gateway.PrototypeGateway(case.settings, authorize=lambda req: req)
    assert adapter.run_stage("validate", case.request)["passed"] is True
    assert observed == ["apexlang"]


def test_default_import_helper_wiring(case, monkeypatch):
    advance(case, "validate")
    advance(case, "prepare_schema")
    original = case.adapter.importer
    monkeypatch.setattr(gateway.sqlcl, "import_apexlang_durable", original)
    adapter = gateway.PrototypeGateway(case.settings, authorize=lambda req: req,
        runner=case.run, preflight=case.adapter.preflight)
    assert adapter.run_stage("import", case.request)["imported"] is True


def test_default_sqlcl_validator_uses_real_helper_and_nolog_transport(case, monkeypatch):
    observed = []
    def transport(sql, args, commands, cwd, **kwargs):
        observed.append(commands)
        assert args == ["-S", "/nolog"]
        assert commands[0].startswith('apex validate -input "')
        assert (Path(cwd) / "apexlang" / "application.apx").is_file()
        return SimpleNamespace(returncode=0, stdout="Validation successful", stderr="")
    monkeypatch.setattr(gateway.sqlcl, "_run_script", transport)
    adapter = gateway.PrototypeGateway(case.settings, authorize=lambda req: req)
    assert adapter.run_stage("validate", case.request)["passed"] is True
    assert len(observed) == 1


def test_default_target_preflight_transports_do_not_reuse_old_profile_gate(case, monkeypatch):
    """Real collect/verify algorithms with controlled external observations."""
    from forms2apex import native_contract
    from forms2apex.target_profile import load_target_profile
    from test_runtime_preflight import install_full_probe_mocks, PROFILE_PATH
    profile = load_target_profile(PROFILE_PATH)
    # The old profile's settings are target/environment identity, not an old
    # rendering contract. 109 fields still use the independent strict renderer.
    case.request["rendering_spec"].update(case.make_spec(109))
    case.request["rendered_zip_sha256"] = hashlib.sha256(case.renderer.deterministic_prototype_zip(
        case.request["rendering_spec"])).hexdigest()
    case.settings.target_profile_path = PROFILE_PATH
    case.settings.generator_model = profile["opaf"]["roles"]["mapper"]["model"]
    case.settings.reviewer_model = profile["opaf"]["roles"]["reviewer"]["model"]
    case.settings.opaf_mapper_workflow_id = profile["opaf"]["roles"]["mapper"]["workflow_id"]
    case.settings.opaf_reviewer_workflow_id = profile["opaf"]["roles"]["reviewer"]["workflow_id"]
    case.settings.apex_base_url = profile["apex"]["ords_origin"] + "/ords"
    observations = install_full_probe_mocks(monkeypatch, profile)
    def forbidden(*args, **kwargs):
        raise AssertionError("Historical native form gate must not be called")
    monkeypatch.setattr(native_contract, "validate_native_spec", forbidden)
    monkeypatch.setattr(gateway.native_target, "verify_native_schema", forbidden)
    advance(case, "validate")
    case.adapter.preflight = case.adapter._target_preflight
    assert advance(case, "prepare_schema")["ready_for_import"] is True
    # Entry and both pre-DDL guards each measure a genuinely current target.
    assert observations == ["imds", "tooling", "database", "oci", "ords"] * 3


def test_nonzero_sqlcl_code_cannot_be_called_passed(case):
    case.adapter.validator = lambda *args: {"passed": True, "return_code": 9}
    assert advance(case, "validate")["status"] == "FAILED"
    with pytest.raises(RuntimeError, match="PRIOR_STAGE_NOT_PASSED"):
        case.adapter.run_stage("prepare_schema", case.request)


def test_unknown_import_outcome_is_never_replayed(case):
    advance(case, "validate")
    advance(case, "prepare_schema")
    def uncertain(*args, **kwargs):
        kwargs["pre_write_check"]()
        raise TimeoutError("unknown external outcome")
    case.adapter.importer = uncertain
    with pytest.raises(TimeoutError):
        case.adapter.run_stage("import", case.request)
    assert case.adapter.recover_stage("import", case.request) is None
    with pytest.raises(RuntimeError, match="ALREADY_ATTEMPTED"):
        case.adapter.run_stage("import", case.request)


def test_wrong_metadata_cannot_prepare_or_import(case):
    advance(case, "validate")
    original = case.adapter.runner
    def malformed(*args, **kwargs):
        result = original(*args, **kwargs)
        if "FOX_NATIVE_COLUMN=" in result.stdout:
            result.stdout = result.stdout.replace("FOX_NATIVE_PK_COUNT=1", "FOX_NATIVE_PK_COUNT=2")
        return result
    case.adapter.runner = malformed
    with pytest.raises(RuntimeError, match="SCHEMA_METADATA_MISMATCH"):
        case.adapter.run_stage("prepare_schema", case.request)
    assert case.adapter.recover_stage("prepare_schema", case.request) is None
    with pytest.raises(RuntimeError, match="PRIOR_STAGES_INVALID"):
        case.adapter.run_stage("import", case.request)


def test_caller_cannot_select_filesystem_job_path(case):
    case.request["job_id"] = "../different-job"
    with pytest.raises(ValueError, match="job_id"):
        case.adapter.run_stage("validate", case.request)
    assert not case.calls


def authority_bundle(case):
    """Structural fixture only: not fabricated review/invocation proof."""
    identity = case.request["job_id"]
    source = case.request["source_binding"]
    focus = "focus-" + "a" * 24
    raw = b"<synthetic />"
    members = {"candidate-apexlang.zip": b"structural-only-not-a-live-package",
               "sources/source-000.xml": raw}
    binding = {"job_id": identity, "source_binding": source}
    sources = {"source_binding": source, "files": [{"name": "synthetic.xml", "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest()}]}
    row = {"focus_id": focus}
    for name in gateway._FOCUS_FILES:
        value = {"structural_fixture": name}
        members[focus + "/" + name + ".json"] = gateway.canonical(value)
        row[name + "_sha256"] = digest(value)
    index = {"source_binding": source, "focuses": [row]}
    for name, value in {"binding.json": binding, "sources-manifest.json": sources,
                        "review-index.json": index, "packet.json": {}, "native-plan.json": {},
                        "merged-blueprint.json": {}, "rendered.json": {}}.items():
        members[name] = gateway.canonical(value)
    authority = {"schema_version": 1, "scope": "fox-prototype-source-authority-v1",
                 "binding_sha256": digest(binding), "sources_manifest_sha256": digest(sources),
                 "review_index_sha256": digest(index)}
    descriptor = {"schema_version": 1, "scope": "fox-prototype-authority-bundle-v1", "job_id": identity,
                  "source_binding": source, "source_authority": authority,
                  "files": [{"path": name, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
                            for name, raw in sorted(members.items())]}
    bundle = {**descriptor, "manifest_sha256": digest(descriptor)}
    bundle["files"] = [{**row, "content_base64": base64.b64encode(members[row["path"]]).decode("ascii")}
                       for row in descriptor["files"]]
    return bundle


def rebind_bundle(bundle):
    bundle["files"].sort(key=lambda row: row["path"])
    descriptor = {key: value for key, value in bundle.items() if key != "manifest_sha256"}
    descriptor["files"] = [{key: row[key] for key in ("path", "sha256", "bytes")} for row in bundle["files"]]
    bundle["manifest_sha256"] = digest(descriptor)


def test_epoch_marker_selects_syntax_but_cannot_authorize_legacy_index(case):
    bundle = authority_bundle(case)
    raw = b'{}'
    bundle['files'].append({'path': 'epochs/epoch-000002/epoch-record.json',
        'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw),
        'content_base64': base64.b64encode(raw).decode('ascii')})
    rebind_bundle(bundle)
    with pytest.raises(RuntimeError, match='MEMBERSHIP_MISMATCH'):
        case.adapter.stage_source_authority(case.request['job_id'], bundle)
    assert case.calls == []
    assert case.adapter.recover_source_authority(case.request['job_id']) is None


def test_source_authority_staging_is_immutable_read_only_recoverable_and_not_approval(case):
    bundle = authority_bundle(case)
    assert case.adapter.recover_source_authority(case.request["job_id"]) is None
    receipt = case.adapter.stage_source_authority(case.request["job_id"], bundle)
    assert receipt["staged"] is True and receipt["source_review_authorized"] is False
    assert receipt["manifest_sha256"] == bundle["manifest_sha256"]
    assert case.adapter.recover_source_authority(case.request["job_id"]) == receipt
    assert case.adapter.stage_source_authority(case.request["job_id"], bundle) == receipt
    assert not case.calls  # No validation, database, target probe or model call.
    case.adapter.authorize = None
    with pytest.raises(RuntimeError, match="AUTHORIZATION_UNAVAILABLE"):
        case.adapter.run_stage("validate", case.request)


@pytest.mark.parametrize("bad_path,expected_error", [
    ("../binding.json", "PATH_NOT_ALLOWED"),
    ("/binding.json", "PATH_NOT_ALLOWED"),
    ("C:/binding.json", "PATH_NOT_ALLOWED"),
    ("sources\\source-000.xml", "PATH_NOT_ALLOWED"),
    ("unknown.json", "PATH_NOT_ALLOWED"),
    ("assessment.json", "PATH_NOT_ALLOWED"),
    # Intent names are recognized provenance paths. Replacing the required
    # binding member with one still rejects the incomplete authority closure.
    ("focus-" + "a" * 24 + "/mapper-intent.json", "ROOT_FILES_MISSING"),
])
def test_staging_rejects_path_traversal_extra_artifacts_and_intents(case, bad_path, expected_error):
    before = {p.relative_to(case.settings.jobs_root): p.read_bytes()
              for p in case.settings.jobs_root.rglob('*') if p.is_file()}
    bundle = authority_bundle(case)
    bundle["files"][0]["path"] = bad_path
    rebind_bundle(bundle)
    with pytest.raises(RuntimeError, match=expected_error):
        case.adapter.stage_source_authority(case.request["job_id"], bundle)
    assert not case.calls
    assert {p.relative_to(case.settings.jobs_root): p.read_bytes()
            for p in case.settings.jobs_root.rglob('*') if p.is_file()} == before


def test_staging_rejects_changed_bytes_manifest_and_missing_review(case):
    bundle = authority_bundle(case)
    bundle["files"][0]["content_base64"] = base64.b64encode(b"changed").decode()
    with pytest.raises(RuntimeError, match="BYTES_CHANGED"):
        case.adapter.stage_source_authority(case.request["job_id"], bundle)
    bundle = authority_bundle(case)
    bundle["manifest_sha256"] = "0" * 64
    with pytest.raises(RuntimeError, match="MANIFEST_HASH"):
        case.adapter.stage_source_authority(case.request["job_id"], bundle)
    bundle = authority_bundle(case)
    bundle["files"] = [row for row in bundle["files"] if not row["path"].endswith("/review-receipt.json")]
    rebind_bundle(bundle)
    with pytest.raises(RuntimeError, match="FOCUS_BYTES_CHANGED"):
        case.adapter.stage_source_authority(case.request["job_id"], bundle)


def test_staging_does_not_overwrite_existing_evidence_and_recovery_checks_actual_bytes(case):
    bundle = authority_bundle(case)
    case.adapter.stage_source_authority(case.request["job_id"], bundle)
    root = case.settings.jobs_root / case.request["job_id"] / "prototype-pipeline"
    original = (root / "binding.json").read_bytes()
    candidate = next(row for row in bundle["files"] if row["path"] == "candidate-apexlang.zip")
    candidate["content_base64"] = base64.b64encode(b"different-candidate").decode()
    candidate["bytes"] = len(b"different-candidate")
    candidate["sha256"] = hashlib.sha256(b"different-candidate").hexdigest()
    rebind_bundle(bundle)
    with pytest.raises(RuntimeError, match="ALREADY_EXISTS_PRESERVED"):
        case.adapter.stage_source_authority(case.request["job_id"], bundle)
    assert (root / "binding.json").read_bytes() == original
    (root / "candidate-apexlang.zip").write_bytes(b"changed")
    with pytest.raises(RuntimeError, match="BYTES_CHANGED"):
        case.adapter.recover_source_authority(case.request["job_id"])


def test_get_stage_recovery_never_starts_unknown_request(case):
    assert case.adapter.recover_stage_for_job(case.request["job_id"], "validate") is None
    assert not case.calls
    with pytest.raises(RuntimeError, match="STAGE_INVALID"):
        case.adapter.recover_stage_for_job(case.request["job_id"], "../validate")
