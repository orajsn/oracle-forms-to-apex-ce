"""Two-profile integration with synthetic external transports; not live proof."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from forms2apex import native_blueprint, native_blueprint_required
from forms2apex import prototype_package, prototype_release
from forms2apex.project_reviews import canonical, read_object
from test_native_blueprint_required import project
from test_prototype_gateway import profile_case as case, advance, _case
from test_prototype_release import imported_case, browser_receipt


@pytest.fixture
def required_case(tmp_path_factory):
    return _case(tmp_path_factory, "required-v1")


def test_selected_profile_binds_validation_schema_import_and_snapshot(case):
    advance(case, "validate")
    advance(case, "prepare_schema")
    advance(case, "import")
    root = case.settings.jobs_root / case.request["job_id"] / "prototype-converter"
    snapshot = read_object(root / "snapshot.json")
    assert snapshot["template"] == case.renderer.context()
    assert (root / "candidate-apexlang.zip").read_bytes() == case.renderer.deterministic_prototype_zip(case.request["rendering_spec"])
    assert (root / "synthetic-schema.sql").read_bytes() == case.renderer.render_prototype_schema(case.request["rendering_spec"]).encode()
    assert case.calls.count("import") == 1


def test_other_profile_snapshot_context_cannot_be_adopted_or_recovered(case):
    advance(case, "validate")
    root = case.settings.jobs_root / case.request["job_id"] / "prototype-converter"
    snapshot = read_object(root / "snapshot.json")
    other = native_blueprint_required if case.renderer is native_blueprint else native_blueprint
    snapshot["template"] = other.context()
    (root / "snapshot.json").write_bytes(canonical(snapshot))
    before = list(case.calls)
    with pytest.raises(RuntimeError, match="SNAPSHOT_CHANGED"):
        case.adapter.run_stage("prepare_schema", case.request)
    with pytest.raises(RuntimeError, match="SNAPSHOT_CHANGED"):
        case.adapter.recover_stage_for_job(case.request["job_id"], "validate")
    assert case.calls == before


def test_new_profile_still_requires_original_external_authorizer(case):
    case.adapter.authorize = None
    with pytest.raises(RuntimeError, match="SOURCE_REVIEW_AUTHORIZATION_UNAVAILABLE"):
        case.adapter.run_stage("validate", case.request)
    assert not case.calls


def test_export_members_and_runtime_identity_use_same_profile(imported_case):
    case = imported_case
    advance(case, "verify_runtime")
    request = deepcopy(case.request)
    exported = advance(case, "export")
    binding = read_object(case.root / "snapshot.json")
    receipt = request["prior_receipts"]["verify_runtime"]["runtime_receipt"]
    checked = prototype_package.validate_prototype_package(Path(exported["package_path"]).read_bytes(),
        request=request, runtime_receipt=receipt, imported=request["prior_receipts"]["import"], artifact_binding=binding)
    assert checked["manifest"]["binding"]["profile_id"] == case.renderer.PROFILE_ID
    assert receipt["profile_id"] == case.renderer.PROFILE_ID
    assert exported["target_requirements"]["profile_id"] == case.renderer.PROFILE_ID
    assert checked["members"]["source-to-apex.json"] == canonical(case.renderer.prototype_trace(request["rendering_spec"]))
    assert checked["members"]["schema/01_synthetic_schema.sql"] == case.renderer.render_prototype_schema(request["rendering_spec"]).encode()


@pytest.mark.parametrize("member", ["target-profile", "trace-profile", "runtime-profile"])
def test_rehashed_cross_profile_export_evidence_is_rejected(imported_case, member):
    case = imported_case
    advance(case, "verify_runtime")
    request = deepcopy(case.request)
    exported = advance(case, "export")
    members = prototype_package._package_members(Path(exported["package_path"]).read_bytes())
    runtime = deepcopy(request["prior_receipts"]["verify_runtime"]["runtime_receipt"])
    other = native_blueprint_required if case.renderer is native_blueprint else native_blueprint
    if member == "target-profile":
        value = json.loads(members["evidence/target-requirements.json"])
        value["profile_id"] = other.PROFILE_ID
        members["evidence/target-requirements.json"] = canonical(value)
    elif member == "trace-profile":
        value = json.loads(members["source-to-apex.json"])
        value["scope"] = other.PROFILE_ID + "-trace"
        members["source-to-apex.json"] = canonical(value)
    else:
        runtime["profile_id"] = other.PROFILE_ID
        members["evidence/runtime-receipt.json"] = canonical(runtime)
    manifest = json.loads(members["manifest.json"])
    manifest["files"] = {name: hashlib.sha256(raw).hexdigest() for name, raw in members.items() if name != "manifest.json"}
    members["manifest.json"] = canonical(manifest)
    with pytest.raises(RuntimeError, match="PROFILE_BINDING_MISMATCH|EVIDENCE_MISMATCH"):
        prototype_package.validate_prototype_package(prototype_package._package_zip(members), request=request,
            runtime_receipt=runtime, imported=request["prior_receipts"]["import"],
            artifact_binding=read_object(case.root / "snapshot.json"))


@pytest.mark.parametrize("status", [True, False, "PASSED", "NOT_EXERCISED_NO_ADDITIONAL_REQUIRED_FIELDS", "UNKNOWN", None])
def test_additional_required_runtime_check_has_exact_evidence_state(required_case, status):
    case = required_case
    case = imported_case.__wrapped__(case)
    request = case.request
    binding = read_object(case.root / "snapshot.json")
    imported = request["prior_receipts"]["import"]
    receipt = browser_receipt(request, root=case.root, imported=imported,
        trace=case.renderer.prototype_trace(request["rendering_spec"]), artifact_binding=binding, freshness_check=lambda: None)
    form = next(page for page in receipt["pages"] if "additional_required_input_validation" in page["checks"])
    form["checks"]["additional_required_input_validation"] = status
    report = {key: value for key, value in receipt.items() if key != "artifacts"}
    raw = canonical(report)
    (case.root / "runtime-evidence/browser-report.json").write_bytes(raw)
    receipt["artifacts"][0].update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    if status == "PASSED":
        assert prototype_release.validate_runtime_receipt(case.root, request, imported, binding, receipt) == receipt
    else:
        with pytest.raises(RuntimeError, match="PAGE_COVERAGE_INVALID"):
            prototype_release.validate_runtime_receipt(case.root, request, imported, binding, receipt)


def test_no_additional_required_field_is_explicitly_not_exercised(required_case):
    case = required_case
    for field in case.request["rendering_spec"]["blocks"][0]["fields"]:
        field["value_required"] = False
    case.request["rendered_zip_sha256"] = hashlib.sha256(case.renderer.deterministic_prototype_zip(case.request["rendering_spec"])).hexdigest()
    case = imported_case.__wrapped__(case)
    receipt = advance(case, "verify_runtime")["runtime_receipt"]
    form = next(page for page in receipt["pages"] if page["page_id"] == 2)
    assert form["checks"]["additional_required_input_validation"] == "NOT_EXERCISED_NO_ADDITIONAL_REQUIRED_FIELDS"
    assert next(page for page in receipt["pages"] if page["page_id"] == 4)["checks"]["additional_required_input_validation"] == "PASSED"


def test_required_runtime_binding_rejects_old_or_missing_template(required_case):
    case = required_case
    case = imported_case.__wrapped__(case)
    binding = read_object(case.root / "snapshot.json")
    for template in (None, native_blueprint.context()):
        value = {**binding, "template": template}
        with pytest.raises(RuntimeError, match="TEMPLATE_PROFILE_MISMATCH"):
            prototype_package.runtime_binding(case.request, case.request["prior_receipts"]["import"], value)


def test_required_fields_do_not_make_legacy_projection_an_authorized_downgrade(required_case):
    case = required_case
    advance(case, "validate")
    case.request["rendering_spec"] = project(case.request["rendering_spec"])
    case.request["rendered_zip_sha256"] = hashlib.sha256(native_blueprint.deterministic_prototype_zip(case.request["rendering_spec"])).hexdigest()
    before = list(case.calls)
    with pytest.raises(RuntimeError, match="RECEIPT_BINDING_MISMATCH|PRIOR_RECEIPT_MISMATCH|SNAPSHOT_CHANGED"):
        case.adapter.run_stage("prepare_schema", case.request)
    assert before == case.calls
