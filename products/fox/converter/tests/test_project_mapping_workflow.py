"""Real mapped source/review/render components with synthetic provider records."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from forms2apex import project_reviews as reviews
from forms2apex.workflow_router import capabilities
from mapped_project_test_support import register_mapped_test_profile
from test_project_source import mapped_snapshot
from test_project_workflow import form_payload, workflow


JOB = "fox-" + "9" * 20


@pytest.fixture
def tmp_path(tmp_path_factory):
    return tmp_path_factory.mktemp("pm")


def staged(tmp_path, monkeypatch, *, registered=True, bom=False, shared=False):
    if registered:
        register_mapped_test_profile(tmp_path, monkeypatch)
    w, profile = workflow(tmp_path)
    snap, plan = mapped_snapshot(bom=bom, shared=shared)
    reviews.stage_project_snapshot(w.settings.jobs_root, JOB, snap)
    root = w.store.require(JOB)
    return w, root, profile, snap, plan, w.inspect(JOB)


@pytest.mark.parametrize("bom", [False, True])
@pytest.mark.parametrize("shared", [False, True])
def test_original_projection_and_requests_match_fox_executor(tmp_path, monkeypatch, bom, shared):
    w, root, profile, snap, plan, inspection = staged(tmp_path, monkeypatch, bom=bom, shared=shared)
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "fox"))
    from fox import native_project_pipeline as pipeline
    rows, expanded = pipeline._project_inventories(inspection, snap, plan, JOB)
    assert rows == sorted(reviews.project_inventory_rows(plan, JOB, inspection["shared_inventory"]), key=lambda row: row["module_id"])
    forms = {form["module_id"]: form for form in snap["native_project"]["forms"]}
    for row in rows:
        form = forms[row["module_id"]]
        request = reviews.project_model_request(root, row)
        assert pipeline._form_request(snap, form, row, expanded[row["module_id"]]) == request
        assert request["storage_mapping"] == form["storage_mapping"]
        assert request["ddl_sources"] == form["ddl_sources"]
        assert request["module_execution_binding"] == row["binding"]
        child = reviews.child_root(root, row["module_id"])
        assert reviews.read_object(child / "intake/manifest.json")["storage_mapping"] == form["storage_mapping"]
        for source in snap["files"]:
            raw = (child / "intake" / source["name"]).read_bytes()
            assert raw == (root / "intake" / source["name"]).read_bytes()
            assert hashlib.sha256(raw).hexdigest() == source["sha256"]
        text = "\n".join(module["readable_source"] for module in request["inventory"]["modules"])
        assert form["storage_mapping"]["source_table_name"] in text
        assert form["storage_mapping"]["target_table_name"] not in text
    assert capabilities(profile)["project_mapping"]["paired_profile_ready"] is True


def test_old_profile_advertises_not_ready_and_cannot_seal_mapped_review(tmp_path, monkeypatch):
    w, root, profile, snap, plan, inspection = staged(tmp_path, monkeypatch, registered=False)
    assert capabilities(profile)["project_mapping"]["paired_profile_ready"] is False
    row = inspection["forms"][0]
    with pytest.raises(ValueError, match="new registered paired"):
        reviews.record_project_form_review(root, row["module_id"], form_payload(root, row, profile),
                                          *w.review_identity(), target_profile=profile)
    assert not list(root.rglob("native-review.json"))
    assert not (root / "apexlang").exists()


@pytest.mark.parametrize("role", ["mapper", "reviewer"])
@pytest.mark.parametrize("change", ["omit", "swap_mapping", "ddl_ref", "execution"])
def test_review_cannot_bind_a_request_without_the_exact_mapping(tmp_path, monkeypatch, role, change):
    w, root, profile, snap, plan, inspection = staged(tmp_path, monkeypatch)
    row = inspection["forms"][0]
    payload = form_payload(root, row, profile)
    request = reviews.project_model_request(root, row)
    if change == "omit":
        request.pop("storage_mapping")
    elif change == "swap_mapping":
        request["storage_mapping"] = inspection["forms"][1]["inventory"]["storage_mapping"]
    elif change == "ddl_ref":
        request = deepcopy(request)
        request["ddl_sources"][0]["sha256"] = "a" * 64
    else:
        request = deepcopy(request)
        request["module_execution_binding"]["plan_sha256"] = "b" * 64
    if role == "reviewer":
        request.update(candidate=payload["candidate"], candidate_sha256=reviews.digest(payload["candidate"]))
    payload[role + "_invocation"]["request_sha256"] = reviews.digest(request)
    with pytest.raises(ValueError, match="exact original-source"):
        reviews.record_project_form_review(root, row["module_id"], payload, *w.review_identity(), target_profile=profile)
    assert not list(root.rglob("native-review.json"))


def test_complete_v2_review_and_generation_remain_bound_to_original_source(tmp_path, monkeypatch):
    w, root, profile, snap, plan, inspection = staged(tmp_path, monkeypatch, bom=True, shared=True)
    original = {path.name: path.read_bytes() for path in (root / "intake").iterdir()}
    payload = {"job_id": JOB, "source_hash": snap["source_hash"], "form_reviews": []}
    for row in inspection["forms"]:
        receipt = reviews.record_project_form_review(root, row["module_id"], form_payload(root, row, profile),
                                                     *w.review_identity(), target_profile=profile)
        payload["form_reviews"].append({"module_id": row["module_id"], "receipt_sha256": receipt["receipt_sha256"]})
    sealed = reviews.aggregate_project_review(root, payload, *w.review_identity())
    assert sealed["schema_version"] == 2 and sealed["scope"] == "fox-native-project-review-v2"
    assert sealed["project_id"] == snap["project_id"] and sealed["plan_sha256"] == plan["plan_sha256"]
    for row in sealed["form_reviews"]:
        assert row["execution_binding"] == next(form["binding"] for form in inspection["forms"] if form["module_id"] == row["module_id"])
    generated = w.generate(JOB, json.dumps(sealed["candidate"]))
    assert generated["form_count"] == 2 and generated["application_count"] == 1
    assert w.assert_artifact_binding(JOB)
    assert {path.name: path.read_bytes() for path in (root / "intake").iterdir()} == original
    assert reviews.verify_project_review(root, sealed["candidate"], *w.review_identity()) == sealed
    # A well-formed but altered mapping cannot reuse a previously sealed child.
    child = reviews.child_root(root, inspection["forms"][0]["module_id"])
    changed = reviews.read_object(child / "intake/manifest.json")
    changed["storage_mapping"]["project_id"] = "another-project"
    (child / "intake/manifest.json").write_bytes(reviews.canonical(changed))
    with pytest.raises((ValueError, RuntimeError)):
        w.assert_artifact_binding(JOB)
