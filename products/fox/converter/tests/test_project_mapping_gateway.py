"""Mapped HTTP lifecycle with a labelled synthetic registered profile INPUT.

Profile/source/review/schema/package validators are real. Only SQLcl transport,
database observations and runtime reachability use offline synthetic adapters.
No test evidence represents a real model, database, deployment or acceptance.
"""
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
from types import SimpleNamespace
import zipfile

import pytest
from starlette.testclient import TestClient

from forms2apex import project_release, project_reviews
from forms2apex.workflow_router import WorkflowRouter
from mapped_project_test_support import register_mapped_test_profile
from test_project_gateway import BASE, JOB, application, external_boundaries, get, post
from test_project_source import mapped_snapshot
from test_project_workflow import form_payload, snapshot, workflow


@pytest.fixture
def mapped_api(tmp_path_factory, monkeypatch):
    base = tmp_path_factory.mktemp("mg")
    register_mapped_test_profile(base, monkeypatch)
    prepared, profile = workflow(base)
    router = WorkflowRouter(prepared.settings)
    with TestClient(application(router)) as client:
        yield SimpleNamespace(client=client, router=router, profile=profile,
                              settings=prepared.settings, root=prepared.settings.jobs_root / JOB)


def stage_review(api, *, bom=False, shared=False):
    source, plan = mapped_snapshot(bom=bom, shared=shared)
    assert source["native_project"]["schema_version"] == 2
    result = post(api, BASE, source)
    assert result.status_code == 201, result.text
    original = {row["name"]: (api.root / "intake" / row["name"]).read_bytes() for row in source["files"]}
    result = post(api, BASE + "/actions/inspect")
    assert result.status_code == 200, result.text
    inspection = result.json()
    request = {"job_id": JOB, "source_hash": source["source_hash"], "form_reviews": []}
    for row in inspection["forms"]:
        result = post(api, BASE + "/reviews/" + row["module_id"], form_payload(api.root, row, api.profile))
        assert result.status_code == 200, result.text
        request["form_reviews"].append({"module_id": row["module_id"], "receipt_sha256": result.json()["receipt_sha256"]})
        child = project_reviews.child_root(api.root, row["module_id"])
        assert all((child / "intake" / name).read_bytes() == raw for name, raw in original.items())
    omitted = deepcopy(request)
    omitted["form_reviews"].pop()
    assert post(api, BASE + "/review", omitted).status_code == 409
    assert not (api.root / "project-review.json").exists()
    result = post(api, BASE + "/review", request)
    assert result.status_code == 200, result.text
    sealed = project_reviews.read_object(api.root / "project-review.json")
    assert sealed["schema_version"] == 2 and sealed["scope"] == "fox-native-project-review-v2"
    assert sealed["plan_sha256"] == plan["plan_sha256"]
    return source, plan, inspection, result.json(), original


@pytest.mark.parametrize("bom", [False, True])
@pytest.mark.parametrize("shared", [False, True])
def test_mapped_asgi_lifecycle_preserves_sources_and_unique_storage(mapped_api, monkeypatch, bom, shared):
    api = mapped_api
    capability = get(api, "/fox/capabilities")
    assert capability.status_code == 200
    assert capability.json()["project_mapping"]["paired_profile_ready"] is True
    profile = get(api, "/fox/target-profile")
    assert profile.status_code == 200 and profile.json()["target_profile"] == api.profile
    source, plan, inspection, aggregate, original = stage_review(api, bom=bom, shared=shared)
    for row in source["files"]:
        raw = original[row["name"]]
        assert hashlib.sha256(raw).hexdigest() == row["sha256"]
        assert raw.decode("utf-8-sig") == row["text"]
        if row["name"].endswith(".xml"):
            assert raw.startswith(b"\xef\xbb\xbf") is bom
    status = get(api, BASE)
    assert status.json()["native_project"] == source["native_project"]
    assert "readable_source" not in status.text and "<FormModule" not in status.text
    generated = post(api, BASE + "/actions/generate", aggregate["candidate"])
    assert generated.status_code == 200, generated.text
    assert generated.json()["application_count"] == 1 and generated.json()["form_count"] == 2
    boundary = external_boundaries(api, monkeypatch, source["native_project"])
    assert post(api, BASE + "/actions/validate").json()["passed"] is True
    assert post(api, BASE + "/actions/import").status_code == 409
    assert not (api.root / "import-intent.json").exists()
    prepared = post(api, BASE + "/actions/prepare-schema")
    assert prepared.status_code == 200, prepared.text
    assert prepared.json()["state"] == "READY"
    expected_mappings = {form["native_form"]["table_name"]: form["storage_mapping"]
                         for form in source["native_project"]["forms"]}
    assert len(expected_mappings) == (1 if shared else 2)
    assert {row["table_name"] for row in prepared.json()["tables"]} == set(expected_mappings)
    for row in prepared.json()["tables"]:
        assert row["storage_mapping"] == expected_mappings[row["table_name"]]
        assert row["storage_mapping_sha256"] == project_reviews.digest(row["storage_mapping"])
    assert len(boundary.database.ddl) == len(expected_mappings)
    reconciled = post(api, BASE + "/actions/reconcile-schema")
    assert reconciled.status_code == 200 and reconciled.json()["ready_for_import"] is True
    assert reconciled.json()["database_writes"] is False
    imported = post(api, BASE + "/actions/import")
    assert imported.status_code == 200, imported.text
    assert boundary.calls.count("import") == 1
    assert post(api, BASE + "/actions/import").status_code == 409
    released = post(api, BASE + "/release")
    assert released.status_code == 200, released.text
    evidence = released.json()
    assert evidence["package_reimport_passed"] is True and evidence["application_count"] == 1
    assert evidence["authenticated_runtime_passed"] is False
    assert evidence["clean_schema_install_passed"] is False and evidence["human_acceptance_recorded"] is False
    package = get(api, BASE + "/package")
    assert package.status_code == 200 and package.headers["content-type"] == "application/zip"
    checked = project_release.validate_project_package(package.content,
        expected_project=source["native_project"], expected_evidence=evidence)
    assert checked["trace"]["form_count"] == 2
    with zipfile.ZipFile(io.BytesIO(package.content)) as archive:
        mappings = json.loads(archive.read("schema/storage-mapping.json"))
        assert len(mappings["mappings"]) == len(expected_mappings)
    assert all((api.root / "intake" / name).read_bytes() == raw for name, raw in original.items())
    calls, ddl = list(boundary.calls), list(boundary.database.ddl)
    assert post(api, BASE + "/release").json() == evidence
    assert get(api, BASE + "/package").content == package.content
    assert boundary.calls == calls and boundary.database.ddl == ddl


@pytest.mark.parametrize("change", ["mapping", "original_bytes", "ddl_reference", "plan"])
def test_mapped_source_cannot_stage_forged_mapping_or_original_bytes(mapped_api, change):
    source, _ = mapped_snapshot(bom=True)
    if change == "mapping":
        source["native_project"]["forms"][0]["storage_mapping"]["project_id"] = "forged-project"
    elif change == "original_bytes":
        source["files"][0]["text"] += "<!-- SOURCE_PRIVACY_MARKER_7391 -->"
    elif change == "ddl_reference":
        source["native_project"]["forms"][0]["ddl_sources"][0]["sha256"] = "f" * 64
    else:
        source["plan_sha256"] = "f" * 64
    result = post(mapped_api, BASE, source)
    assert result.status_code == 422
    assert "SOURCE_PRIVACY_MARKER_7391" not in result.text
    assert not list(mapped_api.settings.jobs_root.iterdir())


def test_old_active_profile_rejects_mapped_review_before_generation(tmp_path_factory):
    base = tmp_path_factory.mktemp("og")
    prepared, profile = workflow(base)
    router = WorkflowRouter(prepared.settings)
    with TestClient(application(router)) as client:
        api = SimpleNamespace(client=client, router=router, profile=profile,
                              settings=prepared.settings, root=prepared.settings.jobs_root / JOB)
        assert get(api, "/fox/capabilities").json()["project_mapping"]["paired_profile_ready"] is False
        source, _ = mapped_snapshot(bom=True)
        assert post(api, BASE, source).status_code == 201
        inspection = post(api, BASE + "/actions/inspect").json()
        row = inspection["forms"][0]
        rejected = post(api, BASE + "/reviews/" + row["module_id"], form_payload(api.root, row, profile))
        assert rejected.status_code == 409
        assert not list(api.root.rglob("native-review.json"))
        assert not (api.root / "project-review.json").exists()
        assert not (api.root / "apexlang").exists()
        assert not (api.root / "schema-preparation-intent.json").exists()
        assert not (api.root / "import-intent.json").exists()


@pytest.mark.parametrize("mapped", [False, True], ids=["v1", "v2"])
def test_real_fox_client_consumes_http_receipts_through_complete_pipeline(tmp_path_factory, monkeypatch, mapped):
    """Real FOX orchestration/client and real ASGI routes; no socket is opened."""
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "fox"))
    from fox import native_project_pipeline as pipeline, opaf

    base = tmp_path_factory.mktemp("fc")
    if mapped:
        register_mapped_test_profile(base, monkeypatch)
    prepared, profile = workflow(base)
    source, plan = mapped_snapshot(bom=True, shared=True) if mapped else snapshot(bom=True)
    source["approvals"] = dict.fromkeys(("redacted_source", "external_ai", "synthetic_prototype"), True)
    local_job = base / "f" / JOB
    local_job.mkdir(parents=True)
    (local_job / "source-snapshot.json").write_text(json.dumps(source), encoding="utf-8")
    model_profile = {"schema_version": 2 if mapped else 1,
        "profile_id": "native-project-v1" if mapped else "native-table-form-v1",
        "opaf_base_url": profile["opaf"]["base_url"],
        "certificate_sha256": profile["opaf"]["certificate_sha256"],
        **{role: profile["opaf"]["roles"][role] for role in ("mapper", "reviewer")},
        **(pipeline.PROJECT_MAPPING_CAPABILITY if mapped else {})}
    profile_path = base / "synthetic-model-profile.json"
    profile_path.write_text(json.dumps(model_profile), encoding="utf-8")
    credential_path = base / "synthetic-offline-credentials.json"
    credential_path.write_text(json.dumps({"username": "synthetic-user", "password": "NOT-A-REAL-PASSWORD",
                                          "converter_token": "x" * 48}), encoding="utf-8")
    monkeypatch.setenv("FOX_NATIVE_PROFILE_FILE", str(profile_path))
    monkeypatch.setenv("FOX_OPAF_CREDENTIAL_FILE", str(credential_path))
    monkeypatch.setenv("FOX_CONVERTER_URL", "http://127.0.0.1:8091")
    router = WorkflowRouter(prepared.settings)
    with TestClient(application(router)) as client:
        api = SimpleNamespace(client=client, router=router, profile=profile,
                              settings=prepared.settings, root=prepared.settings.jobs_root / JOB)
        boundary = external_boundaries(api, monkeypatch, source["native_project"])
        requests, model_calls = [], []

        class OfflineAsgiConnection:
            """Replace only the network transport used by the real ConverterClient."""
            def __init__(self, host, port, timeout):
                assert (host, port, timeout) == ("127.0.0.1", 8091, 600)

            def request(self, method, path, body, headers):
                requests.append((method, path))
                self.response = client.request(method, path, content=body, headers=headers)

            def getresponse(self):
                return SimpleNamespace(status=self.response.status_code,
                                       read=lambda limit: self.response.content[:limit])

            def close(self):
                pass

        def synthetic_inference(self, role, request, *, role_name, target_profile):
            assert target_profile == profile and role == profile["opaf"]["roles"][role_name]
            model_calls.append((role_name, deepcopy(request)))
            inspection = project_reviews.read_object(api.root / "normalized-forms-inventory.json")
            row = next(row for row in inspection["forms"] if row["child_job_id"] == request["job_id"])
            payload = form_payload(api.root, row, profile)
            output = payload["candidate"] if role_name == "mapper" else payload["review"]
            invocation = payload[role_name + "_invocation"]
            invocation.update(request_sha256=opaf.canonical_hash(request), response_sha256=opaf.canonical_hash(output))
            return output, invocation, payload["model_environment"][role_name]

        monkeypatch.setattr(opaf.http.client, "HTTPConnection", OfflineAsgiConnection)
        monkeypatch.setattr(opaf.OpafClient, "invoke_with_environment", synthetic_inference)
        evidence = pipeline.run_native_project_job(local_job)
        assert evidence["human_acceptance_recorded"] is False
        assert evidence["authenticated_runtime_passed"] is False
        assert len(model_calls) == 4 and boundary.calls.count("import") == 1
        assert requests.index(("POST", BASE + "/actions/prepare-schema")) < requests.index(("POST", BASE + "/actions/import"))
        sealed = json.loads((local_job / "native-project-pipeline/review-receipt.json").read_bytes())
        assert sealed == project_reviews.read_object(api.root / "project-review.json")
        assert sealed["scope"] == "fox-native-project-review-v" + str(2 if mapped else 1)
        assert len(sealed["form_reviews"]) == 2
        package = (local_job / "apex-package.zip").read_bytes()
        assert pipeline.verify_project_package(package, evidence, source["native_project"], profile) == hashlib.sha256(package).hexdigest()
        checkpoint = json.loads((local_job / "native-project-pipeline/generated.json").read_bytes())
        assert checkpoint["job_id"] == JOB
        old_models, old_sqlcl, old_ddl = list(model_calls), list(boundary.calls), list(boundary.database.ddl)
        assert pipeline.run_native_project_job(local_job) == evidence
        assert model_calls == old_models and boundary.calls == old_sqlcl and boundary.database.ddl == old_ddl
