"""Actual authenticated ASGI project routes; only external services are fake."""
from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace

import pytest
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from forms2apex import native_project, project_release, release, sqlcl
from forms2apex.fox_gateway import attach_routes
from forms2apex.security import alias_for_job
from forms2apex.workflow import ConverterWorkflow
from forms2apex.workflow_router import WorkflowRouter
from test_project_workflow import form_payload, snapshot, workflow
from test_schema_bootstrap import Database


JOB = "fox-" + "7" * 20
BASE = "/fox/jobs/" + JOB
HEADERS = {"Authorization": "Bearer " + "x" * 48}


def application(router):
    routes = []
    class MCP:
        def custom_route(self, path, methods, **kwargs):
            def register(handler):
                routes.append(Route(path, handler, methods=methods))
                return handler
            return register
    attach_routes(MCP(), router, router.settings)
    return Starlette(routes=routes)


@pytest.fixture
def api(tmp_path_factory):
    base = tmp_path_factory.mktemp("gw")
    prepared, profile = workflow(base)
    router = WorkflowRouter(prepared.settings)
    with TestClient(application(router)) as client:
        yield SimpleNamespace(client=client, router=router, profile=profile,
                              settings=prepared.settings, root=prepared.settings.jobs_root / JOB)


def post(api, endpoint, value=None):
    return api.client.post(endpoint, headers=HEADERS, json={} if value is None else value)


def get(api, endpoint):
    return api.client.get(endpoint, headers=HEADERS)


def stage_and_review(api, *, bom=False, aggregate=True):
    source, plan = snapshot(bom=bom)
    assert post(api, BASE, source).status_code == 201
    inspected = post(api, BASE + "/actions/inspect")
    assert inspected.status_code == 200, inspected.text
    inspection = inspected.json()
    request = {"job_id": JOB, "source_hash": source["source_hash"], "form_reviews": []}
    for row in inspection["forms"]:
        response = post(api, BASE + "/reviews/" + row["module_id"], form_payload(api.root, row, api.profile))
        assert response.status_code == 200, response.text
        proof = response.json()
        assert proof["verdict"] == "approve"
        request["form_reviews"].append({"module_id": row["module_id"], "receipt_sha256": proof["receipt_sha256"]})
    response = post(api, BASE + "/review", request) if aggregate else None
    if aggregate:
        assert response.status_code == 200, response.text
        assert response.json()["verdict"] == "approve"
    return source, plan, inspection, request, None if response is None else response.json()


def external_boundaries(api, monkeypatch, project):
    """Keep workflow, durable SQLcl receipts, bootstrap and release code real."""
    w, root = api.router.project, api.root
    database, calls, application_ids, preflights = Database(), [], [], []
    alias = alias_for_job(JOB)
    def preflight(job_id, action):
        assert job_id == JOB
        binding = w.assert_artifact_binding(job_id)
        name = f"target-check-{action}-{len(preflights):016x}.json"
        preflights.append(action)
        raw = project_release._bytes({"artifact_binding": binding, "test_boundary": action})
        (root / name).write_bytes(raw)
        return {"file": name, "sha256": hashlib.sha256(raw).hexdigest(), "action": action}
    monkeypatch.setattr(w, "native_target_preflight", preflight)
    monkeypatch.setattr(w, "assert_native_preflight_fresh", lambda *args: None)
    def transport(path, arguments, commands, cwd, **kwargs):
        script = "\n".join(commands)
        if "apex validate " in script:
            calls.append("compile")
            output = "Validation successful"
        elif "F2A_ALIAS_COUNT=" in script:
            calls.append("allocate_import")
            output = "F2A_ALIAS_COUNT=0"
        elif "apex import -input" in script:
            calls.append("import")
            assert len(database.ddl) == len({form["native_form"]["table_name"] for form in project["forms"]})
            assert "FOX reserved application already exists" in script
            application_ids.append(int(re.search(r" -id (\d+)", script).group(1)))
            output = "Import successful"
        elif "apex export " in script:
            calls.append("capture" if "F2A_CAPTURE_IDENTITY=" in script else "export")
            for name, content in native_project.render_native_project(project).items():
                destination = cwd / alias.lower() / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content.encode())
            if "-exptype SQL" in script:
                (cwd / f"f{application_ids[0]}.sql").write_text("-- synthetic SQLcl transport boundary\n" + "x" * 1200)
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
            pytest.fail("Unexpected SQLcl transport boundary")
        return subprocess.CompletedProcess(arguments, 0, output, "")
    monkeypatch.setattr(sqlcl, "_run_script", transport)
    monkeypatch.setattr(project_release, "_run_script", transport)
    monkeypatch.setattr("forms2apex.schema_bootstrap.SqlclSchemaExecutor", lambda: database)
    monkeypatch.setattr("forms2apex.project_workflow.runtime_login_check", lambda url: {"passed": True})
    monkeypatch.setattr(release, "runtime_login_check", lambda url: {"passed": True})
    return SimpleNamespace(database=database, calls=calls, application_ids=application_ids, preflights=preflights)


@pytest.mark.parametrize("method,path", [
    ("GET", "/fox/capabilities"), ("GET", "/fox/target-profile"),
    ("POST", BASE), ("GET", BASE), ("POST", BASE + "/review"),
    ("POST", BASE + "/reviews/form-" + "a" * 20),
    ("POST", BASE + "/actions/inspect"), ("POST", BASE + "/actions/generate"),
    ("POST", BASE + "/actions/validate"), ("POST", BASE + "/actions/prepare-schema"),
    ("POST", BASE + "/actions/reconcile-schema"), ("POST", BASE + "/actions/import"),
    ("POST", BASE + "/actions/reconcile-import"), ("POST", BASE + "/release"),
    ("GET", BASE + "/package"),
])
def test_every_project_route_checks_bearer_before_work(api, method, path):
    result = api.client.request(method, path, headers={"Authorization": "Bearer wrong"}, json={})
    assert result.status_code == 401
    assert not api.root.exists()


def test_installed_capability_is_exact_and_no_customer_source(api):
    result = get(api, "/fox/capabilities")
    assert result.status_code == 200
    assert result.json() == {"schema_version": 1,
        "conversion_profiles": ["read-only-html-prototype", "native-table-form-v1", "native-project-v1"],
        "project_protocol": "native-project-v1", "schema_preparation": True,
        "project_mapping": {"native_project_schema_versions": [1, 2],
            "storage_mapping_scope": "fox-project-storage-v1",
            "module_execution_scope": "fox-project-module-execution-v2", "paired_profile_ready": False}}


def test_actual_fastmcp_http_server_requires_auth_and_preserves_five_tools(api, monkeypatch):
    """Exercise the production server, not only custom routes or an in-memory MCP client."""
    from forms2apex.config import Settings
    monkeypatch.setattr(Settings, "from_env", classmethod(lambda cls: api.settings))
    path = Path(__file__).resolve().parents[1] / "forms2apex/server.py"
    spec = importlib.util.spec_from_file_location("forms2apex._gateway_auth_contract_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    app = module.mcp.http_app(path="/mcp", json_response=True)
    routes = [(method, "/mcp") for method in ("GET", "POST", "DELETE")]
    routes += [("GET", "/fox/capabilities"), ("GET", "/fox/target-profile"),
               ("POST", BASE), ("GET", BASE), ("POST", BASE + "/review"),
               ("POST", BASE + "/reviews/form-" + "a" * 20),
               ("POST", BASE + "/release"), ("GET", BASE + "/package")]
    routes += [("POST", BASE + "/actions/" + action) for action in
               ("inspect", "generate", "validate", "prepare-schema", "reconcile-schema", "import", "reconcile-import")]
    with TestClient(app) as client:
        for token in (None, "wrong"):
            headers = {"Accept": "application/json, text/event-stream"}
            if token is not None:
                headers["Authorization"] = "Bearer " + token
            for method, path in routes:
                response = client.request(method, path, headers=headers, json={})
                assert response.status_code == 401, (method, path, response.text)
        headers = {**HEADERS, "Accept": "application/json, text/event-stream"}
        response = client.post("/mcp", headers=headers, json={
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                       "clientInfo": {"name": "synthetic-contract-test", "version": "1"}}})
        assert response.status_code == 200, response.text
        headers["Mcp-Session-Id"] = response.headers["mcp-session-id"]
        response = client.post("/mcp", headers=headers,
            json={"jsonrpc": "2.0", "method": "notifications/initialized"})
        assert response.status_code == 202, response.text
        response = client.post("/mcp", headers=headers,
            json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        assert response.status_code == 200, response.text
        assert {tool["name"] for tool in response.json()["result"]["tools"]} == {
            "inspect_forms_job", "generate_apex_draft", "validate_apex_draft",
            "import_validated_draft", "get_job_status"}
        response = client.get("/fox/capabilities", headers=HEADERS)
        assert response.status_code == 200
        assert response.json()["project_protocol"] == "native-project-v1"
        assert response.json()["schema_preparation"] is True
    assert not list(api.settings.jobs_root.iterdir())


@pytest.mark.parametrize("change", ["unknown_profile", "omitted_form", "plan_changed", "unsafe_source"])
def test_invalid_project_source_rejected_atomically_without_echo(api, change):
    value, _ = snapshot()
    marker = "SOURCE_PRIVACY_MARKER_7391"
    if change == "unknown_profile": value["conversion_profile"] = "unrecognized-v9"
    elif change == "omitted_form": value["native_project"]["forms"].pop()
    elif change == "plan_changed": value["plan_sha256"] = "0" * 64
    else: value["files"][0]["text"] += "<!-- password=" + marker + " -->"
    result = post(api, BASE, value)
    assert result.status_code == 422
    assert marker not in result.text and "FormModule" not in result.text
    assert not api.root.exists()
    assert not list(api.settings.jobs_root.iterdir())


@pytest.mark.parametrize("profile", ["legacy", "project"])
@pytest.mark.parametrize("entry", [None, [], "SOURCE_PRIVACY_MARKER_7391", 17])
def test_nonobject_source_entries_rejected_without_partial_intake(api, profile, entry):
    value, _ = snapshot()
    if profile == "legacy":
        value = {key: value[key] for key in ("source_hash", "files")}
    value["files"][0] = entry
    result = post(api, BASE, value)
    assert result.status_code == 422
    assert "SOURCE_PRIVACY_MARKER_7391" not in result.text
    assert not list(api.settings.jobs_root.iterdir())


@pytest.mark.parametrize("raw", [
    b'{"source_hash":"a","source_hash":"b"}',
    b'{"source_hash":NaN}', b'{"source_hash":Infinity}', b'{', b'[]',
])
def test_invalid_json_envelopes_are_rejected_before_staging(api, raw):
    result = api.client.post(BASE, headers=HEADERS, content=raw)
    assert result.status_code == 422
    assert not list(api.settings.jobs_root.iterdir())


def test_unknown_action_rejected_without_creating_job(api):
    assert post(api, BASE + "/actions/replace-existing-app").status_code == 404
    assert not api.root.exists()


def test_profile_dispatch_comes_from_intake_not_generation_candidate(api):
    source, _ = snapshot()
    assert post(api, BASE, source).status_code == 201
    assert post(api, BASE + "/actions/inspect").status_code == 200
    result = post(api, BASE + "/actions/generate", {"template_id": "other-profile", "prototype_html": "PRIVATE_HTML_MARKER"})
    assert result.status_code == 409
    assert "PRIVATE_HTML_MARKER" not in result.text
    assert not (api.root / "apexlang").exists()
    assert api.router.select(JOB) is api.router.project


@pytest.mark.parametrize("path,size", [
    (BASE, 1_000_001), (BASE + "/review", 256_001),
    (BASE + "/reviews/form-" + "a" * 20, 256_001),
    (BASE + "/actions/generate", 4_000_001),
    (BASE + "/actions/validate", 256_001),
])
def test_project_request_body_bounds_include_all_chunks(api, path, size):
    source, _ = snapshot()
    assert post(api, BASE, source).status_code == 201
    chunks = (b" " * (size // 2), b" " * (size - size // 2))
    result = api.client.post(path, headers=HEADERS, content=iter(chunks))
    assert result.status_code == 413
    assert get(api, BASE).json()["state"] == "INTAKE_READY"


def test_project_generate_limit_does_not_increase_legacy_action_limit(api):
    source, _ = snapshot()
    assert post(api, BASE, source).status_code == 201
    large = b" " * 256_001
    # Valid project selects the larger parser bound, then rejects empty JSON.
    assert api.client.post(BASE + "/actions/generate", headers=HEADERS, content=large).status_code == 409
    legacy_id = "fox-" + "8" * 20
    legacy_path = "/fox/jobs/" + legacy_id
    raw = '<FormModule Name="LEGACY"/>'
    sha = hashlib.sha256(raw.encode()).hexdigest()
    legacy = {"source_hash": hashlib.sha256(("legacy.xml:" + sha).encode()).hexdigest(),
              "files": [{"name": "legacy.xml", "text": raw, "sha256": sha}]}
    assert post(api, legacy_path, legacy).status_code == 201
    assert api.router.select(legacy_id) is api.router.legacy
    assert api.client.post(legacy_path + "/actions/generate", headers=HEADERS, content=large).status_code == 413
    assert post(api, legacy_path + "/actions/prepare-schema").status_code == 404


def test_each_form_review_is_required_and_immutable(api):
    source, plan, inspection, request, _ = stage_and_review(api, aggregate=False)
    omitted = deepcopy(request)
    omitted["form_reviews"].pop()
    assert post(api, BASE + "/review", omitted).status_code == 409
    assert not (api.root / "project-review.json").exists()
    approved = post(api, BASE + "/review", request)
    assert approved.status_code == 200
    assert approved.json()["candidate"]["native_project"] == source["native_project"]
    assert post(api, BASE + "/review", request).json() == approved.json()
    before = (api.root / "project-review.json").read_bytes()
    row = inspection["forms"][0]
    changed = form_payload(api.root, row, api.profile)
    changed["review"]["notes"] = "different review"
    assert post(api, BASE + "/reviews/" + row["module_id"], changed).status_code == 409
    assert (api.root / "project-review.json").read_bytes() == before


@pytest.mark.parametrize("action", ["prepare-schema", "reconcile-schema"])
def test_schema_actions_fail_closed_when_target_preflight_rejects(api, monkeypatch, action):
    source, _, _, _, aggregate = stage_and_review(api)
    assert post(api, BASE + "/actions/generate", aggregate["candidate"]).status_code == 200
    boundary = external_boundaries(api, monkeypatch, source["native_project"])
    assert post(api, BASE + "/actions/validate").json()["passed"] is True
    calls = list(boundary.calls)
    attempted = []
    def reject_target(job_id, selected_action):
        attempted.append((job_id, selected_action))
        raise RuntimeError("SYNTHETIC_PRIVATE_TARGET_DIAGNOSTIC")
    monkeypatch.setattr(api.router.project, "native_target_preflight", reject_target)
    result = post(api, BASE + "/actions/" + action)
    assert result.status_code == 409
    assert "SYNTHETIC_PRIVATE_TARGET_DIAGNOSTIC" not in result.text
    assert attempted == [(JOB, action)]
    assert boundary.calls == calls and boundary.database.ddl == []
    state = get(api, BASE).json()
    assert state["state"] == "VALID"
    assert state["schema_intent_exists"] is False and state["import_intent_exists"] is False


@pytest.mark.parametrize("bom", [False, True])
def test_complete_asgi_project_lifecycle_exports_one_verified_package(api, monkeypatch, bom):
    source, _, inspection, _, aggregate = stage_and_review(api, bom=bom)
    if bom:
        assert all((api.root / "intake" / item["name"]).read_bytes().startswith(b"\xef\xbb\xbf") for item in source["files"])
    assert post(api, BASE + "/actions/inspect").json() == inspection
    status = get(api, BASE)
    assert status.status_code == 200
    assert status.json()["native_project"] == source["native_project"]
    assert "readable_source" not in status.text and "<FormModule" not in status.text
    assert status.json()["schema_intent_exists"] is False and status.json()["import_intent_exists"] is False
    generated = post(api, BASE + "/actions/generate", aggregate["candidate"])
    assert generated.status_code == 200, generated.text
    assert generated.json()["application_count"] == 1 and generated.json()["form_count"] == 2
    binding = get(api, BASE).json()["artifact_binding"]
    assert binding["template_id"] == native_project.TEMPLATE_ID
    boundary = external_boundaries(api, monkeypatch, source["native_project"])
    assert post(api, BASE + "/actions/validate").json()["passed"] is True
    assert post(api, BASE + "/actions/import").status_code == 409
    assert not (api.root / "import-intent.json").exists()
    preparation = post(api, BASE + "/actions/prepare-schema")
    assert preparation.status_code == 200, preparation.text
    assert preparation.json()["state"] == "READY" and len(boundary.database.ddl) == 2
    state = get(api, BASE).json()
    assert state["schema_preparation"]["state"] == "READY"
    assert state["schema_intent_exists"] is True and state["import_intent_exists"] is False
    reconciliation = post(api, BASE + "/actions/reconcile-schema")
    assert reconciliation.status_code == 200 and reconciliation.json()["ready_for_import"] is True
    assert reconciliation.json()["database_writes"] is False
    imported = post(api, BASE + "/actions/import")
    assert imported.status_code == 200, imported.text
    assert boundary.calls.count("import") == 1
    assert get(api, BASE).json()["import_intent_exists"] is True
    assert post(api, BASE + "/actions/import").status_code == 409
    released = post(api, BASE + "/release")
    assert released.status_code == 200, released.text
    evidence = released.json()
    assert evidence["application_count"] == 1 and evidence["package_reimport_passed"] is True
    assert evidence["authenticated_runtime_passed"] is False and evidence["clean_schema_install_passed"] is False
    assert evidence["human_acceptance_recorded"] is False and boundary.calls.count("reimport") == 1
    download = get(api, BASE + "/package")
    assert download.status_code == 200 and download.headers["content-type"] == "application/zip"
    checked = project_release.validate_project_package(download.content, expected_project=source["native_project"], expected_evidence=evidence)
    assert checked["trace"]["form_count"] == 2
    calls = list(boundary.calls)
    assert post(api, BASE + "/release").json() == evidence
    assert get(api, BASE + "/package").content == download.content
    assert boundary.calls == calls
    (api.root / "apex-package.zip").write_bytes(download.content + b"tampered")
    assert get(api, BASE + "/package").status_code == 409
