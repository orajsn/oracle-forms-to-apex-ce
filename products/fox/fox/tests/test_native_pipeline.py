"""Synthetic, fully mocked native orchestration tests; never contact a service.

These prove orchestration contracts/recovery, not live SQLcl or browser behavior.
The converter's receipt verifier has its own separate tests.
"""

from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import stat
import warnings
import zipfile

import pytest

from fox import native_pipeline as pipeline
from fox.intake import checked_source, inventory
from fox.native_source import assess_native_source
from fox.opaf import OpafClient as ProtocolClient, OpafError, canonical_hash


FIXTURES = Path(__file__).parent / "fixtures"
TEST_SECRET_MARKER = "synthetic-not-a-live-password"
SYNTHETIC_SQL = b"-- Synthetic unit-test export only; not an executable APEX export\n" * 25


def write_json(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def package_bytes(members, *, manifest=None, additions=()):
    """Build local adversarial ZIP fixtures without extracting any member."""
    if manifest is None:
        manifest = {name: hashlib.sha256(raw).hexdigest() for name, raw in members.items()}
    output = io.BytesIO()
    def member_name(name):
        if isinstance(name, zipfile.ZipInfo):
            return name
        info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        return info
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, raw in members.items():
                archive.writestr(member_name(name), raw)
            archive.writestr(member_name("manifest.json"), json.dumps(manifest))
            for name, raw in additions:
                archive.writestr(member_name(name), raw)
    return output.getvalue()


class NativeHarness:
    def __init__(self, tmp_path, monkeypatch):
        self.job = tmp_path / ("fox-" + "a" * 20)
        self.job.mkdir()
        files = [checked_source(name, (FIXTURES / name).read_bytes())
                 for name in ("native-beta.xml", "native-beta.sql")]
        assessed = assess_native_source(files)
        assert assessed["state"] == "READY"
        self.snapshot = {"files": files, "source_hash": inventory(files)["source_hash"],
                         "conversion_profile": pipeline.PROFILE_ID, "native_form": assessed["native_form"],
                         "approvals": {"redacted_source": True, "external_ai": True, "synthetic_prototype": True}}
        write_json(self.job / "source-snapshot.json", self.snapshot)
        self.profile = {
            "schema_version": 1, "profile_id": pipeline.PROFILE_ID,
            "opaf_base_url": "https://localhost:8080/agentFactory", "certificate_sha256": "1" * 64,
            "mapper": {"workflow_id": "A" * 32, "model": "xai.grok-4.3", "graph_sha256": "2" * 64},
            "reviewer": {"workflow_id": "B" * 32, "model": "xai.grok-4.3", "graph_sha256": "3" * 64},
        }
        self.profile_path = tmp_path / "native-profile.json"
        self.target_profile = json.loads((Path(__file__).resolve().parents[2] / 'deployment/target-profile.jsn.json').read_text())
        self.target_profile['opaf'].update(base_url=self.profile['opaf_base_url'],certificate_sha256=self.profile['certificate_sha256'],
            roles={name:deepcopy(self.profile[name]) for name in ('mapper','reviewer')})
        self.target_profile_requests = 0
        self.credentials_path = tmp_path / "synthetic-credentials.json"
        write_json(self.profile_path, self.profile)
        write_json(self.credentials_path, {"username": "synthetic-user", "password": TEST_SECRET_MARKER,
                                           "converter_token": "x" * 48})
        monkeypatch.setenv("FOX_NATIVE_PROFILE_FILE", str(self.profile_path))
        monkeypatch.setenv("FOX_OPAF_CREDENTIAL_FILE", str(self.credentials_path))
        monkeypatch.setenv("FOX_CONVERTER_URL", "http://127.0.0.1:8091")
        original_temporary_directory = pipeline.tempfile.TemporaryDirectory
        monkeypatch.setattr(pipeline.tempfile, "TemporaryDirectory", lambda **kwargs:
                            original_temporary_directory(dir=tmp_path, **kwargs))
        self.calls = []
        self.model_calls = []
        self.client_constructions = 0
        self.gateway_constructions = 0
        self.state = None
        self.fail_before = {}
        self.fail_after = {}
        self.responses = {}
        self.model_failures = {}
        self.model_outputs = {}
        self.validation_passed = True
        self.reconcile_can_confirm = False
        self.receipt = None
        self.sealed = None
        self.review_payload = None
        self.package_override = None
        self.evidence_changes = {}
        self.path = "/fox/jobs/" + self.job.name
        harness = self

        class FakeOpaf:
            def __init__(self, *args):
                harness.client_constructions += 1

            def invoke(self, role, request):
                return harness.invoke(role, request)

            def invoke_with_environment(self, role, request, *, role_name, target_profile):
                output, invocation = harness.invoke(role, request)
                opaf=target_profile['opaf']
                environment={'schema_version':1,'scope':'opaf-model-environment-v1',
                    'trust_boundary':'authenticated_fox_executor_not_vendor_attestation',
                    'job_id':request['job_id'],'role':role_name,'source_manifest_sha256':request['source_hash'],
                    'target_profile_sha256':canonical_hash(target_profile),'observed_at_utc':invocation['started_at_utc'],
                    'opaf':{key:opaf[key] for key in ('base_url','certificate_sha256','model_authentication','version_number','build_id')},
                    'workflow':{**role,'published':True},'opaf_version':target_profile['tested_versions']['opaf']}
                return output, invocation, environment

        class FakeGateway:
            def __init__(self, *args):
                harness.gateway_constructions += 1

            def request(self, method, path, payload=None, binary=False):
                return harness.request(method, path, payload, binary)

        monkeypatch.setattr(pipeline, "OpafClient", FakeOpaf)
        monkeypatch.setattr(pipeline, "ConverterClient", FakeGateway)

    @property
    def checkpoints(self):
        return self.job / "native-pipeline"

    def run(self):
        return pipeline.run_native_job(self.job)

    def counts(self, action):
        return sum(call[0] == action for call in self.calls)

    def remote(self, state):
        return {"job_id": self.job.name, "source_manifest_sha256": self.snapshot["source_hash"],
                "conversion_profile": pipeline.PROFILE_ID, "native_form": deepcopy(self.snapshot["native_form"]),
                "state": state}

    def candidate(self):
        return {"job_id": self.job.name, "template_id": pipeline.TEMPLATE_ID,
                "data_classification": "synthetic_or_stub_only", "generator": {"model": self.profile["mapper"]["model"]},
                "native_form": deepcopy(self.snapshot["native_form"]), "remediation_items": [],
                "mapping_summary": "One synthetic native report/form with explicit schema and no business code."}

    def invoke(self, role, request):
        name = "mapper" if role == self.profile["mapper"] else "reviewer"
        assert role == self.profile[name]
        self.model_calls.append((name, deepcopy(request)))
        if name in self.model_failures:
            raise self.model_failures.pop(name)
        output = (self.candidate() if name == "mapper" else
                  {"verdict": "approve", "candidate_sha256": canonical_hash(request["candidate"]),
                   "notes": ["Separate review of pinned metadata", "No unsupported logic inferred"],
                   "blocking_findings": []})
        output = deepcopy(self.model_outputs.get(name, output))
        response = {"roomId": "synthetic-" + name, "message": output}
        invocation = {**role, "room_id": response["roomId"], "request_sha256": canonical_hash(request),
                      "response_sha256": canonical_hash(response),
                      "started_at_utc": "2026-10-16T00:00:" + ("00Z" if name == "mapper" else "11Z"),
                      "completed_at_utc": "2026-10-16T00:00:" + ("10Z" if name == "mapper" else "20Z")}
        return output, invocation

    def evidence(self):
        return {"job_id": self.job.name, "source_manifest_sha256": self.snapshot["source_hash"],
                "conversion_profile": pipeline.PROFILE_ID, "reviewer_execution_verified": True,
                "review_receipt_sha256": self.sealed["receipt_sha256"],
                **self.import_identity(),
                "package_reimport": {"passed": True, "application_id": 23456,
                                     "application_alias": "F2A_NATIVE_UNIT_TEST_SQLCHECK",
                                     "sql_sha256": hashlib.sha256(SYNTHETIC_SQL).hexdigest()},
                **self.evidence_changes}

    def import_identity(self):
        return {"application_id": 12345, "application_alias": "F2A_NATIVE_UNIT_TEST",
                "application_url": "https://apex.example.invalid/ords/r/test/f2a_native_unit_test/",
                "artifact_binding": {"source_sha256": self.snapshot["source_hash"], "draft_sha256": "d" * 64}}

    def members(self):
        members = {"sql/f12345.sql": SYNTHETIC_SQL,
                "apexlang/application.apx": b"// Synthetic unit-test project marker\n",
                "schema/01_synthetic_schema.sql": self.snapshot["files"][1]["text"].encode(),
                "native-form-spec.json": json.dumps(self.snapshot["native_form"], sort_keys=True).encode(),
                "evidence/native-review.json": json.dumps(self.receipt, sort_keys=True).encode(),
                "evidence/package-reimport.json": json.dumps(self.evidence()["package_reimport"], sort_keys=True).encode(),
                "evidence/export-validation.log": b"Synthetic mocked SQLcl validation only\n",
                "evidence/release-evidence.json": json.dumps(self.evidence(), sort_keys=True).encode()}
        if self.receipt['schema_version']==2:
            members['evidence/target-profile.json']=json.dumps(self.receipt['historical_target_profile'],
                sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
        evidence = self.evidence()
        completion = {"schema_version": 1, "job_id": self.job.name,
                      "application_id": evidence["application_id"], "application_alias": evidence["application_alias"],
                      "artifact_binding": evidence["artifact_binding"], "apexlang_validation_passed": True,
                      "files": {"f12345.sql": hashlib.sha256(members["sql/f12345.sql"]).hexdigest(),
                                evidence["application_alias"].lower() + "/application.apx": hashlib.sha256(members["apexlang/application.apx"]).hexdigest(),
                                "apexlang-validation.log": hashlib.sha256(members["evidence/export-validation.log"]).hexdigest()}}
        members["evidence/export-completion.json"] = json.dumps(completion, sort_keys=True).encode()
        return members

    def request(self, method, path, payload=None, binary=False):
        if path=='/fox/target-profile':
            assert method=='GET'
            self.target_profile_requests+=1
            return deepcopy(self.responses.get('target-profile',{'target_profile':self.target_profile,
                'target_profile_sha256':canonical_hash(self.target_profile)}))
        assert path.startswith(self.path)
        suffix = path[len(self.path):]
        action = ("get" if method == "GET" else "stage") if not suffix else suffix.split("/")[-1]
        self.calls.append((action, method, deepcopy(payload), binary))
        if action in self.fail_before:
            raise self.fail_before.pop(action)
        if action == "get":
            if self.state is None:
                raise OpafError("Synthetic missing job", 404)
            response = deepcopy(self.state)
        elif action == "stage":
            assert method == "POST"
            if self.state is not None:
                raise OpafError("Synthetic existing job", 409)
            assert payload == {key: self.snapshot[key] for key in ("source_hash", "files", "conversion_profile", "native_form")}
            self.state = self.remote("INTAKE_READY")
            response = {"job_id": self.job.name}
        elif action == "inspect":
            self.state["state"] = "INSPECTED"
            response = {"job_id": self.job.name, "modules": [{"file": "native-beta.xml"}], "remediation_items": []}
        elif action == "review":
            self.review_payload = deepcopy(payload)
            receipt = {**payload, "schema_version": 2 if 'model_environment' in payload else 1,
                       "trust_boundary": "authenticated_fox_executor_not_vendor_attestation",
                       "candidate_sha256": canonical_hash(payload["candidate"]), "intake_sha256": "f" * 64}
            if receipt['schema_version']==2:
                receipt['historical_target_profile']=deepcopy(self.target_profile)
            self.receipt = {**receipt, "receipt_sha256": canonical_hash(receipt)}
            self.sealed = {"verdict": payload["review"]["verdict"],
                           "candidate_sha256": canonical_hash(payload["candidate"]),
                           "receipt_sha256": self.receipt["receipt_sha256"]}
            response = deepcopy(self.sealed)
        elif action == "generate":
            assert self.sealed and self.sealed["verdict"] == "approve"
            assert payload == self.review_payload["candidate"]
            self.state["state"] = "DRAFTED"
            response = {"state": "DRAFTED"}
        elif action == "validate":
            self.state.update(state="VALID" if self.validation_passed else "INVALID",
                              validation={"passed": self.validation_passed})
            response = self.state["validation"]
        elif action == "import":
            assert self.state["state"] == "VALID" and self.state["validation"]["passed"] is True
            assert self.sealed["verdict"] == "approve"
            self.state.update(state="IMPORTED", import_intent_exists=True,
                              **{"import": self.import_identity()})
            response = self.state["import"]
        elif action == "reconcile-import":
            if not self.reconcile_can_confirm:
                raise OpafError("Synthetic target lacks complete evidence; no duplicate import")
            self.state.update(state="IMPORTED", import_intent_exists=True,
                              **{"import": self.import_identity()})
            response = self.state["import"]
        elif action == "release":
            assert self.state["state"] == "IMPORTED"
            response = self.evidence()
        elif action == "package":
            assert method == "GET" and binary is True
            response = self.package_override if self.package_override is not None else package_bytes(self.members())
        else:
            pytest.fail("Unexpected local fake gateway action: " + action)
        if action in self.fail_after:
            raise self.fail_after.pop(action)
        return deepcopy(self.responses.get(action, response))


@pytest.fixture
def harness(tmp_path, monkeypatch):
    return NativeHarness(tmp_path, monkeypatch)


def test_full_native_flow_orders_calls_and_binds_download(harness):
    evidence = harness.run()
    actions = [call[0] for call in harness.calls]
    assert actions == ["get", "stage", "get", "inspect", "review", "get", "generate", "get",
                       "validate", "get", "import", "get", "release", "package"]
    assert [name for name, _ in harness.model_calls] == ["mapper", "reviewer"]
    mapper_request = harness.model_calls[0][1]
    reviewer_request = harness.model_calls[1][1]
    assert mapper_request["native_form"] == harness.snapshot["native_form"]
    assert reviewer_request["candidate_sha256"] == canonical_hash(harness.candidate())
    assert harness.review_payload["reviewer_invocation"]["room_id"] != harness.review_payload["mapper_invocation"]["room_id"]
    assert "reviewer" not in harness.review_payload["candidate"]
    assert read_json(harness.job / "release-evidence.json") == evidence
    digest = hashlib.sha256((harness.job / "apex-package.zip").read_bytes()).hexdigest()
    assert read_json(harness.checkpoints / "download.json") == {"package_sha256": digest, "source_hash": harness.snapshot["source_hash"]}
    assert not list(harness.job.glob(".package-*"))


def test_finished_resume_reuses_models_import_and_exact_download(harness):
    evidence = harness.run()
    before = (harness.job / "apex-package.zip").read_bytes()
    assert harness.run() == evidence
    for action in ("stage", "inspect", "generate", "validate", "import"):
        assert harness.counts(action) == 1
    assert len(harness.model_calls) == 2
    assert (harness.job / "apex-package.zip").read_bytes() == before


@pytest.mark.parametrize("action", ["generate", "validate", "import", "release", "package"])
def test_resume_reconciles_remote_completion_without_duplicate_side_effect(harness, action):
    harness.fail_after[action] = OpafError("Synthetic uncertain response")
    with pytest.raises(OpafError, match="uncertain"):
        harness.run()
    assert harness.run()["application_id"] == 12345
    for stage in ("stage", "generate", "validate", "import"):
        assert harness.counts(stage) == 1
    assert len(harness.model_calls) == 2


@pytest.mark.parametrize("role", ["mapper", "reviewer"])
def test_uncertain_model_result_never_replays_inference(harness, role):
    harness.model_failures[role] = OpafError("Synthetic model timeout")
    with pytest.raises(OpafError, match="timeout"):
        harness.run()
    assert (harness.checkpoints / (role + "-intent.json")).is_file()
    attempts = len(harness.model_calls)
    with pytest.raises(OpafError, match="uncertain result"):
        harness.run()
    assert len(harness.model_calls) == attempts
    assert harness.counts("generate") == harness.counts("import") == 0


def test_uncertain_import_without_remote_completion_is_never_replayed(harness):
    harness.fail_before["import"] = OpafError("Synthetic import transport loss")
    with pytest.raises(OpafError, match="transport loss"):
        harness.run()
    assert harness.state["state"] == "VALID"
    assert (harness.checkpoints / "import-intent.json").is_file()
    with pytest.raises(OpafError, match="no duplicate import"):
        harness.run()
    assert harness.counts("import") == 1 and len(harness.model_calls) == 2
    assert harness.counts("release") == 0


def test_converter_import_intent_blocks_local_missing_intent_replay(harness):
    harness.fail_before["import"] = OpafError("Synthetic lost request")
    with pytest.raises(OpafError):
        harness.run()
    (harness.checkpoints / "import-intent.json").unlink()
    harness.state["import_intent_exists"] = True
    with pytest.raises(OpafError, match="no duplicate import"):
        harness.run()
    assert harness.counts("import") == 1


def test_durable_remote_import_can_reconcile_without_reimport(harness):
    harness.fail_before["import"] = OpafError("Synthetic uncertain receipt")
    with pytest.raises(OpafError):
        harness.run()
    harness.reconcile_can_confirm = True
    assert harness.run()["application_id"] == 12345
    assert harness.counts("reconcile-import") == 1
    assert harness.counts("import") == 1 and len(harness.model_calls) == 2


@pytest.mark.parametrize("confirmed", [True, False])
def test_failed_remote_import_only_uses_readonly_reconciliation(harness, confirmed):
    harness.fail_before["import"] = OpafError("Synthetic interrupted import")
    with pytest.raises(OpafError):
        harness.run()
    harness.state.update(state="FAILED", import_intent_exists=True)
    harness.reconcile_can_confirm = confirmed
    if confirmed:
        assert harness.run()["application_id"] == 12345
    else:
        with pytest.raises(OpafError, match="no duplicate import"):
            harness.run()
    assert harness.counts("reconcile-import") == 1
    assert harness.counts("import") == 1 and len(harness.model_calls) == 2


@pytest.mark.parametrize("state", ["FAILED", "INVALID", "IMPORTING", "UNKNOWN"])
def test_unsafe_remote_states_are_not_reset_or_replayed(harness, state):
    harness.state = harness.remote(state)
    with pytest.raises(OpafError, match="reconciliation"):
        harness.run()
    assert not harness.model_calls and harness.counts("stage") == 0


@pytest.mark.parametrize("state", ["DRAFTED", "VALID", "IMPORTED"])
def test_missing_local_inspection_for_existing_draft_is_not_invented(harness, state):
    harness.state = harness.remote(state)
    with pytest.raises(OpafError, match="inspection checkpoint is absent"):
        harness.run()
    assert not harness.model_calls and harness.counts("inspect") == 0


@pytest.mark.parametrize("field,value", [("job_id", "other-job"), ("source_manifest_sha256", "0" * 64),
                                          ("conversion_profile", "html"), ("native_form", {})])
def test_remote_identity_must_match_exact_approved_source(harness, field, value):
    harness.state = harness.remote("INTAKE_READY")
    harness.state[field] = value
    with pytest.raises(OpafError, match="identity differs"):
        harness.run()
    assert not harness.model_calls


def test_transient_get_failure_does_not_assume_missing_job(harness):
    harness.fail_before["get"] = OpafError("Synthetic service unavailable", 503)
    with pytest.raises(OpafError, match="unavailable"):
        harness.run()
    assert harness.counts("stage") == 0 and not harness.model_calls


def test_changed_source_bytes_are_rejected_before_network(harness):
    snapshot = deepcopy(harness.snapshot)
    snapshot["files"][0]["text"] += "\n<!-- altered -->"
    write_json(harness.job / "source-snapshot.json", snapshot)
    with pytest.raises((OpafError, ValueError), match="changed"):
        harness.run()
    assert not harness.calls and not harness.model_calls


@pytest.mark.parametrize("approval", ["redacted_source", "external_ai", "synthetic_prototype"])
@pytest.mark.parametrize("value", [False, "true", 1, None])
def test_missing_or_nonboolean_approval_blocks_before_any_remote_call(harness, approval, value):
    snapshot = deepcopy(harness.snapshot)
    snapshot["approvals"][approval] = value
    write_json(harness.job / "source-snapshot.json", snapshot)
    with pytest.raises(OpafError, match="approvals are required"):
        harness.run()
    assert not harness.calls and not harness.model_calls


def test_freshly_rehashed_source_cannot_reuse_completed_job(harness):
    harness.run()
    snapshot = deepcopy(harness.snapshot)
    raw = (snapshot["files"][0]["text"] + "\n<!-- reapproved change -->").encode()
    snapshot["files"][0] = checked_source(snapshot["files"][0]["name"], raw)
    snapshot["source_hash"] = inventory(snapshot["files"])["source_hash"]
    write_json(harness.job / "source-snapshot.json", snapshot)
    previous = len(harness.calls)
    with pytest.raises(OpafError, match="checkpoint differs"):
        harness.run()
    assert len(harness.calls) == previous and len(harness.model_calls) == 2


def test_changed_approved_native_spec_is_rejected_before_network(harness):
    snapshot = deepcopy(harness.snapshot)
    snapshot["native_form"]["columns"][1]["length"] += 1
    write_json(harness.job / "source-snapshot.json", snapshot)
    with pytest.raises(OpafError, match="assessment is blocked or has changed"):
        harness.run()
    assert not harness.calls and not harness.model_calls


def test_changed_profile_cannot_reuse_checkpoint(harness):
    harness.run()
    profile = deepcopy(harness.profile)
    profile["reviewer"]["graph_sha256"] = "4" * 64
    write_json(harness.profile_path, profile)
    previous = len(harness.calls)
    with pytest.raises(OpafError, match="checkpoint differs"):
        harness.run()
    assert len(harness.calls) == previous and len(harness.model_calls) == 2


@pytest.mark.parametrize("field,value", [("template_id", "html-template"), ("job_id", "other-job"),
                                          ("native_form", {}), ("mapping_summary", ""),
                                          ("generator", {"model": "other-model"}), ("reviewer", {"verdict": "approve"})])
def test_bad_mapper_candidate_cannot_reach_reviewer_or_generate(harness, field, value):
    candidate = harness.candidate()
    candidate[field] = value
    harness.model_outputs["mapper"] = candidate
    with pytest.raises(OpafError, match="Mapper output"):
        harness.run()
    assert [name for name, _ in harness.model_calls] == ["mapper"]
    assert harness.counts("generate") == 0


@pytest.mark.parametrize("role", ["mapper", "reviewer"])
def test_changed_role_checkpoint_is_not_silently_reused(harness, role):
    harness.run()
    path = harness.checkpoints / (role + ".json")
    saved = read_json(path)
    saved["output"]["mapping_summary" if role == "mapper" else "notes"] = "Tampered checkpoint"
    write_json(path, saved)
    with pytest.raises(OpafError, match="role checkpoint changed"):
        harness.run()
    assert len(harness.model_calls) == 2 and harness.counts("import") == 1


def test_changed_local_review_receipt_is_not_overwritten(harness):
    harness.run()
    path = harness.checkpoints / "review-receipt.json"
    receipt = read_json(path)
    receipt["receipt_sha256"] = "9" * 64
    write_json(path, receipt)
    with pytest.raises(OpafError, match="checkpoint differs"):
        harness.run()
    assert read_json(path) == receipt and harness.counts("import") == 1


@pytest.mark.parametrize("sealed", [
    {"verdict": "reject", "candidate_sha256": "0" * 64, "receipt_sha256": "1" * 64},
    {"verdict": "approve", "candidate_sha256": "0" * 64, "receipt_sha256": "1" * 64},
])
def test_reviewer_rejection_or_candidate_mismatch_cannot_generate(harness, sealed):
    harness.responses["review"] = sealed
    with pytest.raises(OpafError, match="did not approve"):
        harness.run()
    assert harness.counts("generate") == harness.counts("import") == 0


def test_failed_validation_cannot_import(harness):
    harness.validation_passed = False
    with pytest.raises(OpafError, match="validation has not passed"):
        harness.run()
    assert harness.counts("import") == harness.counts("release") == 0


@pytest.mark.parametrize("value", [1, "false", "true", None, [], {}])
def test_validation_requires_exact_boolean_true_before_import(harness, value):
    harness.validation_passed = value
    with pytest.raises(OpafError, match="validation has not passed"):
        harness.run()
    assert harness.counts("import") == harness.counts("release") == 0


@pytest.mark.parametrize("field,value", [("job_id", "other-job"), ("source_manifest_sha256", "0" * 64),
                                          ("conversion_profile", "other-profile"), ("reviewer_execution_verified", False),
                                          ("review_receipt_sha256", "0" * 64)])
def test_unbound_release_evidence_cannot_download(harness, field, value):
    harness.evidence_changes[field] = value
    with pytest.raises(OpafError, match="not bound"):
        harness.run()
    assert harness.counts("package") == 0 and not (harness.job / "apex-package.zip").exists()


@pytest.mark.parametrize("field,value", [("application_id", 99999), ("application_alias", "OTHER_APPLICATION")])
def test_release_identity_must_match_confirmed_import_before_download(harness, field, value):
    harness.evidence_changes[field] = value
    with pytest.raises(OpafError):
        harness.run()
    assert harness.counts("package") == 0
    assert not (harness.job / "apex-package.zip").exists()


def test_changed_downloaded_package_is_preserved_and_blocks_resume(harness):
    harness.run()
    path = harness.job / "apex-package.zip"
    path.write_bytes(b"Changed local package")
    with pytest.raises(OpafError, match="package differs"):
        harness.run()
    assert path.read_bytes() == b"Changed local package"
    assert harness.counts("import") == 1 and len(harness.model_calls) == 2


@pytest.mark.parametrize("value", [[], None, 1, "not-an-object", {}, {"username": "u", "password": TEST_SECRET_MARKER}])
def test_malformed_credentials_never_leak_or_contact_services(harness, value, caplog):
    write_json(harness.credentials_path, value)
    with pytest.raises(OpafError, match="protected credentials are unavailable") as failure:
        harness.run()
    assert TEST_SECRET_MARKER not in str(failure.value) + caplog.text
    assert not harness.calls and not harness.model_calls and harness.gateway_constructions == 0


def test_unparseable_credentials_never_expose_parser_excerpt(harness, caplog):
    harness.credentials_path.write_text('{"password": "' + TEST_SECRET_MARKER + '" BROKEN}')
    with pytest.raises(OpafError, match="protected credentials are unavailable") as failure:
        harness.run()
    assert TEST_SECRET_MARKER not in str(failure.value) + caplog.text
    assert not harness.calls


@pytest.mark.parametrize("name", ["FOX_NATIVE_PROFILE_FILE", "FOX_OPAF_CREDENTIAL_FILE", "FOX_CONVERTER_URL"])
def test_missing_configuration_fails_closed(harness, monkeypatch, name):
    monkeypatch.delenv(name)
    with pytest.raises(OpafError, match="configuration or protected credentials"):
        harness.run()
    assert not harness.calls and not harness.model_calls


def test_interrupted_local_package_publish_resumes_without_remote_import(harness, monkeypatch):
    original_link = pipeline.os.link
    package = harness.job / "apex-package.zip"
    def interrupted(source, target, *args, **kwargs):
        if Path(target) == package:
            raise OSError("Synthetic local package publication interruption")
        return original_link(source, target, *args, **kwargs)
    monkeypatch.setattr(pipeline.os, "link", interrupted)
    with pytest.raises(OSError, match="publication interruption"):
        harness.run()
    assert not package.exists() and not list(harness.job.glob(".package-*"))
    assert not (harness.job / "release-evidence.json").exists()
    monkeypatch.setattr(pipeline.os, "link", original_link)
    assert harness.run()["application_id"] == 12345
    assert harness.counts("import") == 1 and len(harness.model_calls) == 2


@pytest.fixture
def valid_package(harness):
    # Package-specific negatives do not need to repeat filesystem staging and
    # the complete orchestration already exercised above.
    request = {"job_id": harness.job.name, "native_form": harness.snapshot["native_form"]}
    candidate, mapper = harness.invoke(harness.profile["mapper"], request)
    review_request = {**request, "candidate": candidate}
    review, reviewer = harness.invoke(harness.profile["reviewer"], review_request)
    harness.request("POST", harness.path + "/review", {
        "job_id": harness.job.name, "source_hash": harness.snapshot["source_hash"], "candidate": candidate,
        "mapper_invocation": mapper, "reviewer_invocation": reviewer, "review": review})
    return harness.members(), harness.evidence(), harness.snapshot["native_form"]


def test_package_verifier_accepts_exact_bytes_without_extracting(valid_package, tmp_path):
    members, evidence, native = valid_package
    raw = package_bytes(members)
    assert pipeline.verify_package(raw, evidence, native) == hashlib.sha256(raw).hexdigest()
    assert not (tmp_path / "sql").exists()


@pytest.mark.parametrize("name", ["../escape.sql", "/absolute.sql", "C:stream.sql", "folder\\file.sql",
                                    "folder//file.sql", "./file.sql", "folder/../file.sql", "folder/"])
def test_package_rejects_unsafe_paths(valid_package, name):
    members, evidence, native = valid_package
    members[name] = b"untrusted"
    # Windows ZIP readers may normalize a backslash before exposing filename;
    # exact manifest matching must still reject that altered path.
    with pytest.raises(OpafError):
        pipeline.verify_package(package_bytes(members), evidence, native)


def test_package_rejects_symlink_member(valid_package):
    members, evidence, native = valid_package
    info = zipfile.ZipInfo("linked.sql")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    with pytest.raises(OpafError, match="Unsafe native package member"):
        pipeline.verify_package(package_bytes(members, additions=[(info, b"../outside")]), evidence, native)


def test_package_rejects_encrypted_member_flag(valid_package):
    members, evidence, native = valid_package
    raw = bytearray(package_bytes(members))
    # zipfile deliberately does not write encrypted archives; mark the ZIP
    # headers locally to exercise fail-closed rejection before reading data.
    for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        cursor = raw.find(signature)
        while cursor >= 0:
            raw[cursor + offset] |= 1
            cursor = raw.find(signature, cursor + 4)
    with pytest.raises(OpafError, match="Unsafe native package member"):
        pipeline.verify_package(bytes(raw), evidence, native)


def test_package_rejects_duplicate_members(valid_package):
    members, evidence, native = valid_package
    name = next(iter(members))
    with pytest.raises(OpafError, match="structure"):
        pipeline.verify_package(package_bytes(members, additions=[(name, b"duplicate")]), evidence, native)


@pytest.mark.parametrize("digest", ["0" * 64, "A" * 64, "not-a-hash", None, 1])
def test_package_rejects_corrupt_or_invalid_member_hash(valid_package, digest):
    members, evidence, native = valid_package
    manifest = {name: hashlib.sha256(raw).hexdigest() for name, raw in members.items()}
    manifest[next(iter(members))] = digest
    with pytest.raises(OpafError, match="integrity"):
        pipeline.verify_package(package_bytes(members, manifest=manifest), evidence, native)


@pytest.mark.parametrize("manifest", [[], None, {}, {"ghost.sql": "0" * 64}])
def test_package_rejects_incomplete_or_nonobject_manifest(valid_package, manifest):
    members, evidence, native = valid_package
    raw = package_bytes(members, manifest=manifest if manifest is not None else [])
    with pytest.raises(OpafError, match="manifest is incomplete"):
        pipeline.verify_package(raw, evidence, native)


@pytest.mark.parametrize("member", ["evidence/release-evidence.json", "native-form-spec.json"])
def test_package_rejects_rehashed_but_wrong_evidence_or_schema(valid_package, member):
    members, evidence, native = valid_package
    members[member] = b'{}'
    with pytest.raises(OpafError, match="differs"):
        pipeline.verify_package(package_bytes(members), evidence, native)


@pytest.mark.parametrize("member", ["schema/01_synthetic_schema.sql", "evidence/native-review.json"])
def test_package_rejects_missing_native_supporting_members(valid_package, member):
    members, evidence, native = valid_package
    del members[member]
    with pytest.raises(OpafError, match="lacks"):
        pipeline.verify_package(package_bytes(members), evidence, native)


def test_package_rejects_changed_review_receipt_even_with_rehashed_manifest(valid_package):
    members, evidence, native = valid_package
    receipt = json.loads(members["evidence/native-review.json"])
    receipt["review"]["verdict"] = "reject"
    members["evidence/native-review.json"] = json.dumps(receipt).encode()
    with pytest.raises(OpafError):
        pipeline.verify_package(package_bytes(members), evidence, native)


@pytest.mark.parametrize("field,value", [("job_id", "other-job"), ("source_hash", "0" * 64),
                                          ("candidate_sha256", "0" * 64)])
def test_resealed_wrong_review_identity_still_blocks(valid_package, field, value):
    members, evidence, native = valid_package
    receipt = json.loads(members["evidence/native-review.json"])
    receipt[field] = value
    receipt["receipt_sha256"] = canonical_hash({key: item for key, item in receipt.items() if key != "receipt_sha256"})
    evidence["review_receipt_sha256"] = receipt["receipt_sha256"]
    members["evidence/native-review.json"] = json.dumps(receipt).encode()
    members["evidence/release-evidence.json"] = json.dumps(evidence).encode()
    with pytest.raises(OpafError, match="reviewer evidence"):
        pipeline.verify_package(package_bytes(members), evidence, native)


@pytest.mark.parametrize("field,value", [("job_id", "other-job"), ("application_id", 999),
                                          ("application_alias", "OTHER"), ("artifact_binding", {}),
                                          ("apexlang_validation_passed", False), ("files", {})])
def test_export_completion_identity_and_tree_must_match(valid_package, field, value):
    members, evidence, native = valid_package
    completion = json.loads(members["evidence/export-completion.json"])
    completion[field] = value
    members["evidence/export-completion.json"] = json.dumps(completion).encode()
    with pytest.raises(OpafError, match="completion|export tree"):
        pipeline.verify_package(package_bytes(members), evidence, native)


@pytest.mark.parametrize("name", ["sql/f12345.sql", "apexlang/application.apx"])
def test_changed_actual_export_bytes_cannot_use_old_completion(valid_package, name):
    members, evidence, native = valid_package
    members[name] += b"\n// altered after export\n"
    with pytest.raises(OpafError, match="export tree"):
        pipeline.verify_package(package_bytes(members), evidence, native)


def test_changed_sql_and_rehashed_local_manifests_cannot_override_reimport_proof(valid_package):
    members, evidence, native = valid_package
    members["sql/f12345.sql"] += b"-- altered after validated reimport\n"
    completion = json.loads(members["evidence/export-completion.json"])
    completion["files"]["f12345.sql"] = hashlib.sha256(members["sql/f12345.sql"]).hexdigest()
    members["evidence/export-completion.json"] = json.dumps(completion).encode()
    with pytest.raises(OpafError):
        pipeline.verify_package(package_bytes(members), evidence, native)


def test_changed_validation_log_cannot_use_old_completion(valid_package):
    members, evidence, native = valid_package
    members["evidence/export-validation.log"] = b"Changed claimed validation log\n"
    with pytest.raises(OpafError):
        pipeline.verify_package(package_bytes(members), evidence, native)


def test_package_expanded_size_is_bounded(valid_package):
    members, evidence, native = valid_package
    members["expanded.txt"] = b"x" * 20_000_001
    with pytest.raises(OpafError, match="expanded bound"):
        pipeline.verify_package(package_bytes(members), evidence, native)


def test_package_member_count_is_bounded(valid_package):
    members, evidence, native = valid_package
    members.update({f"extras/{index}.txt": b"x" for index in range(501)})
    with pytest.raises(OpafError, match="structure"):
        pipeline.verify_package(package_bytes(members), evidence, native)


@pytest.mark.parametrize("prefix", ["sql/", "apexlang/"])
def test_package_requires_actual_application_artifacts(valid_package, prefix):
    members, evidence, native = valid_package
    members = {name: raw for name, raw in members.items() if not name.startswith(prefix)}
    with pytest.raises(OpafError):
        pipeline.verify_package(package_bytes(members), evidence, native)


@pytest.mark.parametrize("raw", [b"not zip", b"", b"x" * 8_000_001, "not bytes"],
                         ids=["not-zip", "empty", "oversized", "wrong-type"])
def test_package_rejects_bad_downloads(valid_package, raw):
    _, evidence, native = valid_package
    with pytest.raises(OpafError):
        pipeline.verify_package(raw, evidence, native)


def test_bad_package_cannot_become_a_local_release(harness):
    harness.package_override = b"Synthetic malformed ZIP"
    with pytest.raises(OpafError, match="malformed"):
        harness.run()
    assert not (harness.job / "apex-package.zip").exists()
    assert not (harness.job / "release-evidence.json").exists()
    assert not (harness.checkpoints / "download.json").exists()


def test_opaf_protocol_records_exact_observed_response_and_request(monkeypatch):
    graph = {"nodes": [{"id": "synthetic-generator"}], "edges": []}
    role = {"workflow_id": "A" * 32, "model": "xai.grok-4.3", "graph_sha256": canonical_hash(graph)}
    request = {"job_id": "fox-" + "a" * 20, "synthetic": True}
    response = {"roomId": "separate-synthetic-room", "message": json.dumps({"mapping_summary": "Synthetic"})}
    calls = []
    def observed(self, method, path, payload=None, login=False):
        calls.append((method, path, deepcopy(payload), login))
        if path == "/v1/loginValidation":
            return {"ok": True}
        if path == "/v1/agents/" + role["workflow_id"]:
            return {"data": {"published": True, "data": graph}}
        assert path == "/v1/agentBuilder/run/" + role["workflow_id"]
        return deepcopy(response)
    monkeypatch.setattr(ProtocolClient, "_request", observed)
    output, invocation = ProtocolClient("https://localhost:8080/agentFactory", "synthetic", TEST_SECRET_MARKER).invoke(role, request)
    assert output == {"mapping_summary": "Synthetic"}
    assert invocation["request_sha256"] == canonical_hash(request)
    assert invocation["response_sha256"] == canonical_hash(response)
    assert invocation["room_id"] == response["roomId"]
    assert invocation["graph_sha256"] == role["graph_sha256"]
    assert invocation["completed_at_utc"] >= invocation["started_at_utc"]
    assert [call[0] for call in calls] == ["GET", "GET", "POST"]
    assert json.loads(calls[-1][2]["message"]) == request
    assert TEST_SECRET_MARKER not in str(invocation)


@pytest.mark.parametrize("published,changed", [(False, False), (True, True)])
def test_opaf_changed_or_unpublished_graph_blocks_before_model_run(monkeypatch, published, changed):
    graph = {"nodes": [], "edges": []}
    role = {"workflow_id": "A" * 32, "model": "xai.grok-4.3", "graph_sha256": canonical_hash(graph)}
    calls = []
    def observed(self, method, path, payload=None, login=False):
        calls.append(method)
        if path == "/v1/loginValidation":
            return {"ok": True}
        assert method == "GET", "Model execution must not occur after graph drift"
        return {"data": {"published": published, "data": {"changed": True} if changed else graph}}
    monkeypatch.setattr(ProtocolClient, "_request", observed)
    with pytest.raises(OpafError, match="changed or is unpublished"):
        ProtocolClient("https://localhost:8080/agentFactory", "synthetic", TEST_SECRET_MARKER).invoke(role, {})
    assert calls == ["GET", "GET"]
