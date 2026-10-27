"""Real project package/proof readers plus synthetic local SQLite promotion.

The converter helper uses the real source/review/render/schema/import/release
components while isolating SQLcl/HTTP/database-adapter transports. Receipts
below are authored test observations, never live evidence or human acceptance.
No positive package, source, JSON, hash, selection or proof validator is mocked.
Windows tests isolate owner-private POSIX I/O at a confined temporary tree;
they do not claim Windows ACL or POSIX ownership validation.
"""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
from types import SimpleNamespace
import zipfile

import pytest

from fox import source_history as history
from fox import project_verification_runtime as gate
from fox import native_verification_policy as policy_module
from fox.intake import checked_source, inventory
from fox.native_project_pipeline import verify_project_package
from fox.native_qa_plan import qa_plan_sha256
from fox.native_verification import ORDS
from fox.native_verification_policy import BoundVerificationPolicy, FIXED_TARGET, INSTANCE
from fox.opaf import canonical_hash
from fox.project_qa_plan import derive_project_qa_plan, derive_project_qa_profile
from fox.project_verification import ProjectVerificationError, verify_project_detached_proof
from test_project_qa_plan import runtime
from test_source_history_store import SCHEMA


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 25, 0, 10, tzinfo=timezone.utc)
CREATED = datetime(2026, 10, 25, tzinfo=timezone.utc).timestamp()


def raw(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


def put(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if isinstance(value, bytes) else raw(value))


@pytest.fixture(scope="module", params=[1, 2], ids=["native-v1", "mapped-v2"])
def actual_release(tmp_path_factory, request):
    """Produce once; every case receives immutable bytes and fresh local data."""
    with pytest.MonkeyPatch.context() as boundary:
        boundary.syspath_prepend(str(ROOT / "converter"))
        boundary.syspath_prepend(str(ROOT / "converter" / "tests"))
        path = ROOT / "converter" / "tests" / "test_project_release.py"
        spec = importlib.util.spec_from_file_location("fox_actual_project_release_test_support", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        source_snapshot = None
        if request.param == 2:
            from test_project_source import mapped_snapshot
            source_snapshot = mapped_snapshot()
        built = module.build_actual_project_release(tmp_path_factory, boundary,
                                                    source_snapshot=source_snapshot)
        # These are production package validators, not test doubles. Preserve
        # this assertion even though the converter helper also checks them.
        assert verify_project_package(built.package, built.evidence, built.project, built.profile) == sha(built.package)
        assert built.project["schema_version"] == request.param
        boundary.syspath_prepend(str(ROOT))
        from qa.operator.project_contracts import load_package
        clean_package = load_package(built.package, sha(built.package))
        with zipfile.ZipFile(io.BytesIO(built.package)) as archive:
            assert clean_package["binding"]["project_spec_sha256"] == sha(archive.read("native-project-spec.json"))
            assert clean_package["binding"]["source_to_apex_sha256"] == sha(archive.read("source-to-apex.json"))
        assert clean_package["binding"]["tables"] == sorted({form["native_form"]["table_name"] for form in built.project["forms"]})
        return SimpleNamespace(package=built.package, evidence=deepcopy(built.evidence),
            project=deepcopy(built.project), snapshot=deepcopy(built.snapshot), profile=deepcopy(built.profile))


def observations(built):
    """Authored observations for the exact REAL generated package bytes."""
    with zipfile.ZipFile(io.BytesIO(built.package)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        project = json.loads(archive.read("native-project-spec.json"))
        trace = json.loads(archive.read("source-to-apex.json"))
    plan = derive_project_qa_plan(project, manifest["native-project-spec.json"], trace, manifest["source-to-apex.json"])
    target = {**FIXED_TARGET, "workspace": "FOX_QA_261025_ABCDEF12", "parsing_schema": "FOX_QA_261025_ABCDEF12",
              "workspace_id": "90071992547409930001", "application_id": 444, "application_alias": "F2A_QA_261025_ABCDEF12"}
    versions = {"apex": "26.1.5", "sqlcl": "26.1.2.0", "database": "23.26.4.1.0", "mmd": "26.1.0+3102"}
    binding = {"job_id": built.evidence["job_id"], "source_manifest_sha256": project["source_manifest_sha256"],
               "package_sha256": sha(built.package)}
    allocation = {"schema_version": 1, "scope": "fox-clean-allocation-v2", "passed": True, "plan_sha256": "e" * 64,
        "allocated_at_utc": "2026-10-25T00:01:00Z", "binding": deepcopy(binding), "target": {**target, "instance_id": INSTANCE},
        "observed_versions": versions, "fresh_namespace": {"workspace_created_fresh": True, "schema_created_fresh": True,
                                                           "application_count": 0, "user_object_count": 0}}
    allocation_raw = raw(allocation)
    policy = BoundVerificationPolicy(raw({"schema_version": 1, "scope": "fox-native-verification-profile-v2", "policy_id": "jsn-clean-native-v2",
        "binding": {**binding, "allocation_receipt_sha256": sha(allocation_raw)}, "target": target,
        "expected_versions": versions, "max_evidence_age_seconds": 86400}))
    binding.update(project_spec_sha256=manifest["native-project-spec.json"], source_to_apex_sha256=manifest["source-to-apex.json"],
        schema_script_sha256=manifest["schema/01_synthetic_schema.sql"], sql_sha256=manifest[f"sql/f{built.evidence['application_id']}.sql"],
        verification_profile_sha256=policy.sha256, allocation_receipt_sha256=sha(allocation_raw))
    profile = derive_project_qa_profile(project, plan)
    tables = {form["native_form"]["table_name"]: form["native_form"] for form in project["forms"]}
    metadata = []
    for name in sorted(tables):
        native = tables[name]
        key = next(column["name"] for column in native["columns"] if column["primary_key"])
        metadata.append({"table_name": name, "schema": target["parsing_schema"], "row_count": 0, "primary_keys": [],
            "unexpected_schema_dependency_count": 0,
            "columns": [{"name": column["name"], "data_type": column["data_type"], "nullable": column["nullable"],
                         "char_length": column["length"] if column["data_type"] == "VARCHAR2" else 0,
                         "identity": column["identity"]} for column in native["columns"]],
            "primary_key": {"columns": [key], "status": "ENABLED", "validated": "VALIDATED"}})
    clean = {"schema_version": 1, "scope": "fox-project-clean-package-install-v1", "profile_id": "native-project-v1",
        **binding, "target": target, "observed_versions": versions,
        "before_install": {"application_ids": [], "user_object_count": 0},
        "after_install": {"application_ids": [444], "physical_tables": sorted(tables), "unexpected_schema_dependency_count": 0},
        "table_metadata": metadata,
        "module_metadata": [{key: form[key] for key in ("module_id", "table_name", "report_page_id", "form_page_id", "items")} for form in plan["forms"]],
        "page_ids": [0, *range(1, 2 * len(plan["forms"]) + 1), 9999],
        "navigation": [{"module_id": form["module_id"], "report_page_id": form["report_page_id"]} for form in plan["forms"]],
        "original_parsing_schema": built.profile["database"]["parsing_schema"], "original_schema_reference_count": 0,
        "started_at_utc": "2026-10-25T00:02:00Z", "finished_at_utc": "2026-10-25T00:03:00Z"}
    url = ORDS + "/r/" + target["workspace"].lower() + "/" + target["application_alias"].lower() + "/"
    qa_target = {"schema_version": 1, "scope": "fox-project-qa-target-v1", **binding, "target": target,
        "url": url, "profile_sha256": sha(raw(profile)), "import_receipt_sha256": sha(raw(clean)),
        "test_plan_sha256": qa_plan_sha256(plan), "synthetic_qa_approved": True}
    qa = runtime(project, plan)
    qa.update(target=qa_target, target_receipt_sha256=sha(raw(qa_target)),
        input_sha256={**binding, "profile_sha256": sha(raw(profile)), "import_receipt_sha256": sha(raw(clean)),
                      "target_receipt_sha256": sha(raw(qa_target))},
        started_at="2026-10-25T00:04:00Z", finished_at="2026-10-25T00:09:00Z")
    for index, form in enumerate(qa["forms"]):
        form.update(started_at=f"2026-10-25T00:0{4 + index * 2}:00Z", finished_at=f"2026-10-25T00:0{5 + index * 2}:00Z")
    return SimpleNamespace(policy=policy, receipts={"clean-install.json": raw(clean), "qa-result.json": raw(qa),
        "qa-target.json": raw(qa_target), "qa-profile.json": raw(profile), "verification-profile.json": policy.raw,
        "allocation-receipt.json": allocation_raw}, plan=plan)


@pytest.fixture
def case(actual_release, tmp_path, monkeypatch):
    if actual_release.project["schema_version"] == 2:
        # The package builder's temporary registry is already restored. Keep
        # only this synthetic historical INPUT registered for the full case;
        # do not change active-target selection or replace a validator.
        from forms2apex import target_profile
        profile = deepcopy(actual_release.profile)
        digest = canonical_hash(profile)
        monkeypatch.setattr(target_profile, "_KNOWN_HISTORICAL_PROFILES",
            {**target_profile._KNOWN_HISTORICAL_PROFILES, digest: profile})
        assert target_profile.validate_historical_target_profile(profile) == profile
    base = tmp_path.resolve()
    root, operator = base / "data", base / "operator"
    root.mkdir(); operator.mkdir()
    run_id = actual_release.evidence["job_id"]
    job = root / "jobs" / run_id
    job.mkdir(parents=True)
    snapshot = deepcopy(actual_release.snapshot)
    snapshot["project"] = snapshot["project_id"]
    observed = observations(actual_release)
    for name, content in observed.receipts.items():
        put(operator / name, content)
    put(job / "source-snapshot.json", snapshot)
    put(job / "release-evidence.json", actual_release.evidence)
    put(job / "apex-package.zip", actual_release.package)
    put(job / "native-project-pipeline/download.json", {"package_sha256": sha(actual_release.package), "source_hash": snapshot["source_hash"]})
    put(job / "native-project-pipeline/target-profile.json", {"target_profile": actual_release.profile,
        "target_profile_sha256": canonical_hash(actual_release.profile)})
    with sqlite3.connect(root / "fox.sqlite3") as db:
        db.executescript(SCHEMA)
        db.execute("BEGIN IMMEDIATE")
        db.execute("INSERT INTO projects VALUES(?,?,?,?,?,?)", (snapshot["project_id"], "synthetic-owner", "Synthetic", snapshot["project_name"], "", CREATED))
        history.initialize(db)
        history.publish_upload(db, snapshot["project_id"], snapshot["files"], CREATED, "synthetic-owner")
        db.execute("INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)", (run_id, snapshot["project_id"], snapshot["source_hash"],
            "QA_REQUIRED", "Synthetic observed receipts pending", CREATED, CREATED, str((job / "apex-package.zip").relative_to(root))))
    # Real production strict read/create-only code remains in use. Only the
    # POSIX ownership/ancestor/sync OS boundary is isolated inside fresh base.
    def confined(path):
        candidate = Path(path).absolute()
        resolved = candidate.resolve(strict=True)
        if candidate != resolved or not resolved.is_relative_to(base):
            raise gate.native_io.VerificationError("Synthetic fixture path escaped its root.")
        for parent in (candidate, *candidate.parents):
            if parent == base:
                break
            if parent.is_symlink():
                raise gate.native_io.VerificationError("Synthetic fixture path is linked.")
        return resolved
    def private(path, directory=False):
        checked = confined(path)
        if not (checked.is_dir() if directory else checked.is_file()):
            raise gate.native_io.VerificationError("Synthetic fixture type differs.")
        return checked
    monkeypatch.setattr(gate.native_io, "_safe_path", confined)
    monkeypatch.setattr(gate.native_io, "_private", private)
    if os.name == "nt":
        monkeypatch.setattr(gate.native_io, "_sync_dir", lambda path: None)
    return SimpleNamespace(root=root, operator=operator, job=job, run_id=run_id, snapshot=snapshot,
        built=actual_release, observed=observed, policy=observed.policy, now=NOW,
        retained=job / "project-technical-verification")


def promote(case, **overrides):
    return gate.promote_project_run(**({"root": case.root, "run_id": case.run_id,
        "operator_receipt_dir": case.operator, "policy": case.policy, "now": case.now} | overrides))


def row(case):
    with sqlite3.connect(case.root / "fox.sqlite3") as db:
        db.row_factory = sqlite3.Row
        return dict(db.execute("SELECT * FROM runs WHERE id=?", (case.run_id,)).fetchone())


def counts(case):
    with sqlite3.connect(case.root / "fox.sqlite3") as db:
        exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='technical_verifications'").fetchone()
        return {"proofs": db.execute("SELECT COUNT(*) FROM technical_verifications").fetchone()[0] if exists else 0,
            "technical_events": db.execute("SELECT COUNT(*) FROM events WHERE action='project_technical_verified'").fetchone()[0],
            "acceptances": db.execute("SELECT COUNT(*) FROM acceptances").fetchone()[0]}


def read_checked(case):
    with sqlite3.connect(case.root / "fox.sqlite3") as db:
        return gate.checked_project_release(db, case.root, row(case))


def change_sources(case):
    source = case.snapshot["files"][0]
    changed = checked_source(source["name"], (source["text"] + "\n").encode())
    with sqlite3.connect(case.root / "fox.sqlite3") as db:
        db.execute("BEGIN IMMEDIATE")
        result = history.publish_upload(db, case.snapshot["project_id"], [changed], CREATED + 1000, "synthetic-owner")
        assert inventory(history.selected_sources(db, case.snapshot["project_id"]))["source_hash"] != case.snapshot["source_hash"]
    return result


def test_real_package_and_full_proof_promote_atomically_without_acceptance(case):
    first = promote(case)
    assert first["state"] == "VERIFIED" and first["idempotent"] is False
    assert row(case)["state"] == "VERIFIED"
    assert counts(case) == {"proofs": 1, "technical_events": 1, "acceptances": 0}
    checked = read_checked(case)
    assert checked["package"] == case.built.package and len(checked["proof"]["form_results"]) == 2
    assert checked["proof"]["human_acceptance_recorded"] is False
    assert checked["proof"]["business_acceptance_required"] is True


def test_identical_retry_preserves_exact_proof_bytes_and_one_event(case):
    first = promote(case)
    before = {path.name: path.read_bytes() for path in case.retained.iterdir()}
    second = promote(case, now=NOW + timedelta(days=30))
    assert second == {**first, "idempotent": True}
    assert {path.name: path.read_bytes() for path in case.retained.iterdir()} == before
    assert counts(case) == {"proofs": 1, "technical_events": 1, "acceptances": 0}


@pytest.mark.parametrize("member", ["clean-install.json", "qa-target.json", "qa-result.json"])
@pytest.mark.parametrize("field", ["project_spec_sha256", "source_to_apex_sha256"])
def test_exact_spec_and_trace_hashes_cannot_be_substituted_in_any_proof_input(case, member, field):
    path = case.operator / member
    value = json.loads(path.read_bytes())
    target = value["input_sha256"] if member == "qa-result.json" else value
    target[field] = "0" * 64
    put(path, value)
    with pytest.raises(ProjectVerificationError):
        promote(case)
    assert row(case)["state"] == "QA_REQUIRED"
    assert counts(case) == {"proofs": 0, "technical_events": 0, "acceptances": 0}


def test_historical_accepted_read_ignores_current_selection_and_active_version_allowlist(case, monkeypatch):
    promote(case)
    change_sources(case)
    with sqlite3.connect(case.root / "fox.sqlite3") as db:
        # Test only: simulate an already separately human-accepted historical
        # state. No production API or real acceptance is invoked or fabricated.
        db.execute("UPDATE runs SET state='ACCEPTED' WHERE id=?", (case.run_id,))
    monkeypatch.setattr(policy_module, "SUPPORTED_ACTIVE_VERSIONS", frozenset())
    before = {path.name: path.read_bytes() for path in case.retained.iterdir()}
    before_row, before_counts = row(case), counts(case)
    checked = read_checked(case)
    report = gate.verify_existing_project_run(root=case.root, run_id=case.run_id)
    assert checked["package"] == case.built.package and report["state"] == "ACCEPTED"
    assert report["active_policy_applied"] is False and report["read_only"] is True
    assert {path.name: path.read_bytes() for path in case.retained.iterdir()} == before
    assert row(case) == before_row and counts(case) == before_counts
    assert counts(case)["acceptances"] == 0


@pytest.mark.parametrize("name", ["clean-install.json", "qa-result.json", "qa-target.json", "qa-profile.json",
    "verification-profile.json", "allocation-receipt.json", "attempt.json", "verification.json"])
@pytest.mark.parametrize("mutation", ["missing", "different_bytes"])
def test_retained_receipt_changes_block_reader_and_retry(case, name, mutation):
    promote(case)
    path = case.retained / name
    if mutation == "missing":
        path.rename(path.with_suffix(".preserved"))
    else:
        path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ProjectVerificationError):
        read_checked(case)
    with pytest.raises(ProjectVerificationError):
        promote(case)
    assert counts(case)["technical_events"] == 1


@pytest.mark.parametrize("relative", ["apex-package.zip", "source-snapshot.json", "release-evidence.json",
    "native-project-pipeline/download.json", "native-project-pipeline/target-profile.json"])
def test_frozen_job_byte_changes_block_historical_read(case, relative):
    promote(case)
    path = case.job / relative
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ProjectVerificationError):
        read_checked(case)


@pytest.mark.parametrize("column,value", [("source_hash", "0" * 64), ("artifact_sha256", "0" * 64),
    ("proof_sha256", "0" * 64), ("proof_json", "{}"), ("created", CREATED)])
def test_stored_technical_decision_tamper_blocks_reader(case, column, value):
    promote(case)
    with sqlite3.connect(case.root / "fox.sqlite3") as db:
        db.execute(f"UPDATE technical_verifications SET {column}=? WHERE run=?", (value, case.run_id))
    with pytest.raises(ProjectVerificationError):
        read_checked(case)


def test_rehashed_boolean_attempt_version_cannot_reuse_integer_contract(case):
    promote(case)
    attempt_path = case.retained / "attempt.json"
    attempt = json.loads(attempt_path.read_bytes())
    attempt["schema_version"] = True
    attempt_path.write_bytes(raw(attempt))
    proof_path = case.retained / "verification.json"
    proof = json.loads(proof_path.read_bytes())
    proof["operator_attempt_sha256"] = sha(attempt_path.read_bytes())
    proof_bytes = raw(proof)
    proof_path.write_bytes(proof_bytes)
    with sqlite3.connect(case.root / "fox.sqlite3") as db:
        db.execute("UPDATE technical_verifications SET proof_json=?,proof_sha256=? WHERE run=?",
                   (proof_bytes.decode(), sha(proof_bytes), case.run_id))
    with pytest.raises(ProjectVerificationError):
        read_checked(case)
    with pytest.raises(ProjectVerificationError):
        promote(case)


def test_new_decision_requires_current_complete_selected_source(case):
    change_sources(case)
    with pytest.raises(ProjectVerificationError, match="Selected project sources changed"):
        promote(case)
    assert row(case)["state"] == "QA_REQUIRED" and not case.retained.exists()
    assert counts(case) == {"proofs": 0, "technical_events": 0, "acceptances": 0}


def test_historical_flag_cannot_authorize_first_decision(case):
    historical = BoundVerificationPolicy(case.policy.raw, historical=True)
    with pytest.raises(ProjectVerificationError, match="Historical policy cannot"):
        promote(case, policy=historical)
    assert not case.retained.exists() and row(case)["state"] == "QA_REQUIRED"


def test_removed_active_version_cannot_authorize_first_decision(case, monkeypatch):
    monkeypatch.setattr(policy_module, "SUPPORTED_ACTIVE_VERSIONS", frozenset())
    with pytest.raises(ProjectVerificationError):
        promote(case)
    assert not case.retained.exists() and counts(case)["proofs"] == 0


def test_historical_reader_rejects_changed_original_run_creation_time(case):
    promote(case)
    with sqlite3.connect(case.root / "fox.sqlite3") as db:
        db.execute("UPDATE runs SET created=? WHERE id=?", (CREATED - 100, case.run_id))
    with pytest.raises(ProjectVerificationError):
        read_checked(case)


def test_operator_directory_must_be_outside_data_tree(case):
    inside = case.root / "operator"
    shutil.copytree(case.operator, inside)
    with pytest.raises(ProjectVerificationError, match="outside FOX data"):
        promote(case, operator_receipt_dir=inside)
    assert counts(case)["proofs"] == 0


@pytest.mark.parametrize("at", ["attempt.json", "verification.json"])
def test_interrupted_local_persistence_resumes_original_time_without_active_allowlist(case, monkeypatch, at):
    saved = gate.native_io._save_once
    def interrupted(path, content):
        saved(path, content)
        if path.name == at:
            raise OSError("Synthetic post-persistence interruption")
    monkeypatch.setattr(gate.native_io, "_save_once", interrupted)
    with pytest.raises(ProjectVerificationError):
        promote(case)
    assert row(case)["state"] == "QA_REQUIRED" and counts(case)["proofs"] == 0
    original_attempt = (case.retained / "attempt.json").read_bytes()
    monkeypatch.setattr(gate.native_io, "_save_once", saved)
    monkeypatch.setattr(policy_module, "SUPPORTED_ACTIVE_VERSIONS", frozenset())
    historical = BoundVerificationPolicy(case.policy.raw, historical=True)
    result = promote(case, now=NOW + timedelta(days=30), policy=historical)
    assert result["state"] == "VERIFIED" and (case.retained / "attempt.json").read_bytes() == original_attempt
    with sqlite3.connect(case.root / "fox.sqlite3") as db:
        assert db.execute("SELECT created FROM technical_verifications").fetchone()[0] == NOW.timestamp()
    assert counts(case)["technical_events"] == 1


@pytest.mark.parametrize("change", ["package", "selection", "receipt", "operator_receipt", "run_created"])
def test_precommit_rechecks_block_changes_after_proof_validation(case, monkeypatch, change):
    saved = gate.native_io._save_once
    def mutate(path, content):
        saved(path, content)
        if path.name == "verification.json":
            if change == "package":
                target = case.job / "apex-package.zip"
                target.write_bytes(target.read_bytes() + b"changed")
            elif change == "selection":
                change_sources(case)
            elif change == "receipt":
                target = case.retained / "qa-result.json"
                target.write_bytes(target.read_bytes() + b"\n")
            elif change == "operator_receipt":
                target = case.operator / "qa-result.json"
                target.write_bytes(target.read_bytes() + b"\n")
            else:
                with sqlite3.connect(case.root / "fox.sqlite3") as db:
                    db.execute("UPDATE runs SET created=? WHERE id=?", (CREATED - 100, case.run_id))
    monkeypatch.setattr(gate.native_io, "_save_once", mutate)
    with pytest.raises(ProjectVerificationError):
        promote(case)
    assert row(case)["state"] == "QA_REQUIRED"
    assert counts(case) == {"proofs": 0, "technical_events": 0, "acceptances": 0}


@pytest.mark.parametrize("failure_point", ["state_update", "event_insert"])
def test_sqlite_failure_rolls_back_decision_state_and_event_but_keeps_evidence(case, failure_point):
    with sqlite3.connect(case.root / "fox.sqlite3") as db:
        if failure_point == "state_update":
            db.execute("CREATE TRIGGER synthetic_block_promotion BEFORE UPDATE ON runs WHEN NEW.state='VERIFIED' BEGIN SELECT RAISE(ABORT,'synthetic failure'); END")
        else:
            db.execute("CREATE TRIGGER synthetic_block_promotion BEFORE INSERT ON events WHEN NEW.action='project_technical_verified' BEGIN SELECT RAISE(ABORT,'synthetic failure'); END")
    with pytest.raises(ProjectVerificationError):
        promote(case)
    assert row(case)["state"] == "QA_REQUIRED" and (case.retained / "verification.json").is_file()
    assert counts(case) == {"proofs": 0, "technical_events": 0, "acceptances": 0}
    with sqlite3.connect(case.root / "fox.sqlite3") as db:
        db.execute("DROP TRIGGER synthetic_block_promotion")
    assert promote(case)["state"] == "VERIFIED" and counts(case)["technical_events"] == 1


def test_project_generated_without_proof_never_returns_permissive_none(case):
    with pytest.raises(ProjectVerificationError, match="technical verification is required"):
        read_checked(case)


def test_new_operator_receipt_cannot_replace_existing_decision(case):
    first = promote(case)
    path = case.operator / "qa-result.json"
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ProjectVerificationError, match="different operator input"):
        promote(case)
    assert read_checked(case)["proof"] and counts(case)["technical_events"] == 1
    with sqlite3.connect(case.root / "fox.sqlite3") as db:
        assert db.execute("SELECT proof_sha256 FROM technical_verifications").fetchone()[0] == first["proof_sha256"]
