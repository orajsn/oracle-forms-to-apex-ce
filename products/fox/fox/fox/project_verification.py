"""Detached project verification, separate from native v1/v2 and acceptance.

This is a pure reader, not a promotion endpoint. Operator provenance must be
established by the caller using private, immutable receipts before a durable
decision is made. It executes no SQL/browser/model calls and grants no target
authority. Generated packages cannot become VERIFIED from release booleans:
one fresh import, exact metadata and real observations for EVERY module are
required. Receipts are operator attestations, not vendor signatures.
"""
from __future__ import annotations

import hashlib
import io
import math
import re
import zipfile
from datetime import datetime

from .native_verification import VerificationError, _json, _time, ORDS
from .native_verification_policy import BoundVerificationPolicy, validate_allocation_receipt, VerificationPolicyError
from .opaf import canonical_hash, OpafError
from .project_conversion import assess_project_conversion, ProjectConversionInputError
from .project_qa_plan import (PROFILE_ID, ProjectQaPlanError, derive_project_qa_plan,
                              derive_project_qa_profile, validate_project_qa_result)
from .native_qa_plan import qa_plan_sha256


RECEIPT_NAMES = ("clean-install.json", "qa-result.json", "qa-target.json", "qa-profile.json")
PROOF_SCOPE = "fox-project-technical-verification-v1"
_MAX_PACKAGE = 32_000_000


class ProjectVerificationError(VerificationError):
    """Bounded project release-gate failure."""


def _require(condition, message):
    if not condition:
        raise ProjectVerificationError(message)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _same(left, right):
    return qa_plan_sha256({"value": left}) == qa_plan_sha256({"value": right})


def _int(value, expected):
    return type(value) is int and value == expected


def _module_observations(plan):
    return [{key: form[key] for key in ("module_id", "table_name", "report_page_id", "form_page_id", "items")}
            for form in plan["forms"]]


def _validate_clean(clean, project, plan, binding, policy, original_parsing_schema):
    _require(_int(clean.get("schema_version"), 1)
             and clean.get("scope") == "fox-project-clean-package-install-v1"
             and clean.get("profile_id") == PROFILE_ID
             and all(clean.get(key) == value for key, value in binding.items())
             and _same(clean.get("target"), policy.target)
             and _same(clean.get("observed_versions"), policy.versions),
             "Clean project import is not bound to the exact package, allocation and target.")
    before, after = clean.get("before_install", {}), clean.get("after_install", {})
    _require(before.get("application_ids") == [] and _int(before.get("user_object_count"), 0),
             "The project clean-import namespace was not observed empty.")
    app = policy.target["application_id"]
    tables = [table["table_name"] for table in plan["tables"]]
    _require(_same(after.get("application_ids"), [app])
             and after.get("physical_tables") == tables
             and _int(after.get("unexpected_schema_dependency_count"), 0),
             "Clean import did not produce one application and exactly the expected physical tables.")
    observations = clean.get("table_metadata")
    _require(isinstance(observations, list) and len(observations) == len(tables)
             and [table.get("table_name") if isinstance(table, dict) else None for table in observations] == tables,
             "Clean import omitted or duplicated a physical-table observation.")
    for observation in observations:
        spec = next(form["native_form"] for form in project["forms"]
                    if form["native_form"]["table_name"] == observation["table_name"])
        columns = [{"name": column["name"], "data_type": column["data_type"], "nullable": column["nullable"],
                    "char_length": column["length"] if column["data_type"] == "VARCHAR2" else 0,
                    "identity": column.get("identity", False)} for column in spec["columns"]]
        key = next(column["name"] for column in spec["columns"] if column.get("primary_key"))
        _require(observation.get("schema") == policy.target["parsing_schema"]
                 and _int(observation.get("row_count"), 0) and observation.get("primary_keys") == []
                 and _int(observation.get("unexpected_schema_dependency_count"), 0)
                 and _same(observation.get("columns"), columns)
                 and _same(observation.get("primary_key"), {"columns": [key], "status": "ENABLED", "validated": "VALIDATED"}),
                 "Clean-import table columns, key, identity, dependencies or initial rows differ.")
    _require(_same(clean.get("module_metadata"), _module_observations(plan))
             and _same(clean.get("page_ids"), [0, *range(1, len(plan["forms"]) * 2 + 1), 9999])
             and _same(clean.get("navigation"), [{"module_id": form["module_id"], "report_page_id": form["report_page_id"]}
                                                for form in plan["forms"]]),
             "Clean-import native pages, items or navigation omit or orphan a form.")
    _require(clean.get("original_parsing_schema") == original_parsing_schema
             and original_parsing_schema != policy.target["parsing_schema"]
             and isinstance(clean.get("original_parsing_schema"), str)
             and re.fullmatch(r"[A-Z][A-Z0-9_]{0,29}", clean["original_parsing_schema"])
             and _int(clean.get("original_schema_reference_count"), 0),
             "Clean import has not proved independence from its original parsing schema.")


def _verify(*, package: bytes, snapshot: dict, release: dict, clean_install_raw: bytes,
            qa_result_raw: bytes, qa_target_raw: bytes, qa_profile_raw: bytes,
            policy: BoundVerificationPolicy, allocation_receipt_raw: bytes,
            now: datetime, run_created: float, target_profile: dict | None = None,
            _historical: bool = False):
    _require(type(policy) is BoundVerificationPolicy and type(_historical) is bool
             and policy.historical is _historical,
             "A project proof requires its exact active or retained verification policy.")
    _require(isinstance(now, datetime) and now.tzinfo is not None
             and type(run_created) in (float, int) and math.isfinite(run_created),
             "Verification times must be finite and timezone-aware.")
    _require(isinstance(package, bytes) and 0 < len(package) <= _MAX_PACKAGE
             and isinstance(snapshot, dict) and isinstance(release, dict), "Exact project package and frozen evidence are required.")
    source, job = snapshot.get("source_hash"), release.get("job_id")
    _require(isinstance(job, str) and re.fullmatch(r"fox-[a-f0-9]{20}", job)
             and isinstance(source, str) and re.fullmatch(r"[a-f0-9]{64}", source)
             and release.get("source_manifest_sha256") == source
             and snapshot.get("conversion_profile") == PROFILE_ID and release.get("conversion_profile") == PROFILE_ID,
             "Project source, job or conversion profile differs.")
    assessment = assess_project_conversion(snapshot["files"], project_id=snapshot["project_id"],
        project_name=snapshot["project_name"], source_hash=source)
    _require(assessment["state"] == "READY" and assessment["assessment_complete"] is True
             and _same(assessment["rendering_spec"], snapshot.get("native_project")),
             "Selected complete sources no longer produce this project; no form may be omitted.")
    # A lazy import avoids a pipeline import cycle. The established pipeline
    # package reader owns ZIP/export/model-review/schema preparation integrity.
    from .native_project_pipeline import verify_project_package
    digest = verify_project_package(package, release, snapshot["native_project"], target_profile=target_profile)
    _require(digest == _sha(package), "Project package reader returned a different exact-byte identity.")
    with zipfile.ZipFile(io.BytesIO(package)) as archive:
        manifest = _json(archive.read("manifest.json"))
        project_raw = archive.read("native-project-spec.json")
        trace_raw = archive.read("source-to-apex.json")
        historical_target = _json(archive.read("evidence/target-profile.json"))
    project, trace = _json(project_raw), _json(trace_raw)
    _require(_same(project, snapshot["native_project"]), "Packaged project differs from the selected source version.")
    plan = derive_project_qa_plan(project, _sha(project_raw), trace, _sha(trace_raw))
    _require(all(release.get(key) is True for key in (
        "reviewer_approved", "reviewer_execution_verified", "sqlcl_valid", "import_passed",
        "runtime_smoke_passed", "package_reimport_passed"))
        and release.get("business_acceptance_required") is True,
        "Project generation or independent review gates are incomplete.")
    _require(policy.binding["job_id"] == job and policy.binding["source_manifest_sha256"] == source
             and policy.binding["package_sha256"] == digest, "The clean target was allocated for a different project package.")
    allocation = validate_allocation_receipt(allocation_receipt_raw, policy)
    app = policy.target["application_id"]
    _require(app not in {release.get("application_id"), release.get("package_reimport", {}).get("application_id")}
             and policy.target["application_alias"] not in {release.get("application_alias"), release.get("package_reimport", {}).get("application_alias")},
             "Clean project verification must use its own allocated application.")
    binding = {"job_id": job, "source_manifest_sha256": source, "package_sha256": digest,
        "project_spec_sha256": _sha(project_raw), "source_to_apex_sha256": _sha(trace_raw),
        "schema_script_sha256": manifest["schema/01_synthetic_schema.sql"],
        "sql_sha256": manifest[f"sql/f{release['application_id']}.sql"],
        "verification_profile_sha256": policy.sha256,
        "allocation_receipt_sha256": _sha(allocation_receipt_raw)}
    clean, runtime, target, profile = map(_json, (clean_install_raw, qa_result_raw, qa_target_raw, qa_profile_raw))
    _validate_clean(clean, project, plan, binding, policy, historical_target["database"]["parsing_schema"])
    expected_profile = derive_project_qa_profile(project, plan)
    _require(_same(profile, expected_profile), "Runtime profile omitted or changed a project's mapped form.")
    app_url = ORDS + "/r/" + policy.target["workspace"].lower() + "/" + policy.target["application_alias"].lower() + "/"
    expected_target = {"schema_version": 1, "scope": "fox-project-qa-target-v1",
        **binding, "target": policy.target, "url": app_url, "profile_sha256": _sha(qa_profile_raw),
        "import_receipt_sha256": _sha(clean_install_raw), "test_plan_sha256": qa_plan_sha256(plan),
        "synthetic_qa_approved": True}
    _require(_same(target, expected_target), "Runtime target differs from the exact clean project import.")
    _require(_same(runtime.get("target"), target)
             and runtime.get("target_receipt_sha256") == _sha(qa_target_raw)
             and _same(runtime.get("input_sha256"), {**binding, "profile_sha256": _sha(qa_profile_raw),
                  "import_receipt_sha256": _sha(clean_install_raw), "target_receipt_sha256": _sha(qa_target_raw)}),
             "Runtime result did not bind every mounted project input byte hash.")
    cases = validate_project_qa_result(runtime, project, plan, app)
    allocated = _time(allocation["allocated_at_utc"])
    started, finished = _time(clean.get("started_at_utc")), _time(clean.get("finished_at_utc"))
    qa_started, qa_finished = _time(runtime.get("started_at")), _time(runtime.get("finished_at"))
    _require(run_created <= allocated <= started <= finished <= qa_started <= qa_finished
             and qa_finished <= now.timestamp() + 300
             and now.timestamp() - qa_finished <= policy.max_evidence_age_seconds,
             "Project verification evidence is stale, future-dated or out of sequence.")
    previous = qa_started
    for form in runtime["forms"]:
        form_started, form_finished = _time(form.get("started_at")), _time(form.get("finished_at"))
        _require(previous <= form_started <= form_finished <= qa_finished,
                 "Per-form runtime observations are missing or out of sequence.")
        previous = form_finished
    return {"schema_version": 1, "scope": PROOF_SCOPE, "conversion_profile": PROFILE_ID,
        "job_id": job, "source_manifest_sha256": source, "package_sha256": digest,
        "source_snapshot_sha256": canonical_hash(snapshot), "release_evidence_sha256": canonical_hash(release),
        "verification_profile": policy.document, "verification_profile_sha256": policy.sha256,
        "allocation_receipt_sha256": _sha(allocation_receipt_raw), "target": policy.target,
        "clean_application_id": app, "clean_application_alias": policy.target["application_alias"],
        "clean_application_url": app_url, "observed_versions": policy.versions,
        "receipt_sha256": dict(zip(RECEIPT_NAMES, map(_sha, (clean_install_raw, qa_result_raw, qa_target_raw, qa_profile_raw)))),
        "test_plan": plan, "test_plan_sha256": qa_plan_sha256(plan),
        "form_results": [{"module_id": form["module_id"], "table_name": form["table_name"],
                          "report_page_id": form["report_page_id"], "form_page_id": form["form_page_id"],
                          "required_tests": [case["name"] for case in form["cases"] if case["applicable"]]}
                         for form in plan["forms"] if form["module_id"] in cases],
        "physical_tables": [table["table_name"] for table in plan["tables"]],
        "authenticated_runtime_passed": True, "clean_schema_install_passed": True,
        "qa_finished_at": runtime["finished_at"], "business_acceptance_required": True,
        "human_acceptance_recorded": False, "provenance": "Owner-private operator receipts; not vendor signatures.",
        "scope_limit": "Exact complete synthetic project package only; no customer business equivalence claim."}


def verify_project_detached_proof(**arguments):
    """Return a whole-project technical proof; never mutate run/acceptance state."""
    try:
        # Historical replay is owned by the durable reader after authenticating
        # retained hashes/SQLite identity. This public new-decision entrypoint
        # cannot be switched into that mode by a caller-provided flag.
        _require("_historical" not in arguments, "New project proof cannot select historical replay.")
        return _verify(**arguments, _historical=False)
    except ProjectVerificationError:
        raise
    except (VerificationError, VerificationPolicyError, ProjectConversionInputError, ProjectQaPlanError,
            OpafError, KeyError, TypeError, ValueError, AttributeError, RecursionError, zipfile.BadZipFile):
        raise ProjectVerificationError("Exact project evidence is unavailable, malformed or incomplete.") from None
