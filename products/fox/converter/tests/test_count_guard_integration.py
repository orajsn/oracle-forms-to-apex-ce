"""Closed v3 dispatch and mandatory runtime proof; no live execution claims."""
from copy import deepcopy
from datetime import datetime, timezone
import hashlib

import pytest

from forms2apex import blueprint_profiles, native_blueprint_required as required
from forms2apex import native_blueprint_count_guard as guard
from forms2apex.prototype_package import (COUNT_GUARD_RUNTIME_CHECKS,
    expected_runtime_pages, runtime_binding, alias_for_job)
from forms2apex.prototype_release import validate_runtime_receipt
from test_native_blueprint_count_guard import spec


def request_and_import():
    value = spec()
    request = {"rendering_spec": value, "job_id": "synthetic-count-check",
        "project_id": value["project_id"], "source_binding": value["source_binding"],
        "plan_sha256": "a" * 64, "rendered_zip_sha256": "b" * 64}
    from forms2apex import count_guard_fixture as fixture
    plan = fixture.plan(request)
    request["prior_receipts"] = {"prepare_schema": {
        "status": "COMPLETE", "ready_for_import": True, "request_sha256": "e" * 64,
        "count_guard_fixture": {"plan": plan, "plan_sha256": fixture.digest(plan),
            "request_sha256": "e" * 64, "prepared": True,
            "fixture_sql_sha256": hashlib.sha256(fixture.insert_sql(request).encode()).hexdigest(),
            "rows": [{"case": row["case"], "primary_key": str(index + 1)}
                     for index, row in enumerate(plan["cases"])]}}}
    imported = {"imported": True, "application_id": 12345,
        "application_alias": alias_for_job(request["job_id"]), "workspace": "FORMS2APEX_POC",
        "import_intent_sha256": "c" * 64, "compiled_metadata_sha256": "d" * 64}
    return request, imported, {"template": guard.context()}


def test_exact_v3_closed_dispatch_and_historical_required_dispatch():
    value = spec()
    assert blueprint_profiles.select(value) is guard
    assert blueprint_profiles.select(guard._required_projection(value)) is required
    for version in (True, 1, 2, 4, "3"):
        changed = {**value, "schema_version": version}
        with pytest.raises(ValueError, match="PROFILE_UNSUPPORTED"):
            blueprint_profiles.select(changed)
    with pytest.raises(ValueError, match="PROFILE_UNSUPPORTED"):
        blueprint_profiles.select({**value, "profile_id": "arbitrary.module"})


def test_runtime_checks_add_only_proven_owner_check_and_retain_required_tests():
    value = spec()
    old = expected_runtime_pages(guard._required_projection(value))
    pages = expected_runtime_pages(value)
    owner = value["count_guard"]["source_objects"]["owner_block"]
    selected = [row for row in pages if row["source_block_id"] == owner and row["page_id"] % 2]
    assert len(selected) == 1
    assert set(COUNT_GUARD_RUNTIME_CHECKS) <= set(selected[0]["checks"])
    for row, prior in zip(pages, old, strict=True):
        remaining = [name for name in row["checks"] if name not in COUNT_GUARD_RUNTIME_CHECKS]
        assert {**row, "checks": remaining} == prior
    assert all("additional_required_input_validation" in row["checks"]
               for row in pages if row["page_id"] % 2 == 0)


@pytest.mark.parametrize("context", [None, {}, required.context()])
def test_new_runtime_requires_exact_physical_count_guard_context(context):
    request, imported, artifact = request_and_import()
    artifact["template"] = context
    with pytest.raises(RuntimeError, match="TEMPLATE_PROFILE_MISMATCH"):
        runtime_binding(request, imported, artifact)


def test_count_runtime_requires_original_fixture_receipt_and_binds_its_hash():
    from forms2apex.prototype_package import digest
    request, imported, artifact = request_and_import()
    actual = runtime_binding(request, imported, artifact)
    assert actual["count_guard_fixture_sha256"] == digest(request["prior_receipts"]["prepare_schema"]["count_guard_fixture"])
    request.pop("prior_receipts")
    with pytest.raises(RuntimeError, match="FIXTURE_PREPARATION_REQUIRED"):
        runtime_binding(request, imported, artifact)


@pytest.mark.parametrize("omitted", COUNT_GUARD_RUNTIME_CHECKS)
def test_missing_any_count_check_blocks_runtime_acceptance(tmp_path, omitted):
    request, imported, artifact = request_and_import()
    stamp = datetime.now(timezone.utc).isoformat()
    value = {**runtime_binding(request, imported, artifact), "passed": True,
        "authenticated": True, "business_pages_tested": True, "business_behavior_accepted": False,
        "started_at_utc": stamp, "completed_at_utc": stamp,
        "runner": {"kind": "authenticated_browser", "tool": "playwright",
                   "code_sha256": "e" * 64, "image_id": "sha256:" + "f" * 64},
        "pages": [], "artifacts": [], "data_retention": "synthetic_test_rows_retained",
        "retained_rows": []}
    for block in request["rendering_spec"]["blocks"]:
        if block["native_component"] == "form":
            value["retained_rows"].append({"source_block_id": block["source_block_id"],
                "table_name": block["table_name"], "primary_key": "1", "marker": "FPQ-abcdef012345",
                "created": True, "updated": True, "deleted": False})
    for page in expected_runtime_pages(request["rendering_spec"]):
        checks = {name: True for name in page["checks"] if name != omitted}
        if "additional_required_input_validation" in checks:
            checks["additional_required_input_validation"] = "NOT_EXERCISED_NO_ADDITIONAL_REQUIRED_FIELDS"
        value["pages"].append({"page_id": page["page_id"], "source_block_id": page["source_block_id"],
                               "passed": True, "authenticated": True, "checks": checks})
    original = deepcopy(value)
    with pytest.raises(RuntimeError, match="PAGE_COVERAGE_INVALID"):
        validate_runtime_receipt(tmp_path, request, imported, artifact, value)
    assert value == original
