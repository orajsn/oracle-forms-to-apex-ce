"""Authored synthetic observation fixtures; these tests are not live QA proof."""
from copy import deepcopy
import hashlib
import json

import pytest

from fox.native_qa_plan import derive_native_qa_plan, qa_plan_sha256
from fox.project_qa_plan import (ProjectQaPlanError, derive_project_qa_plan,
                                 derive_project_qa_profile, validate_project_qa_result)


def native(table="FOX_NATIVE_SHARED", typed=True):
    columns = [{"name": "ID", "label": "Identity", "data_type": "NUMBER", "nullable": False,
                "primary_key": True, "identity": True},
               {"name": "TITLE", "label": "Title", "data_type": "VARCHAR2", "nullable": False,
                "primary_key": False, "identity": False, "length": 20}]
    if typed:
        columns += [{"name": "AMOUNT", "label": "Amount", "data_type": "NUMBER", "nullable": False,
                     "primary_key": False, "identity": False},
                    {"name": "DUE", "label": "Due", "data_type": "DATE", "nullable": True,
                     "primary_key": False, "identity": False}]
    return {"profile_id": "native-table-form-v1", "data_mode": "synthetic_test_only",
            "table_name": table, "columns": columns, "supported_operations": ["query", "insert", "update"]}


def objects(shared=True, typed=True):
    project = {"schema_version": 1, "profile_id": "native-project-v1", "data_mode": "synthetic_test_only",
        "project_name": "Synthetic project", "source_manifest_sha256": "a" * 64,
        "forms": [{"module_id": "form-" + str(index).zfill(20), "form_name": f"FORM_{index}",
                   "source_name": f"form{index}.xml", "source_sha256": str(index) * 64,
                   "native_form": native("FOX_NATIVE_SHARED" if shared else f"FOX_NATIVE_T{index}", typed)}
                  for index in (1, 2)]}
    trace = trace_for(project)
    return project, trace


def trace_for(project):
    forms, tables = [], {}
    for index, form in enumerate(project["forms"]):
        spec = form["native_form"]
        schema = {**spec, "columns": [{key: value for key, value in column.items() if key != "label"}
                                      for column in spec["columns"]]}
        digest = qa_plan_sha256(schema)
        tables.setdefault(spec["table_name"], {"table_name": spec["table_name"],
            "schema_contract_sha256": digest, "schema_sql_sha256": "e" * 64, "module_ids": []})["module_ids"].append(form["module_id"])
        report, page = index * 2 + 1, index * 2 + 2
        forms.append({key: form[key] for key in ("module_id", "form_name", "source_name", "source_sha256")} | {
            "report_page_id": report, "form_page_id": page, "report_alias": f"FORM_{index + 1}",
            "form_alias": f"EDIT_{index + 1}", "report_file": f"pages/p{report:05d}-form_{index + 1}.apx",
            "form_file": f"pages/p{page:05d}-edit_{index + 1}.apx", "table_name": spec["table_name"],
            "schema_contract_sha256": digest, "native_spec_sha256": qa_plan_sha256(spec),
            "items": [{"column": column["name"], "item": f"P{page}_{column['name']}"} for column in spec["columns"]]})
    return {"schema_version": 1, "scope": "fox-native-project-render-trace-v1",
        "project_name": project["project_name"], "source_manifest_sha256": project["source_manifest_sha256"],
        "rendering_spec_sha256": qa_plan_sha256(project), "application_count": 1,
        "form_count": len(forms), "forms": forms, "tables": [tables[name] for name in sorted(tables)],
        "template": {"template_id": "sqlcl-26.1.2-fox-project-v1", "sha256": "d" * 64,
            "profile_id": "native-project-v1", "data_mode": "synthetic_test_only", "max_forms": 50,
            "navigation_policy": "stable_module_id_order_not_inferred_business_flow",
            "home_policy": "first_report_not_a_business_start_claim"},
        "source_completeness_verified": False, "reviewer_approval_verified": False,
        "sqlcl_validated": False, "imported": False, "runtime_verified": False,
        "human_acceptance_recorded": False}


def plan_for(project, trace):
    return derive_project_qa_plan(project, qa_plan_sha256(project), trace, qa_plan_sha256(trace))


def values(spec, phase):
    row = {"create": ("A", "1", "2026-01-01"), "edit": ("B", "2", "2026-01-02"),
           "cancel_edit": ("C", "3", "2026-01-03"), "cancel_create": ("F", "6", "2026-01-06")}[phase]
    return {column["name"]: row[("VARCHAR2", "NUMBER", "DATE").index(column["data_type"])]
            for column in spec["columns"] if not column["primary_key"]}


def runtime(project, plan):
    result = {"schema_version": 1, "scope": "fox-project-runtime-qa-v1", "application_id": 444,
        "status": "PASSED", "test_plan": deepcopy(plan), "test_plan_sha256": qa_plan_sha256(plan),
        "forms": [], "human_acceptance_recorded": False, "credentials_recorded": False,
        "browser_storage_saved": False, "browser_errors": [], "network_denials": [],
        "delete_or_reset_performed": False, "final_table_records": {}}
    ledger = {table["table_name"]: [] for table in plan["tables"]}
    for index, (form, planned) in enumerate(zip(project["forms"], plan["forms"])):
        spec, table = form["native_form"], planned["table_name"]
        # Greater than JS safe-integer range and distinct in exact decimal text.
        key = str(900719925474099312345678901234567890 + index)
        base = derive_native_qa_plan(spec, planned["native_spec_sha256"])
        tests = [{**deepcopy(case), "required": case["applicable"],
                  "status": "PASSED" if case["applicable"] else "NOT_APPLICABLE",
                  "field_results": [{"field_name": name, "status": "PASSED"} for name in case["field_names"]],
                  "evidence": {}} for case in base["cases"]]
        by_name = {test["name"]: test for test in tests}
        by_name["login"]["evidence"] = {"authenticated": True, "rendered_application_id": 444,
            "report_page_id": planned["report_page_id"], "form_page_id": planned["form_page_id"],
            "navigation_module_id": form["module_id"]}
        for name in ("create", "reread", "edit_save", "cancel_edit", "cancel_create"):
            by_name[name]["evidence"] = {"observed_record": {"primary_key": key,
                "values": values(spec, "create" if name in ("create", "reread") else "edit")}}
            if name != "reread":
                phase = name if name in ("create", "cancel_edit", "cancel_create") else "edit"
                by_name[name]["evidence"].update(attempted_values=values(spec, phase),
                    action="CANCEL" if name.startswith("cancel_") else "CREATE" if name == "create" else "SAVE",
                    returned_report_page_id=planned["report_page_id"])
        for name in ("search_positive", "search_negative"):
            positive = name == "search_positive"
            by_name[name]["evidence"] = {"filter_column": "ID", "filter_value": key if positive else "0",
                                       "observed_primary_keys": [key] if positive else []}
        required_checks = [("preflight", None), ("final", None)] + [(name, None) for name in
            ("create", "reread", "edit_save", "cancel_edit", "cancel_create", "concurrent_edit")]
        for name in ("required_fields", "invalid_number", "invalid_date", "maximum_length"):
            observations = []
            for field in by_name[name]["field_names"]:
                column = next(column for column in spec["columns"] if column["name"] == field)
                observation = {"field_name": field, "item_name": planned["item_prefix"] + field,
                               "persisted_value": values(spec, "edit")[field]}
                if name == "maximum_length":
                    observation.update(declared_limit=column["length"], attempted_value="X" * (column["length"] + 1),
                                       observed_input_value="X" * column["length"])
                else:
                    observation.update(attempted_value={"required_fields": "", "invalid_number": "not-a-number",
                        "invalid_date": "not-a-date"}[name], validation_message_visible=True)
                observations.append(observation)
                required_checks.append((name, field))
            by_name[name]["evidence"] = {"field_observations": observations}
        winner = values(spec, "edit") | {planned["edit_field"]: "D"}
        by_name["concurrent_edit"]["evidence"] = {"field": planned["edit_field"], "independent_browser_contexts": 2,
            "account_identity_sha256": ["c" * 64, "d" * 64], "stale_writer_rejected": True,
            "account_contexts": [{"account_identity_sha256": account, "rendered_context": {
                "application_id": 444, "page_id": planned["form_page_id"],
                "page_item_names": [item["item"] for item in planned["items"]]}} for account in ("c" * 64, "d" * 64)],
            "attempted_stale_value": "E", "observed_record": {"primary_key": key, "values": winner}}
        by_name["browser_runtime_errors"]["evidence"] = {"unhandled_error_count": 0}
        for test in tests:
            if not test["applicable"]:
                continue
            report_context = {"application_id": 444, "page_id": planned["report_page_id"], "page_item_names": []}
            form_context = {"application_id": 444, "page_id": planned["form_page_id"],
                            "page_item_names": [item["item"] for item in planned["items"]]}
            test["evidence"]["rendered_contexts"] = ([report_context, form_context] if test["name"] == "login" else
                [report_context] if test["name"] in {"search_positive", "search_negative", "browser_runtime_errors"}
                else [form_context, form_context] if test["name"] == "concurrent_edit" else [form_context])
        baseline = deepcopy(ledger[table])
        ledger[table].append({"primary_key": key, "values": winner})
        def pagination(records):
            return {"page_primary_keys": [[record["primary_key"] for record in records]],
                    "reported_total_rows": len(records), "terminal_next_page_enabled": False}
        receipt = {"module_id": form["module_id"], "status": "PASSED",
            "form_binding": {key: deepcopy(value) for key, value in planned.items() if key not in {"cases", "row_tracking", "edit_field"}},
            "tests": tests, "additional_checks": [{"name": name, "required": False, "status": "NOT_RUN",
                "reason": "Separate operator readback"} for name in ("database_constraints", "database_sql_readback")],
            "row_tracking": {"mode": "retained_table_baseline_then_observed_pk",
                "observation_scope": "all_rows_not_visible_page_subset", "baseline_records": baseline,
                "baseline_pagination": pagination(baseline), "final_pagination": pagination(ledger[table]),
                "retained_primary_key": {"name": "ID", "value": key}, "final_records": deepcopy(ledger[table]),
                "pk_set_checks": [{"test_name": name, "field_name": field,
                    "observed_primary_keys": [record["primary_key"] for record in (baseline if name == "preflight" else ledger[table])],
                    "observation_scope": "all_rows_not_visible_page_subset",
                    "pagination": pagination(baseline if name == "preflight" else ledger[table])} for name, field in required_checks]}}
        result["forms"].append(receipt)
    result["final_table_records"] = deepcopy(ledger)
    return result


def test_project_plan_uses_all_forms_dynamic_pages_and_one_shared_physical_table():
    project, trace = objects()
    original = deepcopy(project), deepcopy(trace)
    plan = plan_for(project, trace)
    assert (project, trace) == original
    assert len(plan["forms"]) == 2 and len(plan["tables"]) == 1
    assert [form["primary_key"]["item_name"] for form in plan["forms"]] == ["P2_ID", "P4_ID"]
    assert plan["tables"][0]["module_ids"] == plan["execution_order"]
    profile = derive_project_qa_profile(project, plan)
    assert [form["primary_key_item"] for form in profile["forms"]] == ["P2_ID", "P4_ID"]


@pytest.mark.parametrize("shared", [False, True])
@pytest.mark.parametrize("typed", [False, True])
def test_complete_measured_runtime_with_retained_exact_numeric_keys(shared, typed):
    project, trace = objects(shared, typed)
    plan = plan_for(project, trace)
    result = runtime(project, plan)
    assert len(validate_project_qa_result(result, project, plan, 444)) == 2
    if shared:
        assert len(result["forms"][1]["row_tracking"]["baseline_records"]) == 1
        assert len(result["final_table_records"]["FOX_NATIVE_SHARED"]) == 2


@pytest.mark.parametrize("change", [
    lambda p, t: t["forms"].pop(),
    lambda p, t: t["forms"][1].update(form_page_id=2),
    lambda p, t: t["forms"][1]["items"][0].update(item="P2_ID"),
    lambda p, t: t["tables"].pop(),
    lambda p, t: t["tables"][0]["module_ids"].pop(),
    lambda p, t: p["forms"][1].update(module_id=p["forms"][0]["module_id"]),
    lambda p, t: p["forms"][1]["native_form"]["columns"][1].update(length=21),
    lambda p, t: t.update(application_count=True),
])
def test_missing_ambiguous_or_tampered_project_mapping_never_derives(change):
    project, trace = objects()
    change(project, trace)
    with pytest.raises(ProjectQaPlanError):
        plan_for(project, trace)


def test_conditional_cases_are_independent_for_each_form():
    project, _ = objects(shared=False)
    project["forms"][1]["native_form"] = native("FOX_NATIVE_OTHER", typed=False)
    plan = plan_for(project, trace_for(project))
    numbers = [next(case for case in form["cases"] if case["name"] == "invalid_number") for form in plan["forms"]]
    assert numbers[0]["field_names"] == ["AMOUNT"] and numbers[1]["applicable"] is False
    assert validate_project_qa_result(runtime(project, plan), project, plan, 444)


@pytest.mark.parametrize("change", [
    lambda r: r["forms"].pop(),
    lambda r: r["forms"].reverse(),
    lambda r: r["forms"].__setitem__(1, deepcopy(r["forms"][0])),
    lambda r: r.update(application_id=True),
    lambda r: r.update(human_acceptance_recorded=True),
    lambda r: r.update(delete_or_reset_performed=True),
    lambda r: r["forms"][1]["form_binding"].update(item_prefix="P2_"),
    lambda r: r["forms"][1]["row_tracking"].update(baseline_records=[]),
    lambda r: r["forms"][1]["row_tracking"]["final_records"].pop(0),
    lambda r: r["forms"][1]["row_tracking"]["final_records"][0]["values"].update(TITLE="changed"),
    lambda r: r["forms"][0]["row_tracking"]["retained_primary_key"].update(value=9007199254740993),
    lambda r: r["forms"][0]["row_tracking"].update(observation_scope="visible_page"),
    lambda r: r["forms"][1]["row_tracking"]["final_pagination"].update(reported_total_rows=20),
    lambda r: r["forms"][1]["row_tracking"]["final_pagination"].update(terminal_next_page_enabled=True),
    lambda r: r["forms"][1]["row_tracking"]["final_pagination"]["page_primary_keys"][0].pop(0),
    lambda r: r["forms"][0]["row_tracking"]["pk_set_checks"].pop(),
    lambda r: r["forms"][0]["tests"][1].update(evidence={}),
    lambda r: r["forms"][0]["tests"][0]["evidence"].update(form_page_id=4),
    lambda r: r["forms"][1]["tests"][1]["evidence"]["rendered_contexts"][0].update(page_id=2),
    lambda r: r["forms"][1]["tests"][6]["evidence"].pop("attempted_values"),
    lambda r: r["forms"][1]["tests"][7]["evidence"].pop("action"),
    lambda r: r["forms"][0]["tests"][-2]["evidence"].update(account_identity_sha256=["c" * 64, "c" * 64]),
    lambda r: r["forms"][0]["tests"][-2]["evidence"]["account_contexts"][1].update(account_identity_sha256="c" * 64),
    lambda r: r["forms"][0]["tests"][-2]["evidence"]["observed_record"]["values"].update(TITLE="E"),
    lambda r: r["forms"][0]["tests"][-1]["evidence"].update(unhandled_error_count=False),
    lambda r: r["final_table_records"].clear(),
])
def test_passed_flags_cannot_cover_missing_or_failed_observations(change):
    project, trace = objects()
    plan = plan_for(project, trace)
    result = runtime(project, plan)
    change(result)
    with pytest.raises(ProjectQaPlanError):
        validate_project_qa_result(result, project, plan, 444)


@pytest.mark.parametrize("name", ["required_fields", "invalid_number", "invalid_date", "maximum_length"])
def test_every_applicable_field_requires_actual_validation_observation(name):
    project, trace = objects()
    plan = plan_for(project, trace)
    result = runtime(project, plan)
    test = next(test for test in result["forms"][1]["tests"] if test["name"] == name)
    test["evidence"]["field_observations"].clear()
    with pytest.raises(ProjectQaPlanError):
        validate_project_qa_result(result, project, plan, 444)


def test_old_single_form_receipt_is_not_project_proof():
    project, trace = objects()
    plan = plan_for(project, trace)
    with pytest.raises(ProjectQaPlanError):
        validate_project_qa_result({"scope": "fox-native-runtime-qa-v2", "status": "PASSED"}, project, plan, 444)


def test_exhaustive_pagination_covers_retained_rows_across_multiple_pages():
    project, trace = objects()
    plan = plan_for(project, trace)
    result = runtime(project, plan)
    pagination = result["forms"][1]["row_tracking"]["final_pagination"]
    pagination["page_primary_keys"] = [[key] for key in pagination["page_primary_keys"][0]]
    assert validate_project_qa_result(result, project, plan, 444)
