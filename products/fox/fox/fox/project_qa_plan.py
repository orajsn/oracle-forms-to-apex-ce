"""Pure whole-project QA contract. No target access, writes or acceptance.

Project/spec/trace byte hashes bind the packaged documents. A form's native
spec hash is the canonical nested object hash used by the renderer, not a
pretended separate file hash. The caller independently verifies source
completeness and package provenance before trusting this structural plan.

Runtime receipts are observations from an owner-controlled runner, not vendor
signatures. Every form must execute; a shared table does not waive its cases.
Rows from earlier forms are retained and checked, never reset for convenience.
"""
from __future__ import annotations

import re

from .native_qa_plan import (NativeQaPlanError, derive_native_qa_plan,
                             derive_native_qa_profile, qa_plan_sha256,
                             validate_native_qa_result_cases)
from .project_conversion import (ProjectConversionInputError,
                                 validate_project_storage_mappings)


PROFILE_ID = "native-project-v1"
PLAN_SCOPE = "fox-project-qa-plan-v1"
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_MODULE = re.compile(r"form-[a-f0-9]{20}\Z")
_KEY = re.compile(r"[1-9][0-9]{0,37}\Z")
_CONDITIONAL = {"required_fields", "invalid_number", "invalid_date", "maximum_length"}
_PROJECT_FIELDS = {"schema_version", "profile_id", "data_mode", "project_name",
                   "source_manifest_sha256", "forms"}
_FORM_FIELDS = {"module_id", "form_name", "source_name", "source_sha256", "native_form"}
_TRACE_FIELDS = {"schema_version", "scope", "project_name", "source_manifest_sha256",
                 "rendering_spec_sha256", "application_count", "form_count", "forms", "tables", "template",
                 "source_completeness_verified", "reviewer_approval_verified", "sqlcl_validated",
                 "imported", "runtime_verified", "human_acceptance_recorded"}
_TRACE_NOT_PROOF = {"source_completeness_verified", "reviewer_approval_verified", "sqlcl_validated",
                    "imported", "runtime_verified", "human_acceptance_recorded"}
_TEMPLATE_FIELDS = {"template_id": "sqlcl-26.1.2-fox-project-v1", "profile_id": PROFILE_ID,
                    "data_mode": "synthetic_test_only", "max_forms": 50,
                    "navigation_policy": "stable_module_id_order_not_inferred_business_flow",
                    "home_policy": "first_report_not_a_business_start_claim"}


class ProjectQaPlanError(ValueError):
    """Bounded project metadata or observation failure."""


def _require(condition, message):
    if not condition:
        raise ProjectQaPlanError(message)


def _same(left, right):
    return qa_plan_sha256({"value": left}) == qa_plan_sha256({"value": right})


def _schema(spec):
    # Normalize optional false flags exactly as the established native contract.
    return {"profile_id": spec["profile_id"], "data_mode": spec["data_mode"],
            "table_name": spec["table_name"], "supported_operations": ["query", "insert", "update"],
            "columns": [{**{key: value for key, value in column.items() if key != "label"},
                         "primary_key": column.get("primary_key", False),
                         "identity": column.get("identity", False)} for column in spec["columns"]]}


def _derive(project, project_spec_sha256, trace, trace_sha256):
    _require(isinstance(project, dict) and type(project.get("schema_version")) is int
        and project["schema_version"] in {1, 2},
        "Project QA requires an explicit supported project specification version.")
    mapped = project["schema_version"] == 2
    _require(set(project) == _PROJECT_FIELDS | ({"project_id"} if mapped else set())
        and project["profile_id"] == PROFILE_ID and project["data_mode"] == "synthetic_test_only",
        "Project QA requires the explicit supported synthetic project specification.")
    _require(all(isinstance(value, str) and _SHA.fullmatch(value)
                 for value in (project_spec_sha256, trace_sha256, project["source_manifest_sha256"])),
             "Exact project specification and trace byte hashes are required.")
    forms = project["forms"]
    _require(isinstance(forms, list) and 1 <= len(forms) <= 50
             and all(isinstance(form, dict) and set(form) == _FORM_FIELDS |
                     ({"ddl_sources", "storage_mapping"} if mapped else set()) for form in forms),
             "Project QA must include every supported form.")
    if mapped:
        # Recompute the full identity from the original name and structural
        # schema, then prove the declared physical table is its projection.
        # Both full and truncated collisions fail before any runtime plan.
        validate_project_storage_mappings(forms, project_id=project["project_id"])
        sources = {}
        for form in forms:
            for source in [{"name": form["source_name"], "sha256": form["source_sha256"]}, *form["ddl_sources"]]:
                key = source["name"].casefold()
                _require(key not in sources or sources[key] == source,
                         "Original source filenames have conflicting byte identities.")
                sources[key] = source
    ids = [form["module_id"] for form in forms]
    _require(all(isinstance(value, str) and _MODULE.fullmatch(value) for value in ids)
             and len(set(ids)) == len(ids) and ids == sorted(ids),
             "Project modules must be unique and in canonical order.")
    _require(isinstance(trace, dict) and set(trace) == _TRACE_FIELDS | ({"project_id"} if mapped else set())
             and trace.get("scope") == f"fox-native-project-render-trace-v{project['schema_version']}"
             and type(trace.get("schema_version")) is int and trace["schema_version"] == project["schema_version"]
             and (not mapped or trace["project_id"] == project["project_id"])
             and type(trace.get("application_count")) is int and trace["application_count"] == 1
             and type(trace.get("form_count")) is int and trace["form_count"] == len(forms)
             and trace.get("project_name") == project["project_name"]
             and trace.get("source_manifest_sha256") == project["source_manifest_sha256"]
             and trace.get("rendering_spec_sha256") == qa_plan_sha256(project)
             and isinstance(trace.get("forms"), list) and len(trace["forms"]) == len(forms),
             "Project trace is incomplete or bound to another specification.")
    template = trace["template"]
    _require(all(trace[key] is False for key in _TRACE_NOT_PROOF)
             and isinstance(template, dict) and set(template) == set(_TEMPLATE_FIELDS) | {"sha256"}
             and all(_same(template[key], value) for key, value in _TEMPLATE_FIELDS.items())
             and isinstance(template["sha256"], str) and _SHA.fullmatch(template["sha256"]),
             "Render trace template metadata or non-proof declarations differ.")
    plans, tables, trace_tables, schemas = [], {}, {}, {}
    for index, (form, mapping) in enumerate(zip(forms, trace["forms"])):
        _require(isinstance(form["source_sha256"], str) and _SHA.fullmatch(form["source_sha256"]),
                 "A form lacks its exact source identity.")
        native = form["native_form"]
        native_hash = qa_plan_sha256(native)
        base = derive_native_qa_plan(native, native_hash)
        report_page, form_page = index * 2 + 1, index * 2 + 2
        schema = _schema(native)
        schema_hash = qa_plan_sha256(schema)
        table = native["table_name"]
        _require(table not in schemas or _same(schemas[table], schema),
                 "Forms sharing a physical table have conflicting schemas.")
        schemas[table] = schema
        expected_mapping = {key: form[key] for key in ("module_id", "form_name", "source_name", "source_sha256")}
        expected_mapping.update(report_page_id=report_page, form_page_id=form_page,
            report_alias=f"FORM_{index + 1}", form_alias=f"EDIT_{index + 1}",
            report_file=f"pages/p{report_page:05d}-form_{index + 1}.apx",
            form_file=f"pages/p{form_page:05d}-edit_{index + 1}.apx",
            table_name=table, schema_contract_sha256=schema_hash, native_spec_sha256=native_hash,
            items=[{"column": column["name"], "item": f"P{form_page}_{column['name']}"}
                   for column in native["columns"]])
        if mapped:
            expected_mapping.update(ddl_sources=form["ddl_sources"], storage_mapping=form["storage_mapping"])
        _require(_same(mapping, expected_mapping), "A form trace has missing or mismatched pages, items or source bindings.")
        tables.setdefault(table, {"table_name": table, "schema_contract_sha256": schema_hash,
                                  "module_ids": []})["module_ids"].append(form["module_id"])
        if mapped:
            entry = trace_tables.setdefault(table, {"storage_mapping": form["storage_mapping"], "ddl_sources": {}})
            for source in form["ddl_sources"]:
                entry["ddl_sources"][source["name"]] = source
        plans.append({"module_id": form["module_id"], "form_name": form["form_name"],
            "source_name": form["source_name"], "source_sha256": form["source_sha256"],
            "table_name": table, "native_spec_sha256": native_hash,
            "schema_contract_sha256": schema_hash, "report_page_id": report_page,
            "form_page_id": form_page, "report_alias": f"FORM_{index + 1}",
            "form_alias": f"EDIT_{index + 1}", "item_prefix": f"P{form_page}_",
            "items": expected_mapping["items"], "primary_key": {
                **base["primary_key"], "item_name": f"P{form_page}_{base['primary_key']['name']}"},
            "row_tracking": {"mode": "retained_table_baseline_then_observed_pk", "delete_or_reset_allowed": False},
            "edit_field": base["edit_field"], "cases": base["cases"]})
    expected_tables = [tables[name] for name in sorted(tables)]
    _require(isinstance(trace.get("tables"), list) and len(trace["tables"]) == len(expected_tables),
             "Project trace does not cover each distinct physical table.")
    for actual, expected in zip(trace["tables"], expected_tables):
        expected_trace = dict(expected)
        if mapped:
            entry = trace_tables[expected["table_name"]]
            expected_trace.update(storage_mapping=entry["storage_mapping"],
                                  ddl_sources=[entry["ddl_sources"][name] for name in sorted(entry["ddl_sources"])])
        _require(isinstance(actual, dict) and set(actual) == set(expected_trace) | {"schema_sql_sha256"}
                 and all(_same(actual[key], value) for key, value in expected_trace.items())
                 and isinstance(actual["schema_sql_sha256"], str) and _SHA.fullmatch(actual["schema_sql_sha256"]),
                 "Project trace has orphaned, duplicate or conflicting physical tables.")
    return {"schema_version": 1, "scope": PLAN_SCOPE, "profile_id": PROFILE_ID,
        "data_mode": "synthetic_test_only", "source_manifest_sha256": project["source_manifest_sha256"],
        "project_spec_sha256": project_spec_sha256, "source_to_apex_sha256": trace_sha256,
        "application_count": 1, "form_count": len(plans), "forms": plans,
        "tables": expected_tables, "execution_order": ids,
        "table_observation_scope": "all_rows_not_visible_page_subset",
        "delete_or_reset_allowed": False, "human_acceptance_recorded": False}


def derive_project_qa_plan(project, project_spec_sha256, trace, trace_sha256):
    """Derive all forms; bytes must be duplicate-key-safe parsed by the caller."""
    try:
        return _derive(project, project_spec_sha256, trace, trace_sha256)
    except (NativeQaPlanError, ProjectConversionInputError, KeyError, TypeError, AttributeError, RecursionError):
        raise ProjectQaPlanError("Project QA metadata is malformed or unsupported.") from None


def derive_project_qa_profile(project, plan):
    """Deterministic values/selectors for every form, with no omission overrides."""
    _require(len(project["forms"]) == len(plan["forms"]), "Project profile form coverage differs.")
    forms = []
    for form, expected in zip(project["forms"], plan["forms"]):
        _require(form["module_id"] == expected["module_id"], "Project profile module identity differs.")
        profile = derive_native_qa_profile(form["native_form"])
        forms.append({"module_id": form["module_id"], "report_page_id": expected["report_page_id"],
            "form_page_id": expected["form_page_id"], "item_prefix": expected["item_prefix"],
            "primary_key_item": expected["primary_key"]["item_name"], "native_profile": profile})
    return {"schema_version": 1, "scope": "fox-project-qa-profile-v1", "profile_id": PROFILE_ID,
            "test_plan_sha256": qa_plan_sha256(plan), "forms": forms}


def _keys(value):
    _require(isinstance(value, list) and all(isinstance(key, str) and _KEY.fullmatch(key) for key in value)
             and len(value) == len(set(value)), "Observed row keys must be unique exact positive decimal strings.")
    return set(value)


def _records(value, native):
    _require(isinstance(value, list), "Complete observed row records are required.")
    columns = [column for column in native["columns"] if not column.get("primary_key")]
    records = {}
    for record in value:
        _require(isinstance(record, dict) and set(record) == {"primary_key", "values"}, "Observed row record is malformed.")
        key = record["primary_key"]
        _keys([key])
        _require(key not in records and isinstance(record["values"], dict)
                 and set(record["values"]) == {column["name"] for column in columns},
                 "Observed row keys or field coverage is incomplete.")
        for column in columns:
            val = record["values"][column["name"]]
            _require(val is None and column["nullable"] or isinstance(val, str),
                     "Observed values must preserve exact strings or declared nulls.")
        records[key] = record["values"]
    return records


def _pagination(value, expected_keys):
    """Require measured report-page coverage, not a visible-page-only claim."""
    _require(isinstance(value, dict) and set(value) == {
        "page_primary_keys", "reported_total_rows", "terminal_next_page_enabled"},
        "Complete report pagination observations are required.")
    pages = value["page_primary_keys"]
    _require(isinstance(pages, list) and pages and all(isinstance(page, list) for page in pages),
             "Observed report pages are missing.")
    for page in pages:
        _keys(page)
    flattened = [key for page in pages for key in page]
    _require(_keys(flattened) == set(expected_keys)
             and type(value["reported_total_rows"]) is int and value["reported_total_rows"] == len(flattened)
             and value["terminal_next_page_enabled"] is False,
             "Report pagination omitted or duplicated rows, or did not reach the final page.")


def _values(native, phase, edit_field=None):
    values = {"create": ("A", "1", "2026-01-01"), "edit": ("B", "2", "2026-01-02"),
              "cancel_edit": ("C", "3", "2026-01-03"), "winner": ("D", "4", "2026-01-04"),
              "stale": ("E", "5", "2026-01-05"), "cancel_create": ("F", "6", "2026-01-06")}
    result = {}
    for column in native["columns"]:
        if column.get("primary_key"):
            continue
        chosen = "edit" if phase == "winner" and column["name"] != edit_field else phase
        result[column["name"]] = values[chosen][("VARCHAR2", "NUMBER", "DATE").index(column["data_type"])]
    return result


def _validate_result(result, project, plan, application_id):
    _require(type(application_id) is int and application_id > 0, "An exact application identity is required.")
    _require(isinstance(result, dict) and result.get("scope") == "fox-project-runtime-qa-v1"
             and type(result.get("schema_version")) is int and result["schema_version"] == 1
             and result.get("status") == "PASSED" and result.get("application_id") == application_id
             and type(result.get("application_id")) is int
             and _same(result.get("test_plan"), plan)
             and result.get("test_plan_sha256") == qa_plan_sha256(plan),
             "Project runtime result is not bound to the independently derived plan and application.")
    forms = result.get("forms")
    _require(isinstance(forms, list) and len(forms) == len(plan["forms"])
             and [item.get("module_id") if isinstance(item, dict) else None for item in forms] == plan["execution_order"],
             "Project runtime omitted, duplicated or reordered a form.")
    _require(result.get("human_acceptance_recorded") is False
             and result.get("credentials_recorded") is False and result.get("browser_storage_saved") is False
             and result.get("browser_errors") == [] and result.get("network_denials") == []
             and result.get("delete_or_reset_performed") is False,
             "Project runtime reported unsafe side effects or errors.")
    ledger = {item["table_name"]: {} for item in plan["tables"]}
    indexed = {}
    for receipt, form, expected in zip(forms, project["forms"], plan["forms"]):
        native, table = form["native_form"], expected["table_name"]
        _require(_same(receipt.get("form_binding"), {key: value for key, value in expected.items()
                                                   if key not in {"cases", "row_tracking", "edit_field"}}),
                 "Runtime form source, pages, items or table binding differs.")
        # Reuse the established fourteen-case/field validator only for coverage.
        # Its v2 clean-single-row semantics are deliberately NOT reused.
        base = derive_native_qa_plan(native, expected["native_spec_sha256"])
        coverage = {**receipt, "test_plan": base, "test_plan_sha256": qa_plan_sha256(base)}
        tests = validate_native_qa_result_cases(coverage, base)
        # Declaring form_binding at the top is insufficient: a runner could
        # navigate to B then accidentally run B's cases against a stale A tab.
        # Each attempted case must record its rendered app/page/item surface.
        report_context = {"application_id": application_id, "page_id": expected["report_page_id"], "page_item_names": []}
        form_context = {"application_id": application_id, "page_id": expected["form_page_id"],
                        "page_item_names": [item["item"] for item in expected["items"]]}
        for case in expected["cases"]:
            if not case["applicable"]:
                continue
            contexts = ([report_context, form_context] if case["name"] == "login" else
                        [report_context] if case["name"] in {"search_positive", "search_negative", "browser_runtime_errors"}
                        else [form_context, form_context] if case["name"] == "concurrent_edit"
                        else [form_context])
            _require(_same(tests[case["name"]].get("evidence", {}).get("rendered_contexts"), contexts),
                     "An applicable runtime case ran on an unobserved or different module surface.")
        login = tests["login"].get("evidence", {})
        _require(login.get("authenticated") is True
                 and type(login.get("rendered_application_id")) is int and login["rendered_application_id"] == application_id
                 and type(login.get("report_page_id")) is int and login["report_page_id"] == expected["report_page_id"]
                 and type(login.get("form_page_id")) is int and login["form_page_id"] == expected["form_page_id"]
                 and login.get("navigation_module_id") == expected["module_id"],
                 "Authenticated navigation did not observe this module's application and pages.")
        tracking = receipt.get("row_tracking", {})
        _require(tracking.get("mode") == "retained_table_baseline_then_observed_pk"
                 and tracking.get("observation_scope") == "all_rows_not_visible_page_subset",
                 "Runtime must observe the entire physical table, including retained rows.")
        baseline = _records(tracking.get("baseline_records"), native)
        _require(_same(baseline, ledger[table]), "Runtime lost or changed retained rows from an earlier form.")
        _pagination(tracking.get("baseline_pagination"), baseline)
        key = tracking.get("retained_primary_key", {})
        _require(isinstance(key, dict) and set(key) == {"name", "value"}
                 and key["name"] == expected["primary_key"]["name"], "Runtime did not observe the mapped primary key.")
        _keys([key["value"]])
        _require(key["value"] not in baseline, "Runtime reused an existing row instead of observing one new identity.")
        post_keys = set(baseline) | {key["value"]}
        required_checks = {("preflight", None), ("final", None)}
        required_checks.update((name, None) for name in ("create", "reread", "edit_save", "cancel_edit", "cancel_create", "concurrent_edit"))
        required_checks.update((case["name"], field) for case in expected["cases"] if case["name"] in _CONDITIONAL
                               for field in case["field_names"])
        checks = tracking.get("pk_set_checks")
        _require(isinstance(checks, list) and len(checks) == len(required_checks), "Runtime row-set coverage is incomplete.")
        seen = set()
        for check in checks:
            _require(isinstance(check, dict) and set(check) == {"test_name", "field_name", "observed_primary_keys", "observation_scope", "pagination"},
                     "A runtime row-set observation is malformed.")
            identity = (check["test_name"], check["field_name"])
            _require(identity in required_checks and identity not in seen
                     and check["observation_scope"] == "all_rows_not_visible_page_subset"
                     and _keys(check["observed_primary_keys"]) == (set(baseline) if identity[0] == "preflight" else post_keys),
                     "A cancelled, rejected or successful operation changed unexpected rows.")
            _pagination(check["pagination"], check["observed_primary_keys"])
            seen.add(identity)
        for name, phase in (("create", "create"), ("reread", "create"), ("edit_save", "edit"),
                            ("cancel_edit", "edit"), ("cancel_create", "edit")):
            observation = tests[name].get("evidence", {})
            _require(_same(observation.get("observed_record"), {"primary_key": key["value"], "values": _values(native, phase)}),
                     "Runtime lacks the complete created, edited or preserved field readback.")
            if name != "reread":
                attempted_phase = name if name in {"cancel_edit", "cancel_create"} else phase
                _require(_same(observation.get("attempted_values"), _values(native, attempted_phase))
                         and observation.get("action") == ("CANCEL" if name.startswith("cancel_") else "CREATE" if name == "create" else "SAVE")
                         and type(observation.get("returned_report_page_id")) is int
                         and observation["returned_report_page_id"] == expected["report_page_id"],
                         "Runtime did not observe the intended input/action and return navigation.")
        for name, matches in (("search_positive", [key["value"]]), ("search_negative", [])):
            observation = tests[name].get("evidence", {})
            _require(observation.get("filter_column") == expected["primary_key"]["name"]
                     and observation.get("filter_value") == (key["value"] if matches else "0")
                     and _keys(observation.get("observed_primary_keys")) == set(matches),
                     "Runtime search did not observe the expected exact-key match set.")
        for name in _CONDITIONAL:
            case = next(case for case in expected["cases"] if case["name"] == name)
            observations = tests[name].get("evidence", {}).get("field_observations", [])
            _require(isinstance(observations, list) and len(observations) == len(case["field_names"])
                     and [item.get("field_name") if isinstance(item, dict) else None for item in observations] == case["field_names"],
                     "Runtime validation observations omit an applicable field.")
            for observation in observations:
                _require(observation.get("item_name") == expected["item_prefix"] + observation["field_name"]
                         and observation.get("persisted_value") == _values(native, "edit")[observation["field_name"]],
                         "A rejected value persisted or its readback is missing.")
                if name == "maximum_length":
                    column = next(column for column in native["columns"] if column["name"] == observation["field_name"])
                    _require(type(observation.get("declared_limit")) is int and observation["declared_limit"] == column["length"]
                             and observation.get("attempted_value") == "X" * (column["length"] + 1)
                             and (observation.get("observed_input_value") == "X" * column["length"]
                                  or observation.get("observed_input_value") == observation["attempted_value"]
                                  and observation.get("validation_message_visible") is True),
                             "Runtime maximum-length behavior is unobserved.")
                else:
                    invalid = {"required_fields": "", "invalid_number": "not-a-number", "invalid_date": "not-a-date"}[name]
                    _require(observation.get("attempted_value") == invalid
                             and observation.get("validation_message_visible") is True,
                             "Runtime invalid-input behavior is unobserved.")
        concurrency = tests["concurrent_edit"].get("evidence", {})
        accounts = concurrency.get("account_identity_sha256")
        winner = _values(native, "winner", expected["edit_field"])
        _require(concurrency.get("field") == expected["edit_field"]
                 and type(concurrency.get("independent_browser_contexts")) is int and concurrency["independent_browser_contexts"] == 2
                 and isinstance(accounts, list) and len(accounts) == 2 and len(set(accounts)) == 2
                 and all(isinstance(account, str) and _SHA.fullmatch(account) for account in accounts)
                 and _same(concurrency.get("account_contexts"), [
                     {"account_identity_sha256": account, "rendered_context": form_context} for account in accounts])
                 and concurrency.get("stale_writer_rejected") is True
                 and concurrency.get("attempted_stale_value") == _values(native, "stale")[expected["edit_field"]]
                 and _same(concurrency.get("observed_record"), {"primary_key": key["value"], "values": winner}),
                 "Independent-account concurrency or first-writer readback is unproven.")
        errors = tests["browser_runtime_errors"].get("evidence", {}).get("unhandled_error_count")
        _require(type(errors) is int and errors == 0, "Runtime error observations are missing.")
        final = _records(tracking.get("final_records"), native)
        _require(_same(final, {**baseline, key["value"]: winner}), "Runtime modified or deleted a retained row.")
        _pagination(tracking.get("final_pagination"), final)
        ledger[table] = final
        indexed[expected["module_id"]] = tests
    observed = result.get("final_table_records")
    _require(isinstance(observed, dict) and set(observed) == set(ledger), "Final physical-table coverage is incomplete.")
    for table, records in ledger.items():
        native = next(form["native_form"] for form in project["forms"] if form["native_form"]["table_name"] == table)
        _require(_same(_records(observed[table], native), records), "Final physical-table readback differs from the retained-row ledger.")
    return indexed


def validate_project_qa_result(result, project, plan, application_id):
    """Validate every case's measured observations, not a project passed flag.

    ``plan`` must come from independently checked exact package bytes, never
    from the result. Clean import establishes empty tables; subsequent forms
    inherit the complete retained-row ledger for each shared physical table.
    """
    try:
        return _validate_result(result, project, plan, application_id)
    except (NativeQaPlanError, KeyError, TypeError, AttributeError, RecursionError):
        raise ProjectQaPlanError("Project runtime observations are malformed or incomplete.") from None
