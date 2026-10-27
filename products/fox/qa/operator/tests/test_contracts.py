"""Offline tests: no network, secrets, subprocesses, files, or database access."""

from copy import deepcopy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest


MODULE = Path(__file__).resolve().parents[1] / "contracts.py"
SPEC = importlib.util.spec_from_file_location("fox_operator_contracts", MODULE)
c = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(c)

JOB = "fox-aaaaaaaaaaaaaaaaaaaa"
NAMESPACE = "FOX_QA_261017_89ABCDEF"
TIME = "2026-10-17T01:02:03.000000Z"
LATER = "2026-10-17T01:03:03.000000Z"
HASH = "a" * 64
CODE = "b" * 64
NATIVE = "c" * 64


def fixture():
    sql, schema = b"-- already validated original application SQL\n", b"-- already validated exact synthetic schema SQL\n"
    source = {"schema_version": 1, "scope": c.SOURCE_SCOPE, "observed_at_utc": TIME,
              "instance_id": c.INSTANCE, "compartment_id": c.COMPARTMENT, "region": c.REGION,
              "job_id": JOB, "run_state": "QA_REQUIRED", "package_sha256": "1" * 64,
              "package_bytes": 12345, "source_manifest_sha256": "2" * 64}
    package = {"package_sha256": source["package_sha256"], "job_id": JOB,
               "source_manifest_sha256": source["source_manifest_sha256"], "application_id": 123,
               "application_alias": "F2A_FOX_AAAAAAAAAAAAAAAAAAAA",
               "native_form": {"profile_id": "native-table-form-v1", "data_mode": "synthetic_test_only", "table_name": "FOX_NATIVE_BETA"},
               "schema_member": "schema/01_synthetic_schema.sql", "application_member": "sql/f123.sql",
               "schema_sql": schema, "application_sql": sql,
               "selected_member_sha256": {"schema/01_synthetic_schema.sql": c.digest(schema), "sql/f123.sql": c.digest(sql)},
               "validation_scope": "package_integrity_and_synthetic_schema_only",
               "review_proof_scope": "fixture", "historical_model_environment_verified": False,
               "historical_target_profile": None, "current_target_authorized": False, "customer_compatibility_verified": False}
    package["release_evidence"] = {"job_id": JOB, "application_id": 123,
        "application_alias": package["application_alias"], "source_manifest_sha256": source["source_manifest_sha256"],
        "package_reimport": {"passed": True, "application_id": 456,
                             "application_alias": package["application_alias"] + "_SQLCHECK"}}
    return source, package


def plan():
    source, package = fixture()
    return c.make_plan(source, package, NAMESPACE, TIME, native_spec_sha256=NATIVE, operator_code_sha256=CODE)


def allocation(p=None):
    p = p or plan()
    return {"schema_version": 1, "scope": c.ALLOCATION_SCOPE, "passed": True,
            "plan_sha256": c.plan_sha256(p), "allocated_at_utc": LATER,
            "binding": {key: p["binding"][key] for key in ("job_id", "source_manifest_sha256", "package_sha256")},
            "target": {**p["target"], "workspace_id": "22042420337195501", "application_id": 34567},
            "observed_versions": dict(c.VERSIONS), "fresh_namespace": {"workspace_created_fresh": True,
                "schema_created_fresh": True, "application_count": 0, "user_object_count": 0}}


def phase(state="intent", name="allocate"):
    return {"schema_version": 1, "scope": c.PHASE_SCOPE, "plan_sha256": c.plan_sha256(plan()),
            "phase": name, "state": state, "started_at_utc": TIME,
            "finished_at_utc": LATER if state == "complete" else None,
            "evidence_sha256": HASH if state == "complete" else None}


class ContractTests(unittest.TestCase):
    def test_public_failure_is_an_allowlist_not_an_exception_text_filter(self):
        diagnostic = {'category': 'SQL_EXECUTION_FAILED', 'error_codes': ['ORA-01031', 'SP2-0552'], 'return_code': 1}
        result = c.failure_response('PHASE_UNCONFIRMED_NO_REPLAY', 'schema', diagnostic)
        self.assertEqual(result['diagnostics'], diagnostic)
        self.assertEqual(result['phase'], 'schema')
        self.assertFalse(result['automatic_replay_permitted'])
        self.assertEqual(c.failure_response('UPPERCASE_SECRET', 'not a phase'), {
            'status': 'STOPPED', 'code': 'OPERATOR_GUARD_FAILED_OUTPUT_WITHHELD',
            'automatic_replay_permitted': False, 'phase': None})

    def test_sql_diagnostic_fields_types_and_numeric_codes_are_bounded(self):
        diagnostic = {'category': 'SQL_EXECUTION_FAILED', 'error_codes': ['ORA-01031'], 'return_code': 1}
        bad = [{**diagnostic, 'provider_text': 'secret'}, {**diagnostic, 'category': 'SECRET'},
               {**diagnostic, 'error_codes': ['ORA-01031 secret']}, {**diagnostic, 'error_codes': ['ORA-010310']},
               {**diagnostic, 'error_codes': ['ORA-01031'] * 9}, {**diagnostic, 'return_code': True},
               {**diagnostic, 'return_code': '1 secret'}, {**diagnostic, 'return_code': 2 ** 32}]
        for value in bad:
            with self.subTest(value=value):
                self.assertIsNone(c.safe_diagnostics(value))
                self.assertNotIn('diagnostics', c.failure_response('SQL_FAILED_OUTPUT_WITHHELD', diagnostics=value))

    def test_old_golden_application_id_is_never_a_new_allocation(self):
        value = allocation()
        value['target']['application_id'] = 103
        with self.assertRaises(c.ContractError):
            c.validate_allocation(value, plan())

    def test_canonical_json_sorted_compact_utf8_and_lf(self):
        self.assertEqual(c.canonical_bytes({"z": "é", "a": 2}), b'{"a":2,"z":"\xc3\xa9"}\n')
        self.assertEqual(c.digest(b"abc"), hashlib.sha256(b"abc").hexdigest())

    def test_json_rejects_duplicate_keys_at_every_level(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":{"a":1,"a":2}}'):
            with self.subTest(raw=raw), self.assertRaises(c.ContractError):
                c.load_json(raw)

    def test_json_rejects_nan_float_utf8_arrays_and_limits(self):
        for raw in (b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1.0}', b'[]', b'\xff', b'\xef\xbb\xbf{}', b"{}" * 40000):
            with self.subTest(raw=raw[:32]), self.assertRaises(c.ContractError):
                c.load_json(raw)

    def test_canonical_types_fail_closed(self):
        for value in ({1: "x"}, {"x": 1.0}, {"x": b"secret"}, {"x": "\ud800"}, [], {"x": "z" * c.MAX_JSON_BYTES}):
            with self.subTest(value_type=type(value)), self.assertRaises(c.ContractError):
                c.canonical_bytes(value)
        with self.assertRaises(c.ContractError):
            c.digest("not bytes")

    def test_deep_json_is_bounded(self):
        nested = {}
        for _ in range(22):
            nested = {"x": nested}
        with self.assertRaises(c.ContractError):
            c.canonical_bytes(nested)

    def test_valid_plan_detaches_mutable_inputs(self):
        source, package = fixture()
        p = c.make_plan(source, package, NAMESPACE, TIME, native_spec_sha256=NATIVE, operator_code_sha256=CODE)
        source["run_state"] = "ATTENTION"
        package["native_form"]["table_name"] = "OTHER"
        self.assertEqual(p["source_origin"]["run_state"], "QA_REQUIRED")
        self.assertEqual(p["binding"]["table_name"], "FOX_NATIVE_BETA")
        restored = c.validate_plan(c.canonical_bytes(p))
        restored["target"]["workspace"] = "OTHER"
        self.assertEqual(p["target"]["workspace"], NAMESPACE)

    def test_raw_plan_hash_equals_canonical_hash(self):
        p = plan(); raw = c.canonical_bytes(p)
        self.assertEqual(c.plan_sha256(raw), c.digest(raw))
        for other in (raw.rstrip(), b" " + raw, json.dumps(p, indent=2).encode()):
            self.assertNotEqual(c.digest(other), c.plan_sha256(p))
            with self.assertRaises(c.ContractError):
                c.validate_plan(other)

    def test_independent_revalidation_binds_all_inputs(self):
        source, package = fixture()
        p = plan()
        self.assertEqual(c.validate_plan(p, source_attestation=source, validated_package=package,
            native_spec_sha256=NATIVE, operator_code_sha256=CODE), p)
        for kwargs in ({"operator_code_sha256": HASH}, {"native_spec_sha256": HASH}, {"validated_package": package}):
            with self.subTest(kwargs=list(kwargs)), self.assertRaises(c.ContractError):
                c.validate_plan(p, **kwargs)

    def test_selected_sql_raw_bytes_cannot_be_swapped(self):
        for key in ("schema_sql", "application_sql"):
            source, package = fixture(); package[key] += b"-- changed"
            with self.subTest(key=key), self.assertRaises(c.ContractError):
                c.make_plan(source, package, NAMESPACE, TIME, native_spec_sha256=NATIVE, operator_code_sha256=CODE)

    def test_fresh_reobservation_preserves_original_and_allows_progress(self):
        source, _ = fixture(); p = plan()
        source.update(observed_at_utc=LATER, run_state="VERIFIED")
        result = c.validate_plan(p, source_attestation=source)
        self.assertEqual(result["source_origin"]["observed_at_utc"], TIME)
        self.assertEqual(result["source_origin"]["run_state"], "QA_REQUIRED")
        self.assertEqual(c.plan_sha256(result), c.plan_sha256(p))
        for key, value in (("package_sha256", HASH), ("source_manifest_sha256", HASH),
                           ("job_id", "fox-bbbbbbbbbbbbbbbbbbbb"), ("instance_id", "other"),
                           ("package_bytes", 12346), ("observed_at_utc", "2026-10-17T01:02:02Z")):
            changed = deepcopy(source); changed[key] = value
            with self.subTest(key=key), self.assertRaises(c.ContractError):
                c.validate_plan(p, source_attestation=changed)

    def test_selected_sql_and_hash_replaced_fail_plan_revalidation(self):
        source, package = fixture()
        package["application_sql"] += b"-- changed"
        package["selected_member_sha256"]["sql/f123.sql"] = c.digest(package["application_sql"])
        with self.assertRaises(c.ContractError):
            c.validate_plan(plan(), validated_package=package, native_spec_sha256=NATIVE)

    def test_package_requires_existing_validator_contract(self):
        for key, value in (("current_target_authorized", True), ("customer_compatibility_verified", True),
                           ("schema_member", "../escape.sql"), ("application_member", "sql/f999.sql"),
                           ("validation_scope", "validated_everything"), ("application_id", True)):
            source, package = fixture(); package[key] = value
            with self.subTest(key=key), self.assertRaises(c.ContractError):
                c.make_plan(source, package, NAMESPACE, TIME, native_spec_sha256=NATIVE, operator_code_sha256=CODE)
        source, package = fixture(); package["zip_path"] = "/arbitrary.zip"
        with self.assertRaises(c.ContractError):
            c.make_plan(source, package, NAMESPACE, TIME, native_spec_sha256=NATIVE, operator_code_sha256=CODE)

    def test_source_swaps_rejected(self):
        for key, value in (("job_id", "fox-bbbbbbbbbbbbbbbbbbbb"), ("package_sha256", HASH),
                           ("source_manifest_sha256", HASH), ("instance_id", "other"),
                           ("compartment_id", "other"), ("region", "ap-singapore-1")):
            source, package = fixture(); source[key] = value
            with self.subTest(key=key), self.assertRaises(c.ContractError):
                c.make_plan(source, package, NAMESPACE, TIME, native_spec_sha256=NATIVE, operator_code_sha256=CODE)

    def test_attestation_not_arbitrary_path_or_credential_input(self):
        for key in ("path", "password", "url", "database_id", "verification_profile_sha256"):
            source, _ = fixture(); source[key] = "sentinel-never-echoed"
            with self.subTest(key=key), self.assertRaises(c.ContractError) as caught:
                c.validate_source_attestation(source)
            self.assertNotIn("sentinel", str(caught.exception))

    def test_source_state_and_size_are_strict(self):
        for key, value in (("run_state", "RUNNING"), ("run_state", True), ("package_bytes", True),
                           ("package_bytes", 0), ("package_bytes", 8_000_001), ("schema_version", True)):
            source, _ = fixture(); source[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(c.ContractError):
                c.validate_source_attestation(source)
        for state in ("QA_REQUIRED", "VERIFIED", "ACCEPTED"):
            source, _ = fixture(); source["run_state"] = state
            self.assertEqual(c.validate_source_attestation(source)["run_state"], state)

    def test_source_observation_keeps_exact_finite_future_and_staleness_bounds(self):
        self.assertEqual(c.MAX_CLOCK_SKEW_SECONDS, 5)
        for observed in ("2026-10-16T01:02:03Z", "2026-10-17T01:02:08Z"):
            source, package = fixture(); source["observed_at_utc"] = observed
            result = c.make_plan(source, package, NAMESPACE, TIME, native_spec_sha256=NATIVE, operator_code_sha256=CODE)
            self.assertEqual(result['source_origin']['observed_at_utc'], observed)
            self.assertEqual(result['created_at_utc'], TIME)
        for observed in ("2026-10-16T01:02:02.999999Z", "2026-10-17T01:02:08.000001Z"):
            source, package = fixture(); source["observed_at_utc"] = observed
            with self.subTest(observed=observed), self.assertRaises(c.ContractError):
                c.make_plan(source, package, NAMESPACE, TIME, native_spec_sha256=NATIVE, operator_code_sha256=CODE)

    def test_namespace_strict_new_pattern_calendar_and_date(self):
        for namespace in ("FOX_QA_261017A", "FORMS2APEX_POC", "FOX_QA_261017_89abcdef", "FOX_QA_261332_89ABCDEF",
                          "FOX_QA_260229_89ABCDEF", "FOX_QA_261016_89ABCDEF", "FOX_QA_261017_89ABCDEG",
                          "FOX_QA_261017_89ABCDEF\n", "FOX_QA_261017_89ABCDEF;DROP", True):
            source, package = fixture()
            with self.subTest(namespace=namespace), self.assertRaises(c.ContractError):
                c.make_plan(source, package, namespace, TIME, native_spec_sha256=NATIVE, operator_code_sha256=CODE)

    def test_timestamp_must_be_real_explicit_utc(self):
        for timestamp in ("2026-10-17", "2026-10-17T01:02:03", "2026-10-17T01:02:03+07:00",
                          "2026-10-17T25:02:03Z", "2026-02-30T01:02:03Z", "2026-10-17T01:02:03.1234567Z", True):
            p = plan(); p["created_at_utc"] = timestamp
            with self.subTest(timestamp=timestamp), self.assertRaises(c.ContractError):
                c.validate_plan(p)

    def test_plan_target_and_versions_are_pinned(self):
        for key in c.FIXED_TARGET:
            p = plan(); p["target"][key] = "foreign"
            with self.subTest(key=key), self.assertRaises(c.ContractError):
                c.validate_plan(p)
        for key in c.VERSIONS:
            p = plan(); p["expected_versions"][key] = "99.1"
            with self.subTest(version=key), self.assertRaises(c.ContractError):
                c.validate_plan(p)

    def test_plan_unknown_keys_at_all_contract_boundaries(self):
        for container in (None, "target", "binding", "source_origin", "expected_versions"):
            p = plan(); target = p if container is None else p[container]; target["url"] = "https://not-permitted/"
            with self.subTest(container=container), self.assertRaises(c.ContractError):
                c.validate_plan(p)

    def test_plan_strict_hash_job_and_integer_binding(self):
        for key, value in (("job_id", "fox-AAAAAAAAAAAAAAAAAAAA"), ("job_id", "fox-gggggggggggggggggggg"),
                           ("package_sha256", "A" * 64), ("native_spec_sha256", "a" * 63),
                           ("source_application_id", True), ("source_reimport_application_id", 123),
                           ("source_application_id", c.MAX_SAFE_INTEGER + 1), ("sql_member", "sql/f456.sql")):
            p = plan(); p["binding"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(c.ContractError):
                c.validate_plan(p)

    def test_allocation_exact_identity_and_profile_shape(self):
        p = plan(); a = allocation(p); raw = c.canonical_bytes(a)
        self.assertEqual(c.validate_allocation(raw, p), a)
        profile = c.make_verification_profile(p, raw)
        self.assertEqual(set(profile), {"schema_version", "scope", "policy_id", "binding", "target", "expected_versions", "max_evidence_age_seconds"})
        self.assertEqual(profile["scope"], "fox-native-verification-profile-v2")
        self.assertEqual(profile["target"]["workspace_id"], "22042420337195501")
        self.assertNotIn("instance_id", profile["target"])
        self.assertEqual(profile["binding"]["allocation_receipt_sha256"], c.digest(raw))
        self.assertEqual(profile["max_evidence_age_seconds"], 86400)

    def test_allocation_hash_is_actual_raw_not_canonical(self):
        p = plan(); a = allocation(p)
        compact = c.canonical_bytes(a); pretty = json.dumps(a, indent=2).encode()
        first, second = c.make_verification_profile(p, compact), c.make_verification_profile(p, pretty)
        self.assertNotEqual(first["binding"]["allocation_receipt_sha256"], second["binding"]["allocation_receipt_sha256"])
        self.assertEqual(second["binding"]["allocation_receipt_sha256"], c.digest(pretty))
        with self.assertRaises(c.ContractError):
            c.make_verification_profile(p, a)

    def test_no_allocation_profile_hash_cycle(self):
        a = allocation()
        for container in (None, "binding", "target", "observed_versions", "fresh_namespace"):
            candidate = deepcopy(a); target = candidate if container is None else candidate[container]
            target["verification_profile_sha256"] = HASH
            with self.subTest(container=container), self.assertRaises(c.ContractError):
                c.validate_allocation(candidate, plan())
        self.assertNotIn("verification_profile_sha256", c.canonical_bytes(a).decode())

    def test_allocation_rejects_plan_source_target_version_swaps(self):
        for mutate in (
            lambda a: a.update(plan_sha256=HASH),
            lambda a: a["binding"].update(job_id="fox-bbbbbbbbbbbbbbbbbbbb"),
            lambda a: a["binding"].update(package_sha256=HASH),
            lambda a: a["binding"].update(source_manifest_sha256=HASH),
            lambda a: a["target"].update(workspace="FOX_QA_261017_01234567", parsing_schema="FOX_QA_261017_01234567", application_alias="F2A_QA_261017_01234567"),
            lambda a: a["target"].update(database_id="OTHER"),
            lambda a: a["observed_versions"].update(apex="26.1.6"),
            lambda a: a.update(allocated_at_utc="2026-10-17T01:02:02Z"),
        ):
            a = allocation(); mutate(a)
            with self.subTest(allocation=a), self.assertRaises(c.ContractError):
                c.validate_allocation(a, plan())

    def test_workspace_id_keeps_large_decimal_precision(self):
        a = allocation(); a["target"]["workspace_id"] = "9" * 38
        self.assertEqual(c.validate_allocation(a, plan())["target"]["workspace_id"], "9" * 38)
        for value in (22042420337195501, True, "022042420337195501", "0", "9" * 39, "1e18", "123\n", 1.0):
            a = allocation(); a["target"]["workspace_id"] = value
            with self.subTest(value=value), self.assertRaises(c.ContractError):
                c.validate_allocation(a, plan())

    def test_application_id_safe_int_and_distinct_from_existing(self):
        for value in (True, False, 0, -1, "34567", 34567.0, c.MAX_SAFE_INTEGER + 1, 123, 456):
            a = allocation(); a["target"]["application_id"] = value
            with self.subTest(value=value), self.assertRaises(c.ContractError):
                c.validate_allocation(a, plan())
        a = allocation(); a["target"]["application_id"] = c.MAX_SAFE_INTEGER
        self.assertEqual(c.validate_allocation(a, plan())["target"]["application_id"], c.MAX_SAFE_INTEGER)

    def test_allocation_fresh_counts_and_booleans_are_strict(self):
        for key, value in (("workspace_created_fresh", 1), ("schema_created_fresh", "true"),
                           ("application_count", False), ("user_object_count", 0.0),
                           ("user_object_count", 1), ("application_count", "0")):
            a = allocation(); a["fresh_namespace"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(c.ContractError):
                c.validate_allocation(a, plan())
        for value in (1, "true", False):
            a = allocation(); a["passed"] = value
            with self.subTest(passed=value), self.assertRaises(c.ContractError):
                c.validate_allocation(a, plan())

    def test_absent_only_is_unattempted(self):
        self.assertEqual(c.validate_phase_record(None, plan(), "allocate"), "unattempted")
        for value in ({}, b"", False, []):
            with self.subTest(value=value), self.assertRaises(c.ContractError):
                c.validate_phase_record(value, plan(), "allocate")

    def test_uncertain_intent_and_attention_never_retry(self):
        for state in ("intent", "attention"):
            self.assertEqual(c.validate_phase_record(phase(state), plan(), "allocate"), "attention")
        record = phase("attention"); record["finished_at_utc"] = LATER
        self.assertEqual(c.validate_phase_record(record, plan(), "allocate"), "attention")

    def test_complete_requires_bound_proof_and_time(self):
        self.assertEqual(c.validate_phase_record(phase("complete"), plan(), "allocate"), "complete")
        for key, value in (("evidence_sha256", None), ("evidence_sha256", "BAD"), ("finished_at_utc", None),
                           ("finished_at_utc", "2026-10-17T01:02:02Z"), ("plan_sha256", HASH), ("phase", "import")):
            record = phase("complete"); record[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(c.ContractError):
                c.validate_phase_record(record, plan(), "allocate")

    def test_incomplete_cannot_claim_completion_evidence(self):
        for state in ("intent", "attention"):
            record = phase(state); record["evidence_sha256"] = HASH
            with self.subTest(state=state), self.assertRaises(c.ContractError):
                c.validate_phase_record(record, plan(), "allocate")
        record = phase(); record["finished_at_utc"] = LATER
        with self.assertRaises(c.ContractError):
            c.validate_phase_record(record, plan(), "allocate")

    def test_phase_unknown_keys_states_and_old_plan_block(self):
        for key, value in (("retry_allowed", True), ("password", "never-echo-this"), ("schema_version", True),
                           ("state", "failed_safe_to_retry"), ("started_at_utc", "2026-10-16T01:02:03Z")):
            record = phase(); record[key] = value
            with self.subTest(key=key), self.assertRaises(c.ContractError):
                c.validate_phase_record(record, plan(), "allocate")
        for name in ("qa", "delete", "import-again", True):
            with self.subTest(phase=name), self.assertRaises(c.ContractError):
                c.validate_phase_record(None, plan(), name)


if __name__ == "__main__":
    unittest.main()
