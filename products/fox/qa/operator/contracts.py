"""Pure, fail-closed contracts for the JSN-only native clean-install operator.

These helpers perform no I/O and grant no authority. The caller obtains the
source attestation from the pinned VM, validates the ZIP with the existing
``validate_native_package`` implementation, and supplies the exact packaged
native-spec digest. Attestations are operator observations, not signatures.
Plans are canonical immutable bytes; allocation and verification-profile hashes
are hashes of their *actual stored bytes*. Allocation never depends on a profile
hash, so the evidence graph has no hash cycle.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re


COMPARTMENT = "ocid1.compartment.oc1..aaaaaaaa2q5aelkapmt5mhumvxadcynq5chez2faeucy5plefhy3ylmahtba"
INSTANCE = "ocid1.instance.oc1.iad.anuwcljtc7x6gxic5w37qsyp3rst64betkt4uk2pdcrtmy3okspcpbv77qea"
DATABASE = "ocid1.autonomousdatabase.oc1.iad.anuwcljrc7x6gxiapkxouj7emfbelvnvompwjcpoxx5vg727cegjsqkbp4rq"
REGION = "us-ashburn-1"
DB_NAME = "ASZ8EQWFM8UNCA2_JSNF2APEX"
POLICY_ID = "jsn-clean-native-v2"
PLAN_SCOPE = "fox-clean-install-plan-v2"
ALLOCATION_SCOPE = "fox-clean-allocation-v2"
PROFILE_SCOPE = "fox-native-verification-profile-v2"
PHASE_SCOPE = "fox-clean-operator-phase-v1"
SOURCE_SCOPE = "fox-private-job-package-read-v1"
VERSIONS = {"apex": "26.1.5", "sqlcl": "26.1.2.0", "database": "23.26.4.1.0", "mmd": "26.1.0+3102"}
FIXED_TARGET = {"compartment_id": COMPARTMENT, "database_id": DATABASE,
                "region": REGION, "db_name": DB_NAME, "instance_id": INSTANCE}
MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_JSON_BYTES = 65_536
MAX_CLOCK_SKEW_SECONDS = 5
PROTECTED_APPLICATION_IDS = frozenset({103})
PHASES = frozenset({"allocate", "schema", "import", "verify"})
PUBLIC_FAILURE_CODES = frozenset({
    "SQL_FAILED_OUTPUT_WITHHELD", "SQL_TIMEOUT_UNCERTAIN_NO_REPLAY", "SQL_EXECUTION_UNAVAILABLE",
    "PHASE_UNCONFIRMED_NO_REPLAY", "PHASE_NOT_STARTABLE_NO_REPLAY", "UNCERTAIN_PHASE_NO_REPLAY",
    "OPERATOR_GUARD_FAILED_OUTPUT_WITHHELD", "REMOTE_OPERATOR_GUARD_FAILED", "LOCAL_OPERATOR_GUARD_FAILED",
    "VM_SCOPE_MISMATCH", "VM_SCOPE_UNAVAILABLE", "DATABASE_IDENTITY_UNPROVEN", "SCHEMA_IDENTITY_UNPROVEN",
    "TESTED_VERSION_PROFILE_MISMATCH", "PRE_DISPATCH_VERSION_CHANGED", "SQLCL_VERSION_UNAVAILABLE",
    "TOOLING_VERSION_UNAVAILABLE", "MISSING_OR_DUPLICATE_MARKER", "INVALID_NUMERIC_MARKER",
    "PRIVATE_DIRECTORY_UNSAFE", "PRIVATE_DIRECTORY_PERMISSIONS", "PRIVATE_FILE_PERMISSIONS",
    "NAMESPACE_NOT_UNUSED", "TARGET_ISOLATION_MISMATCH", "ANOTHER_OPERATOR_IS_ACTIVE",
    "APPROVED_PLAN_DIGEST_MISMATCH", "OPERATOR_CODE_CHANGED_REPREPARE_OR_REVIEW",
    "EXACT_PLAN_SHA_REQUIRED_FOR_APPLY", "PLAN_SHA_MISMATCH", "EXACT_JSN_RESOURCE_IDENTITY_REQUIRED",
    "EXISTING_VM_MUST_BE_STARTED_BY_OPERATOR", "EXISTING_DATABASE_MUST_BE_AVAILABLE",
    "PROTECTED_TRANSPORT_FAILED_OUTPUT_WITHHELD", "TRANSPORT_TIMEOUT_OUTCOME_UNCERTAIN_NO_REPLAY",
    "WINDOWS_PLAN_PROTECTION_FAILED", "WINDOWS_PLAN_PERMISSIONS_INVALID", "OPERATOR_OWNED_PLAN_REQUIRED",
    "OCI_CLI_FAILED_OUTPUT_WITHHELD", "OCI_DIAGNOSTIC_OUTPUT_REVIEW_REQUIRED",
    "OCI_PROJECTED_JSON_INVALID", "OCI_PROJECTED_FIELDS_INVALID",
})
DIAGNOSTIC_CATEGORIES = frozenset({"SQL_EXECUTION_FAILED", "SQL_EXECUTION_TIMEOUT", "SQL_CLIENT_UNAVAILABLE"})
ERROR_NUMBER = re.compile(r"(?:ORA-[0-9]{5}|SP2-[0-9]{4}|SP-[0-9]{4,5})\Z")
_HASH = re.compile(r"[a-f0-9]{64}\Z")
_JOB = re.compile(r"fox-[a-f0-9]{20}\Z")
_NAMESPACE = re.compile(r"FOX_QA_([0-9]{6})_([A-F0-9]{8})\Z")
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|\+00:00)\Z")
_HASH_KEYS = {"source_manifest_sha256", "package_sha256", "sql_sha256", "schema_script_sha256", "native_spec_sha256"}
_BINDING_KEYS = _HASH_KEYS | {"job_id", "source_application_id", "source_application_alias",
    "source_reimport_application_id", "source_reimport_application_alias", "table_name", "profile_id",
    "sql_member", "schema_member"}
_SOURCE_KEYS = {"schema_version", "scope", "observed_at_utc", "instance_id", "compartment_id", "region",
                "job_id", "run_state", "package_sha256", "package_bytes", "source_manifest_sha256"}
_PLAN_KEYS = {"schema_version", "scope", "policy_id", "created_at_utc", "operator_code_sha256",
              "source_origin", "binding", "target", "expected_versions"}
_ALLOCATION_KEYS = {"schema_version", "scope", "passed", "plan_sha256", "allocated_at_utc", "binding", "target",
                    "observed_versions", "fresh_namespace"}
_VALIDATED_PACKAGE_KEYS = {"package_sha256", "job_id", "source_manifest_sha256", "application_id", "application_alias",
    "native_form", "release_evidence", "schema_member", "application_member", "schema_sql", "application_sql",
    "selected_member_sha256", "validation_scope", "review_proof_scope", "historical_model_environment_verified",
    "historical_target_profile", "current_target_authorized", "customer_compatibility_verified"}


class ContractError(ValueError):
    """Bounded validation error that never echoes submitted values or secrets."""


def safe_diagnostics(value):
    """Project recognized numeric SQL diagnostics only; never provider text."""
    if type(value) is not dict or set(value) != {"category", "error_codes", "return_code"}:
        return None
    category, codes, status = value["category"], value["error_codes"], value["return_code"]
    if type(category) is not str or category not in DIAGNOSTIC_CATEGORIES:
        return None
    if type(codes) is not list or len(codes) > 8 or any(type(code) is not str or not ERROR_NUMBER.fullmatch(code) for code in codes):
        return None
    if status is not None and (type(status) is not int or not -(2 ** 31) <= status <= 2 ** 32 - 1):
        return None
    return {"category": category, "error_codes": list(dict.fromkeys(codes)), "return_code": status}


def failure_response(code, phase=None, diagnostics=None):
    """The only public failed-dispatch shape; arbitrary exception text is not a code."""
    result = {"status": "STOPPED", "code": code if type(code) is str and code in PUBLIC_FAILURE_CODES
              else "OPERATOR_GUARD_FAILED_OUTPUT_WITHHELD", "automatic_replay_permitted": False,
              "phase": phase if type(phase) is str and phase in PHASES else None}
    safe = safe_diagnostics(diagnostics)
    if safe is not None:
        result["diagnostics"] = safe
    return result


def _require(condition, message):
    if not condition:
        raise ContractError(message)


def _keys(value, expected, message):
    _require(type(value) is dict and set(value) == set(expected), message)


def _json_types(value, depth=0):
    _require(depth <= 20, "JSON nesting exceeds the operator bound.")
    if type(value) is dict:
        _require(all(type(key) is str for key in value), "JSON object keys must be strings.")
        for item in value.values():
            _json_types(item, depth + 1)
    elif type(value) is list:
        for item in value:
            _json_types(item, depth + 1)
    else:
        _require(type(value) in (str, int, bool, type(None)), "Unsupported JSON scalar type.")


def canonical_bytes(value):
    """Stable UTF-8, sorted compact JSON with a final LF; floats are forbidden."""
    _require(type(value) is dict, "Contract must be a JSON object.")
    _json_types(value)
    try:
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False) + "\n").encode("utf-8")
    except (ValueError, UnicodeError, RecursionError):
        raise ContractError("Contract cannot be encoded as canonical JSON.") from None
    _require(len(raw) <= MAX_JSON_BYTES, "Contract exceeds the JSON byte bound.")
    return raw


def digest(raw):
    """Hash exact bytes, never an implicitly re-serialized document."""
    _require(type(raw) is bytes, "Digest input must be exact bytes.")
    return hashlib.sha256(raw).hexdigest()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "Duplicate JSON keys are forbidden.")
        result[key] = value
    return result


def load_json(raw):
    """Decode a bounded exact-byte object and reject ambiguous JSON values."""
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_JSON_BYTES, "Bounded exact JSON bytes are required.")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ContractError("Non-finite JSON is forbidden.")))
    except (ValueError, UnicodeError, RecursionError):
        raise ContractError("Contract JSON is malformed or ambiguous.") from None
    _require(type(value) is dict, "Contract must be a JSON object.")
    _json_types(value)
    return value


def _document(value):
    return load_json(value) if type(value) is bytes else load_json(canonical_bytes(value))


def _sha(value):
    _require(type(value) is str and _HASH.fullmatch(value), "A lowercase SHA-256 digest is required.")
    return value


def _timestamp(value):
    _require(type(value) is str and _UTC.fullmatch(value), "An explicit UTC timestamp is required.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ContractError("UTC timestamp is invalid.") from None
    _require(parsed.tzinfo == timezone.utc, "Timestamp must use UTC.")
    return parsed


def _integer(value):
    _require(type(value) is int and 0 < value <= MAX_SAFE_INTEGER, "A positive safe integer application ID is required.")
    return value


def _versions(value):
    _keys(value, VERSIONS, "Version tuple contains missing or unknown fields.")
    _require(value == VERSIONS, "Version tuple is outside the tested JSN profile.")


def _namespace(value):
    match = _NAMESPACE.fullmatch(value) if type(value) is str else None
    _require(match is not None, "A fresh version-two QA namespace is required.")
    try:
        parsed = datetime.strptime(match[1], "%y%m%d")
    except ValueError:
        raise ContractError("Namespace date is invalid.") from None
    _require(parsed.strftime("%y%m%d") == match[1], "Namespace date is not canonical.")
    return value


def _target(value, allocated=False):
    keys = set(FIXED_TARGET) | {"workspace", "parsing_schema", "application_alias"}
    if allocated:
        keys |= {"workspace_id", "application_id"}
    _keys(value, keys, "Target contains missing or unknown fields.")
    _require(all(value[key] == fixed for key, fixed in FIXED_TARGET.items()), "Target is outside the existing JSN resources.")
    name = _namespace(value["workspace"])
    _require(value["parsing_schema"] == name and value["application_alias"] == "F2A_QA_" + name[7:],
             "Schema and alias must derive from the exact allocated namespace.")
    if allocated:
        _require(type(value["workspace_id"]) is str and re.fullmatch(r"[1-9][0-9]{0,37}", value["workspace_id"]),
                 "Workspace ID must be an exact positive decimal string.")
        _integer(value["application_id"])


def validate_source_attestation(value):
    result = _document(value)
    _keys(result, _SOURCE_KEYS, "Source attestation contains missing or unknown fields.")
    _require(type(result["schema_version"]) is int and result["schema_version"] == 1 and result["scope"] == SOURCE_SCOPE,
             "Source attestation scope or version is invalid.")
    _timestamp(result["observed_at_utc"])
    _require(result["instance_id"] == INSTANCE and result["compartment_id"] == COMPARTMENT and result["region"] == REGION,
             "Source observation is outside the pinned JSN VM.")
    _require(type(result["job_id"]) is str and _JOB.fullmatch(result["job_id"]), "Source FOX job ID is invalid.")
    _require(result["run_state"] in ("QA_REQUIRED", "VERIFIED", "ACCEPTED"), "Source job is not in an eligible retained-package state.")
    _require(type(result["package_bytes"]) is int and 0 < result["package_bytes"] <= 8_000_000, "Source package byte count is invalid.")
    _sha(result["package_sha256"]); _sha(result["source_manifest_sha256"])
    return result


def _package_binding(package, native_spec_sha256):
    # This is a boundary check of the existing validator's output, not a second
    # ZIP parser or a replacement for its review/schema/export validation.
    _keys(package, _VALIDATED_PACKAGE_KEYS, "Validated package result has an unexpected contract.")
    _require(package["validation_scope"] == "package_integrity_and_synthetic_schema_only"
             and package["current_target_authorized"] is False and package["customer_compatibility_verified"] is False,
             "Package validation must not assert target authority or customer compatibility.")
    job = package["job_id"]
    _require(type(job) is str and _JOB.fullmatch(job), "Validated package FOX job ID is invalid.")
    app = _integer(package["application_id"])
    alias = "F2A_" + job.upper().replace("-", "_")
    _require(package["application_alias"] == alias, "Validated package application alias differs from its job.")
    sql_member, schema_member = "sql/f" + str(app) + ".sql", "schema/01_synthetic_schema.sql"
    _require(package["application_member"] == sql_member and package["schema_member"] == schema_member,
             "Validated package selected members differ from original identities.")
    _keys(package["selected_member_sha256"], {sql_member, schema_member}, "Validated selected-member set is not exact.")
    sql_hash, schema_hash = digest(package["application_sql"]), digest(package["schema_sql"])
    _require(sql_hash == package["selected_member_sha256"][sql_member]
             and schema_hash == package["selected_member_sha256"][schema_member], "Selected SQL bytes differ from validated member hashes.")
    native, release = package["native_form"], package["release_evidence"]
    _require(type(native) is dict and native.get("profile_id") == "native-table-form-v1"
             and native.get("data_mode") == "synthetic_test_only"
             and type(native.get("table_name")) is str and re.fullmatch(r"FOX_NATIVE_[A-Z0-9_]{1,19}", native["table_name"]),
             "Validated package must use the supported synthetic native profile.")
    _require(type(release) is dict and release.get("job_id") == job and release.get("application_id") == app
             and release.get("application_alias") == alias and release.get("source_manifest_sha256") == package["source_manifest_sha256"],
             "Validated release identity differs from selected package.")
    reimport = release.get("package_reimport")
    _require(type(reimport) is dict and reimport.get("passed") is True, "Validated SQL reimport identity is required.")
    reimport_id = _integer(reimport.get("application_id"))
    _require(reimport_id != app and reimport.get("application_alias") == alias + "_SQLCHECK", "Validated SQL reimport identity is invalid.")
    return {"job_id": job, "source_manifest_sha256": _sha(package["source_manifest_sha256"]),
            "package_sha256": _sha(package["package_sha256"]), "sql_sha256": sql_hash,
            "schema_script_sha256": schema_hash, "native_spec_sha256": _sha(native_spec_sha256),
            "source_application_id": app, "source_application_alias": alias,
            "source_reimport_application_id": reimport_id, "source_reimport_application_alias": reimport["application_alias"],
            "table_name": native["table_name"], "profile_id": native["profile_id"],
            "sql_member": sql_member, "schema_member": schema_member}


def make_plan(source_attestation, validated_package, namespace, created_at, *, native_spec_sha256, operator_code_sha256):
    """Bind an operator-observed retained package to one new QA namespace."""
    namespace = _namespace(namespace)
    plan = {"schema_version": 1, "scope": PLAN_SCOPE, "policy_id": POLICY_ID,
            "created_at_utc": created_at, "operator_code_sha256": _sha(operator_code_sha256),
            "source_origin": validate_source_attestation(source_attestation),
            "binding": _package_binding(validated_package, native_spec_sha256),
            "target": {**FIXED_TARGET, "workspace": namespace, "parsing_schema": namespace,
                       "application_alias": "F2A_QA_" + namespace[7:]}, "expected_versions": dict(VERSIONS)}
    return validate_plan(plan)


def validate_plan(value, *, source_attestation=None, validated_package=None, native_spec_sha256=None, operator_code_sha256=None):
    """Validate a plan and optionally compare independently re-observed inputs.

    A raw loaded plan must already be canonical, so its raw hash and canonical
    plan hash cannot disagree. A returned dictionary is a detached copy.
    """
    plan = _document(value)
    if type(value) is bytes:
        _require(value == canonical_bytes(plan), "Stored plan bytes must be exactly canonical.")
    _keys(plan, _PLAN_KEYS, "Plan contains missing or unknown fields.")
    _require(type(plan["schema_version"]) is int and plan["schema_version"] == 1
             and plan["scope"] == PLAN_SCOPE and plan["policy_id"] == POLICY_ID, "Plan scope or version is invalid.")
    created = _timestamp(plan["created_at_utc"])
    _sha(plan["operator_code_sha256"])
    origin = validate_source_attestation(plan["source_origin"])
    age = (created - _timestamp(origin["observed_at_utc"])).total_seconds()
    _require(-MAX_CLOCK_SKEW_SECONDS <= age <= 86_400,
             "Source observation must be within one day and the bounded clock-skew allowance.")
    _target(plan["target"]); _versions(plan["expected_versions"])
    _require(plan["target"]["workspace"][7:13] == created.strftime("%y%m%d"), "Namespace date differs from plan creation date.")
    binding = plan["binding"]
    _keys(binding, _BINDING_KEYS, "Plan package binding contains missing or unknown fields.")
    _require(type(binding["job_id"]) is str and _JOB.fullmatch(binding["job_id"]), "Plan FOX job ID is invalid.")
    for key in _HASH_KEYS:
        _sha(binding[key])
    _require(all(origin[key] == binding[key] for key in ("job_id", "package_sha256", "source_manifest_sha256")),
             "Private source observation differs from the bound package.")
    app, reimport = _integer(binding["source_application_id"]), _integer(binding["source_reimport_application_id"])
    alias = "F2A_" + binding["job_id"].upper().replace("-", "_")
    _require(app != reimport and binding["source_application_alias"] == alias
             and binding["source_reimport_application_alias"] == alias + "_SQLCHECK", "Plan source application identities are inconsistent.")
    _require(binding["sql_member"] == "sql/f" + str(app) + ".sql"
             and binding["schema_member"] == "schema/01_synthetic_schema.sql", "Plan selected SQL members are inconsistent.")
    _require(binding["profile_id"] == "native-table-form-v1" and type(binding["table_name"]) is str
             and re.fullmatch(r"FOX_NATIVE_[A-Z0-9_]{1,19}", binding["table_name"]), "Plan synthetic native profile is invalid.")
    if source_attestation is not None:
        observed = validate_source_attestation(source_attestation)
        stable = _SOURCE_KEYS - {"observed_at_utc", "run_state"}
        _require(all(origin[key] == observed[key] for key in stable), "Source attestation differs from the immutable plan.")
        _require(_timestamp(observed["observed_at_utc"]) >= _timestamp(origin["observed_at_utc"]),
                 "Source re-observation predates the original attestation.")
        # The original observation remains immutable. A newer eligible run
        # state is legitimate; the dispatch caller separately checks current
        # observation freshness against its own trusted clock.
    if validated_package is not None:
        _require(native_spec_sha256 is not None, "Revalidation requires the exact packaged native-spec digest.")
        _require(binding == _package_binding(validated_package, native_spec_sha256), "Validated package differs from the immutable plan.")
    elif native_spec_sha256 is not None:
        _require(binding["native_spec_sha256"] == _sha(native_spec_sha256), "Native-spec digest differs from the immutable plan.")
    if operator_code_sha256 is not None:
        _require(plan["operator_code_sha256"] == _sha(operator_code_sha256), "Operator code differs from the immutable plan.")
    return plan


def plan_sha256(value):
    return digest(canonical_bytes(validate_plan(value)))


def validate_allocation(value, plan):
    """Validate allocation independently of any later verification profile."""
    plan, allocation = validate_plan(plan), _document(value)
    _keys(allocation, _ALLOCATION_KEYS, "Allocation contains missing or unknown fields.")
    _require(type(allocation["schema_version"]) is int and allocation["schema_version"] == 1
             and allocation["scope"] == ALLOCATION_SCOPE and allocation["passed"] is True, "Allocation scope, version, or result is invalid.")
    _require(allocation["plan_sha256"] == plan_sha256(plan), "Allocation does not bind the exact plan.")
    _require(_timestamp(allocation["allocated_at_utc"]) >= _timestamp(plan["created_at_utc"]), "Allocation predates its plan.")
    keys = {"job_id", "source_manifest_sha256", "package_sha256"}
    _keys(allocation["binding"], keys, "Allocation binding contains missing or unknown fields.")
    _require(all(allocation["binding"][key] == plan["binding"][key] for key in keys), "Allocation source/package binding differs.")
    _target(allocation["target"], allocated=True)
    _require(all(allocation["target"][key] == value for key, value in plan["target"].items()), "Allocation target differs from the planned namespace.")
    _require(allocation["target"]["application_id"] not in {plan["binding"]["source_application_id"], plan["binding"]["source_reimport_application_id"]},
             "Allocation cannot reuse an existing source application ID.")
    _require(allocation["target"]["application_id"] not in PROTECTED_APPLICATION_IDS,
             "Allocation cannot target the retained golden application.")
    _versions(allocation["observed_versions"])
    fresh = allocation["fresh_namespace"]
    _keys(fresh, {"workspace_created_fresh", "schema_created_fresh", "application_count", "user_object_count"},
          "Allocation emptiness proof contains missing or unknown fields.")
    _require(fresh["workspace_created_fresh"] is True and fresh["schema_created_fresh"] is True
             and all(type(fresh[key]) is int and fresh[key] == 0 for key in ("application_count", "user_object_count")),
             "Allocation must prove a freshly created empty namespace.")
    return allocation


def make_verification_profile(plan, allocation_raw):
    """Make the exact consumer profile, binding actual stored allocation bytes."""
    _require(type(allocation_raw) is bytes, "Verification requires the actual stored allocation bytes.")
    plan = validate_plan(plan)
    allocation = validate_allocation(allocation_raw, plan)
    return {"schema_version": 1, "scope": PROFILE_SCOPE, "policy_id": POLICY_ID,
            "binding": {**allocation["binding"], "allocation_receipt_sha256": digest(allocation_raw)},
            "target": {key: value for key, value in allocation["target"].items() if key != "instance_id"},
            "expected_versions": dict(VERSIONS), "max_evidence_age_seconds": 86_400}


def validate_phase_record(value, plan, phase):
    """Return unattempted/complete/attention; uncertainty never permits retry.

    ``None`` means the private journal has never existed; the filesystem caller
    must establish absence securely. An intent, error, or interrupted outcome
    remains attention. Completion requires a separate exact evidence digest.
    Invalid records raise and must never be treated as an absent journal.
    """
    plan = validate_plan(plan)
    _require(type(phase) is str and phase in PHASES, "Unknown operator phase.")
    if value is None:
        return "unattempted"
    record = _document(value)
    _keys(record, {"schema_version", "scope", "plan_sha256", "phase", "state", "started_at_utc", "finished_at_utc", "evidence_sha256"},
          "Phase journal contains missing or unknown fields.")
    _require(type(record["schema_version"]) is int and record["schema_version"] == 1 and record["scope"] == PHASE_SCOPE
             and record["plan_sha256"] == plan_sha256(plan) and record["phase"] == phase,
             "Phase journal identity differs from the immutable plan.")
    started = _timestamp(record["started_at_utc"])
    _require(started >= _timestamp(plan["created_at_utc"]), "Phase journal predates its plan.")
    _require(record["state"] in ("intent", "complete", "attention"), "Unknown phase journal state.")
    if record["state"] == "complete":
        _require(_timestamp(record["finished_at_utc"]) >= started, "Phase completion predates dispatch.")
        _sha(record["evidence_sha256"])
        return "complete"
    _require(record["evidence_sha256"] is None, "Incomplete phase cannot claim completion evidence.")
    if record["state"] == "intent":
        _require(record["finished_at_utc"] is None, "Dispatch intent must not claim completion time.")
    elif record["finished_at_utc"] is not None:
        _require(_timestamp(record["finished_at_utc"]) >= started, "Attention record predates dispatch.")
    return "attention"
