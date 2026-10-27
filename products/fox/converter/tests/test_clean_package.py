"""Offline synthetic-package tests; no SQL, credentials or services are used."""
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import stat
import struct
import warnings
import zipfile

import pytest

from forms2apex import clean_package as clean
from forms2apex.native import TEMPLATE_ID
from forms2apex.native_contract import validate_native_spec
from forms2apex.native_schema import render_native_schema
from forms2apex.review_receipts import candidate_sha256
from forms2apex.security import alias_for_job


JOB = "fox-" + "a" * 20
PINNED_SHA = "850a904dd89bccad91821c9bd10d7fc1957c65da3401ae862ed71bff6f535209"
PINNED_PACKAGE = Path(__file__).resolve().parents[2] / "outputs/beta/hosted-native/fox-9bd15abe4dab480198b7/apex-package.zip"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def pack(members, manifest=None, extras=(), compression=zipfile.ZIP_DEFLATED):
    if manifest is None:
        manifest = {name: digest(raw) for name, raw in members.items()}
    output = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(output, "w", compression) as archive:
            for name, raw in [*members.items(), ("manifest.json", encoded(manifest)), *extras]:
                if isinstance(name, str):
                    info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
                    info.compress_type = compression
                else:
                    info = name
                archive.writestr(info, raw)
    return output.getvalue()


def validate(members, **kwargs):
    raw = pack(members, **kwargs)
    return clean.validate_native_package(raw, digest(raw))


def edit(members, name, mutation):
    value = json.loads(members[name])
    mutation(value)
    members[name] = encoded(value)


def rebind_evidence(members):
    """Recompute outer file bindings to test inner invariants, not just hashes."""
    release = json.loads(members["evidence/release-evidence.json"])
    imported = json.loads(members["evidence/imported-application.json"])
    completion = json.loads(members["evidence/export-completion.json"])
    binding = release["artifact_binding"]
    for key, name in {"native_review_sha256": "evidence/native-review.json", "inventory_sha256": "evidence/normalized-forms-inventory.json",
                      "remediation_sha256": "evidence/migration-and-exception-report.json", "reviewed_spec_sha256": "evidence/migration-spec.json"}.items():
        binding[key] = digest(members[name])
    imported["artifact_binding"] = binding; completion["artifact_binding"] = binding
    members["evidence/imported-application.json"] = encoded(imported)
    completion["imported_application_sha256"] = digest(members["evidence/imported-application.json"])
    members["evidence/export-completion.json"] = encoded(completion)
    members["evidence/release-evidence.json"] = encoded(release)


def reseal_review(members, mutation):
    review = json.loads(members["evidence/native-review.json"])
    mutation(review)
    review["receipt_sha256"] = digest(encoded({key: value for key, value in review.items() if key != "receipt_sha256"}))
    members["evidence/native-review.json"] = encoded(review)
    def release_mutation(release):
        release["review_receipt_sha256"] = review["receipt_sha256"]
        release["reviewer"]["receipt_sha256"] = review["receipt_sha256"]
    edit(members, "evidence/release-evidence.json", release_mutation)
    rebind_evidence(members)


@pytest.fixture
def members():
    spec = validate_native_spec({"profile_id": "native-table-form-v1", "data_mode": "synthetic_test_only",
        "table_name": "FOX_NATIVE_TEST", "columns": [
            {"name": "ID", "data_type": "NUMBER", "nullable": False, "primary_key": True, "identity": True, "label": "ID"},
            {"name": "TITLE", "data_type": "VARCHAR2", "length": 100, "nullable": False, "label": "Title"}]})
    source = '<FormModule Name="SYNTHETIC"><Block Name="TEST"/></FormModule>'
    source_hash = digest(("source.xml:" + digest(source.encode())).encode())
    inventory = {"schema_version": 1, "job_id": JOB, "approved_native_form": spec,
                 "modules": [{"file": "source.xml", "sha256": digest(source.encode()), "readable_source": source}]}
    candidate = {"job_id": JOB, "template_id": TEMPLATE_ID, "data_classification": "synthetic_or_stub_only",
                 "generator": {"model": "xai.grok-4.3"}, "native_form": spec,
                 "remediation_items": [], "mapping_summary": "Synthetic unit fixture only; no customer conversion."}
    candidate_hash = candidate_sha256(candidate)
    def invocation(role, start, stop):
        return {"workflow_id": role * 32, "room_id": role + "-synthetic-room", "model": "xai.grok-4.3",
                "graph_sha256": "c" * 64, "request_sha256": "d" * 64, "response_sha256": "e" * 64,
                "started_at_utc": "2026-10-17T00:00:" + start + "Z", "completed_at_utc": "2026-10-17T00:00:" + stop + "Z"}
    review = {"schema_version": 1, "trust_boundary": "authenticated_fox_executor_not_vendor_attestation",
              "job_id": JOB, "source_hash": source_hash, "candidate": candidate, "candidate_sha256": candidate_hash,
              "intake_sha256": "f" * 64, "mapper_invocation": invocation("A", "00", "01"),
              "reviewer_invocation": invocation("B", "02", "03"),
              "review": {"verdict": "approve", "candidate_sha256": candidate_hash, "notes": [], "blocking_findings": []}}
    review["receipt_sha256"] = digest(encoded(review))
    reviewer = {"model": "xai.grok-4.3", "verdict": "approve", "receipt_sha256": review["receipt_sha256"],
                "room_id": review["reviewer_invocation"]["room_id"]}
    migration = {**candidate, "reviewer": reviewer, "materialized_files": ["application.apx"]}
    result = {"native-form-spec.json": encoded(spec), clean.SCHEMA_MEMBER: render_native_schema(spec).encode(),
              "evidence/native-review.json": encoded(review), "evidence/normalized-forms-inventory.json": encoded(inventory),
              "evidence/migration-and-exception-report.json": encoded({"job_id": JOB, "remediation_items": []}),
              "evidence/migration-spec.json": encoded(migration),
              "sql/f12345.sql": b"-- Synthetic unit-test bytes; not executable APEX export\n" * 30,
              "apexlang/application.apx": b"// Synthetic unit-test APEXlang marker\n",
              "evidence/export-validation.log": b"Synthetic validation result only\n"}
    binding = {"schema_version": 1, "job_id": JOB, "template_id": TEMPLATE_ID,
               "draft_sha256": "a" * 64, "draft_zip_sha256": "b" * 64,
               "intake_sha256": "f" * 64, "template_sha256": "c" * 64}
    for key, name in {"native_review_sha256": "evidence/native-review.json", "inventory_sha256": "evidence/normalized-forms-inventory.json",
                      "remediation_sha256": "evidence/migration-and-exception-report.json", "reviewed_spec_sha256": "evidence/migration-spec.json"}.items():
        binding[key] = digest(result[name])
    identity = {"job_id": JOB, "application_id": 12345, "application_alias": alias_for_job(JOB),
                "application_url": "https://example.invalid/synthetic", "artifact_binding": binding}
    imported = {**identity, "workspace": "SYNTHETIC_TEST"}
    reimport = {"passed": True, "application_id": 23456, "application_alias": alias_for_job(JOB + "-sqlcheck"),
                "sql_sha256": digest(result["sql/f12345.sql"])}
    release = {**identity, "source_manifest_sha256": source_hash, "conversion_profile": "native-table-form-v1",
               "reviewer": reviewer, "reviewer_approved": True, "reviewer_execution_verified": True,
               "sqlcl_valid": True, "import_passed": True, "package_reimport_passed": True,
               "review_receipt_sha256": review["receipt_sha256"], "package_reimport": reimport,
               "authenticated_runtime_passed": False, "clean_schema_install_passed": False}
    result["evidence/imported-application.json"] = encoded(imported)
    result["evidence/package-reimport.json"] = encoded(reimport)
    result["evidence/release-evidence.json"] = encoded(release)
    completion = {**{key: identity[key] for key in ("job_id", "application_id", "application_alias", "artifact_binding")},
                  "schema_version": 1, "apexlang_validation_passed": True,
                  "imported_application_sha256": digest(result["evidence/imported-application.json"]),
                  "files": {"f12345.sql": digest(result["sql/f12345.sql"]),
                            alias_for_job(JOB).lower() + "/application.apx": digest(result["apexlang/application.apx"]),
                            "apexlang-validation.log": digest(result["evidence/export-validation.log"])}}
    result["evidence/export-completion.json"] = encoded(completion)
    return result


def test_portable_synthetic_package_returns_original_bytes_and_truthful_scope(members):
    result = validate(members)
    assert result["application_id"] == 12345
    assert result["schema_sql"] == members[clean.SCHEMA_MEMBER]
    assert result["application_sql"] == members["sql/f12345.sql"]
    assert result["selected_member_sha256"] == {clean.SCHEMA_MEMBER: digest(result["schema_sql"]), "sql/f12345.sql": digest(result["application_sql"])}
    assert result["validation_scope"] == "package_integrity_and_synthetic_schema_only"
    assert result["customer_compatibility_verified"] is False
    assert result["release_evidence"]["clean_schema_install_passed"] is False


def test_exact_approved_hosted_candidate_readonly():
    if not PINNED_PACKAGE.is_file():
        pytest.skip("Operator candidate artifact is not present in this checkout; portable unit tests still run")
    before = PINNED_PACKAGE.read_bytes()
    result = clean.validate_native_package(PINNED_PACKAGE, PINNED_SHA)
    assert result["application_id"] == 43032135
    assert result["job_id"] == "fox-9bd15abe4dab480198b7"
    assert result["selected_member_sha256"][clean.SCHEMA_MEMBER] == "af0bb2fd8c8500a0d95013c821560c18459e3167e73752f558474739c2916521"
    assert digest(result["application_sql"]) == "dc29c3c9605148a4ae23595ea2a04154b15b1189c4dac6a4edf16699ac17b62a"
    assert PINNED_PACKAGE.read_bytes() == before


@pytest.mark.parametrize("expected", [None, "", "A" * 64, "0" * 64, "not-a-hash"])
def test_explicit_approved_hash_is_mandatory(members, expected):
    with pytest.raises(clean.PackageValidationError):
        clean.validate_native_package(pack(members), expected)


@pytest.mark.parametrize("raw", [b"", b"not zip", b"x" * 8_000_001], ids=["empty", "not-zip", "too-big"])
def test_bad_or_oversize_zip_fails(raw):
    with pytest.raises(clean.PackageValidationError):
        clean.validate_native_package(raw, digest(raw))


@pytest.mark.parametrize("envelope", ["prepend", "append", "comment"])
def test_unsupported_zip_envelopes_fail(members, envelope):
    raw = pack(members)
    if envelope == "prepend": raw = b"MZ" + raw
    elif envelope == "append": raw += b"appended"
    else:
        output = io.BytesIO(raw)
        with zipfile.ZipFile(output, "a") as archive: archive.comment = b"link metadata"
        raw = output.getvalue()
    with pytest.raises(clean.PackageValidationError): clean.validate_native_package(raw, digest(raw))


@pytest.mark.parametrize("name", ["../outside.sql", "/absolute.sql", "C:stream.sql", "x\\y.sql", "x//y.sql", "./x.sql",
                                    "x/../y.sql", "folder/", "NUL.sql", "COM1", "con.txt", "x./y.sql", "x /y.sql", "weird%2e.sql"])
def test_unsafe_names_are_rejected(members, name):
    members[name] = b"unsafe"
    with pytest.raises(clean.PackageValidationError): validate(members)


@pytest.mark.parametrize("kind", [stat.S_IFLNK, stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR, stat.S_IFBLK, stat.S_IFDIR])
def test_link_and_nonregular_members_fail(members, kind):
    info = zipfile.ZipInfo("linked.sql"); info.create_system = 3
    info.external_attr = (kind | 0o600) << 16
    with pytest.raises(clean.PackageValidationError): validate(members, extras=[(info, b"target")])


def test_hardlink_extension_metadata_is_rejected(members):
    info = zipfile.ZipInfo("hardlink.sql"); info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o600) << 16
    info.extra = struct.pack("<HH", 0x000D, 6) + b"target"
    with pytest.raises(clean.PackageValidationError): validate(members, extras=[(info, b"target")])


def test_duplicate_member_is_rejected(members):
    with pytest.raises(clean.PackageValidationError):
        validate(members, extras=[("sql/f12345.sql", b"duplicate")])


def test_case_insensitive_member_collision_is_rejected(members):
    members["SQL/F12345.SQL"] = b"case alias"
    with pytest.raises(clean.PackageValidationError): validate(members)


def test_file_directory_collision_is_rejected(members):
    members["sql"] = b"not a directory"
    with pytest.raises(clean.PackageValidationError): validate(members)


def test_encrypted_zip_flags_are_rejected(members):
    raw = bytearray(pack(members))
    for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        index = raw.find(signature)
        while index >= 0:
            raw[index + offset] |= 1; index = raw.find(signature, index + 4)
    raw = bytes(raw)
    with pytest.raises(clean.PackageValidationError): clean.validate_native_package(raw, digest(raw))


def test_member_count_bound(members):
    members.update({f"extra/{n}.txt": b"x" for n in range(501)})
    with pytest.raises(clean.PackageValidationError): validate(members)


def test_high_compression_ratio_is_rejected(members):
    members["bomb.txt"] = b"x" * 1_000_000
    with pytest.raises(clean.PackageValidationError, match="compression ratio"): validate(members)


def test_member_expansion_bound(members, monkeypatch):
    monkeypatch.setattr(clean, "MAX_MEMBER_BYTES", 100)
    with pytest.raises(clean.PackageValidationError, match="size bound"): validate(members)


def test_total_expansion_bound(members, monkeypatch):
    monkeypatch.setattr(clean, "MAX_EXPANDED_BYTES", 500)
    with pytest.raises(clean.PackageValidationError, match="expanded size"): validate(members)


@pytest.mark.parametrize("manifest", [{}, [], {"ghost.sql": "0" * 64}, {"manifest.json": "0" * 64}])
def test_incomplete_or_self_referential_manifest_fails(members, manifest):
    with pytest.raises(clean.PackageValidationError): validate(members, manifest=manifest)


@pytest.mark.parametrize("bad_hash", ["0" * 64, "A" * 64, None, 123])
def test_invalid_or_changed_member_hash_fails(members, bad_hash):
    manifest = {name: digest(raw) for name, raw in members.items()}
    manifest[clean.SCHEMA_MEMBER] = bad_hash
    with pytest.raises(clean.PackageValidationError): validate(members, manifest=manifest)


def test_duplicate_json_key_is_not_last_writer_wins(members):
    members["native-form-spec.json"] = b'{"profile_id":"native-table-form-v1","profile_id":"other"}'
    with pytest.raises(clean.PackageValidationError, match="Duplicate JSON"): validate(members)


@pytest.mark.parametrize("value", [b"[]", b"null", b'{"a":NaN}', b'{"a":Infinity}', b"not-json"])
def test_bad_json_evidence_fails(members, value):
    members["native-form-spec.json"] = value
    with pytest.raises(clean.PackageValidationError): validate(members)


@pytest.mark.parametrize("suffix", [b"\n", b"DROP TABLE FOX_NATIVE_TEST;\n", b"-- identical-looking change\n"])
def test_packaged_schema_must_match_exact_renderer_bytes(members, suffix):
    members[clean.SCHEMA_MEMBER] += suffix
    with pytest.raises(clean.PackageValidationError, match="schema SQL differs"): validate(members)


@pytest.mark.parametrize("field,value", [("data_mode", "production"), ("table_name", "CUSTOMER_ORDERS"), ("profile_id", "any-table")])
def test_schema_contract_cannot_be_widened(members, field, value):
    edit(members, "native-form-spec.json", lambda obj: obj.update({field: value}))
    with pytest.raises(clean.PackageValidationError): validate(members)


@pytest.mark.parametrize("flag", ["reviewer_approved", "reviewer_execution_verified", "sqlcl_valid", "import_passed", "package_reimport_passed"])
@pytest.mark.parametrize("value", [False, 1, "true"])
def test_release_requires_explicit_true(members, flag, value):
    edit(members, "evidence/release-evidence.json", lambda obj: obj.update({flag: value}))
    with pytest.raises(clean.PackageValidationError): validate(members)


@pytest.mark.parametrize("member", ["evidence/native-review.json", "evidence/normalized-forms-inventory.json",
                                      "evidence/migration-spec.json", "evidence/migration-and-exception-report.json"])
def test_rehashed_zip_does_not_override_artifact_evidence_binding(members, member):
    members[member] += b"\n"
    with pytest.raises(clean.PackageValidationError, match="artifact binding"): validate(members)


@pytest.mark.parametrize("member", ["sql/f12345.sql", "apexlang/application.apx", "evidence/export-validation.log"])
def test_changed_export_or_validation_log_is_rejected(members, member):
    members[member] += b"-- changed\n"
    with pytest.raises(clean.PackageValidationError): validate(members)


def test_changed_sql_plus_completion_cannot_override_reimport_receipt(members):
    members["sql/f12345.sql"] += b"-- changed\n"
    edit(members, "evidence/export-completion.json", lambda obj: obj["files"].update({"f12345.sql": digest(members["sql/f12345.sql"])}))
    with pytest.raises(clean.PackageValidationError, match="separate reimport"): validate(members)


@pytest.mark.parametrize("field,value", [("application_id", 999), ("application_alias", "OTHER"), ("application_url", "https://elsewhere.invalid")])
def test_confirmed_import_identity_cannot_change(members, field, value):
    edit(members, "evidence/imported-application.json", lambda obj: obj.update({field: value}))
    with pytest.raises(clean.PackageValidationError): validate(members)


@pytest.mark.parametrize("field,value", [("job_id", "other-job"), ("application_id", 99), ("apexlang_validation_passed", 1),
                                          ("artifact_binding", {}), ("imported_application_sha256", "0" * 64), ("files", {})])
def test_export_completion_must_bind_exact_original_import(members, field, value):
    edit(members, "evidence/export-completion.json", lambda obj: obj.update({field: value}))
    with pytest.raises(clean.PackageValidationError): validate(members)


def test_missing_required_member_fails(members):
    del members["apexlang/application.apx"]
    with pytest.raises(clean.PackageValidationError): validate(members)


def test_other_application_sql_is_not_extracted(members):
    members["sql/f999.sql"] = b"not approved"
    with pytest.raises(clean.PackageValidationError, match="exactly the original"): validate(members)


def test_corrupted_seal_fails_even_after_outer_binding_is_recomputed(members):
    edit(members, "evidence/native-review.json", lambda obj: obj["review"].update(notes=["changed after sealing"]))
    rebind_evidence(members)
    with pytest.raises(clean.PackageValidationError): validate(members)


@pytest.mark.parametrize("field,value", [("job_id", "another-job"), ("source_hash", "0" * 64),
                                          ("intake_sha256", "0" * 64), ("candidate_sha256", "0" * 64)])
def test_resealed_receipt_cannot_change_candidate_or_source_identity(members, field, value):
    reseal_review(members, lambda obj: obj.update({field: value}))
    with pytest.raises(clean.PackageValidationError): validate(members)


@pytest.mark.parametrize("field,value", [("verdict", "reject"), ("candidate_sha256", "0" * 64),
                                          ("blocking_findings", ["Missing key proof"])])
def test_resealed_nonapproval_is_never_approval(members, field, value):
    reseal_review(members, lambda obj: obj["review"].update({field: value}))
    with pytest.raises(clean.PackageValidationError): validate(members)


@pytest.mark.parametrize("field,value", [("workflow_id", "A" * 32), ("room_id", "A-synthetic-room"),
                                          ("started_at_utc", "2026-10-17T00:00:00Z"), ("model", "different-model")])
def test_resealed_review_must_remain_a_separate_ordered_invocation(members, field, value):
    reseal_review(members, lambda obj: obj["reviewer_invocation"].update({field: value}))
    with pytest.raises(clean.PackageValidationError): validate(members)


def test_changed_candidate_cannot_be_hidden_by_outer_binding(members):
    reseal_review(members, lambda obj: obj["candidate"].update(mapping_summary="Changed candidate"))
    with pytest.raises(clean.PackageValidationError): validate(members)


def test_inventory_readable_source_hash_is_checked_not_only_file_binding(members):
    edit(members, "evidence/normalized-forms-inventory.json", lambda obj: obj["modules"][0].update(readable_source="changed source"))
    rebind_evidence(members)
    with pytest.raises(clean.PackageValidationError, match="Source content"): validate(members)


def test_rehashed_inventory_source_cannot_change_approved_manifest(members):
    def change(inventory):
        inventory["modules"][0].update(readable_source="changed source", sha256=digest(b"changed source"))
    edit(members, "evidence/normalized-forms-inventory.json", change)
    rebind_evidence(members)
    with pytest.raises(clean.PackageValidationError, match="Inventory differs"): validate(members)


def test_materialized_candidate_must_match_the_reviewed_candidate(members):
    edit(members, "evidence/migration-spec.json", lambda obj: obj.update(mapping_summary="Different materialized mapping"))
    rebind_evidence(members)
    with pytest.raises(clean.PackageValidationError, match="Materialized migration spec"): validate(members)


def test_no_generic_extraction_or_sql_execution_api_is_exposed():
    assert not hasattr(clean, "extract_validated_package")
    assert not hasattr(clean, "subprocess")


def test_rejects_linked_input_file_without_opening_it(members, tmp_path, monkeypatch):
    path = tmp_path / "linked.zip"
    path.write_bytes(pack(members))
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda value: value == path or original(value))
    with pytest.raises(clean.PackageValidationError, match="unlinked regular file"):
        clean.validate_native_package(path, digest(path.read_bytes()))


@pytest.fixture
def v2_members(members):
    from forms2apex.target_profile import load_target_profile
    profile = load_target_profile(Path(__file__).resolve().parents[2] / "deployment/target-profile.jsn.json")
    profile_hash = digest(encoded(profile))
    def make_v2(review):
        review["schema_version"] = 2
        review["historical_target_profile"] = deepcopy(profile)
        review["model_environment"] = {}
        for role in ("mapper", "reviewer"):
            invocation = review[role + "_invocation"]
            invocation.update(profile["opaf"]["roles"][role])
            review["model_environment"][role] = {
                "schema_version": 1, "scope": "opaf-model-environment-v1",
                "trust_boundary": "authenticated_fox_executor_not_vendor_attestation",
                "job_id": review["job_id"], "role": role, "source_manifest_sha256": review["source_hash"],
                "target_profile_sha256": profile_hash, "observed_at_utc": invocation["started_at_utc"],
                "opaf": {key: profile["opaf"][key] for key in ("base_url", "certificate_sha256", "model_authentication", "version_number", "build_id")},
                "workflow": {**profile["opaf"]["roles"][role], "published": True},
                "opaf_version": profile["tested_versions"]["opaf"],
            }
    reseal_review(members, make_v2)
    members["evidence/target-profile.json"] = encoded(profile)
    return members


def test_selfcontained_v2_package_binds_canonical_profile_and_reports_historical_only(v2_members):
    result = validate(v2_members)
    profile = json.loads(v2_members["evidence/target-profile.json"])
    assert result["historical_target_profile"] == profile
    assert result["historical_model_environment_verified"] is True
    assert result["review_proof_scope"] == "historical_model_environment_and_invocation_candidate_source_binding"
    assert result["current_target_authorized"] is False
    assert result["customer_compatibility_verified"] is False
    assert result["schema_sql"] == v2_members[clean.SCHEMA_MEMBER]


def test_v2_missing_bundled_profile_is_not_backfilled(v2_members):
    del v2_members["evidence/target-profile.json"]
    with pytest.raises(clean.PackageValidationError): validate(v2_members)


def test_v2_missing_sealed_profile_is_not_backfilled_from_bundle(v2_members):
    reseal_review(v2_members, lambda receipt: receipt.pop("historical_target_profile"))
    with pytest.raises(clean.PackageValidationError): validate(v2_members)


def test_v2_bundled_profile_must_be_exact_canonical_bytes(v2_members):
    profile = json.loads(v2_members["evidence/target-profile.json"])
    v2_members["evidence/target-profile.json"] = json.dumps(profile, indent=2).encode()
    with pytest.raises(clean.PackageValidationError, match="canonical sealed historical profile"): validate(v2_members)


def test_v2_changed_bundled_profile_cannot_substitute_for_sealed_profile(v2_members):
    edit(v2_members, "evidence/target-profile.json", lambda profile: profile["opaf"].update(build_id=1))
    with pytest.raises(clean.PackageValidationError, match="canonical sealed historical profile"): validate(v2_members)


def test_v2_resealed_and_rebundled_unknown_profile_still_requires_known_registry(v2_members):
    def mutate(receipt):
        receipt["historical_target_profile"]["opaf"]["build_id"] += 1
        new_hash = digest(encoded(receipt["historical_target_profile"]))
        for role in ("mapper", "reviewer"):
            receipt["model_environment"][role]["target_profile_sha256"] = new_hash
            receipt["model_environment"][role]["opaf"]["build_id"] += 1
    reseal_review(v2_members, mutate)
    receipt = json.loads(v2_members["evidence/native-review.json"])
    v2_members["evidence/target-profile.json"] = encoded(receipt["historical_target_profile"])
    with pytest.raises(clean.PackageValidationError): validate(v2_members)


@pytest.mark.parametrize("role", ["mapper", "reviewer"])
@pytest.mark.parametrize("field,value", [("job_id", "other-job"), ("source_manifest_sha256", "0" * 64),
                                          ("role", "generator"), ("target_profile_sha256", "0" * 64),
                                          ("opaf_version", "26.5"), ("observed_at_utc", "2026-01-01T00:00:00Z")])
def test_v2_resealed_observation_must_match_actual_invocation_context(v2_members, role, field, value):
    reseal_review(v2_members, lambda receipt: receipt["model_environment"][role].update({field: value}))
    with pytest.raises(clean.PackageValidationError): validate(v2_members)


@pytest.mark.parametrize("field,value", [("graph_sha256", "0" * 64), ("published", False), ("workflow_id", "A" * 32)])
def test_v2_observed_workflow_must_match_registered_historical_snapshot(v2_members, field, value):
    reseal_review(v2_members, lambda receipt: receipt["model_environment"]["reviewer"]["workflow"].update({field: value}))
    with pytest.raises(clean.PackageValidationError): validate(v2_members)


def test_v2_historical_package_verifies_with_opaf_offline_and_deployable_profile_rotated(v2_members, monkeypatch):
    import forms2apex.runtime_preflight as runtime
    import forms2apex.target_profile as profiles
    old_profile = json.loads(v2_members["evidence/target-profile.json"])
    new_profile = profiles.load_target_profile(Path(__file__).resolve().parents[2] /
                                               'deployment/target-profile.jsn-project-v2.json')
    new_digest = profiles.target_profile_sha256(new_profile)
    monkeypatch.setattr(profiles, "_DEPLOYABLE_TARGET_PROFILES", {new_digest: new_profile})
    def forbidden(*args, **kwargs): pytest.fail("Offline package verification must not probe live services or clock")
    monkeypatch.setattr(runtime, "_now", forbidden)
    monkeypatch.setattr(runtime.http.client, "HTTPConnection", forbidden)
    monkeypatch.setattr(runtime.http.client, "HTTPSConnection", forbidden)
    monkeypatch.setattr(runtime.subprocess, "run", forbidden)
    result = validate(v2_members)
    assert result["historical_target_profile"] == old_profile
    assert result["current_target_authorized"] is False


def test_v1_package_must_not_invent_bundled_historical_profile(members):
    members["evidence/target-profile.json"] = b"{}"
    with pytest.raises(clean.PackageValidationError, match="Legacy v1"): validate(members)


def test_v1_package_must_not_invent_sealed_environment(members):
    reseal_review(members, lambda receipt: receipt.update(model_environment={"mapper": {}, "reviewer": {}}))
    with pytest.raises(clean.PackageValidationError): validate(members)


def test_v1_scope_remains_explicitly_without_environment_evidence(members):
    result = validate(members)
    assert result["historical_model_environment_verified"] is False
    assert result["historical_target_profile"] is None
    assert result["review_proof_scope"] == "legacy_invocation_candidate_source_binding_no_model_environment"
    assert result["current_target_authorized"] is False


@pytest.mark.parametrize("bom", [False, True], ids=["utf8", "utf8-sig"])
@pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["lf", "crlf"])
@pytest.mark.parametrize("with_byte_count", [False, True], ids=["legacy-no-count", "original-count"])
def test_source_identity_preserves_exact_bom_and_line_ending_bytes(bom, newline, with_byte_count):
    text = newline.join(['<FormModule Name="SYNTHETIC">', '<Block Name="TEST"/>', '</FormModule>', ''])
    raw = (b"\xef\xbb\xbf" if bom else b"") + text.encode("utf-8")
    original_hash = digest(raw)
    module = {"file": "source.xml", "readable_source": text, "sha256": original_hash}
    if with_byte_count:
        module["bytes"] = len(raw)
    inventory = {"modules": [module]}; before = deepcopy(inventory)
    assert clean._source_identity(inventory) == digest(("source.xml:" + original_hash).encode())
    assert inventory == before


@pytest.mark.parametrize("count", [None, True, False, -1, "10", 1.0, 0, 999])
def test_provided_original_source_byte_count_is_strict(count):
    raw = b"\xef\xbb\xbf" + "synthetic café\r\n".encode("utf-8")
    inventory = {"modules": [{"file": "source.xml", "readable_source": raw.decode("utf-8-sig"),
                              "sha256": digest(raw), "bytes": count}]}
    with pytest.raises(clean.PackageValidationError, match="byte count"):
        clean._source_identity(inventory)


def test_original_byte_count_includes_bom_and_multibyte_characters():
    text = "synthetic café\r\n"; raw = b"\xef\xbb\xbf" + text.encode("utf-8")
    module = {"file": "source.xml", "readable_source": text, "sha256": digest(raw), "bytes": len(raw)}
    assert clean._source_identity({"modules": [module]})
    for wrong in (len(text), len(text.encode("utf-8"))):
        module["bytes"] = wrong
        with pytest.raises(clean.PackageValidationError, match="byte count"):
            clean._source_identity({"modules": [module]})


@pytest.mark.parametrize("text,original", [
    ("first\nsecond\n", b"first\r\nsecond\r\n"),
    ("first\r\nsecond\r\n", b"first\nsecond\n"),
    ("café", "café".encode("latin-1")),
    ("café", "café".encode("utf-16")),
])
def test_source_identity_never_guesses_other_encodings_or_normalized_hashes(text, original):
    inventory = {"modules": [{"file": "source.xml", "readable_source": text, "sha256": digest(original)}]}
    with pytest.raises(clean.PackageValidationError, match="Source content"):
        clean._source_identity(inventory)


@pytest.mark.parametrize("count,passes", [(299997, True), (299998, False)])
def test_source_size_bound_counts_original_bom_bytes_even_for_legacy_inventory(count, passes):
    text = "x" * count; raw = b"\xef\xbb\xbf" + text.encode()
    inventory = {"modules": [{"file": "source.xml", "readable_source": text, "sha256": digest(raw)}]}
    if passes:
        assert clean._source_identity(inventory)
    else:
        with pytest.raises(clean.PackageValidationError, match="intake bound"):
            clean._source_identity(inventory)


@pytest.mark.parametrize("fixture_name", ["members", "v2_members"], ids=["v1", "v2"])
def test_complete_package_accepts_bom_crlf_source_without_normalizing_proof(request, fixture_name):
    members = request.getfixturevalue(fixture_name)
    text = '<FormModule Name="SYNTHETIC">\r\n<Block Name="TEST"/>\r\n</FormModule>\r\n'
    raw = b"\xef\xbb\xbf" + text.encode(); original_hash = digest(raw)
    source_hash = digest(("source.xml:" + original_hash).encode())
    edit(members, "evidence/normalized-forms-inventory.json", lambda obj:
         obj["modules"][0].update(readable_source=text, sha256=original_hash, bytes=len(raw)))
    edit(members, "evidence/release-evidence.json", lambda obj: obj.update(source_manifest_sha256=source_hash))
    def reviewed_original_source(receipt):
        receipt["source_hash"] = source_hash
        if receipt["schema_version"] == 2:
            for role in ("mapper", "reviewer"):
                receipt["model_environment"][role]["source_manifest_sha256"] = source_hash
    reseal_review(members, reviewed_original_source)
    before = deepcopy(members)
    result = validate(members)
    assert result["source_manifest_sha256"] == source_hash
    assert members == before

