"""Local assembly tests with sanitized sources and explicitly synthetic validation.

No test here invokes SQLcl, Oracle, a provider, or business acceptance.
"""
from copy import deepcopy
import hashlib
import io
import json
import zipfile

import pytest

from fox import behavior_package as assembly
from fox.forms_behavior_plan import build_behavior_plan
from fox.opaf import OpafError
from fox.opaf import canonical_hash
from test_forms_behavior_plan import documents, package


UNVERIFIED = (
    "import_verified", "runtime_verified", "clean_schema_install_passed",
    "package_reimport_passed", "technically_verified", "business_behavior_accepted",
)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def unpack(raw):
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def pack(files):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return stream.getvalue()


def fixture():
    docs = documents()
    # Extend the public sanitized fixture to 53 genuine parser-discovered units.
    extra = ''.join(f'<Trigger Name="UNSUPPORTED_{i}" TriggerText="NULL;"/>' for i in range(50))
    docs = [(docs[0][0], docs[0][1].replace(b'</Block>', extra.encode() + b'</Block>'))]
    parent = package(docs)
    plan = build_behavior_plan(docs, parent)
    files = unpack(parent)
    # Planner fixtures use compact APX; assembly must exercise the canonical
    # renderer's multiline report contract with the same sanitized target.
    files["pages/p00003-parcel.apx"] = (
        "page 3 (\n    region records (\n        type: interactiveReport\n"
        "        source {\n            location: localDatabase\n            type: tableView\n"
        "            tableName: FOX_TEST\n        }\n"
        + ''.join(f"        column {column} (\n        )\n" for column in
                  ("FOX_ROW_ID", "C_MASS", "C_STATE", "C_ROUNDED"))
        + "        savedReport primary (\n        )\n    )\n)\n"
    ).encode()
    remediation = [
        {"code": "code_unit_not_translated", "code_unit_id": row["source_unit_id"],
         "reason": "Original source behavior remains unimplemented"}
        for row in plan["coverage"]
    ]
    remediation += [{"code": "dependency_unresolved", "reason": "Review dependency"},
                    {"code": "mapping_warning", "code_unit_id": plan["operations"][0]["source_unit_id"]}]
    historical = {"data_mode": "synthetic", "selected_code_scope": "explicit_sanitized_units",
                  "compatibility": {"apex": "synthetic-test-only", "renderer_template": "synthetic-parent"}, "prerequisites": ["Review target"],
                  "format_validated": True, "validation": {"passed": True, "historical": True}}
    files.update({"fox-package/metadata.json": json.dumps(historical).encode(),
                  "fox-package/remediation.json": json.dumps(remediation).encode(),
                  "fox-package/README.md": b"Historical parent instructions",
                  "fox-package/ai-review.json": b'{"approved":true,"scope":"original mapping"}',
                  ".apex/apexlang.json": b'{"synthetic":"retained configuration"}',
                  "application.apx": b'app synthetic ( )'})
    return docs, pack(files)


def authored_fake_validator(candidate, directory):
    """Author a test log only; this is explicitly not a real compiler result."""
    directory.mkdir(parents=True, exist_ok=True)
    log = b"AUTHORED SYNTHETIC TEST VALIDATOR. NO ORACLE EXECUTION.\n" + sha(candidate).encode()
    digest = sha(log)
    (directory / f"offline-{digest}.log").write_bytes(log)
    return {"passed": True, "return_code": 0, "connection_mode": "/nolog",
            "sqlcl_version": "SYNTHETIC-TEST-ONLY", "validation_log_sha256": digest}


def test_prepare_rebuilds_source_plan_retains_parent_and_reports_all_53_units():
    docs, parent = fixture()
    before = deepcopy(docs), parent
    expected_plan = build_behavior_plan(docs, parent)
    candidate, receipt = assembly.prepare_behavior_package(docs, parent)
    assert receipt["plan"] == expected_plan
    assert receipt["candidate_sha256"] == sha(candidate)
    assert (docs, parent) == before
    original, current = unpack(parent), unpack(candidate)
    metadata = json.loads(current["fox-package/metadata.json"])
    assert metadata["source_parser_rebuilt"] is True
    assert metadata["parent_zip_sha256"] == sha(parent)
    assert metadata["parent_metadata_sha256"] == sha(original["fox-package/metadata.json"])
    assert metadata["status"] == "GENERATED_FORMAT_VALIDATION_PENDING"
    assert metadata["format_validated"] is False and metadata["validation"] is None
    assert metadata["parent_validation_applies"] is False
    assert metadata["parent_AI_reviews_apply_to"] == "original mapping only"
    assert metadata["renderer_receipt_sha256"] == canonical_hash(json.loads(current[metadata["renderer_receipt_path"]]))
    assert metadata["compatibility"]["parent_renderer_template"] == "synthetic-parent"
    assert metadata["compatibility"]["behavior_renderer"]["sources"] == receipt["renderer_receipt"]["renderer_sources"]
    assert all(metadata[key] is False for key in UNVERIFIED)
    assert receipt["format_validated"] is receipt["runtime_verified"] is receipt["business_behavior_accepted"] is False
    for name in ("metadata.json", "remediation.json", "source-to-page.json", "README.md"):
        assert current["fox-package/parent/" + name] == original["fox-package/" + name]
    changed = set(receipt["renderer_receipt"]["changed_members"])
    replaced = {"fox-package/" + name for name in ("metadata.json", "remediation.json", "source-to-page.json", "README.md")}
    for name in original.keys() - changed - replaced:
        assert current[name] == original[name]
    coverage = json.loads(current["fox-package/behavior-coverage.json"])
    assert len(coverage) == 53
    generated = {row["source_unit_id"] for row in coverage if row["status"] == "generated_wired_adapted"}
    assert len(generated) == 2
    assert sum(row["status"] == "unsupported" for row in coverage) == 51
    assert metadata["behavior_coverage"] == {"total": 53, "counts": {"generated_wired_adapted": 2, "unsupported": 51}}
    assert all(row["runtime_verified"] is row["business_accepted"] is False for row in coverage)
    old_rows = json.loads(original["fox-package/remediation.json"])
    new_rows = json.loads(current["fox-package/remediation.json"])
    assert len(old_rows) == len(new_rows) == 55
    for old, new in zip(old_rows, new_rows):
        if old["code"] == "code_unit_not_translated" and old["code_unit_id"] in generated:
            assert new["code"] == "behavior_generated_runtime_pending"
            assert new["generation_status"] == "generated_wired_adapted"
        else:
            assert new == old
    trace = json.loads(current["fox-package/source-to-page.json"])
    assert trace["coverage"] == coverage
    assert trace["runtime_verified"] is trace["business_behavior_accepted"] is False


def test_prepare_rejects_changed_source_and_missing_supported_selection():
    docs, parent = fixture()
    stale = [(docs[0][0], docs[0][1].replace(b"Actual amount", b"Changed amount"))]
    with pytest.raises(ValueError):
        assembly.prepare_behavior_package(stale, parent)
    with pytest.raises(ValueError, match="No complete supported behavior"):
        assembly.prepare_behavior_package(docs, parent, [])
    files = unpack(parent)
    manifest = json.loads(files["fox-package/source-manifest.json"])
    manifest["selected_chunk_hashes"] = {}
    files["fox-package/source-manifest.json"] = json.dumps(manifest).encode()
    with pytest.raises(ValueError, match="No complete supported behavior"):
        assembly.prepare_behavior_package(docs, pack(files))


def test_explicit_selection_retains_omitted_coverage_and_remediation():
    docs, parent = fixture()
    selected = build_behavior_plan(docs, parent)["operations"][0]["source_unit_id"]
    candidate, receipt = assembly.prepare_behavior_package(docs, parent, [selected])
    assert len(receipt["renderer_receipt"]["generated_operations"]) == 1
    files = unpack(candidate)
    coverage = json.loads(files["fox-package/behavior-coverage.json"])
    assert len(coverage) == 53
    assert sum(row["status"] == "generated_wired_adapted" for row in coverage) == 1
    assert sum(row["code"] == "code_unit_not_translated" for row in json.loads(files["fox-package/remediation.json"])) == 52


def test_prepare_rejects_archive_collision_without_overwriting_parent_evidence():
    docs, parent = fixture()
    files = unpack(parent)
    files["fox-package/parent/metadata.json"] = b"Existing historical evidence"
    parent = pack(files)
    before = parent
    with pytest.raises(ValueError, match="Parent evidence archive already exists"):
        assembly.prepare_behavior_package(docs, parent)
    assert parent == before


def test_synthetic_validation_receives_exact_candidate_and_preserves_all_apex_bytes(tmp_path):
    docs, parent = fixture()
    candidate, prepared = assembly.prepare_behavior_package(docs, parent)
    seen = []
    def validator(raw, directory):
        seen.append(raw)
        return authored_fake_validator(raw, directory)
    output, evidence = assembly.validate_behavior_package(candidate, tmp_path, validator=validator)
    assert seen == [candidate]
    assert evidence["candidate_sha256"] == sha(candidate)
    assert evidence["package_sha256"] == sha(output)
    before, after = unpack(candidate), unpack(output)
    apex_names = {name for name in before if name.endswith(".apx") or name.startswith(".apex/")}
    assert apex_names and any(name.startswith(".apex/") for name in apex_names)
    assert {name for name in after if name.endswith(".apx") or name.startswith(".apex/")} == apex_names
    assert all(after[name] == before[name] for name in apex_names)
    assert evidence["apex_members"] == prepared["apex_members"]
    assert {name for name in before if before[name] != after[name]} == {"fox-package/metadata.json"}
    metadata = json.loads(after["fox-package/metadata.json"])
    assert metadata["format_validated"] is True
    assert metadata["status"] == "GENERATED_FORMAT_VALIDATED_RUNTIME_UNVERIFIED"
    assert metadata["validation"]["sqlcl_version"] == "SYNTHETIC-TEST-ONLY"
    assert all(metadata[key] is False for key in UNVERIFIED)
    assert evidence["runtime_verified"] is evidence["business_behavior_accepted"] is False


@pytest.mark.parametrize("mode", ["missing_log", "changed_log", "failed", "unknown", "nonzero", "connected"])
def test_validation_rejects_missing_failed_unknown_or_changed_evidence(tmp_path, mode):
    candidate, _ = assembly.prepare_behavior_package(*fixture())
    def validator(raw, directory):
        result = authored_fake_validator(raw, directory)
        path = directory / ("offline-" + result["validation_log_sha256"] + ".log")
        if mode == "missing_log":
            path.unlink()
        elif mode == "changed_log":
            path.write_bytes(b"changed")
        elif mode == "failed":
            result["passed"] = False
        elif mode == "unknown":
            return None
        elif mode == "nonzero":
            result["return_code"] = 1
        elif mode == "connected":
            result["connection_mode"] = "connected"
        return result
    with pytest.raises(OpafError):
        assembly.validate_behavior_package(candidate, tmp_path, validator=validator)


def test_seal_rejects_evidence_bound_to_another_candidate(tmp_path):
    candidate, _ = assembly.prepare_behavior_package(*fixture())
    validation = authored_fake_validator(candidate, tmp_path)
    with pytest.raises(ValueError, match="another candidate"):
        assembly._seal_validated_behavior_package(candidate, {"candidate_sha256": "0" * 64, "validation": validation}, tmp_path)


@pytest.mark.parametrize("change", [
    {"scope": "unexpected"}, {"format_validated": True}, {"validation": {"passed": True}},
    {"parent_validation_applies": True}, {"runtime_verified": True},
    {"business_behavior_accepted": True}, {"apex_members": {}},
])
def test_validation_rejects_unexpected_candidate_metadata(tmp_path, change):
    candidate, _ = assembly.prepare_behavior_package(*fixture())
    files = unpack(candidate)
    metadata = json.loads(files["fox-package/metadata.json"])
    metadata.update(change)
    files["fox-package/metadata.json"] = json.dumps(metadata).encode()
    with pytest.raises(ValueError, match="metadata or generated APEX content changed"):
        assembly.validate_behavior_package(pack(files), tmp_path, validator=authored_fake_validator)


@pytest.mark.parametrize("name", ["application.apx", ".apex/apexlang.json"])
def test_validation_rejects_apex_member_changed_after_preparation(tmp_path, name):
    candidate, _ = assembly.prepare_behavior_package(*fixture())
    files = unpack(candidate)
    files[name] += b"tampered"
    with pytest.raises(ValueError, match="metadata or generated APEX content changed"):
        assembly.validate_behavior_package(pack(files), tmp_path, validator=authored_fake_validator)
