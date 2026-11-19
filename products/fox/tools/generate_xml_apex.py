"""Generate one deterministic synthetic APEXlang application from preserved Forms XML."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import sys

PRODUCT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(PRODUCT / "fox"), str(PRODUCT / "converter")]
from fox.xml_mapping import generate_xml_package, mapping_catalog, validate_xml_package
from fox.forms_facts import MAX_FILE_BYTES
from fox.forms_understanding_packet import MAX_FILES, MAX_TOTAL_SOURCE_BYTES


def _write(path, raw):
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xml", type=Path, action="append")
    parser.add_argument("--project-id")
    parser.add_argument("--project-name")
    parser.add_argument("--approved-policy-id")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--validate-sqlcl", action="store_true")
    parser.add_argument("--list-mappings", action="store_true")
    args = parser.parse_args(argv)
    if args.list_mappings:
        print(_json(mapping_catalog()).decode("utf-8"))
        return 0
    for name in ("xml", "project_id", "project_name", "approved_policy_id", "output"):
        if getattr(args, name) is None:
            parser.error("--" + name.replace("_", "-") + " is required for generation")
    # Fail before reading input or doing generation when destination is occupied.
    if args.output.exists() or args.output.is_symlink():
        raise ValueError("Output must be a fresh create-only directory.")
    if not 1 <= len(args.xml) <= MAX_FILES:
        raise ValueError("Supply between 1 and 4 Forms XML documents.")
    if any(path.is_symlink() or not path.is_file() for path in args.xml):
        raise ValueError("XML inputs must be regular original files, not links.")
    sizes = [path.stat().st_size for path in args.xml]
    if any(not 0 < size <= MAX_FILE_BYTES for size in sizes) or sum(sizes) > MAX_TOTAL_SOURCE_BYTES:
        raise ValueError("XML inputs exceed the existing bounded source-byte limits.")
    documents = [(path.name, path.read_bytes()) for path in args.xml]
    candidate, report = generate_xml_package(documents, args.project_id, args.project_name, args.approved_policy_id)
    args.output.mkdir(parents=True, exist_ok=False)
    _write(args.output / "candidate.zip", candidate)
    _write(args.output / "generation-report.json", _json(report))
    final = None
    if args.validate_sqlcl:
        final, validation = validate_xml_package(candidate, args.output)
        _write(args.output / "APEXlang-xml-package.zip", final)
        _write(args.output / "format-validation.json", _json(validation))
    metadata = report["metadata"]
    summary = {"status": "FORMAT_VALIDATED" if final else "GENERATED_VALIDATION_PENDING",
        "source_binding": report["source_binding"], "structural_only": metadata["structural_only"],
        "application_count": 1, "behavior_coverage": metadata["behavior_coverage"],
        "applied_rule_ids": metadata["applied_rule_ids"], "catalog_sha256": metadata["catalog_sha256"],
        "candidate_sha256": report["candidate_sha256"],
        "package_sha256": hashlib.sha256(final).hexdigest() if final else None,
        "provider_calls": 0, "database_imports": 0,
        "runtime_verified": False, "business_behavior_accepted": False}
    _write(args.output / "result.json", _json(summary))
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
