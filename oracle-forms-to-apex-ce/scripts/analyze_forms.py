#!/usr/bin/env python3
"""Build a conservative inventory from Oracle Forms XML and PLD evidence."""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


OBJECT_TYPES = (
    "Alert",
    "AttachedLibrary",
    "Block",
    "Canvas",
    "Item",
    "Trigger",
    "ProgramUnit",
    "PropertyClass",
    "RecordGroup",
    "LOV",
    "Report",
    "Window",
    "Parameter",
    "Relation",
    "VisualAttribute",
    "Menu",
    "MenuItem",
)
PARENT_CONTEXT_TYPES = {"Item", "Block", "FormModule", "MenuModule", "ObjectLibrary"}
SQL_PATTERNS = (
    re.compile(r"\bFROM\s+([A-Z][A-Z0-9_$#]*(?:\.[A-Z][A-Z0-9_$#]*)?)", re.I),
    re.compile(r"\bJOIN\s+([A-Z][A-Z0-9_$#]*(?:\.[A-Z][A-Z0-9_$#]*)?)", re.I),
    re.compile(r"\bUPDATE\s+([A-Z][A-Z0-9_$#]*(?:\.[A-Z][A-Z0-9_$#]*)?)", re.I),
    re.compile(r"\bINSERT\s+INTO\s+([A-Z][A-Z0-9_$#]*(?:\.[A-Z][A-Z0-9_$#]*)?)", re.I),
    re.compile(r"\bDELETE\s+FROM\s+([A-Z][A-Z0-9_$#]*(?:\.[A-Z][A-Z0-9_$#]*)?)", re.I),
)
PLD_ROUTINE_PATTERN = re.compile(
    r"^\s*(PROCEDURE|FUNCTION|PACKAGE(?:\s+BODY)?)\s+([A-Z][A-Z0-9_$#]*)",
    re.I | re.M,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser.parse_args()


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def attribute(node: ET.Element | None, name: str) -> str | None:
    return node.attrib.get(name) if node is not None else None


def decode_forms_text(value: str | None) -> str:
    return html.unescape(value or "")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_text(path: Path) -> str:
    for encoding in ("utf-8-sig", "utf-16", "cp1252"):
        try:
            return path.read_text(encoding=encoding)
        except UnicodeError:
            continue
    raise UnicodeError(f"Could not decode text file: {path}")


def reject_symlink(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"Symlinks are not accepted: {path}")


def collect_files(input_path: Path, extension: str) -> list[Path]:
    reject_symlink(input_path)
    resolved = input_path.expanduser().resolve(strict=True)
    if resolved.is_file():
        return [resolved] if resolved.suffix.lower() == extension else []
    files: list[Path] = []
    for candidate in resolved.rglob("*"):
        if candidate.is_symlink():
            raise ValueError(f"Symlinks are not accepted: {candidate}")
        if candidate.is_file() and candidate.suffix.lower() == extension:
            files.append(candidate.resolve())
    return sorted(files, key=lambda item: str(item).lower())


def parent_context(node: ET.Element, parents: dict[ET.Element, ET.Element]) -> str:
    parent = parents.get(node)
    while parent is not None and local_name(parent.tag) not in PARENT_CONTEXT_TYPES:
        parent = parents.get(parent)
    if parent is None:
        return "Unknown"
    return f"{local_name(parent.tag)}:{attribute(parent, 'Name') or ''}"


def write_csv(path: Path, fieldnames: list[str], rows: Iterable[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    args = parse_args()
    input_path = args.input.expanduser()
    output_dir = args.output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    xml_files = collect_files(input_path, ".xml")
    pld_files = collect_files(input_path, ".pld")
    if not xml_files and not pld_files:
        raise ValueError("No .xml or .pld evidence files were found.")

    modules: list[dict[str, object]] = []
    triggers: list[dict[str, object]] = []
    program_units: list[dict[str, object]] = []
    reports: list[dict[str, object]] = []
    pld_routines: list[dict[str, object]] = []
    source_texts: list[str] = []

    for file_path in xml_files:
        tree = ET.parse(file_path)
        root = tree.getroot()
        nodes = list(root.iter())
        parents = {child: parent for parent in nodes for child in parent}
        module_node = next(
            (
                node
                for node in nodes
                if local_name(node.tag) in {"FormModule", "MenuModule", "ObjectLibrary"}
            ),
            None,
        )
        counts = {
            object_type: sum(1 for node in nodes if local_name(node.tag) == object_type)
            for object_type in OBJECT_TYPES
        }
        modules.append(
            {
                "file": str(file_path),
                "sha256": sha256(file_path),
                "module_type": local_name(module_node.tag) if module_node is not None else None,
                "module_name": attribute(module_node, "Name"),
                "title": attribute(module_node, "Title"),
                "menu_module": attribute(module_node, "MenuModule"),
                "object_counts": counts,
            }
        )

        for node in nodes:
            kind = local_name(node.tag)
            if kind == "Trigger":
                source = decode_forms_text(attribute(node, "TriggerText"))
                source_texts.append(source)
                triggers.append(
                    {
                        "file": file_path.name,
                        "context": parent_context(node, parents),
                        "name": attribute(node, "Name"),
                        "source": source,
                    }
                )
            elif kind == "ProgramUnit":
                source = decode_forms_text(attribute(node, "ProgramUnitText"))
                source_texts.append(source)
                program_units.append(
                    {
                        "file": file_path.name,
                        "name": attribute(node, "Name"),
                        "type": attribute(node, "ProgramUnitType"),
                        "source": source,
                    }
                )
            elif kind == "RecordGroup":
                source_texts.append(decode_forms_text(attribute(node, "RecordGroupQuery")))
            elif kind == "Report":
                reports.append(
                    {
                        "file": file_path.name,
                        "name": attribute(node, "Name"),
                        "filename": attribute(node, "Filename"),
                        "source_supplied": False,
                    }
                )

    for file_path in pld_files:
        content = read_text(file_path)
        source_texts.append(content)
        for match in PLD_ROUTINE_PATTERN.finditer(content):
            pld_routines.append(
                {
                    "file": file_path.name,
                    "type": match.group(1).upper(),
                    "name": match.group(2).upper(),
                }
            )

    combined_source = "\n".join(source_texts)
    database_candidates = sorted(
        {
            match.group(1).upper()
            for pattern in SQL_PATTERNS
            for match in pattern.finditer(combined_source)
        }
    )
    unique_pld_routines = sorted(
        {
            (str(row["file"]), str(row["type"]), str(row["name"]))
            for row in pld_routines
        }
    )
    pld_routines = [
        {"file": file_name, "type": routine_type, "name": routine_name}
        for file_name, routine_type, routine_name in unique_pld_routines
    ]

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input": str(input_path.resolve()),
        "modules": modules,
        "pld_files": [str(path) for path in pld_files],
        "counts": {
            "modules": len(modules),
            "triggers": len(triggers),
            "program_units": len(program_units),
            "reports_registered": len(reports),
            "pld_routines": len(pld_routines),
            "database_candidates": len(database_candidates),
        },
        "database_object_candidates": database_candidates,
        "interpretation_boundary": (
            "Database candidates and report registrations are inventory evidence only; "
            "verify existence, source, behavior, and ownership manually."
        ),
    }

    (output_dir / "migration-inventory.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )
    write_csv(
        output_dir / "forms-triggers.csv",
        ["file", "context", "name", "source"],
        triggers,
    )
    write_csv(
        output_dir / "forms-program-units.csv",
        ["file", "name", "type", "source"],
        program_units,
    )
    write_csv(
        output_dir / "report-registrations.csv",
        ["file", "name", "filename", "source_supplied"],
        reports,
    )
    write_csv(
        output_dir / "pld-routines.csv",
        ["file", "type", "name"],
        pld_routines,
    )
    print(json.dumps(summary, indent=2))
    print(f"Inventory written to {output_dir}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ET.ParseError, OSError, UnicodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
