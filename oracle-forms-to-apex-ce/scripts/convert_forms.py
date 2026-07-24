#!/usr/bin/env python3
"""Convert Oracle Forms modules to XML using installed Oracle tooling."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable


SOURCE_EXTENSIONS = {".fmb", ".mmb", ".olb"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", action="append", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--converter-path", type=Path)
    parser.add_argument("--validator-path", type=Path)
    parser.add_argument("--dump", choices=("OVERRIDDEN", "ALL"), default="OVERRIDDEN")
    return parser.parse_args()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def reject_symlink(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"Symlinks are not accepted: {path}")


def first_existing(candidates: Iterable[Path | None]) -> Path | None:
    for candidate in candidates:
        if candidate and candidate.expanduser().is_file():
            return candidate.expanduser().resolve()
    return None


def tool_names(base: str) -> tuple[str, ...]:
    if os.name == "nt":
        return (f"{base}.bat", f"{base}.cmd", f"{base}.exe", base)
    return (base, f"{base}.sh")


def default_homes() -> list[Path]:
    homes: list[Path] = []
    if os.environ.get("ORACLE_HOME"):
        homes.append(Path(os.environ["ORACLE_HOME"]).expanduser())
    if os.name == "nt":
        homes.append(Path("C:/Oracle/Middleware/FormsBuilderInstance"))
    return homes


def resolve_tool(explicit: Path | None, base: str, sibling: Path | None = None) -> Path | None:
    candidates: list[Path | None] = [explicit]
    if sibling:
        candidates.extend(sibling.parent / name for name in tool_names(base))
    for home in default_homes():
        for name in tool_names(base):
            candidates.extend((home / "bin" / name, home / "forms" / "bin" / name))
    found = first_existing(candidates)
    if found:
        return found
    for name in tool_names(base):
        path = shutil.which(name)
        if path:
            return Path(path).resolve()
    return None


def collect_sources(inputs: list[Path]) -> list[Path]:
    sources: set[Path] = set()
    for raw in inputs:
        path = raw.expanduser().resolve(strict=True)
        reject_symlink(raw.expanduser())
        if path.is_dir():
            for candidate in path.rglob("*"):
                if candidate.is_symlink():
                    raise ValueError(f"Symlinks are not accepted: {candidate}")
                if candidate.is_file() and candidate.suffix.lower() in SOURCE_EXTENSIONS:
                    sources.add(candidate.resolve())
        elif path.suffix.lower() in SOURCE_EXTENSIONS:
            sources.add(path)
    if not sources:
        raise ValueError("No .fmb, .mmb, or .olb files were found.")
    return sorted(sources, key=lambda item: str(item).lower())


def command_for(tool: Path, arguments: list[str]) -> list[str] | str:
    if os.name == "nt" and tool.suffix.lower() in {".bat", ".cmd"}:
        values = [str(tool), *arguments]
        if any('"' in value for value in values):
            raise ValueError('Oracle tool paths and arguments must not contain a double quote (").')
        quoted = " ".join(f'"{value}"' for value in values)
        return f'cmd.exe /d /s /c "{quoted}"'
    return [str(tool), *arguments]


def run_tool(tool: Path, arguments: list[str], log_path: Path) -> int:
    completed = subprocess.run(
        command_for(tool, arguments),
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )
    log_path.write_text(
        completed.stdout + completed.stderr,
        encoding="utf-8",
        errors="replace",
    )
    return completed.returncode


def main() -> int:
    args = parse_args()
    converter = resolve_tool(args.converter_path, "frmf2xml")
    if not converter:
        if platform.system() == "Darwin":
            raise SystemExit(
                "Oracle Forms2XML was not found. Native macOS Forms installation is not "
                "documented; use preconverted XML/PLD or an approved Windows/Linux worker."
            )
        raise SystemExit(
            "Oracle Forms2XML was not found. Run preflight.py and configure Oracle Forms Builder."
        )
    validator = resolve_tool(args.validator_path, "frmxmlv", sibling=converter)

    output_dir = args.output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    log_dir = output_dir / "_logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    sources = collect_sources(args.input)

    manifest: list[dict[str, object]] = []
    for source in sources:
        extension_name = source.suffix[1:].lower()
        expected_xml = output_dir / f"{source.stem}_{extension_name}.xml"
        conversion_log = log_dir / f"{source.stem}_{extension_name}.conversion.log"
        arguments = [
            f"DUMP={args.dump}",
            "OVERWRITE=YES",
            f"OUTPUTDIR={output_dir}",
            str(source),
        ]
        conversion_exit = run_tool(converter, arguments, conversion_log)
        if conversion_exit != 0 or not expected_xml.is_file():
            raise SystemExit(f"Conversion failed for {source}. See {conversion_log}")

        try:
            ET.parse(expected_xml)
        except ET.ParseError as exc:
            raise SystemExit(f"Generated XML is malformed: {expected_xml}: {exc}") from exc

        validation_exit: int | None = None
        validation_log: Path | None = None
        if validator:
            validation_log = log_dir / f"{source.stem}_{extension_name}.validation.log"
            validation_exit = run_tool(validator, [str(expected_xml)], validation_log)
            if validation_exit != 0:
                raise SystemExit(
                    f"Oracle Forms XML validation failed for {expected_xml}. See {validation_log}"
                )

        manifest.append(
            {
                "source": str(source),
                "source_sha256": sha256(source),
                "xml": str(expected_xml),
                "xml_sha256": sha256(expected_xml),
                "converter": str(converter),
                "conversion_exit_code": conversion_exit,
                "validator": str(validator) if validator else None,
                "validation_exit_code": validation_exit,
                "validation_log": str(validation_log) if validation_log else None,
                "dump": args.dump,
            }
        )

    manifest_path = output_dir / "conversion-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({"manifest": str(manifest_path), "files": len(manifest)}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
