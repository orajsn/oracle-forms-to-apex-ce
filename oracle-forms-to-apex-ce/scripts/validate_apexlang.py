#!/usr/bin/env python3
"""Validate an APEXlang project with Oracle SQLcl."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable


ERROR_MARKER = re.compile(
    r"(?i)(\b(error|failed|exception|severe|traceback|ioexception|"
    r"uncheckedioexception|warning)\b|unsupported input path type|"
    r"APEXLang Compile Errors)"
)
SUCCESS_MARKER = re.compile(r"(?i)\bValidation successful\b")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--sqlcl-path", type=Path)
    parser.add_argument("--log-path", type=Path)
    return parser.parse_args()


def first_existing(candidates: Iterable[Path | None]) -> Path | None:
    for candidate in candidates:
        if candidate and candidate.expanduser().is_file():
            return candidate.expanduser().resolve()
    return None


def resolve_sqlcl(explicit: Path | None) -> Path | None:
    candidates: list[Path | None] = [explicit]
    if os.name == "nt":
        candidates.append(Path("C:/o/sqlcl/bin/sql.exe"))
    found = first_existing(candidates)
    if found:
        return found
    for name in ("sql.exe", "sql"):
        command = shutil.which(name)
        if command:
            return Path(command).resolve()
    return None


def main() -> int:
    args = parse_args()
    input_path = args.input.expanduser().resolve(strict=True)
    if '"' in str(input_path):
        raise ValueError('APEXlang input path must not contain a double quote (").')
    sqlcl = resolve_sqlcl(args.sqlcl_path)
    if not sqlcl:
        raise FileNotFoundError(
            "SQLcl was not found. Run preflight.py or pass --sqlcl-path."
        )
    log_path = (
        args.log_path.expanduser().resolve()
        if args.log_path
        else input_path.parent / "apexlang-validation.log"
    )
    log_path.parent.mkdir(parents=True, exist_ok=True)

    script_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="ascii",
            suffix=".sql",
            prefix="validate-apexlang-",
            delete=False,
        ) as handle:
            handle.write(f'apex validate -input "{input_path}"\n')
            handle.write("exit\n")
            script_path = Path(handle.name)

        completed = subprocess.run(
            [str(sqlcl), "/nolog", f"@{script_path}"],
            input="",
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
        output = completed.stdout + completed.stderr
        log_path.write_text(output, encoding="utf-8")
        if completed.returncode != 0:
            raise RuntimeError(
                f"APEXlang validation failed with exit code {completed.returncode}. "
                f"See {log_path}"
            )
        if ERROR_MARKER.search(output):
            raise RuntimeError(
                f"APEXlang validation output contains an error marker. Review {log_path}"
            )
        if not SUCCESS_MARKER.search(output):
            raise RuntimeError(
                f"SQLcl did not report 'Validation successful'. Review {log_path}"
            )
        print(f"APEXlang validation completed successfully. Log: {log_path}")
        return 0
    finally:
        if script_path:
            script_path.unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
