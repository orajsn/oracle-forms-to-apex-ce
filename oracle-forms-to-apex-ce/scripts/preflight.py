#!/usr/bin/env python3
"""Cross-platform prerequisite check for the Forms-to-APEX CE skill."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable


VALID_STATUSES = {"REUSE", "MISSING", "INCOMPATIBLE", "BLOCKED", "NOT_REQUIRED"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("check", "assess", "poc", "export"), default="check")
    parser.add_argument("--forms-home", type=Path)
    parser.add_argument("--forms-instance-home", type=Path)
    parser.add_argument("--sqlcl-path", type=Path)
    parser.add_argument("--apex-url", default="http://localhost:8181/ords/apex")
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--json", action="store_true", dest="as_json")
    return parser.parse_args()


def add_result(
    results: list[dict[str, str]],
    component: str,
    status: str,
    evidence: str,
    action: str,
) -> None:
    if status not in VALID_STATUSES:
        raise ValueError(f"Unsupported status: {status}")
    results.append(
        {
            "component": component,
            "status": status,
            "evidence": evidence,
            "action": action,
        }
    )


def first_existing(candidates: Iterable[Path | None]) -> Path | None:
    for candidate in candidates:
        if candidate and candidate.expanduser().is_file():
            return candidate.expanduser().resolve()
    return None


def find_command(names: Iterable[str], candidates: Iterable[Path | None] = ()) -> Path | None:
    explicit = first_existing(candidates)
    if explicit:
        return explicit
    for name in names:
        found = shutil.which(name)
        if found:
            return Path(found).resolve()
    return None


def first_line(command: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            [str(command), *arguments],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=15,
            check=False,
        )
    except OSError as exc:
        return str(exc)
    output = (completed.stdout + "\n" + completed.stderr).strip().splitlines()
    return output[0] if output else f"exit={completed.returncode}"


def physical_memory_bytes() -> int | None:
    if os.name == "nt":
        class MemoryStatus(ctypes.Structure):
            _fields_ = [
                ("length", ctypes.c_ulong),
                ("memory_load", ctypes.c_ulong),
                ("total_physical", ctypes.c_ulonglong),
                ("available_physical", ctypes.c_ulonglong),
                ("total_page_file", ctypes.c_ulonglong),
                ("available_page_file", ctypes.c_ulonglong),
                ("total_virtual", ctypes.c_ulonglong),
                ("available_virtual", ctypes.c_ulonglong),
                ("available_extended_virtual", ctypes.c_ulonglong),
            ]

        status = MemoryStatus()
        status.length = ctypes.sizeof(MemoryStatus)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return int(status.total_physical)
        return None
    try:
        return int(os.sysconf("SC_PAGE_SIZE")) * int(os.sysconf("SC_PHYS_PAGES"))
    except (AttributeError, OSError, ValueError):
        return None


def forms_candidates(args: argparse.Namespace) -> tuple[list[Path], tuple[str, ...]]:
    windows = os.name == "nt"
    names = ("frmf2xml.bat", "frmf2xml") if windows else ("frmf2xml", "frmf2xml.sh")
    homes: list[Path] = []
    for value in (args.forms_home, args.forms_instance_home):
        if value:
            homes.append(value.expanduser())
    if os.environ.get("ORACLE_HOME"):
        homes.append(Path(os.environ["ORACLE_HOME"]).expanduser())
    if windows:
        homes.append(Path("C:/Oracle/Middleware/FormsBuilderInstance"))

    candidates: list[Path] = []
    for home in homes:
        for name in names:
            candidates.extend((home / "bin" / name, home / "forms" / "bin" / name))
    return candidates, names


def find_sibling_tool(converter: Path, names: tuple[str, ...]) -> Path | None:
    return first_existing(converter.parent / name for name in names)


def print_table(results: list[dict[str, str]]) -> None:
    widths = {
        key: min(
            max(len(key.upper()), max((len(row[key]) for row in results), default=0)),
            limit,
        )
        for key, limit in (
            ("component", 30),
            ("status", 16),
            ("evidence", 70),
            ("action", 80),
        )
    }
    header = "  ".join(key.upper().ljust(widths[key]) for key in widths)
    print(header)
    print("  ".join("-" * widths[key] for key in widths))
    for row in results:
        print(
            "  ".join(
                row[key][: widths[key]].ljust(widths[key])
                for key in widths
            )
        )


def main() -> int:
    args = parse_args()
    results: list[dict[str, str]] = []
    host = f"{platform.system()} {platform.release()} ({platform.machine()})"
    add_result(
        results,
        "Host platform",
        "REUSE",
        host,
        "Use the platform route in references/compatibility-profile.md.",
    )

    python_ok = sys.version_info >= (3, 10)
    add_result(
        results,
        "Python",
        "REUSE" if python_ok else "INCOMPATIBLE",
        f"{Path(sys.executable).resolve()} - {platform.python_version()}",
        "Use Python 3.10 or newer for the portable skill core.",
    )

    memory = physical_memory_bytes()
    if memory is None:
        add_result(
            results,
            "System memory",
            "BLOCKED",
            "Physical memory could not be inspected",
            "Check physical RAM manually before installing Oracle Forms.",
        )
    else:
        memory_gb = memory / (1024**3)
        add_result(
            results,
            "System memory",
            "REUSE" if memory_gb >= 8 else "BLOCKED",
            f"{memory_gb:.1f} GB physical RAM",
            "Keep at least 8 GB physical RAM for the documented Forms installation baseline.",
        )

    try:
        usage = shutil.disk_usage(Path.cwd().anchor or Path.cwd())
        free_gb = usage.free / (1024**3)
        add_result(
            results,
            "System disk",
            "REUSE" if free_gb >= 20 else "BLOCKED",
            f"{free_gb:.1f} GB free",
            "Keep at least 20 GB free for a small local lab; larger cases need more.",
        )
    except OSError as exc:
        add_result(
            results,
            "System disk",
            "BLOCKED",
            str(exc),
            "Check free disk space manually.",
        )

    java = find_command(("java.exe", "java"))
    add_result(
        results,
        "Java",
        "REUSE" if java else "MISSING",
        f"{java} - {first_line(java, '-version')}" if java else "java was not found on PATH",
        "Use a certified Java release; SQLcl and ORDS support Java 17 or 21.",
    )

    podman = find_command(("podman.exe", "podman"))
    add_result(
        results,
        "Podman",
        "REUSE" if podman else "NOT_REQUIRED",
        f"{podman} - {first_line(podman, '--version')}" if podman else "podman was not found",
        "Use Podman only when the selected local database approach requires it.",
    )
    if podman:
        try:
            completed = subprocess.run(
                [str(podman), "ps", "--format", "{{.Names}}|{{.Status}}"],
                capture_output=True,
                text=True,
                errors="replace",
                timeout=15,
                check=False,
            )
            matches = [
                line
                for line in completed.stdout.splitlines()
                if any(token in line.lower() for token in ("oracle", "database", "free"))
            ]
            add_result(
                results,
                "Oracle Database container",
                "REUSE" if matches else "MISSING",
                "; ".join(matches) if matches else "No running Oracle database container detected",
                "Verify database version and PDB, or use an approved local/OCI APEX target.",
            )
        except (OSError, subprocess.SubprocessError) as exc:
            add_result(
                results,
                "Oracle Database container",
                "BLOCKED",
                str(exc),
                "Check the Podman machine and container status manually.",
            )

    candidates, converter_names = forms_candidates(args)
    converter = find_command(converter_names, candidates)
    if converter:
        validator_names = (
            ("frmxmlv.bat", "frmxmlv")
            if os.name == "nt"
            else ("frmxmlv", "frmxmlv.sh")
        )
        validator = find_sibling_tool(converter, validator_names) or find_command(validator_names)
        add_result(
            results,
            "Oracle Forms XML tools",
            "REUSE",
            f"frmf2xml={converter}; frmxmlv={validator or 'not found'}",
            "Reuse the configured Oracle Forms Builder installation.",
        )
    else:
        action = (
            "macOS has no documented native Forms installer; use preconverted XML/PLD "
            "or an approved Windows/Linux conversion worker."
            if platform.system() == "Darwin"
            else "Install and configure Oracle Forms Builder, or use preconverted XML/PLD."
        )
        add_result(
            results,
            "Oracle Forms XML tools",
            "MISSING",
            f"None of {', '.join(converter_names)} was found",
            action,
        )

    sql_candidates = [args.sqlcl_path]
    if os.name == "nt":
        sql_candidates.append(Path("C:/o/sqlcl/bin/sql.exe"))
    sqlcl = find_command(("sql.exe", "sql"), sql_candidates)
    add_result(
        results,
        "SQLcl",
        "REUSE" if sqlcl else "MISSING",
        f"{sqlcl} - {first_line(sqlcl, '-version')}" if sqlcl else "SQLcl was not found",
        "Install SQLcl compatible with the target APEX release.",
    )

    if args.apex_url:
        try:
            request = urllib.request.Request(args.apex_url, method="GET")
            with urllib.request.urlopen(request, timeout=args.timeout) as response:
                status = getattr(response, "status", 200)
            add_result(
                results,
                "APEX/ORDS HTTP",
                "REUSE",
                f"{args.apex_url} returned HTTP {status}",
                "Verify APEX and ORDS versions from the target environment.",
            )
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            add_result(
                results,
                "APEX/ORDS HTTP",
                "MISSING",
                f"{args.apex_url} - {exc}",
                "Start the approved APEX/ORDS target or pass its URL.",
            )

    payload = {
        "mode": args.mode,
        "host": host,
        "checks": results,
    }
    if args.as_json:
        print(json.dumps(payload, indent=2))
    else:
        print_table(results)
    return 0 if all(row["status"] not in {"INCOMPATIBLE", "BLOCKED"} for row in results) else 2


if __name__ == "__main__":
    raise SystemExit(main())
