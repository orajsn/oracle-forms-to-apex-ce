#!/usr/bin/env python3
"""Install the bundled Oracle Forms-to-APEX CE skill into Codex."""

from __future__ import annotations

import argparse
import hashlib
import os
import py_compile
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


SKILL_NAME = "oracle-forms-to-apex-ce"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        default=Path(__file__).resolve().parent / SKILL_NAME,
        help="Skill folder to install.",
    )
    parser.add_argument(
        "--codex-home",
        type=Path,
        help="Codex home directory. Defaults to CODEX_HOME or ~/.codex.",
    )
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_source(source: Path) -> list[Path]:
    if source.is_symlink() or not source.is_dir():
        raise ValueError(f"Skill source is not a normal directory: {source}")
    skill_file = source / "SKILL.md"
    if not skill_file.is_file():
        raise ValueError(f"Missing required file: {skill_file}")
    content = skill_file.read_text(encoding="utf-8")
    if not content.startswith("---\n") or f"name: {SKILL_NAME}" not in content:
        raise ValueError("SKILL.md frontmatter is missing or has the wrong skill name.")

    files: list[Path] = []
    for path in source.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"Symlinks are not accepted in the skill: {path}")
        if path.is_file():
            files.append(path)
    if not files:
        raise ValueError("The skill source is empty.")
    python_files = [path for path in files if path.suffix == ".py"]
    with tempfile.TemporaryDirectory(prefix="codex-skill-compile-") as temp_dir:
        for index, path in enumerate(python_files):
            compiled = Path(temp_dir) / f"{index}.pyc"
            py_compile.compile(str(path), cfile=str(compiled), doraise=True)
    return sorted(files, key=lambda item: str(item).lower())


def relative_hashes(root: Path, files: list[Path]) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): sha256(path)
        for path in files
        if "__pycache__" not in path.parts and path.suffix != ".pyc"
    }


def main() -> int:
    args = parse_args()
    source = args.source.expanduser().resolve(strict=True)
    source_files = validate_source(source)
    source_hashes = relative_hashes(source, source_files)

    codex_home = (
        args.codex_home
        or (Path(os.environ["CODEX_HOME"]) if os.environ.get("CODEX_HOME") else None)
        or Path.home() / ".codex"
    ).expanduser().resolve()
    skills_dir = codex_home / "skills"
    target = skills_dir / SKILL_NAME
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = skills_dir / ".backups" / f"{SKILL_NAME}-{timestamp}"
    staging = skills_dir / f".{SKILL_NAME}.install-{os.getpid()}"

    print(f"Source: {source}")
    print(f"Target: {target}")
    print(f"Files: {len(source_hashes)}")
    if args.dry_run:
        print("Dry run only; no files changed.")
        return 0

    skills_dir.mkdir(parents=True, exist_ok=True)
    if staging.exists():
        raise FileExistsError(f"Staging path already exists: {staging}")

    shutil.copytree(
        source,
        staging,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    staged_files = validate_source(staging)
    if relative_hashes(staging, staged_files) != source_hashes:
        shutil.rmtree(staging, ignore_errors=True)
        raise RuntimeError("Staged skill hashes do not match the source.")

    moved_existing = False
    try:
        if target.exists():
            backup.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(target), str(backup))
            moved_existing = True
        shutil.move(str(staging), str(target))
    except Exception:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        if moved_existing and backup.exists() and not target.exists():
            shutil.move(str(backup), str(target))
        raise

    installed_files = validate_source(target)
    if relative_hashes(target, installed_files) != source_hashes:
        raise RuntimeError("Installed skill hashes do not match the source.")

    print(f"Installed: {target}")
    if moved_existing:
        print(f"Previous version backed up to: {backup}")
    print("Restart Codex or start a new task to reload the updated skill.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
