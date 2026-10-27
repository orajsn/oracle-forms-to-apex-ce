from __future__ import annotations

from collections import Counter
from pathlib import Path
import json
import hashlib
import re
import xml.etree.ElementTree as ET

from .security import assert_no_secrets


UNSUPPORTED_PATTERNS = {
    "host_command": re.compile(r"\bHOST\s*\(", re.I),
    "ole_or_activex": re.compile(r"\b(?:OLE2|OCX|ACTIVEX)\b", re.I),
    "webutil": re.compile(r"\bWEBUTIL\b", re.I),
    "dde": re.compile(r"\bDDE\.", re.I),
    "client_file_io": re.compile(r"\b(?:TEXT_IO|CLIENT_TEXT_IO|CLIENT_GET_FILE_NAME)\b", re.I),
    "run_product": re.compile(r"\bRUN_PRODUCT\s*\(", re.I),
    "external_call": re.compile(r"\b(?:UTL_HTTP|HTTPURITYPE|WEB\.SHOW_DOCUMENT)\b", re.I),
}


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _object_name(element: ET.Element) -> str | None:
    for key, value in element.attrib.items():
        if key.lower() in {"name", "label", "title"} and value.strip():
            return value.strip()
    return None


def inspect_intake(job_root: Path) -> dict:
    intake = job_root / "intake"
    if not intake.is_dir():
        raise FileNotFoundError("job intake directory is missing")
    manifest_path = intake / "manifest.json"
    if not manifest_path.is_file():
        raise FileNotFoundError("intake manifest.json is missing")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))

    modules: list[dict] = []
    exceptions: list[dict] = []
    dependencies: set[str] = set()
    totals: Counter[str] = Counter()
    source_bytes = 0

    for entry in manifest.get("files", []):
        relative = entry["packaged_name"]
        source = (intake / Path(relative)).resolve()
        if intake.resolve() not in source.parents or not source.is_file():
            raise ValueError(f"manifest path is missing or escaped intake: {relative}")
        raw = source.read_bytes()
        if hashlib.sha256(raw).hexdigest().lower() != str(entry.get("sha256", "")).lower():
            raise ValueError(f"source hash mismatch: {relative}")
        source_bytes += len(raw)
        if source_bytes > 300_000:
            raise ValueError("source exceeds the MVP model input limit; split into a smaller business flow")
        text = raw.decode("utf-8-sig", errors="strict")
        assert_no_secrets(text, relative)
        module = {
            "file": relative,
            "source_kind": entry.get("source_kind"),
            "sha256": entry.get("sha256"),
            "bytes": len(raw),
            "object_counts": {},
            "named_objects": {},
            "readable_source": text,
        }

        if source.suffix.lower() == ".xml":
            try:
                root = ET.fromstring(text)
            except ET.ParseError as exc:
                exceptions.append({"file": relative, "kind": "malformed_xml", "detail": str(exc)})
                modules.append(module)
                continue
            counts: Counter[str] = Counter()
            names: dict[str, list[str]] = {}
            for element in root.iter():
                kind = _local_name(element.tag)
                counts[kind] += 1
                name = _object_name(element)
                if name:
                    names.setdefault(kind, []).append(name)
            module["object_counts"] = dict(sorted(counts.items()))
            module["named_objects"] = {key: sorted(set(values))[:500] for key, values in sorted(names.items())}
            totals.update(counts)
        else:
            line_count = text.count("\n") + (1 if text else 0)
            module["object_counts"] = {"text_lines": line_count}
            totals["text_lines"] += line_count

        for kind, pattern in UNSUPPORTED_PATTERNS.items():
            if pattern.search(text):
                exceptions.append(
                    {
                        "file": relative,
                        "kind": kind,
                        "severity": "requires_manual_remediation",
                        "detail": "No safe automatic APEX equivalent is assumed.",
                    }
                )
        for match in re.finditer(r"(?i)\b(?:CALL|EXECUTE|RUN_PRODUCT)\s*\(?\s*['\"]?([A-Z][A-Z0-9_$#.]+)", text):
            dependencies.add(match.group(1))
        modules.append(module)

    return {
        "schema_version": 1,
        "job_id": manifest.get("job_id", job_root.name),
        "source_policy": manifest.get("source_policy"),
        "modules": modules,
        "totals": dict(sorted(totals.items())),
        "dependencies": sorted(dependencies),
        "remediation_items": exceptions,
        "automatic_conversion_policy": "Only explicitly mapped constructs may be generated; all others remain remediation items.",
    }
