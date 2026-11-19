"""Fresh source-bound whole lookup plans. No original data source is queried."""
from __future__ import annotations

from copy import deepcopy
import io
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

from .forms_understanding_packet import _build
from .forms_behavior_plan import _source_objects
from forms2apex import native_relations
from forms2apex.native_assignments import _canonical, _sha
from forms2apex.source_lookup import SCOPE, derive_lookup_operations, validate_lookup_plan


def build_lookup_plan(documents, parent_zip):
    """Rebuild source catalog and bind exact retained XML/native trace/DDL bytes.

    Call after existing parent renderers, before catalog finalization. The native
    renderer must check the exact parent digest and rebind this source catalog.
    """
    packet, chunks = _build(documents)
    objects, metadata = _source_objects(documents, packet)
    raw = parent_zip if type(parent_zip) is bytes else Path(parent_zip).read_bytes()
    if not 0 < len(raw) <= 32 * 1024 * 1024:
        raise ValueError("LOOKUP_PARENT_SIZE")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if (len(infos) > 4096 or len(names) != len({n.casefold() for n in names})
                    or sum(i.file_size for i in infos) > 64 * 1024 * 1024):
                raise ValueError("LOOKUP_PARENT_MEMBERS")
            for info in infos:
                path = PurePosixPath(info.filename)
                if (path.is_absolute() or ".." in path.parts or "\\" in info.filename or ":" in info.filename
                        or stat.S_ISLNK(info.external_attr >> 16) or info.filename.startswith("fox-package/lookup-")):
                    raise ValueError("LOOKUP_PARENT_PATH_OR_ALREADY_ADAPTED")
            files = {info.filename: archive.read(info) for info in infos}
        manifest, trace, blocks, targets = native_relations._targets(files)
    except (zipfile.BadZipFile, KeyError, UnicodeError, OSError, RuntimeError):
        raise ValueError("LOOKUP_PARENT_PROOF_MISSING") from None
    sources = [{k: entry["source"][k] for k in ("name", "sha256", "bytes")} for entry in packet["sources"]]
    if (manifest.get("source_binding") != packet["source_binding"] or manifest.get("files") != sources
            or trace.get("source_binding") != packet["source_binding"]):
        raise ValueError("LOOKUP_PARENT_SOURCE_BINDING")
    native_relations._originals(files, sources)
    for name, source in documents:
        if files.get("fox-package/sources/" + name) != source:
            raise ValueError("LOOKUP_ORIGINAL_SOURCE_CHANGED")
    available = {c["id"]: c["sha256"] for c in chunks}
    selected = manifest.get("selected_chunk_hashes")
    if type(selected) is not dict or any(available.get(k) != v for k, v in selected.items()):
        raise ValueError("LOOKUP_SOURCE_CHUNK_BINDING")
    for block_id, block in blocks.items():
        obj = objects.get(block_id)
        if (obj is None or obj["kind"] != "Block" or obj["module_id"] != block.get("source_module_id") or obj["name"] != block.get("name")):
            raise ValueError("LOOKUP_PARENT_BLOCK_BINDING")
        for field in block["items"]:
            item = objects.get(field["source_item_id"])
            if (item is None or item["kind"] != "Item" or item["block_id"] != block_id or item["name"] != field["source_name"]):
                raise ValueError("LOOKUP_PARENT_FIELD_BINDING")
    chunks = {c["code_unit_id"]: c for c in chunks}
    catalog = {"objects": [], "units": []}
    for obj in sorted(objects.values(), key=lambda row: row["id"]):
        row = {key: deepcopy(obj.get(key)) for key in ("id", "kind", "name", "module_id", "block_id", "parent_id", "classification", "database_item")}
        row["metadata"] = deepcopy(metadata[obj["id"]])
        catalog["objects"].append(row)
    for entry in packet["sources"]:
        for unit in entry["facts"]["code_units"]:
            catalog["units"].append({**{key: deepcopy(unit[key]) for key in ("id", "owner_id", "source_attribute", "sha256", "location")},
                                     "chunk_id": chunks[unit["id"]]["id"], "text": chunks[unit["id"]]["text"]})
    operations, coverage = derive_lookup_operations(catalog, trace, packet["source_binding"])
    schema = files["fox-package/supporting-schema.sql"].decode()
    for op in operations:
        if op["source_chunk_id"] not in selected:
            raise ValueError("LOOKUP_SOURCE_NOT_SELECTED")
        table = op["target"]["table"]
        declaration = re.findall(r"\bCREATE TABLE " + re.escape(table) + r" \(\s*(.*?)\n\);", schema, re.S)
        if len(declaration) != 1:
            raise ValueError("LOOKUP_NATIVE_TABLE_BINDING")
        for binding in op["input_bindings"] + op["output_bindings"]:
            if binding["data_type"] == "VARCHAR2":
                lengths = re.findall(r"^\s*" + re.escape(binding["column"]) + r"\s+VARCHAR2\(([0-9]+)\)", declaration[0], re.M)
                if lengths != [str(binding["max_length"])]:
                    raise ValueError("LOOKUP_NATIVE_LENGTH_BINDING")
    plan = {"schema_version": 1, "scope": SCOPE, "source_binding": packet["source_binding"],
        "parent_zip_sha256": _sha(raw), "source_manifest_sha256": _sha(files[native_relations.MANIFEST]),
        "parent_trace_sha256": _sha(files[native_relations.TRACE]), "trace_sha256": _sha(_canonical(trace)),
        "source_catalog_sha256": _sha(_canonical(catalog)), "sources": sources, "source_catalog": catalog,
        "parent_trace": trace, "operations": operations, "coverage": coverage, "code_unit_count": len(coverage),
        "native_generated": False, "event_activated": False, "runtime_verified": False, "business_accepted": False}
    plan["plan_sha256"] = _sha(_canonical(plan))
    return validate_lookup_plan(plan)
