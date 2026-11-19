"""Fresh source-bound whole duplicate-record plans over rendered relations.

This planner preserves originals and grants no runtime or execution authority.
The integration caller must rebuild it immediately before native rendering.
"""
from __future__ import annotations

from copy import deepcopy
import io
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

from .forms_understanding_packet import _build
from .forms_behavior_plan import _source_objects
from .forms_assignment_plan import _proven_relations
from .forms_relation_plan import build_relation_plan
from forms2apex import native_relations
from forms2apex.record_buffer import SCOPE, derive_buffer_operations, validate_buffer_plan
from forms2apex.native_assignments import _canonical, _sha


def build_buffer_plan(documents, parent_zip):
    """Rebuild complete trigger/formula/helper and direct native context proofs."""
    packet, chunks = _build(documents)
    objects, metadata = _source_objects(documents, packet)
    raw = parent_zip if type(parent_zip) is bytes else Path(parent_zip).read_bytes()
    if not 0 < len(raw) <= 32 * 1024 * 1024:
        raise ValueError("BUFFER_PARENT_SIZE")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if (len(infos) > 4096 or len(names) != len({name.casefold() for name in names})
                    or sum(info.file_size for info in infos) > 64 * 1024 * 1024):
                raise ValueError("BUFFER_PARENT_MEMBERS")
            for info in infos:
                path = PurePosixPath(info.filename)
                if (path.is_absolute() or ".." in path.parts or "\\" in info.filename or ":" in info.filename
                        or stat.S_ISLNK(info.external_attr >> 16) or info.filename.startswith("fox-package/buffer-")):
                    raise ValueError("BUFFER_PARENT_PATH_OR_ALREADY_ADAPTED")
            files = {info.filename: archive.read(info) for info in infos}
        manifest, trace, blocks, targets = native_relations._targets(files)
        if "fox-package/relation-plan.json" in files:
            relation_plan = native_relations._read_json(files["fox-package/relation-plan.json"])
            relation_receipt = native_relations._read_json(files.get("fox-package/relation-receipt.json", b"{}"))
        else:
            relation_plan = build_relation_plan(documents, raw)
            if relation_plan["operations"]:
                raise ValueError("BUFFER_REQUIRED_RELATION_NOT_RENDERED")
            relation_receipt = {}
    except (zipfile.BadZipFile, KeyError, UnicodeError, OSError, RuntimeError):
        raise ValueError("BUFFER_PARENT_PROOF_MISSING") from None
    sources = [{key: entry["source"][key] for key in ("name", "sha256", "bytes")} for entry in packet["sources"]]
    if (manifest.get("source_binding") != packet["source_binding"] or manifest.get("files") != sources
            or trace.get("source_binding") != packet["source_binding"]):
        raise ValueError("BUFFER_PARENT_SOURCE_BINDING")
    native_relations._originals(files, sources)
    for name, source in documents:
        if files.get("fox-package/sources/" + name) != source:
            raise ValueError("BUFFER_ORIGINAL_SOURCE_CHANGED")
    available = {chunk["id"]: chunk["sha256"] for chunk in chunks}
    selected = manifest.get("selected_chunk_hashes")
    if type(selected) is not dict or any(available.get(key) != value for key, value in selected.items()):
        raise ValueError("BUFFER_SOURCE_CHUNK_BINDING")
    # Source-derived relation verification includes ambiguity/cycle checks over
    # all declarations, even declarations omitted from the supplied parent plan.
    _proven_relations(relation_plan, packet, objects, metadata, trace)
    for block_id, block in blocks.items():
        obj = objects.get(block_id)
        if (obj is None or obj["kind"] != "Block" or obj["module_id"] != block.get("source_module_id")
                or obj["name"] != block.get("name")):
            raise ValueError("BUFFER_PARENT_BLOCK_BINDING")
        for field in block["items"]:
            item = objects.get(field["source_item_id"])
            if (item is None or item["kind"] != "Item" or item["block_id"] != block_id
                    or item["name"] != field["source_name"]):
                raise ValueError("BUFFER_PARENT_FIELD_BINDING")
    chunk_by_unit = {chunk["code_unit_id"]: chunk for chunk in chunks}
    catalog = {"objects": [], "units": []}
    for obj in sorted(objects.values(), key=lambda row: row["id"]):
        row = {key: deepcopy(obj.get(key)) for key in ("id", "kind", "name", "module_id", "block_id", "parent_id",
                                                      "classification", "database_item")}
        row["metadata"] = deepcopy(metadata[obj["id"]])
        catalog["objects"].append(row)
    for entry in packet["sources"]:
        for unit in entry["facts"]["code_units"]:
            catalog["units"].append({**{key: deepcopy(unit[key]) for key in
                ("id", "owner_id", "source_attribute", "sha256", "location")},
                "chunk_id": chunk_by_unit[unit["id"]]["id"], "text": chunk_by_unit[unit["id"]]["text"]})
    operations, coverage = derive_buffer_operations(catalog, trace, packet["source_binding"], relation_plan, relation_receipt)
    schema = files["fox-package/supporting-schema.sql"].decode()
    for operation in operations:
        proofs = [operation, operation["formula"], operation["helper"]]
        if any(proof["source_chunk_id"] not in selected for proof in proofs):
            raise ValueError("BUFFER_PIPELINE_SOURCE_NOT_SELECTED")
        for binding in operation["key_bindings"]:
            block = blocks[binding["source_block_id"]]
            declaration = re.findall(r"\bCREATE TABLE " + re.escape(block["table_name"]) + r" \(\s*(.*?)\n\);", schema, re.S)
            lengths = re.findall(r"\b" + re.escape(binding["column"]) + r"\s+VARCHAR2\(([0-9]+)\)", declaration[0])
            if lengths != [str(binding["max_length"])]:
                raise ValueError("BUFFER_NATIVE_KEY_LENGTH_BINDING")
        relation = operation["relation"]
        page = files.get(relation["page_file"], b"").decode()
        if (not page.startswith(f"page {relation['page_id']} (\n")
                or page.count("pageItem " + relation["parent_item"] + " (") != 1):
            raise ValueError("BUFFER_NATIVE_RELATION_PAGE_BINDING")
        for binding in (operation["control_key"], operation["summary"]):
            page = files.get(binding["native_page_file"], b"").decode()
            if (not page.startswith(f"page {binding['native_page_id']} (\n")
                    or page.count("pageItem " + binding["native_item"] + " (") != 1):
                raise ValueError("BUFFER_NATIVE_CONTROL_PAGE_BINDING")
    plan = {"schema_version": 1, "scope": SCOPE, "source_binding": packet["source_binding"],
            "parent_zip_sha256": _sha(raw), "source_manifest_sha256": _sha(files[native_relations.MANIFEST]),
            "parent_trace_sha256": _sha(files[native_relations.TRACE]), "trace_sha256": _sha(_canonical(trace)),
            "relation_plan_sha256": _sha(_canonical(relation_plan)),
            "relation_receipt_sha256": _sha(_canonical(relation_receipt)),
            "sources": sources, "source_catalog": catalog, "parent_trace": trace,
            "relation_plan": relation_plan, "relation_receipt": relation_receipt,
            "operations": operations, "coverage": coverage, "code_unit_count": len(coverage),
            "native_generated": False, "event_activated": False, "runtime_verified": False, "business_accepted": False}
    plan["plan_sha256"] = _sha(_canonical(plan))
    return validate_buffer_plan(plan)
