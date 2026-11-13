"""Pure, source-bound evidence packets, not a model-transfer authorization.

The orchestrator must independently validate a fresh approved external-processing
receipt before invoking any provider. Selecting content here grants neither user
legal permission nor provider authorization. No filesystem, network, execution,
generation gate or Oracle operation is performed by this module.
"""
from __future__ import annotations

import hashlib
import json

from . import forms_facts

MAX_FILES = 4
MAX_TOTAL_SOURCE_BYTES = MAX_FILES * forms_facts.MAX_FILE_BYTES
MAX_REQUEST_BYTES = 500_000
SCOPE = "fox-forms-understanding-packet-v1"


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _build(documents: list[tuple[str, bytes]]) -> tuple[dict, list[dict]]:
    from .prototype_read_scope import current_read_root, optional_document_build
    root = current_read_root()
    if root is None or type(documents) is not list or not 1 <= len(documents) <= MAX_FILES:
        return _build_uncached(documents)
    # Copy the container; every accepted key component is a plain immutable
    # value. Subclasses/malformed inputs retain the original uncached behavior.
    snapshot = list(documents)
    if any(type(row) is not tuple or len(row) != 2 or type(row[0]) is not str
           or len(row[0]) > 180 or type(row[1]) is not bytes
           or not 0 < len(row[1]) <= forms_facts.MAX_FILE_BYTES for row in snapshot):
        return _build_uncached(documents)
    if sum(len(raw) for _, raw in snapshot) > MAX_TOTAL_SOURCE_BYTES:
        return _build_uncached(documents)
    identity = tuple((name, len(raw), _hash(raw)) for name, raw in snapshot)
    return optional_document_build(root, identity, lambda: _build_uncached(snapshot))


def _build_uncached(documents: list[tuple[str, bytes]]) -> tuple[dict, list[dict]]:
    if not isinstance(documents, list) or not 1 <= len(documents) <= MAX_FILES:
        raise ValueError("Supply between 1 and 4 Forms XML documents.")
    names, digests, validated = set(), set(), []
    total_bytes = 0
    for document in documents:
        if not isinstance(document, tuple) or len(document) != 2:
            raise ValueError("Each document must be a filename and original bytes tuple.")
        name, raw = document
        # The facts assessor validates the exact name, original bytes, limits,
        # XML structure and credential suspicions. No caller-supplied facts enter.
        facts = forms_facts.assess_forms_xml(name, raw)
        folded = name.casefold()
        if folded in names:
            raise ValueError("Duplicate source filenames are not accepted.")
        names.add(folded)
        if facts["source"]["sha256"] in digests:
            raise ValueError("Duplicate source bytes are not accepted; retain one original source.")
        digests.add(facts["source"]["sha256"])
        total_bytes += len(raw)
        if total_bytes > MAX_TOTAL_SOURCE_BYTES:
            raise ValueError("Forms XML exceeds the total source-byte limit.")
        validated.append((name, raw, facts))

    sources, chunks = [], []
    for name, raw, facts in sorted(validated, key=lambda row: row[0]):
        sources.append({"source": dict(facts["source"]), "facts": facts})
        # Reuse the same safe parser and exact source coordinates as the facts
        # extractor. XML decoding (including entities, CRLF and attributes) must
        # match, not a regex/raw-source slice or a guessed SQL line range.
        root, locations = forms_facts._safe_input(name, raw)
        nodes = {location["path"]: (node, location)
                 for node, location in zip(root.iter(), locations, strict=True)}
        for unit in facts["code_units"]:
            match = nodes.get(unit["location"]["path"])
            if match is None or match[1] != unit["location"]:
                raise ValueError("Code-unit source location does not match fresh facts.")
            node = match[0]
            attribute = unit["source_attribute"]
            if attribute == "#text":
                text = node.text
            elif attribute.endswith(".text") and attribute[:-5] == forms_facts._local(node.tag):
                text = node.text
            else:
                text = node.get(attribute)
            if not isinstance(text, str):
                raise ValueError("Code-unit text is unavailable from the original XML.")
            encoded = text.encode("utf-8")
            if len(encoded) != unit["bytes"] or _hash(encoded) != unit["sha256"]:
                raise ValueError("Decoded code-unit hash does not match fresh facts.")
            # One indivisible chunk per complete decoded code unit. A caller may
            # select units, never approve an arbitrary substring or truncate one.
            chunk_id = "fup1-" + _hash(_canonical([name, facts["source"]["sha256"], unit["id"]]))
            chunks.append({"id": chunk_id, "source_sha256": facts["source"]["sha256"],
                           "code_unit_id": unit["id"], "sha256": unit["sha256"],
                           "bytes": len(encoded), "text": text})
    descriptors = [{key: value for key, value in chunk.items() if key != "text"}
                   for chunk in chunks]
    binding = _hash(_canonical({"sources": sources, "chunks": descriptors}))
    packet = {"schema_version": 1, "scope": SCOPE, "source_binding": binding,
              "sources": sources, "chunks": descriptors,
              "selectable_code_unit_ids": [chunk["code_unit_id"] for chunk in chunks],
              "transfer_authorized": False, "caller_must_check_processing_approval": True,
              "interpretation_boundary": "Source evidence only. Candidate dependencies remain candidates; no behavior, APEX conversion or transfer permission is established.",
              "safety": {"code_executed": False, "source_content_is_untrusted": True,
                         "model_submission_allowed": False, "native_generation_allowed": False}}
    return packet, chunks


def local_packet(documents: list[tuple[str, bytes]]) -> dict:
    """Inventory all sources without returning any code text or raw XML.

    Complete fresh facts and chunk descriptors support deliberate content review.
    There is no automatic selection, persisted approval or provider invocation.
    """
    packet, _chunks = _build(documents)
    packet["selection_status"] = "NOT_SELECTED"
    return packet


def approved_packet(documents: list[tuple[str, bytes]], *, expected_source_binding: str,
                    approved_chunk_hashes: dict[str, str]) -> dict:
    """Return only explicitly selected whole chunks and all source metadata.

    ``approved`` means scoped content selection only. The orchestrator must
    independently validate a fresh approved external-processing receipt before
    invoking any provider. This function grants no legal/provider authorization.
    An empty selection is an explicit metadata-only request, not permission to
    send metadata externally. The complete canonical JSON request must fit the
    byte budget; nothing is silently dropped or truncated. Local inventory has
    no provider-request cap. Large inventories need a deliberate focus/chunk
    strategy before transfer; a metadata-reduction strategy is not implemented.
    """
    packet, chunks = _build(documents)
    if not isinstance(expected_source_binding, str) or expected_source_binding != packet["source_binding"]:
        raise ValueError("Source binding is stale or does not match the original documents.")
    if not isinstance(approved_chunk_hashes, dict):
        raise ValueError("Select chunks using a chunk ID to complete SHA256 mapping.")
    available = {chunk["id"]: chunk for chunk in chunks}
    for chunk_id, expected_hash in approved_chunk_hashes.items():
        if not isinstance(chunk_id, str) or chunk_id not in available:
            raise ValueError("Selected chunk is unknown for this source binding.")
        if not isinstance(expected_hash, str) or expected_hash != available[chunk_id]["sha256"]:
            raise ValueError("Selected chunk hash must match the complete original code unit.")
    selected = [chunk for chunk in chunks if chunk["id"] in approved_chunk_hashes]
    packet["chunks"] = selected
    packet.pop("selectable_code_unit_ids")
    packet["selection_status"] = "SCOPED_CONTENT_SELECTED" if selected else "METADATA_ONLY"
    packet["selected_code_unit_ids"] = [chunk["code_unit_id"] for chunk in selected]
    packet["no_automatic_selection"] = True
    if len(_canonical(packet)) > MAX_REQUEST_BYTES:
        raise ValueError("Selected request exceeds the 500000-byte limit; reduce scope explicitly.")
    return packet
