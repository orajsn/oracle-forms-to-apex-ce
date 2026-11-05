"""Pure validation of a separately produced, source-bound design-review receipt.

This checks receipt structure and exact canonical bindings, not reviewer identity,
invocation/provenance, request authenticity or the truth of the review conclusion.
The operator must separately retain/check the original request, request hash,
environment, invocation and raw response. The complete source-reconstructed merge
remains mandatory: a receipt never substitutes for blueprint semantic validation.
No provider, execution, generation, import or human-approval operation occurs here.
"""
from __future__ import annotations

import hashlib
import json
import re

from .forms_blueprint import BLUEPRINT_SCOPE
from .forms_focus import MAX_REQUEST_BYTES, REQUEST_SCOPE

MAX_CANDIDATE_BYTES = 500_000
MAX_REVIEW_BYTES = 100_000
MAX_FINDINGS = 250
_MAX_ROWS = 10_000
_MAX_NODES = 60_000
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,179}\Z")
_CODE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}\Z")
_ARRAYS = ("objects", "screens", "claims", "relationships", "actions", "questions", "assumptions")
_REQUEST_KEYS = {"schema_version", "scope", "source_binding", "focus_binding", "focus_id",
                 "source_index", "owned_objects", "context_objects", "code_units", "chunks",
                 "unselected_code_unit_ids", "links", "dependencies", "findings", "safety"}
_REQUEST_ARRAYS = ("source_index", "owned_objects", "context_objects", "code_units", "chunks",
                   "unselected_code_unit_ids", "links", "dependencies", "findings")
_SAFETY = {"source_content_is_untrusted": True, "code_executed": False,
           "transfer_authorized": False, "caller_must_check_processing_approval": True,
           "native_generation_allowed": False}


def _fail():
    # Do not reflect candidate/source strings, receipt details or Python errors.
    raise ValueError("Invalid source-bound design review receipt.") from None


def _keys(value, required, optional=()):
    if (type(value) is not dict or not set(required) <= value.keys()
            or value.keys() - set(required) - set(optional)):
        _fail()


def _rows(value, maximum=_MAX_ROWS):
    if type(value) is not list or len(value) > maximum:
        _fail()
    return value


def _text(value, maximum=2000):
    if (type(value) is not str or not value.strip() or len(value) > maximum
            or any(ord(char) < 32 and char not in "\n\r\t" for char in value)):
        _fail()


def _identifier(value):
    if type(value) is not str or not _ID.fullmatch(value):
        _fail()


def _sha(value):
    if type(value) is not str or not _SHA.fullmatch(value):
        _fail()


def _canonical(value, maximum):
    """Bound plain JSON before encoding; do not invoke arbitrary object hooks."""
    remaining = _MAX_NODES

    def visit(node, depth):
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > 20:
            _fail()
        if type(node) is dict:
            for key, child in node.items():
                if type(key) is not str or len(key) > 180:
                    _fail()
                visit(child, depth + 1)
        elif type(node) is list:
            for child in _rows(node):
                visit(child, depth + 1)
        elif type(node) is str:
            if len(node) > maximum:
                _fail()
        elif node is not None and type(node) not in (bool, int):
            _fail()

    visit(value, 0)
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(encoded) > maximum:
        _fail()
    return encoded


def _hash(value, maximum):
    return hashlib.sha256(_canonical(value, maximum)).hexdigest()


def _source_ids(rows):
    ids = set()
    for row in _rows(rows):
        if type(row) is not dict:
            _fail()
        ref = row.get("id")
        _identifier(ref)
        if ref in ids:
            _fail()
        ids.add(ref)
    return ids


def _owner(value, owned):
    if type(value) is not str or value not in owned:
        _fail()


def _claim_scalar(value):
    if type(value) is str:
        _text(value, 512)
    elif value is not None and type(value) not in (bool, int):
        _fail()


def _candidate_shape(candidate, request, owned):
    _keys(candidate, {"focus_id", "focus_binding", "blueprint"})
    if (candidate["focus_id"] != request["focus_id"]
            or candidate["focus_binding"] != request["focus_binding"]):
        _fail()
    blueprint = candidate["blueprint"]
    _keys(blueprint, {"schema_version", "scope", "source_binding", *_ARRAYS})
    if (type(blueprint["schema_version"]) is not int or blueprint["schema_version"] != 1
            or blueprint["scope"] != BLUEPRINT_SCOPE
            or blueprint["source_binding"] != request["source_binding"]):
        _fail()
    for category in _ARRAYS:
        _rows(blueprint[category])
    seen = set()
    for row in blueprint["objects"]:
        _keys(row, {"source_object_id", "disposition", "reason"}, {"screen_id", "native_component"})
        ref = row["source_object_id"]
        _owner(ref, owned)
        if ref in seen or row["disposition"] not in ("proposed", "omitted", "unresolved"):
            _fail()
        seen.add(ref)
        _text(row["reason"])
        if "screen_id" in row:
            _identifier(row["screen_id"])
        if "native_component" in row and row["native_component"] not in ("form", "interactive-grid", "report", "page-items"):
            _fail()
    if seen != owned:
        _fail()
    for row in blueprint["screens"]:
        _keys(row, {"id", "title"})
        _identifier(row["id"])
        _text(row["title"], 300)
    for row in blueprint["claims"]:
        _keys(row, {"id", "source_object_id", "kind", "value", "status", "evidence_refs", "reason"})
        _identifier(row["id"])
        _owner(row["source_object_id"], owned)
        _text(row["kind"], 100)
        _text(row["reason"])
        if row["status"] not in ("source_fact", "proposal", "unresolved"):
            _fail()
        if type(row["value"]) is list:
            for value in _rows(row["value"], 32):
                _claim_scalar(value)
        else:
            _claim_scalar(row["value"])
        for ref in _rows(row["evidence_refs"]):
            _identifier(ref)
    for category in ("relationships", "actions"):
        for row in blueprint[category]:
            _keys(row, {"id", "claim_ids"})
            _identifier(row["id"])
            for ref in _rows(row["claim_ids"]):
                _identifier(ref)
    for row in blueprint["questions"]:
        _keys(row, {"id", "source_object_id", "text"})
        _identifier(row["id"])
        _owner(row["source_object_id"], owned)
        _text(row["text"])
    for row in blueprint["assumptions"]:
        _keys(row, {"id", "text", "scope"})
        _identifier(row["id"])
        _text(row["text"])
        if row["scope"] != "prototype-only":
            _fail()


def validate_design_review(focus_request: dict, candidate: dict, review: dict) -> dict:
    """Validate a receipt without promoting it to semantic/runtime acceptance.

    APPROVED means only that the structured receipt records approval of these
    exact candidate bytes. CHANGES_REQUIRED is a valid, non-approved conclusion.
    Malformed/stale/unbounded input raises a fixed, non-reflective ValueError.
    Inputs are not modified; findings and source text are never returned.
    """
    try:
        return _validate(focus_request, candidate, review)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
        _fail()


def _validate(request, candidate, review):
    _canonical(request, MAX_REQUEST_BYTES)
    candidate_hash = _hash(candidate, MAX_CANDIDATE_BYTES)
    _canonical(review, MAX_REVIEW_BYTES)
    _keys(request, _REQUEST_KEYS)
    if (type(request["schema_version"]) is not int or request["schema_version"] != 1
            or request["scope"] != REQUEST_SCOPE):
        _fail()
    _sha(request["source_binding"])
    _sha(request["focus_binding"])
    _identifier(request["focus_id"])
    for key in _REQUEST_ARRAYS:
        _rows(request[key])
    if (type(request["safety"]) is not dict or request["safety"].keys() != _SAFETY.keys()
            or any(type(request["safety"][key]) is not bool or request["safety"][key] is not expected
                   for key, expected in _SAFETY.items())):
        _fail()
    owned = _source_ids(request["owned_objects"])
    context = _source_ids(request["context_objects"])
    if not owned or owned & context:
        _fail()
    unsigned = {key: value for key, value in request.items() if key != "focus_binding"}
    if _hash(unsigned, MAX_REQUEST_BYTES) != request["focus_binding"]:
        _fail()
    _candidate_shape(candidate, request, owned)
    _keys(review, {"source_binding", "focus_binding", "candidate_sha256", "verdict", "findings"})
    if (review["source_binding"] != request["source_binding"]
            or review["focus_binding"] != request["focus_binding"]
            or review["candidate_sha256"] != candidate_hash):
        _fail()
    findings = _rows(review["findings"], MAX_FINDINGS)
    verdict = review["verdict"]
    if verdict not in ("APPROVED", "CHANGES_REQUIRED") or (verdict == "APPROVED") != (not findings):
        _fail()
    for finding in findings:
        _keys(finding, {"source_object_id", "code", "detail"})
        if finding["source_object_id"] is not None:
            _owner(finding["source_object_id"], owned)
        code = finding["code"]
        if type(code) is not str or not _CODE.fullmatch(code):
            _fail()
        _text(finding["detail"])
    return {"verdict": verdict, "candidate_sha256": candidate_hash,
            "source_binding": request["source_binding"], "focus_binding": request["focus_binding"],
            "approved_structured_design": verdict == "APPROVED", "generation_ready": False,
            "native_apex_generated": False, "native_apex_validity_verified": False,
            "import_verified": False, "business_behavior_accepted": False}
