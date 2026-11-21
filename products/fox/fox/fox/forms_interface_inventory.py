"""Source-bound interface/call-site register, without executing or emitting code.

Positions are zero-based Unicode offsets in decoded PL/SQL, with one-based
in-unit line/column. XML element lines are separate. This is a lexical register,
not a PL/SQL compiler, name resolver, privilege check or execution proof.
"""
from collections import Counter, defaultdict
from bisect import bisect_right
from copy import deepcopy
import csv
import hashlib
import io
import json
import re

from .forms_behavior_plan import decode_control_entities, UnsupportedBehavior, _source_objects
from .forms_discrepancies import build_dependency_evidence, FORMS_APIS, _PLSQL_SYNTAX
from .forms_facts import _BUILTIN


SCOPE = "fox-source-interface-register-v1"
_WORD = re.compile(r"[A-Za-z][A-Za-z0-9_$#]*")
_NUMBER = re.compile(r"(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?")
# Optional detailed metadata must not obstruct independently supported generation.
# Complete conservative references remain in discrepancy-evidence.json.
MAX_SCAN_CHARACTERS = 500_000
MAX_TOKENS = 50_000
MAX_RECORDS = 1_000
MAX_ARGUMENT_TOKENS = 2_048
MAX_ARGUMENTS = 64
MAX_ACTION_PATHS = 16
MAX_PATH_DEPTH = 16
MAX_NESTED_DECLARATIONS = 256
MAX_DETAIL_BYTES = 1_000_000
MAX_CSV_BYTES = 2_000_000
MAX_CSV_ROWS = 5_000
_PLATFORM = (_BUILTIN - {"IF", "ELSIF", "WHILE", "LOOP", "VALUES", "IN", "SELECT", "CASE"}) | {
    "CEIL", "LPAD", "RPAD", "ABS", "MOD", "REPLACE", "LTRIM", "RTRIM", "INSTR", "CHR",
    "ASCII", "TRUNC", "FLOOR", "ADD_MONTHS", "LAST_DAY", "SYSDATE", "SYSTIMESTAMP"}
_SYNTAX = _PLSQL_SYNTAX | (_BUILTIN - _PLATFORM) | {
    "BEGIN", "END", "NULL", "RAISE", "EXCEPTION", "DECLARE", "PROCEDURE", "FUNCTION",
    "IS", "AS", "CURSOR", "OPEN", "CLOSE", "FETCH", "COMMIT", "ROLLBACK", "SAVEPOINT",
    "INTO", "UPDATE", "DELETE", "INSERT", "MERGE", "RETURNING", "USING", "SET", "OF",
    "EXIT", "CONTINUE", "GOTO", "PIPE"}


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _lex(text, token_budget=MAX_TOKENS):
    """Keep offsets and opaque literal tokens; never split an argument as text."""
    result, errors, i = [], [], 0
    while i < len(text):
        if len(result) >= token_budget:
            errors.append("token_limit")
            break
        start, char = i, text[i]
        if char.isspace():
            i += 1
            continue
        if text.startswith("--", i):
            while i < len(text) and text[i] not in "\r\n":
                i += 1
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end < 0:
                errors.append("unterminated_comment")
                break
            i = end + 2
            continue
        kind = None
        if char in "qQ" and text[i:i + 2].lower() == "q'" and i + 2 < len(text):
            delimiter = {"[": "]", "{": "}", "(": ")", "<": ">"}.get(text[i + 2], text[i + 2])
            end = text.find(delimiter + "'", i + 3)
            if end < 0:
                errors.append("unterminated_literal")
                break
            i, kind = end + 2, "literal"
        elif char in "'\"":
            quote = char
            i += 1
            while i < len(text):
                if text[i] == quote:
                    i += 1
                    if i < len(text) and text[i] == quote:
                        i += 1
                        continue
                    break
                i += 1
            else:
                errors.append("unterminated_literal_or_identifier")
            kind = "literal" if quote == "'" else "quoted"
        else:
            word = _WORD.match(text, i)
            number = _NUMBER.match(text, i)
            if word:
                i, kind = word.end(), "word"
            elif number:
                i, kind = number.end(), "number"
            else:
                i += 2 if text[i:i + 2] in {"=>", ":=", "||", "<=", ">=", "<>", "!="} else 1
                kind = "symbol"
        result.append((kind, text[start:i] if kind not in {"literal", "number"} else "", start, i))
    return result, errors


def _name(tokens, index):
    if index >= len(tokens) or tokens[index][0] not in {"word", "quoted"}:
        return None, index
    parts, end = [tokens[index][1]], index + 1
    while end + 1 < len(tokens) and tokens[end][1] in {".", "@"} and tokens[end + 1][0] in {"word", "quoted"}:
        parts.extend((tokens[end][1], tokens[end + 1][1]))
        end += 2
    return "".join(parts), end


class _Positions:
    def __init__(self, text):
        self.line_starts = [0] + [m.end() for m in re.finditer(r"\r\n|\r|\n", text)]


def _position(positions, start, end):
    line = bisect_right(positions.line_starts, start)
    return {"character_offset": start, "end_character_offset": end,
            "line": line, "column": start - positions.line_starts[line - 1] + 1}


def _arguments(tokens, opening):
    depth, start, parts = 0, opening + 1, []
    for index in range(opening + 1, min(len(tokens), opening + MAX_ARGUMENT_TOKENS)):
        value = tokens[index][1]
        if value == "(":
            depth += 1
        elif value == ")":
            if depth == 0:
                if index > start:
                    parts.append(tokens[start:index])
                elif parts:
                    return None, index, "empty_argument"
                return parts, index, None
            depth -= 1
        elif value == "," and depth == 0:
            if index == start:
                return None, index, "empty_argument"
            parts.append(tokens[start:index])
            if len(parts) >= MAX_ARGUMENTS:
                return None, index, "argument_limit"
            start = index + 1
        elif value == ";" and depth == 0:
            return None, index, "unclosed_argument_list"
    index = min(len(tokens) - 1, opening + MAX_ARGUMENT_TOKENS - 1)
    return None, index, "call_span_limit" if index < len(tokens) - 1 else "unclosed_argument_list"


def _nested_ranges(tokens, owner):
    """Named complete nested bodies only; anonymous/ambiguous scopes stay unknown."""
    found, declarations = [], 0
    for index, token in enumerate(tokens):
        if token[1].upper() not in {"PROCEDURE", "FUNCTION"} or index + 1 >= len(tokens):
            continue
        declarations += 1
        if declarations > MAX_NESTED_DECLARATIONS:
            break
        name = tokens[index + 1][1].upper()
        if owner["kind"] == "ProgramUnit" and index == 0 and name == (owner["name"] or "").upper():
            continue
        body = next((j for j in range(index + 2, len(tokens)) if tokens[j][1].upper() in {"IS", "AS", ";"}), None)
        if body is None or tokens[body][1] == ";":
            continue
        ending = next((j for j in range(body + 1, len(tokens) - 2)
                       if tokens[j][1].upper() == "END" and tokens[j + 1][1].upper() == name
                       and tokens[j + 2][1] == ";"), None)
        if ending is not None:
            found.append({"name": name, "start": token[2], "end": tokens[ending + 2][3]})
    return found


def _declared_type(metadata, item_id):
    value = metadata.get(item_id, {}).get("DataType")
    return value if isinstance(value, str) and value.upper() in {
        "CHAR", "VARCHAR2", "NUMBER", "DATE", "DATETIME", "TIME", "INTEGER", "LONG", "RAW",
        "CLOB", "BLOB", "BOOLEAN", "NCHAR", "NVARCHAR2", "TIMESTAMP"} else None


def _local_actual_types(tokens, nested_ranges, positions):
    """Unique scalar declarations before BEGIN, only without nested scopes."""
    if nested_ranges:
        return {}
    declarations = defaultdict(list)
    for index, token in enumerate(tokens):
        if token[1].upper() == "BEGIN":
            break
        if token[0] != "word" or index == 0 or tokens[index - 1][1].upper() not in {"DECLARE", "IS", "AS", ";", "(", ","}:
            continue
        cursor = index + 1
        while cursor < len(tokens) and tokens[cursor][1].upper() in {"IN", "OUT", "NOCOPY", "CONSTANT"}:
            cursor += 1
        if cursor < len(tokens) and tokens[cursor][1].upper() in {"CHAR", "VARCHAR2", "NUMBER", "DATE", "BOOLEAN", "PLS_INTEGER", "BINARY_INTEGER"}:
            if cursor + 1 < len(tokens) and tokens[cursor + 1][1] in {".", "%"}:
                continue
            declarations[token[1].upper()].append({"type": tokens[cursor][1],
                "declaration_position": _position(positions, token[2], tokens[cursor][3])})
    return {name: rows[0] for name, rows in declarations.items() if len(rows) == 1}


def _binds(tokens, owner, binding_index, metadata, text):
    result = []
    for index, token in enumerate(tokens):
        if token[1] != ":":
            continue
        name, end = _name(tokens, index + 1)
        if not name:
            continue
        parts = name.upper().split(".")
        kind, item, matches = "unresolved_bind", None, []
        if parts[0] in {"GLOBAL", "SYSTEM", "PARAMETER"}:
            kind = parts[0].lower() + "_bind"
        else:
            scope = owner["block_id"] if len(parts) == 1 else parts[0] if len(parts) == 2 else None
            matches = binding_index.get((owner["module_id"], scope, parts[-1]), [])
            if len(matches) == 1:
                kind, item = "forms_field", matches[0]
        result.append({"name": name, "kind": kind, "source_item_id": item["id"] if item else None,
            "source_declared_type": _declared_type(metadata, item["id"]) if item else None,
            "position": _position(text, token[2], tokens[end - 1][3]),
            "data_flow": "unknown", "limitation": None if item or kind != "unresolved_bind" else
                "No unique field identity is proved in this module and owner scope."})
    return result


def _argument_rows(parts, owner, objects, metadata, text, local_types):
    result = []
    for ordinal, part in enumerate(parts, 1):
        named = part[0][1] if len(part) > 1 and part[0][0] == "word" and part[1][1] == "=>" else None
        actual = part[2:] if named else part
        binds = _binds(actual, owner, objects, metadata, text)
        if len(actual) == 1 and actual[0][0] in {"literal", "number"}:
            kind = "character_literal" if actual[0][0] == "literal" else "numeric_literal"
        elif len(actual) == 1 and actual[0][1].upper() == "NULL":
            kind = "null_literal"
        elif (binds and actual[0][1] == ":" and len(binds) == 1
              and _name(actual, 1)[1] == len(actual)):
            kind = "direct_bind"
        elif len(actual) == 1 and actual[0][0] == "word" and actual[0][1].upper() in local_types:
            kind = "local_identifier"
        else:
            kind = "expression"
        type_evidence = local_types.get(actual[0][1].upper()) if kind == "local_identifier" else None
        result.append({"ordinal": ordinal, "named_parameter": named,
            "position": _position(text, part[0][2], part[-1][3]), "actual_kind": kind,
            "source_declared_type": binds[0]["source_declared_type"] if kind == "direct_bind" else type_evidence["type"] if type_evidence else None,
            "source_type_evidence": deepcopy(type_evidence),
            "binds": binds, "formal_parameter_direction": "unknown"})
    return result


def build_interface_inventory(packet, chunks, ledger, *, dependency_evidence=None, discrepancies=None, documents=None):
    """Build a deterministic additive register; leave ledger and source untouched."""
    fresh = build_dependency_evidence(packet, chunks, ledger)
    if dependency_evidence is not None and _canonical(fresh) != _canonical(dependency_evidence):
        raise ValueError("Interface inventory dependency evidence differs from fresh source.")
    objects, sources, units, metadata = {}, {}, {}, {}
    for entry in packet["sources"]:
        for obj in entry["facts"]["objects"]:
            objects[obj["id"]], sources[obj["id"]] = obj, entry["source"]
        units.update((u["id"], u) for u in entry["facts"]["code_units"])
    if documents is not None:
        from .forms_understanding_packet import _build
        source_packet, source_chunks = _build(documents)
        if (source_packet["source_binding"] != packet["source_binding"] or source_packet["sources"] != packet["sources"]
                or source_packet["chunks"] != packet["chunks"] or source_chunks != chunks):
            raise ValueError("Interface inventory documents differ from fresh source.")
        _, metadata = _source_objects(documents, source_packet)
    groups = {}
    if discrepancies is not None:
        if discrepancies.get("source_binding") != packet["source_binding"]:
            raise ValueError("Interface inventory discrepancy binding differs from source.")
        for group in discrepancies["dependencies"]:
            for occurrence in group["occurrences"]:
                groups[(occurrence["source_object_id"], group["name"].upper())] = group["id"]
    local = defaultdict(list)
    binding_index = defaultdict(list)
    by_owner = defaultdict(list)
    for uid, unit in units.items():
        by_owner[unit["owner_id"]].append(uid)
    for obj in objects.values():
        if obj["kind"] == "ProgramUnit" and obj["name"]:
            local[(obj["module_id"], obj["name"].upper())].append(obj["id"])
        elif obj["kind"] == "Item" and obj["name"]:
            binding_index[(obj["module_id"], obj["block_id"], obj["name"].upper())].append(obj)
            block_name = (objects.get(obj["block_id"], {}).get("name") or "").upper()
            binding_index[(obj["module_id"], block_name, obj["name"].upper())].append(obj)
    manifest = {u["source_unit_id"]: u for u in fresh["units"]}
    records, located, source_refs = [], set(), {}
    limits = Counter()
    budget = {"characters": 0, "tokens": 0, "detail_bytes": 0, "body_characters": 0, "body_tokens": 0}
    text_chunks = {c["code_unit_id"]: c for c in chunks}
    body_bindings = {}

    def source_ref(owner, unit=None):
        cache_key = (owner["id"], unit["id"] if unit else None)
        if cache_key in source_refs:
            return source_refs[cache_key]
        source = sources[owner["id"]]
        chain, current = [], owner
        while current:
            chain.append({"id": current["id"], "kind": current["kind"], "name": current["name"]})
            current = objects.get(current["parent_id"])
        result = {"file": source["name"], "file_sha256": source["sha256"], "module_id": owner["module_id"],
            "module_name": objects.get(owner["module_id"], {}).get("name"),
            "owner_id": owner["id"], "owner_kind": owner["kind"], "owner_name": owner["name"],
            "owner_path": list(reversed(chain)), "xml_element_line": (unit or owner)["location"]["line"],
            "xml_path": (unit or owner)["location"]["path"], "source_unit_id": unit["id"] if unit else None,
            "source_unit_sha256": unit["sha256"] if unit else None,
            "source_attribute": unit["source_attribute"] if unit else None,
            "semantic_sha256": manifest[unit["id"]]["semantic_sha256"] if unit else None}
        source_refs[cache_key] = result
        return result

    def add(owner, unit, name, role, classification, *, position=None, arguments=None, limitation=None, nested=None):
        if len(records) >= MAX_RECORDS:
            limits["record_limit"] += 1
            return None
        row = {"name": name, "role": role, "classification": classification,
            "source": source_ref(owner, unit), "position": position,
            "dependency_group_id": groups.get((owner["id"], (name or "").upper())),
            "argument_count": len(arguments) if arguments is not None else None,
            "arguments": arguments, "lexical_enclosing_routine": nested,
            "bound_local_unit_id": None, "affected_actions": [], "data_flow": "unknown",
            "limitation": limitation, "runtime_verified": False, "business_behavior_accepted": False}
        row["id"] = "fir1-" + _sha(_canonical(row))[:24]
        row_bytes = len(_canonical(row))
        if budget["detail_bytes"] + row_bytes > MAX_DETAIL_BYTES:
            limits["detail_byte_limit"] += 1
            return None
        budget["detail_bytes"] += row_bytes
        records.append(row)
        located.add((unit["id"] if unit else None, (name or "").upper()))
        return row

    for chunk in chunks:
        uid, text = chunk["code_unit_id"], chunk["text"]
        unit, info = units[uid], manifest[uid]
        owner = objects[unit["owner_id"]]
        if budget["characters"] + len(text) > MAX_SCAN_CHARACTERS or budget["tokens"] >= MAX_TOKENS or len(records) >= MAX_RECORDS:
            limits["units_without_detail"] += 1
            continue
        if info["decoding"] != "decoded":
            add(owner, unit, None, "unresolved_source_unit", "unresolved", limitation=info["limitation"])
            continue
        semantic, _ = decode_control_entities(text)
        budget["characters"] += len(text)
        tokens, errors = _lex(semantic, MAX_TOKENS - budget["tokens"])
        budget["tokens"] += len(tokens)
        positions = _Positions(semantic)
        nested_ranges = _nested_ranges(tokens, owner)
        local_types = _local_actual_types(tokens, nested_ranges, positions)
        if sum(t[1].upper() in {"FUNCTION", "PROCEDURE"} for t in tokens) > MAX_NESTED_DECLARATIONS:
            limits["nested_declaration_limit_units"] += 1
        for error in errors:
            if error.endswith("limit"):
                limits[error] += 1
            add(owner, unit, None, "unresolved_syntax", "unresolved", limitation=error)
        database_starts = set()
        # Static target scanning is token-based, preserving full qualified names.
        for index, token in enumerate(tokens):
            word, target, role = token[1].upper(), index + 1, None
            previous = tokens[index - 1][1].upper() if index else None
            if word in {"FROM", "JOIN"}:
                role = "delete" if word == "FROM" and previous == "DELETE" else "read"
            elif (word == "DELETE" and previous in {None, ";", "BEGIN", "THEN", "ELSE", "LOOP"}
                  and target < len(tokens) and tokens[target][1].upper() != "FROM"):
                # Oracle permits DELETE table WHERE ... without FROM. A
                # collection's .DELETE method is a different operation.
                role = "delete"
            elif word == "UPDATE" and previous != "FOR":
                role = "update"
            elif word in {"INSERT", "MERGE"} and target < len(tokens) and tokens[target][1].upper() == "INTO":
                role, target = word.lower(), target + 1
            elif word == "USING":
                statement_start = next((j + 1 for j in range(index - 1, -1, -1) if tokens[j][1] == ";"), 0)
                if any(t[1].upper() == "MERGE" for t in tokens[statement_start:index]):
                    role = "read"
            if not role:
                continue
            name, end = _name(tokens, target)
            if name is None:
                add(owner, unit, None, "unresolved_sql_target", "unresolved",
                    position=_position(positions, token[2], token[3]),
                    limitation="SQL target is a subquery, dynamic or unavailable; no whole static object is proved.")
                continue
            if name.upper() in _SYNTAX:
                continue
            names = [(name, target, end)]
            # FROM A [alias], B [alias] only. Parenthesized subqueries are not flattened.
            if word == "FROM" and role == "read":
                cursor = end
                while cursor < len(tokens):
                    if tokens[cursor][1].upper() == "AS":
                        cursor += 1
                    if cursor + 1 < len(tokens) and tokens[cursor][0] == "word" and tokens[cursor + 1][1] == ",":
                        cursor += 1
                    if cursor >= len(tokens) or tokens[cursor][1] != ",":
                        break
                    next_name, following = _name(tokens, cursor + 1)
                    if not next_name:
                        break
                    names.append((next_name, cursor + 1, following))
                    cursor = following
            for name, start, end in names:
                database_starts.add(start)
                nested = next((r["name"] for r in reversed(nested_ranges) if r["start"] <= tokens[start][2] < r["end"]), None)
                add(owner, unit, name, role, "oracle_platform_object" if name.upper() in {"DUAL", "SYS.DUAL"} else "database_object_to_verify",
                    position=_position(positions, tokens[start][2], tokens[end - 1][3]), nested=nested,
                    limitation="Quoted identifier or database link needs authoritative name resolution." if '"' in name or "@" in name else None)
        for index, token in enumerate(tokens):
            if len(records) >= MAX_RECORDS:
                limits["units_with_record_limit"] += 1
                break
            if token[0] not in {"word", "quoted"} or (index and tokens[index - 1][1] in {".", "@", ":"}):
                continue
            name, end = _name(tokens, index)
            upper = name.upper()
            previous = tokens[index - 1][1].upper() if index else None
            if index in database_starts or previous in {"PROCEDURE", "FUNCTION", "END"} or upper in _SYNTAX:
                continue
            paren = end < len(tokens) and tokens[end][1] == "("
            bare = (end < len(tokens) and tokens[end][1] == ";" and
                    (index == 0 or previous in {";", "BEGIN", "THEN", "ELSE", "LOOP"}))
            if not paren and not bare:
                continue
            scopes = [r for r in nested_ranges if r["start"] <= token[2] < r["end"]]
            enclosing = scopes[-1]["name"] if scopes else None
            nested = [r for r in nested_ranges if r["name"] == upper]
            definitions = local.get((owner["module_id"], upper), [])
            bound = None
            if nested:
                classification = "source_nested_routine"
                limitation = "Named nested body supplied in this unit; lexical scope/overload and execution remain unverified."
            elif len(definitions) == 1:
                classification = "source_program_unit"
                candidates = by_owner[definitions[0]]
                if len(candidates) == 1:
                    target = candidates[0]
                    if target not in body_bindings:
                        body_bindings[target] = False
                        raw = text_chunks[target]["text"]
                        if (budget["body_characters"] + len(raw) <= MAX_SCAN_CHARACTERS
                                and budget["body_tokens"] < MAX_TOKENS):
                            budget["body_characters"] += len(raw)
                            try:
                                body, _ = decode_control_entities(raw)
                                body_tokens, body_errors = _lex(body, MAX_TOKENS - budget["body_tokens"])
                                budget["body_tokens"] += len(body_tokens)
                                values = [t[1].upper() for t in body_tokens]
                                body_bindings[target] = (not body_errors and len(values) >= 7
                                    and values[:2] in (["PROCEDURE", upper], ["FUNCTION", upper])
                                    and any(v in values for v in {"IS", "AS"}) and "BEGIN" in values
                                    and (values[-2:] == ["END", ";"] or values[-3:] == ["END", upper, ";"]))
                            except UnsupportedBehavior:
                                pass
                        else:
                            limits["local_body_scan_limit"] += 1
                    if body_bindings[target]:
                        bound = target
                limitation = "Same-module ProgramUnit body bound lexically; compilation, branches and execution unverified." if bound else "Same-module registration supplied; no unique complete body is proved."
            elif upper in FORMS_APIS:
                classification, limitation = "forms_platform_api", "Known Forms name; local shadowing and target adaptation remain unverified."
            elif upper in _PLATFORM:
                classification, limitation = "oracle_platform_routine", "Known Oracle name; local shadowing and expression types remain unverified."
            else:
                classification = "qualified_routine_to_verify" if "." in name else "unresolved_routine_candidate"
                limitation = "Ownership, formal parameter directions/types, target availability and execution are unverified."
                if '"' in name or "@" in name:
                    limitation += " Quoted name or database link needs authoritative resolution."
            if paren:
                parts, closing, error = _arguments(tokens, end)
                args = None if parts is None else _argument_rows(parts, owner, binding_index, metadata, positions, local_types)
                if error:
                    limitation += " Argument mapping unavailable: " + error + "."
                    if error.endswith("limit"):
                        limits[error] += 1
                finish = tokens[closing][3]
            else:
                args, finish = [], tokens[end - 1][3]
            row = add(owner, unit, name, "routine_invocation", classification,
                position=_position(positions, token[2], finish), arguments=args, limitation=limitation, nested=enclosing)
            if row is not None:
                row["bound_local_unit_id"] = bound
        for index, token in enumerate(tokens):
            if token[1].upper() == "EXECUTE" and index + 1 < len(tokens) and tokens[index + 1][1].upper() == "IMMEDIATE":
                add(owner, unit, None, "dynamic_sql", "unresolved", position=_position(positions, token[2], tokens[index + 1][3]),
                    limitation="Dynamic SQL target and argument roles cannot be proved without execution; literal text is withheld.")

    # Preserve property/registration references and any lexical evidence we could
    # not locate (including fallback decoding); never fabricate a call position.
    for reference in fresh["references"]:
        ref = reference["evidence"]
        if reference["kind"] != "dependencies" or ref["kind"] not in {"database_object", "routine", "report"}:
            continue
        owner, name = objects[ref["source_id"]], ref["name"]
        candidates = [units[uid] for uid in by_owner[owner["id"]]
                      if units[uid]["location"] == ref["location"] and ref.get("evidence") == "code:" + units[uid]["source_attribute"]]
        if candidates and all((u["id"], name.upper()) in located for u in candidates):
            continue
        role = "report_registration" if ref["kind"] == "report" else "property_reference" if ref.get("evidence", "").startswith("property:") else "unlocated_reference"
        classification = "report_to_verify" if ref["kind"] == "report" else "database_object_to_verify" if ref["kind"] == "database_object" else "unresolved_routine_candidate"
        add(owner, candidates[0] if len(candidates) == 1 else None, name, role, classification,
            limitation="Original source evidence retained; exact static call position or operational role is not proved." if role == "unlocated_reference" else
                "Source registration/property only; definition, executable actions and target availability unverified.")

    # Reverse same-module, unique body-bound call edges. Paths are static source
    # relationships, never reachable/executed paths. Nested definitions do not
    # inherit the surrounding ProgramUnit's callers.
    incoming = defaultdict(list)
    for row in records:
        if row["bound_local_unit_id"] and not row["lexical_enclosing_routine"]:
            incoming[row["bound_local_unit_id"]].append(row)
    for row in records:
        uid = row["source"]["source_unit_id"]
        if not uid:
            continue
        direct = {"action": deepcopy(row["source"]), "via_call_site_ids": [],
            "unit_path": [uid], "relationship": "direct_source_reference"}
        action_bytes = len(_canonical(direct))
        if budget["detail_bytes"] + action_bytes > MAX_DETAIL_BYTES:
            limits["action_byte_limit"] += 1
            continue
        budget["detail_bytes"] += action_bytes
        row["affected_actions"].append(direct)
        if row["lexical_enclosing_routine"]:
            continue
        queue = [(uid, [], [uid])]
        while queue:
            current, sites, path = queue.pop(0)
            for caller in incoming[current]:
                parent = caller["source"]["source_unit_id"]
                if parent in path:
                    continue
                next_sites, next_path = [caller["id"]] + sites, [parent] + path
                action = {"action": deepcopy(caller["source"]), "via_call_site_ids": next_sites,
                    "unit_path": next_path, "relationship": "static_local_body_call_chain_execution_unproved"}
                action_bytes = len(_canonical(action))
                if budget["detail_bytes"] + action_bytes > MAX_DETAIL_BYTES:
                    limits["action_byte_limit"] += 1
                    queue = []
                    break
                budget["detail_bytes"] += action_bytes
                row["affected_actions"].append(action)
                if len(row["affected_actions"]) >= MAX_ACTION_PATHS:
                    row["limitation"] = (row["limitation"] or "") + " Static action path limit reached; additional paths may exist."
                    limits["records_with_path_limit"] += 1
                    queue = []
                    break
                if len(next_path) < MAX_PATH_DEPTH:
                    queue.append((parent, next_sites, next_path))
                elif incoming[parent]:
                    limits["records_with_path_depth_limit"] += 1
    retained_units = {r["source"]["source_unit_id"] for r in records}
    result = {"schema_version": 1, "scope": SCOPE, "source_binding": packet["source_binding"],
        "position_convention": "Zero-based Unicode offsets/end-exclusive in semantic decoded unit; one-based in-unit line/column; XML element line separate.",
        "interpretation_boundary": "Source references only. Ownership and formal directions remain unknown unless supplied source establishes them. Static helper paths do not prove executable reachability. No database/model calls or business acceptance.",
        "runtime_verified": False, "business_behavior_accepted": False,
        "complete_reference_index": "fox-package/discrepancy-evidence.json",
        "detail_coverage": {"complete": not limits, "limits_reached": dict(sorted(limits.items())),
            "scanned_characters": budget["characters"], "scanned_tokens": budget["tokens"],
            "maximum_records": MAX_RECORDS, "maximum_action_paths_per_record": MAX_ACTION_PATHS,
            "maximum_path_depth": MAX_PATH_DEPTH,
            "maximum_detail_bytes": MAX_DETAIL_BYTES,
            "boundary": "Limits apply only to optional per-site/argument/path detail. The complete conservative semantic reference index remains in discrepancy-evidence.json; omissions never indicate no interface."},
        "csv_export_limits": {"maximum_rows": MAX_CSV_ROWS, "maximum_bytes": MAX_CSV_BYTES,
            "boundary": "CSV includes a visible final omission row if an export limit is reached; JSON and the complete semantic reference index remain authoritative."},
        "source_units": deepcopy([u for u in fresh["units"] if u["source_unit_id"] in retained_units]),
        "records": records,
        "summary": {"records": len(records), "by_classification": dict(sorted(Counter(r["classification"] for r in records).items()))}}
    result["register_sha256"] = _sha(_canonical(result))
    return result


def validate_interface_inventory(register, packet, chunks, ledger, **kwargs):
    """Fresh-source validation, including omissions, positions and path tampering."""
    if _canonical(register) != _canonical(build_interface_inventory(packet, chunks, ledger, **kwargs)):
        raise ValueError("Interface register differs from fresh source-bound inventory.")
    return deepcopy(register)


def interface_inventory_csv(register):
    """Flat one-row-per-reference/action/argument, with formula-safe cells."""
    output = io.StringIO(newline="")
    fields = ["record_id", "name", "role", "classification", "file", "file_sha256", "module", "owner_kind", "owner",
        "xml_element_line", "source_unit_id", "source_unit_sha256", "in_unit_line", "in_unit_column", "character_offset",
        "argument_count", "argument_ordinal", "named_parameter", "actual_kind", "source_declared_type",
        "argument_line", "argument_column", "argument_character_offset", "bind_name", "bind_kind", "bind_source_item_id",
        "bind_source_declared_type", "bind_line", "bind_column", "bind_character_offset", "bind_data_flow",
        "formal_parameter_direction", "affected_owner", "affected_unit_id", "unit_path", "via_call_site_ids", "relationship", "limitation"]
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    written_bytes, written_rows = len(output.getvalue().encode("utf-8")), 0
    for row in register["records"]:
        source, position = row["source"], row["position"] or {}
        for action in row["affected_actions"] or [None]:
            argument_binds = [(arg, binding) for arg in row["arguments"] or [None]
                for binding in (arg["binds"] or [None] if arg else [None])]
            for arg, binding in argument_binds:
                cells = {"record_id": row["id"], "name": row["name"], "role": row["role"], "classification": row["classification"],
                    "file": source["file"], "file_sha256": source["file_sha256"], "module": source["module_name"],
                    "owner_kind": source["owner_kind"], "owner": source["owner_name"], "xml_element_line": source["xml_element_line"],
                    "source_unit_id": source["source_unit_id"], "source_unit_sha256": source["source_unit_sha256"],
                    "in_unit_line": position.get("line"), "in_unit_column": position.get("column"), "character_offset": position.get("character_offset"),
                    "argument_count": row["argument_count"], "argument_ordinal": arg["ordinal"] if arg else None,
                    "named_parameter": arg["named_parameter"] if arg else None, "actual_kind": arg["actual_kind"] if arg else None,
                    "source_declared_type": arg["source_declared_type"] if arg else None,
                    "argument_line": arg["position"]["line"] if arg else None,
                    "argument_column": arg["position"]["column"] if arg else None,
                    "argument_character_offset": arg["position"]["character_offset"] if arg else None,
                    "bind_name": binding["name"] if binding else None,
                    "bind_kind": binding["kind"] if binding else None,
                    "bind_source_item_id": binding["source_item_id"] if binding else None,
                    "bind_source_declared_type": binding["source_declared_type"] if binding else None,
                    "bind_line": binding["position"]["line"] if binding else None,
                    "bind_column": binding["position"]["column"] if binding else None,
                    "bind_character_offset": binding["position"]["character_offset"] if binding else None,
                    "bind_data_flow": binding["data_flow"] if binding else "unknown",
                    "formal_parameter_direction": arg["formal_parameter_direction"] if arg else "unknown",
                    "affected_owner": action["action"]["owner_name"] if action else None,
                    "affected_unit_id": action["action"]["source_unit_id"] if action else None,
                    "unit_path": " > ".join(action["unit_path"]) if action else None,
                    "via_call_site_ids": " > ".join(action["via_call_site_ids"]) if action else None,
                    "relationship": action["relationship"] if action else None, "limitation": row["limitation"]}
                safe = {key: "'" + value if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")) else value
                        for key, value in cells.items()}
                buffer = io.StringIO(newline="")
                csv.DictWriter(buffer, fieldnames=fields, lineterminator="\n").writerow(safe)
                encoded_size = len(buffer.getvalue().encode("utf-8"))
                if written_rows >= MAX_CSV_ROWS - 1 or written_bytes + encoded_size > MAX_CSV_BYTES - 512:
                    writer.writerow({"role": "csv_detail_omitted", "limitation":
                        "CSV export limit reached. Further rows omitted; inspect JSON and fox-package/discrepancy-evidence.json. No absence of interfaces is implied."})
                    return output.getvalue()
                output.write(buffer.getvalue())
                written_rows += 1
                written_bytes += encoded_size
    return output.getvalue()
