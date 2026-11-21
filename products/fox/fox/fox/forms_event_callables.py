"""Translate complete scalar Forms triggers into explicit PL/SQL procedure contracts."""
from __future__ import annotations

from collections import defaultdict
import hashlib
import json
import re

from .forms_behavior_plan import UnsupportedBehavior, _source_objects, decode_control_entities
from .forms_interface_inventory import _lex

CODE_MEMBER = "fox-package/scalar-events.sql"
_WORD = r"[A-Z][A-Z0-9_$#]{0,127}"
_REF = rf": ({_WORD}(?: \. {_WORD})?)"
_ASSIGN = re.compile(_REF + rf" := (SYSDATE|: GLOBAL \. {_WORD}) ; ")
_LIMIT = re.compile(r"IF " + _REF + r" (>=|>|<=|<) ([0-9]{1,20}(?:\.[0-9]{1,10})?) THEN MESSAGE \( (L@[0-9]+) \) ; RAISE FORM_TRIGGER_FAILURE ; END IF ; ")
_STATUS = re.compile(r"IF : SYSTEM \. RECORD_STATUS = (L@[0-9]+) THEN ")
_CHAR = {"", "CHAR", "VARCHAR2"}


def _tokens(raw):
    decoded, _ = decode_control_entities(raw)
    tokens, errors = _lex(decoded, 256)
    if errors or any(t[0] == "quoted" for t in tokens):
        return "", {}
    words, literals = [], {}
    for kind, _, start, end in tokens:
        value = decoded[start:end]
        if kind == "literal":
            # Only small ordinary Oracle literals, safe in both PL/SQL and SQLcl scripts.
            if (not re.fullmatch(r"'(?:[^']|'')*'", value) or len(value.encode()) > 500
                    or any(ord(c) < 32 or c in "&`" for c in value)):
                return "", {}
            key = f"L@{len(literals)}"
            literals[key] = value
            words.append(key)
        elif kind == "symbol" and value not in {":", ".", ":=", ";", "(", ")", "=", "<", ">", "<=", ">="}:
            return "", {}
        else:
            words.append(value.upper())
    return " ".join(words) + " ", literals


def _compile(raw, owner, block, resolve, properties):
    text, literals = _tokens(raw)
    if not text.startswith("BEGIN ") or not text.endswith("END ; "):
        return None
    text = text.removeprefix("BEGIN ").removesuffix("END ; ")
    guard = None
    arguments = {}
    def argument(key, mode, datatype, **binding):
        if key not in arguments:
            arguments[key] = dict(name=f'p_{len(arguments)+1}', mode=mode, data_type=datatype, **binding)
        return arguments[key]["name"]

    limit, status = _LIMIT.match(text), _STATUS.match(text)
    if limit:
        ref, comparator, number, message = limit.groups()
        item = resolve(block, ref)
        if (item is None or item["id"] != owner["parent_id"]
                or properties[item["id"]].get("DataType", "").upper() not in {"NUMBER", "INTEGER"}):
            return None
        value = argument(item["id"], "IN", "NUMBER", kind="current_value", source_item_id=item["id"])
        guard = {"kind":"numeric_limit", "parameter":value, "operator":comparator,
                 "value":number, "message":literals[message][1:-1].replace("''", "'")}
        text = text[limit.end():]
    elif status:
        literal = literals[status[1]]
        if literal not in {"'CHANGED'", "'QUERY'", "'NEW'", "'INSERT'", "'UPDATE'"} or not text.endswith("END IF ; "):
            return None
        value = argument("SYSTEM.RECORD_STATUS", "IN", "VARCHAR2", kind="record_status", reference="SYSTEM.RECORD_STATUS")
        guard = {"kind":"record_status", "parameter":value, "equals":literal[1:-1]}
        text = text[status.end():-len("END IF ; ")]

    statements = []
    while text:
        match = _ASSIGN.match(text)
        if not match:
            return None
        ref, rhs = match.groups()
        item = resolve(block, ref)
        if item is None:
            return None
        dtype = properties[item["id"]].get("DataType", "").upper()
        if rhs == "SYSDATE":
            if dtype not in {"DATE", "DATETIME"}:
                return None
            expr, target_type = "SYSDATE", "DATE"
        else:
            if dtype not in _CHAR:
                return None
            global_name = "GLOBAL." + rhs.split()[-1]
            expr = argument(global_name, "IN", "VARCHAR2", kind="forms_global", reference=global_name)
            target_type = "VARCHAR2"
        if item["id"] in arguments and arguments[item["id"]]["mode"] != "IN OUT":
            return None
        target = argument(item["id"], "IN OUT", target_type, kind="current_row_output",
                          source_item_id=item["id"], source_name=item["name"], block_id=block["id"])
        statements.append({"target":target,"expression":expr})
        text = text[match.end():]
    if not statements:
        return None
    return {"parameters":list(arguments.values()), "guard":guard, "assignments":statements}


def build_event_callables(documents, packet, chunks, coverage, project_id):
    objects, properties = _source_objects(documents, packet)
    items = defaultdict(list)
    for obj in objects.values():
        if obj["kind"] == "Item":
            items[(obj["block_id"], (obj["name"] or "").upper())].append(obj)
    def resolve(block, reference):
        parts = reference.split(" . ")
        if len(parts) == 2 and parts[0] != (block["name"] or "").upper():
            return None
        found = items[(block["id"], parts[-1])]
        return found[0] if len(found) == 1 else None

    texts = {c["code_unit_id"]:c for c in chunks}
    namespace = hashlib.sha256(json.dumps([project_id,packet["source_binding"]]).encode()).hexdigest()[:20].upper()
    package = "FOX_EVT_" + namespace
    ops, declarations, bodies = {}, [], []
    for row in coverage:
        uid, oid = row["source_unit_id"], row["source_owner_id"]
        owner = objects[oid]
        if (row["status"] == "generated_wired_adapted" or row.get("encoding_status") == "generated_unwired"
                or owner["kind"] != "Trigger" or owner["name"] not in {"WHEN-CREATE-RECORD","POST-CHANGE"}
                or owner.get("block_id") not in objects):
            continue
        chunk = texts[uid]
        if hashlib.sha256(chunk["text"].encode()).hexdigest() != row["source_unit_sha256"]:
            raise ValueError("Scalar event differs from its source.")
        try:
            op = _compile(chunk["text"], owner, objects[owner["block_id"]], resolve, properties)
        except UnsupportedBehavior:
            continue
        if op is None:
            continue
        name = "E_" + hashlib.sha256(uid.encode()).hexdigest()[:24].upper()
        args = ", ".join(f"{p['name']} {p['mode']} {p['data_type']}" for p in op["parameters"])
        signature = f"  PROCEDURE {name}({args})"
        declarations.append(signature + ";")
        lines = [signature + " IS", "  BEGIN"]
        guard = op["guard"]
        indent = "    "
        if guard and guard["kind"] == "numeric_limit":
            message = guard["message"].replace("'", "''")
            lines.extend([f"    IF {guard['parameter']} {guard['operator']} {guard['value']} THEN",
                          f"      raise_application_error(-20001, '{message}');", "    END IF;"])
        if guard and guard["kind"] == "record_status":
            lines.append(f"    IF {guard['parameter']} = '{guard['equals']}' THEN")
            indent = "      "
        lines += [f"{indent}{s['target']} := {s['expression']};" for s in op["assignments"]]
        if guard and guard["kind"] == "record_status":
            lines.append("    END IF;")
        lines.append(f"  END {name};")
        bodies.append("\n".join(lines))
        ops[uid] = dict(op, source_unit_id=uid, source_unit_sha256=row["source_unit_sha256"],
                        source_event=owner["name"], source_block_id=owner["block_id"], source_owner_id=oid,
                        package_name=package, procedure_name=name, code_member=CODE_MEMBER,
                        native_event_wired=False, oracle_compiled=False, business_accepted=False)
    if not ops:
        return ops, None
    code = ("-- Optional source-bound procedures for a verified event host.\n"
            "-- The host supplies the current row, record status, trusted globals and field constraints.\n"
            f"CREATE OR REPLACE PACKAGE {package} AUTHID CURRENT_USER AS\n" + "\n".join(declarations)
            + f"\nEND {package};\n/\nCREATE OR REPLACE PACKAGE BODY {package} AS\n"
            + "\n".join(bodies) + f"\nEND {package};\n/\n")
    return ops, code.encode("utf-8")
