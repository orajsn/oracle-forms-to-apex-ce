"""Closed source grammar for caller POST-CHANGE scalar companion lookup."""
from copy import deepcopy
import re

from .forms_behavior_plan import decode_control_entities
from .forms_interface_inventory import _lex


def message_supported(value):
    # Reserve space below RAISE_APPLICATION_ERROR's byte bound even when APEX
    # HTML escaping expands punctuation to its longest six-byte entity.
    return (isinstance(value, str) and bool(value) and all(ord(ch) >= 32 for ch in value)
            and sum(6 if ch in '&<>"\'/' else len(ch.encode('utf-8')) for ch in value) <= 1800)


def compile_typed_lookup(c, objects, units, chunks):
    candidates = [u for u in units if objects[u['owner_id']]['parent_id'] == c['source_caller_item_id']
                  and objects[u['owner_id']]['kind'] == 'Trigger'
                  and (objects[u['owner_id']]['name'] or '').upper() == 'POST-CHANGE']
    if not candidates:
        return {}
    gap = {'typed_lookup_gap': 'Complete caller POST-CHANGE semantics are unsupported; changed caller mutations are blocked.'}
    if len(candidates) != 1:
        return gap
    unit, = candidates
    text, _ = decode_control_entities(chunks[unit['id']]['text'])
    tokens, errors = _lex(text)
    values = [t[1].upper() for t in tokens]
    # Retain the prior no-op fixture behavior, without claiming an event receipt.
    if not errors and values == ['BEGIN', 'NULL', ';', 'END', ';']:
        return {}
    try:
        if errors:
            raise ValueError()
        pos = 0

        def take(expected):
            nonlocal pos
            if pos >= len(tokens) or values[pos] != expected:
                raise ValueError()
            pos += 1

        def identifier():
            nonlocal pos
            if pos >= len(tokens) or tokens[pos][0] != 'word' or not re.fullmatch(r'[A-Z][A-Z0-9_$#]*', values[pos]):
                raise ValueError()
            result = values[pos]
            pos += 1
            return result

        def reference(bind=False):
            if bind:
                take(':')
            result = [identifier()]
            if pos < len(tokens) and values[pos] == '.':
                take('.')
                result.append(identifier())
            return result

        def refs(bind=False):
            result = [reference(bind)]
            while pos < len(tokens) and values[pos] == ',':
                take(',')
                result.append(reference(bind))
            return result

        take('BEGIN'); take('SELECT')
        columns = refs()
        take('INTO')
        targets = refs(True)
        take('FROM')
        table = identifier()
        take('WHERE')
        key = reference()
        take('=')
        caller = reference(True)
        take(';'); take('EXCEPTION'); take('WHEN'); take('NO_DATA_FOUND'); take('THEN'); take('MESSAGE'); take('(')
        token = tokens[pos]
        literal = text[token[2]:token[3]]
        if token[0] != 'literal' or not re.fullmatch(r"'(?:[^']|'')*'", literal, re.S):
            raise ValueError()
        message = literal[1:-1].replace("''", "'")
        if not message_supported(message):
            raise ValueError()
        pos += 1
        take(')'); take(';'); take('RAISE'); take('FORM_TRIGGER_FAILURE'); take(';'); take('END'); take(';')
        if pos != len(tokens) or table != c['source_table']:
            raise ValueError()

        def col(parts):
            if len(parts) == 2 and parts[0] != table:
                raise ValueError()
            return parts[-1]

        def field(parts):
            if len(parts) == 2 and parts[0] != c['source_block_name'].upper():
                raise ValueError()
            matches = [f for f in c['fields'] if f['source_name'].upper() == parts[-1]]
            if len(matches) != 1:
                raise ValueError()
            return matches[0]

        if field(caller) != c['caller'] or col(key) != c['caller']['source_column']:
            raise ValueError()
        assignments = [{'source_column': col(p), 'field': deepcopy(field(t))}
                       for p, t in zip(columns, targets, strict=True)]
        expected = [f for f in c['fields'] if f != c['caller']]
        if (len(assignments) != len(expected) or len({a['field']['source_item_id'] for a in assignments}) != len(expected)
                or {a['field']['source_item_id'] for a in assignments} != {f['source_item_id'] for f in expected}
                or any(a['source_column'] != a['field']['source_column'] for a in assignments)
                or not c['caller']['direct_edit_allowed']):
            raise ValueError()
        return {'typed_lookup': {'source_unit_id': unit['id'], 'source_unit_sha256': unit['sha256'],
            'source_chunk_id': chunks[unit['id']]['id'], 'source_owner_id': unit['owner_id'],
            'source_attribute': unit['source_attribute'], 'source_event': 'POST-CHANGE',
            'source_table': table, 'key_column': col(key), 'caller_source_item_id': c['source_caller_item_id'],
            'assignments': assignments, 'no_data_message': message, 'no_data_failure': 'FORM_TRIGGER_FAILURE',
            'active_filter_applied': False, 'exact_one_required': True}}
    except (ValueError, IndexError, KeyError):
        return gap
