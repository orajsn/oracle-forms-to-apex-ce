"""Show dependencies from the saved source of each unfinished action."""
from collections import defaultdict
import re

from .forms_behavior_plan import decode_control_entities, UnsupportedBehavior
from .forms_discrepancies import _semantic_mask

_STATE = re.compile(r":\s*(GLOBAL|SYSTEM)\s*\.\s*([A-Za-z][A-Za-z0-9_$#]{0,127})", re.I)
_GROUPS = ('routines', 'tables', 'reports', 'forms_state', 'unreached_calls')


def add_gap_requirements(gaps, packet, chunks, inventory):
    owners = {o['id']: o for s in packet['sources'] for o in s['facts']['objects']}
    units = {u['id']: u for s in packet['sources'] for u in s['facts']['code_units']}
    texts = {c['code_unit_id']: c for c in chunks}
    records = defaultdict(list)
    for r in inventory['records']:
        records[r['source']['source_unit_id']].append(r)
    for gap in gaps['gaps']:
        uid = gap['source_unit_id']
        obj = owners[units[uid]['owner_id']]
        event = (obj['name'] or '').upper()
        path = []
        while obj:
            if obj['name']:
                path.append(obj['name'])
            obj = owners.get(obj.get('parent_id'))
        groups = {k: set() for k in _GROUPS}
        incomplete = not inventory['detail_coverage']['complete']
        for r in records[uid]:
            if not r['position']:
                continue
            if r['classification'] in ('qualified_routine_to_verify', 'unresolved_routine_candidate'):
                group = 'unreached_calls' if r.get('control_flow') == 'select_after_unconditional_form_trigger_failure' else 'routines'
                groups[group].add(r['name'])
            if r['classification'] == 'database_object_to_verify' and r['role'] in ('read','insert','delete','update','merge'):
                groups['tables'].add(r['name'])
            if r.get('registered_report'):
                groups['reports'].add(r['registered_report'])
        try:
            code, _ = decode_control_entities(texts[uid]['text'])
            groups['forms_state'].update('.'.join(m.groups()).upper() for m in _STATE.finditer(_semantic_mask(code)))
        except UnsupportedBehavior:
            incomplete = True
        owner_path = ' / '.join(reversed(path))
        incomplete |= len(owner_path) > 1000
        summary = {'owner_path': owner_path[:1000]}
        for k, values in groups.items():
            names = sorted({v.upper() for v in values if v})
            summary[k] = [n for n in names if len(n) <= 256][:24]
            incomplete |= len(summary[k]) != len(names)
        summary['limited'] = incomplete
        next_check = ''
        if summary['reports']:
            next_check = 'Verify the registered report layout, its parameters and the report service that returns the document.'
        elif event == 'KEY-CREREC' and summary['routines'] and summary['tables']:
            next_check = 'Verify the routines, parameter data and session values used during record creation.'
        elif event == 'PRE-FORM' and summary['routines']:
            next_check = 'Bind the startup routine to a trusted session and verify the startup branch that consumes its return value.'
        elif event == 'WHEN-VALIDATE-ITEM' and summary['routines'] and summary['tables']:
            next_check = 'Verify the validation routines and lookup data for each reachable branch, including their return values and error handling.'
        elif event == 'KEY-NEXT-ITEM' and summary['routines']:
            next_check = 'Verify the routine called during navigation and its effects before continuing the source key action.'
        elif summary['tables'] and not summary['routines']:
            next_check = 'Verify the referenced tables, column types and query results against the supplied SQL before connecting this action.'
        summary['next_check'] = next_check
        gap['requirements'] = summary


def valid_gap_requirements(value):
    if (not isinstance(value, dict) or set(value) != {'owner_path','limited','next_check',*_GROUPS}
            or not isinstance(value['owner_path'],str) or len(value['owner_path']) > 1000
            or not isinstance(value['next_check'],str) or len(value['next_check']) > 500
            or type(value['limited']) is not bool):
        return False
    return all(isinstance(value[k],list) and len(value[k]) <= 24 and
               all(type(n) is str and 0 < len(n) <= 256 for n in value[k]) for k in _GROUPS)
