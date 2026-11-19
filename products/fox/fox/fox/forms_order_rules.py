"""Whole source ORDER BY clauses become initial native saved-report sorts.

The assembler supplies fresh original XML and its rebuilt report trace. This
module never executes source SQL or interprets partial/unknown clauses.
"""
from copy import deepcopy
import hashlib
import json
import re

from .forms_behavior_plan import _source_objects, decode_control_entities, UnsupportedBehavior

RULE_ID = 'fox.query.initial-report-order'
_IDENTIFIER = r'[A-Za-z][A-Za-z0-9_$#]{0,127}'
_TERM = re.compile(rf'({_IDENTIFIER})(?:\s+(ASC|DESC))?(?:\s+NULLS\s+(FIRST|LAST))?', re.I)


def parse_order(text):
    """Accept only 1..6 direct column references, direction and NULL placement."""
    if not isinstance(text, str) or len(text) > 2048:
        raise ValueError('order_clause_capacity')
    parts = text.split(',')
    if not 1 <= len(parts) <= 6:
        raise ValueError('order_clause_capacity')
    terms = []
    for part in parts:
        match = _TERM.fullmatch(part.strip())
        if not match:
            raise ValueError('order_clause_not_direct_columns')
        name, direction, nulls = match.groups()
        direction = (direction or 'ASC').lower()
        terms.append({'source_name': name.upper(), 'direction': direction,
                      'nulls': (nulls or ('LAST' if direction == 'asc' else 'FIRST')).lower()})
    if len({t['source_name'] for t in terms}) != len(terms):
        raise ValueError('order_clause_duplicate_column')
    return terms


def apply_order_rules(documents, packet, chunks, trace, members):
    """Copy files; render proven clauses once before related pages are cloned."""
    objects, props = _source_objects(documents, packet)
    texts = {c['code_unit_id']: c for c in chunks}
    files, operations, gaps = dict(members), [], []
    if trace.get('source_binding') != packet['source_binding']:
        raise ValueError('ORDER_TRACE_SOURCE_MISMATCH')
    for source in packet['sources']:
        for unit in source['facts']['code_units']:
            if unit['source_attribute'] != 'OrderByClause':
                continue
            try:
                owner = objects[unit['owner_id']]
                if owner['kind'] != 'Block' or owner['classification'] != 'database':
                    raise ValueError('order_requires_database_block')
                chunk = texts[unit['id']]
                if hashlib.sha256(chunk['text'].encode()).hexdigest() != unit['sha256']:
                    raise ValueError('order_source_hash_mismatch')
                text, receipt = decode_control_entities(chunk['text'])
                terms = parse_order(text)
                targets = [b for b in trace['blocks'] if b['source_block_id'] == owner['id']]
                if len(targets) != 1 or targets[0].get('source_module_id') != owner['module_id']:
                    raise ValueError('order_report_target_not_unique')
                target = targets[0]
                if target['classification'] != 'database' or not target.get('report_file'):
                    raise ValueError('order_requires_native_report')
                for term in terms:
                    candidates = [o for o in objects.values() if o['kind'] == 'Item'
                        and o['block_id'] == owner['id'] and o.get('database_item') is True
                        and (props[o['id']].get('ColumnName', '').strip() or o['name'] or '').upper() == term['source_name']]
                    if len(candidates) != 1:
                        raise ValueError('order_source_column_not_unique')
                    item = candidates[0]
                    p = props[item['id']]
                    if (item.get('database_item') is not True or p.get('Formula', '').strip()
                            or any(p.get(k, '').strip().upper() not in ('', 'NONE')
                                   for k in ('CalculateMode', 'CalculationMode', 'SummaryFunction'))):
                        raise ValueError('order_requires_direct_noncomputed_column')
                    fields = [f for f in target['items'] if f['source_item_id'] == item['id']]
                    if (len(fields) != 1 or fields[0].get('database_bound') is not True
                            or not re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', fields[0].get('column') or '')
                            or fields[0].get('data_type') not in ('NUMBER', 'VARCHAR2', 'DATE')):
                        raise ValueError('order_column_not_mapped')
                    term.update(source_item_id=item['id'], column=fields[0]['column'])
                page = files[target['report_file']].decode('utf8')
                anchor = '        savedReport primary (\n'
                if page.count(anchor) != 1 or re.search(r'\bsort\s', page):
                    raise ValueError('order_report_sort_anchor_changed')
                rendered = ''.join(f"            sort (\n                column: {t['column']}\n"
                    f"                sort {{\n                    sequence: {n}\n"
                    f"                    direction: {t['direction']}\n                    nulls: {t['nulls']}\n"
                    f"                }}\n            )\n" for n, t in enumerate(terms, 1))
                files[target['report_file']] = page.replace(anchor, anchor + rendered, 1).encode()
                operations.append({'source_unit_id': unit['id'], 'source_unit_sha256': unit['sha256'],
                    'source_owner_id': owner['id'], 'source_module_id': owner['module_id'],
                    'operation_id': 'order-' + unit['sha256'][:16] + '-' + owner['id'][-8:],
                    'kind': 'initial_report_order', 'rule_id': RULE_ID, 'terms': terms,
                    'decode_receipt': receipt, 'target': {'report_file': target['report_file'],
                    'report_page_id': target['report_page_id']}, 'generation_status': 'generated_wired_adapted',
                    'adaptation': 'Initial persisted-row report order; users may change saved-report sorting. Equal-key order is unspecified. Matching database collation is required.',
                    'runtime_verified': False, 'business_accepted': False})
            except (ValueError, UnsupportedBehavior) as exc:
                gaps.append({'source_unit_id': unit['id'], 'reason': str(exc)})
    result = {'schema_version': 1, 'scope': 'fox-source-order-rules-v1',
        'source_binding': packet['source_binding'], 'generated_operations': operations, 'gaps': gaps,
        'runtime_verified': False, 'business_accepted': False}
    result['receipt_sha256'] = hashlib.sha256(json.dumps(result, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return files, deepcopy(result)
