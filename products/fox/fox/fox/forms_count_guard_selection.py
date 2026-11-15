"""Read-only source discovery and closed, creation-only count-check selection.

No model, raw-code execution, target operation or consent is performed here.
The complete project source binding and current owner remain caller authority.
"""
from copy import deepcopy
import re

from .forms_understanding_packet import local_packet

POLICY_ID = 'forms-isolated-count-check-v1'
SCOPE = 'fox-prototype-count-check-discovery-v1'
SELECTION_FIELDS = {'source_name', 'source_sha256', 'module', 'block', 'item'}
MAX_DESCRIPTORS = 64
NOTICE = ('Only the first null-or-zero count check is selected as a separate native action over saved '
          'synthetic rows. Negative nonzero values and no matching rows pass this isolated predicate. '
          'The original button, approval, later rules and exception handling remain unconverted.')


def bound_count_guard(binding):
    """Absent preserves historical behavior; explicit malformed/null groups reject."""
    if 'count_guard' not in binding:
        return None
    value = binding['count_guard']
    if (type(value) is not dict or set(value) != {'policy_id', 'selection', 'partial_scope_consent'}
            or value['policy_id'] != POLICY_ID or value['partial_scope_consent'] is not True):
        raise ValueError('Invalid immutable isolated count-check policy or partial-scope consent.')
    _validate_selection(value['selection'])
    return deepcopy(value)


def _validate_selection(selected):
    if (type(selected) is not dict or set(selected) != SELECTION_FIELDS
            or any(type(v) is not str or not v for v in selected.values())
            or re.fullmatch(r'[a-f0-9]{64}', selected['source_sha256']) is None
            or len(selected['source_name']) > 180 or '..' in selected['source_name']
            or any(c in selected['source_name'] for c in '/\\:')
            or not selected['source_name'].lower().endswith('.xml')
            or any(re.fullmatch(r'[A-Za-z][A-Za-z0-9_$#]{0,127}', selected[key]) is None
                   for key in ('module', 'block', 'item'))):
        raise ValueError('Invalid exact count-check source selection.')
    return selected


def _extract_source_rule(raw, source, selected):
    from forms2apex.forms_count_guard import extract_count_guard
    rule = extract_count_guard(raw, source_sha256=selected['source_sha256'],
        module=selected['module'], block=selected['block'], item=selected['item'])
    facts = {obj['id']: obj for obj in source['facts']['objects']}
    if any(row['id'] not in facts or facts[row['id']]['location']['path'] != row['path']
           for row in rule['source_objects'].values()):
        raise ValueError('Count-check source identities differ from fresh project facts.')
    return rule


def selected_source_rule(documents, choice):
    """Fresh source facts plus the reviewed deterministic prefix extractor."""
    choice = bound_count_guard({'count_guard': choice})
    packet = local_packet(documents)
    selected = choice['selection']
    matches = [(raw, source) for name, raw in documents for source in packet['sources']
               if name == selected['source_name'] == source['source']['name']]
    if len(matches) != 1 or matches[0][1]['source']['sha256'] != selected['source_sha256']:
        raise ValueError('The selected count-check source is missing, changed or ambiguous.')
    raw, source = matches[0]
    return _extract_source_rule(raw, source, selected)


def prepare_count_guard_choice(documents, *, policy=None, selection=None, approved_partial_scope=None):
    if policy is None and selection is None and approved_partial_scope is None:
        return None
    choice = bound_count_guard({'count_guard': {'policy_id': policy, 'selection': selection,
                                               'partial_scope_consent': approved_partial_scope}})
    selected_source_rule(documents, choice)
    return choice


def describe_count_checks(documents):
    """Bounded descriptors only; source bodies and original messages never escape."""
    from forms2apex import forms_count_guard  # availability is not an unsupported-source finding
    packet = local_packet(documents)
    raw_by_name = dict(documents)
    checks, unsupported, considered = [], [], 0
    for entry in packet['sources']:
        objects = {row['id']: row for row in entry['facts']['objects']}
        for trigger in entry['facts']['objects']:
            if trigger['kind'] != 'Trigger' or trigger['name'] != 'WHEN-BUTTON-PRESSED':
                continue
            button = objects.get(trigger['parent_id'], {})
            if button.get('kind') != 'Item' or button.get('item_type') != 'Push Button':
                continue
            considered += 1
            block = objects.get(button.get('block_id'), {})
            module = objects.get(button.get('module_id'), {})
            selection = {'source_name': entry['source']['name'], 'source_sha256': entry['source']['sha256'],
                         'module': module.get('name'), 'block': block.get('name'), 'item': button.get('name')}
            try:
                _validate_selection(selection)
                rule = _extract_source_rule(raw_by_name[entry['source']['name']], entry, selection)
            except (ValueError, KeyError, TypeError, ImportError):
                if len(unsupported) < MAX_DESCRIPTORS:
                    unsupported.append({'source_name': entry['source']['name'],
                        'source_sha256': entry['source']['sha256'], 'source_trigger_id': trigger['id'],
                        'code': 'count_check_prefix_or_binding_unsupported',
                        'reason': 'No unambiguous supported count-check prefix and source binding were established.'})
                continue
            if len(checks) < MAX_DESCRIPTORS:
                checks.append({'selection': selection,
                    'source_objects': {key: row['id'] for key, row in rule['source_objects'].items()},
                    'source_prefix_sha256': rule['source']['prefix_sha256'],
                    'source_remainder_sha256': rule['unsupported_remainder']['sha256'],
                    'requires_explicit_partial_scope_consent': True, 'scope_notice': NOTICE})
    return {'scope': SCOPE, 'count_guard_policy': POLICY_ID, 'source_binding': packet['source_binding'],
            'checks': checks, 'unsupported': unsupported, 'considered_button_count': considered,
            'descriptors_truncated': considered > len(checks) + len(unsupported),
            'processing_approved': False, 'partial_scope_approved': False,
            'business_behavior_accepted': False, 'scope_notice': NOTICE}
