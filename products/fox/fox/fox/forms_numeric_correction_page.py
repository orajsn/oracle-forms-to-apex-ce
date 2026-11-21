"""Native saved-row weight correction, separate from source navigation/approval.

Only the deterministic correction compiler supplies executable SQL. Browser
inputs identify signed selections and the proposed text value; the baseline and
one-use marker stay on the server. No existing draft editor is repurposed.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import re

from forms2apex import native_buffer
from .forms_master_detail import _report

SCOPE = 'fox-native-numeric-correction-v1'
REQUEST = 'FOX_NUMERIC_SAVE'


def _need(value, reason):
    if not value:
        raise ValueError('NUMERIC_CORRECTION_PAGE_' + reason)


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode()


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _append(raw, text):
    value = raw.decode()
    _need(value.endswith(')\n'), 'PAGE_ANCHOR')
    return (value[:-2] + native_buffer._expand_groups(text) + ')\n').encode()


def _item(page, name, *, label=None, hidden=False, server_only=False, session=False):
    kind = 'hidden' if hidden else 'displayOnly'
    label_text = '' if label is None else f'        label {{ label: {json.dumps(label)} }}\n'
    never = '        serverSideCondition { type: never }\n' if server_only else ''
    return f'''    pageItem P{page}_{name} (
        type: {kind}
{label_text}        layout {{ sequence: 10
            region: @editor
            slot: regionBody }}
        sessionState {{ storage: {'session' if session else 'request'}
            dataType: {'number' if name in ('PARENT_ID', 'ROW_ID') else 'varchar2'} }}
        security {{ sessionStateProtection: {'checksumRequiredSessionLevel' if hidden else 'restricted'} }}
{never}    )
'''


def _identity(page, *, row=False):
    return ''.join(_item(page, name, hidden=True, session=True)
                   for name in (('PARENT_ID', 'TOKEN', 'ROW_ID') if row else ('PARENT_ID', 'TOKEN')))


def _target(source, destination):
    return f'''page: {destination}
                clearCache: {destination}
                items: {{ P{destination}_PARENT_ID: "&P{source}_PARENT_ID."
                    P{destination}_TOKEN: "&P{source}_TOKEN." }}'''


def _return(source, destination, *, label='Cancel and return', slug='cancel-weight-correction'):
    return f'''    button {slug} (
        buttonName: FOX_NUMERIC_CANCEL
        label: {json.dumps(label)}
        layout {{ sequence: 30
            region: @editor
            slot: change }}
        appearance {{ buttonTemplate: @/text }}
        behavior {{ action: redirectThisApp
            target: {{ {_target(source, destination)} }} }}
    )
'''


def _shell(page, title, description, body):
    return native_buffer._expand_groups(f'''page {page} (
    name: {json.dumps(title)}
    alias: FOX_WEIGHT_{page}
    title: {json.dumps(title)}
    appearance {{ pageTemplate: @/standard
        templateOptions: #DEFAULT# }}
    advanced {{ reloadOnSubmit: always }}
    security {{ authentication: required
        pageAccessProtection: argumentsMustHaveChecksum }}
    region editor (
        name: Saved bag weight
        type: staticContent
        source {{ htmlCode: {json.dumps(description)} }}
        layout {{ sequence: 5
            slot: body }}
        appearance {{ template: @/standard
            templateOptions: #DEFAULT# }}
    )
{body})
''').encode()


def _fields(op):
    return [deepcopy(op['fields'][role]) for role in ('bag_number', 'weight')]


def _visible_query(query, fields):
    # Internal eligibility/context projections include the server baseline.
    # Never expose that projection as an interactive report's available data.
    names = ['FOX_ROW_ID'] + [field['column'] for field in fields]
    _need(all(re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', name) for name in names), 'DISPLAY_COLUMNS')
    return 'select ' + ','.join('v.' + name for name in names) + ' from (' + query + ') v'


def _chooser(op, page, editor, queries):
    # FOX_ROW_ID, not the arbitrary bag label reported by readiness, selects
    # the row. Both parts of the original header selection travel unchanged.
    fields = _fields(op) + [{'column': 'CORRECTION_STATUS', 'data_type': 'VARCHAR2', 'source_name': 'Correction status'}]
    report = _report('weight-choices', 'Select a saved bag', _visible_query(queries['chooser_query_sql'], fields), fields, link=editor)
    old = f'''                    items: {{ P{editor}_PARENT_ID: "#FOX_ROW_ID#"
                        P{editor}_TOKEN: "#FOX_MASTER_TOKEN#" }}'''
    new = f'''                    clearCache: {editor}
                    items: {{ P{editor}_PARENT_ID: "&P{page}_PARENT_ID."
                        P{editor}_TOKEN: "&P{page}_TOKEN."
                        P{editor}_ROW_ID: "#FOX_ROW_ID#" }}'''
    _need(report.count(old) == 1, 'ROW_LINK_TEMPLATE')
    report = report.replace(old, new).replace('linkText: Select master', 'linkText: Correct weight')
    # The shared report helper adds a fingerprint column only for its own
    # master selection. This row selector uses the signed actual row ID.
    report, count = re.subn(r'        column FOX_MASTER_TOKEN \(.*?\n        \)\n', '', report, flags=re.S)
    _need(count == 1 and '#FOX_MASTER_TOKEN#' not in report, 'ROW_LINK_TOKEN')
    description = ('Select the saved bag by its row number and bag number. Only bags with missing or zero actual weight '
                   'for this manifest are listed. No rows means there is no eligible saved bag or the selection changed. '
                   'Return to readiness to recheck. Your session drafts are retained.')
    return _shell(page, 'Correct saved bag weight', description,
                  report + _identity(page) + _return(page, op['approval_page_id'], label='Return to readiness'))


def _editor(op, page, queries):
    open_code = f"begin if :REQUEST is null then\n{queries['open_code']}\nend if; end;"
    save_code = queries['save_code']
    _need(all(len(value.encode()) <= 32767 for value in (open_code, save_code)), 'PROCESS_CAPACITY')
    body = _report('saved-bag-context', 'Selected saved bag', _visible_query(queries['context_query_sql'], _fields(op)), _fields(op))
    body += _identity(page, row=True)
    # A browser-held opaque nonce distinguishes tabs. Its matching baseline
    # remains server-side; a second open invalidates the earlier tab's nonce.
    body += _item(page, 'NONCE', hidden=True)
    # Never render or submit this item. Restricted display-only state is
    # populated by the open process and consumed by the Save process.
    body += _item(page, 'MARKER', server_only=True, session=True)
    body += _item(page, 'STATE', label='Correction state')
    body += _item(page, 'MESSAGE', label='Correction status')
    body += f'''    pageItem P{page}_VALUE (
        type: textField
        settings {{ trimSpaces: none }}
        label {{ label: Actual weight }}
        layout {{ sequence: 20
            region: @editor
            slot: regionBody }}
        appearance {{ template: @/optional-floating }}
        sessionState {{ storage: request
            dataType: varchar2 }}
        security {{ sessionStateProtection: unrestricted }}
    )
    button save-weight-correction (
        buttonName: {REQUEST}
        label: Save weight and recheck
        layout {{ sequence: 20
            region: @editor
            slot: change }}
        appearance {{ buttonTemplate: @/text }}
        behavior {{ action: submitPage
            executeValidations: false }}
        serverSideCondition {{ type: expression
            language: plsql
            plsqlExpression: ":P{page}_STATE='READY'" }}
    )
'''
    body += _return(page, op['approval_page_id'])
    body += native_buffer._process('open-weight-correction', open_code, point='beforeHeader')
    process = native_buffer._process('save-weight-correction', save_code, point='processing')
    _need(process.endswith('    )\n'), 'PROCESS_TEMPLATE')
    body += process[:-6] + f'''        serverSideCondition {{ type: requestIsContainedInValue
            value: {REQUEST} }}
    )
    branch return-to-weight-readiness (
        name: Recheck the same manifest
        execution {{ sequence: 10
            point: afterProcessing }}
        behavior {{ type: pageOrUrl
            target: {{ {_target(page, op['approval_page_id'])} }} }}
        serverSideCondition {{ type: expression
            language: plsql
            plsqlExpression: ":REQUEST='{REQUEST}' and :P{page}_STATE in ('SAVED','UNCHANGED')" }}
    )
'''
    rules = op['rules']
    notation = ('Use a whole number.' if rules['scale'] == 0
                else f"Use a decimal point and up to {rules['scale']} decimal places.")
    limits = f" Minimum: {rules['minimum']}."
    if rules['maximum'] is not None:
        limits += f" Maximum: {rules['maximum']}."
    description = ('Enter actual weight and choose Save weight and recheck. ' + notation + limits
                   + ' Cancel leaves the saved bag unchanged. '
                   'If the selection changed or a draft conflicts, return and resolve it before selecting the bag again. '
                   'This action does not approve the manifest.')
    return _shell(page, 'Enter saved bag actual weight', description, body)


def _entry(readiness, chooser, gate):
    return f'''    button correct-saved-weight (
        buttonName: FOX_CORRECT_SAVED_WEIGHT
        label: Correct saved bag weight
        layout {{ sequence: 8600
            region: @approval-scope
            slot: regionBody }}
        appearance {{ buttonTemplate: @/text }}
        behavior {{ action: redirectThisApp
            target: {{ {_target(readiness, chooser)} }} }}
        serverSideCondition {{ type: rowsReturned
            sqlQuery:
                ```sql
{native_buffer._indent(gate)}
                ```
        }}
    )
'''


def apply_numeric_corrections(documents, packet, chunks, trace, files):
    """Add selection/edit pages only for a completely proved correction plan."""
    from .forms_numeric_correction import build_numeric_correction_plan, render_numeric_correction_sql

    _need(not any(re.fullmatch(r'pages/p\d+-fox_weight_\d+\.apx', n) for n in files), 'ALREADY_APPLIED')
    plan = build_numeric_correction_plan(documents, packet, chunks, trace, files)
    output = dict(files)
    receipt = {'schema_version': 1, 'scope': SCOPE, 'source_binding': packet['source_binding'],
               'generated_operations': [], 'adapted_operations': [], 'gaps': deepcopy(plan['gaps']),
               'converted_code_unit_count': 0, 'customer_table_writes': False,
               'synthetic_table_writes': False, 'approval_flag_written': False,
               'original_reads_enabled': False, 'external_calls_enabled': False,
               'forms_commit_implemented': False, 'oracle_compiled': False,
               'runtime_verified': False, 'business_accepted': False}
    occupied = {int(m[1]) for n in files if (m := re.fullmatch(r'pages/p(\d+)-[^/]+\.apx', n))}
    page = 8800

    def allocate():
        nonlocal page
        while page in occupied:
            page += 1
        _need(page < 9000, 'PAGE_CAPACITY')
        occupied.add(page)
        return page

    approval = json.loads(files.get('fox-package/approval-action-receipt.json', b'{"adapted_operations":[]}'))
    for op in plan['operations']:
        identity = {k: op[k] for k in ('operation_id', 'source_unit_id', 'source_unit_sha256', 'approval_source_unit_id')}
        try:
            selected = [row for row in approval['adapted_operations']
                        if row['source_unit_id'] == op['approval_source_unit_id']]
            _need(len(selected) == 1, 'EXACT_READINESS_REQUIRED')
            selected = selected[0]
            _need(approval['source_binding'] == packet['source_binding']
                  and selected['page_id'] == op['approval_page_id']
                  and selected['page_file'] == op['approval_page_file'], 'READINESS_BINDING')
            entry_file = selected['page_file']
            original_page = output[entry_file]
            _need(original_page.decode().startswith(f"page {selected['page_id']} (\n")
                  and 'pageAccessProtection: argumentsMustHaveChecksum' in original_page.decode()
                  and 'button correct-saved-weight (' not in original_page.decode(), 'PROTECTED_READINESS')
            chooser, editor = allocate(), allocate()
            chooser_sql = render_numeric_correction_sql(op, chooser)
            editor_sql = render_numeric_correction_sql(op, editor)
            # Readiness's first guard has a much smaller equivalent than its
            # full diagnostic projection (which can exceed the condition cap).
            # Keep exactly its selected header, source button permission and
            # null/zero child predicate; do not infer a row from WEIGHT_BAG.
            c = selected['contract']
            gate = (f"select 1 from ({selected['selected_context_sql']}) p "
                    f"where nvl(({c['permission_sql']}),0)=1 and exists "
                    f"(select 1 from {c['blocks']['bag']['table_name']} b where {selected['weight_predicate_sql']})")
            _need(len(gate.encode()) <= 4000, 'ENTRY_CONDITION_CAPACITY')
            chooser_file = f'pages/p{chooser:05d}-fox_weight_{chooser}.apx'
            editor_file = f'pages/p{editor:05d}-fox_weight_{editor}.apx'
            changes = {chooser_file: _chooser(op, chooser, editor, chooser_sql),
                       editor_file: _editor(op, editor, editor_sql),
                       entry_file: _append(original_page, _entry(selected['page_id'], chooser, gate))}
            output.update(changes)
            receipt['adapted_operations'].append({**deepcopy(op), **identity,
                'kind': 'saved_synthetic_numeric_correction', 'page_id': editor, 'page_file': editor_file,
                'chooser_page_id': chooser, 'chooser_page_file': chooser_file,
                'entry_file': entry_file, 'return_page_id': selected['page_id'],
                **editor_sql, 'chooser_query_sql': chooser_sql['chooser_query_sql'],
                'visible_chooser_query_sql': _visible_query(chooser_sql['chooser_query_sql'],
                    _fields(op) + [{'column': 'CORRECTION_STATUS'}]),
                'visible_context_query_sql': _visible_query(editor_sql['context_query_sql'], _fields(op)),
                'entry_condition_sql': gate, 'readiness_query_unchanged': True,
                'readiness_query_sha256': _sha(selected['readiness_query_sql'].encode()),
                'readiness_original_page_sha256': _sha(original_page),
                'readiness_final_page_sha256': _sha(changes[entry_file]),
                'synthetic_table_writes': True, 'customer_table_writes': False, 'approval_flag_written': False,
                'native_event_wired': True, 'whole_source_unit_converted': False,
                'runtime_verified': False, 'business_accepted': False})
            receipt['synthetic_table_writes'] = True
        except (ValueError, KeyError, TypeError) as exc:
            receipt['gaps'].append({**identity, 'reason': str(exc) if isinstance(exc, ValueError)
                                   else 'NUMERIC_CORRECTION_PAGE_PROVIDER_UNAVAILABLE'})
    output['fox-package/numeric-correction-plan.json'] = _json(plan)
    receipt['receipt_sha256'] = _sha(_json(receipt))
    return output, receipt
