"""Project source-proven display values on saved synthetic rows."""
from collections import defaultdict
import hashlib
import re
from textwrap import dedent

from . import native_relations
from .display_expression import render_display_expression


class DisplayReportError(ValueError):
    pass


def _need(condition, reason):
    if not condition:
        raise DisplayReportError(reason)


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _show_column(region, column):
    report, count = re.subn(
        r'^        savedReport primary \(\n.*?^        \)',
        lambda m: _add_column(m.group(), column), region, flags=re.M | re.S)
    _need(count == 1, 'primary_report_unavailable')
    return report


def _add_column(report, column):
    if f'            displayColumn {column} (\n' in report:
        return report
    sequences = [int(n) for n in re.findall(r'^                sequence: ([0-9]+)$', report, re.M)]
    position = report.rindex('        )')
    return (report[:position] + f'            displayColumn {column} (\n'
            f'                sequence: {max(sequences, default=0) + 1}\n            )\n' + report[position:])


def _sql_query(query, trailing=''):
    _need(len(query.encode('utf-8')) <= 32767, 'report_query_capacity')
    return ('        source {\n            location: localDatabase\n            type: sqlQuery\n'
            '            sqlQuery:\n                ```sql\n' +
            '\n'.join('                ' + line for line in query.splitlines()) +
            '\n                ```\n' + trailing + '        }')


def _replace_source(source, block, operations, related):
    table = block['table_name']
    cols = [block['synthetic_key']['column']] + [f['column'] for f in block['items']]
    _need(len(cols) == len(set(cols)) and all(re.fullmatch(r'[A-Z][A-Z0-9_]*', col) for col in cols),
          'report_columns_unavailable')
    table_source = ('        source {\n            location: localDatabase\n            type: tableView\n'
                    f'            tableName: {table}\n        }}')
    trailing = ''
    if source == table_source and not related:
        alias = 'r'
        projection = [alias + '.' + col for col in cols]
        rest = f'\nfrom {table} {alias}'
    else:
        match = re.fullmatch(
            r'        source \{\n            location: localDatabase\n            type: sqlQuery\n'
            r'            sqlQuery:\n                ```sql\n(.*?)\n                ```\n'
            r'((?:            pageItemsToSubmit: P[0-9]+_PARENT_ID\n)?)        \}', source, re.S)
        _need(match is not None, 'existing_report_source_not_composable')
        query, trailing = dedent(match[1]), match[2]
        if related:
            alias = 'fox_child'
            projection = [alias + '.' + col for col in cols]
            prefix = 'select ' + ', '.join(projection)
            _need(query.startswith(prefix + '\nfrom (select '), 'related_report_projection_changed')
            rest = query[len(prefix):]
        else:
            alias = table
            prefix, separator, tail = query.partition(f'\nfrom {table}')
            _need(separator and prefix.startswith('select ') and
                  (not tail or tail.startswith(('\nwhere ', '\norder by '))), 'existing_report_source_not_composable')
            checked = native_relations._projection_columns(prefix[7:], cols)
            projection = list(checked)
            rest = separator + tail
    for op in operations:
        column = op['target_column']
        _need(column in cols, 'target_column_not_in_report')
        slot = cols.index(column)
        _need(projection[slot] in (column, f'{alias}.{column}'), 'target_already_computed')
        expression = render_display_expression(op['expression'], row_alias=alias)
        checks = []
        for field in op['bindings']:
            if field['data_type'] != 'VARCHAR2':
                continue
            ref = alias + '.' + field['column']
            checks.append(f'nvl(lengthb({ref}),0)<={field["maximum_bytes"]}')
            if field['source_length_semantics'] != 'BYTE':
                checks.append(f'nvl(length({ref}),0)<={field["source_maximum_length"]}')
        if checks:
            expression = 'case when ' + ' and '.join(checks) + ' then ' + expression + ' end'
        projection[slot] = expression + ' as ' + column
    return _sql_query('select ' + ', '.join(projection) + rest, trailing)


def _report(raw, block, page, operations, related):
    text = raw.decode('utf-8')
    _need(text.startswith(f'page {page} (\n'), 'unexpected_report_page')
    sections = list(re.finditer(r'^    region records \(\n.*?^    \)', text, re.M | re.S))
    _need(len(sections) == 1, 'report_region_unavailable')
    region = sections[0].group()
    _need('        type: interactiveReport\n' in region, 'report_type_unavailable')
    sources = list(re.finditer(r'^        source \{\n.*?^        \}', region, re.M | re.S))
    _need(len(sources) == 1, 'report_source_unavailable')
    match = sources[0]
    replacement = _replace_source(match.group(), block, operations, related)
    region = region[:match.start()] + replacement + region[match.end():]
    for op in operations:
        col = op['target_column']
        _need(region.count(f'        column {col} (\n') == 1, 'target_report_column_unavailable')
        region = _show_column(region, col)
    text = text[:sections[0].start()] + region + text[sections[0].end():]
    _need(text.endswith(')\n') and '    region saved-display-scope (' not in text, 'report_scope_collision')
    notice = '''    region saved-display-scope (
        name: Calculated display fields
        type: staticContent
        source {
            htmlCode: "<p>Display values use the saved row. A value is blank if all its parts are empty or an input exceeds the source length. Edits and original Forms events have separate behavior.</p>"
        }
        layout {
            sequence: 9900
            slot: body
        }
        appearance {
            template: @/standard
        }
    )
'''
    return (text[:-2] + notice + ')\n').encode('utf-8')


def apply_display_projections(files, trace, plan, relation_receipt):
    """Apply each block atomically to its base report and related report copies."""
    _need(plan['source_binding'] == trace['source_binding'], 'display_source_changed')
    blocks = {b['source_block_id']: b for b in trace['blocks']}
    groups = defaultdict(list)
    for op in plan['projections']:
        groups[op['source_block_id']].append(op)
    changed, gaps, applied = {}, [], []
    for block_id, operations in groups.items():
        block = blocks[block_id]
        pages = [(block['report_file'], block['report_page_id'], False)]
        pages.extend((e['page_file'], e['page_id'], True) for e in (relation_receipt or {}).get('generated_operations', [])
                     if e['child_block_id'] == block_id)
        def compose(selected):
            trial = {}
            for path, page, related in pages:
                _need(path in files and path not in changed and path not in trial, 'report_path_conflict')
                trial[path] = _report(files[path], block, page, selected, related)
            return trial

        _need(len({op['target_column'] for op in operations}) == len(operations), 'ambiguous_display_target')
        accepted = operations
        try:
            trial = compose(operations)
        except (DisplayReportError, native_relations.RelationRenderError) as exc:
            if len(operations) == 1:
                gaps.append({'source_item_id': operations[0]['source_item_id'], 'reason': str(exc)})
                continue
            # Retain independent fields when one slot is already computed or
            # the combined query exceeds SQLcl's single-query text limit.
            trial, accepted = {}, []
            for op in operations:
                try:
                    next_files = compose([*accepted, op])
                except (DisplayReportError, native_relations.RelationRenderError) as single:
                    gaps.append({'source_item_id': op['source_item_id'], 'reason': str(single)})
                else:
                    accepted.append(op)
                    trial = next_files
        changed.update(trial)
        for op in accepted:
            applied.append({**op, 'page_files': list(trial), 'native_event_wired': False})
    receipt = {'scope': 'fox-saved-display-projection-v1', 'source_binding': plan['source_binding'],
               'applied': applied, 'gaps': plan['gaps'] + gaps,
               'changed_members': {p: {'before': _digest(files[p]), 'after': _digest(raw)} for p, raw in changed.items()},
               'runtime_verified': False, 'business_accepted': False}
    return {**files, **changed}, receipt
