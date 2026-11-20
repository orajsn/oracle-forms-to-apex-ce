"""Whole block predicates adapted to separately gated source query reports.

This is a read adapter, not block-wide filtering of the synthetic prototype.
Existing synthetic lookups, parent locks and drafts remain unchanged. The
assembler supplies its fresh structural trace and owns package validation.
"""
from copy import deepcopy
import hashlib
import json
import re

from forms2apex import native, native_contract
from forms2apex.native_buffer import _expand_groups
from .forms_behavior_plan import _source_objects, decode_control_entities
from .forms_order_rules import parse_order
from .forms_understanding_packet import _build

RULE_ID = 'fox.query.source-block-filter'
_IDENT = re.compile(r'[A-Z][A-Z0-9_$#]{0,127}\Z')
_RESERVED = set(('SELECT FROM WHERE AND OR NULL IS NOT IN JOIN ON AS GROUP BY '
                 'ORDER UNION ALL DISTINCT INSERT UPDATE DELETE CREATE DROP '
                 'ALTER INTO HAVING WITH FOR EXISTS CASE WHEN THEN ELSE END').split())
_TOKEN = re.compile(r"(?P<string>'(?:[^']|'')*')|(?P<number>[+-]?[0-9]+(?:\.[0-9]+)?)|"
                    r'(?P<word>[A-Za-z][A-Za-z0-9_$#]*)|(?P<symbol>[=.:])')


def _need(value, reason):
    if not value:
        raise ValueError('FILTER_' + reason)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _identifier(value):
    _need(type(value) is str and _IDENT.fullmatch(value) and value not in _RESERVED,
          'IDENTIFIER')
    return value


def _name(value):
    parts = value.strip().upper().split('.')
    _need(1 <= len(parts) <= 2, 'SOURCE_TABLE')
    return '.'.join(_identifier(p) for p in parts)


def parse_where_clause(raw):
    """Consume all of column = literal / :GLOBAL.name, joined only by AND.

    Functions, comments, column comparisons, form-item binds, alternate
    operators, quoted identifiers and trailing code stay unsupported.
    """
    _need(type(raw) is str and 0 < len(raw) <= 8192, 'CLAUSE_CAPACITY')
    text, decode = decode_control_entities(raw)
    tokens, pos = [], 0
    while pos < len(text):
        if text[pos].isspace():
            pos += 1
            continue
        match = _TOKEN.match(text, pos)
        _need(match is not None, 'CLAUSE_TOKEN')
        kind, value = match.lastgroup, match.group()
        if kind == 'word':
            value = value.upper()
        if kind == 'string':
            value = value[1:-1].replace("''", "'")
            _need(len(value) <= 4000 and not any(c in value for c in '&`')
                  and all(32 <= ord(c) != 127 and (not c.isspace() or c == ' ')
                          for c in value), 'LITERAL_CONTEXT')
        tokens.append((kind, value))
        _need(len(tokens) <= 256, 'CLAUSE_CAPACITY')
        pos = match.end()
    pos, terms = 0, []

    def take(kind, value=None):
        nonlocal pos
        _need(pos < len(tokens) and tokens[pos][0] == kind
              and (value is None or tokens[pos][1] == value), 'CLAUSE_SYNTAX')
        result = tokens[pos][1]
        pos += 1
        return result

    while True:
        column = _identifier(take('word'))
        take('symbol', '=')
        _need(pos < len(tokens), 'CLAUSE_SYNTAX')
        if tokens[pos] == ('symbol', ':'):
            take('symbol', ':')
            take('word', 'GLOBAL')
            take('symbol', '.')
            value = {'kind': 'global', 'name': _identifier(take('word'))}
        else:
            _need(tokens[pos][0] in ('string', 'number'), 'EQUALITY_VALUE')
            kind = tokens[pos][0]
            value = {'kind': kind, 'value': take(kind)}
        terms.append({'source_column': column, 'value': value})
        _need(len(terms) <= 16, 'CLAUSE_CAPACITY')
        if pos == len(tokens):
            break
        take('word', 'AND')
    return terms, decode


def _direct_fields(owner, target, objects, props):
    fields, omissions = [], []
    for item in objects.values():
        if item['kind'] != 'Item' or item['block_id'] != owner['id']:
            continue
        p = props[item['id']]
        try:
            _need(item.get('database_item') is True
                  and p.get('DatabaseItem', '').strip().lower() == 'true',
                  'NON_DATABASE_ITEM_NOT_PROJECTED')
            _need(item['module_id'] == owner['module_id']
                  and not p.get('Formula', '').strip()
                  and all(p.get(k, '').strip().upper() in ('', 'NONE')
                          for k in ('CalculateMode', 'CalculationMode', 'SummaryFunction')),
                  'DIRECT_NONCOMPUTED_FIELD_REQUIRED')
            dtype = {'CHAR': 'VARCHAR2', 'VARCHAR2': 'VARCHAR2',
                     'NUMBER': 'NUMBER', 'DATE': 'DATE'}.get(p.get('DataType', '').upper())
            found = [f for f in target['items'] if f['source_item_id'] == item['id']]
            _need(len(found) == 1, 'FIELD_NOT_UNIQUE')
            field = found[0]
            _need(dtype is not None and field.get('data_type') == dtype
                  and field.get('source_name') == item['name']
                  and field.get('database_bound') is True
                  and re.fullmatch(r'[A-Z][A-Z0-9_]{0,127}', field.get('column', '')),
                  'FIELD_TARGET_MISMATCH')
            source_name = _identifier((p.get('ColumnName', '').strip() or item['name']).upper())
            fields.append({'source_item_id': item['id'], 'source_column': source_name,
                           'column': field['column'], 'data_type': dtype,
                           'source_item_name': item['name']})
        except ValueError as exc:
            omissions.append({'source_item_id': item['id'], 'source_item_name': item['name'],
                              'reason': str(exc)})
    _need(0 < len(fields) <= 100 and len({f['source_column'] for f in fields}) == len(fields)
          and len({f['column'] for f in fields}) == len(fields), 'DIRECT_FIELDS_NOT_UNIQUE')
    for field in fields:
        declarations = [i for i in objects.values() if i['kind'] == 'Item'
            and i['block_id'] == owner['id'] and i.get('database_item') is True
            and (props[i['id']].get('ColumnName', '').strip() or i['name']).upper()
            == field['source_column']]
        _need(len(declarations) == 1, 'SOURCE_COLUMN_NOT_UNIQUE')
    return fields, omissions


def _rhs(value, globals_):
    if value['kind'] == 'global':
        return ':' + globals_[value['name']]
    if value['kind'] == 'number':
        return value['value']
    return "'" + value['value'].replace("'", "''") + "'"


def _app_item(name):
    return f'''appItem {name} (
    scope: app
    security {{
        sessionStateProtection: restricted
    }}
)
'''


def _report(page, fields, sql, label, omission_count):
    columns = '\n'.join(native._report_column(
        {'name': f['column'], 'label': f['source_item_name'], 'data_type': f['data_type'],
         'primary_key': False, 'nullable': True}, (i + 1) * 10) for i, f in enumerate(fields))
    displays = '\n'.join(f"            displayColumn {f['column']} (\n                sequence: {(i+1)*10}\n            )"
                         for i, f in enumerate(fields))
    indented_sql = '\n'.join('                ' + line for line in sql.splitlines())
    return f'''page {page} (
    name: {native._label(label)}
    alias: FOX_FILTER_{page}
    title: {native._label(label)}
    appearance {{
        pageTemplate: @/standard
        templateOptions: #DEFAULT#
    }}
    security {{
        authentication: required
        pageAccessProtection: argumentsMustHaveChecksum
    }}
    region scope (
        name: Source query scope
        type: staticContent
        source {{
            htmlCode: "Read-only source query adaptation. Original database reads are disabled until an administrator verifies the table, columns, access and trusted session globals. This filter applies only to this query screen. Existing reports, lookups, related records and drafts use synthetic demonstration data. {omission_count} source items are omitted from this query projection; see the conversion receipt. Forms query coordination and customer record saving remain unimplemented."
        }}
        layout {{
            sequence: 5
            slot: body
        }}
        appearance {{
            template: @/standard
            templateOptions: #DEFAULT#
        }}
    )
    region records (
        name: {native._label(label)}
        type: interactiveReport
        source {{
            location: localDatabase
            type: sqlQuery
            sqlQuery:
                ```sql
{indented_sql}
                ```
        }}
        layout {{
            sequence: 10
            slot: body
        }}
        appearance {{
            template: @/interactive-report
            templateOptions: #DEFAULT#
        }}
        searchBar {{
            includeSearchBar: true
            searchField: true
        }}
{columns}
        savedReport primary (
            visibility: primaryDefault
            view {{
                default: report
                rowsPerPage: 15
            }}
{displays}
        )
    )
)
'''


def apply_manifest_filters(documents, packet, chunks, trace, members):
    """Return native source read adapters and precise, partial scope receipts.

    No synthetic read paths, schema objects or lock targets are rewritten.
    Source reads have both a native region condition and an SQL predicate;
    missing trusted GLOBAL values never become an unrestricted source query.
    """
    fresh, fresh_chunks = _build(documents)
    _need(packet.get('source_binding') == fresh['source_binding']
          and packet.get('sources') == fresh['sources'] and chunks == fresh_chunks,
          'SOURCE_CHANGED')
    _need(trace.get('source_binding') == fresh['source_binding'], 'TRACE_SOURCE')
    _need(not any(re.fullmatch(r'pages/p\d+-fox_filter_\d+\.apx', n) for n in members),
          'ALREADY_ADAPTED')
    objects, props = _source_objects(documents, fresh)
    texts = {c['code_unit_id']: c for c in fresh_chunks}
    units = [u for s in fresh['sources'] for u in s['facts']['code_units']
             if u['source_attribute'] == 'WhereClause']
    _need(len(units) <= 100, 'OPERATION_CAPACITY')
    files, operations, gaps = dict(members), [], []
    occupied = {int(m[1]) for n in files if (m := re.fullmatch(r'pages/p(\d+)-[^/]+\.apx', n))}
    page = 8300
    for unit in units:
        try:
            owner = objects[unit['owner_id']]
            _need(owner['kind'] == 'Block' and owner['classification'] == 'database',
                  'DATABASE_BLOCK_REQUIRED')
            terms, decode = parse_where_clause(texts[unit['id']]['text'])
            targets = [b for b in trace['blocks'] if b['source_block_id'] == owner['id']]
            _need(len(targets) == 1, 'BLOCK_NOT_UNIQUE')
            target = targets[0]
            _need(target.get('source_module_id') == owner['module_id']
                  and target.get('classification') == 'database'
                  and target.get('name') == owner['name']
                  and target.get('report_file') in files
                  and re.fullmatch(r'FOX_NATIVE_[A-F0-9]+', target.get('table_name', '')),
                  'BLOCK_TARGET_MISMATCH')
            p = props[owner['id']]
            _need(p.get('QueryDataSourceType', '').strip().upper() == 'TABLE', 'TABLE_SOURCE_REQUIRED')
            table = _name(p.get('QueryDataSourceName', ''))
            fields, omissions = _direct_fields(owner, target, objects, props)
            by_column = {f['source_column']: f for f in fields}
            for term in terms:
                _need(term['source_column'] in by_column, 'PREDICATE_COLUMN_NOT_MAPPED')
                term.update(source_item_id=by_column[term['source_column']]['source_item_id'],
                            column=by_column[term['source_column']]['column'])
                dtype, kind = by_column[term['source_column']]['data_type'], term['value']['kind']
                _need((dtype == 'VARCHAR2' and kind in ('string', 'global'))
                      or (dtype == 'NUMBER' and kind == 'number'), 'PREDICATE_TYPE_NOT_PROVEN')
            global_names = sorted({t['value']['name'] for t in terms if t['value']['kind'] == 'global'})
            globals_ = {name: 'FOX_RG_G_' + _sha(_canonical([owner['module_id'], ['GLOBAL', name]]))[:20].upper()
                        for name in global_names}
            slug = _sha(_canonical([fresh['source_binding'], unit['id']]))[:20].upper()
            gate = 'FOX_FILTER_' + slug
            source_predicates = [t['source_column'] + ' = ' + _rhs(t['value'], globals_) for t in terms]
            synthetic_predicates = [t['column'] + ' = ' + _rhs(t['value'], globals_) for t in terms]
            guards = [f":{gate} = 'Y'"] + [':' + globals_[name] + ' IS NOT NULL' for name in global_names]
            sql = ('SELECT ' + ', '.join(f['source_column'] + ' AS ' + f['column'] for f in fields)
                   + '\nFROM ' + table + '\nWHERE ' + '\nAND '.join(source_predicates + guards))
            order_status = 'not_declared'
            order_raw = p.get('OrderByClause', '').strip()
            if order_raw:
                order_status = 'separate_unimplemented'
                try:
                    order, _ = decode_control_entities(order_raw)
                    sorts = parse_order(order)
                    _need(all(t['source_name'] in by_column for t in sorts), 'ORDER_COLUMN_NOT_MAPPED')
                    sql += '\nORDER BY ' + ', '.join(t['source_name'] + ' ' + t['direction'].upper()
                        + ' NULLS ' + t['nulls'].upper() for t in sorts)
                    order_status = 'adapted_on_source_screen_only'
                except ValueError:
                    pass
            while page in occupied:
                page += 1
            _need(page < 9000 and len(sql) <= 32767, 'OUTPUT_CAPACITY')
            label = native_contract._label(owner['name'] + ' source query')
            native._label(label)
            text = _report(page, fields, sql, label, len(omissions))
            condition = _expand_groups('''        serverSideCondition { type: expression
            language: plsql
            plsqlExpression: %s
        }
''' % json.dumps(':' + gate + " = 'Y'" + ''.join(' and :' + globals_[n] + ' is not null' for n in global_names)))
            text = text.replace('        savedReport primary (\n', condition + '        savedReport primary (\n', 1)
            report_file = target['report_file']
            old = files[report_file].decode()
            _need(old.endswith(')\n') and old.count('    region records (\n') == 1,
                  'NAVIGATION_ANCHOR_CHANGED')
            button = _expand_groups(f'''    button source-filter-{page} (
        buttonName: FOX_FILTER_{page}
        label: {native._label(label)}
        layout {{ sequence: {page}
            region: @records
            slot: rightOfInteractiveReportSearchBar
        }}
        appearance {{ buttonTemplate: @/text }}
        behavior {{ action: redirectThisApp
            target: {{ page: {page}
                clearCache: {page}
            }}
        }}
    )
''')
            app_path = 'shared-components/app-items.apx'
            app_text = files.get(app_path, b'').decode()
            for name in [gate] + list(globals_.values()):
                declaration = _app_item(name)
                if re.search(r'\bappItem\s+' + re.escape(name) + r'\b', app_text):
                    _need(app_text.count(declaration) == 1, 'EXISTING_APP_ITEM_NOT_RESTRICTED')
                else:
                    app_text += '\n' + declaration
            page_file = f'pages/p{page:05d}-fox_filter_{page}.apx'
            # Stage all validation before applying this unit's output.
            files[page_file] = text.encode()
            files[report_file] = (old[:-2] + button + ')\n').encode()
            files[app_path] = app_text.encode()
            occupied.add(page)
            operations.append({'operation_id': 'source-filter-' + slug.lower(),
                'kind': 'source_filtered_block_query', 'rule_id': RULE_ID,
                'source_unit_id': unit['id'], 'source_unit_sha256': unit['sha256'],
                'source_chunk_id': texts[unit['id']]['id'], 'source_owner_id': owner['id'],
                'source_module_id': owner['module_id'], 'source_table': table,
                'source_bindings': fields, 'projection_omissions': omissions,
                'source_projection_complete': not omissions, 'terms': terms, 'decode_receipt': decode,
                'global_bindings': [{'source_reference': ['GLOBAL', name], 'app_item': globals_[name],
                                     'trusted_provider_required': True} for name in global_names],
                'readiness_item': gate, 'source_query_sql': sql,
                'synthetic_predicate_sql': ' AND '.join(synthetic_predicates),
                'synthetic_predicate_applied': False, 'block_wide_filter_applied': False,
                'unfiltered_source_records_exposed': False, 'order_status': order_status,
                'page_id': page, 'page_file': page_file, 'report_files': [report_file],
                'generation_status': 'generated_wired_adapted', 'native_event_wired': True,
                'adaptation': 'Read-only source query adapter only. Existing report, lookup, relation and draft paths remain synthetic demonstrations; block-wide source query coordination is unimplemented.',
                'scope_status': 'partial_read_adapter', 'original_interface_enabled': False,
                'source_query_executed': False, 'customer_table_writes': False,
                'runtime_verified': False, 'business_accepted': False})
            page += 1
        except ValueError as exc:
            gaps.append({'source_unit_id': unit['id'], 'reason': str(exc)})
    receipt = {'schema_version': 1, 'scope': 'fox-source-filter-adapter-v1',
        'source_binding': fresh['source_binding'], 'generated_operations': operations, 'gaps': gaps,
        'block_wide_filter_applied': False, 'original_reads_enabled': False,
        'runtime_verified': False, 'business_accepted': False}
    receipt['receipt_sha256'] = _sha(_canonical(receipt))
    return files, deepcopy(receipt)
