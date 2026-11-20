"""Closed source SELECT adaptation to gated native reference reports.

Pure generation only. The application caller supplies a freshly rebuilt trace;
original interfaces are disabled, and LOV selection/return is not implemented.
No source SQL is copied into output: only the complete parsed tree is rendered.
"""
from copy import deepcopy
import hashlib
import json
import re

from . import native, native_contract
from .native_buffer import _expand_groups

SCOPE = 'fox-native-record-groups-v1'
IDENT = re.compile(r'[A-Z][A-Z0-9_$#]{0,127}\Z')
RESERVED = set(('SELECT FROM WHERE AND OR IN IS NOT NULL ORDER BY ASC DESC AS '
                'DISTINCT ALL UNION INTERSECT MINUS JOIN ON WITH INTO UPDATE '
                'DELETE INSERT CREATE DROP ALTER FOR CONNECT START GROUP HAVING '
                'EXISTS CASE WHEN THEN ELSE END FETCH OFFSET ROWS').split())


def _need(value, reason):
    if not value:
        raise ValueError('RECORD_GROUP_' + reason)


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _literal(value):
    return "'" + value.replace("'", "''") + "'"


def _identifier(value):
    _need(type(value) is str and IDENT.fullmatch(value) and value not in RESERVED, 'IDENTIFIER')
    return value


def _label(value):
    """Validate text before native JSON quoting, including substitution guards."""
    text = native_contract._label(value)
    native._label(text)
    return text


def _lov_metadata(documents, packet):
    from fox import forms_facts
    result = {}
    for name, raw in documents:
        root, locations = forms_facts._safe_input(name, raw)
        nodes = {loc['path']: node for node, loc in zip(root.iter(), locations, strict=True)}
        source = next(entry for entry in packet['sources'] if entry['source']['name'] == name)
        for obj in source['facts']['objects']:
            if obj['kind'] != 'LOV': continue
            node = nodes[obj['location']['path']]
            returns = [{'source_column_name': child.get('Name'), 'return_item': child.get('ReturnItem')}
                       for child in node if forms_facts._local(child.tag) == 'LOVColumnMapping'
                       and (child.get('ReturnItem') or '').strip()]
            result[obj['id']] = {'source_lov_id': obj['id'], 'source_lov_name': obj['name'],
                                 'return_mappings': returns, 'lov_return_implemented': False}
    return result


def _tokens(text):
    tokens, pos = [], 0
    pattern = re.compile(r"(?P<string>'(?:[^']|'')*')|(?P<word>[A-Za-z][A-Za-z0-9_$#]*)|(?P<number>[0-9]+(?:\.[0-9]+)?)|(?P<symbol><>|[=.,:()])")
    while pos < len(text):
        if text[pos].isspace():
            pos += 1
            continue
        if text.startswith('--', pos):
            end = re.search(r'[\r\n]', text[pos + 2:])
            pos = len(text) if end is None else pos + 2 + end.start()
            continue
        if text.startswith('/*', pos):
            end = text.find('*/', pos + 2)
            _need(end >= 0 and '/*' not in text[pos + 2:end], 'COMMENT')
            pos = end + 2
            continue
        match = pattern.match(text, pos)
        _need(match is not None, 'ACTIVE_TOKEN')
        kind, value = match.lastgroup, match.group()
        if kind == 'word': value = value.upper()
        if kind == 'string':
            value = value[1:-1].replace("''", "'")
            # SQL quoting does not neutralize APEX substitutions or an
            # enclosing APEXlang fence. Keep those source literals as gaps.
            _need('`' not in value and '&' not in value and
                  all(ord(char) >= 32 and ord(char) != 127 and (not char.isspace() or char == ' ') for char in value), 'LITERAL_CONTEXT')
        _need(len(value) <= 4000, 'TOKEN_CAPACITY')
        tokens.append((kind, value))
        _need(len(tokens) <= 2048, 'TOKEN_CAPACITY')
        pos = match.end()
    return tokens


class _Parser:
    def __init__(self, tokens):
        self.tokens, self.pos, self.binds = tokens, 0, []

    def peek(self, value):
        return self.pos < len(self.tokens) and self.tokens[self.pos][0] != 'string' and self.tokens[self.pos][1] == value

    def take(self, value=None, kind=None):
        _need(self.pos < len(self.tokens), 'INCOMPLETE_QUERY')
        token = self.tokens[self.pos]
        _need((value is None or self.peek(value)) and (kind is None or token[0] == kind), 'QUERY_SYNTAX')
        self.pos += 1
        return token[1]

    def name(self):
        parts = [_identifier(self.take(kind='word'))]
        if self.peek('.'):
            self.take('.')
            parts.append(_identifier(self.take(kind='word')))
        return parts

    def operand(self):
        if self.peek(':'):
            self.take(':')
            parts = self.name()
            if parts not in self.binds: self.binds.append(parts)
            return {'kind': 'bind', 'parts': parts}
        if self.pos < len(self.tokens) and self.tokens[self.pos][0] in ('string', 'number'):
            kind, value = self.tokens[self.pos]
            self.pos += 1
            return {'kind': kind, 'value': value}
        return {'kind': 'column', 'parts': self.name()}

    def query(self, depth=0):
        _need(depth <= 3, 'QUERY_DEPTH')
        self.take('SELECT')
        projections = [self.name()]
        while self.peek(','):
            self.take(',')
            projections.append(self.name())
        self.take('FROM')
        tables = [self.name()]
        while self.peek(','):
            self.take(',')
            tables.append(self.name())
        self.take('WHERE')
        predicates = []
        while True:
            left = self.operand()
            if self.peek('IS'):
                self.take('IS')
                op = 'IS NOT NULL' if self.peek('NOT') else 'IS NULL'
                if self.peek('NOT'): self.take('NOT')
                self.take('NULL')
                predicate = {'left': left, 'op': op}
            elif self.peek('IN'):
                self.take('IN')
                self.take('(')
                child = self.query(depth + 1)
                _need(len(child['projections']) == 1, 'IN_PROJECTION')
                self.take(')')
                predicate = {'left': left, 'op': 'IN', 'query': child}
            else:
                _need(self.peek('=') or self.peek('<>'), 'PREDICATE_OPERATOR')
                predicate = {'left': left, 'op': self.take(), 'right': self.operand()}
            predicates.append(predicate)
            if not self.peek('AND'): break
            self.take('AND')
        order = []
        if depth == 0 and self.peek('ORDER'):
            self.take('ORDER')
            self.take('BY')
            while True:
                term = {'parts': self.name(), 'direction': None}
                if self.peek('ASC') or self.peek('DESC'): term['direction'] = self.take()
                order.append(term)
                if not self.peek(','): break
                self.take(',')
        _need(1 <= len(projections) <= 30 and len(tables) <= 8 and len(predicates) <= 40 and len(order) <= 6, 'QUERY_CAPACITY')
        return {'projections': projections, 'tables': tables, 'predicates': predicates, 'order': order}


def parse_record_group_query(raw):
    """Complete SELECT columns FROM tables WHERE conjunction [ORDER BY columns].

    Predicates: equality, inequality, null test, or IN a single-column filtered
    subquery. No functions, aliases, writes, DB links, unions or unknown suffix.
    Original case-insensitive identifiers and literal values retain SQL meaning.
    """
    from fox.forms_behavior_plan import decode_control_entities
    _need(type(raw) is str and 0 < len(raw) <= 32767, 'QUERY_CAPACITY')
    semantic, decode = decode_control_entities(raw)
    parser = _Parser(_tokens(semantic))
    query = parser.query()
    _need(parser.pos == len(parser.tokens), 'TRAILING_QUERY')
    return query, parser.binds, decode


def render_query(query, bindings, extra_predicates=()):
    """Render the parser's private tree with proven, generated bind providers."""
    def operand(value):
        kind = value['kind']
        if kind == 'bind': return bindings[tuple(value['parts'])]
        if kind == 'column': return '.'.join(value['parts'])
        if kind == 'string': return _literal(value['value'])
        if kind == 'number': return value['value']
        raise ValueError('RECORD_GROUP_OPERAND')
    predicates = []
    for pred in query['predicates']:
        text = operand(pred['left']) + ' ' + pred['op']
        if 'right' in pred: text += ' ' + operand(pred['right'])
        if 'query' in pred: text += ' (' + render_query(pred['query'], bindings) + ')'
        predicates.append(text)
    predicates.extend(extra_predicates)
    result = ('SELECT ' + ', '.join('.'.join(v) for v in query['projections']) + '\nFROM ' +
              ', '.join('.'.join(v) for v in query['tables']) + '\nWHERE ' + '\nAND '.join(predicates))
    if query['order']:
        result += '\nORDER BY ' + ', '.join('.'.join(v['parts']) + (' ' + v['direction'] if v['direction'] else '') for v in query['order'])
    return result


def _report(page, specs, source, *, label, link='', condition=''):
    columns = '\n'.join(native._report_column(spec, (i + 1) * 10) for i, spec in enumerate(specs))
    displays = '\n'.join(f"            displayColumn {s['name']} (\n                sequence: {(i+1)*10}\n            )" for i, s in enumerate(specs))
    return f'''page {page} (
    name: {native._label(label)}
    alias: FOX_GROUP_{page}
    title: {native._label(label)}
    appearance {{
        pageTemplate: @/standard
        templateOptions: #DEFAULT#
    }}
    security {{
        authentication: required
        pageAccessProtection: argumentsMustHaveChecksum
    }}
    region records (
        name: {native._label(label)}
        type: interactiveReport
{source}
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
{link}{columns}
        savedReport primary (
            visibility: primaryDefault
            view {{
                default: report
                rowsPerPage: 15
            }}
{displays}
        )
{condition}    )
)
'''


def _sql_source(query):
    return '        source {\n            location: localDatabase\n            type: sqlQuery\n            sqlQuery:\n                ```sql\n' + '\n'.join('                '+line for line in query.splitlines()) + '\n                ```\n        }'


def _append(text, fragment):
    _need(text.endswith(')\n'), 'PAGE_SHAPE')
    return text[:-2] + fragment + ')\n'


def _app_item(name):
    return f'''appItem {name} (
    scope: app
    security {{
        sessionStateProtection: restricted
    }}
)
'''


def _button(page, suffix, label):
    return _expand_groups(f'''    button record-group-{suffix} (
        buttonName: FOX_GROUP_{suffix}
        label: {native._label(label)}
        layout {{ sequence: {900+suffix}
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


def apply_record_groups(documents, packet, chunks, trace, members):
    """Return copied members and one receipt entry per actually emitted query.

    Fresh original packet and chunks are checked here. The integration caller
    owns rebuilding the native baseline/trace and the normal package gates.
    A separate synthetic-row chooser preserves existing per-row navigation.
    """
    from fox.forms_understanding_packet import _build
    from fox.forms_behavior_plan import _source_objects
    fresh, fresh_chunks = _build(documents)
    _need(packet.get('source_binding') == fresh['source_binding'] and
          packet.get('sources') == fresh['sources'] and chunks == fresh_chunks, 'SOURCE_CHANGED')
    _need(trace.get('source_binding') == fresh['source_binding'], 'TRACE_SOURCE')
    _need(not any(re.fullmatch(r'pages/p\d+-(?:fox_group_\d+|record-group(?:-context)?)\.apx', name) for name in members), 'ALREADY_ADAPTED')
    objects, properties = _source_objects(documents, fresh)
    lov_metadata = _lov_metadata(documents, fresh)
    texts = {row['code_unit_id']: row for row in fresh_chunks}
    files, operations, gaps = dict(members), [], []
    occupied = {int(m[1]) for name in files if (m := re.fullmatch(r'pages/p(\d+)-[^/]+\.apx', name))}
    page = 8000
    units = [u for entry in fresh['sources'] for u in entry['facts']['code_units'] if u['source_attribute'] == 'RecordGroupQuery']
    _need(len(units) <= 100, 'OPERATION_CAPACITY')
    for unit in units:
        try:
            owner = objects[unit['owner_id']]
            _need(owner['kind'] == 'RecordGroup', 'SOURCE_OWNER')
            _need(properties[owner['id']].get('RecordGroupType', 'Query').upper() == 'QUERY', 'SOURCE_TYPE')
            associated_lovs = [obj for obj in objects.values() if obj['kind'] == 'LOV' and
                obj['module_id'] == owner['module_id'] and
                (properties[obj['id']].get('RecordGroupName') or '').upper() == (owner['name'] or '').upper()]
            titles = {properties[obj['id']].get('Title', '').strip() for obj in associated_lovs} - {''}
            try:
                label = _label(next(iter(titles))) if len(titles) == 1 else _label(owner['name'])
            except ValueError:
                label = _label(owner['name'])
            lovs = [deepcopy(lov_metadata[obj['id']]) for obj in associated_lovs]
            returns = sum(len(lov['return_mappings']) for lov in lovs)
            query, refs, decode = parse_record_group_query(texts[unit['id']]['text'])
            bindings, item_refs, global_refs = [], [], []
            for ref in refs:
                if len(ref) == 2 and ref[0] == 'GLOBAL':
                    name = 'FOX_RG_G_' + _sha(_json([owner['module_id'], ref]))[:20].upper()
                    global_refs.append({'source_reference': ref, 'app_item': name, 'trusted_provider_required': True})
                    continue
                matches = [o for o in objects.values() if o['kind'] == 'Item' and o['module_id'] == owner['module_id']
                    and (o['name'] or '').upper() == ref[-1] and (len(ref) == 1 or (objects[o['block_id']]['name'] or '').upper() == ref[0])]
                _need(len(matches) == 1, 'SOURCE_BIND_NOT_UNIQUE')
                item = matches[0]
                mapped = [(b, f) for b in trace['blocks'] for f in b.get('items', []) if f['source_item_id'] == item['id']]
                _need(len(mapped) == 1, 'SOURCE_BIND_NOT_MAPPED')
                block, field = mapped[0]
                _need(block['source_block_id'] == item['block_id'] and block.get('source_module_id') == owner['module_id'] and
                      block.get('classification') == 'database' and block.get('report_file') in files and
                      field.get('source_name') == item['name'] and field.get('data_type') in ('VARCHAR2', 'NUMBER', 'DATE'), 'SOURCE_BIND_PROVIDER')
                _identifier(block['table_name'])
                _need(block['table_name'].startswith('FOX_NATIVE_'), 'SYNTHETIC_PROVIDER_REQUIRED')
                _identifier(field['column'])
                item_refs.append({'source_reference': ref, 'source_item_id': item['id'], 'source_block_id': item['block_id'],
                                  'source_item_name': _label(item['name']), 'column': field['column'], 'data_type': field['data_type']})
                bindings.append(block)
            # One explicitly selected source row; cross-block contexts remain gaps.
            _need(len({b['source_block_id'] for b in bindings}) <= 1, 'CROSS_BLOCK_CONTEXT')
            context = bindings[0] if bindings else None
            if context is None:
                candidates = [b for b in trace['blocks'] if b.get('classification') == 'database' and b.get('source_module_id') == owner['module_id'] and b.get('report_file') in files]
                _need(len(candidates) == 1, 'NAVIGATION_CONTEXT_NOT_UNIQUE')
                context = candidates[0]
            children = [o for o in objects.values() if o['kind'] == 'RecordGroupColumn' and o['parent_id'] == owner['id']]
            _need(len(children) == len(query['projections']), 'SOURCE_COLUMNS')
            specs = []
            for child, projection in zip(children, query['projections']):
                _need((child['name'] or '').upper() == projection[-1], 'SOURCE_COLUMN_ORDER')
                name = _identifier(projection[-1])
                dtype = {'CHARACTER': 'VARCHAR2', 'NUMBER': 'NUMBER', 'DATE': 'DATE'}.get(properties[child['id']].get('ColumnDataType', '').upper())
                _need(dtype is not None and name not in {s['name'] for s in specs}, 'SOURCE_COLUMN_TYPE')
                specs.append({'name': name, 'label': name, 'data_type': dtype, 'primary_key': False, 'nullable': True})
            while page in occupied or page + 1 in occupied: page += 2
            _need(page + 1 < 9000, 'PAGE_CAPACITY')
            chooser, result = page, page + 1
            page += 2
            slug = _sha(_json([fresh['source_binding'], unit['id']]))[:20].upper()
            gate = 'FOX_RG_' + slug
            item = f'P{result}_ROW_ID'
            replacements = {tuple(b['source_reference']): ':'+b['app_item'] for b in global_refs}
            for binding in item_refs:
                replacements[tuple(binding['source_reference'])] = f"(SELECT FOX_RG_CTX.{binding['column']} FROM {context['table_name']} FOX_RG_CTX WHERE FOX_RG_CTX.FOX_ROW_ID = :{item})"
            guards = [f"EXISTS (SELECT 1 FROM {context['table_name']} FOX_RG_CTX WHERE FOX_RG_CTX.FOX_ROW_ID = :{item})", f"NVL(V('{gate}'), 'N') = 'Y'"]
            sql = render_query(query, replacements, guards)
            _need(len(sql) <= 32767, 'RENDER_CAPACITY')
            condition = _expand_groups(f'''        serverSideCondition {{ type: expression
            language: plsql
            plsqlExpression: {json.dumps("nvl(v('"+gate+"'),'N')='Y' and :"+item+" is not null")}
        }}
''')
            result_text = _report(result, specs, _sql_source(sql), label=label, condition=condition)
            scope = '''    region scope (
        name: Query adaptation scope
        type: staticContent
        source {
            htmlCode: "Read-only source query adaptation. Original database reads are disabled until an administrator verifies the interface and configures trusted session globals. Choose a synthetic source row to supply filter values. LOV field selection and return remain unimplemented. This page saves no customer records."
        }
        layout {
            sequence: 5
            slot: body
        }
        appearance {
            template: @/standard
            templateOptions: #DEFAULT#
        }
    )
'''
            if returns:
                scope = scope.replace('This page saves no customer records.', f'{returns} explicit source LOV return mappings remain unimplemented. This page saves no customer records.')
            result_text = _append(result_text, scope + _expand_groups(f'''    process validate-source-row (
        name: Validate selected synthetic source row
        type: executeCode
        source {{ plsqlCode:
                ```plsql
                declare l_count number;
                begin
                  if :{item} is not null then
                    select count(*) into l_count from {context['table_name']} where FOX_ROW_ID = :{item};
                    if l_count <> 1 then raise_application_error(-20002, 'Selected synthetic source row is unavailable.'); end if;
                  end if;
                end;
                ```
        }}
        execution {{ sequence: 10
            point: beforeHeader
        }}
    )
    pageItem {item} (
        type: hidden
        layout {{ sequence: 10
            region: @records
            slot: regionBody
        }}
        sessionState {{ storage: session
            dataType: number
        }}
        security {{ sessionStateProtection: checksumRequiredSessionLevel }}
    )
'''))
            # This independent chooser owns its link; the original report's
            # Edit/Lookup/validation navigation is preserved byte for byte.
            chooser_specs = [{'name': 'FOX_ROW_ID', 'label': 'Prototype record identity', 'data_type': 'NUMBER', 'primary_key': True, 'nullable': False}]
            chooser_specs += [{'name': b['column'], 'label': b['source_item_name'], 'data_type': b['data_type'], 'primary_key': False, 'nullable': True} for b in item_refs]
            chooser_specs = list({s['name']: s for s in chooser_specs}.values())
            link = _expand_groups(f'''        link {{ linkColumn: customTarget
            target: {{ page: {result}
                clearCache: {result}
                items: {{ {item}: "#FOX_ROW_ID#" }}
            }}
            linkIcon: Reference choices
        }}
''')
            chooser_source = '        source {\n            location: localDatabase\n            type: tableView\n            tableName: '+context['table_name']+'\n        }'
            chooser_text = _append(_report(chooser, chooser_specs, chooser_source, label='Choose source row: '+label, link=link), scope)
            report_file = context['report_file']
            parent = files[report_file].decode('utf8')
            _need(parent.startswith(f"page {context['report_page_id']} (\n") and parent.count('    region records (\n') == 1, 'NAVIGATION_PAGE')
            result_file = f'pages/p{result:05d}-fox_group_{result}.apx'
            chooser_file = f'pages/p{chooser:05d}-fox_group_{chooser}.apx'
            files[report_file] = _append(parent, _button(chooser, len(operations)+1, label)).encode()
            files[result_file], files[chooser_file] = result_text.encode(), chooser_text.encode()
            occupied.update((chooser, result))
            app_name = 'shared-components/app-items.apx'
            app_text = files.get(app_name, b'').decode()
            for name in [gate] + [b['app_item'] for b in global_refs]:
                if f'appItem {name} (' not in app_text: app_text += '\n' + _app_item(name)
            files[app_name] = app_text.encode()
            operations.append({'operation_id': 'record-group-'+slug.lower(), 'kind': 'record_group_reference_report',
                'source_unit_id': unit['id'], 'source_unit_sha256': unit['sha256'], 'source_chunk_id': texts[unit['id']]['id'],
                'source_owner_id': owner['id'], 'source_module_id': owner['module_id'], 'query': query, 'decode_receipt': decode,
                'source_kind': owner['kind'], 'source_attribute': unit['source_attribute'], 'route_label': label,
                'associated_lovs': lovs, 'unimplemented_lov_return_mapping_count': returns,
                'warnings': ['explicit_source_lov_return_mappings_unimplemented'] if returns else [],
                'source_bindings': item_refs, 'global_bindings': global_refs, 'readiness_item': gate,
                'page_file': result_file, 'page_id': result, 'chooser_file': chooser_file, 'chooser_page_id': chooser,
                'report_files': [report_file], 'generation_status': 'generated_wired_adapted', 'native_event_wired': True,
                'adaptation': 'Explicit synthetic-row selection and read-only reference query; LOV field selection/return is unimplemented.',
                'lov_return_implemented': False, 'original_interface_enabled': False, 'source_query_executed': False,
                'customer_table_writes': False, 'oracle_compiled': False, 'runtime_verified': False, 'business_accepted': False})
        except ValueError as exc:
            gaps.append({'source_unit_id': unit['id'], 'reason': str(exc)})
    receipt = {'schema_version': 1, 'scope': SCOPE, 'source_binding': fresh['source_binding'],
        'generated_operations': operations, 'gaps': gaps, 'original_reads_enabled': False,
        'lov_return_implemented': False, 'runtime_verified': False, 'business_accepted': False}
    receipt['receipt_sha256'] = _sha(_json(receipt))
    return files, deepcopy(receipt)
