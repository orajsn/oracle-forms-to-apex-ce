"""Bind a whole block-level create rule to literal initial values in one rate draft."""


def create_default_rule(packet, plan, receipt, contract, *, properties=None, parent_keys=()):
    """Return a source-bound initializer, or leave the existing policy gap intact."""
    mid, bid = contract['source_module_id'], contract['source_block_id']
    if not (packet['source_binding'] == plan['source_binding'] == receipt['source_binding']
            == contract['source_binding']):
        raise ValueError('Rate create-default source binding differs')
    if receipt['plan_sha256'] != plan['plan_sha256'] or receipt['trace_sha256'] != plan['trace_sha256']:
        raise ValueError('Rate create-default policy receipt differs')
    objects = (o for s in packet['sources'] for o in s['facts']['objects'])
    triggers = [o for o in objects if o['kind'] == 'Trigger' and o['module_id'] == mid
                and o['parent_id'] in (mid, bid) and (o['name'] or '').upper() == 'WHEN-CREATE-RECORD']
    if len(triggers) != 1 or triggers[0]['parent_id'] != bid:
        return None
    trigger = triggers[0]
    def inherits_source(oid):
        return any(
            (key.lower().startswith(('subclass', 'inherit')) or key == 'PropertyClass')
            and str(value).strip().lower() not in ('', 'false', 'no', 'none')
            for key, value in (properties or {}).get(oid, {}).items()
        )

    if any(inherits_source(oid) for oid in (mid,bid,trigger['id'])):
        return None
    matches = [op for op in plan['operations'] if op['source_event'] == 'WHEN-CREATE-RECORD'
               and op['source_owner_id'] == trigger['id'] and op['source_parent_id'] == bid
               and op['source_module_id'] == mid]
    if len(matches) != 1:
        return None
    op = matches[0]
    units = [unit for source in packet['sources'] for unit in source['facts']['code_units']
             if unit['owner_id'] == trigger['id']]
    if (len(units) != 1 or units[0]['source_attribute'] != 'TriggerText'
            or units[0]['id'] != op['source_unit_id'] or units[0]['sha256'] != op['source_unit_sha256']):
        return None
    proof = [r for r in receipt['generated_operations'] if r['operation_id'] == op['operation_id']
             and r['source_unit_id'] == op['source_unit_id'] and r['source_unit_sha256'] == op['source_unit_sha256']]
    if len(proof) != 1 or op['local_calls'] or not op['body']:
        return None
    for node in op['body']:
        if node['kind'] != 'assign' or node['target']['kind'] != 'field' or node['value']['kind'] != 'literal':
            return None
        item = node['target']['ref']
        if item in parent_keys or inherits_source(item):
            return None
    return op


def bind_create_fields(op, contract, bundle, numbers):
    """Admit the whole rule against the actual projected storage and pictures."""
    from .forms_rate_numbers import validate_numeric_value

    mid, bid = contract['source_module_id'], contract['source_block_id']
    all_fields = contract['fields'] + bundle['fields'] + (numbers['fields'] if numbers else [])
    fields = {f['source_item_id']: f for f in all_fields}
    assignments = []
    for node in op['body']:
        item = node['target']['ref']
        source, field = op['fields'][item], fields.get(item)
        if (not field or source['source_item_id'] != item or source['source_block_id'] != bid
                or source['source_module_id'] != mid or field['source_block_id'] != bid
                or field['source_module_id'] != mid or field.get('source_insert_allowed') is not True
                or field['data_type'] not in ('VARCHAR2', 'NUMBER') or source['data_type'] != field['data_type']
                or node['target']['data_type'] != field['data_type']):
            return None
        value, dtype = node['value']['value'], node['value']['data_type']
        if dtype == 'NULL':
            if value is not None:
                return None
        elif dtype == field['data_type'] == 'VARCHAR2' and isinstance(value, str):
            size = len(value.encode()) if field['length_semantics'] == 'BYTE' else len(value)
            if size > field['max_length'] or len(value.encode()) > 4000:
                return None
        elif dtype == field['data_type'] == 'NUMBER' and isinstance(value, str) and value:
            try:
                validate_numeric_value(value, field)
            except ValueError:
                return None
        else:
            return None
        assignments.append({'source_item_id':item,'source_name':field['source_name'],'column':field['column'],
                            'data_type':field['data_type'],'value':value})
    return {'scope': 'rate_new_draft_literal_initialization', 'source_event': 'WHEN-CREATE-RECORD',
            'synthetic_create_wired': True, 'original_forms_runtime_executed': False,
            'source_owner_id':op['source_owner_id'],'source_parent_id':bid,'source_binding':contract['source_binding'],
            'source_module_id':mid,'source_block_id':bid,'source_unit_id':op['source_unit_id'],
            'source_unit_sha256':op['source_unit_sha256'],'operation_id':op['operation_id'],
            'assignments':assignments,'original_writes':False}


def bind_rate_create_defaults(packet, plan, receipt, contract, bundle, *, properties=None, parent_keys=()):
    """Compatibility entry point for callers that have no numeric projection."""
    rule = create_default_rule(packet, plan, receipt, contract, properties=properties, parent_keys=parent_keys)
    return bind_create_fields(rule, contract, bundle, None) if rule else None


def literal_sql(assignment):
    value = assignment['value']
    if value is None:
        return 'null'
    if assignment['data_type'] == 'NUMBER':
        # Only decimal digits, an optional sign and decimal point were admitted.
        from decimal import Decimal
        from .forms_rate_numbers import _DECIMAL
        if not isinstance(value, str) or not _DECIMAL.fullmatch(value):
            raise ValueError('RATE_DEFAULT_NUMBER_LITERAL')
        return format(Decimal(value), 'f')
    # Keep each SQL literal below Oracle's literal bound even after UTF-16 escaping.
    pieces = []
    for offset in range(0, len(value), 250):
        raw = value[offset:offset+250].encode('utf-16-be').hex().upper()
        escaped = ''.join('\\' + raw[i:i+4] for i in range(0, len(raw), 4))
        pieces.append("to_char(unistr('" + escaped + "'))")
    return '||'.join(pieces) or 'null'


def effective_values(initializer):
    # Every expression has already been proven literal. Retain source order in
    # the receipt; subsequent assignments to the same item replace earlier ones.
    return {a['column']:literal_sql(a) for a in initializer['assignments']}


def create_sql(code, initializer, fields, contract, names, page, *, parent_launcher=False):
    """Extend only the known fresh-row INSERT. Reads of older rows are comparisons."""
    from . import forms_route_lookup_native as route
    from . import forms_rate_workspace as workspace
    from forms2apex import native_buffer

    values = effective_values(initializer)
    by_col = {f['column']:f for f in fields}
    if not set(values) <= set(by_col):
        raise ValueError('RATE_DEFAULT_FIELD_BINDING')
    assignments = {k:'l_init_'+k for k in values}
    declarations = []
    statements = []
    edits = [by_col[k] for k in values if by_col[k]['direct_edit_allowed']] if not parent_launcher else []
    for column, expression in values.items():
        declarations.append('l_init_'+column+' '+workspace._storage(by_col[column])+':='+expression+';')
    if edits:
        # Determine whether the operator actually edited the displayed field.
        # A new draft started from a saved preview must not inherit its old values.
        cols = ','.join(f['column'] for f in edits)
        previous = ','.join('l_before_'+f['column'] for f in edits)
        for f in edits:
            declarations.append('l_before_'+f['column']+' '+workspace._storage(f)+';')
        statements.extend([f'if :P{page}_ROW is not null then',
            f"select {cols} into {previous} from {names['draft_table']} where {route._row(contract,page,revision=True)};",
            f'elsif :P{page}_OPEN is not null then',
            f"select {cols} into {previous} from {names['saved_table']} where {workspace._saved_row(page)} and REVISION=to_number(:P{page}_SREV);",
            'else', *['l_before_'+f['column']+':=l_init_'+f['column']+';' for f in edits], 'end if;'])
    for f in edits:
        col=f['column'];prior='l_before_'+col;current='l_init_'+col
        if f['data_type'] == 'NUMBER':
            submitted = workspace._number_input(f, page)
            # Oracle IF treats NULL as unknown, so explicitly handle both
            # transitions between a number and NULL before choosing a default.
            statements.extend([f'if {prior}<>{submitted} or ({prior} is null and {submitted} is not null) '
                               f'or ({prior} is not null and {submitted} is null) then',
                               f'{current}:={submitted}; end if;',
                               f'{submitted}:={current};'])
            # Standalone Create already includes the parsed number in its INSERT.
            del assignments[col]
            continue
        submitted=f":P{page}_F{f['slot']}"
        declarations.append('l_edited_'+col+' number;')
        same=native_buffer._parent_match(prior,submitted)
        statements.extend([f'select case when {same} then 0 else 1 end into l_edited_{col} from dual;',
                           f'if l_edited_{col}=1 then',route._validate_value(f,submitted,required=False),f'{current}:={submitted};'])
        if col==contract['caller']['column'] and (contract.get('typed_lookup') or contract.get('typed_lookup_gap')):
            same=native_buffer._parent_match(current,values[col])
            statements.extend([f'select case when {same} then 0 else 1 end into l_edited_{col} from dual;',
                               f'if l_edited_{col}=1 then'])
            typed=contract.get('typed_lookup')
            if typed:
                for i,a in enumerate(typed['assignments'],1):
                    target=a['field']['column']
                    declarations.append(f'l_typed{i} varchar2(4000);')
                    if target not in assignments:
                        assignments[target]='l_init_'+target
                        declarations.append('l_init_'+target+' varchar2(4000);')
                statements.append(route._typed_read(typed,names['catalog_table'],current))
                statements.extend(f"{assignments[a['field']['column']]}:=l_typed{i};" for i,a in enumerate(typed['assignments'],1))
            else:
                statements.append("raise_application_error(-20031,'Caller POST-CHANGE is unresolved; nothing was applied.');")
            statements.append('end if;')
        statements.append('end if;')
    insert=f"insert into {names['draft_table']}("
    if not code.startswith('declare ') or code.count(insert)!=1:
        raise ValueError('RATE_DEFAULT_CREATE_ANCHOR')
    before, rest = code.split(insert)
    separator = ') values(' if parent_launcher else ')\nvalues('
    if separator not in rest:
        raise ValueError('RATE_DEFAULT_VALUES_ANCHOR')
    columns, rest = rest.split(separator, 1)
    if set(columns.split(',')) & assignments.keys():
        raise ValueError('RATE_DEFAULT_DUPLICATE_COLUMN')
    # The launcher has no numeric inputs. Standalone Create already contains them.
    # Keep the remaining assignments and parent keys in one atomic INSERT.
    before = before.replace('declare ', 'declare ' + '\n'.join(declarations) + '\n', 1)
    if assignments:
        columns = ','.join(assignments) + ',' + columns
        rest = ','.join(assignments.values()) + ',' + rest
    code = before + '\n'.join(statements) + '\n' + insert + columns + separator + rest
    if len(code.encode()) > 32767:
        raise ValueError('RATE_DEFAULT_CAPACITY')
    return code
