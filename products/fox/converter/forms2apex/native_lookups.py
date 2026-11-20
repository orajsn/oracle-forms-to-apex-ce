"""Source-backed read lookup events; original interfaces are disabled by default.

Only closed parsed SELECT IR is emitted. No original query, Oracle import or target
activation occurs here. The owning assembler must rebuild from original XML.
"""
from collections import defaultdict
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

from .source_lookup import validate_lookup_plan
from . import native_project
from .native_buffer import _expand_groups

SCOPE = 'fox-native-source-lookups-v1'


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _json(v):
    return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()


def _need(v,code):
    if not v:raise ValueError('LOOKUP_'+code)


def _slug(op):
    return _sha(_json(op))[:20].upper()


def gate_name(op):
    return 'FOX_LKP_'+_slug(op)


def _request(op):
    return 'FOX_LOOKUP_'+_slug(op)


def _item(page,binding):
    return f"P{page}_{binding['column']}"


def _literal(value):
    return "'"+value.replace("'","''")+"'"


def _indent(text,n=16):
    return '\n'.join(' '*n+line for line in text.splitlines())


def _query(op,inputs,outputs):
    def operand(v):
        if v['kind']=='column':return '.'.join(v['parts'])
        if v['kind']=='bind':return inputs[v['source_item_id']]
        if v['kind']=='string':return _literal(v['value'])
        if v['kind']=='number':return v['value']
        raise ValueError('LOOKUP_QUERY_OPERAND')
    query=op['query']
    return ('SELECT '+', '.join('.'.join(p['parts']) for p in query['projections'])+
            '\nINTO '+', '.join(outputs[p['output_item_id']] for p in query['projections'])+
            '\nFROM '+', '.join('.'.join(t['parts']) for t in query['tables'])+
            '\nWHERE '+' AND '.join(operand(p['left'])+' = '+operand(p['right']) for p in query['predicates'])+';')


def _datatype(b):
    if b['data_type']=='NUMBER':return 'NUMBER'
    unit='BYTE' if b['source_length_semantics']=='BYTE' else 'CHAR'
    return f"VARCHAR2({b['max_length']} {unit})"


def _block_label(op):
    # SQL gives table columns precedence over bare PL/SQL variable names.
    # A block-qualified bind cannot be captured by a source column; keep the
    # generated qualifier distinct from every retained table qualification.
    names={part.upper() for t in op['query']['tables'] for part in t['parts']}
    label='LKP_'+_slug(op)
    while label.upper() in names:
        label+='X'
    _need(len(label)<=30,'BLOCK_LABEL_CAPACITY')
    return label


def _source_body(op,page):
    inputs={b['source_item_id']:f'l_input_{i}' for i,b in enumerate(op['input_bindings'],1)}
    outputs={b['source_item_id']:f'l_output_{i}' for i,b in enumerate(op['output_bindings'],1)}
    declarations=[f"{inputs[b['source_item_id']]} {_datatype(b)};" for b in op['input_bindings']]
    declarations += [f"{outputs[b['source_item_id']]} {_datatype(b)};" for b in op['output_bindings']]
    initialize=[]
    for b in op['input_bindings']:
        name=_item(page,b)
        value=':'+name
        # Changed-item casing is confined to explicit lookup submissions. A
        # fetched read-only field is reread unchanged in the outer context guard.
        changed=op['source_event']=='POST-CHANGE' and b['source_item_id']==op['event_item_id']
        if changed and b['case_restriction']!='NONE':
            allowed=(b['source_update_allowed'] is not False and op['target']['source_update_allowed'] is not False)
            condition='true' if allowed else f':P{page}_FOX_ROW_ID is null'
            initialize.append(f"if {condition} then {value} := {b['case_restriction'].lower()}({value}); end if;")
        if b['data_type']=='VARCHAR2':
            fn='lengthb' if b['source_length_semantics']=='BYTE' else 'length'
            initialize.append(f"if nvl({fn}({value}),0)>{b['max_length']} then raise_application_error(-20003,'Lookup input exceeds its source field limit.'); end if;")
        initialize.append(inputs[b['source_item_id']]+' := '+value+';')
    assignments=[f":{_item(page,b)} := {outputs[b['source_item_id']]};" for b in op['output_bindings']]
    by_id={b['source_item_id']:b for b in op['output_bindings']}
    resets=[f":{_item(page,by_id[uid])} := NULL;" for uid in op['reset_order']]
    label=_block_label(op)
    sql_inputs={key:label+'.'+value for key,value in inputs.items()}
    sql_outputs={key:label+'.'+value for key,value in outputs.items()}
    return ('<<'+label+'>>\ndeclare\n'+'\n'.join(declarations)+'\nbegin\n'+_guard(op,page)+'\n'+'\n'.join(initialize)+
            '\nbegin\n'+_query(op,sql_inputs,sql_outputs)+'\n'+'\n'.join(assignments)+
            '\nexception when '+op['exception_kind']+' then\n'+'\n'.join(resets)+'\nend;\nend;')


def _new_input_eligible(op):
    # Only the event item has an editable provider on this standalone page.
    # Other inputs are authoritative only after loading an existing row; source
    # InsertAllowed alone does not supply their values on a new lookup draft.
    return (op['source_event']=='POST-CHANGE'
            and op['target']['source_insert_allowed'] is not False
            and bool(op['input_bindings'])
            and all(b['source_item_id']==op['event_item_id']
                    and b['source_insert_allowed'] is not False for b in op['input_bindings']))


def _guard(op,page):
    table=op['target']['table']
    code=f"if nvl(v('{gate_name(op)}'),'N')<>'Y' then raise_application_error(-20001,'This source lookup interface has not been verified and enabled.'); end if;"
    if op['source_event']=='POST-QUERY':
        code+=f"\nif :P{page}_FOX_ROW_ID is null then raise_application_error(-20002,'An existing source row is required.'); end if;"
    # Context and immutable source field policies sit OUTSIDE the original
    # exception handler, so WHEN OTHERS cannot hide a binding/policy failure.
    code+=f"\nif :P{page}_FOX_ROW_ID is not null then\n  declare n number; begin select count(*) into n from {table} where FOX_ROW_ID=:P{page}_FOX_ROW_ID; if n<>1 then raise_application_error(-20002,'Lookup record is unavailable.'); end if; end;\nend if;"
    if op['source_event']=='POST-CHANGE':
        if not _new_input_eligible(op):
            code+=f"\nif :P{page}_FOX_ROW_ID is null then raise_application_error(-20004,'This source lookup requires an existing record to supply its input values.'); end if;"
        for b in op['input_bindings']:
            editable=b['source_item_id']==op['event_item_id']
            can_update=editable and b['source_update_allowed'] is not False and op['target']['source_update_allowed'] is not False
            if not can_update:
                code+=f"\nif :P{page}_FOX_ROW_ID is not null then SELECT {b['column']} INTO :{_item(page,b)} FROM {table} WHERE FOX_ROW_ID=:P{page}_FOX_ROW_ID; end if;"
    return code


def _condition(op,page,*,render=False):
    guard=f"nvl(v('{gate_name(op)}'),'N') = 'Y'"
    if op['source_event']=='POST-QUERY':return guard+f" and :P{page}_FOX_ROW_ID is not null and :REQUEST is null"
    if not _new_input_eligible(op):guard+=f" and :P{page}_FOX_ROW_ID is not null"
    return guard if render else guard+f" and :REQUEST = '{_request(op)}'"


def _process(op,page):
    point='beforeHeader' if op['source_event']=='POST-QUERY' else 'processing'
    return f'''    process lookup-source (
        name: Source lookup
        type: executeCode
        source {{ plsqlCode:
                ```plsql
{_indent(_source_body(op,page))}
                ```
        }}
        execution {{ sequence: 30
            point: {point}
        }}
        serverSideCondition {{ type: expression
            language: plsql
            plsqlExpression: {json.dumps(_condition(op,page))}
        }}
    )
'''


def _items(op,page):
    fields=op['input_bindings']+op['output_bindings']
    specs=[{'name':'FOX_ROW_ID','data_type':'NUMBER','label':'Prototype record identity','primary_key':True,'nullable':True,'length':22}]
    specs += [{'name':b['column'],'data_type':b['data_type'],'label':b['source_item_name'],
               'primary_key':False,'nullable':not b['required'],'length':b['max_length'] or 22} for b in fields]
    rendered=[]
    inputs={b['source_item_id'] for b in op['input_bindings']}
    for i,spec in enumerate(specs):
        text=native_project._item(spec,(i+1)*10,page)
        _need(text.endswith('    )'),'ITEM_TEMPLATE')
        text=text[:-5]+f'''        sessionState {{ storage: request
            dataType: {'number' if spec['data_type']=='NUMBER' else 'varchar2'}
        }}
'''+text[-5:]
        if i:
            b=fields[i-1]
            if b['data_type']=='VARCHAR2':
                anchor='        type: textField\n'
                _need(text.count(anchor)==1,'TEXT_ITEM_TEMPLATE')
                text=text.replace(anchor,anchor+'        settings { trimSpaces: none }\n',1)
            case_style=''
            if b['data_type']=='VARCHAR2' and b['case_restriction']!='NONE':
                transform='uppercase' if b['case_restriction']=='UPPER' else 'lowercase'
                attrs=json.dumps('style="text-transform:'+transform+'"')
                text=text[:-5]+f'        advanced {{ customAttributes: {attrs} }}\n'+text[-5:]
                case_style=f'            readOnlyHtmlAttributes: {attrs}\n'
            editable=b['source_item_id'] in inputs and op['source_event']=='POST-CHANGE' and b['source_item_id']==op['event_item_id']
            if not editable:readonly='true'
            else:
                conditions=[f"nvl(v('{gate_name(op)}'),'N')<>'Y'"]
                if b['source_update_allowed'] is False or op['target']['source_update_allowed'] is False:conditions.append(f':P{page}_FOX_ROW_ID is not null')
                if not _new_input_eligible(op):conditions.append(f':P{page}_FOX_ROW_ID is null')
                readonly=' or '.join(conditions)
            text=text[:-5]+f'''        readOnly {{ type: expression
            language: plsql
            plsqlExpression: {json.dumps(readonly)}
{case_style}        }}
'''+text[-5:]
        rendered.append(text)
    return '\n'.join(rendered)


def _scope_region(op):
    return f'''    region lookup-scope (
        name: Lookup scope
        type: staticContent
        source {{ htmlCode:
                ```html
                <p>This page implements a source lookup on a synthetic record or a new lookup input. It does not save a record. Original database interfaces must be verified and enabled by an administrator before the lookup runs. Existing source field edit restrictions are retained. Change events use an explicit Apply lookup action.</p>
                ```
        }}
        layout {{ sequence: 5
            slot: body
        }}
        appearance {{ template: @/standard
            templateOptions: #DEFAULT#
        }}
    )
    region lookup-pending (
        name: Database lookup awaiting connection
        type: staticContent
        source {{ htmlCode:
                ```html
                <p>The generated source lookup is currently disabled. Review and verify its original database interface before enabling it.</p>
                ```
        }}
        layout {{ sequence: 6
            slot: body
        }}
        appearance {{ template: @/standard
            templateOptions: #DEFAULT#
        }}
        serverSideCondition {{ type: expression
            language: plsql
            plsqlExpression: {json.dumps("nvl(v('"+gate_name(op)+"'),'N')<>'Y'")}
        }}
    )
'''


def _page(op,page,menu):
    action=''
    if op['source_event']=='POST-CHANGE':
        action=f'''    button apply-lookup (
        buttonName: {_request(op)}
        label: Apply lookup
        layout {{ sequence: 10
            region: @record
            slot: create
        }}
        appearance {{ buttonTemplate: @/text }}
        behavior {{ action: submitPage
            executeValidations: false
            warnOnUnsavedChanges: doNotCheck
        }}
        serverSideCondition {{ type: expression
            language: plsql
            plsqlExpression: {json.dumps(_condition(op,page,render=True))}
        }}
    )
'''
    # A source POST-QUERY is coupled to an actual existing-row fetch. It is not
    # repeated on an Apply lookup submit or on a new lookup-criteria draft.
    initialize=f'''    process initialize-record (
        name: Load synthetic record
        type: formInitialization
        formRegion: @record
        execution {{ sequence: 10
            point: beforeHeader
        }}
        serverSideCondition {{ type: expression
            language: plsql
            plsqlExpression: ":REQUEST is null"
        }}
    )
'''
    return _expand_groups(f'''page {page} (
    name: Source lookup
    alias: FOX_LOOKUP_{page}
    title: Source lookup
    appearance {{ pageTemplate: @/standard
        templateOptions: #DEFAULT#
    }}
    security {{ authentication: required
        pageAccessProtection: argumentsMustHaveChecksum
    }}
{_scope_region(op)}    region record (
        name: Lookup values
        type: form
        source {{ location: localDatabase
            type: tableView
            tableName: {op['target']['table']}
        }}
        layout {{ sequence: 10
            slot: body
        }}
        appearance {{ template: @/standard
            templateOptions: #DEFAULT#
        }}
    )
{_items(op,page)}
{initialize}{_process(op,page)}{action}    button back (
        buttonName: BACK
        label: Back to record lookups
        layout {{ sequence: 20
            region: @record
            slot: previous
        }}
        appearance {{ buttonTemplate: @/text }}
        behavior {{ action: redirectThisApp
            target: {{ page: {menu}
                items: {{ P{menu}_ROW_ID: "&P{page}_FOX_ROW_ID." }}
            }}
        }}
    )
)
''')


def _menu(block_ops,menu,pages):
    buttons=[]
    for i,op in enumerate(block_ops,1):
        page=pages[op['operation_id']]
        label=', '.join(b['source_item_name'] for b in op['output_bindings'])
        cond='' if _new_input_eligible(op) else f'''        serverSideCondition {{ type: itemIsNotNull
            item: P{menu}_ROW_ID
        }}
'''
        buttons.append(f'''    button lookup-{i} (
        buttonName: LOOKUP_{i}
        label: {json.dumps('Look up '+label)}
        layout {{ sequence: {i*10}
            region: @lookups
            slot: regionBody
        }}
        appearance {{ buttonTemplate: @/text }}
        behavior {{ action: redirectThisApp
            target: {{ page: {page}
                clearCache: {page}
                items: {{ P{page}_FOX_ROW_ID: "&P{menu}_ROW_ID." }}
            }}
        }}
{cond}    )
''')
    return _expand_groups(f'''page {menu} (
    name: Record lookups
    alias: FOX_LOOKUPS_{menu}
    title: Record lookups
    appearance {{ pageTemplate: @/standard
        templateOptions: #DEFAULT#
    }}
    security {{ authentication: required
        pageAccessProtection: argumentsMustHaveChecksum
    }}
    region lookups (
        name: Available source lookups
        type: staticContent
        source {{ htmlCode: "Choose a generated lookup. These actions do not save customer records. Original database connections must be verified before use." }}
        layout {{ sequence: 10
            slot: body
        }}
        appearance {{ template: @/standard
            templateOptions: #DEFAULT#
        }}
    )
    pageItem P{menu}_ROW_ID (
        type: hidden
        layout {{ sequence: 10
            region: @lookups
            slot: regionBody
        }}
        sessionState {{ storage: request
            dataType: number
        }}
        security {{ sessionStateProtection: checksumRequiredSessionLevel }}
    )
{''.join(buttons)})
''')


def _gate_item(op):
    return _expand_groups(f'''appItem {gate_name(op)} (
    scope: app
    security {{ sessionStateProtection: restricted
    }}
)
''')


def _link(text,menu):
    _need(text.count('    region records (\n')==1 and text.count('        type: interactiveReport\n')==1,'REPORT_SHAPE')
    _need(not re.search(r'^        link \{',text,re.M),'REPORT_LINK_CAPACITY')
    anchor='        column ';_need(anchor in text,'REPORT_COLUMNS')
    at=text.index(anchor)
    fragment=_expand_groups(f'''        link {{
            linkColumn: customTarget
            target: {{ page: {menu}
                clearCache: {menu}
                items: {{ P{menu}_ROW_ID: "#FOX_ROW_ID#" }}
            }}
            linkIcon: Lookups
        }}
''')
    return text[:at]+fragment+text[at:]


def _new_input_link(menu):
    return _expand_groups(f'''    button new-lookup-input (
        buttonName: FOX_NEW_LOOKUP_INPUT
        label: New lookup input
        layout {{ sequence: 100
            region: @records
            slot: rightOfInteractiveReportSearchBar
        }}
        appearance {{ buttonTemplate: @/text }}
        behavior {{ action: redirectThisApp
            target: {{ page: {menu}
                clearCache: {menu}
            }}
        }}
    )
''')


def render_lookup_package(parent_zip,plan):
    plan=validate_lookup_plan(plan)
    _need(type(parent_zip) is bytes and _sha(parent_zip)==plan['parent_zip_sha256'],'PARENT_CHANGED')
    _need(len(parent_zip)<=32*1024*1024,'PARENT_SIZE')
    with zipfile.ZipFile(io.BytesIO(parent_zip)) as z:
        infos=z.infolist();names=[i.filename for i in infos]
        _need(len(names)<=4096 and len(names)==len({n.casefold() for n in names}),'MEMBERS')
        _need(sum(i.file_size for i in infos)<=64*1024*1024,'EXPANSION')
        for i in infos:
            n=i.filename
            _need(not PurePosixPath(n).is_absolute() and '..' not in PurePosixPath(n).parts
                  and chr(92) not in n and ':' not in n and not stat.S_ISLNK(i.external_attr>>16)
                  and not n.startswith('fox-package/lookup-'),'PARENT_PATH')
        files={i.filename:z.read(i) for i in infos}
    for member,key in (('fox-package/source-manifest.json','source_manifest_sha256'),('fox-package/source-to-page.json','parent_trace_sha256')):
        _need(member in files and _sha(files[member])==plan[key],'PARENT_PROOF')
    parent_policy=json.loads(files['fox-package/policy-plan.json'])
    _need(parent_policy['source_catalog']==plan['source_catalog'] and parent_policy['parent_trace']==plan['parent_trace']
          and parent_policy['source_binding']==plan['source_binding'],'SOURCE_CATALOG')
    for row in plan['sources']:
        original=files.get('fox-package/sources/'+row['name'])
        _need(original is not None and len(original)==row['bytes'] and _sha(original)==row['sha256'],'ORIGINAL_CHANGED')
    occupied={int(m[1]) for n in files if (m:=re.fullmatch(r'pages/p(\d+)-[^/]+\.apx',n))}
    def allocate():
        value=next((p for p in range(1,9000) if p not in occupied),None)
        _need(value is not None,'PAGE_CAPACITY');occupied.add(value);return value
    relation=json.loads(files.get('fox-package/relation-receipt.json',b'{"generated_operations":[]}'))
    groups=defaultdict(list)
    generated=[];unrendered=[];gate_items=[]
    for op in plan['operations']:
        # An editable fetched cased item needs changed-vs-queried value tracking.
        # Do not uppercase/lowercase an unchanged fetched value merely because
        # the user requests a lookup. Read-only fetched values/new criteria are
        # handled below; this wider editing lifecycle remains an explicit gap.
        if (op['source_event']=='POST-CHANGE' and op['target']['source_update_allowed'] is not False
                and any(b['source_item_id']==op['event_item_id'] and b['case_restriction']!='NONE'
                        and b['source_update_allowed'] is not False for b in op['input_bindings'])):
            unrendered.append({'source_unit_id':op['source_unit_id'],'reason':'source_lookup_edited_case_context_required'})
            continue
        groups[op['source_block_id']].append(op)
    for block_id,ops in sorted(groups.items()):
        paths={ops[0]['target']['report_file']}|{r['page_file'] for r in relation['generated_operations'] if r['child_block_id']==block_id}
        _need(paths<=set(files),'REPORT_MISSING')
        if any(re.search(r'^        link \{',files[path].decode('utf8'),re.M) for path in paths):
            unrendered.extend({'source_unit_id':op['source_unit_id'],'reason':'source_lookup_report_link_capacity'} for op in ops)
            continue
        menu=allocate();pages={op['operation_id']:allocate() for op in ops}
        files[f'pages/p{menu:05d}-fox_lookups_{menu}.apx']=_menu(ops,menu,pages).encode()
        for path in paths:
            text=_link(files[path].decode('utf8'),menu)
            if any(_new_input_eligible(op) for op in ops):
                _need(text.endswith(')\n') and 'button new-lookup-input (' not in text,'REPORT_END')
                text=text[:-2]+_new_input_link(menu)+')\n'
            files[path]=text.encode()
        for op in ops:
            page=pages[op['operation_id']];filename=f'pages/p{page:05d}-fox_lookup_{page}.apx'
            files[filename]=_page(op,page,menu).encode();gate_items.append(_gate_item(op))
            generated.append({'operation_id':op['operation_id'],'kind':op['kind'],
                'source_unit_id':op['source_unit_id'],'source_unit_sha256':op['source_unit_sha256'],
                'generation_status':'generated_wired_adapted','source_event':op['source_event'],
                'event_adapter':'selected_record_load' if op['source_event']=='POST-QUERY' else 'explicit_lookup_submit',
                'page_id':page,'page_file':filename,'menu_page_id':menu,'report_files':sorted(paths),
                'input_items':[_item(page,b) for b in op['input_bindings']],
                'output_items':[_item(page,b) for b in op['output_bindings']],
                'readiness_item':gate_name(op),'source_objects':deepcopy(op['source_objects']),
                'exception_kind':op['exception_kind'],'native_event_wired':True,
                'original_interface_enabled':False,'event_activated':False,'source_query_executed':False,
                'customer_table_writes':False,'oracle_compiled':False,'runtime_verified':False,'business_accepted':False})
    if gate_items:
        member='shared-components/app-items.apx';_need(member not in files,'GATE_MEMBER_COLLISION')
        files[member]='\n'.join(gate_items).encode()
    receipt={'schema_version':1,'scope':SCOPE,'source_binding':plan['source_binding'],
        'parent_zip_sha256':_sha(parent_zip),'plan_sha256':plan['plan_sha256'],
        'renderer_sha256':_sha(Path(__file__).read_bytes()),'generated_operations':generated,
        'unrendered_operations':unrendered,'native_generated':bool(generated),
        'original_reads_enabled_by_default':False,'source_queries_executed':False,
        'runtime_verified':False,'business_accepted':False}
    files['fox-package/lookup-plan.json']=_json(plan);files['fox-package/lookup-receipt.json']=_json(receipt)
    files['fox-package/lookup-activation.md']=(
        '# Original read interfaces are disabled\n\n'
        'No original query ran during conversion. The source lookup handlers are connected in APEX metadata, but each requires a trusted server-only readiness item. '
        'Verify the original objects, columns, types, privileges, row authorization and source error/cardinality behavior in an approved target before enabling any item. '
        'This package supplies no original datasource, credentials or successful mock lookup. The restricted readiness items cannot be set from the browser. '
        'POST-QUERY applies after loading a selected synthetic record; POST-CHANGE uses an explicit Apply lookup action, with source field edit restrictions. '
        'New lookup input is a read-only criteria draft, not CREATE_RECORD, a customer save or full Forms lifecycle. '
        'SQLcl format validation does not compile these statements against Oracle or establish runtime/business acceptance.\n\n'
        +'\n'.join('- '+r['readiness_item']+': '+', '.join('.'.join(o['parts']) for o in r['source_objects']) for r in generated)+'\n').encode()
    stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w') as z:
        for name,raw in sorted(files.items()):
            info=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0));info.external_attr=0o600<<16;z.writestr(info,raw)
    return stream.getvalue(),deepcopy(receipt)
