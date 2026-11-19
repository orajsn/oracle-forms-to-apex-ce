"""Native session-draft record validation, without customer-table writes.

The caller must rebuild the plan from originals immediately before rendering.
Native format, Oracle runtime and business acceptance remain separate gates.
"""
from copy import deepcopy
import hashlib
import html
import io
import json
from pathlib import Path, PurePosixPath
import stat
import re
import zipfile

from . import native_blueprint, native_relations
from .record_buffer import validate_buffer_plan

SCOPE = 'fox-native-record-buffer-v1'
MAX_RECORDS = 1000
REQUESTS = ('FOX_DRAFT_KEEP', 'FOX_DRAFT_PREVIOUS', 'FOX_DRAFT_NEXT', 'FOX_DRAFT_NEW')


class BufferValidationCapacity(ValueError):
    """A complete rule exceeds the native validation source size."""


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def _need(value, message):
    if not value:
        raise ValueError('BUFFER_' + message)


def _literal(value):
    _need(isinstance(value, str) and len(value) <= 4000 and '\x00' not in value, 'LITERAL')
    return "'" + value.replace("'", "''") + "'"


def _indent(code, width=16):
    return '\n'.join(' ' * width + line for line in code.splitlines())


def _name(op):
    return 'FOX_B_' + _sha(_json(op))[:20].upper() + '_'


def _requests():
    return ', '.join(_literal(r) for r in REQUESTS)


def _value_declarations(op):
    return chr(10).join(f'l_value{i} varchar2(4000); l_original{i} varchar2(4000);' for i in range(1,len(op['key_bindings'])+1))


def _load_values(op, page):
    cols=','.join(f'c{i:03d}' for i in range(1,len(op['key_bindings'])+1))
    targets=','.join(f'l_original{i}' for i in range(1,len(op['key_bindings'])+1))
    lines=[f"select {cols} into {targets} from apex_collections where collection_name=l_name and seq_id=l_seq and c050='ROW';"]
    for i,f in enumerate(op['key_bindings'],1):
        key=f':P{page}_K{i}';case=f['case_restriction']
        if case=='NONE':lines.append(f'l_value{i} := {key};')
        else:
            lines.extend([f"if :P{page}_D{i} is null or :P{page}_D{i} not in ('N','Y') then return false; end if;",
                f"if :P{page}_D{i}='Y' or nvl(lengthb({key}),-1)<>nvl(lengthb(l_original{i}),-1)",
                f'   or utl_raw.cast_to_raw({key})<>utl_raw.cast_to_raw(l_original{i}) then',
                f'  l_value{i} := {case.lower()}({key});',f'else l_value{i} := l_original{i}; end if;'])
    return chr(10).join(lines)


def _case_tracking(op, page):
    statements=[]
    for i,f in enumerate(op['key_bindings'],1):
        if f['case_restriction']=='NONE':continue
        style='uppercase' if f['case_restriction']=='UPPER' else 'lowercase'
        statements.append(f'''(function() {{ const field=document.getElementById("P{page}_K{i}");
if(field) {{ field.style.textTransform="{style}"; field.addEventListener("input",function() {{ apex.item("P{page}_D{i}").setValue("Y",null,true); }}); }} }})();''')
    if not statements:return ''
    return '    javaScript {\n        executeWhenPageLoads:\n            ```javascript\n'+_indent(chr(10).join(statements),12)+'\n            ```\n    }\n'


def _key(op, page):
    return ' || '.join(f'l_value{i}' for i in range(1, len(op['key_bindings']) + 1))


def _row_key(op, page):
    # Overlay the current browser draft; every other record comes from this
    # session's same-parent buffer. SQL NULL equality stays UNKNOWN, not true.
    return ' || '.join(f'(case when seq_id = l_seq then l_value{i} else c{i:03d} end)'
                       for i in range(1, len(op['key_bindings']) + 1))


def _checks(op, page, *, controls=True):
    checks = []
    for i, field in enumerate(op['key_bindings'], 1):
        fn = 'lengthb' if field['source_length_semantics'] == 'BYTE' else 'length'
        checks.append(f'nvl({fn}(l_value{i}),0) > {field["max_length"]}')
        if field['required']: checks.append(f'l_value{i} is null')
        checks.append(f'nvl(lengthb(l_value{i}),0) > 4000')
    if controls:
        field = op['control_key']
        fn = 'lengthb' if field['source_length_semantics'] == 'BYTE' else 'length'
        checks.append(f'nvl({fn}({_key(op,page)}),0) > {field["max_length"]}')
        checks.append(f'nvl(lengthb({_key(op,page)}),0) > 4000')
    return ' or '.join(checks)


def _query(op, page):
    rel = op['relation']
    columns = ['c.FOX_ROW_ID'] + ['c.' + field['column'] for field in op['key_bindings']]
    joins = ' and '.join('p.' + pair['parent_column'] + ' = c.' + pair['child_column'] for pair in rel['join_pairs'])
    return (f"select {', '.join(columns)} from {rel['child']['table']} c "
            f"where exists (select 1 from {rel['parent']['table']} p "
            f"where p.FOX_ROW_ID = l_parent and {joins}) order by c.FOX_ROW_ID")


def _declarations(op, page):
    parent = op['relation']['parent']['table']
    fingerprint = _sha(_json(op))
    return f'''{_value_declarations(op)}
l_parent number;
l_name varchar2(255);
l_seq number;
l_revision number;
l_rows number;
l_matches number;
l_key varchar2(4000);
function context_ok return boolean is
  l_exists number;
  e_busy exception;
  pragma exception_init(e_busy,-54);
begin
  if :P{page}_PARENT_ID is null or :P{page}_SEQ is null or :P{page}_REV is null
     or not regexp_like(:P{page}_PARENT_ID, '^[1-9][0-9]{{0,27}}$')
     or not regexp_like(:P{page}_SEQ, '^[1-9][0-9]{{0,9}}$')
     or not regexp_like(:P{page}_REV, '^[0-9]{{1,15}}$') then return false; end if;
  l_parent := to_number(:P{page}_PARENT_ID);
  l_name := '{_name(op)}' || to_char(l_parent,'TM9');
  if not apex_collection.collection_exists(l_name) then return false; end if;
  select FOX_ROW_ID into l_exists from {parent} where FOX_ROW_ID=l_parent for update nowait;
  select n002,n003 into l_seq,l_revision from apex_collections
    where collection_name=l_name and seq_id=1 and n001=l_parent
      and c049='{fingerprint}' and c050='META';
  if l_seq is null or l_seq<>to_number(:P{page}_SEQ)
     or l_revision is null or l_revision<>to_number(:P{page}_REV) then return false; end if;
  select count(*) into l_rows from apex_collections where collection_name=l_name and c050='ROW';
  {_load_values(op,page)}
  return l_rows between 1 and {MAX_RECORDS};
exception when no_data_found or e_busy then return false;
end context_ok;'''


def _compute(op, page):
    # Emit only closed AST composition and native mapped item names. Source
    # messages are quoted data; no source statement text enters this PL/SQL.
    return f'''l_key := {_key(op,page)};
apex_util.set_session_state(p_name=>'{op['control_key']['native_item']}', p_value=>l_key, p_commit=>false);
select nvl(sum(case when (cast(({_row_key(op,page)}) as varchar2(4000)) collate binary) = (cast(l_key as varchar2(4000)) collate binary) then 1 else 0 end),0)
  into l_matches from apex_collections where collection_name=l_name and c050='ROW';
apex_util.set_session_state(p_name=>'{op['summary']['native_item']}', p_value=>to_char(l_matches,'TM9'), p_commit=>false);'''


def _validation(slug, seq, code, message):
    if len(code.encode('utf8')) > 3950:
        raise BufferValidationCapacity('native_record_validation_capacity')
    return f'''    validation {slug} (
        name: {slug}
        execution {{ sequence: {seq} }}
        validation {{
            type: functionBodyReturningBoolean
            plsqlFunctionBody:
                ```plsql
{_indent(code)}
                ```
        }}
        error {{
            errorMessage: {json.dumps(html.escape(message).replace(chr(10),'<br>'),ensure_ascii=False)}
            displayLocation: inlineInNotification
        }}
    )
'''


def _process(slug, code, *, point, sequence=10, submitted=False):
    condition = (f'''        serverSideCondition {{
            type: requestIsContainedInValue
            value: {','.join(REQUESTS)}
        }}
''' if submitted else '')
    return f'''    process {slug} (
        name: {slug}
        type: executeCode
        source {{
            plsqlCode:
                ```plsql
{_indent(code)}
                ```
        }}
        execution {{ sequence: {sequence}
            point: {point}
        }}
{condition}    )
'''


def _initialize(op, page):
    fields = op['key_bindings']
    read_columns = ','.join('c%03d' % i for i in range(1, len(fields)+1))
    into_items = ','.join(f':P{page}_K{i}' for i in range(1,len(fields)+1))
    add_args = ','.join(f'p_c{i:03d}=>r.{f["column"]}' for i,f in enumerate(fields,1))
    row_checks = ' or '.join(f"nvl(lengthb(r.{f['column']}),0)>4000 or nvl({'lengthb' if f['source_length_semantics']=='BYTE' else 'length'}(r.{f['column']}),0)>{f['max_length']}" for f in fields)
    parent = op['relation']['parent']['table']
    reset_flags=chr(10).join(f":P{page}_D{i} := 'N';" for i,f in enumerate(fields,1) if f['case_restriction']!='NONE')
    return f'''declare
l_parent number;
l_name varchar2(255);
l_seq number;
l_revision number;
l_count number := 0;
l_stored_parent number;
l_hash varchar2(4000);
l_kind varchar2(4000);
l_created boolean := false;
begin
  if :P{page}_PARENT_ID is null or not regexp_like(:P{page}_PARENT_ID,'^[1-9][0-9]{{0,27}}$') then
    raise_application_error(-20001,'Open draft records from their parent record.');
  end if;
  l_parent := to_number(:P{page}_PARENT_ID);
  select FOX_ROW_ID into l_stored_parent from {parent} where FOX_ROW_ID=l_parent;
  l_name := '{_name(op)}' || to_char(l_parent,'TM9');
  if not apex_collection.collection_exists(l_name) then
    apex_collection.create_collection(l_name);
    l_created := true;
    apex_collection.add_member(p_collection_name=>l_name,p_c049=>'{_sha(_json(op))}',p_c050=>'META',p_n001=>l_parent,p_n002=>2,p_n003=>0);
    for r in ({_query(op,page)}) loop
      l_count := l_count+1;
      if l_count>{MAX_RECORDS} then raise_application_error(-20002,'This draft exceeds the supported record limit. No records were truncated.'); end if;
      if {row_checks} then raise_application_error(-20003,'A loaded value exceeds the source field limit.'); end if;
      apex_collection.add_member(p_collection_name=>l_name,{add_args},p_c050=>'ROW',p_n001=>r.FOX_ROW_ID);
    end loop;
    if l_count=0 then apex_collection.add_member(p_collection_name=>l_name,p_c050=>'ROW'); end if;
  end if;
  select n001,n002,n003,c049,c050 into l_stored_parent,l_seq,l_revision,l_hash,l_kind
    from apex_collections where collection_name=l_name and seq_id=1;
  if l_stored_parent is null or l_hash is null or l_kind is null or l_stored_parent<>l_parent or l_hash<>'{_sha(_json(op))}' or l_kind<>'META'
     or l_seq is null or l_revision is null then raise_application_error(-20004,'Draft context does not match this page.'); end if;
  :P{page}_SEQ := l_seq;
  :P{page}_REV := l_revision;
  {reset_flags}
  select {read_columns} into {into_items} from apex_collections where collection_name=l_name and seq_id=l_seq and c050='ROW';
  select count(*) into l_count from apex_collections where collection_name=l_name and c050='ROW';
  :P{page}_POSITION := 'Record ' || to_char(l_seq-1,'TM9') || ' of ' || to_char(l_count,'TM9');
exception when others then
  if l_created and apex_collection.collection_exists(l_name) then apex_collection.delete_collection(l_name); end if;
  raise;
end;'''


def _retain_failure(op, page):
    updates = chr(10).join(f"apex_collection.update_member_attribute(p_collection_name=>l_name,p_seq=>l_seq,p_attr_number=>{i},p_attr_value=>l_value{i});" for i in range(1,len(op['key_bindings'])+1))
    return f"""if l_matches>1 then
  {updates}
  apex_collection.update_member_attribute(p_collection_name=>l_name,p_seq=>1,p_attr_number=>1,p_attr_value=>l_key);
  apex_collection.update_member_attribute(p_collection_name=>l_name,p_seq=>1,p_attr_number=>4,p_number_value=>l_matches);
  apex_collection.update_member_attribute(p_collection_name=>l_name,p_seq=>1,p_attr_number=>3,p_number_value=>l_revision+1);
  apex_util.set_session_state(p_name=>'P{page}_REV',p_value=>to_char(l_revision+1,'TM9'),p_commit=>false);
  return false;
end if;"""


def _mutate(op, page):
    updates = '\n'.join(f"apex_collection.update_member_attribute(p_collection_name=>l_name,p_seq=>l_seq,p_attr_number=>{i},p_attr_value=>l_value{i});" for i in range(1,len(op['key_bindings'])+1))
    return f'''declare
l_next number;
{_declarations(op,page)}
begin
  if :REQUEST is null or :REQUEST not in ({_requests()}) then
    raise_application_error(-20005,'Unknown draft action.');
  end if;
  if not context_ok then raise_application_error(-20006,'Draft changed in another request. Reopen it before editing.'); end if;
  if :REQUEST='FOX_DRAFT_NEW' and l_rows>={MAX_RECORDS} then raise_application_error(-20007,'The draft record limit has been reached.'); end if;
  if {_checks(op,page)} then raise_application_error(-20008,'A value exceeds its source field limit.'); end if;
  {_compute(op,page)}
  if l_matches>1 then raise_application_error(-20009,'Duplicate record: correct the values before continuing.'); end if;
  {updates}
  apex_collection.update_member_attribute(p_collection_name=>l_name,p_seq=>1,p_attr_number=>1,p_attr_value=>l_key);
  apex_collection.update_member_attribute(p_collection_name=>l_name,p_seq=>1,p_attr_number=>4,p_number_value=>l_matches);
  l_next := l_seq;
  if :REQUEST='FOX_DRAFT_NEXT' then
    select nvl(min(seq_id),l_seq) into l_next from apex_collections where collection_name=l_name and c050='ROW' and seq_id>l_seq;
  elsif :REQUEST='FOX_DRAFT_PREVIOUS' then
    select nvl(max(seq_id),l_seq) into l_next from apex_collections where collection_name=l_name and c050='ROW' and seq_id<l_seq;
  elsif :REQUEST='FOX_DRAFT_NEW' then
    l_next := apex_collection.add_member(p_collection_name=>l_name,p_c050=>'ROW');
  end if;
  apex_collection.update_member_attribute(p_collection_name=>l_name,p_seq=>1,p_attr_number=>2,p_number_value=>l_next);
  apex_collection.update_member_attribute(p_collection_name=>l_name,p_seq=>1,p_attr_number=>3,p_number_value=>l_revision+1);
end;'''


def _hidden(page, name, sequence, *, protected=True):
    settings='' if protected else '        settings { valueProtected: false }'+chr(10)
    protection='checksumRequiredSessionLevel' if protected else 'unrestricted'
    return f'''    pageItem P{page}_{name} (
        type: hidden
{settings}        layout {{ sequence: {sequence}
            region: @editor
            slot: regionBody
        }}
        sessionState {{ storage: request
            dataType: varchar2
        }}
        security {{ sessionStateProtection: {protection} }}
    )
'''


def _button(slug, request, label, sequence):
    return f'''    button {slug} (
        buttonName: {request}
        label: {json.dumps(label)}
        layout {{ sequence: {sequence}
            region: @editor
            slot: create
        }}
        appearance {{ buttonTemplate: @/text }}
        behavior {{ action: submitPage
            executeValidations: true
            warnOnUnsavedChanges: doNotCheck
        }}
    )
'''


def _raw_page(op, page):
    items = ''.join(_hidden(page,name,i*10) for i,name in enumerate(('PARENT_ID','SEQ','REV'),1))
    for i, field in enumerate(op['key_bindings'],1):
        spec={'name':f'K{i}','source_item_id':field['source_item_id'], 'source_name':field['source_item_name'],
              'data_type':'VARCHAR2','label':field['source_item_name'],'widget':'text','length':field['max_length'],
              'nullable':not field['required'],'in_edit_form':False}
        item=native_blueprint._control_item(spec,100+i*10,page).replace('region: @controls','region: @editor')
        _need(item.count('        type: textField\n')==1,'TEXT_ITEM_TEMPLATE')
        item=item.replace('        type: textField\n','        type: textField\n        settings { trimSpaces: none }\n        sessionState { storage: request\n            dataType: varchar2\n        }\n',1)
        items+=item+'\n'
    for i,field in enumerate(op['key_bindings'],1):
        if field['case_restriction']!='NONE':
            items+=_hidden(page,f'D{i}',40+i,protected=False)
    items+=f'''    pageItem P{page}_POSITION (
        type: displayOnly
        label {{ label: Current record }}
        layout {{ sequence: 90
            region: @editor
            slot: regionBody
        }}
        appearance {{ template: @/optional-floating }}
        sessionState {{ storage: request
            dataType: varchar2
        }}
    )
'''
    context_code=f'''declare
{_declarations(op,page)}
begin
  if :REQUEST is null or :REQUEST not in ({_requests()}) then return false; end if;
  if not context_ok then return false; end if;
  :P{page}_POSITION := 'Record ' || to_char(l_seq-1,'TM9') || ' of ' || to_char(l_rows,'TM9');
  return not (:REQUEST='FOX_DRAFT_NEW' and l_rows>={MAX_RECORDS});
end;'''
    size_code=f'''declare
{_declarations(op,page)}
begin
  if not context_ok then return true; end if;
  return not ({_checks(op,page)});
end;'''
    duplicate_code=f'''declare
{_declarations(op,page)}
begin
  if :REQUEST is null or :REQUEST not in ({_requests()}) then return true; end if;
  if not context_ok or ({_checks(op,page)}) then return true; end if;
  if :REQUEST='FOX_DRAFT_NEW' and l_rows>={MAX_RECORDS} then return true; end if;
  {_compute(op,page)}
  {_retain_failure(op,page)}
  return true;
end;'''
    validations=_validation('draft-context',10,context_code,'This draft changed, its parent is unavailable, or its record limit was reached. Reopen the draft before continuing.')
    validations+=_validation('source-size',20,size_code,'A required value is missing or exceeds its source field or combined-key limit. Correct it before continuing.')
    validations+=_validation('source-record-check',30,duplicate_code,'\n'.join(op['warnings']))
    buttons=''.join(_button(slug,req,label,i*10) for i,(slug,req,label) in enumerate(zip(('keep','previous','next','new'),REQUESTS,('Keep draft','Previous record','Next record','New draft record')),1))
    process=_process('load-draft',_initialize(op,page),point='beforeHeader')
    process+=_process('keep-draft-and-move',_mutate(op,page),point='processing',submitted=True)
    return f'''page {page} (
    name: Validate draft records
    alias: FOX_BUFFER_{page}
    title: Validate draft records
{_case_tracking(op,page)}
    appearance {{ pageTemplate: @/standard
        templateOptions: #DEFAULT#
    }}
    security {{ authentication: required
        pageAccessProtection: argumentsMustHaveChecksum
    }}
    region scope (
        name: Draft record scope
        type: staticContent
        source {{ htmlCode:
                ```html
                <p>Edit the current record, then keep it or move to another record. Duplicate values prevent continuing. Drafts belong to this parent and your current session; customer tables are not changed. Leaving this screen can discard edits you have not kept.</p>
                ```
        }}
        layout {{ sequence: 5
            slot: body
        }}
        appearance {{ template: @/standard
            templateOptions: #DEFAULT#
        }}
    )
    region editor (
        name: Current draft record
        type: staticContent
        layout {{ sequence: 10
            slot: body
        }}
        appearance {{ template: @/standard
            templateOptions: #DEFAULT#
        }}
    )
{items}{buttons}{validations}{process}    branch show-current-record (
        name: Show current draft record
        execution {{ sequence: 10
            point: afterProcessing
        }}
        behavior {{ type: pageOrUrl
            target: {{ page: {page}
                items: {{ P{page}_PARENT_ID: "&P{page}_PARENT_ID." }}
            }}
        }}
        serverSideCondition {{ type: requestIsContainedInValue
            value: {','.join(REQUESTS)}
        }}
    )
)
'''


def _raw_context_link(op, page):
    relation=op['relation']
    return f'''    button draft-records (
        buttonName: FOX_OPEN_DRAFT
        label: Validate draft records
        layout {{ sequence: 100
            region: @records
            slot: rightOfInteractiveReportSearchBar
        }}
        appearance {{ buttonTemplate: @/text }}
        behavior {{ action: redirectThisApp
            target: {{ page: {page}
                items: {{ P{page}_PARENT_ID: "&{relation['parent_item']}." }}
            }}
        }}
    )
'''


def render_buffer_package(parent_zip, plan):
    """Render only a fresh, rederived plan against the exact immutable parent."""
    validated=validate_buffer_plan(plan)
    _need(type(parent_zip) is bytes and _sha(parent_zip)==validated['parent_zip_sha256'],'PARENT_CHANGED')
    _need(len(parent_zip)<=32*1024*1024,'PARENT_SIZE')
    with zipfile.ZipFile(io.BytesIO(parent_zip)) as archive:
        infos=archive.infolist();names=[i.filename for i in infos]
        _need(len(names)<=4096 and len(names)==len({n.casefold() for n in names}),'PARENT_MEMBERS')
        _need(sum(i.file_size for i in infos)<=64*1024*1024,'PARENT_EXPANSION')
        for i in infos:
            name=i.filename
            _need(not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts
                  and chr(92) not in name and ':' not in name and not stat.S_ISLNK(i.external_attr>>16)
                  and not name.startswith('fox-package/buffer-'),'PARENT_PATH')
        files={i.filename:archive.read(i) for i in infos}
    raw=parent_zip
    bindings=(('fox-package/source-manifest.json','source_manifest_sha256'),
              ('fox-package/source-to-page.json','parent_trace_sha256'),
              ('fox-package/relation-plan.json','relation_plan_sha256'),
              ('fox-package/relation-receipt.json','relation_receipt_sha256'))
    for member,digest in bindings:
        _need(member in files,'PARENT_MEMBER_MISSING')
        expected=_sha(files[member]) if digest in ('source_manifest_sha256','parent_trace_sha256') else _sha(_json(json.loads(files[member])))
        _need(expected==validated[digest],'PARENT_MEMBER_CHANGED')
    source_parent=json.loads(files['fox-package/policy-plan.json'])
    _need(source_parent.get('source_binding')==validated['source_binding']
          and source_parent.get('parent_trace')==validated['parent_trace']
          and source_parent.get('source_catalog')==validated['source_catalog'],
          'SOURCE_CATALOG_DIFFERS_FROM_REBUILT_PARENT')
    for source in validated['sources']:
        original=files.get('fox-package/sources/'+source['name'])
        _need(original is not None and _sha(original)==source['sha256'] and len(original)==source['bytes'],'SOURCE_CHANGED')
    occupied={int(m[1]) for name in files if (m:=re.fullmatch(r'pages/p(\d+)-[^/]+\.apx',name))}
    generated=[]
    unrendered=[]
    for op in validated['operations']:
        page=next((p for p in range(1,9000) if p not in occupied),None)
        _need(page is not None,'PAGE_CAPACITY')
        try:
            rendered_page=_page(op,page).encode()
        except BufferValidationCapacity as exc:
            unrendered.append({'source_unit_id':op['source_unit_id'],'reason':str(exc)})
            continue
        occupied.add(page)
        filename=f'pages/p{page:05d}-fox_buffer_{page}.apx'
        context=op['relation']['page_file']
        _need(context in files,'CONTEXT_PAGE_MISSING')
        text=files[context].decode('utf8')
        _need(text.startswith(f"page {op['relation']['page_id']} (\n") and text.endswith(')\n') and 'button draft-records (' not in text,'CONTEXT_PAGE_CHANGED')
        files[context]=(text[:-2]+_context_link(op,page)+')\n').encode()
        files[filename]=rendered_page
        generated.append({'operation_id':op['operation_id'],'source_unit_id':op['source_unit_id'],
            'source_unit_sha256':op['source_unit_sha256'],'kind':op['kind'],
            'generation_status':'generated_wired_adapted','page_file':filename,'page_id':page,
            'context_page_file':context,'source_event':op['source_event'],
            'native_event_wired':True,'event_activated':False,'adapter':'native_session_draft_validate_before_record_navigation',
            'customer_table_writes':False,'oracle_compiled':False,'runtime_verified':False,'business_accepted':False})
    receipt={'schema_version':1,'scope':SCOPE,'source_binding':validated['source_binding'],
        'parent_zip_sha256':_sha(raw),'plan_sha256':validated['plan_sha256'],
        'renderer_sha256':_sha(Path(__file__).read_bytes()),'generated_operations':generated,
        'unrendered_operations':unrendered,
        'native_generated':bool(generated),'runtime_verified':False,'business_accepted':False}
    files['fox-package/buffer-plan.json']=_json(validated)
    files['fox-package/buffer-receipt.json']=_json(receipt)
    stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w') as archive:
        for name,content in sorted(files.items()):
            info=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0));info.external_attr=0o600<<16
            archive.writestr(info,content)
    return stream.getvalue(),deepcopy(receipt)


def _expand_groups(text):
    """Expand trusted template groups into SQLcl's line-oriented APX grammar.

    Quoted values and fenced SQL/HTML are opaque: never reformat source literals.
    """
    output=[]
    stack=[]
    fenced=False
    for line in text.splitlines():
        if line.strip().startswith('```'):
            fenced=not fenced
            output.append(line)
            continue
        if fenced:
            output.append(line)
            continue
        indent=len(line)-len(line.lstrip())
        current=' '*indent
        quoted=False
        escaped=False
        for char in line.lstrip():
            if quoted:
                current+=char
                if escaped: escaped=False
                elif char==chr(92): escaped=True
                elif char=='"': quoted=False
                continue
            if char=='"':
                quoted=True;current+=char
            elif char=='{':
                output.append(current.rstrip()+' {')
                stack.append(len(current)-len(current.lstrip()))
                current=' '*(stack[-1]+4)
            elif char=='}':
                if current.strip():output.append(current.rstrip())
                _need(bool(stack),'GENERATED_GROUP_BALANCE')
                current=' '*stack.pop()+'}'
            else:
                if not current.strip() and char.isspace():continue
                current+=char
        if current.strip():output.append(current.rstrip())
    _need(not stack and not fenced,'GENERATED_GROUP_BALANCE')
    return '\n'.join(output)+'\n'


def _page(op, page):
    return _expand_groups(_raw_page(op,page))


def _context_link(op, page):
    return _expand_groups(_raw_context_link(op,page))
