"""Deterministic source/native and executed SQL boundaries, not APEX proof."""
from copy import deepcopy
import json
import re
import sqlite3
from xml.etree import ElementTree as ET

import pytest

from fox.forms_item_validation import (apply_item_validations, parse_item_validation,
                                      _effect_body, _event_code, _check_capacity, SLOTS)
from fox.forms_synthetic_save import apply_synthetic_saves
from test_forms_synthetic_save import source as save_source, prepare as save_prepare


BODY = """IF :TARGET_CITY IS NULL AND :PIECE_CODE IS NOT NULL AND :SYSTEM.RECORD_STATUS <> 'QUERY' THEN
 MESSAGE('Destination required'); MESSAGE('Destination required'); :STEP_MARKER:='X';
ELSE
 IF :PIECE_CODE IS NOT NULL THEN
  DECLARE PRIOR_LOAD VARCHAR2(20); UNUSED_COUNT NUMBER;
  BEGIN
   :COST_WEIGHT:=0;
   :STORED_ROUTE:=:LOADS.PLANNED_ROUTE;
   BEGIN
    SELECT LOAD_REFERENCE INTO PRIOR_LOAD FROM PIECES
     WHERE PIECE_CODE=:PIECE_CODE AND ROWNUM=1;
   EXCEPTION WHEN NO_DATA_FOUND THEN NULL; END;
   IF PRIOR_LOAD IS NOT NULL THEN
    MESSAGE('Already in load '||PRIOR_LOAD); MESSAGE('Already in load '||PRIOR_LOAD);
    :PIECE_CODE:=NULL; RAISE FORM_TRIGGER_FAILURE;
   ELSE :STEP_MARKER:=TO_CHAR(SYSDATE,'RRMMDDHH24MISS'); END IF;
  END;
 END IF;
END IF;"""


def source(*, renamed=False, changed_body=None, missing_provider=False):
    name, raw = save_source()[0]
    root = ET.fromstring(raw)
    parent, child = list(root.iter('Block'))[:2]
    child.set('QueryDataSourceType', 'Table')
    child.set('QueryDataSourceName', 'PIECES')
    ET.SubElement(parent, 'Item', Name='TARGET_CITY', ItemType='Text Item', DatabaseItem='false',
                  DataType='Char', MaximumLength='10', DataLengthSemantics='BYTE')
    ET.SubElement(child, 'Item', Name='STEP_MARKER', ItemType='Text Item', DatabaseItem='false',
                  DataType='Char', MaximumLength='30', DataLengthSemantics='BYTE')
    ET.SubElement(child, 'Item', Name='COST_WEIGHT', ItemType='Display Item', DatabaseItem='true',
                  DataType='Number', MaximumLength='8', ColumnName='COST_WEIGHT')
    for item in child.iter('Item'):
        if item.get('DatabaseItem') == 'true':
            item.set('ColumnName', item.get('Name'))
    code = next(i for i in child.iter('Item') if i.get('Name') == 'PIECE_CODE')
    ET.SubElement(code, 'Trigger', Name='WHEN-VALIDATE-ITEM', TriggerText=changed_body or BODY)
    if missing_provider:
        child.set('QueryDataSourceName', 'OTHER_DATA')
    raw = ET.tostring(root)
    if renamed:
        for old, new in ((b'LOADS', b'HEADERS'), (b'PIECES', b'CRATES'), (b'PIECE_CODE', b'CRATE_CODE'),
                         (b'LOAD_REFERENCE', b'HEADER_REF'), (b'TARGET_CITY', b'END_TOWN'),
                         (b'COST_WEIGHT', b'BILL_WEIGHT'), (b'STEP_MARKER', b'FOCUS_STAMP'),
                         (b'PLANNED_ROUTE', b'PARENT_PATH'), (b'STORED_ROUTE', b'ACTIVE_PATH')):
            raw = raw.replace(old, new)
    return [('renamed.xml' if renamed else name, raw)]


def prepare(docs=None):
    docs = docs or source()
    packet, chunks, trace, files = save_prepare(docs)
    files, receipt = apply_synthetic_saves(docs,packet,chunks,trace,files)
    files['fox-package/synthetic-save-receipt.json'] = json.dumps(receipt).encode()
    return docs,packet,chunks,trace,files


def generated(**kwargs):
    args = prepare(source(**kwargs))
    files, receipt = apply_item_validations(*args)
    op, = receipt['generated_operations']
    return files,receipt,op,args


@pytest.mark.parametrize('renamed',[False,True])
def test_complete_event_is_bound_to_existing_editor_without_mutating_originals(renamed):
    args = prepare(source(renamed=renamed))
    before = deepcopy(args)
    files, receipt = apply_item_validations(*args)
    assert args == before and (files,receipt) == apply_item_validations(*args)
    assert not receipt['gaps'] and receipt['converted_code_unit_count'] == 1
    op, = receipt['generated_operations']
    assert op['native_event_wired'] and op['source_event'] == 'WHEN-VALIDATE-ITEM'
    assert op['contract']['slots'] == SLOTS
    assert op['contract']['query_scope'] == 'all_persisted_synthetic_rows_all_parents'
    assert op['contract']['parent_input_provenance'] == 'fresh_locked_selected_parent_exact_trace_columns'
    assert not op['navigation_implemented'] and not op['forms_commit_implemented']
    assert all(not receipt[k] for k in ('customer_table_writes','original_reads_enabled','oracle_compiled','runtime_verified','business_accepted'))
    assert {p for p in files if files[p] != args[-1][p]} == {op['page_file']}
    assert files['fox-package/sources/'+args[0][0][0]] == args[0][0][1]
    text = files[op['page_file']].decode()
    assert 'point: afterSubmit' in text and 'process validate-edited-item (' in text
    assert 'reloadOnSubmit: always' in text
    assert 'type: textField' in text and 'FOX_SYNTHETIC_SAVE' in text
    assert 'FOX_I_' in text and 'FOX_S_' not in text


def test_parser_preserves_all_nested_branches_and_full_source():
    parsed, receipt = parse_item_validation(BODY.replace('\n','&#10;'))
    assert parsed['query'] == {'table':'PIECES','projection':'LOAD_REFERENCE','predicate':'PIECE_CODE',
                                'rownum':1,'ordering':None,'exception':'NO_DATA_FOUND'}
    assert len(parsed['warning_messages']) == len(parsed['duplicate_messages']) == 2
    assert len(parsed['ordered_effects']) == 5 and receipt['substitutions']
    assert parsed['counter_length'] == 20 and parsed['clock_mask'] == 'RRMMDDHH24MISS'


@pytest.mark.parametrize('old,new',[
    ('ROWNUM=1','ROWNUM=2'), ('NO_DATA_FOUND','OTHERS'),
    ('RAISE FORM_TRIGGER_FAILURE;','NULL;'), ('END IF;','END IF; COMMIT;'),
    (':COST_WEIGHT:=0;',':COST_WEIGHT:=1;'), ('RRMMDDHH24MISS','YYYY'),
    ('WHERE PIECE_CODE=:PIECE_CODE','WHERE PIECE_CODE=:OTHER'),
])
def test_parser_never_selects_a_partial_source_prefix(old,new):
    with pytest.raises(ValueError):
        parse_item_validation(BODY.replace(old,new))


def test_unproved_provider_keeps_complete_encoding_and_explicit_gap():
    args = prepare(source(missing_provider=True))
    files, receipt = apply_item_validations(*args)
    assert receipt['converted_code_unit_count'] == 0 and not receipt['generated_operations']
    adapted, = receipt['adapted_operations']
    assert files[adapted['page_file']] != args[-1][adapted['page_file']]
    assert adapted['native_event_wired'] and adapted['contract']['query_sql'] is None
    text = files[adapted['page_file']].decode()
    assert 'no lookup outcome was inferred' in text and 'Save is unavailable' not in text
    assert "nvl(l_previous_error,'OK')<>'ERROR'" in text
    assert "l_weight:=0;l_route:=l_parent_route;" in text
    assert receipt['encoded_operations'][0]['parsed']['ordered_effects']
    assert 'EXACT_SOURCE_TABLE_IDENTITY' in receipt['gaps'][0]['reason']


def test_emitted_event_orders_guard_effects_retention_and_failure():
    files,_,op,args = generated()
    buffer, = json.loads(args[-1]['fox-package/buffer-plan.json'])['operations']
    code = _event_code(op['parsed'],buffer,op['page_id'],op['contract'],'FOX_I_01234567890123456789_')
    action = code[code.index('begin\n :P'):]
    assert action.index('if not context_ok') < action.index('select case when') < action.index('for update nowait;')
    assert 'elsif not (decode(' not in code
    assert "nvl(l_previous_error,'OK')<>'ERROR'" in code
    assert "l_failed:=true;l_runtime_error:='ERROR';" in code
    assert 'l_revision<>to_number(' in code and 'l_seq<>to_number(' in code
    assert 'c041=\'SYNTHETIC_SAVE_BASELINE_V1\'' in code
    assert 'decode(c.'+op['contract']['fields']['weight']['column']+',d.n003,1,0)=1' in code
    body = _effect_body(op['parsed'],op['contract'])
    assert body.index('l_weight:=0;') < body.index('l_route:=l_parent_route;') < body.index('select c.')
    assert body.index('l_error:=') < body.index('l_code:=null;') < body.index('l_failed:=true;')
    assert 'exception when no_data_found then null;' in body and 'when others' not in body
    assert action.index('l_failed:=true;') < action.index('p_attr_number=>42') < action.index('if l_failed then')
    assert "'INSERT' else 'CHANGED'" in code
    assert 'commit;' not in code.lower() and not re.search(r'\b(insert into|update FOX_NATIVE_|delete from)\b',code,re.I)
    text = files[op['page_file']].decode()
    for name in ('keep-draft-and-move','save-synthetic-record'):
        part = re.search(r'process '+name+r' \(.*?```plsql\n(.*?)\n\s*```',text,re.S)[1]
        assert 'end context_ok;begin if :P' in part and '_ITEM_ERROR is not null then return;end if;' in part
    for part in re.findall(r'    validation [\w-]+ \(.*?\n    \)',text,re.S):
        body=re.search(r'```plsql\n(.*?)\n\s*```',part,re.S)[1]
        assert '_ITEM_ERROR' not in body
        assert 'type: expression' in part and 'language: plsql' in part
        assert ':REQUEST in (' in part and f':P{op["page_id"]}_ITEM_ERROR is null' in part
        assert len(body.strip().encode()) <= 3950


@pytest.mark.parametrize('kind,limit', [('validation',3950),('process',32767)])
def test_final_body_capacity_counts_bytes_at_and_above_the_real_limit(kind,limit):
    # A Unicode literal tests the physical UTF-8 field boundary without
    # replacing the actual bound. No Oracle compilation is claimed here.
    def component(code):
        return '    '+kind+' capacity (\n        source {\n            ```plsql\n'+code+'\n            ```\n        }\n    )\n'
    # Use active literal payload so whitespace stripping cannot hide bytes.
    at="begin if '"+('a'*(limit-len("begin if '' is null then null;end if;end;")))+"' is null then null;end if;end;"
    _check_capacity(component(at))
    with pytest.raises(ValueError,match=kind.upper()+'_CAPACITY'):
        _check_capacity(component(at.replace("' is null","é' is null")))


def test_near_capacity_source_keeps_validator_bodies_below_the_real_bound():
    name,raw=source()[0]
    root=ET.fromstring(raw)
    helper=next(x for x in root.iter('ProgramUnit') if x.get('Name')=='POLICY')
    helper.set('ProgramUnitText',helper.get('ProgramUnitText').replace(
        "IF :LOADS.APPROVED IS NOT NULL AND :LOADS.APPROVED='Y' THEN",
        'IF '+' AND '.join(":LOADS.APPROVED='Y'" for _ in range(6))+' THEN'))
    args=prepare([(name,ET.tostring(root))])
    files,receipt=apply_item_validations(*args)
    assert not receipt['gaps']
    op,=receipt['generated_operations']
    before=args[-1][op['page_file']].decode();after=files[op['page_file']].decode()
    bodies=lambda text:re.findall(r'    validation [\w-]+ \(.*?```plsql\n(.*?)\n\s*```',text,re.S)
    assert 3900 <= max(len(s.strip().encode()) for s in bodies(before)) <=3950
    normalize=lambda text:re.sub(r'FOX_[SI]_[A-F0-9]{20}_','DRAFT_NAMESPACE',text)
    assert [normalize(s) for s in bodies(before)] == [normalize(s) for s in bodies(after)]
    _check_capacity(after)


def test_generated_capacity_failure_keeps_original_page_and_complete_encoding(monkeypatch):
    import fox.forms_item_validation as adapter
    args=prepare();original=deepcopy(args[-1])
    monkeypatch.setattr(adapter,'_event_code',lambda *a:"begin if '"+('x'*32768)+"' is null then null;end if;end;")
    files,receipt=apply_item_validations(*args)
    assert files == original and not receipt['generated_operations'] and not receipt['adapted_operations']
    assert receipt['encoded_operations'][0]['parsed']['ordered_effects']
    assert receipt['gaps'][0]['reason']=='ITEM_VALIDATION_PROCESS_CAPACITY'


def test_save_extends_weight_projection_and_keeps_current_parent_route_precedence():
    files,_,op,_ = generated()
    code = re.search(r'process save-synthetic-record \(.*?```plsql\n(.*?)\n\s*```',files[op['page_file']].decode(),re.S)[1]
    c = op['contract']; weight=c['fields']['weight']['column'];route=c['fields']['route']['column']
    assert f',{weight})values(' in code and ',l_item_weight)returning FOX_ROW_ID' in code
    assert f',{route}=l_route,{weight}=l_item_weight where FOX_ROW_ID=l_id;' in code
    assert 'decode(l_item_weight,l_base_weight,1,0)=0' in code
    assert 'decode(utl_raw.cast_to_raw(l_active_route),utl_raw.cast_to_raw(l_base_route),1,0)=1' in code
    assert 'c040,c041,n002,n003,c044 into l_id,' in code
    assert f'decode(c.{weight},l_base_weight,1,0)=1 for update nowait;' in code
    assert "p_attr_number=>3,p_number_value=>l_item_weight" in code
    assert "p_attr_number=>44,p_attr_value=>l_route" in code
    assert 'into l_route from '+c['parent_table'] in code
    assert 'l_route:=l_item_route' not in code
    assert 'p_attr_number=>42' not in code  # source navigation marker stays session only
    assert "g_print_success_message||case when apex_application.g_print_success_message is not null then '<br>' end||" in code


class EmittedBoundary:
    """Run emitted query in SQLite, model PL/SQL effects/guards explicitly.

    Does not claim Oracle locks, transaction scheduling, encoding or APEX proof.
    """
    def __init__(self, *, query_ready=True):
        if query_ready:
            _,_,self.op,_ = generated()
        else:
            args=prepare(source(missing_provider=True))
            _,receipt=apply_item_validations(*args)
            self.op,=receipt['adapted_operations']
        self.c = self.op['contract']; self.parsed = self.op['parsed']
        self.db = sqlite3.connect(':memory:')
        if query_ready:
            self.db.execute('create table '+self.c['child_table']+'('+self.c['fields']['code']['column']+' text,'+
                            re.search(r'select c\.(\w+)',self.c['query_sql'])[1]+' text)')
        self.error=False
        self.state = {'code':None,'weight':19,'route':'OLD','marker':'BEFORE','revision':0,'id':None}

    def row(self, code, parent):
        self.db.execute('insert into '+self.c['child_table']+' values (?,?)',(code,parent))

    def submit(self, code, *, destination='TOWN', route='NOW', revision=0, approved=False, stale=False):
        if revision != self.state['revision'] or approved or stale:
            return 'context'
        code = code.upper() if code else None
        if code == self.state['code'] and not self.error:
            return 'unchanged'
        if code is not None and len(code) > self.c['fields']['code']['max_length']:
            return 'length'
        self.state['code'] = code
        result = 'empty'
        if destination is None and code is not None:
            self.state['marker'] = self.parsed['warning_marker'];result='warning'
        elif code is not None:
            self.state.update(weight=0,route=route)
            if not self.c['query_provider_ready']:
                self.error=True;self.state['revision']+=1
                return 'query_unavailable'
            # ROWNUM=1 maps to LIMIT 1 solely for this SQLite boundary check.
            sql = self.c['query_sql'].replace(' into item_event.l_counter','').replace('item_event.l_code','?').replace(' and ROWNUM=1;',' LIMIT 1')
            row = self.db.execute(sql,(code,)).fetchone()
            if row and row[0] is not None:
                self.state['code']=None;result='failure'
            else:
                self.state['marker']='261120123456';result='success'
        self.state['revision']+=1
        self.error=False
        return result


@pytest.mark.parametrize('parent',['CURRENT','ANOTHER'])
def test_duplicate_scans_all_parents_and_preserves_source_effects_on_failure(parent):
    b=EmittedBoundary();b.row('USED',parent)
    assert b.submit('used') == 'failure'
    assert b.state == {'code':None,'weight':0,'route':'NOW','marker':'BEFORE','revision':1,'id':None}


@pytest.mark.parametrize('null_row',[False,True])
def test_no_row_and_null_projected_parent_both_reach_clock_marker(null_row):
    b=EmittedBoundary()
    if null_row:b.row('NEW',None)
    assert b.submit('new') == 'success'
    assert b.state['weight']==0 and b.state['route']=='NOW' and b.state['marker']=='261120123456'


def test_warning_is_not_failure_and_does_not_run_else_assignments_or_lookup():
    b=EmittedBoundary();b.row('USED','ANOTHER')
    assert b.submit('used',destination=None) == 'warning'
    assert b.state['code']=='USED' and b.state['weight']==19 and b.state['route']=='OLD' and b.state['marker']=='X'


def test_source_first_row_null_is_not_replaced_by_a_later_nonnull_match():
    b=EmittedBoundary();b.row('SAME',None);b.row('SAME','ANOTHER')
    assert b.submit('SAME')=='success'
    assert 'ROWNUM=1' in b.c['query_sql'] and 'order by' not in b.c['query_sql'].lower()


def test_partial_query_only_blocks_the_path_that_needs_it_and_retries_retained_error():
    b=EmittedBoundary(query_ready=False)
    assert b.submit('NEW',destination=None)=='warning' and not b.error
    assert b.submit('NEW',revision=1)=='unchanged'  # already validated warning branch
    b=EmittedBoundary(query_ready=False)
    assert b.submit('NEW')=='query_unavailable' and b.error
    assert b.state['weight']==0 and b.state['route']=='NOW' and b.state['marker']=='BEFORE'
    assert b.submit('NEW',revision=1)=='query_unavailable' and b.error
    assert b.submit(None,revision=2)=='empty' and not b.error


@pytest.mark.parametrize('active,baseline,expected',[(None,None,0),('R0','R0',0),
                                                   (None,'R0',1),('R1',None,1),
                                                   ('R1','R0',1),('R0 ','R0',1)])
def test_emitted_save_route_dirty_predicate_is_binary_and_null_safe(active,baseline,expected):
    files,_,op,args=generated()
    text=files[op['page_file']].decode()
    code=re.search(r'process save-synthetic-record \(.*?```plsql\n(.*?)\n\s*```',text,re.S)[1]
    changed=re.search(r'select case when (.*?)then 1 else 0 end into l_changed from dual;',code)[1]
    db=sqlite3.connect(':memory:')
    db.create_function('fox_raw',1,lambda v:None if v is None else v.encode())
    db.create_function('decode',4,lambda a,b,yes,no:yes if a==b else no)
    sql=re.sub(r'\bl_[A-Za-z0-9_]+\b',lambda m:':'+m[0],changed).replace('utl_raw.cast_to_raw(','fox_raw(')
    values={'l_id':41,'l_value1':'PARENT','l_base1':'PARENT','l_value2':'A','l_base2':'A',
            'l_item_weight':0,'l_base_weight':0,'l_active_route':active,'l_base_route':baseline}
    assert db.execute('select case when '+sql+' then 1 else 0 end',values).fetchone()==(expected,)


def test_kept_code_then_warning_back_to_baseline_still_saves_route_using_fresh_parent():
    b=EmittedBoundary();b.state.update(code='A',weight=0,route='R0',id=41)
    assert b.submit('B',route='R1')=='success'
    assert b.submit('A',destination=None,route='R1',revision=1)=='warning'
    assert b.state['code']=='A' and b.state['weight']==0 and b.state['route']=='R1'
    files,_,op,args=generated()
    code=re.search(r'process save-synthetic-record \(.*?```plsql\n(.*?)\n\s*```',files[op['page_file']].decode(),re.S)[1]
    dirty=re.search(r'select case when (.*?)then 1 else 0 end into l_changed from dual;',code)[1]
    db=sqlite3.connect(':memory:')
    db.create_function('fox_raw',1,lambda v:None if v is None else v.encode())
    db.create_function('decode',4,lambda a,c,yes,no:yes if a==c else no)
    convert=lambda sql:re.sub(r'\bl_[A-Za-z0-9_]+\b',lambda m:':'+m[0],sql).replace('utl_raw.cast_to_raw(','fox_raw(')
    values={'l_id':41,'l_value1':'PARENT','l_base1':'PARENT','l_value2':'A','l_base2':'A',
            'l_item_weight':0,'l_base_weight':0,'l_active_route':b.state['route'],'l_base_route':'R0'}
    assert db.execute('select case when '+convert(dirty)+' then 1 else 0 end',values).fetchone()==(1,)
    c=op['contract'];parent_route=c['fields']['parent_route']['column'];route=c['fields']['route']['column']
    db.execute('create table '+c['parent_table']+'(FOX_ROW_ID integer,'+parent_route+' text)')
    db.execute('insert into '+c['parent_table']+' values(1,\'R2\')')
    parent_read=re.search(r'select ('+parent_route+r') into l_route (from '+c['parent_table']+r' where FOX_ROW_ID=l_parent);',code)
    values['l_parent']=1
    values['l_route']=db.execute(convert('select '+parent_read[1]+' '+parent_read[2]),values).fetchone()[0]
    assert values['l_route']=='R2' and values['l_route']!=values['l_active_route']
    buffer,=json.loads(args[-1]['fox-package/buffer-plan.json'])['operations']
    columns=[f['column'] for f in buffer['key_bindings']]+[route,c['fields']['weight']['column']]
    db.execute('create table '+c['child_table']+'(FOX_ROW_ID integer,'+','.join(col+' text' for col in columns)+')')
    db.execute('insert into '+c['child_table']+' values(41,\'PARENT\',\'A\',\'R0\',\'0\')')
    update=re.search(r'update '+c['child_table']+r' set .*?where FOX_ROW_ID=l_id;',code)[0]
    db.execute(convert(update),values)
    assert db.execute('select '+route+' from '+c['child_table']+' where FOX_ROW_ID=41').fetchone()==('R2',)
    for slot in (40,44):
        assert f'p_attr_number=>{slot},p_attr_value=>l_route' in code


@pytest.mark.parametrize('old,new',[("Destination required","Unsafe &P1_NAME."),
                                   ("Already in load ","Unsafe ``` fenced ")])
def test_unsafe_source_message_cannot_enter_native_templates(old,new):
    with pytest.raises(ValueError):
        parse_item_validation(BODY.replace(old,new))


def test_unchanged_loaded_row_empty_input_and_competing_revision_are_preserved():
    b=EmittedBoundary();b.state.update(code='LOADED',id=41);b.row('LOADED','CURRENT')
    before=deepcopy(b.state)
    assert b.submit('LOADED')=='unchanged' and b.state==before
    for kwargs in ({'revision':5},{'approved':True},{'stale':True}):
        assert b.submit('EDITED',**kwargs)=='context' and b.state==before
    assert b.submit(None)=='empty'
    assert b.state['id']==41 and b.state['weight']==19 and b.state['route']=='OLD'
    b=EmittedBoundary();before=deepcopy(b.state)
    assert b.submit('X'*17)=='length' and b.state==before
    assert b.submit(None)=='unchanged' and b.state==before


@pytest.mark.parametrize('part',['source','chunks','trace','page','schema','receipt'])
def test_changed_proofs_are_rejected_or_reported_without_output_mutation(part):
    args=list(prepare());before=deepcopy(args[-1])
    if part=='source':args[0][0]=(args[0][0][0],args[0][0][1]+b' ')
    elif part=='chunks':args[2][0]['text']+=' '
    elif part=='trace':args[3]['blocks'][0]['table_name']='FOX_NATIVE_0000000000000000'
    elif part=='page':args[-1][next(p for p in args[-1] if 'fox_buffer_' in p)]+=b' '
    elif part=='schema':args[-1]['fox-package/supporting-schema.sql']+=b' '
    else:args[-1]['fox-package/synthetic-save-receipt.json']=b'{}'
    try:
        files,receipt=apply_item_validations(*args)
    except (ValueError,KeyError):
        return
    assert receipt['gaps'] and not receipt['generated_operations'] and files==args[-1]
