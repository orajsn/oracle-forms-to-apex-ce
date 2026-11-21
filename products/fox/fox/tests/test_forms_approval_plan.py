"""Complete fictional source, actual local SQLite rows, explicit Forms adapters.

No test here executes Oracle, customer DML, external calls or an APEX runtime.
"""
from copy import deepcopy
import json
import sqlite3
from xml.etree import ElementTree as ET

import pytest

from fox.forms_approval_plan import (AdapterOutcome, build_approval_plan,
                                     execute_approval_model, parse_approval)
from test_forms_synthetic_save import source as save_source, prepare as save_prepare


BODY = """DECLARE
 BAG_COUNT NUMBER:=0; EMPTY_BAG VARCHAR2(30):=NULL;
 LEVEL_BEFORE NUMBER; MISSING_WEIGHT NUMBER;
BEGIN
 SELECT COUNT(0) INTO MISSING_WEIGHT FROM PIECES
 WHERE NVL(ACTUAL_WEIGHT,0)=0 AND LOAD_REFERENCE=:LOAD_REFERENCE;
 IF MISSING_WEIGHT>0 THEN MESSAGE('Save actual weight first'); MESSAGE('Save actual weight first');
 RAISE FORM_TRIGGER_FAILURE; END IF;
 IF :TARGET_CITY IS NULL THEN MESSAGE('Destination required'); MESSAGE('Destination required');
 RAISE FORM_TRIGGER_FAILURE; END IF;
 GO_ITEM('LOAD_REFERENCE');
 LEVEL_BEFORE:=:SYSTEM.MESSAGE_LEVEL;
 IF :SYSTEM.FORM_STATUS='CHANGED' THEN
 :SYSTEM.MESSAGE_LEVEL:=5; COMMIT_FORM; :SYSTEM.MESSAGE_LEVEL:=LEVEL_BEFORE; END IF;
 IF FORM_SUCCESS THEN
 GO_BLOCK('PIECES'); FIRST_RECORD;
 IF :PIECE_CODE IS NOT NULL THEN LOOP
 :STORED_ROUTE:=:PLANNED_ROUTE;
 IF :SYSTEM.LAST_RECORD='TRUE' THEN EXIT; END IF;
 NEXT_RECORD; END LOOP; FIRST_RECORD; END IF;
 :SYSTEM.MESSAGE_LEVEL:=5; COMMIT_FORM; :SYSTEM.MESSAGE_LEVEL:=LEVEL_BEFORE;
 BEGIN SELECT COUNT(0) INTO BAG_COUNT FROM PIECES WHERE LOAD_REFERENCE=:LOAD_REFERENCE;
 EXCEPTION WHEN OTHERS THEN NULL; END;
 IF BAG_COUNT=0 THEN MESSAGE('Add a piece'); MESSAGE('Add a piece');
 RAISE FORM_TRIGGER_FAILURE; END IF;
 BEGIN SELECT PIECE_CODE INTO EMPTY_BAG FROM PIECES WHERE LOAD_REFERENCE=:LOAD_REFERENCE
 AND NOT EXISTS (SELECT 1 FROM CONSIGNMENTS WHERE NOTE_PIECE=PIECE_CODE AND NOTE_LOAD=LOAD_REFERENCE)
 AND ROWNUM=1; EXCEPTION WHEN OTHERS THEN NULL; END;
 IF EMPTY_BAG IS NOT NULL THEN MESSAGE('Add note for '||EMPTY_BAG); MESSAGE('Add note for '||EMPTY_BAG);
 RAISE FORM_TRIGGER_FAILURE; END IF;
 IF FORM_SUCCESS THEN :APPROVED:='Y';
 :SYSTEM.MESSAGE_LEVEL:=5; COMMIT_FORM; :SYSTEM.MESSAGE_LEVEL:=LEVEL_BEFORE;
 ACME.SEND_NOTICE(:LOAD_REFERENCE,'Dispatch ready');
 ACME.RECORD_ENTRY(:CONSIGNMENTS.NOTE_LOAD,:SYSTEM.CURRENT_FORM,:GLOBAL.USER_CODE,'Dispatch','DP');
 END IF; END IF;
 POLICY; :SYSTEM.MESSAGE_LEVEL:=LEVEL_BEFORE;
 EXCEPTION WHEN OTHERS THEN :SYSTEM.MESSAGE_LEVEL:=LEVEL_BEFORE; END;"""


def source(*, renamed=False, changed_body=None, missing_provider=False):
    docs = save_source()
    root = ET.fromstring(docs[0][1])
    parent, child = list(root.iter('Block'))[:2]
    parent.set('QueryDataSourceType','Table'); parent.set('QueryDataSourceName','LOADS')
    child.set('QueryDataSourceType','Table'); child.set('QueryDataSourceName','PIECES')
    ET.SubElement(parent,'Item',Name='TARGET_CITY',ItemType='Text Item',DatabaseItem='true',
                  DataType='Char',MaximumLength='12',DataLengthSemantics='BYTE')
    button = ET.SubElement(parent,'Item',Name='AUTHORIZE',ItemType='Push Button',DatabaseItem='false',
                           DataType='Char',MaximumLength='30',Enabled='true')
    ET.SubElement(button,'Trigger',Name='WHEN-BUTTON-PRESSED',TriggerText=changed_body or BODY)
    ET.SubElement(child,'Item',Name='ACTUAL_WEIGHT',ItemType='Text Item',DatabaseItem='true',
                  DataType='Number',MaximumLength='8')
    notes = ET.SubElement(root,'Block',Name='CONSIGNMENTS',DatabaseBlock='true',
                          QueryDataSourceType='Table',QueryDataSourceName='CONSIGNMENTS')
    for name in ('NOTE_LOAD','NOTE_PIECE','NOTE_CODE'):
        ET.SubElement(notes,'Item',Name=name,ItemType='Text Item',DatabaseItem='true',
                      DataType='Char',MaximumLength='30',DataLengthSemantics='BYTE')
    ET.SubElement(child,'Relation',Name='PIECES_NOTES',DetailBlock='CONSIGNMENTS',RelationType='Join',
                  JoinCondition='PIECES.LOAD_REFERENCE=CONSIGNMENTS.NOTE_LOAD AND PIECES.PIECE_CODE=CONSIGNMENTS.NOTE_PIECE',
                  AutoQuery='false',Deferred='false',DeleteRecord='Isolated')
    helper = next(x for x in root.iter('ProgramUnit') if x.get('Name') == 'POLICY')
    helper.set('ProgramUnitText',helper.get('ProgramUnitText').replace(
        'IS BEGIN ',"IS BEGIN SET_ITEM_PROPERTY('LOADS.AUTHORIZE',ENABLED,PROPERTY_TRUE); ").replace(
        "IF :LOADS.APPROVED IS NOT NULL AND :LOADS.APPROVED='Y' THEN ",
        "IF :LOADS.APPROVED IS NOT NULL AND :LOADS.APPROVED='Y' THEN SET_ITEM_PROPERTY('LOADS.AUTHORIZE',ENABLED,PROPERTY_FALSE); "))
    for item in root.iter('Item'):
        if item.get('DatabaseItem') == 'true': item.set('ColumnName',item.get('Name'))
    if missing_provider: child.set('QueryDataSourceName','UNVERIFIED_PROVIDER')
    raw = ET.tostring(root)
    if renamed:
        for old,new in ((b'DISPATCH_DRAFT',b'DEPOT'),(b'LOADS',b'HEADERS'),(b'PIECES',b'CRATES'),
                        (b'LOAD_REFERENCE',b'HEADER_REF'),(b'PIECE_CODE',b'CRATE_REF'),
                        (b'CONSIGNMENTS',b'RECEIPTS'),(b'NOTE_LOAD',b'RECEIPT_HEADER'),
                        (b'NOTE_PIECE',b'RECEIPT_CRATE'),(b'TARGET_CITY',b'END_TOWN'),
                        (b'ACTUAL_WEIGHT',b'MASS'),(b'STORED_ROUTE',b'ACTIVE_PATH'),
                        (b'PLANNED_ROUTE',b'PLANNED_PATH'),(b'APPROVED',b'RELEASED'),
                        (b'AUTHORIZE',b'RELEASE'),(b'POLICY',b'CHECK_RELEASE')):
            raw=raw.replace(old,new)
    return [('renamed.xml' if renamed else 'approval.xml',raw)]


def prepare(docs=None):
    docs = docs or source()
    packet,chunks,trace,files = save_prepare(docs)
    return docs,packet,chunks,trace,files


def bound(**kwargs):
    args=prepare(source(**kwargs))
    plan=build_approval_plan(*args)
    assert not plan['gaps']
    return plan['operations'][0],args


@pytest.mark.parametrize('renamed',[False,True])
def test_whole_source_is_bound_to_button_fields_tables_and_declared_two_level_relations(renamed):
    args=prepare(source(renamed=renamed)); before=deepcopy(args)
    plan=build_approval_plan(*args)
    assert plan==build_approval_plan(*args) and args==before and not plan['gaps']
    op,=plan['operations']; c=op['contract']
    assert len(c['relations'])==2 and len(c['blocks'])==3
    assert c['fields']['weight']['data_type']=='NUMBER'
    assert c['fields']['bag_number']==c['fields']['bag_key']
    assert [t['stage_id'] for t in op['transaction_boundaries']]==['dirty_commit','route_commit','approval_commit']
    stages=[s['id'] for s in op['stages']]
    assert stages.index('approval_commit')<stages.index('external_1')<stages.index('external_2')<stages.index('final_policy')
    by_stage={s['id']:s for s in op['stages']}
    assert all('indirect_validation_and_write_triggers' in by_stage[s]['required_capabilities']
               for s in ('dirty_commit','route_commit','approval_commit'))
    assert 'current_consignment_buffer' in by_stage['external_2']['required_capabilities']
    assert all(by_stage[s]['provider_status']=='unbound' for s in ('route_copy','external_1','external_2'))
    assert all(call['call_site_id'] and call['formal_types']=='unknown' for call in op['parsed']['external_calls'])
    assert all(not plan[k] for k in ('full_event_converted','runtime_verified','customer_dml_executed','business_accepted'))
    assert args[-1]['fox-package/sources/'+args[0][0][0]]==args[0][0][1]


def test_parser_preserves_exact_observed_arguments_defaults_and_outer_handler():
    p,r=parse_approval(BODY.replace('\n','&#10;'))
    assert r['substitutions'] and p['messages']['weight']==['Save actual weight first']*2
    assert p['queries']['bag_count']['exception_default']==0
    assert p['queries']['missing_consignment']['exception_default'] is None
    assert p['queries']['missing_consignment']['rownum']==1 and p['queries']['missing_consignment']['ordering'] is None
    assert p['outer_exception']=={'when':'OTHERS','action':'restore_saved_message_level','reraises':False,
                                  'rollback':False,'before_capture_saved_value':None}
    c=p['external_calls'][1]
    assert c['observed_source'].startswith('ACME.RECORD_ENTRY(') and c['observed_source'].endswith(')')
    assert c['arguments'][0]=={'kind':'reference','parts':['CONSIGNMENTS','NOTE_LOAD']}
    assert c['arguments'][2]=={'kind':'reference','parts':['GLOBAL','USER_CODE']}


@pytest.mark.parametrize('old,new',[
    ('ROWNUM=1','ROWNUM=2'),('NVL(ACTUAL_WEIGHT,0)=0','ACTUAL_WEIGHT IS NULL'),
    ('NEXT_RECORD;','NEXT_RECORD; DELETE_RECORD;'),('WHEN OTHERS THEN NULL','WHEN NO_DATA_FOUND THEN NULL'),
    ('COMMIT_FORM;','NULL;'),('POLICY;', 'POLICY; COMMIT;'),
    ('AND NOTE_LOAD=LOAD_REFERENCE','AND NOTE_LOAD=OTHER_KEY'),
    ("GO_ITEM('LOAD_REFERENCE')","GO_ITEM('TARGET_CITY')"),
    ('END;','END; UNKNOWN_ACTIVE_CALL;'),
])
def test_parser_rejects_unknown_or_changed_active_statement_with_precise_gap(old,new):
    changed=BODY.replace(old,new,1)
    with pytest.raises(ValueError,match='APPROVAL_'): parse_approval(changed)


def test_missing_source_target_provider_is_encoded_with_precise_gap():
    plan=build_approval_plan(*prepare(source(missing_provider=True)))
    assert len(plan['operations'])==1 and plan['operations'][0]['status']=='encoded_target_binding_missing'
    assert plan['gaps'][0]['reason']=='APPROVAL_EXACT_BAG_TABLE'
    assert len(plan['operations'][0]['stages'])==22


def test_normal_pipeline_packet_enrichment_preserves_authoritative_source_and_complete_chunk_checks():
    args=list(prepare())
    baseline=build_approval_plan(*args)
    args[1]['selection_status']='SELECTED'
    args[1]['selected_code_unit_ids']=[c['code_unit_id'] for c in args[2]]
    assert build_approval_plan(*args)==baseline
    args[1]['sources'][0]['facts']['objects'][0]['name']='FORGED_MODULE'
    with pytest.raises(ValueError,match='APPROVAL_SOURCE_BINDING'):build_approval_plan(*args)


def test_enriched_packet_cannot_replace_source_bytes_or_complete_chunk_descriptor():
    args=list(prepare())
    args[1]['selection_status']='SELECTED'
    args[0][0]=(args[0][0][0],args[0][0][1]+b' ')
    with pytest.raises(ValueError,match='APPROVAL_SOURCE_BINDING'):build_approval_plan(*args)
    args=list(prepare());args[1]['selection_status']='SELECTED'
    args[1]['chunks'][0]['sha256']='0'*64
    with pytest.raises(ValueError,match='APPROVAL_SOURCE_BINDING'):build_approval_plan(*args)


@pytest.mark.parametrize('boundary',['trace','chunks','source','manifest','original','field','relation'])
def test_forged_source_or_target_identity_never_acquires_an_executable_contract(boundary):
    args=list(prepare())
    if boundary=='trace': args[3]['source_binding']='wrong'
    elif boundary=='chunks': args[2][0]['text']+=' NULL;'
    elif boundary=='source': args[0][0]=(args[0][0][0],args[0][0][1]+b' ')
    elif boundary=='manifest':
        m=json.loads(args[-1]['fox-package/source-manifest.json']);m['selected_chunk_hashes']={}
        args[-1]['fox-package/source-manifest.json']=json.dumps(m).encode()
    elif boundary=='original': args[-1]['fox-package/sources/'+args[0][0][0]]+=b' '
    elif boundary=='field':
        f=next(f for b in args[3]['blocks'] for f in b['items'] if f['source_name']=='ACTUAL_WEIGHT');f['source_name']='OTHER'
        args[-1]['fox-package/source-to-page.json']=json.dumps(args[3]).encode()
    elif boundary=='relation':
        docs=source();docs=[(docs[0][0],docs[0][1].replace(b'PIECES.PIECE_CODE=CONSIGNMENTS.NOTE_PIECE',b'PIECES.UNEDITED_NOTE=CONSIGNMENTS.NOTE_PIECE'))]
        args=list(prepare(docs))
    if boundary in ('field','relation'):
        plan=build_approval_plan(*args);assert plan['gaps'] and 'contract' not in plan['operations'][0]
    else:
        with pytest.raises(ValueError,match='APPROVAL_'):build_approval_plan(*args)


class SQLiteModelAdapter:
    """Actual SQLite saved rows, separate modeled buffer/cursor/Forms outcomes.

    The explicit successful provider receipts here are only test input. They do
    not establish the existence of corresponding Oracle/APEX target providers.
    """
    def __init__(self,op,files,*,bags=(('A',2),('B',3)),notes=('A','B'),destination='Town',dirty=False,
                 fail=None,form_success=(True,True)):
        self.c=op['contract'];self.fields=self.c['fields'];self.db=sqlite3.connect(':memory:')
        ddl=files['fox-package/supporting-schema.sql'].decode().replace(
            'NUMBER GENERATED BY DEFAULT ON NULL AS IDENTITY PRIMARY KEY','INTEGER PRIMARY KEY')
        self.db.executescript(ddl)
        self.fail=fail or {};self.destination=destination;self.dirty=dirty
        self.success=iter(form_success);self.level=17;self.cursor=0;self.routes={};self.approved=None
        self.calls=[];self.observed=[]
        b=self.c['blocks']['bag']['table_name'];n=self.c['blocks']['consignment']['table_name'];f=self.fields
        for i,(key,weight) in enumerate(bags,1):
            self.db.execute(f"insert into {b}(FOX_ROW_ID,{f['bag_parent']['column']},{f['bag_key']['column']},{f['bag_weight']['column']},{f['bag_route']['column']}) values(?, 'H1', ?, ?, 'OLD')",(i,key,weight))
        # A sibling parent is never part of the related Forms cursor.
        self.db.execute(f"insert into {b}(FOX_ROW_ID,{f['bag_parent']['column']},{f['bag_key']['column']},{f['bag_weight']['column']},{f['bag_route']['column']}) values(99,'H2','SIBLING',2,'KEEP')")
        for i,key in enumerate(notes,1):
            self.db.execute(f"insert into {n}(FOX_ROW_ID,{f['consignment_parent']['column']},{f['consignment_key']['column']}) values(?,'H1',?)",(i,key))
        self.db.commit()
        self.rows=self.db.execute(f"select FOX_ROW_ID,{f['bag_key']['column']} from {b} where {f['bag_parent']['column']}='H1' order by FOX_ROW_ID").fetchall()

    def perform(self,o):
        self.observed.append(o)
        if o.id in self.fail:return self.fail[o.id]
        value=None
        b=self.c['blocks']['bag']['table_name'];n=self.c['blocks']['consignment']['table_name'];f=self.fields
        if o.kind=='query':
            if o.id=='weight_count':
                value=self.db.execute(f"select count(0) from {b} where coalesce({f['bag_weight']['column']},0)=0 and {f['bag_parent']['column']}='H1'").fetchone()[0]
            elif o.id=='bag_count':
                value=self.db.execute(f"select count(0) from {b} where {f['bag_parent']['column']}='H1'").fetchone()[0]
            else:
                row=self.db.execute(f"select b.{f['bag_key']['column']} from {b} b where b.{f['bag_parent']['column']}='H1' and not exists(select 1 from {n} n where n.{f['consignment_key']['column']}=b.{f['bag_key']['column']} and n.{f['consignment_parent']['column']}=b.{f['bag_parent']['column']}) limit 1").fetchone()
                value=row[0] if row else None
        elif o.id=='destination_guard':value=self.destination
        elif o.kind=='read_message_level':value=self.level
        elif o.kind=='set_message_level':self.level=o.payload['value']
        elif o.kind=='read_form_status':value='CHANGED' if self.dirty else 'QUERY'
        elif o.kind=='form_success':value=next(self.success)
        elif o.kind=='first_record':self.cursor=0
        elif o.id=='first_bag_key':value=self.rows[0][1] if self.rows else None
        elif o.kind=='current_related_bag':value={'identity':self.rows[self.cursor][0],'related_to_current_header':True}
        elif o.kind=='assign_current_bag_route':self.routes[o.payload['row_identity']]='CURRENT_ROUTE'
        elif o.kind=='read_last_record':value=self.cursor==len(self.rows)-1
        elif o.kind=='next_record':self.cursor+=1
        elif o.kind=='assign_field':self.approved=o.payload['value']
        elif o.kind=='commit':
            for row,route in self.routes.items():
                self.db.execute(f"update {b} set {f['bag_route']['column']}=? where FOX_ROW_ID=?",(route,row))
            self.db.commit();self.routes={}
            return AdapterOutcome('completed',committed=True)
        elif o.kind=='qualified_call':self.calls.append(o.payload['call_site_id'])
        return AdapterOutcome('completed',value)


def modeled(**kwargs):
    op,args=bound(); adapter=SQLiteModelAdapter(op,args[-1],**kwargs)
    return execute_approval_model(op,adapter),adapter,op


@pytest.mark.parametrize('weight',[None,0])
def test_weight_precedes_destination_and_capture_and_outer_restores_initial_null(weight):
    r,a,_=modeled(bags=(('A',weight),),destination=None)
    assert r['messages']==['Save actual weight first']*2 and not r['commit_history']
    assert [e['stage_id'] for e in r['events']]==['weight_count','outer_exception'] and a.level is None
    assert r['status']=='source_guard_rejected'


def test_destination_after_weight_no_commit_or_cursor_and_no_negative_weight_invention():
    r,a,_=modeled(bags=(('A',-2),),destination=None)
    assert r['messages']==['Destination required']*2 and not r['commit_history']
    assert a.level is None


@pytest.mark.parametrize('dirty,expected',[(False,['route_commit','approval_commit']),
                                          (True,['dirty_commit','route_commit','approval_commit'])])
def test_all_independent_commits_route_iterations_external_order_and_sibling_preservation(dirty,expected):
    r,a,op=modeled(dirty=dirty)
    assert [e['stage_id'] for e in r['commit_history']]==expected
    assert r['status']=='source_path_completed_by_adapters' and a.level==17
    assert a.calls==[c['call_site_id'] for c in op['parsed']['external_calls']]
    stages=[e['stage_id'] for e in r['events']]
    assert stages.count('route_copy')==2 and stages.index('approval_commit')<stages.index('external_1')<stages.index('external_2')
    b=a.c['blocks']['bag']['table_name'];f=a.fields
    assert a.db.execute(f"select {f['bag_route']['column']} from {b} order by FOX_ROW_ID").fetchall()==[('CURRENT_ROUTE',),('CURRENT_ROUTE',),('KEEP',)]
    assert not r['business_approved'] and not r['customer_dml_executed']


@pytest.mark.parametrize('success,commits,calls',[(False,0,0),(True,2,2)])
def test_first_form_success_false_skips_whole_block_but_runs_final_helper(success,commits,calls):
    r,a,_=modeled(form_success=(success,True))
    assert len(r['commit_history'])==commits and len(a.calls)==calls
    assert any(e['stage_id']=='final_policy' for e in r['events'])


def test_second_form_success_false_preserves_route_commit_and_skips_approval():
    r,a,_=modeled(form_success=(True,False))
    assert [e['stage_id'] for e in r['commit_history']]==['route_commit'] and not a.calls and a.approved is None
    assert r['status']=='source_path_completed_by_adapters'


def test_no_bags_and_count_exception_default_reject_after_unconditional_route_commit():
    for kwargs in ({'bags':(),'notes':()}, {'fail':{'bag_count':AdapterOutcome('failed',reason='query exception')}}):
        r,a,_=modeled(**kwargs)
        assert r['messages']==['Add a piece']*2
        assert [e['stage_id'] for e in r['commit_history']]==['route_commit'] and not a.calls
        assert a.level==17 and r['status']=='source_guard_rejected'


def test_not_exists_requires_both_foreign_keys_and_source_messages_after_commit():
    r,a,_=modeled(notes=('A',))
    assert r['messages']==['Add note for B']*2 and not a.calls
    assert [e['stage_id'] for e in r['commit_history']]==['route_commit']


def test_consignment_with_same_bag_key_under_another_header_does_not_satisfy_not_exists():
    op,args=bound(); a=SQLiteModelAdapter(op,args[-1],bags=(('A',2),),notes=())
    n=a.c['blocks']['consignment']['table_name'];f=a.fields
    a.db.execute(f"insert into {n}(FOX_ROW_ID,{f['consignment_parent']['column']},{f['consignment_key']['column']}) values(50,'H2','A')")
    a.db.commit()
    r=execute_approval_model(op,a)
    assert r['messages']==['Add note for A']*2 and not a.calls


def test_source_null_first_bag_key_skips_only_route_loop_and_retains_later_checks():
    r,a,_=modeled(bags=((None,2),),notes=())
    assert all(o.id!='route_copy' for o in a.observed)
    assert any(o.id=='bag_count' for o in a.observed)
    assert [e['stage_id'] for e in r['commit_history']]==['route_commit','approval_commit']
    assert len(a.calls)==2 and not r['business_approved']


def test_missing_consignment_query_exception_uses_null_default_in_original_source():
    r,a,_=modeled(notes=(),fail={'missing_consignment':AdapterOutcome('failed',reason='SQL error')})
    assert r['status']=='source_path_completed_by_adapters' and len(a.calls)==2
    assert not r['messages'] and not r['business_approved']


@pytest.mark.parametrize('stage,commits',[
    ('weight_count',[]),('focus_header',[]),('route_copy',[]),
    ('bag_count',['route_commit']),('approval_assignment',['route_commit']),
    ('external_1',['route_commit','approval_commit']),('external_2',['route_commit','approval_commit']),
    ('final_policy',['route_commit','approval_commit']),
])
def test_unmet_capabilities_stop_at_exact_boundary_preserving_prior_commits(stage,commits):
    r,a,_=modeled(fail={stage:AdapterOutcome('unmet',reason='No verified target provider')})
    assert r['status']=='unmet' and r['pending']==[{'stage_id':stage,'reason':'No verified target provider'}]
    assert [e['stage_id'] for e in r['commit_history']]==commits
    assert r['last_stage']==stage and not r['business_approved']


def test_unknown_commit_is_recorded_once_and_never_retried_or_undone_by_later_failure():
    r,a,_=modeled(dirty=True,fail={'dirty_commit':AdapterOutcome('unknown',reason='transport lost')})
    assert r['status']=='unknown' and len(r['commit_history'])==1
    assert r['last_stage']=='dirty_commit' and len([o for o in a.observed if o.kind=='commit'])==1
    assert a.level==5 and r['pending'][0]['stage_id']=='dirty_commit'


def test_failed_external_call_after_commit_is_swallowed_restores_level_and_never_retries():
    r,a,_=modeled(fail={'external_1':AdapterOutcome('failed',reason='explicit provider exception')})
    assert r['status']=='source_exception_swallowed' and a.level==17
    assert [e['stage_id'] for e in r['commit_history']]==['route_commit','approval_commit']
    assert len([o for o in a.observed if o.kind=='qualified_call'])==1
    assert all(e['stage_id']!='final_policy' for e in r['events'])


def test_commit_return_without_success_flag_still_follows_source_and_requires_later_form_success():
    # COMMIT_FORM can return FORM_SUCCESS false without raising; source has no
    # post-route/post-approval FORM_SUCCESS check immediately before next work.
    r,a,_=modeled(fail={'approval_commit':AdapterOutcome('completed',committed=False)})
    assert r['status']=='source_path_completed_by_adapters' and len(a.calls)==2
    assert r['commit_history'][-1]['committed'] is False and not r['business_approved']


def test_commit_completed_without_explicit_commit_outcome_fails_closed():
    r,_,_=modeled(fail={'route_commit':AdapterOutcome('completed')})
    assert r['status']=='unknown' and r['pending'][0]['reason']=='commit_outcome_unknown'


@pytest.mark.parametrize('stage,value,reason',[
    ('weight_count',None,'count_outcome_unknown'),
    ('form_success_routes',None,'explicit_form_success_required'),
    ('route_current_context',{'identity':1,'related_to_current_header':False},'current_related_bag_required'),
    ('last_bag',None,'last_record_outcome_unknown'),
])
def test_unproved_or_malformed_provider_data_is_unknown_instead_of_dummy_success(stage,value,reason):
    r,_,_=modeled(fail={stage:AdapterOutcome('completed',value)})
    assert r['status']=='unknown' and r['pending']==[{'stage_id':stage,'reason':reason}]
    assert r['last_stage']==stage and not r['business_approved']


@pytest.mark.parametrize('stage,dirty,commits',[
    ('weight_count',False,[]),('focus_header',False,[]),('dirty_commit',True,['dirty_commit']),
    ('route_copy',True,['dirty_commit']),('route_commit',True,['dirty_commit','route_commit']),
    ('approval_assignment',True,['dirty_commit','route_commit']),
    ('approval_commit',True,['dirty_commit','route_commit','approval_commit']),
])
def test_source_exception_before_and_after_independent_commit_keeps_exact_commit_history(stage,dirty,commits):
    outcome=AdapterOutcome('failed',reason='Explicit target exception',committed=False if 'commit' in stage else None)
    r,a,_=modeled(dirty=dirty,fail={stage:outcome})
    assert r['status']=='source_exception_swallowed' and r['failure_stage']==stage
    assert [e['stage_id'] for e in r['commit_history']]==commits
    assert a.level==(None if stage in ('weight_count','focus_header') else 17)
    assert not a.calls


def test_outer_restore_failure_is_reported_without_inventing_message_level_or_rollback():
    r,a,_=modeled(bags=(('A',0),),fail={'outer_exception':AdapterOutcome('failed',reason='null level rejected')})
    assert r['status']=='source_exception_handler_failed' and not r['commit_history']
    assert r['failure_stage']=='weight_guard' and a.level==17


def test_restore_exception_after_commit_reaches_outer_handler_without_rollback_or_next_queries():
    r,a,_=modeled(fail={'route_commit_restore':AdapterOutcome('failed',reason='restoration failed')})
    assert r['status']=='source_exception_swallowed' and a.level==17
    assert r['failure_stage']=='route_commit_restore'
    assert [e['stage_id'] for e in r['commit_history']]==['route_commit']
    assert all(o.id!='bag_count' for o in a.observed)


def test_missing_target_after_second_commit_never_rolls_back_or_invents_business_approval():
    r,a,_=modeled(fail={'external_2':AdapterOutcome('unknown',reason='No retained invocation receipt')})
    assert r['status']=='unknown' and a.calls and len(a.calls)==1
    assert [e['stage_id'] for e in r['commit_history']]==['route_commit','approval_commit']
    assert all(e['kind']!='rollback' for e in r['events']) and not r['business_approved']


def test_operation_is_immutable_and_cannot_replace_source_argument_after_binding():
    op,_=bound(); op['parsed']['external_calls'][0]['arguments'][1]['value']='Invented outcome'
    class Never:
        def perform(self,o):raise AssertionError('tampered operation reached adapter')
    with pytest.raises(ValueError,match='IMMUTABLE_OPERATION_BINDING'):execute_approval_model(op,Never())


def test_oversized_missing_bag_select_is_reported_by_target_then_source_uses_null_default():
    # Length semantics belong to the source environment; the model does not
    # guess character versus byte capacity or silently truncate a target value.
    r,a,_=modeled(fail={'missing_consignment':AdapterOutcome('failed',reason='SELECT INTO value error')})
    observed=next(o for o in a.observed if o.id=='missing_consignment')
    assert observed.payload['select_into_capacity']==30
    assert observed.payload['length_semantics']=='source_environment_provider_required'
    assert r['status']=='source_path_completed_by_adapters' and len(a.calls)==2
