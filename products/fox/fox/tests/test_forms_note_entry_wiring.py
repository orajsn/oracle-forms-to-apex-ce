"""Executed generated SQL and DOM-model checks; no Oracle/live acceptance claim."""
from copy import deepcopy
import hashlib
import json
import math
import re
import shutil
import sqlite3
import subprocess
from xml.etree import ElementTree as ET

import pytest

from fox.forms_note_entry_wiring import apply_note_entry_wiring, RECEIPT
from fox.forms_item_validation import apply_item_validations
from fox.forms_item_commands import apply_item_commands
from fox.forms_item_entry_workflow import apply_item_entry_workflows
from fox.forms_master_detail import _fingerprint
from test_forms_item_validation import source as validation_source, prepare as validation_prepare


def source(renamed=False):
    name,raw=validation_source()[0]
    root=ET.fromstring(raw)
    parent,bag=list(root.iter('Block'))[:2]
    def item(b,n,dtype='Char',stored=True,**attrs):
        return ET.SubElement(b,'Item',Name=n,DatabaseItem=str(stored).lower(),DataType=dtype,
                             MaximumLength='40',ItemType='Text Item',**attrs)
    notice=item(parent,'NOTICE')
    ET.SubElement(notice,'Trigger',Name='KEY-NEXT-ITEM',TriggerText="GO_ITEM('PIECES.PIECE_CODE');")
    status=item(bag,'STATUS')
    ET.SubElement(status,'Trigger',Name='KEY-NEXT-ITEM',TriggerText="GO_ITEM('NOTES.NOTE_CODE');")
    note=ET.SubElement(root,'Block',Name='NOTES',DatabaseBlock='true')
    item(note,'HEADER');item(note,'BAG');item(note,'NOTE_CODE')
    note.set('NavigationStyle','Change Record')
    next(i for i in note.iter('Item') if i.get('Name')=='NOTE_CODE').set('CanvasName','C')
    owner=item(note,'STEP',stored=False,CanvasName='C')
    ET.SubElement(owner,'Trigger',Name='WHEN-NEW-ITEM-INSTANCE',TriggerText="""IF :NOTE_CODE IS NOT NULL AND :CITY <> 'INVALID' AND NVL(:APPROVED,'N')='N' THEN
    :COST_WEIGHT:=:TOTAL;IF :SYSTEM.FORM_STATUS <> 'QUERY' THEN COMMIT_FORM;END IF;NEXT_ITEM;
    ELSIF :CITY='INVALID' AND NVL(:APPROVED,'N')='N' THEN GO_ITEM('NOTE_CODE');ELSE NEXT_RECORD;END IF;""")
    item(note,'CITY',stored=False);item(note,'MASS','Number')
    item(note,'ROUNDED','Number',False,CalculateMode='Formula',Formula='CEIL(:MASS)')
    item(note,'TOTAL','Number',False,CalculateMode='Summary',SummaryFunction='Sum',SummaryBlockName='NOTES',SummaryItemName='ROUNDED')
    ET.SubElement(bag,'Relation',Name='BAG_NOTES',DetailBlock='NOTES',RelationType='JOIN',
                  JoinCondition=f'PIECES.LOAD_REFERENCE=NOTES.HEADER AND PIECES.PIECE_CODE=NOTES.BAG')
    ET.SubElement(root,'ProgramUnit',Name='REFRESH_NOTE',ProgramUnitType='Procedure',
                  ProgramUnitText="PROCEDURE REFRESH_NOTE IS BEGIN GO_BLOCK('LOADS');GO_ITEM('NOTICE');:COST_WEIGHT:=:TOTAL;END;")
    raw=ET.tostring(root)
    if renamed:
        for old,new in ((b'COST_WEIGHT',b'CHARGE_MASS'),(b'NOTES',b'PARCELS'),(b'NOTE_CODE',b'PARCEL_CODE'),
                        (b'REFRESH_NOTE',b'RECALCULATE'),(b'MASS',b'WEIGHT_INPUT')):
            raw=raw.replace(old,new)
    return [(name,raw)]


def prepare(renamed=False,docs=None):
    docs=docs or source(renamed)
    docs,p,c,t,f=validation_prepare(docs)
    f,r=apply_item_validations(docs,p,c,t,f)
    f['fox-package/item-validation-receipt.json']=json.dumps(r).encode()
    assert len(r['generated_operations'])==1
    f,r=apply_item_commands(docs,p,c,t,f)
    f['fox-package/item-command-receipt.json']=json.dumps(r).encode()
    f,r=apply_item_entry_workflows(docs,p,c,t,f)
    assert len(r['adapted_operations'])==1
    return docs,p,c,t,f


@pytest.mark.parametrize('renamed',[False,True])
def test_current_cost_assignment_is_source_bound_and_does_not_modify_bag_editor(renamed):
    args=prepare(renamed);before=deepcopy(args)
    out,r=apply_note_entry_wiring(*args)
    assert args==before and (out,r)==apply_note_entry_wiring(*args)
    assert not r['gaps'] and len(r['adapted_operations'])==2 and not r['generated_operations']
    op,routine=r['adapted_operations']
    assert {n for n in out if out[n]!=args[-1].get(n)}=={RECEIPT,op['page_file']}
    assert op['draft_assignment_slot']=='n002'
    assert op['contract']['fields']['weight']['source_item_id']
    assert routine['callable']=='window.foxNoteEntryBridge.invoke' and not routine['source_caller_installed']
    assert all(o['source_unit_sha256'] and not o['runtime_verified'] and not o['business_accepted'] for o in (op,routine))
    assert out['fox-package/sources/'+args[0][0][0]]==args[0][0][1]
    assert 'Open this header' in out[op['page_file']].decode()
    assert 'Unposted consignment edits' in out[op['page_file']].decode()
    assert 'reloadOnSubmit: always' in out[op['page_file']].decode()


class SQL:
    """Run the emitted SELECTs, including full composite selection and guards.

    SQLite does not prove Oracle locking, collection APIs or APEX transactions.
    """
    def __init__(self):
        self.args=prepare();_,self.r=apply_note_entry_wiring(*self.args);self.op=self.r['adapted_operations'][0]
        self.db=sqlite3.connect(':memory:')
        for name,n,fn in [('nvl',2,lambda a,b:b if a is None else a),('ceil',1,lambda v:None if v is None else math.ceil(v)),
                          ('standard_hash',2,lambda v,a:None if v is None else hashlib.sha256(str(v).encode()).digest()),
                          ('rawtohex',1,lambda v:None if v is None else v.hex().upper()),
                          ('decode',4,lambda a,b,y,n:y if a==b else n),('fox_raw',1,lambda v:None if v is None else str(v).encode())]:
            self.db.create_function(name,n,fn)
        self.blocks={b['name']:b for b in self.args[3]['blocks'] if b['classification']=='database'}
        for b in self.blocks.values():
            self.db.execute('create table '+b['table_name']+'(FOX_ROW_ID integer,'+','.join(f['column']+' '+('numeric' if f['data_type']=='NUMBER' else 'text') for f in b['items'])+')')
        self.insert('LOADS',1,LOAD_REFERENCE='H1',APPROVED='N',PLANNED_ROUTE='R')
        self.insert('LOADS',2,LOAD_REFERENCE='H2',APPROVED='N',PLANNED_ROUTE='R')
        self.insert('PIECES',11,LOAD_REFERENCE='H1',PIECE_CODE='SAME',STORED_ROUTE='R',COST_WEIGHT=8)
        self.insert('PIECES',12,LOAD_REFERENCE='H2',PIECE_CODE='SAME',STORED_ROUTE='R',COST_WEIGHT=7)
        self.insert('NOTES',21,HEADER='H1',BAG='SAME',NOTE_CODE='N1',CITY='VALID',MASS=.25)
        self.insert('NOTES',22,HEADER='H1',BAG='SAME',NOTE_CODE='N2',CITY='VALID',MASS=.25)
        self.insert('NOTES',23,HEADER='H2',BAG='SAME',NOTE_CODE='N3',CITY='INVALID',MASS=8.1)
        self.insert('NOTES',24,HEADER='H1',BAG='OTHER',NOTE_CODE='N4',CITY='INVALID',MASS=40.1)
    def col(self,b,n):return next(f['column'] for f in self.blocks[b]['items'] if f['source_name']==n)
    def insert(self,b,rowid,**values):
        cols=['FOX_ROW_ID']+[self.col(b,k) for k in values]
        self.db.execute('insert into '+self.blocks[b]['table_name']+'('+','.join(cols)+') values('+','.join('?' for _ in cols)+')',[rowid,*values.values()])
    def params(self):
        p=self.op['page_id'];result={}
        for i,(name,rowid) in enumerate((('LOADS',1),('PIECES',11),('NOTES',21))):
            b=self.blocks[name];token=self.db.execute('select '+_fingerprint(b['items'],'r')+' from '+b['table_name']+' r where FOX_ROW_ID=?',[rowid]).fetchone()[0]
            result[f'P{p}_ID{i}']=rowid;result[f'P{p}_TOKEN{i}']=token
        return result
    def update(self,b,rowid,**values):
        self.db.execute('update '+self.blocks[b]['table_name']+' set '+','.join(self.col(b,k)+'=?' for k in values)+' where FOX_ROW_ID=?',[*values.values(),rowid])


def test_emitted_query_sums_ceil_per_note_under_composite_bag_and_fresh_signature():
    s=SQL();p=s.params();q=s.op['query_sql']
    assert s.db.execute(q,p).fetchall()==[(2,'ASSIGN')]
    s.update('NOTES',21,MASS=1.1)
    assert s.db.execute(q,p).fetchall()==[]
    assert s.db.execute(q,s.params()).fetchall()==[(3,'ASSIGN')]
    s.update('NOTES',21,CITY='INVALID')
    assert s.db.execute(q,s.params()).fetchall()==[(3,'INVALID_FOCUS')]
    s.update('NOTES',21,CITY=None)
    assert s.db.execute(q,s.params()).fetchall()==[(3,'NEXT_RECORD')]


def test_next_record_is_actual_same_bag_selection_and_stops_at_end():
    s=SQL();p=s.params();q=s.op['next_record_query_sql'];page=s.op['page_id']
    assert s.db.execute(q,p).fetchone()==(22,)
    p[f'P{page}_ID2']=22
    assert s.db.execute(q,p).fetchone()==(None,)
    s.update('PIECES',11,PIECE_CODE='CHANGED')
    assert s.db.execute(q,p).fetchone()==(None,)


def test_ambiguous_composite_parent_and_wrong_selected_bag_are_rejected():
    s=SQL();p=s.params();page=s.op['page_id']
    p[f'P{page}_ID1']=12
    assert s.db.execute(s.op['query_sql'],p).fetchall()==[]
    s.insert('PIECES',13,LOAD_REFERENCE='H1',PIECE_CODE='SAME')
    assert s.db.execute(s.op['query_sql'],s.params()).fetchall()==[]


def test_collection_guards_use_actual_cursor_revision_nonce_policy_baseline_and_pending_action():
    _,r=apply_note_entry_wiring(*prepare());op=r['adapted_operations'][0];code=op['process_plsql']
    assert 'n002,n003 into l_seq,l_rev' in code and "c050='META'" in code
    assert 'c001=:P' in code and 'n002=l_rev and n003=l_seq' in code
    assert 'd.n001=:P' in code and 'd.seq_id=l_seq' in code
    assert 'd.c045 is null' in code and "nvl(d.c043,'OK')<>'ERROR'" in code
    assert "d.c041='SYNTHETIC_SAVE_BASELINE_V1'" in code and 'd.c021' in code and 'd.c002' in code
    assert 'd.n003,1,0)=1' in code and 'd.c040' in code
    assert 'guard_context(l_branch=\'ASSIGN\'' in code
    assert 'for update nowait' in code and 'if p_write and nvl(l_found,0)<>1' in code
    assert code.index('savepoint fox_note_entry')<code.index('guard_context(l_branch=')<code.index('p_number_value=>l_sum')
    assert code.index('p_number_value=>l_sum')<code.index('WHOLE_FORM_STATUS_REQUIRED')
    assert 'rollback to fox_note_entry;' in code
    assert not re.search(r'\b(commit\s*;|insert into|update FOX_NATIVE_|delete from)\b',code,re.I)
    # No sibling collection row or original table is ever a target.
    assert code.count('apex_collection.update_member_attribute(p_collection_name=>l_name,')==2
    assert 'p_seq=>l_seq,p_attr_number=>2,p_number_value=>l_sum' in code
    assert 'p_seq=>1,p_attr_number=>3,p_number_value=>l_rev+1' in code
    assert 'apex_collection.truncate_collection' not in code
    assert 'p_seq=>l_nonce_seq' in code and 'd001>sysdate-1/24' in code
    assert '_NOTE_SEQ is null' in code and '_NOTE_REV is null' in code and 'l_seq is null or l_rev is null' in code
    after=code[code.index(' savepoint fox_note_entry;'):]
    assert after.index(' guard_context;')<after.index('lock table ')<after.index('select (select sum(')
    assert 'if l_commit_started then' in code and "l_commit_result='COMMITTED'" in code
    assert "return 'UNKNOWN'" in code and "return 'UNAVAILABLE'" in code


def test_explicit_trusted_host_can_supply_whole_form_status_and_commit_with_recheck():
    args=prepare()
    provider=dict(trusted=True,source_binding=args[1]['source_binding'],provider_id='test-local-provider',
                  scope='whole_forms_transaction',declarations_plsql="function host_form_status return varchar2 is begin return 'QUERY';end;\nfunction host_commit_form return varchar2 is begin return 'FAILED';end;")
    _,r=apply_note_entry_wiring(*args,whole_form_adapter=provider)
    assert not r['gaps'];op=r['adapted_operations'][0]
    assert op['whole_form_provider']['provider_id']==provider['provider_id']
    code=op['process_plsql']
    assert code.index('p_number_value=>l_sum')<code.index('l_form_status:=host_form_status')
    continuation=code[code.index('if l_continue then'):]
    assert continuation.index('guard_context(true)')<continuation.index('into l_next')
    bad=dict(provider,source_binding='foreign')
    with pytest.raises(ValueError):apply_note_entry_wiring(*args,whole_form_adapter=bad)


def test_note_entry_remains_available_without_any_program_unit_caller_or_helper():
    docs=source();root=ET.fromstring(docs[0][1])
    root.remove(next(p for p in root.iter('ProgramUnit') if p.get('Name')=='REFRESH_NOTE'))
    args=prepare(docs=[(docs[0][0],ET.tostring(root))])
    _,r=apply_note_entry_wiring(*args)
    assert not r['gaps'] and len(r['adapted_operations'])==1
    op=r['adapted_operations'][0]
    assert op['source_event']=='WHEN-NEW-ITEM-INSTANCE'
    assert op['runtime_config']['operation_id'] is None
    assert 'No unique source procedure is bound.' in op['process_plsql']


@pytest.mark.parametrize('attribute,value,connected',[('NextNavigationItem','NOTE_CODE',True),
                          ('NextNavigationItem','MISSING_FIELD',False),('ItemType','List Item',False)])
def test_relative_navigation_honors_explicit_target_and_rejects_unsupported_widgets(attribute,value,connected):
    docs=source();root=ET.fromstring(docs[0][1])
    owner=next(i for i in root.iter('Item') if i.get('Name')=='STEP');owner.set(attribute,value)
    args=prepare(docs=[(docs[0][0],ET.tostring(root))])
    _,r=apply_note_entry_wiring(*args)
    if connected:
        assert r['adapted_operations'][0]['relative_next']['proof']=='explicit_XML_NextNavigationItem'
        assert r['adapted_operations'][0]['relative_next']['kind']=='focus'
    else:
        assert not r['adapted_operations'] and r['gaps']


class Session(SQL):
    """Execute generated guard/nonce SELECTs; model collection API transaction.

    APEX collection updates and PL/SQL control flow below are a disposable local
    boundary model, not a live APEX flow. Their SQL guards are emitted verbatim.
    """
    def __init__(self):
        super().__init__();self.p=self.params();self.page=self.op['page_id'];self.collection='CURRENT_DRAFT'
        self.db.execute('create table apex_collections(collection_name text,seq_id integer,c001 text,c002 text,c003 text,c021 text,c022 text,c040 text,c041 text,c043 text,c045 text,c049 text,c050 text,n001 numeric,n002 numeric,n003 numeric,d001 numeric)')
        self.db.execute("insert into apex_collections(collection_name,seq_id,c001,c002,c021,c022,c040,c041,c050,n001,n002,n003) values(?,2,'H1','SAME','H1','SAME','R','SYNTHETIC_SAVE_BASELINE_V1','ROW',11,8,8)",[self.collection])
        self.db.execute("insert into apex_collections(collection_name,seq_id,c001,c002,c021,c022,c040,c041,c050,n001,n002,n003) values(?,3,'H2','SAME','H2','SAME','R','SYNTHETIC_SAVE_BASELINE_V1','ROW',12,7,7)",[self.collection])
        self.db.commit()
    def guard(self):
        code=self.op['process_plsql']
        q=re.search(r'(select d.seq_id) into l_found( from apex_collections d,.*?);',code,re.S)
        query=q[1]+q[2]
        query=query.replace('utl_raw.cast_to_raw','fox_raw')
        query=re.sub(r'\bl_name\b',':draft_name',query)
        query=re.sub(r'\bl_seq\b',':draft_seq',query)
        return self.db.execute(query,dict(self.p,draft_name=self.collection,draft_seq=2)).fetchall()
    def apply(self,fail_after_assignment=False):
        self.db.execute('savepoint note_model')
        try:
            assert self.guard()==[(2,)]
            total,branch=self.db.execute(self.op['query_sql'],self.p).fetchone()
            assert branch=='ASSIGN'
            # Interpret the real update_member_attribute call's numeric slot.
            slot=int(re.search(r'p_seq=>l_seq,p_attr_number=>([0-9]+),p_number_value=>l_sum',self.op['process_plsql'])[1])
            self.db.execute(f'update apex_collections set n{slot:03}=? where collection_name=? and seq_id=2',[total,self.collection])
            if fail_after_assignment:raise RuntimeError('injected collection API failure')
        except Exception:
            self.db.execute('rollback to note_model');raise
        self.db.execute('release note_model')


def test_real_generated_guard_and_collection_assignment_leave_siblings_untouched_and_rollback():
    s=Session();assert s.guard()==[(2,)]
    before=s.db.execute('select * from apex_collections order by seq_id').fetchall()
    with pytest.raises(RuntimeError):s.apply(fail_after_assignment=True)
    assert s.db.execute('select * from apex_collections order by seq_id').fetchall()==before
    s.apply()
    rows=s.db.execute('select * from apex_collections order by seq_id').fetchall()
    assert rows[1]==before[1]
    assert s.db.execute('select n002,n003 from apex_collections where seq_id=2').fetchone()==(2,8)


@pytest.mark.parametrize('change',["n001=12","c002='CHANGED'","c022='CHANGED'","c045='PENDING'","c043='ERROR'","n003=99","c040='STALE'"])
def test_actual_emitted_current_bag_guard_denies_stale_keys_weight_baseline_pending_and_wrong_bag(change):
    s=Session();s.db.execute('update apex_collections set '+change+' where seq_id=2')
    assert s.guard()==[]
    before=s.db.execute('select * from apex_collections order by seq_id').fetchall()
    with pytest.raises(AssertionError):s.apply()
    assert s.db.execute('select * from apex_collections order by seq_id').fetchall()==before


@pytest.mark.parametrize('update',[None,"n002=5","n003=7","n001=12","c001='foreign'","c002='foreign'","c003='COMMIT_UNKNOWN'","d001=0"])
def test_emitted_nonce_select_is_exact_per_open_revision_bound_and_expiring(update):
    s=Session();code=s.op['process_plsql']
    match=re.search(r'select seq_id,c001 into l_nonce_seq,l_nonce( from apex_collections .*?);',code,re.S)
    query='select seq_id,c001'+match[1]
    query=query.replace('sysdate',':now').replace('1/24','1.0/24')  # Oracle NUMBER division, not SQLite integer division.
    for name in ('l_selection','l_rev','l_seq'):
        query=re.sub(r'\b'+name+r'\b',':'+name,query)
    name=s.op['nonce_collection']
    for seq,nonce in ((9,'one'),(10,'newer-tab')):
        s.db.execute('insert into apex_collections(collection_name,seq_id,c001,c002,n001,n002,n003,d001) values(?,?,?,?,?,?,?,?)',
                     [name,seq,nonce,'selection',11,0,2,1])
    p=dict(s.p,l_selection='selection',l_rev=0,l_seq=2,now=1)
    p[f'P{s.page}_NOTE_NONCE']='one'
    if update:s.db.execute('update apex_collections set '+update+' where seq_id=9')
    result=s.db.execute(query,p).fetchall()
    assert result==([] if update else [(9,'one')])
    if result:s.db.execute('delete from apex_collections where collection_name=? and seq_id=?',[name,result[0][0]])
    # Exact intent consumption cannot truncate another open tab's nonce.
    assert s.db.execute('select c001 from apex_collections where seq_id=10').fetchall()==[('newer-tab',)]


@pytest.mark.parametrize('mutation',['page','slot','namespace','source'])
def test_untrusted_saved_page_draft_contract_and_originals_are_not_used(mutation):
    args=prepare();f=args[-1]
    if mutation=='page':
        _,r=apply_note_entry_wiring(*args);f[r['adapted_operations'][0]['page_file']]+=b'/* changed */'
    elif mutation in ('slot','namespace'):
        r=json.loads(f['fox-package/item-validation-receipt.json']);c=r['generated_operations'][0]['contract']
        if mutation=='slot':c['slots']['active_weight']='n003'
        else:c['collection_namespace']='FORGED'
        f['fox-package/item-validation-receipt.json']=json.dumps(r).encode()
    else:
        f['fox-package/sources/'+args[0][0][0]]+=b' '
        with pytest.raises(ValueError):apply_note_entry_wiring(*args)
        return
    out,r=apply_note_entry_wiring(*args)
    assert not r['adapted_operations'] and r['gaps']


def test_emitted_callable_checks_real_focus_before_submission_and_no_automatic_caller(tmp_path):
    node=shutil.which('node')
    if not node:pytest.skip('Node runtime unavailable')
    _,r=apply_note_entry_wiring(*prepare());op=r['adapted_operations'][0];cfg=op['runtime_config']
    script=op['javascript']
    harness='''const vm=require('node:vm');const assert=require('node:assert/strict');
const c=CONFIG;const code=CODE;
function run(focusWorks=true,change=false,ready=true){
 const calls=[];const doc={activeElement:null};const nodes={};
 for(const id of [...c.identities,c.state,c.result,c.focus,c.invalid_focus,c.focus_ack])nodes[id]={value:'x',focus(){calls.push('focus');if(focusWorks)doc.activeElement=this;if(change)nodes[c.identities[0]].value='changed';}};
 nodes[c.state].value=ready?'READY':'OPEN_MATCHING_DRAFT';nodes[c.result].value='';
 doc.getElementById=id=>nodes[id]||null;
 const context={document:doc,window:{},apex:{page:{isChanged:()=>false},submit:p=>calls.push(p.request)}};
 vm.runInNewContext(code,context);
 assert.deepEqual(calls,[]);let error=null;try{context.window.foxNoteEntryBridge.invoke(c.operation_id);}catch(e){error=e;}
 return {calls,error,nodes};
}
let a=run();assert.equal(a.error,null);assert.deepEqual(a.calls,['focus',c.call_request]);assert.equal(a.nodes[c.focus_ack].value,c.focus_source_item_id);
a=run(false);assert.ok(a.error);assert.deepEqual(a.calls,['focus']);
a=run(true,true);assert.ok(a.error);assert.deepEqual(a.calls,['focus']);
a=run(true,false,false);assert.ok(a.error);assert.deepEqual(a.calls,[]);
console.log('callable DOM model: four paths passed');
'''.replace('CONFIG',json.dumps(cfg)).replace('CODE',json.dumps(script))
    target=tmp_path/'note.cjs';target.write_text(harness)
    result=subprocess.run([node,str(target)],capture_output=True,text=True)
    assert result.returncode==0,result.stdout+result.stderr
