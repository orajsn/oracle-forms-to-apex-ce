"""Whole-source recognition and emitted SQL; no Oracle runtime claim."""
from copy import deepcopy
import hashlib
import json
import sqlite3
from xml.etree import ElementTree as ET

import pytest

from fox.forms_item_commands import (apply_item_commands, parse_item_command,
                                     recognize_item_commands)
from fox.forms_understanding_packet import _build
from test_forms_record_entry import source as record_source, prepare


def source(*, renamed=False, mutate=None):
    root = ET.fromstring(record_source(text='NULL;'))
    header, bag, note = list(root.iter('Block'))
    # The same reusable source units as the assigned boundary, independently named.
    notice = ET.SubElement(header, 'Item', Name='NOTICE', DatabaseItem='true', DataType='Char', MaximumLength='40', ItemType='Text Item')
    ET.SubElement(notice, 'Trigger', Name='KEY-NEXT-ITEM', TriggerText="GO_ITEM('BAGS.KEY');")
    status = ET.SubElement(bag, 'Item', Name='STATUS', DatabaseItem='true', DataType='Char', MaximumLength='10', ItemType='Text Item')
    ET.SubElement(status, 'Trigger', Name='KEY-NEXT-ITEM', TriggerText="BEGIN GO_ITEM('PARCELS.PKEY'); END;")
    weight = ET.SubElement(bag, 'Item', Name='WEIGHT', DatabaseItem='true', DataType='Number', MaximumLength='22', ItemType='Text Item')
    for item in (status, weight):
        for event in ('KEY-ENTQRY', 'KEY-EXEQRY'):
            ET.SubElement(item, 'Trigger', Name=event, TriggerText='/* literal override */ NULL;')
    if mutate:
        mutate(root)
    raw = ET.tostring(root)
    if renamed:
        for old,new in ((b'DISPATCH',b'DELIVERY'),(b'JOURNEYS',b'TRIPS'),(b'BAGS',b'CRATES'),(b'PARCELS',b'SHIPMENTS'),(b'NOTICE',b'REMARK'),(b'STATUS',b'FLAG_STATUS'),(b'WEIGHT',b'MASS'),(b'PKEY',b'CRATE_REF'),(b'HKEY',b'TRIP_REF')):
            raw = raw.replace(old,new)
    return [('commands.xml',raw)]


def apply(docs=None):
    docs = docs or source()
    args = (docs,*prepare(docs))
    return *apply_item_commands(*args),args


@pytest.mark.parametrize('renamed',[False,True])
def test_six_complete_commands_have_reachable_source_bound_focusable_fields(renamed):
    docs = source(renamed=renamed); args=(docs,*prepare(docs)); before=deepcopy(args)
    out,r=apply_item_commands(*args)
    assert args == before and (out,r) == apply_item_commands(*args)
    assert r['converted_code_unit_count']==6 and len(r['screens'])==4 and not r['gaps']
    assert len({op['source_unit_id'] for op in r['generated_operations']})==6
    assert [op['kind'] for op in r['generated_operations']].count('literal_item_focus')==2
    assert out['fox-package/sources/commands.xml']==docs[0][1]
    for op in r['generated_operations']:
        assert op['owner_item']['item_name'] in out[op['page_file']].decode()
        assert op['source_unit_sha256'] and op['native_event'] and op['rule_id']
        assert op['scope']=='selected_read_only_saved_synthetic_rows'
        assert not op['implicit_validation_implemented'] and not op['item_entry_lifecycle_implemented']
    for b in args[3]['blocks']:
        if b['classification']=='database':
            assert b'Saved record field navigation' in out[b['report_file']]
    for screen in r['screens']:
        page = out[screen['page_file']].decode()
        assert 'argumentsMustHaveChecksum' in page
        assert 'readonly aria-readonly=' in page or not screen['field_bindings']
        assert 'No matching' not in (screen['chooser_query_sql'] or '')
        assert all('checksumRequiredSessionLevel' in page for _ in screen['path_block_ids'])
        assert 'insert into' not in screen['process_plsql'].lower()
    final = r['screens'][-1]
    assert len(final['context_aliases'])==3
    assert all(f':P{final["page_id"]}_ID{i}' in final['selected_record_sql'] and
               f':P{final["page_id"]}_TOKEN{i}' in final['selected_record_sql'] for i in range(3))


@pytest.mark.parametrize('event,text',[
    ('KEY-NEXT-ITEM',"GO_ITEM('BAGS.KEY'); COMMIT_FORM;"),
    ('KEY-NEXT-ITEM',"IF true THEN GO_ITEM('BAGS.KEY'); END IF;"),
    ('KEY-NEXT-ITEM',"GO_ITEM(:DYNAMIC_NAME);"),
    ('KEY-NEXT-ITEM',"GO_ITEM('BAGS.KEY'); -- comment\nNEXT_RECORD;"),
    ('KEY-ENTQRY','NULL; EXECUTE_QUERY;'),
    ('KEY-EXEQRY','EXECUTE_QUERY;'),
    ('KEY-ENTQRY',"IF false THEN EXECUTE_QUERY; ELSE NULL; END IF;"),
])
def test_partial_bodies_and_other_active_effects_are_never_counted(event,text):
    with pytest.raises(ValueError): parse_item_command(text,event)


def test_unknown_ambiguous_and_other_module_target_fail_closed():
    for mutate in (
        lambda root: next(t for t in root.iter('Trigger') if t.get('Name')=='KEY-NEXT-ITEM').set('TriggerText',"GO_ITEM('UNKNOWN');"),
        lambda root: next(t for t in root.iter('Trigger') if t.get('Name')=='KEY-NEXT-ITEM').set('TriggerText',"GO_ITEM('KEY');"),
        lambda root: next(t for t in root.iter('Trigger') if t.get('Name')=='KEY-NEXT-ITEM').set('TriggerText',"GO_ITEM('ELSEWHERE.KEY');"),
    ):
        out,r,args=apply(source(mutate=mutate))
        assert len(r['generated_operations'])==5 and r['gaps']


def test_nonoverride_query_trigger_and_disabled_target_do_not_claim_source_behavior():
    def alter(root):
        root.find(".//Item[@Name='STATUS']/Trigger[@Name='KEY-ENTQRY']").set('ExecutionStyle','After')
        root.find(".//Item[@Name='PKEY']").set('Enabled','false')
    _, receipt, _ = apply(source(mutate=alter))
    assert len(receipt['generated_operations'])==4
    reasons={g['reason'] for g in receipt['gaps']}
    assert {'ITEM_COMMAND_PARENT_TRIGGER_SEQUENCE_UNSUPPORTED','ITEM_COMMAND_SOURCE_FIELD_NOT_FOCUSABLE'} <= reasons


def test_no_matching_source_commands_preserves_all_members():
    docs=[('ordinary.xml',record_source(text='NULL;'))]
    args=(docs,*prepare(docs)); out,r=apply_item_commands(*args)
    assert out==args[-1] and r['generated_operations']==[] and r['screens']==[]


def test_same_named_fields_in_foreign_module_cannot_supply_a_target():
    docs=source()
    other=b'<FormModule Name="OTHER"><Block Name="ELSEWHERE" DatabaseBlock="true"><Item Name="TARGET" DatabaseItem="true" DataType="Char" MaximumLength="20" ItemType="Text Item"/></Block></FormModule>'
    root=ET.fromstring(docs[0][1])
    next(t for t in root.iter('Trigger') if t.get('Name')=='KEY-NEXT-ITEM').set('TriggerText',"GO_ITEM('ELSEWHERE.TARGET');")
    docs=[(docs[0][0],ET.tostring(root)),('other.xml',other)]
    packet,chunks=_build(docs)
    r=recognize_item_commands(docs,packet,chunks)
    assert len(r['operations'])==5 and len(r['gaps'])==1
    # Same ordinary names in another module do not make our qualified target ambiguous.
    original=source()+[('other.xml',other.replace(b'ELSEWHERE',b'BAGS').replace(b'TARGET',b'KEY'))]
    p,c=_build(original)
    assert len(recognize_item_commands(original,p,c)['operations'])==6


def test_second_child_cannot_authorize_an_arbitrary_relation_chain():
    def branch(root):
        header=next(root.iter('Block'))
        ET.SubElement(header,'Relation',Name='SECOND_CHILD',DetailBlock='EXTRA',RelationType='JOIN',JoinCondition='JOURNEYS.KEY=EXTRA.HKEY')
        child=ET.SubElement(root,'Block',Name='EXTRA',DatabaseBlock='true')
        ET.SubElement(child,'Item',Name='HKEY',DatabaseItem='true',DataType='Char',MaximumLength='10',ItemType='Text Item')
    out,r,args=apply(source(mutate=branch))
    assert not r['generated_operations'] and not r['screens']
    assert len(r['gaps'])==6


@pytest.mark.parametrize('boundary',['chunks','trace','schema','relation','source','manifest'])
def test_stale_source_trace_or_relation_never_authorizes_viewer(boundary):
    args=list((source(),*prepare(source())))
    args=deepcopy(args)
    if boundary=='chunks':args[2][0]['text']+='NULL;'
    if boundary=='trace':args[3]['blocks'][0]['table_name']='OTHER_TABLE'
    if boundary=='schema':args[4]['fox-package/supporting-schema.sql']+=b'-- changed\n'
    if boundary=='relation':
        plan=json.loads(args[4]['fox-package/relation-plan.json']);plan['operations'][0]['join_pairs'][0]['parent_column']='FOREIGN_COLUMN'
        args[4]['fox-package/relation-plan.json']=json.dumps(plan).encode()
    if boundary=='source':args[4]['fox-package/sources/commands.xml']+=b' '
    if boundary=='manifest':
        manifest=json.loads(args[4]['fox-package/source-manifest.json']);manifest['selected_chunk_hashes']={}
        args[4]['fox-package/source-manifest.json']=json.dumps(manifest).encode()
    with pytest.raises(ValueError):apply_item_commands(*args)


class SQLBoundary:
    """SQLite evaluates the actual emitted read-only query with Oracle hash UDFs."""
    def __init__(self):
        self.out,self.receipt,args=apply()
        self.blocks=args[3]['blocks'];self.db=sqlite3.connect(':memory:')
        self.db.create_function('standard_hash',2,lambda v,a:None if v is None else hashlib.sha256(str(v).encode()).digest())
        self.db.create_function('rawtohex',1,lambda v:None if v is None else v.hex().upper())
        self.db.create_function('nvl',2,lambda a,b:b if a is None else a)
        self.db.executescript(self.out['fox-package/supporting-schema.sql'].decode().replace('NUMBER GENERATED BY DEFAULT ON NULL AS IDENTITY PRIMARY KEY','INTEGER PRIMARY KEY'))
    def insert(self,index,row,**values):
        b=self.blocks[index];cols={f['source_name']:f['column'] for f in b['items']}
        self.db.execute('insert into '+b['table_name']+'(FOX_ROW_ID,'+','.join(cols[k] for k in values)+') values ('+','.join('?' for _ in range(len(values)+1))+')',[row,*values.values()])
    def parameters(self,screen):
        p=screen['page_id'];params={}
        for i,b in enumerate(self.blocks):
            from fox.forms_master_detail import _fingerprint
            params[f'P{p}_ID{i}']=i+1
            params[f'P{p}_TOKEN{i}']=self.db.execute('select '+_fingerprint(b['items'],'r')+' from '+b['table_name']+' r where FOX_ROW_ID=?',[i+1]).fetchone()[0]
        return params


def test_actual_emitted_sql_rejects_siblings_stale_and_missing_selected_rows():
    s=SQLBoundary()
    s.insert(0,1,KEY='M1',NOTICE='first')
    s.insert(1,2,KEY='B1',HKEY='M1',STATUS='N',WEIGHT=12)
    s.insert(2,3,PKEY='B1',FLAG='A')
    s.insert(0,11,KEY='M2',NOTICE='second')
    s.insert(1,12,KEY='B2',HKEY='M2',STATUS='N',WEIGHT=14)
    s.insert(2,13,PKEY='B2',FLAG='B')
    screen=s.receipt['screens'][-1];q=screen['selected_record_sql'];p=screen['page_id'];params=s.parameters(screen)
    assert len(s.db.execute(q,params).fetchall())==1
    foreign=dict(params);foreign[f'P{p}_ID2']=13
    assert s.db.execute(q,foreign).fetchall()==[]
    # A changed saved field invalidates the complete row fingerprint.
    field=next(f['column'] for f in s.blocks[1]['items'] if f['source_name']=='STATUS')
    s.db.execute('update '+s.blocks[1]['table_name']+' set '+field+"='CHANGED' where FOX_ROW_ID=2")
    assert s.db.execute(q,params).fetchall()==[]
    params=s.parameters(screen)
    assert len(s.db.execute(q,params).fetchall())==1
    s.db.execute('delete from '+s.blocks[2]['table_name']+' where FOX_ROW_ID=3')
    assert s.db.execute(q,params).fetchall()==[]


def test_duplicate_master_business_keys_do_not_expose_arbitrary_child():
    s=SQLBoundary();s.insert(0,1,KEY='M1');s.insert(0,9,KEY='M1')
    s.insert(1,2,KEY='B1',HKEY='M1');s.insert(2,3,PKEY='B1')
    screen=s.receipt['screens'][-1]
    assert s.db.execute(screen['selected_record_sql'],s.parameters(screen)).fetchall()==[]
