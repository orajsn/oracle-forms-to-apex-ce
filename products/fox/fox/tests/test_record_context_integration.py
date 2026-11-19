"""Real generator wiring: read context is separate from inactive write artifacts."""
import json
import pytest
from fox.xml_mapping import generate_xml_package
from fox.xml_mapping_job import _context_fields
from fox.forms_native_plan import POLICY_ID
from fox.prototype_export_only import _members
from test_forms_relation_plan import documents


def source():
    parent='<Item Name="ORIGIN_ROUTE" ItemType="Text Item" DatabaseItem="true" DataType="Char" MaximumLength="20"/>'
    child='<Item Name="COPIED_ROUTE" ItemType="Text Item" DatabaseItem="true" DataType="Char" MaximumLength="20"/>'
    child+=''.join(f'<Trigger Name="{event}" TriggerText=":COPIED_ROUTE := :ORIGIN_ROUTE;"/>' for event in ('PRE-INSERT','PRE-UPDATE'))
    return documents(extra_parent=parent,extra_child=child)


def generate(docs=None):
    return generate_xml_package(docs or source(),'context-example','Context example',POLICY_ID)


def test_generator_emits_chain_and_two_unwired_assignments_without_count_inflation():
    raw,report=generate();files=_members(raw);summary=report['metadata']['context_summary']
    assert summary=={'relations_generated':2,'relations_not_converted':0,'assignments_generated_unwired':2}
    assert report['metadata']['behavior_coverage']=={'total':3,'counts':{'generated_wired_adapted':1,'unsupported':2}}
    assert report['gap_report']['summary']['engine_context']==2
    units=report['mapping_ledger']['code_units']
    assert sum(r.get('encoding_status')=='generated_unwired' for r in units)==2
    assert all(r['status']=='unsupported' for r in units if r.get('encoding_status'))
    assignments=report['assignment_receipt']['generated_operations']
    assert {r['source_event'] for r in assignments}=={'PRE-INSERT','PRE-UPDATE'}
    assert all(r['event_activated'] is False and r['oracle_compiled'] is False for r in assignments)
    sql=files['fox-package/assignment-review.sql'].decode()
    assert sql.count('p_copy := p_value;')==2
    apx='\n'.join(v.decode() for n,v in files.items() if n.endswith('.apx'))
    assert assignments[0]['package_name'] not in apx
    pages=report['relation_receipt']['added_pages'];assert len(pages)==2
    for page in pages:
        text=files[page].decode();assert 'where exists' in text and 'checksumRequiredSessionLevel' in text
        assert 'storage: session' in text and 'pageItemsToSubmit' not in text
    assert _context_fields(report['metadata'],report['mapping_ledger'])==summary
    assert raw==generate()[0]


def test_legacy_artifact_summary_is_not_fabricated():
    assert _context_fields({}, {}) is None


@pytest.mark.parametrize('value',['Summary','Formula','UNKNOWN'])
@pytest.mark.parametrize('attribute',['CalculateMode','CalculationMode'])
def test_computed_or_unknown_join_key_remains_unconverted_without_aborting_other_work(attribute,value):
    raw,report=generate(documents(key_extra=f'{attribute}="{value}"'))
    summary=report['metadata']['context_summary']
    assert summary['relations_generated']==1 and summary['relations_not_converted']==1
    assert summary['assignments_generated_unwired']==0
    assert report['metadata']['behavior_coverage']['counts']['generated_wired_adapted']==1


def test_emitted_read_queries_select_only_the_chosen_parent_in_a_local_sql_model():
    # SQLite executes the emitted SQL shape on synthetic data only. This is not
    # Oracle/APEX runtime acceptance or a claim about NLS/record-buffer semantics.
    import math
    import re
    import sqlite3
    import textwrap
    raw,report=generate();files=_members(raw)
    trace=json.loads(files['fox-package/source-to-page.json'])
    blocks={b['name']:b for b in trace['blocks']}
    def col(block,name):return next(f['column'] for f in block['items'] if f['source_name']==name)
    with sqlite3.connect(':memory:') as db:
        db.create_function('ceil',1,lambda value:None if value is None else math.ceil(value))
        for block in blocks.values():
            columns=['FOX_ROW_ID INTEGER']+[f"{f['column']} {'REAL' if f['data_type']=='NUMBER' else 'TEXT'}" for f in block['items']]
            db.execute(f"CREATE TABLE {block['table_name']} ({', '.join(columns)})")
        def insert(name,row_id,values):
            block=blocks[name];columns=['FOX_ROW_ID']+[col(block,k) for k in values]
            db.execute(f"INSERT INTO {block['table_name']} ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",[row_id,*values.values()])
        insert('ORDERS',1,{'ORDER_ID':10});insert('ORDERS',2,{'ORDER_ID':20});insert('ORDERS',3,{'ORDER_ID':None})
        insert('LINES',11,{'ORDER_ID':10,'LINE_ID':1,'MASS':1.2});insert('LINES',12,{'ORDER_ID':10,'LINE_ID':2,'MASS':3})
        insert('LINES',21,{'ORDER_ID':20,'LINE_ID':1,'MASS':4});insert('LINES',31,{'ORDER_ID':None,'LINE_ID':1,'MASS':5})
        insert('DETAILS',101,{'ORDER_ID':10,'LINE_ID':1});insert('DETAILS',102,{'ORDER_ID':10,'LINE_ID':2});insert('DETAILS',201,{'ORDER_ID':20,'LINE_ID':1})
        for op in report['relation_receipt']['generated_operations']:
            page=files[op['page_file']].decode()
            query=textwrap.dedent(re.search(r'sqlQuery:\s*```sql\n(.*?)\n\s*```',page,re.S)[1])
            target=next(b for b in blocks.values() if b['source_block_id']==op['child_block_id'])['name']
            expected={1:{11,12},2:{21},3:set(),None:set(),999:set()} if target=='LINES' else {11:{101},12:{102},21:{201},31:set(),None:set(),999:set()}
            for parent_id,ids in expected.items():
                rows=db.execute(query,{op['parent_item']:parent_id}).fetchall()
                assert {r[0] for r in rows}==ids
