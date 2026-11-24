"""Normal-generation checks for source defaults on new synthetic drafts."""
from io import BytesIO
import json
from xml.etree import ElementTree as ET
from zipfile import ZipFile

import pytest

from fox.forms_native_plan import POLICY_ID
from fox.xml_mapping import generate_xml_package
from test_forms_rate_number_workspace import _source_with_price


def source(module, body, other_event=False):
    root = ET.fromstring(_source_with_price())
    root.set('Name',module)
    block = root.find("./Block[@Name='LINES']")
    trigger = block.find("./Trigger[@Name='WHEN-CREATE-RECORD']")
    if trigger is None:
        trigger = ET.SubElement(block,'Trigger',Name='WHEN-CREATE-RECORD')
    trigger.set('TriggerText',body)
    if other_event:
        ET.SubElement(root,'Trigger',Name='WHEN-CREATE-RECORD',TriggerText="BEGIN :LINES.VIA := 'OTHER'; END;")
    return ET.tostring(root)


def package(docs):
    candidate, report = generate_xml_package(docs,'rate-defaults-test','Rate defaults',POLICY_ID)
    with ZipFile(BytesIO(candidate)) as archive:
        read=lambda n:json.loads(archive.read('fox-package/'+n+'.json'))
        ops=[o for o in read('lov-return-receipt')['generated_operations'] if o.get('kind')=='source_optional_row_lookup']
        pages={o['page_file']:archive.read(o['page_file']).decode() for o in ops}
        return ops,pages,read('mapping-gaps')['gaps'],read('metadata')


def test_two_modules_bind_complete_default_to_own_create_only():
    docs=[(m+'.xml',source(m,"BEGIN :VIA := '"+v+"'; END;")) for m,v in [('RATES_A','V1'),('RATES_B','V2')]]
    ops,pages,gaps,metadata=package(docs)
    assert len(ops)==2 and not any(g['source_name']=='WHEN-CREATE-RECORD' for g in gaps)
    assert 'fox.rate.create-record-default' in metadata['applied_rule_ids']
    ids=set();values=set()
    for op in ops:
        init=op['native_target']['new_record_initializer']
        target,=init['assignments']
        assert (target['source_name'],target['column'])==('VIA','F001')
        assert init['source_block_id']==op['source_block_id']
        assert init['source_module_id']==op['contract']['source_module_id']
        assert 'l_init_F001' in pages[op['page_file']]
        assert 'A new draft starts with the initial values' in pages[op['page_file']]
        ids.add(target['source_item_id']);values.add(target['value'])
    assert len(ids)==2 and values=={'V1','V2'}


@pytest.mark.parametrize('body,other_event',[
    ("BEGIN IF :VIA IS NULL THEN :VIA := 'V1'; END IF; END;",False),
    ("BEGIN :VIA := :START_AT; END;",False),
    ("BEGIN :VIA := 'V1'; :DOES_NOT_EXIST := 'X'; END;",False),
    ("BEGIN :VIA := '" + 'X'*300 + "'; END;",False),
    ("BEGIN :VIA := 'V1'; END;",True),
])
def test_nonliteral_incomplete_oversize_or_competing_rule_is_not_partly_applied(body,other_event):
    ops,pages,gaps,meta=package([('case.xml',source('RATES',body,other_event))])
    assert len(ops)==1
    assert 'new_record_initializer' not in ops[0]['native_target']
    assert 'l_init_F001' not in pages[ops[0]['page_file']]
    assert 'fox.rate.create-record-default' not in meta['applied_rule_ids']
    assert any(g['source_name']=='WHEN-CREATE-RECORD' for g in gaps)


def test_repeated_assignment_ends_in_source_null_and_preserves_order():
    from fox.forms_rate_create_defaults import effective_values
    ops,_,_,_=package([('one.xml',source('RATES',"BEGIN :VIA := 'V1'; :VIA := NULL; END;"))])
    init=ops[0]['native_target']['new_record_initializer']
    assert [a['value'] for a in init['assignments']]==['V1',None]
    assert effective_values(init)=={'F001':'null'}


@pytest.mark.parametrize(('literal','value'), [('12.30','12.30'),('-1.25','-1.25'),('+1.25','+1.25'),('0','0'),('NULL',None)])
def test_number_default_uses_one_numeric_storage_column(literal,value):
    ops,pages,gaps,meta=package([('numbers.xml',source('RATES',f"BEGIN :AMOUNT := {literal}; END;"))])
    op,=ops
    field,=op['native_target']['numeric_fields']
    assignment,=op['native_target']['new_record_initializer']['assignments']
    assert (assignment['column'],assignment['value'])==('N001',value)
    assert assignment['source_item_id']==field['source_item_id']
    editor=pages[op['page_file']]
    insert=editor.split('insert into '+op['native_target']['draft_table']+'(',1)[1].split(')',1)[0].split(',')
    assert insert.count('N001')==1 and 'l_input_n1:=l_init_N001;' in editor
    assert 'fox.rate.create-record-default' in meta['applied_rule_ids']
    assert not any(g['source_name']=='WHEN-CREATE-RECORD' for g in gaps)


@pytest.mark.parametrize('body',[
    "BEGIN :VIA := 'V1'; :AMOUNT := 12.345; END;",
    "BEGIN :VIA := 'V1'; :AMOUNT := 123456789; END;",
    "BEGIN :VIA := 'V1'; :AMOUNT := '12.30'; END;",
    "BEGIN :AMOUNT := 12.30; :MISSING := 'x'; END;",
])
def test_ineligible_mixed_default_restores_original_guarded_projection(body):
    ops,_,gaps,meta=package([('numbers.xml',source('RATES',body))])
    assert 'new_record_initializer' not in ops[0]['native_target']
    assert not ops[0]['stored_numbers']['fields'] and ops[0]['stored_numbers']['gaps']
    assert 'fox.rate.create-record-default' not in meta['applied_rule_ids']
    assert any(g['source_name']=='WHEN-CREATE-RECORD' for g in gaps)


def test_other_numeric_event_still_blocks_entire_initializer():
    root=ET.fromstring(source('NUMS',"BEGIN :AMOUNT := 12.30; :VIA := 'V1'; END;"))
    ET.SubElement(root.find("./Block[@Name='LINES']"),'Trigger',Name='WHEN-VALIDATE-RECORD',
                  TriggerText='BEGIN IF :AMOUNT IS NULL THEN NULL; END IF; END;')
    ops,_,_,_=package([('other.xml',ET.tostring(root))])
    assert not ops[0]['stored_numbers']['fields']
    assert 'new_record_initializer' not in ops[0]['native_target']


def test_capacity_fallback_does_not_publish_provisional_numeric_plan(monkeypatch):
    import fox.forms_rate_workspace as workspace
    original=workspace.render_rate_workspace
    def limited(*args,**kw):
        if kw.get('initializer'):
            raise ValueError('RATE_DEFAULT_CAPACITY')
        return original(*args,**kw)
    monkeypatch.setattr(workspace,'render_rate_workspace',limited)
    ops,pages,gaps,meta=package([('size.xml',source('NUMS','BEGIN :AMOUNT := 1; END;'))])
    assert 'pageItem P8900_N1 (' not in pages[ops[0]['page_file']]
    assert not ops[0]['stored_numbers']['fields'] and 'new_record_initializer' not in ops[0]['native_target']
    assert any(g['source_name']=='WHEN-CREATE-RECORD' for g in gaps)


def test_parent_launcher_initializes_draft_without_using_editor_inputs():
    from fox.forms_rate_parent_page import parent_create_code, render_bound_workspace
    from test_forms_rate_parent_workspace import compiled

    c,b,p,n = compiled()
    f = c['caller']
    init = {'assignments':[{'column':f['column'], 'data_type':'VARCHAR2', 'value':'V1'}]}
    launcher = parent_create_code(c,b,p,7800,7900,numbers=n,initializer=init)
    inserted = launcher.split('insert into ',1)[1].split(');',1)[0]
    assert f['column'] in inserted and all(k in inserted for k in ('PARENT_ID','PARENT_STAMP','K001','K002'))
    assert 'l_init_F001' in inserted and ':P7900_F1' not in launcher
    bound = render_bound_workspace(c,b,7800,numbers=n,parent=p,initializer=init)
    assert 'l_init_F001' in bound['pages'][0]['text'].decode()


@pytest.mark.parametrize('level',['block','trigger','target'])
def test_source_property_inheritance_is_checked_for_the_current_module(level):
    root = ET.fromstring(source('RATES',"BEGIN :VIA := 'V1'; END;"))
    block = root.find("./Block[@Name='LINES']")
    node = {'block':block,'target':block.find("./Item[@Name='VIA']"),
            'trigger':block.find("./Trigger[@Name='WHEN-CREATE-RECORD']")}[level]
    node.set('PropertyClass','EXTERNAL_CLASS')
    ops,_,gaps,meta=package([('inherited.xml',ET.tostring(root))])
    assert not any(o['native_target'].get('new_record_initializer') for o in ops)
    assert any(g['source_name']=='WHEN-CREATE-RECORD' for g in gaps)
    assert 'fox.rate.create-record-default' not in meta['applied_rule_ids']


def test_parent_numeric_initializer_uses_source_literal_and_one_slot():
    from fox.forms_rate_parent_page import parent_create_code
    from test_forms_rate_parent_workspace import compiled

    c,b,p,n=compiled()
    init={'assignments':[{'column':'N001','data_type':'NUMBER','value':'-0.25'}]}
    sql=parent_create_code(c,b,p,7800,7900,numbers=n,initializer=init)
    columns=sql.split('insert into ',1)[1].split('(',1)[1].split(')',1)[0].split(',')
    assert columns.count('N001')==1 and 'K001' in columns and 'K002' in columns
    assert 'l_init_N001 number:=-0.25;' in sql and ':P7900_N1' not in sql
