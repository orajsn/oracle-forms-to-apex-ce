"""Generated numeric boundary checks; no Oracle/APEX runtime claim.

SQLite executes emitted DML; PL/SQL locks/control and decimal validation are
explicitly modelled. The separate target gate must execute the emitted parser.
"""
from copy import deepcopy
from decimal import Decimal
from functools import lru_cache
import json
import re
import sqlite3
from xml.etree import ElementTree as ET

import pytest

from fox import forms_rate_workspace as native
from fox.forms_rate_choices import compile_rate_choices
from fox.forms_rate_numbers import compile_rate_numbers, validate_numeric_value
from test_forms_rate_choices import SOURCE, prepare


def _source_with_price(**properties):
    root = ET.fromstring(SOURCE)
    block = root.find("./Block[@Name='LINES']")
    block.set('DatabaseBlock', 'true')
    block.set('QueryDataSourceType', 'Table')
    for item in block.findall('Item'):
        item.set('DataType', 'Char')
        item.attrib.setdefault('DatabaseItem', 'true')
    ET.SubElement(block, 'Item', {
        'Name': 'AMOUNT', 'Prompt': 'Price', 'ColumnName': 'RATE_AMOUNT',
        'ItemType': 'Text Item', 'DataType': 'Number', 'DatabaseItem': 'true',
        'FormatMask': '99,999,990.90', 'MaximumLength': '12', 'Required': 'false',
        **properties})
    return ET.tostring(root)


@lru_cache(maxsize=8)
def compiled(**properties):
    args, c = prepare(_source_with_price(**properties))
    b = compile_rate_choices(*args, c)
    n = compile_rate_numbers(*args, c)
    return c, b, n


def test_number_projection_is_source_bound_and_absence_keeps_existing_output():
    c, b, n = compiled()
    original = deepcopy((c, b, n))
    result = native.render_rate_workspace(c, b, 7800, numbers=n)
    assert (c, b, n) == original
    assert native.render_rate_workspace(c, b, 7800, numbers=n) == result
    m = result['metadata']
    assert len(m['numeric_fields']) == 1
    f, = m['numeric_fields']
    assert (f['source_name'], f['label'], f['column'], f['slot']) == ('AMOUNT', 'Price', 'N001', 1)
    assert m['source_number_contract_id'] == n['contract_id']
    assert result['supporting_sql'].decode().count('N001 number') == 2
    assert 'number(' not in result['supporting_sql'].decode().lower()
    editor = result['pages'][0]['text'].decode()
    assert 'pageItem P7800_N1 (' in editor and 'label: "Price"' in editor
    assert native._number_text('N001') in editor
    assert 'without rounding' in editor
    for page in result['pages'][1:]:
        text = page['text'].decode()
        item, = re.findall(r'pageItem P\d+_N1 \((.*?)\n    \)', text, re.S)
        assert 'type: displayOnly' in item and 'sessionStateProtection: restricted' in item
        assert "to_char(N001,'TM9','NLS_NUMERIC_CHARACTERS=''.,''')" in text
        assert m['draft_table'] in text
    baseline = native.render_rate_workspace(c, b, 7800)
    assert baseline == native.render_rate_workspace(c, b, 7800, numbers=None)
    c2, b2, unsupported = compiled(FormatMask='999D99')
    assert unsupported['fields'] == [] and unsupported['gaps']
    assert native.render_rate_workspace(c2,b2,7800,numbers=unsupported) == native.render_rate_workspace(c2,b2,7800)
    assert baseline['metadata']['draft_table'] != m['draft_table']
    c3,b3,n3 = compiled(MaximumLength='13')
    changed = native.render_rate_workspace(c3,b3,7800,numbers=n3)['metadata']
    assert changed['draft_table'] != m['draft_table'] and changed['saved_table'] != m['saved_table']


def test_numeric_transactions_preserve_locks_revisions_and_submitted_error_values():
    c,b,n = compiled()
    result = native.render_rate_workspace(c,b,7800,numbers=n)
    for action in (*native.route.REQUESTS,native.SAVE,native.REOPEN):
        code = native.action_code(c,b,7800,action,numbers=n)
        assert len(code.encode()) <= 32767 and 'savepoint fox_' in code
        assert 'when others then rollback to fox_' in code
        assert not re.search(r'\b(commit|round|trunc|execute immediate)\b',code,re.I)
        assert 'NLS_NUMERIC_CHARACTERS=' in code
        assert ':P7800_N1:=' not in code
        for sql in re.findall(r'\b(?:select|insert|update|delete)\b[^;]*;',code,re.I):
            assert not re.search(r'\bfox_n\d+\(',sql,re.I)
        if action != 'FOX_ROW_CREATE':
            assert 'for update nowait' in code
    create = native.action_code(c,b,7800,'FOX_ROW_CREATE',numbers=n)
    assert 'ROW_LABEL,REVISION,N001)' in create
    assert 'l_uuid,:P7800_LABEL,0,l_input_n1' in create
    keep = native.action_code(c,b,7800,'FOX_ROW_KEEP',numbers=n)
    assert 'N001=l_input_n1' in keep
    assert keep.index('for update nowait') < keep.index('update FOX_WD_')
    choose = native.action_code(c,b,7800,'FOX_ROW_CHOOSE',numbers=n)
    assert '(N001=l_input_n1)' in choose
    assert 'Keep draft changes before opening the choice list.' in choose
    save = native.action_code(c,b,7800,native.SAVE,numbers=n)
    assert '(N001=l_input_n1)' in save and 'N001=l_n1' in save
    assert 'l_saved_revision is null or l_current<>l_saved_revision' in save
    reopen = native.action_code(c,b,7800,native.REOPEN,numbers=n)
    assert '(l_n1=l_input_n1)' in reopen
    assert reopen.index('for update nowait') < reopen.index('(l_n1=l_input_n1') < reopen.index('insert into ')
    assert 'Nothing was reopened.' in reopen
    assert 'l_input_n1 number;' in reopen[:reopen.index('function fox_n1')]
    for action in ('FOX_ROW_APPLY','FOX_ROW_DISCARD'):
        assert 'l_input_n1:=fox_n1(' not in native.action_code(c,b,7800,action,numbers=n)
    load = native._load(c,b,result['metadata']['draft_fields'],result['metadata'],7800,numbers=n)
    assert "if :REQUEST is null then" in load
    assert 'into :P7800_LABEL,:P7800_F1,:P7800_F2,:P7800_F3,:P7800_F4,:P7800_F5,:P7800_N1' in load


@pytest.mark.parametrize('value,expected',[
    (None,None),('',None),('0','0'),('-0.00','0'),('-1234.56','-1234.56'),
    ('99999999.99','99999999.99'),('-99999999.99','-99999999.99'),
    ('+1.20','1.20'),('000001.20','1.20'),('1','1'),('0.5','0.5'),('-0.01','-0.01')])
def test_exact_decimal_reference_accepts_optional_signed_zero_and_full_picture(value,expected):
    _,_,n = compiled()
    assert validate_numeric_value(value,n['fields'][0]) == (None if expected is None else Decimal(expected))


@pytest.mark.parametrize('value',['1.234','1.230','100000000','1,234.56','1e2','1,20','NaN','Inf','.5','1.',' 1','1 ','--1','1\n','１２','-99999999.999'])
def test_exact_decimal_reference_rejects_bad_notation_precision_and_length(value):
    _,_,n = compiled()
    with pytest.raises(ValueError):
        validate_numeric_value(value,n['fields'][0])


def test_emitted_sql_keeps_two_numeric_rows_isolated_across_save_and_reopen():
    c,b,n = compiled()
    result = native.render_rate_workspace(c,b,7800,numbers=n)
    m = result['metadata']
    db = sqlite3.connect(':memory:')
    context = {'APP_ID':'42','APP_SESSION':'session-a','APP_USER':'TESTER'}
    db.create_function('v',1,context.get)
    db.create_function('to_number',1,lambda x:int(x) if x else None)
    db.create_function('cast_to_raw',1,lambda x:x)
    db.create_function('decode',4,lambda a,b,c,d:c if a == b else d)
    db.execute('create temp table dual(dummy text)')
    db.execute("insert into dual values('X')")
    ddl = re.sub(r'varchar2\(\d+ (?:byte|char)\)','text',result['supporting_sql'].decode(),flags=re.I)
    ddl = re.sub(r'default sysdate\+1','default 11',ddl)
    ddl = re.sub(r'default sysdate','default 10',ddl)
    db.executescript(ddl)

    def code(action):
        return native.action_code(c,b,7800,action,numbers=n)

    def run(statement, params):
        statement = re.sub(r'\bsysdate\b','10',statement)
        statement = statement.replace('utl_raw.cast_to_raw','cast_to_raw')
        statement = re.sub(r'\bl_(uuid|n1|input_n1|f[0-9]+|label|saved_uuid|saved_revision|current)\b',r':l_\1',statement)
        return db.execute(statement,params)

    create, = re.findall(r'insert into .*?;',code('FOX_ROW_CREATE'),re.S)
    keep, = re.findall(r'update FOX_WD_.*?;',code('FOX_ROW_KEEP'),re.S)
    save_insert, = re.findall(r'insert into FOX_WS_.*?;',code(native.SAVE),re.S)
    reopen_insert, = re.findall(r'insert into FOX_WD_.*?;',code(native.REOPEN),re.S)
    for serial,value in [(1,'1234.56'),(2,'-98.70')]:
        row = f'{serial:032X}'
        p = {'l_uuid':row,'P7800_LABEL':f'Row {serial}','P7800_N1':value,
             'P7800_ROW':row,'P7800_REV':'0','P7800_F1':None,
             'l_input_n1':float(validate_numeric_value(value,n['fields'][0]))}
        run(create,p)
        assert run(keep,p).rowcount == 1
        # Replaying the old revision cannot change this row or its companion.
        assert run(keep,{**p,'P7800_N1':'0'}).rowcount == 0
        fields = {f'l_f{i}':None for i in range(1,6)}
        q = {**fields,'l_saved_uuid':f'{serial+10:032X}','l_label':f'Row {serial}',
             'l_n1':float(Decimal(value))}
        run(save_insert,q)
        context['APP_SESSION'] = 'session-b'
        q.update(l_uuid=f'{serial+20:032X}',l_saved_revision=0,P7800_OPEN=q['l_saved_uuid'])
        run(reopen_insert,q)
        assert Decimal(str(db.execute(f'select N001 from {m["draft_table"]} where ROW_UUID=?',(q['l_uuid'],)).fetchone()[0])) == Decimal(value)
        context['APP_SESSION'] = 'session-a'
    rows = db.execute(f'select ROW_LABEL,N001 from {m["saved_table"]} order by ROW_LABEL').fetchall()
    assert [(label,Decimal(str(value))) for label,value in rows] == [('Row 1',Decimal('1234.56')),('Row 2',Decimal('-98.70'))]
    # Execute the emitted saved-preview comparison, including numeric NULL/equality.
    preview, = re.findall(r'select count\(\*\) into l_count from dual where .*?;',code(native.REOPEN),re.S)
    preview = preview.replace(' into l_count','')
    for saved,submitted,count in [(1,1.0,1),(1,1.01,0),(None,None,1),(None,0,0),(0,None,0)]:
        p = {'l_label':'Row','P7800_LABEL':'Row','l_f1':None,'P7800_F1':None,
             'l_n1':saved,'l_input_n1':submitted}
        assert run(preview,p).fetchone()[0] == count


def test_reused_or_tampered_numeric_receipt_is_rejected():
    c,b,n = compiled()
    wrong = deepcopy(n)
    wrong['fields'][0]['scale'] = 3
    with pytest.raises(ValueError):
        native.render_rate_workspace(c,b,7800,numbers=wrong)
    other,_,_ = compiled(MaximumLength='13')
    with pytest.raises(ValueError):
        native.action_code(other,b,7800,native.SAVE,numbers=n)


def test_report_keeps_price_numeric_and_preserves_text_in_other_columns():
    c, b, n = compiled()
    editor = native.render_rate_workspace(c, b, 7800, numbers=n)['pages'][0]['text'].decode()
    region = re.search(r'^    region records \(\n.*?^    \)$', editor, re.M | re.S)[0]
    column = lambda name: re.search(r'^        column '+name+r' \(\n.*?^        \)$',region,re.M | re.S)[0]
    assert 'dataType: NUMBER' in column('N001') and 'heading: "Price"' in column('N001')
    assert 'dataType: STRING' in column('REVISION_TEXT') and 'dataType: STRING' in column('F001')
    query = re.search(r'\x60{3}sql\n(.*?)\n\s*\x60{3}',region,re.S)[1]
    branches = query.lower().split('union all')
    assert len(branches) == 2 and all(',n001 from ' in part for part in branches)
    assert 'to_char(n001' not in query.lower()
    assert "to_char(N001,'TM9'" in editor  # The editor still reloads canonical input.
    assert 'P7800_ROW: "#ROW_UUID#"' in region and 'P7800_OPEN: "#OPEN_ID#"' in region


def test_report_helper_requires_an_explicit_numeric_binding():
    from fox import forms_route_lookup_native as route
    text=route._report(1,'select CODE,PRICE from DEMO',[('CODE','Code'),('PRICE','Price')],'Demo','')
    assert text.count('dataType: STRING') == 2 and 'dataType: NUMBER' not in text


def test_two_modules_share_block_names_but_not_editor_or_chooser_titles():
    from fox.forms_native_plan import POLICY_ID
    from fox.xml_mapping import generate_xml_package, _members

    forms = []
    expected = {'SHIPPING': ('Outbound charge', 2), 'RETURNS': ('Inbound charge', 3)}
    for module, (prompt, scale) in expected.items():
        form = ET.fromstring(_source_with_price(Prompt=prompt, FormatMask='990.' + '0' * scale))
        form.set('Name', module)
        forms.append((module.lower()+'.xml', ET.tostring(form)))
    package, _ = generate_xml_package(forms, 'module-tariff-test', 'Module tariffs', POLICY_ID)
    files = _members(package)
    operations = json.loads(files['fox-package/lov-return-receipt.json'])['generated_operations']
    rates = [op for op in operations if op.get('kind') == 'source_optional_row_lookup']
    assert len(rates) == 2
    seen, titles, tables = set(), set(), set()
    for op in rates:
        target = op['native_target']
        field, = target['numeric_fields']
        module, = [name for name, spec in expected.items() if spec == (field['label'],field['scale'])]
        seen.add(module)
        for key in ('draft_table','saved_table'):
            assert target[key] not in tables
            tables.add(target[key])
        for pid in range(op['page_id'], op['page_id'] + target['page_count']):
            path, = [n for n in files if n.startswith(f'pages/p{pid:05d}-')]
            page = files[path].decode()
            title = json.loads(re.search(r'(?m)^    title: (.+)$',page)[1])
            assert title.startswith(module+' / LINES / ')
            assert title not in titles
            titles.add(title)
    assert seen == set(expected)


def test_explicit_plain_block_label_preserves_all_single_module_native_bytes():
    c, b, n = compiled()
    original = native.render_rate_workspace(c, b, 7800, numbers=n)
    assert native.render_rate_workspace(c, b, 7800, numbers=n, block_label=c['source_block_name']) == original
    long_context = 'A' * 185 + ' / ' + 'B' * 125
    titled = native.render_rate_workspace(c, b, 7800, numbers=n, block_label=long_context)
    for page in titled['pages']:
        title = json.loads(re.search(r'(?m)^    title: (.+)$',page['text'].decode())[1])
        assert len(title) <= 255 and f"[page {page['page_id']}]" in title
