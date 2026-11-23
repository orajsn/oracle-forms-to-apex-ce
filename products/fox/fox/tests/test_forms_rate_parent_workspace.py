"""Exact generated SQL on SQLite; PL/SQL control/locks are modelled, not live."""
from copy import deepcopy
from decimal import Decimal
from functools import lru_cache
from hashlib import sha256
import re
import sqlite3
from xml.etree import ElementTree as ET

import pytest

from fox import forms_rate_workspace as workspace
from fox import forms_rate_parent_page as linked
from fox.forms_rate_choices import compile_rate_choices
from fox.forms_rate_numbers import compile_rate_numbers
from fox.forms_rate_parent import compile_rate_parent
from test_forms_rate_choices import COMPANIONS, ITEMS
from test_forms_rate_parent import SOURCE, setup


@lru_cache(maxsize=2)
def compiled(prevent='false'):
    root = ET.fromstring(SOURCE)
    root.find('./Block/Relation').set('PreventMasterlessOperations',prevent)
    ET.SubElement(root.find("./Block[@Name='HEADER']"), 'Item', Name='DESCRIPTION',
                  ItemType='Text Item', DataType='Char', DatabaseItem='true', MaximumLength='40')
    child = root.find("./Block[@Name='LINES']")
    child.extend(list(ET.fromstring(b'<Root>' + ITEMS + b'</Root>')))
    for item in child.findall('Item'):
        item.attrib.setdefault('DataType','Char')
        item.attrib.setdefault('DatabaseItem','true')
    root.extend(list(ET.fromstring(b'<Root>' + COMPANIONS + b'</Root>')))
    ET.SubElement(child, 'Item', Name='AMOUNT', ColumnName='RATE_AMOUNT', DatabaseItem='true',
                  ItemType='Text Item', DataType='Number', Prompt='Price',
                  FormatMask='99,999,990.90', MaximumLength='12')
    args, c = setup(ET.tostring(root))
    return c, compile_rate_choices(*args,c), compile_rate_parent(*args,c), compile_rate_numbers(*args,c)


def context(p):
    return deepcopy(p['binding']['native_entry']['action'])


def test_rendering_is_deterministic_immutable_and_explicitly_partial():
    c,b,p,n = compiled()
    before = deepcopy((c,b,p,n))
    result = workspace.render_rate_workspace(c,b,7800,numbers=n,parent=p)
    assert result == workspace.render_rate_workspace(c,b,7800,numbers=n,parent=p)
    assert (c,b,p,n) == before
    m = result['metadata']
    assert m['parent_copy_fields'] == p['binding']['join_pairs']
    assert m['parent_copy_immutable'] and m['standalone_rows_allowed']
    assert m['draft_table'] != workspace.render_rate_workspace(c,b,7800,numbers=n)['metadata']['draft_table']
    for page in result['pages']:
        text = page['text'].decode()
        assert 'Copied PARENT_ID' in text and 'Copied PARENT_BRANCH' in text
        for key in ('K1','K2'):
            item, = re.findall(r'pageItem P\d+_' + key + r' \((.*?)\n    \)',text,re.S)
            assert 'type: displayOnly' in item and 'sessionStateProtection: restricted' in item
        assert 'FOX_RATE_PARENT_CREATE' not in text
    assert result['supporting_sql'].count(b'K001 varchar2(4000 byte)') == 2
    editor = result['pages'][0]['text'].decode()
    assert 'Create a separate standalone partial draft' in editor
    assert 'Copied parent keys are immutable' in editor


def test_parent_launcher_is_signed_exact_context_and_exposes_only_server_copies():
    c,b,p,n = compiled()
    launch = linked.render_parent_page(c,b,p,7800,7900,context(p),numbers=n)
    text = launch['pages'][0]['text'].decode()
    fragment = launch['entry_fragment']
    assert 'pageAccessProtection: argumentsMustHaveChecksum' in text
    assert 'storage: request' in text and 'storage: session' not in text
    assert 'P7900_PARENT_ID: "#FOX_PARENT_ID#"' in fragment
    assert 'P7900_TOKEN: "#FOX_PARENT_TOKEN#"' in fragment
    item = context(p)['parent_item']
    assert ':' + item in fragment and 'pageItemsToSubmit: ' + item in fragment
    assert 'region rate-parent-entry (' in fragment
    assert 'sessionStateProtection: checksumRequiredSessionLevel' in text
    code = linked.parent_create_code(c,b,p,7800,7900,numbers=n)
    assert code.index('for update nowait') < code.index('insert into ')
    assert 'l_key1:=l_current_key1' in code and 'l_key2:=l_current_key2' in code
    assert ':P7900_K1' not in code and ':P7900_K2' not in code
    assert 'PARENT_ID,PARENT_STAMP,K001,K002)' in code
    assert 'lengthb(l_current_key2)>30' in code and 'lengthb(l_current_key2)>20' in code
    assert not re.search(r'\b(commit|substr|execute immediate)\b',code,re.I)
    assert launch['metadata']['parent_copy_fields'] == p['binding']['join_pairs']
    assert launch['metadata']['create_request'] == linked.CREATE
    assert 'runtime_verified' in launch['metadata'] and not launch['metadata']['runtime_verified']
    assert 'conservative byte bound without truncation' in text


@pytest.mark.parametrize('mutation',['relation','page','item','file','parent','child'])
def test_launcher_context_is_not_an_arbitrary_read_navigation_capability(mutation):
    c,b,p,n = compiled()
    ctx = context(p)
    key = {'relation':'relation_id','page':'page_id','item':'parent_item','file':'page_file',
           'parent':'parent_block_id','child':'child_block_id'}[mutation]
    ctx[key] = 'other'
    with pytest.raises(ValueError):
        linked.render_parent_page(c,b,p,7800,7900,ctx,numbers=n)


def test_mutations_check_current_parent_and_never_reassign_copied_keys():
    c,b,p,n = compiled()
    for action in (*workspace.route.REQUESTS,workspace.SAVE,workspace.REOPEN):
        code = workspace.action_code(c,b,7800,action,numbers=n,parent=p)
        assert len(code.encode()) < 32767
        assert 'when others then rollback to ' in code
        if action not in ('FOX_ROW_CREATE','FOX_ROW_DISCARD'):
            assert 'l_current_stamp' in code and 'Parent changed.' in code
            assert 'for update nowait' in code
            assert code.index('l_parent_id number;') < code.index('function fox_n1')
        for update in re.findall(r'update [^;]+;',code,re.I):
            assert not re.search(r'(?:K001|K002|PARENT_ID|PARENT_STAMP)\s*=',update)
        assert ':P7800_K1' not in code and ':P7800_K2' not in code
    standalone = workspace.action_code(c,b,7800,'FOX_ROW_CREATE',numbers=n,parent=p)
    insert, = re.findall(r'insert into [^;]+;',standalone)
    assert 'PARENT_ID' not in insert and 'K001' not in insert
    save = workspace.action_code(c,b,7800,workspace.SAVE,numbers=n,parent=p)
    assert 'Saved parent binding changed.' in save
    reopen = workspace.action_code(c,b,7800,workspace.REOPEN,numbers=n,parent=p)
    assert 'l_parent_id,l_parent_stamp,l_key1,l_key2' in reopen
    assert 'l_key1:=l_current_key1' not in reopen


def test_no_parent_binding_retains_existing_output_bytes():
    c,b,p,n = compiled()
    # A real no-binding receipt must come from the same source compile. The
    # source fixture without CopyValueFromItem remains valid as a partial editor.
    root = ET.fromstring(SOURCE)
    for item in root.iter('Item'):
        item.attrib.pop('CopyValueFromItem',None)
    child = root.find("./Block[@Name='LINES']")
    child.extend(list(ET.fromstring(b'<Root>' + ITEMS + b'</Root>')))
    for item in child.findall('Item'):
        item.attrib.setdefault('DataType','Char')
        item.attrib.setdefault('DatabaseItem','true')
    root.extend(list(ET.fromstring(b'<Root>' + COMPANIONS + b'</Root>')))
    args,c = setup(ET.tostring(root))
    b,p = compile_rate_choices(*args,c),compile_rate_parent(*args,c)
    assert p['binding'] is None
    assert workspace.render_rate_workspace(c,b,7800,parent=p) == workspace.render_rate_workspace(c,b,7800)
    for action in (*workspace.route.REQUESTS,workspace.SAVE,workspace.REOPEN):
        assert workspace.action_code(c,b,7800,action,parent=p) == workspace.action_code(c,b,7800,action)
    assert workspace.choice_query(c,b,7800,parent=p) == workspace.choice_query(c,b,7800)


def test_source_masterless_prohibition_hides_and_guards_standalone_creation():
    c,b,p,n = compiled('true')
    result = workspace.render_rate_workspace(c,b,7800,parent=p,numbers=n)
    assert result['metadata']['standalone_rows_allowed'] is False
    assert 'button fox-row-create (' not in result['pages'][0]['text'].decode()
    code = workspace.action_code(c,b,7800,'FOX_ROW_CREATE',parent=p,numbers=n)
    assert code.index('This source requires explicit parent selection') < code.index('insert into ')


class SQLBoundary:
    """Runs exact emitted SELECT/DML; callers model PL/SQL branching/revisions."""
    def __init__(self):
        self.c,self.b,self.p,self.n = compiled()
        self.result = workspace.render_rate_workspace(self.c,self.b,7800,numbers=self.n,parent=self.p)
        self.m = self.result['metadata']
        self.db = sqlite3.connect(':memory:')
        self.ctx = dict(APP_ID='42', APP_SESSION='session-a', APP_USER='TESTER')
        self.db.create_function('v',1,self.ctx.get)
        self.db.create_function('to_number',1,lambda value: None if value is None else int(value))
        self.db.create_function('to_char',-1,lambda value,*_: None if value is None else str(value))
        self.db.create_function('cast_to_raw',1,lambda value: None if value is None else str(value))
        self.db.create_function('decode',4,lambda a,b,c,d:c if a==b else d)
        self.db.create_function('rawtohex',1,lambda value: value.hex().upper() if isinstance(value,bytes) else value)
        self.db.create_function('standard_hash',2,lambda value,_:sha256(str(value).encode()).digest())
        self.db.executescript("create temp table dual(dummy text);insert into dual values('X');")
        ddl = re.sub(r'varchar2\(\d+ (?:byte|char)\)','text',self.result['supporting_sql'].decode(),flags=re.I)
        ddl = re.sub(r'default sysdate\+1','default 11',ddl)
        ddl = re.sub(r'default sysdate','default 10',ddl)
        self.db.executescript(ddl)
        cols = self.p['binding']['parent_native_block']['items']
        self.parent = self.p['binding']['parent']['table']
        self.db.execute(f'create table {self.parent}(FOX_ROW_ID number primary key,' + ','.join(col['column']+' text' for col in cols)+')')
        self.db.executemany(f'insert into {self.parent} values(?,?,?,?)',
                            [(1,'SAME','NORTH','North customer'),(2,'SAME','SOUTH','South customer')])

    def code(self, action):
        return workspace.action_code(self.c,self.b,7800,action,numbers=self.n,parent=self.p)

    def run(self, statement, params=None):
        statement = re.sub(r'\bsysdate\b','10',statement)
        statement = statement.replace('utl_raw.cast_to_raw','cast_to_raw')
        statement = re.sub(r'\bfor update nowait\b','',statement)
        statement = re.sub(r'\bl_(parent_id|parent_stamp|key[12]|current_stamp|current_key[12]|token|uuid|n1|input_n1|f[0-9]+|label|saved_uuid|saved_revision|current)\b',r':l_\1',statement)
        return self.db.execute(statement,params or {})

    def snapshot(self,parent_id):
        sql = f'select {linked._stamp(self.p)} from {self.parent} p where p.FOX_ROW_ID=:id'
        return self.run(sql,dict(id=parent_id)).fetchone()[0]


def test_exact_emitted_sql_two_branches_save_reopen_new_session_and_isolation():
    h = SQLBoundary()
    create_code = linked.parent_create_code(h.c,h.b,h.p,7800,7900,numbers=h.n)
    create, = re.findall(r'insert into [^;]+;',create_code)
    save, = re.findall(r'insert into FOX_WS_[^;]+;',h.code(workspace.SAVE))
    reopen, = re.findall(r'insert into FOX_WD_[^;]+;',h.code(workspace.REOPEN))
    for serial,branch,price in [(1,'NORTH','1234.56'),(2,'SOUTH','-98.70')]:
        params = dict(l_uuid=f'{serial:032X}',P7900_LABEL=f'Rate {branch}',l_parent_id=serial,
                      l_parent_stamp=h.snapshot(serial),l_key1='SAME',l_key2=branch)
        h.run(create,params)
        draft = h.db.execute(f"select K001,K002,PARENT_ID from {h.m['draft_table']} where ROW_UUID=?",(params['l_uuid'],)).fetchone()
        assert draft == ('SAME',branch,serial)
        fields = {f'l_f{i}':None for i in range(1,6)}
        save_params = dict(params,**fields,l_saved_uuid=f'{serial+10:032X}',l_label=f'Rate {branch}',l_n1=float(Decimal(price)))
        h.run(save,save_params)
        h.ctx['APP_SESSION'] = 'new-session'
        save_params.update(l_uuid=f'{serial+20:032X}',l_saved_revision=0,P7800_OPEN=save_params['l_saved_uuid'])
        h.run(reopen,save_params)
        row = h.db.execute(f"select K001,K002,N001,PARENT_ID from {h.m['draft_table']} where ROW_UUID=?",(save_params['l_uuid'],)).fetchone()
        assert row[:2] == ('SAME',branch) and Decimal(str(row[2]))==Decimal(price) and row[3]==serial
        h.ctx['APP_SESSION'] = 'session-a'
    # Exact parent-scoped query with valid tab-specific token returns just its
    # branch despite matching customer ID, and works in a fresh APEX session.
    h.ctx['APP_SESSION'] = 'session-c'
    for parent_id,branch in [(1,'NORTH'),(2,'SOUTH')]:
        stamp = h.snapshot(parent_id)
        token = h.run('select '+linked._token(h.p,':stamp')+' from dual',dict(stamp=stamp)).fetchone()[0]
        query = linked.scoped_query(h.c,h.b,h.p,7900,numbers=h.n)
        params = dict(P7900_PARENT_ID=parent_id,P7900_TOKEN=token)
        rows = h.run(query,params).fetchall()
        assert len(rows)==1 and rows[0][2:]==('Rate '+branch,'SAME',branch)
        description = next(col['column'] for col in h.p['binding']['parent_native_block']['items']
                           if col['source_name']=='DESCRIPTION')
        h.db.execute(f'update {h.parent} set {description}=? where FOX_ROW_ID=?',('Renamed display',parent_id))
        assert h.snapshot(parent_id)==stamp
        assert h.run(query,params).fetchall()==rows
        assert not h.run(query,dict(params,P7900_PARENT_ID=3-parent_id)).fetchall()
        for field,value in [('APP_ID','99'),('APP_USER','OTHER'),('APP_USER','NOBODY')]:
            original = h.ctx[field]
            h.ctx[field]=value
            assert not h.run(query,params).fetchall()
            h.ctx[field]=original
        column = h.p['binding']['join_pairs'][1]['parent_column']
        h.db.execute(f'update {h.parent} set {column}=? where FOX_ROW_ID=?',('CHANGED',parent_id))
        assert not h.run(query,params).fetchall()
        h.db.execute(f'update {h.parent} set {column}=? where FOX_ROW_ID=?',(branch,parent_id))


def test_emitted_selection_reads_reject_removed_null_changed_parent_and_two_tabs():
    h = SQLBoundary()
    code = linked.parent_create_code(h.c,h.b,h.p,7800,7900,numbers=h.n)
    selection, = re.findall(r'select RAWTOHEX\(STANDARD_HASH\(.*? into l_current_stamp,.*?;',code)
    query = re.sub(r' into l_current_stamp,l_current_key1,l_current_key2', '', selection)
    first = h.run(query,dict(l_parent_id=1)).fetchone()
    second = h.run(query,dict(l_parent_id=2)).fetchone()
    assert first[1:]==('SAME','NORTH') and second[1:]==('SAME','SOUTH') and first[0]!=second[0]
    key = h.p['binding']['join_pairs'][1]['parent_column']
    h.db.execute(f'update {h.parent} set {key}=NULL where FOX_ROW_ID=1')
    assert h.run(query,dict(l_parent_id=1)).fetchone() is None
    assert h.run(query,dict(l_parent_id=2)).fetchone() == second
    h.db.execute(f'update {h.parent} set {key}=? where FOX_ROW_ID=1',('CHANGED',))
    changed = h.run(query,dict(l_parent_id=1)).fetchone()
    assert changed[0] != first[0]
    h.db.execute(f'delete from {h.parent} where FOX_ROW_ID=1')
    assert h.run(query,dict(l_parent_id=1)).fetchone() is None
    assert h.run(query,dict(l_parent_id=2)).fetchone() == second


def test_exact_keep_revision_check_preserves_parent_keys_across_two_tabs():
    h = SQLBoundary()
    create_code = linked.parent_create_code(h.c,h.b,h.p,7800,7900,numbers=h.n)
    create, = re.findall(r'insert into [^;]+;',create_code)
    params = dict(l_uuid='A'*32,P7900_LABEL='Rate north',l_parent_id=1,
                  l_parent_stamp=h.snapshot(1),l_key1='SAME',l_key2='NORTH')
    h.run(create,params)
    keep, = re.findall(r'update FOX_WD_[^;]+;',h.code('FOX_ROW_KEEP'))
    names = set(re.findall(r':([A-Za-z0-9_]+)',keep))
    controls = {name:None for name in names}
    controls.update(P7800_ROW='A'*32,P7800_REV='0',P7800_LABEL='Rate north',l_input_n1=1234.56)
    assert h.run(keep,controls).rowcount==1
    assert h.run(keep,dict(controls,l_input_n1=0)).rowcount==0
    row = h.db.execute(f"select K001,K002,N001,REVISION from {h.m['draft_table']} where ROW_UUID=?",('A'*32,)).fetchone()
    assert row==('SAME','NORTH',1234.56,1)
    h.ctx['APP_USER']='OTHER'
    assert h.run(keep,dict(controls,P7800_REV='1',l_input_n1=0)).rowcount==0
