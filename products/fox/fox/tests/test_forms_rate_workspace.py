"""Execute emitted SQL in SQLite; PL/SQL control/locks are explicitly modelled.

These checks do not claim Oracle compilation, APEX import, signed-link runtime
or business acceptance. Target checks consume the same public action_code API.
"""
from copy import deepcopy
from functools import lru_cache
import hashlib
import re
import sqlite3

import pytest

from fox import forms_rate_workspace as native
from fox import forms_route_lookup_native as route
from fox.forms_rate_choices import compile_rate_choices
from test_forms_rate_choices import SOURCE, prepare
from test_forms_route_lookup_plan import TYPED_BODY


@lru_cache(maxsize=4)
def compiled(renamed=False, typed=False):
    raw = SOURCE
    if typed:
        raw = raw.replace(b'BEGIN NULL; END;',TYPED_BODY.encode())
    if renamed:
        for a,b in [(b'SHIPPING',b'ORDERING'),(b'LINES',b'POSITIONS'),(b'TIER',b'GRADE'),
                    (b'UNIT',b'MEASURE'),(b'CODE',b'IDENTIFIER'),(b'FACTOR',b'MULTIPLIER')]:
            raw = raw.replace(a,b)
    args,c = prepare(raw)
    return c,compile_rate_choices(*args,c)


@pytest.mark.parametrize('renamed',[False,True])
def test_editor_and_all_choosers_share_one_owned_row_with_no_invented_returns(renamed):
    c,b = compiled(renamed)
    before = deepcopy((c,b))
    result = native.render_rate_workspace(c,b,7800)
    assert native.render_rate_workspace(c,b,7800) == result and (c,b) == before
    m = result['metadata']
    assert [p['page_id'] for p in result['pages']] == [7800,7801,7802,7803]
    for p in result['pages']:
        assert f"alias: FOX_RATE_{p['page_id']}\n" in p['text'].decode()
        assert p['page_file'] == f"pages/p{p['page_id']:05d}-fox_rate_{p['page_id']}.apx"
    assert m['page_count'] == 4 and len(m['draft_fields']) == 5
    assert m['saved_row_key'] == ['APP_ID','OWNER_NAME','SAVED_UUID']
    assert m['durable_synthetic_save'] and not m['saved_rows_expire']
    assert not any(m[k] for k in ('business_table_writes','runtime_verified','oracle_compiled','business_accepted'))
    assert m['catalog_table'] in m['synthetic_query_sql']
    assert route._names(c)['catalog_table'] not in m['synthetic_query_sql']
    editor = result['pages'][0]['text'].decode()
    for label in ('Save synthetic row','Reopen selected saved row','Open row','unrepresented','source commits'):
        assert label in editor
    for token in re.findall(r'#([A-Z_]+)#',editor):
        if token in ('DEFAULT',):
            continue
        assert re.search(r'column '+token+r' \(',editor),token
    for f in b['fields']:
        item = re.search(r'pageItem P7800_F'+str(f['slot'])+r' \((.*?)\n    \)',editor,re.S)[1]
        assert 'type: displayOnly' in item and 'sessionStateProtection: restricted' in item
    for i,ch in enumerate(b['choices'],2):
        meta = m['companion_choices'][i-2]
        assert meta['source_lov_id'] == ch['source_lov_id']
        assert meta['chooser_page_id'] == 7800+i and meta['chooser_page_file'] == result['pages'][i]['page_file']
        assert meta['return_mappings'] == ch['returns'] and meta['catalog_columns'] == ch['columns']
        query = native.choice_query(c,b,7800+i,i-1,ordered=True)
        assert query.endswith('q.'+ch['query']['order'][0]['parts'][-1]+(' DESC' if i == 3 else ''))
        code = native.action_code(c,b,7800+i,'FOX_ROW_APPLY',i-1)
        update, = re.findall(r'update FOX_WD_.*?;',code,re.S)
        assert f"{ch['returns'][0]['column']}=l_return1" in update
        assert all(f['column']+'=' not in update for f in m['draft_fields'] if f not in ch['returns'])
        assert len(re.findall(r'l_return\d+ varchar2',code)) == len(ch['returns'])
        assert ch['source_table'] not in code
    ddl = result['supporting_sql'].decode()
    saved = ddl[ddl.index('create table '+m['saved_table']):].split(');')[0]
    assert 'SESSION_ID' not in saved and 'EXPIRES_AT' not in saved
    assert all(f['column']+' varchar2' in saved for f in m['draft_fields'])
    assert 'FACTOR number' in ddl or 'MULTIPLIER number' in ddl
    numeric = b['choices'][1]['columns'][2]['name']
    numeric_column = re.search(r'column '+numeric+r' \((.*?)\n        \)',result['pages'][3]['text'].decode(),re.S)[1]
    assert 'dataType: NUMBER' in numeric_column


def test_route_actions_reuse_original_typed_semantics_and_every_link_preserves_context():
    c,b = compiled(typed=True)
    result = native.render_rate_workspace(c,b,7800)
    names = result['metadata']
    for action in route.REQUESTS:
        expected = route.action_code(c,7800,action)
        for key,old in route._names(c).items():
            expected = expected.replace(old,names[key])
        assert native.action_code(c,b,7800,action) == expected
    for p in result['pages']:
        text = p['text'].decode()
        assert 'authentication: required' in text and 'pageAccessProtection: argumentsMustHaveChecksum' in text
        for suffix in ('ROW','REV','CHOICE','OPEN','SREV'):
            item = re.search(r'pageItem P'+str(p['page_id'])+'_'+suffix+r' \((.*?)\n    \)',text,re.S)[1]
            assert 'checksumRequiredSessionLevel' in item and 'storage: request' in item
        for items in re.findall(r'items \{(.*?)\n\s*\}',text,re.S):
            if '_ROW:' in items:
                assert '_REV:' in items
            if '_OPEN:' in items:
                assert '_SREV:' in items
        if p['page_id'] != 7800:
            cancel = re.search(r'button cancel-choice \((.*?)\n    \)',text,re.S)[1]
            assert 'redirectThisApp' in cancel and 'submitPage' not in cancel
    for rec in names['typed_lookup_receipts']:
        for binding in rec['page_bindings']:
            assert binding['page_file'] == next(p['page_file'] for p in result['pages'] if p['page_id'] == binding['page_id'])


@pytest.mark.parametrize('action,index',[(native.SAVE,0),(native.REOPEN,0),('FOX_ROW_APPLY',1),('FOX_ROW_APPLY',2)])
def test_new_transactions_are_bounded_and_rollback_owned_atomic_writes(action,index):
    c,b = compiled()
    code = native.action_code(c,b,7800,action,index)
    assert len(code.encode()) <= 32767 and 'for update nowait' in code
    assert 'rollback to fox_rate_workspace' in code
    assert "APP_ID=to_number(v('APP_ID'))" in code and "OWNER_NAME=v('APP_USER')" in code
    assert not re.search(r'\b(commit|execute immediate|apex_web_service)\b',code,re.I)
    if action == native.SAVE:
        assert 'l_saved_revision is null or l_current<>l_saved_revision' in code
        assert 'SAVED_REVISION=l_current,REVISION=REVISION+1' in code
        assert 'Keep draft changes before saving or choosing.' in code
        assert 'list-validated value changed or is ambiguous' in code
    if action != native.REOPEN:
        assert "SESSION_ID=v('APP_SESSION')" in code


@pytest.mark.parametrize('mutation',['source','slot','mapping','type','vfl','hash','overlap'])
def test_tampered_or_aliased_companions_fail_closed(mutation):
    c,b = deepcopy(compiled())
    if mutation == 'source': b['source_binding'] = 'other'
    elif mutation == 'slot': b['fields'][0]['slot'] = 1
    elif mutation == 'mapping': b['choices'][0]['returns'].clear()
    elif mutation == 'type': b['choices'][1]['columns'][2]['data_type'] = 'VARCHAR2'
    elif mutation == 'vfl': b['choices'][0]['validate_from_list'] = False
    elif mutation == 'hash': b['bundle_id'] = 'rate-choices-'+'0'*24
    else: b['choices'][0]['returns'][0]['source_item_id'] = c['fields'][0]['source_item_id']
    with pytest.raises(ValueError):
        native.render_rate_workspace(c,b,7800)


class SqlBoundary:
    """Model PL/SQL branches; execute exact emitted SELECT and DML statements."""
    def __init__(self,path=':memory:',*,existing=None,renamed=False):
        self.c,self.b = deepcopy(compiled(renamed))
        self.result = native.render_rate_workspace(self.c,self.b,7800)
        self.m = self.result['metadata']
        self.fields = self.m['draft_fields']
        self.context = {'APP_ID':'42','APP_SESSION':'314159','APP_USER':'TESTER'}
        self.db = sqlite3.connect(path)
        for name,n,fn in [
            ('v',1,lambda k:self.context.get(k)),('to_number',1,lambda x:int(x) if x is not None else None),
            ('to_char',-1,lambda x,*_:str(x) if x is not None else None),
            ('STANDARD_HASH',2,lambda a,b:hashlib.sha256(str(a).encode()).digest()),
            ('RAWTOHEX',1,lambda x:x.hex().upper() if x else None),
            ('lengthb',1,lambda x:len(x.encode()) if x is not None else None),
            ('nvl',2,lambda a,b:b if a is None else a),('now_clock',0,lambda:10),
            ('decode',4,lambda a,b,c,d:c if a==b else d),('cast_to_raw',1,lambda x:x.encode() if x is not None else None)]:
            self.db.create_function(name,n,fn)
        if not existing:
            ddl = re.sub(r'varchar2\([0-9]+ (?:byte|char)\)','text',self.result['supporting_sql'].decode(),flags=re.I)
            ddl = re.sub(r'default sysdate\+1','default (now_clock()+1)',ddl,flags=re.I)
            ddl = re.sub(r'default sysdate','default (now_clock())',ddl,flags=re.I)
            self.db.executescript(ddl)
        self.serial = 100 if existing else 0

    def sql(self,text):
        text = re.sub(r'\bsysdate\b','now_clock()',text,flags=re.I).replace('utl_raw.cast_to_raw','cast_to_raw')
        return re.sub(r'\bl_(uuid|return[0-9]+|f[0-9]+|label|saved_uuid|saved_revision|current)\b',r':l_\1',text)

    def code(self,action,index=0):
        return native.action_code(self.c,self.b,7800,action,index)

    def params(self,row,revision):
        return {'P7800_ROW':row,'P7800_REV':str(revision)}

    def run(self,statement,params):
        return self.db.execute(self.sql(statement),params)

    def uuid(self):
        self.serial += 1
        return f'{self.serial:032X}'

    def create(self,label):
        row = self.uuid()
        statement = re.search(r'insert into .*?;',self.code('FOX_ROW_CREATE'),re.S)[0]
        self.run(statement,{'P7800_LABEL':label,'l_uuid':row})
        return row

    def values(self,row):
        return self.db.execute('select ROW_LABEL,REVISION,SAVED_UUID,SAVED_REVISION,'+','.join(f['column'] for f in self.fields)+' from '+self.m['draft_table']+' where ROW_UUID=?',(row,)).fetchone()

    def seed(self):
        routecols = self.c['columns']
        active = self.c['active_predicate']['left']['parts'][-1]
        self.db.executemany('insert into '+self.m['catalog_table']+'('+','.join([col['name'] for col in routecols]+[active])+') values(?,?,?,?)',[
            ('R1','A','B','1'),('R2','C','D','1'),('R0','E','F','0')])
        for i,choice in enumerate(self.m['companion_choices']):
            cols = ','.join(col['name'] for col in choice['catalog_columns'])
            rows = [('S1','First'),('S2','Second')] if i == 0 else [('U1','One',1.5),('U2','Two',2.5)]
            self.db.executemany('insert into '+choice['catalog_table']+'('+cols+') values('+','.join('?' for _ in rows[0])+')',rows)

    def choices(self,row,revision,index):
        return self.run(native.choice_query(self.c,self.b,7800,index,ordered=True),self.params(row,revision)).fetchall()

    def lock(self,code,params):
        match = re.search(r'select REVISION into l_revision (.*?) for update nowait;',code,re.S)
        result = self.run('select REVISION '+match[1],params).fetchall()
        return len(result) == 1 and result[0][0] == int(params['P7800_REV'])

    def apply(self,row,revision,token,index):
        code = self.code('FOX_ROW_APPLY',index)
        p = {**self.params(row,revision),'P7800_CHOICE':token}
        if not self.lock(code,p): return False
        match = re.search(r'select (q\..*?) into (l_return1.*?) from (.*?) where q.FOX_CHOICE=:P7800_CHOICE;',code,re.S)
        values = self.run('select '+match[1]+' from '+match[3]+' where q.FOX_CHOICE=:P7800_CHOICE',p).fetchall()
        if len(values) != 1: return False
        p.update({'l_return'+str(i):v for i,v in enumerate(values[0],1)})
        for condition in re.findall(r'if (nvl\(lengthb\(l_return.*?) then',code):
            if self.run('select case when '+condition+' then 1 else 0 end',p).fetchone()[0]: return False
        update, = re.findall(r'update FOX_WD_.*?;',code,re.S)
        return self.run(update,p).rowcount == 1

    def keep(self,row,revision,*,label=None,caller=None):
        code = self.code('FOX_ROW_KEEP')
        old = self.values(row)
        p = {**self.params(row,revision),'P7800_LABEL':old[0] if label is None else label,'P7800_F1':old[4] if caller is None else caller}
        if not self.lock(code,p): return False
        update, = re.findall(r'update FOX_WD_.*?;',code,re.S)
        return self.run(update,p).rowcount == 1

    def save(self,row,revision,*,submitted_label=None,submitted_caller=None):
        code = self.code(native.SAVE)
        old = self.values(row)
        p = {**self.params(row,revision),'P7800_LABEL':old[0] if submitted_label is None else submitted_label,'P7800_F1':old[4] if submitted_caller is None else submitted_caller}
        self.db.execute('savepoint action')
        try:
            if not self.lock(code,p): raise ValueError('stale draft')
            dirty = re.search(r'select count\(\*\) into l_count (.*?);',code,re.S)[1]
            if self.run('select count(*) '+dirty,p).fetchone()[0] != 1: raise ValueError('dirty')
            load = re.search(r'select (SAVED_UUID,SAVED_REVISION,ROW_LABEL,.*?) into (.*?) from (.*?) where (.*?);',code,re.S)
            values = self.run('select '+load[1]+' from '+load[3]+' where '+load[4],p).fetchone()
            p.update(zip(load[2].split(','),values))
            for condition in re.findall(r'if (nvl\(lengthb\(l_f.*?) then',code):
                if self.run('select case when '+condition+' then 1 else 0 end',p).fetchone()[0]: raise ValueError('constraint')
            membership = re.findall(r'select count\(\*\) into l_count from (\(select q\..*?\) q where .*?);',code,re.S)
            for ch,sql in zip(self.b['choices'],membership,strict=True):
                if any(p['l_f'+str(f['slot'])] is not None for f in ch['returns']):
                    if self.run('select count(*) from '+sql,p).fetchone()[0] != 1: raise ValueError('membership')
            if p['l_saved_uuid'] is None:
                p['l_saved_uuid'],p['l_current'] = self.uuid(),0
                insert, = re.findall(r'insert into FOX_WS_.*?;',code,re.S)
                self.run(insert,p)
            else:
                select = re.search(r'select REVISION into l_current (.*?) for update nowait;',code,re.S)[1]
                rows = self.run('select REVISION '+select,p).fetchall()
                if len(rows) != 1 or rows[0][0] != p['l_saved_revision']: raise ValueError('saved stale')
                update, = re.findall(r'update FOX_WS_.*?;',code,re.S)
                if self.run(update,p).rowcount != 1: raise ValueError('cas')
                p['l_current'] = rows[0][0]+1
            update, = re.findall(r'update FOX_WD_.*?;',code,re.S)
            if self.run(update,p).rowcount != 1: raise ValueError('draft cas')
            self.db.execute('release action')
            return p['l_saved_uuid']
        except (ValueError,sqlite3.IntegrityError):
            self.db.execute('rollback to action')
            self.db.execute('release action')
            return False

    def reopen(self,saved,revision):
        code = self.code(native.REOPEN)
        p = {'P7800_OPEN':saved,'P7800_SREV':str(revision),'l_uuid':self.uuid()}
        select = re.search(r'select (REVISION,ROW_LABEL,.*?) into (.*?) from (.*?) where (.*?) for update nowait;',code,re.S)
        values = self.run('select '+select[1]+' from '+select[3]+' where '+select[4],p).fetchall()
        if len(values) != 1 or values[0][0] != revision: return False
        p.update(zip(select[2].split(','),values[0]))
        insert, = re.findall(r'insert into FOX_WD_.*?;',code,re.S)
        self.run(insert,p)
        return p['l_uuid']


@pytest.mark.parametrize('renamed',[False,True])
def test_actual_emitted_chooser_sql_preserves_siblings_two_rows_and_stale_tokens(renamed):
    h = SqlBoundary(renamed=renamed)
    h.seed()
    a,b = h.create('first'),h.create('second')
    for row in (a,b):
        for revision,index in enumerate((0,1,2)):
            choices = h.choices(row,revision,index)
            assert h.apply(row,revision,choices[-1][-1],index)
    assert h.values(a)[4:] == ('R2','C','D','S2','U1')
    before = h.values(b)
    token = h.choices(a,3,1)[0][-1]
    assert not h.apply(b,3,token,1) and h.values(b) == before
    assert not h.apply(a,3,token,2) # token cannot cross a LOV
    assert h.apply(a,3,token,1) and not h.apply(a,3,token,1)
    assert h.values(b) == before
    h.context['APP_USER'] = 'OTHER'
    assert not h.choices(a,4,1) and not h.apply(a,4,token,1)
    h.context.update(APP_USER='TESTER',APP_ID='99')
    assert not h.choices(a,4,1)


def test_durable_save_close_reopen_refreshes_baseline_and_rejects_stale_retry(tmp_path):
    path = tmp_path/'saved.sqlite'
    h = SqlBoundary(path)
    h.seed()
    a = h.create('one')
    assert not h.save(a,0) # required source values remain required
    for rev,index in enumerate((0,1)):
        assert h.apply(a,rev,h.choices(a,rev,index)[0][-1],index)
    assert not h.save(a,2,submitted_label='dirty')
    saved = h.save(a,2)
    assert saved and h.values(a)[3] == 0 and h.values(a)[-1] is None # optional choice
    assert not h.save(a,2) # same first-save retry cannot duplicate
    assert h.db.execute('select count(*) from '+h.m['saved_table']).fetchone()[0] == 1
    h.db.commit()
    h.db.close()
    h = SqlBoundary(path,existing=True)
    h.context['APP_SESSION'] = '271828'
    assert not h.choices(a,3,1) # old session draft remains private
    first,second = h.reopen(saved,0),h.reopen(saved,0)
    assert first != second and h.values(first)[4:] == ('R1','A','B','S1',None)
    assert h.apply(first,0,h.choices(first,0,2)[0][-1],2)
    assert h.save(first,1) == saved and h.values(first)[3] == 1
    assert h.apply(first,2,h.choices(first,2,2)[-1][-1],2)
    assert h.save(first,3) == saved and h.values(first)[3] == 2 # refreshed baseline
    stale_snapshot = h.values(second)
    assert not h.save(second,0) and h.values(second) == stale_snapshot
    assert not h.reopen(saved,0)
    for context in ({'APP_USER':'OTHER'},{'APP_ID':'88'}):
        before = dict(h.context)
        h.context.update(context)
        assert not h.reopen(saved,2)
        h.context = before
    assert h.db.execute('select count(*) from '+h.m['saved_table']).fetchone()[0] == 1


def test_invalid_duplicate_and_disappeared_choices_rollback_and_discard_is_draft_only():
    h = SqlBoundary()
    h.seed()
    a,b = h.create('a'),h.create('b')
    for rev,index in enumerate((0,1)):
        assert h.apply(a,rev,h.choices(a,rev,index)[0][-1],index)
    saved = h.save(a,2)
    prior = h.values(a)
    table = h.m['companion_choices'][0]['catalog_table']
    h.db.execute('delete from '+table)
    assert not h.save(a,3) and h.values(a) == prior
    h.db.executemany('insert into '+table+' values(?,?)',[('S1','a'),('S1','a')])
    token = h.choices(a,3,1)[0][-1]
    assert not h.apply(a,3,token,1) and not h.save(a,3)
    assert h.values(a) == prior
    # Opening and cancelling do not perform DML. Discard is the only removal.
    code = h.code('FOX_ROW_CHOOSE')
    assert not re.search(r'\b(insert into|update FOX_WD_|delete from)\b',code,re.I)
    code = h.code('FOX_ROW_DISCARD')
    delete, = re.findall(r'delete from FOX_WD_.*?;',code,re.S)
    assert h.run(delete,h.params(a,3)).rowcount == 1
    assert h.values(a) is None and h.values(b) is not None
    assert h.db.execute('select SAVED_UUID from '+h.m['saved_table']).fetchone()[0] == saved


def test_required_null_overlength_and_optional_null_choices_touch_only_their_declared_field():
    h = SqlBoundary()
    h.seed()
    a = h.create('a')
    before = h.values(a)
    service = h.m['companion_choices'][0]
    h.db.executemany('insert into '+service['catalog_table']+' values(?,?)',[(None,'Null'),('X'*11,'Long')])
    for choice in h.choices(a,0,1):
        if choice[0] is None or len(choice[0]) > 10:
            assert not h.apply(a,0,choice[-1],1) and h.values(a) == before
    unit = h.m['companion_choices'][1]
    h.db.execute('insert into '+unit['catalog_table']+' values(?,?,?)',(None,'Empty',123.456))
    choice = next(row for row in h.choices(a,0,2) if row[0] is None)
    assert h.apply(a,0,choice[-1],2)
    assert h.values(a)[4:] == (None,None,None,None,None)
    assert not h.save(a,1) # nullable currency cannot satisfy required route/service


def test_wrong_session_save_discard_and_catalog_mutation_preserve_all_rows():
    h = SqlBoundary()
    h.seed()
    a = h.create('a')
    b = h.create('b')
    token = h.choices(a,0,2)[0][-1]
    catalog = h.m['companion_choices'][1]['catalog_table']
    number = h.m['companion_choices'][1]['catalog_columns'][2]['name']
    h.db.execute('update '+catalog+' set '+number+'='+number+'+1')
    assert not h.apply(a,0,token,2) # even display-only changes invalidate the token
    before = h.values(a),h.values(b)
    h.context['APP_SESSION'] = 'other-session'
    assert not h.save(a,0)
    delete, = re.findall(r'delete from FOX_WD_.*?;',h.code('FOX_ROW_DISCARD'),re.S)
    assert h.run(delete,h.params(a,0)).rowcount == 0
    assert (h.values(a),h.values(b)) == before
