"""Native emission and actual emitted SQL on disposable SQLite tables.

The SQL boundary tests model PL/SQL control flow. They do not assert Oracle
locking, APEX import/runtime, signed-URL behavior or business acceptance.
"""
from copy import deepcopy
from functools import lru_cache
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3

import pytest

from fox.forms_route_lookup_native import action_code, choice_query, render_row_lookup, _source_message
from fox.forms_route_lookup_plan import compile_row_lookups
from test_forms_route_lookup_plan import SOURCE, prepare, typed_source, TYPED_BODY


@lru_cache(maxsize=4)
def _contract(renamed=False):
    raw = SOURCE
    if renamed:
        for a,b in [(b'SHIPPING',b'ORDERING'),(b'LINES',b'POSITIONS'),(b'VIA',b'PATH'),
                    (b'CHOICES',b'OPTIONS'),(b'NETWORK',b'GRAPH'),(b'STATE',b'ENABLED_FLAG'),
                    (b'START_AT',b'LEFT_END'),(b'END_AT',b'RIGHT_END')]:
            raw = raw.replace(a,b)
    result, = compile_row_lookups(*prepare(raw))
    return result


def contract(renamed=False):
    return deepcopy(_contract(renamed))


@pytest.mark.parametrize('renamed',[False,True])
def test_native_rows_choices_fields_and_source_scope_are_visible_and_deterministic(renamed):
    c = contract(renamed)
    before = deepcopy(c)
    result = render_row_lookup(c,7800)
    assert c == before and render_row_lookup(c,7800) == result
    editor,chooser = [p['text'].decode() for p in result['pages']]
    assert result['metadata']['entry_page_id'] == 7800
    assert result['metadata']['chooser_page_id'] == 7801
    assert c['source_block_name'] in editor and c['source_caller_name'] in chooser
    assert 'Session draft owner' in editor and 'Session draft row UUID' in editor
    assert 'Open draft' in editor and 'Create a separate draft' in editor
    assert 'Keep draft changes' in editor and 'Open choice list' in editor
    assert 'Apply choice to this draft' in chooser and 'Cancel and return to draft' in chooser
    assert 'POST-CHANGE' in editor and 'WHEN-CREATE-RECORD' in editor
    for f in c['fields']:
        item = re.search(r'pageItem P7800_F'+str(f['slot'])+r' \((.*?)\n    \)',editor,re.S)[1]
        assert ('type: displayOnly' if f['display_only'] else 'type: textField') in item
        assert f['source_name'] in item
        if f['display_only']:
            assert 'sessionStateProtection: restricted' in item
    # There is no required APEX item: empty source-required fields are valid
    # incomplete drafts, while a complete Apply enforces source requirements.
    assert 'valueRequired: true' not in editor
    assert 'Source POST-CHANGE' in editor
    assert 'no original' not in chooser.lower() or not result['metadata']['original_interface_enabled']
    assert result['metadata']['session_draft_table_writes']
    assert not result['metadata']['business_table_writes']
    assert not any(result['metadata'][k] for k in ('oracle_compiled','runtime_verified','business_accepted'))


def test_all_generated_navigation_keeps_checked_row_and_revision_through_redirect():
    pages = render_row_lookup(contract(),7800)['pages']
    for page in pages:
        text = page['text'].decode()
        assert 'authentication: required' in text
        assert 'pageAccessProtection: argumentsMustHaveChecksum' in text
        for suffix in ('ROW','REV','CHOICE'):
            item = re.search(r'pageItem P'+str(page['page_id'])+'_'+suffix+r' \((.*?)\n    \)',text,re.S)[1]
            assert 'storage: request' in item and 'checksumRequiredSessionLevel' in item
            assert 'label {' not in item # SQLcl hidden items have no label group
        for items in re.findall(r'items \{(.*?)\n\s*\}', text,re.S):
            if '_ROW:' in items:
                assert '_REV:' in items
    editor = pages[0]['text'].decode()
    assert 'clearCache: 7801' in editor
    chooser = pages[1]['text'].decode()
    assert 'P7801_CHOICE: "#FOX_CHOICE#"' in chooser
    assert 'Chosen START_AT' in chooser and 'Chosen END_AT' in chooser


def test_emitted_apply_locks_validates_exact_choice_then_updates_every_return_once():
    c = contract()
    code = action_code(c,7801,'FOX_ROW_APPLY')
    assert code.index('for update nowait') < code.index('l_revision<>to_number') < code.index('select q.')
    assert code.index('select q.') < code.index('nvl(lengthb(l_return1)') < code.index('update FOX_RD_')
    update, = re.findall(r'update FOX_RD_.*?;',code,re.S)
    for i,f in enumerate(c['returns'],1):
        assert f"{f['column']}=l_return{i}" in update
    assert 'REVISION=REVISION+1' in update and 'REVISION=:P7801_REV' in update
    assert all(k in update for k in ('APP_ID=', 'SESSION_ID=', 'OWNER_NAME=', 'ROW_UUID=', 'EXPIRES_AT>sysdate'))
    assert 'when no_data_found then rollback to fox_row_lookup' in code
    assert 'when too_many_rows then rollback to fox_row_lookup' in code
    assert ':P7801_F' not in code
    assert not re.search(r'\b(?:commit|execute immediate|apex_web_service)\b',code,re.I)
    assert c['source_table'] not in code and c['caller_source_table'] not in code


def test_choice_open_and_cancel_do_not_write_or_consume_revision_and_dirty_inputs_are_explicit():
    code = action_code(contract(),7800,'FOX_ROW_CHOOSE')
    assert not re.search(r'\b(?:insert into|update FOX_RD_|delete from)\b',code,re.I)
    assert 'Keep draft changes before opening the choice list.' in code
    assert 'utl_raw.cast_to_raw(ROW_LABEL)' in code
    assert ':P7800_F1' in code and ':P7800_F2' not in code and ':P7800_F3' not in code
    chooser = render_row_lookup(contract(),7800)['pages'][1]['text'].decode()
    cancel = re.search(r'button cancel-route \((.*?)\n    \)',chooser,re.S)[1]
    assert 'redirectThisApp' in cancel and 'submitPage' not in cancel
    assert 'P7800_ROW:' in cancel and 'P7800_REV:' in cancel


@pytest.mark.parametrize('action',['FOX_ROW_CREATE','FOX_ROW_KEEP','FOX_ROW_CHOOSE','FOX_ROW_DISCARD','FOX_ROW_APPLY'])
def test_emitted_process_is_bounded_authenticated_and_owning_session_scoped(action):
    c = contract()
    code = action_code(c,7800,action)
    assert len(code.encode()) <= 32767
    assert "upper(v('APP_USER'))='NOBODY'" in code
    assert 'SESSION_ID=v(\'APP_SESSION\')' in code and "OWNER_NAME=v('APP_USER')" in code
    assert "APP_ID=to_number(v('APP_ID'))" in code or "to_number(v('APP_ID'))" in code
    if action != 'FOX_ROW_CREATE':
        assert 'for update nowait' in code
    if action == 'FOX_ROW_CREATE':
        assert 'rownum<=100' in code and 'l_count>=100' in code
        assert 'rawtohex(sys_guid())' in code and 'l_return' not in code
    if action == 'FOX_ROW_KEEP':
        assert 'F001=:P7800_F1' in code
        assert 'F002=' not in code and 'F003=' not in code


@pytest.mark.parametrize('mutation', ['table','projection','predicate','field','role','mapping','column','interface'])
def test_renderer_rejects_unsafe_or_incomplete_contract_boundaries(mutation):
    c = contract()
    if mutation == 'table': c['query']['tables'][0][0] = 'X; DELETE FROM Y'
    elif mutation == 'projection': c['query']['projections'][0] = ['OTHER','CODE']
    elif mutation == 'predicate': c['active_predicate']['right'] = {'kind':'bind','parts':['X']}
    elif mutation == 'field': c['fields'][0]['column'] = 'X,REVISION=99'
    elif mutation == 'role': c['fields'][1]['direct_edit_allowed'] = True
    elif mutation == 'mapping': c['returns'].pop()
    elif mutation == 'column': c['columns'][0]['max_length'] = 0
    else: c['original_interface_enabled'] = True
    with pytest.raises((ValueError,KeyError)):
        render_row_lookup(c,7800)


class EmittedSqlBoundary:
    """Run emitted SELECT/INSERT/UPDATE SQL; model PL/SQL control and locks.

    Oracle builtins receive narrow SQLite equivalents. The production source
    SQL itself supplies ownership, active filtering, full-value tokens, CAS and
    the single complete update. No server, APEX or Oracle claim is made here.
    """
    def __init__(self, renamed=False, *, compiled_contract=None):
        self.c = contract(renamed) if compiled_contract is None else deepcopy(compiled_contract)
        self.page = 7800
        self.result = render_row_lookup(self.c,self.page)
        self.m = self.result['metadata']
        self.db = sqlite3.connect(':memory:')
        self.context = {'APP_ID':'42','APP_SESSION':'314159','APP_USER':'TESTER'}
        self.clock = 10
        self.db.create_function('v',1,lambda k:self.context.get(k))
        self.db.create_function('to_number',1,lambda v: None if v is None else int(v))
        self.db.create_function('to_char',-1,lambda v,*_:str(v) if v is not None else None)
        self.db.create_function('STANDARD_HASH',2,lambda a,b:hashlib.sha256(str(a).encode()).digest())
        self.db.create_function('RAWTOHEX',1,lambda a:a.hex().upper() if a else None)
        self.db.create_function('lengthb',1,lambda a:len(a.encode()) if a is not None else None)
        self.db.create_function('nvl',2,lambda a,b:b if a is None else a)
        self.db.create_function('now_clock',0,lambda:self.clock)
        self.db.create_function('decode',4,lambda a,b,c,d:c if a==b else d)
        self.db.create_function('cast_to_raw',1,lambda a:a.encode() if a is not None else None)
        ddl = self.result['supporting_sql'].decode()
        ddl = re.sub(r'varchar2\([0-9]+ (?:byte|char)\)','text',ddl,flags=re.I)
        ddl = re.sub(r'default sysdate\+1', 'default (now_clock()+1)', ddl, flags=re.I)
        ddl = re.sub(r'default sysdate', 'default (now_clock())', ddl, flags=re.I)
        self.db.executescript(ddl)
        self.serial = 0

    def sql(self,text):
        text = re.sub(r'\bsysdate\b','now_clock()',text,flags=re.I)
        text = text.replace('utl_raw.cast_to_raw','cast_to_raw')
        return re.sub(r'\bl_(uuid|return[0-9]+|typed[0-9]+|prior_caller|caller_unchanged)\b',r':l_\1',text)

    def seed(self, rows):
        names = [col['name'] for col in self.c['columns']]
        active = self.c['active_predicate']['left']['parts'][-1]
        if active not in names: names.append(active)
        self.db.executemany('insert into '+self.m['catalog_table']+'('+','.join(names)+') values('+','.join('?' for _ in names)+')',rows)

    def create(self,label):
        self.serial += 1
        row = f'{self.serial:032X}'
        code = action_code(self.c,self.page,'FOX_ROW_CREATE')
        statement = re.search(r'insert into .*?;',code,re.S)[0]
        self.db.execute(self.sql(statement),{f'P{self.page}_LABEL':label,'l_uuid':row})
        return row

    def draft(self,row):
        return self.db.execute('select ROW_LABEL,REVISION,'+','.join(f['column'] for f in self.c['fields'])+' from '+self.m['draft_table']+' where ROW_UUID=?',(row,)).fetchone()

    def choices(self,row,revision=0):
        params = {f'P{self.page}_ROW':row,f'P{self.page}_REV':str(revision)}
        return self.db.execute(self.sql(choice_query(self.c,self.page)),params).fetchall()

    def apply(self,row,revision,token):
        code = action_code(self.c,self.page,'FOX_ROW_APPLY')
        params = {f'P{self.page}_ROW':row,f'P{self.page}_REV':str(revision),f'P{self.page}_CHOICE':token}
        # Execute the actual emitted owning-row SELECT, omitting Oracle lock
        # syntax. Tests of Oracle FOR UPDATE itself belong to the target gate.
        lock = re.search(r'select REVISION into l_revision (.*?) for update nowait;',code,re.S)[1]
        current = self.db.execute(self.sql('select REVISION '+lock),params).fetchall()
        if len(current)!=1 or current[0][0]!=revision:
            return False
        lookup = re.search(r'select (q\..*?) into (l_return1.*?) from (.*?) where q.FOX_CHOICE=:P'+str(self.page)+'_CHOICE;',code,re.S)
        rows = self.db.execute(self.sql('select '+lookup[1]+' from '+lookup[3]+f' where q.FOX_CHOICE=:P{self.page}_CHOICE'),params).fetchall()
        if len(rows)!=1:
            return False
        params.update({'l_return'+str(i):value for i,value in enumerate(rows[0],1)})
        for condition in re.findall(r'if (nvl\(lengthb\(l_return.*?) then',code):
            if self.db.execute(self.sql('select case when '+condition+' then 1 else 0 end'),params).fetchone()[0]:
                return False
        if not self.typed_boundary(code,params):
            return False
        statement, = re.findall(r'update FOX_RD_.*?;',code,re.S)
        return self.db.execute(self.sql(statement),params).rowcount==1

    def typed_boundary(self, code, params):
        """Model PL/SQL branch/exception control, executing emitted SQL."""
        self.last_error = None
        prior = re.search(r'select (F\d+) into l_prior_caller (.*?);',code,re.S)
        if not prior:
            return True
        params['l_prior_caller'] = self.db.execute(self.sql('select '+prior[1]+' '+prior[2]),params).fetchone()[0]
        comparison = re.search(r'select (case when .*?) into l_caller_unchanged from dual;',code,re.S)[1]
        same = self.db.execute(self.sql('select '+comparison),params).fetchone()[0]
        params['l_caller_unchanged'] = same
        lookup = re.search(r'select ([A-Z0-9_$#,]+) into (l_typed1.*?) from (.*?);',code,re.S)
        if not same:
            if lookup is None:
                self.last_error = 'unresolved'
                return False
            rows = self.db.execute(self.sql('select '+lookup[1]+' from '+lookup[3]),params).fetchall()
            if len(rows) != 1:
                self.last_error = 'no_data_found' if not rows else 'too_many_rows'
                return False
            params.update({'l_typed'+str(i):value for i,value in enumerate(rows[0],1)})
            for condition in re.findall(r'if (nvl\(lengthb\(l_typed.*?) then',code):
                if self.db.execute(self.sql('select case when '+condition+' then 1 else 0 end'),params).fetchone()[0]:
                    self.last_error = 'constraint'
                    return False
        elif lookup:
            # Oracle local variables are null before assignment.
            params.update({name:None for name in re.findall(r'l_typed\d+',lookup[2])})
        return True

    def typed_keep(self,row,revision,label,value):
        code = action_code(self.c,self.page,'FOX_ROW_KEEP')
        params = {f'P{self.page}_ROW':row,f'P{self.page}_REV':str(revision),
                  f'P{self.page}_LABEL':label,f'P{self.page}_F1':value or None}
        lock = re.search(r'select REVISION into l_revision (.*?) for update nowait;',code,re.S)[1]
        current = self.db.execute(self.sql('select REVISION '+lock),params).fetchall()
        if len(current)!=1 or current[0][0]!=revision:
            return False
        if not self.typed_boundary(code,params):
            return False
        statement, = re.findall(r'update FOX_RD_.*?;',code,re.S)
        return self.db.execute(self.sql(statement),params).rowcount==1

    def keep(self,row,revision,label,value):
        code = action_code(self.c,self.page,'FOX_ROW_KEEP')
        statement, = re.findall(r'update FOX_RD_.*?;',code,re.S)
        return self.db.execute(self.sql(statement),{f'P{self.page}_ROW':row,f'P{self.page}_REV':str(revision),
            f'P{self.page}_LABEL':label,f'P{self.page}_F1':value}).rowcount==1

    def can_open_chooser(self,row,revision,label,value):
        code = action_code(self.c,self.page,'FOX_ROW_CHOOSE')
        check = re.search(r'select count\(\*\) into l_count (.*?);',code,re.S)[1]
        return self.db.execute(self.sql('select count(*) '+check),{f'P{self.page}_ROW':row,
            f'P{self.page}_REV':str(revision),f'P{self.page}_LABEL':label,f'P{self.page}_F1':value}).fetchone()[0]==1


@pytest.mark.parametrize('renamed',[False,True])
def test_emitted_sql_active_filter_all_mappings_independent_rows_change_repeat_and_cancel(renamed):
    b = EmittedSqlBoundary(renamed)
    one,two = b.create('First draft'),b.create('Sibling draft')
    b.seed([('A','NORTH','SOUTH','1'),('B','EAST','WEST','1'),('HIDDEN','X','Y','0')])
    first,second = b.choices(one)
    assert len(first)==4 and first[:3]==('A','NORTH','SOUTH')
    assert b.apply(one,0,first[-1])
    assert b.draft(one)==('First draft',1,'A','NORTH','SOUTH')
    assert b.draft(two)==('Sibling draft',0,None,None,None)
    assert not b.apply(one,0,first[-1]) # one-use revision, including repeat
    assert not b.apply(two,0,second[-1]) # token belongs to first row
    # Opening and cancelling use no DML/revision write.
    before = b.draft(one)
    assert b.can_open_chooser(one,1,'First draft','A')
    b.choices(one,1)
    assert b.draft(one)==before
    assert not b.can_open_chooser(one,1,'Unsaved label','A')
    assert not b.can_open_chooser(one,1,'First draft','UNSAVED')
    token = b.choices(one,1)[1][-1]
    assert b.apply(one,1,token)
    assert b.draft(one)==('First draft',2,'B','EAST','WEST')
    token = b.choices(one,2)[1][-1]
    assert b.apply(one,2,token) # explicit repeat applies a fresh complete choice
    assert b.draft(one)==('First draft',3,'B','EAST','WEST')
    assert b.keep(two,0,'Sibling changed','MANUAL')
    assert b.draft(two)==('Sibling changed',1,'MANUAL',None,None)
    assert b.draft(one)==('First draft',3,'B','EAST','WEST')


@pytest.mark.parametrize('changed_column',[0,1,2,3])
def test_changed_or_inactive_catalog_choice_is_stale_before_any_assignment(changed_column):
    b = EmittedSqlBoundary()
    row = b.create('Draft')
    b.seed([('A','NORTH','SOUTH','1')])
    token = b.choices(row)[0][-1]
    columns = [c['name'] for c in b.c['columns']]+[b.c['active_predicate']['left']['parts'][-1]]
    b.db.execute('update '+b.m['catalog_table']+' set '+columns[changed_column]+'=?',('0' if changed_column==3 else 'DIFFERENT',))
    assert not b.apply(row,0,token)
    assert b.draft(row)==('Draft',0,None,None,None)


def test_duplicate_complete_choice_and_constraint_violation_leave_every_target_unchanged():
    b = EmittedSqlBoundary()
    row = b.create('Draft')
    choice = ('A','NORTH','SOUTH','1')
    b.seed([choice,choice])
    choices = b.choices(row)
    assert len(choices)==2 and choices[0][-1]==choices[1][-1]
    assert not b.apply(row,0,choices[0][-1])
    assert b.draft(row)==('Draft',0,None,None,None)
    b.db.execute('delete from '+b.m['catalog_table'])
    # SQLite does not impose Oracle VARCHAR2 lengths, so exercise the actual
    # emitted source-field predicates before the emitted UPDATE.
    b.seed([('A','界'*4,'SOUTH','1')])
    assert not b.apply(row,0,b.choices(row)[0][-1])
    assert b.draft(row)==('Draft',0,None,None,None)
    b.db.execute('delete from '+b.m['catalog_table'])
    b.seed([(None,'NORTH','SOUTH','1')])
    assert not b.apply(row,0,b.choices(row)[0][-1])
    assert b.draft(row)==('Draft',0,None,None,None)


@pytest.mark.parametrize('key,value',[('APP_ID','43'),('APP_SESSION','OTHER'),('APP_USER','OTHER'),('APP_USER','NOBODY'),('APP_USER',None)])
def test_wrong_app_session_or_authenticated_owner_never_sees_or_mutates_draft(key,value):
    b = EmittedSqlBoundary()
    row = b.create('Draft')
    b.seed([('A','NORTH','SOUTH','1')])
    token = b.choices(row)[0][-1]
    b.context[key]=value
    assert not b.choices(row)
    assert not b.apply(row,0,token)
    assert b.draft(row)==('Draft',0,None,None,None)


def test_expired_draft_is_not_selectable_and_token_never_revives_it():
    b = EmittedSqlBoundary()
    row = b.create('Draft')
    b.seed([('A','NORTH','SOUTH','1')])
    token = b.choices(row)[0][-1]
    b.clock += 2
    assert not b.choices(row) and not b.apply(row,0,token)
    assert b.draft(row)==('Draft',0,None,None,None)


def test_supporting_catalog_starts_empty_and_never_seeds_customer_choices_or_source_tables():
    c = contract()
    result = render_row_lookup(c,7800)
    ddl = result['supporting_sql'].decode()
    assert ddl.lower().count('create table ')==2
    assert not re.search(r'\b(?:insert|drop|truncate|commit)\b',ddl,re.I)
    assert c['source_table'] not in ddl and c['caller_source_table'] not in ddl
    assert result['metadata']['catalog_columns']==c['columns']
    assert 'fixture capacity' in ddl and '4000 bytes' in ddl
    assert not EmittedSqlBoundary().choices('A'*32)


def test_optional_project_local_original_contract_emits_and_executes_generic_choices():
    """A locally compiled contract supplies identities; no original data is seeded."""
    value = os.environ.get('ROW_LOOKUP_NATIVE_CONTRACT')
    if not value:
        pytest.skip('Set ROW_LOOKUP_NATIVE_CONTRACT to the private freshly compiled source contract.')
    c = json.loads(Path(value).read_text(encoding='utf-8'))
    if isinstance(c,list):
        c, = c
    b = EmittedSqlBoundary(compiled_contract=c)
    first,second = b.create('First disposable draft'),b.create('Second disposable draft')
    b.seed([('PATH_A','SITE_A','SITE_B',c['active_predicate']['right']['value']),
            ('PATH_B','SITE_C','SITE_D','0')])
    choices = b.choices(first)
    assert len(choices)==1 and choices[0][:3]==('PATH_A','SITE_A','SITE_B')
    assert b.apply(first,0,choices[0][-1])
    assert b.draft(first)==('First disposable draft',1,'PATH_A','SITE_A','SITE_B')
    assert b.draft(second)==('Second disposable draft',0,None,None,None)
    result = render_row_lookup(c,7800)
    assert result == render_row_lookup(c,7800)
    assert len([f for f in c['returns'] if f['display_only']])==2


def typed_contract(renamed=False, body=TYPED_BODY):
    raw = typed_source(body)
    if renamed:
        for a,b in [(b'LINES',b'POSITIONS'),(b'VIA',b'PATH'),(b'NETWORK',b'GRAPH'),
                    (b'CODE',b'IDENTITY'),(b'START_AT',b'LEFT_END'),(b'END_AT',b'RIGHT_END'),
                    (b'DEPARTURE',b'LEFT_NODE'),(b'ARRIVAL',b'RIGHT_NODE')]:
            raw = raw.replace(a,b)
    c, = compile_row_lookups(*prepare(raw))
    return c


@pytest.mark.parametrize('renamed',[False,True])
def test_typed_keep_exact_source_lookup_changes_all_companions_only_for_changed_caller(renamed):
    b = EmittedSqlBoundary(compiled_contract=typed_contract(renamed))
    first,second = b.create('First'),b.create('Other')
    b.seed([('A','NORTH','SOUTH','1'),('INACTIVE','EAST','WEST','0')])
    assert b.typed_keep(first,0,'First','A')
    assert b.draft(first)==('First',1,'A','NORTH','SOUTH')
    assert b.draft(second)==('Other',0,None,None,None)
    # Changing the source catalog does not rerun an unchanged field event.
    b.db.execute('delete from '+b.m['catalog_table'])
    assert b.typed_keep(first,1,'Label only','A')
    assert b.draft(first)==('Label only',2,'A','NORTH','SOUTH')
    b.seed([('INACTIVE','EAST','WEST','0')])
    assert not b.choices(first,2) # chooser still has its active predicate
    assert b.typed_keep(first,2,'Typed inactive','INACTIVE')
    assert b.draft(first)==('Typed inactive',3,'INACTIVE','EAST','WEST')
    assert not b.typed_keep(first,2,'Stale','INACTIVE')
    assert b.draft(first)==('Typed inactive',3,'INACTIVE','EAST','WEST')


@pytest.mark.parametrize('bad',['MISSING',None,'','a','A '])
def test_typed_missing_null_case_and_space_mismatch_preserve_prior_values_and_revision(bad):
    b = EmittedSqlBoundary(compiled_contract=typed_contract())
    row = b.create('Draft')
    b.seed([('A','NORTH','SOUTH','1')])
    assert b.typed_keep(row,0,'Draft','A')
    before = b.draft(row)
    assert not b.typed_keep(row,1,'Must rollback',bad)
    assert b.last_error == 'no_data_found' and b.draft(row)==before
    code = action_code(b.c,b.page,'FOX_ROW_KEEP')
    assert 'raise_application_error(-20031,'+_source_message('Invalid routing')+')' in code
    assert 'when others then rollback to fox_row_lookup' in code


def test_typed_ambiguous_even_inactive_match_and_changed_catalog_are_not_chooser_semantics():
    b = EmittedSqlBoundary(compiled_contract=typed_contract())
    row = b.create('Draft')
    b.seed([('A','NORTH','SOUTH','1'),('A','EAST','WEST','0')])
    choices = b.choices(row)
    assert len(choices)==1
    assert not b.typed_keep(row,0,'Draft','A') and b.last_error=='too_many_rows'
    assert not b.apply(row,0,choices[0][-1]) and b.last_error=='too_many_rows'
    assert b.draft(row)==('Draft',0,None,None,None)
    b.db.execute('delete from '+b.m['catalog_table'])
    b.seed([('A','CURRENT','TARGET','1')])
    assert not b.apply(row,0,choices[0][-1]) # old chooser full-value token
    assert b.typed_keep(row,0,'Draft','A')
    assert b.draft(row)==('Draft',1,'A','CURRENT','TARGET')


def test_typed_apply_cannot_skip_event_but_unchanged_caller_preserves_normal_lov_returns():
    b = EmittedSqlBoundary(compiled_contract=typed_contract())
    row = b.create('Draft')
    b.seed([('A','NORTH','SOUTH','1')])
    assert b.apply(row,0,b.choices(row)[0][-1])
    assert b.draft(row)==('Draft',1,'A','NORTH','SOUTH')
    b.db.execute('update '+b.m['catalog_table']+' set DEPARTURE=\'CHANGED\'')
    # Same caller value does not invoke source POST-CHANGE again. Ordinary
    # complete LOV mapping still applies the newly selected companion values.
    assert b.apply(row,1,b.choices(row,1)[0][-1])
    assert b.draft(row)==('Draft',2,'A','CHANGED','SOUTH')


@pytest.mark.parametrize('key,value',[('APP_ID','43'),('APP_SESSION','OTHER'),('APP_USER','OTHER'),('APP_USER','NOBODY'),('APP_USER',None)])
def test_typed_wrong_owner_or_session_cannot_run_event_or_update(key,value):
    b = EmittedSqlBoundary(compiled_contract=typed_contract())
    row = b.create('Draft')
    b.seed([('A','NORTH','SOUTH','1')])
    b.context[key]=value
    assert not b.typed_keep(row,0,'Changed','A')
    assert b.draft(row)==('Draft',0,None,None,None)


def test_typed_receipt_binds_source_unit_pages_and_adaptation_without_runtime_claim():
    c = typed_contract()
    result = render_row_lookup(c,7800)
    receipt, = result['metadata']['typed_lookup_receipts']
    assert receipt['source_unit_id']==c['typed_lookup']['source_unit_id']
    assert receipt['source_unit_sha256']==c['typed_lookup']['source_unit_sha256']
    assert receipt['native_event_wired'] and receipt['changed_input_only']
    assert receipt['page_bindings']==[
        {'page_id':7800,'page_file':result['pages'][0]['page_file'],'request':'FOX_ROW_KEEP'},
        {'page_id':7801,'page_file':result['pages'][1]['page_file'],'request':'FOX_ROW_APPLY'}]
    assert receipt['adaptation'] and receipt['unresolved_semantics']
    assert not any(receipt[k] for k in ['source_query_executed','oracle_compiled','runtime_verified','business_accepted'])
    assert result['metadata']['source_post_change_wired'] and not result['metadata']['source_post_change_executed']
    code = action_code(c,7800,'FOX_ROW_KEEP')
    lookup = re.search(r'select .*? into l_typed1.*?;',code)[0]
    assert 'STATE' not in lookup and c['source_table'] not in lookup
    assert code.index('for update nowait') < code.index('into l_prior_caller') < code.index('into l_typed1') < code.index('update FOX_RD_')


def test_nonmatching_body_mutation_is_gated_on_keep_and_apply():
    c = typed_contract(body=TYPED_BODY.replace('FROM NETWORK','FROM DIFFERENT_TABLE'))
    b = EmittedSqlBoundary(compiled_contract=c)
    row = b.create('Draft')
    b.seed([('A','NORTH','SOUTH','1')])
    assert not b.typed_keep(row,0,'Draft','A') and b.last_error=='unresolved'
    assert not b.apply(row,0,b.choices(row)[0][-1]) and b.last_error=='unresolved'
    assert b.draft(row)==('Draft',0,None,None,None)


def test_typed_message_literal_is_not_interpreted_as_code_or_binding():
    message = "Invalid ''route'' & :value <tag>"
    c = typed_contract(body=TYPED_BODY.replace('Invalid routing',message))
    code = action_code(c,7800,'FOX_ROW_KEEP')
    expression = re.search(r"apex_escape.html\(unistr\('([^']+)'\)\)",code)[1]
    decoded = bytes.fromhex(expression.replace('\\','')).decode('utf-16-be')
    assert decoded==message.replace("''", "'")
    assert '<tag>' not in code and '& :value' not in code
    assert render_row_lookup(c,7800)['metadata']['typed_lookup_receipts'][0]['no_data_message']==message.replace("''", "'")


def test_typed_wrong_row_token_expiry_and_companion_constraints_preserve_every_row():
    b = EmittedSqlBoundary(compiled_contract=typed_contract())
    first,second = b.create('First'),b.create('Second')
    b.seed([('A','NORTH','SOUTH','1')])
    token = b.choices(first)[0][-1]
    assert not b.apply(second,0,token)
    assert b.draft(first)==('First',0,None,None,None)
    assert b.draft(second)==('Second',0,None,None,None)
    b.db.execute('update '+b.m['catalog_table']+' set DEPARTURE=?',('界'*4,))
    assert not b.typed_keep(first,0,'Changed','A') and b.last_error=='constraint'
    assert b.draft(first)==('First',0,None,None,None)
    b.clock += 2
    assert not b.typed_keep(first,0,'Expired','A')
    assert b.draft(first)==('First',0,None,None,None)


def test_unchanged_null_caller_keeps_label_without_lookup_or_fabricated_companions():
    b = EmittedSqlBoundary(compiled_contract=typed_contract())
    row = b.create('Before')
    assert b.typed_keep(row,0,'After',None)
    assert b.draft(row)==('After',1,None,None,None)


@pytest.mark.parametrize('mutation',['table','key','target','message','proof','filter'])
def test_typed_renderer_rejects_inconsistent_contract(mutation):
    c = typed_contract()
    t = c['typed_lookup']
    if mutation=='table': t['source_table']='UNRELATED'
    elif mutation=='key': t['key_column']='OTHER'
    elif mutation=='target': t['assignments'][0]['field']=deepcopy(c['caller'])
    elif mutation=='message': t['no_data_message']='bad\nmessage'
    elif mutation=='proof': t['source_unit_sha256']='invented'
    else: t['active_filter_applied']=True
    with pytest.raises(ValueError,match='ROW_LOOKUP_NATIVE_TYPED_'):
        render_row_lookup(c,7800)


@pytest.mark.parametrize('action',['FOX_ROW_KEEP','FOX_ROW_APPLY'])
def test_changed_input_comparison_keeps_sql_only_decode_out_of_procedural_if(action):
    code = action_code(typed_contract(),7800,action)
    assert re.search(r'select case when decode\(utl_raw.cast_to_raw\(l_prior_caller\).*? into l_caller_unchanged from dual;',code)
    assert 'if l_caller_unchanged=0 then' in code
    assert not re.search(r'\bif\s+(?:not\s*\()?decode\(',code,re.I)
    assert 'case when l_caller_unchanged=1 then' in code
