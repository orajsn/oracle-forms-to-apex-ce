"""Generated source boundary tests; these do not claim Oracle/APEX execution."""
from copy import deepcopy
import json
import hashlib
import re
import sqlite3
from xml.etree import ElementTree as ET

import pytest

from forms2apex import native_blueprint, native_record_groups as groups
from fox.forms_lov_return import apply_lov_returns, _choice_query, _process_code
from fox.forms_native_plan import build_native_prototype_plan, POLICY_ID
from fox.forms_understanding_packet import _build
from fox.xml_mapping import _blueprint


SOURCE = b'''<FormModule Name="DISPATCH_CHOICES">
<Block Name="HEADER" DatabaseBlock="true">
 <Item Name="SOURCE_DEPOT" ItemType="Display Item" DataType="Char" DatabaseItem="true" MaximumLength="10" DataLengthSemantics="BYTE"/>
 <Item Name="VIA" ItemType="Text Item" DataType="Char" DatabaseItem="true" MaximumLength="10" DataLengthSemantics="BYTE" LovName="VIA_CHOICES" ValidateFromList="true"/>
 <Item Name="CITY" ItemType="Display Item" DataType="Char" DatabaseItem="false" MaximumLength="40" DataLengthSemantics="CHAR"/>
 <Item Name="APPROVED" ItemType="Text Item" DataType="Char" DatabaseItem="true" MaximumLength="1" DataLengthSemantics="BYTE"/>
</Block>
<Trigger Name="WHEN-NEW-RECORD-INSTANCE" TriggerText="CHECK_ACCESS;"/>
<ProgramUnit Name="CHECK_ACCESS" ProgramUnitType="Procedure" ProgramUnitText="PROCEDURE CHECK_ACCESS IS BEGIN SET_ITEM_PROPERTY('HEADER.VIA', UPDATE_ALLOWED, PROPERTY_TRUE); IF :HEADER.APPROVED = 'Y' THEN SET_ITEM_PROPERTY('HEADER.VIA', UPDATE_ALLOWED, PROPERTY_FALSE); END IF; END;"/>
<LOV Name="VIA_CHOICES" RecordGroupName="AVAILABLE_DEPOTS">
 <LOVColumnMapping Name="ROUTE_DEST" ReturnItem="HEADER.VIA"/>
 <LOVColumnMapping Name="CITY_NAME" ReturnItem="HEADER.CITY"/>
</LOV>
<RecordGroup Name="AVAILABLE_DEPOTS" RecordGroupType="Query" RecordGroupQuery="SELECT ROUTE_DEST, CITY_NAME FROM SOURCE_ROUTES,SOURCE_CITIES WHERE ROUTE_ORIGIN = :SOURCE_DEPOT AND ROUTE_DEST = CITY_CODE AND ROUTE_STATUS = '1' AND CITY_EXCHANGE = 'Y' ORDER BY ROUTE_DEST">
 <RecordGroupColumn Name="ROUTE_DEST" ColumnDataType="Character" MaximumLength="10"/>
 <RecordGroupColumn Name="CITY_NAME" ColumnDataType="Character" MaximumLength="40"/>
</RecordGroup>
</FormModule>'''


def prepare(raw=SOURCE, *, renamed=False):
    if renamed:
        for old,new in ((b'HEADER',b'ORDER_TOP'),(b'VIA_CHOICES',b'TOWN_PICK'),(b'AVAILABLE_DEPOTS',b'TOWN_ROWS'),
                        (b'SOURCE_DEPOT',b'ORIGIN_CODE'),(b'VIA',b'VIA_CODE'),(b'CITY_NAME',b'TOWN_NAME'),
                        (b'CITY',b'TOWN'),(b'APPROVED',b'LOCKED')):
            raw = raw.replace(old,new)
    docs = [('dispatch.xml',raw)]
    packet,chunks = _build(docs)
    spec = build_native_prototype_plan(docs,_blueprint(packet),project_id='lov-test',project_name='Choice draft',
                                       approved_policy_id=POLICY_ID)['rendering_spec']
    files = {k:v.encode() for k,v in native_blueprint.render_native_blueprint(spec).items()}
    trace = native_blueprint.prototype_trace(spec)
    objects = {o['id']:o for entry in packet['sources'] for o in entry['facts']['objects']}
    for block in trace['blocks']:
        block['source_module_id'] = objects[block['source_block_id']]['module_id']
    files,receipt = groups.apply_record_groups(docs,packet,chunks,trace,files)
    files['fox-package/record-group-receipt.json'] = groups._json(receipt)
    files['fox-package/sources/dispatch.xml'] = raw
    files['fox-package/supporting-schema.sql'] = native_blueprint.render_prototype_schema(spec).encode()
    return docs,packet,chunks,trace,files


@pytest.mark.parametrize('renamed',[False,True])
def test_source_caller_receives_all_returns_in_one_selected_draft(renamed):
    args = prepare(renamed=renamed)
    before = deepcopy(args)
    files,receipt = apply_lov_returns(*args)
    assert args == before and (files,receipt) == apply_lov_returns(*args)
    assert not receipt['gaps']
    op, = receipt['generated_operations']
    assert receipt['converted_code_unit_count'] == 0 and op['query_already_counted']
    assert op['source_caller_item_id'] in {f['source_item_id'] for f in op['return_mappings']}
    assert len(op['return_mappings']) == 2 and any(f['display_only'] for f in op['return_mappings'])
    text = files[op['page_file']].decode()
    assert 'type: textField' in text and 'plsqlExpression: "true"' in text
    assert 'Select choice' in text and 'label: Apply choice' in text
    assert 'source_block_id' in op['contract']['block']
    assert 'LOV field selection and return remain unimplemented.' not in files[json.loads(files['fox-package/record-group-receipt.json'])['generated_operations'][0]['page_file']].decode()
    assert files['fox-package/record-group-receipt.json'] == before[-1]['fox-package/record-group-receipt.json']
    assert all(not receipt[k] for k in ('original_reads_enabled','customer_table_writes','synthetic_table_writes','oracle_compiled','runtime_verified','business_accepted'))


def generated(args=None):
    args = args or prepare()
    files,receipt = apply_lov_returns(*args)
    op, = receipt['generated_operations']
    group, = json.loads(args[-1]['fox-package/record-group-receipt.json'])['generated_operations']
    return group,op,files,args


def test_apply_rechecks_locked_policy_identity_revision_baseline_readiness_and_complete_choice():
    group,op,_,_ = generated()
    page,c = op['page_id'],op['contract']
    code = _process_code(group,c,page,apply=True)
    assert code.index('for update nowait') < code.index('if nvl(l_allowed,0)<>1') < code.index("Source interface is not ready")
    assert code.index('l_revision<>to_number(') < code.index('select choices.') < code.index('apex_collection.update_member_attribute')
    assert "c050='LOV_ROW'" in code and 'n001=:P' in code and 'c021' in code
    assert 'utl_raw.cast_to_raw' in code and 'nvl(lengthb(l_return1),0)>10' in code
    assert 'nvl(length(l_return2),0)>40' in code
    assert 'when too_many_rows' in code and 'rollback to fox_lov_return' in code
    assert not re.search(r'\b(insert into|update FOX_NATIVE_|delete from|commit\s*;)',code,re.I)
    assert ':P'+str(page)+'_F1' not in code[:code.index('apex_collection.update_member_attribute')]
    query = _choice_query(group,c,page)
    assert "CASE WHEN q.ROUTE_DEST IS NULL THEN 'C:N'" in query
    assert "CASE WHEN q.CITY_NAME IS NULL THEN 'C:N'" in query
    assert 'JSON_ARRAY' not in query and 'SELECT n002 FROM apex_collections' in query
    assert 'ORDER BY' not in query
    assert _choice_query(group,c,page,ordered=True).endswith('ORDER BY q.ROUTE_DEST')


@pytest.mark.parametrize('apply',[False,True])
def test_emitted_load_and_apply_derive_namespace_in_sql_after_locked_row_read(apply):
    group,op,files,_=generated()
    code=_process_code(group,op['contract'],op['page_id'],apply=apply)
    namespace=re.search(r"select ('FOX_L_.*?into l_name from dual;)",code,re.I)
    assert namespace is not None
    assert code.index('for update nowait;') < code.index('if nvl(l_allowed,0)<>1') < namespace.start()
    assert 'l_base1' in namespace[1] and "STANDARD_HASH(l_base1,'SHA256')" in namespace[1]
    assert '(SELECT' not in namespace[1].upper()
    assert 'l_name:=' not in code
    # Inspect actual emitted native page fences too, not only a helper string.
    page=files[op['page_file']].decode()
    emitted=re.findall(r'```plsql\s+(.*?)\s+```',page,re.S)
    assert len(emitted)==2
    for block in emitted:
        assignments=re.findall(r'\b\w+\s*:=\s*([^;]*);',block)
        assert all(not re.search(r'\bSELECT\b',value,re.I) for value in assignments)


def test_reopen_retains_returns_and_never_resets_existing_collection():
    group,op,_,_ = generated()
    code = _process_code(group,op['contract'],op['page_id'],apply=False)
    assert 'if not apex_collection.collection_exists(l_name)then' in code
    assert 'create_or_truncate_collection' not in code and 'delete_collection' not in code
    assert "'||to_char(:P" in code
    assert 'p_c001=>l_base1,p_c021=>l_base1' in code


@pytest.mark.parametrize('attribute,value,reason',[
    ('UpdateAllowed','false','EXISTING_ROW_UPDATE_DISABLED'),
    ('Enabled','false','EXISTING_ROW_UPDATE_DISABLED'),
    ('ValidateFromList','false','VALIDATE_FROM_LIST_REQUIRED'),
    ('LovName','','DECLARED_RETURNS_WITHOUT_SOURCE_CALLER'),
    ('DataType','Number','CHARACTER_DRAFT_FIELD_REQUIRED'),
    ('DataLengthSemantics','','EXPLICIT_FIELD_LENGTH_REQUIRED'),
])
def test_source_permissions_missing_callers_and_semantic_constraints_are_not_invented(attribute,value,reason):
    root = ET.fromstring(SOURCE)
    next(i for i in root.iter('Item') if i.get('Name')=='VIA').set(attribute,value)
    args = prepare(ET.tostring(root))
    files,receipt = apply_lov_returns(*args)
    assert not receipt['generated_operations'] and reason in receipt['gaps'][0]['reason']
    assert files == args[-1] and receipt['gaps'][0]['query_reporting_retained']


def test_declared_return_type_mismatch_and_ambiguous_mapping_are_gaps():
    root = ET.fromstring(SOURCE)
    next(root.iter('RecordGroupColumn')).set('ColumnDataType','Number')
    _,receipt = apply_lov_returns(*prepare(ET.tostring(root)))
    assert 'RETURN_SEMANTIC_TYPE_MISMATCH' in receipt['gaps'][0]['reason']
    root = ET.fromstring(SOURCE)
    lov = next(root.iter('LOV'))
    ET.SubElement(lov,'LOVColumnMapping',Name='CITY_NAME',ReturnItem='HEADER.CITY')
    _,receipt = apply_lov_returns(*prepare(ET.tostring(root)))
    assert 'RETURN_TARGET_NOT_UNIQUE' in receipt['gaps'][0]['reason']


@pytest.mark.parametrize('tamper',['schema','trace','source','group','gate'])
def test_rehashed_or_submitted_proofs_do_not_grant_authority(tamper):
    args = list(prepare())
    files = args[-1]
    if tamper=='schema': files['fox-package/supporting-schema.sql'] += b'\n-- changed'
    if tamper=='trace': args[3]['blocks'][0]['items'][0]['column']='OTHER'
    if tamper=='source': files['fox-package/sources/dispatch.xml'] += b' '
    if tamper=='group':
        receipt=json.loads(files['fox-package/record-group-receipt.json'])
        receipt['generated_operations'][0]['query']['predicates'].pop()
        files['fox-package/record-group-receipt.json']=groups._json(receipt)
    if tamper=='gate':
        files['shared-components/app-items.apx']=files['shared-components/app-items.apx'].replace(b'restricted',b'unrestricted')
    with pytest.raises(ValueError,match='LOV_RETURN_'):
        apply_lov_returns(*args)


def test_generated_eligibility_sql_preserves_source_filter_and_duplicate_rows():
    group,op,_,_ = generated()
    # Execute the deterministic AST's emitted eligibility SELECT against real
    # SQLite tables. APEX collections/locks and Oracle hash are separate gates.
    query=deepcopy(group['query']);query['order']=[]
    sql=groups.render_query(query,{('SOURCE_DEPOT',):':origin'})
    db=sqlite3.connect(':memory:')
    db.executescript('CREATE TABLE SOURCE_ROUTES(ROUTE_DEST TEXT,ROUTE_ORIGIN TEXT,ROUTE_STATUS TEXT);'
                     'CREATE TABLE SOURCE_CITIES(CITY_CODE TEXT,CITY_NAME TEXT,CITY_EXCHANGE TEXT);')
    db.executemany('INSERT INTO SOURCE_ROUTES VALUES(?,?,?)',[('D','A','1'),('X','B','1'),('N','A','0')])
    db.executemany('INSERT INTO SOURCE_CITIES VALUES(?,?,?)',[('D','Town','Y'),('X','Other','Y'),('N','No','Y')])
    assert db.execute(sql,{'origin':'A'}).fetchall()==[('D','Town')]
    assert db.execute(sql,{'origin':None}).fetchall()==[]
    db.execute("INSERT INTO SOURCE_ROUTES VALUES('D','A','1')")
    assert db.execute(sql,{'origin':'A'}).fetchall()==[('D','Town'),('D','Town')]
    assert 'distinct' not in sql.lower() and 'fetch first' not in sql.lower()


class ChoiceSqlBoundary:
    """Execute emitted choice/policy SQL with SQLite compatibility functions.

    This models the PL/SQL lock/revision/transaction boundary explicitly. It
    does not prove Oracle locks, APEX item protection, or Oracle NLS conversion.
    """
    def __init__(self):
        self.group,self.op,self.files,_=generated()
        self.contract=self.op['contract'];self.page=self.op['page_id']
        self.db=sqlite3.connect(':memory:')
        self.ready='Y';self.user='TESTER'
        self.db.create_function('V',1,lambda key:self.user if key=='APP_USER' else self.ready)
        self.db.create_function('nvl',2,lambda a,b:b if a is None else a)
        self.db.create_function('to_char',-1,lambda *a:str(a[0]))
        self.db.create_function('STANDARD_HASH',2,lambda a,b:hashlib.sha256(a.encode()).digest())
        self.db.create_function('RAWTOHEX',1,lambda a:a.hex().upper())
        schema=self.files['fox-package/supporting-schema.sql'].decode().replace('NUMBER GENERATED BY DEFAULT ON NULL AS IDENTITY PRIMARY KEY','INTEGER PRIMARY KEY')
        self.db.executescript(schema)
        self.db.execute('CREATE TABLE apex_collections(collection_name TEXT,seq_id NUMBER,n001 NUMBER,n002 NUMBER,c050 TEXT,'+
                        ','.join(f'c{i:03d} TEXT' for i in list(range(1,19))+list(range(21,39)))+')')
        self.db.executescript("CREATE TABLE SOURCE_ROUTES(ROUTE_DEST TEXT,ROUTE_ORIGIN TEXT,ROUTE_STATUS TEXT);"
                              "CREATE TABLE SOURCE_CITIES(CITY_CODE TEXT,CITY_NAME TEXT,CITY_EXCHANGE TEXT);"
                              "INSERT INTO SOURCE_ROUTES VALUES('D','A','1');"
                              "INSERT INTO SOURCE_CITIES VALUES('D','Town','Y');")
        self.names={}
        self.policy_column=next(f['column'] for f in self.contract['block']['items'] if f['source_name']=='APPROVED')
        self.table=self.contract['block']['table_name']
        for rid in (1,2):
            fields=self.contract['fields']
            self.db.execute('INSERT INTO '+self.table+'(FOX_ROW_ID,'+','.join(f['column'] for f in fields)+','+self.policy_column+') VALUES('+','.join('?' for _ in range(len(fields)+2))+')',
                            (rid,'A',None,None,None))
            self.reopen(rid)
        self.query=_choice_query(self.group,self.contract,self.page)

    def reopen(self,rid=1):
        from fox.forms_lov_return import _collection_sql
        name=self.db.execute('SELECT '+_collection_sql(self.contract,self.page),{f'P{self.page}_ID0':rid}).fetchone()[0]
        if not self.db.execute('SELECT 1 FROM apex_collections WHERE collection_name=?',(name,)).fetchone():
            values=self.db.execute('SELECT '+','.join(f['column'] for f in self.contract['fields'])+' FROM '+self.table+' WHERE FOX_ROW_ID=?',(rid,)).fetchone()
            self.db.execute('INSERT INTO apex_collections(collection_name,seq_id,n001,n002,c050,c001,c002,c003,c021,c022,c023) VALUES(?,1,?,0,\'LOV_ROW\',?,?,?,?,?,?)',(name,rid,*values,*values))
        self.names[rid]=name

    def choices(self,rid=1):
        return self.db.execute(self.query,{f'P{self.page}_ID0':rid}).fetchall()

    def apply(self,token,*,rid=1,revision=0,submitted=('FORGED','FORGED')):
        # All assertions model the generated pre-mutation checks. Submitted
        # visible caller and display fields are deliberately never read.
        stored=self.db.execute('SELECT '+','.join(f['column'] for f in self.contract['fields'])+','+
            self.contract['policy_expression_sql']+' FROM '+self.table+' WHERE FOX_ROW_ID=?',(rid,)).fetchone()
        draft=self.db.execute('SELECT n002,c021,c022,c023 FROM apex_collections WHERE collection_name=?',(self.names[rid],)).fetchone()
        if self.user in (None,'NOBODY') or self.ready!='Y' or stored is None or stored[-1]!=1 or draft is None or draft[0]!=revision or tuple(draft[1:])!=tuple(stored[:-1]):
            return False
        rows=[r for r in self.choices(rid) if r[-1]==token]
        if len(rows)!=1 or any(len(v.encode())>f['max_length'] for v,f in zip(rows[0][:-1],self.contract['returns']) if v is not None):
            return False
        current=self.db.execute('SELECT c002,c003 FROM apex_collections WHERE collection_name=?',(self.names[rid],)).fetchone()
        values=rows[0][:-1]
        if tuple(values)!=current:
            self.db.execute('UPDATE apex_collections SET c002=?,c003=?,n002=n002+1 WHERE collection_name=?',(*values,self.names[rid]))
        return True

    def draft(self,rid=1):
        return self.db.execute('SELECT c001,c002,c003,n002 FROM apex_collections WHERE collection_name=?',(self.names[rid],)).fetchone()


def test_actual_choice_sql_and_modelled_apply_return_fields_preserve_owner_and_noop():
    boundary=ChoiceSqlBoundary()
    token=boundary.choices()[0][-1]
    assert boundary.apply(token,submitted=('ATTACK','WRONG'))
    assert boundary.draft()==('A','D','Town',1)
    assert boundary.draft(2)==('A',None,None,0)
    assert not boundary.apply(token,revision=1)  # old revision token
    new_token=boundary.choices()[0][-1]
    assert boundary.apply(new_token,revision=1) and boundary.draft()==('A','D','Town',1)
    assert not boundary.apply(new_token,rid=2)  # choice is bound to selected row


@pytest.mark.parametrize('change',['disabled','anonymous','approved','input','duplicate','missing','oversize'])
def test_actual_choice_sql_and_modelled_apply_deny_without_any_draft_change(change):
    b=ChoiceSqlBoundary();token=b.choices()[0][-1];before=b.draft()
    if change=='disabled':b.ready='N'
    if change=='anonymous':b.user='NOBODY'
    if change=='approved':b.db.execute(f'UPDATE {b.table} SET {b.policy_column}=?',('Y',))
    if change=='input':b.db.execute(f"UPDATE {b.table} SET {b.contract['inputs'][0]['column']}='B'")
    if change=='duplicate':b.db.execute("INSERT INTO SOURCE_ROUTES VALUES('D','A','1')")
    if change=='missing':b.db.execute('DELETE FROM SOURCE_ROUTES')
    if change=='oversize':b.db.execute("UPDATE SOURCE_CITIES SET CITY_NAME=?",('X'*41,));token=b.choices()[0][-1]
    assert not b.apply(token) and b.draft()==before
    if change in ('disabled','anonymous'):assert b.choices()==[]


def test_choice_token_distinguishes_null_strings_framing_and_context():
    b=ChoiceSqlBoundary()
    first=b.choices()[0][-1]
    assert first!=b.choices(2)[0][-1]
    b.db.execute("UPDATE SOURCE_CITIES SET CITY_NAME=NULL")
    null=b.choices()[0][-1]
    b.db.execute("UPDATE SOURCE_CITIES SET CITY_NAME='null'")
    assert b.choices()[0][-1]!=null
    b.db.execute("UPDATE SOURCE_ROUTES SET ROUTE_DEST='AB'")
    b.db.execute("UPDATE SOURCE_CITIES SET CITY_CODE='AB',CITY_NAME='C'")
    framed=b.choices()[0][-1]
    b.db.execute("UPDATE SOURCE_ROUTES SET ROUTE_DEST='A'")
    b.db.execute("UPDATE SOURCE_CITIES SET CITY_CODE='A',CITY_NAME='BC'")
    assert b.choices()[0][-1]!=framed


def test_changed_stored_baseline_reopens_fresh_draft_and_preserves_old_return():
    b=ChoiceSqlBoundary();token=b.choices()[0][-1]
    assert b.apply(token)
    old_name=b.names[1]
    input_column=b.contract['inputs'][0]['column']
    b.db.execute(f"UPDATE {b.table} SET {input_column}='B' WHERE FOX_ROW_ID=1")
    assert b.choices()==[]  # no source lookup context until reopening
    b.reopen()
    assert b.names[1]!=old_name and b.draft()==('B',None,None,0)
    old=b.db.execute('SELECT c001,c002,c003,n002 FROM apex_collections WHERE collection_name=?',(old_name,)).fetchone()
    assert old==('A','D','Town',1)
    assert 'preserves the earlier session draft separately' in b.files[b.op['page_file']].decode()


def test_wide_character_values_hash_before_bounded_framing():
    from fox.forms_lov_return import _fingerprint
    b=ChoiceSqlBoundary()
    first='"\\\n'*1000
    second='x'*3900
    expression=_fingerprint([(':wide','VARCHAR2'),(':second','VARCHAR2'),(':none','NUMBER')])
    token=b.db.execute('SELECT '+expression,{'wide':first,'second':second,'none':None}).fetchone()[0]
    assert len(token)==64 and 'JSON_ARRAY' not in expression
    # Type markers distinguish equal textual representations.
    assert _fingerprint([(':value','VARCHAR2')])!=_fingerprint([(':value','NUMBER')])


def test_no_repeated_adaptation_and_failed_navigation_does_not_emit_half_editor():
    args=prepare();files,receipt=apply_lov_returns(*args)
    with pytest.raises(ValueError,match='ALREADY_ADAPTED'):
        apply_lov_returns(*args[:-1],files)
    args=prepare();report=args[3]['blocks'][0]['report_file'];args[-1][report]=b'wrong page\n'
    files,receipt=apply_lov_returns(*args)
    assert not receipt['generated_operations'] and files==args[-1]


def test_mixed_lovs_on_one_group_report_connected_and_pending_returns_once():
    root=ET.fromstring(SOURCE)
    lov=ET.SubElement(root,'LOV',Name='REPORT_ONLY',RecordGroupName='AVAILABLE_DEPOTS')
    ET.SubElement(lov,'LOVColumnMapping',Name='ROUTE_DEST',ReturnItem='HEADER.VIA')
    args=prepare(ET.tostring(root));files,receipt=apply_lov_returns(*args)
    assert len(receipt['generated_operations'])==1 and len(receipt['gaps'])==1
    group,=json.loads(files['fox-package/record-group-receipt.json'])['generated_operations']
    for path in (group['page_file'],group['chooser_file']):
        text=files[path].decode()
        assert '2 declared return mappings are connected' in text
        assert '1 declared return mappings remain pending' in text
        assert '3 explicit source LOV return mappings remain unimplemented' not in text
    assert 'DECLARED_RETURNS_WITHOUT_SOURCE_CALLER' in receipt['gaps'][0]['reason']


def test_unresolved_entry_policy_cannot_enable_a_caller():
    root=ET.fromstring(SOURCE)
    next(root.iter('ProgramUnit')).set('ProgramUnitText','PROCEDURE CHECK_ACCESS IS BEGIN DO_UNKNOWN_WORK; END;')
    args=prepare(ET.tostring(root));files,receipt=apply_lov_returns(*args)
    assert not receipt['generated_operations'] and files==args[-1]
    assert 'COMPLETE_ENTRY_POLICY_REQUIRED' in receipt['gaps'][0]['reason']


def test_missing_trusted_global_and_disabled_interface_have_restricted_gates():
    root=ET.fromstring(SOURCE);group=next(root.iter('RecordGroup'))
    group.set('RecordGroupQuery',group.get('RecordGroupQuery').replace(' ORDER BY',' AND ROUTE_BRANCH = :GLOBAL.BRANCH ORDER BY'))
    args=prepare(ET.tostring(root));g,op,files,_=generated(args)
    query=_choice_query(g,op['contract'],op['page_id'])
    global_item=g['global_bindings'][0]['app_item']
    assert ':'+global_item+' IS NOT NULL' in query
    code=_process_code(g,op['contract'],op['page_id'],apply=True)
    assert code.index('Trusted source input is unavailable') < code.index('select choices.')
    page=files[op['page_file']].decode()
    assert 'serverSideCondition' in page and g['readiness_item'] in page
    assert groups._app_item(global_item) in files['shared-components/app-items.apx'].decode()


def test_enriched_packet_preserves_exact_source_provenance_and_no_lov_is_a_noop():
    args=list(prepare());expected=apply_lov_returns(*args)
    args[1]['derived_target_review']={'context':'normal pipeline enrichment'}
    assert apply_lov_returns(*args)==expected
    root=ET.fromstring(SOURCE)
    root.remove(next(root.iter('LOV')));root.remove(next(root.iter('RecordGroup')))
    args=prepare(ET.tostring(root));files,receipt=apply_lov_returns(*args)
    assert files==args[-1] and not receipt['generated_operations'] and not receipt['gaps']


def test_normal_generation_entry_point_accepts_enriched_packet():
    from fox.xml_mapping import generate_xml_package, _members
    args=prepare()
    candidate,_=generate_xml_package(args[0],'lov-normal','Normal caller generation',POLICY_ID)
    files=_members(candidate)
    assert any(re.fullmatch(r'pages/p\d+-fox_lov_\d+\.apx',name) for name in files)
