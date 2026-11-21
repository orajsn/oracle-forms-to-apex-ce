"""Complete fictional events, actual disposable SQL, explicit runtime adapters.

No customer package/provider/Oracle runtime is executed or simulated as proven.
"""
from copy import deepcopy
from decimal import Decimal
import json
import sqlite3
from xml.etree import ElementTree as ET

import pytest

from fox.forms_delete_plan import (DeleteOutcome, build_delete_plan,
                                   execute_delete_model, parse_delete_source)
from test_forms_synthetic_save import source as save_source, prepare as save_prepare


MASTER = """DECLARE ONE_ROW CHAR(1); CURSOR RELATED_CUR IS
 SELECT 1 FROM PIECES C WHERE C.LOAD_REFERENCE=:LOADS.LOAD_REFERENCE;
 BEGIN OPEN RELATED_CUR; FETCH RELATED_CUR INTO ONE_ROW;
 IF (RELATED_CUR%FOUND) THEN
 MESSAGE('Matching detail prevents removal'); CLOSE RELATED_CUR;
 RAISE FORM_TRIGGER_FAILURE; END IF; CLOSE RELATED_CUR; END;"""
KEY = """IF ACME.CAN_REMOVE(:PIECE_CODE)>0 THEN
 MESSAGE('Request revision first'); MESSAGE('Request revision first');
 RAISE FORM_TRIGGER_FAILURE; ELSE DELETE_RECORD; COMMIT_FORM; END IF;"""
NOTE_KEY = """IF ACME.CAN_REMOVE_NOTE(:NOTE_CODE)>0 THEN
 MESSAGE('Request revision first'); MESSAGE('Request revision first');
 RAISE FORM_TRIGGER_FAILURE; ELSE DELETE_RECORD;
 :PIECES.CALCULATED_WEIGHT:=:TOTAL_WEIGHT; COMMIT_FORM;
 GO_BLOCK('PIECES'); NEXT_RECORD; END IF;"""
PRE = """BEGIN ACME.AUDIT_REMOVE(:PIECE_CODE,:LOADS.LOAD_REFERENCE,
 :GLOBAL.USER_CODE,'DISPATCH',:LOADS.APPROVED);
 DELETE FROM PIECE_FLAGS WHERE FLAG_LOAD=:LOAD_REFERENCE AND FLAG_PIECE=:PIECE_CODE;
 END; FORMS_DDL('COMMIT'); BEGIN DELETE FROM NOTES C
 WHERE C.NOTE_LOAD=:PIECES.LOAD_REFERENCE AND C.NOTE_PIECE=:PIECES.PIECE_CODE; END;"""
NOTE_PRE = """BEGIN ACME.AUDIT_REMOVE_NOTE(:NOTE_CODE,:LOADS.LOAD_REFERENCE,
 :GLOBAL.USER_CODE,'DISPATCH',:LOADS.APPROVED); END;"""


def source(*, renamed=False, change=None, extra=False):
    root = ET.fromstring(save_source()[0][1])
    parent, child = list(root.iter('Block'))[:2]
    parent.set('DeleteAllowed','false')
    parent.set('QueryDataSourceType','Table'); parent.set('QueryDataSourceName','LOADS')
    child.set('QueryDataSourceType','Table'); child.set('QueryDataSourceName','PIECES')
    for name in ('CALCULATED_WEIGHT',):
        ET.SubElement(child,'Item',Name=name,DatabaseItem='true',ItemType='Text Item',DataType='Number',MaximumLength='12')
    notes = ET.SubElement(root,'Block',Name='NOTES',DatabaseBlock='true',QueryDataSourceType='Table',
                          QueryDataSourceName='NOTES',DeleteAllowed='true')
    for name in ('NOTE_LOAD','NOTE_PIECE','NOTE_CODE'):
        ET.SubElement(notes,'Item',Name=name,DatabaseItem='true',ItemType='Text Item',DataType='Char',MaximumLength='30')
    ET.SubElement(notes,'Item',Name='TOTAL_WEIGHT',DatabaseItem='false',ItemType='Text Item',DataType='Number',MaximumLength='12')
    rel = next(parent.iter('Relation')); rel.set('DeleteRecord','Non Isolated')
    ET.SubElement(child,'Relation',Name='PIECES_NOTES',DetailBlock='NOTES',RelationType='Join',
                  JoinCondition='PIECES.LOAD_REFERENCE=NOTES.NOTE_LOAD AND PIECES.PIECE_CODE=NOTES.NOTE_PIECE',
                  DeleteRecord='Cascading',Deferred='false',AutoQuery='false')
    bodies = [(parent,'ON-CHECK-DELETE-MASTER',MASTER),(child,'KEY-DELREC',KEY),
              (child,'PRE-DELETE',PRE),(notes,'KEY-DELREC',NOTE_KEY),(notes,'PRE-DELETE',NOTE_PRE)]
    for block,event,body in bodies:
        if change and change[0] == event and block.get('Name') == change[1]:
            body = change[2]
        ET.SubElement(block,'Trigger',Name=event,TriggerText=body)
    for name,value in (('LOCK_ALL','FALSE'),('UNLOCK_ALL','TRUE')):
        ET.SubElement(root,'ProgramUnit',Name=name,ProgramUnitType='Procedure',ProgramUnitText=
            f"PROCEDURE {name} IS BEGIN SET_BLOCK_PROPERTY('LOADS',DELETE_ALLOWED,PROPERTY_{value}); END;")
    for item in root.iter('Item'):
        if item.get('DatabaseItem') == 'true':
            item.set('ColumnName',item.get('Name'))
    raw = ET.tostring(root)
    if renamed:
        for old,new in ((b'DISPATCH_DRAFT',b'DEPOT'),(b'LOADS',b'HEADERS'),(b'PIECES',b'CRATES'),
                        (b'LOAD_REFERENCE',b'HEADER_REF'),(b'PIECE_CODE',b'CRATE_REF'),
                        (b'NOTES',b'RECEIPTS'),(b'NOTE_LOAD',b'RECEIPT_HEADER'),
                        (b'NOTE_PIECE',b'RECEIPT_CRATE'),(b'NOTE_CODE',b'RECEIPT_CODE'),
                        (b'ACME',b'OTHER_API')):
            raw=raw.replace(old,new)
    return [('renamed.xml' if renamed else 'deletion.xml',raw)]


def prepare(docs=None):
    docs = docs or source()
    return (docs,*save_prepare(docs))


def bound(kind='pre_delete', block='PIECES'):
    plan = build_delete_plan(*prepare())
    assert not plan['gaps'], plan['gaps']
    return next(o for o in plan['operations'] if o['kind']==kind and o['contract']['block']['name']==block)


@pytest.mark.parametrize('renamed',[False,True])
def test_complete_five_units_exact_typed_bindings_policies_spans_and_order(renamed):
    args = prepare(source(renamed=renamed)); before=deepcopy(args)
    plan=build_delete_plan(*args)
    assert plan==build_delete_plan(*args) and args==before
    assert not plan['gaps'],plan['gaps']
    assert len(plan['operations'])==5
    assert len({o['source_unit_id'] for o in plan['operations']})==5
    master=next(o for o in plan['operations'] if o['kind']=='master_existence_guard')
    assert master['contract']['existence_guard']['delete_record']=='Non Isolated'
    policy=master['contract']['delete_policy']
    assert policy['static_value'] is False
    assert {s['value'] for s in policy['dynamic_setters']}=={False,True}
    assert not policy['static_false_is_current_no_delete']
    for op in plan['operations']:
        assert len(op['source_unit_sha256'])==64 and len(op['operation_sha256'])==64
        assert op['whole_source_unit_converted'] is False
        if op['kind']=='key_delete':
            assert op['paired_pre_delete_unit_id']
            assert op['parsed']['pre_delete_timing']=='posting_during_commit_form_not_delete_record'
            assert op['contract']['permission_argument']['data_type']=='VARCHAR2'
        for call in op['external_calls']:
            body=next(c['text'] for c in args[2] if c['code_unit_id']==op['source_unit_id'])
            parsed,_=parse_delete_source(body,op['source_event'])
            assert parsed['kind']==op['kind']
            assert call['arity'] in (1,5) and call['position']['line']>=1
            assert len(call['arguments'])==call['arity']
            for arg in call['arguments']:
                assert arg['observed_source'] and arg['position']['end_character_offset']>arg['position']['character_offset']
    pre=next(o for o in plan['operations'] if o['kind']=='pre_delete' and o['parsed']['flag_delete'])
    assert pre['parsed']['source_order']==['audit_call','flag_delete','forms_ddl_commit','cascade_delete']
    assert len(pre['table_accesses'])==2 and len(pre['contract']['cascade']['predicates'])==2


@pytest.mark.parametrize('part', ['packet','chunks','trace','manifest','source','ddl'])
def test_tampered_authority_or_target_is_rejected(part):
    args=list(prepare()); docs,packet,chunks,trace,files=args
    if part=='packet': packet['sources'][0]['source']['sha256']='0'*64
    if part=='chunks': chunks[0]['text']+=' NULL;'
    if part=='trace': trace['blocks'][0]['name']='OTHER'
    if part=='manifest': files['fox-package/source-manifest.json']=b'{}'
    if part=='source': files['fox-package/sources/'+docs[0][0]]+=b' '
    if part=='ddl': files['fox-package/supporting-schema.sql']=b'-- missing'
    try:
        plan=build_delete_plan(*args)
        assert plan['gaps'] and not plan['operations']
    except (ValueError,KeyError):
        pass


@pytest.mark.parametrize('body', [KEY+' NULL;',KEY.replace('>0','>=0'),KEY.replace('DELETE_RECORD;','DELETE_RECORD; COMMIT;'),
                                KEY.replace('END IF;','EXCEPTION WHEN OTHERS THEN NULL; END IF;'),
                                KEY.replace('CAN_REMOVE','CAN_REMOVE(')])
def test_malformed_extra_or_changed_key_body_is_a_precise_gap(body):
    plan=build_delete_plan(*prepare(source(change=('KEY-DELREC','PIECES',body))))
    assert len(plan['operations'])==4 and len(plan['gaps'])==1
    assert plan['gaps'][0]['source_event']=='KEY-DELREC'


@pytest.mark.parametrize('body',[PRE+'DELETE FROM PIECES;',PRE.replace('AND FLAG_PIECE=:PIECE_CODE',''),
                               PRE.replace('C.NOTE_PIECE=:PIECES.PIECE_CODE','C.NOTE_PIECE=:LOADS.LOAD_REFERENCE'),
                               PRE.replace("FORMS_DDL('COMMIT');",'')])
def test_incomplete_or_cross_scope_cascade_cannot_compile(body):
    plan=build_delete_plan(*prepare(source(change=('PRE-DELETE','PIECES',body))))
    assert len(plan['operations'])==4 and len(plan['gaps'])==1
    key=next(o for o in plan['operations'] if o['kind']=='key_delete' and o['contract']['block']['name']=='PIECES')
    assert 'paired_pre_delete_unit_id' not in key


class FixtureAdapter:
    """Explicit receipts for fictional fixture capabilities; no real provider claim."""
    def __init__(self, receipts=None, db=None):
        self.receipts=receipts or {}; self.events=[]; self.db=db

    def perform(self, stage):
        self.events.append(stage)
        result=self.receipts.get(stage.id,DeleteOutcome('unmet',reason='fixture_not_bound'))
        if callable(result): return result(stage)
        if stage.id=='forms_ddl_commit' and result.status=='completed' and result.committed is True:
            self.db.commit()
        return result


def database():
    db=sqlite3.connect(':memory:')
    db.executescript('CREATE TABLE PIECES(LOAD_REFERENCE TEXT,PIECE_CODE TEXT);'
        'CREATE TABLE PIECE_FLAGS(FLAG_LOAD TEXT,FLAG_PIECE TEXT);'
        'CREATE TABLE NOTES(NOTE_LOAD TEXT,NOTE_PIECE TEXT,NOTE_CODE TEXT);')
    for table in ('PIECES','PIECE_FLAGS'):
        db.executemany('INSERT INTO '+table+' VALUES (?,?)',[('H1','B1'),('H1','B2'),('H2','B1')])
    db.executemany('INSERT INTO NOTES VALUES (?,?,?)',[('H1','B1','N1'),('H1','B2','N2'),('H2','B1','N3')])
    db.commit(); return db


def refs(op):
    values={}
    for field in op['contract']['fields']:
        ref=field['source_reference']
        values[tuple(ref)]=('user-fixture' if ref[0]=='GLOBAL' else
            'H1' if ref[-1] in ('LOAD_REFERENCE',) else 'N' if ref[-1]=='APPROVED' else
            7 if ref[-1] in ('TOTAL_WEIGHT','CALCULATED_WEIGHT') else
            'N1' if ref[-1]=='NOTE_CODE' else 'B1')
    return values


def test_master_guard_runs_actual_current_rows_and_never_authorizes_header_delete():
    op=bound('master_existence_guard','LOADS'); db=database()
    references={('LOADS','LOAD_REFERENCE'):'H1'}
    result=execute_delete_model(op,connection=db,references=references)
    assert result['status']=='form_trigger_failure' and result['matching_children'] is True
    assert db.execute('SELECT COUNT(*) FROM PIECES').fetchone()==(3,)
    references[('LOADS','LOAD_REFERENCE')]='EMPTY'
    result=execute_delete_model(op,connection=db,references=references)
    assert result['status']=='guard_passed_no_delete_authority'
    references[('LOADS','LOAD_REFERENCE')]=None
    assert execute_delete_model(op,connection=db,references=references)['matching_children'] is False
    assert execute_delete_model(op,connection=db)['status']=='unmet'


@pytest.mark.parametrize('permission,denied',[(1,True),(7,True),(0,False),(-1,False),(None,False)])
def test_key_positive_zero_negative_and_known_null_gate_mark_then_commit(permission,denied):
    op=bound('key_delete'); db=database()
    adapter=FixtureAdapter({'permission_call':DeleteOutcome('completed',permission),
        'current_delete_policy':DeleteOutcome('completed',True),
        'mark_delete':DeleteOutcome('completed'),
        'commit_form':DeleteOutcome('completed',{'posted':True},True)})
    result=execute_delete_model(op,adapter,references=refs(op))
    assert result['status']==('form_trigger_failure' if denied else 'completed')
    assert result['marked'] is not denied
    assert [s.id for s in adapter.events]==(['permission_call'] if denied else
        ['permission_call','current_delete_policy','mark_delete','commit_form'])
    assert not any(s.id=='audit_call' for s in adapter.events)
    assert db.execute('SELECT COUNT(*) FROM PIECES').fetchone()==(3,)
    if not denied:
        commit=adapter.events[-1]
        assert commit.payload['posting_pre_delete_unit_id']==op['paired_pre_delete_unit_id']


@pytest.mark.parametrize('outcome',[DeleteOutcome('unmet'),DeleteOutcome('unknown'),DeleteOutcome('failed'),
                                  DeleteOutcome('completed','0'),DeleteOutcome('completed',False),
                                  DeleteOutcome('completed',float('nan'))])
def test_missing_failure_unknown_and_non_numeric_gate_are_not_zero(outcome):
    op=bound('key_delete'); adapter=FixtureAdapter({'permission_call':outcome})
    result=execute_delete_model(op,adapter,references=refs(op))
    assert result['status'] in ('unmet','unknown','failed') and not result['marked']
    assert len(adapter.events)==1


def test_note_assignment_precedes_posting_and_navigation_follows_commit():
    op=bound('key_delete','NOTES')
    adapter=FixtureAdapter({name:DeleteOutcome('completed',value,commit) for name,value,commit in (
        ('permission_call',None,None),('current_delete_policy',True,None),('mark_delete',None,None),
        ('summary_assignment',None,None),('commit_form',{'posted':True},True),('go_block',None,None),('next_record',None,None))})
    result=execute_delete_model(op,adapter,references=refs(op))
    assert result['status']=='completed'
    assert [s.id for s in adapter.events]==['permission_call','current_delete_policy','mark_delete','summary_assignment','commit_form','go_block','next_record']
    assert adapter.events[3].payload['value']==7


def test_audit_missing_is_not_success_and_blocks_every_write():
    op=bound(); db=database()
    result=execute_delete_model(op,connection=db,references=refs(op))
    assert result['status']=='unmet' and not result['sql_effects']
    assert db.execute('SELECT COUNT(*) FROM PIECE_FLAGS').fetchone()==(3,)


def test_scoped_flag_delete_commits_before_composite_cascade_with_other_parent_preserved():
    op=bound(); db=database()
    adapter=FixtureAdapter({'audit_call':DeleteOutcome('completed'),
        'forms_ddl_commit':DeleteOutcome('completed',committed=True)},db)
    result=execute_delete_model(op,adapter,connection=db,references=refs(op))
    assert result['status']=='pre_delete_completed_owner_posting_pending'
    assert [e['stage_id'] for e in result['events']]==['audit_call','flag_delete','forms_ddl_commit','cascade_delete']
    assert db.execute('SELECT * FROM PIECE_FLAGS ORDER BY 1,2').fetchall()==[('H1','B2'),('H2','B1')]
    assert db.execute('SELECT * FROM NOTES ORDER BY 1,2').fetchall()==[('H1','B2','N2'),('H2','B1','N3')]
    assert db.in_transaction  # child DELETE follows independent committed flag work
    db.rollback()  # caller test cleanup; never performed by model
    assert db.execute('SELECT COUNT(*) FROM NOTES').fetchone()==(3,)
    assert db.execute('SELECT COUNT(*) FROM PIECE_FLAGS').fetchone()==(2,)
    assert result['posted'] is False and result['rolled_back'] is False


@pytest.mark.parametrize('stage',['audit','flag','commit','cascade'])
def test_failure_before_and_after_commit_preserves_partial_effects_without_retry(stage):
    op=bound(); db=database()
    receipts={'audit_call':DeleteOutcome('completed'),'forms_ddl_commit':DeleteOutcome('completed',committed=True)}
    if stage=='audit': receipts['audit_call']=DeleteOutcome('failed',reason='fixture_audit_raise')
    if stage=='flag': db.execute('DROP TABLE PIECE_FLAGS'); db.commit()
    if stage=='commit': receipts['forms_ddl_commit']=DeleteOutcome('failed',committed=False,reason='fixture_raise_before_commit')
    if stage=='cascade': db.execute('DROP TABLE NOTES'); db.commit()
    adapter=FixtureAdapter(receipts,db)
    result=execute_delete_model(op,adapter,connection=db,references=refs(op))
    assert result['status']=='failed' and not result['rolled_back']
    assert result['partial_outcome'] is (stage in ('commit','cascade'))
    assert [s.id for s in adapter.events].count('audit_call')==1
    if stage=='cascade':
        assert result['committed'] is True and db.execute('SELECT COUNT(*) FROM PIECE_FLAGS').fetchone()==(2,)
    if stage=='commit':
        assert db.in_transaction and db.execute('SELECT COUNT(*) FROM NOTES').fetchone()==(3,)


@pytest.mark.parametrize('committed',[None,False])
def test_normally_returned_forms_ddl_without_status_branch_continues_but_does_not_invent_commit(committed):
    op=bound(); db=database()
    adapter=FixtureAdapter({'audit_call':DeleteOutcome('completed'),
        'forms_ddl_commit':DeleteOutcome('completed',value={'form_success':False},committed=committed)},db)
    result=execute_delete_model(op,adapter,connection=db,references=refs(op))
    assert result['sql_effects'][-1]['stage_id']=='cascade_delete'
    assert result['committed'] is committed and db.in_transaction
    assert result['status']==('source_sequence_completed_transaction_outcome_unknown' if committed is None else
                              'pre_delete_completed_owner_posting_pending')


@pytest.mark.parametrize('event,body', [('KEY-DELREC','IF'),('KEY-DELREC','IF ACME.CHECK('),
                                        ('PRE-DELETE','BEGIN'),('PRE-DELETE','BEGIN ACME.AUDIT(')])
def test_truncated_delete_call_reports_only_the_affected_unit(event, body):
    plan = build_delete_plan(*prepare(source(change=(event, 'PIECES', body))))
    assert len(plan['operations']) == 4
    gap, = plan['gaps']
    assert gap['source_event'] == event and gap['reason'].startswith('DELETE_EXPECTED_ROUTINE_')


def test_operation_mutation_cannot_run_local_model():
    op=bound(); op['parsed']['flag_delete']['predicates'].pop()
    with pytest.raises(ValueError,match='IMMUTABLE_OPERATION_BINDING'):
        execute_delete_model(op,connection=database(),references=refs(op))


def test_dynamic_policy_targets_and_properties_are_unresolved_not_absent():
    docs=source(); root=ET.fromstring(docs[0][1])
    ET.SubElement(root,'ProgramUnit',Name='DYNAMIC_TARGET',ProgramUnitType='Procedure',
        ProgramUnitText='PROCEDURE DYNAMIC_TARGET IS BEGIN SET_BLOCK_PROPERTY(:CTRL.TARGET,DELETE_ALLOWED,PROPERTY_TRUE); END;')
    ET.SubElement(root,'ProgramUnit',Name='DYNAMIC_PROPERTY',ProgramUnitType='Procedure',
        ProgramUnitText="PROCEDURE DYNAMIC_PROPERTY IS BEGIN SET_BLOCK_PROPERTY('LOADS',:CTRL.PROPERTY,PROPERTY_TRUE); END;")
    ET.SubElement(root,'ProgramUnit',Name='UNRESOLVED_SETTER',ProgramUnitType='Procedure',
        ProgramUnitText="PROCEDURE UNRESOLVED_SETTER IS BEGIN SET_BLOCK_PROPERTY('LOADS',:CTRL.PROP,PROPERTY_TRUE); x := x + 1; END;")
    plan=build_delete_plan(*prepare([(docs[0][0],ET.tostring(root))]))
    assert not plan['gaps']
    guard=next(o for o in plan['operations'] if o['kind']=='master_existence_guard')
    setters=guard['contract']['delete_policy']['dynamic_setters']
    assert any(s.get('dynamic_target_unresolved') is True for s in setters)
    assert any(s.get('dynamic_property_unresolved') is True for s in setters)
    assert any(s.get('lexically_unresolved') is True for s in setters)
    assert guard['contract']['delete_policy']['static_false_is_current_no_delete'] is False


def test_unrelated_incomplete_relation_does_not_discard_bound_deletion_events():
    from test_forms_buffer_plan import members, parent_package
    from fox.forms_understanding_packet import _build
    docs=source(); root=ET.fromstring(docs[0][1])
    parent=next(root.iter('Block'))
    ET.SubElement(parent,'Relation',Name='UNRELATED_INCOMPLETE',DetailBlock='UNRESOLVED_IMPORTED_BLOCK',RelationType='Join')
    docs=[(docs[0][0],ET.tostring(root))]
    files=members(parent_package(docs)); packet,chunks=_build(docs)
    plan=build_delete_plan(docs,packet,chunks,json.loads(files['fox-package/source-to-page.json']),files)
    assert len(plan['operations'])==5 and not plan['gaps']
    assert all(o['contract']['unresolved_relations'] for o in plan['operations'])


@pytest.mark.parametrize('permission,expected',[(Decimal('1.01'),'form_trigger_failure'),
    (Decimal('0'),'completed'),(Decimal('-1'),'completed'),(Decimal('NaN'),'unknown'),
    (Decimal('Infinity'),'unknown')])
def test_oracle_numeric_return_uses_decimal_null_and_finite_semantics(permission,expected):
    op=bound('key_delete')
    adapter=FixtureAdapter({'permission_call':DeleteOutcome('completed',permission),
        'current_delete_policy':DeleteOutcome('completed',True),'mark_delete':DeleteOutcome('completed'),
        'commit_form':DeleteOutcome('completed',{'posted':True},True)})
    assert execute_delete_model(op,adapter,references=refs(op))['status']==expected


@pytest.mark.parametrize('newline',['\r','\n','\r\n'])
def test_call_positions_are_exact_decoded_character_spans_for_all_line_endings(newline):
    raw=newline.join(NOTE_PRE.splitlines())
    parsed,_=parse_delete_source(raw,'PRE-DELETE'); call=parsed['audit_call']
    assert raw[call['position']['character_offset']:call['position']['end_character_offset']]==call['observed_source']
    assert call['arguments'][2]['position']['line']==2
    assert call['arguments'][2]['position']['column']==2
    for arg in call['arguments']:
        p=arg['position']
        assert raw[p['character_offset']:p['end_character_offset']]==arg['observed_source']


@pytest.mark.parametrize('posted,committed',[(False,False),(True,False),(False,True),(True,None)])
def test_normally_returned_commit_keeps_navigation_but_false_unknown_posting_is_not_success(posted,committed):
    op=bound('key_delete','NOTES')
    adapter=FixtureAdapter({'permission_call':DeleteOutcome('completed',0),
        'current_delete_policy':DeleteOutcome('completed',True),'mark_delete':DeleteOutcome('completed'),
        'summary_assignment':DeleteOutcome('completed'),
        'commit_form':DeleteOutcome('completed',{'posted':posted},committed),
        'go_block':DeleteOutcome('completed'),'next_record':DeleteOutcome('completed')})
    result=execute_delete_model(op,adapter,references=refs(op))
    assert result['status'] in ('source_sequence_completed_deletion_unconfirmed',
                                'source_sequence_completed_transaction_outcome_unknown')
    assert [s.id for s in adapter.events][-2:]==['go_block','next_record']
    assert result['posted'] is posted and result['committed'] is committed
    assert result['business_accepted'] is False


@pytest.mark.parametrize('committed',[False,True,None])
def test_raised_commit_failure_preserves_mark_and_observed_commit_outcome(committed):
    op=bound('key_delete','NOTES')
    adapter=FixtureAdapter({'permission_call':DeleteOutcome('completed',0),
        'current_delete_policy':DeleteOutcome('completed',True),'mark_delete':DeleteOutcome('completed'),
        'summary_assignment':DeleteOutcome('completed'),
        'commit_form':DeleteOutcome('failed',committed=committed,reason='fixture_raise')})
    result=execute_delete_model(op,adapter,references=refs(op))
    assert result['status']=='failed' and result['marked'] is True
    assert result['partial_outcome'] and result['committed'] is committed
    assert adapter.events[-1].id=='commit_form' and not result['rolled_back']


def test_stage_ordinals_and_conditions_distinguish_gate_branch_from_following_effects():
    plan=build_delete_plan(*prepare())
    key=next(o for o in plan['operations'] if o['kind']=='key_delete')
    assert [s['ordinal'] for s in key['stages']]==list(range(1,len(key['stages'])+1))
    assert key['stages'][1]['condition']=='permission_return_positive'
    assert all(s['condition']=='permission_return_not_positive_including_null' for s in key['stages'][2:])
    pre=next(o for o in plan['operations'] if o['kind']=='pre_delete' and o['parsed']['cascade_delete'])
    assert [s['id'] for s in pre['stages']]==['audit_call','flag_delete','forms_ddl_commit','cascade_delete']
    assert all(s['condition']=='normal_source_sequence' for s in pre['stages'])
