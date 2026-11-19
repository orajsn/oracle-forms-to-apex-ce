"""Source ORDER BY emits initial saved-report sorts; no Oracle runtime proof."""
from html import escape
import pytest
from fox.forms_order_rules import parse_order
from fox.xml_mapping import generate_xml_package
from fox.forms_native_plan import POLICY_ID
from fox.prototype_export_only import _members


def source(clause='A DESC, B ASC NULLS FIRST', a_extra='', child=''):
    return (f'<FormModule Name="F"><Block Name="ROWS" DatabaseBlock="true" OrderByClause="{escape(clause,quote=True)}">'
      f'<Item Name="A" DatabaseItem="true" DataType="Number" ItemType="Text Item" {a_extra}/>'
      '<Item Name="B" DatabaseItem="true" DataType="Char" ItemType="Text Item"/>'
      f'{child}</Block></FormModule>').encode()


def generate(raw):
    return generate_xml_package([('sort.xml',raw)],'sort','Sort',POLICY_ID)


def test_complete_sort_preserves_directions_nulls_order_and_coverage():
    raw=source(); candidate,report=generate(raw)
    assert (candidate,report)==generate(raw)
    rows=report['order_receipt']['generated_operations'];assert len(rows)==1
    op=rows[0];page=_members(candidate)[op['target']['report_file']].decode()
    assert [(t['direction'],t['nulls']) for t in op['terms']]==[('desc','first'),('asc','first')]
    for n,t in enumerate(op['terms'],1):
        assert f"column: {t['column']}" in page
        assert f'sequence: {n}\n' in page
    assert page.index('direction: desc')<page.index('direction: asc')
    assert report['metadata']['behavior_coverage']=={'total':1,'counts':{'generated_wired_adapted':1}}
    assert report['metadata']['policy_summary']=={'rules_generated_unwired':0}
    assert report['gap_report']['not_yet_converted']==0
    assert not report['metadata']['runtime_verified']
    assert _members(candidate)['fox-package/sources/sort.xml']==raw


def test_oracle_default_null_order_and_explicit_override():
    assert [(r['direction'],r['nulls']) for r in parse_order('A,b DESC,c desc nulls last')]==[('asc','last'),('desc','first'),('desc','last')]


@pytest.mark.parametrize('clause',['A DESC; DELETE FROM T','A DESC -- hi','LOWER(B)','1','A,A','ROWS.A','"A"','A NULLS MIDDLE','A COLLATE X','A,B,C,D,E,F,G','A desc,'])
def test_unsupported_whole_clause_never_partially_sorts(clause):
    candidate,report=generate(source(clause))
    assert not report['order_receipt']['generated_operations']
    assert report['metadata']['behavior_coverage']['counts']=={'unsupported':1}
    assert '            sort (' not in _members(candidate)['pages/p00001-block_1.apx'].decode()


@pytest.mark.parametrize('extra',['Formula="CEIL(:B)"','CalculateMode="Summary"','CalculationMode="Formula"','SummaryFunction="Sum"'])
def test_computed_columns_are_not_treated_as_stored_sort_inputs(extra):
    _,report=generate(source('A DESC',a_extra=extra))
    assert not report['order_receipt']['generated_operations']


def test_unknown_columns_and_other_module_names_never_bind():
    raw=source('UNKNOWN DESC');_,report=generate(raw)
    assert not report['order_receipt']['generated_operations']
    other=source('A ASC').replace(b'Name="F"',b'Name="OTHER"')
    _,report=generate_xml_package([('one.xml',raw),('two.xml',other)],'sort','Sort',POLICY_ID)
    assert len(report['order_receipt']['generated_operations'])==1


def test_policy_review_count_does_not_promote_source_event():
    trigger='<Trigger Name="WHEN-VALIDATE-RECORD" TriggerText="IF :A = 1 THEN MESSAGE(\'Check value\'); END IF;"/>'
    _,report=generate(source(child=trigger))
    assert report['metadata']['behavior_coverage']=={'total':2,'counts':{'generated_wired_adapted':1,'unsupported':1}}
    assert report['metadata']['policy_summary']=={'rules_generated_unwired':1}
    unit=next(r for r in report['mapping_ledger']['code_units'] if r['rule_id']=='fox.policy.finite-review')
    assert unit['encoding_status']=='generated_unwired'
    assert report['gap_report']['gaps'][0]['reason']=='policy_rule_encoded_event_context_unimplemented'
    assert report['gap_report']['summary']['engine_context']==1


def test_explicit_database_column_names_bind_the_correct_item():
    raw=source('A DESC',a_extra='ColumnName="B"').replace(b'Name="B" DatabaseItem',b'Name="B" ColumnName="A" DatabaseItem')
    candidate,report=generate(raw)
    op=report['order_receipt']['generated_operations'][0]
    block=report['native_plan']['rendering_spec']['blocks'][0]
    expected=next(f for f in block['fields'] if f['source_name']=='B')
    assert op['terms'][0]['column']==expected['name']
    assert op['terms'][0]['source_item_id']==expected['source_item_id']


def test_multiple_items_for_one_database_column_stay_ambiguous():
    _,report=generate(source('B DESC',a_extra='ColumnName="B"'))
    assert not report['order_receipt']['generated_operations']
    assert report['order_receipt']['gaps'][0]['reason']=='order_source_column_not_unique'


def test_unrelated_database_column_alias_does_not_block_proven_sort():
    _,report=generate(source('B DESC',a_extra='ColumnName="SOURCE_A"'))
    assert len(report['order_receipt']['generated_operations'])==1
