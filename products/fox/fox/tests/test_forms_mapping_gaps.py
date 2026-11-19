"""Gap causes are source-grounded, not a claim that APEX cannot convert code."""
from copy import deepcopy
from fox.forms_mapping_gaps import classify_gaps
from fox.forms_understanding_packet import _build
import pytest


def fixture():
    raw=b'''<FormModule Name="EXAMPLE"><Block Name="HEADER" DatabaseBlock="true"><Item Name="ROUTE" DataType="Char" ItemType="Text Item"/></Block><Block Name="DETAIL" DatabaseBlock="true"><Item Name="ROUTE_COPY" DataType="Char" ItemType="Text Item"/><Trigger Name="PRE-INSERT" TriggerText=":ROUTE_COPY := :ROUTE;"/><Trigger Name="CHECK" TriggerText="BEGIN EXTERNAL_API.CHECK_VALUE(1); END;"/></Block><ProgramUnit Name="HELPER" ProgramUnitText="PROCEDURE HELPER IS BEGIN NULL; END;"/><RecordGroup Name="CHOICES" RecordGroupQuery="SELECT VALUE FROM LOOKUP_TABLE"/></FormModule>'''
    packet,chunks=_build([('example.xml',raw)])
    coverage=[{'source_unit_id':c['code_unit_id'],'source_unit_sha256':c['sha256'],'status':'unsupported','reason':'unsupported_unit_kind'} for c in chunks]
    return packet,chunks,coverage


def test_source_present_assignment_gets_engine_context_and_queries_get_mapping_gap():
    packet,chunks,coverage=fixture();result=classify_gaps(packet,chunks,coverage)
    rows={r['source_name']:r for r in result['gaps']}
    assert rows['PRE-INSERT']['category']=='engine_context'
    assert rows['HELPER']['category']==rows['CHOICES']['category']=='engine_mapping'
    assert rows['CHECK']['category']=='engine_mapping'
    assert result['summary']=={'engine_mapping':3,'engine_context':1,'missing_source':0,'review_required':0}
    assert all(r['owner']=='FOX_ENGINE' for r in result['gaps'])
    assert result['dependency_candidates_are_confirmed_missing_inputs'] is False
    assert all(r['source_file']=='example.xml' and r['source_line']>0 for r in result['gaps'])


def test_recognizer_missing_definition_and_ambiguity_have_different_owners():
    p,c,v=fixture();v[0]['reason']='local_function_definition_missing';v[1]['reason']='item_reference_is_not_unique'
    result=classify_gaps(p,c,v)
    assert result['gaps'][0]['category']=='missing_source' and result['gaps'][0]['owner']=='SOURCE_OWNER'
    assert result['gaps'][1]['category']=='review_required' and result['gaps'][1]['owner']=='REVIEWER'


def test_generated_units_never_become_gaps_and_capacity_stays_engine_owned():
    p,c,v=fixture();v[0]['status']='generated_wired_adapted';v[1]['reason']='behavior_operation_capacity_exceeded'
    result=classify_gaps(p,c,v)
    assert result['not_yet_converted']==3 and sum(result['summary'].values())==3
    assert v[0]['source_unit_id'] not in {r['source_unit_id'] for r in result['gaps']}
    assert result['gaps'][0]['category']=='engine_mapping' and 'capacity' in result['gaps'][0]['message']


@pytest.mark.parametrize('mutation',['hash','missing','duplicate'])
def test_source_identity_and_full_coverage_required(mutation):
    p,c,v=fixture();v=deepcopy(v)
    if mutation=='hash':v[0]['source_unit_sha256']='0'*64
    elif mutation=='missing':v.pop()
    else:v[-1]=v[0]
    with pytest.raises(ValueError):classify_gaps(p,c,v)
