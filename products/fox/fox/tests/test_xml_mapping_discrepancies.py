"""Source-linked reports must not gate partial output or relabel saved results."""
from copy import deepcopy
import json

import pytest

from fox import xml_mapping, xml_mapping_job
from fox.forms_native_plan import POLICY_ID
from fox.prototype_export_only import _members

SOURCE = b'''<FormModule Name="SHIPMENTS"><Block Name="ROWS" DatabaseBlock="true">
<Item Name="AMOUNT" ItemType="Text Item" DataType="Number" DatabaseItem="true"/>
<Item Name="TOTAL" ItemType="Display Item" DataType="Number" DatabaseItem="false" Formula="CEIL(:AMOUNT)"/>
<Trigger Name="WHEN-VALIDATE-RECORD" TriggerText="IF :AMOUNT = 0 THEN MESSAGE('Check the amount'); END IF;"/>
<Trigger Name="WHEN-BUTTON-PRESSED" TriggerText="BEGIN REMOTE_API.CHECK_VALUE(:AMOUNT); GO_ITEM('ROWS.AMOUNT'); END;"/>
</Block><RecordGroup Name="CODES" RecordGroupQuery="SELECT CODE, NAME FROM SHIPPING_CODES"/>
<Report Name="SUMMARY_REPORT" Filename="SHIPMENT_REPORT"/></FormModule>'''


def generated():
    return xml_mapping.generate_xml_package([('shipments.xml',SOURCE)],'shipments','Shipments',POLICY_ID)


def test_partial_generation_contains_every_unit_and_unverified_reference():
    candidate,report=generated();files=_members(candidate)
    d=report['discrepancies'];m=report['metadata'];summary=d['summary']
    assert d==json.loads(files['fox-package/discrepancies.json'])
    assert m['discrepancy_report_sha256']==xml_mapping._sha(files[m['discrepancy_report_path']])
    assert summary['total_units']==len(report['mapping_ledger']['code_units'])
    assert summary['generated_units']==1 and summary['encoded_unwired_units']==1
    assert sum(summary[k] for k in ('generated_units','encoded_unwired_units','unimplemented_units'))==summary['total_units']
    assert any(r['kind']=='routine_reference' and r['name']=='REMOTE_API.CHECK_VALUE' and r['status']=='unverified' for r in d['dependencies'])
    assert any(r['kind']=='forms_api' and r['name']=='GO_ITEM' for r in d['dependencies'])
    assert any(r['kind']=='database_object' and r['name']=='SHIPPING_CODES' for r in d['dependencies'])
    assert not d['runtime_verified'] and not d['business_behavior_accepted']
    assert len(report['gap_report']['gaps'])==summary['encoded_unwired_units']+summary['unimplemented_units']
    assert SOURCE==files['fox-package/sources/shipments.xml']


def test_report_retrieval_preserves_saved_classifications_without_rebuilding(monkeypatch):
    from fox import forms_discrepancies
    candidate,report=generated();files=_members(candidate)
    def forbid(*a,**k):raise AssertionError('Saved result must not be reclassified')
    monkeypatch.setattr(forms_discrepancies,'build_discrepancies',forbid)
    monkeypatch.setattr(forms_discrepancies,'build_dependency_evidence',forbid)
    checked=xml_mapping_job._discrepancy_fields(report['metadata'],report['mapping_ledger'],report['gap_report'],files)
    assert checked==report['discrepancies']


def test_legacy_report_absence_does_not_block_old_download():
    assert xml_mapping_job._discrepancy_fields({}, {'code_units':[]}, None, {}) is None


def test_saved_partial_draft_guard_identifies_its_page_and_keeps_the_source_unit_unfinished():
    from test_forms_draft_policy import source
    _, result = xml_mapping.generate_xml_package(source(renamed=True), 'warehouse', 'Warehouse', POLICY_ID)
    ledger, metadata = result['mapping_ledger'], result['metadata']
    guard, = ledger['draft_policy_guards']
    unit = next(u for u in result['discrepancies']['units'] if u['source_unit_id'] == guard['source_unit_id'])
    assert unit['status'] == 'encoded_unwired'
    assert "draft editor checks the selected parent's edit permissions" in unit['message']
    helper, = guard['supporting_units']
    helper_row = next(u for u in ledger['code_units'] if u['source_unit_id'] == helper['source_unit_id'])
    assert helper_row['rule_id'] == 'fox.policy.parent-draft-guard'
    assert xml_mapping_job._policy_fields(metadata, ledger) == metadata['policy_summary']
    for key, value in (('page_id', guard['page_id'] + 1), ('customer_table_writes', True), ('status', 'read_only_unresolved')):
        changed = deepcopy(ledger)
        changed['draft_policy_guards'][0][key] = value
        with pytest.raises(ValueError, match='partial draft policy'):
            xml_mapping_job._policy_fields(metadata, changed)


def test_unresolved_parent_permissions_do_not_count_an_unreachable_draft_validator():
    from test_forms_draft_policy import source
    _, result = xml_mapping.generate_xml_package(source(trigger='UNKNOWN_RULE;'), 'warehouse', 'Warehouse', POLICY_ID)
    ledger = result['mapping_ledger']
    assert ledger['draft_policy_gaps'] and not ledger['buffer_flows']
    assert result['metadata']['buffer_summary'] == {'record_validation_flows': 0}
    unit = next(u for u in result['discrepancies']['units'] if u['source_name'] == 'WHEN-VALIDATE-RECORD')
    assert unit['status'] == 'unimplemented' and 'read-only' in unit['message']


@pytest.mark.parametrize('mutation',['changed_bytes','wrong_path','missing_member','promoted_unit'])
def test_report_integrity_and_unit_promotion_are_rejected(mutation):
    candidate,report=generated();files=_members(candidate);metadata=deepcopy(report['metadata']);path=metadata['discrepancy_report_path']
    if mutation=='changed_bytes':files[path]+=b' '
    elif mutation=='wrong_path':metadata['discrepancy_report_path']='outside.json'
    elif mutation=='missing_member':files.pop(path)
    else:
        d=json.loads(files[path]);row=next(r for r in d['units'] if r['status']=='encoded_unwired');row['status']='generated'
        d['summary']['encoded_unwired_units']-=1;d['summary']['generated_units']+=1
        files[path]=xml_mapping._bytes(d);metadata['discrepancy_report_sha256']=xml_mapping._sha(files[path])
    with pytest.raises(ValueError):
        xml_mapping_job._discrepancy_fields(metadata,report['mapping_ledger'],report['gap_report'],files)


def test_reference_evidence_bytes_are_checked_before_serving_report():
    candidate,report=generated();files=_members(candidate)
    path=report['metadata']['discrepancy_evidence_path']
    files[path]+=b' '
    with pytest.raises(ValueError,match='reference evidence changed'):
        xml_mapping_job._discrepancy_fields(report['metadata'],report['mapping_ledger'],report['gap_report'],files)


def test_encoded_newlines_do_not_hide_external_calls_from_the_ui_report():
    raw=SOURCE.replace(b'BEGIN REMOTE_API.CHECK_VALUE(:AMOUNT);',b'BEGIN -- retained comment&amp;#10; REMOTE_API.CHECK_VALUE(:AMOUNT);')
    candidate,report=xml_mapping.generate_xml_package([('encoded.xml',raw)],'encoded','Encoded source',POLICY_ID)
    d=report['discrepancies']
    assert any(g['name']=='REMOTE_API.CHECK_VALUE' and g['kind']=='routine_reference' for g in d['dependencies'])
    assert report['metadata']['behavior_coverage']['counts']=={'generated_wired_adapted':1,'unsupported':3}
    files=_members(candidate)
    assert files['fox-package/sources/encoded.xml']==raw
    evidence=json.loads(files['fox-package/discrepancy-evidence.json'])
    assert evidence['source_binding']==report['source_binding']


@pytest.mark.parametrize('variant, expected', [
    ('connected', ('caller VIA returns ROUTE_DEST to HEADER.VIA, CITY_NAME to HEADER.CITY', 'selected draft')),
    ('disabled', ('declared returns ROUTE_DEST to HEADER.VIA, CITY_NAME to HEADER.CITY remain unconnected', 'Existing-row updates are disabled', 'new-draft inputs and permissions are not established')),
    ('no_caller', ('declared returns ROUTE_DEST to HEADER.VIA, CITY_NAME to HEADER.CITY remain unconnected', 'No source calling item was found')),
])
def test_record_group_discrepancy_explains_source_lov_return(variant, expected):
    from test_forms_lov_return import SOURCE as lov_source
    raw = lov_source
    if variant == 'disabled':
        raw = raw.replace(b'LovName="VIA_CHOICES"', b'UpdateAllowed="false" LovName="VIA_CHOICES"')
    elif variant == 'no_caller':
        raw = raw.replace(b'LovName="VIA_CHOICES"', b'')
    candidate, report = xml_mapping.generate_xml_package([('dispatch.xml', raw)], 'lov-note', 'LOV note', POLICY_ID)
    group, = report['mapping_ledger']['record_group_reports']
    unit = next(u for u in report['discrepancies']['units'] if u['source_unit_id'] == group['source_unit_id'])
    assert unit['status'] == 'generated'
    assert all(part in unit['message'] for part in expected)
    assert not report['discrepancies']['runtime_verified'] and not report['discrepancies']['business_behavior_accepted']
    files = _members(candidate)
    assert xml_mapping_job._discrepancy_fields(report['metadata'], report['mapping_ledger'], report['gap_report'], files) == report['discrepancies']


def test_lov_message_limit_reports_omitted_details_explicitly():
    from fox.forms_discrepancies import _lov_return_note
    target = {'kind': 'record_group_reference_report', 'associated_lovs': [{
        'source_lov_name': 'CHOICES', 'return_mappings': [{'source_column_name': 'COLUMN', 'return_item': 'X' * 5000}],
        'lov_return_implemented': False, 'return_gap': 'LOV_RETURN_DECLARED_RETURNS_WITHOUT_SOURCE_CALLER'}]}
    note = _lov_return_note(target, 300)
    assert 'exceed the report message limit' in note and 'complete fields and gaps' in note
    assert len(note) <= 300
