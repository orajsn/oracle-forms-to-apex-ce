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
