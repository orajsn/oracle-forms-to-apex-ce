"""Generated APEX event/state contracts; these checks do not run Oracle."""
from copy import deepcopy
import json
from pathlib import Path
import re
import sys

import pytest

# Source tests exercise the complete producer, not an arbitrary hand-authored plan.
APP = Path(__file__).resolve().parents[2] / 'fox'
sys.path.insert(0, str(APP))
from fox.xml_mapping import generate_xml_package
from fox.forms_native_plan import POLICY_ID
from fox.prototype_export_only import _members, _zip
from forms2apex import native_buffer


def generated():
    sample=Path(__file__).resolve().parents[2]/'examples/xml-mapping/record_buffer.xml'
    return generate_xml_package([('record_buffer.xml',sample.read_bytes())],'buffer','Record drafts',POLICY_ID)


def page_data():
    candidate,report=generated()
    files=_members(candidate)
    op=report['buffer_plan']['operations'][0]
    rendered=report['buffer_receipt']['generated_operations'][0]
    return files,report,op,rendered,files[rendered['page_file']].decode()


def test_event_pipeline_native_bindings_and_truthful_scope():
    files,report,op,rendered,page=page_data()
    assert len(report['buffer_receipt']['generated_operations'])==1
    assert rendered['source_unit_id']==op['source_unit_id']
    assert rendered['native_event_wired'] and not rendered['event_activated']
    assert not any(rendered[k] for k in ('customer_table_writes','oracle_compiled','runtime_verified','business_accepted'))
    assert 'Validate draft records' in files[rendered['context_page_file']].decode()
    assert all(request in page for request in native_buffer.REQUESTS)
    assert 'point: beforeHeader' in page and 'point: processing' in page and 'point: afterProcessing' in page
    assert page.count('executeValidations: true')==4
    assert page.count('trimSpaces: none')==len(op['key_bindings'])
    assert 'storage: session' not in page  # hidden browser revisions cannot use shared cached fallback
    assert page.count('sessionStateProtection: checksumRequiredSessionLevel')==3
    assert "p_commit=>false" in page and not re.search(r'\bcommit\s*;',page,re.I)
    assert not re.search(r'\b(?:insert\s+into|update\s+FOX_T|delete\s+from)\b',page,re.I)
    assert 'for update nowait' in page and 'collate binary' in page
    assert 'source-record-check' in page
    assert report['metadata']['buffer_summary']=={'record_validation_flows':1}
    assert not report['metadata']['runtime_verified']


def test_scope_loaded_rows_current_overlay_and_source_order():
    _,_,op,_,page=page_data()
    for pair in op['relation']['join_pairs']:
        assert f"p.{pair['parent_column']} = c.{pair['child_column']}" in page
    assert 'seq_id = l_seq then' in page
    assert "c050='ROW'" in page and 'nvl(sum(case when' in page
    compute=native_buffer._compute(op,42)
    assert compute.index(op['control_key']['native_item'])<compute.index('sum(case when')<compute.index(op['summary']['native_item'])
    assert '||' in compute and 'trim(' not in compute.lower()
    failure=native_buffer._retain_failure(op,42)
    assert failure.index('update_member_attribute')<failure.index("p_name=>'P42_REV'")<failure.index('return false')
    assert 'p_number_value=>l_revision+1' in failure
    mutation=native_buffer._mutate(op,42)
    assert mutation.index('not context_ok')<mutation.index('p_attr_value=>l_value1')
    assert mutation.index("l_rows>=1000")<mutation.index('p_attr_value=>l_value1')
    assert mutation.index('l_matches>1')<mutation.index('p_attr_value=>l_value1')


def test_untrusted_parent_or_rehashed_ir_is_rejected():
    _,report,_,_,_=page_data()
    plan=deepcopy(report['buffer_plan'])
    with pytest.raises(ValueError,match='PARENT_CHANGED'):
        native_buffer.render_buffer_package(b'not the parent',plan)
    plan['operations'][0]['key_bindings'][0]['column']='UNTRUSTED_COLUMN'
    plan['plan_sha256']=native_buffer._sha(native_buffer._json({k:v for k,v in plan.items() if k!='plan_sha256'}))
    with pytest.raises(ValueError,match='SOURCE_IR_MISMATCH'):
        native_buffer.render_buffer_package(b'not the parent',plan)


def test_source_messages_are_inert_display_text():
    rendered=native_buffer._validation('message',1,'return false;',"<script>alert('x')</script>")
    assert '<script>' not in rendered and '&lt;script&gt;' in rendered


def test_required_and_edited_only_case_properties_reach_native_code():
    sample=Path(__file__).resolve().parents[2]/'examples/xml-mapping/record_buffer.xml'
    raw=sample.read_bytes().replace(b'Name="PREFIX" ItemType',b'Name="PREFIX" Required="true" ItemType').replace(b'Name="CODE" ItemType',b'Name="CODE" CaseRestriction="Upper" ItemType')
    candidate,report=generate_xml_package([('case.xml',raw)],'case','Case-aware drafts',POLICY_ID)
    op=report['buffer_receipt']['generated_operations'][0]
    page=_members(candidate)[op['page_file']].decode()
    assert 'valueRequired: true' in page and 'l_value1 is null' in page
    assert 'valueProtected: false' in page and 'sessionStateProtection: unrestricted' in page
    assert 'textTransform="uppercase"' in page and 'addEventListener("input"' in page
    assert 'l_value2 := upper(' in page and 'else l_value2 := l_original2' in page
    assert 'utl_raw.cast_to_raw' in page
    assert 'textCase: upper' not in page  # would alter untouched queried values on submit


def test_native_validation_capacity_preserves_source_gap_instead_of_partial_code():
    sample=Path(__file__).resolve().parents[2]/'examples/xml-mapping/record_buffer.xml'
    raw=sample.read_bytes().replace(b'Name="PREFIX" ItemType',b'Name="PREFIX" CaseRestriction="Upper" ItemType').replace(b'Name="CODE" ItemType',b'Name="CODE" CaseRestriction="Upper" ItemType')
    extra=b'<Item Name="PART3" ItemType="Text Item" DatabaseItem="true" DataType="Char" MaximumLength="16" CaseRestriction="Upper"/><Item Name="PART4" ItemType="Text Item" DatabaseItem="true" DataType="Char" MaximumLength="16" CaseRestriction="Upper"/>'
    raw=raw.replace(b'<Item Name="MATCHES"',extra+b'<Item Name="MATCHES"').replace(b':PACKS.PREFIX || :PACKS.CODE',b':PACKS.PREFIX || :PACKS.CODE || :PACKS.PART3 || :PACKS.PART4').replace(b'MaximumLength="50"',b'MaximumLength="128"')
    candidate,report=generate_xml_package([('capacity.xml',raw)],'capacity','Capacity',POLICY_ID)
    assert report['buffer_plan']['operations']
    assert report['buffer_receipt']['generated_operations']==[]
    assert report['buffer_receipt']['unrendered_operations'][0]['reason']=='native_record_validation_capacity'
    assert report['metadata']['buffer_summary']=={'record_validation_flows':0}
    assert report['metadata']['behavior_coverage']['counts']=={'generated_wired_adapted':2,'unsupported':1}
    assert not any('-fox_buffer_' in name for name in _members(candidate))
    assert report['gap_report']['gaps'][0]['reason']=='native_record_validation_capacity'


def test_coordinated_rehashed_catalog_cannot_replace_original_parent(monkeypatch):
    from forms2apex.record_buffer import derive_buffer_operations, validate_buffer_plan
    real=native_buffer.render_buffer_package
    seen=[]
    def tampered(parent,plan):
        edited=deepcopy(plan)
        unit_id=edited['operations'][0]['source_unit_id']
        unit=next(u for u in edited['source_catalog']['units'] if u['id']==unit_id)
        unit['text']=unit['text'].replace('This record already exists','Different source warning')
        unit['sha256']=native_buffer._sha(unit['text'].encode())
        owner=next(o for o in edited['source_catalog']['objects'] if o['id']==unit['owner_id'])
        owner['metadata'][unit['source_attribute']]=unit['text']
        edited['operations'],edited['coverage']=derive_buffer_operations(edited['source_catalog'],edited['parent_trace'],edited['source_binding'],edited['relation_plan'],edited['relation_receipt'])
        edited['plan_sha256']=native_buffer._sha(native_buffer._json({k:v for k,v in edited.items() if k!='plan_sha256'}))
        validate_buffer_plan(edited)  # Internally consistent; original parent must still reject it.
        seen.append(True)
        return real(parent,edited)
    monkeypatch.setattr(native_buffer,'render_buffer_package',tampered)
    with pytest.raises(ValueError,match='SOURCE_CATALOG_DIFFERS_FROM_REBUILT_PARENT'):
        generated()
    assert seen==[True]
