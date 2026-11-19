"""Native event wiring and source-query gates; no Oracle queries are executed."""
from copy import deepcopy
from pathlib import Path
import json
import re
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'fox'))
from fox.xml_mapping import generate_xml_package
from fox.forms_native_plan import POLICY_ID
from fox.prototype_export_only import _members
from forms2apex import native_lookups
from forms2apex.source_lookup import validate_lookup_plan,derive_lookup_operations


def generate(raw=None):
    path=Path(__file__).resolve().parents[2]/'examples/xml-mapping/source_lookups.xml'
    return generate_xml_package([('source_lookups.xml',raw or path.read_bytes())],'lookup','Source lookups',POLICY_ID)


def test_all_complete_events_emit_native_connections_without_activation():
    candidate,report=generate();files=_members(candidate)
    assert report['metadata']['behavior_coverage']=={'total':3,'counts':{'generated_wired_adapted':3}}
    assert report['metadata']['lookup_summary']=={'generated_lookup_handlers':3,'original_reads_enabled':False}
    assert len(report['lookup_receipt']['generated_operations'])==3
    gates=files['shared-components/app-items.apx'].decode()
    assert gates.count('sessionStateProtection: restricted')==3
    assert 'default' not in gates.lower() and 'sessionStateDataType' not in gates
    for r in report['lookup_receipt']['generated_operations']:
        page=files[r['page_file']].decode();op=next(o for o in report['lookup_plan']['operations'] if o['operation_id']==r['operation_id'])
        assert r['native_event_wired'] and not r['original_interface_enabled']
        assert all(r[k] is False for k in ('event_activated','source_query_executed','customer_table_writes','oracle_compiled','runtime_verified','business_accepted'))
        assert r['readiness_item'] in gates and r['readiness_item'] in page
        assert 'formInitialization' in page and 'formAutoRowProcessing' not in page
        assert 'serverSideCondition' in page and 'type: expression' in page
        assert 'exception when '+op['exception_kind']+' then' in page
        assert 'EXCEPTION WHEN OTHERS' not in page.upper() if op['exception_kind']=='NO_DATA_FOUND' else True
        assert all('Lookups' in files[p].decode() for p in r['report_files'])
        assert 'storage: request' in page and 'checksumRequiredSessionLevel' in page
        if op['source_event']=='POST-QUERY':
            assert r['event_adapter']=='selected_record_load'
            assert 'point: beforeHeader' in page and ':REQUEST is null' in page
        else:
            assert r['event_adapter']=='explicit_lookup_submit'
            assert 'point: processing' in page and 'Apply lookup' in page
            assert 'trimSpaces: none' in page
    assert files['fox-package/lookup-activation.md']


def test_readonly_source_input_is_reloaded_outside_original_exception_handler():
    _,report=generate();op=next(o for o in report['lookup_plan']['operations'] if o['source_event']=='POST-CHANGE')
    b=op['input_bindings'][0];assert b['source_update_allowed'] is False
    code=native_lookups._source_body(op,99)
    assert code.index("has not been verified and enabled")<code.index('SELECT DEST_CODE')
    assert code.index('SELECT '+b['column'])<code.index('SELECT DEST_CODE')
    assert 'lengthb(:P99_'+b['column']+')' in code
    assert 'ROWNUM' not in code and 'MAX(' not in code
    resets=[f":P99_{o['column']} := NULL;" for o in op['output_bindings']]
    assert code.index(resets[0])<code.index(resets[1])
    page=native_lookups._page(op,99,98)
    assert 'readOnly' in page and ':P99_FOX_ROW_ID is not null' in page
    assert 'executeValidations: false' in page  # POST-CHANGE is not a customer record save.


def test_canonical_app_item_file_and_parent_proof_required():
    _,report=generate();plan=report['lookup_plan']
    with pytest.raises(ValueError,match='PARENT_CHANGED'):
        native_lookups.render_lookup_package(b'wrong parent',plan)
    changed=deepcopy(plan);changed['operations'][0]['query']['tables'][0]['parts']=['INJECTED_TABLE']
    changed['plan_sha256']=native_lookups._sha(native_lookups._json({k:v for k,v in changed.items() if k!='plan_sha256'}))
    with pytest.raises(ValueError):validate_lookup_plan(changed)


def test_unsupported_extra_statement_never_enters_native_query():
    path=Path(__file__).resolve().parents[2]/'examples/xml-mapping/source_lookups.xml'
    raw=path.read_bytes().replace(b'EXCEPTION WHEN NO_DATA_FOUND',b'DELETE FROM OTHER_TABLE; EXCEPTION WHEN NO_DATA_FOUND')
    candidate,report=generate(raw);files=_members(candidate)
    assert len(report['lookup_receipt']['generated_operations'])==2
    assert report['metadata']['behavior_coverage']=={'total':3,'counts':{'generated_wired_adapted':2,'unsupported':1}}
    assert not any(b'DELETE FROM OTHER_TABLE' in b for n,b in files.items() if n.endswith('.apx'))


def test_source_bind_uses_block_qualification_to_prevent_column_capture():
    _,report=generate();op=report['lookup_plan']['operations'][0]
    code=native_lookups._source_body(op,99);label=native_lookups._block_label(op)
    assert code.startswith('<<'+label+'>>')
    assert label+'.l_input_1' in code and label+'.l_output_1' in code
    assert not re.search(r'=\s*l_input_\d',code)


def test_editable_fetched_cased_input_remains_a_gap_without_changed_value_context():
    path=Path(__file__).resolve().parents[2]/'examples/xml-mapping/source_lookups.xml'
    raw=path.read_bytes().replace(b'UpdateAllowed="false"',b'UpdateAllowed="true" CaseRestriction="Upper"')
    _,report=generate(raw)
    assert len(report['lookup_receipt']['generated_operations'])==2
    assert report['lookup_receipt']['unrendered_operations'][0]['reason']=='source_lookup_edited_case_context_required'
    assert report['metadata']['behavior_coverage']['counts']=={'generated_wired_adapted':2,'unsupported':1}
