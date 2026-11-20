from pathlib import Path
import json
import pytest
from fox.xml_mapping import generate_xml_package, _members
from fox.forms_native_plan import POLICY_ID
from fox.forms_session_defaults import parse_default

BODY = "begin select nvl(PERCENTAGE,0) into :global.rate from RATE_PARAMETERS where OFFICE=:global.office; exception when others then null; end;"

def test_defaults_preserve_previous_value_on_lookup_failure_and_gate_once():
    xml = ('<FormModule Name="RATES"><Block Name="LAB" DatabaseBlock="true">'
           '<Item Name="OFFICE" DataType="Char" DatabaseItem="true" ItemType="Text Item" MaximumLength="10"/>'
           '</Block><Trigger Name="WHEN-NEW-FORM-INSTANCE" TriggerText="'+BODY+'"/></FormModule>').encode()
    candidate, result = generate_xml_package([('rates.xml',xml)],'rates','Rates',POLICY_ID)
    files = _members(candidate)
    entry, = result['mapping_ledger']['session_defaults']
    assert entry['source_global']=='OFFICE' and entry['destination_global']=='RATE'
    assert result['metadata']['behavior_coverage']['counts']=={'generated_wired_adapted':1}
    assert result['metadata']['original_read_adapters']['enabled_by_default'] is False
    assert files['shared-components/app-items.apx'].count(b'sessionStateProtection: restricted')==4
    for name in entry['entry_pages']:
        page=files[name].decode()
        assert 'exception when others then null;' in page
        assert 'where OFFICE=:'+entry['input_item'] in page
        assert page.index('select nvl(PERCENTAGE,0)') < page.index(':'+entry['output_item']+' := l_value;') < page.index('exception when others then null;')
        assert "v('"+entry['readiness_item']+"')='Y'" in page
        assert 'point: beforeHeader' in page
    assert json.loads(files['fox-package/session-defaults.json'])['runtime_verified'] is False


@pytest.mark.parametrize('body',[BODY.replace('null; end;',':global.rate := null; end;'),
                                BODY.replace(':global.office',':BLOCK.office'),
                                BODY + 'commit;',BODY.replace('PERCENTAGE','MY_API()')])
def test_other_initializers_are_left_unconverted(body):
    with pytest.raises(ValueError):
        parse_default(body)
