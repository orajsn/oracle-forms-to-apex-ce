"""Use the complete generator to verify source fields as presented on a saved run."""
import json
from xml.etree import ElementTree as ET

import pytest

from fox.forms_native_plan import POLICY_ID
from fox.prototype_export_only import _members
from fox.xml_mapping import generate_xml_package
from fox.xml_mapping_job import _rate_number_summary
from test_forms_rate_choices import SOURCE


def test_public_summary_keeps_numeric_inputs_and_unresolved_events_distinct():
    form = ET.fromstring(SOURCE)
    block = form.find("./Block[@Name='LINES']")
    block.set('DatabaseBlock', 'true')
    block.set('QueryDataSourceType', 'Table')
    for item in block.findall('Item'):
        item.set('DataType', 'Char')
        item.attrib.setdefault('DatabaseItem', 'true')
    for name, prompt in [('AMOUNT', 'Amount'), ('ADJUSTMENT', 'Adjustment')]:
        field = ET.SubElement(block, 'Item', Name=name, Prompt=prompt, ItemType='Text Item',
                              DataType='Number', DatabaseItem='true', ColumnName=name,
                              MaximumLength='12', FormatMask='99,999,990.90')
        if name == 'ADJUSTMENT':
            ET.SubElement(field, 'Trigger', Name='WHEN-VALIDATE-ITEM', TriggerText='BEGIN NULL; END;')
    package, report = generate_xml_package([('shipping.xml', ET.tostring(form))],
                                           'price-ui', 'Synthetic prices', POLICY_ID)
    files = _members(package)
    meta = report['metadata']
    summary = _rate_number_summary(meta, files)
    assert not summary['limited']
    rows = {row['item']: row for row in summary['items']}
    assert set(rows) == {'AMOUNT', 'ADJUSTMENT'}
    assert rows['AMOUNT']['stored'] and rows['AMOUNT']['label'] == 'Amount'
    assert not rows['ADJUSTMENT']['stored'] and 'event' in rows['ADJUSTMENT']['note']
    assert meta['row_lookup_summary'] == {'editors': 1, 'mapped_returns': 5}
    assert 'fox.row.stored-number' in meta['applied_rule_ids']
    receipt = 'fox-package/lov-return-receipt.json'
    mismatched = json.loads(files[receipt])
    op = next(o for o in mismatched['generated_operations'] if o.get('stored_numbers'))
    op['stored_numbers']['source_block_id'] = 'different'
    with pytest.raises(ValueError, match='evidence'):
        _rate_number_summary(meta, {**files, receipt: json.dumps(mismatched).encode()})


def test_legacy_saved_run_has_no_numeric_summary():
    assert _rate_number_summary({'saved_lookup_workspaces': [{'page_file': 'old.apx'}]}, {}) is None
