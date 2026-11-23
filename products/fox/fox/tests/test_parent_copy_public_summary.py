"""Cross-check copied parent keys against a generated multi-choice numeric workspace."""
from copy import deepcopy
from xml.etree import ElementTree as ET

import pytest

from fox.forms_native_plan import POLICY_ID
from fox.prototype_export_only import _members
from fox.xml_mapping import generate_xml_package
from fox.xml_mapping_job import _rate_parent_summary
from test_forms_rate_numbers import SOURCE


def shipping_source(copy_second=True):
    form = ET.fromstring(SOURCE)
    account = form.find("./Block[@Name='HEADER']")
    account.set('QueryDataSourceName', 'EXAMPLE_ACCOUNTS')
    account.set('QueryDataSourceType', 'Table')
    line = form.find("./Block[@Name='LINES']")
    note = ET.SubElement(form, 'Block', Name='NOTES', DatabaseBlock='true',
                         QueryDataSourceName='EXAMPLE_NOTES', QueryDataSourceType='Table')
    for block, names in [(account, ['CUSTOMER', 'SITE']), (line, ['OWNER_CODE', 'OWNER_SITE']),
                         (note, ['NOTE_CUSTOMER', 'NOTE_SITE'])]:
        for index, name in enumerate(names):
            item = ET.SubElement(block, 'Item', Name=name, ColumnName=name, DatabaseItem='true',
                                 DataType='Char', ItemType='Text Item', MaximumLength='20')
            if block is account or index == 0:
                item.set('DataLengthSemantics', 'BYTE')
            if block is line and (index == 0 or copy_second):
                item.set('CopyValueFromItem', 'HEADER.' + ['CUSTOMER', 'SITE'][index])
    for block, condition in [('LINES', 'OWNER_CODE=HEADER.CUSTOMER AND OWNER_SITE=HEADER.SITE'),
                             ('NOTES', 'NOTES.NOTE_CUSTOMER=HEADER.CUSTOMER AND NOTES.NOTE_SITE=HEADER.SITE')]:
        ET.SubElement(account, 'Relation', Name='ACCOUNT_' + block, DetailBlock=block,
                      RelationType='Join', JoinCondition=condition, PreventMasterlessOperations='false',
                      Deferred='false', AutoQuery='false')
    return ET.tostring(form)


@pytest.mark.parametrize('copy_second', [True, False])
def test_parent_copy_summary_matches_whole_source_and_saved_workspace(copy_second):
    raw, report = generate_xml_package([('shipping.xml', shipping_source(copy_second))],
                                       'parent-copy-web', 'Synthetic scoped rates', POLICY_ID)
    files = _members(raw)
    meta = report['metadata']
    assert len(report['relation_receipt']['generated_operations']) == 2
    assert meta['row_lookup_summary'] == {'editors': 1, 'mapped_returns': 5}
    workspace, = meta['saved_lookup_workspaces']
    row, = _rate_parent_summary(meta, files)['items']
    assert row['child'] == 'LINES' and row['linked'] == copy_second
    if copy_second:
        assert row['fields'] == [{'parent': 'CUSTOMER', 'child': 'OWNER_CODE'},
                                 {'parent': 'SITE', 'child': 'OWNER_SITE'}]
        assert 'byte and character' in row['note']
        assert workspace['parent_launcher_page'] in files
        assert 'fox.row.parent-copy' in meta['applied_rule_ids']
        changed = deepcopy(meta)
        changed['saved_lookup_workspaces'][0]['copied_parent_keys'].pop()
        with pytest.raises(ValueError, match='fields'):
            _rate_parent_summary(changed, files)
    else:
        assert not row['fields'] and 'parent_launcher_page' not in workspace
        assert 'fox.row.parent-copy' not in meta['applied_rule_ids']
        assert workspace['stored_number_fields']


def test_no_parent_declaration_preserves_legacy_public_shape():
    assert _rate_parent_summary({'saved_lookup_workspaces': [{'page_file': 'old-page.apx'}]}, {}) is None
