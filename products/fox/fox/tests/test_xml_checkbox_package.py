"""Synthetic package assembly checks; no SQLcl, Oracle or browser runtime claim."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
from xml.etree import ElementTree as ET

import pytest

from forms2apex import native_blueprint, native_record_groups
from fox import forms_checkbox_group, forms_checkbox_workspace
from fox import xml_mapping as mapping
from fox.forms_native_plan import POLICY_ID, build_native_prototype_plan
from fox.forms_understanding_packet import _build, generation_sources


def documents(*, count=1, unsupported=False, event=True):
    root = ET.Element('FormModule', Name='DELIVERY')
    for index in range(count):
        block = ET.SubElement(root, 'Block', Name=f'DRAFTS{index}', DatabaseBlock='true',
                              QueryDataSourceName=f'DELIVERIES{index}')
        for name in ('SCHEDULE', 'DAY_A', 'DAY_B'):
            item = ET.SubElement(block, 'Item', Name=name, ItemType='Check Box', DatabaseItem='true',
                DataType='Char', ColumnName=name, MaximumLength='1', DataLengthSemantics='BYTE',
                CheckedValue='Y', UncheckedValue='N', InitializeValue='N',
                CheckBoxOtherValues='Not Allowed', Prompt=name)
            if name == 'SCHEDULE' and event:
                code = """BEGIN
IF :SCHEDULE = 'Y' THEN
 SET_ITEM_PROPERTY('DAY_A', ENABLED, PROPERTY_TRUE);
 SET_ITEM_PROPERTY('DAY_B', ENABLED, PROPERTY_TRUE);
ELSE
 :DAY_A := 'N'; :DAY_B := 'N';
 SET_ITEM_PROPERTY('DAY_A', ENABLED, PROPERTY_FALSE);
 SET_ITEM_PROPERTY('DAY_B', ENABLED, PROPERTY_FALSE);
END IF;
END;"""
                if unsupported:
                    code += ' COMMIT;'
                ET.SubElement(item, 'Trigger', Name='WHEN-CHECKBOX-CHANGED', TriggerText=code)
        # Explicitly retained source-entry rule; the checkbox adapter must not claim it.
        ET.SubElement(block, 'Trigger', Name='WHEN-NEW-RECORD-INSTANCE', TriggerText='NULL;')
    return [('delivery.xml', ET.tostring(root))]


def prepare(docs=None):
    docs = documents() if docs is None else docs
    with generation_sources(docs):
        packet, chunks = _build(docs)
        spec = build_native_prototype_plan(docs, mapping._blueprint(packet), project_id='checkbox-package',
            project_name='Synthetic checkbox assembly', approved_policy_id=POLICY_ID)['rendering_spec']
        trace = native_blueprint.prototype_trace(spec)
        objects = {obj['id']: obj for source in packet['sources'] for obj in source['facts']['objects']}
        for block in trace['blocks']:
            block['source_module_id'] = objects[block['source_block_id']]['module_id']
        files = mapping._members(native_blueprint.deterministic_prototype_zip(spec))
        files['fox-package/supporting-schema.sql'] = native_blueprint.render_prototype_schema(spec).encode()
    return docs, packet, chunks, trace, files


def test_normal_generation_connects_bounded_drafts_and_preserves_source_event_status():
    docs = documents(count=2)
    before = deepcopy(docs)
    candidate, report = mapping.generate_xml_package(docs, 'checkbox-package', 'Synthetic checkbox assembly', POLICY_ID)
    assert docs == before
    assert (candidate, report) == mapping.generate_xml_package(docs, 'checkbox-package', 'Synthetic checkbox assembly', POLICY_ID)
    files = mapping._members(candidate)
    descriptor = report['checkbox_drafts']
    assert descriptor == report['metadata']['checkbox_drafts']
    assert descriptor['generated_group_count'] == 2 and descriptor['gap_count'] == 0
    receipt = json.loads(files[descriptor['member']])
    assert hashlib.sha256(files[descriptor['member']]).hexdigest() == descriptor['sha256']
    assert receipt['converted_code_unit_count'] == descriptor['converted_code_unit_count'] == 0
    assert files['fox-package/sources/delivery.xml'] == docs[0][1]
    assert not report['metadata']['structural_only']
    assert 'fox.checkbox.session-draft' in report['metadata']['applied_rule_ids']
    assert 'forms_checkbox_group.py' in report['metadata']['implementation_sources']
    assert 'forms_checkbox_workspace.py' in report['metadata']['implementation_sources']
    assert b'No source unit is counted as converted' in files['fox-package/README.md']
    for key in ('null_other_values_accepted', 'original_access_rights_proven',
                'record_entry_initialization_implemented', 'durable_synthetic_save',
                'customer_table_writes', 'runtime_verified', 'business_accepted'):
        assert descriptor[key] is False
    ledger = {row['source_unit_id']: row for row in report['mapping_ledger']['code_units']}
    assert len({g['page_id'] for g in descriptor['groups']}) == 2
    assert len({g['native_target']['draft_table'] for g in receipt['groups']}) == 2
    for group, summary in zip(receipt['groups'], descriptor['groups'], strict=True):
        target = group['native_target']
        assert ledger[group['source_unit_id']]['status'] != 'generated_wired_adapted'
        assert ledger[group['source_unit_id']]['source_unit_sha256'] == group['source_unit_sha256']
        assert group['record_entry_rules'] and not group['record_entry_initialization_implemented']
        assert summary['controller'] == 'SCHEDULE' and summary['dependents'] == ['DAY_A', 'DAY_B']
        assert summary['reset_on_manual_off'] is True
        assert target['page_file'] in report['apex_members']
        assert target['draft_table'].encode() in files['fox-package/supporting-schema.sql']
        report_page = files[group['report_file']]
        assert f"column FOX_EDIT_{target['page_id']} (".encode() in report_page
        assert b'region checkbox-entry-' not in report_page
        assert target['entry_mode'] == 'source_report_row'
        assert 'source_event_proof' not in summary and 'checked_value' not in summary


def test_non_candidate_preflight_does_not_rebuild_checkbox_source(monkeypatch):
    args = prepare(documents(event=False))
    before = deepcopy(args)
    def forbidden(*_):
        raise AssertionError('Non-checkbox forms must not run the checkbox compiler.')
    monkeypatch.setattr(forms_checkbox_group, 'build_checkbox_groups', forbidden)
    assert mapping._attach_checkbox_drafts(*args) is None
    assert args == before


def test_source_entry_region_and_existing_links_are_preserved():
    args = prepare()
    files, trace = args[-1], args[-2]
    path = trace['blocks'][0]['report_file']
    fragment = '    region preserved-entry (\n        name: Existing workflow entry\n    )\n'
    files[path] = native_record_groups._append(files[path].decode(), fragment).encode()
    original = files[path]
    descriptor = mapping._attach_checkbox_drafts(*args)
    assert fragment.encode() in files[path]
    assert b'region checkbox-entry-' not in files[path]
    assert files[path].count(b'        type: interactiveReport\n') == 1
    assert b'column FOX_EDIT_8100 (' in files[path]
    for column in trace['blocks'][0]['items']:
        declaration = f"        column {column['column']} (\n".encode()
        assert declaration in original and declaration in files[path]
    assert descriptor['generated_group_count'] == 1


def test_first_free_page_allocation_observes_filename_and_declared_page_ids():
    args = prepare(documents(count=2))
    files = args[-1]
    files['pages/p08100-existing.apx'] = b'page 8100 (\n)\n'
    files['pages/custom.apx'] = b'page 8101 (\n)\n'
    descriptor = mapping._attach_checkbox_drafts(*args)
    assert [group['page_id'] for group in descriptor['groups']] == [8102, 8103]
    assert files['pages/custom.apx'] == b'page 8101 (\n)\n'


def test_page_capacity_leaves_explicit_gap_without_overwriting_or_adding_ddl():
    args = prepare()
    files = args[-1]
    schema = files['fox-package/supporting-schema.sql']
    for page in range(8100, 10000):
        files[f'pages/p{page:05d}-existing.apx'] = f'page {page} (\n)\n'.encode()
    before = deepcopy(files)
    descriptor = mapping._attach_checkbox_drafts(*args)
    assert not descriptor['groups'] and descriptor['gap_count'] == 1
    assert descriptor['gaps'][0]['reason'] == 'CHECKBOX_PACKAGE_PAGE_CAPACITY'
    assert files['fox-package/supporting-schema.sql'] == schema
    assert all(files[name] == raw for name, raw in before.items())


@pytest.mark.parametrize('collision', ['draft_table', 'alias', 'missing_report', 'wrong_report'])
def test_existing_table_alias_or_unbound_report_is_rejected(collision):
    args = prepare()
    group, = forms_checkbox_group.build_checkbox_groups(*args[:4])['groups']
    rendered = forms_checkbox_workspace.render_checkbox_workspace(group, 8100)
    files = args[-1]
    if collision == 'draft_table':
        files['fox-package/supporting-schema.sql'] += rendered['supporting_sql']
    elif collision == 'alias':
        files['pages/p00099-other.apx'] = b'page 99 (\n    alias: FOX_CHECKBOX_8100\n)\n'
    elif collision == 'missing_report':
        del files[group['report_file']]
    else:
        files[group['report_file']] = b'page 999 (\n)\n'
    with pytest.raises(ValueError, match='Checkbox'):
        mapping._attach_checkbox_drafts(*args)


def test_unsupported_whole_event_is_visible_and_never_executed():
    candidate, report = mapping.generate_xml_package(documents(unsupported=True), 'checkbox-package', 'Unsupported event', POLICY_ID)
    files = mapping._members(candidate)
    descriptor = report['checkbox_drafts']
    assert descriptor['generated_group_count'] == 0 and descriptor['gap_count'] == 1
    assert descriptor['gaps'][0]['reason'] == 'CHECKBOX_GROUP_WHOLE_EVENT_GRAMMAR'
    assert 'fox.checkbox.session-draft' not in report['metadata']['applied_rule_ids']
    assert not any(re.search(r'\bCOMMIT\s*;', raw.decode(), re.I)
                   for name, raw in files.items() if name.endswith('.apx'))


def test_forms_without_changed_event_have_no_optional_draft_descriptor():
    candidate, report = mapping.generate_xml_package(documents(event=False), 'checkbox-package', 'No changed event', POLICY_ID)
    assert 'checkbox_drafts' not in report and 'checkbox_drafts' not in report['metadata']
    assert 'fox-package/checkbox-drafts.json' not in mapping._members(candidate)


def test_checkbox_implementation_fingerprints_cover_both_actual_source_files():
    catalog = mapping.mapping_catalog()
    for module in (forms_checkbox_group, forms_checkbox_workspace):
        path = Path(module.__file__)
        assert catalog['implementation_sources'][path.name] == hashlib.sha256(path.read_bytes()).hexdigest()


def _custom_report(args, projection, suffix=''):
    block = args[-2]['blocks'][0]
    table = block['table_name']
    path = block['report_file']
    text = args[-1][path].decode()
    original = f'            type: tableView\n            tableName: {table}\n'
    assert text.count(original) == 1
    columns = ['FOX_ROW_ID'] + [item['column'] for item in block['items']]
    sql = projection(columns) + '\nfrom ' + table + ' r' + suffix
    formatted = '\n'.join('                ' + line for line in sql.splitlines())
    args[-1][path] = text.replace(original, '            type: sqlQuery\n            sqlQuery:\n'
                                 '                \x60\x60\x60sql\n' + formatted + '\n                \x60\x60\x60\n').encode()
    return path


def test_link_uses_exact_filtered_row_and_retains_display_expression_and_order():
    from textwrap import dedent
    from test_forms_checkbox_workspace import database

    args = prepare()
    block = args[-2]['blocks'][0]
    suffix = '\nwhere r.FOX_ROW_ID > 10\norder by r.FOX_ROW_ID desc'
    def projection(cols):
        return 'select ' + ', '.join('r.' + c for c in cols[:-1]) + ', upper(r.' + cols[-1] + ') as ' + cols[-1]
    path = _custom_report(args, projection, suffix)
    original = args[-1][path].decode()
    relation = '    region secondary-action (\n        name: Related rows\n    )\n'
    args[-1][path] = native_record_groups._append(original, relation).encode()
    result = mapping._attach_checkbox_drafts(*args)
    assert result['generated_group_count'] == 1 and not result['gaps']
    report = args[-1][path].decode()
    assert relation in report and 'P8100_ID0: "#FOX_ROW_ID#"' in report
    assert 'P8100_TOKEN: "#FOX_TOKEN_8100#"' in report
    sql = dedent(re.search(r'\x60{3}sql\n(.*?)\n *\x60{3}', report, re.S)[1])
    assert sql.endswith(suffix) and projection(['FOX_ROW_ID'] + [i['column'] for i in block['items']]) in sql
    db = database()
    fields = [i['column'] for i in block['items']]
    table = block['table_name']
    db.execute('create table ' + table + '(FOX_ROW_ID integer,' + ','.join(fields) + ')')
    db.executemany('insert into ' + table + ' values(?,?,?,?)',
                   [(10,'Y','Y','N'),(20,'N','Y','N'),(30,'Y','N','N'),(40,None,'N','Y'),(50,'X','Y','Y')])
    sql = sql.replace('utl_raw.cast_to_raw', 'CAST_TO_RAW')
    records = db.execute(sql).fetchall()
    assert [r[0] for r in records] == [50,40,30,20]
    assert all(r[-3:-1] == (None,None) and r[-1].startswith('Unavailable') for r in records[:2])
    assert all(len(r[-3]) == 64 and r[-2:] == ('Open draft','Available') for r in records[2:])
    assert records[2][-3] != records[3][-3]


@pytest.mark.parametrize('projection,suffix', [
    (lambda c: 'select ' + ', '.join(c[1:]), ''),
    (lambda c: 'select 0 as FOX_ROW_ID, ' + ', '.join(c[1:]), ''),
    (lambda c: 'select count(*) as FOX_ROW_ID, ' + ', '.join(c[1:]), ''),
    (lambda c: 'select FOX_ROW_ID, count(*) as ' + c[1] + ', ' + ', '.join(c[2:]), ''),
    (lambda c: 'select ' + ', '.join(c), ' group by FOX_ROW_ID'),
])
def test_report_action_does_not_bind_an_unproved_row(projection, suffix):
    args = prepare()
    path = _custom_report(args, projection, suffix)
    before = args[-1][path]
    result = mapping._attach_checkbox_drafts(*args)
    assert result['generated_group_count'] == 0 and result['gap_count'] == 1
    assert before == args[-1][path]
    assert not any('fox_checkbox_8100.apx' in n for n in args[-1])


def test_two_independent_controllers_link_from_one_report():
    raw = documents()[0][1]
    root = ET.fromstring(raw)
    block = root.find('Block')
    for item in list(block.findall('Item')):
        duplicate = ET.fromstring(ET.tostring(item).replace(b'SCHEDULE',b'BACKUP')
                                  .replace(b'DAY_A',b'ALT_A').replace(b'DAY_B',b'ALT_B'))
        block.append(duplicate)
    args = prepare([('delivery.xml',ET.tostring(root))])
    d = mapping._attach_checkbox_drafts(*args)
    assert d['generated_group_count'] == 2 and not d['gaps']
    text = args[-1][args[-2]['blocks'][0]['report_file']].decode()
    for g in d['groups']:
        page = g['page_id']
        assert f'P{page}_TOKEN: "#FOX_TOKEN_{page}#"' in text
        assert text.count(f'column FOX_EDIT_{page} (') == 1
    assert text.count('        type: interactiveReport\n') == 1


def test_existing_display_projection_and_checkbox_action_share_default_report():
    from test_forms_display_projection import SOURCE
    root = ET.fromstring(SOURCE)
    block = root.find('Block')
    for item in ET.fromstring(documents()[0][1]).findall('Block/Item'):
        block.append(item)
    raw, result = mapping.generate_xml_package([('accounts.xml',ET.tostring(root))], 'display-checkbox',
                                                'Account schedules',POLICY_ID)
    files = mapping._members(raw)
    projections = json.loads(files[result['metadata']['saved_display_fields']['member']])['applied']
    assert len(projections) == 1
    entry, = result['checkbox_drafts']['groups']
    report = files[json.loads(files['fox-package/source-to-page.json'])['blocks'][0]['report_file']].decode()
    assert 'displayColumn ' + projections[0]['target_column'] in report
    assert f"displayColumn FOX_EDIT_{entry['page_id']}" in report
    assert 'region checkbox-entry-' not in report


def test_oversize_row_query_keeps_labelled_all_rows_fallback():
    args = prepare()
    # This valid base report fits the original SQL budget. The additional
    # source fingerprint and admission checks cannot share that budget.
    path = _custom_report(args, lambda cols: 'select ' + ', '.join(cols),
                          '\nwhere ' + ' and '.join('r.FOX_ROW_ID > 0' for _ in range(1430)))
    original = args[-1][path]
    d = mapping._attach_checkbox_drafts(*args)
    assert d['generated_group_count'] == 1 and not d['gaps']
    receipt = json.loads(args[-1][d['member']])
    assert receipt['groups'][0]['native_target']['entry_mode'] == 'all_rows_selector_at_query_limit'
    assert original[:-2] in args[-1][path]
    assert b'All saved rows for checkbox drafts (separate from the report filter)' in args[-1][path]
