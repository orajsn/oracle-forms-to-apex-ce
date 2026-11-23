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
        assert f"region checkbox-entry-{target['page_id']} (".encode() in files[group['report_file']]
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
    assert original[:-2] in files[path]
    assert files[path].count(b'region checkbox-entry-') == 1
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
