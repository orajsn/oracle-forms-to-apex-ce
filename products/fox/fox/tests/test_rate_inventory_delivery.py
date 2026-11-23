"""Bounded optional evidence must preserve existing native bytes and complete counts."""
from copy import deepcopy
import json

import pytest

from fox import xml_mapping as mapping
from fox.xml_mapping_job import _saved_rate_field_coverage


def fixture(count=130):
    workspace = {'source_block_id': 'block-a', 'page_file': 'pages/rates.apx'}
    meta = {'source_binding': 'a' * 64, 'apex_members': {}, 'saved_lookup_workspaces': [workspace]}
    items = [{'id': f'field-{i}', 'name': f'F{i}', 'label': f'Field {i}', 'status': 'saved',
              'database_item': True, 'note': 'Included in the saved projection.'} for i in range(count)]
    items[-1].update(status='pending', note='The list binding still needs confirmation.')
    items[0]['label'] = ' \t'
    items[1].update(label=None, name=None)
    w = {'block_id': 'block-a', 'block': 'RATES', 'page_file': workspace['page_file'],
         'items': items, 'counts': {'total': count, 'saved': count-1, 'parent_linked': 0,
                                    'pending': 1, 'control': 0}}
    report = {'scope': 'fox-rate-field-coverage-v1', 'schema_version': 1,
              'source_binding': meta['source_binding'], 'workspaces': [w]}
    files = {'fox-package/metadata.json': mapping._bytes(meta), 'application.apx': b'app synthetic ()'}
    return meta, files, report


def test_size_and_ui_bounds_keep_counts_and_explain_a_pending_item(monkeypatch):
    meta, files, report = fixture()
    before = deepcopy(report)
    monkeypatch.setattr(mapping, 'MAX_ZIP', 9000)
    mapping._attach_rate_field_coverage(files, meta, report)
    assert report == before and files['application.apx'] == b'app synthetic ()'
    assert len(mapping._zip(files)) < mapping.MAX_ZIP
    summary = _saved_rate_field_coverage(meta, files)
    w, = summary['workspaces']
    assert w['limited'] and w['counts'] == {'saved': 129, 'pending': 1, 'control': 0, 'parent_linked': 0}
    assert len(w['items']) < 100 and w['items'][0]['status'] == 'pending'
    assert any(row['name'] == row['label'] == 'F0' for row in w['items'])
    assert any(row['name'] == row['label'] == 'field-1' for row in w['items'])
    desc = meta['rate_field_coverage']
    files[desc['member']] += b' '
    with pytest.raises(ValueError, match='binding'):
        _saved_rate_field_coverage(meta, files)


def test_existing_result_survives_when_supplement_cannot_fit(monkeypatch):
    meta, files, report = fixture(2)
    prior = deepcopy((meta, files))
    monkeypatch.setattr(mapping, 'MAX_ZIP', len(mapping._zip(files)) + 200)
    mapping._attach_rate_field_coverage(files, meta, report)
    assert (meta, files) == prior
    assert _saved_rate_field_coverage(meta, files) is None


def test_an_inconsistent_full_report_is_rejected_even_if_descriptor_matches():
    meta, files, report = fixture(2)
    mapping._attach_rate_field_coverage(files, meta, report)
    desc = meta['rate_field_coverage']
    saved = json.loads(files[desc['member']])
    saved['workspaces'][0]['items'][0]['status'] = 'pending'
    files[desc['member']] = mapping._bytes(saved)
    desc['sha256'] = mapping._sha(files[desc['member']])
    with pytest.raises(ValueError, match='counts'):
        _saved_rate_field_coverage(meta, files)
