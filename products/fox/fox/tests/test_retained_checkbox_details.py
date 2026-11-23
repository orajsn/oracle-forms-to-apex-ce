"""Saved synthetic API/package checks. Compiler is a labelled test double.

No SQLcl, Oracle, installed APEX, provider or business acceptance is claimed.
"""
from copy import deepcopy
import json

import pytest

from fox import xml_mapping_job as jobs
from fox import xml_mapping as mapping
from fox.forms_native_plan import POLICY_ID
from test_xml_checkbox_package import documents
from test_xml_mapping_web import (client, installed_compiler, settings, no_external_actions,
                                  finish, connection)


@pytest.fixture(scope='module')
def base_package():
    package, report = mapping.generate_xml_package(documents(), 'retained-checkbox', 'Retained synthetic checkbox', POLICY_ID)
    return report['metadata'], report['mapping_ledger'], mapping._members(package)


@pytest.fixture
def saved(base_package):
    return deepcopy(base_package)


def replace_receipt(metadata, files, mutate):
    member = metadata['checkbox_drafts']['member']
    receipt = json.loads(files[member])
    mutate(receipt)
    files[member] = jobs.encoded(receipt)
    metadata['checkbox_drafts']['sha256'] = jobs.sha(files[member])
    return receipt


def test_verified_projection_exposes_only_declared_presentation_fields(saved):
    metadata, ledger, files = saved
    before = deepcopy(saved)
    summary = jobs._saved_checkbox_summary(*saved)
    receipt = json.loads(files[metadata['checkbox_drafts']['member']])
    assert receipt['groups'][0]['input_policy']['source_other_values_policy_proven'] is True
    assert receipt['groups'][0]['input_policy']['other_value_display_implemented'] is False
    assert summary == metadata['checkbox_drafts']
    assert saved == before
    group, = summary['groups']
    assert group['controller'] == 'SCHEDULE' and group['dependents'] == ['DAY_A', 'DAY_B']
    assert set(group) == {'source_unit_id', 'source_unit_sha256', 'source_block_id', 'source_block_name',
                          'controller', 'dependents', 'page_id', 'page_file', 'reset_on_manual_off'}
    assert summary['converted_code_unit_count'] == 0
    text = json.dumps(summary)
    assert all(key not in text for key in ('source_event_proof', 'source_snapshot_sql', 'checked_value',
                                          'supporting_sql', 'draft_table', 'TriggerText'))


def test_old_package_without_descriptor_does_not_acquire_new_capabilities(saved):
    metadata, ledger, files = saved
    del metadata['checkbox_drafts']
    assert jobs._saved_checkbox_summary(metadata, ledger, files) is None


@pytest.mark.parametrize('change', ['hash', 'member', 'missing', 'scope', 'count', 'bool_count',
                                   'permission', 'record_entry', 'database_save', 'unknown_key', 'extra_group_key'])
def test_descriptor_tamper_is_rejected(saved, change):
    metadata, ledger, files = saved
    descriptor = metadata['checkbox_drafts']
    if change == 'hash': descriptor['sha256'] = '0' * 64
    elif change == 'member': descriptor['member'] = '../checkbox-drafts.json'
    elif change == 'missing': del files[descriptor['member']]
    elif change == 'scope': descriptor['scope'] = 'full_conversion'
    elif change == 'count': descriptor['generated_group_count'] += 1
    elif change == 'bool_count': descriptor['generated_group_count'] = True
    elif change == 'permission': descriptor['original_access_rights_proven'] = True
    elif change == 'record_entry': descriptor['record_entry_initialization_implemented'] = True
    elif change == 'database_save': descriptor['durable_synthetic_save'] = True
    elif change == 'unknown_key': descriptor['sql'] = 'select sensitive_value from anything'
    else: descriptor['groups'][0]['sql'] = 'begin null; end;'
    with pytest.raises(ValueError, match='checkbox'):
        jobs._saved_checkbox_summary(metadata, ledger, files)


@pytest.mark.parametrize('change', ['schema', 'source_binding', 'project', 'runtime', 'unit_hash',
                                   'block', 'page', 'target_permission', 'target_field', 'duplicate_group'])
def test_hash_consistent_but_inconsistent_receipt_is_rejected(saved, change):
    metadata, ledger, files = saved
    def mutate(receipt):
        group = receipt['groups'][0]
        if change == 'schema': receipt['schema_version'] = True
        elif change == 'source_binding': receipt['source_binding'] = '0' * 64
        elif change == 'project': receipt['project_id'] = 'another-project'
        elif change == 'runtime': receipt['runtime_verified'] = True
        elif change == 'unit_hash': group['source_unit_sha256'] = '0' * 64
        elif change == 'block': group['source_block_id'] = 'ff1-' + '0' * 24
        elif change == 'page': group['native_target']['page_file'] = 'pages/not-the-generated-page.apx'
        elif change == 'target_permission': group['native_target']['business_table_writes'] = True
        elif change == 'target_field': group['native_target']['fields'][0]['source_name'] = 'OTHER'
        else: receipt['groups'].append(deepcopy(group))
    replace_receipt(metadata, files, mutate)
    with pytest.raises(ValueError, match='checkbox'):
        jobs._saved_checkbox_summary(metadata, ledger, files)


@pytest.mark.parametrize('name', ['<script>alert(1)</script>', 'SCHEDULE\nselect secret', 'A' * 129])
def test_raw_source_names_cannot_smuggle_code_into_ui_summary(saved, name):
    metadata, ledger, files = saved
    def mutate(receipt):
        receipt['groups'][0]['controller']['source_name'] = name
        receipt['groups'][0]['native_target']['fields'][0]['source_name'] = name
    replace_receipt(metadata, files, mutate)
    metadata['checkbox_drafts']['groups'][0]['controller'] = name
    with pytest.raises(ValueError, match='checkbox'):
        jobs._saved_checkbox_summary(metadata, ledger, files)


def test_raw_receipt_unknown_data_never_spreads_into_frontend(saved):
    metadata, ledger, files = saved
    replace_receipt(metadata, files, lambda receipt: receipt['groups'][0].update(extra_sql='select secret from hidden'))
    summary = jobs._saved_checkbox_summary(metadata, ledger, files)
    assert 'extra_sql' not in json.dumps(summary) and 'select secret' not in json.dumps(summary)


@pytest.mark.parametrize('raw', [b'{"schema_version":1,"schema_version":1}', b'{"schema_version":NaN}', b'{'])
def test_malformed_or_ambiguous_json_rejected(saved, raw):
    metadata, ledger, files = saved
    member = metadata['checkbox_drafts']['member']
    files[member] = raw
    metadata['checkbox_drafts']['sha256'] = jobs.sha(raw)
    with pytest.raises(ValueError):
        jobs._saved_checkbox_summary(metadata, ledger, files)


def test_bounded_receipt_is_checked_before_parsing(saved, monkeypatch):
    monkeypatch.setattr(jobs, 'MAX_SNAPSHOT_BYTES', 1)
    with pytest.raises(ValueError, match='checkbox'):
        jobs._saved_checkbox_summary(*saved)


def test_saved_page_bytes_must_match_apex_member_fingerprint(saved):
    metadata, ledger, files = saved
    page = metadata['checkbox_drafts']['groups'][0]['page_file']
    files[page] += b'\n'
    with pytest.raises(ValueError, match='checkbox'):
        jobs._saved_checkbox_summary(metadata, ledger, files)


def test_gap_reason_free_text_is_replaced_with_fixed_scoped_message():
    package, report = mapping.generate_xml_package(documents(unsupported=True), 'gap-checkbox', 'Gap checkbox', POLICY_ID)
    metadata, ledger, files = report['metadata'], report['mapping_ledger'], mapping._members(package)
    reason = 'select PRIVATE_TEXT from original_source;'
    replace_receipt(metadata, files, lambda receipt: receipt['gaps'][0].update(reason=reason))
    metadata['checkbox_drafts']['gaps'][0]['reason'] = reason
    summary = jobs._saved_checkbox_summary(metadata, ledger, files)
    assert summary['gaps'][0]['reason'] == 'CHECKBOX_WORKSPACE_ADMISSION_UNRESOLVED'
    assert 'PRIVATE_TEXT' not in json.dumps(summary)


def test_normal_saved_status_details_and_download_keep_summary_without_regeneration(client, monkeypatch):
    c, root, pid, body, run = finish(client, documents())
    rid = run['id']
    summary = run['checkbox_drafts']
    assert summary['generated_group_count'] == 1 and summary['groups'][0]['controller'] == 'SCHEDULE'
    def forbidden(*_args, **_kwargs):
        raise AssertionError('Retained reads must not regenerate or compile.')
    monkeypatch.setattr(mapping, 'generate_xml_package', forbidden)
    monkeypatch.setattr(mapping, 'validate_offline', forbidden)
    current = c.get(f'/api/projects/{pid}/xml-mapping/runs/{rid}').json()
    assert current['state'] == 'GENERATED' and current['checkbox_drafts'] == summary
    assert c.get(f'/api/projects/{pid}/xml-mapping').json()['runs'][0]['checkbox_drafts'] == summary
    assert c.get(f'/api/projects/{pid}').json()['runs'][0]['checkbox_drafts'] == summary
    with connection(root)() as db:
        row = db.execute('SELECT * FROM runs WHERE id=?', (rid,)).fetchone()
        package, details = jobs.checked_output(db, root, row)
    assert details['checkbox_drafts'] == summary and jobs.sha(package) == current['package_sha256']
    response = c.get(current['download_url'])
    assert response.status_code == 200 and response.content == package
    assert current['runtime_verified'] is False and current['business_behavior_accepted'] is False


def test_normal_old_status_remains_compatible_without_checkbox_field(client):
    c, root, pid, body, run = finish(client)
    assert run['state'] == 'GENERATED' and 'checkbox_drafts' not in run
    assert c.get(f"/api/projects/{pid}/xml-mapping/runs/{run['id']}").json() == run


def test_normal_tampered_saved_package_is_not_exposed_or_replayed(client, monkeypatch):
    c, root, pid, body, run = finish(client, documents())
    path = root / 'jobs' / run['id'] / 'xml-mapping' / 'apexlang.zip'
    path.write_bytes(path.read_bytes() + b' tampered')
    def forbidden(*_args, **_kwargs):
        raise AssertionError('Tamper must not trigger generation.')
    monkeypatch.setattr(mapping, 'generate_xml_package', forbidden)
    current = c.get(f"/api/projects/{pid}/xml-mapping/runs/{run['id']}").json()
    assert current['state'] == 'ATTENTION' and 'checkbox_drafts' not in current
    assert current['download_url'] is None
    assert c.get(run['download_url']).status_code == 409
