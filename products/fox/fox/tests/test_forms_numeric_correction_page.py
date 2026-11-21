"""Source/native generation probes; no Oracle or installed APEX runtime claim."""
from copy import deepcopy
import hashlib
import json
import re

import pytest

from forms2apex import native_buffer
from fox.forms_numeric_correction_page import apply_numeric_corrections, _chooser, _editor


def prepared(*, renamed=False):
    from test_forms_numeric_correction import source, prepare
    return prepare(source(renamed=renamed))


def only(receipt):
    assert len(receipt['adapted_operations']) == 1, receipt['gaps']
    return receipt['adapted_operations'][0]


@pytest.mark.parametrize('renamed', [False, True])
def test_source_bound_correction_is_reachable_and_preserves_existing_pages(renamed):
    args = prepared(renamed=renamed)
    before = deepcopy(args)
    files, receipt = apply_numeric_corrections(*args)
    assert args == before
    assert (files, receipt) == apply_numeric_corrections(*args)
    op = only(receipt)
    original = args[-1]
    assert {name for name in original if files[name] != original[name]} == {op['entry_file']}
    assert all(files['fox-package/sources/' + name] == raw for name, raw in args[0])
    assert files['fox-package/approval-action-receipt.json'] == original['fox-package/approval-action-receipt.json']
    approval = json.loads(original['fox-package/approval-action-receipt.json'])['adapted_operations'][0]
    assert op['entry_file'] == approval['page_file']
    assert op['readiness_query_sha256'] == hashlib.sha256(approval['readiness_query_sql'].encode()).hexdigest()
    assert op['readiness_original_page_sha256'] == hashlib.sha256(original[op['entry_file']]).hexdigest()
    assert op['readiness_final_page_sha256'] == hashlib.sha256(files[op['entry_file']]).hexdigest()
    assert op['readiness_query_unchanged']
    entry = files[op['entry_file']].decode()
    assert 'label: Correct saved bag weight' in entry
    assert native_buffer._indent(op['entry_condition_sql']) in entry
    assert native_buffer._indent(approval['readiness_query_sql']) in entry
    assert approval['selected_context_sql'] in op['entry_condition_sql']
    assert approval['weight_predicate_sql'] in op['entry_condition_sql']
    assert len(op['entry_condition_sql'].encode()) <= 4000
    assert 'type: executeCode' not in entry
    chooser = files[op['chooser_page_file']].decode()
    editor = files[op['page_file']].decode()
    assert f"page: {op['chooser_page_id']}" in entry
    assert f"page: {op['page_id']}" in chooser
    assert f"P{op['page_id']}_ROW_ID: \"#FOX_ROW_ID#\"" in chooser
    assert '#FOX_MASTER_TOKEN#' not in chooser
    assert 'linkText: Correct weight' in chooser
    assert f"P{op['page_id']}_PARENT_ID: \"&P{op['chooser_page_id']}_PARENT_ID.\"" in chooser
    assert f"P{op['page_id']}_TOKEN: \"&P{op['chooser_page_id']}_TOKEN.\"" in chooser
    for page in (chooser, editor):
        assert 'authentication: required' in page and 'pageAccessProtection: argumentsMustHaveChecksum' in page
        assert f"page: {approval['page_id']}" in page
        assert f"P{approval['page_id']}_PARENT_ID:" in page and f"P{approval['page_id']}_TOKEN:" in page
        assert 'discard that' not in page
    assert 'Use a whole number.' in editor and 'decimal point' not in editor
    assert 'Correction status' in chooser
    assert native_buffer._indent(op['visible_chooser_query_sql']) in chooser
    assert native_buffer._indent(op['visible_context_query_sql']) in editor
    # The report's outer projection cannot make a baseline/nonce selectable
    # through interactive report column controls.
    assert 'ROW_SNAPSHOT' not in op['visible_context_query_sql'].split(' from (', 1)[0]
    assert receipt['converted_code_unit_count'] == 0 and not receipt['generated_operations']
    assert receipt['synthetic_table_writes'] and op['synthetic_table_writes']
    assert all(not receipt[key] for key in ('customer_table_writes', 'approval_flag_written',
        'forms_commit_implemented', 'external_calls_enabled', 'runtime_verified', 'business_accepted'))
    assert op['source_unit_id'] != op['approval_source_unit_id']


def test_baseline_stays_server_side_and_nonce_is_protected_per_browser_form():
    files, receipt = apply_numeric_corrections(*prepared())
    op = only(receipt)
    page = files[op['page_file']].decode()
    prefix = f"P{op['page_id']}_"
    marker = re.search(r'    pageItem ' + prefix + r'MARKER \(.*?\n    \)', page, re.S)[0]
    assert 'type: displayOnly' in marker and 'storage: session' in marker
    assert 'sessionStateProtection: restricted' in marker and 'type: never' in marker
    nonce = re.search(r'    pageItem ' + prefix + r'NONCE \(.*?\n    \)', page, re.S)[0]
    assert 'type: hidden' in nonce and 'storage: request' in nonce
    assert 'sessionStateProtection: checksumRequiredSessionLevel' in nonce
    assert 'valueProtected: false' not in nonce
    assert not re.search(r'pageItem \w*(?:BASELINE|SNAPSHOT)', page)
    for name in ('STATE', 'MESSAGE'):
        item = re.search(r'    pageItem ' + prefix + name + r' \(.*?\n    \)', page, re.S)[0]
        assert 'type: displayOnly' in item and 'sessionStateProtection: restricted' in item
    value = re.search(r'    pageItem ' + prefix + r'VALUE \(.*?\n    \)', page, re.S)[0]
    assert 'type: textField' in value and 'dataType: varchar2' in value and 'trimSpaces: none' in value
    assert 'type: numberField' not in value


def test_save_is_explicit_and_failed_submit_preserves_input_and_context():
    args = prepared()
    files, receipt = apply_numeric_corrections(*args)
    op = only(receipt)
    page = files[op['page_file']].decode()
    init = re.search(r'    process open-weight-correction \(.*?\n    \)', page, re.S)[0]
    save = re.search(r'    process save-weight-correction \(.*?\n    \)', page, re.S)[0]
    branch = re.search(r'    branch return-to-weight-readiness \(.*?\n    \)', page, re.S)[0]
    cancel = re.search(r'    button cancel-weight-correction \(.*?\n    \)', page, re.S)[0]
    assert 'begin if :REQUEST is null then' in init
    assert 'point: beforeHeader' in init and 'point: processing' in save
    assert 'value: FOX_NUMERIC_SAVE' in save
    assert 'reloadOnSubmit: always' in page
    assert native_buffer._indent(op['save_code']) in save
    button = re.search(r'    button save-weight-correction \(.*?\n    \)', page, re.S)[0]
    assert f"plsqlExpression: \":P{op['page_id']}_STATE='READY'\"" in button
    assert 'BLOCKED' not in button
    assert "STATE:=case when l_error=-20062 then 'READY' else 'BLOCKED' end;" in save
    assert "in ('SAVED','UNCHANGED')" in branch and ":REQUEST='FOX_NUMERIC_SAVE'" in branch
    assert f"P{op['return_page_id']}_PARENT_ID: \"&P{op['page_id']}_PARENT_ID.\"" in branch
    assert f"P{op['return_page_id']}_TOKEN: \"&P{op['page_id']}_TOKEN.\"" in branch
    assert 'action: redirectThisApp' in cancel and 'submitPage' not in cancel
    assert 'formAutomaticRowProcessing' not in page
    # The existing numeric Continue remains a navigation/validation action.
    before = args[-1]
    assert all(files[name] == raw for name, raw in before.items() if name != op['entry_file'])


def test_repeat_application_fails_without_adding_another_save_path():
    args = prepared()
    files, _ = apply_numeric_corrections(*args)
    with pytest.raises(ValueError, match='ALREADY_APPLIED'):
        apply_numeric_corrections(*args[:-1], files)


@pytest.mark.parametrize('renamed', [False, True])
def test_exact_visible_queries_keep_distinct_saved_rows_and_no_baseline_columns(renamed):
    from test_forms_numeric_correction import Boundary
    boundary = Boundary(renamed)
    files, receipt = apply_numeric_corrections(*boundary.args)
    op = only(receipt)
    # The disposable engine boundary uses 8801. Bind the actual generated page
    # IDs explicitly; no chooser row label is used as a key.
    params = {f'P{op["chooser_page_id"]}_PARENT_ID': 1,
              f'P{op["chooser_page_id"]}_TOKEN': boundary.token}
    cursor = boundary.db.execute(boundary.adapt(op['visible_chooser_query_sql']), params)
    columns = [column[0] for column in cursor.description]
    rows = [dict(zip(columns, row)) for row in cursor]
    assert [row['FOX_ROW_ID'] for row in rows] == [1, 2]
    assert columns == ['FOX_ROW_ID', op['fields']['bag_number']['column'],
                       op['fields']['weight']['column'], 'CORRECTION_STATUS']
    params = {f'P{op["page_id"]}_PARENT_ID': 1, f'P{op["page_id"]}_TOKEN': boundary.token,
              f'P{op["page_id"]}_ROW_ID': 2}
    cursor = boundary.db.execute(boundary.adapt(op['visible_context_query_sql']), params)
    assert [column[0] for column in cursor.description] == columns[:3]
    assert cursor.fetchall()[0][0] == 2


@pytest.mark.parametrize('change', ['receipt', 'page', 'source'])
def test_missing_or_altered_readiness_cannot_render_a_correction(change):
    args = list(prepared())
    before_files = args[-1] = deepcopy(args[-1])
    approval = json.loads(before_files['fox-package/approval-action-receipt.json'])
    if change == 'receipt':
        del before_files['fox-package/approval-action-receipt.json']
    elif change == 'page':
        path = approval['adapted_operations'][0]['page_file']
        before_files[path] += b'changed'
    else:
        approval['source_binding'] = 'changed'
        before_files['fox-package/approval-action-receipt.json'] = json.dumps(approval).encode()
    unchanged = deepcopy(args)
    files, receipt = apply_numeric_corrections(*args)
    assert not receipt['adapted_operations'] and receipt['gaps']
    assert not any('fox_weight_' in name for name in files)
    assert args == unchanged


@pytest.mark.parametrize('renamed', [False, True])
def test_normal_generator_seals_correction_and_original_source(renamed):
    from test_forms_numeric_correction import source
    from fox.forms_native_plan import POLICY_ID
    from fox.prototype_export_only import _members
    from fox.xml_mapping import generate_xml_package
    docs = source(renamed=renamed)
    raw, report = generate_xml_package(docs, 'saved-weight', 'Saved bag weight', POLICY_ID)
    files = _members(raw)
    receipt = json.loads(files['fox-package/numeric-correction-receipt.json'])
    op = only(receipt)
    assert files[op['page_file']] and files[op['chooser_page_file']]
    assert json.loads(files['fox-package/numeric-correction-plan.json'])['operations']
    assert files['fox-package/sources/' + docs[0][0]] == docs[0][1]
    assert not op['whole_source_unit_converted'] and not op['approval_flag_written']
