"""Actual deterministic native baseline and adapter; no compiler/runtime doubles.

Unit assertions establish generation/bindings only. Separate retained SQLcl
proof covers syntax, not imported Oracle runtime or business acceptance.
"""
from copy import deepcopy
from html import escape
import json
import re

import pytest

from fox.forms_module_navigation import apply_module_navigation
from fox.forms_native_plan import POLICY_ID, build_native_prototype_plan
from fox.forms_understanding_packet import _build
from fox.prototype_export_only import _members
from fox.xml_mapping import _blueprint
from forms2apex import native_blueprint


def form(name, code=None, *, block='ROWS', second=False, item_type='Push Button', event='WHEN-BUTTON-PRESSED'):
    encoded = escape(code or '', quote=True).replace('\n', '&#10;')
    button = '' if code is None else (f'<Item Name="NEXT" ItemType="{item_type}" DatabaseItem="false">'
        f'<Trigger Name="{event}" TriggerText="{encoded}"/></Item>')
    body = f'<Block Name="{block}" DatabaseBlock="false"><Item Name="CODE" ItemType="Text Item" DatabaseItem="false"/>{button}</Block>'
    if second:
        body += '<Block Name="OPTIONS" DatabaseBlock="false"><Item Name="CODE" ItemType="Text Item" DatabaseItem="false"/></Block>'
    return f'<FormModule Name="{name}">{body}</FormModule>'.encode()


def documents(code="BEGIN OPEN_FORM('DETAIL'); END;", *, target='DETAIL', second=False):
    return [('caller.xml', form('CALLER', code)), ('target.xml', form(target, second=second))]


def baseline(docs=None, project_id='nav-project'):
    docs = documents() if docs is None else docs
    # Use the actual production structural planner/renderer before the adapter,
    # so adding the adapter to xml_mapping does not run it twice in these units.
    packet, chunks = _build(docs)
    packet['selection_status'] = 'NOT_SELECTED'
    plan = build_native_prototype_plan(docs, _blueprint(packet), project_id=project_id,
        project_name='Synthetic module navigation', approved_policy_id=POLICY_ID)
    candidate = native_blueprint.deterministic_prototype_zip(plan['rendering_spec'])
    files = _members(candidate)
    trace = native_blueprint.prototype_trace(plan['rendering_spec'])
    objects = {o['id']: o for s in packet['sources'] for o in s['facts']['objects']}
    for b in trace['blocks']:
        b['source_module_id'] = objects[b['source_block_id']]['module_id']
    files['fox-package/source-to-page.json'] = json.dumps(trace, sort_keys=True).encode()
    return docs, packet, chunks, trace, files


def apply(docs=None, project_id='nav-project'):
    args = baseline(docs, project_id)
    files, receipt = apply_module_navigation(*args)
    return args, files, receipt


def test_generated_package_binds_navigation_and_reports_absent_module():
    import hashlib
    from fox.xml_mapping import generate_xml_package

    def generate(docs):
        package, result = generate_xml_package(docs, 'nav-pilot', 'Cross-module pilot', POLICY_ID)
        files = _members(package)
        descriptor = result['metadata']['module_navigation']
        raw = files[descriptor['member']]
        assert hashlib.sha256(raw).hexdigest() == descriptor['sha256']
        return files, result, json.loads(raw)

    docs = documents()
    files, result, nav = generate(docs)
    op, = nav['operations']
    unit, = result['mapping_ledger']['code_units']
    assert unit['source_unit_sha256'] == op['source_unit_sha256']
    assert unit['target'] == op and unit['rule_id'] == 'fox.navigation.module-button'
    assert unit['reason'] == 'module_navigation_partly_connected'
    assert unit['status'] != 'generated_wired_adapted' and not op['whole_unit_converted']
    assert ('page: ' + str(op['target_page_id'])).encode() in files[op['caller_page_file']]
    assert 'DETAIL' in result['discrepancies']['units'][0]['message']

    _, result, nav = generate(docs[:1])
    assert not nav['operations'] and not nav['changed_members']
    gap, = result['gap_report']['gaps']
    assert gap['category'] == 'missing_source'
    assert gap['reason'] == 'module_navigation_pending' and 'DETAIL' in gap['message']

    _, result, nav = generate(docs + [('first&X.xml', form('detail'))])
    assert not nav['operations']
    assert result['gap_report']['gaps'][0]['category'] == 'review_required'
    assert 'More than one' in result['discrepancies']['units'][0]['message']
    assert len({entry['label'] for entry in nav['qualified_labels']}) == 3


def test_complete_cross_file_call_emits_native_source_button_and_module_overview():
    args, files, receipt = apply(documents(second=True))
    op, = receipt['operations']; landing, = receipt['module_pages']
    assert receipt['whole_units_converted'] == 0 and op['whole_unit_converted'] is False
    assert op['call_kind'] == 'OPEN_FORM' and op['status'] == 'manual_navigation_partial'
    assert op['literal_target'] == 'DETAIL' and op['target_module_id'] == landing['source_module_id']
    assert op['target_source_file'] == landing['source_file']
    assert len(landing['blocks']) == 2 and landing['entry_policy'] == 'explicit_generated_module_overview_not_forms_startup'
    caller = files[op['caller_page_file']].decode()
    assert 'button ' + op['button_alias'] + ' (' in caller
    assert f"page: {op['target_page_id']}" in caller
    target = files[landing['page_file']].decode()
    assert 'authentication: required' in target and 'pageAccessProtection: argumentsMustHaveChecksum' in target
    assert 'DETAIL - generated pages' in target
    assert all(f"page: {b['page_id']}" in target for b in landing['blocks'])
    assert 'Unsaved input is not transferred' in caller
    assert op['source_block_id'] == next(b['source_block_id'] for b in args[3]['blocks'] if b['page_file'] == op['caller_page_file'])
    assert receipt['runtime_verified'] is False and receipt['business_behavior_accepted'] is False
    assert all('BEGIN OPEN_FORM' not in raw.decode() for n, raw in files.items() if n.endswith('.apx'))


@pytest.mark.parametrize('code,kind', [
    ("CALL_FORM('DETAIL');", 'CALL_FORM'),
    ("begin open_form('detail'); end;", 'OPEN_FORM'),
    ("BEGIN /* comment */ OPEN_FORM('DETAIL'); -- comment\nEND;", 'OPEN_FORM'),
    ("BEGIN&#10;OPEN_FORM('DETAIL');&#10;END;", 'OPEN_FORM'),
])
def test_whole_literal_event_grammar_and_case_insensitive_module_identity(code, kind):
    _, _, receipt = apply(documents(code))
    op, = receipt['operations']
    assert op['call_kind'] == kind and not receipt['gaps']
    assert any('return stack' in s for s in op['limitations'])
    assert any('transaction' in s for s in op['limitations'])
    assert op['whole_unit_converted'] is False


@pytest.mark.parametrize('code', [
    "BEGIN OPEN_FORM('DETAIL'); COMMIT; END;", "OPEN_FORM('DETAIL'); NULL;",
    "BEGIN OPEN_FORM('DETAIL', ACTIVATE); END;", "BEGIN CALL_FORM('DETAIL', NO_HIDE); END;",
    "BEGIN OPEN_FORM(:GLOBAL.TARGET); END;", "BEGIN OPEN_FORM('DE' || 'TAIL'); END;",
    "BEGIN IF 1=1 THEN OPEN_FORM('DETAIL'); END IF; END;", "BEGIN pkg.OPEN_FORM('DETAIL'); END;",
    "BEGIN OPEN_FORM('DETAIL'); END; NULL;", "BEGIN OPEN_FORM('DETAIL.fmb'); END;",
    "BEGIN OPEN_FORM('DETAIL'); EXCEPTION WHEN OTHERS THEN NULL; END;",
])
def test_dynamic_parameters_and_any_extra_executable_source_emit_no_navigation(code):
    _, files, receipt = apply(documents(code))
    assert not receipt['operations'] and not receipt['module_pages'] and len(receipt['gaps']) == 1
    assert not any('fox_module_nav_' in n for n in files)


@pytest.mark.parametrize('code', ["MESSAGE('OPEN_FORM(''DETAIL'')');", "-- OPEN_FORM('DETAIL');\nNULL;", "/* CALL_FORM('DETAIL'); */ NULL;"])
def test_call_names_in_comments_and_strings_do_not_invent_actions_or_gaps(code):
    _, _, receipt = apply(documents(code))
    assert not receipt['operations'] and not receipt['gaps']


def test_absent_target_and_duplicate_cross_file_names_fail_closed():
    for docs, reason in [([documents()[0]], 'TARGET_SOURCE_ABSENT'),
        (documents() + [('duplicate.xml', form('detail', second=True))], 'TARGET_SOURCE_AMBIGUOUS')]:
        _, files, receipt = apply(docs)
        assert not receipt['operations'] and not receipt['module_pages']
        gap, = receipt['gaps']
        assert gap['literal_target'] == 'DETAIL' and gap['reason'] == 'MODULE_NAV_' + reason
        assert len(gap['candidate_module_ids']) == (0 if reason.endswith('ABSENT') else 2)
        assert not any('fox_module_nav_' in n for n in files)


def test_known_target_without_rendered_blocks_stays_a_gap():
    docs = [documents()[0], ('empty.xml', b'<FormModule Name="DETAIL"/>')]
    _, _, receipt = apply(docs)
    assert not receipt['operations'] and receipt['gaps'][0]['reason'] == 'MODULE_NAV_TARGET_HAS_NO_RENDERED_BLOCKS'


@pytest.mark.parametrize('item_type,event', [('Text Item','WHEN-BUTTON-PRESSED'), ('Push Button','KEY-NEXT-ITEM')])
def test_only_exact_button_event_is_eligible(item_type, event):
    docs = [('caller.xml', form('CALLER', "OPEN_FORM('DETAIL');", item_type=item_type, event=event)), documents()[1]]
    _, _, receipt = apply(docs)
    assert not receipt['operations'] and len(receipt['gaps']) == 1


def test_duplicate_source_button_events_are_not_partially_extracted():
    source = form('CALLER', "OPEN_FORM('DETAIL');")
    source = source.replace(b'</Item></Block>', b'<Trigger Name="WHEN-BUTTON-PRESSED" TriggerText="NULL;"/></Item></Block>')
    _, _, receipt = apply([('caller.xml', source), documents()[1]])
    assert not receipt['operations'] and receipt['gaps'][0]['reason'] == 'MODULE_NAV_BUTTON_EVENT_AMBIGUOUS'


def test_existing_links_preserved_and_duplicate_labels_qualified_in_pages_and_menu():
    args = baseline()
    before = deepcopy(args)
    files, receipt = apply_module_navigation(*args)
    assert args == before  # Does not mutate XML, packet, chunks, trace or member bytes.
    assert len(receipt['qualified_labels']) == 2
    for b in args[3]['blocks']:
        text = files[b['page_file']].decode()
        module = next(m for m in receipt['modules'] if m['source_module_id'] == b['source_module_id'])
        assert f"{module['name']} / ROWS" in text
    for n in ('shared-components/lists.apx', 'shared-components/breadcrumbs.apx'):
        assert re.findall(r'^\s+page: (\d+)$', files[n].decode(), re.M) == re.findall(r'^\s+page: (\d+)$', args[4][n].decode(), re.M)
    assert len(files) == len(args[4]) + 1
    for n, raw in args[4].items():
        if n not in receipt['changed_members']:
            assert files[n] == raw


def test_same_module_duplicate_block_names_fail_closed_at_existing_generator_gate():
    root = form('DETAIL', second=True).replace(b'Name="OPTIONS"', b'Name="ROWS"')
    with pytest.raises(ValueError, match='Duplicate source block or item identity'):
        apply([documents()[0], ('target.xml', root)])


def test_independent_generation_rename_input_order_and_project_isolation():
    args, files, receipt = apply()
    assert apply_module_navigation(*args) == (files, receipt)
    assert apply(list(reversed(documents())))[1:] == (files, receipt)
    renamed = [(n, b.replace(b'CALLER', b'INVOICE').replace(b'DETAIL', b'PAYMENT')) for n, b in documents()]
    _, other, mapped = apply(renamed)
    assert mapped['operations'][0]['literal_target'] == 'PAYMENT'
    assert mapped['source_binding'] != receipt['source_binding']
    assert mapped['operations'][0]['source_unit_sha256'] != receipt['operations'][0]['source_unit_sha256']
    _, separate, separate_receipt = apply(project_id='separate-project')
    assert separate['fox-package/source-to-page.json'] != files['fox-package/source-to-page.json']
    assert json.loads(separate['fox-package/source-to-page.json'])['project_id'] == 'separate-project'
    assert separate_receipt['source_binding'] == receipt['source_binding']
    assert separate_receipt['operations'][0]['target_source_file'] == receipt['operations'][0]['target_source_file']


@pytest.mark.parametrize('part', ['source','chunks','trace','page'])
def test_tampered_source_and_dangling_trace_or_page_are_rejected(part):
    args = list(baseline())
    if part == 'source': args[1]['source_binding'] = '0' * 64
    elif part == 'chunks': args[2][0]['text'] += ' NULL;'
    elif part == 'trace': args[3]['blocks'][0]['source_module_id'] = 'unrelated-module'
    else: args[4].pop(args[3]['blocks'][0]['page_file'])
    with pytest.raises(ValueError, match='MODULE_NAV_'):
        apply_module_navigation(*args)


def test_adapter_refuses_reapplication_instead_of_duplicating_buttons():
    args, files, _ = apply()
    with pytest.raises(ValueError, match='MODULE_NAV_ALREADY_ADAPTED'):
        apply_module_navigation(*args[:4], files)


@pytest.mark.parametrize('display_only', [False, True])
def test_form_and_readonly_report_shapes_preserve_existing_native_actions(display_only):
    kind = 'Display Item' if display_only else 'Text Item'
    source = (b'<FormModule Name="CALLER"><Block Name="SOURCE" DatabaseBlock="true">'
        + f'<Item Name="CODE" ItemType="{kind}" DataType="Char" MaximumLength="20" DatabaseItem="true"/>'.encode()
        + b'<Item Name="NEXT" ItemType="Push Button" DatabaseItem="false"><Trigger Name="WHEN-BUTTON-PRESSED" '
        + b'TriggerText="BEGIN OPEN_FORM(\'DETAIL\'); END;"/></Item></Block></FormModule>')
    args, files, receipt = apply([('caller.xml', source), documents()[1]])
    op, = receipt['operations']
    before = args[4][op['caller_page_file']].decode()
    after = files[op['caller_page_file']].decode()
    assert after.startswith(before[:-2])
    assert after.count('button create (') == before.count('button create (')
    assert after.count('type: formAutoRowProcessing') == before.count('type: formAutoRowProcessing')
    assert len(receipt['qualified_labels']) == 0


def test_generated_storage_isolation_survives_navigation_adapter():
    docs = [(n, raw.replace(b'DatabaseBlock="false"', b'DatabaseBlock="true"')) for n, raw in documents()]
    a, _, ra = apply(docs, 'project-one')
    b, _, rb = apply(docs, 'project-two')
    tables = lambda args: {block['table_name'] for block in args[3]['blocks'] if block['table_name']}
    assert tables(a) and tables(b) and not tables(a) & tables(b)
    assert ra['operations'][0]['target_module_id'] == rb['operations'][0]['target_module_id']
