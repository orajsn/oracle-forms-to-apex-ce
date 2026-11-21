"""Source-bound companion proofs; fixtures and catalogs are synthetic."""
from copy import deepcopy
import os
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

from fox.forms_rate_choices import compile_rate_choices, validate_rate_choices, _digest
from fox.forms_route_lookup_plan import compile_row_lookups
from test_forms_route_lookup_plan import SOURCE as ROUTE_SOURCE, prepare as prepare_route


COMPANIONS = b'''
<LOV Name="TIER_PICK" RecordGroupName="TIERS">
 <LOVColumnMapping Name="CODE" ReturnItem="LINES.TIER"/>
 <LOVColumnMapping Name="DESCRIPTION" ReturnItem=""/>
</LOV>
<RecordGroup Name="TIERS" RecordGroupQuery="SELECT ALL TIER_CATALOG.CODE,TIER_CATALOG.DESCRIPTION FROM TIER_CATALOG ORDER BY CODE">
 <RecordGroupColumn Name="CODE" ColumnDataType="Character" MaximumLength="10"/>
 <RecordGroupColumn Name="DESCRIPTION" ColumnDataType="Character" MaximumLength="30"/>
</RecordGroup>
<LOV Name="UNIT_PICK" RecordGroupName="UNITS">
 <LOVColumnMapping Name="CODE" ReturnItem="LINES.UNIT"/>
 <LOVColumnMapping Name="DESCRIPTION" ReturnItem=""/>
 <LOVColumnMapping Name="FACTOR" ReturnItem=""/>
</LOV>
<RecordGroup Name="UNITS" RecordGroupQuery="SELECT ALL UNIT_CATALOG.CODE,UNIT_CATALOG.DESCRIPTION,UNIT_CATALOG.FACTOR FROM UNIT_CATALOG ORDER BY CODE DESC">
 <RecordGroupColumn Name="CODE" ColumnDataType="Character" MaximumLength="3"/>
 <RecordGroupColumn Name="DESCRIPTION" ColumnDataType="Character" MaximumLength="20"/>
 <RecordGroupColumn Name="FACTOR" ColumnDataType="Number" MaximumLength="12"/>
</RecordGroup>
'''
ITEMS = b'''
 <Item Name="TIER" ItemType="Text Item" MaximumLength="10" DataLengthSemantics="BYTE" LovName="TIER_PICK" ValidateFromList="true" Required="true"/>
 <Item Name="UNIT" ItemType="Text Item" MaximumLength="3" DataLengthSemantics="BYTE" LovName="UNIT_PICK" ValidateFromList="true" Required="false"/>
'''
SOURCE = ROUTE_SOURCE.replace(b'<Trigger Name="WHEN-CREATE-RECORD"', ITEMS + b'<Trigger Name="WHEN-CREATE-RECORD"').replace(
    b'</FormModule>', COMPANIONS + b'</FormModule>')


def prepare(raw=SOURCE, **kwargs):
    args = prepare_route(raw, **kwargs)
    route, = compile_row_lookups(*args)
    return args, route


def compile_source(raw=SOURCE, **kwargs):
    args, route = prepare(raw, **kwargs)
    return compile_rate_choices(*args, route)


def change(raw=SOURCE, *, name, tag=None, **properties):
    root = ET.fromstring(raw)
    node = next(n for n in root.iter() if n.get('Name') == name and (tag is None or n.tag == tag))
    for key, value in properties.items():
        if value is None: node.attrib.pop(key, None)
        else: node.set(key, value)
    return ET.tostring(root)


@pytest.mark.parametrize('renamed', [False, True])
def test_complete_same_row_contract_is_deterministic_and_preserves_originals(renamed):
    raw = SOURCE
    if renamed:
        for a, b in [(b'SHIPPING', b'ORDERING'), (b'LINES', b'POSITIONS'), (b'TIER', b'GRADE'),
                     (b'UNIT', b'MEASURE'), (b'CODE', b'IDENTIFIER'), (b'FACTOR', b'MULTIPLIER')]:
            raw = raw.replace(a, b)
    args, route = prepare(raw)
    before = deepcopy((args, route))
    bundle = compile_rate_choices(*args, route)
    assert compile_rate_choices(*args, route) == bundle
    assert (args, route) == before
    assert validate_rate_choices(bundle, route) == bundle
    assert len(bundle['choices']) == 2 and bundle['gaps'] == []
    assert [f['column'] for f in bundle['fields']] == ['F004', 'F005']
    assert [f['required'] for f in bundle['fields']] == [True, False]
    first, second = bundle['choices']
    assert [len(c['returns']) for c in bundle['choices']] == [1, 1]
    assert [c['query']['order'][0]['direction'] for c in bundle['choices']] == [None, 'DESC']
    assert [c['active_predicate'] for c in bundle['choices']] == [None, None]
    assert [v['data_type'] for v in second['columns']] == ['VARCHAR2', 'VARCHAR2', 'NUMBER']
    assert [v['display_only'] for v in second['columns']] == [False, True, True]
    assert all(f['data_type'] == 'VARCHAR2' for f in bundle['fields'])
    assert all(not f['direct_edit_allowed'] for f in bundle['fields'])
    for c in bundle['choices']:
        assert c['source_binding'] == route['source_binding']
        assert c['source_block_id'] == route['source_block_id']
        assert c['query_already_counted'] and c['validate_from_list']
        assert 'WHEN-CREATE-RECORD' in {e['source_event'] for e in c['unexecuted_source_events']}
        assert all(not e['native_event_wired'] for e in c['unexecuted_source_events'])
        assert not any(c[k] for k in ('original_interface_enabled', 'source_query_executed',
                                     'customer_table_writes', 'runtime_verified', 'business_accepted'))


@pytest.mark.parametrize('name,tag,properties', [
    ('TIER', None, {'ValidateFromList': 'false'}),
    ('TIER', None, {'ValidateFromList': None}),
    ('TIER', None, {'Enabled': 'false'}),
    ('TIER', None, {'UpdateAllowed': 'false'}),
    ('TIER', None, {'Required': 'unknown'}),
    ('TIER', None, {'DataType': 'Number'}),
    ('TIER', None, {'MaximumLength': None}),
    ('TIER', None, {'DataLengthSemantics': 'CHAR'}),
    ('TIER', None, {'Formula': '1', 'CalculateMode': 'Formula'}),
    ('CODE', 'RecordGroupColumn', {'ColumnDataType': 'Number'}),
])
def test_unsupported_field_proofs_never_emit_partial_choice(name, tag, properties):
    if tag:
        root = ET.fromstring(SOURCE)
        group = next(n for n in root.iter('RecordGroup') if n.get('Name') == 'TIERS')
        node = next(n for n in group if n.get('Name') == name)
        for key, value in properties.items():
            if value is None: node.attrib.pop(key, None)
            else: node.set(key, value)
        raw = ET.tostring(root)
    else:
        raw = change(name=name, tag=tag, **properties)
    bundle = compile_source(raw)
    assert len(bundle['choices']) == 1
    assert bundle['choices'][0]['source_caller_name'] == 'UNIT'
    assert len(bundle['gaps']) == 1 and not bundle['gaps'][0]['native_event_wired']
    assert [f['column'] for f in bundle['fields']] == ['F004']


@pytest.mark.parametrize('old,new', [
    (b'ReturnItem="LINES.TIER"', b'ReturnItem="HEADER.LABEL"'),
    (b'ReturnItem="LINES.TIER"', b'ReturnItem="TIER"'),
    (b'ReturnItem="LINES.TIER"', b'ReturnItem="LINES.VIA"'),
    (b'<LOVColumnMapping Name="DESCRIPTION" ReturnItem=""/>', b''),
    (b'FROM TIER_CATALOG ORDER BY', b'FROM TIER_CATALOG, EXTRA ORDER BY'),
    (b'TIER_CATALOG.DESCRIPTION FROM', b'OTHER.DESCRIPTION FROM'),
    (b'TIER_CATALOG.DESCRIPTION FROM', b'TIER_CATALOG.CODE FROM'),
    (b'FROM TIER_CATALOG ORDER BY', b"FROM TIER_CATALOG WHERE CODE=:LINES.TIER ORDER BY"),
    (b'FROM TIER_CATALOG ORDER BY', b"FROM TIER_CATALOG WHERE ACTIVE='0' ORDER BY"),
])
def test_bad_return_or_query_preserves_ordinary_gap(old, new):
    assert old in SOURCE
    args, route = prepare(SOURCE.replace(old, new, 1))
    bundle = compile_rate_choices(*args, route)
    assert all(c['source_caller_name'] != 'TIER' for c in bundle['choices'])
    # Normal query gaps remain authoritative if no source group was generated.
    assert bundle['gaps'] or args[-2]['gaps']


def test_declared_optional_additional_character_return_is_complete():
    raw = SOURCE.replace(b'<Item Name="UNIT"', b'<Item Name="TIER_DESC" ItemType="Display Item" MaximumLength="30" DataLengthSemantics="BYTE" Required="false"/><Item Name="UNIT"')
    raw = raw.replace(b'<LOVColumnMapping Name="DESCRIPTION" ReturnItem=""/>',
                      b'<LOVColumnMapping Name="DESCRIPTION" ReturnItem="LINES.TIER_DESC"/>', 1)
    bundle = compile_source(raw)
    first, second = bundle['choices']
    assert [f['source_name'] for f in first['returns']] == ['TIER', 'TIER_DESC']
    assert [f['required'] for f in first['returns']] == [True, False]
    assert [f['column'] for f in bundle['fields']] == ['F004', 'F005', 'F006']
    assert second['caller']['column'] == 'F006'


def test_numeric_display_projection_can_never_be_assigned_to_a_row():
    raw = SOURCE.replace(b'Name="FACTOR" ReturnItem=""', b'Name="FACTOR" ReturnItem="LINES.TIER"')
    bundle = compile_source(raw)
    assert len(bundle['choices']) == 1 and bundle['choices'][0]['source_caller_name'] == 'TIER'
    assert 'NUMERIC_RETURN_UNSUPPORTED' in bundle['gaps'][0]['reason']


def test_active_rule_and_order_are_retained_exactly():
    raw = SOURCE.replace(b'FROM TIER_CATALOG ORDER BY', b"FROM TIER_CATALOG WHERE TIER_CATALOG.ACTIVE='Y' ORDER BY")
    c = compile_source(raw)['choices'][0]
    assert c['active_predicate']['right'] == {'kind': 'string', 'value': 'Y'}
    assert c['query']['select_all'] is True
    assert c['query']['order'] == [{'parts': ['CODE'], 'direction': None}]


@pytest.mark.parametrize('body', [
    "SET_LOV_PROPERTY('TIER_PICK',GROUP_NAME,'OTHER');",
    "POPULATE_GROUP_WITH_QUERY('TIERS','select x from y');",
    "SET_ITEM_PROPERTY('TIER',LOV_NAME,'OTHER');",
    "SET_ITEM_PROPERTY(:TARGET,ENABLED,PROPERTY_FALSE);",
])
def test_computed_or_relevant_dynamic_overrides_remain_unbound(body):
    extra = ET.Element('ProgramUnit', Name='CHANGE_CHOICES', ProgramUnitText='PROCEDURE CHANGE_CHOICES IS BEGIN ' + body + ' END;')
    raw = SOURCE.replace(b'</FormModule>', ET.tostring(extra) + b'</FormModule>')
    # Existing row compiler also rejects unknown property targets globally.
    args = prepare_route(raw)
    routes = compile_row_lookups(*args)
    if routes:
        bundle = compile_rate_choices(*args, routes[0])
        assert not any(c['source_caller_name'] == 'TIER' for c in bundle['choices'])
        assert bundle['gaps']
    else:
        assert args[-1]['gaps']


@pytest.mark.parametrize('event', ['POST-CHANGE', 'WHEN-VALIDATE-ITEM', 'KEY-LISTVAL', 'KEY-NEXT-ITEM'])
def test_return_owned_source_event_requires_explicit_mapping(event):
    root = ET.fromstring(SOURCE)
    node = next(n for n in root.iter('Item') if n.get('Name') == 'TIER')
    ET.SubElement(node, 'Trigger', Name=event, TriggerText='BEGIN :LINES.UNIT := NULL; END;')
    bundle = compile_source(ET.tostring(root))
    assert [c['source_caller_name'] for c in bundle['choices']] == ['UNIT']
    assert bundle['gaps'][0]['reason'] == 'RATE_CHOICES_RETURN_EVENT_UNIMPLEMENTED'


def test_ambiguous_callers_and_targets_are_rejected_without_first_match_wins():
    raw = SOURCE.replace(b'<Item Name="UNIT"', b'<Item Name="OTHER" ItemType="Text Item" LovName="TIER_PICK"/><Item Name="UNIT"')
    assert [c['source_caller_name'] for c in compile_source(raw)['choices']] == ['UNIT']
    raw = SOURCE.replace(b'<LOVColumnMapping Name="DESCRIPTION" ReturnItem=""/>',
                         b'<LOVColumnMapping Name="DESCRIPTION" ReturnItem="LINES.UNIT"/>', 1)
    bundle = compile_source(raw)
    assert not bundle['choices'] and len(bundle['gaps']) == 2
    assert all(g['reason'] == 'RATE_CHOICES_AMBIGUOUS_RETURN_TARGET' for g in bundle['gaps'])


def test_project_identity_changes_bundle_catalog_and_row_contracts():
    a, route_a = prepare(project_id='project-a')
    b, route_b = prepare(project_id='project-b')
    first, second = compile_rate_choices(*a, route_a), compile_rate_choices(*b, route_b)
    assert first['source_binding'] == second['source_binding']
    assert first['bundle_id'] != second['bundle_id']
    assert {c['contract_id'] for c in first['choices']}.isdisjoint(c['contract_id'] for c in second['choices'])
    with pytest.raises(ValueError, match='RATE_CHOICES_ROUTE_BINDING'):
        validate_rate_choices(first, route_b)
    with pytest.raises(ValueError, match='RATE_CHOICES_FRESH_ROUTE_REQUIRED'):
        compile_rate_choices(*a, route_b)


@pytest.mark.parametrize('target', ['packet', 'chunk', 'schema', 'source', 'group', 'lov', 'route'])
def test_fresh_source_receipts_and_original_route_are_required(target):
    args, route = prepare()
    if target == 'packet': args[1]['source_binding'] = 'changed'
    elif target == 'chunk': args[2][0]['text'] += ' '
    elif target == 'schema': args[4]['fox-package/supporting-schema.sql'] += b'\n'
    elif target == 'source': args[4]['fox-package/sources/shipping.xml'] += b'\n'
    elif target == 'group': args[5]['generated_operations'][0]['query']['order'] = [{'parts': ['CHANGED'], 'direction': None}]
    elif target == 'lov': args[6]['gaps'] = []
    else: route['caller_source_table'] = 'CHANGED'
    with pytest.raises(ValueError, match='ROW_LOOKUP_|RATE_CHOICES_'):
        compile_rate_choices(*args, route)


@pytest.mark.parametrize('target', ['binding', 'column', 'required', 'source-id', 'projection', 'vfl', 'field-list', 'gate'])
def test_retained_bundle_hash_detects_mutation(target):
    args, route = prepare()
    bundle = compile_rate_choices(*args, route)
    if target == 'binding': bundle['source_binding'] = 'wrong'
    elif target == 'column': bundle['choices'][0]['returns'][0]['column'] = 'F002'
    elif target == 'required': bundle['choices'][0]['returns'][0]['required'] = False
    elif target == 'source-id': bundle['choices'][0]['source_lov_id'] = 'wrong'
    elif target == 'projection': bundle['choices'][1]['columns'][2]['display_only'] = False
    elif target == 'vfl': bundle['choices'][0]['validate_from_list'] = False
    elif target == 'field-list': bundle['fields'].pop()
    else: bundle['choices'][0]['customer_table_writes'] = True
    with pytest.raises(ValueError, match='RATE_CHOICES_BUNDLE_HASH'):
        validate_rate_choices(bundle, route)


@pytest.mark.parametrize('target', ['numeric', 'slot', 'required', 'vfl', 'binding', 'source-id', 'gate'])
def test_rehashed_malformed_bundle_is_still_structurally_rejected(target):
    args, route = prepare()
    bundle = compile_rate_choices(*args, route)
    c = bundle['choices'][0]
    if target == 'numeric': bundle['choices'][1]['columns'][2]['display_only'] = False
    elif target == 'slot':
        for f in c['fields'] + c['returns'] + [c['caller']]: f['slot'] = 1; f['column'] = 'F001'
        bundle['fields'][0]['slot'] = 1; bundle['fields'][0]['column'] = 'F001'
    elif target == 'required':
        for f in c['fields'] + c['returns'] + [c['caller']]: f['required'] = 'false'
    elif target == 'vfl': c['validate_from_list'] = False
    elif target == 'binding': c['source_binding'] = 'wrong'
    elif target == 'source-id': c['source_lov_id'] = 'bad'
    else: c['customer_table_writes'] = True
    for choice in bundle['choices']: choice['contract_id'] = _digest(choice, 'contract_id', 'rate-choice-')
    bundle['bundle_id'] = _digest(bundle, 'bundle_id', 'rate-choices-')
    with pytest.raises(ValueError, match='RATE_CHOICES_'):
        validate_rate_choices(bundle, route)


def test_optional_original_source_proof():
    value = os.environ.get('RATE_CHOICES_SOURCE_XML')
    if not value:
        pytest.skip('Set RATE_CHOICES_SOURCE_XML for exact project-local source proof.')
    source = Path(value)
    args, route = prepare(source.read_bytes(), name=source.name)
    bundle = compile_rate_choices(*args, route)
    assert len(bundle['choices']) == 2 and bundle['gaps'] == []
    assert len(bundle['fields']) == 2
    assert sorted(f['required'] for f in bundle['fields']) == [False, True]
    assert sorted(len(c['columns']) for c in bundle['choices']) == [2, 3]
    numeric = [p for c in bundle['choices'] for p in c['columns'] if p['data_type'] == 'NUMBER']
    assert len(numeric) == 1 and numeric[0]['display_only']
    assert all(len(c['returns']) == 1 for c in bundle['choices'])
    assert args[-1]['gaps'] and len(args[-2]['generated_operations']) == 18
