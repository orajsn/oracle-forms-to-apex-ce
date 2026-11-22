"""Closed grammar and genuine source-bound generation; no Oracle/model calls."""
from copy import deepcopy
from pathlib import Path
import re
import sqlite3
import sys
from xml.sax.saxutils import escape

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'fox'))
from fox.forms_understanding_packet import _build
from fox.forms_native_plan import build_native_prototype_plan, POLICY_ID
from fox.xml_mapping import _blueprint
from forms2apex import native_blueprint
from forms2apex.native_record_groups import apply_record_groups, parse_record_group_query, render_query


SOURCE = b'''<FormModule Name="DISPATCH_CHOICES">
<Block Name="DISPATCH" DatabaseBlock="true">
<Item Name="DEPOT" ItemType="Text Item" DataType="Char" DatabaseItem="true" MaximumLength="10"/>
<Item Name="CITY" ItemType="Text Item" DataType="Char" DatabaseItem="true" MaximumLength="10"/>
</Block>
<LOV Name="PARCEL_CHOICES" RecordGroupName="AVAILABLE_PARCELS">
<LOVColumnMapping Name="PARCEL_NO" ReturnItem="DISPATCH.DEPOT"/>
</LOV>
<RecordGroup Name="AVAILABLE_PARCELS" RecordGroupType="Query" RecordGroupQuery="SELECT PARCEL_NO, PARCEL_WEIGHT FROM SOURCE_PARCELS,SOURCE_SERVICES WHERE PARCEL_BRANCH = :GLOBAL.DIVISION AND SERVICE_CODE = PARCEL_SERVICE AND SERVICE_TYPE &lt;&gt; '3' AND PARCEL_MANIFEST IS NULL AND PARCEL_PRINTED = 'Y' AND PARCEL_DEST IN (SELECT ROUTE_DEST FROM SOURCE_ROUTES WHERE ROUTE_ORIGIN = :DEPOT AND ROUTE_CITY = :DISPATCH.CITY) ORDER BY PARCEL_NO">
<RecordGroupColumn Name="PARCEL_NO" ColumnDataType="Character" MaximumLength="20"/>
<RecordGroupColumn Name="PARCEL_WEIGHT" ColumnDataType="Number"/>
</RecordGroup>
</FormModule>'''


def baseline(raw=SOURCE, name='dispatch_choices.xml'):
    documents = [(name, raw)]
    packet, chunks = _build(documents)
    plan = build_native_prototype_plan(documents, _blueprint(packet), project_id='groups',
        project_name='Reference choices', approved_policy_id=POLICY_ID)
    spec = plan['rendering_spec']
    files = {k: v.encode() for k, v in native_blueprint.render_native_blueprint(spec).items()}
    trace = native_blueprint.prototype_trace(spec)
    objects = {o['id']: o for entry in packet['sources'] for o in entry['facts']['objects']}
    for block in trace['blocks']:
        block['source_module_id'] = objects[block['source_block_id']]['module_id']
    return documents, packet, chunks, trace, files


def test_native_route_retains_full_filter_and_explicit_row_context():
    args = baseline()
    before = deepcopy(args)
    files, receipt = apply_record_groups(*args)
    assert args == before
    assert not receipt['gaps'] and len(receipt['generated_operations']) == 1
    op = receipt['generated_operations'][0]
    page = files[op['page_file']].decode()
    chooser = files[op['chooser_file']].decode()
    original = args[4][op['report_files'][0]].decode()
    changed = files[op['report_files'][0]].decode()
    assert changed.startswith(original[:-2]) and 'FOX_GROUP_1' in changed
    assert 'clearCache: ' + str(op['page_id']) in chooser and '#FOX_ROW_ID#' in chooser
    assert op['page_file'] == f"pages/p{op['page_id']:05d}-fox_group_{op['page_id']}.apx"
    assert op['chooser_file'] == f"pages/p{op['chooser_page_id']:05d}-fox_group_{op['chooser_page_id']}.apx"
    assert 'label: "AVAILABLE_PARCELS"' in changed
    assert 'name: "AVAILABLE_PARCELS"' in page
    assert 'heading: "DEPOT"' in chooser and 'heading: "CITY"' in chooser
    assert op['source_kind'] == 'RecordGroup' and op['source_attribute'] == 'RecordGroupQuery'
    assert op['unimplemented_lov_return_mapping_count'] == 1
    assert op['warnings'] == ['explicit_source_lov_return_mappings_unimplemented']
    assert op['associated_lovs'][0]['return_mappings'] == [{'source_column_name': 'PARCEL_NO', 'return_item': 'DISPATCH.DEPOT'}]
    assert '1 explicit source LOV return mappings remain unimplemented.' in page
    assert 'Reference choices' in chooser and 'SOURCE_PARCELS' not in chooser
    assert 'PARCEL_BRANCH = :' + op['global_bindings'][0]['app_item'] in page
    assert "SERVICE_TYPE <> '3'" in page and 'PARCEL_MANIFEST IS NULL' in page
    assert "PARCEL_PRINTED = 'Y'" in page
    assert 'PARCEL_DEST IN (SELECT ROUTE_DEST' in page
    assert 'ORDER BY PARCEL_NO' in page and ':GLOBAL.' not in page and ':DEPOT' not in page
    for binding in op['source_bindings']:
        assert 'SELECT FOX_RG_CTX.' + binding['column'] in page
    assert 'EXISTS (SELECT 1 FROM FOX_NATIVE_' in page
    assert 'Validate selected synthetic source row' in page and 'l_count <> 1' in page
    assert 'checksumRequiredSessionLevel' in page and 'argumentsMustHaveChecksum' in page
    assert 'serverSideCondition' in page and op['readiness_item'] in page
    assert "is not null" in page and 'storage: session' in page
    assert 'LOV field selection and return remain unimplemented' in page
    app_items = files['shared-components/app-items.apx'].decode()
    assert app_items.count('sessionStateProtection: restricted') == 2
    assert 'default' not in app_items.lower()
    assert not op['lov_return_implemented'] and not op['original_interface_enabled']
    assert all(op[k] is False for k in ('source_query_executed', 'customer_table_writes', 'oracle_compiled', 'runtime_verified', 'business_accepted'))
    for text in (page, chooser):
        assert not re.search(r'\b(?:INSERT|DELETE|UPDATE|MERGE|COMMIT)\b', text, re.I)
    assert apply_record_groups(*args) == (files, receipt)
    with pytest.raises(ValueError, match='ALREADY_ADAPTED'):
        apply_record_groups(*args[:-1], files)


@pytest.mark.parametrize('query', [
    'SELECT X FROM T WHERE X = :X; DELETE FROM T',
    'SELECT X FROM T WHERE X = :X UNION SELECT X FROM SECRET',
    'SELECT SECRET_FUNCTION(X) FROM T WHERE X = :X',
    'SELECT X FROM T WHERE X = :X OR 1=1',
    'SELECT X FROM T WHERE X = :X FOR UPDATE',
    'SELECT X FROM T@REMOTE WHERE X = :X',
    'SELECT X FROM T WHERE X = :X ORDER BY UNKNOWN_FUNCTION(X)',
    'SELECT X FROM T WHERE X IN (SELECT X,Y FROM U WHERE Y = :Y)',
    'SELECT X FROM T WHERE X = :X /* unterminated',
    'SELECT X FROM T WHERE X = :X /* nested /* */',
    'SELECT X FROM T WHERE X = :X AND',
    'SELECT X FROM T WHERE X = :X ORDER BY',
    'SELECT X FROM T WHERE X = :X INTO :OUT',
    "SELECT X FROM T WHERE X = '&#10;'",
    'SELECT X FROM T WHERE X = :X &amp;#59; DELETE FROM T',
    "SELECT X FROM T WHERE X = '&APP_USER.'",
    "SELECT X FROM T WHERE X = '```'",
    "SELECT X FROM T WHERE X = 'literal\nnewline'",
])
def test_closed_parser_rejects_whole_unsupported_source(query):
    with pytest.raises(ValueError): parse_record_group_query(query)


def test_comments_escaped_literals_entities_and_subquery_binds_preserved():
    query, refs, decode = parse_record_group_query("select CODE from ROUTES where FLAG = 'a''b--x' -- note&#10;and CODE in (select DEST from PATHS where ORIGIN = :HUB and AREA = :GLOBAL.AREA) order by CODE desc")
    assert refs == [['HUB'], ['GLOBAL', 'AREA']] and len(decode['substitutions']) == 1
    rendered = render_query(query, {('HUB',): ':P1_HUB', ('GLOBAL', 'AREA'): ':TRUSTED_AREA'})
    assert "FLAG = 'a''b--x'" in rendered and ':P1_HUB' in rendered and ':TRUSTED_AREA' in rendered
    assert 'ORDER BY CODE DESC' in rendered and 'note' not in rendered


@pytest.mark.parametrize('mutation,reason', [
    (lambda raw: raw.replace(b':DEPOT', b':MISSING'), 'SOURCE_BIND_NOT_UNIQUE'),
    (lambda raw: raw.replace(b':DEPOT', b':OTHER.DEPOT'), 'SOURCE_BIND_NOT_UNIQUE'),
    (lambda raw: raw.replace(b'<LOV Name=', b'<Block Name="SECOND" DatabaseBlock="true"><Item Name="DEPOT" DataType="Char" DatabaseItem="true" MaximumLength="10"/></Block><LOV Name='), 'SOURCE_BIND_NOT_UNIQUE'),
    (lambda raw: raw.replace(b'ORDER BY PARCEL_NO', b'ORDER BY PARCEL_NO FOR UPDATE'), 'TRAILING_QUERY'),
    (lambda raw: raw.replace(b'ColumnDataType="Number"', b'ColumnDataType="Unknown"'), 'SOURCE_COLUMN_TYPE'),
])
def test_unsupported_unit_emits_no_partial_query_or_app_items(mutation, reason):
    args = baseline(mutation(SOURCE))
    files, receipt = apply_record_groups(*args)
    assert not receipt['generated_operations'] and len(receipt['gaps']) == 1
    assert reason in receipt['gaps'][0]['reason'] and files == args[-1]


def test_fresh_source_and_chunk_binding_required():
    args = list(baseline())
    args[2] = deepcopy(args[2])
    args[2][0]['text'] += ' OR 1=1'
    with pytest.raises(ValueError, match='SOURCE_CHANGED'): apply_record_groups(*args)
    args = list(baseline())
    args[3] = deepcopy(args[3])
    args[3]['source_binding'] = 'a'*64
    with pytest.raises(ValueError, match='TRACE_SOURCE'): apply_record_groups(*args)


def test_query_unit_count_once_and_existing_row_links_preserved():
    raw = SOURCE.replace(b'</FormModule>', b'''<RecordGroup Name="CITY_CHOICES" RecordGroupQuery="SELECT CITY_CODE FROM SOURCE_CITIES WHERE CITY_DEPOT = :DEPOT">
<RecordGroupColumn Name="CITY_CODE" ColumnDataType="Character"/>
</RecordGroup></FormModule>''')
    args = baseline(raw)
    from forms2apex.native_lookups import _link
    source_report = args[3]['blocks'][0]['report_file']
    args[-1][source_report] = _link(args[-1][source_report].decode(), 7000).encode()
    files, receipt = apply_record_groups(*args)
    ops = receipt['generated_operations']
    assert len(ops) == len({op['source_unit_id'] for op in ops}) == 2
    report_file = ops[0]['report_files'][0]
    assert files[report_file].decode().count('linkIcon: Lookups') == args[-1][report_file].decode().count('linkIcon: Lookups') == 1
    assert files[report_file].decode().count('button record-group-') == 2
    assert sum(name.startswith('pages/p08') for name in files) == 4
    assert 'label: "AVAILABLE_PARCELS"' in files[report_file].decode()
    assert 'label: "CITY_CHOICES"' in files[report_file].decode()
    assert all(files[name] == value for name, value in args[-1].items() if name != report_file)


def test_source_lov_title_is_inert_quoted_and_unsafe_substitution_falls_back():
    raw = SOURCE.replace(b'RecordGroupName="AVAILABLE_PARCELS"', b'RecordGroupName="AVAILABLE_PARCELS" Title="Parcel &quot;choices&quot;"')
    args = baseline(raw)
    files, receipt = apply_record_groups(*args)
    op = receipt['generated_operations'][0]
    assert op['route_label'] == 'Parcel "choices"'
    assert 'label: "Parcel \\"choices\\""' in files[op['report_files'][0]].decode()
    raw = SOURCE.replace(b'RecordGroupName="AVAILABLE_PARCELS"', b'RecordGroupName="AVAILABLE_PARCELS" Title="&amp;APP_USER."')
    files, receipt = apply_record_groups(*baseline(raw))
    op = receipt['generated_operations'][0]
    assert op['route_label'] == 'AVAILABLE_PARCELS'
    assert '&APP_USER.' not in files[op['page_file']].decode()


def test_only_query_record_group_kind_is_adapted():
    args = baseline(SOURCE.replace(b'RecordGroupType="Query"', b'RecordGroupType="Static"'))
    files, receipt = apply_record_groups(*args)
    assert not receipt['generated_operations'] and files == args[-1]
    assert 'SOURCE_TYPE' in receipt['gaps'][0]['reason']


@pytest.mark.parametrize("separator", [chr(0x85), chr(0x2028), chr(0x2029)])
def test_sql_string_separators_cannot_change_when_embedded_in_apexlang(separator):
    with pytest.raises(ValueError, match="LITERAL_CONTEXT"):
        parse_record_group_query("SELECT C FROM T WHERE FLAG = 'a" + separator + "b'")


@pytest.mark.parametrize('raw', [
    'select all C.CODE, C.DESCRIPTION from C order by CODE desc, DESCRIPTION asc',
    'select C.CODE, C.DESCRIPTION from C',
    "select all C.CODE, C.DESCRIPTION from C where FLAG = 'Y' order by CODE",
    "select all CODE from C where CODE in (select all CODE from ALLOWED where FLAG = :GLOBAL.FLAG)",
])
def test_projected_single_table_and_explicit_all_round_trip(raw):
    query, refs, _ = parse_record_group_query(raw)
    replacements = {tuple(ref): ':TRUSTED_FLAG' for ref in refs}
    rendered = render_query(query, replacements)
    reparsed, rebound, _ = parse_record_group_query(rendered)
    assert reparsed['projections'] == query['projections']
    assert reparsed['order'] == query['order']
    assert reparsed.get('select_all') == query.get('select_all')
    assert rebound == ([['TRUSTED_FLAG']] if refs else [])
    if not query['predicates']:
        assert '\nWHERE ' not in rendered
        guarded = render_query(query, replacements, [":READY = 'Y'"])
        assert guarded.count('\nWHERE ') == 1
        if query['order']:
            assert guarded.index('\nWHERE ') < guarded.index('\nORDER BY ')


@pytest.mark.parametrize('raw', [
    'SELECT ALL CODE FROM C,T',
    'SELECT CODE FROM C,T ORDER BY CODE',
    'SELECT ALL * FROM C',
    'SELECT DISTINCT CODE FROM C',
    'SELECT ALL DISTINCT CODE FROM C',
    'SELECT ALL CODE FROM C WHERE',
    'SELECT ALL CODE FROM C WHERE FLAG =',
    'SELECT ALL CODE FROM C WHERE FLAG = :GLOBAL.FLAG AND',
    'SELECT ALL CODE FROM C ORDER BY 2',
    'SELECT ALL CODE FROM C ORDER BY CODE NULLS FIRST',
    'SELECT ALL CODE FROM C UNION SELECT CODE FROM PRIVATE_CODES',
    'SELECT ALL CODE FROM C; DELETE FROM C',
    'SELECT ALL CODE FROM C FOR UPDATE',
    'SELECT ALL CODE FROM C OFFSET 1 ROWS',
    'SELECT ALL CODE FROM C WHERE FLAG = :GLOBAL.FLAG OR 1 = 1',
    'SELECT ALL CODE FROM C WHERE CODE NOT IN (1,2)',
    'SELECT ALL CODE AS NAME.EXTRA FROM C',
    'SELECT ALL CODE FROM C ALIAS',
    'SELECT ALL CODE FROM C ORDER BY CODE WHERE FLAG = 1',
    'SELECT ALL CODE FROM C WHERE CODE IN (SELECT CODE FROM C,T)',
])
def test_new_select_family_rejects_complete_unsupported_queries(raw):
    with pytest.raises(ValueError):
        parse_record_group_query(raw)


@pytest.mark.parametrize('where', ['', " WHERE FLAG = 'Y'", ' WHERE CODE = :CODE'])
def test_render_preserves_bag_projection_nulls_filter_and_order(where):
    # SQLite is a local SQL semantics check, not an Oracle/runtime acceptance.
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE CHOICES (CODE TEXT, DESCRIPTION TEXT, FLAG TEXT)')
        db.executemany('INSERT INTO CHOICES VALUES (?,?,?)', [
            ('B', 'second', 'Y'), ('A', 'first', 'Y'), ('A', 'first', 'Y'),
            ('A', None, 'N'), (None, 'unknown', 'Y'), ('Z', 'last', None)])
        raw = 'SELECT ALL CODE, DESCRIPTION FROM CHOICES' + where + ' ORDER BY CODE DESC, DESCRIPTION ASC'
        query, refs, _ = parse_record_group_query(raw)
        rendered = render_query(query, {tuple(ref): ':INPUT_CODE' for ref in refs})
        original = db.execute(raw, {'CODE': 'A'}).fetchall()
        assert db.execute(rendered, {'INPUT_CODE': 'A'}).fetchall() == original
        assert original.count(('A', 'first')) == 2
        guarded = render_query(query, {tuple(ref): ':INPUT_CODE' for ref in refs}, [":READY = 'Y'"])
        assert db.execute(guarded, {'INPUT_CODE': 'A', 'READY': 'N'}).fetchall() == []
        assert db.execute(guarded, {'INPUT_CODE': 'A', 'READY': 'Y'}).fetchall() == original


@pytest.mark.parametrize('raw,has_global', [
    ('SELECT ALL PARCEL_NO, PARCEL_WEIGHT FROM SOURCE_PARCELS ORDER BY PARCEL_NO', False),
    ('SELECT PARCEL_NO, PARCEL_WEIGHT FROM SOURCE_PARCELS', False),
    ('SELECT ALL PARCEL_NO, PARCEL_WEIGHT FROM SOURCE_PARCELS WHERE PARCEL_BRANCH = :GLOBAL.DIVISION', True),
])
def test_new_family_is_navigable_and_retains_all_interface_gates(raw, has_global):
    source = re.sub(rb'RecordGroupQuery="[^"]*"',
        ('RecordGroupQuery="' + escape(raw, {'"': '&quot;'}) + '"').encode(), SOURCE)
    args = baseline(source)
    files, receipt = apply_record_groups(*args)
    assert not receipt['gaps'] and len(receipt['generated_operations']) == 1
    op = receipt['generated_operations'][0]
    page = files[op['page_file']].decode()
    chooser = files[op['chooser_file']].decode()
    parent = files[op['report_files'][0]].decode()
    assert f'page: {op["chooser_page_id"]}' in parent
    assert f'page: {op["page_id"]}' in chooser and '#FOX_ROW_ID#' in chooser
    assert 'SOURCE_PARCELS' not in chooser
    assert 'EXISTS (SELECT 1 FROM FOX_NATIVE_' in page
    assert "NVL(V('" + op['readiness_item'] + "'), 'N') = 'Y'" in page
    assert 'serverSideCondition' in page and 'is not null' in page
    assert 'Validate selected synthetic source row' in page
    assert 'checksumRequiredSessionLevel' in page
    assert 'Original database reads are disabled' in page
    assert 'sessionStateProtection: restricted' in files['shared-components/app-items.apx'].decode()
    assert bool(op['global_bindings']) is has_global
    assert not receipt['original_reads_enabled'] and not op['original_interface_enabled']
    assert not op['source_query_executed'] and not op['business_accepted']
    assert not op['lov_return_implemented']
    assert op['unimplemented_lov_return_mapping_count'] == 1
    if raw.startswith('SELECT ALL '):
        assert 'SELECT ALL PARCEL_NO, PARCEL_WEIGHT' in page
    if 'ORDER BY' in raw:
        assert 'ORDER BY PARCEL_NO' in page
    if has_global:
        assert ':GLOBAL.DIVISION' not in page
        assert 'PARCEL_BRANCH = :' + op['global_bindings'][0]['app_item'] in page


def test_implicit_all_filtered_tree_and_sql_remain_compatible():
    query, refs, _ = parse_record_group_query('SELECT CODE FROM CHOICES WHERE FLAG = :GLOBAL.FLAG ORDER BY CODE')
    assert set(query) == {'projections', 'tables', 'predicates', 'order'}
    assert refs == [['GLOBAL', 'FLAG']]
    assert render_query(query, {('GLOBAL', 'FLAG'): ':TRUSTED_FLAG'}) == (
        'SELECT CODE\nFROM CHOICES\nWHERE FLAG = :TRUSTED_FLAG\nORDER BY CODE')


def test_unfiltered_query_cannot_invent_an_ambiguous_navigation_context():
    source = re.sub(rb'RecordGroupQuery="[^"]*"',
        b'RecordGroupQuery="SELECT ALL PARCEL_NO, PARCEL_WEIGHT FROM SOURCE_PARCELS"', SOURCE)
    source = source.replace(b'<LOV Name=', b'''<Block Name="SECOND" DatabaseBlock="true">
        <Item Name="CODE" DataType="Char" DatabaseItem="true" MaximumLength="10"/>
        </Block><LOV Name=''')
    args = baseline(source)
    files, receipt = apply_record_groups(*args)
    assert not receipt['generated_operations'] and files == args[-1]
    assert receipt['gaps'][0]['reason'] == 'RECORD_GROUP_NAVIGATION_CONTEXT_NOT_UNIQUE'


NAVIGATION_SOURCE = b'''<FormModule Name="DELIVERY_REFERENCE">
<Block Name="OVERVIEW" DatabaseBlock="true">
 <Item Name="CODE" ItemType="Text Item" DataType="Char" DatabaseItem="true" MaximumLength="20"/>
</Block>
<Block Name="TARIFFS" DatabaseBlock="true">
 <Item Name="LANE" ItemType="Text Item" DataType="Char" DatabaseItem="true" MaximumLength="20" LovName="LANE_PICK"/>
 <Item Name="LANE_DESCRIPTION" ItemType="Text Item" DataType="Char" DatabaseItem="true" MaximumLength="30" LovName="LANE_PICK"/>
</Block>
<LOV Name="LANE_PICK" RecordGroupName="LANES">
 <LOVColumnMapping Name="LANE_CODE" ReturnItem="TARIFFS.LANE"/>
</LOV>
<RecordGroup Name="LANES" RecordGroupQuery="SELECT LANE_CODE FROM REFERENCE_LANES">
 <RecordGroupColumn Name="LANE_CODE" ColumnDataType="Character" MaximumLength="20"/>
</RecordGroup>
</FormModule>'''


@pytest.mark.parametrize('global_filter', [False, True])
def test_unbound_query_uses_all_source_lov_callers_in_one_rendered_block(global_filter):
    source = NAVIGATION_SOURCE
    if global_filter:
        source = source.replace(b'FROM REFERENCE_LANES"', b'FROM REFERENCE_LANES WHERE BRANCH = :GLOBAL.DIVISION"')
    args = baseline(source)
    before = deepcopy(args)
    files, receipt = apply_record_groups(*args)
    assert args == before and not receipt['gaps']
    op, = receipt['generated_operations']
    overview, tariffs = args[3]['blocks']
    assert op['report_files'] == [tariffs['report_file']]
    assert files[overview['report_file']] == args[4][overview['report_file']]
    assert 'FOX_GROUP_1' in files[tariffs['report_file']].decode()
    chooser = files[op['chooser_file']].decode()
    page = files[op['page_file']].decode()
    assert tariffs['table_name'] in chooser and overview['table_name'] not in chooser
    assert tariffs['table_name'] in page and overview['table_name'] not in page
    assert '#FOX_ROW_ID#' in chooser and 'checksumRequiredSessionLevel' in page
    assert 'select count(*)' in page and "l_count <> 1" in page
    assert not op['source_bindings'] and len(op['global_bindings']) == int(global_filter)
    assert not receipt['original_reads_enabled'] and not op['original_interface_enabled']
    assert not op['source_query_executed'] and not op['customer_table_writes']
    assert not op['runtime_verified'] and not op['business_accepted']
    assert "NVL(V('" + op['readiness_item'] + "'), 'N') = 'Y'" in page


@pytest.mark.parametrize('mutation', [
    # Both caller items must resolve to the same source block.
    lambda raw: raw.replace(b'Name="CODE" ItemType=', b'Name="CODE" LovName="LANE_PICK" ItemType='),
    # Every associated LOV must have a resolvable caller, not just one LOV.
    lambda raw: raw.replace(b'<RecordGroup Name=', b'<LOV Name="ORPHAN_PICK" RecordGroupName="LANES"/><RecordGroup Name='),
    lambda raw: raw.replace(b'LovName="LANE_PICK"', b'LovName="MISSING_PICK"'),
    # An explicit control caller never becomes a database context.
    lambda raw: raw.replace(b'Name="TARIFFS" DatabaseBlock="true"', b'Name="TARIFFS" DatabaseBlock="false"').replace(
        b'<LOV Name=', b'<Block Name="THIRD" DatabaseBlock="true"><Item Name="OTHER" ItemType="Text Item" DataType="Char" MaximumLength="20"/></Block><LOV Name='),
    lambda raw: raw.replace(b'Name="TARIFFS" DatabaseBlock="true"', b'Name="TARIFFS"').replace(
        b'<LOV Name=', b'<Block Name="THIRD" DatabaseBlock="true"><Item Name="OTHER" ItemType="Text Item" DataType="Char" MaximumLength="20"/></Block><LOV Name='),
    # A source database block without a rendered caller item is unresolved.
    lambda raw: raw.replace(b'LovName="LANE_PICK"', b'LovName="LANE_PICK" Rendered="false" ItemType="Image"').replace(
        b'ItemType="Text Item" DataType="Char" DatabaseItem="true" MaximumLength="20" LovName=',
        b'DataType="Char" DatabaseItem="true" MaximumLength="20" LovName=').replace(
        b'ItemType="Text Item" DataType="Char" DatabaseItem="true" MaximumLength="30" LovName=',
        b'DataType="Char" DatabaseItem="true" MaximumLength="30" LovName='),
])
def test_unbound_query_rejects_mixed_missing_control_and_unmapped_lov_callers(mutation):
    args = baseline(mutation(NAVIGATION_SOURCE))
    files, receipt = apply_record_groups(*args)
    assert not receipt['generated_operations'] and files == args[4]
    assert receipt['gaps'][0]['reason'] == 'RECORD_GROUP_NAVIGATION_CONTEXT_NOT_UNIQUE'


def test_lov_context_does_not_resolve_callers_from_a_different_module():
    source = b'<Module>' + NAVIGATION_SOURCE.replace(b'LovName="LANE_PICK"', b'LovName="OTHER"') + b'''<FormModule Name="OTHER_MODULE">
      <Block Name="TARIFFS" DatabaseBlock="true"><Item Name="LANE" ItemType="Text Item" DataType="Char" MaximumLength="20" LovName="LANE_PICK"/></Block>
    </FormModule></Module>'''
    args = baseline(source)
    files, receipt = apply_record_groups(*args)
    assert not receipt['generated_operations'] and files == args[4]
    assert receipt['gaps'][0]['reason'] == 'RECORD_GROUP_NAVIGATION_CONTEXT_NOT_UNIQUE'


def test_multiple_associated_lovs_can_prove_one_caller_block():
    source = NAVIGATION_SOURCE.replace(b'MaximumLength="30" LovName="LANE_PICK"',
        b'MaximumLength="30" LovName="LABEL_PICK"').replace(b'<RecordGroup Name=',
        b'<LOV Name="LABEL_PICK" RecordGroupName="LANES"/><RecordGroup Name=')
    args = baseline(source)
    _, receipt = apply_record_groups(*args)
    assert not receipt['gaps']
    op, = receipt['generated_operations']
    assert len(op['associated_lovs']) == 2
    assert op['report_files'] == [args[3]['blocks'][1]['report_file']]


@pytest.mark.parametrize('duplicate', ['block', 'field'])
def test_source_lov_navigation_refuses_duplicate_target_mappings(duplicate):
    args = baseline(NAVIGATION_SOURCE)
    target = args[3]['blocks'][1]
    if duplicate == 'block':
        args[3]['blocks'].append(deepcopy(target))
    else:
        target['items'].append(deepcopy(target['items'][0]))
    files, receipt = apply_record_groups(*args)
    assert not receipt['generated_operations'] and files == args[4]
    assert receipt['gaps'][0]['reason'] == 'RECORD_GROUP_NAVIGATION_CONTEXT_NOT_UNIQUE'


@pytest.mark.parametrize('raw', [
    "SELECT ALL C.CODE, C.DESCRIPTION FROM C WHERE ACTIVE = 'Y' AND CODE NOT IN ('990','992') ORDER BY 1",
    "SELECT CODE ID, (DESCRIPTION) NAME FROM C WHERE ACTIVE = 'Y' ORDER BY 1 DESC",
    "SELECT C.CODE AS ID, (C.DESCRIPTION) AS NAME FROM C ORDER BY ID, 2 DESC",
    "SELECT CODE FROM C WHERE CODE IN ('A', 'B', NULL) ORDER BY 1",
])
def test_literal_lists_aliases_and_ordinals_round_trip(raw):
    query, refs, _ = parse_record_group_query(raw)
    assert not refs
    rendered = render_query(query, {})
    assert parse_record_group_query(rendered)[0] == query
    assert query['order'][0]['parts'][-1] == query['projections'][0][-1]
    if ' AS ' in rendered:
        assert query['projections'] == [['ID'], ['NAME']]
        assert 'projection_sources' in query


@pytest.mark.parametrize('clause,expected', [
    ("CODE NOT IN ('990','992')", [('A', 'first'), ('A', 'first'), ('B', None)]),
    ("CODE IN ('A','B')", [('A', 'first'), ('A', 'first'), ('B', None)]),
    ("CODE NOT IN ('990', NULL)", []),
    ("CODE IN ('A', NULL)", [('A', 'first'), ('A', 'first')]),
    ("CODE NOT IN ('990', '')", []),
])
def test_new_query_family_preserves_exact_bag_rows_nulls_aliases_and_order(clause, expected):
    with sqlite3.connect(':memory:') as db:
        db.execute('CREATE TABLE C (CODE TEXT, DESCRIPTION TEXT, ACTIVE TEXT)')
        db.executemany('INSERT INTO C VALUES (?,?,?)', [
            ('B', None, 'Y'), ('A', 'first', 'Y'), ('A', 'first', 'Y'),
            ('990', 'excluded', 'Y'), ('992', 'excluded', 'Y'),
            (None, 'null code', 'Y'), ('A', 'inactive', 'N')])
        raw = f"SELECT ALL CODE ID, (DESCRIPTION) NAME FROM C WHERE ACTIVE = 'Y' AND {clause} ORDER BY 1, 2"
        query, _, _ = parse_record_group_query(raw)
        rendered = render_query(query, {})
        # Oracle's empty string is NULL; SQLite needs this explicit model.
        sqlite_raw = raw.replace("''", 'NULL')
        sqlite_rendered = rendered.replace("''", 'NULL')
        cursor = db.execute(sqlite_rendered)
        assert [column[0] for column in cursor.description] == ['ID', 'NAME']
        assert cursor.fetchall() == db.execute(sqlite_raw).fetchall() == expected
        guarded = render_query(query, {}, [":READY = 'Y'"]).replace("''", 'NULL')
        assert db.execute(guarded, {'READY': 'N'}).fetchall() == []
        assert db.execute(guarded, {'READY': 'Y'}).fetchall() == expected


@pytest.mark.parametrize('raw', [
    'SELECT * FROM C', 'SELECT C.* FROM C', 'SELECT ALL * FROM DUAL',
    'SELECT *, DUMMY FROM DUAL', 'SELECT * FROM SYS.DUAL',
    'SELECT * FROM DUAL WHERE DUMMY = :X', 'SELECT * FROM DUAL ORDER BY 1',
    'SELECT (CODE + DESCRIPTION) NAME FROM C', 'SELECT ((CODE)) NAME FROM C',
    'SELECT CODE AS FROM C', 'SELECT CODE NAME OTHER FROM C',
    "SELECT CODE FROM C WHERE CODE NOT IN ()", "SELECT CODE FROM C WHERE CODE NOT IN ('A',)",
    'SELECT CODE FROM C WHERE CODE NOT IN (OTHER)', 'SELECT CODE FROM C WHERE CODE NOT IN (:VALUE)',
    'SELECT CODE FROM C WHERE CODE NOT IN (1,2)',
    'SELECT CODE FROM C WHERE CODE NOT IN (SELECT CODE FROM T)',
    'SELECT CODE FROM C WHERE CODE NOT LIKE OTHER',
    'SELECT CODE FROM C ORDER BY 0', 'SELECT CODE FROM C ORDER BY 01',
    'SELECT CODE FROM C ORDER BY 1.0', 'SELECT CODE FROM C ORDER BY -1',
])
def test_new_family_remains_closed_on_malformed_and_unproved_variants(raw):
    with pytest.raises(ValueError):
        parse_record_group_query(raw)


def test_aliased_report_uses_output_names_and_original_interface_gate():
    source = re.sub(rb'RecordGroupQuery="[^"]*"',
        b'''RecordGroupQuery="SELECT PARCEL_NO AS ID, (PARCEL_WEIGHT) WEIGHT FROM SOURCE_PARCELS ORDER BY 1"''', SOURCE)
    source = source.replace(b'RecordGroupColumn Name="PARCEL_NO"', b'RecordGroupColumn Name="ID"')
    source = source.replace(b'RecordGroupColumn Name="PARCEL_WEIGHT"', b'RecordGroupColumn Name="WEIGHT"')
    files, receipt = apply_record_groups(*baseline(source))
    assert not receipt['gaps']
    op = receipt['generated_operations'][0]
    page = files[op['page_file']].decode()
    assert 'SELECT PARCEL_NO AS ID, PARCEL_WEIGHT AS WEIGHT' in page
    assert 'column ID (' in page and 'column WEIGHT (' in page
    assert 'displayColumn ID (' in page and 'ORDER BY 1' in page
    assert not op['original_interface_enabled'] and not receipt['original_reads_enabled']
    assert op['readiness_item'] in page and 'serverSideCondition' in page


def dual_source():
    source = re.sub(rb'<RecordGroup Name=.*?</RecordGroup>', b'''<RecordGroup Name="RG_DUMMY" RecordGroupQuery="SELECT * FROM DUAL">
        <RecordGroupColumn Name="DUMMY" ColumnDataType="Character" MaximumLength="1"/>
        </RecordGroup>''', SOURCE, flags=re.S)
    return source


def test_canonical_dual_expansion_requires_exact_declaration_and_retains_gate():
    source = dual_source()
    query, refs, _ = parse_record_group_query('SELECT * FROM DUAL')
    assert query == {'projections': [['DUMMY']], 'tables': [['DUAL']], 'predicates': [], 'order': [], 'dual_wildcard': True}
    assert not refs and render_query(query, {}) == 'SELECT DUMMY\nFROM DUAL'
    files, receipt = apply_record_groups(*baseline(source))
    assert not receipt['gaps']
    op = receipt['generated_operations'][0]
    page = files[op['page_file']].decode()
    assert 'SELECT DUMMY' in page and 'FROM DUAL' in page and 'SELECT *' not in page
    # Unqualified DUAL may be shadowed. No database interface exemption is made.
    assert not receipt['original_reads_enabled'] and not op['original_interface_enabled']
    assert op['readiness_item'] in page and 'serverSideCondition' in page
    assert "NVL(V('" + op['readiness_item'] + "'), 'N') = 'Y'" in page
    assert 'sessionStateProtection: restricted' in files['shared-components/app-items.apx'].decode()


@pytest.mark.parametrize('mutation', [
    lambda raw: raw.replace(b'Name="DUMMY"', b'Name="OTHER"'),
    lambda raw: raw.replace(b'MaximumLength="1"', b'MaximumLength="2"'),
    lambda raw: raw.replace(b'ColumnDataType="Character"', b'ColumnDataType="Number"'),
    lambda raw: raw.replace(b'</RecordGroup>', b'<RecordGroupColumn Name="SECOND" ColumnDataType="Character"/></RecordGroup>'),
])
def test_dual_wildcard_without_exact_source_declaration_is_a_whole_unit_gap(mutation):
    args = baseline(mutation(dual_source()))
    files, receipt = apply_record_groups(*args)
    assert not receipt['generated_operations'] and files == args[-1]
    assert receipt['gaps'][0]['reason'] == 'RECORD_GROUP_CANONICAL_DUAL_DECLARATION_REQUIRED'
