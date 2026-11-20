"""Closed grammar and genuine source-bound generation; no Oracle/model calls."""
from copy import deepcopy
from pathlib import Path
import re
import sys

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
