"""Deterministic native generation and SQLite predicate probes, not Oracle proof."""
from copy import deepcopy
from html import escape
import hashlib
import json
import sqlite3

import pytest

from forms2apex import native_blueprint
from fox.forms_manifest_filter import apply_manifest_filters, parse_where_clause
from fox.forms_native_plan import POLICY_ID, build_native_prototype_plan
from fox.forms_understanding_packet import _build
from fox.prototype_export_only import _members
from fox.xml_mapping import _blueprint


def source(clause="KIND='1' AND DEPOT=:GLOBAL.ORIGIN", *, module='DISPATCH',
           block='MANIFESTS', table='OPS.MANIFEST_ROWS', extra='', order='SERIAL desc',
           kind_extra='', depot_extra='', query_type='Table'):
    return (f'<FormModule Name="{module}"><Block Name="{block}" DatabaseBlock="true" '
        f'QueryDataSourceName="{table}" QueryDataSourceType="{query_type}" '
        f'WhereClause="{escape(clause, quote=True)}" OrderByClause="{escape(order, quote=True)}">'
        f'<Item Name="CATEGORY" ColumnName="KIND" DataType="Char" DatabaseItem="true" ItemType="Text Item" {kind_extra}/>'
        f'<Item Name="ORIGIN_CODE" ColumnName="DEPOT" DataType="Char" DatabaseItem="true" ItemType="Text Item" {depot_extra}/>'
        '<Item Name="SERIAL" DataType="Number" DatabaseItem="true" ItemType="Text Item"/>'
        '<Item Name="DECORATION" DataType="Char" DatabaseItem="false" ItemType="Text Item"/>'
        f'{extra}</Block></FormModule>').encode()


def prepare(docs):
    packet, chunks = _build(docs)
    plan = build_native_prototype_plan(docs, _blueprint(packet), project_id='filters',
        project_name='Source filter', approved_policy_id=POLICY_ID)
    spec = plan['rendering_spec']
    files = _members(native_blueprint.deterministic_prototype_zip(spec))
    trace = native_blueprint.prototype_trace(spec)
    objects = {o['id']: o for s in packet['sources'] for o in s['facts']['objects']}
    for b in trace['blocks']:
        b['source_module_id'] = objects[b['source_block_id']]['module_id']
    for name, raw in docs:
        files['fox-package/sources/' + name] = raw
    return packet, chunks, trace, files


def apply(raw=None):
    docs = [('dispatch.xml', raw or source())]
    args = prepare(docs)
    files, receipt = apply_manifest_filters(docs, *args)
    return files, receipt, args


def test_full_native_read_adapter_uses_source_table_and_preserves_demo_scope():
    docs = [('dispatch.xml', source())]
    args = prepare(docs)
    before = deepcopy((docs, args))
    files, receipt = apply_manifest_filters(docs, *args)
    assert (docs, args) == before
    assert (files, receipt) == apply_manifest_filters(docs, *args)
    assert not receipt['gaps'] and len(receipt['generated_operations']) == 1
    op = receipt['generated_operations'][0]
    assert op['kind'] == 'source_filtered_block_query'
    assert op['source_table'] == 'OPS.MANIFEST_ROWS'
    assert '\nFROM OPS.MANIFEST_ROWS\n' in op['source_query_sql']
    assert 'ORDER BY SERIAL DESC NULLS FIRST' in op['source_query_sql']
    assert op['order_status'] == 'adapted_on_source_screen_only'
    assert len(op['source_bindings']) == 3
    assert {t['source_column'] for t in op['terms']} == {'KIND', 'DEPOT'}
    mapped = {f['source_item_id']: f['column'] for f in args[2]['blocks'][0]['items']}
    assert all(t['column'] == mapped[t['source_item_id']] for t in op['terms'])
    page = files[op['page_file']].decode()
    assert 'authentication: required' in page and 'argumentsMustHaveChecksum' in page
    assert 'type: expression' in page and op['readiness_item'] in page
    assert 'Existing reports, lookups, related records and drafts use synthetic' in page
    assert 'type: executeCode' not in page and '    pageItem ' not in page
    assert '    process ' not in page and '    branch ' not in page
    assert not op['block_wide_filter_applied'] and not op['synthetic_predicate_applied']
    assert op['scope_status'] == 'partial_read_adapter'
    assert not any(op[k] for k in ('original_interface_enabled', 'source_query_executed',
                                  'customer_table_writes', 'runtime_verified', 'business_accepted'))
    original_report = args[3][op['report_files'][0]].decode()
    assert files[op['report_files'][0]].decode().startswith(original_report[:-2])
    changed = {op['report_files'][0], 'shared-components/app-items.apx'}
    assert all(files[n] == raw for n, raw in args[3].items() if n not in changed)
    assert files['fox-package/sources/dispatch.xml'] == docs[0][1]


def test_emitted_predicate_enforces_trusted_origin_and_readiness_without_writes():
    _, receipt, (_, _, trace, _) = apply()
    op = receipt['generated_operations'][0]
    db = sqlite3.connect(':memory:')
    db.execute('attach database ":memory:" as OPS')
    db.execute('create table OPS.MANIFEST_ROWS (KIND text, DEPOT text, SERIAL number)')
    db.executemany('insert into OPS.MANIFEST_ROWS values (?,?,?)',
                   [('1', 'JKT', 1), ('1', 'JKT', 3), ('1', 'BDG', 2), ('2', 'JKT', 4), ('1', None, 5)])
    global_item = op['global_bindings'][0]['app_item']
    for ready, origin, expected in ((None, None, []), ('N', 'JKT', []),
                                    ('Y', None, []), ('Y', 'JKT', [3, 1]),
                                    ('Y', 'BDG', [2]), ('Y', "JKT' OR 1=1 --", [])):
        before = db.total_changes
        rows = db.execute(op['source_query_sql'], {op['readiness_item']: ready, global_item: origin}).fetchall()
        assert [r[2] for r in rows] == expected
        assert db.total_changes == before
    # The equivalent hashed predicate is explicitly a plan, not installed on
    # every synthetic read path. Prove its field mapping without that claim.
    block = trace['blocks'][0]
    db.execute('create table ' + block['table_name'] + ' (' +
               ','.join(f['column'] + ' text' for f in op['source_bindings']) + ')')
    db.executemany('insert into ' + block['table_name'] + ' values (?,?,?)',
                   [('1', 'JKT', '1'), ('2', 'JKT', '2'), ('1', 'BDG', '3')])
    assert db.execute('select * from ' + block['table_name'] + ' where ' +
                      op['synthetic_predicate_sql'], {global_item: 'JKT'}).fetchall() == [('1', 'JKT', '1')]


def test_shared_global_provider_is_restricted_module_bound_and_has_no_default():
    files, receipt, _ = apply()
    op = receipt['generated_operations'][0]
    ref = op['global_bindings'][0]
    key = json.dumps([op['source_module_id'], ['GLOBAL', 'ORIGIN']],
                     ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
    assert ref['app_item'] == 'FOX_RG_G_' + hashlib.sha256(key).hexdigest()[:20].upper()
    app = files['shared-components/app-items.apx'].decode()
    assert app.count('sessionStateProtection: restricted') == 2
    assert 'default:' not in app and 'source:' not in app
    assert ref['trusted_provider_required']


@pytest.mark.parametrize('clause', [
    'KIND=1 OR DEPOT=:GLOBAL.ORIGIN', 'KIND=1;', 'KIND=1 -- tail',
    'KIND=1 /* tail */', 'KIND=1 AND', 'KIND <> 1', 'KIND=:OTHER.ORIGIN',
    'KIND=:ORIGIN', 'KIND=DEPOT', 'LOWER(KIND)=1', 'MANIFESTS.KIND=1',
    'KIND IS NULL', 'KIND=1 UNION SELECT A FROM B', 'KIND=1 AND DEPOT=:GLOBAL.ORIGIN; COMMIT;',
    "KIND='&SESSION.'", "KIND='```'", "KIND='bad\x01'", "KIND='bad\u2028line'", '',
])
def test_unknown_or_partial_clause_never_generates_an_unfiltered_read(clause):
    with pytest.raises(ValueError):
        parse_where_clause(clause)
    if '\x01' in clause:
        with pytest.raises(ValueError): apply(source(clause))
    elif clause:
        _, receipt, _ = apply(source(clause))
        assert not receipt['generated_operations'] and len(receipt['gaps']) == 1


def test_literals_are_reconstructed_and_numeric_types_require_proof():
    terms, _ = parse_where_clause("KIND='O''Hare AND X' AND SERIAL=-2.5")
    assert terms[0]['value']['value'] == "O'Hare AND X"
    files, receipt, _ = apply(source("KIND='O''Hare AND X' AND SERIAL=-2.5"))
    op = receipt['generated_operations'][0]
    assert "KIND = 'O''Hare AND X'" in op['source_query_sql']
    assert 'SERIAL = -2.5' in op['source_query_sql']
    assert not op['global_bindings']
    _, receipt, _ = apply(source("KIND=1"))
    assert not receipt['generated_operations']


@pytest.mark.parametrize('change', ['unknown_column', 'duplicate_column', 'computed',
                                   'query_source', 'injected_table', 'date_bind'])
def test_ambiguous_or_unproven_source_interfaces_stay_gaps(change):
    raw = source()
    if change == 'unknown_column': raw = source("MISSING='1'")
    if change == 'duplicate_column': raw = source(extra='<Item Name="OTHER" ColumnName="KIND" DataType="Char" DatabaseItem="true" ItemType="Text Item"/>')
    if change == 'computed': raw = source(kind_extra='Formula="1"')
    if change == 'query_source': raw = source(query_type='From clause query')
    if change == 'injected_table': raw = source(table='OPS.X;DELETE')
    if change == 'date_bind': raw = source('SERIAL=:GLOBAL.ORIGIN')
    _, receipt, (_, _, _, originals) = apply(raw)
    assert not receipt['generated_operations'] and receipt['gaps']
    files, _, _ = apply(raw)
    assert files == originals


def test_unsupported_order_remains_explicit_and_does_not_weaken_filter():
    _, receipt, _ = apply(source(order='LOWER(KIND)'))
    op = receipt['generated_operations'][0]
    assert op['order_status'] == 'separate_unimplemented'
    assert 'ORDER BY' not in op['source_query_sql']
    assert 'KIND =' in op['source_query_sql'] and 'DEPOT =' in op['source_query_sql']


def test_unproven_projection_is_omitted_visibly_without_dropping_any_predicate():
    raw = source(extra='<Item Name="EVENT_DATE" DataType="Datetime" DatabaseItem="true" ItemType="Text Item"/>')
    files, receipt, _ = apply(raw)
    op = receipt['generated_operations'][0]
    assert not op['source_projection_complete']
    assert {o['source_item_name'] for o in op['projection_omissions']} == {'DECORATION', 'EVENT_DATE'}
    assert '2 source items are omitted' in files[op['page_file']].decode()
    assert 'EVENT_DATE AS' not in op['source_query_sql']
    assert 'KIND =' in op['source_query_sql'] and 'DEPOT =' in op['source_query_sql']
    _, blocked, _ = apply(raw.replace(b"KIND=&#x27;1&#x27;", b"EVENT_DATE=&#x27;1&#x27;"))
    assert not blocked['generated_operations'] and blocked['gaps']


def test_unsupported_duplicate_source_column_cannot_hide_ambiguity():
    _, receipt, _ = apply(source(extra='<Item Name="OTHER" ColumnName="DEPOT" DataType="Datetime" DatabaseItem="true" ItemType="Text Item"/>'))
    assert not receipt['generated_operations'] and receipt['gaps']


def test_multiple_modules_and_altered_ids_do_not_share_origin_provider():
    docs = [('one.xml', source()), ('two.xml', source(module='RENAMED', block='LOADS', table='LOAD_ROWS'))]
    files, receipt = apply_manifest_filters(docs, *prepare(docs))
    ops = receipt['generated_operations']
    assert len(ops) == 2 and not receipt['gaps']
    assert len({o['page_file'] for o in ops}) == 2
    assert len({o['global_bindings'][0]['app_item'] for o in ops}) == 2
    assert {o['source_table'] for o in ops} == {'OPS.MANIFEST_ROWS', 'LOAD_ROWS'}
    assert len(files) > len(prepare(docs)[3])


@pytest.mark.parametrize('change', ['chunk', 'packet', 'trace', 'field', 'module', 'app_security'])
def test_source_or_security_tampering_cannot_acquire_source_query(change):
    docs = [('dispatch.xml', source())]
    packet, chunks, trace, files = prepare(docs)
    if change == 'chunk': chunks[0]['text'] += ' OR 1=1'
    if change == 'packet': packet['sources'][0]['facts']['code_units'][0]['sha256'] = '0' * 64
    if change == 'trace': trace['source_binding'] = 'changed'
    if change == 'field': trace['blocks'][0]['items'][0]['database_bound'] = False
    if change == 'module': trace['blocks'][0]['source_module_id'] = 'changed'
    if change == 'app_security':
        _, receipt = apply_manifest_filters(docs, packet, chunks, trace, files)
        name = receipt['generated_operations'][0]['global_bindings'][0]['app_item']
        files['shared-components/app-items.apx'] = f'appItem {name} (\n    scope: app\n)\n'.encode()
    if change in ('chunk', 'packet', 'trace'):
        with pytest.raises(ValueError): apply_manifest_filters(docs, packet, chunks, trace, files)
    else:
        returned, receipt = apply_manifest_filters(docs, packet, chunks, trace, files)
        assert not receipt['generated_operations'] and receipt['gaps']
        assert returned == files


def test_repeat_adapter_application_is_rejected():
    files, _, args = apply()
    with pytest.raises(ValueError, match='ALREADY_ADAPTED'):
        apply_manifest_filters([('dispatch.xml', source())], *args[:3], files)
