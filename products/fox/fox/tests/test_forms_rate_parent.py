"""Small deterministic source boundaries; no Oracle or live browser claim."""
from copy import deepcopy
import io
import json
import zipfile
from xml.etree import ElementTree as ET

import pytest

from fox.forms_rate_parent import (compile_rate_parent, validate_rate_parent,
                                   validate_parent_values, _digest)
from fox.forms_route_lookup_plan import compile_row_lookups
from fox.forms_relation_plan import build_relation_plan
from fox.forms_native_plan import POLICY_ID, build_native_prototype_plan
from fox.xml_mapping import _blueprint
from forms2apex import native_relations, native_blueprint
from test_forms_route_lookup_plan import SOURCE as ROUTE_SOURCE, prepare


def _source():
    root = ET.fromstring(ROUTE_SOURCE)
    parent = root.find("./Block[@Name='HEADER']")
    parent.set('QueryDataSourceName', 'PARENT_SOURCE')
    first = parent.find('Item')
    first.set('DatabaseItem', 'true')
    first.set('DataLengthSemantics', 'BYTE')
    first.set('MaximumLength', '10')
    ET.SubElement(parent, 'Item', Name='BRANCH', ItemType='Text Item', DataType='Char',
                  DatabaseItem='true', MaximumLength='20', DataLengthSemantics='BYTE', Required='true')
    ET.SubElement(parent, 'Relation', Name='HEADER_LINES', RelationType='Join', DetailBlock='LINES',
                  JoinCondition='PARENT_ID=HEADER.LABEL AND PARENT_BRANCH=HEADER.BRANCH',
                  Deferred='false', AutoQuery='false', PreventMasterlessOperations='false', DeleteRecord='Non Isolated')
    child = root.find("./Block[@Name='LINES']")
    child.set('DatabaseBlock', 'true')
    for item in child.findall('Item'):
        item.set('DataType', 'Char')
        item.attrib.setdefault('DatabaseItem', 'true')
    ET.SubElement(child, 'Item', Name='PARENT_ID', ItemType='Text Item', DataType='Char',
                  DatabaseItem='true', MaximumLength='10', DataLengthSemantics='BYTE', Required='true',
                  CopyValueFromItem='HEADER.LABEL')
    ET.SubElement(child, 'Item', Name='PARENT_BRANCH', ItemType='Text Item', DataType='Char',
                  DatabaseItem='true', MaximumLength='30', CopyValueFromItem='HEADER.BRANCH')
    return ET.tostring(root)


SOURCE = _source()


def setup(raw=SOURCE):
    args = list(prepare(raw))
    docs, packet, chunks, trace, files, _, _ = args
    spec = build_native_prototype_plan(docs, _blueprint(packet), project_id=trace['project_id'],
        project_name='Parent proof', approved_policy_id=POLICY_ID)['rendering_spec']
    # Relation navigation precedes later LOV controls in the actual pipeline.
    baseline = native_blueprint.render_native_blueprint(spec)
    for block in trace['blocks']:
        files[block['report_file']] = baseline[block['report_file']].encode()
    files['fox-package/source-to-page.json'] = json.dumps(trace).encode()
    files['fox-package/source-manifest.json'] = json.dumps({
        'source_binding': packet['source_binding'],
        'files': [{k: s['source'][k] for k in ('name', 'sha256', 'bytes')} for s in packet['sources']],
        'selected_chunk_hashes': {c['id']: c['sha256'] for c in chunks}}).encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    plan = build_relation_plan(docs, output.getvalue())
    if plan['operations']:
        rendered, _ = native_relations.render_relation_package(output.getvalue(), plan)
        with zipfile.ZipFile(io.BytesIO(rendered)) as archive:
            args[4] = {n: archive.read(n) for n in archive.namelist()}
    route, = compile_row_lookups(*args)
    return args, route


def compile_source(raw=SOURCE):
    args, route = setup(raw)
    return compile_rate_parent(*args, route)


def change(name, **properties):
    root = ET.fromstring(SOURCE)
    node = next(n for n in root.iter() if n.get('Name') == name)
    for key, value in properties.items():
        if value is None:
            node.attrib.pop(key, None)
        else:
            node.set(key, value)
    return ET.tostring(root)


@pytest.mark.parametrize('renamed', [False, True])
def test_explicit_complete_copy_is_deterministic_and_preserves_inputs(renamed):
    raw = SOURCE
    if renamed:
        for old, new in ((b'HEADER', b'OWNER'), (b'LINES', b'DETAILS'), (b'PARENT_ID', b'ACCOUNT'),
                         (b'PARENT_BRANCH', b'OFFICE'), (b'BRANCH', b'DIVISION'), (b'LABEL', b'CODE')):
            raw = raw.replace(old, new)
    args, route = setup(raw)
    before = deepcopy((args, route))
    receipt = compile_rate_parent(*args, route)
    assert receipt == compile_rate_parent(*args, route)
    assert (args, route) == before
    assert validate_rate_parent(receipt, route) == receipt
    binding = receipt['binding']
    assert binding is not None
    assert [f['column'] for f in binding['join_pairs']] == ['K001', 'K002']
    assert [f['max_length'] for f in binding['join_pairs']] == [10, 30]
    assert [f['required'] for f in binding['join_pairs']] == [True, False]
    assert binding['join_pairs'][1]['source_length_semantics'] is None
    assert binding['join_pairs'][1]['length_semantics'] == 'BYTE'
    assert len(receipt['gaps']) == 1 and 'SOURCE_LENGTH_SEMANTICS_ABSENT' in receipt['gaps'][0]['reason']
    assert binding['parent']['table'].startswith('FOX_NATIVE_')
    assert len(binding['parent_snapshot_columns']) == 2
    assert binding['copy_policy'] == 'atomic_create_only_immutable_parent_snapshot'
    assert all(not receipt[k] for k in ('runtime_verified', 'business_accepted', 'customer_table_writes',
                                       'implicit_event_context', 'source_query_executed'))
    checked = validate_rate_parent(receipt, route)
    checked['binding']['join_pairs'][0]['child_name'] = 'CHANGED'
    assert checked != receipt


@pytest.mark.parametrize('name,properties,reason', [
    ('PARENT_ID', {'CopyValueFromItem': None}, 'EXPLICIT_COMPONENT_COPY_REQUIRED'),
    ('PARENT_BRANCH', {'CopyValueFromItem': 'OTHER.BRANCH'}, 'EXPLICIT_COMPONENT_COPY_REQUIRED'),
    ('PARENT_ID', {'CopyValueFromItem': ':HEADER.LABEL'}, 'EXPLICIT_COMPONENT_COPY_REQUIRED'),
    ('PARENT_BRANCH', {'InitialValue': 'NORTH'}, 'OVERRIDE'),
    ('PARENT_BRANCH', {'SynchronizeWithItem': 'HEADER.BRANCH'}, 'OVERRIDE'),
    ('PARENT_BRANCH', {'Formula': '1'}, 'OVERRIDE'),
    ('PARENT_BRANCH', {'UpdateAllowed': 'false'}, 'EDIT_DISABLED'),
    ('PARENT_BRANCH', {'InsertAllowed': 'false'}, 'EDIT_DISABLED'),
    ('PARENT_BRANCH', {'Required': 'unknown'}, 'NULL_RULE'),
    ('PARENT_BRANCH', {'DataLengthSemantics': 'unknown'}, 'SEMANTICS'),
    ('PARENT_BRANCH', {'MaximumLength': None}, 'LENGTH'),
    ('PARENT_BRANCH', {'DatabaseItem': 'false'}, 'STORED_CHARACTER'),
    ('PARENT_BRANCH', {'DataType': 'Number'}, 'STORED_CHARACTER'),
    ('BRANCH', {'InitialValue': ':GLOBAL.BRANCH'}, 'OVERRIDE'),
    ('BRANCH', {'DatabaseItem': 'false'}, 'STORED_CHARACTER'),
    ('HEADER_LINES', {'JoinCondition': 'PARENT_ID=HEADER.LABEL OR PARENT_BRANCH=HEADER.BRANCH'}, 'qualified_equality'),
])
def test_unproved_component_never_emits_partial_copy(name, properties, reason):
    receipt = compile_source(change(name, **properties))
    assert receipt['binding'] is None
    assert any(reason in g['reason'] for g in receipt['gaps'])


@pytest.mark.parametrize('body', [
    'BEGIN :LINES.PARENT_ID := NULL; END;',
    'BEGIN CHECK_IT(:PARENT_BRANCH); END;',
    "BEGIN COPY('OTHER','LINES.PARENT_BRANCH'); END;",
    "BEGIN SET_ITEM_PROPERTY('LINES.PARENT_ID',UPDATE_ALLOWED,PROPERTY_FALSE); END;",
])
def test_conflicting_or_uncertain_event_is_an_actionable_gap(body):
    root = ET.fromstring(SOURCE)
    ET.SubElement(root, 'ProgramUnit', Name='OVERRIDE', ProgramUnitText='PROCEDURE OVERRIDE IS ' + body)
    receipt = compile_source(ET.tostring(root))
    assert receipt['binding'] is None and receipt['gaps']


def test_relation_alone_and_legacy_trigger_never_grant_copy_authority():
    root = ET.fromstring(SOURCE)
    child = root.find("./Block[@Name='LINES']")
    for item in child.findall('Item'):
        item.attrib.pop('CopyValueFromItem', None)
    ET.SubElement(child, 'Trigger', Name='PRE-INSERT',
                  TriggerText='BEGIN :PARENT_ID := :HEADER.LABEL; :PARENT_BRANCH := :HEADER.BRANCH; END;')
    receipt = compile_source(ET.tostring(root))
    assert receipt['binding'] is None
    assert receipt['gaps'] == []  # Ordinary legacy assignment is outside this feature.


def test_duplicate_incoming_relation_rejects_every_candidate():
    root = ET.fromstring(SOURCE)
    parent = root.find("./Block[@Name='HEADER']")
    other = deepcopy(parent.find('Relation'))
    other.set('Name', 'SECOND_EDGE')
    parent.append(other)
    receipt = compile_source(ET.tostring(root))
    assert receipt['binding'] is None and len(receipt['gaps']) == 2
    assert all('NOT_UNIQUE' in g['reason'] for g in receipt['gaps'])


def test_no_relation_returns_visible_reason_and_none_compatibility():
    root = ET.fromstring(SOURCE)
    parent = root.find("./Block[@Name='HEADER']")
    parent.remove(parent.find('Relation'))
    receipt = compile_source(ET.tostring(root))
    assert receipt['binding'] is None and receipt['gaps']
    assert validate_rate_parent(None, {}) is None


def test_plain_standalone_or_read_relation_has_no_invented_copy_gap():
    root = ET.fromstring(SOURCE)
    for item in root.findall('./Block/Item'):
        item.attrib.pop('CopyValueFromItem', None)
    receipt = compile_source(ET.tostring(root))
    assert receipt['binding'] is None and receipt['gaps'] == []


def test_copies_without_generated_relation_stay_actionable():
    args, route = setup()
    del args[4]['fox-package/relation-receipt.json']
    receipt = compile_rate_parent(*args, route)
    assert receipt['binding'] is None
    assert 'GENERATED_NATIVE_RELATION_REQUIRED' in receipt['gaps'][0]['reason']


def test_saved_parent_read_does_not_require_source_parent_edit_permission():
    root = ET.fromstring(SOURCE)
    parent = root.find("./Block[@Name='HEADER']")
    parent.set('UpdateAllowed', 'false')
    item = parent.find('Item')
    item.set('UpdateAllowed', 'false')
    ET.SubElement(item, 'Trigger', Name='POST-CHANGE', TriggerText='BEGIN NULL; END;')
    receipt = compile_source(ET.tostring(root))
    assert receipt['binding'] is not None
    assert not receipt['customer_table_writes'] and not receipt['implicit_event_context']


def test_trusted_existing_native_buttons_do_not_erase_local_table_proof():
    args, route = setup()
    decorated = prepare(SOURCE)[4]  # Real normal LOV mapper, not a mock button.
    report = next(b for b in args[3]['blocks'] if b['source_block_id'] == route['source_block_id'])['report_file']
    assert b'    button ' in decorated[report] or b'    pageItem ' in decorated[report]
    args[4][report] = decorated[report]
    receipt = compile_rate_parent(*args, route)
    assert receipt['binding'] is not None
    assert receipt['binding']['child']['report_file'] == report


def test_snapshot_scope_is_complete_keys_and_excludes_unrelated_parent_labels():
    root = ET.fromstring(SOURCE)
    parent = root.find("./Block[@Name='HEADER']")
    ET.SubElement(parent, 'Item', Name='DESCRIPTION', ItemType='Text Item', DatabaseItem='true',
                  DataType='Char', MaximumLength='100', DataLengthSemantics='CHAR')
    receipt = compile_source(ET.tostring(root))
    b = receipt['binding']
    assert b['selection_policy'] == 'explicit_row_id_and_current_copied_key_fingerprint'
    assert len(b['parent_native_block']['items']) == 3
    assert b['parent_snapshot_columns'] == [
        {'column': f['parent_column'], 'data_type': 'VARCHAR2'} for f in b['join_pairs']]
    assert len(b['parent_snapshot_columns']) == 2


@pytest.mark.parametrize('part', ['operation', 'action', 'page', 'plan_hash'])
def test_native_relation_proof_mismatch_cannot_create_copy_binding(part):
    args, route = setup()
    files = args[4]
    if part == 'page':
        receipt = json.loads(files['fox-package/relation-receipt.json'])
        del files[receipt['generated_operations'][0]['page_file']]
    elif part == 'action':
        receipt = json.loads(files['fox-package/relation-receipt.json'])
        receipt['generated_operations'][0]['parent_item'] = 'P8999_WRONG'
        files['fox-package/relation-receipt.json'] = json.dumps(receipt).encode()
    else:
        plan = json.loads(files['fox-package/relation-plan.json'])
        if part == 'operation':
            plan['operations'][0]['join_pairs'].pop()
            plan['plan_sha256'] = native_relations._sha(native_relations._json(
                {k: v for k, v in plan.items() if k != 'plan_sha256'}))
            receipt = json.loads(files['fox-package/relation-receipt.json'])
            receipt['plan_sha256'] = plan['plan_sha256']
            receipt['plan_artifact_sha256'] = native_relations._sha(native_relations._json(plan))
            files['fox-package/relation-receipt.json'] = json.dumps(receipt).encode()
        else:
            plan['plan_sha256'] = '0' * 64
        files['fox-package/relation-plan.json'] = json.dumps(plan).encode()
    receipt = compile_rate_parent(*args, route)
    assert receipt['binding'] is None and receipt['gaps']
    assert any('NATIVE_' in g['reason'] for g in receipt['gaps'])


@pytest.mark.parametrize('index', range(7))
def test_fresh_source_receipts_trace_schema_and_originals_are_required(index):
    args, route = setup()
    args = deepcopy(list(args))
    if index == 0:
        args[0][0] = (args[0][0][0], args[0][0][1].replace(b'MaximumLength="30"', b'MaximumLength="31"'))
    elif index == 1:
        args[1]['source_binding'] = 'changed'
    elif index == 2:
        args[2][0]['sha256'] = '0' * 64
    elif index == 3:
        args[3]['blocks'][0]['table_name'] = 'OTHER_TABLE'
    elif index == 4:
        args[4]['fox-package/supporting-schema.sql'] += b'\n-- changed'
    elif index == 5:
        args[5]['scope'] = 'changed'
    else:
        del args[4]['fox-package/sources/shipping.xml']
    with pytest.raises(ValueError):
        compile_rate_parent(*args, route)


@pytest.mark.parametrize('part', ['hash', 'route', 'identity', 'copy', 'limit', 'join', 'storage', 'gates', 'snapshot'])
def test_retained_validator_rejects_tampering_even_after_receipt_rehash(part):
    args, route = setup()
    receipt = compile_rate_parent(*args, route)
    b = receipt['binding']
    if part == 'hash':
        receipt['scope_note'] = 'changed'
    elif part == 'route':
        receipt['project_id'] = 'other'
    elif part == 'identity':
        b['join_pairs'][0]['parent_item_id'] = 'ff1-' + '0' * 24
    elif part == 'copy':
        b['join_pairs'][1]['copy_from'] = 'HEADER.LABEL'
    elif part == 'limit':
        b['join_pairs'][1]['max_length'] = 4000
    elif part == 'join':
        b['join_pairs'].pop()
    elif part == 'storage':
        b['join_pairs'][1]['column'] = 'K001'
    elif part == 'gates':
        receipt['implicit_event_context'] = True
    else:
        b['parent_snapshot_columns'].pop()
    if part != 'hash':
        receipt['contract_id'] = _digest(receipt)
    with pytest.raises(ValueError):
        validate_rate_parent(receipt, route)


@pytest.mark.parametrize('values,valid', [
    (['ACCT01', 'NORTH'], True), (['ACCT01', 'SOUTH'], True),
    (['ACCT01', None], False), ([None, 'NORTH'], False), (['', 'NORTH'], False),
    (['A' * 11, 'NORTH'], False), (['ACCT01', 'B' * 21], False),
    (['ACCT01', 'é' * 11], False), (['é' * 5, 'NORTH'], True),
])
def test_values_reject_null_and_overlength_without_truncation(values, valid):
    args, route = setup()
    receipt = compile_rate_parent(*args, route)
    before = deepcopy((receipt, values))
    if valid:
        assert validate_parent_values(values, receipt, route) == tuple(values)
    else:
        with pytest.raises(ValueError):
            validate_parent_values(values, receipt, route)
    assert (receipt, values) == before
