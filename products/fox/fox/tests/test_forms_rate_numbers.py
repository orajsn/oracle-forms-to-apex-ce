"""Small synthetic source/compiler checks; no Oracle execution is claimed."""
from copy import deepcopy
from decimal import Decimal
from xml.etree import ElementTree as ET

import pytest

from fox.forms_rate_numbers import (compile_rate_numbers, validate_rate_numbers,
                                    numeric_rules, validate_numeric_value, _digest)
from fox.forms_route_lookup_plan import compile_row_lookups
from test_forms_rate_choices import SOURCE as CHOICE_SOURCE
from test_forms_route_lookup_plan import prepare


ITEM = b'''<Item Name="AMOUNT" ColumnName="RATE_AMOUNT" DatabaseItem="true"
 ItemType="Text Item" DataType="Number" Prompt="Amount" FormatMask="99,999,990.90" MaximumLength="12"/>'''
def _source():
    root = ET.fromstring(CHOICE_SOURCE)
    block = root.find("./Block[@Name='LINES']")
    block.set('DatabaseBlock', 'true')
    for item in block.findall('Item'):
        item.set('DataType', 'Char')
        item.attrib.setdefault('DatabaseItem', 'true')
    return ET.tostring(root).replace(b'<Trigger Name="WHEN-CREATE-RECORD"',
                                    ITEM + b'<Trigger Name="WHEN-CREATE-RECORD"')


SOURCE = _source()


def prepare_numbers(raw=SOURCE):
    args = prepare(raw)
    route, = compile_row_lookups(*args)
    return args, route


def compile_source(raw=SOURCE):
    args, route = prepare_numbers(raw)
    return compile_rate_numbers(*args, route)


def change(**properties):
    root = ET.fromstring(SOURCE)
    item = root.find("./Block/Item[@Name='AMOUNT']")
    for key, value in properties.items():
        if value is None:
            item.attrib.pop(key, None)
        else:
            item.set(key, value)
    return ET.tostring(root)


@pytest.mark.parametrize('rename', [False, True])
def test_complete_source_identity_and_optional_number_are_deterministic(rename):
    raw = SOURCE
    if rename:
        for old, new in [(b'SHIPPING', b'ORDERING'), (b'LINES', b'POSITIONS'),
                         (b'AMOUNT', b'UNIT_PRICE'), (b'RATE_AMOUNT', b'PRICE_VALUE')]:
            raw = raw.replace(old, new)
    args, route = prepare_numbers(raw)
    original = deepcopy((args, route))
    receipt = compile_rate_numbers(*args, route)
    assert compile_rate_numbers(*args, route) == receipt
    assert (args, route) == original
    assert validate_rate_numbers(receipt, route) == receipt
    field, = receipt['fields']
    assert receipt['gaps'] == []
    assert field['column'] == 'N001' and field['slot'] == 1 and field['data_type'] == 'NUMBER'
    assert field['integer_digits'] == 8 and field['scale'] == 2
    assert field['precision'] is None and field['min_value'] is None and field['max_value'] is None
    assert field['max_length'] == 12 and field['required'] is False
    assert field['source_event_scan'] and all(not p['native_event_wired'] for p in field['source_event_scan'])
    assert field['direct_edit_allowed'] and not field['programmatic_return_allowed']
    assert not receipt['runtime_verified'] and not receipt['business_accepted']
    assert not receipt['customer_table_writes'] and not receipt['original_interface_enabled']
    checked = validate_rate_numbers(receipt, route)
    checked['fields'][0]['label'] = 'changed copy'
    assert receipt['fields'][0]['label'] == 'Amount'


@pytest.mark.parametrize('properties,reason', [
    ({'DatabaseItem': 'false'}, 'STORED_NUMBER'),
    ({'DatabaseItem': None}, 'STORED_NUMBER'),
    ({'ColumnName': None}, 'COLUMN'),
    ({'ItemType': 'Display Item'}, 'STORED_NUMBER'),
    ({'ItemType': 'List Item'}, 'STORED_NUMBER'),
    ({'Formula': ':VIA+1'}, 'DERIVED_NUMBER'),
    ({'CalculateMode': 'Summary'}, 'DERIVED_NUMBER'),
    ({'CalculationMode': 'Formula'}, 'DERIVED_NUMBER'),
    ({'SummaryFunction': 'SUM'}, 'DERIVED_NUMBER'),
    ({'InitialValue': '0'}, 'SOURCE_DEFAULT'),
    ({'CopyValueFromItem': 'LINES.VIA'}, 'SOURCE_DEFAULT'),
    ({'SynchronizeWithItem': 'LINES.VIA'}, 'SOURCE_DEFAULT'),
    ({'ImplementationClass': 'unproved.JavaItem'}, 'JAVA_POLICY'),
    ({'PropertyClass': 'UNPROVED'}, 'INHERITED'),
    ({'LovName': 'UNKNOWN'}, 'LIST_NUMBER'),
    ({'ValidateFromList': 'true'}, 'LIST_NUMBER'),
    ({'InsertAllowed': 'false'}, 'EDIT_DISABLED'),
    ({'UpdateAllowed': 'false'}, 'EDIT_DISABLED'),
    ({'Enabled': 'false'}, 'EDIT_DISABLED'),
    ({'Required': 'unknown'}, 'NULL_RULE'),
    ({'FormatMask': None}, 'PICTURE'),
    ({'FormatMask': '99G999D00'}, 'PICTURE'),
    ({'FormatMask': '99.99EEEE'}, 'PICTURE'),
    ({'MaximumLength': None}, 'NUMERIC_LIMITS'),
    ({'LowestAllowedValue': ':HEADER.LABEL'}, 'BOUND'),
    ({'LowestAllowedValue': '2', 'HighestAllowedValue': '1'}, 'BOUND_ORDER'),
])
def test_unproved_numeric_properties_remain_visible_gaps(properties, reason):
    receipt = compile_source(change(**properties))
    assert receipt['fields'] == [] and len(receipt['gaps']) == 1
    gap, = receipt['gaps']
    assert reason in gap['reason']
    assert gap['source_name'] == 'AMOUNT' and gap['native_event_wired'] is False


def test_absent_numeric_fields_preserves_empty_receipt_and_none_compatibility():
    receipt = compile_source(SOURCE.replace(ITEM, b''))
    assert receipt['fields'] == [] and receipt['gaps'] == []
    assert validate_rate_numbers(None, {}) is None


@pytest.mark.parametrize('body', [
    'BEGIN :LINES.AMOUNT := 1; END;',
    'BEGIN CHECK_PRICE(:AMOUNT); END;',
    'BEGIN :"LINES"."AMOUNT" := 1; END;',
    'BEGIN SELECT AMOUNT INTO :LINES.AMOUNT FROM OLD_LINES; END;',
    "BEGIN COPY('1','LINES.AMOUNT'); END;",
    "BEGIN x := NAME_IN('LINES.AMOUNT'); END;",
    "BEGIN COPY('1',:TARGET); END;",
    "BEGIN DEFAULT_VALUE('1','LINES.AMOUNT'); END;",
    "BEGIN SET_ITEM_PROPERTY('LINES.AMOUNT', UPDATE_ALLOWED, PROPERTY_FALSE); END;",
])
def test_source_references_and_dynamic_numeric_policy_remain_gaps(body):
    extra = ET.Element('ProgramUnit', Name='EDIT_POLICY', ProgramUnitText='PROCEDURE EDIT_POLICY IS ' + body)
    receipt = compile_source(SOURCE.replace(b'</FormModule>', ET.tostring(extra) + b'</FormModule>'))
    assert receipt['fields'] == [] and len(receipt['gaps']) == 1


def test_item_trigger_is_not_silently_dropped():
    root = ET.fromstring(SOURCE)
    item = root.find("./Block/Item[@Name='AMOUNT']")
    ET.SubElement(item, 'Trigger', Name='WHEN-VALIDATE-ITEM', TriggerText='BEGIN NULL; END;')
    receipt = compile_source(ET.tostring(root))
    assert not receipt['fields'] and 'ITEM_EVENT_UNIMPLEMENTED' in receipt['gaps'][0]['reason']


def test_comments_literals_and_unrelated_static_dynamic_references_are_not_field_events():
    body = "PROCEDURE SAFE IS BEGIN MESSAGE('AMOUNT'); /* :LINES.AMOUNT */ COPY('x','HEADER.LABEL'); END;"
    extra = ET.Element('ProgramUnit', Name='SAFE', ProgramUnitText=body)
    receipt = compile_source(SOURCE.replace(b'</FormModule>', ET.tostring(extra) + b'</FormModule>'))
    assert len(receipt['fields']) == 1 and receipt['gaps'] == []


def test_shared_number_column_aliases_are_ambiguous_and_never_partially_emitted():
    other = ITEM.replace(b'Name="AMOUNT"', b'Name="OTHER_AMOUNT"')
    receipt = compile_source(SOURCE.replace(ITEM, ITEM + other))
    assert receipt['fields'] == [] and len(receipt['gaps']) == 2


def test_independent_numbers_keep_separate_contiguous_numeric_slots():
    other = ITEM.replace(b'Name="AMOUNT"', b'Name="OTHER_AMOUNT"').replace(b'ColumnName="RATE_AMOUNT"', b'ColumnName="OTHER_VALUE"')
    receipt = compile_source(SOURCE.replace(ITEM, ITEM + other))
    assert [f['column'] for f in receipt['fields']] == ['N001', 'N002']


def test_source_or_normal_receipt_tampering_is_rejected_before_fields_compile():
    args, route = prepare_numbers()
    damaged = list(deepcopy(args))
    damaged[4]['fox-package/sources/shipping.xml'] += b' '
    with pytest.raises(ValueError, match='ORIGINAL_SOURCES_REQUIRED'):
        compile_rate_numbers(*damaged, route)
    stale = deepcopy(route)
    stale['project_id'] = 'another-project'
    with pytest.raises(ValueError, match='FRESH_ROUTE_REQUIRED'):
        compile_rate_numbers(*args, stale)


@pytest.mark.parametrize('key,value', [('source_binding', 'changed'), ('project_id', 'other'),
                                        ('source_block_id', 'ff1-'+'0'*24), ('route_contract_id', 'other')])
def test_even_rehashed_receipts_cannot_cross_source_or_project_binding(key, value):
    args, route = prepare_numbers()
    receipt = compile_rate_numbers(*args, route)
    receipt[key] = value
    receipt['contract_id'] = _digest(receipt)
    with pytest.raises(ValueError):
        validate_rate_numbers(receipt, route)


@pytest.mark.parametrize('key,value', [('column', 'F001'), ('slot', 2), ('scale', 1),
                                        ('required', True), ('min_value', '0'), ('precision', 10),
                                        ('direct_edit_allowed', False)])
def test_rehashed_field_rule_changes_are_rejected(key, value):
    args, route = prepare_numbers()
    receipt = compile_rate_numbers(*args, route)
    receipt['fields'][0][key] = value
    receipt['contract_id'] = _digest(receipt)
    with pytest.raises(ValueError):
        validate_rate_numbers(receipt, route)


@pytest.mark.parametrize('property_name,value', [('Formula', '1'), ('LovName', 'UNKNOWN'),
    ('InitialValue', '0'), ('ColumnName', 'SOME_OTHER_COLUMN'), ('ImplementationClass', 'unproved.JavaItem')])
def test_rehashed_properties_cannot_bypass_unsupported_numeric_semantics(property_name, value):
    from forms2apex import native_record_groups as groups
    args, route = prepare_numbers()
    receipt = compile_rate_numbers(*args, route)
    field, = receipt['fields']
    field['source_properties'][property_name] = value
    field['source_properties_sha256'] = groups._sha(groups._json(field['source_properties']))
    receipt['contract_id'] = _digest(receipt)
    with pytest.raises(ValueError):
        validate_rate_numbers(receipt, route)


def test_unproved_procedure_dml_stays_a_numeric_gap():
    root = ET.fromstring(SOURCE)
    root.find("./Block[@Name='LINES']").set('DMLDataTargetType', 'Procedure')
    receipt = compile_source(ET.tostring(root))
    assert not receipt['fields'] and 'DML_TARGET_UNPROVEN' in receipt['gaps'][0]['reason']


@pytest.mark.parametrize('text,expected', [(None, None), ('', None), ('0', Decimal('0')),
    ('-0', Decimal('-0')), ('+0', Decimal('0')), ('-123.45', Decimal('-123.45')),
    ('+1.20', Decimal('1.20')), ('99999999.99', Decimal('99999999.99')),
    ('-99999999.99', Decimal('-99999999.99')), ('0001.20', Decimal('1.20'))])
def test_optional_signed_numbers_are_exact_with_no_positive_only_assumption(text, expected):
    assert validate_numeric_value(text, numeric_rules(ET.fromstring(ITEM).attrib)) == expected


@pytest.mark.parametrize('text', ['1,234.50', '1.234,50', '1e2', 'NaN', 'Infinity', ' 1', '1 ',
                                  '.5', '1.', '1.230', '100000000', '1234567890123', '--1', '１', 1, False])
def test_unsupported_numeric_notation_overflow_and_fractional_excess_never_round(text):
    with pytest.raises(ValueError):
        validate_numeric_value(text, numeric_rules(ET.fromstring(ITEM).attrib))


def test_required_explicit_signed_bounds_are_canonical_and_enforced():
    p = dict(ET.fromstring(ITEM).attrib, Required='true', LowestAllowedValue='-001.500', HighestAllowedValue='+02.00')
    rules = numeric_rules(p)
    assert rules['min_value'] == '-1.5' and rules['max_value'] == '2'
    assert validate_numeric_value('-1.50', rules) == Decimal('-1.5')
    assert validate_numeric_value('+2.00', rules) == Decimal('2')
    for value in (None, '', '-1.51', '2.01'):
        with pytest.raises(ValueError):
            validate_numeric_value(value, rules)


def test_explicit_bound_requiring_oracle_rounding_is_unproved():
    p = dict(ET.fromstring(ITEM).attrib, LowestAllowedValue='1.' + '0' * 38 + '1')
    with pytest.raises(ValueError, match='EXACT_BOUND_REQUIRED'):
        numeric_rules(p)


CALENDAR_CALLBACK = '''PROCEDURE PICKED_DAY IS BEGIN
 COPY(TO_CHAR(CALENDAR_HELPER.CHOSEN_DAY,'DD-MM-YYYY HH24:MI'),CALENDAR_HELPER.RETURN_TARGET);
 GO_ITEM(CALENDAR_HELPER.RETURN_TARGET);
 IF CALENDAR_HELPER.AUTO_ADVANCE = TRUE THEN NEXT_ITEM; END IF;
END;'''
CALENDAR_CALL = "CALENDAR_HELPER.PICK_DAY(SYSDATE,'BOOKED_DATE',240,60,'Date','OK','Cancel',TRUE,FALSE,FALSE);"


def calendar_source(*, caller=CALENDAR_CALL, callback=CALENDAR_CALLBACK, extra=None):
    root = ET.fromstring(SOURCE)
    block = root.find("./Block[@Name='LINES']")
    date_item = ET.SubElement(block, 'Item', Name='BOOKED_DATE', ItemType='Text Item',
                              DataType='Date', DatabaseItem='true', ColumnName='BOOKED_DATE')
    ET.SubElement(date_item, 'Trigger', Name='KEY-LISTVAL', TriggerText=caller)
    ET.SubElement(root, 'ProgramUnit', Name='PICKED_DAY', ProgramUnitText=callback)
    if extra:
        ET.SubElement(root, 'ProgramUnit', Name='OTHER_BODY', ProgramUnitText=extra)
    return ET.tostring(root)


@pytest.mark.parametrize('renamed', [False, True])
def test_audited_legacy_calendar_is_explicitly_omitted_without_nonoverlap_claim(renamed):
    raw = calendar_source()
    if renamed:
        for before, after in [(b'CALENDAR_HELPER', b'APPOINTMENT_UTIL'), (b'CHOSEN_DAY', b'VALUE_MEMBER'),
                              (b'RETURN_TARGET', b'ITEM_MEMBER'), (b'AUTO_ADVANCE', b'SKIP_MEMBER'),
                              (b'PICK_DAY', b'CHOOSE_DATE'), (b'PICKED_DAY', b'DATE_CALLBACK'),
                              (b'BOOKED_DATE', b'APPOINTMENT_DATE')]:
            raw = raw.replace(before, after)
    receipt = compile_source(raw)
    field, = receipt['fields']
    omission, = field['omitted_legacy_date_callbacks']
    assert omission['kind'] == 'suppressed_external_date_callback'
    assert omission['target_nonoverlap_proven'] is False
    assert omission['native_event_wired'] is False and omission['runtime_verified'] is False
    assert omission['business_accepted'] is False and 'unknown' in omission['reason']
    caller, = omission['callers']
    assert caller['data_type'] == 'DATE' and caller['source_item_id'] != field['source_item_id']
    assert omission['callback'] in field['source_event_scan']
    args, route = prepare_numbers(raw)
    assert validate_rate_numbers(receipt, route) == receipt


@pytest.mark.parametrize('mutation', ['numeric_caller', 'handle_assignment', 'handle_argument',
    'literal_handle_write', 'unknown_package_call', 'other_dynamic_writer', 'callback_extra',
    'callback_different_target', 'caller_extra'])
@pytest.mark.parametrize('renamed', [False, True])
def test_calendar_exception_never_hides_numeric_or_unknown_writers(mutation, renamed):
    callback, caller, extra = CALENDAR_CALLBACK, CALENDAR_CALL, None
    if mutation == 'numeric_caller':
        caller = caller.replace("'BOOKED_DATE'", "'AMOUNT'")
    elif mutation == 'handle_assignment':
        extra = "PROCEDURE OTHER_BODY IS BEGIN CALENDAR_HELPER.RETURN_TARGET := 'AMOUNT'; END;"
    elif mutation == 'handle_argument':
        extra = 'PROCEDURE OTHER_BODY IS BEGIN UNKNOWN_WRITER(CALENDAR_HELPER.RETURN_TARGET); END;'
    elif mutation == 'literal_handle_write':
        extra = "PROCEDURE OTHER_BODY IS BEGIN COPY('AMOUNT','CALENDAR_HELPER.RETURN_TARGET'); END;"
    elif mutation == 'unknown_package_call':
        extra = 'PROCEDURE OTHER_BODY IS BEGIN CALENDAR_HELPER.OTHER_METHOD; END;'
    elif mutation == 'other_dynamic_writer':
        extra = "PROCEDURE OTHER_BODY IS BEGIN COPY('1',:TARGET_ITEM); END;"
    elif mutation == 'callback_extra':
        callback = callback.replace('END;', 'NULL; END;')
    elif mutation == 'callback_different_target':
        callback = callback.replace('GO_ITEM(CALENDAR_HELPER.RETURN_TARGET)', 'GO_ITEM(CALENDAR_HELPER.OTHER_TARGET)')
    elif mutation == 'caller_extra':
        caller += ' NULL;'
    raw = calendar_source(caller=caller, callback=callback, extra=extra)
    if renamed:
        for before, after in [(b'CALENDAR_HELPER', b'APPOINTMENT_UTIL'), (b'BOOKED_DATE', b'APPOINTMENT_DATE'),
                              (b'AMOUNT', b'CHARGE'), (b'LINES', b'ENTRIES')]:
            raw = raw.replace(before, after)
    receipt = compile_source(raw)
    assert not receipt['fields'] and len(receipt['gaps']) == 1


def test_rehashed_calendar_omission_cannot_claim_runtime_or_disjoint_target_state():
    args, route = prepare_numbers(calendar_source())
    receipt = compile_rate_numbers(*args, route)
    for key in ('target_nonoverlap_proven', 'native_event_wired', 'runtime_verified', 'business_accepted'):
        changed = deepcopy(receipt)
        changed['fields'][0]['omitted_legacy_date_callbacks'][0][key] = True
        changed['contract_id'] = _digest(changed)
        with pytest.raises(ValueError, match='DATE_OMISSION_GATES'):
            validate_rate_numbers(changed, route)


def test_nonbind_sql_and_record_identifiers_do_not_become_form_item_writes():
    body = '''PROCEDURE COPY_HISTORY IS
 CURSOR PRICES IS SELECT AMOUNT FROM OLD_LINES;
 BEGIN FOR REC IN PRICES LOOP INSERT INTO ARCHIVE_LINES(AMOUNT) VALUES(REC.AMOUNT); END LOOP; END;'''
    extra = ET.Element('ProgramUnit', Name='COPY_HISTORY', ProgramUnitText=body)
    receipt = compile_source(SOURCE.replace(b'</FormModule>', ET.tostring(extra) + b'</FormModule>'))
    field, = receipt['fields']
    mention, = field['omitted_source_identifier_references']
    assert mention['classification'] == 'non_bind_identifier' and mention['occurrences'] == 3
    assert mention['native_event_wired'] is False
    assert not receipt['customer_table_writes'] and not receipt['runtime_verified']
