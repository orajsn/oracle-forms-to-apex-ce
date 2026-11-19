"""Source-supported operations exceeding renderer capacity stay explicit."""
import hashlib
import io
import json
import zipfile
from html import escape

from fox.forms_understanding_packet import _build
from fox.forms_native_plan import POLICY_ID
from fox.xml_mapping import generate_xml_package
from forms2apex.native_behavior import MAX_OPERATIONS


def documents(*, two_guards=False, formulas=1):
    def field(name, guard=False):
        code = f"BEGIN IF NVL(:{name},0)=0 THEN MESSAGE('Required'); RAISE FORM_TRIGGER_FAILURE; END IF; GO_ITEM('STATE'); END;"
        trigger = f'<Trigger Name="KEY-NEXT-ITEM" TriggerText="{escape(code, quote=True)}"/>' if guard else ''
        return f'<Item Name="{name}" ItemType="Text Item" DataType="Number" DatabaseItem="true">{trigger}</Item>'
    xml = ('<FormModule Name="CAPACITY"><Block Name="DETAIL" DatabaseBlock="true">'
           + field('FIRST', True) + field('SECOND', two_guards)
           + '<Item Name="STATE" ItemType="Text Item" DataType="Char" MaximumLength="30" DatabaseItem="true"/>'
           + ''.join(f'<Item Name="F{i}" ItemType="Display Item" DataType="Number" DatabaseItem="false" Formula=":FIRST + {i}"/>' for i in range(formulas))
           + '</Block></FormModule>')
    return [('capacity.xml', xml.encode())]


def generate(docs):
    return generate_xml_package(docs, 'capacity-test', 'Capacity test', POLICY_ID)


def test_two_guards_on_one_report_keep_other_rule_and_complete_ledger():
    docs = documents(two_guards=True)
    candidate, report = generate(docs)
    plan = report['behavior_plan']
    coverage = report['mapping_ledger']['code_units']
    assert len(coverage) == 3
    assert [op['kind'] for op in plan['operations']] == ['numeric_nonzero_then_focus', 'numeric_expression_report_column']
    deferred = [row for row in coverage if row['status'] == 'unsupported']
    assert len(deferred) == 1
    assert deferred[0]['reason'] == 'report_validation_link_capacity_exceeded'
    assert deferred[0]['rule_id'] == 'fox.behavior.unresolved-unit'
    assert deferred[0]['target'] is None
    assert candidate == generate(docs)[0]
    with zipfile.ZipFile(io.BytesIO(candidate)) as archive:
        assert archive.read('fox-package/sources/capacity.xml') == docs[0][1]
        pages = [archive.read(n).decode() for n in archive.namelist() if n.endswith('.apx')]
    assert sum('name: Value validation only' in page for page in pages) == 1
    assert sum('type: sqlQuery' in page for page in pages) >= 1


def test_operation_cap_preserves_hashes_and_only_defers_excess_rules():
    docs = documents(formulas=MAX_OPERATIONS + 1)
    candidate, report = generate(docs)
    plan = report['behavior_plan']
    ledger = report['mapping_ledger']['code_units']
    assert len(plan['operations']) == MAX_OPERATIONS
    assert len(ledger) == MAX_OPERATIONS + 2
    assert sum(row['status'] == 'generated_wired_adapted' for row in ledger) == MAX_OPERATIONS
    assert sum(row.get('reason') == 'behavior_operation_capacity_exceeded' for row in ledger) == 2
    _, chunks = _build(docs)
    assert {r['source_unit_id']: r['source_unit_sha256'] for r in ledger} == {c['code_unit_id']: c['sha256'] for c in chunks}
    unsigned = {k:v for k,v in plan.items() if k != 'plan_sha256'}
    assert plan['plan_sha256'] == hashlib.sha256(json.dumps(unsigned,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
    assert report['metadata']['runtime_verified'] is False
    assert report['metadata']['business_behavior_accepted'] is False
