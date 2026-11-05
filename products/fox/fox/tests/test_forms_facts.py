"""Synthetic-only local Forms fact tests. No customer sources or provider calls."""
import hashlib
import json
from xml.sax.saxutils import quoteattr

import pytest

from fox import forms_facts
from fox.forms_facts import assess_forms_xml


def synthetic_forms(blocks=9, items=222, triggers=54):
    """Public, fabricated structural fixture; never a customer Forms export."""
    parts = ['<Module xmlns="http://xmlns.oracle.com/Forms"><FormModule Name="SYNTHETIC">',
             '<Canvas Name="MAIN" WindowName="WINDOW"/><Window Name="WINDOW"/>']
    for block in range(blocks):
        parts.append(f'<Block Name="B{block}" DatabaseBlock="{"true" if block % 2 else "false"}" QueryDataSourceName="TABLE_{block}">')
        for item in range(items // blocks + (block < items % blocks)):
            parts.append(f'<Item Name="I{item}" CanvasName="MAIN" DatabaseItem="true" ItemType="Text Item"/>')
        for trigger in range(triggers // blocks + (block < triggers % blocks)):
            code = f"BEGIN INSERT INTO APP.AUDIT_{block} (EVENT_ID, STATUS) VALUES ({trigger}, 'NORMAL'); CUSTOM_API.SAVE(:B{block}.I0); END;"
            parts.append(f'<Trigger Name="TR_{trigger}" TriggerText={quoteattr(code)}/>')
        parts.append('</Block>')
    parts.append('<ProgramUnit Name="LOCAL_API" ProgramUnitType="Procedure" ProgramUnitText="BEGIN NULL; END;"/></FormModule></Module>')
    return ''.join(parts).encode()


@pytest.mark.parametrize('blocks,items,triggers', [(9, 222, 54), (51, 414, 95)])
def test_broad_synthetic_inventory_not_narrow_generation_eligibility(blocks, items, triggers):
    raw = synthetic_forms(blocks, items, triggers)
    facts = assess_forms_xml('synthetic.xml', raw)
    assert facts['totals']['modules'] == 1
    assert facts['totals']['blocks'] == blocks
    assert facts['totals']['items'] == items
    assert facts['totals']['triggers'] == triggers
    assert facts['totals']['program_units'] == 1
    assert facts['totals']['code_units'] == triggers + 1
    assert facts['source'] == {'name': 'synthetic.xml', 'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw), 'encoding': 'utf-8'}
    assert facts['schema_version'] == 1 and facts['scope'] == 'fox-forms-facts-v1'
    assert facts['assessment_status'] == 'LOCAL_FACTS_ONLY'
    assert facts['modules'][0]['object_counts']['Block'] == blocks
    assert facts['safety'] == {'local_only': True, 'code_executed': False, 'model_submission_allowed': False, 'import_allowed': False, 'native_generation_allowed': False}
    assert facts['findings']
    assert any(f['code'] == 'BEHAVIOR_NOT_ASSESSED' for f in facts['findings'])
    assert not any(f['code'] == 'CONFLICTING_OBJECT_NAME' for f in facts['findings'])
    assert {b['classification'] for b in facts['blocks']} == {'database', 'control'}
    assert {d['name'] for d in facts['dependencies']} >= {'APP.AUDIT_0', 'CUSTOM_API.SAVE'}
    rendered = json.dumps(facts)
    assert 'INSERT INTO' not in rendered and 'NORMAL' not in rendered
    assert facts == assess_forms_xml('synthetic.xml', raw)


def test_exact_original_locations_and_decoded_code_hash_no_body():
    code = "BEGIN\n  :B.I := 'é & ordinary';\nEND;"
    raw = ('\ufeff<Module>\n<FormModule Name="SYNTHETIC">\n<Block Name="B" DatabaseBlock="false"><Item Name="I"/>\n'
           f'<Trigger Name="WHEN-VALIDATE-ITEM" TriggerText={quoteattr(code)}/></Block></FormModule></Module>').encode()
    facts = assess_forms_xml('synthetic.xml', raw)
    unit = facts['code_units'][0]
    assert unit['sha256'] == hashlib.sha256(code.encode()).hexdigest()
    assert unit['bytes'] == len(code.encode())
    assert unit['lines'] == 3
    assert unit['source_attribute'] == 'TriggerText'
    location = unit['location']
    assert location['path'] == '/Module[1]/FormModule[1]/Block[1]/Trigger[1]'
    assert location['line'] == 4 and location['column'] == 1
    assert raw[location['byte_offset']:].startswith(b'<Trigger ')
    assert 'ordinary' not in json.dumps(facts)
    assert facts['links'][0]['status'] == 'resolved'


def test_multiple_modules_namespace_and_object_ancestry():
    raw = b'''<Module xmlns:f="http://xmlns.oracle.com/Forms" xmlns:other="urn:other">
    <FormModule Name="A"><Block Name="B" DatabaseBlock="false"><Item Name="I"/></Block></FormModule>
    <f:FormModule Name="B"><f:Block Name="B" DatabaseBlock="true"><f:Item Name="I"/></f:Block></f:FormModule>
    <other:Block Name="NOT_FORMS"/><MenuModule Name="MENU"><Menu Name="M"><MenuItem Name="GO"/></Menu></MenuModule>
    </Module>'''
    facts = assess_forms_xml('synthetic.xml', raw)
    assert [m['name'] for m in facts['modules']] == ['A', 'B', 'MENU']
    assert len({r['id'] for r in facts['objects']}) == len(facts['objects'])
    assert facts['totals']['blocks'] == 2
    assert facts['modules'][1]['location']['path'] == '/Module[1]/FormModule[2]'
    assert facts['items'][0]['module_id'] != facts['items'][1]['module_id']
    assert facts['totals']['uninterpreted_elements'] == 1


def test_all_named_structural_objects_unknown_properties_not_leaked():
    raw = b'''<FormModule Name="SYNTHETIC"><Coordinate CharacterCellWidth="secret-value-not-a-credential"/>
    <Alert Name="WARNING"/><Parameter Name="P"/><PropertyClass Name="PC"/><VisualAttribute Name="VA"/>
    <Relation Name="R" MasterBlock="MASTER" DetailBlock="DETAIL"/>
    <Canvas Name="C" WindowName="W"/><Window Name="W"/><LOV Name="L" RecordGroupName="RG"/>
    <RecordGroup Name="RG"><RecordGroupQuery>select id from APP.TABLE_X where status = 'OK' and id = 7</RecordGroupQuery></RecordGroup>
    <AttachedLibrary Name="UTIL" LibraryLocation="C:\\private\\UTIL.pll"/>
    <Report Name="REP" Filename="/private/REP.rdf"/>
    <Block Name="MASTER" DatabaseBlock="true"><Item Name="ID" CanvasName="C" LovName="L"/></Block>
    <Block Name="DETAIL" DatabaseBlock="false"/></FormModule>'''
    facts = assess_forms_xml('synthetic.xml', raw)
    assert facts['totals']['uninterpreted_elements'] == 0
    assert {row['kind'] for row in facts['objects']} >= {'Alert', 'Parameter', 'PropertyClass', 'VisualAttribute', 'Relation', 'AttachedLibrary', 'Report', 'RecordGroup'}
    assert {d['name'] for d in facts['dependencies']} == {'APP.TABLE_X', 'UTIL', 'REP'}
    assert {link['status'] for link in facts['links']} == {'resolved'}
    assert 'private' not in json.dumps(facts) and 'secret-value' not in json.dumps(facts)


def test_conflicts_unknowns_and_code_representation_not_silently_ready():
    raw = b'''<Module><FormModule Name="SYNTHETIC"><Block Name="B"><Item Name="I"/><Item Name="I"/>
    <Trigger Name="T"><TriggerText>BEGIN :B.I := 1; END;</TriggerText></Trigger>
    <Trigger Name="EMPTY"/></Block><Canvas Name="C"/><Canvas Name="C"/>
    <Item Name="ORPHAN" CanvasName="C"/><ProgramUnit Name="P"><ProgramUnitText>BEGIN NULL; END;</ProgramUnitText></ProgramUnit>
    <Block Name="not a normal &lt;name&gt;"/></FormModule><FormModule Name="SYNTHETIC"/></Module>'''
    facts = assess_forms_xml('synthetic.xml', raw)
    codes = {row['code'] for row in facts['findings']}
    assert codes >= {'BLOCK_TYPE_UNKNOWN', 'CONFLICTING_OBJECT_NAME', 'SOURCE_LINK_AMBIGUOUS', 'CODE_SOURCE_UNAVAILABLE', 'OBJECT_NAME_UNAVAILABLE', 'ITEM_WITHOUT_BLOCK'}
    assert len(facts['code_units']) == 2
    assert facts['blocks'][1]['name'] is None
    assert facts['items'][2]['block_id'] is None
    assert 'normal' not in json.dumps(facts)


def test_literals_comments_dynamic_sql_no_false_dependency_or_execution():
    code = """BEGIN
      -- SELECT * FROM FALSE_COMMENT;
      x := 'FROM FALSE_LITERAL'; x := q'[JOIN FALSE_Q]'; x := 'don''t FROM FALSE_ESCAPED';
      password := v_password;
      INSERT INTO APP.REAL_TABLE(id, status) VALUES (42, 'PENDING');
      /* UPDATE FALSE_BLOCK SET a=1; */
      EXECUTE IMMEDIATE 'select * from NOT_STATIC';
      APP.API(:GLOBAL.X, :SYSTEM.CURSOR_ITEM, :PARAMETER.ID);
    END;"""
    raw = f'<FormModule Name="SYNTHETIC"><Trigger Name="T" TriggerText={quoteattr(code)}/></FormModule>'.encode()
    facts = assess_forms_xml('synthetic.xml', raw)
    assert {row['name'] for row in facts['dependencies']} == {'APP.REAL_TABLE', 'APP.API'}
    assert not any(row['name'] == 'APP.REAL_TABLE' and row['kind'] == 'routine' for row in facts['dependencies'])
    assert any(row['code'] == 'DYNAMIC_REFERENCE_REVIEW' for row in facts['findings'])
    assert not any(row['code'] == 'BIND_BLOCK_UNRESOLVED' for row in facts['findings'])


@pytest.mark.parametrize('name,raw', [
    ('../bad.xml', b'<FormModule Name="A"/>'), ('path\\bad.xml', b'<FormModule Name="A"/>'),
    ('bad.fmb', b'<FormModule Name="A"/>'), ('bad.xml', b''),
    ('bad.xml', b'\xff\xfe'), ('bad.xml', b'\0'), ('bad.xml', b'<FormModule'),
    ('bad.xml', b'<?xml version="1.0" encoding="ISO-8859-1"?><FormModule Name="A"/>'),
    ('bad.xml', b'<!DOCTYPE x [<!ENTITY e "x">]><FormModule Name="A">&e;</FormModule>'),
    ('bad.xml', b'<!DOCTYPE x SYSTEM "file:///not-read"><FormModule Name="A"/>'),
    ('bad.xml', b'<not_forms/>'), ('bad.xml', b'<Module/>'),
    ('bad.xml', b'<FormModule xmlns="urn:fake" Name="A"/>'),
])
def test_safe_bounded_errors(name, raw):
    with pytest.raises(ValueError) as caught:
        assess_forms_xml(name, raw)
    assert len(str(caught.value)) < 200
    assert 'file:///' not in str(caught.value)


@pytest.mark.parametrize('body', [
    '<Trigger Name="T" TriggerText="password := &apos;synthetic-secret&apos;;"/>',
    '<Trigger Name="T"><TriggerText>pwd := &apos;synthetic-secret&apos;;</TriggerText></Trigger>',
    '<Trigger Name="T" TriggerText="client_secret := &apos;synthetic-secret&apos;;"/>',
    '<Property Name="password" Value="synthetic-secret"/>',
    '<Property Password="synthetic-secret"/>',
    '<Trigger Name="T" TriggerText="-----BEGIN PRIVATE KEY-----"/>',
    '<Trigger Name="T" TriggerText="connect user/synthetic-secret@db"/>',
])
def test_secret_suspicions_do_not_emit_values(body):
    with pytest.raises(ValueError, match='Possible credential') as caught:
        assess_forms_xml('synthetic.xml', f'<FormModule Name="A">{body}</FormModule>'.encode())
    assert 'synthetic-secret' not in str(caught.value)


def test_exact_file_limit_and_structure_limits(monkeypatch):
    raw = b'<FormModule Name="A"/>'
    monkeypatch.setattr(forms_facts, 'MAX_FILE_BYTES', len(raw))
    assert assess_forms_xml('boundary.xml', raw)['source']['bytes'] == len(raw)
    with pytest.raises(ValueError, match='at most'):
        assess_forms_xml('boundary.xml', raw + b' ')
    monkeypatch.setattr(forms_facts, 'MAX_FILE_BYTES', 10000)
    monkeypatch.setattr(forms_facts, 'MAX_ELEMENTS', 2)
    with pytest.raises(ValueError, match='bounded element'):
        assess_forms_xml('boundary.xml', b'<FormModule Name="A"><Block Name="B"><Item Name="I"/></Block></FormModule>')
    monkeypatch.setattr(forms_facts, 'MAX_ELEMENTS', 100)
    monkeypatch.setattr(forms_facts, 'MAX_DEPTH', 2)
    with pytest.raises(ValueError, match='bounded element'):
        assess_forms_xml('boundary.xml', b'<FormModule Name="A"><Block Name="B"><Item Name="I"/></Block></FormModule>')


def test_source_revision_changes_binding_not_original_identity():
    original = assess_forms_xml('synthetic.xml', b'<FormModule Name="A"><Block Name="B"/></FormModule>')
    changed = assess_forms_xml('synthetic.xml', b'<FormModule Name="A"><Block Name="B"/> </FormModule>')
    assert original['source']['sha256'] != changed['source']['sha256']
    assert original['blocks'][0]['id'] != changed['blocks'][0]['id']
    assert original['source']['bytes'] + 1 == changed['source']['bytes']


def test_static_module_calls_cross_module_links_not_arbitrary_literals():
    code = "BEGIN OPEN_FORM('OTHER'); CALL_FORM(:GLOBAL.TARGET); x := 'PRIVATE VALUE'; END;"
    raw = f'<Module><FormModule Name="MAIN" MenuModule="MENU"><Trigger Name="T" TriggerText={quoteattr(code)}/></FormModule><FormModule Name="OTHER"/><MenuModule Name="MENU"/></Module>'.encode()
    facts = assess_forms_xml('synthetic.xml', raw)
    assert next(row for row in facts['links'] if row['relation'] == 'calls_form')['status'] == 'resolved'
    assert next(row for row in facts['links'] if row['relation'] == 'uses_menu')['status'] == 'resolved'
    assert any(row['kind'] == 'forms_module' and row['name'] == 'OTHER' for row in facts['dependencies'])
    assert any(row['code'] == 'DYNAMIC_MODULE_TARGET' for row in facts['findings'])
    assert 'PRIVATE VALUE' not in json.dumps(facts)


def test_actual_five_megabyte_boundary_and_decoded_text_chunk_continuity():
    start, end = b'<FormModule Name="SYNTHETIC"><Trigger Name="T"><![CDATA[BEGIN ', b"NULL; END;]]></Trigger></FormModule>"
    raw = start + b' ' * (forms_facts.MAX_FILE_BYTES - len(start) - len(end)) + end
    facts = assess_forms_xml('boundary.xml', raw)
    assert facts['source']['bytes'] == forms_facts.MAX_FILE_BYTES
    assert facts['code_units'][0]['bytes'] == forms_facts.MAX_FILE_BYTES - len(start) - len(end) + len(b'BEGIN NULL; END;')
    with pytest.raises(ValueError, match='at most'):
        assess_forms_xml('boundary.xml', raw + b' ')


def test_reference_budget_includes_direct_source_relationships(monkeypatch):
    monkeypatch.setattr(forms_facts, 'MAX_REFERENCES', 1)
    with pytest.raises(ValueError, match='bounded reference'):
        assess_forms_xml('boundary.xml', b'<FormModule Name="A"><Item Name="I" CanvasName="C" LovName="L"/></FormModule>')


def test_assessment_has_no_external_io_or_execution(monkeypatch):
    import builtins
    import socket
    import subprocess

    def forbidden(*_args, **_kwargs):
        raise AssertionError('External operation attempted')

    monkeypatch.setattr(builtins, 'open', forbidden)
    monkeypatch.setattr(socket, 'socket', forbidden)
    monkeypatch.setattr(subprocess, 'run', forbidden)
    assert assess_forms_xml('synthetic.xml', synthetic_forms())['totals']['blocks'] == 9
