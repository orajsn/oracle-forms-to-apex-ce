"""Opt-in tests using the operator's installed Oracle runtime; no vendor assets.

FOX_TEST_ORACLE_HOME and FOX_TEST_JAVA must be explicitly set. Oracle XML2Forms
creates synthetic binaries locally; Forms2XML then extracts those binaries.
This verifies the plumbing, not customer-module compatibility or APEX import.
"""
import json
import os
import shutil
from pathlib import Path
import pytest
from fox.extractor import OracleFormsBackend, prepare, verify, NS, PLL_NS, ExtractionError
from defusedxml import ElementTree as ET

pytestmark = pytest.mark.skipif(
    not os.environ.get('FOX_TEST_ORACLE_HOME') or not os.environ.get('FOX_TEST_JAVA'),
    reason='Explicit opt-in and installed Oracle Forms runtime required.')


@pytest.mark.parametrize('ext,kind', [('fmb', 'FormModule'), ('mmb', 'MenuModule'), ('olb', 'ObjectLibrary')])
def test_native_binary_roundtrip(tmp_path, ext, kind):
    backend = OracleFormsBackend(Path(os.environ['FOX_TEST_ORACLE_HOME']), Path(os.environ['FOX_TEST_JAVA']))
    backend.check()
    source = tmp_path / 'binary'
    source.mkdir()
    xml = tmp_path / ('synthetic_' + ext + '.xml')
    children = '<Block Name="DEMO" DatabaseBlock="false"><Item Name="VALUE" ItemType="Text Item"/></Block>' if ext == 'fmb' else ''
    xml.write_text(f'<Module xmlns="http://xmlns.oracle.com/Forms" version="141020000"><{kind} Name="FOX_SYNTHETIC">{children}</{kind}></Module>', encoding='utf-8')
    backend.run([str(backend.java), '-cp', os.pathsep.join(map(str, backend.jars)),
        'oracle.forms.util.xmltools.XML2Forms', 'OVERWRITE=NO', 'OUTPUTDIR=' + str(source), str(xml)], source, source)
    native = source / ('synthetic.' + ext)
    assert native.is_file() and native.stat().st_size > 1000
    original = native.read_bytes()
    job = prepare(source, tmp_path / 'jobs', backend)
    assert verify(job)['files'] == 1
    result = job / 'ready' / ('synthetic_' + ext + '.xml')
    assert ET.fromstring(result.read_bytes())[0].tag == NS + kind
    if ext == 'fmb':
        assert b'Name="DEMO"' in result.read_bytes()
        assert b'Name="VALUE"' in result.read_bytes()
    assert native.read_bytes() == original
    assert not list(job.rglob('*.' + ext))
    manifest = json.loads((job / 'manifest.json').read_text())
    assert manifest['files'][0]['backend'] == backend.name


@pytest.mark.parametrize('sample,expected_units', [('EnableDisableItem',2),('websocketJSI',2),('webutil',53),('rp2rro',2)])
def test_native_pll_installed_samples(tmp_path,sample,expected_units):
    # Read local Oracle-supplied samples only. Their sources never enter Git.
    backend=OracleFormsBackend(Path(os.environ['FOX_TEST_ORACLE_HOME']),Path(os.environ['FOX_TEST_JAVA']),timeout=25)
    source=tmp_path/'sources'; source.mkdir()
    output=tmp_path/'output'; output.mkdir()
    binary=source/(sample+'.pll')
    shutil.copyfile(backend.home/'forms'/binary.name,binary)
    original=binary.read_bytes()
    result=backend.extract(binary,output)
    doc=ET.fromstring(result.read_bytes())
    units=doc[0].findall(PLL_NS+'ProgramUnit')
    assert len(units)==expected_units
    assert all(u.find(PLL_NS+'ProgramUnitText').text for u in units)
    # Same-name spec/body must not be collapsed to one program unit.
    assert {'3','4'}.issubset({u.get('ProgramUnitType') for u in units})
    assert doc.get('DatabaseConnected')=='false'
    assert original==binary.read_bytes()
    if sample=='EnableDisableItem':
        job=prepare(source,tmp_path/'jobs',backend)
        assert verify(job)['files']==1
        assert not list(job.rglob('*.pll'))
        assert (job/'ready/EnableDisableItem_pll.xml').is_file()


def test_native_invalid_pll_blocks(tmp_path):
    backend=OracleFormsBackend(Path(os.environ['FOX_TEST_ORACLE_HOME']),Path(os.environ['FOX_TEST_JAVA']),timeout=10)
    source=tmp_path/'sources'; source.mkdir()
    (source/'malformed.pll').write_bytes(b'NOT AN ORACLE LIBRARY')
    with pytest.raises(ExtractionError):
        prepare(source,tmp_path/'jobs',backend,'invalid-pll')
    assert not (tmp_path/'jobs/invalid-pll/ready').exists()
    assert json.loads((tmp_path/'jobs/invalid-pll/status.json').read_text())['status']=='BLOCKED'
