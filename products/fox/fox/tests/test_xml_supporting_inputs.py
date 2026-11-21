import json
from copy import deepcopy

import pytest

from fox import xml_mapping, xml_supporting_inputs as support
from fox.forms_native_plan import POLICY_ID
from fox.prototype_export_only import _members, _zip
from test_xml_mapping import source


def build(docs):
    return xml_mapping.generate_xml_package(docs, 'source-evidence', 'Source evidence', POLICY_ID)


@pytest.fixture(scope='module')
def mixed():
    xml = ('form.xml',source())
    inputs = [xml, ('source.sql', b'\xef\xbb\xbfCREATE TABLE DEMO_DATA (ID NUMBER);\r\n'),
              ('checked.pks',b'CREATE PACKAGE CHECKED AS PROCEDURE REPORT; END;')]
    archive, report = build(inputs)
    return inputs, _members(archive), report


def test_all_inputs_are_hash_bound_and_only_xml_is_converted(mixed):
    inputs, files, report = mixed
    original, _ = build(inputs[:1])
    baseline = _members(original)
    assert report['metadata']['apex_members'] == json.loads(baseline['fox-package/metadata.json'])['apex_members']
    assert files['fox-package/supporting-schema.sql'] == baseline['fox-package/supporting-schema.sql']
    evidence = support.retained(files, report['metadata'], dict(inputs))
    assert [e['name'] for e in evidence['files']]==['checked.pks','source.sql']
    for f in evidence['files']:
        assert f['member'].endswith('.txt') and files[f['member']]==dict(inputs)[f['name']]
    assert evidence['source_execution'] is evidence['original_interfaces_enabled'] is False
    assert not (set(files)-set(baseline)) - {support.MEMBER, *[f['member'] for f in evidence['files']]}
    assert build(inputs[::-1])[0] == _zip(files)
    assert xml_mapping._check_candidate(_zip(files))[1]==report['metadata']


@pytest.mark.parametrize('change',['missing','different','unlisted','wrong_metadata','other_source'])
def test_changed_attachment_or_receipt_cannot_pass_saved_verification(mixed,change):
    inputs, originals, report = mixed
    files=dict(originals); metadata=deepcopy(report['metadata']); docs=dict(inputs)
    path=support.PREFIX+'001.txt'
    if change=='missing': del files[path]
    if change=='different': files[path]+=b'x'
    if change=='unlisted': files[support.PREFIX+'099.txt']=b'x'
    if change=='wrong_metadata':metadata['supporting_inputs']['count']=999
    if change=='other_source':docs['checked.pks']+=b' '
    with pytest.raises((ValueError,KeyError)):
        support.retained(files,metadata,docs)


def test_candidate_cannot_seal_with_different_supporting_original(mixed):
    _,originals,_ = mixed; files=dict(originals)
    files[support.PREFIX+'001.txt']+=b'\n'
    with pytest.raises(ValueError):
        xml_mapping._check_candidate(_zip(files))


@pytest.mark.parametrize('extra',[
    [('note.txt',b'not a supported definition')],
    [('only.pkl',b'x')], [('bad.sql',b'INSERT INTO T VALUES (1);')],
    [('bad.pks',b'\xff')], [('same.sql',b'A'),('SAME.SQL',b'B')],
    [('../bad.sql',b'-- declaration')],
])
def test_unsupported_or_unchecked_evidence_never_silently_drops(extra):
    with pytest.raises(ValueError):
        build([('form.xml',source()),*extra])
