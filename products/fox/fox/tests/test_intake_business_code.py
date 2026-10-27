"""Assessment-only synthetic DML classification; no remote/model calls."""
import hashlib
import json
from pathlib import Path
import sqlite3
from xml.sax.saxutils import escape, quoteattr

from fastapi.testclient import TestClient
import pytest

from fox.app import create_app, password_hash
from fox.intake import checked_source, inventory
from fox.native_source import assess_native_source
from fox.opaf import stage_job


INSERT = 'BEGIN INSERT INTO FOX_NATIVE_BETA (TITLE) VALUES (:BETA.TITLE); COMMIT; END;'
MERGE = ('BEGIN MERGE INTO FOX_NATIVE_BETA t USING (SELECT :BETA.ID id, :BETA.TITLE title FROM dual) s '
         'ON (t.id=s.id) WHEN MATCHED THEN UPDATE SET t.title=s.title '
         'WHEN NOT MATCHED THEN INSERT (id,title) VALUES (s.id,s.title); END;')
FIXTURES = Path(__file__).parent/'fixtures'


def form(code=INSERT, location='attribute'):
    original=(FIXTURES/'native-beta.xml').read_text(encoding='utf-8')
    if location=='attribute':
        unit='<Trigger Name="SAVE" TriggerText='+quoteattr(code)+'/>'
    elif location=='text':
        unit='<Trigger Name="SAVE">'+escape(code)+'</Trigger>'
    elif location=='cdata':
        unit='<Trigger Name="SAVE"><![CDATA['+code+']]></Trigger>'
    elif location=='program_attribute':
        unit='<ProgramUnit Name="SAVE" ProgramUnitText='+quoteattr(code)+'/>'
    else:
        unit='<ProgramUnit Name="SAVE"><ProgramUnitText>'+escape(code)+'</ProgramUnitText></ProgramUnit>'
    return original.replace('</Block>',unit+'</Block>').encode()


def prepared(raw):
    return [checked_source('native-beta.xml',raw),checked_source('native-beta.sql',(FIXTURES/'native-beta.sql').read_bytes())]


@pytest.mark.parametrize('code',[INSERT,MERGE,INSERT.replace('INSERT INTO','INSERT /* harmless */ INTO'),
    INSERT.replace('INSERT INTO','INSERT-- harmless\n INTO')])
@pytest.mark.parametrize('location',['attribute','text','cdata','program_attribute','program_child'])
def test_bound_transaction_source_is_assessable_never_convertible(code,location):
    sources=prepared(form(code,location))
    report=inventory(sources)
    assert report['conversion_eligible'] is False
    assert 'BUSINESS_DML_REVIEW_REQUIRED' in {b['code'] for b in report['conversion_blockers']}
    finding=next(i for i in report['issues'] if i['target']=='BUSINESS_DML')
    assert finding['classification']=='BUSINESS_REVIEW'
    assert finding['status']=='UNCONVERTED_REVIEW_REQUIRED' and finding['evidence']
    assert 'not proof' in finding['scope_note']
    assert code not in str(finding)
    assert sources[0]['sha256']==hashlib.sha256(form(code,location)).hexdigest()
    native=assess_native_source(sources)
    assert native['state']=='BLOCKED'
    assert 'BUSINESS_CODE_REVIEW_REQUIRED' in {b['code'] for b in native['blockers']}


def test_jdapi_program_source_is_classified_not_treated_as_oracle_provenance():
    xml=('<Module xmlns="urn:fox:forms-library:v1" Format="FOX-JDAPI-LIBRARY-1" DatabaseConnected="false">'
         '<LibraryModule Name="SYNTHETIC_LIB"><ProgramUnit Name="SAVE" ProgramUnitType="2">'
         '<ProgramUnitText>'+escape(INSERT)+'</ProgramUnitText></ProgramUnit></LibraryModule></Module>')
    report=inventory([checked_source('synthetic-library.xml',xml.encode())])
    assert report['conversion_eligible'] is False
    assert next(i for i in report['issues'] if i['target']=='BUSINESS_DML')['classification']=='BUSINESS_REVIEW'


@pytest.mark.parametrize('code',[
    "INSERT INTO FOX_NATIVE_BETA (TITLE) VALUES ('Synthetic literal record');",
    'INSERT INTO FOX_NATIVE_BETA (AMOUNT) VALUES (42);',
    'INSERT INTO FOX_NATIVE_BETA (AMOUNT) VALUES (1e9);',
    'INSERT INTO FOX_NATIVE_BETA (AMOUNT) VALUES (.5);',
    'INSERT INTO FOX_NATIVE_BETA (TITLE) VALUES (NULL); -- :BETA.TITLE',
    'INSERT INTO FOX_NATIVE_BETA (TITLE) VALUES (NULL) /* :BETA.TITLE */;',
    'BEGIN IF :BETA.ID IS NOT NULL THEN INSERT INTO FOX_NATIVE_BETA (TITLE) VALUES (NULL); END IF; END;',
    INSERT+" INSERT INTO FOX_NATIVE_BETA (TITLE) VALUES ('literal');",
    INSERT+' INSERT INTO FOX_NATIVE_BETA (TITLE) VALUES (NULL);',
    'INSERT INTO FOX_NATIVE_BETA (TITLE) VALUES (NULL) INSERT INTO FOX_NATIVE_BETA (TITLE) VALUES (:BETA.TITLE);',
    'INSERT INTO FOX_NATIVE_BETA (TITLE) VALUES (:BETA.TITLE)',
    INSERT+" -- INSERT INTO FOX_NATIVE_BETA VALUES ('record in comment');",
    INSERT+" /* INSERT INTO FOX_NATIVE_BETA VALUES ('record in comment'); */",
    '/* comment /* nested */ INSERT INTO FOX_NATIVE_BETA VALUES (:BETA.TITLE);',
    INSERT+' /* unfinished',
    "EXECUTE IMMEDIATE 'INSERT INTO FOX_NATIVE_BETA (TITLE) VALUES (:BETA.TITLE)';",
    INSERT+' EXECUTE IMMEDIATE :BETA.SQL_TEXT;',
    INSERT+' DBMS_SQL.PARSE(:BETA.SQL_TEXT);',
    "INSERT INTO FOX_NATIVE_BETA (TITLE) VALUES (q'[literal]');",
    'INSERT ALL INTO FOX_NATIVE_BETA (TITLE) VALUES (:BETA.TITLE) SELECT :BETA.ID FROM dual;',
    'INSERT INTO "FOX_NATIVE_BETA" (TITLE) VALUES (:BETA.TITLE);',
])
def test_literal_rows_ambiguous_or_dynamic_code_stays_blocked(code):
    with pytest.raises(ValueError,match='DML cannot be classified safely'):
        checked_source('source.xml',form(code))


@pytest.mark.parametrize('raw',[
    ('<catalog><Trigger Name="SAVE" TriggerText='+quoteattr(INSERT)+'/></catalog>').encode(),
    ('<Module><FormModule><Trigger Name="SAVE" TriggerText='+quoteattr(INSERT)+'/></FormModule></Module>').encode(),
    ('<FormModule Name="F"><Trigger TriggerText='+quoteattr(INSERT)+'/></FormModule>').encode(),
    ('<FormModule Name="F" Description='+quoteattr(INSERT)+'/>').encode(),
    ('<FormModule Name="F"><Comment>'+escape(INSERT)+'</Comment></FormModule>').encode(),
    ('<FormModule xmlns="urn:fake" Name="F"><Trigger Name="SAVE" TriggerText='+quoteattr(INSERT)+'/></FormModule>').encode(),
    ('<FormModule Name="F"><Trigger xmlns="urn:fake" Name="SAVE" TriggerText='+quoteattr(INSERT)+'/></FormModule>').encode(),
    ('<Module xmlns="urn:fox:forms-library:v1"><LibraryModule Name="L"><ProgramUnit Name="P"><ProgramUnitText>'+escape(INSERT)+'</ProgramUnitText></ProgramUnit></LibraryModule></Module>').encode(),
    form()+b'<!-- INSERT INTO records VALUES(1); -->',
    form()+b'<?records INSERT INTO records VALUES(1); ?>',
    form().replace(b'</FormModule>',b'<Data>INSERT INTO records VALUES(1);</Data></FormModule>'),
])
def test_data_cannot_be_admitted_by_renaming_or_faking_code_context(raw):
    with pytest.raises(ValueError):checked_source('looks-like-forms.xml',raw)


@pytest.mark.parametrize('suffix',['sql','pkb','pks','pld','txt'])
def test_standalone_code_or_data_remains_neutral_unsupported(suffix):
    with pytest.raises(ValueError,match='standalone PL/SQL classification is not supported'):
        checked_source('source.'+suffix,INSERT.encode())


@pytest.mark.parametrize('sensitive',[
    'pass&#119;ord = hiddenvalue', 'client_secret = &#115;ecretvalue',
    'person&#64;example.com', 'con&#110;ect demo/secret&#64;db',
])
def test_decoded_xml_does_not_bypass_secret_or_identifier_scan(sensitive):
    raw=form().replace(b'</FormModule>',('<Comment>'+sensitive+'</Comment></FormModule>').encode())
    with pytest.raises(ValueError,match='credential or personal identifier'):
        checked_source('source.xml',raw)


def test_xml_entities_cannot_hide_dml_or_create_data_exception():
    bound=form().replace(b'INSERT INTO',b'INSERT&#32;INTO')
    assert inventory(prepared(bound))['conversion_eligible'] is False
    literal=form("INSERT INTO FOX_NATIVE_BETA (TITLE) VALUES ('record');").replace(b'INSERT INTO',b'INSERT&#32;INTO')
    with pytest.raises(ValueError):checked_source('source.xml',literal)


@pytest.mark.parametrize('name,raw',[
    ('raw.fmb',b'raw'),('raw.pll',b'raw'),('archive.zip',b'PK'),
    ('source.xml',b'<FormModule Name="F">\0</FormModule>'),
    ('source.xml',b'<!DOCTYPE x [<!ENTITY a "unsafe">]><FormModule Name="F">&a;</FormModule>'),
])
def test_original_binary_archive_and_xml_gates_remain(name,raw):
    with pytest.raises(ValueError):checked_source(name,raw)


def test_api_retains_assessment_but_cannot_queue_or_submit_to_model(tmp_path,monkeypatch):
    origin='http://127.0.0.1:8100'
    monkeypatch.setenv('FOX_PASSWORD_HASH',password_hash('synthetic-test-password'))
    monkeypatch.setenv('FOX_PUBLIC_ORIGIN',origin)
    monkeypatch.setenv('FOX_CONVERSION_PROFILE','native-table-form-v1')
    with TestClient(create_app(tmp_path,enable_worker=False),base_url=origin) as client:
        client.headers['Origin']=origin
        assert client.post('/api/login',json={'username':'jason','password':'synthetic-test-password'}).status_code==200
        project=client.post('/api/projects',json={'customer':'Synthetic local QA','name':'DML assessment'}).json()['id']
        response=client.post(f'/api/projects/{project}/sources',files=[
            ('files',('native-beta.xml',form(),'application/xml')),
            ('files',('native-beta.sql',(FIXTURES/'native-beta.sql').read_bytes(),'text/plain'))])
        assert response.status_code==200
        assessment=response.json()
        assert assessment['native_assessment']['state']=='BLOCKED'
        submitted=client.post(f'/api/projects/{project}/runs',json={'source_hash':assessment['source_hash'],
            'approved_redacted_source':True,'approved_external_ai':True,'approved_prototype_scope':True})
        assert submitted.status_code==409 and 'assessment-only' in submitted.json()['detail']
    with sqlite3.connect(tmp_path/'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0]==0
    assert not (tmp_path/'jobs').exists()


def test_handcrafted_legacy_snapshot_cannot_bypass_assessment_blocker(tmp_path):
    sources=prepared(form())
    job=tmp_path/'fox-0123456789abcdef0123';job.mkdir()
    shared=tmp_path/'shared';shared.mkdir()
    (job/'source-snapshot.json').write_text(json.dumps({'files':sources,
        'source_hash':inventory(sources)['source_hash'],'conversion_profile':'legacy-html-prototype-v1'}))
    with pytest.raises(ValueError,match='source assessment blocks conversion'):
        stage_job(job,shared)
    assert not list(shared.iterdir())
