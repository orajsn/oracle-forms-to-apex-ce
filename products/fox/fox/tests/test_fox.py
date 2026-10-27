import hashlib
import sqlite3

import pytest
from fastapi.testclient import TestClient

from fox.app import create_app, password_hash
from fox.intake import checked_source, inventory, MAX_CONVERSION_BYTES
from fox.worker import process_one

ORIGIN = 'http://127.0.0.1:8100'

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv('FOX_PASSWORD_HASH', password_hash('test-only-password'))
    monkeypatch.setenv('FOX_PUBLIC_ORIGIN', ORIGIN)
    monkeypatch.delenv('FOX_OPAF_RUN_URL', raising=False)
    with TestClient(create_app(tmp_path, enable_worker=False), base_url=ORIGIN) as c:
        c.headers['Origin'] = ORIGIN
        yield c, tmp_path

def signed_in(client):
    c, root = client
    assert c.post('/api/login', json={'username':'jason','password':'test-only-password'}).status_code == 200
    return c, root

def project(c):
    r = c.post('/api/projects', json={'customer':'Synthetic development fixture','name':'Orders'})
    assert r.status_code == 201
    return r.json()['id']

@pytest.mark.parametrize('name,raw', [
    ('../x.xml',b'<x/>'), ('folder\\x.xml',b'<x/>'), ('x.fmb',b'raw'),
    ('x.zip',b'PK'), ('x.xml',b'<bad>'), ('x.txt',b'password=secretvalue'),
    ('x.sql',b'INSERT INTO customers VALUES (1)'), ('x.txt',b'person@example.com'),
    ('x.xml',b'<!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><x>&a;</x>'),
])
def test_source_rejections(name,raw):
    with pytest.raises(ValueError): checked_source(name,raw)

def test_missing_package_requires_spec_and_body():
    form=checked_source('orders.xml',b'<FormModule Name="ORDERS"><Trigger TriggerText="orders_api.save(); HOST(\'demo\');"/></FormModule>')
    spec=checked_source('orders.pks',b'CREATE PACKAGE orders_api AS PROCEDURE save; END;')
    body=checked_source('orders.pkb',b'CREATE PACKAGE BODY orders_api AS PROCEDURE save IS BEGIN NULL; END; END;')
    assert inventory([form,spec])['missing_count']==1
    result=inventory([form,spec,body])
    assert result['missing_count']==0
    assert result['issues'][0]['target']=='HOST'
    assert result['source_hash']==inventory([body,form,spec])['source_hash']

@pytest.mark.parametrize('xml', [b'<catalog><item name="x"/></catalog>', b'<Module/>'])
def test_unrelated_xml_remains_assessable_but_cannot_enable_conversion(xml):
    result=inventory([checked_source('support.xml',xml)])
    assert result['missing_count']==0
    assert result['forms_source_files']==[]
    assert result['conversion_eligible'] is False
    assert [item['code'] for item in result['conversion_blockers']]==['NO_FORMS_MODULE']

@pytest.mark.parametrize('xml', [
    b'<FormModule Name="ORDERS"/>',
    b'<Module xmlns="http://xmlns.oracle.com/Forms"><FormModule Name="ORDERS"/></Module>',
    b'<Module><MenuModule Name="MENU"/></Module>',
    b'<Module><ObjectLibrary Name="OBJECTS"/></Module>',
    b'<Module xmlns="urn:fox:forms-library:v1"><LibraryModule Name="LIB"/></Module>',
])
def test_recognized_forms_envelopes_remain_conversion_candidates(xml):
    result=inventory([checked_source('source.xml',xml)])
    assert result['conversion_eligible'] is True
    assert result['forms_source_files']==['source.xml']
    assert result['conversion_blockers']==[]

def test_schema_qualified_table_is_not_a_package_call():
    form=checked_source('orders.xml',b'<FormModule Name="ORDERS"><Block Name="B" QueryDataSourceName="APP.ORDERS"/></FormModule>')
    ddl=checked_source('schema.sql',b'CREATE TABLE APP.ORDERS (ID NUMBER);')
    result=inventory([form,ddl])
    assert result['missing_count']==0
    assert [(item['target'],item['kind'],item['status']) for item in result['dependencies']]==[('APP.ORDERS','table','SOURCE_PRESENT')]
    assert result['conversion_eligible'] is True

def test_package_calls_in_create_body_still_require_source():
    result=inventory([checked_source('body.pkb',b'CREATE PACKAGE BODY APP.ORDERS_API AS PROCEDURE save IS BEGIN OTHER_API.call_it(); END; END;')])
    assert [(item['target'],item['kind']) for item in result['dependencies']]==[('OTHER_API','package')]

def test_conversion_byte_limit_matches_utf8_payload_and_includes_dependencies():
    xml=b'<FormModule Name="ORDERS"/>'
    support=('é'*((MAX_CONVERSION_BYTES-len(xml))//2)).encode('utf-8')
    sources=[checked_source('source.xml',xml),checked_source('notes.txt',support)]
    result=inventory(sources)
    assert result['source_bytes']==len(xml)+len(support)
    assert result['conversion_source_bytes']==len(xml)+len(support)
    assert result['max_conversion_bytes']==MAX_CONVERSION_BYTES
    assert result['conversion_eligible'] is True
    sources[1]=checked_source('notes.txt',support+b'abc')
    result=inventory(sources)
    assert result['conversion_eligible'] is False
    assert [item['code'] for item in result['conversion_blockers']]==['CONVERSION_SIZE_LIMIT']

def test_byte_count_distinguishes_original_bom_from_conversion_payload():
    raw=b'\xef\xbb\xbf<FormModule Name="ORDERS"/>'
    result=inventory([checked_source('source.xml',raw)])
    assert result['source_bytes']==len(raw)
    assert result['conversion_source_bytes']==len(raw)-3

def test_auth_and_origin(client):
    c,_=client
    assert c.get('/api/projects').status_code==401
    assert c.post('/api/login',json={'username':'jason','password':'test-only-password'},headers={'Origin':'https://evil.invalid'}).status_code==403
    signed_in(client)
    assert c.cookies.get('fox_session')
    assert c.get('/api/session').json()['conversion_configured'] is False
    assert c.post('/api/logout',json={}).status_code==200
    assert c.get('/api/projects').status_code==401

def test_upload_is_atomic_and_persistent(client):
    c,root=signed_in(client); pid=project(c)
    r=c.post(f'/api/projects/{pid}/sources', files=[('files',('ok.xml',b'<FormModule Name="A"/>')),('files',('bad.xml',b'<broken>'))])
    assert r.status_code==422
    assert c.get(f'/api/projects/{pid}').json()['inventory']['files']==[]
    assert c.post(f'/api/projects/{pid}/sources',files={'files':('ok.xml',b'<FormModule Name="A"/>')}).status_code==200
    first=c.get(f'/api/projects/{pid}').json()['inventory']['source_hash']
    assert c.post(f'/api/projects/{pid}/sources',files={'files':('ok.xml',b'<FormModule Name="B"/>')}).status_code==200
    assert c.get(f'/api/projects/{pid}').json()['inventory']['source_hash']!=first
    with sqlite3.connect(root/'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM sources').fetchone()[0]==2
        db.execute('UPDATE projects SET owner=? WHERE id=?',('different-owner',pid))
    assert c.get(f'/api/projects/{pid}').status_code==404
    assert c.get(f'/api/projects/{pid}/assessment').status_code==404

def test_conversion_gates_and_idempotency(client,monkeypatch):
    c,root=signed_in(client); pid=project(c)
    c.post(f'/api/projects/{pid}/sources',files={'files':('ok.xml',b'<FormModule Name="A"/>')})
    source_hash=c.get(f'/api/projects/{pid}').json()['inventory']['source_hash']
    body=dict(source_hash=source_hash,approved_redacted_source=True,approved_external_ai=True,approved_prototype_scope=True)
    url=f'/api/projects/{pid}/runs'
    assert c.post(url,json=body).status_code==503
    monkeypatch.setenv('FOX_OPAF_RUN_URL','https://operator-configured.invalid')
    assert c.post(url,json={**body,'approved_external_ai':False}).status_code==422
    assert c.post(url,json={**body,'source_hash':'0'*64}).status_code==409
    r=c.post(url,json=body)
    assert r.status_code==202
    rid=r.json()['id']
    assert c.post(url,json=body).json()['id']==rid
    assert c.get(f'{url}/{rid}/download').status_code==409
    def db():
        conn=sqlite3.connect(root/'fox.sqlite3');conn.row_factory=sqlite3.Row;return conn
    monkeypatch.delenv('FOX_RUN_ADAPTER',raising=False)
    process_one(db,root)
    with db() as conn: assert conn.execute('SELECT state FROM runs').fetchone()[0]=='ATTENTION'
    assert c.get(f'{url}/{rid}/download').status_code==409

@pytest.mark.parametrize('payload,blocker', [
    (b'<catalog><item name="x"/></catalog>','NO_FORMS_MODULE'),
    (b'<FormModule Name="ORDERS"><Description>'+b'x'*MAX_CONVERSION_BYTES+b'</Description></FormModule>','CONVERSION_SIZE_LIMIT'),
], ids=['unrelated-xml', 'oversize-forms'])
def test_ineligible_source_rejected_before_queue_or_job_directory(client,monkeypatch,payload,blocker):
    c,root=signed_in(client);pid=project(c)
    monkeypatch.setenv('FOX_OPAF_RUN_URL','https://operator-configured.invalid')
    uploaded=c.post(f'/api/projects/{pid}/sources',files={'files':('source.xml',payload)})
    assert uploaded.status_code==200
    report=uploaded.json()
    assert blocker in [item['code'] for item in report['conversion_blockers']]
    response=c.post(f'/api/projects/{pid}/runs',json=dict(source_hash=report['source_hash'],approved_redacted_source=True,approved_external_ai=True,approved_prototype_scope=True))
    assert response.status_code==409
    with sqlite3.connect(root/'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0]==0
    assert not (root/'jobs').exists()

def test_login_throttle(client):
    c,_=client
    for _ in range(10): assert c.post('/api/login',json={'username':'jason','password':'wrong'}).status_code==401
    assert c.post('/api/login',json={'username':'jason','password':'wrong'}).status_code==429
