"""Demo branches use normal planners; no model, SQLcl or OCI is called."""
from copy import deepcopy
import json
import sqlite3

import pytest

from fox.intake import inventory
from fox.partial_draft import prepare_partial_draft, saved_draft_scope
from fox.project_conversion import assess_project_conversion
from test_project_conversion import pair, source, xml, module, ddl
from test_source_history_api import client, settings, no_external_actions, upload, new_project


def prepare(files, pid='project-one', name='Demo project'):
    return prepare_partial_draft(files,project_id=pid,project_name=name,
                                 source_hash=inventory(files)['source_hash'])


def with_call(table='ORDERS'):
    return [source('orders.xml',xml(module('ORDERS',table,
        extra='<Trigger Name="WHEN-BUTTON-PRESSED" TriggerText="ORDER_API.SUBMIT_ORDER();"/>'))),
        source('orders.sql',ddl(table))]


def test_known_business_omissions_produce_a_separate_ready_subset_without_mutating_sources():
    files=with_call();original=deepcopy(files)
    report,derived=prepare(files)
    assert files==original
    assert report['available'] and len(report['included_forms'])==1
    assert {'BUSINESS_CODE_REVIEW_REQUIRED','MISSING_DEPENDENCY'} <= {x['code'] for x in report['omissions']}
    assert report['parent_source_hash']==inventory(files)['source_hash']
    assert report['derived_source_hash']==inventory(derived)['source_hash']!=report['parent_source_hash']
    plan=assess_project_conversion(derived,project_id='project-one',project_name='Demo project',
                                 source_hash=report['derived_source_hash'])
    assert plan['can_generate'] and plan['state']=='READY'
    assert plan['rendering_spec']['schema_version']==2
    assert len(plan['rendering_spec']['forms'])==1
    assert plan['forms'][0]['form_name']=='ORDERS - Draft'
    assert 'TriggerText' not in next(x['text'] for x in derived if x['name'].endswith('.xml'))
    sql=next(x['text'] for x in derived if x['name'].endswith('.sql'))
    assert report['draft_sha256'] in sql and 'MISSING_DEPENDENCY' in sql


def test_valid_form_can_be_generated_while_another_without_ddl_is_explicitly_omitted():
    files=pair(table='ORDERS')+[source('missing.xml',xml(module('MISSING','MISSING_TABLE')))]
    report,derived=prepare(files)
    assert report['available'] and len(report['included_forms'])==1
    assert report['omitted_forms'][0]['form_name']=='MISSING'
    assert any(item['code']=='DDL_REQUIRED' for item in report['omitted_forms'][0]['findings'])
    assert len([x for x in derived if x['name'].endswith('.xml')])==1


@pytest.mark.parametrize('change',[
    lambda f:f[:1],
    lambda f:[f[0],source('orders.sql','CREATE TABLE ORDERS (ID NUMBER, TITLE VARCHAR2(40));')],
    lambda f:[*f,source('conflict.sql',ddl('ORDERS',kind='NUMBER'))],
    lambda f:[source('orders.xml',xml(module('ORDERS','ORDERS',prompt='A')+module('ORDERS','ORDERS',prompt='B'))),f[1]],
    lambda f:[source('orders.xml',f[0]['text'].replace('QueryDataSourceName="ORDERS"','QueryDataSourceName="ORDERS" WhereClause="STATUS = 1"')),f[1]],
    lambda f:[source('orders.xml',f[0]['text'].replace('Name="TITLE"','Name="MISSING_COLUMN"')),f[1]],
    lambda f:[source('orders.xml',f[0]['text'].replace('Prompt="Title"','Prompt="Title" Enabled="false"')),f[1]],
])
def test_unproven_schema_mapping_and_restricted_operations_are_not_guessed(change):
    report,derived=prepare(change(with_call()))
    assert report['available'] is False and derived==[]
    assert report['omitted_forms'] or 'conflicting' in report['next_action']


def test_supplied_library_source_is_retained_as_an_omission_not_executed():
    report,derived=prepare(with_call()+[source('library.pld','PROCEDURE DO_WORK IS BEGIN NULL; END;')])
    assert report['available']
    assert any(x['code']=='UNCONVERTED_SUPPORTING_SOURCE' for x in report['omissions'])
    assert not any(x['name'].endswith('.pld') for x in derived)


def test_projection_and_preview_hash_are_deterministic():
    assert prepare(with_call())==prepare(list(reversed(with_call())))
    a,_=prepare(with_call());b,_=prepare(with_call(),pid='other')
    assert a['draft_sha256']!=b['draft_sha256']


def setup_api(client,monkeypatch,files=None):
    c,root,pid=client
    monkeypatch.setenv('FOX_CONVERSION_PROFILE','native-project-v1')
    initial=upload(c,pid,[(x['name'],x['text'].encode()) for x in (files or with_call())])
    preview=c.get(f'/api/projects/{pid}/partial-draft')
    assert preview.status_code==200,preview.text
    report=preview.json()
    body={'source_hash':initial['source_hash'],'expected_current_source_set_id':initial['selected_source_set_id'],
          'draft_sha256':report['draft_sha256'],'accepted_omissions':True}
    return c,root,pid,initial,report,body


def test_preview_is_read_only_and_create_preserves_original_version(client,monkeypatch):
    c,root,pid,initial,report,body=setup_api(client,monkeypatch)
    assert c.get(f'/api/projects/{pid}').json()['inventory']['source_hash']==initial['source_hash']
    result=c.post(f'/api/projects/{pid}/partial-draft',json=body)
    assert result.status_code==201,result.text
    ack=result.json();assert ack['source_hash']!=initial['source_hash']
    detail=c.get(f'/api/projects/{pid}').json()
    assert detail['draft_scope']==ack['draft_scope']
    assert detail['project_plan']['can_generate']
    assert detail['runs']==[]
    exported=c.get(f'/api/projects/{pid}/draft-scope',params={'source_hash':ack['source_hash']})
    assert exported.status_code==200 and exported.json()['parent_source_hash']==initial['source_hash']
    assert exported.json()['parent_source_set_id']==initial['selected_source_set_id']
    selected=c.post(f'/api/projects/{pid}/source-sets/{initial["selected_source_set_id"]}/select',
        json={'expected_current_source_set_id':ack['selected_source_set_id']})
    assert selected.status_code==200
    original=c.get(f'/api/projects/{pid}').json()
    assert original['inventory']['source_hash']==initial['source_hash']
    assert original['draft_scope'] is None and not original['project_plan']['can_generate']
    with sqlite3.connect(root/'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0]==0
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0]==0
        assert db.execute('SELECT COUNT(*) FROM source_sets WHERE project=?',(pid,)).fetchone()[0]==2


@pytest.mark.parametrize('field,value,status',[
    ('accepted_omissions',False,422),('accepted_omissions','true',422),
    ('draft_sha256','0'*64,409),('source_hash','0'*64,409),
    ('expected_current_source_set_id','ss-'+'0'*32,409),('extra','ignored',422),
])
def test_stale_unconfirmed_or_extra_fields_do_not_create_a_branch(client,monkeypatch,field,value,status):
    c,root,pid,initial,_,body=setup_api(client,monkeypatch)
    body[field]=value
    result=c.post(f'/api/projects/{pid}/partial-draft',json=body)
    assert result.status_code==status,result.text
    assert c.get(f'/api/projects/{pid}').json()['inventory']['source_hash']==initial['source_hash']
    with sqlite3.connect(root/'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM source_sets WHERE project=?',(pid,)).fetchone()[0]==1


def test_cross_project_requests_and_unapproved_profile_cannot_create_drafts(client,monkeypatch):
    c,_,pid,_,_,body=setup_api(client,monkeypatch)
    other=new_project(c)
    assert c.post(f'/api/projects/{other}/partial-draft',json=body).status_code==409
    assert c.get('/api/projects/unknown/partial-draft').status_code==404
    assert c.post('/api/projects/unknown/partial-draft',json=body).status_code==404
    monkeypatch.setenv('FOX_CONVERSION_PROFILE','legacy-html-prototype-v1')
    assert c.post(f'/api/projects/{pid}/partial-draft',json=body).status_code==409


def test_repeat_request_is_not_an_automatic_replay(client,monkeypatch):
    c,root,pid,_,_,body=setup_api(client,monkeypatch)
    ack=c.post(f'/api/projects/{pid}/partial-draft',json=body)
    assert ack.status_code==201
    assert c.post(f'/api/projects/{pid}/partial-draft',json=body).status_code==409
    assert c.get(f'/api/projects/{pid}').json()['runs']==[]
    with sqlite3.connect(root/'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM source_sets WHERE project=?',(pid,)).fetchone()[0]==2
        assert db.execute("SELECT COUNT(*) FROM events WHERE action LIKE 'partial_draft:%'").fetchone()[0]==1


def test_real_source_revision_invalidates_the_preview_without_losing_either_version(client,monkeypatch):
    c,root,pid,initial,_,body=setup_api(client,monkeypatch)
    revised=upload(c,pid,[('orders.xml',with_call()[0]['text'].replace('SUBMIT_ORDER','CANCEL_ORDER').encode())])
    assert revised['source_hash']!=initial['source_hash']
    result=c.post(f'/api/projects/{pid}/partial-draft',json=body)
    assert result.status_code==409
    assert c.get(f'/api/projects/{pid}').json()['inventory']['source_hash']==revised['source_hash']
    with sqlite3.connect(root/'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM source_sets WHERE project=?',(pid,)).fetchone()[0]==2
        assert db.execute("SELECT COUNT(*) FROM events WHERE action LIKE 'partial_draft:%'").fetchone()[0]==0


def test_identical_sources_in_independent_projects_cannot_share_scope_consent_or_receipts(client,monkeypatch):
    c,_,pid,initial,report,body=setup_api(client,monkeypatch)
    other=new_project(c)
    other_initial=upload(c,other,[(item['name'],item['text'].encode()) for item in with_call()])
    assert other_initial['source_hash']==initial['source_hash']
    other_report=c.get(f'/api/projects/{other}/partial-draft').json()
    assert other_report['draft_sha256']!=report['draft_sha256']
    other_body={**body,'expected_current_source_set_id':other_initial['selected_source_set_id']}
    assert c.post(f'/api/projects/{other}/partial-draft',json=other_body).status_code==409
    ack=c.post(f'/api/projects/{pid}/partial-draft',json=body).json()
    assert c.get(f'/api/projects/{other}/draft-scope',params={'source_hash':ack['source_hash']}).status_code==404
    assert c.get(f'/api/projects/{other}').json()['draft_scope'] is None
    other_body['draft_sha256']=other_report['draft_sha256']
    other_ack=c.post(f'/api/projects/{other}/partial-draft',json=other_body)
    assert other_ack.status_code==201,other_ack.text
    assert other_ack.json()['source_hash']!=ack['source_hash']
    assert other_ack.json()['draft_scope']['project_id']==other


def test_partial_branch_cannot_lose_its_scope_through_upload_or_exclusion(client,monkeypatch):
    c,_,pid,_,_,body=setup_api(client,monkeypatch)
    ack=c.post(f'/api/projects/{pid}/partial-draft',json=body).json()
    sid=ack['selected_source_set_id']
    assert c.post(f'/api/projects/{pid}/sources',files=[('files',('extra.txt',b'Synthetic note'))]).status_code==409
    file_id=c.get(f'/api/projects/{pid}/source-sets/{sid}').json()['files'][0]['id']
    assert c.post(f'/api/projects/{pid}/source-sets/{sid}/exclude',json={
        'expected_current_source_set_id':sid,'excluded_file_ids':[file_id]}).status_code==409
    assert c.get(f'/api/projects/{pid}').json()['draft_scope']==ack['draft_scope']


def test_receipt_corruption_is_not_reported_as_complete(client,monkeypatch):
    c,root,pid,_,_,body=setup_api(client,monkeypatch)
    ack=c.post(f'/api/projects/{pid}/partial-draft',json=body).json()
    with sqlite3.connect(root/'fox.sqlite3') as db:
        db.execute('UPDATE events SET object_id=? WHERE action=?',
            ('{}','partial_draft:'+ack['selected_source_set_id']))
    result=c.get(f'/api/projects/{pid}')
    assert result.status_code==409 and result.json()['code']=='DRAFT_RECEIPT_UNAVAILABLE'


@pytest.mark.parametrize('corruption',['delete','owner'])
def test_missing_or_wrong_owner_receipt_blocks_reclassification_and_processing(client,monkeypatch,corruption):
    from test_project_submission import consent
    c,root,pid,_,_,body=setup_api(client,monkeypatch)
    ack=c.post(f'/api/projects/{pid}/partial-draft',json=body).json()
    plan=c.get(f'/api/projects/{pid}/conversion-plan').json()
    with sqlite3.connect(root/'fox.sqlite3') as db:
        if corruption=='delete':
            db.execute('DELETE FROM events WHERE action=?',('partial_draft:'+ack['selected_source_set_id'],))
        else:
            db.execute('UPDATE events SET owner=? WHERE action=?',
                ('other-synthetic-owner','partial_draft:'+ack['selected_source_set_id']))
    for path in (f'/api/projects/{pid}',f'/api/projects/{pid}/draft-scope?source_hash='+ack['source_hash']):
        result=c.get(path)
        assert result.status_code==409 and result.json()['code']=='DRAFT_RECEIPT_UNAVAILABLE'
    assert c.get(f'/api/projects/{pid}/conversion-plan').status_code!=200
    result=c.post(f'/api/projects/{pid}/runs',json=consent(plan))
    assert result.status_code==409 and result.json()['code']=='DRAFT_RECEIPT_UNAVAILABLE'
    assert c.post(f'/api/projects/{pid}/sources',files=[('files',('extra.txt',b'Synthetic note'))]).status_code==409
    with sqlite3.connect(root/'fox.sqlite3') as db:
        assert db.execute('SELECT COUNT(*) FROM runs').fetchone()[0]==0
        assert db.execute('SELECT COUNT(*) FROM acceptances').fetchone()[0]==0
        assert db.execute('SELECT COUNT(*) FROM source_sets WHERE project=?',(pid,)).fetchone()[0]==2
