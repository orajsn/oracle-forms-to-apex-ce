"""Real read-only assessment/request flow on synthetic source and local SQLite."""
from copy import deepcopy
import sqlite3

import pytest

from fox.source_requests import build_source_requests,request_text
from test_dependency_guidance import form,spec,body,ddl,src,assess
from test_source_history_api import client,settings,no_external_actions,upload,new_project


def two_forms():
    other=src('history.xml',form()['text'].replace('Name="ORDER_ENTRY"','Name="ORDER_HISTORY"'))
    return [form(),other,ddl(),spec()]


def test_shared_body_is_one_request_with_all_callers_and_no_plan_mutation():
    plan=assess(two_forms());original=deepcopy(plan);value=build_source_requests(plan)
    group=next(g for g in value['groups'] if g['kind']=='package')
    assert group['state']=='MISSING_SOURCE' and group['missing_parts']==['package_body']
    assert group['form_count']==group['reference_count']==2 and value['counts']['requests']==1
    text=request_text(plan,value)
    assert '.pkb' in text and '.pks' not in text
    assert 'ORDER_ENTRY' in text and 'ORDER_HISTORY' in text and 'Button Approve order' in text
    assert plan==original and plan['can_generate'] is False


def test_body_availability_resolves_request_not_behavior():
    before=assess(two_forms());after=assess(two_forms()+[body()])
    first=build_source_requests(before);later=build_source_requests(after)
    assert first['counts']['requests']==1 and later['counts']['requests']==0
    assert any(g['kind']=='package' and g['state']=='SOURCE_AVAILABLE' for g in later['groups'])
    assert after['can_generate'] is False and after['rendering_spec'] is None
    assert 'not conversion readiness' in request_text(after,later)
    assert {g['id'] for g in first['groups']}.isdisjoint(g['id'] for g in later['groups'])


def test_wrong_routine_is_still_an_action_not_a_missing_body_guess():
    plan=assess([form(),ddl(),spec('CANCEL_ORDER'),body('CANCEL_ORDER')])
    group=next(g for g in build_source_requests(plan)['groups'] if g['kind']=='package')
    assert group['state']=='ROUTINE_UNCONFIRMED' and group['missing_parts']==[]
    assert group['routines']==['APPROVE_ORDER'] and not plan['can_generate']


def test_schema_qualified_objects_are_not_combined():
    files=two_forms();files[1]=src('history.xml',files[1]['text'].replace('ORDER_API.APPROVE_ORDER','APP.ORDER_API.APPROVE_ORDER'))
    groups=[g for g in build_source_requests(assess(files))['groups'] if g['kind']=='package']
    assert len(groups)==2 and {g['target'] for g in groups}=={'ORDER_API','APP.ORDER_API'}


def test_unaffected_form_does_not_inflate_request_count():
    plan=assess(two_forms());extra=deepcopy(plan['forms'][0])
    extra['module_id']='unaffected-form';extra['form_name']='ORDER_LOOKUP'
    extra['dependencies']=[d for d in extra['dependencies'] if d['kind']!='package']
    plan['forms'].append(extra)
    value=build_source_requests(plan)
    assert value['counts']['requests']==1 and value['counts']['forms']==2
    assert any(g['form_count']==3 for g in value['groups'] if g['state']=='SOURCE_AVAILABLE')


def test_incomplete_or_large_lists_keep_counts_unconfirmed_not_zero():
    plan=assess(two_forms());plan['assessment_complete']=False
    assert build_source_requests(plan)['counts'] is None
    plan=assess(two_forms());plan['forms'][0]['dependencies']*=1001
    value=build_source_requests(plan)
    assert value['complete'] is False and value['counts'] is None
    with pytest.raises(ValueError):request_text(plan,value)


def test_same_project_upload_reassesses_and_stale_request_export_is_rejected(client):
    c,root,pid=client
    def send(files):return upload(c,pid,[(f['name'],f['text'].encode()) for f in files])
    send(two_forms())
    initial=c.get('/api/projects/'+pid).json();plan=initial['project_plan'];checklist=initial['source_requests']
    assert checklist['counts']['requests']==1 and checklist['source_hash']==plan['source_hash']
    path=f"/api/projects/{pid}/source-requests.txt?source_hash={plan['source_hash']}&plan_sha256={plan['plan_sha256']}"
    export=c.get(path);assert export.status_code==200 and 'ORDER_HISTORY' in export.text
    send([body()])
    current=c.get('/api/projects/'+pid).json()
    assert current['id']==initial['id'] and current['source_requests']['counts']['requests']==0
    assert current['project_plan']['can_generate'] is False
    assert c.get(path).status_code==409
    with sqlite3.connect(root/'fox.sqlite3') as db:
        assert db.execute('SELECT count(*) FROM runs').fetchone()[0]==0
        assert db.execute('SELECT count(*) FROM acceptances').fetchone()[0]==0


def test_source_requests_are_owner_scoped(client):
    c,root,_=client
    with sqlite3.connect(root/'fox.sqlite3') as db:
        db.execute('INSERT INTO projects VALUES(?,?,?,?,?,?)',('not-yours','another-owner','Synthetic','Other','',1))
    assert c.get('/api/projects/not-yours/source-requests.txt?source_hash=x&plan_sha256=y').status_code==404
