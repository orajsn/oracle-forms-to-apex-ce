"""Saved history uses real package validators, with external transports isolated.

Synthetic local fixture only: not a live Oracle import or human acceptance.
"""
import sqlite3

from fastapi.testclient import TestClient

from fox.app import create_app,password_hash
from test_project_verification_runtime import actual_release,case,row,change_sources
from test_source_history_api import no_external_actions


def retained(case):
    return {str(p.relative_to(case.job)):p.read_bytes() for p in case.job.rglob('*') if p.is_file()}


def test_history_api_keeps_original_form_names_after_source_changes(case,monkeypatch):
    monkeypatch.setenv('FOX_ADMIN_USERNAME','synthetic-owner')
    monkeypatch.setenv('FOX_PASSWORD_HASH',password_hash('synthetic-history-only'))
    monkeypatch.setenv('FOX_PUBLIC_ORIGIN','http://testserver')
    monkeypatch.setenv('FOX_CONVERSION_PROFILE','native-project-v1')
    monkeypatch.setenv('FOX_VERIFICATION_ENABLED','0')
    app=create_app(case.root,enable_worker=False)
    with TestClient(app) as c:
        c.headers['Origin']='http://testserver'
        assert c.post('/api/login',json={'username':'synthetic-owner','password':'synthetic-history-only'}).status_code==200
        original_row=row(case);original_files=retained(case)
        plan=case.snapshot['native_project']
        expected={form['module_id']:(form['form_name'],form['source_name']) for form in plan['forms']}
        def read_run():
            detail=c.get('/api/projects/'+case.snapshot['project_id'])
            assert detail.status_code==200
            return detail.json(),detail.json()['runs'][0]
        initial,run=read_run()
        assert {f['module_id']:(f['form_name'],f['source_name']) for f in run['forms']}==expected
        assert all(set(f)=={'module_id','form_name','source_name','state','message'} for f in run['forms'])
        assert run['artifact_generated'] and not run['technical_verified'] and not run['human_accepted']
        change_sources(case)
        current,later=read_run()
        assert current['inventory']['source_hash']!=run['source_hash']
        assert later['forms']==run['forms'] and later['source_hash']==run['source_hash']
        assert later['recovery']=={'kind':'check_status','enabled':True,'safety':'read_only','label':'Check run status'}
        for _ in range(3):assert read_run()[1]['forms']==run['forms']
        assert row(case)==original_row and retained(case)==original_files
        with sqlite3.connect(case.root/'fox.sqlite3') as db:
            assert db.execute('SELECT count(*) FROM runs').fetchone()[0]==1
            assert db.execute('SELECT count(*) FROM acceptances').fetchone()[0]==0
