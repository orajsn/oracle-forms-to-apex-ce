"""Real read-only legacy-v0 file/SQLite binding; synthetic sources only.

The production fixed scan is executed with only its two filesystem roots
mapped to pytest-owned paths. No OCI, model, import, lease or service action.
"""
import ast
from contextlib import redirect_stdout
from copy import deepcopy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3

import pytest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('legacy_v0_controller',ROOT/'deployment/cutover_project_release.py')
M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
pytestmark=pytest.mark.skipif(os.name!='posix',reason='actual POSIX fixed no-follow scan and readonly SQLite')


def execute(jobs,database):
    tree=ast.parse(M.LIVE_ROLLBACK_SCAN)
    mapping={'/home/opc/fox/data/jobs':str(jobs),'/home/opc/fox/data/fox.sqlite3':str(database)}
    counts={key:0 for key in mapping}
    for node in ast.walk(tree):
        if isinstance(node,ast.Constant) and node.value in mapping:
            counts[node.value]+=1;node.value=mapping[node.value]
    assert set(counts.values())=={1}
    output=io.StringIO()
    with redirect_stdout(output):
        exec(compile(tree,'<actual-fixed-legacy-v0-scan>','exec'),{'__name__':'synthetic_legacy_test'})
    return json.loads(output.getvalue())


def fixture(tmp_path,*,bom=False):
    jobs=tmp_path/'jobs';job=jobs/('fox-'+'1'*20);job.mkdir(parents=True)
    project='a'*32;file_id='b'*32;text='<FormModule Name="SYNTHETIC"/>'
    raw=(b'\xef\xbb\xbf' if bom else b'')+text.encode()
    source={'id':file_id,'project':project,'name':'synthetic.xml','sha256':hashlib.sha256(raw).hexdigest(),
            'bytes':len(raw),'text':text,'created':42.0}
    manifest=hashlib.sha256((source['name']+':'+source['sha256']).encode()).hexdigest()
    value={'project':project,'source_hash':manifest,'files':[source],
        'inventory':{'files':[],'dependencies':[],'issues':[],'missing_count':0,'scope_note':'Authored synthetic legacy fixture.', 'source_hash':manifest}}
    database=tmp_path/'fox.sqlite3'
    with sqlite3.connect(database) as db:
        db.execute('CREATE TABLE runs(id TEXT,project TEXT,source_hash TEXT,state TEXT)')
        db.execute('CREATE TABLE sources(id TEXT,project TEXT,name TEXT,sha256 TEXT,bytes INTEGER,text TEXT,created REAL)')
        db.execute('INSERT INTO runs VALUES(?,?,?,?)',(job.name,project,manifest,'REVIEW_REQUIRED'))
        db.execute('INSERT INTO sources VALUES(?,?,?,?,?,?,?)',tuple(source[k] for k in ('id','project','name','sha256','bytes','text','created')))
    snapshot=job/'source-snapshot.json';snapshot.write_bytes(json.dumps(value).encode())
    return jobs,database,snapshot,value


@pytest.mark.parametrize('bom',[False,True])
def test_complete_bound_v0_is_readable_without_relabel_approval_or_bytes_changed(tmp_path,bom):
    jobs,database,snapshot,value=fixture(tmp_path,bom=bom)
    original=snapshot.read_bytes();db_bytes=database.read_bytes()
    result=execute(jobs,database)
    assert result['read_only'] is True and result['project_history_present'] is False and result['jobs_checked']==1
    assert snapshot.read_bytes()==original and database.read_bytes()==db_bytes
    assert set(json.loads(snapshot.read_bytes()))=={'project','source_hash','files','inventory'}
    assert 'approvals' not in value and 'conversion_profile' not in value


@pytest.mark.parametrize('change',['empty','top_extra','native_form','project_marker','wrong_hash','wrong_file_hash',
    'changed_text','changed_size','boolean_created','file_extra','wrong_project','bad_inventory','duplicate_name'])
def test_incomplete_or_ambiguous_v0_cannot_be_treated_as_legacy(tmp_path,change):
    jobs,database,snapshot,value=fixture(tmp_path)
    if change=='empty':value={}
    elif change=='top_extra':value['approve_for_processing']=True
    elif change=='native_form':value['native_form']={}
    elif change=='project_marker':(snapshot.parent/'native-project-pipeline').mkdir()
    elif change=='wrong_hash':value['source_hash']='f'*64
    elif change=='wrong_file_hash':value['files'][0]['sha256']='e'*64
    elif change=='changed_text':value['files'][0]['text']+=' changed'
    elif change=='changed_size':value['files'][0]['bytes']+=1
    elif change=='boolean_created':value['files'][0]['created']=True
    elif change=='file_extra':value['files'][0]['new_untrusted_field']='x'
    elif change=='wrong_project':value['project']='c'*32
    elif change=='bad_inventory':value['inventory']['source_hash']='d'*64
    else:value['files'].append(deepcopy(value['files'][0]))
    snapshot.write_bytes(json.dumps(value).encode());original=snapshot.read_bytes()
    with pytest.raises(RuntimeError,match='LIVE_SOURCE_NOT_SAFE_FOR_G_RECOVERY'):
        execute(jobs,database)
    assert snapshot.read_bytes()==original


@pytest.mark.parametrize('change',['missing_run','wrong_run_project','wrong_run_source','queued','processing','wrong_stored_source','missing_source'])
def test_saved_source_must_match_real_readonly_database_binding(tmp_path,change):
    jobs,database,snapshot,value=fixture(tmp_path)
    with sqlite3.connect(database) as db:
        if change=='missing_run':db.execute('DELETE FROM runs')
        elif change=='wrong_run_project':db.execute("UPDATE runs SET project=?",('c'*32,))
        elif change=='wrong_run_source':db.execute("UPDATE runs SET source_hash=?",('f'*64,))
        elif change in ('queued','processing'):db.execute('UPDATE runs SET state=?',(change.upper(),))
        elif change=='wrong_stored_source':db.execute("UPDATE sources SET text='Different synthetic bytes'")
        else:db.execute('DELETE FROM sources')
    before=database.read_bytes()
    with pytest.raises(RuntimeError,match='LIVE_SOURCE_NOT_SAFE_FOR_G_RECOVERY'):
        execute(jobs,database)
    assert database.read_bytes()==before
