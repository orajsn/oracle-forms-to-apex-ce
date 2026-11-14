"""Real local SQLite/files; historical outcomes intentionally remain unknown."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace

import pytest

from fox import paused_stage_preservation as inert, verification_recovery as recovery


@pytest.fixture
def inert_case(tmp_path):
    root=tmp_path/'data';job_id='fox-'+'d'*20;job=root/'jobs'/job_id
    pipeline=job/'prototype-pipeline';pipeline.mkdir(parents=True)
    source='b'*64;profile='c'*64
    snapshot={'project_id':'project-a','source_hash':source,'selected_source_set_id':'source-set-a',
              'approvals':{'owner':'owner-a'},'prototype':{'target_profile_sha256':profile}}
    (job/'source-snapshot.json').write_text(json.dumps(snapshot))
    request={'schema_version':1,'scope':'fox-prototype-converter-request-v1','job_id':job_id,
        'project_id':'project-a','source_binding':source,'plan_sha256':'d'*64,'rendered_zip_sha256':'e'*64,
        'rendering_spec':{'profile_id':'native-blueprint-prototype-v1'},'source_authority':{},
        'prior_receipts':{'validate':{'unknown':'preserved'},'prepare_schema':{'unknown':'preserved'},
                          'import':{'application_id':12345,'application_alias':'APP_A','unknown':'preserved'}}}
    (pipeline/'verify_runtime-intent.json').write_text(json.dumps({'request_sha256':inert.hashed(request)}))
    # Unclosed historical data is retained, NOT promoted to closed/successful.
    (pipeline/'unknown-old-intent.json').write_text('{"outcome":"unknown"}')
    database=root/'fox.sqlite3'
    with sqlite3.connect(database) as db:
        db.executescript('''
        CREATE TABLE runs(id TEXT,project TEXT,source_hash TEXT,state TEXT,artifact TEXT,created REAL,updated REAL,message TEXT);
        CREATE TABLE projects(id TEXT,owner TEXT);
        CREATE TABLE project_source_selection(project TEXT,current_source_set_id TEXT);
        CREATE TABLE events(owner TEXT,action TEXT,object_id TEXT,created REAL);
        CREATE TABLE verification_queue(job_id TEXT,state TEXT);
        CREATE TABLE verification_retry_attempts(attempt_id TEXT,job_id TEXT);
        CREATE TABLE verification_retry_events(attempt_id TEXT,sequence INTEGER,state TEXT);
        ''')
        db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',(job_id,'project-a',source,'ATTENTION',None,1.,2.,'original failure'))
        db.execute('INSERT INTO projects VALUES(?,?)',('project-a','owner-a'))
        db.execute('INSERT INTO project_source_selection VALUES(?,?)',('project-a','source-set-a'))
        db.execute('INSERT INTO events VALUES(?,?,?,?)',('owner-a','unknown-original-event',job_id,1.))
    receiver=tmp_path/'receiver';stage=receiver/job_id/'prototype-converter';stage.mkdir(parents=True)
    for name,value in {'verify_runtime-request.json':request,'verify_runtime-intent.json':{'request_sha256':inert.hashed(request)},
                       'import.json':request['prior_receipts']['import'],'snapshot.json':{'opaque':'preserved'}}.items():
        (stage/name).write_text(json.dumps(value))
    def observe(path=database):
        with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as db:
            db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
            return inert.observe_fox(path,db)
    fox=observe();tree={job_id:recovery.preclaim_tree(receiver/job_id)}
    baseline={'schema_version':1,'scope':inert.BASELINE_SCOPE,**fox,'receiver':tree,'runtime':{'synthetic':'metadata'}}
    identity={**{key:'f'*64 for key in ('pair_sha256','lease_sha256','release_sha256','source_sha256','profile_sha256')},
              'runtime_state':'running','stopped_writer_sha256':None,
              'admission':{'enabled':True,'release_sha256':'f'*64}}
    expected={'baseline':baseline,'baseline_sha256':inert.hashed(baseline),'identity':identity}
    now=datetime.now(timezone.utc)
    packet={'schema_version':1,'scope':inert.READ_SCOPE,'binding':expected['baseline_sha256'],
            'observed_at_utc':now.isoformat(),'expires_at_utc':(now+timedelta(seconds=30)).isoformat(),
            'fox':fox,'receiver':tree,'identity':identity,'host':{'runtime_sha256':inert.hashed(baseline['runtime']),
             'receiver_sha256':inert.hashed(tree),'observation_sha256':'1'*64,'blockers':[]}}
    return SimpleNamespace(root=root,job=job,job_id=job_id,database=database,receiver=receiver,stage=stage,
                           request=request,baseline=baseline,packet=packet,expected=expected,now=now,observe=observe)


@pytest.fixture
def mixed_inert_case(inert_case):
    c=inert_case;c.opaque_id='fox-'+'a'*20;c.opaque_job=c.root/'jobs'/c.opaque_id
    c.opaque_job.mkdir()
    snapshot=json.loads((c.job/'source-snapshot.json').read_bytes())
    snapshot['prototype']['target_profile_sha256']='9'*64  # Historical, NOT current runtime authority.
    (c.opaque_job/'source-snapshot.json').write_text(json.dumps(snapshot))
    (c.opaque_job/'prototype-result.json').write_text('{"unresolved":true,"accepted":false}')
    for number in range(8):(c.opaque_job/f'retained-{number}.json').write_text('{"unknown":"preserved"}')
    with sqlite3.connect(c.database) as db:
        db.execute('INSERT INTO runs VALUES(?,?,?,?,?,?,?,?)',
            (c.opaque_id,'project-a','b'*64,'ATTENTION',None,.25,.5,'earlier failure remains unresolved'))
        db.execute('INSERT INTO events VALUES(?,?,?,?)',('owner-a','unknown-earlier-event',c.opaque_id,.25))
    def refresh():
        fox=c.observe();tree={job:inert.receiver_job_tree(c.receiver,job)for job in fox['jobs']}
        c.baseline.update(fox,receiver=tree);c.expected['baseline_sha256']=inert.hashed(c.baseline)
        c.packet.update(fox=fox,receiver=tree,binding=c.expected['baseline_sha256'])
        c.packet['host']['receiver_sha256']=inert.hashed(tree)
    c.refresh=refresh;refresh()
    return c


def test_mixed_runtime_and_earlier_failure_preserve_all_rows_trees_and_absence(mixed_inert_case):
    c=mixed_inert_case;before=(c.database.read_bytes(),recovery.preclaim_tree(c.job),recovery.preclaim_tree(c.opaque_job))
    assert len(before[2]['files'])==10 and not (c.receiver/c.opaque_id).exists()
    assert set(c.baseline['jobs'])=={c.job_id,c.opaque_id}
    assert c.baseline['jobs'][c.opaque_id]['boundary']==inert.OPAQUE_BOUNDARY
    assert c.baseline['jobs'][c.opaque_id]['runtime_request_sha256']is None
    assert c.baseline['receiver'][c.opaque_id]=={'absent':True,'parent_namespace':{
        'device':c.receiver.stat().st_dev,'inode':c.receiver.stat().st_ino,
        'owner':c.receiver.stat().st_uid,'mode':__import__('stat').S_IMODE(c.receiver.stat().st_mode)}}
    assert inert.runtime_target(c.baseline['jobs'])=={'target_profile_sha256':'c'*64}
    assert inert.runtime_target(dict(reversed(list(c.baseline['jobs'].items()))))=={'target_profile_sha256':'c'*64}
    for job in (c.job_id,c.opaque_id):
        with sqlite3.connect(c.database.as_uri()+'?mode=ro',uri=True)as db:
            db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
            value=inert.validate_pair(c.database,db,job,c.packet,c.expected,now=c.now)
        assert value['admission']['blocks_admission']is True and value['admission']['retry_eligible']is False
        assert value['preserved']['closure_claimed']is value['preserved']['continuation_authorized']is False
        assert value['preserved']['boundary']==('runtime_predispatch_unresolved'if job==c.job_id else inert.OPAQUE_BOUNDARY)
    assert before==(c.database.read_bytes(),recovery.preclaim_tree(c.job),recovery.preclaim_tree(c.opaque_job))
    assert not(c.receiver/c.opaque_id).exists()


@pytest.mark.parametrize('name',['verify_runtime-intent.json','verify_runtime-request.json','verify_runtime.json',
    'export-intent.json','export.json','runtime-request.json','runtime-evidence'])
@pytest.mark.parametrize('directory',[False,True])
def test_opaque_cannot_hide_runtime_or_later_file_or_directory(mixed_inert_case,name,directory):
    c=mixed_inert_case;pipeline=c.opaque_job/'prototype-pipeline';pipeline.mkdir()
    path=pipeline/name
    if directory:path.mkdir()
    else:path.write_text('{"request_sha256":"invalid"}')
    with pytest.raises((inert.PreservationError,recovery.RecoveryError)):
        c.observe()


@pytest.mark.parametrize('fault',['new-file','row','source','event','queued','processing','ledger','receiver-created','parent-namespace'])
def test_mixed_opaque_mutations_and_runnable_work_fail_closed(mixed_inert_case,fault):
    c=mixed_inert_case;p=deepcopy(c.packet)
    if fault=='new-file':(c.opaque_job/'new.json').write_text('{}')
    elif fault=='source':
        snapshot=json.loads((c.opaque_job/'source-snapshot.json').read_bytes());snapshot['approvals']['owner']='changed'
        (c.opaque_job/'source-snapshot.json').write_text(json.dumps(snapshot))
    elif fault in ('row','event','queued','processing','ledger'):
        with sqlite3.connect(c.database)as db:
            if fault=='row':db.execute('UPDATE runs SET message=? WHERE id=?',('changed',c.opaque_id))
            elif fault=='event':db.execute('INSERT INTO events VALUES(?,?,?,?)',('owner-a','new-event',c.opaque_id,3.))
            elif fault=='ledger':db.execute('INSERT INTO verification_queue VALUES(?,?)',(c.opaque_id,'attention'))
            else:db.execute('UPDATE runs SET state=? WHERE id=?',(fault.upper(),c.opaque_id))
    elif fault=='receiver-created':
        (c.receiver/c.opaque_id).mkdir()
        p['receiver'][c.opaque_id]=inert.receiver_job_tree(c.receiver,c.opaque_id)
        p['host']['receiver_sha256']=inert.hashed(p['receiver'])
    else:
        p['receiver'][c.opaque_id]['parent_namespace']['inode']+=1
        p['host']['receiver_sha256']=inert.hashed(p['receiver'])
    with pytest.raises((inert.PreservationError,recovery.RecoveryError)):
        validate(c,p)


def test_runtime_target_refuses_missing_or_conflicting_runtime_candidates(mixed_inert_case):
    c=mixed_inert_case;jobs=deepcopy(c.baseline['jobs'])
    jobs[c.opaque_id]['boundary']=inert.RUNTIME_CANDIDATE;jobs[c.opaque_id]['runtime_request_sha256']='e'*64
    with pytest.raises(inert.PreservationError,match='RUNTIME_TARGET'):inert.runtime_target(jobs)
    with pytest.raises(inert.PreservationError,match='RUNTIME_TARGET'):inert.runtime_target({c.opaque_id:c.baseline['jobs'][c.opaque_id]})


def validate(case,packet=None,expected=None):
    with sqlite3.connect(case.database.as_uri()+'?mode=ro',uri=True) as db:
        db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
        return inert.validate_pair(case.database,db,case.job_id,packet or case.packet,expected or case.expected,now=case.now)


def test_unknown_history_is_unchanged_blocked_and_never_eligibility(inert_case,monkeypatch):
    case=inert_case;before=(case.database.read_bytes(),recovery.preclaim_tree(case.job))
    monkeypatch.setattr(recovery.VerificationRecovery,'_eligibility',lambda *a,**k:pytest.fail('No historical semantic classification'))
    store=recovery.VerificationRecovery(case.database,enabled=True)
    with sqlite3.connect(case.database.as_uri()+'?mode=ro',uri=True) as db:
        db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
        result=store._protected_read_status(db,case.job_id,purpose=inert.PURPOSE,paired_readback=case.packet,
                                           expected_pair=case.expected,now=case.now)
    assert result['admission']=={'blocks_admission':True,'retry_eligible':False,'recovery_state':inert.STATE}
    assert result['preserved']['unresolved'] is True
    assert result['preserved']['closure_claimed'] is result['preserved']['continuation_authorized'] is False
    assert before==(case.database.read_bytes(),recovery.preclaim_tree(case.job))
    from fox.prototype_authority import _retained_request
    with pytest.raises(ValueError):_retained_request(case.job,case.packet)


@pytest.mark.parametrize('fault',['floor','row','owner','selection','extra-event','queued','processing','qa-queued',
                                 'retry','paused-ledger','stale','identity','disabled','profile','host','extra-paused'])
def test_every_changed_floor_or_runnable_boundary_fails(inert_case,fault):
    c=inert_case;p=deepcopy(c.packet);e=deepcopy(c.expected)
    if fault=='floor':(c.job/'added.json').write_text('{}')
    elif fault in ('row','owner','selection','extra-event','queued','processing','qa-queued','retry','paused-ledger','extra-paused'):
        with sqlite3.connect(c.database) as db:
            if fault=='row':db.execute("UPDATE runs SET message='changed'")
            elif fault=='owner':db.execute("UPDATE projects SET owner='someone-else'")
            elif fault=='selection':db.execute("UPDATE project_source_selection SET current_source_set_id='new'")
            elif fault=='extra-event':db.execute("INSERT INTO events VALUES('x','extra','x',3)")
            elif fault in ('queued','processing'):db.execute('UPDATE runs SET state=?',(fault.upper(),))
            elif fault in ('qa-queued','paused-ledger'):db.execute('INSERT INTO verification_queue VALUES(?,?)',(c.job_id,'queued' if fault=='qa-queued' else 'attention'))
            elif fault=='retry':
                db.execute("INSERT INTO verification_retry_attempts VALUES('a','another')")
                db.execute("INSERT INTO verification_retry_events VALUES('a',1,'reserved')")
            else:db.execute("INSERT INTO runs VALUES(?, 'project-a', ?, 'ATTENTION', NULL, 1, 2, 'other')",('fox-'+'b'*20,'b'*64))
    elif fault=='stale':p['expires_at_utc']=(c.now-timedelta(seconds=1)).isoformat()
    elif fault in ('identity','disabled','profile'):
        key={'identity':'pair_sha256','profile':'profile_sha256'}.get(fault)
        if fault=='disabled':e['identity']['admission']['enabled']=False
        else:p['identity'][key]='0'*64
    else:p['host']['blockers']=['unknown runtime producer']
    with pytest.raises((inert.PreservationError,recovery.RecoveryError,FileNotFoundError)):
        validate(c,p,e)


def test_naming_projection_matches_existing_browser_contract_without_authority(inert_case,monkeypatch):
    from forms2apex import prototype_package, blueprint_profiles
    c=inert_case;request=c.request
    imported={'imported':True,'application_id':12345,'application_alias':prototype_package.alias_for_job(c.job_id),
              'workspace':'FORMS2APEX_POC','import_intent_sha256':'1'*64,'compiled_metadata_sha256':'2'*64}
    renderer=SimpleNamespace(PROFILE_ID=request['rendering_spec']['profile_id'],validate_prototype_spec=lambda value:value)
    monkeypatch.setattr(blueprint_profiles,'select',lambda value:renderer)
    snapshot={'opaque':'preserved'}
    assert inert.runtime_identity(request,imported,snapshot)==prototype_package.runtime_binding(request,imported,snapshot)


def test_disabled_recovery_store_cannot_use_maintenance_packet(inert_case):
    c=inert_case;store=recovery.VerificationRecovery(c.database,enabled=False)
    with sqlite3.connect(c.database.as_uri()+'?mode=ro',uri=True) as db:
        db.row_factory=sqlite3.Row;db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
        with pytest.raises(recovery.RecoveryError,match='ENABLED_ADMISSION'):
            store._protected_read_status(db,c.job_id,purpose=inert.PURPOSE,paired_readback=c.packet,expected_pair=c.expected)
