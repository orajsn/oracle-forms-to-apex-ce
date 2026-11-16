"""Current-owner admission for one unchanged, failed connectionless validation."""
import hashlib
import json
from pathlib import Path
import re
import time

from .native_pipeline import _json, _save_once
from .opaf import OpafError, canonical_hash

SCOPE = 'fox-prototype-validation-retry-v1'
RECORD = 'validation-retry.json'
INTENT = 'validation-retry-intent.json'
EVENT = 'approved_prototype_validation_retry'


def present(job):
    return (Path(job)/RECORD).exists() or (Path(job)/RECORD).is_symlink()


def request_for(job,snapshot):
    from .prototype_preclaim_continuation import request_for as original_request
    return original_request(job,snapshot)


def checkpoint(request,witness,snapshot_sha256):
    return canonical_hash({'scope':SCOPE,'request':request,'witness':witness,'snapshot_sha256':snapshot_sha256})


def validate_owner(job,snapshot,original,connection):
    if not present(job):
        if connection.execute('SELECT 1 FROM events WHERE action=? AND object_id LIKE ?', (EVENT,job.name+':%')).fetchone():
            raise OpafError('Validation retry lost its durable owner record.')
        return None
    value=_json(job/RECORD)
    if (set(value)!={'schema_version','scope','job_id','project_id','owner','approved_at','snapshot_sha256',
            'source_hash','target_profile_sha256','request','witness','checkpoint_sha256','approvals'}
            or type(value['schema_version']) is not int or value['schema_version']!=1 or value['scope']!=SCOPE
            or value['job_id']!=job.name or value['project_id']!=snapshot['project_id']
            or value['owner']!=snapshot['approvals']['owner'] or value['source_hash']!=snapshot['source_hash']
            or value['target_profile_sha256']!=snapshot['prototype']['target_profile_sha256']
            or value['snapshot_sha256']!=hashlib.sha256(original).hexdigest()
            or value['request']!=request_for(job,snapshot)
            or value['checkpoint_sha256']!=checkpoint(value['request'],value['witness'],value['snapshot_sha256'])
            or type(value['approvals']) is not dict or set(value['approvals'])!={'redacted_source','external_ai','synthetic_prototype'}
            or any(v is not True for v in value['approvals'].values())):
        raise OpafError('Validation retry differs from original source-owner permission.')
    rows=connection.execute('SELECT owner,object_id,created FROM events WHERE action=? AND object_id LIKE ?',
        (EVENT,job.name+':%')).fetchall()
    if [tuple(r) for r in rows]!=[(value['owner'],job.name+':'+canonical_hash(value),value['approved_at'])]:
        raise OpafError('Validation retry has no exact durable owner event.')
    return value


def check_witness(request,witness,target,manifest_sha256):
    from .prototype_authority import execution_target
    hashes=('request_sha256','source_binding','plan_sha256','rendered_zip_sha256','failed_receipt_sha256',
            'failed_log_sha256','execution_target_sha256','manifest_sha256')
    if (type(witness) is not dict or set(witness)!={'schema_version','scope','attempt','job_id',*hashes,
            'connection_mode','source_review_authorized'}
            or type(witness['schema_version']) is not int or witness['schema_version']!=1
            or witness['scope']!='fox-prototype-failed-validation-v1' or type(witness['attempt']) is not int
            or witness['attempt']!=2 or witness['job_id']!=request['job_id']
            or witness['request_sha256']!=canonical_hash(request)
            or any(witness[k]!=request[k] for k in ('source_binding','plan_sha256','rendered_zip_sha256'))
            or witness['execution_target_sha256']!=canonical_hash(execution_target(target))
            or witness['manifest_sha256']!=manifest_sha256 or witness['connection_mode']!='/nolog'
            or witness['source_review_authorized'] is not False
            or any(type(witness[k]) is not str or not re.fullmatch('[a-f0-9]{64}',witness[k]) for k in hashes)):
        raise OpafError('Failed validation witness does not match the unchanged candidate and target.')
    return witness


def attach_routes(app,*,root,db,project_owner,current_sources,admission_allowed,target_reader,input_model,
                  installation_projection=None,configuration_loader=None):
    from fastapi import Request,HTTPException
    from fastapi.responses import Response
    from . import source_history
    from .prototype_job import read_prototype_snapshot,validate_prototype_snapshot
    from .prototype_pipeline import authorize_prototype_request
    from .prototype_transport import PrototypeHttpConverterAdapter
    import sqlite3
    errors=(ValueError,TypeError,KeyError,AttributeError,OSError,RuntimeError,sqlite3.Error)

    def context(c,pid,rid,owner):
        if not re.fullmatch('fox-[a-f0-9]{20}',rid): raise HTTPException(404,'Run not found.')
        row=c.execute('SELECT * FROM runs WHERE id=? AND project=?',(rid,pid)).fetchone()
        job=root/'jobs'/rid
        if not row or job.is_symlink() or (root/'jobs').is_symlink(): raise ValueError()
        run=dict(row)
        snapshot,original=read_prototype_snapshot(job)
        documents=validate_prototype_snapshot(snapshot)
        selected=snapshot['prototype']
        sources=current_sources(pid,c)
        target=target_reader()
        locked=c.execute('SELECT owner FROM projects WHERE id=?',(pid,)).fetchone()
        if (not locked or locked['owner']!=owner or snapshot['approvals']['owner']!=owner
                or snapshot['project_id']!=pid or run['source_hash']!=snapshot['source_hash'] or run['artifact'] is not None
                or run['state'] not in ('ATTENTION','QUEUED','PROCESSING','GENERATED')
                or source_history._hash(sources)!=snapshot['source_hash']
                or source_history.selected_source_set_id(c,pid)!=snapshot['selected_source_set_id']
                or [(s['name'],source_history.readable_source_bytes(s)) for s in sources]!=documents
                or target['target_profile_sha256']!=selected['target_profile_sha256']
                or canonical_hash(target['target_profile'])!=selected['target_profile_sha256']): raise ValueError()
        request=request_for(job,snapshot)
        authorize_prototype_request(job,request)
        recorded=present(job)
        validate_owner(job,snapshot,original,c)
        if recorded:
            record=validate_owner(job,snapshot,original,c)
        else:
            if run['state']!='ATTENTION' or (job/INTENT).exists(): raise ValueError()
            for stage in ('prepare_schema','import','verify_runtime','export'):
                if any((job/'prototype-pipeline'/(stage+s)).exists() for s in ('.json','-intent.json')): raise ValueError()
            if (job/'prototype-pipeline/validate.json').exists(): raise ValueError()
        from .prototype_job import _configuration
        configured=(configuration_loader or _configuration)(selected['target_profile_sha256'],installation_projection=installation_projection)
        adapter=PrototypeHttpConverterAdapter(job,configured['gateway'])
        witness=adapter.validation_retry_witness()
        manifest=_json(job/'prototype-transport/authority.json')['manifest_sha256']
        check_witness(request,witness,target['target_profile'],manifest)
        key=checkpoint(request,witness,hashlib.sha256(original).hexdigest())
        if recorded and (record['witness']!=witness or record['checkpoint_sha256']!=key): raise ValueError()
        pipeline=job/'prototype-pipeline'
        calls=len(list(pipeline.glob('focus-*/mapper.json')))+len(list(pipeline.glob('focus-*/reviewer.json')))
        calls+=int((pipeline/'container-review/reviewer.json').is_file())
        projection={'schema_version':1,'scope':SCOPE,'project_id':pid,'run_id':rid,'source_hash':snapshot['source_hash'],
            'source_binding':selected['source_binding'],'selected_source_set_id':snapshot['selected_source_set_id'],
            'target_profile_sha256':selected['target_profile_sha256'],'approved_chunk_hashes':selected['approved_chunk_hashes'],
            'checkpoint_sha256':key,'eligible':not recorded,'continuation_recorded':recorded,'validation_attempt':2,
            'retained_model_calls':calls,'new_model_calls':0,'validation_database_calls':0,'continues_original_pipeline':True,
            'next_action':'open_run' if recorded else 'confirm_validation_retry','business_behavior_accepted':False,
            'reason':'Recheck the unchanged draft without rerunning AI. Validation uses no database connection; a pass continues the original synthetic pipeline.'}
        return projection,job,snapshot,original,request,witness,run

    route='/api/projects/{pid}/prototype-runs/{rid}/retry-validation'
    @app.get(route)
    def get_retry(pid:str,rid:str,request:Request):
        owner=project_owner(request,pid)['owner']
        try:
            with db() as c:
                c.execute('BEGIN')
                value=context(c,pid,rid,owner)[0]
            return Response(json.dumps(value),media_type='application/json',headers={'Cache-Control':'no-store'})
        except HTTPException: raise
        except errors:
            raise HTTPException(409,'An unchanged, definitively failed validation retry could not be verified. Retained outcomes remain unchanged.') from None

    @app.post(route,status_code=202)
    def post_retry(pid:str,rid:str,body:input_model,request:Request):
        owner=project_owner(request,pid)['owner']
        try:
            with db() as c:
                c.execute('BEGIN IMMEDIATE')
                value,job,snapshot,original,first,witness,run=context(c,pid,rid,owner)
                if (body.checkpoint_sha256!=value['checkpoint_sha256'] or body.source_hash!=value['source_hash']
                        or body.source_binding!=value['source_binding']
                        or body.expected_current_source_set_id!=value['selected_source_set_id']
                        or body.target_profile_sha256!=value['target_profile_sha256']
                        or body.approved_chunk_hashes!=value['approved_chunk_hashes']
                        or not all(v is True for v in (body.approved_redacted_source,body.approved_external_ai,body.approved_prototype_scope))): raise ValueError()
                result={'id':rid,'state':run['state'] if value['continuation_recorded'] else 'QUEUED',
                    'conversion_profile':'native-blueprint-prototype-v1','continued':True,'continuation_recorded':True,
                    'next_action':'open_run','business_behavior_accepted':False}
                if value['continuation_recorded']:
                    return Response(json.dumps(result),status_code=200,media_type='application/json',headers={'Cache-Control':'no-store'})
                if not admission_allowed(c): raise HTTPException(429,'Other unresolved work blocks validation retry.')
                now=time.time()
                record={'schema_version':1,'scope':SCOPE,'job_id':rid,'project_id':pid,'owner':owner,'approved_at':now,
                    'snapshot_sha256':hashlib.sha256(original).hexdigest(),'source_hash':snapshot['source_hash'],
                    'target_profile_sha256':value['target_profile_sha256'],'request':first,'witness':witness,
                    'checkpoint_sha256':value['checkpoint_sha256'],
                    'approvals':{'redacted_source':True,'external_ai':True,'synthetic_prototype':True}}
                _save_once(job/RECORD,record)
                if read_prototype_snapshot(job)[1]!=original: raise ValueError()
                changed=c.execute("UPDATE runs SET state='QUEUED',message=?,updated=? WHERE id=? AND state='ATTENTION' AND artifact IS NULL",
                    ('Retrying unchanged connectionless draft validation; saved model and failed validation evidence are preserved.',now,rid))
                if changed.rowcount!=1: raise ValueError()
                c.execute('INSERT INTO events(owner,action,object_id,created) VALUES(?,?,?,?)',
                    (owner,EVENT,rid+':'+canonical_hash(record),now))
            return Response(json.dumps(result),status_code=202,media_type='application/json',headers={'Cache-Control':'no-store'})
        except HTTPException: raise
        except errors:
            raise HTTPException(409,'Validation retry was not queued. Reconcile retained outcomes without replay.') from None
