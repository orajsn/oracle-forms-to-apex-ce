"""Isolate stopped prototype history for a new project, never authorize its replay.

Only fresh submission calls this inside its existing BEGIN IMMEDIATE. Legacy
verification/retry admission is unchanged. Converter observations describe the
fixed single-process protocol, not arbitrary host processes or a maintenance
lease. Maintenance ingress draining and its data rechecks remain separate.
"""
from __future__ import annotations

from pathlib import Path
import hashlib
import re
import secrets
import sqlite3

from .opaf import OpafError, canonical_hash
from .prototype_admission import PROFILE_ID
from .prototype_job import read_prototype_snapshot, validate_prototype_snapshot
from .verification_recovery import preclaim_tree

_JOB = re.compile(r'fox-[a-f0-9]{20}\Z')
_PROJECT = re.compile(r'[a-f0-9]{32}\Z')
_SHA = re.compile(r'[a-f0-9]{64}\Z')
_MESSAGE = 'A previous operation needs an operator check before a new prototype can start. Your files are saved.'


class FreshPrototypeAdmissionError(RuntimeError):
    def __init__(self, message=_MESSAGE, status_code=409):
        super().__init__(message)
        self.status_code = status_code


def _need(value, message=_MESSAGE, status_code=409):
    if not value:
        raise FreshPrototypeAdmissionError(message, status_code)


def _sha(value):
    return type(value) is str and _SHA.fullmatch(value) is not None


def _rows(connection):
    rows = list(connection.execute('SELECT * FROM runs ORDER BY id'))
    _need(len(rows) <= 10000)
    return {row['id']:dict(row) for row in rows}


def _ledger_tables(connection):
    tables = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
              if row[0].startswith('verification_') or row[0] in ('technical_verifications','acceptances')]
    _need(len(tables)<=128)
    result={}
    for table in tables:
        if table=='verification_operator_contact':
            continue  # Mutable liveness is neither a claim nor execution clearance.
        _need(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*',table))
        columns={row[1] for row in connection.execute('PRAGMA table_info('+table+')')}
        result[table]='job_id' if 'job_id' in columns else ('run' if 'run' in columns else None)
    return result


def _ledger_rows(connection):
    result = {}
    for table,column in _ledger_tables(connection).items():
        rows = connection.execute('SELECT * FROM '+table).fetchmany(10001)
        _need(len(rows) <= 10000)
        def cells(row):
            return {key:({'blob_sha256':hashlib.sha256(value).hexdigest(),'bytes':len(value)}
                         if type(value) is bytes else value) for key,value in dict(row).items()}
        result[table] = (column, sorted(canonical_hash(cells(row)) for row in rows))
    return result


def _no_ledger(connection, job_id):
    return all(column is None or connection.execute(
        'SELECT 1 FROM '+table+' WHERE '+column+'=? LIMIT 1',(job_id,)).fetchone() is None
        for table,column in _ledger_tables(connection).items())


def _prototype(root, connection, row):
    job = root/'jobs'/row['id']
    if not _JOB.fullmatch(row['id']) or job.is_symlink() or not job.is_dir():
        return None
    snapshot,raw = read_prototype_snapshot(job)
    if snapshot.get('conversion_profile') != PROFILE_ID:
        return None
    validate_prototype_snapshot(snapshot)
    owner = connection.execute('SELECT owner FROM projects WHERE id=?',(row['project'],)).fetchone()
    _need(owner is not None and snapshot['project_id']==row['project']
          and snapshot['source_hash']==row['source_hash']
          and snapshot['approvals']['owner']==owner[0])
    return {'job':job,'snapshot':snapshot,'raw':raw,'owner':owner[0], 'tree':preclaim_tree(job)}


def _match_witness(value, *, row, saved, challenge, execution_target_sha256):
    fields = {'schema_version','scope','job_id','challenge','boundary','project_id','source_binding',
              'request_sha256','execution_target_sha256','retained_sha256','execution_authorized',
              'retry_authorized','closure_claimed','business_behavior_accepted','process_scope'}
    _need(type(value) is dict and set(value)==fields and type(value['schema_version']) is int
          and value['schema_version']==1 and value['scope']=='fox-prototype-isolation-witness-v1'
          and value['job_id']==row['id'] and value['challenge']==challenge
          and value['process_scope']=='single_converter_process' and _sha(value['retained_sha256'])
          and all(value[name] is False for name in
                  ('execution_authorized','retry_authorized','closure_claimed','business_behavior_accepted')))
    files = saved['tree']['files']; nodes=set(files)|set(saved['tree']['directories'])
    pipeline = saved['job']/'prototype-pipeline'
    boundary = value['boundary']
    if boundary=='receiver_absent':
        _need(row['state']=='ATTENTION' and all(value[name] is None for name in
              ('project_id','source_binding','request_sha256','execution_target_sha256')))
        _need(not any(name.startswith('prototype-pipeline/'+stage) for name in nodes
              for stage in ('validate','prepare_schema','import','verify_runtime','export')))
        return
    _need(value['project_id']==row['project']
          and value['source_binding']==saved['snapshot']['prototype']['source_binding']
          and value['execution_target_sha256']==execution_target_sha256
          and _sha(value['request_sha256']))
    from .verification_recovery import _load, preclaim_request
    from .prototype_pipeline import _check_converter_receipt
    stage = 'verify_runtime' if boundary=='runtime_not_dispatched' else 'export'
    _need(boundary in ('runtime_not_dispatched','export_complete')
          and row['state']==('ATTENTION' if boundary=='runtime_not_dispatched' else 'GENERATED'))
    intent_name='prototype-pipeline/'+stage+'-intent.json'
    _need(intent_name in files)
    intent=_load((pipeline/(stage+'-intent.json')).read_bytes())
    _need(intent=={'request_sha256':value['request_sha256']})
    if boundary=='runtime_not_dispatched':
        _need(not any('prototype-pipeline/'+name in nodes for name in
              ('verify_runtime.json','export-intent.json','export.json','runtime-request.json',
               'runtime-claim.json','runtime-result.json','runtime-receipt.json','runtime-evidence')))
        stages=('validate','prepare_schema','import')
    else:
        stages=('validate','prepare_schema','import','verify_runtime','export')
    base=preclaim_request(saved['job'])
    _need(base['job_id']==row['id'] and base['project_id']==row['project']
          and base['source_binding']==value['source_binding'])
    receipts={};final_request=None
    for prior in stages:
        _need('prototype-pipeline/'+prior+'.json' in files)
        request={**base,'prior_receipts':dict(receipts)}
        receipt=_load((pipeline/(prior+'.json')).read_bytes())
        _check_converter_receipt(prior,request,receipt)
        _need(receipt.get('stage')==prior and receipt.get('status')=='COMPLETE'
              and type(receipt.get('schema_version')) is int and receipt['schema_version']==1
              and receipt.get('scope')=='fox-prototype-converter-receipt-v1'
              and receipt.get('source_binding')==value['source_binding']
              and receipt.get('business_behavior_accepted') is False)
        if prior==stage:final_request=request
        receipts[prior]=receipt
    if final_request is None:final_request={**base,'prior_receipts':receipts}
    _need(canonical_hash(final_request)==value['request_sha256'])


class FreshAdmissionRead:
    """Transaction-scoped recheck; cannot be reused after commit or for old work."""
    def __init__(self, connection, recovery, root, project_id, source_hash, rows, ledgers, saved, target_check, target_sha):
        self.connection,self.recovery,self.root=connection,recovery,root
        self.project_id,self.source_hash=project_id,source_hash
        self.rows,self.ledgers,self.saved=rows,ledgers,saved
        self.target_check=target_check
        self.target_sha=target_sha

    def __call__(self, *, new_run_id=None):
        try:
            return self._recheck(new_run_id=new_run_id)
        except FreshPrototypeAdmissionError:
            raise
        except (OSError,ValueError,TypeError,KeyError,AttributeError,RuntimeError,sqlite3.Error):
            raise FreshPrototypeAdmissionError() from None

    def _recheck(self, *, new_run_id=None):
        self.recovery._transaction(self.connection)
        current=_rows(self.connection)
        if new_run_id is not None:
            _need(type(new_run_id) is str and _JOB.fullmatch(new_run_id) and new_run_id not in self.rows)
            added=current.pop(new_run_id,None)
            _need(added is not None and added['project']==self.project_id
                  and added['source_hash']==self.source_hash and added['state']=='QUEUED'
                  and added['artifact'] is None)
        _need(current==self.rows and _ledger_rows(self.connection)==self.ledgers)
        for job_id,pin in self.saved.items():
            owner=self.connection.execute('SELECT owner FROM projects WHERE id=?',
                                          (self.rows[job_id]['project'],)).fetchone()
            _need(owner is not None and owner[0]==pin['owner'] and _no_ledger(self.connection,job_id)
                  and preclaim_tree(pin['job'])==pin['tree']
                  and read_prototype_snapshot(pin['job'])[1]==pin['raw'])
        if self.saved:
            _need(self.target_check()==self.target_sha)


def prepare_fresh_admission(*, root, connection, recovery, project_id, source_hash,
                            witness_reader, target_check):
    """Only other-project stopped prototypes may avoid the unrelated-history gate.

    The caller has already verified new-project ownership, exact selected source,
    redaction, external-processing consent and target approval. It retains its
    BEGIN IMMEDIATE through this call, both rechecks and the unique insertion.
    """
    try:
        root=Path(root).absolute()
        recovery._transaction(connection)
        _need(type(project_id) is str and _PROJECT.fullmatch(project_id) and _sha(source_hash)
              and root.resolve()==root and not root.is_symlink() and not (root/'jobs').is_symlink())
        _need(not connection.execute("SELECT 1 FROM sqlite_master WHERE type='trigger' AND tbl_name IN ('runs','events') LIMIT 1").fetchone())
        rows=_rows(connection);ledgers=_ledger_rows(connection)
        _need(not any(row['project']==project_id for row in rows.values()),
              'This project already has a conversion. Open its saved run or create a new project for another prototype.')
        _need(not any(row['state'] in ('QUEUED','PROCESSING') for row in rows.values()),
              'Another conversion is active. Your files are saved; try again when it finishes.',429)
        saved={};target_sha=None
        for job_id in recovery._job_ids(connection):
            row=rows.get(job_id);_need(row is not None)
            pin=None
            if row['state'] in ('ATTENTION','GENERATED') and row['artifact'] is None:
                pin=_prototype(root,connection,row)
                if pin is not None:
                    _need(_no_ledger(connection,job_id))
            if pin is None:
                _need(recovery._eligibility(connection,job_id)['blocks_admission'] is False)
                continue
            challenge=secrets.token_hex(32)
            expected_target=target_check();_need(_sha(expected_target))
            _need(target_sha is None or target_sha==expected_target)
            target_sha=expected_target
            value=witness_reader(job_id,challenge)
            _need(target_check()==expected_target)
            _match_witness(value,row=row,saved=pin,challenge=challenge,execution_target_sha256=expected_target)
            saved[job_id]=pin
        result=FreshAdmissionRead(connection,recovery,root,project_id,source_hash,rows,ledgers,saved,target_check,target_sha)
        result()
        return result
    except FreshPrototypeAdmissionError:
        raise
    except OpafError as error:
        if error.status_code in (423,429,503):
            raise FreshPrototypeAdmissionError('The converter is busy or unavailable. Try again shortly; no new run was started.',503) from None
        raise FreshPrototypeAdmissionError() from None
    except (OSError,ValueError,TypeError,KeyError,AttributeError,RuntimeError,sqlite3.Error):
        raise FreshPrototypeAdmissionError() from None
