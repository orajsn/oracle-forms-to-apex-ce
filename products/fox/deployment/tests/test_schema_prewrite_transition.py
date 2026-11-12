"""Authored controller boundaries only; no cloud, database or preservation grant."""
from contextlib import redirect_stdout
import base64
import io
import json
import sys

import pytest

from test_current_pair_transition import M


@pytest.mark.parametrize('scope,stage',[
    ('fox-reviewed-preclaim-terminal-baseline-v1','validate'),
    ('fox-reviewed-claimed-validation-terminal-baseline-v1','validate'),
    ('fox-reviewed-schema-prewrite-terminal-baseline-v1','prepare_schema'),
])
def test_baseline_kind_selects_only_explicit_known_stage(scope,stage):
    assert M.preservation_stage({'scope':scope})==stage


@pytest.mark.parametrize('scope',[None,True,1,[],{},'prepare_schema','unknown'])
def test_unknown_or_untyped_baseline_scope_refuses(scope):
    with pytest.raises(M.TransitionError,match='BASELINE_INVALID'):
        M.preservation_stage({'scope':scope})


SOURCE=r'''
from contextlib import contextmanager
from pathlib import Path
SCHEMA_PREWRITE_MAINTENANCE_SCOPE='schema-read'
CLAIMED_VALIDATION_MAINTENANCE_SCOPE='claimed-read'
calls=[]
class DB:
 def execute(self,statement,params=()):
  assert statement in ('PRAGMA query_only=ON','BEGIN','SELECT * FROM runs WHERE id=?')
  self.params=params;return self
 def fetchone(self):return {'id':self.params[0],'state':'ATTENTION','artifact':None}
class VerificationRecovery:
 def __init__(self,database,enabled):self.database=database
 @contextmanager
 def _db(self,write):
  assert write is False;yield DB()
 def _job_ids(self,db):return ['fox-'+'a'*20]
 def _protected_read_status(self,db,job,purpose,paired_readback=None,expected_pair=None):
  calls.append(purpose)
  if purpose=='maintenance_schema_prewrite_preservation':
   assert paired_readback['scope']=='schema-read'
   stage='prepare_schema';state='schema_prewrite_history'
  elif purpose=='maintenance_preclaim_preservation':
   assert paired_readback['scope']=='claimed-read','EXPLICIT_SCHEMA_PURPOSE_REQUIRED'
   stage='validate';state='claimed_validation_history'
  else:
   return {'admission':{'blocks_admission':False,'retry_eligible':False},'preservation_allowed':False}
  return {'admission':{'blocks_admission':True,'retry_eligible':False},'preservation_allowed':True,
   'preservation_state':state,'preserved':{'stage':stage,'retry_allowed':False}}
 def _precheck_schema(self,db):return False
 def _precheck_original_rows(self,db):return {'unchanged':True}
def validate_preclaim_pair(database,db,run,readback,expected,stage='validate'):
 assert stage==('prepare_schema' if readback['scope']=='schema-read' else 'validate')
 calls.append('validate:'+stage)
 return {'stage':stage,'retry_allowed':False}
'''


def execute_backend(monkeypatch,**maps):
    raw=SOURCE.encode();payload={'source':base64.b64encode(raw).decode(),
        'sha256':M.sha(raw),'paths':list(sys.path),'data':'/synthetic',**maps}
    monkeypatch.setattr(sys,'stdin',io.StringIO(json.dumps(payload)))
    monkeypatch.setitem(sys.modules,'fox._transition_recovery',None)
    output=io.StringIO()
    with redirect_stdout(output):exec(compile(M.BACKEND,'<actual-controller-backend>','exec'),{})
    return json.loads(output.getvalue()),list(sys.modules['fox._transition_recovery'].calls)


def test_schema_map_uses_distinct_purpose_and_does_not_clear_admission(monkeypatch):
    job='fox-'+'a'*20
    value,calls=execute_backend(monkeypatch,paired_schema_prewrite={job:{'readback':{'scope':'schema-read'},'expected':{}}})
    assert calls==['maintenance_schema_prewrite_preservation','validate:prepare_schema']
    assert value['eligibility'][job]=={'blocks_admission':True,'retry_eligible':False}
    assert value['preservation'][job]['state']=='schema_prewrite_history'
    assert value['outcomes']=={'unchanged':True}
    assert value['closed_prechecks']==value['closed_qa_stages']==value['closed_project_prewrite']=={}


def test_existing_claimed_validation_map_keeps_original_purpose(monkeypatch):
    job='fox-'+'a'*20
    value,calls=execute_backend(monkeypatch,paired_preclaim={job:{'readback':{'scope':'claimed-read'},'expected':{}}})
    assert calls==['maintenance_preclaim_preservation','validate:validate']
    assert value['preservation'][job]['state']=='claimed_validation_history'


def test_schema_scope_is_not_implicitly_upgraded_under_old_purpose(monkeypatch):
    job='fox-'+'a'*20
    with pytest.raises(AssertionError,match='EXPLICIT_SCHEMA_PURPOSE_REQUIRED'):
        execute_backend(monkeypatch,paired_preclaim={job:{'readback':{'scope':'schema-read'},'expected':{}}})


def test_overlapping_or_unknown_job_maps_refuse(monkeypatch):
    job='fox-'+'a'*20;value={job:{'readback':{'scope':'schema-read'},'expected':{}}}
    with pytest.raises(AssertionError):execute_backend(monkeypatch,paired_preclaim=value,paired_schema_prewrite=value)
    with pytest.raises(AssertionError):execute_backend(monkeypatch,paired_schema_prewrite={'unknown':value[job]})


def test_generated_programs_compile_and_schema_mode_is_read_only():
    compile(M.BACKEND,'<backend>','exec');compile(M.PRECLAIM_TECHNICAL,'<technical>','exec')
    assert "stage='prepare_schema'" in M.BACKEND
    assert 'r.schema_prewrite_request' in M.PRECLAIM_TECHNICAL
    assert 'r.preclaim_request' in M.PRECLAIM_TECHNICAL
    assert 'UPDATE runs' not in M.BACKEND and 'INSERT INTO' not in M.BACKEND
