import importlib.util
from pathlib import Path
from types import SimpleNamespace

spec=importlib.util.spec_from_file_location('direct_poll',Path(__file__).parents[1]/'poll_direct_runtime.py')
poll=importlib.util.module_from_spec(spec);spec.loader.exec_module(poll)

def test_expired_unclaimed_request_does_not_hide_later_work(monkeypatch):
    config=SimpleNamespace(io=SimpleNamespace(pending=lambda limit:['old','new'],read=lambda job,*args:job))
    monkeypatch.setattr(poll,'object_bytes',lambda raw:raw)
    def deadline(packet):
        if packet=='old':raise RuntimeError('PROTOTYPE_BRIDGE_EXPIRED_UNKNOWN_NO_REPLAY')
    monkeypatch.setattr(poll,'remaining_seconds',deadline)
    called=[]
    def run(cfg,job):called.append(job);return {'state':'COMPLETE'}
    monkeypatch.setattr(poll,'run_once',run)
    assert poll.poll_once(config)==[{'job_id':'old','state':'RETAINED_REQUEST_NEEDS_RECONCILIATION'},{'job_id':'new','state':'COMPLETE'}]
    assert called==['new']

def test_runtime_failure_does_not_exit_supervisor_or_replay(monkeypatch):
    pending=['new'];calls=[]
    config=SimpleNamespace(io=SimpleNamespace(pending=lambda limit:list(pending),read=lambda *args:b'{}'))
    monkeypatch.setattr(poll,'object_bytes',lambda raw:{})
    monkeypatch.setattr(poll,'remaining_seconds',lambda packet:10)
    def uncertain(cfg,job):
        calls.append(job);pending.remove(job);raise RuntimeError('UNKNOWN')
    monkeypatch.setattr(poll,'run_once',uncertain)
    assert poll.poll_once(config)[0]['state']=='RUNTIME_OUTCOME_UNCONFIRMED_NO_REPLAY'
    assert poll.poll_once(config)==[]
    assert calls==['new']
