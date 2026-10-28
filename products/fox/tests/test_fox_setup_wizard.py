"""Real loopback wizard transport and actual nonroot storage controller."""
import http.client
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import threading
from unittest.mock import patch

import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'fox')]
from qa.operator import setup_wizard as w


@pytest.fixture
def controller(tmp_path):
    if os.name!='posix' or os.geteuid()==0:pytest.skip('actual nonroot Linux required')
    tmp_path.chmod(0o700)
    return w.Controller(),str(tmp_path/'install')


def test_plan_does_not_write_and_approval_is_exact(controller):
    c,root=controller;status=c.plan({'installation_root':root})
    assert status['state']=='REVIEW_PLAN' and not Path(root).exists()
    with pytest.raises(w.WizardError):c.initialize({'plan_sha256':status['plan_sha256'],'confirmed':1})
    with pytest.raises(w.WizardError):c.initialize({'plan_sha256':'0'*64,'confirmed':True})
    assert not Path(root).exists()


def test_duplicate_approval_never_repeats_write(controller):
    c,root=controller;value=c.plan({'installation_root':root})
    body={'plan_sha256':value['plan_sha256'],'confirmed':True}
    first=c.initialize(body);assert first['state']=='STORAGE_PREPARED'
    with patch.object(w.step,'initialize',side_effect=AssertionError('no duplicate apply')):
        assert c.initialize(body)['state']=='STORAGE_PREPARED'
        checked=c.recheck();assert checked['state']=='STORAGE_PREPARED'
        assert checked['storage']['installation_id']==first['storage']['installation_id']
    assert not c.status()['conversion_ready'] and not c.status()['installation_complete']


def test_recheck_drift_clears_old_positive_state(controller):
    c,root=controller;v=c.plan({'installation_root':root})
    c.initialize({'plan_sha256':v['plan_sha256'],'confirmed':True})
    (Path(root)/'unrelated').write_bytes(b'preserve synthetic drift')
    result=c.recheck()
    assert result['state']=='ATTENTION' and result['storage'] is None
    assert (Path(root)/'unrelated').read_bytes()==b'preserve synthetic drift'


def test_failed_plan_invalidates_previous_approval(controller):
    c,root=controller;old=c.plan({'installation_root':root})
    with pytest.raises(Exception):c.plan({'installation_root':'../unsafe'})
    with pytest.raises(w.WizardError):c.initialize({'plan_sha256':old['plan_sha256'],'confirmed':True})
    assert not Path(root).exists()


def test_missing_parent_is_explained_before_any_confirmation(controller):
    c,root=controller
    with pytest.raises(w.step.InstallerStorageError,match='INSTALLATION_PARENT_MISSING'):
        c.plan({'installation_root':root+'/child'})
    assert c.value is None and not Path(root).exists()


def test_unknown_write_outcome_stays_attention_no_retry(controller):
    c,root=controller;value=c.plan({'installation_root':root})
    body={'plan_sha256':value['plan_sha256'],'confirmed':True}
    with patch.object(w.step,'initialize',side_effect=RuntimeError('synthetic-secret-value')):
        result=c.initialize(body)
    assert result['state']=='ATTENTION' and result['code']=='SETUP_OPERATION_UNCONFIRMED'
    assert 'synthetic-secret-value' not in json.dumps(result)
    with patch.object(w.step,'initialize',side_effect=AssertionError('no replay')):
        assert c.initialize(body)['state']=='ATTENTION'
        assert c.recheck()['state']=='ATTENTION'


def test_restarted_wizard_reads_completed_phase(controller):
    c,root=controller;v=c.plan({'installation_root':root})
    c.initialize({'plan_sha256':v['plan_sha256'],'confirmed':True})
    fresh=w.Controller();v=fresh.plan({'installation_root':root})
    assert v['storage']['status']=='STORAGE_OBSERVED_NOT_INSTALLED'
    with patch.object(w.step.storage,'initialize_storage',side_effect=AssertionError('no new producer')):
        assert fresh.initialize({'plan_sha256':v['plan_sha256'],'confirmed':True})['state']=='STORAGE_PREPARED'


@pytest.mark.parametrize('raw',[b'{"a":1,"a":2}',b'{"a":NaN}',b'[]',b'not-json'])
def test_bad_request_json_is_closed(raw):
    with pytest.raises(w.WizardError):w.json_body(raw)


class StubController:
    def __init__(self):self.calls=[]
    def plan(self,b):self.calls.append(('plan',b));return {'state':'REVIEW_PLAN'}
    def initialize(self,b):self.calls.append(('initialize',b));return {'state':'STORAGE_PREPARED','conversion_ready':False}
    def configure(self,b):self.calls.append(('configure',None));return {'state':'CONNECTION_INPUTS_SAVED','conversion_ready':False}
    def recheck(self):self.calls.append(('recheck',None));return {'state':'CHOOSE_LOCATION','conversion_ready':False}


@pytest.fixture
def server():
    controller=StubController();server,token=w.create_server(controller=controller)
    thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True);thread.start()
    try:yield server,token,controller
    finally:server.shutdown();server.server_close();thread.join(5)


def request(server,path,*,method='GET',body=None,auth=True,origin=True,host=None,raw=None):
    s,token,_=server
    connection=http.client.HTTPConnection('127.0.0.1',s.server_port,timeout=10)
    headers={'Host':host or '127.0.0.1:'+str(s.server_port)}
    if auth:headers['Authorization']='Bearer '+token
    if origin:headers['Origin']='http://127.0.0.1:'+str(s.server_port)
    if method=='POST':headers['Content-Type']='application/json'
    value=raw if raw is not None else json.dumps(body).encode() if body is not None else None
    connection.request(method,path,body=value,headers=headers)
    response=connection.getresponse();data=response.read();status=response.status;hdr=dict(response.getheaders());connection.close()
    return status,data,hdr


def test_server_is_literal_loopback_and_static_assets_have_policy(server):
    s,_,_=server;assert s.server_address[0]=='127.0.0.1'
    for path in ('/','/wizard.js','/wizard.css'):
        status,body,headers=request(server,path,auth=False,origin=False)
        assert status==200 and body
        assert headers['Cache-Control']=='no-store'
        assert "frame-ancestors 'none'" in headers['Content-Security-Policy']


@pytest.mark.parametrize('options',[{'auth':False},{'origin':False},{'host':'untrusted.example'}])
@pytest.mark.parametrize('path',['/api/initialize','/api/connections'])
def test_unauthorized_or_cross_site_mutation_never_reaches_controller(server,options,path):
    status,_,_=request(server,path,method='POST',body={},**options)
    assert status==400 and not server[2].calls


def test_actual_transport_routes_and_status_are_separate(server):
    assert request(server,'/api/status',origin=False)[0]==200
    assert server[2].calls==[('recheck',None)]
    assert request(server,'/api/plan',method='POST',body={'installation_root':'/synthetic/root'})[0]==200
    assert request(server,'/api/initialize',method='POST',body={})[0]==200
    assert request(server,'/api/connections',method='POST',body={})[0]==200
    assert [a for a,_ in server[2].calls]==['recheck','plan','initialize','configure']


@pytest.mark.parametrize('path',['/api/status?token=synthetic','/../private','/api/initialize','/missing'])
def test_arbitrary_get_cannot_read_file_or_mutate(server,path):
    status,_,_=request(server,path)
    assert status==400 and not server[2].calls


def test_oversized_and_duplicate_payloads_do_not_run(server):
    for body in (b'{"a":1,"a":2}',b'X'*4097):
        assert request(server,'/api/plan',method='POST',raw=body)[0]==400
    assert not server[2].calls


@pytest.mark.parametrize('length',['-1','+2','\u00b2','9'*5000])
def test_malformed_or_unbounded_length_is_rejected_without_integer_conversion(server,length):
    s,token,c=server
    connection=http.client.HTTPConnection('127.0.0.1',s.server_port,timeout=10)
    connection.putrequest('POST','/api/connections')
    for key,value in {'Origin':'http://127.0.0.1:'+str(s.server_port),
        'Authorization':'Bearer '+token,'Content-Type':'application/json','Content-Length':length}.items():
        connection.putheader(key,value)
    connection.endheaders()
    response=connection.getresponse()
    assert response.status==400 and json.loads(response.read())['code']=='REQUEST_SIZE_INVALID'
    connection.close();assert not c.calls


def test_read_status_requires_setup_auth(server):
    assert request(server,'/api/status',auth=False)[0]==400
    assert not server[2].calls


def test_expired_session_cannot_act_or_read_state(server):
    with patch.object(w,'monotonic',return_value=float('inf')):
        for path,method in (('/api/status','GET'),('/api/plan','POST')):
            status,body,_=request(server,path,method=method,body={} if method=='POST' else None)
            assert status==400 and json.loads(body)['code']=='SETUP_SESSION_EXPIRED'
    assert not server[2].calls


def test_wrong_origin_cannot_reach_storage(server):
    s,token,c=server
    connection=http.client.HTTPConnection('127.0.0.1',s.server_port,timeout=10)
    connection.request('POST','/api/initialize',body=b'{}',headers={
        'Host':'127.0.0.1:'+str(s.server_port),'Origin':'https://untrusted.example',
        'Authorization':'Bearer '+token,'Content-Type':'application/json'})
    response=connection.getresponse()
    assert response.status==400 and json.loads(response.read())['code']=='SETUP_ORIGIN_REJECTED'
    connection.close();assert not c.calls


def test_actual_setup_cli_starts_and_closes_owned_listener(controller):
    # No setup token is emitted to pytest output or included in assertion text.
    child=subprocess.Popen([sys.executable,'-I','-B',str(ROOT/'scripts/fox-setup.py'),'setup'],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        readable,_,_=select.select([child.stdout],[],[],10)
        assert readable,'setup did not report a listener'
        startup=json.loads(child.stdout.readline())
        assert startup['setup_url'].startswith('http://127.0.0.1:')
        assert len(startup['setup_code'])>=40 and not startup['conversion_ready']
        port=int(startup['setup_url'].rsplit(':',1)[1])
        connection=http.client.HTTPConnection('127.0.0.1',port,timeout=5)
        connection.request('GET','/')
        response=connection.getresponse();assert response.status==200;response.read();connection.close()
    finally:
        if child.poll() is None:child.send_signal(signal.SIGINT)
        child.communicate(timeout=10)
    assert child.returncode==0
