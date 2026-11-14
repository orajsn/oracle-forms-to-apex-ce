"""Read-only TLS warmup contracts; authored responses, no network or service calls."""
import ast
import errno
import http.client
import importlib.util
import json
from pathlib import Path
import socket
import ssl
from types import SimpleNamespace
import urllib.error
import urllib.request

import pytest

ROOT=Path(__file__).resolve().parents[2]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module);return module
M=load('tls_warmup_controller',ROOT/'deployment/current_pair_transition.py')
S=load('tls_warmup_strict_checker',ROOT/'deployment/cutover_project_release.py')
URL='https://fox.129.213.189.48.sslip.io/api/health'
HEALTH={'url':URL,'https_verified':True,'worker_healthy':True}


class Clock:
    def __init__(self):self.now=0;self.sleeps=[]
    def monotonic(self):return self.now
    def sleep(self,seconds):self.sleeps.append(seconds);self.now+=seconds


@pytest.mark.parametrize('error',[
    ConnectionRefusedError(errno.ECONNREFUSED,'authored'),ConnectionResetError(errno.ECONNRESET,'authored'),
    ConnectionAbortedError(errno.ECONNABORTED,'authored'),TimeoutError('authored'),
    OSError(errno.ETIMEDOUT,'authored'),urllib.error.URLError(ConnectionRefusedError(errno.ECONNREFUSED,'authored')),
    urllib.error.URLError(socket.timeout('authored')),urllib.error.HTTPError(URL,502,'authored',{},None),
    urllib.error.HTTPError(URL,503,'authored',{},None)])
def test_only_transient_failure_retried_then_unchanged_strict_result(monkeypatch,error):
    clock=Clock();monkeypatch.setattr(M,'time',clock);calls=[]
    def check(*,timeout):
        calls.append(timeout)
        if len(calls)==1:raise error
        return HEALTH
    assert M.wait_public_health(check)is HEALTH
    assert calls==[5,5]and clock.sleeps==[1]


@pytest.mark.parametrize('error',[
    urllib.error.HTTPError(URL,302,'redirect',{},None),urllib.error.HTTPError(URL,401,'auth',{},None),
    urllib.error.HTTPError(URL,403,'auth',{},None),urllib.error.HTTPError(URL,500,'server',{},None),
    urllib.error.HTTPError(URL,504,'not-approved',{},None),
    urllib.error.URLError(ssl.SSLCertVerificationError('certificate')),
    urllib.error.URLError(ssl.SSLError(errno.ECONNRESET,'TLS protocol, not connection reset')),
    ssl.CertificateError('hostname'),urllib.error.URLError(socket.gaierror(-2,'DNS')),
    urllib.error.URLError('timed out'),PermissionError(errno.EACCES,'denied'),BrokenPipeError(errno.EPIPE,'pipe'),
    json.JSONDecodeError('bad JSON','x',0),S.CutoverError('PUBLIC_WORKER_NOT_HEALTHY'),RuntimeError('unknown')])
def test_terminal_failures_are_not_retried(monkeypatch,error):
    clock=Clock();monkeypatch.setattr(M,'time',clock);calls=[]
    def check(*,timeout):calls.append(timeout);raise error
    with pytest.raises(type(error)):M.wait_public_health(check)
    assert calls==[5]and clock.sleeps==[]


def test_deadline_caps_attempt_time_and_does_not_make_late_attempt(monkeypatch):
    clock=Clock();monkeypatch.setattr(M,'time',clock);calls=[]
    def check(*,timeout):
        calls.append((clock.now,timeout));clock.now+=timeout;raise TimeoutError('authored timeout')
    with pytest.raises(M.TransitionError,match='PUBLIC_HEALTH_WARMUP_TIMEOUT'):
        M.wait_public_health(check)
    assert clock.now==60 and calls[-1]==(54,5)
    assert all(0<timeout<=min(5,60-start)for start,timeout in calls)


def test_late_health_is_never_accepted(monkeypatch):
    clock=Clock();monkeypatch.setattr(M,'time',clock)
    def check(*,timeout):clock.now=60;return HEALTH
    with pytest.raises(M.TransitionError,match='PUBLIC_HEALTH_WARMUP_TIMEOUT'):
        M.wait_public_health(check)


def test_final_fractional_timeout_and_sleep_stay_inside_budget(monkeypatch):
    clock=Clock();monkeypatch.setattr(M,'time',clock);calls=[]
    def check(*,timeout):
        calls.append(timeout)
        if len(calls)==1:clock.now=59.75;raise ConnectionRefusedError(errno.ECONNREFUSED,'authored')
        pytest.fail('No attempt may start after deadline')
    with pytest.raises(M.TransitionError,match='PUBLIC_HEALTH_WARMUP_TIMEOUT'):
        M.wait_public_health(check)
    assert calls==[5]and clock.sleeps==[0.25]and clock.now==60


def test_request_timeout_shrinks_to_remaining_fraction(monkeypatch):
    clock=Clock();monkeypatch.setattr(M,'time',clock);calls=[]
    def check(*,timeout):
        calls.append(timeout)
        if len(calls)==1:clock.now=58.75;raise ConnectionRefusedError(errno.ECONNREFUSED,'authored')
        clock.now+=0.1;return HEALTH
    assert M.wait_public_health(check)is HEALTH
    assert calls==[5,0.25]and clock.now<60


def strict_checker(monkeypatch,*,value=None,status=200,url=URL,error=None,raw_override=None):
    captured={};raw=json.dumps(value or {'product':'FOX','status':'ok','worker':{'enabled':True,'healthy':True}}).encode()
    if raw_override is not None:raw=raw_override
    original=urllib.request.build_opener
    class Response:
        def __enter__(self):return self
        def __exit__(self,*a):pass
        def read(self,limit):assert limit==65537;return raw[:limit]
    def build(*handlers):
        captured['handlers']=handlers;captured['opener']=original(*handlers)
        def open_(actual_url,*,timeout):
            captured['url']=actual_url;captured['timeout']=timeout
            if error:raise error
            response=Response();response.status=status;response.url=url;return response
        return SimpleNamespace(open=open_)
    monkeypatch.setattr(S.urllib.request,'build_opener',build)
    return captured


def test_real_strict_public_checker_default_and_optional_timeout_and_tls_contract(monkeypatch):
    captured=strict_checker(monkeypatch)
    assert S.public_health()==HEALTH and captured['timeout']==15
    assert S.public_health(timeout=0.25)==HEALTH and captured['timeout']==0.25
    assert captured['url']==URL and captured['handlers'][0].proxies=={}
    redirect=captured['handlers'][1]
    assert isinstance(redirect,urllib.request.HTTPRedirectHandler)
    assert redirect.redirect_request(None,None,None,None,None,None)is None
    https=[handler for handler in captured['opener'].handlers if isinstance(handler,urllib.request.HTTPSHandler)]
    assert len(https)==1
    context=https[0]._context
    # Python versions either defer or eagerly construct the default context.
    if context is not None:assert context.verify_mode==ssl.CERT_REQUIRED and context.check_hostname is True
    connection=http.client.HTTPSConnection('fox.129.213.189.48.sslip.io')  # Constructor only, no socket.
    assert connection._context.verify_mode==ssl.CERT_REQUIRED and connection._context.check_hostname is True


@pytest.mark.parametrize('timeout',[True,0,-1,16,float('inf'),float('nan'),'5',None])
def test_public_checker_invalid_timeout_refuses_before_io(monkeypatch,timeout):
    monkeypatch.setattr(S.urllib.request,'build_opener',lambda *a:pytest.fail('Invalid timeout reached IO'))
    with pytest.raises(S.CutoverError,match='PUBLIC_HEALTH_TIMEOUT_INVALID'):S.public_health(timeout=timeout)


@pytest.mark.parametrize('fault',['status','redirect','product','worker','boolean','json','oversize','json-status'])
def test_real_checker_bad_response_is_terminal_without_warmup_retry(monkeypatch,fault):
    value={'product':'FOX','status':'ok','worker':{'enabled':True,'healthy':True}}
    if fault=='product':value['product']='OTHER'
    if fault=='worker':value['worker']['healthy']=False
    if fault=='boolean':value['worker']['enabled']=1
    if fault=='json-status':value['status']='not-ok'
    captured=strict_checker(monkeypatch,value=value,status=201 if fault=='status'else 200,
        url=URL+'/redirect'if fault=='redirect'else URL,
        raw_override=b'{'if fault=='json'else(b'x'*65537 if fault=='oversize'else None))
    clock=Clock();monkeypatch.setattr(M,'time',clock)
    with pytest.raises((S.CutoverError,json.JSONDecodeError)):M.wait_public_health(S.public_health)
    assert clock.sleeps==[]and captured['timeout']==5


def test_real_strict_checker_certificate_failure_propagates_without_retry(monkeypatch):
    error=urllib.error.URLError(ssl.SSLCertVerificationError('authored certificate failure'))
    captured=strict_checker(monkeypatch,error=error)
    clock=Clock();monkeypatch.setattr(M,'time',clock)
    with pytest.raises(urllib.error.URLError)as caught:M.wait_public_health(S.public_health)
    assert caught.value is error and clock.sleeps==[]and captured['timeout']==5


def test_controller_only_one_tls_start_and_existing_post_health_identity_guard():
    tree=ast.parse((ROOT/'deployment/current_pair_transition.py').read_bytes())
    apply=next(node for node in ast.walk(tree)if isinstance(node,ast.FunctionDef)and node.name=='apply')
    calls=[node for node in ast.walk(apply)if isinstance(node,ast.Call)]
    starts=[node for node in calls if isinstance(node.func,ast.Attribute)and node.func.attr=='effect'
        and node.args and isinstance(node.args[0],ast.Constant)and node.args[0].value=='release-tls']
    assert len(starts)==1
    source=ast.unparse(apply)
    assert 'wait_public_health(self.M.public_health)'in source
    assert "self.operator_identity() == identity, 'OPERATOR_CHANGED_DURING_RELEASE'"in source
