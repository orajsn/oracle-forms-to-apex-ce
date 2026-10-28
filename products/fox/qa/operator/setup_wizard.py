"""Loopback-only guided setup shell; implemented storage phase, not readiness.

No listener is created on import. The same controller is exercised by the UI and
HTTP tests. It owns one operator session and never accepts client-provided plans.
"""
from __future__ import annotations

import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import secrets
from time import monotonic

from . import installer_storage as step

ASSETS = Path(__file__).resolve().parents[2] / 'installer' / 'web'
MAX_BODY = 4096


class WizardError(ValueError):
    pass


def require(value, code):
    if not value:raise WizardError(code)


def closed(error):
    value = str(error)
    return value if isinstance(error, (WizardError, step.InstallerStorageError,
        step.storage.FreshStorageError)) and re.fullmatch(r'[A-Z][A-Z0-9_]{1,95}', value) else 'SETUP_OPERATION_UNCONFIRMED'


class Controller:
    def __init__(self):
        require(os.name == 'posix' and os.geteuid() > 0, 'POSIX_SETUP_OWNER_REQUIRED')
        self.value = None; self.hash = None; self.result = None
        self.state = 'CHOOSE_LOCATION'; self.code = None; self.attempted = False

    def status(self):
        return {'state': self.state, 'code': self.code,
            'write_attempted':self.attempted,
            'installation_root': self.value['installation_root'] if self.value else None,
            'plan_sha256': self.hash, 'storage': self.result,
            'conversion_ready': False, 'installation_complete': False,
            'remaining_phases': ['Runtime dependencies', 'OPAF and APEX connections',
                                 'Service startup', 'End-to-end verification']}

    def plan(self, body):
        require(not self.attempted, 'EXISTING_ATTEMPT_REQUIRES_RECHECK')
        self.value=None;self.hash=None;self.result=None;self.state='CHOOSE_LOCATION'
        require(type(body) is dict and set(body) == {'installation_root'}, 'PLAN_REQUEST_INVALID')
        value = step.plan(body['installation_root'], owner_uid=os.geteuid())
        digest = step.digest(value)
        observed = step.inspect(value, expected_plan_sha256=digest)
        self.value = value; self.hash = digest; self.code = None; self.result = observed
        self.state = 'REVIEW_PLAN'
        return self.status()

    def initialize(self, body):
        require(type(body) is dict and set(body) == {'plan_sha256', 'confirmed'}
                and body['confirmed'] is True and self.value is not None
                and type(body['plan_sha256']) is str
                and hmac.compare_digest(body['plan_sha256'], self.hash), 'EXACT_CONFIRMED_PLAN_REQUIRED')
        if self.attempted:
            # A duplicate HTTP request cannot repeat a known write or a failure.
            return self.status()
        self.attempted = True; self.state = 'INITIALIZING_STORAGE'
        try:
            self.result = step.initialize(self.value, expected_plan_sha256=self.hash, apply=True)
            self.state = 'STORAGE_PREPARED'; self.code = None
        except Exception as error:
            self.result = None;self.state = 'ATTENTION'; self.code = closed(error)
        return self.status()

    def recheck(self):
        if self.value is not None:
            try:
                self.result = step.inspect(self.value, expected_plan_sha256=self.hash)
                if self.result['status'] == 'STORAGE_OBSERVED_NOT_INSTALLED':
                    self.state = 'STORAGE_PREPARED'; self.code = None
            except Exception as error:
                self.result = None;self.state = 'ATTENTION'; self.code = closed(error)
        return self.status()


def json_body(raw):
    def pairs(items):
        value={}
        for key,item in items:
            require(key not in value,'DUPLICATE_REQUEST_FIELD');value[key]=item
        return value
    try:
        value=json.loads(raw.decode('utf-8'),object_pairs_hook=pairs,
                         parse_constant=lambda _: (_ for _ in ()).throw(WizardError('REQUEST_JSON_INVALID')))
    except WizardError:raise
    except (ValueError,UnicodeError,RecursionError):raise WizardError('REQUEST_JSON_INVALID') from None
    require(type(value) is dict,'REQUEST_OBJECT_REQUIRED')
    return value


def create_server(*, port=0, controller=None):
    require(type(port) is int and (port == 0 or 1024 <= port <= 65535), 'UNPRIVILEGED_SETUP_PORT_REQUIRED')
    controller = controller if controller is not None else Controller()
    token = secrets.token_urlsafe(32)
    expires_at = monotonic()+1800

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.0'
        def setup(self):
            super().setup();self.connection.settimeout(5)
        def log_message(self,*_args):pass  # No request headers, paths, or supplied values in logs.
        def send_error(self,*_args,**_kwargs):
            self.reply(400,{'code':'SETUP_METHOD_OR_REQUEST_REJECTED'})
        def reply(self,status,value,content_type='application/json'):
            raw=value if type(value) is bytes else json.dumps(value).encode()
            self.send_response(status)
            for key,item in {'Content-Type':content_type,'Content-Length':str(len(raw)),
                'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
                'Referrer-Policy':'no-referrer','Content-Security-Policy':
                "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"}.items():
                self.send_header(key,item)
            self.end_headers()
            try:self.wfile.write(raw)
            except (BrokenPipeError,ConnectionResetError):pass  # Controller retains the outcome.
        def checked(self, *, mutation=False, authorized=False):
            expected='127.0.0.1:'+str(self.server.server_port)
            require(self.headers.get_all('Host') == [expected], 'SETUP_HOST_REJECTED')
            origins=self.headers.get_all('Origin')
            require((origins is None and not mutation) or origins == ['http://'+expected], 'SETUP_ORIGIN_REJECTED')
            if authorized:
                require(monotonic() <= expires_at,'SETUP_SESSION_EXPIRED')
                auth=self.headers.get_all('Authorization')
                require(auth is not None and len(auth)==1 and hmac.compare_digest(auth[0],'Bearer '+token),
                        'SETUP_AUTHENTICATION_REQUIRED')
        def do_GET(self):
            try:
                self.checked(authorized=self.path.startswith('/api/'))
                if self.path == '/api/status':return self.reply(200,controller.recheck())
                files={'/':('index.html','text/html; charset=utf-8'),
                       '/wizard.js':('wizard.js','text/javascript; charset=utf-8'),
                       '/wizard.css':('wizard.css','text/css; charset=utf-8')}
                require(self.path in files,'SETUP_ROUTE_NOT_FOUND')
                name,kind=files[self.path];raw=(ASSETS/name).read_bytes()
                require(len(raw)<100000,'SETUP_ASSET_BOUND')
                self.reply(200,raw,kind)
            except Exception as error:self.reply(400,{'code':closed(error)})
        def do_POST(self):
            try:
                self.checked(mutation=True,authorized=True)
                require(self.path in ('/api/plan','/api/initialize'),'SETUP_ROUTE_NOT_FOUND')
                require(self.headers.get_all('Content-Type') == ['application/json']
                        and self.headers.get('Transfer-Encoding') is None,'REQUEST_ENCODING_REJECTED')
                lengths=self.headers.get_all('Content-Length')
                require(lengths is not None and len(lengths)==1 and lengths[0].isdigit()
                        and 0<int(lengths[0])<=MAX_BODY,'REQUEST_SIZE_INVALID')
                self.connection.settimeout(5)
                raw=self.rfile.read(int(lengths[0]));require(len(raw)==int(lengths[0]),'REQUEST_TRUNCATED')
                body=json_body(raw)
                result=controller.plan(body) if self.path=='/api/plan' else controller.initialize(body)
                self.reply(200,result)
            except Exception as error:self.reply(400,{'code':closed(error)})

    server=HTTPServer(('127.0.0.1',port),Handler)
    server.timeout=1
    return server,token


def serve(*,port=0):
    server,token=create_server(port=port)
    print(json.dumps({'setup_url':'http://127.0.0.1:'+str(server.server_port),
        'setup_code':token,'scope':'loopback-operator-setup-only',
        'conversion_ready':False}),flush=True)
    try:server.serve_forever(poll_interval=.25)
    except KeyboardInterrupt:pass
    finally:server.server_close()
