import http.server
import json
import threading
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from forms2apex.release_login import check_copy_login, validate_saved_copy_login


RECEIPT = {'application_id': 112, 'application_alias': 'APP_COPY', 'sql_sha256': 'c'*64}
IDENTITY = '<input value="112" type="hidden" name="p_flow_id">'
LOGIN = '<input type="text" name="P9999_USERNAME"><input type="password" name="P9999_PASSWORD">'
FORM = '<form>' + IDENTITY + LOGIN + '</form>'


@contextmanager
def serve(reply):
    seen = []
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            status, location, body = reply(self.path)
            self.send_response(status)
            if location:
                self.send_header('Location', location)
            self.end_headers()
            self.wfile.write(body.encode())
        def log_message(self, *args):
            pass
    with http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval':0.02})
        thread.start()
        try:
            yield SimpleNamespace(apex_base_url=f'http://127.0.0.1:{server.server_port}/ords',
                                  apex_workspace='DEMO'), seen
        finally:
            server.shutdown()
            thread.join()


def test_exact_copy_and_safe_friendly_login_redirect():
    def reply(path):
        if path.endswith('/'):
            return 302, '/ords/r/demo/app_copy/login?session=LOCAL_SESSION', ''
        return 200, None, FORM
    with serve(reply) as (settings, seen):
        proof = check_copy_login(settings, 111, RECEIPT)
    assert len(seen)==2 and proof['application_id']==112 and proof['http_status']==200
    assert proof['authenticated_business_flow_tested'] is False
    assert 'LOCAL_SESSION' not in json.dumps(proof)
    validate_saved_copy_login({'application_id':111,'reimport_login':proof}, RECEIPT)
    with pytest.raises(ValueError):validate_saved_copy_login({'application_id':111,'reimport_login':dict(proof,application_id=111)},RECEIPT)
    validate_saved_copy_login({'application_id':111}, RECEIPT)


@pytest.mark.parametrize(('status','html'), [
    (404, FORM), (500, FORM), (200,'application unavailable'), (200,FORM.replace('112','111')),
    (200,FORM.replace(IDENTITY,'')), (200,FORM.replace(IDENTITY,IDENTITY+IDENTITY)),
    (200,FORM.replace('hidden','text')), (200,FORM.replace('112','00112')),
    (200,'<form>'+IDENTITY+'</form><form>'+LOGIN+'</form>'),
    (200,'<form>'+LOGIN+'<!-- '+IDENTITY+' --></form>'),
    (200,'<form>'+LOGIN+'<script>'+IDENTITY+'</script></form>'),
    (200,'<template>'+FORM+'</template>'),
    (200,FORM.replace('type="password"', 'disabled type="password"')),
    (200,FORM.replace('type="password"', 'form="another" type="password"')),
    (200,'<fieldset disabled>'+FORM+'</fieldset>'),
])
def test_unproved_copy_is_rejected(status,html):
    with serve(lambda path:(status,None,html)) as (settings,_):
        with pytest.raises(RuntimeError,match='reimported SQL application'):
            check_copy_login(settings,111,RECEIPT)


def test_redirect_to_another_app_or_origin_is_never_followed():
    with serve(lambda path:(200,None,FORM)) as (foreign,foreign_hits):
        for url in (foreign.apex_base_url+'/r/demo/app_copy/login',
                    '/ords/r/demo/wrong/login?session=SENSITIVE_QUERY'):
            with serve(lambda path:(302,url,'')) as (settings,seen):
                with pytest.raises(RuntimeError) as failure:
                    check_copy_login(settings,111,RECEIPT)
                assert len(seen)==1 and not foreign_hits and 'SENSITIVE_QUERY' not in str(failure.value)


def test_source_id_or_malformed_copy_alias_cannot_start_a_probe():
    with serve(lambda path:(200,None,FORM)) as (settings,seen):
        for original,receipt in [(112,RECEIPT),(111,dict(RECEIPT,application_alias='../OTHER'))]:
            with pytest.raises(ValueError):check_copy_login(settings,original,receipt)
        assert seen==[]
