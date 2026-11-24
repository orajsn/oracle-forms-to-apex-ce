"""Read-only login evidence for the application created by conventional SQL reimport."""
from html.parser import HTMLParser
import http.client
import http.cookiejar
import re
import urllib.parse
import urllib.request


class _LoginForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.form = None
        self.form_count = 0
        self.form_name = None
        self.disabled_fieldsets = []
        self.inert = 0
        self.fields = {}
        self.ambiguous = False

    def handle_starttag(self, tag, attrs):
        if tag in ('template', 'noscript'):
            self.inert += 1
        if self.inert:
            return
        data = dict(attrs)
        if tag == 'fieldset':
            self.disabled_fieldsets.append('disabled' in data)
        if tag == 'form':
            self.form_name = data.get('id')
            self.ambiguous |= self.form is not None
            self.form_count += 1
            self.form = self.form_count
        if tag != 'input' or self.form is None:
            return
        name = data.get('name')
        if name not in ('p_flow_id', 'P9999_USERNAME', 'P9999_PASSWORD'):
            return
        self.ambiguous |= (name in self.fields or len(data) != len(attrs) or 'disabled' in data
                           or any(self.disabled_fieldsets)
                           or ('form' in data and (not self.form_name or data['form'] != self.form_name)))
        self.fields[name] = (self.form, (data.get('type') or 'text').lower(), data.get('value'))

    def handle_endtag(self, tag):
        if tag in ('template', 'noscript') and self.inert:
            self.inert -= 1
        elif not self.inert:
            if tag == 'fieldset' and self.disabled_fieldsets:
                self.disabled_fieldsets.pop()
            elif tag == 'form':
                self.form = self.form_name = None

    def matches(self, app_id):
        if self.ambiguous or set(self.fields) != {'p_flow_id', 'P9999_USERNAME', 'P9999_PASSWORD'}:
            return False
        form, kind, value = self.fields['p_flow_id']
        user, password = self.fields['P9999_USERNAME'], self.fields['P9999_PASSWORD']
        return (kind == 'hidden' and value == str(app_id)
                and user[0] == password[0] == form
                and user[1] in ('text', 'email') and password[1] == 'password')


def _origin(parts):
    if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username is not None or parts.password is not None:
        raise ValueError('Invalid configured APEX origin')
    return parts.scheme, parts.hostname, parts.port or (443 if parts.scheme == 'https' else 80)


class _AppRoute(urllib.request.HTTPRedirectHandler):
    def __init__(self, url):
        super().__init__()
        parts = urllib.parse.urlsplit(url)
        self.origin = _origin(parts)
        self.prefix = parts.path.rstrip('/').lower()

    def check(self, url):
        parts = urllib.parse.urlsplit(url)
        path = urllib.parse.unquote(parts.path).lower().rstrip('/')
        if (_origin(parts) != self.origin or '..' in path.split('/') or '\\' in path
                or not (path == self.prefix or path.startswith(self.prefix + '/'))):
            raise ValueError('Login response left the expected APEX application')

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.check(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _identity(original_id, receipt):
    copy_id, alias, digest = (receipt.get(k) for k in ('application_id', 'application_alias', 'sql_sha256'))
    if (type(original_id) is not int or original_id <= 0 or type(copy_id) is not int or copy_id <= 0
            or original_id == copy_id or not isinstance(alias, str) or not re.fullmatch(r'[A-Z0-9_-]+', alias)
            or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest)):
        raise ValueError('Invalid reimported application binding')
    return {'scope': 'reimported_login_page_identity', 'application_id': copy_id,
            'application_alias': alias, 'sql_sha256': digest, 'http_status': 200,
            'authenticated_business_flow_tested': False}


def check_copy_login(settings, original_id, receipt):
    evidence = _identity(original_id, receipt)
    base = urllib.parse.urlsplit(settings.apex_base_url)
    _origin(base)
    workspace = settings.apex_workspace
    if (base.query or base.fragment or not isinstance(workspace, str)
            or not re.fullmatch(r'[A-Za-z0-9_-]+', workspace)):
        raise ValueError('Invalid reimport login route')
    url = (settings.apex_base_url.rstrip('/') + '/r/' + workspace.lower() + '/'
           + evidence['application_alias'].lower() + '/')
    route = _AppRoute(url)
    opener = urllib.request.build_opener(route, urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    try:
        with opener.open(url, timeout=30) as response:
            route.check(response.geturl())
            raw = response.read(2_000_001)
            if response.status != 200 or len(raw) > 2_000_000:
                raise ValueError('Incomplete login response')
            form = _LoginForm()
            form.feed(raw.decode('utf-8', errors='replace'))
            form.close()
            if not form.matches(evidence['application_id']):
                raise ValueError('Login form identity differs')
    except (OSError, ValueError, http.client.HTTPException) as exc:
        # HTTP exception strings can include session IDs. Store no credentials,
        # redirect URLs, response bodies or cookies in the exported evidence.
        raise RuntimeError('Could not verify the login page of the reimported SQL application '
                           f'({type(exc).__name__}).') from None
    return evidence


def validate_saved_copy_login(evidence, receipt):
    # Older, hash-bound packages only recorded the source application's reachability.
    if 'reimport_login' in evidence:
        actual = evidence['reimport_login']
        if (not isinstance(actual, dict) or actual != _identity(evidence['application_id'], receipt)
                or actual.get('authenticated_business_flow_tested') is not False
                or type(actual.get('application_id')) is not int or type(actual.get('http_status')) is not int):
            raise ValueError('Saved reimport login evidence does not match the SQL receipt')
